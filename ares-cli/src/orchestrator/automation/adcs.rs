//! auto_adcs_enumeration -- detect ADCS servers via CertEnroll share.

use std::sync::Arc;
use std::time::Duration;

use serde_json::json;
use tokio::sync::watch;
use tracing::{info, warn};

use ares_llm::ToolCall;

use crate::orchestrator::dispatcher::Dispatcher;
use crate::orchestrator::state::*;

/// Extract domain from an ADCS host's FQDN.
/// e.g. "srv01.fabrikam.local" -> "fabrikam.local"
fn extract_domain_from_fqdn(fqdn: &str) -> Option<String> {
    fqdn.to_lowercase()
        .split_once('.')
        .map(|(_, d)| d.to_string())
}

/// Work item for ADCS enumeration.
///
/// When no cleartext credential is available but an NTLM hash is, the work
/// item carries a synthetic `Credential` with the hash-owner's username and
/// an empty password. The worker's credential resolver looks up the matching
/// `Hash` record by `(username, domain)` and injects it as the `hash` arg, so
/// the dispatcher doesn't need to thread the hash through separately.
struct AdcsWork {
    host_ip: String,
    /// Auth-and-identity dedup key
    /// (e.g. `"192.168.58.10:cred:jdoe@contoso.local"` or `"…:hash:admin@…"`).
    /// Including the credential identity prevents one wrong-domain attempt
    /// from permanently locking a CA host against later, possibly-correct creds.
    dedup_key: String,
    dc_ip: Option<String>,
    domain: String,
    credential: ares_core::models::Credential,
}

/// Dedup key for a cred-based certipy_find attempt.
/// Format: `{host}:cred:{username}@{domain}` (lowercased identity).
pub(crate) fn dedup_key_cred(host: &str, cred: &ares_core::models::Credential) -> String {
    format!(
        "{}:cred:{}@{}",
        host,
        cred.username.to_lowercase(),
        cred.domain.to_lowercase()
    )
}

/// Dedup key for a hash-based certipy_find attempt.
/// Format: `{host}:hash:{username}@{domain}` (lowercased identity).
pub(crate) fn dedup_key_hash(host: &str, hash: &ares_core::models::Hash) -> String {
    format!(
        "{}:hash:{}@{}",
        host,
        hash.username.to_lowercase(),
        hash.domain.to_lowercase()
    )
}

/// Returns true when `host` advertises an LDAP service (port 389 or 636,
/// or a service line containing `ldap`). LDAP availability is the
/// authoritative signal that a host is a DC (or CA-co-located DC) and is
/// a valid certipy_find target even when share enumeration hasn't surfaced
/// a `CertEnroll` entry yet.
fn host_has_ldap(host: &ares_core::models::Host) -> bool {
    host.services.iter().any(|s| {
        let l = s.to_lowercase();
        l.starts_with("389/") || l.starts_with("636/") || l.contains("ldap")
    })
}

/// Collect ADCS enumeration work items from current state.
///
/// Pure logic extracted from `auto_adcs_enumeration` so it can be unit-tested
/// without needing a `Dispatcher` or async runtime.
///
/// Candidate hosts come from two sources:
///   1. Confirmed CA hosts — any host with a `CertEnroll` share. These are
///      certainly running ADCS web enrollment.
///   2. LDAP-open hosts — any DC-like host where `auto_share_enumeration`
///      didn't (yet) surface `CertEnroll`. Cross-forest SMB auth often fails
///      with access-denied and silently disables ADCS enumeration. Falling
///      back to LDAP-only hosts lets certipy_find probe the CA via LDAP
///      directly even when SMB share-listing failed.
fn collect_adcs_work(state: &StateInner) -> Vec<AdcsWork> {
    if state.credentials.is_empty() && state.hashes.is_empty() {
        return Vec::new();
    }

    // Source 1: hosts with confirmed CertEnroll share.
    let cert_share_hosts: Vec<String> = state
        .shares
        .iter()
        .filter(|s| s.name.to_lowercase() == "certenroll")
        .map(|s| s.host.clone())
        .collect();

    // Source 2: LDAP-open hosts not already covered by a CertEnroll share.
    // These are tried with the same credential/hash selection logic; if the
    // host doesn't actually run ADCS, certipy_find will return nothing and
    // the dedup key marks it as processed (no further attempts).
    let cert_share_set: std::collections::HashSet<String> =
        cert_share_hosts.iter().cloned().collect();
    let ldap_fallback_hosts: Vec<String> = state
        .hosts
        .iter()
        .filter(|h| host_has_ldap(h) && !cert_share_set.contains(&h.ip))
        .map(|h| h.ip.clone())
        .collect();

    let mut candidate_hosts = cert_share_hosts;
    candidate_hosts.extend(ldap_fallback_hosts);

    candidate_hosts
        .into_iter()
        .filter_map(|host_ip| {
            let host_lower = host_ip.to_lowercase();

            let domain = state
                .hosts
                .iter()
                .find(|h| h.ip == host_ip || h.hostname.to_lowercase() == host_lower)
                .and_then(|h| extract_domain_from_fqdn(&h.hostname))
                .and_then(|d| {
                    if state.domains.iter().any(|known| known.to_lowercase() == d) {
                        Some(d)
                    } else {
                        state
                            .domains
                            .iter()
                            .find(|known| d.ends_with(&format!(".{}", known.to_lowercase())))
                            .or_else(|| {
                                state
                                    .domains
                                    .iter()
                                    .find(|known| known.to_lowercase().ends_with(&format!(".{d}")))
                            })
                            .cloned()
                            .or(Some(d))
                    }
                })
                .or_else(|| state.domains.first().cloned())?;

            // Skip domains we already own — DA on a domain means we don't
            // need to escalate via its CA. (We may still need ADCS against an
            // un-owned domain via cross-trust, so this is per-domain not global.)
            if state.dominated_domains.contains(&domain) {
                return None;
            }

            // Look up DC IP for this domain (certipy needs LDAP on a DC, not the CA host).
            // Uses resolve_dc_ip() which falls back to scanning hosts list when
            // domain_controllers doesn't have an entry.
            let dc_ip = state.resolve_dc_ip(&domain);

            // certipy_find authenticates via LDAP bind to the target DC.
            // NTLM/Kerberos bind succeeds within the same forest (same domain or
            // parent/child/sibling) but fails 52e across a forest trust because
            // the source principal does not exist in the target's domain and
            // impacket cannot follow Kerberos cross-realm referrals.
            //
            // Restrict cred selection to the same forest as the target. If no
            // same-forest cred exists, skip dispatch — other automations
            // (foreign_group_enum, mssql_linked_server, golden_cert) handle
            // the cross-forest foothold path that yields a same-forest cred.
            //
            // The dedup key includes the candidate credential's identity, so a
            // failed first attempt with one cred does not block a later, possibly
            // correct cred against the same CA host.
            let domain_lower = domain.to_lowercase();
            let target_forest = state.forest_root_of(&domain_lower);
            // Same-domain creds first, same-forest cross-domain creds second,
            // and stop at the first unprocessed dedup key. Chained iterators —
            // no intermediate Vec — to satisfy clippy::needless_collect.
            let cred = state
                .credentials
                .iter()
                .filter(|c| {
                    !c.password.is_empty()
                        && c.domain.to_lowercase() == domain_lower
                        && !state.is_delegation_account(&c.username)
                        && !state.is_principal_quarantined(&c.username, &c.domain)
                })
                .chain(state.credentials.iter().filter(|c| {
                    let cd = c.domain.to_lowercase();
                    !c.password.is_empty()
                        && cd != domain_lower
                        && state.forest_root_of(&cd) == target_forest
                        && !state.is_delegation_account(&c.username)
                        && !state.is_principal_quarantined(&c.username, &c.domain)
                }))
                .find(|c| !state.is_processed(DEDUP_ADCS_SERVERS, &dedup_key_cred(&host_ip, c)))
                .cloned();

            // Look for NTLM hash (PTH) only if cred path is exhausted (no
            // unprocessed cred candidate exists). Same identity-aware dedup.
            let hash_pick = if cred.is_none() {
                let pred_admin_same = |h: &&ares_core::models::Hash| {
                    h.hash_type.eq_ignore_ascii_case("ntlm")
                        && (h.domain.to_lowercase() == domain_lower || h.domain.is_empty())
                        && h.username.to_lowercase() == "administrator"
                };
                let pred_any_same = |h: &&ares_core::models::Hash| {
                    h.hash_type.eq_ignore_ascii_case("ntlm")
                        && (h.domain.to_lowercase() == domain_lower || h.domain.is_empty())
                        && !state.is_delegation_account(&h.username)
                };
                let same_forest = |h: &&ares_core::models::Hash| -> bool {
                    let hd = h.domain.to_lowercase();
                    !hd.is_empty() && state.forest_root_of(&hd) == target_forest
                };
                let pred_admin_xdom = |h: &&ares_core::models::Hash| {
                    h.hash_type.eq_ignore_ascii_case("ntlm")
                        && same_forest(h)
                        && h.username.to_lowercase() == "administrator"
                };
                let pred_any_xdom = |h: &&ares_core::models::Hash| {
                    h.hash_type.eq_ignore_ascii_case("ntlm")
                        && same_forest(h)
                        && !state.is_delegation_account(&h.username)
                };

                let mut candidates: Vec<&ares_core::models::Hash> = Vec::new();
                candidates.extend(state.hashes.iter().filter(pred_admin_same));
                candidates.extend(state.hashes.iter().filter(pred_any_same).filter(|h| {
                    h.username.to_lowercase() != "administrator"
                        || (h.domain.to_lowercase() != domain_lower && !h.domain.is_empty())
                }));
                candidates.extend(
                    state.hashes.iter().filter(pred_admin_xdom).filter(|h| {
                        h.domain.to_lowercase() != domain_lower && !h.domain.is_empty()
                    }),
                );
                candidates.extend(
                    state
                        .hashes
                        .iter()
                        .filter(pred_any_xdom)
                        .filter(|h| h.username.to_lowercase() != "administrator"),
                );
                candidates
                    .into_iter()
                    .find(|h| !state.is_processed(DEDUP_ADCS_SERVERS, &dedup_key_hash(&host_ip, h)))
                    .cloned()
            } else {
                None
            };
            // Kerberos ticket fallback — when no same-forest plaintext cred
            // or NTLM hash exists (common for a freshly-discovered foreign
            // forest), a pre-forged inter-realm ccache is enough for
            // certipy_find's LDAP bind. The credential_resolver injects the
            // ticket for cross-forest tools; we just need a synthetic
            // credential seeded with the ticket's identity so the resolver
            // can match it. Dedup key uses the ticket's source domain so a
            // single forge attempt doesn't permanently block later retries
            // with a real cred if one lands in state.
            let ticket_cred = if cred.is_none() && hash_pick.is_none() {
                state
                    .kerberos_tickets
                    .iter()
                    .find(|t| t.target_domain.to_lowercase() == domain_lower)
                    .map(|t| {
                        let dedup = format!(
                            "{}:ticket:{}@{}",
                            host_ip,
                            t.username.to_lowercase(),
                            t.source_domain.to_lowercase()
                        );
                        (
                            dedup,
                            ares_core::models::Credential {
                                id: String::new(),
                                username: t.username.clone(),
                                password: String::new(),
                                domain: t.source_domain.clone(),
                                source: "kerberos_ticket".into(),
                                is_admin: true,
                                discovered_at: None,
                                parent_id: None,
                                attack_step: 0,
                            },
                        )
                    })
                    .filter(|(dedup, _)| !state.is_processed(DEDUP_ADCS_SERVERS, dedup))
            } else {
                None
            };

            // Need a cred, hash, or forged Kerberos ticket
            if cred.is_none() && hash_pick.is_none() && ticket_cred.is_none() {
                return None;
            }

            let (dedup_key, credential) = if let Some((dk, tc)) = ticket_cred {
                (dk, tc)
            } else {
                let dk = match (&cred, &hash_pick) {
                    (Some(c), _) => dedup_key_cred(&host_ip, c),
                    (None, Some(h)) => dedup_key_hash(&host_ip, h),
                    (None, None) => return None,
                };
                // Synthetic credential from the hash owner's identity when no
                // cleartext cred is available; credential_resolver looks up the
                // matching Hash record by (username, domain) and injects the
                // `hash` arg, which `certipy_find` accepts via `-hashes`.
                let c = cred.unwrap_or_else(|| {
                    let h = hash_pick.as_ref().expect("guard above ensures one is Some");
                    ares_core::models::Credential {
                        id: String::new(),
                        username: h.username.clone(),
                        password: String::new(),
                        domain: domain.clone(),
                        source: "hash_fallback".into(),
                        is_admin: false,
                        discovered_at: None,
                        parent_id: None,
                        attack_step: 0,
                    }
                });
                (dk, c)
            };

            Some(AdcsWork {
                host_ip,
                dedup_key,
                dc_ip,
                domain,
                credential,
            })
        })
        .collect()
}

/// Detects ADCS servers by looking for CertEnroll shares and dispatches certipy_find.
/// Interval: 30s.
pub async fn auto_adcs_enumeration(
    dispatcher: Arc<Dispatcher>,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut interval = tokio::time::interval(Duration::from_secs(30));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            _ = interval.tick() => {},
            _ = shutdown.changed() => break,
        }
        if *shutdown.borrow() {
            break;
        }

        let work = {
            let state = dispatcher.state.read().await;
            let creds = state.credentials.len();
            let hashes = state.hashes.len();
            let certenroll_shares: Vec<_> = state
                .shares
                .iter()
                .filter(|s| s.name.to_lowercase() == "certenroll")
                .collect();
            let ce_count = certenroll_shares.len();
            let ce_hosts: Vec<_> = certenroll_shares.iter().map(|s| s.host.as_str()).collect();
            let cred_domains: Vec<_> = state
                .credentials
                .iter()
                .map(|c| c.domain.as_str())
                .collect();
            let hash_domains: Vec<_> = state.hashes.iter().map(|h| h.domain.as_str()).collect();
            let domains: Vec<_> = state.domains.iter().map(|d| d.as_str()).collect();
            let w = collect_adcs_work(&state);
            info!(
                creds,
                hashes,
                certenroll_shares = ce_count,
                ?ce_hosts,
                ?cred_domains,
                ?hash_domains,
                ?domains,
                work_items = w.len(),
                "auto_adcs_enumeration: tick"
            );
            w
        };

        for item in work {
            // Use DC IP for certipy LDAP queries; fall back to CA host IP
            let target_ip = item.dc_ip.as_deref().unwrap_or(&item.host_ip);
            // Pass CA host IP separately so the parser sets the correct vuln target
            // (the CA server, not the DC used for LDAP).
            let ca_host_ip = if item.dc_ip.is_some() {
                Some(item.host_ip.as_str())
            } else {
                None
            };

            // Mark dedup BEFORE dispatch so concurrent ticks don't double-fire
            // against the same (CA, credential) pair. The spawned task clears
            // dedup on transport failure so the next tick can retry.
            dispatcher
                .state
                .write()
                .await
                .mark_processed(DEDUP_ADCS_SERVERS, item.dedup_key.clone());
            let _ = dispatcher
                .state
                .persist_dedup(&dispatcher.queue, DEDUP_ADCS_SERVERS, &item.dedup_key)
                .await;

            // Deterministic tool dispatch — bypass the LLM "recon" agent.
            // The LLM-routed path (`request_certipy_find`) puts a task in the
            // recon queue with instructions to call `certipy_find` and
            // register vulns. In practice the recon agent has been observed
            // burning its budget on adjacent techniques (unconstrained
            // delegation TGT dumps that need local admin, WinRM exec without
            // a WinRM tool installed, etc.) and never reaching certipy_find
            // against discovered ADCS servers — even when a usable cred for
            // the CA's domain is sitting in state. Bypassing the agent
            // guarantees every (CA host, cred) pair gets one certipy_find
            // shot; the worker's parser (`parse_certipy_find`) extracts ESC
            // vulns from raw output and the result_processing pipeline
            // publishes them, letting `auto_adcs_exploitation` pick up
            // immediately. Same approach as `auto_mssql_link_pivot`.
            let task_id = format!(
                "adcs_find_{}",
                &uuid::Uuid::new_v4().simple().to_string()[..12]
            );
            let mut args = json!({
                "username": item.credential.username,
                "domain": item.domain,
                "dc_ip": target_ip,
                "vulnerable": true,
            });
            if let Some(ref ca_ip) = ca_host_ip {
                // Surfaces ca_host_ip in the params object the parser reads to
                // set the resulting vuln's `target` to the CA, not the DC.
                args["ca_host_ip"] = json!(ca_ip);
            }
            // Credential resolver injects password/hash from state given
            // (username, domain) — we never carry secrets in the args here.
            let call = ToolCall {
                id: format!("certipy_find_{}", uuid::Uuid::new_v4().simple()),
                name: "certipy_find".to_string(),
                arguments: args,
            };
            info!(
                task_id = %task_id,
                ca_host = %item.host_ip,
                dc_ip = ?item.dc_ip,
                domain = %item.domain,
                user = %item.credential.username,
                "ADCS find dispatched (direct tool, no LLM)"
            );

            let dispatcher_bg = dispatcher.clone();
            let dedup_key_bg = item.dedup_key.clone();
            let host_ip_bg = item.host_ip.clone();
            let task_id_bg = task_id.clone();
            tokio::spawn(async move {
                let result = dispatcher_bg
                    .llm_runner
                    .tool_dispatcher()
                    .dispatch_tool("recon", &task_id_bg, &call)
                    .await;
                match result {
                    Ok(exec) => {
                        let vulns_found = exec
                            .discoveries
                            .as_ref()
                            .and_then(|d| d.get("vulnerabilities"))
                            .and_then(|v| v.as_array())
                            .map(|a| a.len())
                            .unwrap_or(0);
                        info!(
                            task_id = %task_id_bg,
                            ca_host = %host_ip_bg,
                            vulns_found,
                            "Deterministic certipy_find completed"
                        );
                        // No vulns + no transport error → genuine "nothing
                        // vulnerable here". Keep dedup locked. The exec
                        // path may also emit an error if creds were
                        // missing — in which case clear dedup to allow a
                        // later credential to retry.
                        if let Some(err) = exec.error {
                            warn!(
                                task_id = %task_id_bg,
                                ca_host = %host_ip_bg,
                                err = %err,
                                "Deterministic certipy_find failed — clearing dedup for retry"
                            );
                            dispatcher_bg
                                .state
                                .write()
                                .await
                                .unmark_processed(DEDUP_ADCS_SERVERS, &dedup_key_bg);
                            let _ = dispatcher_bg
                                .state
                                .unpersist_dedup(
                                    &dispatcher_bg.queue,
                                    DEDUP_ADCS_SERVERS,
                                    &dedup_key_bg,
                                )
                                .await;
                        }
                    }
                    Err(e) => {
                        warn!(
                            task_id = %task_id_bg,
                            ca_host = %host_ip_bg,
                            err = %e,
                            "Deterministic certipy_find dispatch errored — clearing dedup for retry"
                        );
                        dispatcher_bg
                            .state
                            .write()
                            .await
                            .unmark_processed(DEDUP_ADCS_SERVERS, &dedup_key_bg);
                        let _ = dispatcher_bg
                            .state
                            .unpersist_dedup(
                                &dispatcher_bg.queue,
                                DEDUP_ADCS_SERVERS,
                                &dedup_key_bg,
                            )
                            .await;
                    }
                }
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ares_core::models::{Credential, Host, Share};

    fn make_credential(username: &str, password: &str, domain: &str) -> Credential {
        Credential {
            id: format!("c-{username}"),
            username: username.into(),
            password: password.into(), // pragma: allowlist secret
            domain: domain.into(),
            source: "test".into(),
            is_admin: false,
            discovered_at: None,
            parent_id: None,
            attack_step: 0,
        }
    }

    fn make_host(ip: &str, hostname: &str, is_dc: bool) -> Host {
        Host {
            ip: ip.into(),
            hostname: hostname.into(),
            os: String::new(),
            roles: Vec::new(),
            services: Vec::new(),
            is_dc,
            owned: false,
        }
    }

    fn make_share(host: &str, name: &str) -> Share {
        Share {
            host: host.into(),
            name: name.into(),
            permissions: String::new(),
            comment: String::new(),
            authenticated_as: None,
        }
    }

    // --- collect_adcs_work tests ---

    #[test]
    fn collect_empty_state_returns_no_work() {
        let state = StateInner::new("test-op".into());
        let work = collect_adcs_work(&state);
        assert!(work.is_empty());
    }

    #[test]
    fn collect_no_credentials_returns_no_work() {
        let mut state = StateInner::new("test-op".into());
        state.shares.push(make_share("192.168.58.50", "CertEnroll"));
        let work = collect_adcs_work(&state);
        assert!(work.is_empty());
    }

    #[test]
    fn collect_certenroll_share_produces_work() {
        let mut state = StateInner::new("test-op".into());
        state.shares.push(make_share("192.168.58.50", "CertEnroll"));
        state
            .hosts
            .push(make_host("192.168.58.50", "ca01.contoso.local", false));
        state.domains.push("contoso.local".into());
        state
            .credentials
            .push(make_credential("admin", "P@ssw0rd!", "contoso.local")); // pragma: allowlist secret
        let work = collect_adcs_work(&state);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].host_ip, "192.168.58.50");
        assert_eq!(work[0].domain, "contoso.local");
        assert_eq!(work[0].credential.username, "admin");
    }

    #[test]
    fn collect_ldap_open_host_produces_work_even_without_certenroll_share() {
        // LDAP-fallback path: a DC with port 389 open but no CertEnroll share
        // discovered (e.g., share enum failed cross-forest). The chain should
        // still emit a certipy_find work item against it.
        let mut state = StateInner::new("test-op".into());
        let mut dc = make_host("192.168.58.20", "dc02.fabrikam.local", true);
        dc.services.push("389/tcp ldap".into());
        state.hosts.push(dc);
        state.domains.push("fabrikam.local".into());
        state
            .credentials
            .push(make_credential("alice", "P@ssw0rd!", "fabrikam.local")); // pragma: allowlist secret
        let work = collect_adcs_work(&state);
        assert_eq!(work.len(), 1, "ldap-open host should yield ADCS work");
        assert_eq!(work[0].host_ip, "192.168.58.20");
        assert_eq!(work[0].domain, "fabrikam.local");
    }

    #[test]
    fn collect_skips_ldap_host_already_covered_by_certenroll_share() {
        // When the same host has BOTH a CertEnroll share AND LDAP open, we
        // should emit exactly one work item (no double-dispatch).
        let mut state = StateInner::new("test-op".into());
        state.shares.push(make_share("192.168.58.50", "CertEnroll"));
        let mut ca = make_host("192.168.58.50", "ca01.contoso.local", false);
        ca.services.push("389/tcp ldap".into());
        state.hosts.push(ca);
        state.domains.push("contoso.local".into());
        state
            .credentials
            .push(make_credential("admin", "P@ssw0rd!", "contoso.local")); // pragma: allowlist secret
        let work = collect_adcs_work(&state);
        assert_eq!(work.len(), 1, "ldap-fallback must not duplicate share path");
    }

    #[test]
    fn collect_skips_host_without_ldap_or_certenroll() {
        // A plain SMB-only file server has no LDAP and no CertEnroll share —
        // not a candidate for ADCS enumeration.
        let mut state = StateInner::new("test-op".into());
        let mut fs = make_host("192.168.58.40", "fs01.contoso.local", false);
        fs.services.push("445/tcp microsoft-ds".into());
        state.hosts.push(fs);
        state.domains.push("contoso.local".into());
        state
            .credentials
            .push(make_credential("admin", "P@ssw0rd!", "contoso.local")); // pragma: allowlist secret
        let work = collect_adcs_work(&state);
        assert!(
            work.is_empty(),
            "non-LDAP host should not be an ADCS candidate"
        );
    }

    #[test]
    fn host_has_ldap_detects_port_and_service() {
        let mut h = make_host("192.168.58.10", "dc01.contoso.local", true);
        assert!(!host_has_ldap(&h));
        h.services.push("389/tcp ldap".into());
        assert!(host_has_ldap(&h));

        let mut h2 = make_host("192.168.58.11", "dc02.contoso.local", true);
        h2.services.push("636/tcp ssl/ldap".into());
        assert!(host_has_ldap(&h2));

        let mut h3 = make_host("192.168.58.12", "ws01.contoso.local", false);
        h3.services.push("445/tcp microsoft-ds".into());
        assert!(!host_has_ldap(&h3));
    }

    #[test]
    fn collect_dedup_skips_already_processed() {
        let mut state = StateInner::new("test-op".into());
        state.shares.push(make_share("192.168.58.50", "CertEnroll"));
        state
            .hosts
            .push(make_host("192.168.58.50", "ca01.contoso.local", false));
        state.domains.push("contoso.local".into());
        let cred = make_credential("admin", "P@ssw0rd!", "contoso.local"); // pragma: allowlist secret
        state.credentials.push(cred.clone());
        // Mark the identity-aware dedup key for the only candidate cred.
        state.mark_processed(DEDUP_ADCS_SERVERS, dedup_key_cred("192.168.58.50", &cred));
        let work = collect_adcs_work(&state);
        assert!(work.is_empty());
    }

    #[test]
    fn collect_non_certenroll_share_ignored() {
        let mut state = StateInner::new("test-op".into());
        state.shares.push(make_share("192.168.58.50", "SYSVOL"));
        state
            .hosts
            .push(make_host("192.168.58.50", "dc01.contoso.local", true));
        state.domains.push("contoso.local".into());
        state
            .credentials
            .push(make_credential("admin", "P@ssw0rd!", "contoso.local")); // pragma: allowlist secret
        let work = collect_adcs_work(&state);
        assert!(work.is_empty());
    }

    #[test]
    fn collect_prefers_same_domain_credential() {
        let mut state = StateInner::new("test-op".into());
        state.shares.push(make_share("192.168.58.50", "CertEnroll"));
        state
            .hosts
            .push(make_host("192.168.58.50", "ca01.fabrikam.local", false));
        state.domains.push("fabrikam.local".into());
        state
            .credentials
            .push(make_credential("crossuser", "Cross!1", "contoso.local")); // pragma: allowlist secret
        state
            .credentials
            .push(make_credential("fabadmin", "Fab!Pass1", "fabrikam.local")); // pragma: allowlist secret
        let work = collect_adcs_work(&state);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].credential.username, "fabadmin");
    }

    #[test]
    fn collect_falls_back_to_first_domain_when_no_host_match() {
        let mut state = StateInner::new("test-op".into());
        state.shares.push(make_share("192.168.58.50", "CertEnroll"));
        // No matching host in state.hosts
        state.domains.push("contoso.local".into());
        state
            .credentials
            .push(make_credential("admin", "P@ssw0rd!", "contoso.local")); // pragma: allowlist secret
        let work = collect_adcs_work(&state);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].domain, "contoso.local");
    }

    #[test]
    fn collect_certenroll_case_insensitive() {
        let mut state = StateInner::new("test-op".into());
        state.shares.push(make_share("192.168.58.50", "certenroll"));
        state.domains.push("contoso.local".into());
        state
            .credentials
            .push(make_credential("admin", "P@ssw0rd!", "contoso.local")); // pragma: allowlist secret
        let work = collect_adcs_work(&state);
        assert_eq!(work.len(), 1);
    }

    #[test]
    fn collect_multiple_adcs_hosts() {
        let mut state = StateInner::new("test-op".into());
        state.shares.push(make_share("192.168.58.50", "CertEnroll"));
        state.shares.push(make_share("192.168.58.51", "CertEnroll"));
        state
            .hosts
            .push(make_host("192.168.58.50", "ca01.contoso.local", false));
        state
            .hosts
            .push(make_host("192.168.58.51", "ca02.fabrikam.local", false));
        state.domains.push("contoso.local".into());
        state.domains.push("fabrikam.local".into());
        state
            .credentials
            .push(make_credential("admin", "P@ssw0rd!", "contoso.local")); // pragma: allowlist secret
        state
            .credentials
            .push(make_credential("fabadmin", "Fab!Pass1", "fabrikam.local")); // pragma: allowlist secret
        let work = collect_adcs_work(&state);
        assert_eq!(work.len(), 2);
    }

    #[test]
    fn collect_skips_cross_forest_cred_for_ca_host() {
        // contoso.local CA, only fabrikam.local cred (different forest).
        // certipy_find LDAP bind across forest trust fails 52e — skip dispatch.
        let mut state = StateInner::new("test-op".into());
        state.shares.push(make_share("192.168.58.50", "CertEnroll"));
        state
            .hosts
            .push(make_host("192.168.58.50", "ca01.contoso.local", false));
        state.domains.push("contoso.local".into());
        state.domains.push("fabrikam.local".into());
        state
            .credentials
            .push(make_credential("foreigner", "P@ss!", "fabrikam.local")); // pragma: allowlist secret
        let work = collect_adcs_work(&state);
        assert!(
            work.is_empty(),
            "should not dispatch ADCS enum with cross-forest cred"
        );
    }

    #[test]
    fn collect_uses_child_domain_cred_for_parent_ca() {
        // child cred → parent CA: same forest, LDAP bind succeeds.
        let mut state = StateInner::new("test-op".into());
        state.shares.push(make_share("192.168.58.50", "CertEnroll"));
        state
            .hosts
            .push(make_host("192.168.58.50", "ca01.contoso.local", false));
        state.domains.push("contoso.local".into());
        state.domains.push("dev.contoso.local".into());
        state
            .credentials
            .push(make_credential("childuser", "P@ss!", "dev.contoso.local")); // pragma: allowlist secret
        let work = collect_adcs_work(&state);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].credential.username, "childuser");
    }

    #[test]
    fn collect_quarantined_same_domain_does_not_fall_back_cross_forest() {
        let mut state = StateInner::new("test-op".into());
        state.shares.push(make_share("192.168.58.50", "CertEnroll"));
        state
            .hosts
            .push(make_host("192.168.58.50", "ca01.contoso.local", false));
        state.domains.push("contoso.local".into());
        state.domains.push("fabrikam.local".into());
        state
            .credentials
            .push(make_credential("baduser", "P@ssw0rd!", "contoso.local")); // pragma: allowlist secret
        state
            .credentials
            .push(make_credential("gooduser", "Pass!456", "fabrikam.local")); // pragma: allowlist secret
        state.quarantine_principal("baduser", "contoso.local");
        let work = collect_adcs_work(&state);
        assert!(
            work.is_empty(),
            "cross-forest LDAP bind fails 52e — must not dispatch with fabrikam cred"
        );
    }

    #[test]
    fn collect_quarantined_same_domain_falls_back_to_sibling_in_same_forest() {
        let mut state = StateInner::new("test-op".into());
        state.shares.push(make_share("192.168.58.50", "CertEnroll"));
        state
            .hosts
            .push(make_host("192.168.58.50", "ca01.contoso.local", false));
        state.domains.push("contoso.local".into());
        state.domains.push("dev.contoso.local".into());
        state
            .credentials
            .push(make_credential("baduser", "P@ssw0rd!", "contoso.local")); // pragma: allowlist secret
        state
            .credentials
            .push(make_credential("gooduser", "Pass!456", "dev.contoso.local")); // pragma: allowlist secret
        state.quarantine_principal("baduser", "contoso.local");
        let work = collect_adcs_work(&state);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].credential.username, "gooduser");
    }

    #[test]
    fn extract_domain_from_fqdn_typical() {
        assert_eq!(
            extract_domain_from_fqdn("srv01.fabrikam.local"),
            Some("fabrikam.local".to_string())
        );
    }

    #[test]
    fn extract_domain_from_fqdn_nested() {
        assert_eq!(
            extract_domain_from_fqdn("host.child.contoso.local"),
            Some("child.contoso.local".to_string())
        );
    }

    #[test]
    fn extract_domain_from_fqdn_case_insensitive() {
        assert_eq!(
            extract_domain_from_fqdn("DC01.CONTOSO.LOCAL"),
            Some("contoso.local".to_string())
        );
    }

    #[test]
    fn extract_domain_from_fqdn_bare_hostname() {
        assert_eq!(extract_domain_from_fqdn("dc01"), None);
    }

    #[test]
    fn extract_domain_from_fqdn_empty() {
        assert_eq!(extract_domain_from_fqdn(""), None);
    }

    #[test]
    fn extract_domain_from_fqdn_trailing_dot() {
        // "host." splits into ("host", "") -> Some("")
        assert_eq!(extract_domain_from_fqdn("host."), Some("".to_string()));
    }

    #[test]
    fn dedup_set_name() {
        assert_eq!(DEDUP_ADCS_SERVERS, "adcs_servers");
    }

    #[test]
    fn certenroll_share_name_match() {
        let share_name = "CertEnroll";
        assert_eq!(share_name.to_lowercase(), "certenroll");
    }

    #[test]
    fn certenroll_case_insensitive() {
        let names = vec!["CertEnroll", "certenroll", "CERTENROLL"];
        for name in names {
            assert_eq!(name.to_lowercase(), "certenroll");
        }
    }

    #[test]
    fn domain_resolution_from_fqdn() {
        // Verifies domain extraction works for typical ADCS hosts
        assert_eq!(
            extract_domain_from_fqdn("ca01.contoso.local"),
            Some("contoso.local".to_string())
        );
        assert_eq!(
            extract_domain_from_fqdn("ca01.fabrikam.local"),
            Some("fabrikam.local".to_string())
        );
    }

    #[test]
    fn credential_selection_prefers_same_domain() {
        let creds = [
            ares_core::models::Credential {
                id: "c1".into(),
                username: "admin".into(),
                password: "P@ssw0rd!".into(), // pragma: allowlist secret
                domain: "contoso.local".into(),
                source: "test".into(),
                is_admin: false,
                discovered_at: None,
                parent_id: None,
                attack_step: 0,
            },
            ares_core::models::Credential {
                id: "c2".into(),
                username: "admin2".into(),
                password: "P@ssw0rd!".into(), // pragma: allowlist secret
                domain: "fabrikam.local".into(),
                source: "test".into(),
                is_admin: false,
                discovered_at: None,
                parent_id: None,
                attack_step: 0,
            },
        ];
        let target_domain = "fabrikam.local";
        let selected = creds.iter().find(|c| {
            !c.password.is_empty() && c.domain.to_lowercase() == target_domain.to_lowercase()
        });
        assert!(selected.is_some());
        assert_eq!(selected.unwrap().domain, "fabrikam.local");
    }
}
