//! auto_stall_detection -- detect when the operation is stuck and take action.
//!
//! When no new credentials or hashes have been discovered for a configurable
//! period (default: 5 minutes), this automation triggers fallback actions:
//!
//!   1. Re-attempt password spray with discovered users
//!   2. Start responder + NTLM relay if not already running
//!   3. Re-run LDAP description search with all known creds
//!
//! This prevents the operation from idling when all easy wins are exhausted.

use std::sync::Arc;
use std::time::{Duration, Instant};

use serde_json::json;
use tokio::sync::watch;
use tracing::{info, warn};

use crate::orchestrator::dispatcher::Dispatcher;
use crate::orchestrator::state::*;

/// Collect the set of lowercased domains that have at least one pending
/// (un-exploited) constrained-delegation or RBCD vuln. The stall-recovery
/// password spray uses this set to skip domains where a spray would lock
/// out delegation accounts before S4U gets to use them.
pub(crate) fn domains_with_pending_delegation(
    state: &StateInner,
) -> std::collections::HashSet<String> {
    state
        .discovered_vulnerabilities
        .values()
        .filter(|v| {
            let vt = v.vuln_type.to_lowercase();
            (vt == "constrained_delegation" || vt == "rbcd")
                && !state.exploited_vulnerabilities.contains(&v.vuln_id)
        })
        .filter_map(|v| {
            v.details
                .get("domain")
                .or_else(|| v.details.get("Domain"))
                .and_then(|d| d.as_str())
                .map(|d| d.to_lowercase())
        })
        .collect()
}

/// Build the stall-recovery spray dedup key. The `recovery_attempts` counter
/// is embedded so each round emits a fresh, distinct key — otherwise a single
/// stall would only ever trigger one spray dispatch.
pub(crate) fn stall_spray_dedup_key(domain: &str, recovery_attempts: u32) -> String {
    format!("stall_spray:{}:{recovery_attempts}", domain.to_lowercase())
}

/// Build the stall-recovery low-hanging-fruit dedup key.
pub(crate) fn stall_lhf_dedup_key(domain: &str, username: &str, recovery_attempts: u32) -> String {
    format!(
        "stall_lhf:{}:{}:{recovery_attempts}",
        domain.to_lowercase(),
        username.to_lowercase()
    )
}

/// Resolve a DC IP for stall-recovery LHF dispatch.
///
/// Tries exact match in `domain_controllers` first, then any child-domain
/// DC (`d.ends_with(".{cred_domain}")`). Returns `None` when no DC for
/// this cred's forest is known yet.
pub(crate) fn resolve_stall_dc_ip(state: &StateInner, cred_domain: &str) -> Option<String> {
    let cred_domain = cred_domain.to_lowercase();
    state
        .domain_controllers
        .get(&cred_domain)
        .cloned()
        .or_else(|| {
            let suffix = format!(".{cred_domain}");
            state
                .domain_controllers
                .iter()
                .find(|(d, _)| d.ends_with(&suffix))
                .map(|(_, ip)| ip.clone())
        })
}

/// Select stall-recovery password-spray work items for this tick.
///
/// Returns `(domain, dc_ip)` for each known DC whose domain has no pending
/// delegation vulns AND whose round-specific dedup key
/// (`stall_spray:{domain}:{recovery_attempts}`) is unprocessed.
pub(crate) fn select_stall_spray_work(
    state: &StateInner,
    recovery_attempts: u32,
) -> Vec<(String, String)> {
    let delegation_domains = domains_with_pending_delegation(state);
    state
        .domain_controllers
        .iter()
        .filter(|(domain, _)| !delegation_domains.contains(&domain.to_lowercase()))
        .filter(|(domain, _)| {
            let key = stall_spray_dedup_key(domain, recovery_attempts);
            !state.is_processed(DEDUP_PASSWORD_SPRAY, &key)
        })
        .map(|(domain, dc_ip)| (domain.clone(), dc_ip.clone()))
        .collect()
}

/// Select stall-recovery low-hanging-fruit work items, capped at `max_items`.
pub(crate) fn select_stall_lhf_work(
    state: &StateInner,
    recovery_attempts: u32,
    max_items: usize,
) -> Vec<(String, String, String, ares_core::models::Credential)> {
    state
        .credentials
        .iter()
        .filter(|c| !c.domain.is_empty() && !c.password.is_empty())
        .filter_map(|cred| {
            let cred_domain = cred.domain.to_lowercase();
            let key = stall_lhf_dedup_key(&cred_domain, &cred.username, recovery_attempts);
            if state.is_processed(DEDUP_EXPANSION_CREDS, &key) {
                return None;
            }
            let dc_ip = resolve_stall_dc_ip(state, &cred_domain)?;
            Some((key, dc_ip, cred_domain, cred.clone()))
        })
        .take(max_items)
        .collect()
}

/// How long without new discoveries before we consider the op stalled.
const STALL_THRESHOLD: Duration = Duration::from_secs(180); // 3 minutes

/// Minimum interval between stall recovery actions.
const RECOVERY_COOLDOWN: Duration = Duration::from_secs(120); // 2 minutes

/// Monitors for discovery stalls and triggers fallback actions.
/// Interval: 60s.
pub async fn auto_stall_detection(
    dispatcher: Arc<Dispatcher>,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut interval = tokio::time::interval(Duration::from_secs(60));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    let start = Instant::now();
    let mut last_cred_count = 0usize;
    let mut last_hash_count = 0usize;
    let mut last_change = Instant::now();
    let mut last_recovery = Instant::now() - RECOVERY_COOLDOWN; // allow immediate first recovery
    let mut recovery_attempts = 0u32;

    loop {
        tokio::select! {
            _ = interval.tick() => {},
            _ = shutdown.changed() => break,
        }
        if *shutdown.borrow() {
            break;
        }

        // Don't check stall in the first 3 minutes (let initial recon complete)
        if start.elapsed() < Duration::from_secs(180) {
            continue;
        }

        let (cred_count, hash_count, has_da, has_creds, has_users, has_dcs) = {
            let state = dispatcher.state.read().await;
            (
                state.credentials.len(),
                state.hashes.len(),
                state.has_domain_admin,
                !state.credentials.is_empty(),
                !state.users.is_empty(),
                !state.domain_controllers.is_empty(),
            )
        };

        // Skip only when ALL forests are dominated — stall recovery must
        // keep firing if undominated forests remain after initial DA.
        // In comprehensive mode, never skip — keep discovering.
        if has_da && !dispatcher.config.strategy.should_continue_after_da() {
            let state = dispatcher.state.read().await;
            if state.all_forests_dominated() {
                continue;
            }
        }

        // Check if there has been progress
        if cred_count > last_cred_count || hash_count > last_hash_count {
            last_cred_count = cred_count;
            last_hash_count = hash_count;
            last_change = Instant::now();
            recovery_attempts = 0; // Reset on progress
            continue;
        }

        // Not stalled yet
        if last_change.elapsed() < STALL_THRESHOLD {
            continue;
        }

        // Cooldown between recovery actions
        if last_recovery.elapsed() < RECOVERY_COOLDOWN {
            continue;
        }

        // Cap recovery attempts (don't spam indefinitely)
        if recovery_attempts >= 10 {
            continue;
        }

        info!(
            stall_duration_secs = last_change.elapsed().as_secs(),
            cred_count,
            hash_count,
            recovery_attempt = recovery_attempts + 1,
            "Operation stall detected — triggering fallback actions"
        );

        last_recovery = Instant::now();
        recovery_attempts += 1;

        // Skip domains with pending delegation vulns — sprays lock delegation
        // accounts and prevent S4U exploitation from succeeding.
        // Also respect strategy gate — don't spray when excluded.
        if has_users && has_dcs && dispatcher.is_technique_allowed("password_spray") {
            let spray_work: Vec<(String, String)> = {
                let state = dispatcher.state.read().await;
                select_stall_spray_work(&state, recovery_attempts)
            };

            for (domain, dc_ip) in spray_work {
                let payload = json!({
                    "technique": "password_spray",
                    "target_ip": dc_ip,
                    "domain": domain,
                    "use_common_passwords": true,
                    "acknowledge_no_policy": true,
                });

                match dispatcher
                    .throttled_submit("credential_access", "credential_access", payload, 7)
                    .await
                {
                    Ok(Some(task_id)) => {
                        info!(task_id = %task_id, domain = %domain, "Stall recovery: password spray dispatched");
                        let key = stall_spray_dedup_key(&domain, recovery_attempts);
                        dispatcher
                            .state
                            .write()
                            .await
                            .mark_processed(DEDUP_PASSWORD_SPRAY, key.clone());
                        let _ = dispatcher
                            .state
                            .persist_dedup(&dispatcher.queue, DEDUP_PASSWORD_SPRAY, &key)
                            .await;
                    }
                    Ok(None) => {}
                    Err(e) => warn!(err = %e, "Stall recovery: spray failed"),
                }
            }
        }

        if has_creds && has_dcs {
            let lhf_work: Vec<(String, String, String, ares_core::models::Credential)> = {
                let state = dispatcher.state.read().await;
                select_stall_lhf_work(&state, recovery_attempts, 2)
            };

            for (key, dc_ip, domain, cred) in lhf_work {
                match dispatcher
                    .request_low_hanging_fruit(&dc_ip, &domain, &cred, 6)
                    .await
                {
                    Ok(Some(task_id)) => {
                        info!(task_id = %task_id, domain = %domain, "Stall recovery: low-hanging fruit dispatched");
                        dispatcher
                            .state
                            .write()
                            .await
                            .mark_processed(DEDUP_EXPANSION_CREDS, key.clone());
                        let _ = dispatcher
                            .state
                            .persist_dedup(&dispatcher.queue, DEDUP_EXPANSION_CREDS, &key)
                            .await;
                    }
                    Ok(None) => {}
                    Err(e) => warn!(err = %e, "Stall recovery: low-hanging fruit failed"),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    fn make_vuln_with_domain(
        vuln_id: &str,
        vuln_type: &str,
        domain: &str,
    ) -> ares_core::models::VulnerabilityInfo {
        let mut details = std::collections::HashMap::new();
        details.insert("domain".into(), serde_json::json!(domain));
        ares_core::models::VulnerabilityInfo {
            vuln_id: vuln_id.to_string(),
            vuln_type: vuln_type.to_string(),
            target: "192.168.58.10".to_string(),
            discovered_by: "test".into(),
            discovered_at: chrono::Utc::now(),
            details,
            recommended_agent: String::new(),
            priority: 1,
        }
    }

    #[test]
    fn stall_spray_dedup_key_includes_recovery_attempt() {
        assert_eq!(
            stall_spray_dedup_key("contoso.local", 3),
            "stall_spray:contoso.local:3"
        );
    }

    #[test]
    fn stall_spray_dedup_key_lowercases_domain() {
        assert_eq!(
            stall_spray_dedup_key("Contoso.Local", 0),
            "stall_spray:contoso.local:0"
        );
    }

    #[test]
    fn stall_lhf_dedup_key_combines_domain_user_attempt() {
        assert_eq!(
            stall_lhf_dedup_key("contoso.local", "Administrator", 1),
            "stall_lhf:contoso.local:administrator:1"
        );
    }

    #[test]
    fn pending_delegation_empty_state() {
        let s = StateInner::new("op".into());
        assert!(domains_with_pending_delegation(&s).is_empty());
    }

    #[test]
    fn pending_delegation_collects_constrained_delegation_vulns() {
        let mut s = StateInner::new("op".into());
        let v = make_vuln_with_domain("v1", "constrained_delegation", "contoso.local");
        s.discovered_vulnerabilities.insert(v.vuln_id.clone(), v);
        let set = domains_with_pending_delegation(&s);
        assert!(set.contains("contoso.local"));
    }

    #[test]
    fn pending_delegation_collects_rbcd_vulns() {
        let mut s = StateInner::new("op".into());
        let v = make_vuln_with_domain("v1", "rbcd", "fabrikam.local");
        s.discovered_vulnerabilities.insert(v.vuln_id.clone(), v);
        let set = domains_with_pending_delegation(&s);
        assert!(set.contains("fabrikam.local"));
    }

    #[test]
    fn pending_delegation_skips_exploited_vulns() {
        let mut s = StateInner::new("op".into());
        let v = make_vuln_with_domain("v1", "constrained_delegation", "contoso.local");
        s.discovered_vulnerabilities.insert(v.vuln_id.clone(), v);
        s.exploited_vulnerabilities.insert("v1".into());
        assert!(domains_with_pending_delegation(&s).is_empty());
    }

    #[test]
    fn pending_delegation_skips_non_delegation_types() {
        let mut s = StateInner::new("op".into());
        let v = make_vuln_with_domain("v1", "kerberoastable_account", "contoso.local");
        s.discovered_vulnerabilities.insert(v.vuln_id.clone(), v);
        assert!(domains_with_pending_delegation(&s).is_empty());
    }

    #[test]
    fn pending_delegation_picks_up_capitalized_domain_key_alias() {
        let mut s = StateInner::new("op".into());
        let mut details = std::collections::HashMap::new();
        details.insert("Domain".into(), serde_json::json!("contoso.local"));
        let v = ares_core::models::VulnerabilityInfo {
            vuln_id: "v1".into(),
            vuln_type: "rbcd".into(),
            target: "x".into(),
            discovered_by: "test".into(),
            discovered_at: chrono::Utc::now(),
            details,
            recommended_agent: String::new(),
            priority: 1,
        };
        s.discovered_vulnerabilities.insert(v.vuln_id.clone(), v);
        assert!(domains_with_pending_delegation(&s).contains("contoso.local"));
    }

    #[test]
    fn resolve_stall_dc_ip_exact_match() {
        let mut s = StateInner::new("op".into());
        s.domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        assert_eq!(
            resolve_stall_dc_ip(&s, "contoso.local").as_deref(),
            Some("192.168.58.10")
        );
    }

    #[test]
    fn resolve_stall_dc_ip_child_fallback() {
        let mut s = StateInner::new("op".into());
        s.domain_controllers
            .insert("child.contoso.local".into(), "192.168.58.11".into());
        assert_eq!(
            resolve_stall_dc_ip(&s, "contoso.local").as_deref(),
            Some("192.168.58.11")
        );
    }

    #[test]
    fn resolve_stall_dc_ip_returns_none_for_unrelated() {
        let mut s = StateInner::new("op".into());
        s.domain_controllers
            .insert("fabrikam.local".into(), "192.168.58.40".into());
        assert!(resolve_stall_dc_ip(&s, "contoso.local").is_none());
    }

    #[test]
    fn select_stall_spray_empty_state() {
        let s = StateInner::new("op".into());
        assert!(select_stall_spray_work(&s, 0).is_empty());
    }

    #[test]
    fn select_stall_spray_emits_known_dc() {
        let mut s = StateInner::new("op".into());
        s.domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        let work = select_stall_spray_work(&s, 1);
        assert_eq!(
            work,
            vec![("contoso.local".to_string(), "192.168.58.10".to_string())]
        );
    }

    #[test]
    fn select_stall_spray_skips_delegation_domains() {
        let mut s = StateInner::new("op".into());
        s.domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        let v = make_vuln_with_domain("v1", "constrained_delegation", "contoso.local");
        s.discovered_vulnerabilities.insert(v.vuln_id.clone(), v);
        assert!(select_stall_spray_work(&s, 1).is_empty());
    }

    #[test]
    fn select_stall_spray_skips_already_processed_for_this_round() {
        let mut s = StateInner::new("op".into());
        s.domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        s.mark_processed(
            DEDUP_PASSWORD_SPRAY,
            stall_spray_dedup_key("contoso.local", 0),
        );
        // Same recovery_attempt → skipped.
        assert!(select_stall_spray_work(&s, 0).is_empty());
        // Different recovery_attempt → re-emitted (fresh round).
        assert_eq!(select_stall_spray_work(&s, 1).len(), 1);
    }

    #[test]
    fn select_stall_lhf_empty_state() {
        let s = StateInner::new("op".into());
        assert!(select_stall_lhf_work(&s, 0, 2).is_empty());
    }

    #[test]
    fn select_stall_lhf_emits_when_cred_dc_match() {
        let mut s = StateInner::new("op".into());
        s.credentials
            .push(make_cred("alice", "Pw", "contoso.local"));
        s.domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        let work = select_stall_lhf_work(&s, 0, 5);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].3.username, "alice");
        assert_eq!(work[0].1, "192.168.58.10");
    }

    #[test]
    fn select_stall_lhf_skips_empty_credential_fields() {
        let mut s = StateInner::new("op".into());
        s.credentials.push(make_cred("alice", "", "contoso.local"));
        s.credentials.push(make_cred("bob", "Pw", ""));
        s.domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        assert!(select_stall_lhf_work(&s, 0, 5).is_empty());
    }

    #[test]
    fn select_stall_lhf_caps_at_max_items() {
        let mut s = StateInner::new("op".into());
        s.domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        for u in &["alice", "bob", "carol", "dave"] {
            s.credentials.push(make_cred(u, "Pw", "contoso.local"));
        }
        assert_eq!(select_stall_lhf_work(&s, 0, 2).len(), 2);
        assert_eq!(select_stall_lhf_work(&s, 0, 10).len(), 4);
    }
}
