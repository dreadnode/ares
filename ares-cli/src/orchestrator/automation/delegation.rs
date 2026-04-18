//! auto_delegation_enumeration -- find delegation for new creds.
//!
//! Dispatches `find_delegation` as a **direct tool call** (no LLM in the loop).
//! Previous versions submitted an LLM task, but the agent often used LDAP
//! queries + `report_finding` instead of calling the tool — so the parser
//! never fired and vulnerabilities never reached `discovered_vulnerabilities`.

use std::sync::Arc;
use std::time::Duration;

use serde_json::json;
use tokio::sync::watch;
use tracing::{info, warn};

use ares_llm::ToolCall;

use crate::orchestrator::dispatcher::Dispatcher;
use crate::orchestrator::state::*;

/// Dispatches delegation enumeration for new credentials.
/// Interval: 30s. Matches Python `_auto_delegation_enumeration`.
pub async fn auto_delegation_enumeration(
    dispatcher: Arc<Dispatcher>,
    mut shutdown: watch::Receiver<bool>,
) {
    let notify = dispatcher.delegation_notify.clone();
    let mut interval = tokio::time::interval(Duration::from_secs(30));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            _ = interval.tick() => {},
            _ = notify.notified() => {},
            _ = shutdown.changed() => break,
        }
        if *shutdown.borrow() {
            break;
        }

        let work: Vec<(String, String, String, ares_core::models::Credential)> = {
            let state = dispatcher.state.read().await;
            state
                .credentials
                .iter()
                // Skip delegation accounts — delegation enum is already done
                // with other creds, and using a delegation account's cred
                // burns auth budget reserved for S4U.
                .filter(|c| !state.is_delegation_account(&c.username))
                .filter(|c| !state.is_credential_quarantined(&c.username, &c.domain))
                .filter_map(|cred| {
                    if cred.domain.is_empty() {
                        return None;
                    }
                    let cred_domain = cred.domain.to_lowercase();
                    let dedup = format!("{}:{}", cred_domain, cred.username.to_lowercase());
                    if state.is_processed(DEDUP_DELEGATION_CREDS, &dedup) {
                        return None;
                    }
                    // Exact match first
                    let dc_ip = state
                        .domain_controllers
                        .get(&cred_domain)
                        .cloned()
                        .or_else(|| {
                            // Child-domain fallback: cred domain is parent,
                            // DC is registered under child (e.g. cred=contoso.local,
                            // DC=child.contoso.local)
                            let suffix = format!(".{cred_domain}");
                            state
                                .domain_controllers
                                .iter()
                                .find(|(d, _)| d.ends_with(&suffix))
                                .map(|(_, ip)| ip.clone())
                        })
                        .or_else(|| {
                            // Parent-domain fallback: cred domain is child,
                            // DC is registered under parent
                            state
                                .domain_controllers
                                .iter()
                                .find(|(d, _)| cred_domain.ends_with(&format!(".{d}")))
                                .map(|(_, ip)| ip.clone())
                        })?;
                    Some((dedup, cred.domain.clone(), dc_ip, cred.clone()))
                })
                .collect()
        };

        for (dedup_key, domain, dc_ip, cred) in work {
            // Dispatch find_delegation as a DIRECT tool call so the parser
            // always fires and vulnerabilities get registered in state.
            let tool_args = json!({
                "dc_ip": dc_ip,
                "domain": domain,
                "username": cred.username,
                "password": cred.password,
            });
            let call = ToolCall {
                id: format!("deleg_{}", uuid::Uuid::new_v4().simple()),
                name: "find_delegation".to_string(),
                arguments: tool_args,
            };
            let task_id = format!("delegation_enum_{}", uuid::Uuid::new_v4().simple());

            match dispatcher
                .llm_runner
                .tool_dispatcher()
                .dispatch_tool("privesc", &task_id, &call)
                .await
            {
                Ok(result) => {
                    info!(
                        domain = %domain,
                        dc_ip = %dc_ip,
                        has_discoveries = result.discoveries.is_some(),
                        "Direct find_delegation completed"
                    );
                    // Discoveries are already pushed to the real-time discovery
                    // list by the tool dispatcher — the poller will publish them
                    // to state including any constrained_delegation vulns.
                    if let Some(ref disc) = result.discoveries {
                        if let Some(vulns) = disc.get("vulnerabilities").and_then(|v| v.as_array())
                        {
                            info!(
                                count = vulns.len(),
                                domain = %domain,
                                "Delegation vulnerabilities discovered"
                            );
                        }
                    }
                    dispatcher
                        .state
                        .write()
                        .await
                        .mark_processed(DEDUP_DELEGATION_CREDS, dedup_key.clone());
                    let _ = dispatcher
                        .state
                        .persist_dedup(&dispatcher.queue, DEDUP_DELEGATION_CREDS, &dedup_key)
                        .await;
                }
                Err(e) => {
                    warn!(err = %e, domain = %domain, "Direct find_delegation failed");
                    // Still mark as processed to avoid retry storms on auth errors
                    if e.to_string().contains("Invalid Credentials")
                        || e.to_string().contains("LOGON_FAILURE")
                    {
                        dispatcher
                            .state
                            .write()
                            .await
                            .mark_processed(DEDUP_DELEGATION_CREDS, dedup_key.clone());
                        let _ = dispatcher
                            .state
                            .persist_dedup(&dispatcher.queue, DEDUP_DELEGATION_CREDS, &dedup_key)
                            .await;
                    }
                }
            }
        }
    }
}
