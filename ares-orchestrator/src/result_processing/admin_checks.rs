//! Domain admin indicator checks, golden ticket detection, Pwn3d! credential
//! upgrades, and domain SID extraction.

use std::sync::Arc;

use serde_json::Value;
use tracing::{info, warn};

use super::parsing::has_domain_admin_indicator;
use crate::dispatcher::Dispatcher;

/// Check result for domain admin indicators and update state.
pub(crate) async fn check_domain_admin_indicators(payload: &Value, dispatcher: &Arc<Dispatcher>) {
    if !has_domain_admin_indicator(payload) {
        return;
    }
    let already_da = {
        let state = dispatcher.state.read().await;
        state.has_domain_admin
    };
    let path = if payload.get("has_domain_admin").and_then(|v| v.as_bool()) == Some(true) {
        payload
            .get("domain_admin_path")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
    } else {
        Some("secretsdump -> krbtgt hash".to_string())
    };
    if let Err(e) = dispatcher
        .state
        .set_domain_admin(&dispatcher.queue, path.clone())
        .await
    {
        warn!(err = %e, "Failed to set domain admin flag");
    } else {
        info!("Domain Admin achieved!");
    }
    if !already_da {
        let (domain, dc_target) = {
            let state = dispatcher.state.read().await;
            let domain = state.domains.first().cloned().unwrap_or_default();
            let dc = state
                .domain_controllers
                .get(&domain.to_lowercase())
                .cloned()
                .unwrap_or_else(|| domain.clone());
            (domain, dc)
        };
        if !domain.is_empty() {
            let vuln_id = format!("domain_admin_{}", domain.to_lowercase());
            let mut details = std::collections::HashMap::new();
            details.insert("domain".into(), serde_json::Value::String(domain.clone()));
            if let Some(ref p) = path {
                details.insert("path".into(), serde_json::Value::String(p.clone()));
            }
            details.insert(
                "note".into(),
                serde_json::Value::String(
                    "Domain admin achieved via agent-reported indicator".to_string(),
                ),
            );
            let vuln = ares_core::models::VulnerabilityInfo {
                vuln_id: vuln_id.clone(),
                vuln_type: "domain_admin".to_string(),
                target: dc_target,
                discovered_by: "result_processing".to_string(),
                discovered_at: chrono::Utc::now(),
                details,
                recommended_agent: String::new(),
                priority: 1,
            };
            let _ = dispatcher
                .state
                .publish_vulnerability(&dispatcher.queue, vuln)
                .await;
            let _ = dispatcher
                .state
                .mark_exploited(&dispatcher.queue, &vuln_id)
                .await;
        }
    }
}

pub(crate) async fn check_golden_ticket_completion(
    payload: &Value,
    task_id: &str,
    dispatcher: &Arc<Dispatcher>,
) {
    if !task_id.contains("exploit") && !task_id.contains("golden") {
        return;
    }
    {
        let state = dispatcher.state.read().await;
        if state.has_golden_ticket {
            return;
        }
    }
    let mut found_ticket = false;
    let mut domain = String::new();
    if let Some(arr) = payload.get("tool_outputs").and_then(|v| v.as_array()) {
        for item in arr {
            let text = item
                .as_str()
                .or_else(|| item.get("output").and_then(|v| v.as_str()))
                .unwrap_or("");
            if text.contains("Saving ticket in") && text.contains(".ccache") {
                found_ticket = true;
                break;
            }
        }
    }
    if !found_ticket {
        for key in &["tool_output", "output", "summary"] {
            if let Some(text) = payload.get(*key).and_then(|v| v.as_str()) {
                if text.contains("Saving ticket in") && text.contains(".ccache") {
                    found_ticket = true;
                    break;
                }
            }
        }
    }
    if !found_ticket && payload.get("has_golden_ticket").and_then(|v| v.as_bool()) == Some(true) {
        found_ticket = true;
    }
    if !found_ticket {
        return;
    }
    if let Some(d) = payload.get("domain").and_then(|v| v.as_str()) {
        domain = d.to_string();
    }
    if domain.is_empty() {
        let state = dispatcher.state.read().await;
        domain = state.domains.first().cloned().unwrap_or_default();
    }
    if let Err(e) = dispatcher
        .state
        .set_golden_ticket(&dispatcher.queue, &domain)
        .await
    {
        warn!(err = %e, "Failed to set golden ticket flag");
    }
}

pub(crate) async fn detect_and_upgrade_admin_credentials(text: &str, dispatcher: &Arc<Dispatcher>) {
    for line in text.lines() {
        if !line.contains("Pwn3d!") || !line.contains("[+]") {
            continue;
        }
        if let Some(after_plus) = line.split("[+]").nth(1) {
            let after_plus = after_plus.trim();
            if let Some(backslash) = after_plus.find('\\') {
                let domain_part = after_plus[..backslash].trim();
                let rest = &after_plus[backslash + 1..];
                let username = if let Some(colon) = rest.find(':') {
                    &rest[..colon]
                } else {
                    rest.split_whitespace().next().unwrap_or("")
                };
                let username = username.trim();
                let domain = domain_part.to_lowercase();
                if username.is_empty() || domain.is_empty() {
                    continue;
                }
                info!(username = %username, domain = %domain, "Pwn3d! detected -- upgrading credential to admin");
                let upgraded = {
                    let mut state = dispatcher.state.write().await;
                    let mut found = false;
                    for cred in state.credentials.iter_mut() {
                        if cred.username.to_lowercase() == username.to_lowercase()
                            && cred.domain.to_lowercase() == domain
                            && !cred.is_admin
                        {
                            cred.is_admin = true;
                            found = true;
                        }
                    }
                    found
                };
                if upgraded {
                    let pwned_ip = line
                        .split_whitespace()
                        .find(|w| {
                            w.split('.').count() == 4
                                && w.split('.').all(|o| o.parse::<u8>().is_ok())
                        })
                        .map(|s| s.to_string());
                    info!(
                        username = %username,
                        domain = %domain,
                        pwned_host = ?pwned_ip,
                        "Credential upgraded to admin -- dispatching priority secretsdump"
                    );
                    let work: Vec<(String, ares_core::models::Credential)> = {
                        let state = dispatcher.state.read().await;
                        let dc_ips: Vec<String> =
                            state.domain_controllers.values().cloned().collect();
                        let mut targets: Vec<String> = dc_ips;
                        if let Some(ref ip) = pwned_ip {
                            if !targets.contains(ip) {
                                targets.push(ip.clone());
                            }
                        }
                        state
                            .credentials
                            .iter()
                            .filter(|c| {
                                c.username.to_lowercase() == username.to_lowercase()
                                    && c.domain.to_lowercase() == domain
                                    && c.is_admin
                            })
                            .flat_map(|cred| {
                                targets
                                    .iter()
                                    .map(|ip| (ip.clone(), cred.clone()))
                                    .collect::<Vec<_>>()
                            })
                            .collect()
                    };
                    for (target_ip, cred) in work {
                        match dispatcher.request_secretsdump(&target_ip, &cred, 1).await {
                            Ok(Some(task_id)) => {
                                info!(
                                    task_id = %task_id,
                                    target = %target_ip,
                                    username = %username,
                                    "Admin Pwn3d! secretsdump dispatched (priority 1)"
                                );
                            }
                            Ok(None) => {}
                            Err(e) => warn!(err = %e, "Failed to dispatch Pwn3d! secretsdump"),
                        }
                    }
                }
            }
        }
    }
}

pub(crate) async fn extract_and_cache_domain_sid(payload: &Value, dispatcher: &Arc<Dispatcher>) {
    let mut text_parts: Vec<&str> = Vec::new();
    for key in &["tool_output", "output"] {
        if let Some(s) = payload.get(*key).and_then(|v| v.as_str()) {
            text_parts.push(s);
        }
    }
    if let Some(arr) = payload.get("tool_outputs").and_then(|v| v.as_array()) {
        for item in arr {
            if let Some(s) = item.as_str() {
                text_parts.push(s);
            } else if let Some(s) = item.get("output").and_then(|v| v.as_str()) {
                text_parts.push(s);
            }
        }
    }
    if text_parts.is_empty() {
        return;
    }
    let combined = text_parts.join("\n");
    if let Some(sid) = ares_core::parsing::extract_domain_sid(&combined) {
        let domain = payload
            .get("domain")
            .and_then(|v| v.as_str())
            .map(|d| d.to_lowercase())
            .filter(|d| !d.is_empty());
        let domain = match domain {
            Some(d) => d,
            None => {
                let state = dispatcher.state.read().await;
                match state.domains.first() {
                    Some(d) => d.to_lowercase(),
                    None => return,
                }
            }
        };
        let already_cached = {
            let state = dispatcher.state.read().await;
            state
                .domain_sids
                .get(&domain)
                .map(|s| s == &sid)
                .unwrap_or(false)
        };
        if !already_cached {
            let op_id = {
                let state = dispatcher.state.read().await;
                state.operation_id.clone()
            };
            let reader = ares_core::state::RedisStateReader::new(op_id);
            let mut conn = dispatcher.queue.connection();
            if let Err(e) = reader.set_domain_sid(&mut conn, &domain, &sid).await {
                warn!(err = %e, domain = %domain, "Failed to persist domain SID to Redis");
            } else {
                info!(domain = %domain, sid = %sid, "Domain SID cached from task output");
                dispatcher
                    .state
                    .write()
                    .await
                    .domain_sids
                    .insert(domain.clone(), sid);
            }
        }
        if let Some(admin_name) = ares_core::parsing::extract_rid500_name(&combined) {
            let already_known = {
                let state = dispatcher.state.read().await;
                state.admin_names.contains_key(&domain)
            };
            if !already_known {
                let op_id = {
                    let state = dispatcher.state.read().await;
                    state.operation_id.clone()
                };
                let reader = ares_core::state::RedisStateReader::new(op_id);
                let mut conn = dispatcher.queue.connection();
                if let Err(e) = reader.set_admin_name(&mut conn, &domain, &admin_name).await {
                    warn!(err = %e, domain = %domain, "Failed to persist admin name to Redis");
                } else {
                    info!(domain = %domain, name = %admin_name, "RID-500 account name cached from task output");
                    dispatcher
                        .state
                        .write()
                        .await
                        .admin_names
                        .insert(domain, admin_name);
                }
            }
        }
    }
}
