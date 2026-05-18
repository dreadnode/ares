//! Domain admin indicator checks, golden ticket detection, Pwn3d! credential
//! upgrades, and domain SID extraction.

use std::sync::Arc;

use serde_json::Value;
use tracing::{info, warn};

use super::parsing::has_domain_admin_indicator;
use super::timeline::{create_admin_upgrade_timeline_event, create_domain_admin_timeline_event};
use crate::orchestrator::dispatcher::Dispatcher;
use crate::orchestrator::state::StateInner;

/// Resolve a NetBIOS/flat domain name (e.g. `FABRIKAM`) to a known FQDN.
///
/// Checks three sources, in order:
/// 1. `state.trusted_domains`: each `TrustInfo` carries an explicit `flat_name`.
/// 2. `state.netbios_to_fqdn`: published mappings from host short names; useful
///    when the flat name happens to match a hostname mapping.
/// 3. `state.domains`: derive each FQDN's first label and compare. Catches the
///    primary domain (which is rarely in `trusted_domains`).
///
/// Returns `None` when the flat name does not correspond to any known domain.
/// Callers must treat that as "skip caching" — guessing risks attributing the
/// SID to the wrong domain.
fn resolve_flat_to_fqdn(flat: &str, state: &StateInner) -> Option<String> {
    let target = flat.to_uppercase();

    if let Some(t) = state
        .trusted_domains
        .values()
        .find(|t| !t.flat_name.is_empty() && t.flat_name.to_uppercase() == target)
    {
        return Some(t.domain.to_lowercase());
    }

    if let Some(fqdn) = state
        .netbios_to_fqdn
        .get(&target)
        .or_else(|| state.netbios_to_fqdn.get(flat))
    {
        // Only accept the mapping if it looks like a domain FQDN, not a host
        // FQDN (e.g. "DC02" → "dc02.contoso.local" should NOT yield "dc02…").
        let lower = fqdn.to_lowercase();
        if is_valid_domain_fqdn(&lower) && state.domains.iter().any(|d| d.to_lowercase() == lower) {
            return Some(lower);
        }
    }

    state
        .domains
        .iter()
        .find(|d| {
            d.split('.')
                .next()
                .map(|first| first.eq_ignore_ascii_case(flat))
                .unwrap_or(false)
        })
        .map(|d| d.to_lowercase())
}

/// Validate that a string looks like a domain FQDN.
///
/// Rejects empty strings, IP-like patterns, strings with whitespace, and strings
/// without at least one dot. Used to filter out malformed domain values that
/// occasionally appear in tool payloads (e.g. `"192.168.58.30 - dc01"`).
fn is_valid_domain_fqdn(s: &str) -> bool {
    if s.is_empty() || s.contains(' ') || s.contains(':') || s.contains('/') {
        return false;
    }
    if !s.contains('.') {
        return false;
    }
    let first_label = s.split('.').next().unwrap_or("");
    if first_label.is_empty() || first_label.chars().all(|c| c.is_ascii_digit()) {
        return false;
    }
    s.chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_')
}

/// Determine the domain admin path from a payload.
pub(crate) fn resolve_da_path(_payload: &Value) -> Option<String> {
    Some("secretsdump -> krbtgt hash".to_string())
}

/// Check if text indicates a golden ticket was saved.
pub(crate) fn has_golden_ticket_indicator(text: &str) -> bool {
    text.contains("Saving ticket in") && text.contains(".ccache")
}

/// Parse a Pwn3d! line to extract (domain, username).
///
/// Format: `[+] DOMAIN\username:password (Pwn3d!)` or `[+] DOMAIN\username (Pwn3d!)`
pub(crate) fn parse_pwned_line(line: &str) -> Option<(String, String)> {
    if !line.contains("Pwn3d!") || !line.contains("[+]") {
        return None;
    }
    let after_plus = line.split("[+]").nth(1)?.trim();
    let backslash = after_plus.find('\\')?;
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
        return None;
    }
    Some((domain, username.to_string()))
}

/// Extract an IP address from a line of text.
pub(crate) fn extract_ip_from_line(line: &str) -> Option<String> {
    line.split_whitespace()
        .find(|w| w.split('.').count() == 4 && w.split('.').all(|o| o.parse::<u8>().is_ok()))
        .map(|s| s.to_string())
}

/// Aggregate every string `tool_output` / `output` / `tool_outputs[i]` field
/// in `payload` into a `Vec<String>`. `tool_outputs` accepts both bare-string
/// entries and objects with an `output` field.
///
/// Drives the SID extraction path so the same caller produces the same input
/// regardless of which output convention the tool used. Pure — no Redis, no
/// dispatcher.
pub(crate) fn collect_payload_text_parts(payload: &Value) -> Vec<String> {
    let mut parts: Vec<String> = Vec::new();
    if let Some(arr) = payload.get("tool_outputs").and_then(|v| v.as_array()) {
        for item in arr {
            if let Some(s) = item.as_str() {
                parts.push(s.to_string());
            } else if let Some(s) = item.get("output").and_then(|v| v.as_str()) {
                parts.push(s.to_string());
            }
        }
    }
    parts
}

/// Scan trusted tool-output text fields for a "golden ticket saved" marker.
///
/// Walks `tool_outputs` (string OR `{output: string}` form). Agent-completion
/// `summary` and `has_golden_ticket: true` are intentionally ignored.
pub(crate) fn payload_contains_golden_ticket_marker(payload: &Value) -> bool {
    collect_payload_text_parts(payload)
        .into_iter()
        .any(|text| has_golden_ticket_indicator(&text))
}

/// Extract a domain SID and (optional) flat name from already-collected text.
///
/// Returns `Some((sid, Some(flat)))` when the SID came from `rpcclient
/// lsaquery` output (which always carries the flat name).
/// Returns `Some((sid, None))` when the SID came from
/// `impacket-lookupsid`'s `Domain SID is: …` header (flat name lives in the
/// RID lines, callers extract it separately).
/// Returns `None` when neither path matches.
pub(crate) fn parse_sid_from_combined_text(combined: &str) -> Option<(String, Option<String>)> {
    let lookupsid_sid = ares_core::parsing::LOOKUPSID_HEADER_RE
        .captures(combined)
        .and_then(|c| c.get(1).map(|m| m.as_str().to_string()));
    let lsaquery_pair = ares_core::parsing::extract_lsaquery_domain_sid(combined);
    match (lookupsid_sid, lsaquery_pair) {
        (Some(s), _) => Some((s, None)),
        (None, Some((flat, s))) => Some((s, Some(flat))),
        (None, None) => None,
    }
}

/// Check result for domain admin indicators and update state.
pub(crate) async fn check_domain_admin_indicators(payload: &Value, dispatcher: &Arc<Dispatcher>) {
    if !has_domain_admin_indicator(payload) {
        return;
    }
    let already_da = {
        let state = dispatcher.state.read().await;
        state.has_domain_admin
    };
    let path = resolve_da_path(payload);
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
        // Emit Domain Admin timeline event
        let da_domain = {
            let state = dispatcher.state.read().await;
            state.domains.first().cloned().unwrap_or_default()
        };
        create_domain_admin_timeline_event(dispatcher, &da_domain, path.as_deref()).await;
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
    task_domain: Option<&str>,
    dispatcher: &Arc<Dispatcher>,
) {
    if !task_id.contains("exploit") && !task_id.contains("golden") {
        return;
    }
    // Per-domain dedup happens after we resolve `domain` below — a forge
    // for one domain must not block recording another (multi-domain ops
    // routinely capture krbtgt for parent + child or both forests).
    if !payload_contains_golden_ticket_marker(payload) {
        return;
    }
    let mut domain = String::new();
    if let Some(d) = task_domain.filter(|d| !d.is_empty()) {
        domain = d.to_string();
    } else if let Some(d) = payload.get("domain").and_then(|v| v.as_str()) {
        domain = d.to_string();
    }
    // Require a krbtgt hash to actually exist for the chosen domain before
    // marking GT — `Saving ticket in *.ccache` also appears in inter-realm
    // forge output where no target krbtgt was ever obtained, so without this
    // gate we'd publish a false-positive GT for the source/first domain.
    {
        let state = dispatcher.state.read().await;
        let has_krbtgt = |d: &str| -> bool {
            let lower = d.to_lowercase();
            state.hashes.iter().any(|h| {
                h.username.eq_ignore_ascii_case("krbtgt") && h.domain.to_lowercase() == lower
            })
        };
        if domain.is_empty() {
            domain = state
                .domains
                .iter()
                .find(|d| has_krbtgt(d))
                .cloned()
                .unwrap_or_default();
        } else if !has_krbtgt(&domain) {
            warn!(
                domain = %domain,
                "Suppressing golden_ticket marker — no krbtgt hash present for domain (likely inter-realm forge output)"
            );
            return;
        }
    }
    if domain.is_empty() {
        return;
    }
    // Per-domain dedup: skip the timeline-event emit + set_golden_ticket
    // call when this specific domain's GT vuln is already exploited. The
    // global `has_golden_ticket` bool is not consulted here — it would
    // suppress legitimate forges for additional domains.
    {
        let state = dispatcher.state.read().await;
        let vuln_id = format!("golden_ticket_{}", domain.to_lowercase());
        if state.exploited_vulnerabilities.contains(&vuln_id) {
            return;
        }
    }
    if let Err(e) = dispatcher
        .state
        .set_golden_ticket(&dispatcher.queue, &domain)
        .await
    {
        warn!(err = %e, "Failed to set golden ticket flag");
    }

    // Emit attack path timeline event for golden ticket
    let techniques = vec!["T1558.001".to_string()];
    let event_id = format!("evt-gt-{}", &uuid::Uuid::new_v4().simple().to_string()[..8]);
    let event = serde_json::json!({
        "id": event_id,
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "source": "golden_ticket",
        "description": format!("Golden ticket forged for domain {domain}"),
        "mitre_techniques": techniques,
    });
    let _ = dispatcher
        .state
        .persist_timeline_event(&dispatcher.queue, &event, &techniques)
        .await;
}

pub(crate) async fn detect_and_upgrade_admin_credentials(text: &str, dispatcher: &Arc<Dispatcher>) {
    for line in text.lines() {
        let Some((domain, username)) = parse_pwned_line(line) else {
            continue;
        };
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
            let pwned_ip = extract_ip_from_line(line);
            info!(
                username = %username,
                domain = %domain,
                pwned_host = ?pwned_ip,
                "Credential upgraded to admin -- dispatching priority secretsdump"
            );
            // Mark the host as owned so automations (lsassy_dump, etc.) can fire
            if let Some(ref ip) = pwned_ip {
                if let Err(e) = dispatcher
                    .state
                    .mark_host_owned(&dispatcher.queue, ip)
                    .await
                {
                    warn!(err = %e, ip = %ip, "Failed to mark host as owned");
                }
            }
            create_admin_upgrade_timeline_event(dispatcher, &username, &domain).await;
            let work: Vec<(String, ares_core::models::Credential)> = {
                let state = dispatcher.state.read().await;
                let dc_ips: Vec<String> = state.domain_controllers.values().cloned().collect();
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
                if !dispatcher.is_technique_allowed("secretsdump") {
                    break;
                }
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

pub(crate) async fn extract_and_cache_domain_sid(
    payload: &Value,
    task_domain: Option<&str>,
    dispatcher: &Arc<Dispatcher>,
) {
    let text_parts = collect_payload_text_parts(payload);
    if text_parts.is_empty() {
        return;
    }
    let combined = text_parts.join("\n");

    // Only cache when the output is genuine LSARPC SID-discovery output — i.e.
    // it has either the impacket-lookupsid `[*] Domain SID is: …` header or
    // the rpcclient `lsaquery` `Domain Name / Domain Sid` pair. Arbitrary recon
    // output (LDAP group enumeration, BloodHound dumps, etc.) routinely contains
    // foreign-security-principal SIDs that *look* like domain SIDs but are
    // actually `<sid>-<rid>` entries from a different forest. Caching a
    // regex-truncated FSP SID against the task's payload domain misforges
    // every downstream golden / inter-realm ticket.
    //
    // lsaquery is the primary unauth path for cross-forest target SID discovery
    // — it routinely succeeds against null sessions where impacket-lookupsid
    // gets STATUS_ACCESS_DENIED, so both parsers must be wired or the forge
    // fires with has_target_sid=false.
    let Some((sid, lsaquery_flat)) = parse_sid_from_combined_text(&combined) else {
        return;
    };

    // Resolve the FQDN this SID belongs to. Anchor preference order:
    // 1. Flat name parsed from the output — authoritative when present. For
    //    impacket-lookupsid we get it from the RID lines (e.g. `500: FABRIKAM\…`);
    //    for rpcclient lsaquery we get it from `Domain Name: FABRIKAM`.
    // 2. Trusted task domain captured from pending-task params before
    //    `complete_task` removed the entry. This is the orchestrator's own
    //    target realm, not an LLM-authored payload field.
    // 3. State's primary domain — last resort, only when nothing else applies.
    let parsed_flat = lsaquery_flat.or_else(|| {
        ares_core::parsing::extract_domain_sid_and_flat_name(&combined).map(|(flat, _)| flat)
    });
    let domain = {
        let state = dispatcher.state.read().await;
        if let Some(flat) = parsed_flat.as_deref() {
            resolve_flat_to_fqdn(flat, &state).or_else(|| {
                // Flat name parsed but unmapped — refuse to cache. Caching
                // against the payload's domain would re-introduce the
                // wrong-domain SID poisoning this whole function guards against.
                warn!(
                    flat_name = %flat,
                    sid = %sid,
                    "Skipping SID cache: flat name does not match any known domain"
                );
                None
            })
        } else {
            task_domain
                .map(|d| d.to_lowercase())
                .filter(|d| is_valid_domain_fqdn(d))
                .or_else(|| state.domains.first().map(|d| d.to_lowercase()))
        }
    };
    let Some(domain) = domain else {
        return;
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
                .insert(domain.clone(), sid.clone());
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

#[cfg(test)]
mod tests {
    use super::*;
    use ares_core::models::TrustInfo;
    use serde_json::json;

    fn make_trust(domain: &str, flat: &str) -> TrustInfo {
        TrustInfo {
            domain: domain.to_string(),
            flat_name: flat.to_string(),
            direction: "bidirectional".to_string(),
            trust_type: "forest".to_string(),
            sid_filtering: true,
            security_identifier: None,
        }
    }

    // -- resolve_flat_to_fqdn -----------------------------------------------

    #[test]
    fn resolve_flat_uses_trusted_domain_metadata() {
        let mut state = StateInner::new("op-test".into());
        state.trusted_domains.insert(
            "fabrikam.local".into(),
            make_trust("fabrikam.local", "FABRIKAM"),
        );
        assert_eq!(
            resolve_flat_to_fqdn("FABRIKAM", &state).as_deref(),
            Some("fabrikam.local")
        );
    }

    #[test]
    fn resolve_flat_falls_back_to_primary_domain_label() {
        let mut state = StateInner::new("op-test".into());
        state.domains.push("contoso.local".into());
        assert_eq!(
            resolve_flat_to_fqdn("CONTOSO", &state).as_deref(),
            Some("contoso.local")
        );
    }

    #[test]
    fn resolve_flat_unknown_returns_none() {
        let state = StateInner::new("op-test".into());
        assert_eq!(resolve_flat_to_fqdn("UNKNOWN", &state), None);
    }

    #[test]
    fn resolve_flat_does_not_match_host_short_name() {
        // netbios_to_fqdn maps DC02 → dc02.contoso.local (a host, not domain).
        // resolve_flat_to_fqdn must reject this — dc02.contoso.local is not in
        // state.domains, so it cannot be a domain FQDN.
        let mut state = StateInner::new("op-test".into());
        state.domains.push("contoso.local".into());
        state
            .netbios_to_fqdn
            .insert("DC02".into(), "dc02.contoso.local".into());
        assert_eq!(resolve_flat_to_fqdn("DC02", &state), None);
    }

    #[test]
    fn resolve_flat_prefers_trust_metadata_over_primary_label() {
        // Both child.contoso.local and contoso.local are known.
        // Flat "CONTOSO" should resolve to the parent FQDN even when
        // both could plausibly match by first-label heuristic.
        let mut state = StateInner::new("op-test".into());
        state.domains.push("child.contoso.local".into());
        state.domains.push("contoso.local".into());
        state.trusted_domains.insert(
            "contoso.local".into(),
            make_trust("contoso.local", "CONTOSO"),
        );
        assert_eq!(
            resolve_flat_to_fqdn("CONTOSO", &state).as_deref(),
            Some("contoso.local")
        );
    }

    // -- resolve_da_path ----------------------------------------------------

    #[test]
    fn resolve_da_path_always_secretsdump() {
        // Agent-provided path fields are ignored; path is always fixed.
        let payload = json!({
            "has_domain_admin": true,
            "domain_admin_path": "spray → secretsdump → krbtgt"
        });
        assert_eq!(
            resolve_da_path(&payload).as_deref(),
            Some("secretsdump -> krbtgt hash")
        );
    }

    #[test]
    fn resolve_da_path_no_fields() {
        let payload = json!({ "has_domain_admin": true });
        assert_eq!(
            resolve_da_path(&payload).as_deref(),
            Some("secretsdump -> krbtgt hash")
        );
    }

    #[test]
    fn resolve_da_path_not_explicit_falls_back() {
        let payload = json!({ "tool_output": "got krbtgt" });
        assert_eq!(
            resolve_da_path(&payload).as_deref(),
            Some("secretsdump -> krbtgt hash")
        );
    }

    #[test]
    fn resolve_da_path_explicit_false_falls_back() {
        let payload = json!({ "has_domain_admin": false });
        assert_eq!(
            resolve_da_path(&payload).as_deref(),
            Some("secretsdump -> krbtgt hash")
        );
    }

    // -- has_golden_ticket_indicator ----------------------------------------

    #[test]
    fn golden_ticket_indicator_positive() {
        assert!(has_golden_ticket_indicator(
            "Saving ticket in administrator.ccache"
        ));
    }

    #[test]
    fn golden_ticket_indicator_missing_ccache() {
        assert!(!has_golden_ticket_indicator("Saving ticket in /tmp/ticket"));
    }

    #[test]
    fn golden_ticket_indicator_missing_saving() {
        assert!(!has_golden_ticket_indicator("Found file admin.ccache"));
    }

    #[test]
    fn golden_ticket_indicator_empty() {
        assert!(!has_golden_ticket_indicator(""));
    }

    // -- parse_pwned_line ---------------------------------------------------

    #[test]
    fn parse_pwned_full_format() {
        let line = "[+] CONTOSO\\administrator:P@ssw0rd (Pwn3d!)";
        let (domain, username) = parse_pwned_line(line).unwrap();
        assert_eq!(domain, "contoso");
        assert_eq!(username, "administrator");
    }

    #[test]
    fn parse_pwned_no_password() {
        let line = "[+] CONTOSO\\administrator (Pwn3d!)";
        let (domain, username) = parse_pwned_line(line).unwrap();
        assert_eq!(domain, "contoso");
        assert_eq!(username, "administrator");
    }

    #[test]
    fn parse_pwned_missing_marker() {
        assert!(parse_pwned_line("[*] CONTOSO\\admin:pass").is_none());
    }

    #[test]
    fn parse_pwned_missing_plus() {
        assert!(parse_pwned_line("CONTOSO\\admin (Pwn3d!)").is_none());
    }

    #[test]
    fn parse_pwned_no_backslash() {
        assert!(parse_pwned_line("[+] admin (Pwn3d!)").is_none());
    }

    #[test]
    fn parse_pwned_domain_lowercased() {
        let line = "[+] FABRIKAM.LOCAL\\svc_admin:secret (Pwn3d!)";
        let (domain, _) = parse_pwned_line(line).unwrap();
        assert_eq!(domain, "fabrikam.local");
    }

    #[test]
    fn parse_pwned_whitespace_only_after_backslash() {
        // After backslash we get " (Pwn3d!)" — first word is "(Pwn3d!)"
        // which is a garbage username, but the parser returns it
        let line = "[+] CONTOSO\\ (Pwn3d!)";
        let result = parse_pwned_line(line);
        // Parser doesn't reject this — it extracts "(Pwn3d!)" as username
        assert!(result.is_some());
    }

    #[test]
    fn parse_pwned_empty_domain() {
        let line = "[+] \\administrator (Pwn3d!)";
        assert!(parse_pwned_line(line).is_none());
    }

    // -- extract_ip_from_line -----------------------------------------------

    #[test]
    fn extract_ip_basic() {
        let line = "SMB 192.168.58.10 445 DC01 [+] admin (Pwn3d!)";
        assert_eq!(extract_ip_from_line(line).as_deref(), Some("192.168.58.10"));
    }

    #[test]
    fn extract_ip_none_when_missing() {
        assert!(extract_ip_from_line("no ip here").is_none());
    }

    #[test]
    fn extract_ip_rejects_non_octets() {
        assert!(extract_ip_from_line("999.999.999.999").is_none());
    }

    #[test]
    fn extract_ip_picks_first() {
        let line = "192.168.58.1 connected to 192.168.58.2";
        assert_eq!(extract_ip_from_line(line).as_deref(), Some("192.168.58.1"));
    }

    #[test]
    fn extract_ip_not_fooled_by_version() {
        assert!(extract_ip_from_line("version 1.2.3 released").is_none());
    }

    // ── is_valid_domain_fqdn ──────────────────────────────────────────

    #[test]
    fn valid_fqdn_accepts_standard_domain() {
        assert!(is_valid_domain_fqdn("contoso.local"));
        assert!(is_valid_domain_fqdn("fabrikam.local"));
        assert!(is_valid_domain_fqdn("child.contoso.local"));
    }

    #[test]
    fn valid_fqdn_rejects_empty_string() {
        assert!(!is_valid_domain_fqdn(""));
    }

    #[test]
    fn valid_fqdn_rejects_no_dot() {
        // A flat name (e.g. "CONTOSO") has no dot — not a valid FQDN.
        assert!(!is_valid_domain_fqdn("CONTOSO"));
        assert!(!is_valid_domain_fqdn("localonly"));
    }

    #[test]
    fn valid_fqdn_rejects_strings_with_spaces() {
        assert!(!is_valid_domain_fqdn("contoso .local"));
        assert!(!is_valid_domain_fqdn("192.168.58.30 - dc01"));
    }

    #[test]
    fn valid_fqdn_rejects_strings_with_colons_or_slashes() {
        assert!(!is_valid_domain_fqdn("http://contoso.local"));
        assert!(!is_valid_domain_fqdn("contoso:local"));
    }

    #[test]
    fn valid_fqdn_rejects_ip_like_strings() {
        // First label is all digits → looks like an IP, not a domain.
        assert!(!is_valid_domain_fqdn("192.168.58.10"));
        assert!(!is_valid_domain_fqdn("10.0.0.1"));
    }

    #[test]
    fn valid_fqdn_rejects_leading_dot() {
        // First label is empty → ".contoso.local" is malformed.
        assert!(!is_valid_domain_fqdn(".contoso.local"));
    }

    #[test]
    fn valid_fqdn_accepts_domain_with_hyphens_and_underscores() {
        assert!(is_valid_domain_fqdn("my-domain.local"));
        assert!(is_valid_domain_fqdn("_kerberos.contoso.local"));
    }

    // ── collect_payload_text_parts ─────────────────────────────────────

    #[test]
    fn collect_text_parts_ignores_top_level_scalar_fields() {
        let p = json!({
            "tool_output": "alpha",
            "output": "beta",
            "summary": "ignored",
        });
        assert!(collect_payload_text_parts(&p).is_empty());
    }

    #[test]
    fn collect_text_parts_walks_tool_outputs_array_strings() {
        let p = json!({
            "tool_outputs": ["first", "second"],
        });
        assert_eq!(collect_payload_text_parts(&p), vec!["first", "second"]);
    }

    #[test]
    fn collect_text_parts_walks_tool_outputs_array_objects() {
        let p = json!({
            "tool_outputs": [
                {"name": "tool1", "output": "first"},
                {"name": "tool2", "output": "second"},
            ],
        });
        assert_eq!(collect_payload_text_parts(&p), vec!["first", "second"]);
    }

    #[test]
    fn collect_text_parts_mixes_string_and_object_entries() {
        let p = json!({
            "tool_output": "scalar",
            "tool_outputs": [
                "bare-string",
                {"output": "from-object"},
            ],
        });
        assert_eq!(
            collect_payload_text_parts(&p),
            vec!["bare-string", "from-object"]
        );
    }

    #[test]
    fn collect_text_parts_ignores_scalar_fields() {
        let p = json!({
            "tool_output": "scalar",
            "output": "also-scalar",
            "tool_outputs": [
                "bare-string",
                {"output": "from-object"},
            ],
        });
        assert_eq!(
            collect_payload_text_parts(&p),
            vec!["bare-string", "from-object"]
        );
    }

    #[test]
    fn collect_text_parts_skips_non_string_entries() {
        let p = json!({
            "tool_outputs": [42, true, null, "kept"],
        });
        assert_eq!(collect_payload_text_parts(&p), vec!["kept"]);
    }

    #[test]
    fn collect_text_parts_empty_for_empty_payload() {
        assert!(collect_payload_text_parts(&json!({})).is_empty());
    }

    // ── payload_contains_golden_ticket_marker ──────────────────────────

    #[test]
    fn gt_marker_in_tool_outputs_string_form() {
        let p = json!({
            "tool_outputs": ["Saving ticket in admin.ccache"],
        });
        assert!(payload_contains_golden_ticket_marker(&p));
    }

    #[test]
    fn gt_marker_in_tool_outputs_object_form() {
        let p = json!({
            "tool_outputs": [
                {"output": "Saving ticket in admin.ccache for Administrator"},
            ],
        });
        assert!(payload_contains_golden_ticket_marker(&p));
    }

    #[test]
    fn gt_marker_ignores_summary() {
        let p = json!({
            "summary": "Saving ticket in admin.ccache; krbtgt forged",
        });
        assert!(!payload_contains_golden_ticket_marker(&p));
    }

    #[test]
    fn gt_marker_ignores_scalar_tool_output_field() {
        let p = json!({
            "tool_output": "Saving ticket in foo.ccache",
        });
        assert!(!payload_contains_golden_ticket_marker(&p));
    }

    #[test]
    fn gt_marker_ignores_explicit_flag() {
        let p = json!({
            "has_golden_ticket": true,
        });
        assert!(!payload_contains_golden_ticket_marker(&p));
    }

    #[test]
    fn gt_marker_explicit_flag_false_does_not_trigger() {
        let p = json!({
            "has_golden_ticket": false,
        });
        assert!(!payload_contains_golden_ticket_marker(&p));
    }

    #[test]
    fn gt_marker_requires_both_saving_and_ccache() {
        // "Saving ticket in" without ".ccache" → not a match.
        let p = json!({"summary": "Saving ticket in memory"});
        assert!(!payload_contains_golden_ticket_marker(&p));
        // ".ccache" without "Saving ticket in" → not a match.
        let p = json!({"summary": "Found a .ccache file at /tmp/x.ccache"});
        assert!(!payload_contains_golden_ticket_marker(&p));
    }

    #[test]
    fn gt_marker_returns_false_for_unrelated_payload() {
        let p = json!({"summary": "nothing here"});
        assert!(!payload_contains_golden_ticket_marker(&p));
    }

    // ── parse_sid_from_combined_text ───────────────────────────────────

    #[test]
    fn parse_sid_recognises_lookupsid_header() {
        let text = "Brute forcing SIDs at 192.168.58.10
[*] StringBinding ncacn_np:192.168.58.10[\\PIPE\\lsarpc]
[*] Domain SID is: S-1-5-21-1111-2222-3333";
        let (sid, flat) = parse_sid_from_combined_text(text).unwrap();
        assert_eq!(sid, "S-1-5-21-1111-2222-3333");
        assert!(flat.is_none());
    }

    #[test]
    fn parse_sid_recognises_lsaquery_pair() {
        // lsaquery output carries both Domain Name and Domain Sid.
        let text = "\
Domain Name: FABRIKAM
Domain Sid: S-1-5-21-9999-8888-7777";
        let (sid, flat) = parse_sid_from_combined_text(text).unwrap();
        assert_eq!(sid, "S-1-5-21-9999-8888-7777");
        assert_eq!(flat.as_deref(), Some("FABRIKAM"));
    }

    #[test]
    fn parse_sid_returns_none_for_unrelated_text() {
        assert!(parse_sid_from_combined_text("nothing here").is_none());
    }

    #[test]
    fn parse_sid_prefers_lookupsid_header_over_lsaquery() {
        // Both formats present — lookupsid wins (the first branch in the match).
        let text = "\
[*] Domain SID is: S-1-5-21-1111-2222-3333
Domain Name: FABRIKAM
Domain Sid: S-1-5-21-9999-8888-7777";
        let (sid, flat) = parse_sid_from_combined_text(text).unwrap();
        assert_eq!(sid, "S-1-5-21-1111-2222-3333");
        assert!(flat.is_none());
    }
}
