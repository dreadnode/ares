//! Domain admin indicator checks, golden ticket detection, Pwn3d! credential
//! upgrades, and domain SID extraction.

use std::sync::Arc;

use serde_json::Value;
use tracing::{info, warn};

use super::parsing::has_domain_admin_indicator;
use super::timeline::{create_admin_upgrade_timeline_event, create_domain_admin_timeline_event};
use crate::orchestrator::dispatcher::Dispatcher;
use crate::orchestrator::state::{
    canonicalize_domain_label, is_valid_domain_fqdn, krbtgt_da_path, resolve_flat_to_fqdn,
    StateInner, DEDUP_ADMIN_HASH_UPGRADE,
};

/// Determine the domain admin path from parser-derived state.
///
/// The payload is deliberately not consulted: an agent's `domain_admin_path`
/// is a model claim, and claims never feed state writes. The tool that
/// actually produced the krbtgt hash is recorded by a parser in `Hash.source`,
/// so that is what the path names.
///
/// Returns `None` when no krbtgt hash has landed — the DA flag can be set by
/// an indicator alone, and naming a technique on that evidence is what made
/// every report assert `secretsdump` regardless of what ran. Callers render
/// their own fallback (the report derives a path from the credential chain).
pub(crate) fn resolve_da_path(state: &StateInner) -> Option<String> {
    state.latest_krbtgt_source().map(krbtgt_da_path)
}

/// Check if text indicates a golden ticket was saved.
///
/// ticketer prints the same `Saving ticket in <principal>.ccache` line whether
/// it forged a TGT or an SPN-scoped TGS, so a silver ticket would otherwise
/// publish the domain-wide golden-ticket milestone off a single-service ticket.
/// `generate_silver_ticket` stamps its SPN into stdout; its presence disqualifies
/// the text.
pub(crate) fn has_golden_ticket_indicator(text: &str) -> bool {
    text.contains("Saving ticket in")
        && text.contains(".ccache")
        && !text.contains(ares_tools::parsers::SILVER_TICKET_SPN_MARKER)
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
    let (already_da, path) = {
        let state = dispatcher.state.read().await;
        (state.has_domain_admin, resolve_da_path(&state))
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
}

/// Dedup key for the hash-backed admin credit — one per principal, matching
/// the per-principal granularity of `mark_credentials_admin`'s flip.
pub(crate) fn admin_hash_dedup_key(username: &str, domain: &str) -> String {
    format!("{}\\{}", domain.to_lowercase(), username.to_lowercase())
}

/// Resolve the NTLM hash that backs a `Pwn3d!` line for a principal that holds
/// no credential row, or `None` when the discovery is not creditable this way.
///
/// `mark_credentials_admin` only credits `state.credentials`, so a principal
/// obtained by DCSync — held as a hash — produces a `Pwn3d!` line, no admin
/// timeline event and no priority secretsdump. This is the `find_source_hash`
/// fallback `dacl_abuse` already applies to the same asymmetry.
///
/// Declines in three cases. A credential row for the principal already exists,
/// which means the credential path owns the decision and has already deduped
/// it (`mark_credentials_admin` returns `false` both for "no row" and for
/// "already admin", so the caller cannot tell them apart). The principal was
/// already credited this operation. Or no hash for the principal is in state —
/// requiring one keeps the admin event backed by real material rather than by
/// the log line alone, which is the phantom shape `seimpersonate` credit had.
///
/// `find_source_hash`'s last-resort arm matches on username alone, so the
/// hash's own domain is checked against the pwned domain — both canonicalized,
/// since netexec reports flat names and hashes carry FQDNs. Without that,
/// `administrator` in one forest would credit a `Pwn3d!` in another.
pub(crate) fn resolve_hash_only_admin(
    state: &StateInner,
    username: &str,
    domain: &str,
) -> Option<ares_core::models::Hash> {
    let holds_credential = state.credentials.iter().any(|c| {
        c.username.eq_ignore_ascii_case(username) && c.domain.eq_ignore_ascii_case(domain)
    });
    if holds_credential {
        return None;
    }
    if state.is_processed(
        DEDUP_ADMIN_HASH_UPGRADE,
        &admin_hash_dedup_key(username, domain),
    ) {
        return None;
    }
    let hash = state.find_source_hash(username, domain)?;
    let canonical =
        |d: &str| canonicalize_domain_label(d, state).unwrap_or_else(|| d.to_lowercase());
    (canonical(&hash.domain) == canonical(domain)).then_some(hash)
}

/// Credit a `Pwn3d!` line whose principal is held only as an NTLM hash.
///
/// Emits the same admin-upgrade timeline event and priority secretsdump the
/// credential path emits, over `request_secretsdump_hash` rather than a
/// password. The dedup key is written before any dispatch so a failed submit
/// cannot re-credit on the next `Pwn3d!` line for the same principal.
async fn credit_hash_only_admin(
    dispatcher: &Arc<Dispatcher>,
    username: &str,
    domain: &str,
    pwned_ip: Option<&str>,
) {
    let hash = {
        let state = dispatcher.state.read().await;
        resolve_hash_only_admin(&state, username, domain)
    };
    let Some(hash) = hash else {
        return;
    };
    let dedup_key = admin_hash_dedup_key(username, domain);
    {
        let mut state = dispatcher.state.write().await;
        state.mark_processed(DEDUP_ADMIN_HASH_UPGRADE, dedup_key.clone());
    }
    let _ = dispatcher
        .state
        .persist_dedup(&dispatcher.queue, DEDUP_ADMIN_HASH_UPGRADE, &dedup_key)
        .await;
    info!(
        username = %username,
        domain = %domain,
        pwned_host = ?pwned_ip,
        "Hash-only principal confirmed local admin -- crediting from NTLM hash"
    );
    if let Some(ip) = pwned_ip {
        if let Err(e) = dispatcher
            .state
            .mark_host_owned(&dispatcher.queue, ip)
            .await
        {
            warn!(err = %e, ip = %ip, "Failed to mark host as owned");
        }
    }
    create_admin_upgrade_timeline_event(dispatcher, username, domain, pwned_ip).await;
    if !dispatcher.is_technique_allowed("secretsdump") {
        return;
    }
    let mut targets: Vec<String> = {
        let state = dispatcher.state.read().await;
        state.domain_controllers.values().cloned().collect()
    };
    if let Some(ip) = pwned_ip {
        if !targets.iter().any(|t| t == ip) {
            targets.push(ip.to_string());
        }
    }
    for target_ip in targets {
        match dispatcher
            .request_secretsdump_hash(
                &target_ip,
                &hash.username,
                &hash.domain,
                &hash.hash_value,
                1,
                None,
            )
            .await
        {
            Ok(Some(task_id)) => {
                info!(
                    task_id = %task_id,
                    target = %target_ip,
                    username = %username,
                    "Admin Pwn3d! pass-the-hash secretsdump dispatched (priority 1)"
                );
            }
            Ok(None) => {}
            Err(e) => {
                warn!(err = %e, "Failed to dispatch Pwn3d! pass-the-hash secretsdump")
            }
        }
    }
}

pub(crate) async fn detect_and_upgrade_admin_credentials(text: &str, dispatcher: &Arc<Dispatcher>) {
    for line in text.lines() {
        let Some((domain, username)) = parse_pwned_line(line) else {
            continue;
        };
        info!(username = %username, domain = %domain, "Pwn3d! detected -- upgrading credential to admin");
        let upgraded = match dispatcher
            .state
            .mark_credentials_admin(&dispatcher.queue, &username, &domain)
            .await
        {
            Ok(flipped) => flipped,
            Err(e) => {
                warn!(err = %e, username = %username, domain = %domain, "Failed to persist admin flag");
                false
            }
        };
        let pwned_ip = extract_ip_from_line(line);
        if upgraded {
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
            create_admin_upgrade_timeline_event(
                dispatcher,
                &username,
                &domain,
                pwned_ip.as_deref(),
            )
            .await;
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
        } else {
            credit_hash_only_admin(dispatcher, &username, &domain, pwned_ip.as_deref()).await;
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
    use serde_json::json;

    // -- resolve_da_path ----------------------------------------------------

    fn krbtgt_hash_from(source: &str) -> ares_core::models::Hash {
        ares_core::models::Hash {
            id: "h1".to_string(),
            username: "krbtgt".to_string(),
            hash_value: "aad3b435b51404eeaad3b435b51404ee:deadbeef".to_string(),
            hash_type: "NTLM".to_string(),
            domain: "contoso.local".to_string(),
            source: source.to_string(),
            cracked_password: None,
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
    fn resolve_da_path_names_the_tool_that_produced_the_hash() {
        let mut state = StateInner::new("op-test".to_string());
        state
            .hashes
            .push(krbtgt_hash_from("certipy_esc1_full_chain"));
        assert_eq!(
            resolve_da_path(&state).as_deref(),
            Some("certipy_esc1_full_chain → krbtgt NTLM hash")
        );
    }

    #[test]
    fn resolve_da_path_tracks_secretsdump_when_that_is_the_source() {
        let mut state = StateInner::new("op-test".to_string());
        state.hashes.push(krbtgt_hash_from("secretsdump"));
        assert_eq!(
            resolve_da_path(&state).as_deref(),
            Some("secretsdump → krbtgt NTLM hash")
        );
    }

    #[test]
    fn resolve_da_path_is_none_without_a_krbtgt_hash() {
        let state = StateInner::new("op-test".to_string());
        assert_eq!(resolve_da_path(&state), None);
    }

    #[test]
    fn resolve_da_path_ignores_a_non_krbtgt_hash() {
        let mut state = StateInner::new("op-test".to_string());
        let mut other = krbtgt_hash_from("secretsdump");
        other.username = "alice".to_string();
        state.hashes.push(other);
        assert_eq!(resolve_da_path(&state), None);
    }

    #[test]
    fn resolve_da_path_prefers_the_most_recent_capture() {
        let mut state = StateInner::new("op-test".to_string());
        state.hashes.push(krbtgt_hash_from("secretsdump"));
        state
            .hashes
            .push(krbtgt_hash_from("certipy_esc1_full_chain"));
        assert_eq!(
            resolve_da_path(&state).as_deref(),
            Some("certipy_esc1_full_chain → krbtgt NTLM hash")
        );
    }

    #[test]
    fn krbtgt_da_path_omits_an_empty_source() {
        assert_eq!(krbtgt_da_path("   "), "krbtgt NTLM hash");
    }

    // -- has_golden_ticket_indicator ----------------------------------------

    #[test]
    fn golden_ticket_indicator_positive() {
        assert!(has_golden_ticket_indicator(
            "Saving ticket in administrator.ccache"
        ));
    }

    /// A silver ticket forge prints the identical `Saving ticket in
    /// <principal>.ccache` line. Crediting it as a golden ticket would publish
    /// the domain-wide TGT milestone off a ticket good for one service.
    #[test]
    fn golden_ticket_indicator_rejects_a_silver_ticket_forge() {
        let silver = format!(
            "[*] Saving ticket in Administrator.ccache\n{}MSSQLSvc/sql01.contoso.local:1433\n",
            ares_tools::parsers::SILVER_TICKET_SPN_MARKER
        );
        assert!(!has_golden_ticket_indicator(&silver));
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

    fn admin_state() -> StateInner {
        let mut state = StateInner::new("op-admin".into());
        state.domains = vec!["contoso.local".into(), "fabrikam.local".into()];
        state
    }

    fn ntlm_hash(username: &str, domain: &str) -> ares_core::models::Hash {
        ares_core::models::Hash {
            id: format!("hash-{username}-{domain}"),
            username: username.into(),
            hash_value: "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0".into(),
            hash_type: "NTLM".into(),
            domain: domain.into(),
            cracked_password: None,
            source: "secretsdump".into(),
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

    fn plain_credential(username: &str, domain: &str) -> ares_core::models::Credential {
        ares_core::models::Credential {
            id: format!("cred-{username}"),
            username: username.into(),
            password: "P@ssw0rd!".into(),
            domain: domain.into(),
            source: "test".into(),
            discovered_at: None,
            is_admin: false,
            parent_id: None,
            attack_step: 0,
        }
    }

    /// The §2.3 case: a DCSync-obtained principal pwns a host, `Pwn3d!` fires,
    /// and `mark_credentials_admin` finds nothing because the principal is
    /// held as a hash. Before this fallback the discovery was uncreditable.
    #[test]
    fn hash_only_admin_credits_a_principal_with_no_credential_row() {
        let mut state = admin_state();
        state
            .hashes
            .push(ntlm_hash("administrator", "fabrikam.local"));
        let hash = resolve_hash_only_admin(&state, "administrator", "fabrikam.local").unwrap();
        assert_eq!(hash.domain, "fabrikam.local");
        assert!(hash
            .hash_value
            .ends_with("31d6cfe0d16ae931b73c59d7e0c089c0"));
    }

    #[test]
    fn hash_only_admin_declines_when_a_credential_row_exists() {
        let mut state = admin_state();
        state.hashes.push(ntlm_hash("alice", "contoso.local"));
        state
            .credentials
            .push(plain_credential("alice", "contoso.local"));
        assert!(resolve_hash_only_admin(&state, "alice", "contoso.local").is_none());
    }

    #[test]
    fn hash_only_admin_declines_a_second_pwn3d_line_for_the_same_principal() {
        let mut state = admin_state();
        state.hashes.push(ntlm_hash("alice", "contoso.local"));
        assert!(resolve_hash_only_admin(&state, "alice", "contoso.local").is_some());
        state.mark_processed(
            DEDUP_ADMIN_HASH_UPGRADE,
            admin_hash_dedup_key("alice", "contoso.local"),
        );
        assert!(resolve_hash_only_admin(&state, "alice", "contoso.local").is_none());
    }

    /// `find_source_hash`'s last-resort arm matches on username alone, so
    /// without the domain check `administrator` in one forest would credit a
    /// `Pwn3d!` in another.
    #[test]
    fn hash_only_admin_declines_a_same_name_hash_from_another_domain() {
        let mut state = admin_state();
        state
            .hashes
            .push(ntlm_hash("administrator", "contoso.local"));
        assert!(
            state
                .find_source_hash("administrator", "fabrikam.local")
                .is_some(),
            "guard must be what declines, not an empty find_source_hash"
        );
        assert!(resolve_hash_only_admin(&state, "administrator", "fabrikam.local").is_none());
    }

    #[test]
    fn hash_only_admin_accepts_a_flat_pwned_domain_naming_the_hash_domain() {
        let mut state = admin_state();
        state
            .hashes
            .push(ntlm_hash("administrator", "fabrikam.local"));
        assert!(resolve_hash_only_admin(&state, "administrator", "fabrikam").is_some());
    }

    #[test]
    fn hash_only_admin_declines_when_no_hash_is_held() {
        let state = admin_state();
        assert!(resolve_hash_only_admin(&state, "bob", "contoso.local").is_none());
    }

    #[test]
    fn hash_only_admin_declines_a_hash_with_no_domain() {
        let mut state = admin_state();
        state.hashes.push(ntlm_hash("alice", ""));
        assert!(resolve_hash_only_admin(&state, "alice", "contoso.local").is_none());
    }

    /// Only NTLM is usable for pass-the-hash; a roast ciphertext for the same
    /// principal must not be credited as admin material.
    #[test]
    fn hash_only_admin_declines_a_non_ntlm_hash() {
        let mut state = admin_state();
        let mut roast = ntlm_hash("svc_sql", "contoso.local");
        roast.hash_type = "krb5tgs".into();
        state.hashes.push(roast);
        assert!(resolve_hash_only_admin(&state, "svc_sql", "contoso.local").is_none());
    }

    #[test]
    fn hash_only_admin_matches_the_principal_case_insensitively() {
        let mut state = admin_state();
        state
            .hashes
            .push(ntlm_hash("Administrator", "Contoso.Local"));
        assert!(resolve_hash_only_admin(&state, "administrator", "contoso.local").is_some());
    }

    #[test]
    fn admin_hash_dedup_key_is_case_folded() {
        assert_eq!(
            admin_hash_dedup_key("Administrator", "CONTOSO.LOCAL"),
            admin_hash_dedup_key("administrator", "contoso.local")
        );
        assert_eq!(
            admin_hash_dedup_key("alice", "contoso.local"),
            "contoso.local\\alice"
        );
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
