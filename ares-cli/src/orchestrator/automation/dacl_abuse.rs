//! auto_dacl_abuse -- direct ACL abuse for known attack paths.
//!
//! Unlike acl_chain_follow (which requires BloodHound to populate acl_chains),
//! this module proactively dispatches known ACL abuse techniques when:
//!   - A credential is available for a user known to have dangerous permissions
//!   - The target object exists in the domain
//!
//! Covers: ForceChangePassword, GenericWrite (targeted Kerberoast), WriteDacl,
//! WriteOwner, GenericAll. Each abuse type maps to a specific tool invocation
//! (e.g., net rpc password for ForceChangePassword, bloodyAD for GenericWrite).

use std::sync::Arc;
use std::time::Duration;

use serde_json::json;
use tokio::sync::watch;
use tracing::{debug, info, warn};

use crate::dedup::is_ghost_machine_account;
use crate::orchestrator::dispatcher::{Dispatcher, SubmissionOutcome};
use crate::orchestrator::state::*;

/// Dispatches ACL abuse when matching credentials + bloodhound paths exist.
/// Interval: 30s.
pub async fn auto_dacl_abuse(dispatcher: Arc<Dispatcher>, mut shutdown: watch::Receiver<bool>) {
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

        if !dispatcher.is_technique_allowed("dacl_abuse") {
            continue;
        }

        let work: Vec<DaclWork> = {
            let state = dispatcher.state.read().await;
            collect_dacl_work(&state)
        };

        for item in work {
            let payload = json!({
                "technique": "dacl_abuse",
                "acl_type": item.vuln_type,
                "vuln_id": item.vuln_id,
                "source_user": item.source_user,
                "target_user": item.target_user,
                "target_ip": item.dc_ip,
                "domain": item.domain,
                "credential": {
                    "username": item.credential.username,
                    "password": item.credential.password,
                    "domain": item.credential.domain,
                },
            });

            let priority = dispatcher.effective_priority("dacl_abuse");
            // Mark dedup on Submitted OR Deferred to prevent the 30s tick from
            // re-emitting identical work each cycle and bloating the deferred
            // ZSET past its per-type cap (which silently drops entries). Only
            // skip dedup on Dropped — those need to be reconsidered next tick.
            let mark_dedup = match dispatcher
                .throttled_submit_outcome("acl_chain_step", "acl", payload, priority)
                .await
            {
                Ok(SubmissionOutcome::Submitted(task_id)) => {
                    info!(
                        task_id = %task_id,
                        vuln_id = %item.vuln_id,
                        acl_type = %item.vuln_type,
                        source = %item.source_user,
                        target = %item.target_user,
                        "DACL abuse dispatched"
                    );
                    true
                }
                Ok(SubmissionOutcome::Deferred) => {
                    debug!(vuln_id = %item.vuln_id, "DACL abuse deferred (will retry via deferred drain)");
                    true
                }
                Ok(SubmissionOutcome::Dropped) => {
                    debug!(vuln_id = %item.vuln_id, "DACL abuse dropped (will reconsider next tick)");
                    false
                }
                Err(e) => {
                    warn!(err = %e, vuln_id = %item.vuln_id, "Failed to dispatch DACL abuse");
                    false
                }
            };
            if mark_dedup {
                {
                    let mut state = dispatcher.state.write().await;
                    state.mark_processed(DEDUP_DACL_ABUSE, item.dedup_key.clone());
                }
                let _ = dispatcher
                    .state
                    .persist_dedup(&dispatcher.queue, DEDUP_DACL_ABUSE, &item.dedup_key)
                    .await;
            }
        }
    }
}

/// Collect DACL abuse work items from state without holding async locks.
///
/// Extracted for testability: scans `discovered_vulnerabilities` for ACL-type
/// vulns that have a matching credential and haven't been processed yet.
fn collect_dacl_work(state: &StateInner) -> Vec<DaclWork> {
    if state.credentials.is_empty() {
        return Vec::new();
    }

    let mut items = Vec::new();

    // Check discovered_vulnerabilities for ACL-related vulns
    // (populated by BloodHound analysis or recon agents)
    for vuln in state.discovered_vulnerabilities.values() {
        let vtype = vuln.vuln_type.to_lowercase();

        let is_acl_vuln = vtype.contains("forcechangepassword")
            || vtype.contains("genericwrite")
            || vtype.contains("writedacl")
            || vtype.contains("writeowner")
            || vtype.contains("genericall")
            || vtype.contains("self_membership")
            || vtype.contains("write_membership")
            || vtype.contains("writeproperty")
            || vtype.contains("allextendedrights")
            || vtype.contains("addmember")
            || vtype.contains("addself");

        if !is_acl_vuln {
            continue;
        }

        if state.exploited_vulnerabilities.contains(&vuln.vuln_id) {
            continue;
        }

        let dedup_key = format!("dacl:{}", vuln.vuln_id);
        if state.is_processed(DEDUP_DACL_ABUSE, &dedup_key) {
            continue;
        }

        let target_name = vuln
            .details
            .get("target")
            .or_else(|| vuln.details.get("target_user"))
            .or_else(|| vuln.details.get("to"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if is_ghost_machine_account(target_name) {
            debug!(
                vuln_id = %vuln.vuln_id,
                target = %target_name,
                "Skipping ACL abuse for ghost machine account target"
            );
            continue;
        }

        // Extract source user from vuln details
        let source_user = vuln
            .details
            .get("source")
            .or_else(|| vuln.details.get("source_user"))
            .or_else(|| vuln.details.get("from"))
            .and_then(|v| v.as_str())
            .unwrap_or("");

        let source_domain = vuln
            .details
            .get("source_domain")
            .or_else(|| vuln.details.get("domain"))
            .and_then(|v| v.as_str())
            .unwrap_or("");

        if source_user.is_empty() {
            continue;
        }

        // Find matching credential.
        //
        // BloodHound often emits ACL edges with SID principals (e.g. for
        // well-known groups like Enterprise Admins). When `source` is a SID,
        // resolve to any privileged credential in the source's domain so the
        // ACL chain can still be exercised.
        let cred = state
            .credentials
            .iter()
            .find(|c| {
                c.username.to_lowercase() == source_user.to_lowercase()
                    && (source_domain.is_empty()
                        || c.domain.to_lowercase() == source_domain.to_lowercase())
            })
            .cloned()
            .or_else(|| resolve_sid_principal(state, source_user, source_domain));

        if let Some(cred) = cred {
            let target_user = vuln
                .details
                .get("target")
                .or_else(|| vuln.details.get("target_user"))
                .or_else(|| vuln.details.get("to"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();

            let dispatch_domain = cred.domain.to_lowercase();

            if state.dominated_domains.contains(&dispatch_domain) {
                debug!(vuln_id = %vuln.vuln_id, domain = %cred.domain, "DACL abuse skipped: domain dominated");
                continue;
            }

            // Defer (don't mark dedup) so the next tick re-evaluates once
            // DCSync either finishes (domain becomes dominated above) or its
            // in-flight TTL expires and the chain runs as fallback.
            if state.credential_capture_in_flight_for(&dispatch_domain) {
                debug!(vuln_id = %vuln.vuln_id, domain = %cred.domain, "DACL abuse deferred: credential capture in flight");
                continue;
            }

            // ForceChangePassword / GenericAll overwrite the target's
            // plaintext via `bloodyad_set_password`. Skip when we already
            // have material so the scoreboard's back-verification against
            // the original lab-provisioned password still holds.
            let is_destructive_acl =
                vtype.contains("forcechangepassword") || vtype.contains("genericall");
            if is_destructive_acl && !target_user.is_empty() {
                let target_lower = target_user.to_lowercase();
                let already_have_material = state.credentials.iter().any(|c| {
                    !c.password.is_empty()
                        && c.username.to_lowercase() == target_lower
                        && c.domain.to_lowercase() == dispatch_domain
                }) || state.hashes.iter().any(|h| {
                    h.username.to_lowercase() == target_lower
                        && h.domain.to_lowercase() == dispatch_domain
                });
                if already_have_material {
                    debug!(vuln_id = %vuln.vuln_id, target = %target_user, "Destructive ACL skipped: target material already in state");
                    continue;
                }
            }

            let dc_ip = state
                .domain_controllers
                .get(&dispatch_domain)
                .cloned()
                .unwrap_or_default();

            // When BloodHound emitted the source as a raw SID and we resolved
            // it via `resolve_sid_principal`, surface the resolved credential's
            // SAM account name as `source_user` — not the SID. Tool schemas
            // require a username for credential injection by `(user, domain)`,
            // and the LLM otherwise echoes the SID as the auth principal.
            let dispatched_source_user = if source_user.starts_with("S-1-5-21-") {
                cred.username.clone()
            } else {
                source_user.to_string()
            };

            items.push(DaclWork {
                dedup_key,
                vuln_id: vuln.vuln_id.clone(),
                vuln_type: vtype,
                source_user: dispatched_source_user,
                target_user,
                domain: cred.domain.clone(),
                dc_ip,
                credential: cred,
            });
        }
    }

    items
}

struct DaclWork {
    dedup_key: String,
    vuln_id: String,
    vuln_type: String,
    source_user: String,
    target_user: String,
    domain: String,
    dc_ip: String,
    credential: ares_core::models::Credential,
}

/// RIDs of well-known privileged groups whose membership is owned by privileged
/// credentials in the same domain. Resolving a SID-typed source to "any DA-cred
/// in this domain" is correct for these RIDs because the abuse only requires
/// *a* member of the group, not a specific principal.
fn is_privileged_well_known_rid(rid: u32) -> bool {
    matches!(
        rid,
        512 // Domain Admins
            | 518 // Schema Admins
            | 519 // Enterprise Admins
            | 520 // Group Policy Creator Owners
            | 526 // Key Admins
            | 527 // Enterprise Key Admins
    )
}

/// When the ACL edge source is a SID (typically a well-known group), resolve
/// it to a credential of an actual member.
///
/// Strategy:
///   1. Parse `S-1-5-21-X-Y-Z-RID` and extract the domain SID prefix and RID.
///   2. Reverse-look up the domain via `state.domain_sids` (or fall back to
///      `source_domain` from the vuln details).
///   3. For privileged well-known RIDs, return any `is_admin` credential in
///      that domain. As a last resort, return any credential in the domain.
fn resolve_sid_principal(
    state: &StateInner,
    source: &str,
    source_domain: &str,
) -> Option<ares_core::models::Credential> {
    if !source.starts_with("S-1-5-21-") {
        return None;
    }
    let (prefix, rid_str) = source.rsplit_once('-')?;
    let rid: u32 = rid_str.parse().ok()?;

    let resolved_domain = state
        .domain_sids
        .iter()
        .find(|(_, sid)| sid.eq_ignore_ascii_case(prefix))
        .map(|(d, _)| d.to_lowercase())
        .or_else(|| {
            if source_domain.is_empty() {
                None
            } else {
                Some(source_domain.to_lowercase())
            }
        })?;

    if !is_privileged_well_known_rid(rid) {
        return None;
    }

    let admin = state
        .credentials
        .iter()
        .find(|c| c.is_admin && c.domain.to_lowercase() == resolved_domain)
        .cloned();
    if admin.is_some() {
        return admin;
    }

    state
        .credentials
        .iter()
        .find(|c| c.domain.to_lowercase() == resolved_domain)
        .cloned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dedup_key_format() {
        let key = format!("dacl:{}", "vuln-acl-001");
        assert_eq!(key, "dacl:vuln-acl-001");
    }

    #[test]
    fn dedup_set_name() {
        assert_eq!(DEDUP_DACL_ABUSE, "dacl_abuse");
    }

    #[test]
    fn acl_vuln_type_matching() {
        let positives = [
            "ForceChangePassword",
            "GenericWrite",
            "WriteDacl",
            "WriteOwner",
            "GenericAll",
            "self_membership",
            "write_membership",
            "WriteProperty",
            "AllExtendedRights",
            "AddMember",
            "AddSelf",
            "SomePrefix_forcechangepassword_suffix",
        ];
        for t in &positives {
            let vtype = t.to_lowercase();
            let is_acl_vuln = vtype.contains("forcechangepassword")
                || vtype.contains("genericwrite")
                || vtype.contains("writedacl")
                || vtype.contains("writeowner")
                || vtype.contains("genericall")
                || vtype.contains("self_membership")
                || vtype.contains("write_membership")
                || vtype.contains("writeproperty")
                || vtype.contains("allextendedrights")
                || vtype.contains("addmember")
                || vtype.contains("addself");
            assert!(is_acl_vuln, "{t} should match as ACL vuln");
        }
    }

    #[test]
    fn non_acl_vuln_types_rejected() {
        let negatives = [
            "smb_signing_disabled",
            "mssql_access",
            "zerologon",
            "esc1",
            "kerberoast",
        ];
        for t in &negatives {
            let vtype = t.to_lowercase();
            let is_acl_vuln = vtype.contains("forcechangepassword")
                || vtype.contains("genericwrite")
                || vtype.contains("writedacl")
                || vtype.contains("writeowner")
                || vtype.contains("genericall")
                || vtype.contains("self_membership")
                || vtype.contains("write_membership");
            assert!(!is_acl_vuln, "{t} should NOT match as ACL vuln");
        }
    }

    #[test]
    fn source_user_extraction_keys() {
        // Verify the fallback chain for source user extraction
        let details = serde_json::json!({
            "source": "admin",
            "source_user": "admin2",
            "from": "admin3",
        });
        let source = details
            .get("source")
            .or_else(|| details.get("source_user"))
            .or_else(|| details.get("from"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        assert_eq!(source, "admin");

        // Fallback to source_user
        let details2 = serde_json::json!({
            "source_user": "admin2",
        });
        let source2 = details2
            .get("source")
            .or_else(|| details2.get("source_user"))
            .or_else(|| details2.get("from"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        assert_eq!(source2, "admin2");

        // No source returns empty
        let details3 = serde_json::json!({});
        let source3 = details3
            .get("source")
            .or_else(|| details3.get("source_user"))
            .or_else(|| details3.get("from"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        assert_eq!(source3, "");
    }

    #[test]
    fn source_domain_extraction_keys() {
        let details = serde_json::json!({"source_domain": "contoso.local"});
        let source_domain = details
            .get("source_domain")
            .or_else(|| details.get("domain"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        assert_eq!(source_domain, "contoso.local");

        let details2 = serde_json::json!({"domain": "fabrikam.local"});
        let source_domain2 = details2
            .get("source_domain")
            .or_else(|| details2.get("domain"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        assert_eq!(source_domain2, "fabrikam.local");

        let details3 = serde_json::json!({});
        let source_domain3 = details3
            .get("source_domain")
            .or_else(|| details3.get("domain"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        assert_eq!(source_domain3, "");
    }

    #[test]
    fn target_user_extraction_keys() {
        let details = serde_json::json!({"target": "victim", "target_user": "v2", "to": "v3"});
        let target = details
            .get("target")
            .or_else(|| details.get("target_user"))
            .or_else(|| details.get("to"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        assert_eq!(target, "victim");

        let details2 = serde_json::json!({"target_user": "v2"});
        let target2 = details2
            .get("target")
            .or_else(|| details2.get("target_user"))
            .or_else(|| details2.get("to"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        assert_eq!(target2, "v2");

        let details3 = serde_json::json!({"to": "v3"});
        let target3 = details3
            .get("target")
            .or_else(|| details3.get("target_user"))
            .or_else(|| details3.get("to"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        assert_eq!(target3, "v3");
    }

    #[test]
    fn ghost_machine_targets_rejected() {
        assert!(is_ghost_machine_account("WIN-DPPJMLU3XS6$"));
    }

    #[test]
    fn credential_matching_with_domain() {
        let source_user = "admin";
        let source_domain = "contoso.local";
        let cred_username = "Admin";
        let cred_domain = "CONTOSO.LOCAL";

        let matches = cred_username.to_lowercase() == source_user.to_lowercase()
            && (source_domain.is_empty()
                || cred_domain.to_lowercase() == source_domain.to_lowercase());
        assert!(matches);
    }

    #[test]
    fn credential_matching_without_domain() {
        let source_user = "admin";
        let source_domain = "";
        let cred_username = "admin";
        let cred_domain = "contoso.local";

        let matches = cred_username.to_lowercase() == source_user.to_lowercase()
            && (source_domain.is_empty()
                || cred_domain.to_lowercase() == source_domain.to_lowercase());
        assert!(matches);
    }

    #[test]
    fn credential_matching_wrong_user() {
        let source_user = "admin";
        let source_domain = "contoso.local";
        let cred_username = "jdoe";
        let cred_domain = "contoso.local";

        let matches = cred_username.to_lowercase() == source_user.to_lowercase()
            && (source_domain.is_empty()
                || cred_domain.to_lowercase() == source_domain.to_lowercase());
        assert!(!matches);
    }

    #[test]
    fn credential_matching_wrong_domain() {
        let source_user = "admin";
        let source_domain = "contoso.local";
        let cred_username = "admin";
        let cred_domain = "fabrikam.local";

        let matches = cred_username.to_lowercase() == source_user.to_lowercase()
            && (source_domain.is_empty()
                || cred_domain.to_lowercase() == source_domain.to_lowercase());
        assert!(!matches);
    }

    #[test]
    fn dacl_payload_structure() {
        let payload = serde_json::json!({
            "technique": "dacl_abuse",
            "acl_type": "forcechangepassword",
            "vuln_id": "vuln-acl-001",
            "source_user": "admin",
            "target_user": "victim",
            "target_ip": "192.168.58.10",
            "domain": "contoso.local",
            "credential": {
                "username": "admin",
                "password": "P@ssw0rd!",
                "domain": "contoso.local",
            },
        });
        assert_eq!(payload["technique"], "dacl_abuse");
        assert_eq!(payload["acl_type"], "forcechangepassword");
        assert_eq!(payload["source_user"], "admin");
        assert_eq!(payload["target_user"], "victim");
        assert_eq!(payload["credential"]["domain"], "contoso.local");
    }

    #[test]
    fn acl_vuln_type_case_insensitive() {
        for t in [
            "ForceChangePassword",
            "FORCECHANGEPASSWORD",
            "forcechangepassword",
        ] {
            let vtype = t.to_lowercase();
            assert!(vtype.contains("forcechangepassword"), "{t} should match");
        }
    }

    #[test]
    fn source_user_from_key() {
        let details = serde_json::json!({"from": "svc_account"});
        let source = details
            .get("source")
            .or_else(|| details.get("source_user"))
            .or_else(|| details.get("from"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        assert_eq!(source, "svc_account");
    }

    // -- collect_dacl_work integration tests --

    use crate::orchestrator::state::SharedState;
    use ares_core::models::{Credential, VulnerabilityInfo};
    use std::collections::HashMap;

    fn make_credential(username: &str, domain: &str) -> Credential {
        Credential {
            id: format!("cred-{username}"),
            username: username.to_string(),
            password: "P@ssw0rd!".to_string(), // pragma: allowlist secret
            domain: domain.to_string(),
            source: String::new(),
            discovered_at: None,
            is_admin: false,
            parent_id: None,
            attack_step: 0,
        }
    }

    fn make_vuln(
        vuln_id: &str,
        vuln_type: &str,
        details: HashMap<String, serde_json::Value>,
    ) -> VulnerabilityInfo {
        VulnerabilityInfo {
            vuln_id: vuln_id.to_string(),
            vuln_type: vuln_type.to_string(),
            target: "192.168.58.10".to_string(),
            discovered_by: "bloodhound".to_string(),
            discovered_at: chrono::Utc::now(),
            details,
            recommended_agent: String::new(),
            priority: 5,
        }
    }

    fn acl_details(source: &str, target: &str, domain: &str) -> HashMap<String, serde_json::Value> {
        let mut m = HashMap::new();
        m.insert("source".to_string(), serde_json::json!(source));
        m.insert("target".to_string(), serde_json::json!(target));
        m.insert("source_domain".to_string(), serde_json::json!(domain));
        m
    }

    #[tokio::test]
    async fn collect_empty_state_no_work() {
        let shared = SharedState::new("test".into());
        let state = shared.read().await;
        let work = collect_dacl_work(&state);
        assert!(work.is_empty());
    }

    #[tokio::test]
    async fn collect_no_credentials_no_work() {
        let shared = SharedState::new("test".into());
        {
            let mut state = shared.write().await;
            let details = acl_details("admin", "victim", "contoso.local");
            let vuln = make_vuln("vuln-001", "ForceChangePassword", details);
            state
                .discovered_vulnerabilities
                .insert(vuln.vuln_id.clone(), vuln);
        }
        let state = shared.read().await;
        let work = collect_dacl_work(&state);
        assert!(work.is_empty());
    }

    #[tokio::test]
    async fn collect_forcechangepassword_produces_work() {
        let shared = SharedState::new("test".into());
        {
            let mut state = shared.write().await;
            state
                .credentials
                .push(make_credential("admin", "contoso.local"));
            let details = acl_details("admin", "victim", "contoso.local");
            let vuln = make_vuln("vuln-fcp-001", "ForceChangePassword", details);
            state
                .discovered_vulnerabilities
                .insert(vuln.vuln_id.clone(), vuln);
        }

        let state = shared.read().await;
        let work = collect_dacl_work(&state);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].vuln_type, "forcechangepassword");
        assert_eq!(work[0].source_user, "admin");
        assert_eq!(work[0].target_user, "victim");
        assert_eq!(work[0].domain, "contoso.local");
    }

    #[tokio::test]
    async fn collect_genericwrite_produces_work() {
        let shared = SharedState::new("test".into());
        {
            let mut state = shared.write().await;
            state
                .credentials
                .push(make_credential("svc_sql", "contoso.local"));
            let details = acl_details("svc_sql", "targetuser", "contoso.local");
            let vuln = make_vuln("vuln-gw-001", "GenericWrite", details);
            state
                .discovered_vulnerabilities
                .insert(vuln.vuln_id.clone(), vuln);
        }

        let state = shared.read().await;
        let work = collect_dacl_work(&state);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].vuln_type, "genericwrite");
    }

    #[tokio::test]
    async fn collect_writedacl_produces_work() {
        let shared = SharedState::new("test".into());
        {
            let mut state = shared.write().await;
            state
                .credentials
                .push(make_credential("operator", "contoso.local"));
            let details = acl_details("operator", "targetobj", "contoso.local");
            let vuln = make_vuln("vuln-wd-001", "WriteDacl", details);
            state
                .discovered_vulnerabilities
                .insert(vuln.vuln_id.clone(), vuln);
        }

        let state = shared.read().await;
        let work = collect_dacl_work(&state);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].vuln_type, "writedacl");
    }

    #[tokio::test]
    async fn collect_writeowner_produces_work() {
        let shared = SharedState::new("test".into());
        {
            let mut state = shared.write().await;
            state
                .credentials
                .push(make_credential("operator", "contoso.local"));
            let details = acl_details("operator", "targetobj", "contoso.local");
            let vuln = make_vuln("vuln-wo-001", "WriteOwner", details);
            state
                .discovered_vulnerabilities
                .insert(vuln.vuln_id.clone(), vuln);
        }

        let state = shared.read().await;
        let work = collect_dacl_work(&state);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].vuln_type, "writeowner");
    }

    #[tokio::test]
    async fn collect_genericall_produces_work() {
        let shared = SharedState::new("test".into());
        {
            let mut state = shared.write().await;
            state
                .credentials
                .push(make_credential("admin", "contoso.local"));
            let details = acl_details("admin", "victim", "contoso.local");
            let vuln = make_vuln("vuln-ga-001", "GenericAll", details);
            state
                .discovered_vulnerabilities
                .insert(vuln.vuln_id.clone(), vuln);
        }

        let state = shared.read().await;
        let work = collect_dacl_work(&state);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].vuln_type, "genericall");
    }

    #[tokio::test]
    async fn collect_self_membership_produces_work() {
        let shared = SharedState::new("test".into());
        {
            let mut state = shared.write().await;
            state
                .credentials
                .push(make_credential("user1", "contoso.local"));
            let details = acl_details("user1", "Domain Admins", "contoso.local");
            let vuln = make_vuln("vuln-sm-001", "self_membership", details);
            state
                .discovered_vulnerabilities
                .insert(vuln.vuln_id.clone(), vuln);
        }

        let state = shared.read().await;
        let work = collect_dacl_work(&state);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].vuln_type, "self_membership");
    }

    #[tokio::test]
    async fn collect_sid_source_resolves_via_domain_admin() {
        // BloodHound emits ACL edges where the source is a SID for a
        // well-known group (e.g. Enterprise Admins ending in -519). The
        // resolver should pick any DA-marked credential in the same domain.
        let shared = SharedState::new("test".into());
        {
            let mut state = shared.write().await;
            let mut da = make_credential("admin", "contoso.local");
            da.is_admin = true;
            state.credentials.push(da);
            state.domain_sids.insert(
                "contoso.local".to_string(),
                "S-1-5-21-111-222-333".to_string(),
            );
            let details = acl_details("S-1-5-21-111-222-333-519", "victim", "contoso.local");
            let vuln = make_vuln("vuln-sid-001", "GenericAll", details);
            state
                .discovered_vulnerabilities
                .insert(vuln.vuln_id.clone(), vuln);
        }

        let state = shared.read().await;
        let work = collect_dacl_work(&state);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].credential.username, "admin");
        assert_eq!(work[0].vuln_type, "genericall");
        // source_user must be the resolved cred's SAM, not the raw SID — the
        // credential_resolver looks up password by `(username, domain)`, and
        // a SID never matches a credential record.
        assert_eq!(work[0].source_user, "admin");
    }

    #[tokio::test]
    async fn collect_sid_source_non_privileged_rid_skipped() {
        // Only well-known privileged RIDs are auto-resolved; an arbitrary
        // user SID (RID >= 1000) requires an exact match.
        let shared = SharedState::new("test".into());
        {
            let mut state = shared.write().await;
            let mut da = make_credential("admin", "contoso.local");
            da.is_admin = true;
            state.credentials.push(da);
            state.domain_sids.insert(
                "contoso.local".to_string(),
                "S-1-5-21-111-222-333".to_string(),
            );
            let details = acl_details("S-1-5-21-111-222-333-1105", "victim", "contoso.local");
            let vuln = make_vuln("vuln-sid-002", "GenericAll", details);
            state
                .discovered_vulnerabilities
                .insert(vuln.vuln_id.clone(), vuln);
        }

        let state = shared.read().await;
        let work = collect_dacl_work(&state);
        assert!(work.is_empty());
    }

    #[tokio::test]
    async fn collect_write_membership_produces_work() {
        let shared = SharedState::new("test".into());
        {
            let mut state = shared.write().await;
            state
                .credentials
                .push(make_credential("user1", "contoso.local"));
            let details = acl_details("user1", "Domain Admins", "contoso.local");
            let vuln = make_vuln("vuln-wm-001", "write_membership", details);
            state
                .discovered_vulnerabilities
                .insert(vuln.vuln_id.clone(), vuln);
        }

        let state = shared.read().await;
        let work = collect_dacl_work(&state);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].vuln_type, "write_membership");
    }

    #[tokio::test]
    async fn collect_non_acl_vuln_skipped() {
        let shared = SharedState::new("test".into());
        {
            let mut state = shared.write().await;
            state
                .credentials
                .push(make_credential("admin", "contoso.local"));
            let details = acl_details("admin", "dc01", "contoso.local");
            let vuln = make_vuln("vuln-smb-001", "smb_signing_disabled", details);
            state
                .discovered_vulnerabilities
                .insert(vuln.vuln_id.clone(), vuln);
        }

        let state = shared.read().await;
        let work = collect_dacl_work(&state);
        assert!(work.is_empty());
    }

    #[tokio::test]
    async fn collect_already_exploited_skipped() {
        let shared = SharedState::new("test".into());
        {
            let mut state = shared.write().await;
            state
                .credentials
                .push(make_credential("admin", "contoso.local"));
            let details = acl_details("admin", "victim", "contoso.local");
            let vuln = make_vuln("vuln-fcp-002", "ForceChangePassword", details);
            state
                .discovered_vulnerabilities
                .insert(vuln.vuln_id.clone(), vuln);
            state
                .exploited_vulnerabilities
                .insert("vuln-fcp-002".to_string());
        }

        let state = shared.read().await;
        let work = collect_dacl_work(&state);
        assert!(work.is_empty());
    }

    #[tokio::test]
    async fn collect_already_processed_dedup_skipped() {
        let shared = SharedState::new("test".into());
        {
            let mut state = shared.write().await;
            state
                .credentials
                .push(make_credential("admin", "contoso.local"));
            let details = acl_details("admin", "victim", "contoso.local");
            let vuln = make_vuln("vuln-fcp-003", "ForceChangePassword", details);
            state
                .discovered_vulnerabilities
                .insert(vuln.vuln_id.clone(), vuln);
            state.mark_processed(DEDUP_DACL_ABUSE, "dacl:vuln-fcp-003".to_string());
        }

        let state = shared.read().await;
        let work = collect_dacl_work(&state);
        assert!(work.is_empty());
    }

    #[tokio::test]
    async fn collect_source_user_empty_skipped() {
        let shared = SharedState::new("test".into());
        {
            let mut state = shared.write().await;
            state
                .credentials
                .push(make_credential("admin", "contoso.local"));
            let mut details = HashMap::new();
            details.insert("target".to_string(), serde_json::json!("victim"));
            let vuln = make_vuln("vuln-fcp-004", "ForceChangePassword", details);
            state
                .discovered_vulnerabilities
                .insert(vuln.vuln_id.clone(), vuln);
        }

        let state = shared.read().await;
        let work = collect_dacl_work(&state);
        assert!(work.is_empty());
    }

    #[tokio::test]
    async fn collect_no_matching_credential_skipped() {
        let shared = SharedState::new("test".into());
        {
            let mut state = shared.write().await;
            state
                .credentials
                .push(make_credential("otheruser", "contoso.local"));
            let details = acl_details("admin", "victim", "contoso.local");
            let vuln = make_vuln("vuln-fcp-005", "ForceChangePassword", details);
            state
                .discovered_vulnerabilities
                .insert(vuln.vuln_id.clone(), vuln);
        }

        let state = shared.read().await;
        let work = collect_dacl_work(&state);
        assert!(work.is_empty());
    }

    #[tokio::test]
    async fn collect_case_insensitive_credential_match() {
        let shared = SharedState::new("test".into());
        {
            let mut state = shared.write().await;
            state
                .credentials
                .push(make_credential("Admin", "CONTOSO.LOCAL"));
            let details = acl_details("admin", "victim", "contoso.local");
            let vuln = make_vuln("vuln-fcp-006", "ForceChangePassword", details);
            state
                .discovered_vulnerabilities
                .insert(vuln.vuln_id.clone(), vuln);
        }

        let state = shared.read().await;
        let work = collect_dacl_work(&state);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].source_user, "admin");
    }

    #[tokio::test]
    async fn collect_dc_ip_resolved_from_domain_controllers() {
        let shared = SharedState::new("test".into());
        {
            let mut state = shared.write().await;
            state
                .credentials
                .push(make_credential("admin", "contoso.local"));
            state
                .domain_controllers
                .insert("contoso.local".to_string(), "192.168.58.10".to_string());
            let details = acl_details("admin", "victim", "contoso.local");
            let vuln = make_vuln("vuln-fcp-007", "ForceChangePassword", details);
            state
                .discovered_vulnerabilities
                .insert(vuln.vuln_id.clone(), vuln);
        }

        let state = shared.read().await;
        let work = collect_dacl_work(&state);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].dc_ip, "192.168.58.10");
    }

    #[tokio::test]
    async fn collect_dc_ip_empty_when_no_dc_mapping() {
        let shared = SharedState::new("test".into());
        {
            let mut state = shared.write().await;
            state
                .credentials
                .push(make_credential("admin", "contoso.local"));
            let details = acl_details("admin", "victim", "contoso.local");
            let vuln = make_vuln("vuln-fcp-008", "ForceChangePassword", details);
            state
                .discovered_vulnerabilities
                .insert(vuln.vuln_id.clone(), vuln);
        }

        let state = shared.read().await;
        let work = collect_dacl_work(&state);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].dc_ip, "");
    }

    #[tokio::test]
    async fn collect_credential_domain_mismatch_skipped() {
        let shared = SharedState::new("test".into());
        {
            let mut state = shared.write().await;
            state
                .credentials
                .push(make_credential("admin", "fabrikam.local"));
            let details = acl_details("admin", "victim", "contoso.local");
            let vuln = make_vuln("vuln-fcp-009", "ForceChangePassword", details);
            state
                .discovered_vulnerabilities
                .insert(vuln.vuln_id.clone(), vuln);
        }

        let state = shared.read().await;
        let work = collect_dacl_work(&state);
        assert!(work.is_empty());
    }

    #[tokio::test]
    async fn collect_empty_source_domain_matches_any_cred_domain() {
        let shared = SharedState::new("test".into());
        {
            let mut state = shared.write().await;
            state
                .credentials
                .push(make_credential("admin", "fabrikam.local"));
            let mut details = HashMap::new();
            details.insert("source".to_string(), serde_json::json!("admin"));
            details.insert("target".to_string(), serde_json::json!("victim"));
            let vuln = make_vuln("vuln-fcp-010", "ForceChangePassword", details);
            state
                .discovered_vulnerabilities
                .insert(vuln.vuln_id.clone(), vuln);
        }

        let state = shared.read().await;
        let work = collect_dacl_work(&state);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].domain, "fabrikam.local");
    }

    #[tokio::test]
    async fn collect_multiple_vulns_produces_multiple_work_items() {
        let shared = SharedState::new("test".into());
        {
            let mut state = shared.write().await;
            state
                .credentials
                .push(make_credential("admin", "contoso.local"));

            for (i, vtype) in ["ForceChangePassword", "GenericAll", "WriteDacl"]
                .iter()
                .enumerate()
            {
                let details = acl_details("admin", &format!("target{i}"), "contoso.local");
                let vuln = make_vuln(&format!("vuln-multi-{i}"), vtype, details);
                state
                    .discovered_vulnerabilities
                    .insert(vuln.vuln_id.clone(), vuln);
            }
        }

        let state = shared.read().await;
        let work = collect_dacl_work(&state);
        assert_eq!(work.len(), 3);
    }

    #[tokio::test]
    async fn collect_dedup_key_format_matches() {
        let shared = SharedState::new("test".into());
        {
            let mut state = shared.write().await;
            state
                .credentials
                .push(make_credential("admin", "contoso.local"));
            let details = acl_details("admin", "victim", "contoso.local");
            let vuln = make_vuln("vuln-dk-001", "GenericAll", details);
            state
                .discovered_vulnerabilities
                .insert(vuln.vuln_id.clone(), vuln);
        }

        let state = shared.read().await;
        let work = collect_dacl_work(&state);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].dedup_key, "dacl:vuln-dk-001");
    }

    #[tokio::test]
    async fn collect_source_user_fallback_to_from_key() {
        let shared = SharedState::new("test".into());
        {
            let mut state = shared.write().await;
            state
                .credentials
                .push(make_credential("svc_account", "contoso.local"));
            let mut details = HashMap::new();
            details.insert("from".to_string(), serde_json::json!("svc_account"));
            details.insert("target".to_string(), serde_json::json!("victim"));
            details.insert(
                "source_domain".to_string(),
                serde_json::json!("contoso.local"),
            );
            let vuln = make_vuln("vuln-from-001", "GenericWrite", details);
            state
                .discovered_vulnerabilities
                .insert(vuln.vuln_id.clone(), vuln);
        }

        let state = shared.read().await;
        let work = collect_dacl_work(&state);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].source_user, "svc_account");
    }

    fn make_hash(username: &str, domain: &str) -> ares_core::models::Hash {
        ares_core::models::Hash {
            id: format!("hash-{username}"),
            username: username.to_string(),
            hash_value: "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0".into(), // pragma: allowlist secret
            hash_type: "NTLM".into(),
            domain: domain.to_string(),
            cracked_password: None,
            source: String::new(),
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

    #[tokio::test]
    async fn collect_skips_when_domain_already_dominated() {
        let shared = SharedState::new("test".into());
        {
            let mut state = shared.write().await;
            state
                .credentials
                .push(make_credential("admin", "contoso.local"));
            let details = acl_details("admin", "victim", "contoso.local");
            let vuln = make_vuln("vuln-dom-001", "ForceChangePassword", details);
            state
                .discovered_vulnerabilities
                .insert(vuln.vuln_id.clone(), vuln);
            state.dominated_domains.insert("contoso.local".to_string());
        }

        let state = shared.read().await;
        let work = collect_dacl_work(&state);
        assert!(
            work.is_empty(),
            "ACL chain must be suppressed once domain is dominated"
        );
    }

    #[tokio::test]
    async fn collect_defers_when_credential_capture_in_flight() {
        let shared = SharedState::new("test".into());
        {
            let mut state = shared.write().await;
            state
                .credentials
                .push(make_credential("admin", "contoso.local"));
            let details = acl_details("admin", "victim", "contoso.local");
            let vuln = make_vuln("vuln-flight-001", "ForceChangePassword", details);
            state
                .discovered_vulnerabilities
                .insert(vuln.vuln_id.clone(), vuln);
            state.mark_credential_capture_in_flight("contoso.local");
        }

        let state = shared.read().await;
        let work = collect_dacl_work(&state);
        assert!(
            work.is_empty(),
            "ACL chain must defer while DCSync is in flight"
        );
    }

    #[tokio::test]
    async fn collect_skips_destructive_when_target_hash_already_present() {
        let shared = SharedState::new("test".into());
        {
            let mut state = shared.write().await;
            state
                .credentials
                .push(make_credential("admin", "contoso.local"));
            state.hashes.push(make_hash("victim", "contoso.local"));
            let details = acl_details("admin", "victim", "contoso.local");
            let vuln = make_vuln("vuln-mat-001", "ForceChangePassword", details);
            state
                .discovered_vulnerabilities
                .insert(vuln.vuln_id.clone(), vuln);
        }

        let state = shared.read().await;
        let work = collect_dacl_work(&state);
        assert!(
            work.is_empty(),
            "ForceChangePassword must be suppressed when target hash is in state"
        );
    }

    #[tokio::test]
    async fn collect_skips_destructive_when_target_credential_already_present() {
        let shared = SharedState::new("test".into());
        {
            let mut state = shared.write().await;
            state
                .credentials
                .push(make_credential("admin", "contoso.local"));
            state
                .credentials
                .push(make_credential("victim", "contoso.local"));
            let details = acl_details("admin", "victim", "contoso.local");
            let vuln = make_vuln("vuln-mat-002", "GenericAll", details);
            state
                .discovered_vulnerabilities
                .insert(vuln.vuln_id.clone(), vuln);
        }

        let state = shared.read().await;
        let work = collect_dacl_work(&state);
        assert!(
            work.is_empty(),
            "GenericAll must be suppressed when target credential is in state"
        );
    }

    #[tokio::test]
    async fn collect_allows_non_destructive_acl_when_target_material_present() {
        let shared = SharedState::new("test".into());
        {
            let mut state = shared.write().await;
            state
                .credentials
                .push(make_credential("admin", "contoso.local"));
            state.hashes.push(make_hash("victim", "contoso.local"));
            let details = acl_details("admin", "victim", "contoso.local");
            let vuln = make_vuln("vuln-gw-002", "GenericWrite", details);
            state
                .discovered_vulnerabilities
                .insert(vuln.vuln_id.clone(), vuln);
        }

        let state = shared.read().await;
        let work = collect_dacl_work(&state);
        assert_eq!(
            work.len(),
            1,
            "Non-destructive ACL types must still dispatch"
        );
    }

    #[tokio::test]
    async fn collect_target_user_fallback_to_target_user_key() {
        let shared = SharedState::new("test".into());
        {
            let mut state = shared.write().await;
            state
                .credentials
                .push(make_credential("admin", "contoso.local"));
            let mut details = HashMap::new();
            details.insert("source".to_string(), serde_json::json!("admin"));
            details.insert(
                "target_user".to_string(),
                serde_json::json!("fallback_target"),
            );
            details.insert(
                "source_domain".to_string(),
                serde_json::json!("contoso.local"),
            );
            let vuln = make_vuln("vuln-tu-001", "WriteDacl", details);
            state
                .discovered_vulnerabilities
                .insert(vuln.vuln_id.clone(), vuln);
        }

        let state = shared.read().await;
        let work = collect_dacl_work(&state);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].target_user, "fallback_target");
    }
}
