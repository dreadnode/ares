//! auto_sid_history_enum -- detect users carrying foreign-domain SIDs via
//! the `sIDHistory` LDAP attribute.
//!
//! Background: `sIDHistory` is intended for migration scenarios — when a
//! principal moves between domains, the old SID is appended so the user
//! retains access to resources ACLed by the old SID. Attackers also forge
//! `sIDHistory` (post-DA on a child) so a low-priv principal in the child
//! domain carries a privileged ExtraSid from the parent (e.g. EAs) into
//! every Kerberos service ticket. SID-filtering on the trust strips these
//! at the boundary; misconfigured trusts (or intra-forest paths) let them
//! through. Either way, *any* user with a non-empty `sIDHistory` containing
//! a foreign-domain SID is an exploitable primitive.
//!
//! This automation issues an LDAP query `(sIDHistory=*)` per DC and emits
//! one `sid_history_<user>` vulnerability per match. Because *discovery*
//! of an exploitable sIDHistory is the achievement (the next ticket forge
//! can ride the SID directly via `ticketer --extra-sid`), we also call
//! `mark_exploited` on the same vuln_id immediately — matching the
//! scoreboard's expectation that the primitive is credited on detection.
//!
//! Interval: 60s — read-only LDAP, but no rush; we want trust enumeration
//! to populate domain credentials first.

use std::sync::Arc;
use std::time::Duration;

use serde_json::json;
use tokio::sync::watch;
use tracing::{debug, info, warn};

use ares_llm::ToolCall;

use crate::orchestrator::dispatcher::Dispatcher;
use crate::orchestrator::state::*;

struct SidHistoryWork {
    dedup_key: String,
    domain: String,
    dc_ip: String,
    credential: ares_core::models::Credential,
}

/// Collect SID-history enumeration work items from current state.
///
/// One item per (domain, DC) pair, gated on a same-forest credential being
/// available. Same forest because LDAP bind across a forest trust returns
/// 52e — there's no point dispatching the probe with a credential whose
/// realm the target DC doesn't trust.
fn collect_sid_history_work(state: &StateInner) -> Vec<SidHistoryWork> {
    if state.credentials.is_empty() {
        return Vec::new();
    }

    let mut items = Vec::new();
    for (domain, dc_ip) in &state.all_domains_with_dcs() {
        let dedup_key = format!("sid_history:{}", domain.to_lowercase());
        if state.is_processed(DEDUP_SID_HISTORY, &dedup_key) {
            continue;
        }

        // Prefer a credential whose domain matches the target. Fall back to
        // any same-forest credential. Skip if no candidate exists.
        let domain_lower = domain.to_lowercase();
        let target_forest = state.forest_root_of(&domain_lower);
        let cred = state
            .credentials
            .iter()
            .find(|c| {
                !c.password.is_empty()
                    && c.domain.to_lowercase() == domain_lower
                    && !state.is_delegation_account(&c.username)
                    && !state.is_principal_quarantined(&c.username, &c.domain)
            })
            .or_else(|| {
                state.credentials.iter().find(|c| {
                    !c.password.is_empty()
                        && state.forest_root_of(&c.domain.to_lowercase()) == target_forest
                        && !state.is_delegation_account(&c.username)
                        && !state.is_principal_quarantined(&c.username, &c.domain)
                })
            });

        let cred = match cred {
            Some(c) => c.clone(),
            None => continue,
        };

        items.push(SidHistoryWork {
            dedup_key,
            domain: domain.clone(),
            dc_ip: dc_ip.clone(),
            credential: cred,
        });
    }
    items
}

/// Build the `ldap_search` payload for a single SID-history work item.
/// Splits out so the cross-domain `bind_domain` branch can be unit tested
/// without spinning a Dispatcher.
fn build_sid_history_payload(item: &SidHistoryWork) -> serde_json::Value {
    let mut args = json!({
        "target": item.dc_ip,
        "domain": item.domain,
        "username": item.credential.username,
        "password": item.credential.password,
        "filter": "(sIDHistory=*)",
        "attributes": "sAMAccountName,sIDHistory",
    });
    // Cross-domain bind: ldapsearch needs the credential's realm to
    // construct the right bind DN even when querying a different
    // domain's partition.
    if item.credential.domain.to_lowercase() != item.domain.to_lowercase() {
        args["bind_domain"] = json!(item.credential.domain);
    }
    args
}

/// Build the `sid_history_abuse` `VulnerabilityInfo` for a discovered principal.
/// Splits out so the (vuln_id format, vuln_type, target, details) shape can be
/// asserted without running the async dispatch loop. `priority = 3` and
/// `discovered_by = "sid_history_enum"` are fixed.
fn build_sid_history_vuln(principal: &str, domain: &str) -> ares_core::models::VulnerabilityInfo {
    let vuln_id = format!("sid_history_{}", principal.to_lowercase());
    let mut details = std::collections::HashMap::new();
    details.insert(
        "domain".into(),
        serde_json::Value::String(domain.to_string()),
    );
    details.insert(
        "account_name".into(),
        serde_json::Value::String(principal.to_string()),
    );
    details.insert(
        "note".into(),
        serde_json::Value::String(
            "Foreign-domain SID present in sIDHistory — \
             usable as --extra-sid in ticketer / Golden Ticket forge."
                .into(),
        ),
    );
    ares_core::models::VulnerabilityInfo {
        vuln_id,
        vuln_type: "sid_history_abuse".to_string(),
        target: domain.to_string(),
        discovered_by: "sid_history_enum".to_string(),
        discovered_at: chrono::Utc::now(),
        details,
        recommended_agent: String::new(),
        priority: 3,
    }
}

/// Periodic SID-history discovery. Dispatches `ldap_search` deterministically
/// via the tool dispatcher (no LLM round-trip) since the query, filter, and
/// expected output shape are all fixed.
pub async fn auto_sid_history_enum(
    dispatcher: Arc<Dispatcher>,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut interval = tokio::time::interval(Duration::from_secs(60));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            _ = interval.tick() => {},
            _ = shutdown.changed() => break,
        }
        if *shutdown.borrow() {
            break;
        }

        if !dispatcher.is_technique_allowed("sid_history_enum") {
            continue;
        }

        let work: Vec<SidHistoryWork> = {
            let state = dispatcher.state.read().await;
            collect_sid_history_work(&state)
        };

        for item in work {
            let args = build_sid_history_payload(&item);

            let call = ToolCall {
                id: format!("sid_history_{}", uuid::Uuid::new_v4().simple()),
                name: "ldap_search".to_string(),
                arguments: args,
            };
            let task_id = format!(
                "sid_history_{}",
                &uuid::Uuid::new_v4().simple().to_string()[..12]
            );

            // Mark dedup BEFORE spawn so the next tick doesn't re-dispatch
            // against the same domain. The bg task clears dedup on a
            // transport-level failure so a later cred can retry.
            dispatcher
                .state
                .write()
                .await
                .mark_processed(DEDUP_SID_HISTORY, item.dedup_key.clone());
            let _ = dispatcher
                .state
                .persist_dedup(&dispatcher.queue, DEDUP_SID_HISTORY, &item.dedup_key)
                .await;

            info!(
                task_id = %task_id,
                domain = %item.domain,
                dc = %item.dc_ip,
                "SID history enumeration dispatched"
            );

            let dispatcher_bg = dispatcher.clone();
            let domain_bg = item.domain.clone();
            let dedup_key_bg = item.dedup_key.clone();
            tokio::spawn(async move {
                let result = dispatcher_bg
                    .llm_runner
                    .tool_dispatcher()
                    .dispatch_tool("recon", &task_id, &call)
                    .await;
                match result {
                    Ok(exec) => {
                        if let Some(err) = exec.error.as_ref() {
                            warn!(
                                task_id = %task_id,
                                domain = %domain_bg,
                                err = %err,
                                "ldap_search for sIDHistory failed — clearing dedup"
                            );
                            dispatcher_bg
                                .state
                                .write()
                                .await
                                .unmark_processed(DEDUP_SID_HISTORY, &dedup_key_bg);
                            let _ = dispatcher_bg
                                .state
                                .unpersist_dedup(
                                    &dispatcher_bg.queue,
                                    DEDUP_SID_HISTORY,
                                    &dedup_key_bg,
                                )
                                .await;
                            return;
                        }
                        let principals = parse_sid_history_output(&exec.output);
                        if principals.is_empty() {
                            debug!(
                                task_id = %task_id,
                                domain = %domain_bg,
                                "ldap_search returned no sIDHistory matches"
                            );
                            return;
                        }
                        for principal in principals {
                            let vuln = build_sid_history_vuln(&principal, &domain_bg);
                            let vuln_id = vuln.vuln_id.clone();
                            let _ = dispatcher_bg
                                .state
                                .publish_vulnerability(&dispatcher_bg.queue, vuln)
                                .await;
                            // Detection = achievement for the scoreboard token;
                            // the SID is already usable for ticket forging.
                            if let Err(e) = dispatcher_bg
                                .state
                                .mark_exploited(&dispatcher_bg.queue, &vuln_id)
                                .await
                            {
                                warn!(
                                    err = %e,
                                    vuln_id = %vuln_id,
                                    "Failed to mark sid_history exploited"
                                );
                            } else {
                                info!(
                                    vuln_id = %vuln_id,
                                    domain = %domain_bg,
                                    account = %principal,
                                    "sIDHistory primitive surfaced — exploit token emitted"
                                );
                            }
                        }
                    }
                    Err(e) => {
                        warn!(
                            task_id = %task_id,
                            domain = %domain_bg,
                            err = %e,
                            "ldap_search dispatch errored — clearing dedup"
                        );
                        dispatcher_bg
                            .state
                            .write()
                            .await
                            .unmark_processed(DEDUP_SID_HISTORY, &dedup_key_bg);
                        let _ = dispatcher_bg
                            .state
                            .unpersist_dedup(&dispatcher_bg.queue, DEDUP_SID_HISTORY, &dedup_key_bg)
                            .await;
                    }
                }
            });
        }
    }
}

/// Parse `ldapsearch` output for principals carrying a non-empty `sIDHistory`
/// attribute. Returns the deduplicated set of `sAMAccountName` values for
/// matching entries. A single LDIF block looks like:
///
/// ```text
/// dn: CN=Migrated User,CN=Users,DC=...
/// sAMAccountName: migrated.user
/// sIDHistory:: <base64 SID>
/// ```
///
/// We tolerate `sIDHistory` and `sIDHistory::` (base64) and `sIDHistory:`
/// (textual) plus arbitrary whitespace.
fn parse_sid_history_output(output: &str) -> Vec<String> {
    let mut current_sam: Option<String> = None;
    let mut current_has_sid_history = false;
    let mut out: Vec<String> = Vec::new();
    let mut seen = std::collections::HashSet::new();

    for line in output.lines() {
        let trimmed = line.trim_end();
        // Entry boundary: blank line or new `dn:` resets the in-flight block.
        if trimmed.is_empty() || trimmed.starts_with("dn:") {
            if let Some(sam) = current_sam.take() {
                if current_has_sid_history && seen.insert(sam.to_lowercase()) {
                    out.push(sam);
                }
            }
            current_has_sid_history = false;
            continue;
        }
        if let Some(rest) = strip_attribute_prefix(trimmed, "sAMAccountName") {
            if !rest.is_empty() {
                current_sam = Some(rest.to_string());
            }
        } else if strip_attribute_prefix(trimmed, "sIDHistory").is_some() {
            current_has_sid_history = true;
        }
    }
    // Flush the final block.
    if let Some(sam) = current_sam {
        if current_has_sid_history && seen.insert(sam.to_lowercase()) {
            out.push(sam);
        }
    }
    out
}

/// Strip an LDIF-style attribute prefix (handles `name:`, `name::`, and
/// surrounding whitespace). Returns the value portion when the line is for
/// `attr_name`; returns `None` otherwise. Comparison is case-insensitive
/// because some LDAP servers normalise attribute case differently.
fn strip_attribute_prefix<'a>(line: &'a str, attr_name: &str) -> Option<&'a str> {
    let lower = line.to_ascii_lowercase();
    let needle = attr_name.to_ascii_lowercase();
    let prefix = lower.strip_prefix(&needle)?;
    // After the attribute name, expect `:` or `::` (base64 marker).
    let after = prefix.trim_start();
    let after = after.strip_prefix(':')?;
    // Optional second colon for base64 values.
    let after = after.strip_prefix(':').unwrap_or(after);
    // Map back from the lowercased view to the original slice so caller gets
    // the case-preserving value.
    let consumed = line.len() - after.len();
    Some(line[consumed..].trim())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cred(username: &str, password: &str, domain: &str) -> ares_core::models::Credential {
        ares_core::models::Credential {
            id: format!("c-{username}"),
            username: username.into(),
            password: password.into(), // pragma: allowlist secret
            domain: domain.into(),
            source: "test".into(),
            is_admin: false,
            discovered_at: None,
            parent_id: None,
            attack_step: 0,
        }
    }

    #[test]
    fn parse_extracts_account_with_sid_history() {
        let output = "\
dn: CN=Alice,CN=Users,DC=contoso,DC=local
sAMAccountName: alice
sIDHistory:: AQUAAAAAAAUVAAAAAQAAAAAA

dn: CN=Bob,CN=Users,DC=contoso,DC=local
sAMAccountName: bob
";
        let principals = parse_sid_history_output(output);
        assert_eq!(principals, vec!["alice".to_string()]);
    }

    #[test]
    fn parse_handles_multiple_principals() {
        let output = "\
dn: CN=Alice
sAMAccountName: alice
sIDHistory: S-1-5-21-1-2-3-1000

dn: CN=Carol
sAMAccountName: carol
sIDHistory:: AAAA
";
        let mut got = parse_sid_history_output(output);
        got.sort();
        assert_eq!(got, vec!["alice".to_string(), "carol".to_string()]);
    }

    #[test]
    fn parse_skips_entries_without_sid_history() {
        let output = "\
dn: CN=Plain
sAMAccountName: plain

dn: CN=Other
sAMAccountName: other
";
        assert!(parse_sid_history_output(output).is_empty());
    }

    #[test]
    fn parse_handles_attribute_case_variants() {
        let output = "\
dn: CN=Alice
samaccountname: alice
SIDHISTORY:: AQID
";
        assert_eq!(parse_sid_history_output(output), vec!["alice".to_string()]);
    }

    #[test]
    fn parse_dedups_repeated_principals() {
        let output = "\
dn: CN=Alice
sAMAccountName: alice
sIDHistory: S-1-5-21-1-2-3-1000

dn: CN=Alice
sAMAccountName: ALICE
sIDHistory: S-1-5-21-9-9-9-1000
";
        assert_eq!(parse_sid_history_output(output), vec!["alice".to_string()]);
    }

    #[test]
    fn parse_empty_output() {
        assert!(parse_sid_history_output("").is_empty());
        assert!(parse_sid_history_output("# search result\nsearch: 2\n").is_empty());
    }

    #[test]
    fn collect_empty_state_no_work() {
        let state = StateInner::new("test-op".into());
        assert!(collect_sid_history_work(&state).is_empty());
    }

    #[test]
    fn collect_requires_same_forest_cred() {
        let mut state = StateInner::new("test-op".into());
        state
            .domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        // Cross-forest cred only — should NOT produce work for contoso.local.
        state
            .credentials
            .push(cred("alice", "P@ssw0rd!", "fabrikam.local")); // pragma: allowlist secret
        assert!(collect_sid_history_work(&state).is_empty());
    }

    #[test]
    fn collect_same_domain_cred_produces_work() {
        let mut state = StateInner::new("test-op".into());
        state
            .domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        state
            .credentials
            .push(cred("alice", "P@ssw0rd!", "contoso.local")); // pragma: allowlist secret
        let work = collect_sid_history_work(&state);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].domain, "contoso.local");
        assert_eq!(work[0].dc_ip, "192.168.58.10");
        assert_eq!(work[0].credential.username, "alice");
    }

    #[test]
    fn collect_dedup_skips_processed_domain() {
        let mut state = StateInner::new("test-op".into());
        state
            .domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        state
            .credentials
            .push(cred("alice", "P@ssw0rd!", "contoso.local")); // pragma: allowlist secret
        state.mark_processed(DEDUP_SID_HISTORY, "sid_history:contoso.local".into());
        assert!(collect_sid_history_work(&state).is_empty());
    }

    #[test]
    fn collect_one_item_per_domain() {
        let mut state = StateInner::new("test-op".into());
        state
            .domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        state
            .domain_controllers
            .insert("fabrikam.local".into(), "192.168.58.20".into());
        state
            .credentials
            .push(cred("alice", "P@ssw0rd!", "contoso.local")); // pragma: allowlist secret
        state
            .credentials
            .push(cred("bob", "P@ssw0rd!", "fabrikam.local")); // pragma: allowlist secret
        let work = collect_sid_history_work(&state);
        assert_eq!(work.len(), 2);
    }

    #[test]
    fn strip_attribute_prefix_basic() {
        assert_eq!(
            super::strip_attribute_prefix("sAMAccountName: alice", "sAMAccountName"),
            Some("alice")
        );
        assert_eq!(
            super::strip_attribute_prefix("sIDHistory:: AQID", "sIDHistory"),
            Some("AQID")
        );
        assert_eq!(
            super::strip_attribute_prefix("dn: CN=Alice", "sAMAccountName"),
            None
        );
    }

    // collect_sid_history_work — same-forest fallback path

    #[test]
    fn collect_same_forest_cross_domain_cred_falls_back() {
        // child.contoso.local DC discovered with no matching cred; a credential
        // for contoso.local (parent in same forest) should match via the
        // `forest_root_of` fallback. `forest_root_of` requires both domains
        // to be present in state.domains or state.domain_controllers, so we
        // register both.
        let mut state = StateInner::new("test-op".into());
        state.domains.push("contoso.local".into());
        state
            .domain_controllers
            .insert("child.contoso.local".into(), "192.168.58.20".into());
        state
            .domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        state
            .credentials
            .push(cred("alice", "P@ssw0rd!", "contoso.local")); // pragma: allowlist secret
        let work = collect_sid_history_work(&state);
        // Both DCs are eligible — contoso.local matches the same-domain
        // branch, child.contoso.local hits the same-forest fallback.
        assert_eq!(work.len(), 2);
        let child = work
            .iter()
            .find(|w| w.domain == "child.contoso.local")
            .expect("child.contoso.local missing — fallback didn't fire");
        assert_eq!(child.dc_ip, "192.168.58.20");
        assert_eq!(child.credential.domain, "contoso.local");
    }

    #[test]
    fn collect_quarantined_principal_skipped() {
        let mut state = StateInner::new("test-op".into());
        state
            .domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        state
            .credentials
            .push(cred("alice", "P@ssw0rd!", "contoso.local")); // pragma: allowlist secret
        state.quarantine_principal("alice", "contoso.local");
        assert!(collect_sid_history_work(&state).is_empty());
    }

    #[test]
    fn collect_skips_credentials_without_password() {
        let mut state = StateInner::new("test-op".into());
        state
            .domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        // empty password — must be skipped.
        state.credentials.push(cred("alice", "", "contoso.local"));
        assert!(collect_sid_history_work(&state).is_empty());
    }

    // build_sid_history_payload

    fn work_item(cred_domain: &str, target_domain: &str) -> SidHistoryWork {
        SidHistoryWork {
            dedup_key: format!("sid_history:{target_domain}"),
            domain: target_domain.into(),
            dc_ip: "192.168.58.10".into(),
            credential: cred("alice", "P@ssw0rd!", cred_domain),
        }
    }

    #[test]
    fn payload_includes_required_fields() {
        let payload = build_sid_history_payload(&work_item("contoso.local", "contoso.local"));
        assert_eq!(payload["target"], "192.168.58.10");
        assert_eq!(payload["domain"], "contoso.local");
        assert_eq!(payload["username"], "alice");
        assert_eq!(payload["password"], "P@ssw0rd!");
        assert_eq!(payload["filter"], "(sIDHistory=*)");
        assert_eq!(payload["attributes"], "sAMAccountName,sIDHistory");
    }

    #[test]
    fn payload_omits_bind_domain_for_same_domain_cred() {
        // Target == credential domain → no `bind_domain` key needed.
        let payload = build_sid_history_payload(&work_item("contoso.local", "contoso.local"));
        assert!(payload.get("bind_domain").is_none());
    }

    #[test]
    fn payload_sets_bind_domain_for_cross_domain_cred() {
        // Credential lives in parent, query targets child — ldapsearch needs
        // `bind_domain` to construct the right bind DN.
        let payload = build_sid_history_payload(&work_item("contoso.local", "child.contoso.local"));
        assert_eq!(payload["bind_domain"], "contoso.local");
    }

    #[test]
    fn payload_bind_domain_check_is_case_insensitive() {
        // Mixed case on either side must be normalized before comparison —
        // otherwise we'd emit a spurious bind_domain for `Contoso.local`/
        // `contoso.local`.
        let item = SidHistoryWork {
            dedup_key: "sid_history:contoso.local".into(),
            domain: "Contoso.LOCAL".into(),
            dc_ip: "192.168.58.10".into(),
            credential: cred("alice", "P@ssw0rd!", "CONTOSO.local"),
        };
        let payload = build_sid_history_payload(&item);
        assert!(payload.get("bind_domain").is_none());
    }

    // build_sid_history_vuln

    #[test]
    fn vuln_carries_required_scoreboard_tokens() {
        let v = build_sid_history_vuln("migrated.user", "contoso.local");
        assert_eq!(v.vuln_id, "sid_history_migrated.user");
        assert_eq!(v.vuln_type, "sid_history_abuse");
        assert_eq!(v.target, "contoso.local");
        assert_eq!(v.discovered_by, "sid_history_enum");
        assert_eq!(v.priority, 3);
        assert!(v.recommended_agent.is_empty());
    }

    #[test]
    fn vuln_lowercases_vuln_id_principal() {
        // Different casings of the same principal must collapse to one
        // vuln_id so the scoreboard counts the primitive once.
        let v1 = build_sid_history_vuln("Migrated.USER", "contoso.local");
        let v2 = build_sid_history_vuln("migrated.user", "contoso.local");
        assert_eq!(v1.vuln_id, v2.vuln_id);
    }

    #[test]
    fn vuln_details_populated() {
        let v = build_sid_history_vuln("alice", "contoso.local");
        assert_eq!(
            v.details.get("domain").and_then(|x| x.as_str()),
            Some("contoso.local")
        );
        assert_eq!(
            v.details.get("account_name").and_then(|x| x.as_str()),
            Some("alice")
        );
        let note = v.details.get("note").and_then(|x| x.as_str()).unwrap();
        assert!(note.contains("sIDHistory"));
        assert!(note.contains("extra-sid") || note.contains("--extra-sid"));
    }

    #[test]
    fn vuln_account_name_preserves_original_case() {
        // vuln_id is lowercased for dedup, but account_name in details keeps
        // the original casing — useful when the LLM later reads the entry.
        let v = build_sid_history_vuln("Migrated.USER", "contoso.local");
        assert_eq!(
            v.details.get("account_name").and_then(|x| x.as_str()),
            Some("Migrated.USER")
        );
    }
}
