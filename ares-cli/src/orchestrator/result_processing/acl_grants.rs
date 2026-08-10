//! Publish what a successful ACL takeover acquired: the edge a DACL grant
//! minted, and the credential a password reset created.
//!
//! `writedacl` / `writeowner` edges are not directly abusable — they are
//! escalate-first primitives. `auto_dacl_abuse` dispatches `dacl_edit` (or
//! `bloodyad_add_genericall`) to convert them into an actionable right, but
//! nothing recorded the acquired right, so the ACL chain never advanced past
//! its first step and no follow-up shadow-cred / password-reset dispatch could
//! fire.
//!
//! This module scans a completed task's `tool_outputs` for grants the tool
//! itself confirmed, and republishes each one as an ACL vulnerability shaped
//! exactly like the `ldap_acl_enumeration` parser's output — `acl_{right}_
//! {source}_{target}` with a `details` map carrying `source`, `target`,
//! `target_type`, `domain`. The result is indistinguishable from a discovered
//! edge, so `acl_graph::build_edges`, `auto_dacl_abuse`, and
//! `auto_shadow_credentials` consume it with no special-casing.
//!
//! `bloodyad_set_password` deliberately publishes nothing. A reset only yields
//! a credential if something states what the password now is, and bloodyAD's
//! stdout is a bare `Password changed successfully!` — it never echoes the
//! value. The only place that string existed was the `new_password` argument,
//! which is model-authored input, not tool output. Credentials enter state from
//! parsed tool output or not at all, so a reset that no parser can attest to is
//! a reset that credits nothing.
//!
//! This pass runs on every completed task regardless of the agent's own success
//! verdict: the outcome is credited off the tool's stdout, never off the LLM's
//! self-assessment.

use std::sync::Arc;

use serde_json::Value;
use tracing::{debug, info};

use crate::orchestrator::dispatcher::Dispatcher;

/// One ACL right acquired by a confirmed DACL write.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GrantedAclEdge {
    pub right: String,
    pub source: String,
    pub target: String,
    pub target_type: String,
    pub target_dn: String,
    pub domain: String,
}

impl GrantedAclEdge {
    /// Vuln id in the exact shape `ldap_acl_enumeration` emits.
    fn vuln_id(&self) -> String {
        format!(
            "acl_{}_{}_{}",
            self.right,
            self.source.to_lowercase().replace(' ', "_"),
            self.target.to_lowercase().replace('$', "")
        )
    }

    fn into_vulnerability(self) -> ares_core::models::VulnerabilityInfo {
        let vuln_id = self.vuln_id();
        let mut details = std::collections::HashMap::new();
        details.insert("source".into(), Value::String(self.source));
        details.insert("target".into(), Value::String(self.target.clone()));
        details.insert("target_type".into(), Value::String(self.target_type));
        details.insert("domain".into(), Value::String(self.domain));
        if !self.target_dn.is_empty() {
            if let Some(guid) = gpo_guid_from_dn(&self.target_dn) {
                details.insert("gpo_id".into(), Value::String(guid));
            }
            details.insert("target_dn".into(), Value::String(self.target_dn));
        }
        ares_core::models::VulnerabilityInfo {
            vuln_id,
            vuln_type: self.right,
            target: self.target,
            discovered_by: "result_processing".to_string(),
            discovered_at: chrono::Utc::now(),
            details,
            recommended_agent: String::new(),
            priority: 5,
        }
    }
}

/// Normalise a tool's `rights` argument to the bare ACL right token the
/// ACL drivers match on (`acl_graph::is_acl_vuln_type`).
///
/// Covers both the impacket `dacledit.py` vocabulary (`FullControl`,
/// `ResetPassword`, `WriteMembers`) and the BloodHound-style names the tool
/// schema advertises. Rights outside that vocabulary — `DCSync` above all —
/// return `None`: they are real capabilities but not graph edges, and minting
/// a vuln type no automation consumes would only add queue noise.
fn normalize_right(raw: &str) -> Option<&'static str> {
    let key: String = raw
        .to_lowercase()
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .collect();
    match key.as_str() {
        "genericall" | "fullcontrol" | "ga" => Some("genericall"),
        "genericwrite" | "gw" => Some("genericwrite"),
        "writedacl" | "wd" => Some("writedacl"),
        "writeowner" | "wo" => Some("writeowner"),
        "writeproperty" | "wp" => Some("writeproperty"),
        "writemembers" | "writemembership" | "selfmembership" => Some("write_membership"),
        "resetpassword" | "forcechangepassword" => Some("forcechangepassword"),
        "allextendedrights" => Some("allextendedrights"),
        _ => None,
    }
}

/// Reduce a principal reference to a bare SAM account name.
///
/// Accepts the three shapes the ACL tools are given: a distinguished name
/// (`CN=alice,CN=Users,DC=contoso,DC=local`), a down-level logon name
/// (`CONTOSO\alice`), and a UPN (`alice@contoso.local`).
fn principal_name(raw: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.contains('=') {
        if let Some(leaf) = trimmed.split(',').next() {
            if let Some((_, value)) = leaf.split_once('=') {
                return value.trim().to_string();
            }
        }
    }
    let after_domain = trimmed.rsplit('\\').next().unwrap_or(trimmed);
    after_domain
        .split_once('@')
        .map(|(user, _)| user)
        .unwrap_or(after_domain)
        .to_string()
}

/// Extract the `{GUID}` container id from a groupPolicyContainer DN.
pub(crate) fn gpo_guid_from_dn(dn: &str) -> Option<String> {
    let lower = dn.to_lowercase();
    if !lower.contains(",cn=policies,cn=system,") {
        return None;
    }
    let leaf = dn.split(',').next()?.trim();
    let (attr, value) = leaf.split_once('=')?;
    if !attr.trim().eq_ignore_ascii_case("cn") {
        return None;
    }
    let value = value.trim();
    (value.len() > 2 && value.starts_with('{') && value.ends_with('}')).then(|| value.to_string())
}

/// Resolve a `target_dn` to `(name, target_type)`.
///
/// A DN whose every RDN is `DC=` is the domain head: the name becomes the
/// dotted FQDN and the type `Domain`, which `acl_graph::is_high_value_terminal`
/// treats as domain compromise. A groupPolicyContainer DN keeps its GUID as the
/// name and is typed `GPO`, so the republished edge routes back through the DN
/// path rather than being retried against a name nothing resolves. Everything
/// else keeps `Unknown` — the same value `ldap_acl_enumeration` emits when it
/// cannot classify an objectClass, and the value `auto_shadow_credentials`
/// still accepts.
fn resolve_target(target_dn: &str) -> Option<(String, String)> {
    let trimmed = target_dn.trim();
    if trimmed.is_empty() {
        return None;
    }
    if !trimmed.contains('=') {
        return Some((trimmed.to_string(), "Unknown".to_string()));
    }
    if let Some(guid) = gpo_guid_from_dn(trimmed) {
        return Some((guid, "GPO".to_string()));
    }
    let rdns: Vec<&str> = trimmed.split(',').map(str::trim).collect();
    if rdns
        .iter()
        .all(|r| r.to_lowercase().starts_with("dc=") && r.len() > 3)
    {
        let fqdn = rdns
            .iter()
            .filter_map(|r| r.split_once('='))
            .map(|(_, v)| v.trim())
            .collect::<Vec<_>>()
            .join(".");
        if fqdn.is_empty() {
            return None;
        }
        return Some((fqdn, "Domain".to_string()));
    }
    let name = principal_name(trimmed);
    if name.is_empty() {
        None
    } else {
        Some((name, "Unknown".to_string()))
    }
}

/// True when the tool's own stdout confirms the ACE landed.
///
/// Deliberately narrow: a phantom edge would feed exactly the doomed
/// shadow-cred dispatches this whole change exists to stop, so an
/// unrecognised output is treated as "no grant" rather than "probably fine".
fn output_confirms_grant(tool: &str, output: &str) -> bool {
    let lower = output.to_lowercase();
    match tool {
        "dacl_edit" => lower.contains("dacl modified successfully"),
        "bloodyad_add_genericall" => {
            lower.contains("has now genericall on") || lower.contains("has now genericall over")
        }
        _ => false,
    }
}

/// Extract every ACL edge a task's tool calls actually granted.
///
/// Reads the `{name, arguments, output}` entries `submission.rs` writes into
/// `tool_outputs`. Reversal actions (`dacl_edit -action remove`,
/// `bloodyad_add_genericall action=remove`, both used by operation teardown)
/// are skipped — they retract the ACE rather than grant it.
pub(crate) fn extract_granted_acl_edges(payload: &Value) -> Vec<GrantedAclEdge> {
    let Some(entries) = payload.get("tool_outputs").and_then(|v| v.as_array()) else {
        return Vec::new();
    };

    let mut edges = Vec::new();
    for entry in entries {
        let Some(tool) = entry.get("name").and_then(|v| v.as_str()) else {
            continue;
        };
        let Some(args) = entry.get("arguments") else {
            continue;
        };
        let output = entry.get("output").and_then(|v| v.as_str()).unwrap_or("");
        if !output_confirms_grant(tool, output) {
            continue;
        }

        let arg = |key: &str| args.get(key).and_then(|v| v.as_str()).unwrap_or("").trim();
        let action = arg("action").to_lowercase();
        let raw_right = match tool {
            "dacl_edit" => {
                if !action.is_empty() && action != "write" {
                    continue;
                }
                arg("rights")
            }
            "bloodyad_add_genericall" => {
                if !action.is_empty() && action != "add" {
                    continue;
                }
                "GenericAll"
            }
            _ => continue,
        };

        let Some(right) = normalize_right(raw_right) else {
            debug!(tool = %tool, right = %raw_right, "DACL grant right is not a graph edge — not republished");
            continue;
        };
        let source = principal_name(arg("principal"));
        let Some((target, target_type)) = resolve_target(arg("target_dn")) else {
            continue;
        };
        if source.is_empty() || source.eq_ignore_ascii_case(&target) {
            continue;
        }

        edges.push(GrantedAclEdge {
            right: right.to_string(),
            source,
            target,
            target_type,
            target_dn: arg("target_dn").to_string(),
            domain: arg("domain").to_string(),
        });
    }
    edges
}

/// Publish every ACL edge a completed task's tool calls granted.
///
/// Idempotent: `publish_vulnerability` dedups on `vuln_id` via `HSETNX`, so a
/// re-granted ACE is a no-op rather than a duplicate queue entry.
pub(crate) async fn publish_granted_acl_edges(payload: &Value, dispatcher: &Arc<Dispatcher>) {
    for edge in extract_granted_acl_edges(payload) {
        let vuln_id = edge.vuln_id();
        let (right, source, target) =
            (edge.right.clone(), edge.source.clone(), edge.target.clone());
        match dispatcher
            .state
            .publish_vulnerability(&dispatcher.queue, edge.into_vulnerability())
            .await
        {
            Ok(true) => info!(
                vuln_id = %vuln_id,
                right = %right,
                source = %source,
                target = %target,
                "DACL grant confirmed — acquired ACL edge published for follow-on abuse"
            ),
            Ok(false) => debug!(vuln_id = %vuln_id, "Acquired ACL edge already known"),
            Err(e) => {
                tracing::warn!(err = %e, vuln_id = %vuln_id, "Failed to publish acquired ACL edge")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn normalize_right_maps_dacledit_and_bloodhound_vocabularies() {
        assert_eq!(normalize_right("FullControl"), Some("genericall"));
        assert_eq!(normalize_right("GenericAll"), Some("genericall"));
        assert_eq!(normalize_right("generic-all"), Some("genericall"));
        assert_eq!(normalize_right("GenericWrite"), Some("genericwrite"));
        assert_eq!(normalize_right("WriteDacl"), Some("writedacl"));
        assert_eq!(normalize_right("WriteOwner"), Some("writeowner"));
        assert_eq!(normalize_right("WriteMembers"), Some("write_membership"));
        assert_eq!(
            normalize_right("ResetPassword"),
            Some("forcechangepassword")
        );
        assert_eq!(
            normalize_right("AllExtendedRights"),
            Some("allextendedrights")
        );
    }

    #[test]
    fn normalize_right_rejects_non_graph_rights() {
        // DCSync is a capability, not a traversable edge — no ACL automation
        // consumes it, so publishing it would only add exploitation-queue noise.
        assert_eq!(normalize_right("DCSync"), None);
        assert_eq!(normalize_right(""), None);
        assert_eq!(normalize_right("Nonsense"), None);
    }

    #[test]
    fn principal_name_handles_dn_downlevel_and_upn() {
        assert_eq!(
            principal_name("CN=alice,CN=Users,DC=contoso,DC=local"),
            "alice"
        );
        assert_eq!(principal_name("CONTOSO\\alice"), "alice");
        assert_eq!(principal_name("alice@contoso.local"), "alice");
        assert_eq!(principal_name("  alice  "), "alice");
    }

    #[test]
    fn resolve_target_classifies_domain_head_as_domain() {
        assert_eq!(
            resolve_target("DC=contoso,DC=local"),
            Some(("contoso.local".to_string(), "Domain".to_string()))
        );
        assert_eq!(
            resolve_target("DC=child,DC=contoso,DC=local"),
            Some(("child.contoso.local".to_string(), "Domain".to_string()))
        );
    }

    #[test]
    fn resolve_target_classifies_objects_as_unknown() {
        assert_eq!(
            resolve_target("CN=bob,CN=Users,DC=contoso,DC=local"),
            Some(("bob".to_string(), "Unknown".to_string()))
        );
        // bloodyAD accepts a bare sAMAccountName in place of a DN.
        assert_eq!(
            resolve_target("bob"),
            Some(("bob".to_string(), "Unknown".to_string()))
        );
        assert_eq!(resolve_target("   "), None);
    }

    fn tool_entry(name: &str, arguments: Value, output: &str) -> Value {
        json!({ "name": name, "arguments": arguments, "output": output })
    }

    #[test]
    fn extract_publishes_dacledit_grant_in_parser_shape() {
        let payload = json!({
            "tool_outputs": [tool_entry(
                "dacl_edit",
                json!({
                    "domain": "contoso.local",
                    "username": "alice",
                    "dc_ip": "192.168.58.10",
                    "principal": "alice",
                    "rights": "FullControl",
                    "target_dn": "CN=bob,CN=Users,DC=contoso,DC=local",
                }),
                "[*] DACL backed up to dacledit-20260727.bak\n[*] DACL modified successfully!",
            )]
        });

        let edges = extract_granted_acl_edges(&payload);
        assert_eq!(edges.len(), 1);
        assert_eq!(edges[0].right, "genericall");
        assert_eq!(edges[0].source, "alice");
        assert_eq!(edges[0].target, "bob");
        assert_eq!(edges[0].target_type, "Unknown");
        assert_eq!(edges[0].domain, "contoso.local");
        assert_eq!(edges[0].vuln_id(), "acl_genericall_alice_bob");

        // Same id shape and detail keys as ldap_acl_enumeration's parser, so
        // build_edges / collect_dacl_work / select_shadow_credentials_work all
        // treat it as a discovered edge.
        let vuln = edges[0].clone().into_vulnerability();
        assert_eq!(vuln.vuln_id, "acl_genericall_alice_bob");
        assert_eq!(vuln.vuln_type, "genericall");
        assert_eq!(vuln.target, "bob");
        assert_eq!(vuln.details["source"], json!("alice"));
        assert_eq!(vuln.details["target"], json!("bob"));
        assert_eq!(vuln.details["target_type"], json!("Unknown"));
        assert_eq!(vuln.details["domain"], json!("contoso.local"));
    }

    #[test]
    fn republished_gpo_grant_keeps_the_dn_it_was_granted_against() {
        let dn =
            "CN={34034095-875D-4230-9232-2611A167C9E1},CN=Policies,CN=System,DC=contoso,DC=local";
        let payload = json!({
            "tool_outputs": [tool_entry(
                "dacl_edit",
                json!({
                    "domain": "contoso.local",
                    "username": "alice",
                    "dc_ip": "192.168.58.10",
                    "principal": "alice",
                    "rights": "FullControl",
                    "target_dn": dn,
                }),
                "[*] DACL modified successfully!",
            )]
        });

        let edges = extract_granted_acl_edges(&payload);
        assert_eq!(edges.len(), 1);
        assert_eq!(edges[0].target, "{34034095-875D-4230-9232-2611A167C9E1}");
        assert_eq!(edges[0].target_type, "GPO");

        let vuln = edges[0].clone().into_vulnerability();
        assert_eq!(vuln.details["target_dn"], json!(dn));
        assert_eq!(
            vuln.details["gpo_id"],
            json!("{34034095-875D-4230-9232-2611A167C9E1}"),
            "without gpo_id and target_dn the republished edge is the same \
             GUID-only record the ACL tools cannot bind on"
        );
    }

    #[test]
    fn extract_publishes_bloodyad_genericall_grant() {
        let payload = json!({
            "tool_outputs": [tool_entry(
                "bloodyad_add_genericall",
                json!({
                    "domain": "contoso.local",
                    "dc_ip": "192.168.58.10",
                    "principal": "CONTOSO\\alice",
                    "target_dn": "CN=svc_sql,CN=Users,DC=contoso,DC=local",
                }),
                "[+] alice has now GenericAll on CN=svc_sql,CN=Users,DC=contoso,DC=local",
            )]
        });

        let edges = extract_granted_acl_edges(&payload);
        assert_eq!(edges.len(), 1);
        assert_eq!(edges[0].right, "genericall");
        assert_eq!(edges[0].source, "alice");
        assert_eq!(edges[0].target, "svc_sql");
        assert_eq!(edges[0].vuln_id(), "acl_genericall_alice_svc_sql");
    }

    #[test]
    fn extract_ignores_unconfirmed_and_denied_grants() {
        let payload = json!({
            "tool_outputs": [
                tool_entry(
                    "dacl_edit",
                    json!({
                        "domain": "contoso.local",
                        "principal": "alice",
                        "rights": "FullControl",
                        "target_dn": "CN=bob,CN=Users,DC=contoso,DC=local",
                    }),
                    "[-] ldap3.core.exceptions.LDAPInsufficientAccessRightsResult: 00002098",
                ),
                tool_entry(
                    "bloodyad_add_genericall",
                    json!({
                        "domain": "contoso.local",
                        "principal": "alice",
                        "target_dn": "CN=bob,CN=Users,DC=contoso,DC=local",
                    }),
                    "I will now grant GenericAll on bob",
                ),
            ]
        });
        assert!(extract_granted_acl_edges(&payload).is_empty());
    }

    #[test]
    fn extract_ignores_teardown_reversals() {
        let payload = json!({
            "tool_outputs": [
                tool_entry(
                    "dacl_edit",
                    json!({
                        "action": "remove",
                        "domain": "contoso.local",
                        "principal": "alice",
                        "rights": "FullControl",
                        "target_dn": "CN=bob,CN=Users,DC=contoso,DC=local",
                    }),
                    "[*] DACL modified successfully!",
                ),
                tool_entry(
                    "bloodyad_add_genericall",
                    json!({
                        "action": "remove",
                        "domain": "contoso.local",
                        "principal": "alice",
                        "target_dn": "CN=bob,CN=Users,DC=contoso,DC=local",
                    }),
                    "[+] alice has now GenericAll on bob",
                ),
            ]
        });
        assert!(extract_granted_acl_edges(&payload).is_empty());
    }

    #[test]
    fn extract_ignores_non_grant_tools_and_missing_payloads() {
        let payload = json!({
            "tool_outputs": [tool_entry(
                "bloodyad_set_password",
                json!({ "target_user": "bob", "domain": "contoso.local" }),
                "[+] Password changed successfully!",
            )]
        });
        assert!(extract_granted_acl_edges(&payload).is_empty());
        assert!(extract_granted_acl_edges(&json!({})).is_empty());
        assert!(extract_granted_acl_edges(&json!({ "tool_outputs": ["plain string"] })).is_empty());
    }

    #[test]
    fn extract_records_domain_head_grant_as_domain_edge() {
        // WriteDacl on the domain head is the DCSync setup step; the resulting
        // edge must carry target_type=Domain so acl_graph scores it as a
        // high-value terminal.
        let payload = json!({
            "tool_outputs": [tool_entry(
                "dacl_edit",
                json!({
                    "domain": "contoso.local",
                    "principal": "alice",
                    "rights": "WriteDacl",
                    "target_dn": "DC=contoso,DC=local",
                }),
                "[*] DACL modified successfully!",
            )]
        });
        let edges = extract_granted_acl_edges(&payload);
        assert_eq!(edges.len(), 1);
        assert_eq!(edges[0].right, "writedacl");
        assert_eq!(edges[0].target, "contoso.local");
        assert_eq!(edges[0].target_type, "Domain");
        assert_eq!(edges[0].vuln_id(), "acl_writedacl_alice_contoso.local");
    }

    #[test]
    fn extract_drops_self_grants() {
        let payload = json!({
            "tool_outputs": [tool_entry(
                "dacl_edit",
                json!({
                    "domain": "contoso.local",
                    "principal": "alice",
                    "rights": "GenericAll",
                    "target_dn": "CN=alice,CN=Users,DC=contoso,DC=local",
                }),
                "[*] DACL modified successfully!",
            )]
        });
        assert!(extract_granted_acl_edges(&payload).is_empty());
    }

    #[test]
    fn extract_drops_dcsync_grant() {
        let payload = json!({
            "tool_outputs": [tool_entry(
                "dacl_edit",
                json!({
                    "domain": "contoso.local",
                    "principal": "alice",
                    "rights": "DCSync",
                    "target_dn": "DC=contoso,DC=local",
                }),
                "[*] DACL modified successfully!",
            )]
        });
        assert!(extract_granted_acl_edges(&payload).is_empty());
    }

    fn reset_entry(arguments: Value, output: &str) -> Value {
        tool_entry("bloodyad_set_password", arguments, output)
    }

    /// bloodyAD never echoes the password it set, so a confirmed reset has no
    /// parsed source for the one field that would make it a credential. The
    /// `new_password` argument is model-authored input; reading it back would
    /// launder LLM text into `state.credentials` behind a real success line.
    #[test]
    fn a_confirmed_reset_publishes_no_credential() {
        let payload = json!({
            "tool_outputs": [reset_entry(
                json!({
                    "domain": "contoso.local",
                    "username": "alice",
                    "dc_ip": "192.168.58.10",
                    "target_user": "bob",
                    "new_password": "P@ssw0rd!",
                }),
                "[+] Password changed successfully!",
            )]
        });

        assert!(extract_granted_acl_edges(&payload).is_empty());
    }

    #[test]
    fn granted_edge_id_matches_ldap_parser_sanitisation() {
        // ldap_acl_enumeration builds `acl_{right}_{source}_{target}` with the
        // source lowercased and spaces collapsed, and `$` stripped from the
        // target's sAMAccountName. Machine-account targets must land on the
        // same key so a rediscovery dedups instead of duplicating.
        let edge = GrantedAclEdge {
            right: "genericwrite".to_string(),
            source: "Domain Users".to_string(),
            target: "WS01$".to_string(),
            target_type: "Computer".to_string(),
            target_dn: String::new(),
            domain: "contoso.local".to_string(),
        };
        assert_eq!(edge.vuln_id(), "acl_genericwrite_domain_users_ws01");
    }
}
