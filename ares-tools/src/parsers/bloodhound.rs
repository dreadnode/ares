//! BloodHound collector output parser.
//!
//! `bloodhound-python -c All` writes one JSON document per object class
//! (`*_users.json`, `*_groups.json`, `*_computers.json`, `*_domains.json`)
//! into its working directory. [`crate::recon::run_bloodhound`] pins that
//! directory and echoes it as a marker line, so this module can read the
//! documents back and turn their `Aces` arrays into the same ACL-edge
//! `VulnerabilityInfo` shape the live LDAP path
//! ([`super::ntsd::parse_acl_enumeration`]) already produces.

use std::collections::{HashMap, HashSet};

use serde_json::{json, Map, Value};
use tracing::{debug, warn};

use super::ntsd::{is_unactionable_acl_source, well_known_sid};

/// Marker line [`crate::recon::run_bloodhound`] appends to its stdout so the
/// parser can find the collector's JSON without globbing the whole filesystem.
pub const BLOODHOUND_OUTPUT_DIR_MARKER: &str = "[ares] bloodhound_output_dir: ";

/// Schema versions this parser understands: the pre-`data` layout (3), the
/// current `data` layout (4/5), and BloodHound CE (6). Anything else is
/// logged and skipped rather than treated as an error.
const SUPPORTED_SCHEMA_VERSIONS: &[u64] = &[3, 4, 5, 6];

/// Upper bound on emitted edges per collection. A single mid-size forest
/// yields tens of thousands of ACEs; every one of them lands in
/// `discovered_vulnerabilities` and in the LLM's snapshot. Edges are ranked by
/// [`right_severity`] before the cut, so the truncated tail is the least
/// useful part.
const MAX_EMITTED_EDGES: usize = 500;

/// Object-class documents whose `Aces` are worth reading.
const ACE_BEARING_TYPES: &[&str] = &["users", "groups", "computers", "domains", "gpos"];

/// Map a BloodHound `RightName` (optionally refined by the v3 `AceType`) onto
/// the ACL vocabulary `auto_dacl_abuse` matches on, plus the two reader edges
/// that drive their own automation.
///
/// `ReadLAPSPassword` and `ReadGMSAPassword` map to `laps_reader` and
/// `gmsa_reader`, which `is_acl_vuln_type` deliberately does not match: they
/// reach `auto_laps_extraction` and `auto_gmsa_extraction` instead of the ACL
/// driver, which has no way to abuse either right.
///
/// Returns `None` for rights that are real but drive nothing (`Contains`,
/// `GetChanges`, …).
fn classify_bloodhound_right(right_name: &str, ace_type: &str) -> Option<&'static str> {
    let refined = if right_name.eq_ignore_ascii_case("ExtendedRight") && !ace_type.is_empty() {
        ace_type
    } else {
        right_name
    };
    match refined.to_lowercase().as_str() {
        "genericall" | "allextendedrights_genericall" => Some("genericall"),
        "genericwrite" => Some("genericwrite"),
        "writedacl" => Some("writedacl"),
        "writeowner" | "owns" => Some("writeowner"),
        "forcechangepassword" | "user-force-change-password" => Some("forcechangepassword"),
        "allextendedrights" => Some("allextendedrights"),
        "addmember" | "addmembers" => Some("addmember"),
        "addself" | "self-membership" => Some("addself"),
        "writespn" | "writeproperty" | "addkeycredentiallink" => Some("writeproperty"),
        "readlapspassword" => Some("laps_reader"),
        "readgmsapassword" => Some("gmsa_reader"),
        _ => None,
    }
}

/// Ordering used when the edge count exceeds [`MAX_EMITTED_EDGES`]. Lower
/// sorts first.
///
/// The two reader edges outrank everything: a forest yields a handful of them
/// against tens of thousands of `genericall`s, and the alphabetical tie-break
/// would otherwise drop them off the end of the cut.
fn right_severity(right: &str) -> u8 {
    match right {
        "laps_reader" | "gmsa_reader" => 0,
        "genericall" => 1,
        "writedacl" => 2,
        "writeowner" => 3,
        "forcechangepassword" => 4,
        "genericwrite" => 5,
        "addmember" => 6,
        "addself" => 7,
        "allextendedrights" => 8,
        _ => 9,
    }
}

/// One AD object as the collector saw it.
struct BhObject {
    sid: String,
    distinguished_name: String,
    /// sAMAccountName where the object has one, otherwise the DNS/UPN-stripped
    /// `Properties.name`. This is the identifier credentials are matched on.
    name: String,
    /// `User` / `Group` / `Computer` / `Domain` / `GPO` / `Unknown`.
    object_type: String,
    domain: String,
    aces: Vec<BhAce>,
    member_sids: Vec<String>,
}

struct BhAce {
    principal_sid: String,
    right: &'static str,
    is_inherited: bool,
}

/// `Properties.name` shapes: `ALICE@CONTOSO.LOCAL`, `DC01.CONTOSO.LOCAL`,
/// `CONTOSO.LOCAL`. Only the UPN form carries a separable account part.
fn display_name(properties: Option<&Value>, object_type: &str) -> String {
    let prop = |k: &str| {
        properties
            .and_then(|p| p.get(k))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .trim()
    };
    let sam = prop("samaccountname");
    if !sam.is_empty() {
        return sam.to_string();
    }
    let name = prop("name");
    if name.is_empty() {
        return String::new();
    }
    if object_type.eq_ignore_ascii_case("domain") {
        return name.to_string();
    }
    match name.split_once('@') {
        Some((account, _)) if !account.is_empty() => account.to_string(),
        _ => name.to_string(),
    }
}

fn gpo_guid_from_dn(dn: &str) -> Option<String> {
    let leaf = dn.split(',').next()?.trim();
    let (attr, value) = leaf.split_once('=')?;
    if !attr.trim().eq_ignore_ascii_case("cn") {
        return None;
    }
    let value = value.trim();
    (value.len() > 2 && value.starts_with('{') && value.ends_with('}')).then(|| value.to_string())
}

fn object_domain(properties: Option<&Value>, name: &str) -> String {
    let explicit = properties
        .and_then(|p| p.get("domain"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim();
    if !explicit.is_empty() {
        return explicit.to_lowercase();
    }
    name.split_once('@')
        .map(|(_, d)| d.to_lowercase())
        .unwrap_or_default()
}

/// Object-class label for a document, from `meta.type` or the sole non-`meta`
/// top-level key.
fn document_type(doc: &Value) -> Option<String> {
    if let Some(t) = doc
        .get("meta")
        .and_then(|m| m.get("type"))
        .and_then(|v| v.as_str())
    {
        return Some(t.to_lowercase());
    }
    doc.as_object().and_then(|o| {
        o.keys()
            .find(|k| k.as_str() != "meta" && k.as_str() != "data")
            .map(|k| k.to_lowercase())
    })
}

/// The object array: `data` on v4+, a type-named key on v3.
fn document_entries<'a>(doc: &'a Value, doc_type: &str) -> Option<&'a Vec<Value>> {
    doc.get("data")
        .and_then(|v| v.as_array())
        .or_else(|| doc.get(doc_type).and_then(|v| v.as_array()))
}

fn singular_object_type(doc_type: &str) -> &'static str {
    match doc_type {
        "users" => "User",
        "groups" => "Group",
        "computers" => "Computer",
        "domains" => "Domain",
        "gpos" => "GPO",
        _ => "Unknown",
    }
}

fn parse_document(doc: &Value, file_name: &str, out: &mut Vec<BhObject>) {
    let version = doc
        .get("meta")
        .and_then(|m| m.get("version"))
        .and_then(|v| v.as_u64());
    if let Some(v) = version {
        if !SUPPORTED_SCHEMA_VERSIONS.contains(&v) {
            warn!(
                file = %file_name,
                version = v,
                "Unrecognized BloodHound schema version — skipping document"
            );
            return;
        }
    }

    let Some(doc_type) = document_type(doc) else {
        debug!(file = %file_name, "BloodHound document has no recognizable object class");
        return;
    };
    if !ACE_BEARING_TYPES.contains(&doc_type.as_str()) {
        debug!(file = %file_name, doc_type = %doc_type, "Skipping non-ACE BloodHound document");
        return;
    }
    let Some(entries) = document_entries(doc, &doc_type) else {
        debug!(file = %file_name, doc_type = %doc_type, "BloodHound document has no entry array");
        return;
    };
    let object_type = singular_object_type(&doc_type);

    for entry in entries {
        let Some(sid) = entry
            .get("ObjectIdentifier")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
        else {
            continue;
        };
        let properties = entry.get("Properties");
        let name = display_name(properties, object_type);
        if name.is_empty() {
            continue;
        }
        let domain = object_domain(
            properties,
            properties
                .and_then(|p| p.get("name"))
                .and_then(|v| v.as_str())
                .unwrap_or(""),
        );

        let mut aces = Vec::new();
        if let Some(list) = entry.get("Aces").and_then(|v| v.as_array()) {
            for ace in list {
                let principal_sid = ace
                    .get("PrincipalSID")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                if principal_sid.is_empty() {
                    continue;
                }
                let right_name = ace.get("RightName").and_then(|v| v.as_str()).unwrap_or("");
                let ace_type = ace.get("AceType").and_then(|v| v.as_str()).unwrap_or("");
                let Some(right) = classify_bloodhound_right(right_name, ace_type) else {
                    continue;
                };
                aces.push(BhAce {
                    principal_sid: principal_sid.to_string(),
                    right,
                    is_inherited: ace
                        .get("IsInherited")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false),
                });
            }
        }

        let member_sids = entry
            .get("Members")
            .and_then(|v| v.as_array())
            .map(|members| {
                members
                    .iter()
                    .filter_map(|m| {
                        m.get("ObjectIdentifier")
                            .and_then(|v| v.as_str())
                            .map(str::to_string)
                    })
                    .collect()
            })
            .unwrap_or_default();

        let distinguished_name = properties
            .and_then(|p| p.get("distinguishedname"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .trim()
            .to_string();

        out.push(BhObject {
            sid: sid.to_string(),
            distinguished_name,
            name,
            object_type: object_type.to_string(),
            domain,
            aces,
            member_sids,
        });
    }
}

/// Recursively expand `group_sid` into the names of its non-group members.
fn expand_members(
    group_sid: &str,
    members_by_group: &HashMap<String, Vec<String>>,
    by_sid: &HashMap<String, &BhObject>,
    seen: &mut HashSet<String>,
    out: &mut Vec<String>,
) {
    if !seen.insert(group_sid.to_string()) {
        return;
    }
    let Some(members) = members_by_group.get(group_sid) else {
        return;
    };
    for member_sid in members {
        match by_sid.get(member_sid) {
            Some(obj) if obj.object_type == "Group" => {
                expand_members(member_sid, members_by_group, by_sid, seen, out);
            }
            Some(obj) => out.push(obj.name.clone()),
            None => {}
        }
    }
}

/// Turn a set of collector documents into ACL-edge vulnerability discoveries.
///
/// `files` is `(file_name, contents)`; malformed or unrecognized documents are
/// logged and skipped so one bad file can't sink the whole collection.
pub fn parse_bloodhound_documents(files: &[(String, String)], params: &Value) -> Vec<Value> {
    let fallback_domain = params
        .get("domain")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_lowercase();
    let target_ip = params
        .get("dc_ip")
        .or_else(|| params.get("target_ip"))
        .or_else(|| params.get("target"))
        .and_then(|v| v.as_str())
        .unwrap_or("");

    let mut objects: Vec<BhObject> = Vec::new();
    for (file_name, contents) in files {
        match serde_json::from_str::<Value>(contents) {
            Ok(doc) => parse_document(&doc, file_name, &mut objects),
            Err(e) => warn!(file = %file_name, err = %e, "Malformed BloodHound JSON — skipping"),
        }
    }
    if objects.is_empty() {
        return Vec::new();
    }

    let by_sid: HashMap<String, &BhObject> = objects.iter().map(|o| (o.sid.clone(), o)).collect();
    let members_by_group: HashMap<String, Vec<String>> = objects
        .iter()
        .filter(|o| o.object_type == "Group" && !o.member_sids.is_empty())
        .map(|o| (o.sid.clone(), o.member_sids.clone()))
        .collect();

    let mut edges: Vec<(u8, String, Value)> = Vec::new();
    let mut emitted: HashSet<String> = HashSet::new();

    for target in &objects {
        for ace in &target.aces {
            let source_obj = by_sid.get(&ace.principal_sid).copied();
            let source_name = match source_obj {
                Some(o) => o.name.clone(),
                None => well_known_sid(&ace.principal_sid)
                    .map(str::to_string)
                    .unwrap_or_else(|| ace.principal_sid.clone()),
            };
            if source_name.is_empty() || is_unactionable_acl_source(&source_name) {
                continue;
            }
            if source_name.eq_ignore_ascii_case(&target.name) {
                continue;
            }

            let source_type = source_obj
                .map(|o| o.object_type.clone())
                .unwrap_or_else(|| "Unknown".to_string());
            let source_domain = source_obj
                .map(|o| o.domain.clone())
                .filter(|d| !d.is_empty())
                .unwrap_or_else(|| fallback_domain.clone());
            let target_domain = if target.domain.is_empty() {
                fallback_domain.clone()
            } else {
                target.domain.clone()
            };

            let vuln_id = format!(
                "acl_{}_{}_{}",
                ace.right,
                source_name.to_lowercase().replace(' ', "_"),
                target.name.to_lowercase().replace('$', "")
            );
            if !emitted.insert(vuln_id.clone()) {
                continue;
            }

            let mut source_members = Vec::new();
            if source_type == "Group" {
                let mut seen = HashSet::new();
                expand_members(
                    &ace.principal_sid,
                    &members_by_group,
                    &by_sid,
                    &mut seen,
                    &mut source_members,
                );
                source_members.sort();
                source_members.dedup();
            }

            let description = format!(
                "{} has {} on {} ({})",
                source_name, ace.right, target.name, target.object_type
            );

            let mut details = Map::new();
            details.insert("trustee_sid".into(), json!(ace.principal_sid));
            details.insert("source".into(), json!(source_name));
            details.insert("source_type".into(), json!(source_type));
            details.insert("source_sid".into(), json!(ace.principal_sid));
            details.insert("target".into(), json!(target.name));
            details.insert("target_type".into(), json!(target.object_type));
            details.insert("target_sid".into(), json!(target.sid));
            details.insert("domain".into(), json!(target_domain));
            details.insert("source_domain".into(), json!(source_domain));
            details.insert("description".into(), json!(description));
            details.insert("is_inherited".into(), json!(ace.is_inherited));
            if !target.distinguished_name.is_empty() {
                details.insert("target_dn".into(), json!(target.distinguished_name));
            }
            if target.object_type == "GPO" {
                details.insert("gpo_name".into(), json!(target.name));
                if let Some(guid) = gpo_guid_from_dn(&target.distinguished_name) {
                    details.insert("gpo_id".into(), json!(guid));
                }
            }
            if !source_members.is_empty() {
                details.insert("source_members".into(), json!(source_members));
            }

            edges.push((
                right_severity(ace.right),
                vuln_id.clone(),
                json!({
                    "vuln_id": vuln_id,
                    "vuln_type": ace.right,
                    "source": source_name,
                    "target": target.name,
                    "target_type": target.object_type,
                    "target_ip": target_ip,
                    "domain": target_domain,
                    "source_domain": source_domain,
                    "discovered_by": "run_bloodhound",
                    "details": Value::Object(details),
                }),
            ));
        }
    }

    edges.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
    if edges.len() > MAX_EMITTED_EDGES {
        warn!(
            found = edges.len(),
            cap = MAX_EMITTED_EDGES,
            "BloodHound ACL edge count exceeds cap — emitting the most severe subset"
        );
        edges.truncate(MAX_EMITTED_EDGES);
    }
    edges.into_iter().map(|(_, _, v)| v).collect()
}

/// Read the collector's JSON documents out of the directory named by the
/// marker line in `output`, then parse them.
///
/// Returns an empty vec when the marker is absent or the directory is
/// unreadable — a collection run that produced nothing must not fail the tool
/// result.
pub fn parse_bloodhound_collection(output: &str, params: &Value) -> Vec<Value> {
    let Some(dir) = output
        .lines()
        .rev()
        .find_map(|l| l.trim().strip_prefix(BLOODHOUND_OUTPUT_DIR_MARKER))
        .map(str::trim)
        .filter(|d| !d.is_empty())
    else {
        debug!("run_bloodhound output carries no output-dir marker");
        return Vec::new();
    };

    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) => {
            warn!(dir = %dir, err = %e, "Cannot read BloodHound output directory");
            return Vec::new();
        }
    };

    let mut files = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let file_name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_string();
        match std::fs::read_to_string(&path) {
            Ok(contents) => files.push((file_name, contents)),
            Err(e) => warn!(file = %file_name, err = %e, "Cannot read BloodHound JSON"),
        }
    }

    parse_bloodhound_documents(&files, params)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params() -> Value {
        json!({"domain": "contoso.local", "dc_ip": "192.168.58.10"})
    }

    fn user(sid: &str, sam: &str, aces: Value) -> Value {
        json!({
            "ObjectIdentifier": sid,
            "Properties": {
                "name": format!("{}@CONTOSO.LOCAL", sam.to_uppercase()),
                "samaccountname": sam,
                "domain": "CONTOSO.LOCAL",
            },
            "Aces": aces,
        })
    }

    fn doc(doc_type: &str, version: u64, entries: Vec<Value>) -> String {
        json!({
            "data": entries,
            "meta": {"type": doc_type, "count": 0, "version": version, "methods": 0},
        })
        .to_string()
    }

    fn ace(principal: &str, right: &str) -> Value {
        json!({
            "PrincipalSID": principal,
            "PrincipalType": "User",
            "RightName": right,
            "IsInherited": false,
        })
    }

    const ALICE: &str = "S-1-5-21-111-222-333-1105";
    const BOB: &str = "S-1-5-21-111-222-333-1106";
    const CAROL: &str = "S-1-5-21-111-222-333-1107";
    const HELPDESK: &str = "S-1-5-21-111-222-333-1200";

    const GPO_GUID: &str = "{A1B2C3D4-0000-0000-0000-000000000001}";

    #[test]
    fn empty_input_yields_nothing() {
        assert!(parse_bloodhound_documents(&[], &params()).is_empty());
    }

    #[test]
    fn gpo_guid_from_dn_accepts_only_a_policies_container_leaf() {
        assert_eq!(
            gpo_guid_from_dn(
                "CN={A1B2C3D4-0000-0000-0000-000000000001},CN=Policies,CN=System,DC=contoso,DC=local"
            )
            .as_deref(),
            Some(GPO_GUID)
        );
        assert_eq!(
            gpo_guid_from_dn("CN=alice,CN=Users,DC=contoso,DC=local"),
            None
        );
        assert_eq!(gpo_guid_from_dn(""), None);
    }

    #[test]
    fn gpo_target_carries_dn_and_container_guid() {
        let gpo = json!({
            "ObjectIdentifier": "A1B2C3D4-0000-0000-0000-000000000001",
            "Properties": {
                "name": "DEFAULT DOMAIN POLICY@CONTOSO.LOCAL",
                "domain": "CONTOSO.LOCAL",
                "distinguishedname":
                    "CN={A1B2C3D4-0000-0000-0000-000000000001},CN=Policies,CN=System,DC=contoso,DC=local",
            },
            "Aces": [ace(ALICE, "WriteOwner")],
        });
        let files = vec![
            (
                "users.json".into(),
                doc("users", 5, vec![user(ALICE, "alice", json!([]))]),
            ),
            ("gpos.json".into(), doc("gpos", 5, vec![gpo])),
        ];
        let out = parse_bloodhound_documents(&files, &params());
        assert_eq!(out.len(), 1, "expected one GPO edge, got: {out:?}");
        let v = &out[0];
        assert_eq!(v["vuln_type"], "writeowner");
        assert_eq!(v["target_type"], "GPO");
        assert_eq!(
            v["details"]["target_dn"],
            "CN={A1B2C3D4-0000-0000-0000-000000000001},CN=Policies,CN=System,DC=contoso,DC=local",
            "a GPO has no sAMAccountName — the DN is the only handle the ACL tools accept"
        );
        assert_eq!(v["details"]["gpo_id"], GPO_GUID);
        assert_eq!(v["details"]["gpo_name"], "DEFAULT DOMAIN POLICY");
    }

    #[test]
    fn malformed_json_is_skipped_not_fatal() {
        let files = vec![
            ("bad_users.json".into(), "{not json".into()),
            (
                "ok_users.json".into(),
                doc(
                    "users",
                    5,
                    vec![
                        user(ALICE, "alice", json!([])),
                        user(BOB, "bob", json!([ace(ALICE, "GenericAll")])),
                    ],
                ),
            ),
        ];
        let out = parse_bloodhound_documents(&files, &params());
        assert_eq!(out.len(), 1);
        assert_eq!(out[0]["vuln_type"], "genericall");
    }

    #[test]
    fn v5_data_layout_emits_acl_edge() {
        let files = vec![(
            "20260726_users.json".into(),
            doc(
                "users",
                5,
                vec![
                    user(ALICE, "alice", json!([])),
                    user(BOB, "bob", json!([ace(ALICE, "ForceChangePassword")])),
                ],
            ),
        )];
        let out = parse_bloodhound_documents(&files, &params());
        assert_eq!(out.len(), 1);
        assert_eq!(out[0]["vuln_id"], "acl_forcechangepassword_alice_bob");
        assert_eq!(out[0]["vuln_type"], "forcechangepassword");
        assert_eq!(out[0]["source"], "alice");
        assert_eq!(out[0]["target"], "bob");
        assert_eq!(out[0]["target_ip"], "192.168.58.10");
        assert_eq!(out[0]["domain"], "contoso.local");
        assert_eq!(out[0]["details"]["source_domain"], "contoso.local");
    }

    #[test]
    fn v3_type_keyed_layout_is_supported() {
        let raw = json!({
            "users": [
                user(ALICE, "alice", json!([])),
                user(BOB, "bob", json!([ace(ALICE, "GenericWrite")])),
            ],
            "meta": {"type": "users", "count": 2, "version": 3},
        })
        .to_string();
        let out = parse_bloodhound_documents(&[("users.json".into(), raw)], &params());
        assert_eq!(out.len(), 1);
        assert_eq!(out[0]["vuln_type"], "genericwrite");
    }

    #[test]
    fn v3_extended_right_ace_type_refines_the_classification() {
        let refined = json!([{
            "PrincipalSID": ALICE,
            "PrincipalType": "User",
            "RightName": "ExtendedRight",
            "AceType": "ForceChangePassword",
            "IsInherited": false,
        }]);
        let files = vec![(
            "users.json".into(),
            doc(
                "users",
                3,
                vec![user(ALICE, "alice", json!([])), user(BOB, "bob", refined)],
            ),
        )];
        let out = parse_bloodhound_documents(&files, &params());
        assert_eq!(out.len(), 1);
        assert_eq!(out[0]["vuln_type"], "forcechangepassword");
    }

    #[test]
    fn unsupported_schema_version_is_skipped() {
        let files = vec![(
            "users.json".into(),
            doc(
                "users",
                99,
                vec![
                    user(ALICE, "alice", json!([])),
                    user(BOB, "bob", json!([ace(ALICE, "GenericAll")])),
                ],
            ),
        )];
        assert!(parse_bloodhound_documents(&files, &params()).is_empty());
    }

    #[test]
    fn unknown_rights_are_dropped() {
        let files = vec![(
            "users.json".into(),
            doc(
                "users",
                5,
                vec![
                    user(ALICE, "alice", json!([])),
                    user(
                        BOB,
                        "bob",
                        json!([ace(ALICE, "GetChanges"), ace(ALICE, "Contains")]),
                    ),
                ],
            ),
        )];
        assert!(parse_bloodhound_documents(&files, &params()).is_empty());
    }

    #[test]
    fn privileged_group_sources_are_filtered_out() {
        let da = json!({
            "ObjectIdentifier": "S-1-5-21-111-222-333-512",
            "Properties": {"name": "DOMAIN ADMINS@CONTOSO.LOCAL", "domain": "CONTOSO.LOCAL"},
            "Aces": [],
            "Members": [],
        });
        let files = vec![
            ("groups.json".into(), doc("groups", 5, vec![da])),
            (
                "users.json".into(),
                doc(
                    "users",
                    5,
                    vec![user(
                        BOB,
                        "bob",
                        json!([ace("S-1-5-21-111-222-333-512", "GenericAll")]),
                    )],
                ),
            ),
        ];
        assert!(parse_bloodhound_documents(&files, &params()).is_empty());
    }

    #[test]
    fn self_edges_are_dropped() {
        let files = vec![(
            "users.json".into(),
            doc(
                "users",
                5,
                vec![user(ALICE, "alice", json!([ace(ALICE, "GenericAll")]))],
            ),
        )];
        assert!(parse_bloodhound_documents(&files, &params()).is_empty());
    }

    #[test]
    fn group_source_carries_expanded_members() {
        let helpdesk = json!({
            "ObjectIdentifier": HELPDESK,
            "Properties": {"name": "HELPDESK@CONTOSO.LOCAL", "domain": "CONTOSO.LOCAL"},
            "Aces": [],
            "Members": [
                {"ObjectIdentifier": ALICE, "ObjectType": "User"},
                {"ObjectIdentifier": CAROL, "ObjectType": "User"},
            ],
        });
        let files = vec![
            ("groups.json".into(), doc("groups", 5, vec![helpdesk])),
            (
                "users.json".into(),
                doc(
                    "users",
                    5,
                    vec![
                        user(ALICE, "alice", json!([])),
                        user(CAROL, "carol", json!([])),
                        user(BOB, "bob", json!([ace(HELPDESK, "GenericAll")])),
                    ],
                ),
            ),
        ];
        let out = parse_bloodhound_documents(&files, &params());
        assert_eq!(out.len(), 1);
        assert_eq!(out[0]["source"], "HELPDESK");
        assert_eq!(
            out[0]["details"]["source_members"],
            json!(["alice", "carol"])
        );
    }

    #[test]
    fn nested_group_membership_is_expanded_transitively() {
        let outer = json!({
            "ObjectIdentifier": HELPDESK,
            "Properties": {"name": "HELPDESK@CONTOSO.LOCAL", "domain": "CONTOSO.LOCAL"},
            "Aces": [],
            "Members": [{"ObjectIdentifier": "S-1-5-21-111-222-333-1201", "ObjectType": "Group"}],
        });
        let inner = json!({
            "ObjectIdentifier": "S-1-5-21-111-222-333-1201",
            "Properties": {"name": "TIER2@CONTOSO.LOCAL", "domain": "CONTOSO.LOCAL"},
            "Aces": [],
            "Members": [{"ObjectIdentifier": ALICE, "ObjectType": "User"}],
        });
        let files = vec![
            ("groups.json".into(), doc("groups", 5, vec![outer, inner])),
            (
                "users.json".into(),
                doc(
                    "users",
                    5,
                    vec![
                        user(ALICE, "alice", json!([])),
                        user(BOB, "bob", json!([ace(HELPDESK, "WriteDacl")])),
                    ],
                ),
            ),
        ];
        let out = parse_bloodhound_documents(&files, &params());
        assert_eq!(out.len(), 1);
        assert_eq!(out[0]["details"]["source_members"], json!(["alice"]));
    }

    #[test]
    fn membership_cycle_terminates() {
        let a = json!({
            "ObjectIdentifier": "S-1-5-21-111-222-333-1300",
            "Properties": {"name": "GA@CONTOSO.LOCAL", "domain": "CONTOSO.LOCAL"},
            "Aces": [],
            "Members": [{"ObjectIdentifier": "S-1-5-21-111-222-333-1301", "ObjectType": "Group"}],
        });
        let b = json!({
            "ObjectIdentifier": "S-1-5-21-111-222-333-1301",
            "Properties": {"name": "GB@CONTOSO.LOCAL", "domain": "CONTOSO.LOCAL"},
            "Aces": [],
            "Members": [{"ObjectIdentifier": "S-1-5-21-111-222-333-1300", "ObjectType": "Group"}],
        });
        let files = vec![
            ("groups.json".into(), doc("groups", 5, vec![a, b])),
            (
                "users.json".into(),
                doc(
                    "users",
                    5,
                    vec![user(
                        BOB,
                        "bob",
                        json!([ace("S-1-5-21-111-222-333-1300", "GenericAll")]),
                    )],
                ),
            ),
        ];
        let out = parse_bloodhound_documents(&files, &params());
        assert_eq!(out.len(), 1);
        assert!(out[0]["details"].get("source_members").is_none());
    }

    #[test]
    fn domain_object_edge_keeps_domain_target_type() {
        let domain = json!({
            "ObjectIdentifier": "S-1-5-21-111-222-333",
            "Properties": {"name": "CONTOSO.LOCAL", "domain": "CONTOSO.LOCAL"},
            "Aces": [ace(ALICE, "WriteDacl")],
        });
        let files = vec![
            ("domains.json".into(), doc("domains", 5, vec![domain])),
            (
                "users.json".into(),
                doc("users", 5, vec![user(ALICE, "alice", json!([]))]),
            ),
        ];
        let out = parse_bloodhound_documents(&files, &params());
        assert_eq!(out.len(), 1);
        assert_eq!(out[0]["target"], "CONTOSO.LOCAL");
        assert_eq!(out[0]["target_type"], "Domain");
    }

    #[test]
    fn computer_targets_strip_the_dollar_in_the_vuln_id() {
        let computer = json!({
            "ObjectIdentifier": "S-1-5-21-111-222-333-1010",
            "Properties": {
                "name": "DC01.CONTOSO.LOCAL",
                "samaccountname": "DC01$",
                "domain": "CONTOSO.LOCAL",
            },
            "Aces": [ace(ALICE, "GenericWrite")],
        });
        let files = vec![
            ("computers.json".into(), doc("computers", 5, vec![computer])),
            (
                "users.json".into(),
                doc("users", 5, vec![user(ALICE, "alice", json!([]))]),
            ),
        ];
        let out = parse_bloodhound_documents(&files, &params());
        assert_eq!(out.len(), 1);
        assert_eq!(out[0]["vuln_id"], "acl_genericwrite_alice_dc01");
        assert_eq!(out[0]["target"], "DC01$");
    }

    #[test]
    fn duplicate_edges_across_documents_collapse() {
        let entries = vec![
            user(ALICE, "alice", json!([])),
            user(BOB, "bob", json!([ace(ALICE, "GenericAll")])),
        ];
        let files = vec![
            ("a_users.json".into(), doc("users", 5, entries.clone())),
            ("b_users.json".into(), doc("users", 5, entries)),
        ];
        assert_eq!(parse_bloodhound_documents(&files, &params()).len(), 1);
    }

    #[test]
    fn emission_is_capped_and_severity_ordered() {
        let mut entries = vec![user(ALICE, "alice", json!([]))];
        for i in 0..(MAX_EMITTED_EDGES + 50) {
            let sid = format!("S-1-5-21-111-222-333-{}", 2000 + i);
            let right = if i % 2 == 0 {
                "GenericAll"
            } else {
                "AllExtendedRights"
            };
            entries.push(user(&sid, &format!("svc_{i}"), json!([ace(ALICE, right)])));
        }
        let out = parse_bloodhound_documents(
            &[("users.json".into(), doc("users", 5, entries))],
            &params(),
        );
        assert_eq!(out.len(), MAX_EMITTED_EDGES);
        assert!(out
            .iter()
            .all(|v| v["vuln_type"] == "genericall" || v["vuln_type"] == "allextendedrights"));
        assert_eq!(out[0]["vuln_type"], "genericall");
    }

    #[test]
    fn collection_without_marker_returns_nothing() {
        assert!(parse_bloodhound_collection("INFO: Done in 00M 05S", &params()).is_empty());
    }

    #[test]
    fn collection_reads_marked_directory() {
        let dir = std::env::temp_dir().join(format!("ares-bh-test-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("20260726_users.json"),
            doc(
                "users",
                5,
                vec![
                    user(ALICE, "alice", json!([])),
                    user(BOB, "bob", json!([ace(ALICE, "GenericAll")])),
                ],
            ),
        )
        .unwrap();
        std::fs::write(dir.join("ignored.txt"), "not json").unwrap();

        let output = format!(
            "INFO: Done in 00M 05S\n{}{}\n",
            BLOODHOUND_OUTPUT_DIR_MARKER,
            dir.display()
        );
        let out = parse_bloodhound_collection(&output, &params());
        std::fs::remove_dir_all(&dir).ok();

        assert_eq!(out.len(), 1);
        assert_eq!(out[0]["vuln_id"], "acl_genericall_alice_bob");
    }

    #[test]
    fn collection_with_unreadable_directory_returns_nothing() {
        let output = format!("{}/nonexistent/ares-bh\n", BLOODHOUND_OUTPUT_DIR_MARKER);
        assert!(parse_bloodhound_collection(&output, &params()).is_empty());
    }

    #[test]
    fn read_laps_password_maps_to_the_laps_reader_vuln_type() {
        assert_eq!(
            classify_bloodhound_right("ReadLAPSPassword", ""),
            Some("laps_reader")
        );
        assert_eq!(
            classify_bloodhound_right("ExtendedRight", "ReadLAPSPassword"),
            Some("laps_reader")
        );
    }

    #[test]
    fn read_gmsa_password_maps_to_the_gmsa_reader_vuln_type() {
        assert_eq!(
            classify_bloodhound_right("ReadGMSAPassword", ""),
            Some("gmsa_reader")
        );
        assert_eq!(
            classify_bloodhound_right("ExtendedRight", "ReadGMSAPassword"),
            Some("gmsa_reader")
        );
    }

    #[test]
    fn reader_rights_outrank_every_acl_right_for_truncation() {
        assert!(right_severity("laps_reader") < right_severity("genericall"));
        assert!(right_severity("gmsa_reader") < right_severity("genericall"));
        assert!(right_severity("genericall") < right_severity("writedacl"));
        assert!(right_severity("allextendedrights") < right_severity("unmapped"));
    }

    #[test]
    fn reader_edge_carries_source_target_and_domain_for_the_automations() {
        let files = vec![(
            "users.json".to_string(),
            doc(
                "users",
                5,
                vec![
                    user(ALICE, "alice", json!([])),
                    user(BOB, "bob", json!([ace(ALICE, "ReadLAPSPassword")])),
                ],
            ),
        )];
        let vulns = parse_bloodhound_documents(&files, &params());
        let laps = vulns
            .iter()
            .find(|v| v["vuln_type"] == "laps_reader")
            .expect("laps_reader edge");
        assert_eq!(laps["details"]["source"], "alice");
        assert_eq!(laps["details"]["target"], "bob");
        assert_eq!(laps["details"]["domain"], "contoso.local");
    }
}
