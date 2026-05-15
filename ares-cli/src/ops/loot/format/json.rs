use std::collections::HashMap;

use ares_core::models::SharedRedTeamState;

use super::display::build_domain_achievements;
use super::hosts::dedup_hosts;
use super::report_filter::{is_reportable_credential, is_reportable_hash, report_hash_value};
use crate::dedup::{dedup_credentials, dedup_hashes, dedup_users};

pub(super) fn print_loot_json(
    state: &SharedRedTeamState,
    credentials: &[ares_core::models::Credential],
    hashes: &[ares_core::models::Hash],
    domains: &[String],
) {
    let unique_users = dedup_users(&state.all_users, &state.netbios_to_fqdn);
    // dedup first (achievements need the full set), then filter for reporting.
    let unique_creds = dedup_credentials(credentials);
    let unique_hashes = dedup_hashes(hashes);
    let merged_hosts = dedup_hosts(
        &state.all_hosts,
        &state.netbios_to_fqdn,
        &state.domain_controllers,
    );

    // Build per-domain compromise status from the full deduped set — krbtgt
    // hashes and admin entries credit DA/Golden-Ticket achievements even
    // though they're filtered from the report's credentials/hashes lists.
    let achievements = build_domain_achievements(state, &unique_hashes, &unique_creds);

    // Drop noise (machine accounts, krbtgt, local-SAM built-ins,
    // already-cracked hash blobs) before serializing the cred/hash lists
    // consumed by external scoreboards.
    let report_creds: Vec<&ares_core::models::Credential> = unique_creds
        .iter()
        .filter(|c| is_reportable_credential(c))
        .collect();
    let report_hashes: Vec<&ares_core::models::Hash> = unique_hashes
        .iter()
        .filter(|h| is_reportable_hash(h))
        .collect();

    // Build forest structure
    let mut all_domains: Vec<String> = domains
        .iter()
        .map(|d| d.trim().trim_end_matches('.').to_lowercase())
        .filter(|d| !d.is_empty())
        .collect();
    all_domains.sort();
    all_domains.dedup();

    let mut forest_roots: Vec<String> = Vec::new();
    let mut child_map: HashMap<String, String> = HashMap::new();
    for domain in &all_domains {
        let parts: Vec<&str> = domain.split('.').collect();
        if parts.len() >= 3 {
            let parent = parts[1..].join(".");
            if all_domains.contains(&parent) {
                child_map.insert(domain.clone(), parent);
            } else {
                forest_roots.push(domain.clone());
            }
        } else {
            forest_roots.push(domain.clone());
        }
    }

    let domain_compromise: Vec<serde_json::Value> = all_domains
        .iter()
        .map(|d| {
            let (has_da, has_gt, krbtgt_types, admin_users) = if let Some(a) = achievements.get(d) {
                (
                    a.has_da,
                    a.has_golden_ticket,
                    a.krbtgt_hash_types.clone(),
                    a.admin_users.clone(),
                )
            } else {
                (false, false, vec![], vec![])
            };
            let role = if forest_roots.contains(d) {
                "forest_root"
            } else if child_map.contains_key(d) {
                "child"
            } else {
                "unknown"
            };
            serde_json::json!({
                "domain": d,
                "role": role,
                "parent": child_map.get(d),
                "has_domain_admin": has_da,
                "has_golden_ticket": has_gt,
                "krbtgt_hash_types": krbtgt_types,
                "admin_users": admin_users,
            })
        })
        .collect();

    let forest_compromise: Vec<serde_json::Value> = forest_roots
        .iter()
        .map(|root| {
            let root_compromised = achievements
                .get(root)
                .map(|a| a.has_da || a.has_golden_ticket)
                .unwrap_or(false);
            let children: Vec<String> = child_map
                .iter()
                .filter(|(_, parent)| *parent == root)
                .map(|(child, _)| child.clone())
                .collect();
            let compromised_children: Vec<&String> = children
                .iter()
                .filter(|c| {
                    achievements
                        .get(*c)
                        .map(|a| a.has_da || a.has_golden_ticket)
                        .unwrap_or(false)
                })
                .collect();
            serde_json::json!({
                "forest_root": root,
                "compromised": root_compromised || !compromised_children.is_empty(),
                "root_compromised": root_compromised,
                "total_domains": 1 + children.len(),
                "compromised_domains": (if root_compromised { 1 } else { 0 }) + compromised_children.len(),
            })
        })
        .collect();

    let output = serde_json::json!({
        "operation_id": state.operation_id,
        "started_at": state.started_at.to_rfc3339(),
        "completed_at": state.completed_at.map(|dt| dt.to_rfc3339()),
        "has_domain_admin": state.has_domain_admin,
        "domain_admin_path": state.domain_admin_path,
        "has_golden_ticket": state.has_golden_ticket,
        "domain_compromise": domain_compromise,
        "forest_compromise": forest_compromise,
        "domains": domains,
        "hosts": merged_hosts.iter().map(|h| serde_json::json!({
            "ip": h.ip,
            "hostname": h.hostname,
            "os": h.os,
            "is_dc": h.is_dc,
            "services": h.services,
        })).collect::<Vec<_>>(),
        "users": unique_users.iter().map(|u| serde_json::json!({
            "username": u.username,
            "domain": u.domain,
            "is_admin": u.is_admin,
            "source": u.source,
        })).collect::<Vec<_>>(),
        "credentials": report_creds.iter().map(|c| serde_json::json!({
            "username": c.username,
            "password": c.password,
            "domain": c.domain,
            "is_admin": c.is_admin,
        })).collect::<Vec<_>>(),
        "hashes": report_hashes.iter().map(|h| serde_json::json!({
            "username": h.username,
            "domain": h.domain,
            "hash_type": h.hash_type,
            "hash_value": report_hash_value(&h.hash_type, &h.hash_value),
            "source": h.source,
        })).collect::<Vec<_>>(),
        "shares": state.all_shares.iter().map(|s| serde_json::json!({
            "host": s.host,
            "name": s.name,
            "permissions": s.permissions,
        })).collect::<Vec<_>>(),
        "vulnerabilities": state.discovered_vulnerabilities.iter().map(|(vuln_id, v)| serde_json::json!({
            "vuln_id": vuln_id,
            "vuln_type": v.vuln_type,
            "target": v.target,
            "priority": v.priority,
            "exploited": state.exploited_vulnerabilities.contains(vuln_id),
            "details": v.details,
            "discovered_by": v.discovered_by,
        })).collect::<Vec<_>>(),
        "token_coverage": build_token_coverage_json(
            &state.discovered_vulnerabilities,
            &state.exploited_vulnerabilities,
        ),
        "timeline": state.all_timeline_events,
        "techniques": state.all_techniques,
    });

    println!(
        "{}",
        serde_json::to_string_pretty(&output).unwrap_or_default()
    );
}

/// Build a JSON object summarising scoreboard-token coverage:
///
/// ```json
/// {
///   "acl_abuse":        { "discovered": 12, "exploited": 3, "status": "partial" },
///   "adcs_esc1":        { "discovered": 2,  "exploited": 2, "status": "ok" },
///   "constrained_delegation": { "discovered": 2, "exploited": 0, "status": "missing" },
///   ...
/// }
/// ```
///
/// Used by downstream consumers (blue submit, dashboards, the dreadgoad
/// scoreboard verifier) so they don't have to re-derive category mapping
/// from raw `vuln_id` strings. Category logic mirrors
/// `super::display::token_category` — keep them in lock-step so the
/// text/JSON views match.
fn build_token_coverage_json(
    discovered: &HashMap<String, ares_core::models::VulnerabilityInfo>,
    exploited: &std::collections::HashSet<String>,
) -> serde_json::Value {
    let mut discovered_by_cat: std::collections::BTreeMap<String, usize> =
        std::collections::BTreeMap::new();
    let mut exploited_by_cat: std::collections::BTreeMap<String, usize> =
        std::collections::BTreeMap::new();
    for id in discovered.keys() {
        let cat = super::display::token_category(id);
        *discovered_by_cat.entry(cat).or_default() += 1;
    }
    for id in exploited {
        let cat = super::display::token_category(id);
        *exploited_by_cat.entry(cat).or_default() += 1;
    }
    let mut categories: Vec<&String> = discovered_by_cat.keys().collect();
    for k in exploited_by_cat.keys() {
        if !categories.contains(&k) {
            categories.push(k);
        }
    }
    categories.sort();

    let mut out = serde_json::Map::new();
    for cat in categories {
        let d = discovered_by_cat.get(cat).copied().unwrap_or(0);
        let e = exploited_by_cat.get(cat).copied().unwrap_or(0);
        // Status mirrors the text view exactly so the operator's eye and
        // the dashboard's diff land on the same string.
        let status = if d == 0 && e > 0 {
            "ok"
        } else if e == 0 {
            "missing"
        } else if e >= d {
            "ok"
        } else {
            "partial"
        };
        out.insert(
            cat.clone(),
            serde_json::json!({
                "discovered": d,
                "exploited": e,
                "status": status,
            }),
        );
    }
    serde_json::Value::Object(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ares_core::models::VulnerabilityInfo;
    use std::collections::HashSet;

    fn vuln(vuln_type: &str, vuln_id: &str) -> VulnerabilityInfo {
        VulnerabilityInfo {
            vuln_id: vuln_id.to_string(),
            vuln_type: vuln_type.to_string(),
            target: String::new(),
            discovered_by: "test".into(),
            discovered_at: chrono::Utc::now(),
            details: std::collections::HashMap::new(),
            recommended_agent: String::new(),
            priority: 1,
        }
    }

    #[test]
    fn token_coverage_groups_per_category_and_marks_status() {
        let mut discovered: HashMap<String, VulnerabilityInfo> = HashMap::new();
        // 2 ACL primitives discovered, 0 exploited → missing
        discovered.insert(
            "acl_writeproperty_alice_bob".into(),
            vuln("writeproperty", "acl_writeproperty_alice_bob"),
        );
        discovered.insert(
            "acl_genericall_alice_bob".into(),
            vuln("genericall", "acl_genericall_alice_bob"),
        );
        // 1 ESC1 discovered + exploited → ok
        discovered.insert(
            "adcs_esc1_192.168.58.50_template".into(),
            vuln("adcs_esc1", "adcs_esc1_192.168.58.50_template"),
        );
        // 2 mssql_linked_server discovered, 1 exploited → partial
        discovered.insert(
            "mssql_linked_server_192.168.58.51_a".into(),
            vuln("mssql_linked_server", "mssql_linked_server_192.168.58.51_a"),
        );
        discovered.insert(
            "mssql_linked_server_192.168.58.51_b".into(),
            vuln("mssql_linked_server", "mssql_linked_server_192.168.58.51_b"),
        );

        let mut exploited: HashSet<String> = HashSet::new();
        exploited.insert("adcs_esc1_192.168.58.50_template".into());
        exploited.insert("mssql_linked_server_192.168.58.51_a".into());
        // Implicit golden_ticket — emitted by milestones, no matching
        // discovered_vulnerabilities entry. Must still appear.
        exploited.insert("golden_ticket_contoso.local".into());

        let cov = build_token_coverage_json(&discovered, &exploited);
        let obj = cov.as_object().expect("object");

        // ACL: 2 discovered, 0 exploited → missing
        let acl = obj.get("acl_abuse").expect("acl_abuse present");
        assert_eq!(acl.get("discovered").and_then(|v| v.as_u64()), Some(2));
        assert_eq!(acl.get("exploited").and_then(|v| v.as_u64()), Some(0));
        assert_eq!(acl.get("status").and_then(|v| v.as_str()), Some("missing"));

        // ESC1: 1/1 → ok
        let esc1 = obj.get("adcs_esc1").expect("adcs_esc1 present");
        assert_eq!(esc1.get("status").and_then(|v| v.as_str()), Some("ok"));

        // MSSQL Linked Server: 1/2 → partial
        let mls = obj
            .get("mssql_linked_server")
            .expect("mssql_linked_server present");
        assert_eq!(mls.get("status").and_then(|v| v.as_str()), Some("partial"));

        // Golden Ticket: discovered=0, exploited=1 → ok (implicit milestone token)
        let gt = obj.get("golden_ticket").expect("golden_ticket present");
        assert_eq!(gt.get("discovered").and_then(|v| v.as_u64()), Some(0));
        assert_eq!(gt.get("exploited").and_then(|v| v.as_u64()), Some(1));
        assert_eq!(gt.get("status").and_then(|v| v.as_str()), Some("ok"));
    }

    #[test]
    fn token_coverage_empty_state_returns_empty_object() {
        let discovered: HashMap<String, VulnerabilityInfo> = HashMap::new();
        let exploited: HashSet<String> = HashSet::new();
        let cov = build_token_coverage_json(&discovered, &exploited);
        assert_eq!(cov, serde_json::json!({}));
    }
}
