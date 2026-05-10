use std::collections::HashMap;

use ares_core::models::SharedRedTeamState;

use super::display::build_domain_achievements;
use super::hosts::dedup_hosts;
use super::report_filter::{is_reportable_credential, is_reportable_hash};
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
            "hash_value": h.hash_value,
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
        "timeline": state.all_timeline_events,
        "techniques": state.all_techniques,
    });

    println!(
        "{}",
        serde_json::to_string_pretty(&output).unwrap_or_default()
    );
}
