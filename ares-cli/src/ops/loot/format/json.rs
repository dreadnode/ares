use ares_core::models::SharedRedTeamState;

use super::hosts::dedup_hosts;
use crate::dedup::{dedup_credentials, dedup_hashes, dedup_users};

pub(super) fn print_loot_json(
    state: &SharedRedTeamState,
    credentials: &[ares_core::models::Credential],
    hashes: &[ares_core::models::Hash],
    domains: &[String],
) {
    let unique_users = dedup_users(&state.all_users, &state.netbios_to_fqdn);
    let unique_creds = dedup_credentials(credentials);
    let unique_hashes = dedup_hashes(hashes);
    let merged_hosts = dedup_hosts(
        &state.all_hosts,
        &state.netbios_to_fqdn,
        &state.domain_controllers,
    );

    let output = serde_json::json!({
        "operation_id": state.operation_id,
        "started_at": state.started_at.to_rfc3339(),
        "completed_at": state.completed_at.map(|dt| dt.to_rfc3339()),
        "has_domain_admin": state.has_domain_admin,
        "domain_admin_path": state.domain_admin_path,
        "has_golden_ticket": state.has_golden_ticket,
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
        "credentials": unique_creds.iter().map(|c| serde_json::json!({
            "username": c.username,
            "password": c.password,
            "domain": c.domain,
            "is_admin": c.is_admin,
        })).collect::<Vec<_>>(),
        "hashes": unique_hashes.iter().map(|h| serde_json::json!({
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
