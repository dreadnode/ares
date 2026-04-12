use std::collections::{HashMap, HashSet};

use ares_core::models::{Host, SharedRedTeamState};

use crate::dedup::{
    dedup_credentials, dedup_hashes, dedup_users, filter_real_weaknesses, normalize_source_label,
    normalize_state_domains, sanitize_credentials,
};

pub(crate) fn print_loot(state: &SharedRedTeamState, json_output: bool) {
    // Clone mutable parts for domain normalization
    let mut credentials = state.all_credentials.clone();
    let mut hashes = state.all_hashes.clone();
    let mut domains: Vec<String> = state.all_domains.clone();

    // Sanitize credentials: strip "Password: " prefixes, "(Guest)" suffixes,
    // normalize user@domain@domain usernames, remove noise entries
    sanitize_credentials(&mut credentials);

    let target_domain = state.target.as_ref().map(|t| t.domain.as_str());

    normalize_state_domains(
        &state.all_users,
        &mut credentials,
        &mut hashes,
        &mut domains,
        &state.all_hosts,
        target_domain,
    );

    if json_output {
        print_loot_json(state, &credentials, &hashes, &domains);
    } else {
        print_loot_human(state, &credentials, &hashes, &domains);
    }
}

fn print_loot_json(
    state: &SharedRedTeamState,
    credentials: &[ares_core::models::Credential],
    hashes: &[ares_core::models::Hash],
    domains: &[String],
) {
    let unique_users = dedup_users(&state.all_users);
    let unique_creds = dedup_credentials(credentials);
    let unique_hashes = dedup_hashes(hashes);
    let real_weaknesses = filter_real_weaknesses(&state.all_weaknesses);
    let merged_hosts = dedup_hosts(
        &state.all_hosts,
        &state.netbios_to_fqdn,
        &state.domain_controllers,
    );

    let output = serde_json::json!({
        "operation_id": state.operation_id,
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
        "weaknesses": real_weaknesses.iter().map(|(raw, _)| *raw).collect::<Vec<_>>(),
    });

    println!(
        "{}",
        serde_json::to_string_pretty(&output).unwrap_or_default()
    );
}

/// Check if a hostname is an AWS internal PTR name (e.g. `ip-10-1-2-150.us-west-2.compute.internal`).
fn is_aws_hostname(hostname: &str) -> bool {
    let lower = hostname.to_lowercase();
    lower.starts_with("ip-") && lower.contains("compute.internal")
}

/// Resolve a host's display hostname, matching Python's `add_host` logic:
/// 1. Strip AWS internal hostnames (ip-*.compute.internal).
/// 2. If hostname is short (no dots), try netbios_to_fqdn to build an FQDN.
/// 3. Otherwise use the hostname as-is.
fn resolve_display_hostname(host: &Host, netbios_to_fqdn: &HashMap<String, String>) -> String {
    let hostname = host.hostname.trim();

    // If it's an AWS PTR or empty, blank it out (matches Python's add_host behavior)
    if hostname.is_empty() || is_aws_hostname(hostname) {
        return String::new();
    }

    // If hostname has no dots (short/NetBIOS name), try to resolve to FQDN
    if !hostname.contains('.') {
        let lower = hostname.to_lowercase();
        if let Some(fqdn) = netbios_to_fqdn.get(&lower) {
            return fqdn.clone();
        }
        // Try as hostname prefix: check if any netbios entry has this as a prefix
        for (nb, fqdn) in netbios_to_fqdn {
            if fqdn.to_lowercase().starts_with(&format!("{lower}.")) || nb.to_lowercase() == lower {
                return fqdn.clone();
            }
        }
    }

    hostname.to_string()
}

/// Check if `new_hostname` is a more-specific FQDN than `existing` (matching
/// Python's `add_host` logic: same short name but more domain levels).
fn is_more_specific_fqdn(existing: &str, new: &str) -> bool {
    let ex_parts: Vec<&str> = existing.split('.').collect();
    let new_parts: Vec<&str> = new.split('.').collect();
    // Both must be FQDNs with dots
    if ex_parts.len() < 2 || new_parts.len() < 2 {
        return false;
    }
    // Same short hostname (first component)
    if ex_parts[0].to_lowercase() != new_parts[0].to_lowercase() {
        return false;
    }
    // New has more domain levels
    new_parts.len() > ex_parts.len()
}

/// Deduplicate hosts by IP, merging services, preferring FQDN hostnames over
/// short names. Cross-references `domain_controllers` (dc_map) to detect DCs
/// and resolve hostnames. Matches Python's `add_host` merge logic.
fn dedup_hosts(
    hosts: &[Host],
    netbios_to_fqdn: &HashMap<String, String>,
    domain_controllers: &HashMap<String, String>,
) -> Vec<Host> {
    let mut by_ip: HashMap<String, Host> = HashMap::new();

    for host in hosts {
        let resolved = resolve_display_hostname(host, netbios_to_fqdn);

        if let Some(existing) = by_ip.get_mut(&host.ip) {
            let existing_is_short = !existing.hostname.contains('.');
            let new_is_fqdn = !resolved.is_empty() && resolved.contains('.');

            // Replace hostname if: existing is empty, existing is short but new
            // is FQDN, or new is a more-specific FQDN (more domain levels).
            if (existing.hostname.is_empty() && !resolved.is_empty())
                || (existing_is_short && new_is_fqdn)
                || is_more_specific_fqdn(&existing.hostname, &resolved)
            {
                existing.hostname = resolved;
            }

            // Merge services (union)
            for svc in &host.services {
                if !existing.services.contains(svc) {
                    existing.services.push(svc.clone());
                }
            }

            // Upgrade DC status
            if host.is_dc {
                existing.is_dc = true;
            }

            // Fill in missing OS
            if existing.os.is_empty() && !host.os.is_empty() {
                existing.os = host.os.clone();
            }

            // Merge roles
            for role in &host.roles {
                if !existing.roles.contains(role) {
                    existing.roles.push(role.clone());
                }
            }
        } else {
            let mut merged = host.clone();
            merged.hostname = resolved;
            by_ip.insert(host.ip.clone(), merged);
        }
    }

    // Build IP → domains reverse map from dc_map for DC detection and hostname resolution
    let mut ip_to_domains: HashMap<&str, Vec<&str>> = HashMap::new();
    for (domain, ip) in domain_controllers {
        ip_to_domains
            .entry(ip.as_str())
            .or_default()
            .push(domain.as_str());
    }

    // Cross-reference dc_map: mark DCs and resolve hostnames for DC hosts
    for host in by_ip.values_mut() {
        if let Some(domains) = ip_to_domains.get(host.ip.as_str()) {
            host.is_dc = true;

            // Try to resolve hostname from netbios_to_fqdn if still empty
            if host.hostname.is_empty() {
                for domain in domains {
                    let suffix = format!(".{}", domain.to_lowercase());
                    for fqdn in netbios_to_fqdn.values() {
                        if fqdn.to_lowercase().ends_with(&suffix) {
                            host.hostname = fqdn.clone();
                            break;
                        }
                    }
                    if !host.hostname.is_empty() {
                        break;
                    }
                }
            }
        }
    }

    let mut result: Vec<Host> = by_ip.into_values().collect();
    result.sort_by(|a, b| a.ip.cmp(&b.ip));
    result
}

fn print_loot_human(
    state: &SharedRedTeamState,
    credentials: &[ares_core::models::Credential],
    hashes: &[ares_core::models::Hash],
    domains_input: &[String],
) {
    println!("Operation: {}", state.operation_id);
    if state.has_domain_admin {
        println!("*** DOMAIN ADMIN ACHIEVED ***");
        if let Some(path) = &state.domain_admin_path {
            println!("  Path: {path}");
        }
    }
    if state.has_golden_ticket {
        println!("*** GOLDEN TICKET OBTAINED ***");
    }
    println!();

    // Domains with hierarchy
    let mut domains: Vec<String> = domains_input
        .iter()
        .map(|d| d.trim().to_lowercase())
        .filter(|d| !d.is_empty())
        .collect();
    domains.sort();
    domains.dedup();

    let mut forest_roots: Vec<String> = Vec::new();
    let mut child_domains: HashMap<String, String> = HashMap::new();
    for domain in &domains {
        let parts: Vec<&str> = domain.split('.').collect();
        if parts.len() >= 3 {
            let parent = parts[1..].join(".");
            if domains.contains(&parent) {
                child_domains.insert(domain.clone(), parent);
            } else {
                forest_roots.push(domain.clone());
            }
        } else {
            forest_roots.push(domain.clone());
        }
    }

    // Sort forest roots for deterministic output
    forest_roots.sort();

    println!("Domains ({}):", domains.len());
    if domains.is_empty() {
        println!("  - None");
    } else {
        let mut displayed = HashSet::new();
        for root in &forest_roots {
            println!("  - {root} (forest root)");
            displayed.insert(root.clone());
            // Sort children for deterministic output
            let mut children: Vec<_> = child_domains
                .iter()
                .filter(|(_, parent)| *parent == root)
                .map(|(child, _)| child.clone())
                .collect();
            children.sort();
            for child in &children {
                println!("    \u{2514}\u{2500} {child} (child)");
                displayed.insert(child.clone());
            }
        }
        // Display any remaining child domains (whose parent isn't a direct forest root)
        let mut remaining: Vec<_> = child_domains
            .keys()
            .filter(|c| !displayed.contains(*c))
            .cloned()
            .collect();
        remaining.sort();
        for child in &remaining {
            let parent = &child_domains[child];
            println!("  - {child} (child of {parent})");
        }
    }
    println!();

    // Hosts — deduplicated by IP with hostname resolution
    let merged_hosts = dedup_hosts(
        &state.all_hosts,
        &state.netbios_to_fqdn,
        &state.domain_controllers,
    );
    let dcs: Vec<_> = merged_hosts.iter().filter(|h| h.is_dc).collect();
    println!("Hosts ({}, {} DCs):", merged_hosts.len(), dcs.len());
    for host in &merged_hosts {
        let mut parts = Vec::new();
        if !host.hostname.is_empty() {
            parts.push(host.hostname.as_str());
        }
        if !host.ip.is_empty() {
            parts.push(host.ip.as_str());
        }
        let mut line = if parts.is_empty() {
            "(unknown)".to_string()
        } else {
            parts.join(" / ")
        };
        if !host.os.is_empty() {
            line = format!("{line} [{}]", host.os);
        }
        if host.is_dc {
            line = format!("{line} [DC]");
        }
        println!("  - {line}");
        // Normalize and deduplicate services for display
        let mut services: Vec<String> = host
            .services
            .iter()
            .map(|svc| {
                // Strip parens: "445/tcp (microsoft-ds)" → "445/tcp microsoft-ds"
                let stripped = svc.replace(" (", " ").replace(')', "");
                // Strip nmap version/product info: keep only "port/proto service_name"
                // e.g. "389/tcp ldap Microsoft Windows Active Directory LDAP ..." → "389/tcp ldap"
                let parts: Vec<&str> = stripped.split_whitespace().collect();
                if parts.len() >= 2 && parts[0].contains('/') {
                    format!("{} {}", parts[0], parts[1])
                } else {
                    stripped
                }
            })
            .collect();
        services.sort();
        services.dedup();
        for svc in &services {
            println!("      {svc}");
        }
    }
    println!();

    // Users grouped by source (with label normalization)
    let unique_users = dedup_users(&state.all_users);
    println!("Users ({}):", unique_users.len());
    let mut users_by_source: HashMap<String, Vec<_>> = HashMap::new();
    for user in &unique_users {
        let src = if user.source.is_empty() {
            "unknown".to_string()
        } else {
            user.source.clone()
        };
        let label = normalize_source_label(&src);
        users_by_source.entry(label).or_default().push(user);
    }
    let mut sources: Vec<String> = users_by_source.keys().cloned().collect();
    sources.sort();
    for src in &sources {
        let users = &users_by_source[src];
        println!("  [{src}] ({})", users.len());
        for user in users {
            let prefix = if user.domain.is_empty() {
                user.username.clone()
            } else {
                format!("{}\\{}", user.domain, user.username)
            };
            let suffix = if user.is_admin { " (admin)" } else { "" };
            println!("    - {prefix}{suffix}");
        }
    }
    println!();

    // Credentials
    let unique_creds = dedup_credentials(credentials);
    println!("Credentials ({}):", unique_creds.len());
    for cred in &unique_creds {
        let prefix = if cred.domain.is_empty() {
            cred.username.clone()
        } else {
            format!("{}\\{}", cred.domain, cred.username)
        };
        let suffix = if cred.is_admin { " (admin)" } else { "" };
        println!("  - {prefix}:{}{suffix}", cred.password);
    }
    println!();

    // Hashes
    let unique_hashes = dedup_hashes(hashes);
    println!("Hashes ({}):", unique_hashes.len());
    for h in &unique_hashes {
        let prefix = if h.domain.is_empty() {
            h.username.clone()
        } else {
            format!("{}\\{}", h.domain, h.username)
        };
        println!("  - {prefix}:{}:{}", h.hash_type, h.hash_value);
    }
    println!();

    // Shares
    println!("Shares ({}):", state.all_shares.len());
    for share in &state.all_shares {
        let line = if share.host.is_empty() {
            share.name.clone()
        } else {
            format!("{}/{}", share.host, share.name)
        };
        if share.permissions.is_empty() {
            println!("  - {line}");
        } else {
            println!("  - {line} [{}]", share.permissions);
        }
    }
    println!();

    // Weaknesses - filtered and structured
    let real_weaknesses = filter_real_weaknesses(&state.all_weaknesses);
    println!("Weaknesses ({}):", real_weaknesses.len());
    if real_weaknesses.is_empty() {
        println!("  None");
    } else {
        for (i, (_raw, parsed)) in real_weaknesses.iter().enumerate() {
            println!("  {}. {}", i + 1, parsed.title);
            if !parsed.vulnerability.is_empty() {
                let vuln_display = if parsed.vulnerability.len() > 80 {
                    format!("{}...", &parsed.vulnerability[..80])
                } else {
                    parsed.vulnerability.clone()
                };
                println!("     \u{2514}\u{2500} {vuln_display}");
            }
            if !parsed.affected_resource.is_empty() {
                println!("     Resource: {}", parsed.affected_resource);
            }
            if !parsed.impact.is_empty() {
                let impact_display = if parsed.impact.len() > 60 {
                    format!("{}...", &parsed.impact[..60])
                } else {
                    parsed.impact.clone()
                };
                println!("     Impact: {impact_display}");
            }
        }
    }
}
