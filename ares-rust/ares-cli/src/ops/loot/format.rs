use std::collections::{HashMap, HashSet};

use once_cell::sync::Lazy;
use regex::Regex;

use ares_core::models::{Host, SharedRedTeamState};

use crate::dedup::{
    dedup_credentials, dedup_hashes, dedup_users, filter_real_weaknesses, normalize_source_label,
    normalize_state_domains, sanitize_credentials,
};

/// Regex to strip NetExec parenthesized metadata from OS strings.
/// Matches `(name:...)`, `(domain:...)`, `(signing:...)`, `(SMBv1:...)`, `(Null Auth:...)`.
static OS_PAREN_METADATA_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"\s*\([^)]*\)").unwrap());

/// Clean OS string by stripping NetExec metadata like `(name:X) (domain:Y) (signing:True)`.
fn clean_os_string(os: &str) -> String {
    let cleaned = OS_PAREN_METADATA_RE.replace_all(os, "");
    cleaned.trim().to_string()
}

/// Check if a service entry is a real network service (not metadata like `smb_signing_disabled`).
fn is_real_service(svc: &str) -> bool {
    // Real services contain port/proto format like "445/tcp"
    let trimmed = svc.trim();
    if trimmed.is_empty() {
        return false;
    }
    // Must contain port/proto pattern
    trimmed.contains("/tcp") || trimmed.contains("/udp")
}

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
    let unique_users = dedup_users(&state.all_users, &state.netbios_to_fqdn);
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
/// 2. Strip trailing DNS root dots.
/// 3. If hostname is short (no dots), try netbios_to_fqdn to build an FQDN.
/// 4. Otherwise use the hostname as-is.
fn resolve_display_hostname(host: &Host, netbios_to_fqdn: &HashMap<String, String>) -> String {
    let hostname = host.hostname.trim().trim_end_matches('.');

    // If it's an AWS PTR or empty, blank it out (matches Python's add_host behavior)
    if hostname.is_empty() || is_aws_hostname(hostname) {
        return String::new();
    }

    // If hostname has no dots (short/NetBIOS name), try to resolve to FQDN
    if !hostname.contains('.') {
        // netbios_to_fqdn keys are UPPERCASE (from publish_netbios)
        let upper = hostname.to_uppercase();
        if let Some(fqdn) = netbios_to_fqdn.get(&upper) {
            return fqdn.to_lowercase();
        }
        let lower = hostname.to_lowercase();
        // Try as hostname prefix: check if any netbios entry has this as a prefix
        for (nb, fqdn) in netbios_to_fqdn {
            if fqdn.to_lowercase().starts_with(&format!("{lower}.")) || nb.to_lowercase() == lower {
                return fqdn.to_lowercase();
            }
        }
    }

    hostname.to_lowercase()
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

/// Check if a string looks like a valid IP address (v4).
fn looks_like_ip(s: &str) -> bool {
    !s.is_empty() && s.chars().all(|c| c.is_ascii_digit() || c == '.')
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
    // Track hostname-in-IP entries to merge later
    let mut hostname_only: Vec<Host> = Vec::new();

    for host in hosts {
        let ip = host.ip.trim();

        // Skip CIDR subnet entries (e.g. "10.1.2.0/24") — not real hosts
        if ip.contains('/') {
            continue;
        }

        let resolved = resolve_display_hostname(host, netbios_to_fqdn);

        // Detect hostname-in-IP: the IP field contains a hostname (not a valid IP)
        if !looks_like_ip(ip) && !ip.is_empty() {
            let mut h = host.clone();
            // Move the hostname-like value to the hostname field
            if h.hostname.is_empty() {
                h.hostname = ip.trim_end_matches('.').to_string();
            }
            h.ip = String::new();
            hostname_only.push(h);
            continue;
        }

        if ip.is_empty() {
            // Skip entries with no IP at all
            continue;
        }

        if let Some(existing) = by_ip.get_mut(ip) {
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
            by_ip.insert(ip.to_string(), merged);
        }
    }

    // Merge hostname-only entries into existing hosts by matching hostname
    for h in hostname_only {
        let hostname_lower = h.hostname.to_lowercase();
        let mut merged = false;
        for existing in by_ip.values_mut() {
            if existing.hostname.to_lowercase() == hostname_lower {
                // Merge services
                for svc in &h.services {
                    if !existing.services.contains(svc) {
                        existing.services.push(svc.clone());
                    }
                }
                if h.is_dc {
                    existing.is_dc = true;
                }
                if existing.os.is_empty() && !h.os.is_empty() {
                    existing.os = h.os.clone();
                }
                merged = true;
                break;
            }
        }
        // If no match found, skip — don't add entries without a valid IP
        if !merged && !h.services.is_empty() {
            // Only add if it has useful data (services)
            by_ip.insert(format!("_hostname_{}", h.hostname), h);
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
        .map(|d| d.trim().trim_end_matches('.').to_lowercase())
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
        let cleaned_os = clean_os_string(&host.os);
        if !cleaned_os.is_empty() {
            line = format!("{line} [{cleaned_os}]");
        }
        if host.is_dc {
            line = format!("{line} [DC]");
        }
        println!("  - {line}");
        // Normalize and deduplicate services for display
        // Use a map keyed by port/proto so each port only appears once
        let mut port_map: HashMap<String, String> = HashMap::new();
        for svc in &host.services {
            if !is_real_service(svc) {
                continue;
            }
            // Strip parens: "445/tcp (microsoft-ds)" → "445/tcp microsoft-ds"
            let stripped = svc.replace(" (", " ").replace(')', "");
            // Strip nmap version/product info: keep only "port/proto service_name"
            let parts: Vec<&str> = stripped.split_whitespace().collect();
            let normalized = if parts.len() >= 2 && parts[0].contains('/') {
                // Strip trailing '?' from uncertain nmap identifications
                let svc_name = parts[1].trim_end_matches('?');
                format!("{} {}", parts[0], svc_name)
            } else {
                // Still strip trailing '?' even for non-standard formats
                stripped.trim_end_matches('?').to_string()
            };
            // Extract port/proto key (e.g. "445/tcp")
            let port_key = normalized
                .split_whitespace()
                .next()
                .unwrap_or("")
                .to_string();
            // Keep the longer (more descriptive) service name per port
            port_map
                .entry(port_key)
                .and_modify(|existing| {
                    if normalized.len() > existing.len() {
                        *existing = normalized.clone();
                    }
                })
                .or_insert(normalized);
        }
        let mut services: Vec<String> = port_map.into_values().collect();
        services.sort_by(|a, b| {
            let port_a = a
                .split('/')
                .next()
                .unwrap_or("0")
                .parse::<u16>()
                .unwrap_or(0);
            let port_b = b
                .split('/')
                .next()
                .unwrap_or("0")
                .parse::<u16>()
                .unwrap_or(0);
            port_a.cmp(&port_b)
        });
        for svc in &services {
            println!("      {svc}");
        }
    }
    println!();

    // Users grouped by source (with label normalization)
    let unique_users = dedup_users(&state.all_users, &state.netbios_to_fqdn);
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
