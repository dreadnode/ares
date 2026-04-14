use std::collections::{HashMap, HashSet};

use once_cell::sync::Lazy;
use regex::Regex;

use ares_core::models::{Host, SharedRedTeamState, VulnerabilityInfo};

use crate::dedup::{
    dedup_credentials, dedup_hashes, dedup_users, normalize_source_label, normalize_state_domains,
    sanitize_credentials,
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

/// Format a duration as a human-readable string (e.g. "1h 23m 45s").
fn format_duration(dur: chrono::Duration) -> String {
    let total_secs = dur.num_seconds();
    if total_secs < 0 {
        return "0s".to_string();
    }
    let hours = total_secs / 3600;
    let minutes = (total_secs % 3600) / 60;
    let seconds = total_secs % 60;
    if hours > 0 {
        format!("{hours}h {minutes:02}m {seconds:02}s")
    } else if minutes > 0 {
        format!("{minutes}m {seconds:02}s")
    } else {
        format!("{seconds}s")
    }
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

    // Timing
    let started = state.started_at.format("%Y-%m-%d %H:%M:%S UTC");
    if let Some(completed) = state.completed_at {
        let ended = completed.format("%Y-%m-%d %H:%M:%S UTC");
        let elapsed = format_duration(completed - state.started_at);
        println!("Started:   {started}");
        println!("Completed: {ended} ({elapsed})");
    } else {
        let elapsed = format_duration(chrono::Utc::now() - state.started_at);
        println!("Started:   {started}");
        println!("Running:   {elapsed}");
    }

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

    // Discovered Vulnerabilities
    print_vulnerabilities(
        &state.discovered_vulnerabilities,
        &state.exploited_vulnerabilities,
    );

    // Attack Path / Timeline
    print_attack_path(&state.all_timeline_events);

    // MITRE ATT&CK Mapping
    print_mitre_techniques(&state.all_techniques, &state.all_timeline_events);
}

/// Print discovered vulnerabilities table.
fn print_vulnerabilities(
    discovered: &HashMap<String, VulnerabilityInfo>,
    exploited: &HashSet<String>,
) {
    if discovered.is_empty() {
        return;
    }

    // Sort by priority (lower = higher priority), then by type
    let mut vulns: Vec<(&String, &VulnerabilityInfo)> = discovered.iter().collect();
    vulns.sort_by(|a, b| {
        a.1.priority
            .cmp(&b.1.priority)
            .then(a.1.vuln_type.cmp(&b.1.vuln_type))
    });

    println!("Discovered Vulnerabilities ({}):", vulns.len());
    println!(
        "  {:<30} {:<20} {:>8} {:>9}  Details",
        "Type", "Target", "Priority", "Exploited"
    );
    println!("  {}", "-".repeat(100));
    for (vuln_id, vuln) in &vulns {
        let is_exploited = exploited.contains(*vuln_id);
        let exploited_mark = if is_exploited { "\u{2713}" } else { "\u{2717}" };

        // Build details string from the details HashMap
        let details = format_vuln_details(&vuln.details);
        let details_display = if details.len() > 80 {
            let mut end = 80;
            while !details.is_char_boundary(end) {
                end -= 1;
            }
            format!("{}...", &details[..end])
        } else {
            details
        };

        println!(
            "  {:<30} {:<20} {:>8} {:>9}  {}",
            vuln.vuln_type, vuln.target, vuln.priority, exploited_mark, details_display
        );
    }
    println!();
}

/// Format vulnerability details HashMap into a readable string.
fn format_vuln_details(details: &HashMap<String, serde_json::Value>) -> String {
    if details.is_empty() {
        return String::new();
    }
    let mut parts = Vec::new();
    // Display key fields in a consistent order
    let priority_keys = [
        "hostname",
        "account_name",
        "account",
        "domain",
        "target_spn",
        "type",
        "note",
    ];
    let mut seen = HashSet::new();
    for key in &priority_keys {
        if let Some(val) = details.get(*key) {
            let val_str = match val {
                serde_json::Value::String(s) => s.clone(),
                other => other.to_string(),
            };
            if !val_str.is_empty() && val_str != "null" {
                parts.push(format!("{}: {}", capitalize(key), val_str));
                seen.insert(*key);
            }
        }
    }
    // Add remaining keys alphabetically
    let mut remaining: Vec<_> = details
        .keys()
        .filter(|k| !seen.contains(k.as_str()))
        .collect();
    remaining.sort();
    for key in remaining {
        if let Some(val) = details.get(key) {
            let val_str = match val {
                serde_json::Value::String(s) => s.clone(),
                other => other.to_string(),
            };
            if !val_str.is_empty() && val_str != "null" {
                parts.push(format!("{}: {}", capitalize(key), val_str));
            }
        }
    }
    parts.join("; ")
}

fn capitalize(s: &str) -> String {
    let mut c = s.chars();
    match c.next() {
        None => String::new(),
        Some(f) => f.to_uppercase().to_string() + c.as_str(),
    }
}

/// Print the attack path timeline sorted by timestamp.
fn print_attack_path(timeline_events: &[serde_json::Value]) {
    if timeline_events.is_empty() {
        return;
    }

    // Sort events by timestamp
    let mut events: Vec<&serde_json::Value> = timeline_events.iter().collect();
    events.sort_by(|a, b| {
        let ts_a = a.get("timestamp").and_then(|v| v.as_str()).unwrap_or("");
        let ts_b = b.get("timestamp").and_then(|v| v.as_str()).unwrap_or("");
        ts_a.cmp(ts_b)
    });

    println!("Attack Path ({} events):", events.len());
    println!("  {:<23} {:<70} MITRE", "Time (UTC)", "Event");
    println!("  {}", "-".repeat(110));
    for event in &events {
        let timestamp = event
            .get("timestamp")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        // Format timestamp: strip timezone suffix for cleaner display
        let ts_display = format_timeline_timestamp(timestamp);

        let description = event
            .get("description")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown event");

        // Check if this is a critical event (krbtgt, administrator, domain admin)
        let desc_lower = description.to_lowercase();
        let is_critical = desc_lower.contains("krbtgt")
            || (desc_lower.contains("administrator") && desc_lower.contains("hash"))
            || desc_lower.contains("domain admin");
        let prefix = if is_critical { "CRITICAL: " } else { "" };

        let mitre = extract_mitre_from_event(event);

        let desc_display = if description.len() > 65 {
            let mut end = 65;
            while !description.is_char_boundary(end) {
                end -= 1;
            }
            format!("{prefix}{}...", &description[..end])
        } else {
            format!("{prefix}{description}")
        };

        println!("  {:<23} {:<70} {}", ts_display, desc_display, mitre);
    }
    println!();
}

/// Format a timeline timestamp for display.
fn format_timeline_timestamp(ts: &str) -> String {
    // Try to parse as RFC3339 and reformat
    if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(ts) {
        return dt.format("%Y-%m-%d %H:%M:%S").to_string();
    }
    // Try common variants
    if let Ok(dt) = chrono::NaiveDateTime::parse_from_str(ts, "%Y-%m-%dT%H:%M:%S%.f") {
        return dt.format("%Y-%m-%d %H:%M:%S").to_string();
    }
    // Return as-is, truncated
    if ts.len() > 23 {
        ts[..23].to_string()
    } else {
        ts.to_string()
    }
}

/// Extract MITRE technique IDs from a timeline event.
fn extract_mitre_from_event(event: &serde_json::Value) -> String {
    if let Some(techniques) = event.get("mitre_techniques") {
        match techniques {
            serde_json::Value::Array(arr) => {
                let ids: Vec<String> = arr
                    .iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect();
                return ids.join(", ");
            }
            serde_json::Value::String(s) => return s.clone(),
            _ => {}
        }
    }
    String::new()
}

/// Print MITRE ATT&CK technique summary.
///
/// Collects techniques from both the dedicated techniques set and
/// any techniques referenced in timeline events.
fn print_mitre_techniques(techniques: &[String], timeline_events: &[serde_json::Value]) {
    // Collect all unique techniques
    let mut all_techniques: HashSet<String> = techniques.iter().cloned().collect();

    // Also extract from timeline events
    for event in timeline_events {
        if let Some(serde_json::Value::Array(arr)) = event.get("mitre_techniques") {
            for t in arr {
                if let Some(s) = t.as_str() {
                    all_techniques.insert(s.to_string());
                }
            }
        }
    }

    if all_techniques.is_empty() {
        return;
    }

    let mut sorted: Vec<String> = all_techniques.into_iter().collect();
    sorted.sort();

    println!("MITRE ATT&CK Techniques ({}):", sorted.len());
    for technique in &sorted {
        let name = mitre_technique_name(technique);
        if name.is_empty() {
            println!("  - {technique}");
        } else {
            println!("  - {technique} ({name})");
        }
    }
    println!();
}

/// Map common MITRE ATT&CK technique IDs to human-readable names.
fn mitre_technique_name(id: &str) -> &'static str {
    match id {
        "T1003" => "OS Credential Dumping",
        "T1003.001" => "LSASS Memory",
        "T1003.002" => "Security Account Manager",
        "T1003.003" => "NTDS",
        "T1003.004" => "LSA Secrets",
        "T1003.006" => "DCSync",
        "T1021" => "Remote Services",
        "T1021.002" => "SMB/Windows Admin Shares",
        "T1021.006" => "Windows Remote Management",
        "T1046" => "Network Service Discovery",
        "T1047" => "WMI",
        "T1053" => "Scheduled Task/Job",
        "T1069" => "Permission Groups Discovery",
        "T1078" => "Valid Accounts",
        "T1087" => "Account Discovery",
        "T1110" => "Brute Force",
        "T1110.002" => "Password Cracking",
        "T1110.003" => "Password Spraying",
        "T1134" => "Access Token Manipulation",
        "T1135" => "Network Share Discovery",
        "T1187" => "Forced Authentication",
        "T1482" => "Domain Trust Discovery",
        "T1550" => "Use Alternate Authentication Material",
        "T1550.002" => "Pass the Hash",
        "T1550.003" => "Pass the Ticket",
        "T1552" => "Unsecured Credentials",
        "T1552.006" => "Group Policy Preferences",
        "T1555" => "Credentials from Password Stores",
        "T1557" => "Adversary-in-the-Middle",
        "T1558" => "Steal or Forge Kerberos Tickets",
        "T1558.001" => "Golden Ticket",
        "T1558.003" => "Kerberoasting",
        "T1558.004" => "AS-REP Roasting",
        "T1569" => "System Services",
        "T1574" => "Hijack Execution Flow",
        _ => "",
    }
}
