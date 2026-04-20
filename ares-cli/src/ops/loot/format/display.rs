use std::collections::{HashMap, HashSet};

use ares_core::models::{Credential, Hash, SharedRedTeamState, VulnerabilityInfo};

use super::format_duration;
use super::hosts::{clean_os_string, dedup_hosts, is_real_service};
use crate::dedup::{dedup_credentials, dedup_hashes, dedup_users, normalize_source_label};

pub(super) fn print_loot_human(
    state: &SharedRedTeamState,
    credentials: &[ares_core::models::Credential],
    hashes: &[ares_core::models::Hash],
    domains_input: &[String],
) {
    println!("Operation: {}", state.operation_id);

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

    // --- Compute domains and forest structure ---
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
    forest_roots.sort();

    // --- Build per-domain achievement status ---
    let achievements = build_domain_achievements(state, hashes, credentials);
    let compromised_count = achievements
        .values()
        .filter(|a| a.has_da || a.has_golden_ticket)
        .count();
    let compromised_forests: Vec<_> = forest_roots
        .iter()
        .filter(|root| {
            let root_hit = achievements
                .get(*root)
                .map(|a| a.has_da || a.has_golden_ticket)
                .unwrap_or(false);
            let child_hit = child_domains
                .iter()
                .filter(|(_, parent)| *parent == *root)
                .any(|(child, _)| {
                    achievements
                        .get(child)
                        .map(|a| a.has_da || a.has_golden_ticket)
                        .unwrap_or(false)
                });
            root_hit || child_hit
        })
        .cloned()
        .collect();

    // --- Achievement banner ---
    if state.has_domain_admin || state.has_golden_ticket {
        let mut lines = Vec::new();
        if state.has_domain_admin {
            lines.push("\u{2605} DOMAIN ADMIN ACHIEVED".to_string());
            if let Some(path) = &state.domain_admin_path {
                lines.push(format!("  path: {path}"));
            }
        }
        if state.has_golden_ticket {
            lines.push("\u{2605} GOLDEN TICKET OBTAINED".to_string());
        }
        let inner_width = lines.iter().map(|l| l.len()).max().unwrap_or(0) + 2;
        println!("\u{250c}{}\u{2510}", "\u{2500}".repeat(inner_width));
        for line in &lines {
            println!(
                "\u{2502} {:<width$} \u{2502}",
                line,
                width = inner_width - 2
            );
        }
        println!("\u{2514}{}\u{2518}", "\u{2500}".repeat(inner_width));
        println!();
    }

    // --- Domains (single unified section) ---
    if domains.is_empty() {
        println!("Domains: None");
    } else {
        println!(
            "Domains ({}/{} compromised, {}/{} forests):",
            compromised_count,
            domains.len(),
            compromised_forests.len(),
            forest_roots.len()
        );
        let mut displayed = HashSet::new();
        for root in &forest_roots {
            print_domain_line(root, "(forest root)", "  ", &achievements);
            displayed.insert(root.clone());
            let mut children: Vec<_> = child_domains
                .iter()
                .filter(|(_, parent)| *parent == root)
                .map(|(child, _)| child.clone())
                .collect();
            children.sort();
            for child in &children {
                print_domain_line(child, "(child)", "    \u{2514}\u{2500} ", &achievements);
                displayed.insert(child.clone());
            }
        }
        // Any achievement domains not in the discovered domain list
        let mut extra: Vec<_> = achievements
            .keys()
            .filter(|d| !displayed.contains(*d))
            .cloned()
            .collect();
        extra.sort();
        for domain in &extra {
            print_domain_line(domain, "", "  ", &achievements);
        }
    }
    println!();

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
        let mut port_map: HashMap<String, String> = HashMap::new();
        for svc in &host.services {
            if !is_real_service(svc) {
                continue;
            }
            let stripped = svc.replace(" (", " ").replace(')', "");
            let parts: Vec<&str> = stripped.split_whitespace().collect();
            let normalized = if parts.len() >= 2 && parts[0].contains('/') {
                let svc_name = parts[1].trim_end_matches('?');
                format!("{} {}", parts[0], svc_name)
            } else {
                stripped.trim_end_matches('?').to_string()
            };
            let port_key = normalized
                .split_whitespace()
                .next()
                .unwrap_or("")
                .to_string();
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

    print_vulnerabilities(
        &state.discovered_vulnerabilities,
        &state.exploited_vulnerabilities,
    );

    print_attack_path(&state.all_timeline_events);
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
        let ts_display = format_timeline_timestamp(timestamp);

        let description = event
            .get("description")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown event");

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
    let mut all_techniques: HashSet<String> = techniques.iter().cloned().collect();
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

// ---------------------------------------------------------------------------
// Per-domain compromise helpers
// ---------------------------------------------------------------------------

/// Resolve a domain to its FQDN using the NetBIOS mapping.
fn resolve_domain_fqdn(domain: &str, netbios_to_fqdn: &HashMap<String, String>) -> String {
    let lower = domain.trim().trim_end_matches('.').to_lowercase();
    if lower.is_empty() || lower.contains('.') {
        return lower;
    }
    if let Some(fqdn) = netbios_to_fqdn.get(&lower) {
        return fqdn.to_lowercase();
    }
    if let Some(fqdn) = netbios_to_fqdn.get(&domain.to_uppercase()) {
        return fqdn.to_lowercase();
    }
    lower
}

/// Per-domain achievement status.
#[derive(Default)]
pub(super) struct DomainAchievement {
    pub has_da: bool,
    pub has_golden_ticket: bool,
    pub krbtgt_hash_types: Vec<String>,
    pub admin_users: Vec<String>,
}

/// Build per-domain achievements from hashes, credentials, and vulnerabilities.
pub(super) fn build_domain_achievements(
    state: &SharedRedTeamState,
    hashes: &[Hash],
    credentials: &[Credential],
) -> HashMap<String, DomainAchievement> {
    let mut achievements: HashMap<String, DomainAchievement> = HashMap::new();

    // krbtgt hashes indicate DA for that domain
    for h in hashes {
        if h.username.eq_ignore_ascii_case("krbtgt") {
            let domain = resolve_domain_fqdn(&h.domain, &state.netbios_to_fqdn);
            if domain.is_empty() {
                continue;
            }
            let entry = achievements.entry(domain).or_default();
            entry.has_da = true;
            if !entry.krbtgt_hash_types.contains(&h.hash_type) {
                entry.krbtgt_hash_types.push(h.hash_type.clone());
            }
        }
    }

    // golden_ticket vulnerabilities
    for vuln in state.discovered_vulnerabilities.values() {
        if vuln.vuln_type == "golden_ticket" {
            if let Some(domain_val) = vuln.details.get("domain") {
                let raw = domain_val.as_str().unwrap_or("");
                let domain = resolve_domain_fqdn(raw, &state.netbios_to_fqdn);
                if !domain.is_empty() {
                    achievements.entry(domain).or_default().has_golden_ticket = true;
                }
            }
        }
    }

    // Admin credentials
    for c in credentials {
        if c.is_admin {
            let domain = resolve_domain_fqdn(&c.domain, &state.netbios_to_fqdn);
            if domain.is_empty() {
                continue;
            }
            let entry = achievements.entry(domain).or_default();
            let username = c.username.to_lowercase();
            if !entry.admin_users.contains(&username) {
                entry.admin_users.push(username);
            }
        }
    }

    // Administrator hashes also indicate DA
    for h in hashes {
        if h.username.eq_ignore_ascii_case("administrator") {
            let domain = resolve_domain_fqdn(&h.domain, &state.netbios_to_fqdn);
            if domain.is_empty() {
                continue;
            }
            let entry = achievements.entry(domain).or_default();
            entry.has_da = true;
            let name = "administrator".to_string();
            if !entry.admin_users.contains(&name) {
                entry.admin_users.push(name);
            }
        }
    }

    achievements
}

/// Print a single domain line with role, compromise tags, and details.
fn print_domain_line(
    domain: &str,
    role: &str,
    prefix: &str,
    achievements: &HashMap<String, DomainAchievement>,
) {
    let role_str = if role.is_empty() {
        String::new()
    } else {
        format!(" {role}")
    };
    let label = format!("{domain}{role_str}");

    if let Some(status) = achievements.get(domain) {
        if status.has_da || status.has_golden_ticket {
            let mut tags = Vec::new();
            if status.has_da {
                tags.push("DA");
            }
            if status.has_golden_ticket {
                tags.push("GT");
            }
            let tag_str = tags.join("+");

            let mut details = Vec::new();
            if !status.krbtgt_hash_types.is_empty() {
                details.push(format!("krbtgt: {}", status.krbtgt_hash_types.join(",")));
            }
            if !status.admin_users.is_empty() {
                details.push(format!("admin: {}", status.admin_users.join(",")));
            }
            let detail_str = if details.is_empty() {
                String::new()
            } else {
                format!("  {}", details.join(", "))
            };
            println!("{prefix}{label:<40} {tag_str}{detail_str}");
            return;
        }
    }
    println!("{prefix}{label}");
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
