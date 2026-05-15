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

    for line in operation_timing_lines(state, chrono::Utc::now()) {
        println!("{line}");
    }

    let topology = compute_forest_topology(domains_input);
    let domains: Vec<String> = {
        let mut all: Vec<String> = topology.forest_roots.clone();
        all.extend(topology.child_domains.keys().cloned());
        all.sort();
        all.dedup();
        all
    };
    let forest_roots = &topology.forest_roots;
    let child_domains = &topology.child_domains;

    let achievements = build_domain_achievements(state, hashes, credentials);
    let compromised_count = achievements
        .values()
        .filter(|a| a.has_da || a.has_golden_ticket)
        .count();
    let compromised_forests_count = count_compromised_forests(&topology, &achievements);

    if state.has_domain_admin || state.has_golden_ticket {
        let mut lines = Vec::new();
        let total_domains = domains.len();
        if state.has_domain_admin {
            let da_count = achievements.values().filter(|a| a.has_da).count();
            if total_domains > 0 {
                lines.push(format!(
                    "\u{2605} DOMAIN ADMIN ACHIEVED ({da_count}/{total_domains} domains)"
                ));
            } else {
                lines.push("\u{2605} DOMAIN ADMIN ACHIEVED".to_string());
            }
            if let Some(path) = &state.domain_admin_path {
                lines.push(format!("  path: {path}"));
            }
        }
        if state.has_golden_ticket {
            let gt_count = achievements
                .values()
                .filter(|a| a.has_golden_ticket)
                .count();
            if total_domains > 0 {
                lines.push(format!(
                    "\u{2605} GOLDEN TICKET OBTAINED ({gt_count}/{total_domains} domains)"
                ));
            } else {
                lines.push("\u{2605} GOLDEN TICKET OBTAINED".to_string());
            }
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

    if domains.is_empty() {
        println!("Domains: None");
    } else {
        println!(
            "Domains ({}/{} compromised, {}/{} forests):",
            compromised_count,
            domains.len(),
            compromised_forests_count,
            forest_roots.len()
        );
        let mut displayed = HashSet::new();
        for root in forest_roots {
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

    print_token_coverage(
        &state.discovered_vulnerabilities,
        &state.exploited_vulnerabilities,
    );

    print_attack_path(&state.all_timeline_events);
    print_mitre_techniques(&state.all_techniques, &state.all_timeline_events);
}

fn operation_timing_lines(
    state: &SharedRedTeamState,
    now: chrono::DateTime<chrono::Utc>,
) -> Vec<String> {
    let started = state.started_at.format("%Y-%m-%d %H:%M:%S UTC");
    let mut lines = vec![format!("Started:   {started}")];

    if let Some(completed) = state.completed_at {
        let ended = completed.format("%Y-%m-%d %H:%M:%S UTC");
        let elapsed = format_duration(completed - state.started_at);
        lines.push(format!("Completed: {ended} ({elapsed})"));
    } else if let Some(red_completed) = state.red_completed_at {
        let ended = red_completed.format("%Y-%m-%d %H:%M:%S UTC");
        let elapsed = format_duration(red_completed - state.started_at);
        lines.push(format!("Completed: {ended} ({elapsed})"));
        if state.red_blocked_on_blue {
            lines.push("Finalizing: waiting on blue investigations".to_string());
        } else if let Some(reason) = &state.red_completion_reason {
            lines.push(format!("Finalizing: {reason}"));
        }
    } else {
        let elapsed = format_duration(now - state.started_at);
        lines.push(format!("Running:   {elapsed}"));
    }

    lines
}

/// Compact summary used by `ops runtime`: DA/GT banner with per-domain
/// breakdown plus a one-line host/DC count. Shares formatting with
/// `print_loot_human` so the live-watch view stays consistent with `ops loot`.
pub(super) fn print_runtime_summary(
    state: &SharedRedTeamState,
    credentials: &[Credential],
    hashes: &[Hash],
    domains_input: &[String],
) {
    let topology = compute_forest_topology(domains_input);
    let domains: Vec<String> = {
        let mut all: Vec<String> = topology.forest_roots.clone();
        all.extend(topology.child_domains.keys().cloned());
        all.sort();
        all.dedup();
        all
    };
    let forest_roots = &topology.forest_roots;
    let child_domains = &topology.child_domains;

    let achievements = build_domain_achievements(state, hashes, credentials);
    let compromised_count = achievements
        .values()
        .filter(|a| a.has_da || a.has_golden_ticket)
        .count();
    let compromised_forests_count = count_compromised_forests(&topology, &achievements);

    if state.has_domain_admin || state.has_golden_ticket {
        let mut lines = Vec::new();
        let total_domains = domains.len();
        if state.has_domain_admin {
            let da_count = achievements.values().filter(|a| a.has_da).count();
            if total_domains > 0 {
                lines.push(format!(
                    "\u{2605} DOMAIN ADMIN ACHIEVED ({da_count}/{total_domains} domains)"
                ));
            } else {
                lines.push("\u{2605} DOMAIN ADMIN ACHIEVED".to_string());
            }
            if let Some(path) = &state.domain_admin_path {
                lines.push(format!("  path: {path}"));
            }
        }
        if state.has_golden_ticket {
            let gt_count = achievements
                .values()
                .filter(|a| a.has_golden_ticket)
                .count();
            if total_domains > 0 {
                lines.push(format!(
                    "\u{2605} GOLDEN TICKET OBTAINED ({gt_count}/{total_domains} domains)"
                ));
            } else {
                lines.push("\u{2605} GOLDEN TICKET OBTAINED".to_string());
            }
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

    if !domains.is_empty() {
        println!(
            "Domains ({}/{} compromised, {}/{} forests):",
            compromised_count,
            domains.len(),
            compromised_forests_count,
            forest_roots.len()
        );
        let mut displayed = HashSet::new();
        for root in forest_roots {
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

    let merged_hosts = dedup_hosts(
        &state.all_hosts,
        &state.netbios_to_fqdn,
        &state.domain_controllers,
    );
    let dcs_count = merged_hosts.iter().filter(|h| h.is_dc).count();
    println!("Hosts: {} ({} DCs)", merged_hosts.len(), dcs_count);
}

/// Priority threshold (inclusive) at or below which a vulnerability is treated
/// as actively exploitable rather than an informational finding.
const EXPLOITABLE_PRIORITY_MAX: i32 = 3;

/// Print vulnerabilities split into two tables: actively exploitable
/// (priority <= EXPLOITABLE_PRIORITY_MAX) and informational findings (rest).
fn print_vulnerabilities(
    discovered: &HashMap<String, VulnerabilityInfo>,
    exploited: &HashSet<String>,
) {
    if discovered.is_empty() {
        return;
    }

    let mut exploitable: Vec<(&String, &VulnerabilityInfo)> = Vec::new();
    let mut findings: Vec<(&String, &VulnerabilityInfo)> = Vec::new();
    for (id, vuln) in discovered.iter() {
        if vuln.priority <= EXPLOITABLE_PRIORITY_MAX {
            exploitable.push((id, vuln));
        } else {
            findings.push((id, vuln));
        }
    }
    let sort_vulns = |vulns: &mut Vec<(&String, &VulnerabilityInfo)>| {
        vulns.sort_by(|a, b| {
            a.1.priority
                .cmp(&b.1.priority)
                .then(a.1.vuln_type.cmp(&b.1.vuln_type))
        });
    };
    sort_vulns(&mut exploitable);
    sort_vulns(&mut findings);

    let exploited_in_exploitable = exploitable
        .iter()
        .filter(|(id, _)| exploited.contains(*id))
        .count();

    println!(
        "Exploitable Vulnerabilities ({}, {} exploited):",
        exploitable.len(),
        exploited_in_exploitable
    );
    if exploitable.is_empty() {
        println!("  (none)");
    } else {
        print_vuln_table(&exploitable, exploited);
    }
    println!();

    println!("Findings ({}):", findings.len());
    if !findings.is_empty() {
        print_vuln_table(&findings, exploited);
    }
    println!();
}

/// Render a scoreboard-aligned token coverage table:
///
///   Category               Discovered  Exploited  Status
///   ------------------------------------------------------
///   acl_abuse                       12          3  PARTIAL
///   adcs_esc1                        2          2  ✓
///   constrained_delegation           2          0  ✗
///   ...
///
/// The category is the dreadgoad scoreboard token prefix (anything before
/// the first `_<details>` segment). Mirrors `aresExploitedToTechniqueIDs`
/// in `DreadGOAD/cli/internal/scoreboard/transport_ares.go` so what the
/// operator sees here matches what the scoreboard will credit on the next
/// dredgoad pull — the diff between "Discovered" and "Exploited" is the
/// concrete regression backlog.
/// Forest-root and child-domain partitioning of a sorted/deduped domain list.
#[derive(Debug, Default, PartialEq, Eq)]
pub(super) struct ForestTopology {
    /// Sorted list of domain names that are NOT children of any other entry.
    pub forest_roots: Vec<String>,
    /// Map from child FQDN → its parent FQDN. Only populated when the parent
    /// is itself in the input list (`a.b.c.local` is a child of `b.c.local`
    /// only when `b.c.local` was also discovered).
    pub child_domains: HashMap<String, String>,
}

/// Partition a domain list into forest roots and (child → parent) edges.
///
/// Inputs are normalised first: each entry is trimmed, has trailing `.`
/// stripped, lowercased, deduped, and sorted. A domain with 3+ labels whose
/// `labels[1..]` parent appears in the input list is recorded as a child;
/// everything else is a forest root.
///
/// The forest root list is returned sorted ascending. Idempotent — calling
/// twice on the same input produces the same output.
pub(super) fn compute_forest_topology(domains_input: &[String]) -> ForestTopology {
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
    ForestTopology {
        forest_roots,
        child_domains,
    }
}

/// Count compromised forests — a forest is compromised when its root or ANY
/// of its children has DA OR a golden ticket. Used for the
/// `(N/M forests)` figure in the loot human-readable header.
pub(super) fn count_compromised_forests(
    topology: &ForestTopology,
    achievements: &HashMap<String, DomainAchievement>,
) -> usize {
    topology
        .forest_roots
        .iter()
        .filter(|root| {
            let root_hit = achievements
                .get(*root)
                .map(|a| a.has_da || a.has_golden_ticket)
                .unwrap_or(false);
            let child_hit = topology
                .child_domains
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
        .count()
}

/// One row of the token-coverage scoreboard.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct TokenCoverageRow {
    pub category: String,
    pub discovered: usize,
    pub exploited: usize,
    pub status: &'static str,
}

/// Compute the rows of the token-coverage scoreboard from discovered + exploited
/// vuln IDs. Pure — no IO.
///
/// Each row carries the `(category, discovered_count, exploited_count, status)`
/// tuple. `status` is `"\u{2713}"` when fully exploited, `"PARTIAL"` when some
/// of the discovered vulns landed but not all, and `"\u{2717}"` when nothing
/// landed yet. Categories that only appear under `:exploited` (e.g. milestone-
/// emitted golden ticket entries) render with `discovered=0, exploited>0` and
/// status `"\u{2713}"` — implicit-token semantics. Categories are sorted
/// alphabetically.
pub(super) fn compute_token_coverage_rows(
    discovered: &HashMap<String, VulnerabilityInfo>,
    exploited: &HashSet<String>,
) -> Vec<TokenCoverageRow> {
    let mut discovered_by_cat: std::collections::BTreeMap<String, usize> =
        std::collections::BTreeMap::new();
    let mut exploited_by_cat: std::collections::BTreeMap<String, usize> =
        std::collections::BTreeMap::new();

    for id in discovered.keys() {
        let cat = token_category(id);
        *discovered_by_cat.entry(cat).or_default() += 1;
    }
    for id in exploited {
        let cat = token_category(id);
        *exploited_by_cat.entry(cat).or_default() += 1;
    }

    let mut categories: Vec<&String> = discovered_by_cat.keys().collect();
    for k in exploited_by_cat.keys() {
        if !categories.contains(&k) {
            categories.push(k);
        }
    }
    categories.sort();

    categories
        .into_iter()
        .map(|cat| {
            let d = discovered_by_cat.get(cat).copied().unwrap_or(0);
            let e = exploited_by_cat.get(cat).copied().unwrap_or(0);
            let status = if d == 0 && e > 0 {
                "\u{2713}"
            } else if e == 0 {
                "\u{2717}"
            } else if e >= d {
                "\u{2713}"
            } else {
                "PARTIAL"
            };
            TokenCoverageRow {
                category: cat.clone(),
                discovered: d,
                exploited: e,
                status,
            }
        })
        .collect()
}

fn print_token_coverage(
    discovered: &HashMap<String, VulnerabilityInfo>,
    exploited: &HashSet<String>,
) {
    if discovered.is_empty() && exploited.is_empty() {
        return;
    }

    let rows = compute_token_coverage_rows(discovered, exploited);

    println!(
        "Token Coverage ({} categories observed, scoreboard alignment):",
        rows.len()
    );
    println!(
        "  {:<30} {:>10} {:>10}  Status",
        "Category", "Discovered", "Exploited"
    );
    println!("  {}", "-".repeat(70));
    for row in &rows {
        println!(
            "  {:<30} {:>10} {:>10}  {}",
            row.category, row.discovered, row.exploited, row.status
        );
    }
    println!();
}

/// Extract the scoreboard category from a vuln_id. The category is the
/// longest known prefix that matches a dreadgoad token matcher — for
/// `acl_writeproperty_alice_admins` the category is `acl_abuse`; for
/// `golden_ticket-contoso.local` it's `golden_ticket`; for
/// `adcs_esc1_192.168.58.50_template` it's `adcs_esc1`.
///
/// Kept in sync with `aresExploitedToTechniqueIDs` in
/// `DreadGOAD/cli/internal/scoreboard/transport_ares.go`.
///
/// Visible to sibling `json.rs` so the JSON output reuses the exact same
/// classification — divergence between text and JSON views would silently
/// confuse downstream blue-team dashboards.
pub(super) fn token_category(vuln_id: &str) -> String {
    let lower = vuln_id.to_lowercase();
    // ADCS ESC variants are the only category where the trailing digits
    // are part of the category name (esc1, esc10_case1, esc15, ...). Long
    // forms must be matched before short ones so `adcs_esc10_case1` does
    // not collapse to `adcs_esc1`.
    const ADCS: &[&str] = &[
        "adcs_esc10_case1",
        "adcs_esc10_case2",
        "adcs_esc11",
        "adcs_esc13",
        "adcs_esc15",
        "adcs_esc1",
        "adcs_esc2",
        "adcs_esc3",
        "adcs_esc4",
        "adcs_esc6",
        "adcs_esc7",
        "adcs_esc8",
        "adcs_esc9",
    ];
    for esc in ADCS {
        if lower.starts_with(&format!("{esc}_")) || lower == *esc {
            return (*esc).to_string();
        }
    }
    // Special-case ACL primitives — many vuln_id forms (acl_writeproperty,
    // acl_genericall, acl_allextendedrights, etc.) collapse to a single
    // `acl_abuse` scoreboard objective.
    if lower.starts_with("acl_") {
        return "acl_abuse".into();
    }
    // Golden ticket uses `golden_ticket_<domain>` form.
    if lower.starts_with("golden_ticket_") {
        return "golden_ticket".into();
    }
    // Remaining categories — first prefix-segment match wins. Order
    // longest-first to handle nested prefixes (e.g. `mssql_linked_server_`
    // before bare `mssql_`).
    const CATEGORIES: &[&str] = &[
        "mssql_linked_server",
        "mssql_impersonation",
        "constrained_delegation",
        "unconstrained_delegation",
        "shadow_credentials",
        "ntlm_relay",
        "child_to_parent",
        "forest_trust",
        "sid_history",
        "asrep_roast",
        "seimpersonate",
        "kerberoast",
        "ntlmv1",
        "gpo_abuse",
        "gpo",
        "mssql",
        "llmnr",
        "gmsa",
        "laps",
        "rbcd",
    ];
    for c in CATEGORIES {
        if lower.starts_with(&format!("{c}_")) || lower == *c {
            // Normalise alias prefixes to their canonical scoreboard
            // category — `gpo_writeproperty` → `gpo_abuse`, `mssql_*` →
            // `mssql_exploit`.
            return match *c {
                "gpo" => "gpo_abuse".into(),
                "mssql_impersonation" | "mssql" => "mssql_exploit".into(),
                "ntlmv1" => "ntlmv1_downgrade".into(),
                "llmnr" => "llmnr_nbtns_poisoning".into(),
                "sid_history" => "sid_history_abuse".into(),
                "seimpersonate" => "seimpersonate".into(),
                "gmsa" => "gmsa_password_read".into(),
                "laps" => "laps_password_read".into(),
                other => other.to_string(),
            };
        }
    }
    "other".into()
}

/// Render a single vulnerability table body (header + rows).
fn print_vuln_table(vulns: &[(&String, &VulnerabilityInfo)], exploited: &HashSet<String>) {
    println!(
        "  {:<30} {:<20} {:>8} {:>9}  Details",
        "Type", "Target", "Priority", "Exploited"
    );
    println!("  {}", "-".repeat(100));
    for (vuln_id, vuln) in vulns {
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

        let already_critical = description.starts_with("CRITICAL:");
        let desc_lower = description.to_lowercase();
        let is_critical = !already_critical
            && (desc_lower.contains("krbtgt")
                || (desc_lower.contains("administrator") && desc_lower.contains("hash"))
                || desc_lower.contains("domain admin"));
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

/// Defensive filter for domains that originated from a Windows workgroup or
/// auto-generated computer name rather than a real Kerberos realm.
///
/// Upstream parsers (`smb.rs`, `output_extraction::users`) drop these at
/// ingest, but old loot already in state may still carry them. Without this
/// filter, a stray `krbtgt@win-xxx.wgrp.local` row would flip the pseudo-domain
/// to "compromised" in the achievements rollup.
///
/// Heuristic operates on a single domain string (no `(name:...)` context here):
/// matches literal `WORKGROUP`/`MSHOME`, and the Windows default computer-name
/// prefix `WIN-` followed by 11 alphanumerics as the first label.
fn looks_like_workgroup_pseudo_domain(domain: &str) -> bool {
    let domain = domain.trim().trim_end_matches('.');
    if domain.is_empty() {
        return false;
    }
    if domain.eq_ignore_ascii_case("WORKGROUP") || domain.eq_ignore_ascii_case("MSHOME") {
        return true;
    }
    let first_label = domain.split('.').next().unwrap_or("");
    if first_label.len() == 15 && first_label[..4].eq_ignore_ascii_case("WIN-") {
        let suffix = &first_label[4..];
        if suffix.bytes().all(|b| b.is_ascii_alphanumeric()) {
            return true;
        }
    }
    false
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
            if domain.is_empty() || looks_like_workgroup_pseudo_domain(&domain) {
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
                if !domain.is_empty() && !looks_like_workgroup_pseudo_domain(&domain) {
                    achievements.entry(domain).or_default().has_golden_ticket = true;
                }
            }
        }
    }

    // Admin credentials
    for c in credentials {
        if c.is_admin {
            let domain = resolve_domain_fqdn(&c.domain, &state.netbios_to_fqdn);
            if domain.is_empty() || looks_like_workgroup_pseudo_domain(&domain) {
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
            if domain.is_empty() || looks_like_workgroup_pseudo_domain(&domain) {
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // Helper: build a minimal SharedRedTeamState for testing

    fn empty_state() -> SharedRedTeamState {
        SharedRedTeamState::new("op-test-001".to_string())
    }

    fn make_hash(username: &str, domain: &str, hash_type: &str) -> Hash {
        Hash {
            id: "h-1".to_string(),
            username: username.to_string(),
            hash_value: "aad3b435b51404eeaad3b435b51404ee".to_string(),
            hash_type: hash_type.to_string(),
            domain: domain.to_string(),
            cracked_password: None,
            source: String::new(),
            discovered_at: None,
            parent_id: None,
            attack_step: 0,
            aes_key: None,
            is_previous: false,
            source_host: None,
            is_trust_key: false,
            trust_pair_label: None,
        }
    }

    fn make_credential(username: &str, domain: &str, is_admin: bool) -> Credential {
        Credential {
            id: "c-1".to_string(),
            username: username.to_string(),
            password: "P@ssw0rd!".to_string(), // pragma: allowlist secret
            domain: domain.to_string(),
            source: String::new(),
            discovered_at: None,
            is_admin,
            parent_id: None,
            attack_step: 0,
        }
    }

    #[test]
    fn operation_timing_red_complete_waiting_on_blue_prints_completed() {
        let mut state = empty_state();
        state.started_at = chrono::DateTime::parse_from_rfc3339("2026-05-15T20:53:56Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        state.red_completed_at = Some(
            chrono::DateTime::parse_from_rfc3339("2026-05-15T22:04:43Z")
                .unwrap()
                .with_timezone(&chrono::Utc),
        );
        state.red_blocked_on_blue = true;

        let now = chrono::DateTime::parse_from_rfc3339("2026-05-15T22:10:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let lines = operation_timing_lines(&state, now);

        assert_eq!(lines[0], "Started:   2026-05-15 20:53:56 UTC");
        assert_eq!(lines[1], "Completed: 2026-05-15 22:04:43 UTC (1h 10m 47s)");
        assert_eq!(lines[2], "Finalizing: waiting on blue investigations");
        assert!(!lines.iter().any(|line| line.starts_with("Running:")));
    }

    // capitalize

    #[test]
    fn capitalize_normal() {
        assert_eq!(capitalize("hostname"), "Hostname");
    }

    #[test]
    fn capitalize_already_upper() {
        assert_eq!(capitalize("Domain"), "Domain");
    }

    #[test]
    fn capitalize_empty() {
        assert_eq!(capitalize(""), "");
    }

    #[test]
    fn capitalize_single_char() {
        assert_eq!(capitalize("a"), "A");
    }

    // format_vuln_details

    #[test]
    fn format_vuln_details_empty() {
        let details = HashMap::new();
        assert_eq!(format_vuln_details(&details), "");
    }

    #[test]
    fn format_vuln_details_priority_keys_order() {
        let mut details = HashMap::new();
        details.insert("domain".to_string(), json!("contoso.local"));
        details.insert("hostname".to_string(), json!("dc01.contoso.local"));
        details.insert("account_name".to_string(), json!("svc_sql"));

        let result = format_vuln_details(&details);
        // Priority keys should appear in the order defined: hostname, account_name, domain
        let hostname_pos = result.find("Hostname:").unwrap();
        let account_pos = result.find("Account_name:").unwrap();
        let domain_pos = result.find("Domain:").unwrap();
        assert!(hostname_pos < account_pos);
        assert!(account_pos < domain_pos);
    }

    #[test]
    fn format_vuln_details_skips_null_and_empty() {
        let mut details = HashMap::new();
        details.insert("hostname".to_string(), json!("dc01.contoso.local"));
        details.insert("note".to_string(), json!(null));
        details.insert("type".to_string(), json!(""));

        let result = format_vuln_details(&details);
        assert!(result.contains("Hostname: dc01.contoso.local"));
        assert!(!result.contains("Note:"));
        assert!(!result.contains("Type:"));
    }

    #[test]
    fn format_vuln_details_non_string_values() {
        let mut details = HashMap::new();
        details.insert("hostname".to_string(), json!(42));

        let result = format_vuln_details(&details);
        assert!(result.contains("Hostname: 42"));
    }

    #[test]
    fn format_vuln_details_remaining_keys_sorted() {
        let mut details = HashMap::new();
        details.insert("zebra".to_string(), json!("z"));
        details.insert("alpha".to_string(), json!("a"));

        let result = format_vuln_details(&details);
        let alpha_pos = result.find("Alpha:").unwrap();
        let zebra_pos = result.find("Zebra:").unwrap();
        assert!(alpha_pos < zebra_pos);
    }

    // format_timeline_timestamp

    #[test]
    fn format_timeline_timestamp_rfc3339() {
        let result = format_timeline_timestamp("2026-04-20T14:30:00Z");
        assert_eq!(result, "2026-04-20 14:30:00");
    }

    #[test]
    fn format_timeline_timestamp_rfc3339_with_offset() {
        let result = format_timeline_timestamp("2026-04-20T14:30:00+00:00");
        assert_eq!(result, "2026-04-20 14:30:00");
    }

    #[test]
    fn format_timeline_timestamp_naive_with_fractional() {
        let result = format_timeline_timestamp("2026-04-20T14:30:00.123456");
        assert_eq!(result, "2026-04-20 14:30:00");
    }

    #[test]
    fn format_timeline_timestamp_unparseable_short() {
        let result = format_timeline_timestamp("unknown");
        assert_eq!(result, "unknown");
    }

    #[test]
    fn format_timeline_timestamp_unparseable_long() {
        let long = "this-is-a-very-long-timestamp-value-that-exceeds-23-chars";
        let result = format_timeline_timestamp(long);
        assert_eq!(result.len(), 23);
        assert_eq!(result, &long[..23]);
    }

    // extract_mitre_from_event

    #[test]
    fn extract_mitre_from_event_array() {
        let event = json!({
            "mitre_techniques": ["T1003", "T1558.001"]
        });
        let result = extract_mitre_from_event(&event);
        assert_eq!(result, "T1003, T1558.001");
    }

    #[test]
    fn extract_mitre_from_event_string() {
        let event = json!({
            "mitre_techniques": "T1003.006"
        });
        let result = extract_mitre_from_event(&event);
        assert_eq!(result, "T1003.006");
    }

    #[test]
    fn extract_mitre_from_event_missing() {
        let event = json!({
            "description": "some event"
        });
        let result = extract_mitre_from_event(&event);
        assert_eq!(result, "");
    }

    #[test]
    fn extract_mitre_from_event_empty_array() {
        let event = json!({
            "mitre_techniques": []
        });
        let result = extract_mitre_from_event(&event);
        assert_eq!(result, "");
    }

    // mitre_technique_name

    #[test]
    fn mitre_technique_name_known() {
        assert_eq!(mitre_technique_name("T1003"), "OS Credential Dumping");
        assert_eq!(mitre_technique_name("T1558.001"), "Golden Ticket");
        assert_eq!(mitre_technique_name("T1003.006"), "DCSync");
        assert_eq!(mitre_technique_name("T1550.002"), "Pass the Hash");
    }

    #[test]
    fn mitre_technique_name_unknown() {
        assert_eq!(mitre_technique_name("T9999"), "");
        assert_eq!(mitre_technique_name(""), "");
    }

    // resolve_domain_fqdn

    #[test]
    fn resolve_domain_fqdn_already_fqdn() {
        let map = HashMap::new();
        assert_eq!(resolve_domain_fqdn("contoso.local", &map), "contoso.local");
    }

    #[test]
    fn resolve_domain_fqdn_trailing_dot() {
        let map = HashMap::new();
        assert_eq!(resolve_domain_fqdn("contoso.local.", &map), "contoso.local");
    }

    #[test]
    fn resolve_domain_fqdn_netbios_lower_lookup() {
        let mut map = HashMap::new();
        map.insert("contoso".to_string(), "contoso.local".to_string());
        assert_eq!(resolve_domain_fqdn("contoso", &map), "contoso.local");
    }

    #[test]
    fn resolve_domain_fqdn_netbios_upper_lookup() {
        let mut map = HashMap::new();
        map.insert("CONTOSO".to_string(), "contoso.local".to_string());
        assert_eq!(resolve_domain_fqdn("CONTOSO", &map), "contoso.local");
    }

    #[test]
    fn resolve_domain_fqdn_empty() {
        let map = HashMap::new();
        assert_eq!(resolve_domain_fqdn("", &map), "");
    }

    #[test]
    fn resolve_domain_fqdn_unresolvable_netbios() {
        let map = HashMap::new();
        // No match in map, returns as lowercase
        assert_eq!(resolve_domain_fqdn("CONTOSO", &map), "contoso");
    }

    #[test]
    fn resolve_domain_fqdn_case_normalization() {
        let map = HashMap::new();
        assert_eq!(resolve_domain_fqdn("CONTOSO.LOCAL", &map), "contoso.local");
    }

    // build_domain_achievements

    #[test]
    fn build_domain_achievements_empty() {
        let state = empty_state();
        let achievements = build_domain_achievements(&state, &[], &[]);
        assert!(achievements.is_empty());
    }

    #[test]
    fn build_domain_achievements_krbtgt_hash() {
        let state = empty_state();
        let hashes = vec![make_hash("krbtgt", "contoso.local", "ntlm")];

        let achievements = build_domain_achievements(&state, &hashes, &[]);
        let contoso = achievements.get("contoso.local").unwrap();
        assert!(contoso.has_da);
        assert!(!contoso.has_golden_ticket);
        assert_eq!(contoso.krbtgt_hash_types, vec!["ntlm"]);
    }

    #[test]
    fn build_domain_achievements_krbtgt_multiple_hash_types() {
        let state = empty_state();
        let hashes = vec![
            make_hash("krbtgt", "contoso.local", "ntlm"),
            make_hash("krbtgt", "contoso.local", "aes256"),
        ];

        let achievements = build_domain_achievements(&state, &hashes, &[]);
        let contoso = achievements.get("contoso.local").unwrap();
        assert!(contoso.has_da);
        assert_eq!(contoso.krbtgt_hash_types.len(), 2);
        assert!(contoso.krbtgt_hash_types.contains(&"ntlm".to_string()));
        assert!(contoso.krbtgt_hash_types.contains(&"aes256".to_string()));
    }

    #[test]
    fn build_domain_achievements_administrator_hash() {
        let state = empty_state();
        let hashes = vec![make_hash("Administrator", "contoso.local", "ntlm")];

        let achievements = build_domain_achievements(&state, &hashes, &[]);
        let contoso = achievements.get("contoso.local").unwrap();
        assert!(contoso.has_da);
        assert!(contoso.admin_users.contains(&"administrator".to_string()));
    }

    #[test]
    fn build_domain_achievements_admin_credential() {
        let state = empty_state();
        let credentials = vec![make_credential("dadmin", "contoso.local", true)];

        let achievements = build_domain_achievements(&state, &[], &credentials);
        let contoso = achievements.get("contoso.local").unwrap();
        assert!(!contoso.has_da); // admin cred alone does not set has_da
        assert!(contoso.admin_users.contains(&"dadmin".to_string()));
    }

    #[test]
    fn build_domain_achievements_golden_ticket_vuln() {
        let mut state = empty_state();
        let mut details = HashMap::new();
        details.insert("domain".to_string(), json!("contoso.local"));
        state.discovered_vulnerabilities.insert(
            "gt-contoso".to_string(),
            VulnerabilityInfo {
                vuln_id: "gt-contoso".to_string(),
                vuln_type: "golden_ticket".to_string(),
                target: "192.168.58.10".to_string(),
                discovered_by: "agent-1".to_string(),
                discovered_at: chrono::Utc::now(),
                details,
                recommended_agent: String::new(),
                priority: 1,
            },
        );

        let achievements = build_domain_achievements(&state, &[], &[]);
        let contoso = achievements.get("contoso.local").unwrap();
        assert!(contoso.has_golden_ticket);
    }

    #[test]
    fn build_domain_achievements_multi_domain() {
        let mut state = empty_state();
        state
            .netbios_to_fqdn
            .insert("fabrikam".to_string(), "fabrikam.local".to_string());

        let hashes = vec![
            make_hash("krbtgt", "contoso.local", "ntlm"),
            make_hash("Administrator", "fabrikam.local", "ntlm"),
        ];
        let credentials = vec![make_credential("svc_admin", "fabrikam.local", true)];

        let achievements = build_domain_achievements(&state, &hashes, &credentials);
        assert!(achievements.contains_key("contoso.local"));
        assert!(achievements.contains_key("fabrikam.local"));

        let contoso = achievements.get("contoso.local").unwrap();
        assert!(contoso.has_da);

        let fabrikam = achievements.get("fabrikam.local").unwrap();
        assert!(fabrikam.has_da);
        assert!(fabrikam.admin_users.contains(&"administrator".to_string()));
        assert!(fabrikam.admin_users.contains(&"svc_admin".to_string()));
    }

    #[test]
    fn build_domain_achievements_netbios_resolution() {
        let mut state = empty_state();
        state
            .netbios_to_fqdn
            .insert("contoso".to_string(), "contoso.local".to_string());

        // Hash domain is NetBIOS, should resolve via the map
        let hashes = vec![make_hash("krbtgt", "contoso", "ntlm")];

        let achievements = build_domain_achievements(&state, &hashes, &[]);
        assert!(achievements.contains_key("contoso.local"));
        let contoso = achievements.get("contoso.local").unwrap();
        assert!(contoso.has_da);
    }

    #[test]
    fn build_domain_achievements_empty_domain_skipped() {
        let state = empty_state();
        let hashes = vec![make_hash("krbtgt", "", "ntlm")];

        let achievements = build_domain_achievements(&state, &hashes, &[]);
        assert!(achievements.is_empty());
    }

    #[test]
    fn build_domain_achievements_skips_workgroup_pseudo_domain() {
        // Old loot row from before the upstream parsers learned to drop
        // workgroup pseudo-domains: an attacker-box krbtgt entry tagged with
        // the auto-generated WIN-XXX...wgrp.local string. The achievements
        // rollup must NOT promote it to a "compromised domain" (DA).
        let state = empty_state();
        let hashes = vec![
            make_hash("krbtgt", "win-abcdefghijk.wgrp.local", "ntlm"),
            make_hash("Administrator", "WORKGROUP", "ntlm"),
            // Real domain alongside the polluted ones must still come through.
            make_hash("krbtgt", "contoso.local", "ntlm"),
        ];
        let credentials = vec![make_credential("admin", "win-abcdefghijk.local", true)];

        let achievements = build_domain_achievements(&state, &hashes, &credentials);
        assert!(!achievements.contains_key("win-abcdefghijk.wgrp.local"));
        assert!(!achievements.contains_key("workgroup"));
        assert!(!achievements.contains_key("win-abcdefghijk.local"));
        assert!(achievements.get("contoso.local").unwrap().has_da);
    }

    #[test]
    fn looks_like_workgroup_pseudo_domain_detects_win_prefix() {
        assert!(looks_like_workgroup_pseudo_domain(
            "win-abcdefghijk.wgrp.local"
        ));
        assert!(looks_like_workgroup_pseudo_domain("WIN-ABCDEFGHIJK.local"));
        assert!(looks_like_workgroup_pseudo_domain("WORKGROUP"));
        assert!(looks_like_workgroup_pseudo_domain("mshome"));
    }

    #[test]
    fn looks_like_workgroup_pseudo_domain_passes_real_domain() {
        assert!(!looks_like_workgroup_pseudo_domain("contoso.local"));
        assert!(!looks_like_workgroup_pseudo_domain("child.contoso.local"));
        assert!(!looks_like_workgroup_pseudo_domain("fabrikam.local"));
        assert!(!looks_like_workgroup_pseudo_domain(""));
        // Wrong length / suffix shape — don't over-trigger
        assert!(!looks_like_workgroup_pseudo_domain("win-short.local"));
        assert!(!looks_like_workgroup_pseudo_domain(
            "win-toolongsuffix9.local"
        ));
        // First label has WIN- prefix but has non-alphanumeric in the suffix
        assert!(!looks_like_workgroup_pseudo_domain("win-abc!defghij.local"));
    }

    // Domain/forest structure computation (inline in print_loot_human)

    /// Extract the domain/forest structure logic into a helper we can test.
    fn compute_forest_structure(
        domains_input: &[String],
    ) -> (Vec<String>, Vec<String>, HashMap<String, String>) {
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
        (domains, forest_roots, child_domains)
    }

    #[test]
    fn forest_structure_single_domain() {
        let input = vec!["contoso.local".to_string()];
        let (domains, roots, children) = compute_forest_structure(&input);
        assert_eq!(domains, vec!["contoso.local"]);
        assert_eq!(roots, vec!["contoso.local"]);
        assert!(children.is_empty());
    }

    #[test]
    fn forest_structure_parent_child() {
        let input = vec![
            "contoso.local".to_string(),
            "child.contoso.local".to_string(),
        ];
        let (_domains, roots, children) = compute_forest_structure(&input);
        assert_eq!(roots, vec!["contoso.local"]);
        assert_eq!(children.len(), 1);
        assert_eq!(
            children.get("child.contoso.local").unwrap(),
            "contoso.local"
        );
    }

    #[test]
    fn forest_structure_two_forests() {
        let input = vec!["contoso.local".to_string(), "fabrikam.local".to_string()];
        let (_domains, roots, children) = compute_forest_structure(&input);
        assert_eq!(roots, vec!["contoso.local", "fabrikam.local"]);
        assert!(children.is_empty());
    }

    #[test]
    fn forest_structure_dedup_and_normalization() {
        let input = vec![
            "CONTOSO.LOCAL.".to_string(),
            "contoso.local".to_string(),
            "  contoso.local  ".to_string(),
        ];
        let (domains, roots, _children) = compute_forest_structure(&input);
        assert_eq!(domains, vec!["contoso.local"]);
        assert_eq!(roots, vec!["contoso.local"]);
    }

    #[test]
    fn forest_structure_empty_strings_filtered() {
        let input = vec![
            "".to_string(),
            "  ".to_string(),
            "contoso.local".to_string(),
        ];
        let (domains, roots, _children) = compute_forest_structure(&input);
        assert_eq!(domains, vec!["contoso.local"]);
        assert_eq!(roots, vec!["contoso.local"]);
    }

    #[test]
    fn forest_structure_orphan_subdomain() {
        // subdomain without its parent in the list: treated as a forest root
        let input = vec!["sub.contoso.local".to_string()];
        let (_domains, roots, children) = compute_forest_structure(&input);
        assert_eq!(roots, vec!["sub.contoso.local"]);
        assert!(children.is_empty());
    }

    // --- token_category coverage ------------------------------------------

    #[test]
    fn token_category_adcs_long_form_does_not_collapse_to_esc1() {
        // Real vuln_id forms always include `_<details>` after the ESC code.
        // The matcher uses `starts_with("{esc}_")` so `adcs_esc1` does NOT
        // steal `adcs_esc10_*` / `adcs_esc11_*` / `adcs_esc15_*`.
        assert_eq!(
            super::token_category("adcs_esc10_case1_192.168.58.50"),
            "adcs_esc10_case1"
        );
        assert_eq!(
            super::token_category("adcs_esc10_case2_192.168.58.50"),
            "adcs_esc10_case2"
        );
        assert_eq!(
            super::token_category("adcs_esc11_192.168.58.50"),
            "adcs_esc11"
        );
        assert_eq!(
            super::token_category("adcs_esc13_192.168.58.50"),
            "adcs_esc13"
        );
        assert_eq!(
            super::token_category("adcs_esc15_192.168.58.50"),
            "adcs_esc15"
        );
        assert_eq!(
            super::token_category("adcs_esc1_192.168.58.50"),
            "adcs_esc1"
        );
    }

    #[test]
    fn token_category_acl_collapses_to_acl_abuse() {
        assert_eq!(
            super::token_category("acl_writeproperty_alice_admins"),
            "acl_abuse"
        );
        assert_eq!(
            super::token_category("acl_genericall_bob_administrator"),
            "acl_abuse"
        );
        assert_eq!(
            super::token_category("acl_allextendedrights_carol_domain_admins"),
            "acl_abuse"
        );
        assert_eq!(super::token_category("acl_writedacl_dave_eve"), "acl_abuse");
    }

    #[test]
    fn token_category_mssql_normalises_to_canonical() {
        assert_eq!(
            super::token_category("mssql_linked_server_192.168.58.51_sql"),
            "mssql_linked_server"
        );
        assert_eq!(
            super::token_category("mssql_impersonation_192.168.58.51"),
            "mssql_exploit"
        );
        assert_eq!(super::token_category("mssql_10_1_2_51"), "mssql_exploit");
    }

    #[test]
    fn token_category_delegation_and_trust() {
        assert_eq!(
            super::token_category("constrained_delegation_alice"),
            "constrained_delegation"
        );
        assert_eq!(
            super::token_category("unconstrained_delegation_web01$"),
            "unconstrained_delegation"
        );
        assert_eq!(super::token_category("rbcd_dc01_web01"), "rbcd");
        assert_eq!(
            super::token_category("child_to_parent_child_contoso_local_contoso_local"),
            "child_to_parent"
        );
        assert_eq!(
            super::token_category("forest_trust_contoso_local_fabrikam_local"),
            "forest_trust"
        );
    }

    #[test]
    fn token_category_golden_ticket_keeps_domain_in_id() {
        assert_eq!(
            super::token_category("golden_ticket_contoso.local"),
            "golden_ticket"
        );
        assert_eq!(
            super::token_category("golden_ticket_child.contoso.local"),
            "golden_ticket"
        );
    }

    #[test]
    fn token_category_aliases_collapse() {
        assert_eq!(super::token_category("ntlmv1_dc01"), "ntlmv1_downgrade");
        assert_eq!(
            super::token_category("llmnr_attacker_box"),
            "llmnr_nbtns_poisoning"
        );
        assert_eq!(
            super::token_category("sid_history_alice"),
            "sid_history_abuse"
        );
        assert_eq!(super::token_category("gmsa_svc_web"), "gmsa_password_read");
        assert_eq!(super::token_category("laps_dc01"), "laps_password_read");
        assert_eq!(
            super::token_category("gpo_writeproperty_alice_31b2"),
            "gpo_abuse"
        );
        assert_eq!(
            super::token_category("seimpersonate_web01"),
            "seimpersonate"
        );
    }

    #[test]
    fn token_category_roast_tokens() {
        assert_eq!(super::token_category("kerberoast_sql_svc"), "kerberoast");
        assert_eq!(
            super::token_category("asrep_roast_contoso.local"),
            "asrep_roast"
        );
    }

    #[test]
    fn token_category_unknown_falls_through_to_other() {
        assert_eq!(super::token_category("zerologon_dc01"), "other");
        assert_eq!(super::token_category("nopac_192.168.58.10"), "other");
        assert_eq!(super::token_category(""), "other");
    }

    // ── compute_forest_topology ─────────────────────────────────────────

    #[test]
    fn topology_empty_input() {
        let t = super::compute_forest_topology(&[]);
        assert!(t.forest_roots.is_empty());
        assert!(t.child_domains.is_empty());
    }

    #[test]
    fn topology_lowercases_trims_and_dedupes() {
        let input: Vec<String> = vec![
            "Contoso.Local".into(),
            "  contoso.local  ".into(),
            "contoso.local.".into(),
            "".into(),
        ];
        let t = super::compute_forest_topology(&input);
        assert_eq!(t.forest_roots, vec!["contoso.local"]);
        assert!(t.child_domains.is_empty());
    }

    #[test]
    fn topology_two_level_is_forest_root() {
        let input: Vec<String> = vec!["contoso.local".into()];
        let t = super::compute_forest_topology(&input);
        assert_eq!(t.forest_roots, vec!["contoso.local"]);
    }

    #[test]
    fn topology_child_recognised_when_parent_in_set() {
        let input: Vec<String> = vec!["child.contoso.local".into(), "contoso.local".into()];
        let t = super::compute_forest_topology(&input);
        assert_eq!(t.forest_roots, vec!["contoso.local"]);
        assert_eq!(
            t.child_domains
                .get("child.contoso.local")
                .map(String::as_str),
            Some("contoso.local"),
        );
    }

    #[test]
    fn topology_child_promoted_to_root_when_parent_missing() {
        // 3 labels but no matching parent → treated as forest root.
        let input: Vec<String> = vec!["orphan.child.local".into()];
        let t = super::compute_forest_topology(&input);
        assert_eq!(t.forest_roots, vec!["orphan.child.local"]);
        assert!(t.child_domains.is_empty());
    }

    #[test]
    fn topology_multiple_forests_each_root() {
        let input: Vec<String> = vec![
            "contoso.local".into(),
            "fabrikam.local".into(),
            "child.contoso.local".into(),
        ];
        let t = super::compute_forest_topology(&input);
        let mut roots = t.forest_roots;
        roots.sort();
        assert_eq!(roots, vec!["contoso.local", "fabrikam.local"]);
        assert_eq!(t.child_domains.len(), 1);
    }

    #[test]
    fn topology_idempotent_against_repeated_input() {
        let input: Vec<String> = vec![
            "Contoso.Local".into(),
            "child.contoso.local.".into(),
            "child.contoso.local".into(),
            "child.contoso.local".into(),
        ];
        let t1 = super::compute_forest_topology(&input);
        let t2 = super::compute_forest_topology(&input);
        assert_eq!(t1, t2);
    }

    // ── count_compromised_forests ───────────────────────────────────────

    fn ach(has_da: bool, has_gt: bool) -> super::DomainAchievement {
        super::DomainAchievement {
            has_da,
            has_golden_ticket: has_gt,
            krbtgt_hash_types: Vec::new(),
            admin_users: Vec::new(),
        }
    }

    #[test]
    fn count_forests_zero_when_no_achievements() {
        let topology = super::compute_forest_topology(&["contoso.local".into()]);
        assert_eq!(
            super::count_compromised_forests(&topology, &HashMap::new()),
            0
        );
    }

    #[test]
    fn count_forests_counts_root_da() {
        let topology = super::compute_forest_topology(&["contoso.local".into()]);
        let mut a = HashMap::new();
        a.insert("contoso.local".to_string(), ach(true, false));
        assert_eq!(super::count_compromised_forests(&topology, &a), 1);
    }

    #[test]
    fn count_forests_counts_root_golden_ticket_only() {
        let topology = super::compute_forest_topology(&["contoso.local".into()]);
        let mut a = HashMap::new();
        a.insert("contoso.local".to_string(), ach(false, true));
        assert_eq!(super::count_compromised_forests(&topology, &a), 1);
    }

    #[test]
    fn count_forests_credits_root_when_child_compromised() {
        let topology =
            super::compute_forest_topology(&["contoso.local".into(), "child.contoso.local".into()]);
        let mut a = HashMap::new();
        a.insert("child.contoso.local".to_string(), ach(true, false));
        // Root itself wasn't compromised but its child was → forest is.
        assert_eq!(super::count_compromised_forests(&topology, &a), 1);
    }

    #[test]
    fn count_forests_multiple_forests() {
        let topology =
            super::compute_forest_topology(&["contoso.local".into(), "fabrikam.local".into()]);
        let mut a = HashMap::new();
        a.insert("contoso.local".to_string(), ach(true, false));
        // Fabrikam not compromised → count = 1.
        assert_eq!(super::count_compromised_forests(&topology, &a), 1);
        a.insert("fabrikam.local".to_string(), ach(false, true));
        assert_eq!(super::count_compromised_forests(&topology, &a), 2);
    }

    #[test]
    fn count_forests_ignores_neither_da_nor_gt() {
        let topology = super::compute_forest_topology(&["contoso.local".into()]);
        let mut a = HashMap::new();
        a.insert("contoso.local".to_string(), ach(false, false));
        assert_eq!(super::count_compromised_forests(&topology, &a), 0);
    }

    // ── compute_token_coverage_rows ─────────────────────────────────────

    fn discovered_vuln(vuln_id: &str) -> (String, ares_core::models::VulnerabilityInfo) {
        (
            vuln_id.to_string(),
            ares_core::models::VulnerabilityInfo {
                vuln_id: vuln_id.into(),
                vuln_type: "test".into(),
                target: "".into(),
                discovered_by: "test".into(),
                discovered_at: chrono::Utc::now(),
                details: HashMap::new(),
                recommended_agent: String::new(),
                priority: 1,
            },
        )
    }

    fn discovered_map(ids: &[&str]) -> HashMap<String, ares_core::models::VulnerabilityInfo> {
        ids.iter().map(|i| discovered_vuln(i)).collect()
    }

    #[test]
    fn coverage_rows_empty_when_both_empty() {
        let rows = super::compute_token_coverage_rows(&HashMap::new(), &HashSet::new());
        assert!(rows.is_empty());
    }

    #[test]
    fn coverage_rows_x_mark_when_discovered_but_none_exploited() {
        let rows = super::compute_token_coverage_rows(
            &discovered_map(&["kerberoast_svc_sql"]),
            &HashSet::new(),
        );
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].category, "kerberoast");
        assert_eq!(rows[0].discovered, 1);
        assert_eq!(rows[0].exploited, 0);
        assert_eq!(rows[0].status, "\u{2717}");
    }

    #[test]
    fn coverage_rows_check_mark_when_all_exploited() {
        let discovered = discovered_map(&["kerberoast_svc_sql"]);
        let exploited: HashSet<String> = ["kerberoast_svc_sql".to_string()].into_iter().collect();
        let rows = super::compute_token_coverage_rows(&discovered, &exploited);
        assert_eq!(rows[0].status, "\u{2713}");
        assert_eq!(rows[0].exploited, 1);
    }

    #[test]
    fn coverage_rows_partial_when_some_exploited() {
        let discovered = discovered_map(&["kerberoast_a", "kerberoast_b"]);
        let exploited: HashSet<String> = ["kerberoast_a".to_string()].into_iter().collect();
        let rows = super::compute_token_coverage_rows(&discovered, &exploited);
        assert_eq!(rows[0].category, "kerberoast");
        assert_eq!(rows[0].discovered, 2);
        assert_eq!(rows[0].exploited, 1);
        assert_eq!(rows[0].status, "PARTIAL");
    }

    #[test]
    fn coverage_rows_implicit_token_when_only_exploited_set_has_entry() {
        // Milestone-emitted golden_ticket appears only in exploited.
        let exploited: HashSet<String> = ["golden_ticket_contoso.local".to_string()]
            .into_iter()
            .collect();
        let rows = super::compute_token_coverage_rows(&HashMap::new(), &exploited);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].category, "golden_ticket");
        assert_eq!(rows[0].discovered, 0);
        assert_eq!(rows[0].exploited, 1);
        assert_eq!(rows[0].status, "\u{2713}");
    }

    #[test]
    fn coverage_rows_sorted_alphabetically() {
        let discovered = discovered_map(&["kerberoast_a", "asrep_roast_b", "adcs_esc1_c"]);
        let rows = super::compute_token_coverage_rows(&discovered, &HashSet::new());
        let cats: Vec<&str> = rows.iter().map(|r| r.category.as_str()).collect();
        assert_eq!(cats, vec!["adcs_esc1", "asrep_roast", "kerberoast"]);
    }

    #[test]
    fn coverage_rows_excess_exploited_still_check_mark() {
        // exploited >= discovered → check mark, not partial. Mirrors the
        // implicit-token semantics for tokens credited via milestone after
        // discovery dropped them.
        let discovered = discovered_map(&["kerberoast_a"]);
        let exploited: HashSet<String> = ["kerberoast_a".to_string(), "kerberoast_b".to_string()]
            .into_iter()
            .collect();
        let rows = super::compute_token_coverage_rows(&discovered, &exploited);
        assert_eq!(rows[0].status, "\u{2713}");
        assert_eq!(rows[0].discovered, 1);
        assert_eq!(rows[0].exploited, 2);
    }
}
