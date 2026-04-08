//! Report generation using the Tera templating engine.
//!
//! Provides red team and blue team report generators that produce markdown
//! reports from shared operation state. Templates are embedded at compile time
//! using `include_str!`.

use std::collections::{HashMap, HashSet};

use chrono::Utc;
use once_cell::sync::Lazy;
use regex::Regex;
use serde::Serialize;
use tera::{Context, Tera};

use crate::models::{Credential, Hash, Host, Share, SharedRedTeamState, User, VulnerabilityInfo};

// ============================================================================
// Embedded templates
// ============================================================================

const REDTEAM_SUMMARY_TEMPLATE: &str =
    include_str!("../templates/redteam/reports/operation_summary.md.tera");
const REDTEAM_COMPREHENSIVE_TEMPLATE: &str =
    include_str!("../templates/redteam/reports/comprehensive_report.md.tera");
const BLUETEAM_COMPREHENSIVE_TEMPLATE: &str =
    include_str!("../templates/blueteam/reports/comprehensive_report.md.tera");

// ============================================================================
// MITRE technique lookup
// ============================================================================

const MITRE_TECHNIQUES_YAML: &str =
    include_str!("../../../src/ares/templates/mitre_techniques.yaml");

static MITRE_TECHNIQUES: Lazy<HashMap<String, String>> = Lazy::new(|| {
    serde_yaml::from_str::<HashMap<String, String>>(MITRE_TECHNIQUES_YAML).unwrap_or_default()
});

/// Get a display string for a MITRE technique ID (e.g. "T1003.006 (DCSync)").
pub fn get_technique_display(technique_id: &str) -> String {
    match MITRE_TECHNIQUES.get(technique_id) {
        Some(name) => format!("{technique_id} ({name})"),
        None => technique_id.to_string(),
    }
}

// ============================================================================
// Vulnerability detail formatting
// ============================================================================

/// Format vulnerability details into a human-readable string.
pub fn format_vuln_details(details: &HashMap<String, serde_json::Value>) -> String {
    if details.is_empty() {
        return "-".to_string();
    }

    // Ordered key display names
    let key_display: &[(&str, &str)] = &[
        ("account", "Account"),
        ("account_name", "Account"),
        ("username", "Username"),
        ("domain", "Domain"),
        ("target_spn", "Target SPN"),
        ("delegation_type", "Type"),
        ("dc_ip", "DC IP"),
        ("ca_name", "CA Name"),
        ("ca_host", "CA Host"),
        ("hostname", "Hostname"),
        ("hash", "Hash"),
        ("note", "Note"),
        ("attack_type", "Attack Type"),
        ("adcs_server", "ADCS Server"),
    ];

    let skip_keys: HashSet<&str> = [
        "has_credentials",
        "discovered_by",
        "services",
        "available_credentials",
        "attack_steps",
        "is_sql_account",
    ]
    .into_iter()
    .collect();

    let mut parts = Vec::new();
    let mut seen_keys = HashSet::new();

    // Ordered keys first
    for &(key, display_name) in key_display {
        if skip_keys.contains(key) {
            continue;
        }
        if let Some(value) = details.get(key) {
            seen_keys.insert(key);
            if let Some(s) = value_to_display(value) {
                parts.push(format!("{display_name}: {s}"));
            }
        }
    }

    // Remaining keys (not in ordered list or skip list)
    for (key, value) in details {
        let key_str = key.as_str();
        if seen_keys.contains(key_str) || skip_keys.contains(key_str) {
            continue;
        }
        // Skip complex types
        if value.is_array() || value.is_object() {
            continue;
        }
        if let Some(s) = value_to_display(value) {
            let display_key = key.replace('_', " ");
            // Title case
            let display_key: String = display_key
                .split_whitespace()
                .map(|w| {
                    let mut chars = w.chars();
                    match chars.next() {
                        Some(c) => c.to_uppercase().to_string() + &chars.as_str().to_lowercase(),
                        None => String::new(),
                    }
                })
                .collect::<Vec<_>>()
                .join(" ");
            parts.push(format!("{display_key}: {s}"));
        }
    }

    if parts.is_empty() {
        "-".to_string()
    } else {
        parts.join("; ")
    }
}

fn value_to_display(value: &serde_json::Value) -> Option<String> {
    match value {
        serde_json::Value::Null => None,
        serde_json::Value::String(s) if s.is_empty() => None,
        serde_json::Value::String(s) => Some(s.clone()),
        serde_json::Value::Bool(b) => Some(b.to_string()),
        serde_json::Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

// ============================================================================
// Weakness parsing & deduplication
// ============================================================================

static WEAKNESS_FIELD_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\*\*([^*:]+):\*\*\s*(.*)$").unwrap());

/// Parsed weakness block fields.
#[derive(Debug, Clone, Default, Serialize)]
pub struct ParsedWeakness {
    pub title: String,
    pub vulnerability: String,
    pub affected_resource: String,
    pub discovery_method: String,
    pub impact: String,
}

/// Parse a markdown weakness block into structured fields.
fn parse_weakness_block(block: &str) -> ParsedWeakness {
    let mut result = ParsedWeakness::default();
    if block.is_empty() {
        return result;
    }

    for raw_line in block.lines() {
        let stripped = raw_line.trim();
        if stripped.is_empty() {
            continue;
        }

        // Title from ### heading
        if let Some(rest) = stripped.strip_prefix("### ") {
            result.title = rest.trim().to_string();
        } else if stripped.starts_with("**")
            && !stripped.contains(":**")
            && stripped.ends_with("**")
        {
            result.title = stripped.trim_matches('*').trim().to_string();
        } else if stripped.contains(":**") {
            let clean = stripped.trim_start_matches('-').trim();
            if let Some(caps) = WEAKNESS_FIELD_RE.captures(clean) {
                let key = caps[1].trim().to_lowercase().replace(' ', "_");
                let value = caps[2].trim().to_string();
                match key.as_str() {
                    "vulnerability" => result.vulnerability = value,
                    "affected_resource" => result.affected_resource = value,
                    "discovery_method" => result.discovery_method = value,
                    "impact" => result.impact = value,
                    "title" => result.title = value,
                    _ => {}
                }
            }
        }
    }

    result
}

/// Parse and deduplicate weaknesses by normalized title.
pub fn deduplicate_weaknesses(weaknesses: &[String]) -> Vec<ParsedWeakness> {
    let mut seen_titles: HashSet<String> = HashSet::new();
    let mut result = Vec::new();

    for w in weaknesses {
        let parsed = parse_weakness_block(w);
        let title = parsed.title.trim().to_string();
        // Normalize: lowercase, normalize dashes
        let normalized = title
            .to_lowercase()
            .replace(['\u{2014}', '\u{2013}'], "-")
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ");

        if !normalized.is_empty() && seen_titles.contains(&normalized) {
            continue;
        }
        if !normalized.is_empty() {
            seen_titles.insert(normalized);
        }
        result.push(parsed);
    }

    result
}

// ============================================================================
// Credential / Hash deduplication
// ============================================================================

/// Deduplicate credentials by (domain, username, password) case-insensitively.
/// Also normalizes is_admin for known admin usernames.
pub fn dedup_credentials(creds: &[Credential]) -> Vec<Credential> {
    let mut seen = HashSet::new();
    let mut result = Vec::new();
    for c in creds {
        let key = (
            c.domain.trim().to_lowercase(),
            c.username.trim().to_lowercase(),
            c.password.clone(),
        );
        if seen.insert(key) {
            let mut c = c.clone();
            if matches!(
                c.username.to_lowercase().as_str(),
                "administrator" | "krbtgt"
            ) {
                c.is_admin = true;
            }
            result.push(c);
        }
    }
    result
}

/// Deduplicate hashes by (domain, username, hash_value) case-insensitively.
/// Sorts with Administrator and krbtgt first.
pub fn dedup_hashes(hashes: &[Hash]) -> Vec<Hash> {
    let mut seen = HashSet::new();
    let mut result = Vec::new();
    for h in hashes {
        let key = (
            h.domain.trim().to_lowercase(),
            h.username.trim().to_lowercase(),
            h.hash_value.trim().to_lowercase(),
        );
        if seen.insert(key) {
            result.push(h.clone());
        }
    }

    // Sort: Administrator first, then krbtgt, then alphabetical
    result.sort_by(|a, b| {
        fn priority(name: &str) -> u8 {
            match name.to_lowercase().as_str() {
                "administrator" => 0,
                "krbtgt" => 1,
                _ => 2,
            }
        }
        let pa = priority(&a.username);
        let pb = priority(&b.username);
        pa.cmp(&pb)
            .then_with(|| a.username.to_lowercase().cmp(&b.username.to_lowercase()))
    });

    result
}

/// Deduplicate users by (domain, username) case-insensitively.
/// Also normalizes is_admin for known admin usernames.
pub fn dedup_users(users: &[User]) -> Vec<User> {
    let mut seen = HashSet::new();
    let mut result = Vec::new();
    for u in users {
        let key = (u.domain.to_lowercase(), u.username.to_lowercase());
        if seen.insert(key) {
            let mut u = u.clone();
            if matches!(
                u.username.to_lowercase().as_str(),
                "administrator" | "krbtgt"
            ) {
                u.is_admin = true;
            }
            result.push(u);
        }
    }
    result
}

// ============================================================================
// Template context helpers (serializable structs for Tera)
// ============================================================================

#[derive(Serialize)]
struct HostCtx {
    label: String,
    ip: String,
    os: String,
    roles: String,
    services: Vec<String>,
    is_dc: bool,
}

impl From<&Host> for HostCtx {
    fn from(h: &Host) -> Self {
        let is_dc = h.is_dc || h.detect_dc();
        Self {
            label: if h.hostname.is_empty() {
                h.ip.clone()
            } else {
                h.hostname.clone()
            },
            ip: h.ip.clone(),
            os: if h.os.is_empty() {
                String::new()
            } else {
                h.os.clone()
            },
            roles: if h.roles.is_empty() {
                String::new()
            } else {
                h.roles.join(", ")
            },
            services: h.services.clone(),
            is_dc,
        }
    }
}

#[derive(Serialize)]
struct UserCtx {
    username: String,
    domain: String,
    description: String,
    is_admin: bool,
    admin_display: String,
}

impl From<&User> for UserCtx {
    fn from(u: &User) -> Self {
        Self {
            username: u.username.clone(),
            domain: u.domain.clone(),
            description: if u.description.is_empty() {
                String::new()
            } else {
                u.description.clone()
            },
            is_admin: u.is_admin,
            admin_display: if u.is_admin {
                "Yes".to_string()
            } else {
                "No".to_string()
            },
        }
    }
}

#[derive(Serialize)]
struct CredCtx {
    username: String,
    domain: String,
    password: String,
    source: String,
    is_admin: bool,
    admin_display: String,
}

impl From<&Credential> for CredCtx {
    fn from(c: &Credential) -> Self {
        Self {
            username: c.username.clone(),
            domain: if c.domain.is_empty() {
                "Unknown".to_string()
            } else {
                c.domain.clone()
            },
            password: c.password.clone(),
            source: c.source.clone(),
            is_admin: c.is_admin,
            admin_display: if c.is_admin {
                "Yes".to_string()
            } else {
                "No".to_string()
            },
        }
    }
}

#[derive(Serialize)]
struct HashCtx {
    domain: String,
    username: String,
    hash_type: String,
    hash_value: String,
    source: String,
}

impl From<&Hash> for HashCtx {
    fn from(h: &Hash) -> Self {
        Self {
            domain: h.domain.clone(),
            username: h.username.clone(),
            hash_type: h.hash_type.clone(),
            hash_value: h.hash_value.clone(),
            source: h.source.clone(),
        }
    }
}

#[derive(Serialize)]
struct ShareCtx {
    name: String,
    host: String,
    permissions: String,
    comment: String,
}

impl From<&Share> for ShareCtx {
    fn from(s: &Share) -> Self {
        Self {
            name: s.name.clone(),
            host: s.host.clone(),
            permissions: if s.permissions.is_empty() {
                String::new()
            } else {
                s.permissions.clone()
            },
            comment: if s.comment.is_empty() {
                String::new()
            } else {
                s.comment.clone()
            },
        }
    }
}

#[derive(Serialize)]
struct TimelineEventCtx {
    timestamp: String,
    description: String,
    description_short: String,
    mitre_display: String,
    mitre_techniques: Vec<String>,
    confidence_display: String,
}

#[derive(Serialize)]
struct VulnCtx {
    vuln_id: String,
    vuln_type: String,
    target: String,
    target_ip: String,
    target_host: String,
    priority: i32,
    exploited: bool,
    exploited_display: String,
    status_display: String,
    details: String,
}

fn build_vuln_ctx(
    vuln_id: &str,
    vuln: &VulnerabilityInfo,
    exploited_set: &HashSet<String>,
) -> VulnCtx {
    let exploited = exploited_set.contains(vuln_id);
    VulnCtx {
        vuln_id: vuln_id.to_string(),
        vuln_type: vuln.vuln_type.clone(),
        target: vuln.target.clone(),
        target_ip: vuln.target.clone(),
        target_host: vuln.target.clone(),
        priority: vuln.priority,
        exploited,
        exploited_display: if exploited {
            "\u{2713}".to_string() // checkmark
        } else {
            "\u{2717}".to_string() // cross
        },
        status_display: if exploited {
            "EXPLOITED".to_string()
        } else {
            "Not Exploited".to_string()
        },
        details: format_vuln_details(&vuln.details),
    }
}

// ============================================================================
// Red Team Report Generator
// ============================================================================

/// Generates markdown reports from red team operation state using Tera templates.
pub struct RedTeamReportGenerator {
    tera: Tera,
}

impl RedTeamReportGenerator {
    /// Create a new report generator with embedded templates.
    pub fn new() -> Result<Self, tera::Error> {
        let mut tera = Tera::default();
        tera.add_raw_template("operation_summary", REDTEAM_SUMMARY_TEMPLATE)?;
        tera.add_raw_template("comprehensive_report", REDTEAM_COMPREHENSIVE_TEMPLATE)?;
        Ok(Self { tera })
    }

    /// Generate a summary report from shared red team state.
    pub fn generate_summary(
        &self,
        state: &SharedRedTeamState,
        timeline_events: &[serde_json::Value],
        techniques: &[String],
        is_running: bool,
    ) -> Result<String, tera::Error> {
        let now = Utc::now();
        let completed_at = state.completed_at.unwrap_or(now);
        let duration = completed_at - state.started_at;
        let duration_str = format_duration_chrono(duration);

        let status = if state.completed_at.is_some() {
            "completed"
        } else if is_running {
            "in_progress"
        } else {
            "stopped"
        };

        let unique_users = dedup_users(&state.all_users);
        let unique_creds = dedup_credentials(&state.all_credentials);
        let admin_count = unique_creds.iter().filter(|c| c.is_admin).count();

        let executive_summary = generate_executive_summary(state, &unique_users, &unique_creds);

        // Collect all MITRE techniques
        let mut all_techniques: HashSet<String> = techniques.iter().cloned().collect();
        for event in timeline_events {
            if let Some(arr) = event.get("mitre_techniques").and_then(|v| v.as_array()) {
                for t in arr {
                    if let Some(s) = t.as_str() {
                        all_techniques.insert(s.to_string());
                    }
                }
            }
        }
        let mut techniques_enriched: Vec<String> = all_techniques
            .iter()
            .map(|t| get_technique_display(t))
            .collect();
        techniques_enriched.sort();

        // Build vulnerability context
        let mut discovered_vulns: Vec<VulnCtx> = state
            .discovered_vulnerabilities
            .iter()
            .map(|(id, v)| build_vuln_ctx(id, v, &state.exploited_vulnerabilities))
            .collect();
        discovered_vulns.sort_by_key(|v| v.priority);

        // Build timeline context
        let timeline: Vec<TimelineEventCtx> = timeline_events
            .iter()
            .map(timeline_event_from_json)
            .collect();

        let weaknesses = deduplicate_weaknesses(&state.all_weaknesses);

        let hosts: Vec<HostCtx> = state.all_hosts.iter().map(HostCtx::from).collect();
        let users: Vec<UserCtx> = unique_users.iter().map(UserCtx::from).collect();
        let credentials: Vec<CredCtx> = unique_creds.iter().map(CredCtx::from).collect();
        let shares: Vec<ShareCtx> = state.all_shares.iter().map(ShareCtx::from).collect();

        let target_ip = state
            .target
            .as_ref()
            .map(|t| t.ip.clone())
            .unwrap_or_else(|| "Unknown".to_string());

        let mut ctx = Context::new();
        ctx.insert("operation_id", &state.operation_id);
        ctx.insert("target_ip", &target_ip);
        ctx.insert("target_ips", &state.target_ips);
        ctx.insert(
            "started_at",
            &state.started_at.format("%Y-%m-%d %H:%M:%S UTC").to_string(),
        );
        ctx.insert(
            "completed_at",
            &completed_at.format("%Y-%m-%d %H:%M:%S UTC").to_string(),
        );
        ctx.insert("duration", &duration_str);
        ctx.insert("stage", status);
        ctx.insert("executive_summary", &executive_summary);
        ctx.insert("has_domain_admin", &state.has_domain_admin);
        ctx.insert("has_golden_ticket", &state.has_golden_ticket);
        ctx.insert(
            "da_display",
            if state.has_domain_admin {
                "\u{2713} ACHIEVED"
            } else {
                "\u{2717} Not Achieved"
            },
        );
        ctx.insert(
            "gt_display",
            if state.has_golden_ticket {
                "\u{2713} GENERATED"
            } else {
                "\u{2717} Not Generated"
            },
        );
        ctx.insert("host_count", &state.all_hosts.len());
        ctx.insert("user_count", &unique_users.len());
        ctx.insert("credential_count", &unique_creds.len());
        ctx.insert("admin_count", &admin_count);
        ctx.insert(
            "vulnerability_count",
            &state.discovered_vulnerabilities.len(),
        );
        ctx.insert("exploited_count", &state.exploited_vulnerabilities.len());
        ctx.insert("share_count", &state.all_shares.len());
        ctx.insert("hosts", &hosts);
        ctx.insert("users", &users);
        ctx.insert("credentials", &credentials);
        ctx.insert("shares", &shares);
        ctx.insert("weaknesses", &weaknesses);
        ctx.insert("discovered_vulns", &discovered_vulns);
        ctx.insert("timeline", &timeline);
        ctx.insert("techniques_identified", &techniques_enriched);

        self.tera.render("operation_summary", &ctx)
    }

    /// Generate a comprehensive report from shared red team state.
    pub fn generate_comprehensive(
        &self,
        state: &SharedRedTeamState,
        timeline_events: &[serde_json::Value],
        techniques: &[String],
    ) -> Result<String, tera::Error> {
        let now = Utc::now();
        let completed_at = state.completed_at.unwrap_or(now);
        let duration = completed_at - state.started_at;
        let duration_str = format_duration_chrono(duration);

        let unique_creds = dedup_credentials(&state.all_credentials);
        let unique_hashes = dedup_hashes(&state.all_hashes);
        let dc_count = state
            .all_hosts
            .iter()
            .filter(|h| h.is_dc || h.detect_dc())
            .count();

        // Collect all MITRE techniques
        let mut all_techniques: HashSet<String> = techniques.iter().cloned().collect();
        for event in timeline_events {
            if let Some(arr) = event.get("mitre_techniques").and_then(|v| v.as_array()) {
                for t in arr {
                    if let Some(s) = t.as_str() {
                        all_techniques.insert(s.to_string());
                    }
                }
            }
        }
        let mut techniques_enriched: Vec<String> = all_techniques
            .iter()
            .map(|t| get_technique_display(t))
            .collect();
        techniques_enriched.sort();

        // Vulnerability context
        let mut discovered_vulns: Vec<VulnCtx> = state
            .discovered_vulnerabilities
            .iter()
            .map(|(id, v)| build_vuln_ctx(id, v, &state.exploited_vulnerabilities))
            .collect();
        discovered_vulns.sort_by_key(|v| v.priority);

        // Timeline
        let timeline: Vec<TimelineEventCtx> = timeline_events
            .iter()
            .map(timeline_event_from_json)
            .collect();

        let weaknesses = deduplicate_weaknesses(&state.all_weaknesses);

        // Domains sorted, deduped, lowercased
        let mut domains: Vec<String> = state
            .all_domains
            .iter()
            .filter(|d| !d.is_empty())
            .map(|d| d.to_lowercase())
            .collect();
        domains.sort();
        domains.dedup();

        let hosts: Vec<HostCtx> = state.all_hosts.iter().map(HostCtx::from).collect();
        let users: Vec<UserCtx> = state.all_users.iter().map(UserCtx::from).collect();
        let credentials: Vec<CredCtx> = unique_creds.iter().map(CredCtx::from).collect();
        let hashes: Vec<HashCtx> = unique_hashes.iter().map(HashCtx::from).collect();
        let shares: Vec<ShareCtx> = state.all_shares.iter().map(ShareCtx::from).collect();

        let target_ip = state
            .target
            .as_ref()
            .map(|t| t.ip.clone())
            .unwrap_or_else(|| "Unknown".to_string());
        let target_domain = state
            .target
            .as_ref()
            .map(|t| t.domain.clone())
            .unwrap_or_else(|| "Unknown".to_string());

        let mut ctx = Context::new();
        ctx.insert("operation_id", &state.operation_id);
        ctx.insert("target_ip", &target_ip);
        ctx.insert("target_ips", &state.target_ips);
        ctx.insert("target_domain", &target_domain);
        ctx.insert(
            "started_at",
            &state.started_at.format("%Y-%m-%d %H:%M:%S UTC").to_string(),
        );
        ctx.insert(
            "completed_at",
            &completed_at.format("%Y-%m-%d %H:%M:%S UTC").to_string(),
        );
        ctx.insert("duration", &duration_str);
        ctx.insert("has_domain_admin", &state.has_domain_admin);
        ctx.insert("has_golden_ticket", &state.has_golden_ticket);
        ctx.insert(
            "da_display",
            if state.has_domain_admin {
                "ACHIEVED"
            } else {
                "Not Achieved"
            },
        );
        ctx.insert(
            "gt_display",
            if state.has_golden_ticket {
                "GENERATED"
            } else {
                "Not Generated"
            },
        );
        ctx.insert(
            "domain_admin_path",
            &state.domain_admin_path.as_deref().unwrap_or(""),
        );
        // domain_admin_chain would need attack chain data - pass empty vec for now
        let empty_chain: Vec<serde_json::Value> = Vec::new();
        ctx.insert("domain_admin_chain", &empty_chain);
        ctx.insert("domains", &domains);
        ctx.insert("dc_count", &dc_count);
        ctx.insert("hosts", &hosts);
        ctx.insert("users", &users);
        ctx.insert("credentials", &credentials);
        ctx.insert("hashes", &hashes);
        ctx.insert("shares", &shares);
        ctx.insert("weaknesses", &weaknesses);
        ctx.insert("timeline", &timeline);
        ctx.insert("techniques", &techniques_enriched);
        ctx.insert("discovered_vulns", &discovered_vulns);
        ctx.insert(
            "vulnerabilities_found",
            &state.discovered_vulnerabilities.len(),
        );
        ctx.insert(
            "vulnerabilities_exploited",
            &state.exploited_vulnerabilities.len(),
        );
        ctx.insert(
            "generated_at",
            &Utc::now().format("%Y-%m-%d %H:%M:%S UTC").to_string(),
        );

        self.tera.render("comprehensive_report", &ctx)
    }
}

impl Default for RedTeamReportGenerator {
    fn default() -> Self {
        Self::new().expect("Failed to initialize red team report templates")
    }
}

// ============================================================================
// Executive summary generation (matches Python _generate_executive_summary)
// ============================================================================

fn generate_executive_summary(
    state: &SharedRedTeamState,
    unique_users: &[User],
    unique_creds: &[Credential],
) -> String {
    // If the state already has a report summary, use it
    // (SharedRedTeamState doesn't have report_summary field in Rust yet,
    //  so we always generate it)

    let host_count = state.all_hosts.len();
    let credential_count = unique_creds.len();
    let admin_count = unique_creds.iter().filter(|c| c.is_admin).count();
    let vulnerability_count = state.discovered_vulnerabilities.len();
    let exploited_count = state.exploited_vulnerabilities.len();

    let mut summary_parts = Vec::new();

    // Operation overview
    let target_ips = if !state.target_ips.is_empty() {
        state.target_ips.clone()
    } else if let Some(ref t) = state.target {
        vec![t.ip.clone()]
    } else {
        Vec::new()
    };

    let target_desc = if target_ips.len() > 1 {
        let preview: Vec<_> = target_ips.iter().take(3).map(|s| s.as_str()).collect();
        let suffix = if target_ips.len() > 3 { "..." } else { "" };
        format!(
            "**{} targets** ({}{})",
            target_ips.len(),
            preview.join(", "),
            suffix
        )
    } else if let Some(ip) = target_ips.first() {
        format!("target **{ip}**")
    } else {
        "target **Unknown**".to_string()
    };

    summary_parts.push(format!(
        "Red team operation **{}** was executed against {target_desc} \
         in an Active Directory penetration testing engagement.",
        state.operation_id
    ));

    // Key achievements
    let mut achievements = Vec::new();
    if state.has_domain_admin {
        achievements.push("\u{2713} **Domain Administrator access achieved**".to_string());
    }
    if state.has_golden_ticket {
        achievements.push("\u{2713} **Golden ticket generated** for persistent access".to_string());
    }
    if admin_count > 0 {
        achievements.push(format!(
            "\u{2713} **{admin_count} administrator account(s)** discovered"
        ));
    }
    if credential_count > 0 {
        achievements.push(format!(
            "\u{2713} **{credential_count} credential(s)** obtained"
        ));
    }

    if !achievements.is_empty() {
        summary_parts.push(format!(
            "\n\n**Key Achievements:**\n{}",
            achievements.join("\n")
        ));
    }

    // Discovery statistics
    summary_parts.push(format!(
        "\n\n**Discovery Statistics:**\n\
         - Hosts Discovered: {host_count}\n\
         - User Accounts: {}\n\
         - Network Shares: {}\n\
         - Password Hashes: {}\n\
         - Vulnerabilities: {vulnerability_count}\n\
         - Vulnerabilities Exploited: {exploited_count}",
        unique_users.len(),
        state.all_shares.len(),
        state.all_hashes.len(),
    ));

    // Attack path
    if state.has_domain_admin || state.has_golden_ticket {
        if let Some(ref path) = state.domain_admin_path {
            summary_parts.push(format!("\n\n**Attack Path:**\n{path}"));
        } else {
            summary_parts.push(
                "\n\n**Attack Path:**\nDomain admin achieved. See timeline below for details."
                    .to_string(),
            );
        }
    }

    // Security posture
    let (posture, assessment) = if state.has_domain_admin || state.has_golden_ticket {
        (
            "**CRITICAL**",
            "The target environment has critical security weaknesses that allowed \
             full domain compromise. Immediate remediation is required.",
        )
    } else if admin_count > 0 {
        (
            "**HIGH**",
            "The target environment has significant security weaknesses with administrative \
             access obtained. Remediation is strongly recommended.",
        )
    } else if credential_count > 0 {
        (
            "**MEDIUM**",
            "The target environment has moderate security weaknesses with credentials \
             compromised. Security improvements are recommended.",
        )
    } else {
        (
            "**LOW**",
            "The target environment demonstrated resilience against the red team operation. \
             Continue monitoring and maintain security posture.",
        )
    };

    summary_parts.push(format!(
        "\n\n**Security Posture:** {posture}\n\n{assessment}"
    ));

    summary_parts.join("")
}

// ============================================================================
// Blue Team Report Generator
// ============================================================================

/// Template context structures for blue team reports.
#[derive(Serialize)]
pub struct BlueTeamAlertSummary {
    pub investigation_id_short: String,
    pub alert_name: String,
    pub severity: String,
    pub evidence_count: usize,
    pub highest_pyramid_level: i32,
    pub status_display: String,
    pub techniques: Vec<String>,
}

#[derive(Serialize)]
pub struct BlueTeamTechnique {
    pub id: String,
    pub name: String,
    pub tactic: String,
}

#[derive(Serialize)]
pub struct PyramidEntry {
    pub level: i32,
    pub category: String,
    pub count: i32,
    pub pain: String,
}

#[derive(Serialize)]
pub struct BlueTeamEvidenceItem {
    pub id_short: String,
    #[serde(rename = "type")]
    pub ev_type: String,
    pub value: String,
    pub techniques_display: String,
    pub confidence_display: String,
}

#[derive(Serialize)]
pub struct BlueTeamEvidenceLevel {
    pub level: i32,
    pub name: String,
    pub evidence: Vec<BlueTeamEvidenceItem>,
}

#[derive(Serialize)]
pub struct BlueTeamInvestigationDetail {
    pub investigation_id: String,
    pub alert_name: String,
    pub severity: String,
    pub status: String,
    pub evidence_count: usize,
    pub techniques_display: String,
    pub alert_payload: String,
    pub queries: Vec<serde_json::Value>,
    pub queries_display: Vec<serde_json::Value>,
    pub extra_query_count: usize,
}

/// Input data for blue team report generation.
///
/// Since we don't have full blue team state models in Rust yet, this struct
/// provides a data-transfer object that the CLI can populate from Redis.
#[derive(Debug, Clone, Default, Serialize)]
pub struct BlueTeamReportInput {
    pub operation_id: String,
    pub started_at: String,
    pub completed_at: String,
    pub duration: String,
    pub investigation_count: usize,
    pub alert_count: usize,
    pub evidence_count: usize,
    pub technique_count: usize,
    pub tactic_count: usize,
    pub host_count: usize,
    pub user_count: usize,
    pub highest_pyramid_level: i32,
    pub ttp_count: usize,
    pub escalation_count: usize,
    pub attack_synopses: Vec<String>,
    pub alert_summaries: Vec<serde_json::Value>,
    pub evidence_by_level: HashMap<i32, Vec<serde_json::Value>>,
    pub timeline: Vec<serde_json::Value>,
    pub techniques: Vec<serde_json::Value>,
    pub tactics: Vec<String>,
    pub hosts: Vec<String>,
    pub users: Vec<String>,
    pub recommendations: Vec<String>,
    pub investigation_details: Vec<serde_json::Value>,
    pub pyramid_distribution: HashMap<i32, i32>,
}

/// Generates markdown reports from blue team operation data using Tera templates.
pub struct BlueTeamReportGenerator {
    tera: Tera,
}

impl BlueTeamReportGenerator {
    /// Create a new blue team report generator with embedded templates.
    pub fn new() -> Result<Self, tera::Error> {
        let mut tera = Tera::default();
        tera.add_raw_template("comprehensive_report", BLUETEAM_COMPREHENSIVE_TEMPLATE)?;
        Ok(Self { tera })
    }

    /// Generate a comprehensive blue team report from pre-processed input data.
    pub fn generate(&self, input: &BlueTeamReportInput) -> Result<String, tera::Error> {
        let level_names: HashMap<i32, &str> = [
            (6, "TTPs"),
            (5, "Tools"),
            (4, "Network/Host Artifacts"),
            (3, "Domain Names"),
            (2, "IP Addresses"),
            (1, "Hash Values"),
        ]
        .into_iter()
        .collect();

        let level_pain: HashMap<i32, &str> = [
            (6, "Tough!"),
            (5, "Challenging"),
            (4, "Annoying"),
            (3, "Simple"),
            (2, "Easy"),
            (1, "Trivial"),
        ]
        .into_iter()
        .collect();

        // Build pyramid entries (6 down to 1)
        let pyramid_entries: Vec<PyramidEntry> = (1..=6)
            .rev()
            .map(|level| PyramidEntry {
                level,
                category: level_names.get(&level).unwrap_or(&"Unknown").to_string(),
                count: *input.pyramid_distribution.get(&level).unwrap_or(&0),
                pain: level_pain.get(&level).unwrap_or(&"Unknown").to_string(),
            })
            .collect();

        // Build evidence levels
        let evidence_levels: Vec<BlueTeamEvidenceLevel> = (1..=6)
            .rev()
            .map(|level| {
                let evidence = input
                    .evidence_by_level
                    .get(&level)
                    .map(|items| {
                        items
                            .iter()
                            .map(|ev| {
                                let id = ev.get("id").and_then(|v| v.as_str()).unwrap_or("");
                                let id_short = if id.len() > 12 { &id[..12] } else { id };
                                let techniques = ev
                                    .get("techniques")
                                    .and_then(|v| v.as_array())
                                    .map(|arr| {
                                        arr.iter()
                                            .filter_map(|v| v.as_str())
                                            .collect::<Vec<_>>()
                                            .join(", ")
                                    })
                                    .unwrap_or_else(|| "-".to_string());
                                let confidence =
                                    ev.get("confidence").and_then(|v| v.as_f64()).unwrap_or(0.0);

                                BlueTeamEvidenceItem {
                                    id_short: id_short.to_string(),
                                    ev_type: ev
                                        .get("type")
                                        .and_then(|v| v.as_str())
                                        .unwrap_or("")
                                        .to_string(),
                                    value: {
                                        let val =
                                            ev.get("value").and_then(|v| v.as_str()).unwrap_or("");
                                        if val.len() > 80 {
                                            format!("{}...", &val[..80])
                                        } else {
                                            val.to_string()
                                        }
                                    },
                                    techniques_display: techniques,
                                    confidence_display: format!("{:.0}%", confidence * 100.0),
                                }
                            })
                            .collect()
                    })
                    .unwrap_or_default();

                BlueTeamEvidenceLevel {
                    level,
                    name: level_names.get(&level).unwrap_or(&"Unknown").to_string(),
                    evidence,
                }
            })
            .collect();

        // Build alert summaries for template
        let alert_summaries: Vec<BlueTeamAlertSummary> = input
            .alert_summaries
            .iter()
            .map(|a| {
                let inv_id = a
                    .get("investigation_id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let id_short = if inv_id.len() > 16 {
                    &inv_id[..16]
                } else {
                    inv_id
                };
                let escalated = a
                    .get("escalated")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);

                BlueTeamAlertSummary {
                    investigation_id_short: id_short.to_string(),
                    alert_name: a
                        .get("alert_name")
                        .and_then(|v| v.as_str())
                        .unwrap_or("Unknown")
                        .to_string(),
                    severity: a
                        .get("severity")
                        .and_then(|v| v.as_str())
                        .unwrap_or("unknown")
                        .to_string(),
                    evidence_count: a
                        .get("evidence_count")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0) as usize,
                    highest_pyramid_level: a
                        .get("highest_pyramid_level")
                        .and_then(|v| v.as_i64())
                        .unwrap_or(0) as i32,
                    status_display: if escalated {
                        "ESCALATED".to_string()
                    } else {
                        "Completed".to_string()
                    },
                    techniques: a
                        .get("techniques")
                        .and_then(|v| v.as_array())
                        .map(|arr| {
                            arr.iter()
                                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                                .collect()
                        })
                        .unwrap_or_default(),
                }
            })
            .collect();

        // Build timeline for template
        let timeline: Vec<TimelineEventCtx> = input
            .timeline
            .iter()
            .map(|e| {
                let desc = e.get("description").and_then(|v| v.as_str()).unwrap_or("");
                let mitre_arr = e
                    .get("mitre_techniques")
                    .and_then(|v| v.as_array())
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|v| v.as_str().map(|s| s.to_string()))
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default();
                let confidence = e.get("confidence").and_then(|v| v.as_f64()).unwrap_or(0.0);

                TimelineEventCtx {
                    timestamp: e
                        .get("timestamp")
                        .and_then(|v| v.as_str())
                        .unwrap_or("-")
                        .to_string(),
                    description: desc.to_string(),
                    description_short: if desc.len() > 60 {
                        format!("{}...", &desc[..60])
                    } else {
                        desc.to_string()
                    },
                    mitre_display: if mitre_arr.is_empty() {
                        "-".to_string()
                    } else {
                        mitre_arr.join(", ")
                    },
                    mitre_techniques: mitre_arr,
                    confidence_display: format!("{:.0}%", confidence * 100.0),
                }
            })
            .collect();

        // Build techniques for template
        let techniques: Vec<BlueTeamTechnique> = input
            .techniques
            .iter()
            .map(|t| BlueTeamTechnique {
                id: t
                    .get("id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
                name: t
                    .get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
                tactic: t
                    .get("tactic")
                    .and_then(|v| v.as_str())
                    .unwrap_or("Unknown")
                    .to_string(),
            })
            .collect();

        // Detection techniques (first 10)
        let detection_techniques: Vec<&BlueTeamTechnique> = techniques.iter().take(10).collect();

        // Build investigation details
        let investigation_details: Vec<BlueTeamInvestigationDetail> = input
            .investigation_details
            .iter()
            .map(|inv| {
                let techniques_arr = inv
                    .get("techniques")
                    .and_then(|v| v.as_array())
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|v| v.as_str().map(|s| s.to_string()))
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default();

                let queries = inv
                    .get("queries")
                    .and_then(|v| v.as_array())
                    .cloned()
                    .unwrap_or_default();

                let queries_display: Vec<serde_json::Value> =
                    queries.iter().take(10).cloned().collect();
                let extra_query_count = if queries.len() > 10 {
                    queries.len() - 10
                } else {
                    0
                };

                BlueTeamInvestigationDetail {
                    investigation_id: inv
                        .get("investigation_id")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string(),
                    alert_name: inv
                        .get("alert_name")
                        .and_then(|v| v.as_str())
                        .unwrap_or("Unknown")
                        .to_string(),
                    severity: inv
                        .get("severity")
                        .and_then(|v| v.as_str())
                        .unwrap_or("unknown")
                        .to_string(),
                    status: inv
                        .get("status")
                        .and_then(|v| v.as_str())
                        .unwrap_or("Completed")
                        .to_string(),
                    evidence_count: inv
                        .get("evidence_count")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0) as usize,
                    techniques_display: if techniques_arr.is_empty() {
                        "None".to_string()
                    } else {
                        techniques_arr.join(", ")
                    },
                    alert_payload: inv
                        .get("alert_payload")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string(),
                    queries,
                    queries_display,
                    extra_query_count,
                }
            })
            .collect();

        let mut ctx = Context::new();
        ctx.insert("operation_id", &input.operation_id);
        ctx.insert("started_at", &input.started_at);
        ctx.insert("completed_at", &input.completed_at);
        ctx.insert("duration", &input.duration);
        ctx.insert("investigation_count", &input.investigation_count);
        ctx.insert("alert_count", &input.alert_count);
        ctx.insert("evidence_count", &input.evidence_count);
        ctx.insert("technique_count", &input.technique_count);
        ctx.insert("tactic_count", &input.tactic_count);
        ctx.insert("host_count", &input.host_count);
        ctx.insert("user_count", &input.user_count);
        ctx.insert("highest_pyramid_level", &input.highest_pyramid_level);
        ctx.insert("ttp_count", &input.ttp_count);
        ctx.insert("escalation_count", &input.escalation_count);
        ctx.insert("attack_synopses", &input.attack_synopses);
        ctx.insert("alert_summaries", &alert_summaries);
        ctx.insert("evidence_levels", &evidence_levels);
        ctx.insert("timeline", &timeline);
        ctx.insert("techniques", &techniques);
        ctx.insert("detection_techniques", &detection_techniques);
        ctx.insert("tactics", &input.tactics);
        ctx.insert("hosts", &input.hosts);
        ctx.insert("users", &input.users);
        ctx.insert("recommendations", &input.recommendations);
        ctx.insert("investigation_details", &investigation_details);
        ctx.insert("pyramid_entries", &pyramid_entries);
        ctx.insert(
            "generated_at",
            &Utc::now().format("%Y-%m-%d %H:%M:%S UTC").to_string(),
        );

        self.tera.render("comprehensive_report", &ctx)
    }
}

impl Default for BlueTeamReportGenerator {
    fn default() -> Self {
        Self::new().expect("Failed to initialize blue team report templates")
    }
}

// ============================================================================
// Helpers
// ============================================================================

fn timeline_event_from_json(event: &serde_json::Value) -> TimelineEventCtx {
    let ts = event
        .get("timestamp")
        .and_then(|v| v.as_str())
        .unwrap_or("-")
        .to_string();
    let desc = event
        .get("description")
        .and_then(|v| v.as_str())
        .unwrap_or("-")
        .to_string();
    let mitre_arr = event
        .get("mitre_techniques")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let confidence = event
        .get("confidence")
        .and_then(|v| v.as_f64())
        .unwrap_or(0.0);

    TimelineEventCtx {
        timestamp: ts,
        description_short: if desc.len() > 60 {
            format!("{}...", &desc[..60])
        } else {
            desc.clone()
        },
        description: desc,
        mitre_display: if mitre_arr.is_empty() {
            "-".to_string()
        } else {
            mitre_arr.join(", ")
        },
        mitre_techniques: mitre_arr,
        confidence_display: format!("{:.0}%", confidence * 100.0),
    }
}

/// Format a chrono Duration as "Xh Ym Zs".
fn format_duration_chrono(duration: chrono::Duration) -> String {
    let total_seconds = duration.num_seconds().max(0) as u64;
    let hours = total_seconds / 3600;
    let minutes = (total_seconds % 3600) / 60;
    let seconds = total_seconds % 60;
    format!("{hours}:{minutes:02}:{seconds:02}")
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{SharedRedTeamState, Target};

    #[test]
    fn test_mitre_lookup() {
        assert_eq!(get_technique_display("T1003.006"), "T1003.006 (DCSync)");
        assert_eq!(get_technique_display("T9999"), "T9999");
    }

    #[test]
    fn test_format_vuln_details_empty() {
        let details = HashMap::new();
        assert_eq!(format_vuln_details(&details), "-");
    }

    #[test]
    fn test_format_vuln_details_with_values() {
        let mut details = HashMap::new();
        details.insert(
            "account".to_string(),
            serde_json::Value::String("admin".to_string()),
        );
        details.insert(
            "domain".to_string(),
            serde_json::Value::String("contoso.local".to_string()),
        );
        let result = format_vuln_details(&details);
        assert!(result.contains("Account: admin"));
        assert!(result.contains("Domain: contoso.local"));
    }

    #[test]
    fn test_dedup_credentials() {
        let creds = vec![
            Credential {
                id: "1".to_string(),
                username: "admin".to_string(),
                password: "pass".to_string(), // pragma: allowlist secret
                domain: "CONTOSO.LOCAL".to_string(),
                source: "manual".to_string(),
                discovered_at: None,
                is_admin: false,
                parent_id: None,
                attack_step: 0,
            },
            Credential {
                id: "2".to_string(),
                username: "Admin".to_string(),
                password: "pass".to_string(), // pragma: allowlist secret
                domain: "contoso.local".to_string(),
                source: "auto".to_string(),
                discovered_at: None,
                is_admin: false,
                parent_id: None,
                attack_step: 0,
            },
        ];
        let deduped = dedup_credentials(&creds);
        assert_eq!(deduped.len(), 1);
    }

    #[test]
    fn test_dedup_hashes() {
        let hashes = vec![
            Hash {
                id: "1".to_string(),
                username: "administrator".to_string(),
                hash_value: "aad3b435b51404ee".to_string(),
                hash_type: "NTLM".to_string(),
                domain: "contoso.local".to_string(),
                cracked_password: None,
                source: "secretsdump".to_string(),
                discovered_at: None,
                parent_id: None,
                attack_step: 0,
                aes_key: None,
            },
            Hash {
                id: "2".to_string(),
                username: "user1".to_string(),
                hash_value: "deadbeef12345678".to_string(),
                hash_type: "NTLM".to_string(),
                domain: "contoso.local".to_string(),
                cracked_password: None,
                source: "secretsdump".to_string(),
                discovered_at: None,
                parent_id: None,
                attack_step: 0,
                aes_key: None,
            },
        ];
        let deduped = dedup_hashes(&hashes);
        assert_eq!(deduped.len(), 2);
        // Administrator should be sorted first
        assert_eq!(deduped[0].username, "administrator");
    }

    #[test]
    fn test_weakness_dedup() {
        let weaknesses = vec![
            "### Weak Password\n**Vulnerability:** test\n**Impact:** high".to_string(),
            "### Weak Password\n**Vulnerability:** test\n**Impact:** high".to_string(),
            "### Different Issue\n**Vulnerability:** other".to_string(),
        ];
        let deduped = deduplicate_weaknesses(&weaknesses);
        assert_eq!(deduped.len(), 2);
    }

    #[test]
    fn test_redteam_summary_renders() {
        let gen = RedTeamReportGenerator::new().unwrap();
        let state = SharedRedTeamState {
            operation_id: "test-op-001".to_string(),
            target: Some(Target {
                ip: "192.168.58.10".to_string(),
                hostname: "dc01".to_string(),
                domain: "contoso.local".to_string(),
                environment: String::new(),
            }),
            target_ips: vec!["192.168.58.10".to_string()],
            started_at: Utc::now() - chrono::Duration::hours(1),
            completed_at: Some(Utc::now()),
            all_domains: vec!["contoso.local".to_string()],
            all_credentials: Vec::new(),
            all_hashes: Vec::new(),
            all_hosts: Vec::new(),
            all_users: Vec::new(),
            all_shares: Vec::new(),
            all_weaknesses: Vec::new(),
            discovered_vulnerabilities: HashMap::new(),
            exploited_vulnerabilities: HashSet::new(),
            has_domain_admin: false,
            has_golden_ticket: false,
            domain_admin_path: None,
            domain_controllers: HashMap::new(),
            netbios_to_fqdn: HashMap::new(),
        };

        let result = gen.generate_summary(&state, &[], &[], false);
        assert!(result.is_ok());
        let report = result.unwrap();
        assert!(report.contains("# Red Team Operation Report"));
        assert!(report.contains("test-op-001"));
        assert!(report.contains("192.168.58.10"));
    }

    #[test]
    fn test_redteam_comprehensive_renders() {
        let gen = RedTeamReportGenerator::new().unwrap();
        let state = SharedRedTeamState {
            operation_id: "test-op-002".to_string(),
            target: Some(Target {
                ip: "192.168.58.10".to_string(),
                hostname: "dc01".to_string(),
                domain: "contoso.local".to_string(),
                environment: String::new(),
            }),
            target_ips: vec!["192.168.58.10".to_string()],
            started_at: Utc::now() - chrono::Duration::hours(2),
            completed_at: Some(Utc::now()),
            all_domains: vec!["contoso.local".to_string()],
            all_credentials: vec![Credential {
                id: "1".to_string(),
                username: "administrator".to_string(),
                password: "P@ssw0rd!".to_string(), // pragma: allowlist secret
                domain: "contoso.local".to_string(),
                source: "secretsdump".to_string(),
                discovered_at: None,
                is_admin: true,
                parent_id: None,
                attack_step: 0,
            }],
            all_hashes: vec![Hash {
                id: "1".to_string(),
                username: "administrator".to_string(),
                hash_value: "aad3b435b51404ee:deadbeef12345678".to_string(),
                hash_type: "NTLM".to_string(),
                domain: "contoso.local".to_string(),
                cracked_password: None,
                source: "secretsdump".to_string(),
                discovered_at: None,
                parent_id: None,
                attack_step: 0,
                aes_key: None,
            }],
            all_hosts: vec![Host {
                ip: "192.168.58.10".to_string(),
                hostname: "dc01.contoso.local".to_string(),
                os: "Windows Server 2022".to_string(),
                roles: vec!["Domain Controller".to_string()],
                services: vec!["88/tcp kerberos".to_string(), "389/tcp ldap".to_string()],
                is_dc: true,
                owned: true,
            }],
            all_users: Vec::new(),
            all_shares: Vec::new(),
            all_weaknesses: Vec::new(),
            discovered_vulnerabilities: HashMap::new(),
            exploited_vulnerabilities: HashSet::new(),
            has_domain_admin: true,
            has_golden_ticket: false,
            domain_admin_path: Some("secretsdump -> administrator hash -> DA".to_string()),
            domain_controllers: HashMap::new(),
            netbios_to_fqdn: HashMap::new(),
        };

        let result = gen.generate_comprehensive(&state, &[], &["T1003.006".to_string()]);
        assert!(result.is_ok());
        let report = result.unwrap();
        assert!(report.contains("# Red Team Operation Report"));
        assert!(report.contains("DOMAIN ADMIN ACHIEVED"));
        assert!(report.contains("contoso.local"));
        assert!(report.contains("T1003.006 (DCSync)"));
        assert!(report.contains("administrator"));
    }

    #[test]
    fn test_blueteam_report_renders() {
        let gen = BlueTeamReportGenerator::new().unwrap();
        let input = BlueTeamReportInput {
            operation_id: "blue-test-001".to_string(),
            started_at: "2026-04-07 10:00:00 UTC".to_string(),
            completed_at: "2026-04-07 11:00:00 UTC".to_string(),
            duration: "1:00:00".to_string(),
            investigation_count: 2,
            alert_count: 2,
            evidence_count: 5,
            technique_count: 3,
            tactic_count: 2,
            host_count: 1,
            user_count: 1,
            highest_pyramid_level: 4,
            ttp_count: 0,
            escalation_count: 1,
            attack_synopses: vec!["Possible lateral movement detected".to_string()],
            alert_summaries: Vec::new(),
            evidence_by_level: HashMap::new(),
            timeline: Vec::new(),
            techniques: Vec::new(),
            tactics: vec!["Lateral Movement".to_string()],
            hosts: vec!["dc01.contoso.local".to_string()],
            users: vec!["admin@contoso.local".to_string()],
            recommendations: vec!["Review lateral movement paths".to_string()],
            investigation_details: Vec::new(),
            pyramid_distribution: HashMap::new(),
        };

        let result = gen.generate(&input);
        assert!(result.is_ok());
        let report = result.unwrap();
        assert!(report.contains("# Blue Team Operation Report"));
        assert!(report.contains("blue-test-001"));
        assert!(report.contains("ESCALATIONS REQUIRED"));
    }
}
