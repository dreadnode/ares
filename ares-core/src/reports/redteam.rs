//! Red team report generator.

use std::collections::{HashMap, HashSet};

use chrono::Utc;
use tera::{Context, Tera};

use crate::models::{Credential, SharedRedTeamState, User};

use super::context::*;
use super::dedup::{dedup_credentials, dedup_hashes, dedup_users};
use super::mitre::get_technique_display;
use super::templates::{REDTEAM_COMPREHENSIVE_TEMPLATE, REDTEAM_SUMMARY_TEMPLATE};
use super::util::{format_duration_chrono, timeline_event_from_json};

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

        // Filter out CIDR subnet entries (e.g. "192.168.58.0/24") — these aren't hosts.
        let hosts: Vec<HostCtx> = state
            .all_hosts
            .iter()
            .filter(|h| !h.ip.contains('/'))
            .map(HostCtx::from)
            .collect();
        let users: Vec<UserCtx> = unique_users.iter().map(UserCtx::from).collect();
        let credentials: Vec<CredCtx> = unique_creds.iter().map(CredCtx::from).collect();

        // Build IP → hostname map so shares can display hostnames instead of IPs.
        let ip_to_hostname: HashMap<&str, &str> = state
            .all_hosts
            .iter()
            .filter(|h| !h.hostname.is_empty())
            .map(|h| (h.ip.as_str(), h.hostname.as_str()))
            .collect();
        let shares: Vec<ShareCtx> = state
            .all_shares
            .iter()
            .map(|s| {
                let mut ctx = ShareCtx::from(s);
                if let Some(hostname) = ip_to_hostname.get(ctx.host.as_str()) {
                    ctx.host = hostname.to_string();
                }
                ctx
            })
            .collect();

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

        // Domains sorted, deduped, lowercased
        let mut domains: Vec<String> = state
            .all_domains
            .iter()
            .filter(|d| !d.is_empty())
            .map(|d| d.to_lowercase())
            .collect();
        domains.sort();
        domains.dedup();

        // Filter out CIDR subnet entries (e.g. "192.168.58.0/24") — these aren't hosts.
        let hosts: Vec<HostCtx> = state
            .all_hosts
            .iter()
            .filter(|h| !h.ip.contains('/'))
            .map(HostCtx::from)
            .collect();
        let users: Vec<UserCtx> = state.all_users.iter().map(UserCtx::from).collect();
        let credentials: Vec<CredCtx> = unique_creds.iter().map(CredCtx::from).collect();
        let mut hashes: Vec<HashCtx> = unique_hashes.iter().map(HashCtx::from).collect();

        // Symmetric trust-key pair detection: when two `is_trust_key` rows
        // share the same hash_value but have flipped (username, domain) —
        // e.g. `CONTOSO$ @ fabrikam.local` and `FABRIKAM$ @ contoso.local`
        // both = the same inter-realm trust key — badge them so the renderer
        // shows the pair as one entity, not two unrelated rows. Uses
        // lowercased fields for canonical comparison.
        let mut symmetric_groups: std::collections::HashMap<String, Vec<usize>> =
            std::collections::HashMap::new();
        for (i, h) in hashes.iter().enumerate() {
            if !h.is_trust_key {
                continue;
            }
            let key = h.hash_value.trim().to_lowercase();
            symmetric_groups.entry(key).or_default().push(i);
        }
        for idxs in symmetric_groups.values() {
            if idxs.len() < 2 {
                continue;
            }
            // Verify the pair has flipped identity (not just two rows with
            // identical fields, which would already have been deduped).
            let first_user = hashes[idxs[0]].username.to_lowercase();
            let first_dom = hashes[idxs[0]].domain.to_lowercase();
            let flipped = idxs.iter().skip(1).any(|&j| {
                let u = hashes[j].username.to_lowercase();
                let d = hashes[j].domain.to_lowercase();
                u != first_user && d != first_dom
            });
            if flipped {
                for &i in idxs {
                    hashes[i].symmetric_pair_badge = "symmetric pair".to_string();
                }
            }
        }

        // Partition into trust-key rows (rendered above) and the rest. The
        // generic dump excludes trust keys to keep the table focused on
        // direct-auth material; the dedicated section calls out forging
        // material with current/previous and symmetric-pair badges.
        let trust_hashes: Vec<HashCtx> =
            hashes.iter().filter(|h| h.is_trust_key).cloned().collect();
        let hashes: Vec<HashCtx> = hashes.into_iter().filter(|h| !h.is_trust_key).collect();

        // Build IP → hostname map so shares can display hostnames instead of IPs.
        let ip_to_hostname: HashMap<&str, &str> = state
            .all_hosts
            .iter()
            .filter(|h| !h.hostname.is_empty())
            .map(|h| (h.ip.as_str(), h.hostname.as_str()))
            .collect();
        let shares: Vec<ShareCtx> = state
            .all_shares
            .iter()
            .map(|s| {
                let mut ctx = ShareCtx::from(s);
                if let Some(hostname) = ip_to_hostname.get(ctx.host.as_str()) {
                    ctx.host = hostname.to_string();
                }
                ctx
            })
            .collect();

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
        // Build the credential chain to DA from parent_id lineage
        let da_chain = state.build_domain_admin_chain();
        let da_path_from_chain = SharedRedTeamState::format_attack_chain(&da_chain);
        // Use the chain-derived path if the explicit path isn't set
        let domain_admin_path = state
            .domain_admin_path
            .as_deref()
            .filter(|s| !s.is_empty())
            .unwrap_or(&da_path_from_chain);
        ctx.insert("domain_admin_path", domain_admin_path);
        let chain_ctx: Vec<ChainStepCtx> = da_chain
            .iter()
            .map(|step| ChainStepCtx {
                step_number: step.step_number,
                item_type: step.item_type.clone(),
                username: step.username.clone(),
                domain: step.domain.clone(),
                source: step.source.clone(),
                hash_type: step.hash_type.clone(),
            })
            .collect();
        ctx.insert("domain_admin_chain", &chain_ctx);
        ctx.insert("domains", &domains);
        ctx.insert("dc_count", &dc_count);
        ctx.insert("hosts", &hosts);
        ctx.insert("users", &users);
        ctx.insert("credentials", &credentials);
        ctx.insert("hashes", &hashes);
        ctx.insert("trust_hashes", &trust_hashes);
        ctx.insert("shares", &shares);
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
// Executive summary generation
// ============================================================================

pub(crate) fn generate_executive_summary(
    state: &SharedRedTeamState,
    unique_users: &[User],
    unique_creds: &[Credential],
) -> String {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{Credential, Host, Share, SharedRedTeamState, User};

    fn empty_state() -> SharedRedTeamState {
        SharedRedTeamState::new("op-test-1".to_string())
    }

    fn make_user(name: &str, domain: &str) -> User {
        User {
            username: name.to_string(),
            domain: domain.to_string(),
            description: String::new(),
            is_admin: false,
            source: String::new(),
        }
    }

    fn make_cred(name: &str, domain: &str, pass: &str, admin: bool) -> Credential {
        Credential {
            id: "id".to_string(),
            username: name.to_string(),
            password: pass.to_string(),
            domain: domain.to_string(),
            source: String::new(),
            discovered_at: None,
            is_admin: admin,
            parent_id: None,
            attack_step: 0,
        }
    }

    #[test]
    fn executive_summary_critical_when_domain_admin() {
        let mut state = empty_state();
        state.has_domain_admin = true;
        let users = vec![make_user("admin", "contoso.local")];
        let creds = vec![make_cred("admin", "contoso.local", "pass", true)];
        let summary = generate_executive_summary(&state, &users, &creds);
        assert!(summary.contains("**CRITICAL**"));
        assert!(summary.contains("op-test-1"));
    }

    #[test]
    fn executive_summary_critical_when_golden_ticket() {
        let mut state = empty_state();
        state.has_golden_ticket = true;
        let summary = generate_executive_summary(&state, &[], &[]);
        assert!(summary.contains("**CRITICAL**"));
        assert!(summary.contains("Golden ticket"));
    }

    #[test]
    fn executive_summary_high_when_admin_creds() {
        let state = empty_state();
        let creds = vec![make_cred("admin", "contoso.local", "pass", true)];
        let summary = generate_executive_summary(&state, &[], &creds);
        assert!(summary.contains("**HIGH**"));
    }

    #[test]
    fn executive_summary_medium_when_creds_no_admin() {
        let state = empty_state();
        let creds = vec![make_cred("user1", "contoso.local", "pass", false)];
        let summary = generate_executive_summary(&state, &[], &creds);
        assert!(summary.contains("**MEDIUM**"));
    }

    #[test]
    fn executive_summary_low_when_no_findings() {
        let state = empty_state();
        let summary = generate_executive_summary(&state, &[], &[]);
        assert!(summary.contains("**LOW**"));
        assert!(summary.contains("resilience"));
    }

    #[test]
    fn executive_summary_single_target() {
        let mut state = empty_state();
        state.target_ips = vec!["192.168.58.1".to_string()];
        let summary = generate_executive_summary(&state, &[], &[]);
        assert!(summary.contains("**192.168.58.1**"));
    }

    #[test]
    fn executive_summary_multiple_targets_truncated() {
        let mut state = empty_state();
        state.target_ips = vec![
            "192.168.58.1".to_string(),
            "192.168.58.2".to_string(),
            "192.168.58.3".to_string(),
            "192.168.58.4".to_string(),
        ];
        let summary = generate_executive_summary(&state, &[], &[]);
        assert!(summary.contains("**4 targets**"));
        assert!(summary.contains("..."));
    }

    #[test]
    fn executive_summary_domain_admin_path() {
        let mut state = empty_state();
        state.has_domain_admin = true;
        state.domain_admin_path = Some("user1 -> admin -> DA".to_string());
        let summary = generate_executive_summary(&state, &[], &[]);
        assert!(summary.contains("user1 -> admin -> DA"));
    }

    #[test]
    fn executive_summary_discovery_stats() {
        let mut state = empty_state();
        state.all_hosts = vec![Host {
            ip: "192.168.58.1".to_string(),
            hostname: "dc01".to_string(),
            os: String::new(),
            roles: vec![],
            services: vec![],
            is_dc: false,
            owned: false,
        }];
        state.all_shares = vec![Share {
            host: "192.168.58.1".to_string(),
            name: "SYSVOL".to_string(),
            permissions: "READ".to_string(),
            comment: String::new(),
            authenticated_as: None,
        }];
        let users = vec![make_user("u1", "d")];
        let summary = generate_executive_summary(&state, &users, &[]);
        assert!(summary.contains("Hosts Discovered: 1"));
        assert!(summary.contains("User Accounts: 1"));
        assert!(summary.contains("Network Shares: 1"));
    }

    #[test]
    fn report_generator_new_succeeds() {
        let gen = RedTeamReportGenerator::new();
        assert!(gen.is_ok());
    }

    #[test]
    fn report_generator_default_succeeds() {
        let _gen = RedTeamReportGenerator::default();
    }

    #[test]
    fn comprehensive_report_badges_symmetric_trust_pairs() {
        // Two trust-key rows with the same hash_value but flipped
        // (username, domain) — `CONTOSO$ @ fabrikam.local` and
        // `FABRIKAM$ @ contoso.local` — should both be tagged as "symmetric
        // pair" so the operator knows forging from either direction
        // unlocks the trust.
        let mut state = empty_state();
        state.all_hashes = vec![
            crate::models::Hash {
                id: "h1".into(),
                username: "CONTOSO$".into(),
                hash_value: "feedbeef".into(),
                hash_type: "ntlm".into(),
                domain: "fabrikam.local".into(),
                source: "secretsdump".into(),
                cracked_password: None,
                discovered_at: None,
                parent_id: None,
                attack_step: 0,
                aes_key: None,
                is_previous: false,
                source_host: None,
                is_trust_key: true,
                trust_pair_label: Some("CONTOSO".into()),
            },
            crate::models::Hash {
                id: "h2".into(),
                username: "FABRIKAM$".into(),
                hash_value: "feedbeef".into(),
                hash_type: "ntlm".into(),
                domain: "contoso.local".into(),
                source: "secretsdump".into(),
                cracked_password: None,
                discovered_at: None,
                parent_id: None,
                attack_step: 0,
                aes_key: None,
                is_previous: false,
                source_host: None,
                is_trust_key: true,
                trust_pair_label: Some("FABRIKAM".into()),
            },
        ];
        let gen = RedTeamReportGenerator::new().expect("template init");
        let report = gen
            .generate_comprehensive(&state, &[], &[])
            .expect("render");
        assert!(
            report.contains("Trust Keys / Forging Material"),
            "trust-key subsection missing from report"
        );
        assert!(
            report.contains("symmetric pair"),
            "symmetric-pair badge missing from rendered trust-key rows"
        );
        // The dedicated trust-key table should hoist BOTH rows above the
        // generic hash dump.
        assert!(report.contains("CONTOSO$"));
        assert!(report.contains("FABRIKAM$"));
    }

    #[test]
    fn comprehensive_report_omits_symmetric_badge_for_lone_trust_key() {
        // A single trust-key hash with no pair should NOT get the
        // "symmetric pair" badge — that's only for verified pairs.
        let mut state = empty_state();
        state.all_hashes = vec![crate::models::Hash {
            id: "h1".into(),
            username: "FABRIKAM$".into(),
            hash_value: "feedbeef".into(),
            hash_type: "ntlm".into(),
            domain: "contoso.local".into(),
            source: "secretsdump".into(),
            cracked_password: None,
            discovered_at: None,
            parent_id: None,
            attack_step: 0,
            aes_key: None,
            is_previous: false,
            source_host: None,
            is_trust_key: true,
            trust_pair_label: Some("FABRIKAM".into()),
        }];
        let gen = RedTeamReportGenerator::new().expect("template init");
        let report = gen
            .generate_comprehensive(&state, &[], &[])
            .expect("render");
        assert!(report.contains("Trust Keys / Forging Material"));
        assert!(
            !report.contains("symmetric pair"),
            "lone trust key must not be flagged as symmetric"
        );
    }
}
