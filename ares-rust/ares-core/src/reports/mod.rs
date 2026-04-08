//! Report generation using the Tera templating engine.
//!
//! Provides red team and blue team report generators that produce markdown
//! reports from shared operation state. Templates are embedded at compile time
//! using `include_str!`.

mod blueteam;
mod context;
mod dedup;
mod mitre;
mod redteam;
mod templates;
mod util;
mod vuln_details;
mod weakness;

pub use blueteam::*;
pub use dedup::*;
pub use mitre::*;
pub use redteam::*;
pub use vuln_details::*;
pub use weakness::*;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{Credential, Hash, Host, SharedRedTeamState, Target};
    use std::collections::{HashMap, HashSet};

    use chrono::Utc;

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
