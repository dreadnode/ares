//! Report generation using the Tera templating engine.
//!
//! Provides red team and blue team report generators that produce markdown
//! reports from shared operation state. Templates are embedded at compile time
//! using `include_str!`.

#[cfg(feature = "blue")]
mod blueteam;
mod context;
mod dedup;
mod mitre;
mod redteam;
mod templates;
mod util;
mod vuln_details;

#[cfg(feature = "blue")]
pub use blueteam::*;
pub use dedup::*;
pub use mitre::*;
pub use redteam::*;
pub use vuln_details::*;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{Credential, Hash, Host, SharedRedTeamState, Target};
    use std::collections::{HashMap, HashSet};

    use chrono::Utc;

    #[test]
    fn mitre_lookup() {
        assert_eq!(get_technique_display("T1003.006"), "T1003.006 (DCSync)");
        assert_eq!(get_technique_display("T9999"), "T9999");
    }

    #[test]
    fn format_vuln_details_empty() {
        let details = HashMap::new();
        assert_eq!(format_vuln_details(&details), "-");
    }

    #[test]
    fn format_vuln_details_with_values() {
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
    fn deduplicates_credentials() {
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
    fn deduplicates_hashes() {
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
                is_previous: false,
                source_host: None,
                is_trust_key: false,
                trust_pair_label: None,
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
                is_previous: false,
                source_host: None,
                is_trust_key: false,
                trust_pair_label: None,
            },
        ];
        let deduped = dedup_hashes(&hashes);
        assert_eq!(deduped.len(), 2);
        assert_eq!(deduped[0].username, "administrator");
    }

    #[test]
    fn redteam_summary_renders() {
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
            red_completed_at: None,
            red_completion_reason: None,
            red_blocked_on_blue: false,
            all_domains: vec!["contoso.local".to_string()],
            all_credentials: Vec::new(),
            all_hashes: Vec::new(),
            all_hosts: Vec::new(),
            all_users: Vec::new(),
            all_shares: Vec::new(),
            discovered_vulnerabilities: HashMap::new(),
            exploited_vulnerabilities: HashSet::new(),
            superseded_vulnerabilities: HashSet::new(),
            has_domain_admin: false,
            has_golden_ticket: false,
            domain_admin_path: None,
            domain_controllers: HashMap::new(),
            netbios_to_fqdn: HashMap::new(),
            trusted_domains: HashMap::new(),
            all_timeline_events: Vec::new(),
            all_techniques: Vec::new(),
        };

        let result = gen.generate_summary(&state, &[], &[], false);
        assert!(result.is_ok());
        let report = result.unwrap();
        assert!(report.contains("# Red Team Operation Report"));
        assert!(report.contains("test-op-001"));
        assert!(report.contains("192.168.58.10"));
    }

    #[test]
    fn redteam_comprehensive_renders() {
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
            red_completed_at: None,
            red_completion_reason: None,
            red_blocked_on_blue: false,
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
                is_previous: false,
                source_host: None,
                is_trust_key: false,
                trust_pair_label: None,
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
            discovered_vulnerabilities: HashMap::new(),
            exploited_vulnerabilities: HashSet::new(),
            superseded_vulnerabilities: HashSet::new(),
            has_domain_admin: true,
            has_golden_ticket: false,
            domain_admin_path: Some("secretsdump -> administrator hash -> DA".to_string()),
            domain_controllers: HashMap::new(),
            netbios_to_fqdn: HashMap::new(),
            trusted_domains: HashMap::new(),
            all_timeline_events: Vec::new(),
            all_techniques: Vec::new(),
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

    #[cfg(feature = "blue")]
    #[test]
    fn blueteam_report_renders() {
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
            highest_analyst_pyramid_level: 4,
            analyst_evidence_count: 5,
            ttp_count: 0,
            analyst_ttp_count: 0,
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
            analyst_pyramid_distribution: HashMap::new(),
            coverage: None,
        };

        let result = gen.generate(&input);
        assert!(result.is_ok());
        let report = result.unwrap();
        assert!(report.contains("# Blue Team Operation Report"));
        assert!(report.contains("blue-test-001"));
        assert!(report.contains("ESCALATIONS REQUIRED"));
    }

    #[cfg(feature = "blue")]
    #[test]
    fn blueteam_report_derives_tactics_from_techniques() {
        use crate::models::SharedBlueTeamState;

        let gen = BlueTeamReportGenerator::new().unwrap();
        let mut state = SharedBlueTeamState::new("inv-tactics-001".to_string());
        // Blue agents routinely record techniques and no tactics at all; the
        // report used to answer that with "MITRE Tactics | 0" and a table of
        // "Unknown".
        state.identified_techniques = vec![
            "T1003.006".to_string(),
            "T1021.002".to_string(),
            "T1649".to_string(),
        ];
        assert!(state.identified_tactics.is_empty());

        let report = gen
            .generate_from_states("op-tactics-001", &[state], &HashMap::new(), None)
            .unwrap();

        assert!(
            !report.contains("MITRE Tactics | 0"),
            "tactics must be derived, not zero: {report}"
        );
        assert!(report.contains("| MITRE Tactics | 2 |"), "{report}");
        assert!(report.contains("Credential Access"));
        assert!(report.contains("Lateral Movement"));
        assert!(
            report.contains("| T1003.006 | DCSync | Credential Access |"),
            "technique rows must carry a resolved name and tactic: {report}"
        );

        let techniques_table = report
            .split("## Techniques Identified By Blue Team")
            .nth(1)
            .and_then(|s| s.split("## Pyramid").next())
            .expect("technique section present");
        assert!(
            !techniques_table.contains("Unknown"),
            "no technique should render tactic Unknown: {techniques_table}"
        );
    }

    #[cfg(feature = "blue")]
    #[test]
    fn blueteam_report_without_red_state_refuses_to_imply_coverage() {
        let gen = BlueTeamReportGenerator::new().unwrap();
        let input = BlueTeamReportInput {
            operation_id: "blue-test-002".to_string(),
            coverage: None,
            ..Default::default()
        };

        let report = gen.generate(&input).unwrap();
        assert!(report.contains("Red Team Activity Coverage"));
        assert!(
            report.contains("Not measured"),
            "an unmeasurable report must say so: {report}"
        );
        assert!(
            !report.contains("Detection rate |"),
            "must not print a detection rate it did not compute: {report}"
        );
    }

    #[cfg(feature = "blue")]
    #[test]
    fn blueteam_report_reports_missed_red_techniques() {
        use crate::reports::blueteam::RedTeamCoverage;

        let gen = BlueTeamReportGenerator::new().unwrap();
        let mut red = crate::models::SharedRedTeamState::new("op-test-003".to_string());
        red.all_techniques = vec![
            "T1003.006".to_string(),
            "T1078.002".to_string(),
            "T1210".to_string(),
            "T1558.003".to_string(),
        ];
        let mut blue = crate::models::SharedBlueTeamState::new("inv-test-003".to_string());
        blue.identified_techniques = vec!["T1003.006".to_string(), "T1615".to_string()];

        let input = BlueTeamReportInput {
            operation_id: "op-test-003".to_string(),
            coverage: Some(RedTeamCoverage::compute(&red, &[blue])),
            ..Default::default()
        };

        let report = gen.generate(&input).unwrap();
        assert!(
            report.contains("25% (1/4)"),
            "detection rate must be stated against red's real total: {report}"
        );
        assert!(report.contains("T1210"), "missed techniques must be named");
        assert!(report.contains("T1558.003"));
        assert!(
            report.contains("T1615"),
            "blue-only detections must be separated out"
        );
    }

    #[cfg(feature = "blue")]
    #[test]
    fn blueteam_report_weights_the_rate_and_shows_the_silent_tail() {
        use crate::models::Evidence;
        use crate::reports::blueteam::RedTeamCoverage;

        let gen = BlueTeamReportGenerator::new().unwrap();
        let mut red = crate::models::SharedRedTeamState::new("op-test-004".to_string());
        let event = |technique: &str, ts: &str| {
            serde_json::json!({
                "id": format!("evt-{technique}-{ts}"),
                "timestamp": ts,
                "description": format!("red ran {technique}"),
                "mitre_techniques": [technique],
            })
        };
        red.all_timeline_events = vec![
            event("T1046", "2026-07-28T21:28:00Z"),
            event("T1046", "2026-07-28T21:29:00Z"),
            event("T1046", "2026-07-28T21:30:00Z"),
            event("T1003.006", "2026-07-28T21:53:14Z"),
        ];

        let mut blue = crate::models::SharedBlueTeamState::new("inv-test-004".to_string());
        blue.identified_techniques = vec!["T1046".to_string(), "T1003.006".to_string()];
        blue.evidence = vec![Evidence {
            id: "ev-sweep-1".to_string(),
            evidence_type: "technique".to_string(),
            value: "T1046".to_string(),
            source: "detection_sweep:detect_port_scan".to_string(),
            timestamp: Some("2026-07-28T21:28:00Z".to_string()),
            pyramid_level: 6,
            mitre_techniques: vec!["T1046".to_string()],
            confidence: 0.8,
            metadata: HashMap::new(),
            source_query_id: None,
            validated: true,
        }];

        let input = BlueTeamReportInput {
            operation_id: "op-test-004".to_string(),
            coverage: Some(RedTeamCoverage::compute(&red, &[blue])),
            ..Default::default()
        };
        let report = gen.generate(&input).unwrap();

        assert!(
            report.contains("| Detection rate | 75% (3/4) |"),
            "the headline rate must weight each technique by red's action count: {report}"
        );
        assert!(
            report.contains("| Technique coverage (set join) | 100% (2/2) |"),
            "the set join must stay visible, and stay separate: {report}"
        );
        assert!(
            report.contains("| Taken after blue's last detection | 1 |"),
            "red actions past blue's last detection must be counted: {report}"
        );
        assert!(
            report.contains("| T1003.006 | 1 | blue named it"),
            "a technique blue named but never observed must say so: {report}"
        );
    }

    #[cfg(feature = "blue")]
    #[test]
    fn blueteam_investigation_report_renders() {
        use crate::models::{Evidence, SharedBlueTeamState, TimelineEvent};

        let gen = BlueTeamReportGenerator::new().unwrap();
        let mut state = SharedBlueTeamState::new("inv-test-001".to_string());
        state.alert = serde_json::json!({
            "labels": {
                "alertname": "HighCPUUsage",
                "severity": "critical",
                "instance": "dc01.contoso.local",
                "job": "node_exporter"
            }
        });
        state.evidence = vec![
            Evidence {
                id: "ev-001".to_string(),
                evidence_type: "ip".to_string(),
                value: "192.168.58.10".to_string(),
                source: "network_log".to_string(),
                timestamp: Some("2026-04-07T10:00:00Z".to_string()),
                pyramid_level: 2,
                mitre_techniques: vec!["T1021".to_string()],
                confidence: 0.85,
                metadata: HashMap::new(),
                source_query_id: None,
                validated: true,
            },
            Evidence {
                id: "ev-002".to_string(),
                evidence_type: "technique".to_string(),
                value: "Lateral Movement via SMB".to_string(),
                source: "siem".to_string(),
                timestamp: Some("2026-04-07T10:05:00Z".to_string()),
                pyramid_level: 6,
                mitre_techniques: vec!["T1021.002".to_string()],
                confidence: 0.92,
                metadata: HashMap::new(),
                source_query_id: None,
                validated: true,
            },
        ];
        state.timeline = vec![TimelineEvent {
            id: "tl-001".to_string(),
            timestamp: "2026-04-07T10:00:00Z".to_string(),
            description: "SMB connection from workstation to DC".to_string(),
            evidence_ids: vec!["ev-001".to_string()],
            mitre_techniques: vec!["T1021.002".to_string()],
            confidence: 0.9,
            source: "siem".to_string(),
            extra_data_json: None,
        }];
        state.identified_techniques = vec!["T1021".to_string(), "T1021.002".to_string()];
        state.identified_tactics = vec!["Lateral Movement".to_string()];
        state.technique_names = HashMap::from([
            ("T1021".to_string(), "Remote Services".to_string()),
            (
                "T1021.002".to_string(),
                "SMB/Windows Admin Shares".to_string(),
            ),
        ]);
        state.queried_hosts = vec!["dc01.contoso.local".to_string()];
        state.queried_users = vec!["admin@contoso.local".to_string()];
        state.escalated = true;
        state.escalation_reason = Some("High severity lateral movement detected".to_string());
        state.attack_synopsis = Some("Lateral movement via SMB to domain controller".to_string());
        state.recommendations = vec!["Block unauthorized SMB traffic".to_string()];

        let queries = vec![serde_json::json!({
            "type": "loki",
            "query": "{job=\"windows_event\"} |= \"SMB\"",
            "result_count": 15,
        })];

        let result = gen.generate_investigation(&state, &queries);
        assert!(result.is_ok(), "Generate failed: {:?}", result.err());
        let report = result.unwrap();
        assert!(report.contains("# Investigation Report"), "Missing header");
        assert!(report.contains("inv-test-001"), "Missing investigation ID");
        assert!(report.contains("HighCPUUsage"), "Missing alert name");
        assert!(report.contains("ESCALATED"), "Missing escalation status");
        assert!(report.contains("T1021"), "Missing MITRE technique");
        assert!(report.contains("dc01.contoso.local"), "Missing host");
        assert!(
            report.contains("Lateral movement via SMB"),
            "Missing attack synopsis"
        );
        assert!(
            report.contains("Block unauthorized SMB traffic"),
            "Missing recommendation"
        );
        assert!(
            report.contains("Elevation Score"),
            "Missing pyramid assessment"
        );
    }

    #[cfg(feature = "blue")]
    #[test]
    fn blueteam_generate_from_states() {
        use crate::models::{Evidence, SharedBlueTeamState};

        let gen = BlueTeamReportGenerator::new().unwrap();

        let mut state1 = SharedBlueTeamState::new("inv-001".to_string());
        state1.started_at = "2026-04-07T10:00:00Z".to_string();
        state1.alert = serde_json::json!({
            "labels": { "alertname": "BruteForce", "severity": "high" }
        });
        state1.evidence = vec![Evidence {
            id: "ev-001".to_string(),
            evidence_type: "ip".to_string(),
            value: "192.168.58.10".to_string(),
            source: "firewall".to_string(),
            timestamp: None,
            pyramid_level: 2,
            mitre_techniques: vec!["T1110".to_string()],
            confidence: 0.8,
            metadata: HashMap::new(),
            source_query_id: None,
            validated: false,
        }];
        state1.identified_techniques = vec!["T1110".to_string()];
        state1.queried_hosts = vec!["server01".to_string()];

        let mut state2 = SharedBlueTeamState::new("inv-002".to_string());
        state2.started_at = "2026-04-07T10:05:00Z".to_string();
        state2.alert = serde_json::json!({
            "labels": { "alertname": "MalwareDetected", "severity": "critical" }
        });
        state2.evidence = vec![Evidence {
            id: "ev-002".to_string(),
            evidence_type: "hash".to_string(),
            value: "abc123def456".to_string(),
            source: "edr".to_string(),
            timestamp: None,
            pyramid_level: 1,
            mitre_techniques: vec!["T1059".to_string()],
            confidence: 0.95,
            metadata: HashMap::new(),
            source_query_id: None,
            validated: true,
        }];
        state2.identified_techniques = vec!["T1059".to_string()];
        state2.queried_hosts = vec!["workstation01".to_string()];
        state2.escalated = true;

        let states = vec![state1, state2];
        let queries_by_inv = HashMap::new();

        let result = gen.generate_from_states("op-test-001", &states, &queries_by_inv, None);
        assert!(result.is_ok(), "Generate failed: {:?}", result.err());
        let report = result.unwrap();
        assert!(report.contains("# Blue Team Operation Report"));
        assert!(report.contains("op-test-001"));
        assert!(report.contains("BruteForce"));
        assert!(report.contains("MalwareDetected"));
        assert!(report.contains("ESCALATIONS REQUIRED"));
        assert!(report.contains("Investigations | 2"));
    }
}
