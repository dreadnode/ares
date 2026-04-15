use chrono::Utc;

use ares_core::models::SharedRedTeamState;

use super::queries::build_priority_queries;
use super::techniques::{build_technique_detections, pyramid_level_name};
use super::types::{AttackWindow, DetectionPlaybook, DetectionTarget, PlaybookSummary};

pub(crate) fn generate_detection_playbook(
    state: &SharedRedTeamState,
    techniques: &[String],
) -> DetectionPlaybook {
    let now = Utc::now();
    let attack_start = state.started_at;
    let attack_end = state.completed_at.unwrap_or(now);
    let duration_minutes = (attack_end - attack_start).num_minutes();

    // Build detection targets from hosts
    let mut detection_targets = Vec::new();
    for host in &state.all_hosts {
        detection_targets.push(DetectionTarget {
            ioc_type: "ip".into(),
            value: host.ip.clone(),
            pyramid_level: 2,
            pyramid_level_name: pyramid_level_name(2).into(),
            context: format!(
                "Discovered host: {}",
                if host.hostname.is_empty() {
                    "unknown"
                } else {
                    &host.hostname
                }
            ),
            detection_queries: vec![
                format!(r#"{{job="windows-security"}} |= "{}""#, host.ip),
                format!(r#"{{job="firewall"}} |= "{}""#, host.ip),
            ],
            log_sources: vec![
                "windows-security".into(),
                "firewall".into(),
                "netflow".into(),
            ],
            mitre_techniques: vec!["T1046".into()],
        });
        if !host.hostname.is_empty() {
            detection_targets.push(DetectionTarget {
                ioc_type: "hostname".into(),
                value: host.hostname.clone(),
                pyramid_level: 3,
                pyramid_level_name: pyramid_level_name(3).into(),
                context: format!("Host: {}", host.ip),
                detection_queries: vec![format!(
                    r#"{{job="windows-security"}} |~ "(?i){}""#,
                    host.hostname
                )],
                log_sources: vec!["windows-security".into(), "dns".into()],
                mitre_techniques: vec!["T1046".into()],
            });
        }
    }

    // Build detection targets from credentials
    for cred in &state.all_credentials {
        let account_name = if cred.domain.is_empty() {
            cred.username.clone()
        } else {
            format!(r"{}\{}", cred.domain, cred.username)
        };
        detection_targets.push(DetectionTarget {
            ioc_type: "user".into(),
            value: account_name,
            pyramid_level: 4,
            pyramid_level_name: pyramid_level_name(4).into(),
            context: format!(
                "Compromised credential (source: {})",
                if cred.source.is_empty() {
                    "unknown"
                } else {
                    &cred.source
                }
            ),
            detection_queries: vec![
                format!(
                    r#"{{job="windows-security"}} |~ "(?i)(4624|4625|4648)" |~ "(?i){}""#,
                    cred.username
                ),
                format!(
                    r#"{{job="windows-security"}} |~ "(?i)LogonType.*(3|10)" |~ "(?i){}""#,
                    cred.username
                ),
            ],
            log_sources: vec!["windows-security".into()],
            mitre_techniques: vec!["T1078".into(), "T1003".into()],
        });
    }

    // Build detection targets from hashes
    for hash_obj in &state.all_hashes {
        let hash_preview = if hash_obj.hash_value.len() > 16 {
            format!("{}...", &hash_obj.hash_value[..16])
        } else {
            hash_obj.hash_value.clone()
        };
        detection_targets.push(DetectionTarget {
            ioc_type: "hash".into(),
            value: format!("{}:{}", hash_obj.username, hash_preview),
            pyramid_level: 1,
            pyramid_level_name: pyramid_level_name(1).into(),
            context: format!(
                "Dumped from {}",
                if hash_obj.source.is_empty() {
                    "unknown"
                } else {
                    &hash_obj.source
                }
            ),
            detection_queries: vec![format!(
                r#"{{job="windows-security"}} |= "4624" |~ "(?i){}" |~ "NTLM""#,
                hash_obj.username
            )],
            log_sources: vec!["windows-security".into()],
            mitre_techniques: vec!["T1003".into()],
        });
    }

    // Build technique detections
    let technique_detections =
        build_technique_detections(state, techniques, &attack_start, &attack_end);

    // Build priority queries
    let priority_queries = build_priority_queries(state, techniques, &attack_start, &attack_end);

    // Executive summary
    let mut summary_parts = Vec::new();
    summary_parts.push(format!(
        "Red team operation {} ran from {} to {} UTC.",
        state.operation_id,
        attack_start.format("%Y-%m-%d %H:%M"),
        attack_end.format("%Y-%m-%d %H:%M")
    ));
    if state.has_domain_admin {
        summary_parts.push(
            "**CRITICAL:** Domain Admin was achieved. \
             Focus detection efforts on the attack path and lateral movement."
                .into(),
        );
    }
    summary_parts.push(format!(
        "The attack used {} MITRE ATT&CK techniques, compromised {} credentials, \
         and discovered {} hosts.",
        techniques.len(),
        state.all_credentials.len(),
        state.all_hosts.len()
    ));
    if !state.exploited_vulnerabilities.is_empty() {
        summary_parts.push(format!(
            "Exploited {} vulnerabilities. \
             Review technique detections below for specific guidance.",
            state.exploited_vulnerabilities.len()
        ));
    }

    DetectionPlaybook {
        operation_id: state.operation_id.clone(),
        generated_at: now.to_rfc3339(),
        attack_window: AttackWindow {
            start: attack_start.to_rfc3339(),
            end: attack_end.to_rfc3339(),
            duration_minutes,
        },
        summary: PlaybookSummary {
            techniques_used: techniques.to_vec(),
            technique_count: techniques.len(),
            total_credentials: state.all_credentials.len(),
            total_hosts: state.all_hosts.len(),
            achieved_domain_admin: state.has_domain_admin,
            domain_admin_path: state.domain_admin_path.clone(),
        },
        executive_summary: summary_parts.join(" "),
        technique_detections,
        detection_targets,
        priority_queries,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ares_core::models::{Credential, Hash, Host};

    fn make_state() -> SharedRedTeamState {
        SharedRedTeamState::new("test-op-001".to_string())
    }

    #[test]
    fn test_generate_playbook_minimal() {
        let state = make_state();
        let playbook = generate_detection_playbook(&state, &[]);
        assert_eq!(playbook.operation_id, "test-op-001");
        assert_eq!(playbook.summary.technique_count, 0);
        assert_eq!(playbook.summary.total_credentials, 0);
        assert_eq!(playbook.summary.total_hosts, 0);
        assert!(!playbook.summary.achieved_domain_admin);
        assert!(playbook.detection_targets.is_empty());
    }

    #[test]
    fn test_generate_playbook_with_hosts() {
        let mut state = make_state();
        state.all_hosts = vec![Host {
            ip: "192.168.58.10".to_string(),
            hostname: "dc01.contoso.local".to_string(),
            os: String::new(),
            roles: vec![],
            services: vec![],
            is_dc: true,
            owned: false,
        }];
        let playbook = generate_detection_playbook(&state, &["T1046".to_string()]);
        assert_eq!(playbook.summary.total_hosts, 1);
        // Should have IP + hostname detection targets
        let ip_targets: Vec<_> = playbook
            .detection_targets
            .iter()
            .filter(|t| t.ioc_type == "ip")
            .collect();
        assert_eq!(ip_targets.len(), 1);
        assert_eq!(ip_targets[0].value, "192.168.58.10");
        let hostname_targets: Vec<_> = playbook
            .detection_targets
            .iter()
            .filter(|t| t.ioc_type == "hostname")
            .collect();
        assert_eq!(hostname_targets.len(), 1);
    }

    #[test]
    fn test_generate_playbook_with_credentials() {
        let mut state = make_state();
        state.all_credentials = vec![Credential {
            id: String::new(),
            username: "admin".to_string(),
            password: "P@ss1".to_string(),
            domain: "contoso.local".to_string(),
            source: "secretsdump".to_string(),
            discovered_at: None,
            is_admin: false,
            parent_id: None,
            attack_step: 0,
        }];
        let playbook = generate_detection_playbook(&state, &[]);
        let user_targets: Vec<_> = playbook
            .detection_targets
            .iter()
            .filter(|t| t.ioc_type == "user")
            .collect();
        assert_eq!(user_targets.len(), 1);
        assert!(user_targets[0].value.contains("admin"));
    }

    #[test]
    fn test_generate_playbook_with_hashes() {
        let mut state = make_state();
        state.all_hashes = vec![Hash {
            id: String::new(),
            username: "krbtgt".to_string(),
            hash_value: "aabbccddeeff00112233445566778899".to_string(),
            hash_type: "ntlm".to_string(),
            domain: "contoso.local".to_string(),
            cracked_password: None,
            source: "secretsdump".to_string(),
            discovered_at: None,
            parent_id: None,
            attack_step: 0,
            aes_key: None,
        }];
        let playbook = generate_detection_playbook(&state, &[]);
        let hash_targets: Vec<_> = playbook
            .detection_targets
            .iter()
            .filter(|t| t.ioc_type == "hash")
            .collect();
        assert_eq!(hash_targets.len(), 1);
        assert_eq!(hash_targets[0].pyramid_level, 1);
    }

    #[test]
    fn test_generate_playbook_domain_admin_summary() {
        let mut state = make_state();
        state.has_domain_admin = true;
        state.domain_admin_path = Some("admin -> DA".to_string());
        let playbook = generate_detection_playbook(&state, &[]);
        assert!(playbook.summary.achieved_domain_admin);
        assert!(playbook.executive_summary.contains("CRITICAL"));
        assert_eq!(
            playbook.summary.domain_admin_path,
            Some("admin -> DA".to_string())
        );
    }

    #[test]
    fn test_generate_playbook_technique_detections() {
        let state = make_state();
        let techniques = vec!["T1003".to_string(), "T1558.003".to_string()];
        let playbook = generate_detection_playbook(&state, &techniques);
        assert_eq!(playbook.summary.technique_count, 2);
        assert!(playbook.technique_detections.contains_key("T1003"));
        assert!(playbook.technique_detections.contains_key("T1558.003"));
    }
}
