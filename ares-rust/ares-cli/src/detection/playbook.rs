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
