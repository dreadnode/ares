use crate::util::truncate_str;

use super::types::DetectionPlaybook;

pub(crate) fn generate_detection_markdown(playbook: &DetectionPlaybook) -> String {
    let mut md = String::with_capacity(8192);

    md.push_str("# Detection Playbook\n\n");
    md.push_str(&format!("**Operation ID:** `{}`\n", playbook.operation_id));
    md.push_str(&format!("**Generated:** {}\n", playbook.generated_at));
    md.push_str(&format!(
        "**Attack Window:** {} to {}\n\n",
        playbook.attack_window.start, playbook.attack_window.end
    ));
    md.push_str("---\n\n");

    // Executive Summary
    md.push_str("## Executive Summary\n\n");
    md.push_str(&playbook.executive_summary);
    md.push_str("\n\n---\n\n");

    // Attack Statistics
    md.push_str("## Attack Statistics\n\n");
    md.push_str(&format!(
        "- **Techniques Used:** {}\n",
        playbook.summary.technique_count
    ));
    md.push_str(&format!(
        "- **Credentials Harvested:** {}\n",
        playbook.summary.total_credentials
    ));
    md.push_str(&format!(
        "- **Hosts Discovered:** {}\n",
        playbook.summary.total_hosts
    ));
    md.push_str(&format!(
        "- **Domain Admin Achieved:** {}\n",
        if playbook.summary.achieved_domain_admin {
            "Yes"
        } else {
            "No"
        }
    ));
    if let Some(path) = &playbook.summary.domain_admin_path {
        md.push_str(&format!("- **DA Path:** {path}\n"));
    }
    md.push_str("\n---\n\n");

    // Priority Detection Queries
    md.push_str("## Priority Detection Queries\n\n");
    if !playbook.priority_queries.is_empty() {
        md.push_str(
            "Run these queries first - they target the most critical attack techniques.\n\n",
        );
        for (i, query) in playbook.priority_queries.iter().take(10).enumerate() {
            md.push_str(&format!(
                "### {}. {}: {}\n\n",
                i + 1,
                query.technique_id,
                query.technique_name
            ));
            md.push_str(&format!(
                "**Priority:** {}\n",
                query.priority.to_uppercase()
            ));
            md.push_str(&format!("**Description:** {}\n\n", query.description));
            md.push_str("```logql\n");
            md.push_str(&query.logql);
            md.push_str("\n```\n\n");
            if !query.windows_event_ids.is_empty() {
                md.push_str(&format!(
                    "**Event IDs:** {}\n",
                    query.windows_event_ids.join(", ")
                ));
            }
            if !query.expected_evidence.is_empty() {
                md.push_str(&format!(
                    "**Expected Evidence:** {}\n",
                    query.expected_evidence.join(", ")
                ));
            }
            md.push('\n');
        }
    }
    md.push_str("---\n\n");

    // Detection Targets (IOCs)
    md.push_str("## Detection Targets (IOCs)\n\n");
    if !playbook.detection_targets.is_empty() {
        md.push_str("| Type | Value | Pyramid Level | Detection |\n");
        md.push_str("|------|-------|---------------|----------|\n");

        let mut sorted_targets: Vec<_> = playbook.detection_targets.iter().collect();
        sorted_targets.sort_by(|a, b| b.pyramid_level.cmp(&a.pyramid_level));

        for target in sorted_targets.iter().take(20) {
            let value_display = truncate_str(&target.value, 40);
            let detection_preview = target
                .detection_queries
                .first()
                .map(|q| truncate_str(q, 30))
                .unwrap_or_else(|| "N/A".into());
            md.push_str(&format!(
                "| {} | `{}` | {} | {} |\n",
                target.ioc_type, value_display, target.pyramid_level_name, detection_preview
            ));
        }
    }
    md.push_str("\n---\n\n");

    // Technique-Specific Detections
    md.push_str("## Technique-Specific Detections\n\n");
    let mut sorted_techniques: Vec<_> = playbook.technique_detections.iter().collect();
    sorted_techniques.sort_by(|(a, _), (b, _)| a.cmp(b));

    for (tech_id, detection) in sorted_techniques {
        md.push_str(&format!(
            "### {}: {}\n\n",
            tech_id, detection.technique_name
        ));
        md.push_str(if detection.description.is_empty() {
            "No description available."
        } else {
            &detection.description
        });
        md.push_str("\n\n");

        if !detection.targets.is_empty() {
            let targets: Vec<&str> = detection
                .targets
                .iter()
                .take(5)
                .map(|s| s.as_str())
                .collect();
            md.push_str(&format!("**Targets:** {}\n", targets.join(", ")));
        }
        if !detection.credentials_used.is_empty() {
            let creds: Vec<&str> = detection
                .credentials_used
                .iter()
                .take(5)
                .map(|s| s.as_str())
                .collect();
            md.push_str(&format!("**Credentials Used:** {}\n", creds.join(", ")));
        }
        if !detection.windows_event_ids.is_empty() {
            md.push_str(&format!(
                "**Event IDs to Monitor:** {}\n",
                detection.windows_event_ids.join(", ")
            ));
        }
        if !detection.detection_guidance.is_empty() {
            md.push_str(&format!(
                "\n**Detection Guidance:** {}\n",
                detection.detection_guidance
            ));
        }
        if !detection.detection_queries.is_empty() {
            md.push_str("\n**Queries:**\n\n");
            for query in detection.detection_queries.iter().take(3) {
                md.push_str("```logql\n");
                md.push_str(&query.logql);
                md.push_str("\n```\n\n");
            }
        }
        md.push('\n');
    }

    md.push_str("---\n\n*Generated by Ares Detection Playbook Export*\n");
    md
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detection::playbook::generate_detection_playbook;
    use ares_core::models::{Credential, Host, SharedRedTeamState};

    fn make_playbook() -> DetectionPlaybook {
        let mut state = SharedRedTeamState::new("test-op".to_string());
        state.all_hosts = vec![Host {
            ip: "192.168.58.10".to_string(),
            hostname: "dc01.contoso.local".to_string(),
            os: String::new(),
            roles: vec![],
            services: vec![],
            is_dc: true,
            owned: false,
        }];
        state.all_credentials = vec![Credential {
            id: String::new(),
            username: "admin".to_string(),
            password: "P@ss1".to_string(),
            domain: "contoso.local".to_string(),
            source: String::new(),
            discovered_at: None,
            is_admin: false,
            parent_id: None,
            attack_step: 0,
        }];
        generate_detection_playbook(&state, &["T1046".to_string()])
    }

    #[test]
    fn test_generate_markdown_has_header() {
        let md = generate_detection_markdown(&make_playbook());
        assert!(md.starts_with("# Detection Playbook"));
    }

    #[test]
    fn test_generate_markdown_has_operation_id() {
        let md = generate_detection_markdown(&make_playbook());
        assert!(md.contains("test-op"));
    }

    #[test]
    fn test_generate_markdown_has_sections() {
        let md = generate_detection_markdown(&make_playbook());
        assert!(md.contains("## Executive Summary"));
        assert!(md.contains("## Attack Statistics"));
        assert!(md.contains("## Priority Detection Queries"));
        assert!(md.contains("## Detection Targets (IOCs)"));
        assert!(md.contains("## Technique-Specific Detections"));
    }

    #[test]
    fn test_generate_markdown_has_ioc_table() {
        let md = generate_detection_markdown(&make_playbook());
        assert!(md.contains("| Type | Value |"));
        assert!(md.contains("192.168.58.10"));
    }

    #[test]
    fn test_generate_markdown_has_footer() {
        let md = generate_detection_markdown(&make_playbook());
        assert!(md.contains("Generated by Ares Detection Playbook Export"));
    }

    #[test]
    fn test_generate_markdown_has_logql() {
        let md = generate_detection_markdown(&make_playbook());
        assert!(md.contains("```logql"));
    }

    #[test]
    fn test_generate_markdown_domain_admin_no() {
        let md = generate_detection_markdown(&make_playbook());
        assert!(md.contains("**Domain Admin Achieved:** No"));
    }
}
