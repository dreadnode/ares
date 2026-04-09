//! Detection gap analysis and recommendations.
//!
//! Analyzes evaluation results to identify detection gaps and provide
//! actionable recommendations for improving blue team detection capabilities.

use serde::{Deserialize, Serialize};

use super::ground_truth::{ExpectedIOC, ExpectedTechnique};
use super::results::EvaluationResult;

/// A recommendation for improving detection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionRecommendation {
    /// Category: log_source, rule, query, training.
    pub category: String,
    /// Priority: critical, high, medium, low.
    pub priority: String,
    pub title: String,
    pub description: String,
    #[serde(default)]
    pub techniques: Vec<String>,
    #[serde(default)]
    pub implementation_hint: String,
}

/// Complete gap analysis report for an evaluation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GapAnalysisReport {
    pub evaluation_id: String,
    pub operation_id: String,
    pub overall_grade: String,
    #[serde(default)]
    pub detection_gaps: Vec<String>,
    #[serde(default)]
    pub recommendations: Vec<DetectionRecommendation>,
    #[serde(default)]
    pub summary: String,
}

impl GapAnalysisReport {
    /// Generate markdown report.
    pub fn to_markdown(&self) -> String {
        let mut lines = vec![
            "# Detection Gap Analysis Report".to_string(),
            String::new(),
            format!("**Evaluation ID:** {}", self.evaluation_id),
            format!("**Operation ID:** {}", self.operation_id),
            format!("**Grade:** {}", self.overall_grade),
            String::new(),
            "## Executive Summary".to_string(),
            String::new(),
            self.summary.clone(),
            String::new(),
            "## Detection Gaps".to_string(),
            String::new(),
        ];

        if self.detection_gaps.is_empty() {
            lines.push("No significant detection gaps identified.".to_string());
        } else {
            for gap in &self.detection_gaps {
                lines.push(format!("- {gap}"));
            }
        }

        lines.push(String::new());
        lines.push("## Recommendations".to_string());
        lines.push(String::new());

        if self.recommendations.is_empty() {
            lines.push("No specific recommendations at this time.".to_string());
        } else {
            for priority in &["critical", "high", "medium", "low"] {
                let priority_recs: Vec<&DetectionRecommendation> = self
                    .recommendations
                    .iter()
                    .filter(|r| r.priority == *priority)
                    .collect();

                if !priority_recs.is_empty() {
                    let title = format!("{}{}", priority[..1].to_uppercase(), &priority[1..]);
                    lines.push(format!("### {title} Priority"));
                    lines.push(String::new());

                    for rec in priority_recs {
                        lines.push(format!("#### {}", rec.title));
                        lines.push(String::new());
                        lines.push(format!("**Category:** {}", rec.category));
                        if !rec.techniques.is_empty() {
                            lines.push(format!("**Techniques:** {}", rec.techniques.join(", ")));
                        }
                        lines.push(String::new());
                        lines.push(rec.description.clone());
                        if !rec.implementation_hint.is_empty() {
                            lines.push(String::new());
                            lines.push(format!("**Implementation:** {}", rec.implementation_hint));
                        }
                        lines.push(String::new());
                    }
                }
            }
        }

        lines.join("\n")
    }
}

/// Analyze an evaluation result and generate a gap analysis report.
pub fn analyze_detection_gaps(result: &EvaluationResult) -> GapAnalysisReport {
    let mut detection_gaps: Vec<String> = Vec::new();
    let mut recommendations: Vec<DetectionRecommendation> = Vec::new();

    // Analyze missed IOCs
    for ioc in &result.missed_iocs {
        detection_gaps.push(describe_ioc_gap(ioc));
        if let Some(rec) = recommend_for_ioc(ioc) {
            recommendations.push(rec);
        }
    }

    // Analyze missed techniques
    for tech in &result.missed_techniques {
        detection_gaps.push(describe_technique_gap(tech));
        if let Some(rec) = recommend_for_technique(tech) {
            recommendations.push(rec);
        }
    }

    // No alert fired
    if !result.alert_fired {
        detection_gaps.push("No alert fired for this attack scenario".to_string());
        recommendations.push(DetectionRecommendation {
            category: "rule".to_string(),
            priority: "critical".to_string(),
            title: "Create detection rules for attack indicators".to_string(),
            description: "The attack did not trigger any alerts. Review the attack \
                timeline and create Grafana/Prometheus alerting rules for \
                the observed indicators."
                .to_string(),
            techniques: Vec::new(),
            implementation_hint: "Create alertmanager rules matching network anomalies, \
                authentication events, and process execution patterns."
                .to_string(),
        });
    }

    // Investigation started but not completed
    if result.investigation_started && !result.investigation_completed {
        detection_gaps.push("Investigation started but did not complete".to_string());
        recommendations.push(DetectionRecommendation {
            category: "training".to_string(),
            priority: "medium".to_string(),
            title: "Improve investigation workflow completion".to_string(),
            description: "The investigation was started but did not complete all stages. \
                This may indicate gaps in tool availability, data access, \
                or investigation methodology."
                .to_string(),
            techniques: Vec::new(),
            implementation_hint: String::new(),
        });
    }

    // Low pyramid level
    if result.highest_pyramid_level < 4 {
        detection_gaps.push(format!(
            "Only reached pyramid level {}/6 (did not reach Network/Host Artifacts)",
            result.highest_pyramid_level,
        ));
        recommendations.push(DetectionRecommendation {
            category: "log_source".to_string(),
            priority: "high".to_string(),
            title: "Enable higher-fidelity log sources".to_string(),
            description: "Investigation evidence stayed at lower pyramid levels. \
                Enable additional log sources to identify tools and TTPs."
                .to_string(),
            techniques: Vec::new(),
            implementation_hint: "Enable Sysmon, PowerShell script block logging, \
                and command-line auditing."
                .to_string(),
        });
    }

    // Generate summary
    let summary = generate_summary(result, &detection_gaps);

    // Sort recommendations by priority
    let priority_order = |p: &str| -> u8 {
        match p {
            "critical" => 0,
            "high" => 1,
            "medium" => 2,
            "low" => 3,
            _ => 4,
        }
    };
    recommendations.sort_by_key(|r| priority_order(&r.priority));

    GapAnalysisReport {
        evaluation_id: result.evaluation_id.clone(),
        operation_id: result.operation_id.clone(),
        overall_grade: result.grade().to_string(),
        detection_gaps,
        recommendations,
        summary,
    }
}

fn describe_ioc_gap(ioc: &ExpectedIOC) -> String {
    let required_str = if ioc.required { " (required)" } else { "" };
    format!("Missed {} IOC: {}{}", ioc.ioc_type, ioc.value, required_str)
}

fn describe_technique_gap(tech: &ExpectedTechnique) -> String {
    let required_str = if tech.required { " (required)" } else { "" };
    let name = if tech.technique_name.is_empty() {
        String::new()
    } else {
        format!(" - {}", tech.technique_name)
    };
    format!(
        "Missed technique {}{}{}",
        tech.technique_id, name, required_str
    )
}

fn recommend_for_ioc(ioc: &ExpectedIOC) -> Option<DetectionRecommendation> {
    match ioc.ioc_type.as_str() {
        "ip" => Some(DetectionRecommendation {
            category: "query".to_string(),
            priority: if ioc.required { "high" } else { "medium" }.to_string(),
            title: format!("Add network IOC detection for {}", ioc.value),
            description: format!(
                "The IP address {} was involved in the attack but not \
                detected. Add network-based detection for this and similar IPs.",
                ioc.value,
            ),
            techniques: ioc.mitre_techniques.clone(),
            implementation_hint: "Query firewall logs, netflow data, and DNS logs for this IP. \
                Consider adding threat intelligence feeds."
                .to_string(),
        }),

        "user" => Some(DetectionRecommendation {
            category: "query".to_string(),
            priority: if ioc.required { "critical" } else { "high" }.to_string(),
            title: format!("Monitor compromised account: {}", ioc.value),
            description: format!(
                "User account {} was compromised but not detected. \
                Add behavioral analysis for this account type.",
                ioc.value,
            ),
            techniques: ioc.mitre_techniques.clone(),
            implementation_hint: "Query authentication logs (Windows Security, Kerberos). \
                Set up anomaly detection for account behavior."
                .to_string(),
        }),

        "hostname" | "domain" => Some(DetectionRecommendation {
            category: "query".to_string(),
            priority: if ioc.required { "high" } else { "medium" }.to_string(),
            title: format!("Add host/domain detection for {}", ioc.value),
            description: format!(
                "The host/domain {} was involved but not detected. \
                Ensure logs from this host are being collected.",
                ioc.value,
            ),
            techniques: ioc.mitre_techniques.clone(),
            implementation_hint:
                "Verify log forwarding from this host. Add to asset inventory if missing."
                    .to_string(),
        }),

        "hash" => Some(DetectionRecommendation {
            category: "rule".to_string(),
            priority: "medium".to_string(),
            title: "Implement hash-based detection".to_string(),
            description: format!(
                "File hash {}... was not detected. \
                Consider adding hash-based IOC detection.",
                &ioc.value[..ioc.value.len().min(16)],
            ),
            techniques: ioc.mitre_techniques.clone(),
            implementation_hint: "Integrate with threat intelligence for hash lookups. \
                Enable file integrity monitoring."
                .to_string(),
        }),

        _ => None,
    }
}

fn recommend_for_technique(tech: &ExpectedTechnique) -> Option<DetectionRecommendation> {
    struct TechRec {
        title: &'static str,
        description: &'static str,
        hint: &'static str,
    }

    let technique_recommendations: &[(&str, TechRec)] = &[
        (
            "T1003",
            TechRec {
                title: "Improve credential dumping detection",
                description: "OS Credential Dumping (T1003) was not detected. This is a \
                critical technique used in most advanced attacks.",
                hint: "Enable Sysmon Event ID 10 (process access), monitor LSASS access, \
                and alert on known credential dumping tools.",
            },
        ),
        (
            "T1003.006",
            TechRec {
                title: "Detect DCSync attacks",
                description: "DCSync (T1003.006) enables attackers to replicate AD credentials. \
                This is a high-priority detection gap.",
                hint: "Alert on Event ID 4662 with DS-Replication-Get-Changes rights \
                from non-DC sources. Monitor GetNCChanges RPC calls.",
            },
        ),
        (
            "T1078",
            TechRec {
                title: "Enhance valid account abuse detection",
                description: "Valid Accounts (T1078) abuse was not detected. Monitor for \
                unusual authentication patterns.",
                hint: "Implement impossible travel detection, monitor service account \
                usage, and alert on privilege escalation.",
            },
        ),
        (
            "T1558",
            TechRec {
                title: "Improve Kerberos attack detection",
                description: "Kerberos attacks (T1558) were not detected. These include \
                Golden/Silver ticket and Kerberoasting.",
                hint: "Monitor Event ID 4768/4769, detect TGT anomalies, and alert on \
                encryption downgrade attacks.",
            },
        ),
        (
            "T1558.003",
            TechRec {
                title: "Detect Kerberoasting attacks",
                description: "Kerberoasting (T1558.003) was not detected. Attackers request \
                TGS tickets for service accounts to crack offline.",
                hint: "Alert on Event ID 4769 with encryption type 0x17 (RC4). \
                Monitor unusual TGS requests for SPNs. Create Grafana alert: \
                |= \"4769\" |~ \"TicketEncryptionType.*0x17\"",
            },
        ),
        (
            "T1558.004",
            TechRec {
                title: "Detect AS-REP Roasting attacks",
                description: "AS-REP Roasting (T1558.004) was not detected. Targets accounts \
                with Kerberos pre-authentication disabled.",
                hint: "Alert on Event ID 4768 for accounts with pre-auth disabled. \
                Audit accounts with DONT_REQUIRE_PREAUTH flag. Create alert: \
                |= \"4768\" |~ \"PreAuthType.*0\"",
            },
        ),
        (
            "T1558.001",
            TechRec {
                title: "Detect Golden Ticket attacks",
                description: "Golden Ticket (T1558.001) was not detected. Attackers forge TGTs \
                using the krbtgt hash for persistent access.",
                hint: "Alert on TGS requests (4769) without corresponding TGT request (4768). \
                Monitor for TGTs with abnormal lifetimes or missing account correlation.",
            },
        ),
        (
            "T1550",
            TechRec {
                title: "Detect alternate authentication abuse",
                description: "Use Alternate Authentication Material (T1550) was not detected. \
                Includes Pass-the-Hash and Pass-the-Ticket.",
                hint: "Monitor for NTLM authentication from unusual sources. \
                Detect ticket reuse across different client IPs.",
            },
        ),
        (
            "T1550.003",
            TechRec {
                title: "Detect Constrained Delegation abuse",
                description:
                    "Pass the Ticket via Constrained Delegation (T1550.003) was not detected. \
                Attackers abuse S4U protocol to impersonate users.",
                hint: "Alert on Event ID 4769 with TransitedServices field populated. \
                Monitor S4U2Self/S4U2Proxy operations. Audit msDS-AllowedToDelegateTo \
                attribute changes.",
            },
        ),
        (
            "T1021",
            TechRec {
                title: "Detect lateral movement via remote services",
                description: "Remote Services (T1021) lateral movement was not detected. \
                Monitor for unusual remote connections.",
                hint: "Monitor Event ID 4624 Type 3/10, SMB/RDP connections, and \
                WinRM/PSRemoting activity.",
            },
        ),
        (
            "T1110",
            TechRec {
                title: "Improve brute force detection",
                description: "Brute Force (T1110) attacks were not detected. Implement \
                failed authentication monitoring.",
                hint: "Alert on multiple failed logins (Event ID 4625), implement \
                account lockout policies.",
            },
        ),
        (
            "T1649",
            TechRec {
                title: "Detect certificate-based attacks",
                description: "Certificate abuse (T1649) was not detected. ADCS attacks \
                are increasingly common.",
                hint: "Monitor certificate requests (Event ID 4886/4887), detect \
                ESC1-ESC8 vulnerabilities.",
            },
        ),
    ];

    // Check exact match first, then parent
    let tech_base = tech.technique_id.split('.').next().unwrap_or("");
    for key in &[tech.technique_id.as_str(), tech_base] {
        if let Some((_, rec_info)) = technique_recommendations.iter().find(|(k, _)| k == key) {
            return Some(DetectionRecommendation {
                category: "rule".to_string(),
                priority: if tech.required { "critical" } else { "high" }.to_string(),
                title: rec_info.title.to_string(),
                description: rec_info.description.to_string(),
                techniques: vec![tech.technique_id.clone()],
                implementation_hint: rec_info.hint.to_string(),
            });
        }
    }

    // Generic recommendation for unknown techniques
    Some(DetectionRecommendation {
        category: "rule".to_string(),
        priority: if tech.required { "high" } else { "medium" }.to_string(),
        title: format!("Add detection for {}", tech.technique_id),
        description: format!(
            "Technique {} ({}) was used but not detected. Research and implement detection.",
            tech.technique_id,
            if tech.technique_name.is_empty() {
                "Unknown"
            } else {
                &tech.technique_name
            },
        ),
        techniques: vec![tech.technique_id.clone()],
        implementation_hint: "Review MITRE ATT&CK documentation for detection guidance. \
            Consider Sigma rules from the community."
            .to_string(),
    })
}

fn generate_summary(result: &EvaluationResult, gaps: &[String]) -> String {
    let mut parts: Vec<String> = Vec::new();

    // Overall assessment
    let grade = result.grade();
    if grade == "A" || grade == "B" {
        parts.push(format!(
            "The investigation performed well with a grade of {grade}."
        ));
    } else if grade == "C" {
        parts.push(format!(
            "The investigation achieved a passing grade of {grade} but has room for improvement."
        ));
    } else {
        parts.push(format!(
            "The investigation received a grade of {grade}, indicating \
            significant detection gaps that need to be addressed."
        ));
    }

    // Alert status
    if result.alert_fired {
        parts.push("An alert was successfully triggered for this attack.".to_string());
    } else {
        parts.push(
            "No alert was triggered, indicating a critical gap in detection rules.".to_string(),
        );
    }

    // Detection rates
    parts.push(format!(
        "IOC detection rate was {:.0}% and technique coverage was {:.0}%.",
        result.ioc_detection_rate * 100.0,
        result.technique_coverage * 100.0,
    ));

    // Gap count
    if gaps.is_empty() {
        parts.push("No significant detection gaps were identified.".to_string());
    } else {
        parts.push(format!(
            "A total of {} detection gaps were identified.",
            gaps.len()
        ));
    }

    parts.join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::eval::ground_truth::{ExpectedIOC, ExpectedTechnique};
    use crate::models::PyramidLevel;

    fn make_result_with_gaps() -> EvaluationResult {
        EvaluationResult {
            evaluation_id: "eval-1".to_string(),
            operation_id: "op-1".to_string(),
            overall_score: 0.45,
            ioc_detection_rate: 0.3,
            technique_coverage: 0.4,
            highest_pyramid_level: 3,
            alert_fired: false,
            investigation_started: true,
            investigation_completed: false,
            missed_iocs: vec![
                ExpectedIOC {
                    ioc_type: "ip".to_string(),
                    value: "192.168.58.10".to_string(),
                    pyramid_level: PyramidLevel::IpAddresses,
                    mitre_techniques: vec!["T1046".to_string()],
                    required: true,
                    source: String::new(),
                },
                ExpectedIOC {
                    ioc_type: "user".to_string(),
                    value: "admin".to_string(),
                    pyramid_level: PyramidLevel::NetworkHostArtifacts,
                    mitre_techniques: vec![],
                    required: true,
                    source: String::new(),
                },
            ],
            missed_techniques: vec![
                ExpectedTechnique {
                    technique_id: "T1003".to_string(),
                    technique_name: "Credential Dumping".to_string(),
                    required: true,
                    parent_id: None,
                },
                ExpectedTechnique {
                    technique_id: "T1558.003".to_string(),
                    technique_name: "Kerberoasting".to_string(),
                    required: false,
                    parent_id: Some("T1558".to_string()),
                },
            ],
            ..Default::default()
        }
    }

    #[test]
    fn test_analyze_detection_gaps_basic() {
        let result = make_result_with_gaps();
        let report = analyze_detection_gaps(&result);

        assert_eq!(report.evaluation_id, "eval-1");
        assert_eq!(report.operation_id, "op-1");
        assert_eq!(report.overall_grade, "F");

        // 2 missed IOCs + 2 missed techniques + no alert + incomplete investigation + low pyramid
        assert!(
            report.detection_gaps.len() >= 6,
            "Expected >= 6 gaps, got {}",
            report.detection_gaps.len()
        );
        assert!(!report.recommendations.is_empty());
    }

    #[test]
    fn test_analyze_no_gaps() {
        let result = EvaluationResult {
            evaluation_id: "eval-2".to_string(),
            operation_id: "op-2".to_string(),
            overall_score: 0.95,
            ioc_detection_rate: 0.9,
            technique_coverage: 0.9,
            highest_pyramid_level: 6,
            alert_fired: true,
            investigation_started: true,
            investigation_completed: true,
            ..Default::default()
        };
        let report = analyze_detection_gaps(&result);
        assert_eq!(report.overall_grade, "A");
        assert!(report.detection_gaps.is_empty());
    }

    #[test]
    fn test_ioc_gap_descriptions() {
        let ioc = ExpectedIOC {
            ioc_type: "ip".to_string(),
            value: "10.0.0.1".to_string(),
            pyramid_level: PyramidLevel::IpAddresses,
            mitre_techniques: vec![],
            required: true,
            source: String::new(),
        };
        let gap = describe_ioc_gap(&ioc);
        assert!(gap.contains("ip IOC"));
        assert!(gap.contains("10.0.0.1"));
        assert!(gap.contains("(required)"));
    }

    #[test]
    fn test_technique_gap_descriptions() {
        let tech = ExpectedTechnique {
            technique_id: "T1003".to_string(),
            technique_name: "Credential Dumping".to_string(),
            required: true,
            parent_id: None,
        };
        let gap = describe_technique_gap(&tech);
        assert!(gap.contains("T1003"));
        assert!(gap.contains("Credential Dumping"));
        assert!(gap.contains("(required)"));
    }

    #[test]
    fn test_recommend_for_known_technique() {
        let tech = ExpectedTechnique {
            technique_id: "T1003".to_string(),
            technique_name: "Credential Dumping".to_string(),
            required: true,
            parent_id: None,
        };
        let rec = recommend_for_technique(&tech).unwrap();
        assert_eq!(rec.priority, "critical");
        assert!(rec.title.contains("credential dumping"));
        assert!(rec.implementation_hint.contains("Sysmon"));
    }

    #[test]
    fn test_recommend_for_subtechnique_falls_back_to_parent() {
        // T1003.001 is not in the map, but T1003 is
        let tech = ExpectedTechnique {
            technique_id: "T1003.001".to_string(),
            technique_name: "LSASS Memory".to_string(),
            required: false,
            parent_id: Some("T1003".to_string()),
        };
        let rec = recommend_for_technique(&tech).unwrap();
        assert!(rec.title.contains("credential dumping"));
        assert_eq!(rec.priority, "high"); // not required → high
    }

    #[test]
    fn test_recommend_for_unknown_technique() {
        let tech = ExpectedTechnique {
            technique_id: "T9999".to_string(),
            technique_name: "Novel Attack".to_string(),
            required: false,
            parent_id: None,
        };
        let rec = recommend_for_technique(&tech).unwrap();
        assert!(rec.title.contains("T9999"));
        assert_eq!(rec.priority, "medium");
        assert!(rec.description.contains("Novel Attack"));
    }

    #[test]
    fn test_recommend_for_ioc_types() {
        let ip_ioc = ExpectedIOC {
            ioc_type: "ip".to_string(),
            value: "10.0.0.1".to_string(),
            pyramid_level: PyramidLevel::IpAddresses,
            mitre_techniques: vec![],
            required: true,
            source: String::new(),
        };
        assert_eq!(recommend_for_ioc(&ip_ioc).unwrap().priority, "high");

        let user_ioc = ExpectedIOC {
            ioc_type: "user".to_string(),
            value: "admin".to_string(),
            pyramid_level: PyramidLevel::NetworkHostArtifacts,
            mitre_techniques: vec![],
            required: true,
            source: String::new(),
        };
        assert_eq!(recommend_for_ioc(&user_ioc).unwrap().priority, "critical");

        let hash_ioc = ExpectedIOC {
            ioc_type: "hash".to_string(),
            value: "abc123def456789012".to_string(),
            pyramid_level: PyramidLevel::HashValues,
            mitre_techniques: vec![],
            required: false,
            source: String::new(),
        };
        assert_eq!(recommend_for_ioc(&hash_ioc).unwrap().priority, "medium");

        let unknown_ioc = ExpectedIOC {
            ioc_type: "process".to_string(),
            value: "cmd.exe".to_string(),
            pyramid_level: PyramidLevel::Tools,
            mitre_techniques: vec![],
            required: false,
            source: String::new(),
        };
        assert!(recommend_for_ioc(&unknown_ioc).is_none());
    }

    #[test]
    fn test_to_markdown() {
        let result = make_result_with_gaps();
        let report = analyze_detection_gaps(&result);
        let md = report.to_markdown();

        assert!(md.contains("# Detection Gap Analysis Report"));
        assert!(md.contains("## Executive Summary"));
        assert!(md.contains("## Detection Gaps"));
        assert!(md.contains("## Recommendations"));
        assert!(md.contains("Critical Priority"));
        assert!(md.contains("eval-1"));
    }

    #[test]
    fn test_recommendations_sorted_by_priority() {
        let result = make_result_with_gaps();
        let report = analyze_detection_gaps(&result);

        let priorities: Vec<&str> = report
            .recommendations
            .iter()
            .map(|r| r.priority.as_str())
            .collect();
        let priority_val = |p: &str| match p {
            "critical" => 0,
            "high" => 1,
            "medium" => 2,
            "low" => 3,
            _ => 4,
        };
        for window in priorities.windows(2) {
            assert!(
                priority_val(window[0]) <= priority_val(window[1]),
                "Recommendations not sorted: {:?}",
                priorities,
            );
        }
    }

    #[test]
    fn test_summary_generation() {
        let result = make_result_with_gaps();
        let gaps = vec!["gap 1".to_string(), "gap 2".to_string()];
        let summary = generate_summary(&result, &gaps);

        assert!(summary.contains("grade of F"));
        assert!(summary.contains("No alert was triggered"));
        assert!(summary.contains("2 detection gaps"));
    }
}
