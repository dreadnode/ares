//! Types for gap analysis reports and recommendations.

use serde::{Deserialize, Serialize};

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

#[cfg(test)]
mod tests {
    use super::*;

    fn make_report(gaps: Vec<&str>, recs: Vec<DetectionRecommendation>) -> GapAnalysisReport {
        GapAnalysisReport {
            evaluation_id: "eval-1".to_string(),
            operation_id: "op-1".to_string(),
            overall_grade: "B".to_string(),
            detection_gaps: gaps.into_iter().map(String::from).collect(),
            recommendations: recs,
            summary: "Test summary".to_string(),
        }
    }

    fn make_rec(priority: &str, title: &str, category: &str) -> DetectionRecommendation {
        DetectionRecommendation {
            category: category.to_string(),
            priority: priority.to_string(),
            title: title.to_string(),
            description: "desc".to_string(),
            techniques: vec![],
            implementation_hint: String::new(),
        }
    }

    #[test]
    fn to_markdown_contains_header_and_ids() {
        let report = make_report(vec![], vec![]);
        let md = report.to_markdown();
        assert!(md.contains("# Detection Gap Analysis Report"));
        assert!(md.contains("**Evaluation ID:** eval-1"));
        assert!(md.contains("**Operation ID:** op-1"));
        assert!(md.contains("**Grade:** B"));
    }

    #[test]
    fn to_markdown_no_gaps_message() {
        let report = make_report(vec![], vec![]);
        let md = report.to_markdown();
        assert!(md.contains("No significant detection gaps identified."));
    }

    #[test]
    fn to_markdown_lists_gaps() {
        let report = make_report(vec!["Missing T1003", "No lateral detection"], vec![]);
        let md = report.to_markdown();
        assert!(md.contains("- Missing T1003"));
        assert!(md.contains("- No lateral detection"));
    }

    #[test]
    fn to_markdown_no_recs_message() {
        let report = make_report(vec![], vec![]);
        let md = report.to_markdown();
        assert!(md.contains("No specific recommendations at this time."));
    }

    #[test]
    fn to_markdown_groups_recs_by_priority() {
        let recs = vec![
            make_rec("high", "Add Sysmon", "log_source"),
            make_rec("critical", "Fix SIEM", "rule"),
        ];
        let report = make_report(vec![], recs);
        let md = report.to_markdown();
        assert!(md.contains("### Critical Priority"));
        assert!(md.contains("### High Priority"));
        assert!(md.contains("#### Fix SIEM"));
        assert!(md.contains("#### Add Sysmon"));
    }

    #[test]
    fn to_markdown_includes_techniques_when_present() {
        let rec = DetectionRecommendation {
            category: "rule".to_string(),
            priority: "high".to_string(),
            title: "Detect T1003".to_string(),
            description: "Add rule".to_string(),
            techniques: vec!["T1003".to_string(), "T1003.001".to_string()],
            implementation_hint: "Use Sigma".to_string(),
        };
        let report = make_report(vec![], vec![rec]);
        let md = report.to_markdown();
        assert!(md.contains("**Techniques:** T1003, T1003.001"));
        assert!(md.contains("**Implementation:** Use Sigma"));
    }

    #[test]
    fn to_markdown_includes_summary() {
        let report = make_report(vec![], vec![]);
        let md = report.to_markdown();
        assert!(md.contains("Test summary"));
    }
}
