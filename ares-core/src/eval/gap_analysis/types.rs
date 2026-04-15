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
