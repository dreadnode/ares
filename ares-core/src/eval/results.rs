//! Evaluation result schema for blue team evaluation.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::ground_truth::{ExpectedIOC, ExpectedTechnique};

/// Complete evaluation result for a blue team investigation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvaluationResult {
    pub evaluation_id: String,
    pub operation_id: String,
    pub investigation_id: Option<String>,
    pub evaluated_at: DateTime<Utc>,

    // Overall scores (0.0–1.0)
    pub overall_score: f64,
    pub detection_score: f64,
    pub quality_score: f64,
    pub completeness_score: f64,

    // Component scores (0.0–1.0)
    pub stage_score: f64,
    pub ioc_detection_rate: f64,
    pub technique_coverage: f64,
    pub pyramid_elevation_score: f64,
    pub timeline_accuracy: f64,
    pub evidence_quality_score: f64,

    // Stage information
    pub final_stage: Option<String>,
    #[serde(default)]
    pub stages_completed: Vec<String>,

    // Gap analysis
    #[serde(default)]
    pub missed_iocs: Vec<ExpectedIOC>,
    #[serde(default)]
    pub missed_techniques: Vec<ExpectedTechnique>,
    #[serde(default)]
    pub found_iocs: Vec<ExpectedIOC>,
    #[serde(default)]
    pub found_techniques: Vec<ExpectedTechnique>,

    // Investigation stats
    pub evidence_count: usize,
    pub highest_pyramid_level: u32,
    pub ttp_count: usize,

    // Alert/detection status
    pub alert_fired: bool,
    pub investigation_started: bool,
    pub investigation_completed: bool,

    // Timing metrics
    pub time_to_first_evidence: Option<f64>,
    pub time_to_technique_identification: Option<f64>,
    pub time_to_ttp_elevation: Option<f64>,

    // Cost tracking
    #[serde(default)]
    pub total_tokens: u64,
    #[serde(default)]
    pub prompt_tokens: u64,
    #[serde(default)]
    pub completion_tokens: u64,
    #[serde(default)]
    pub estimated_cost_usd: f64,

    // Metadata
    #[serde(default)]
    pub model: String,
    #[serde(default)]
    pub duration_seconds: f64,
    pub error: Option<String>,
}

impl Default for EvaluationResult {
    fn default() -> Self {
        Self {
            evaluation_id: String::new(),
            operation_id: String::new(),
            investigation_id: None,
            evaluated_at: Utc::now(),
            overall_score: 0.0,
            detection_score: 0.0,
            quality_score: 0.0,
            completeness_score: 0.0,
            stage_score: 0.0,
            ioc_detection_rate: 0.0,
            technique_coverage: 0.0,
            pyramid_elevation_score: 0.0,
            timeline_accuracy: 0.0,
            evidence_quality_score: 0.0,
            final_stage: None,
            stages_completed: Vec::new(),
            missed_iocs: Vec::new(),
            missed_techniques: Vec::new(),
            found_iocs: Vec::new(),
            found_techniques: Vec::new(),
            evidence_count: 0,
            highest_pyramid_level: 0,
            ttp_count: 0,
            alert_fired: false,
            investigation_started: false,
            investigation_completed: false,
            time_to_first_evidence: None,
            time_to_technique_identification: None,
            time_to_ttp_elevation: None,
            total_tokens: 0,
            prompt_tokens: 0,
            completion_tokens: 0,
            estimated_cost_usd: 0.0,
            model: String::new(),
            duration_seconds: 0.0,
            error: None,
        }
    }
}

impl EvaluationResult {
    /// Whether the evaluation passed minimum thresholds.
    pub fn passed(&self) -> bool {
        self.overall_score >= 0.5
            && self.ioc_detection_rate >= 0.5
            && self.technique_coverage >= 0.5
    }

    /// Letter grade for the evaluation.
    pub fn grade(&self) -> &'static str {
        if self.overall_score >= 0.9 {
            "A"
        } else if self.overall_score >= 0.8 {
            "B"
        } else if self.overall_score >= 0.7 {
            "C"
        } else if self.overall_score >= 0.6 {
            "D"
        } else {
            "F"
        }
    }

    fn investigation_status(&self) -> &'static str {
        if self.investigation_completed {
            "Completed"
        } else if self.investigation_started {
            "Started"
        } else {
            "Not Started"
        }
    }

    /// Convert to a JSON value.
    pub fn to_value(&self) -> Value {
        serde_json::json!({
            "evaluation_id": self.evaluation_id,
            "operation_id": self.operation_id,
            "investigation_id": self.investigation_id,
            "evaluated_at": self.evaluated_at.to_rfc3339(),
            "scores": {
                "overall": self.overall_score,
                "detection": self.detection_score,
                "quality": self.quality_score,
                "completeness": self.completeness_score,
                "stage": self.stage_score,
                "ioc_detection_rate": self.ioc_detection_rate,
                "technique_coverage": self.technique_coverage,
                "pyramid_elevation": self.pyramid_elevation_score,
                "timeline_accuracy": self.timeline_accuracy,
                "evidence_quality": self.evidence_quality_score,
            },
            "gaps": {
                "missed_iocs": self.missed_iocs.iter().map(|i| serde_json::json!({
                    "type": i.ioc_type,
                    "value": i.value,
                    "required": i.required,
                })).collect::<Vec<_>>(),
                "missed_techniques": self.missed_techniques.iter().map(|t| serde_json::json!({
                    "id": t.technique_id,
                    "name": t.technique_name,
                    "required": t.required,
                })).collect::<Vec<_>>(),
                "found_iocs_count": self.found_iocs.len(),
                "found_techniques_count": self.found_techniques.len(),
            },
            "stats": {
                "evidence_count": self.evidence_count,
                "highest_pyramid_level": self.highest_pyramid_level,
                "ttp_count": self.ttp_count,
            },
            "status": {
                "alert_fired": self.alert_fired,
                "investigation_started": self.investigation_started,
                "investigation_completed": self.investigation_completed,
                "passed": self.passed(),
                "grade": self.grade(),
            },
            "timing": {
                "duration_seconds": self.duration_seconds,
                "time_to_first_evidence": self.time_to_first_evidence,
                "time_to_technique_identification": self.time_to_technique_identification,
                "time_to_ttp_elevation": self.time_to_ttp_elevation,
            },
            "cost": {
                "total_tokens": self.total_tokens,
                "prompt_tokens": self.prompt_tokens,
                "completion_tokens": self.completion_tokens,
                "estimated_cost_usd": self.estimated_cost_usd,
            },
            "metadata": {
                "model": self.model,
                "error": self.error,
            },
        })
    }

    /// Generate a human-readable summary.
    pub fn to_summary(&self) -> String {
        let mut lines = vec![
            format!("Evaluation: {}", self.evaluation_id),
            format!("Operation: {}", self.operation_id),
            format!(
                "Grade: {} ({:.1}%)",
                self.grade(),
                self.overall_score * 100.0
            ),
            String::new(),
            "Scores:".to_string(),
            format!("  Detection: {:.1}%", self.detection_score * 100.0),
            format!("  Quality: {:.1}%", self.quality_score * 100.0),
            format!("  Completeness: {:.1}%", self.completeness_score * 100.0),
            String::new(),
            format!(
                "IOC Detection: {:.1}% ({}/{})",
                self.ioc_detection_rate * 100.0,
                self.found_iocs.len(),
                self.found_iocs.len() + self.missed_iocs.len(),
            ),
            format!(
                "Technique Coverage: {:.1}% ({}/{})",
                self.technique_coverage * 100.0,
                self.found_techniques.len(),
                self.found_techniques.len() + self.missed_techniques.len(),
            ),
            format!("Pyramid Level: {}/6", self.highest_pyramid_level),
            String::new(),
            format!(
                "Alert Fired: {}",
                if self.alert_fired { "Yes" } else { "No" }
            ),
            format!("Investigation: {}", self.investigation_status()),
        ];

        if self.time_to_first_evidence.is_some() || self.duration_seconds > 0.0 {
            lines.push(String::new());
            lines.push("Timing:".to_string());
            lines.push(format!("  Duration: {:.1}s", self.duration_seconds));
            if let Some(ttfe) = self.time_to_first_evidence {
                lines.push(format!("  Time to First Evidence: {ttfe:.1}s"));
            }
            if let Some(ttid) = self.time_to_technique_identification {
                lines.push(format!("  Time to Technique ID: {ttid:.1}s"));
            }
            if let Some(tttp) = self.time_to_ttp_elevation {
                lines.push(format!("  Time to TTP Elevation: {tttp:.1}s"));
            }
        }

        if self.total_tokens > 0 {
            lines.push(String::new());
            lines.push("Cost:".to_string());
            lines.push(format!(
                "  Tokens: {} (prompt: {}, completion: {})",
                self.total_tokens, self.prompt_tokens, self.completion_tokens,
            ));
            lines.push(format!("  Estimated Cost: ${:.4}", self.estimated_cost_usd));
        }

        if !self.missed_techniques.is_empty() {
            lines.push(String::new());
            lines.push("Missed Techniques:".to_string());
            for t in self.missed_techniques.iter().take(5) {
                lines.push(format!("  - {}: {}", t.technique_id, t.technique_name));
            }
            if self.missed_techniques.len() > 5 {
                lines.push(format!(
                    "  ... and {} more",
                    self.missed_techniques.len() - 5
                ));
            }
        }

        if let Some(ref err) = self.error {
            lines.push(String::new());
            lines.push(format!("Error: {err}"));
        }

        lines.join("\n")
    }
}

/// Aggregated results for evaluating a dataset of scenarios.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatasetEvaluationResult {
    pub dataset_name: String,
    pub evaluated_at: DateTime<Utc>,
    #[serde(default)]
    pub results: Vec<EvaluationResult>,
}

impl DatasetEvaluationResult {
    pub fn count(&self) -> usize {
        self.results.len()
    }

    pub fn pass_rate(&self) -> f64 {
        if self.results.is_empty() {
            return 0.0;
        }
        self.results.iter().filter(|r| r.passed()).count() as f64 / self.results.len() as f64
    }

    pub fn avg_overall_score(&self) -> f64 {
        avg(&self.results, |r| r.overall_score)
    }

    pub fn avg_ioc_detection_rate(&self) -> f64 {
        avg(&self.results, |r| r.ioc_detection_rate)
    }

    pub fn avg_technique_coverage(&self) -> f64 {
        avg(&self.results, |r| r.technique_coverage)
    }

    pub fn alert_fire_rate(&self) -> f64 {
        if self.results.is_empty() {
            return 0.0;
        }
        self.results.iter().filter(|r| r.alert_fired).count() as f64 / self.results.len() as f64
    }

    pub fn investigation_completion_rate(&self) -> f64 {
        if self.results.is_empty() {
            return 0.0;
        }
        self.results
            .iter()
            .filter(|r| r.investigation_completed)
            .count() as f64
            / self.results.len() as f64
    }

    pub fn total_cost_usd(&self) -> f64 {
        self.results.iter().map(|r| r.estimated_cost_usd).sum()
    }

    pub fn total_tokens(&self) -> u64 {
        self.results.iter().map(|r| r.total_tokens).sum()
    }

    pub fn avg_duration_seconds(&self) -> f64 {
        avg(&self.results, |r| r.duration_seconds)
    }

    /// Convert to a JSON value.
    pub fn to_value(&self) -> Value {
        serde_json::json!({
            "dataset_name": self.dataset_name,
            "evaluated_at": self.evaluated_at.to_rfc3339(),
            "summary": {
                "count": self.count(),
                "pass_rate": self.pass_rate(),
                "avg_overall_score": self.avg_overall_score(),
                "avg_ioc_detection_rate": self.avg_ioc_detection_rate(),
                "avg_technique_coverage": self.avg_technique_coverage(),
                "alert_fire_rate": self.alert_fire_rate(),
                "investigation_completion_rate": self.investigation_completion_rate(),
                "total_cost_usd": self.total_cost_usd(),
                "total_tokens": self.total_tokens(),
                "avg_duration_seconds": self.avg_duration_seconds(),
            },
            "results": self.results.iter().map(|r| r.to_value()).collect::<Vec<_>>(),
        })
    }

    /// Generate a human-readable summary.
    pub fn to_summary(&self) -> String {
        let mut lines = vec![
            format!("Dataset Evaluation: {}", self.dataset_name),
            format!(
                "Evaluated: {}",
                self.evaluated_at.format("%Y-%m-%d %H:%M:%S UTC")
            ),
            format!("Scenarios: {}", self.count()),
            String::new(),
            "Aggregate Scores:".to_string(),
            format!("  Pass Rate: {:.1}%", self.pass_rate() * 100.0),
            format!("  Avg Overall: {:.1}%", self.avg_overall_score() * 100.0),
            format!(
                "  Avg IOC Detection: {:.1}%",
                self.avg_ioc_detection_rate() * 100.0
            ),
            format!(
                "  Avg Technique Coverage: {:.1}%",
                self.avg_technique_coverage() * 100.0
            ),
            String::new(),
            "Detection Metrics:".to_string(),
            format!("  Alert Fire Rate: {:.1}%", self.alert_fire_rate() * 100.0),
            format!(
                "  Investigation Completion: {:.1}%",
                self.investigation_completion_rate() * 100.0
            ),
            String::new(),
            "Cost & Performance:".to_string(),
            format!("  Total Cost: ${:.4}", self.total_cost_usd()),
            format!("  Total Tokens: {}", self.total_tokens()),
            format!("  Avg Duration: {:.1}s", self.avg_duration_seconds()),
        ];

        // Grade distribution
        let mut grade_counts = [0u32; 5]; // A, B, C, D, F
        for r in &self.results {
            match r.grade() {
                "A" => grade_counts[0] += 1,
                "B" => grade_counts[1] += 1,
                "C" => grade_counts[2] += 1,
                "D" => grade_counts[3] += 1,
                _ => grade_counts[4] += 1,
            }
        }
        lines.push(String::new());
        lines.push("Grade Distribution:".to_string());
        for (grade, &count) in ["A", "B", "C", "D", "F"].iter().zip(&grade_counts) {
            let pct = if self.count() > 0 {
                count as f64 / self.count() as f64 * 100.0
            } else {
                0.0
            };
            let bar = "#".repeat((pct / 5.0) as usize);
            lines.push(format!("  {grade}: {count:3} ({pct:5.1}%) {bar}"));
        }

        lines.join("\n")
    }
}

fn avg(results: &[EvaluationResult], f: impl Fn(&EvaluationResult) -> f64) -> f64 {
    if results.is_empty() {
        return 0.0;
    }
    results.iter().map(f).sum::<f64>() / results.len() as f64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_grade() {
        let r = EvaluationResult {
            overall_score: 0.95,
            ..Default::default()
        };
        assert_eq!(r.grade(), "A");
        let r = EvaluationResult {
            overall_score: 0.85,
            ..Default::default()
        };
        assert_eq!(r.grade(), "B");
        let r = EvaluationResult {
            overall_score: 0.75,
            ..Default::default()
        };
        assert_eq!(r.grade(), "C");
        let r = EvaluationResult {
            overall_score: 0.65,
            ..Default::default()
        };
        assert_eq!(r.grade(), "D");
        let r = EvaluationResult {
            overall_score: 0.4,
            ..Default::default()
        };
        assert_eq!(r.grade(), "F");
    }

    #[test]
    fn test_passed() {
        let mut r = EvaluationResult::default();
        assert!(!r.passed());

        r.overall_score = 0.6;
        r.ioc_detection_rate = 0.6;
        r.technique_coverage = 0.6;
        assert!(r.passed());

        r.technique_coverage = 0.3;
        assert!(!r.passed());
    }

    #[test]
    fn test_dataset_aggregation() {
        let ds = DatasetEvaluationResult {
            dataset_name: "test".to_string(),
            evaluated_at: Utc::now(),
            results: vec![
                EvaluationResult {
                    overall_score: 0.8,
                    ioc_detection_rate: 0.7,
                    technique_coverage: 0.9,
                    alert_fired: true,
                    investigation_completed: true,
                    estimated_cost_usd: 0.05,
                    ..Default::default()
                },
                EvaluationResult {
                    overall_score: 0.4,
                    ioc_detection_rate: 0.3,
                    technique_coverage: 0.5,
                    alert_fired: false,
                    investigation_completed: false,
                    estimated_cost_usd: 0.03,
                    ..Default::default()
                },
            ],
        };

        assert_eq!(ds.count(), 2);
        assert!((ds.pass_rate() - 0.5).abs() < f64::EPSILON);
        assert!((ds.avg_overall_score() - 0.6).abs() < f64::EPSILON);
        assert!((ds.alert_fire_rate() - 0.5).abs() < f64::EPSILON);
        assert!((ds.total_cost_usd() - 0.08).abs() < 0.001);
    }

    #[test]
    fn test_result_to_value() {
        let r = EvaluationResult {
            evaluation_id: "eval-1".to_string(),
            operation_id: "op-1".to_string(),
            overall_score: 0.85,
            ..Default::default()
        };
        let val = r.to_value();
        assert_eq!(val["evaluation_id"], "eval-1");
        assert_eq!(val["scores"]["overall"], 0.85);
        assert_eq!(val["status"]["grade"], "B");
    }
}
