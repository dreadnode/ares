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
    fn grade() {
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
    fn passed() {
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
    fn dataset_aggregation() {
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
    fn result_to_value() {
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

    #[test]
    fn default_creates_valid_result() {
        let r = EvaluationResult::default();
        assert!(r.evaluation_id.is_empty());
        assert!(r.operation_id.is_empty());
        assert!(r.investigation_id.is_none());
        assert_eq!(r.overall_score, 0.0);
        assert_eq!(r.detection_score, 0.0);
        assert_eq!(r.quality_score, 0.0);
        assert_eq!(r.completeness_score, 0.0);
        assert_eq!(r.stage_score, 0.0);
        assert_eq!(r.ioc_detection_rate, 0.0);
        assert_eq!(r.technique_coverage, 0.0);
        assert_eq!(r.pyramid_elevation_score, 0.0);
        assert_eq!(r.timeline_accuracy, 0.0);
        assert_eq!(r.evidence_quality_score, 0.0);
        assert!(r.final_stage.is_none());
        assert!(r.stages_completed.is_empty());
        assert!(r.missed_iocs.is_empty());
        assert!(r.missed_techniques.is_empty());
        assert!(r.found_iocs.is_empty());
        assert!(r.found_techniques.is_empty());
        assert_eq!(r.evidence_count, 0);
        assert_eq!(r.highest_pyramid_level, 0);
        assert_eq!(r.ttp_count, 0);
        assert!(!r.alert_fired);
        assert!(!r.investigation_started);
        assert!(!r.investigation_completed);
        assert!(r.time_to_first_evidence.is_none());
        assert!(r.time_to_technique_identification.is_none());
        assert!(r.time_to_ttp_elevation.is_none());
        assert_eq!(r.total_tokens, 0);
        assert_eq!(r.prompt_tokens, 0);
        assert_eq!(r.completion_tokens, 0);
        assert_eq!(r.estimated_cost_usd, 0.0);
        assert!(r.model.is_empty());
        assert_eq!(r.duration_seconds, 0.0);
        assert!(r.error.is_none());
    }

    #[test]
    fn serde_roundtrip_default() {
        let original = EvaluationResult::default();
        let json = serde_json::to_string(&original).unwrap();
        let deserialized: EvaluationResult = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.overall_score, original.overall_score);
        assert_eq!(deserialized.evaluation_id, original.evaluation_id);
        assert_eq!(deserialized.total_tokens, original.total_tokens);
        assert_eq!(deserialized.alert_fired, original.alert_fired);
    }

    #[test]
    fn serde_roundtrip_all_fields_populated() {
        let original = EvaluationResult {
            evaluation_id: "eval-full".to_string(),
            operation_id: "op-full".to_string(),
            investigation_id: Some("inv-001".to_string()),
            evaluated_at: Utc::now(),
            overall_score: 0.92,
            detection_score: 0.88,
            quality_score: 0.75,
            completeness_score: 0.95,
            stage_score: 0.80,
            ioc_detection_rate: 0.70,
            technique_coverage: 0.85,
            pyramid_elevation_score: 0.90,
            timeline_accuracy: 0.65,
            evidence_quality_score: 0.78,
            final_stage: Some("ttps".to_string()),
            stages_completed: vec!["hashes".to_string(), "ips".to_string(), "ttps".to_string()],
            missed_iocs: vec![ExpectedIOC {
                ioc_type: "ip".to_string(),
                value: "192.168.58.50".to_string(),
                pyramid_level: crate::models::PyramidLevel::IpAddresses,
                mitre_techniques: vec!["T1046".to_string()],
                required: true,
                source: "nmap".to_string(),
            }],
            missed_techniques: vec![ExpectedTechnique {
                technique_id: "T1003.001".to_string(),
                technique_name: "LSASS Memory".to_string(),
                required: true,
                parent_id: Some("T1003".to_string()),
            }],
            found_iocs: vec![ExpectedIOC {
                ioc_type: "hostname".to_string(),
                value: "dc01.contoso.local".to_string(),
                pyramid_level: crate::models::PyramidLevel::DomainNames,
                mitre_techniques: vec![],
                required: true,
                source: "".to_string(),
            }],
            found_techniques: vec![ExpectedTechnique {
                technique_id: "T1558.003".to_string(),
                technique_name: "Kerberoasting".to_string(),
                required: true,
                parent_id: Some("T1558".to_string()),
            }],
            evidence_count: 42,
            highest_pyramid_level: 5,
            ttp_count: 7,
            alert_fired: true,
            investigation_started: true,
            investigation_completed: true,
            time_to_first_evidence: Some(12.5),
            time_to_technique_identification: Some(45.0),
            time_to_ttp_elevation: Some(120.0),
            total_tokens: 50000,
            prompt_tokens: 30000,
            completion_tokens: 20000,
            estimated_cost_usd: 0.15,
            model: "gpt-4.1".to_string(),
            duration_seconds: 300.5,
            error: None,
        };
        let json = serde_json::to_string(&original).unwrap();
        let deserialized: EvaluationResult = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.evaluation_id, "eval-full");
        assert_eq!(deserialized.operation_id, "op-full");
        assert_eq!(deserialized.investigation_id, Some("inv-001".to_string()));
        assert!((deserialized.overall_score - 0.92).abs() < f64::EPSILON);
        assert!((deserialized.detection_score - 0.88).abs() < f64::EPSILON);
        assert_eq!(deserialized.stages_completed.len(), 3);
        assert_eq!(deserialized.missed_iocs.len(), 1);
        assert_eq!(deserialized.missed_iocs[0].value, "192.168.58.50");
        assert_eq!(deserialized.found_techniques.len(), 1);
        assert_eq!(deserialized.evidence_count, 42);
        assert_eq!(deserialized.highest_pyramid_level, 5);
        assert!(deserialized.alert_fired);
        assert!(deserialized.investigation_completed);
        assert_eq!(deserialized.time_to_first_evidence, Some(12.5));
        assert_eq!(deserialized.total_tokens, 50000);
        assert_eq!(deserialized.model, "gpt-4.1");
    }

    #[test]
    fn serde_missing_optional_fields() {
        let json = r#"{
            "evaluation_id": "eval-min",
            "operation_id": "op-min",
            "evaluated_at": "2026-01-15T10:00:00Z",
            "overall_score": 0.5,
            "detection_score": 0.5,
            "quality_score": 0.5,
            "completeness_score": 0.5,
            "stage_score": 0.5,
            "ioc_detection_rate": 0.5,
            "technique_coverage": 0.5,
            "pyramid_elevation_score": 0.5,
            "timeline_accuracy": 0.5,
            "evidence_quality_score": 0.5,
            "evidence_count": 0,
            "highest_pyramid_level": 0,
            "ttp_count": 0,
            "alert_fired": false,
            "investigation_started": false,
            "investigation_completed": false
        }"#;
        let r: EvaluationResult = serde_json::from_str(json).unwrap();
        assert_eq!(r.evaluation_id, "eval-min");
        assert!(r.investigation_id.is_none());
        assert!(r.final_stage.is_none());
        assert!(r.stages_completed.is_empty());
        assert!(r.missed_iocs.is_empty());
        assert!(r.missed_techniques.is_empty());
        assert!(r.found_iocs.is_empty());
        assert!(r.found_techniques.is_empty());
        assert!(r.time_to_first_evidence.is_none());
        assert_eq!(r.total_tokens, 0);
        assert_eq!(r.prompt_tokens, 0);
        assert_eq!(r.completion_tokens, 0);
        assert_eq!(r.estimated_cost_usd, 0.0);
        assert!(r.model.is_empty());
        assert_eq!(r.duration_seconds, 0.0);
        assert!(r.error.is_none());
    }

    #[test]
    fn grade_boundaries() {
        let at_90 = EvaluationResult {
            overall_score: 0.9,
            ..Default::default()
        };
        assert_eq!(at_90.grade(), "A");

        let just_below_90 = EvaluationResult {
            overall_score: 0.8999,
            ..Default::default()
        };
        assert_eq!(just_below_90.grade(), "B");

        let at_80 = EvaluationResult {
            overall_score: 0.8,
            ..Default::default()
        };
        assert_eq!(at_80.grade(), "B");

        let just_below_80 = EvaluationResult {
            overall_score: 0.7999,
            ..Default::default()
        };
        assert_eq!(just_below_80.grade(), "C");

        let at_70 = EvaluationResult {
            overall_score: 0.7,
            ..Default::default()
        };
        assert_eq!(at_70.grade(), "C");

        let just_below_70 = EvaluationResult {
            overall_score: 0.6999,
            ..Default::default()
        };
        assert_eq!(just_below_70.grade(), "D");

        let at_60 = EvaluationResult {
            overall_score: 0.6,
            ..Default::default()
        };
        assert_eq!(at_60.grade(), "D");

        let just_below_60 = EvaluationResult {
            overall_score: 0.5999,
            ..Default::default()
        };
        assert_eq!(just_below_60.grade(), "F");

        let zero = EvaluationResult {
            overall_score: 0.0,
            ..Default::default()
        };
        assert_eq!(zero.grade(), "F");

        let perfect = EvaluationResult {
            overall_score: 1.0,
            ..Default::default()
        };
        assert_eq!(perfect.grade(), "A");
    }

    #[test]
    fn passed_boundary_exactly_half() {
        let r = EvaluationResult {
            overall_score: 0.5,
            ioc_detection_rate: 0.5,
            technique_coverage: 0.5,
            ..Default::default()
        };
        assert!(r.passed());
    }

    #[test]
    fn passed_fails_overall_below_threshold() {
        let r = EvaluationResult {
            overall_score: 0.49,
            ioc_detection_rate: 0.8,
            technique_coverage: 0.8,
            ..Default::default()
        };
        assert!(!r.passed());
    }

    #[test]
    fn passed_fails_ioc_below_threshold() {
        let r = EvaluationResult {
            overall_score: 0.8,
            ioc_detection_rate: 0.49,
            technique_coverage: 0.8,
            ..Default::default()
        };
        assert!(!r.passed());
    }

    #[test]
    fn investigation_status_completed() {
        let r = EvaluationResult {
            investigation_started: true,
            investigation_completed: true,
            ..Default::default()
        };
        let summary = r.to_summary();
        assert!(summary.contains("Investigation: Completed"));
    }

    #[test]
    fn investigation_status_started() {
        let r = EvaluationResult {
            investigation_started: true,
            investigation_completed: false,
            ..Default::default()
        };
        let summary = r.to_summary();
        assert!(summary.contains("Investigation: Started"));
    }

    #[test]
    fn investigation_status_not_started() {
        let r = EvaluationResult {
            investigation_started: false,
            investigation_completed: false,
            ..Default::default()
        };
        let summary = r.to_summary();
        assert!(summary.contains("Investigation: Not Started"));
    }

    #[test]
    fn to_value_contains_all_sections() {
        let r = EvaluationResult {
            evaluation_id: "eval-struct".to_string(),
            operation_id: "op-struct".to_string(),
            overall_score: 0.7,
            alert_fired: true,
            total_tokens: 1000,
            prompt_tokens: 600,
            completion_tokens: 400,
            estimated_cost_usd: 0.01,
            ..Default::default()
        };
        let val = r.to_value();

        // Check nested values
        assert_eq!(val["status"]["alert_fired"], true);
        assert_eq!(val["status"]["passed"], false); // 0.7 overall but 0.0 ioc/tech
        assert_eq!(val["cost"]["total_tokens"], 1000);
        assert_eq!(val["cost"]["prompt_tokens"], 600);
        assert_eq!(val["cost"]["completion_tokens"], 400);
    }

    #[test]
    fn to_value_gaps_counts() {
        let r = EvaluationResult {
            found_iocs: vec![
                ExpectedIOC {
                    ioc_type: "ip".to_string(),
                    value: "192.168.58.10".to_string(),
                    pyramid_level: crate::models::PyramidLevel::IpAddresses,
                    mitre_techniques: vec![],
                    required: true,
                    source: "".to_string(),
                },
                ExpectedIOC {
                    ioc_type: "ip".to_string(),
                    value: "192.168.58.20".to_string(),
                    pyramid_level: crate::models::PyramidLevel::IpAddresses,
                    mitre_techniques: vec![],
                    required: true,
                    source: "".to_string(),
                },
            ],
            missed_iocs: vec![ExpectedIOC {
                ioc_type: "hostname".to_string(),
                value: "dc01.contoso.local".to_string(),
                pyramid_level: crate::models::PyramidLevel::DomainNames,
                mitre_techniques: vec![],
                required: true,
                source: "".to_string(),
            }],
            ..Default::default()
        };
        let val = r.to_value();
        assert_eq!(val["gaps"]["found_iocs_count"], 2);
        assert_eq!(val["gaps"]["missed_iocs"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn to_summary_includes_timing_when_present() {
        let r = EvaluationResult {
            duration_seconds: 120.0,
            time_to_first_evidence: Some(5.5),
            time_to_technique_identification: Some(30.0),
            time_to_ttp_elevation: Some(60.0),
            ..Default::default()
        };
        let summary = r.to_summary();
        assert!(summary.contains("Duration: 120.0s"));
        assert!(summary.contains("Time to First Evidence: 5.5s"));
        assert!(summary.contains("Time to Technique ID: 30.0s"));
        assert!(summary.contains("Time to TTP Elevation: 60.0s"));
    }

    #[test]
    fn to_summary_excludes_timing_when_absent() {
        let r = EvaluationResult::default();
        let summary = r.to_summary();
        assert!(!summary.contains("Timing:"));
        assert!(!summary.contains("Duration:"));
    }

    #[test]
    fn to_summary_includes_cost_when_tokens_present() {
        let r = EvaluationResult {
            total_tokens: 5000,
            prompt_tokens: 3000,
            completion_tokens: 2000,
            estimated_cost_usd: 0.025,
            ..Default::default()
        };
        let summary = r.to_summary();
        assert!(summary.contains("Cost:"));
        assert!(summary.contains("Tokens: 5000"));
        assert!(summary.contains("Estimated Cost: $0.0250"));
    }

    #[test]
    fn to_summary_excludes_cost_when_no_tokens() {
        let r = EvaluationResult::default();
        let summary = r.to_summary();
        assert!(!summary.contains("Cost:"));
    }

    #[test]
    fn to_summary_shows_missed_techniques() {
        let r = EvaluationResult {
            missed_techniques: vec![
                ExpectedTechnique {
                    technique_id: "T1003".to_string(),
                    technique_name: "OS Credential Dumping".to_string(),
                    required: true,
                    parent_id: None,
                },
                ExpectedTechnique {
                    technique_id: "T1558".to_string(),
                    technique_name: "Steal or Forge Kerberos Tickets".to_string(),
                    required: true,
                    parent_id: None,
                },
            ],
            ..Default::default()
        };
        let summary = r.to_summary();
        assert!(summary.contains("Missed Techniques:"));
        assert!(summary.contains("T1003: OS Credential Dumping"));
        assert!(summary.contains("T1558: Steal or Forge Kerberos Tickets"));
    }

    #[test]
    fn to_summary_truncates_missed_techniques_over_five() {
        let techniques: Vec<ExpectedTechnique> = (0..8)
            .map(|i| ExpectedTechnique {
                technique_id: format!("T100{i}"),
                technique_name: format!("Technique {i}"),
                required: true,
                parent_id: None,
            })
            .collect();
        let r = EvaluationResult {
            missed_techniques: techniques,
            ..Default::default()
        };
        let summary = r.to_summary();
        assert!(summary.contains("... and 3 more"));
    }

    #[test]
    fn to_summary_shows_error() {
        let r = EvaluationResult {
            error: Some("LLM rate limited".to_string()),
            ..Default::default()
        };
        let summary = r.to_summary();
        assert!(summary.contains("Error: LLM rate limited"));
    }

    #[test]
    fn dataset_empty_results() {
        let ds = DatasetEvaluationResult {
            dataset_name: "empty".to_string(),
            evaluated_at: Utc::now(),
            results: vec![],
        };
        assert_eq!(ds.count(), 0);
        assert_eq!(ds.pass_rate(), 0.0);
        assert_eq!(ds.avg_overall_score(), 0.0);
        assert_eq!(ds.avg_ioc_detection_rate(), 0.0);
        assert_eq!(ds.avg_technique_coverage(), 0.0);
        assert_eq!(ds.alert_fire_rate(), 0.0);
        assert_eq!(ds.investigation_completion_rate(), 0.0);
        assert_eq!(ds.total_cost_usd(), 0.0);
        assert_eq!(ds.total_tokens(), 0);
        assert_eq!(ds.avg_duration_seconds(), 0.0);
    }

    #[test]
    fn dataset_all_passing() {
        let ds = DatasetEvaluationResult {
            dataset_name: "all-pass".to_string(),
            evaluated_at: Utc::now(),
            results: vec![
                EvaluationResult {
                    overall_score: 0.9,
                    ioc_detection_rate: 0.8,
                    technique_coverage: 0.7,
                    ..Default::default()
                },
                EvaluationResult {
                    overall_score: 0.85,
                    ioc_detection_rate: 0.75,
                    technique_coverage: 0.65,
                    ..Default::default()
                },
            ],
        };
        assert!((ds.pass_rate() - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn dataset_all_failing() {
        let ds = DatasetEvaluationResult {
            dataset_name: "all-fail".to_string(),
            evaluated_at: Utc::now(),
            results: vec![
                EvaluationResult {
                    overall_score: 0.3,
                    ioc_detection_rate: 0.2,
                    technique_coverage: 0.1,
                    ..Default::default()
                },
                EvaluationResult {
                    overall_score: 0.1,
                    ioc_detection_rate: 0.1,
                    technique_coverage: 0.1,
                    ..Default::default()
                },
            ],
        };
        assert_eq!(ds.pass_rate(), 0.0);
    }

    #[test]
    fn dataset_to_value_structure() {
        let ds = DatasetEvaluationResult {
            dataset_name: "test-ds".to_string(),
            evaluated_at: Utc::now(),
            results: vec![EvaluationResult {
                overall_score: 0.8,
                estimated_cost_usd: 0.05,
                total_tokens: 10000,
                duration_seconds: 60.0,
                ..Default::default()
            }],
        };
        let val = ds.to_value();
        assert_eq!(val["dataset_name"], "test-ds");
        assert_eq!(val["summary"]["count"], 1);
        assert_eq!(val["summary"]["total_tokens"], 10000);
        assert!(val["results"].as_array().unwrap().len() == 1);
    }

    #[test]
    fn dataset_to_summary_grade_distribution() {
        let ds = DatasetEvaluationResult {
            dataset_name: "grade-dist".to_string(),
            evaluated_at: Utc::now(),
            results: vec![
                EvaluationResult {
                    overall_score: 0.95,
                    ..Default::default()
                },
                EvaluationResult {
                    overall_score: 0.85,
                    ..Default::default()
                },
                EvaluationResult {
                    overall_score: 0.75,
                    ..Default::default()
                },
                EvaluationResult {
                    overall_score: 0.65,
                    ..Default::default()
                },
                EvaluationResult {
                    overall_score: 0.40,
                    ..Default::default()
                },
            ],
        };
        let summary = ds.to_summary();
        assert!(summary.contains("Grade Distribution:"));
        assert!(summary.contains("A:"));
        assert!(summary.contains("B:"));
        assert!(summary.contains("C:"));
        assert!(summary.contains("D:"));
        assert!(summary.contains("F:"));
    }

    #[test]
    fn dataset_serde_roundtrip() {
        let ds = DatasetEvaluationResult {
            dataset_name: "roundtrip".to_string(),
            evaluated_at: Utc::now(),
            results: vec![EvaluationResult {
                evaluation_id: "e1".to_string(),
                overall_score: 0.75,
                ..Default::default()
            }],
        };
        let json = serde_json::to_string(&ds).unwrap();
        let deserialized: DatasetEvaluationResult = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.dataset_name, "roundtrip");
        assert_eq!(deserialized.results.len(), 1);
        assert!((deserialized.results[0].overall_score - 0.75).abs() < f64::EPSILON);
    }

    #[test]
    fn avg_empty() {
        assert_eq!(avg(&[], |r| r.overall_score), 0.0);
    }

    #[test]
    fn avg_single() {
        let results = vec![EvaluationResult {
            overall_score: 0.8,
            ..Default::default()
        }];
        assert!((avg(&results, |r| r.overall_score) - 0.8).abs() < f64::EPSILON);
    }

    #[test]
    fn avg_multiple() {
        let results = vec![
            EvaluationResult {
                overall_score: 0.6,
                ..Default::default()
            },
            EvaluationResult {
                overall_score: 0.8,
                ..Default::default()
            },
            EvaluationResult {
                overall_score: 1.0,
                ..Default::default()
            },
        ];
        assert!((avg(&results, |r| r.overall_score) - 0.8).abs() < f64::EPSILON);
    }

    #[test]
    fn to_summary_with_missed_techniques() {
        let r = EvaluationResult {
            missed_techniques: vec![
                ExpectedTechnique {
                    technique_id: "T1003".into(),
                    technique_name: "Credential Dumping".into(),
                    required: true,
                    parent_id: None,
                },
                ExpectedTechnique {
                    technique_id: "T1021".into(),
                    technique_name: "Remote Services".into(),
                    required: false,
                    parent_id: None,
                },
            ],
            ..Default::default()
        };
        let summary = r.to_summary();
        assert!(summary.contains("Missed Techniques:"));
        assert!(summary.contains("T1003"));
        assert!(summary.contains("Credential Dumping"));
        assert!(summary.contains("T1021"));
    }

    #[test]
    fn to_summary_truncates_over_five_missed() {
        let techniques: Vec<ExpectedTechnique> = (0..8)
            .map(|i| ExpectedTechnique {
                technique_id: format!("T100{i}"),
                technique_name: format!("Tech {i}"),
                required: true,
                parent_id: None,
            })
            .collect();
        let r = EvaluationResult {
            missed_techniques: techniques,
            ..Default::default()
        };
        let summary = r.to_summary();
        assert!(summary.contains("... and 3 more"));
    }

    #[test]
    fn to_value_scores_all_fields() {
        let r = EvaluationResult {
            overall_score: 0.75,
            detection_score: 0.8,
            quality_score: 0.7,
            completeness_score: 0.65,
            stage_score: 0.5,
            ioc_detection_rate: 0.6,
            technique_coverage: 0.55,
            pyramid_elevation_score: 0.4,
            timeline_accuracy: 0.9,
            evidence_quality_score: 0.85,
            ..Default::default()
        };
        let val = r.to_value();
        let scores = &val["scores"];
        assert_eq!(scores["overall"], 0.75);
        assert_eq!(scores["detection"], 0.8);
        assert_eq!(scores["quality"], 0.7);
        assert_eq!(scores["completeness"], 0.65);
        assert_eq!(scores["stage"], 0.5);
        assert_eq!(scores["ioc_detection_rate"], 0.6);
        assert_eq!(scores["technique_coverage"], 0.55);
        assert_eq!(scores["pyramid_elevation"], 0.4);
        assert_eq!(scores["timeline_accuracy"], 0.9);
        assert_eq!(scores["evidence_quality"], 0.85);
    }

    #[test]
    fn to_value_timing_section() {
        let r = EvaluationResult {
            duration_seconds: 99.9,
            time_to_first_evidence: Some(1.5),
            time_to_technique_identification: None,
            time_to_ttp_elevation: Some(50.0),
            ..Default::default()
        };
        let val = r.to_value();
        let timing = &val["timing"];
        assert_eq!(timing["duration_seconds"], 99.9);
        assert_eq!(timing["time_to_first_evidence"], 1.5);
        assert!(timing["time_to_technique_identification"].is_null());
        assert_eq!(timing["time_to_ttp_elevation"], 50.0);
    }

    #[test]
    fn to_value_cost_section() {
        let r = EvaluationResult {
            total_tokens: 10000,
            prompt_tokens: 7000,
            completion_tokens: 3000,
            estimated_cost_usd: 0.123,
            ..Default::default()
        };
        let val = r.to_value();
        let cost = &val["cost"];
        assert_eq!(cost["total_tokens"], 10000);
        assert_eq!(cost["prompt_tokens"], 7000);
        assert_eq!(cost["completion_tokens"], 3000);
        assert_eq!(cost["estimated_cost_usd"], 0.123);
    }

    #[test]
    fn dataset_to_summary_contains_sections() {
        let ds = DatasetEvaluationResult {
            dataset_name: "pentest-eval".to_string(),
            evaluated_at: Utc::now(),
            results: vec![
                EvaluationResult {
                    overall_score: 0.95,
                    alert_fired: true,
                    investigation_completed: true,
                    estimated_cost_usd: 0.10,
                    total_tokens: 8000,
                    duration_seconds: 60.0,
                    ..Default::default()
                },
                EvaluationResult {
                    overall_score: 0.55,
                    alert_fired: false,
                    investigation_completed: false,
                    estimated_cost_usd: 0.05,
                    total_tokens: 4000,
                    duration_seconds: 30.0,
                    ..Default::default()
                },
            ],
        };
        let summary = ds.to_summary();
        assert!(summary.contains("pentest-eval"));
        assert!(summary.contains("Scenarios: 2"));
        assert!(summary.contains("Pass Rate:"));
        assert!(summary.contains("Grade Distribution:"));
        assert!(summary.contains("Total Cost:"));
    }

    #[test]
    fn dataset_total_tokens_sums() {
        let ds = DatasetEvaluationResult {
            dataset_name: "t".into(),
            evaluated_at: Utc::now(),
            results: vec![
                EvaluationResult {
                    total_tokens: 1000,
                    ..Default::default()
                },
                EvaluationResult {
                    total_tokens: 2500,
                    ..Default::default()
                },
            ],
        };
        assert_eq!(ds.total_tokens(), 3500);
    }

    #[test]
    fn dataset_avg_duration() {
        let ds = DatasetEvaluationResult {
            dataset_name: "t".into(),
            evaluated_at: Utc::now(),
            results: vec![
                EvaluationResult {
                    duration_seconds: 10.0,
                    ..Default::default()
                },
                EvaluationResult {
                    duration_seconds: 20.0,
                    ..Default::default()
                },
            ],
        };
        assert!((ds.avg_duration_seconds() - 15.0).abs() < f64::EPSILON);
    }

    #[test]
    fn to_summary_timing_with_all_fields() {
        let r = EvaluationResult {
            duration_seconds: 45.0,
            time_to_first_evidence: Some(5.2),
            time_to_technique_identification: Some(12.3),
            time_to_ttp_elevation: Some(30.0),
            ..Default::default()
        };
        let summary = r.to_summary();
        assert!(summary.contains("45.0s"));
        assert!(summary.contains("5.2s"));
        assert!(summary.contains("12.3s"));
        assert!(summary.contains("30.0s"));
    }

    #[test]
    fn to_summary_cost_section() {
        let r = EvaluationResult {
            total_tokens: 5000,
            prompt_tokens: 3000,
            completion_tokens: 2000,
            estimated_cost_usd: 0.05,
            ..Default::default()
        };
        let summary = r.to_summary();
        assert!(summary.contains("5000"));
        assert!(summary.contains("3000"));
        assert!(summary.contains("2000"));
        assert!(summary.contains("$0.0500"));
    }

    #[test]
    fn to_value_gaps_section() {
        use crate::models::PyramidLevel;
        let r = EvaluationResult {
            missed_iocs: vec![ExpectedIOC {
                ioc_type: "ip".into(),
                value: "192.168.58.1".into(),
                required: true,
                pyramid_level: PyramidLevel::IpAddresses,
                mitre_techniques: vec![],
                source: String::new(),
            }],
            found_iocs: vec![
                ExpectedIOC {
                    ioc_type: "hash".into(),
                    value: "abc123".into(),
                    required: true,
                    pyramid_level: PyramidLevel::HashValues,
                    mitre_techniques: vec![],
                    source: String::new(),
                },
                ExpectedIOC {
                    ioc_type: "domain".into(),
                    value: "evil.com".into(),
                    required: false,
                    pyramid_level: PyramidLevel::DomainNames,
                    mitre_techniques: vec![],
                    source: String::new(),
                },
            ],
            ..Default::default()
        };
        let val = r.to_value();
        let gaps = &val["gaps"];
        assert_eq!(gaps["found_iocs_count"], 2);
        assert_eq!(gaps["missed_iocs"].as_array().unwrap().len(), 1);
        assert_eq!(gaps["missed_iocs"][0]["type"], "ip");
        assert_eq!(gaps["missed_iocs"][0]["value"], "192.168.58.1");
    }

    #[test]
    fn to_value_status_section() {
        let r = EvaluationResult {
            overall_score: 0.85,
            ioc_detection_rate: 0.7,
            technique_coverage: 0.6,
            alert_fired: true,
            investigation_started: true,
            investigation_completed: false,
            ..Default::default()
        };
        let val = r.to_value();
        let status = &val["status"];
        assert_eq!(status["passed"], true);
        assert_eq!(status["grade"], "B");
        assert_eq!(status["alert_fired"], true);
        assert_eq!(status["investigation_started"], true);
        assert_eq!(status["investigation_completed"], false);
    }
}
