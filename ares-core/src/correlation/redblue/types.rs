//! Data types for red-blue correlation.

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// A single red team activity/action.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedTeamActivity {
    pub timestamp: DateTime<Utc>,
    pub technique_id: Option<String>,
    pub technique_name: Option<String>,
    pub action: String,
    pub target_ip: Option<String>,
    pub target_host: Option<String>,
    pub credential_used: Option<String>,
    pub success: bool,
    #[serde(default)]
    pub metadata: HashMap<String, String>,
}

impl RedTeamActivity {
    /// Unique correlation key for this activity.
    pub fn key(&self) -> String {
        format!(
            "{}:{}:{}",
            self.timestamp.to_rfc3339(),
            self.technique_id.as_deref().unwrap_or("none"),
            self.target_ip.as_deref().unwrap_or("none"),
        )
    }
}

/// A blue team detection/alert.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlueTeamDetection {
    pub timestamp: DateTime<Utc>,
    pub alert_name: String,
    pub technique_id: Option<String>,
    pub severity: String,
    pub target_ip: Option<String>,
    pub target_host: Option<String>,
    pub investigation_id: Option<String>,
    /// completed, escalated, timeout
    pub status: String,
    pub evidence_count: u32,
    pub highest_pyramid_level: u32,
    #[serde(default)]
    pub metadata: HashMap<String, String>,
}

impl BlueTeamDetection {
    /// Unique correlation key for this detection.
    pub fn key(&self) -> String {
        format!(
            "{}:{}:{}",
            self.timestamp.to_rfc3339(),
            self.technique_id.as_deref().unwrap_or("none"),
            self.alert_name,
        )
    }
}

/// A match between red team activity and blue team detection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelationMatch {
    pub red_activity: RedTeamActivity,
    pub blue_detection: BlueTeamDetection,
    pub time_delta_seconds: f64,
    pub technique_match: bool,
    pub target_match: bool,
    pub confidence: f64,
}

impl CorrelationMatch {
    /// Assess the quality of this match.
    pub fn match_quality(&self) -> &'static str {
        let abs_delta = self.time_delta_seconds.abs();
        if self.technique_match && self.target_match && abs_delta < 300.0 {
            "STRONG"
        } else if self.technique_match && abs_delta < 600.0 {
            "GOOD"
        } else if self.technique_match || (self.target_match && abs_delta < 300.0) {
            "WEAK"
        } else {
            "TENUOUS"
        }
    }
}

/// An undetected red team activity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionGap {
    pub red_activity: RedTeamActivity,
    pub reason: String,
    pub recommended_detection: Option<String>,
    #[serde(default)]
    pub mitre_data_sources: Vec<String>,
}

/// Full correlation analysis report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelationReport {
    pub analysis_timestamp: DateTime<Utc>,
    pub red_operation_id: String,
    pub time_window_start: DateTime<Utc>,
    pub time_window_end: DateTime<Utc>,

    // Counts
    pub total_red_activities: usize,
    pub total_blue_detections: usize,
    pub matched_activities: usize,
    pub undetected_activities: usize,
    pub false_positive_detections: usize,

    // Details
    pub matches: Vec<CorrelationMatch>,
    pub gaps: Vec<DetectionGap>,
    pub false_positives: Vec<BlueTeamDetection>,

    // Metrics
    pub detection_rate: f64,
    pub false_positive_rate: f64,
    /// Mean time to detect in seconds, if any detections occurred.
    pub mean_time_to_detect: Option<f64>,

    // By technique
    pub technique_coverage: HashMap<String, TechniqueCoverage>,
}

/// Coverage stats for a single technique.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TechniqueCoverage {
    pub total: usize,
    pub detected: usize,
    pub missed: usize,
    pub detection_rate: f64,
}

impl CorrelationReport {
    /// Convert to a JSON-serializable value.
    pub fn to_value(&self) -> Value {
        serde_json::json!({
            "analysis_timestamp": self.analysis_timestamp.to_rfc3339(),
            "red_operation_id": self.red_operation_id,
            "time_window": {
                "start": self.time_window_start.to_rfc3339(),
                "end": self.time_window_end.to_rfc3339(),
            },
            "summary": {
                "total_red_activities": self.total_red_activities,
                "total_blue_detections": self.total_blue_detections,
                "matched_activities": self.matched_activities,
                "undetected_activities": self.undetected_activities,
                "false_positive_detections": self.false_positive_detections,
                "detection_rate": format!("{:.1}%", self.detection_rate * 100.0),
                "false_positive_rate": format!("{:.1}%", self.false_positive_rate * 100.0),
                "mean_time_to_detect": self.mean_time_to_detect
                    .map(|t| format!("{t:.1}s"))
                    .unwrap_or_else(|| "N/A".to_string()),
            },
            "technique_coverage": self.technique_coverage,
            "matches": self.matches.iter().map(|m| serde_json::json!({
                "red_technique": m.red_activity.technique_id,
                "red_action": &m.red_activity.action[..m.red_activity.action.len().min(100)],
                "blue_alert": m.blue_detection.alert_name,
                "time_delta_seconds": m.time_delta_seconds,
                "match_quality": m.match_quality(),
                "confidence": m.confidence,
            })).collect::<Vec<_>>(),
            "gaps": self.gaps.iter().map(|g| serde_json::json!({
                "technique": g.red_activity.technique_id,
                "action": &g.red_activity.action[..g.red_activity.action.len().min(100)],
                "timestamp": g.red_activity.timestamp.to_rfc3339(),
                "reason": g.reason,
                "recommended_detection": g.recommended_detection,
            })).collect::<Vec<_>>(),
            "false_positives": self.false_positives.iter().map(|fp| serde_json::json!({
                "alert_name": fp.alert_name,
                "technique": fp.technique_id,
                "timestamp": fp.timestamp.to_rfc3339(),
            })).collect::<Vec<_>>(),
        })
    }
}
