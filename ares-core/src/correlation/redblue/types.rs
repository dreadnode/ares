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

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use std::collections::HashMap;

    fn make_red_activity(
        technique_id: Option<&str>,
        target_ip: Option<&str>,
        action: &str,
    ) -> RedTeamActivity {
        RedTeamActivity {
            timestamp: Utc.with_ymd_and_hms(2024, 1, 15, 10, 0, 0).unwrap(),
            technique_id: technique_id.map(String::from),
            technique_name: None,
            action: action.to_string(),
            target_ip: target_ip.map(String::from),
            target_host: None,
            credential_used: None,
            success: true,
            metadata: HashMap::new(),
        }
    }

    fn make_blue_detection(
        technique_id: Option<&str>,
        alert_name: &str,
        target_ip: Option<&str>,
    ) -> BlueTeamDetection {
        BlueTeamDetection {
            timestamp: Utc.with_ymd_and_hms(2024, 1, 15, 10, 2, 0).unwrap(),
            alert_name: alert_name.to_string(),
            technique_id: technique_id.map(String::from),
            severity: "high".to_string(),
            target_ip: target_ip.map(String::from),
            target_host: None,
            investigation_id: None,
            status: "completed".to_string(),
            evidence_count: 3,
            highest_pyramid_level: 4,
            metadata: HashMap::new(),
        }
    }

    #[test]
    fn red_activity_key_with_all_fields() {
        let activity = make_red_activity(Some("T1003"), Some("192.168.58.1"), "credential dump");
        let key = activity.key();
        assert!(key.contains("T1003"));
        assert!(key.contains("192.168.58.1"));
    }

    #[test]
    fn red_activity_key_none_fields_use_none_string() {
        let activity = make_red_activity(None, None, "scan");
        let key = activity.key();
        assert!(key.contains("none:none"));
    }

    #[test]
    fn blue_detection_key_includes_alert_name() {
        let det = make_blue_detection(
            Some("T1003"),
            "Credential Dumping Alert",
            Some("192.168.58.1"),
        );
        let key = det.key();
        assert!(key.contains("T1003"));
        assert!(key.contains("Credential Dumping Alert"));
    }

    #[test]
    fn blue_detection_key_none_technique() {
        let det = make_blue_detection(None, "Generic Alert", None);
        let key = det.key();
        assert!(key.contains("none"));
        assert!(key.contains("Generic Alert"));
    }

    #[test]
    fn match_quality_strong() {
        let m = CorrelationMatch {
            red_activity: make_red_activity(Some("T1003"), Some("192.168.58.1"), "dump"),
            blue_detection: make_blue_detection(Some("T1003"), "Alert", Some("192.168.58.1")),
            time_delta_seconds: 120.0,
            technique_match: true,
            target_match: true,
            confidence: 0.95,
        };
        assert_eq!(m.match_quality(), "STRONG");
    }

    #[test]
    fn match_quality_good() {
        let m = CorrelationMatch {
            red_activity: make_red_activity(Some("T1003"), Some("192.168.58.1"), "dump"),
            blue_detection: make_blue_detection(Some("T1003"), "Alert", Some("192.168.58.2")),
            time_delta_seconds: 400.0,
            technique_match: true,
            target_match: false,
            confidence: 0.7,
        };
        assert_eq!(m.match_quality(), "GOOD");
    }

    #[test]
    fn match_quality_weak_technique_only() {
        let m = CorrelationMatch {
            red_activity: make_red_activity(Some("T1003"), Some("192.168.58.1"), "dump"),
            blue_detection: make_blue_detection(Some("T1003"), "Alert", Some("192.168.58.2")),
            time_delta_seconds: 700.0,
            technique_match: true,
            target_match: false,
            confidence: 0.5,
        };
        assert_eq!(m.match_quality(), "WEAK");
    }

    #[test]
    fn match_quality_weak_target_within_window() {
        let m = CorrelationMatch {
            red_activity: make_red_activity(Some("T1003"), Some("192.168.58.1"), "dump"),
            blue_detection: make_blue_detection(Some("T1003"), "Alert", Some("192.168.58.1")),
            time_delta_seconds: 200.0,
            technique_match: false,
            target_match: true,
            confidence: 0.4,
        };
        assert_eq!(m.match_quality(), "WEAK");
    }

    #[test]
    fn match_quality_tenuous() {
        let m = CorrelationMatch {
            red_activity: make_red_activity(Some("T1003"), Some("192.168.58.1"), "dump"),
            blue_detection: make_blue_detection(Some("T1003"), "Alert", Some("192.168.58.2")),
            time_delta_seconds: 700.0,
            technique_match: false,
            target_match: false,
            confidence: 0.1,
        };
        assert_eq!(m.match_quality(), "TENUOUS");
    }

    #[test]
    fn match_quality_strong_boundary_just_under_300() {
        let m = CorrelationMatch {
            red_activity: make_red_activity(Some("T1003"), Some("192.168.58.1"), "dump"),
            blue_detection: make_blue_detection(Some("T1003"), "Alert", Some("192.168.58.1")),
            time_delta_seconds: 299.9,
            technique_match: true,
            target_match: true,
            confidence: 0.9,
        };
        assert_eq!(m.match_quality(), "STRONG");
    }

    #[test]
    fn match_quality_not_strong_at_300() {
        let m = CorrelationMatch {
            red_activity: make_red_activity(Some("T1003"), Some("192.168.58.1"), "dump"),
            blue_detection: make_blue_detection(Some("T1003"), "Alert", Some("192.168.58.1")),
            time_delta_seconds: 300.0,
            technique_match: true,
            target_match: true,
            confidence: 0.9,
        };
        // At exactly 300, not < 300, so falls to GOOD
        assert_eq!(m.match_quality(), "GOOD");
    }

    #[test]
    fn match_quality_negative_time_delta() {
        // Negative delta (detection before activity)
        let m = CorrelationMatch {
            red_activity: make_red_activity(Some("T1003"), Some("192.168.58.1"), "dump"),
            blue_detection: make_blue_detection(Some("T1003"), "Alert", Some("192.168.58.1")),
            time_delta_seconds: -100.0,
            technique_match: true,
            target_match: true,
            confidence: 0.9,
        };
        assert_eq!(m.match_quality(), "STRONG");
    }

    #[test]
    fn correlation_report_to_value_has_expected_keys() {
        let report = CorrelationReport {
            analysis_timestamp: Utc.with_ymd_and_hms(2024, 1, 15, 12, 0, 0).unwrap(),
            red_operation_id: "op-123".to_string(),
            time_window_start: Utc.with_ymd_and_hms(2024, 1, 15, 8, 0, 0).unwrap(),
            time_window_end: Utc.with_ymd_and_hms(2024, 1, 15, 16, 0, 0).unwrap(),
            total_red_activities: 10,
            total_blue_detections: 8,
            matched_activities: 6,
            undetected_activities: 4,
            false_positive_detections: 2,
            matches: vec![],
            gaps: vec![],
            false_positives: vec![],
            detection_rate: 0.6,
            false_positive_rate: 0.25,
            mean_time_to_detect: Some(45.5),
            technique_coverage: HashMap::new(),
        };
        let val = report.to_value();
        assert_eq!(val["red_operation_id"], "op-123");
        assert_eq!(val["summary"]["total_red_activities"], 10);
        assert_eq!(val["summary"]["matched_activities"], 6);
        assert_eq!(val["summary"]["detection_rate"], "60.0%");
        assert_eq!(val["summary"]["mean_time_to_detect"], "45.5s");
    }

    #[test]
    fn correlation_report_to_value_no_mttd() {
        let report = CorrelationReport {
            analysis_timestamp: Utc::now(),
            red_operation_id: "op-456".to_string(),
            time_window_start: Utc::now(),
            time_window_end: Utc::now(),
            total_red_activities: 0,
            total_blue_detections: 0,
            matched_activities: 0,
            undetected_activities: 0,
            false_positive_detections: 0,
            matches: vec![],
            gaps: vec![],
            false_positives: vec![],
            detection_rate: 0.0,
            false_positive_rate: 0.0,
            mean_time_to_detect: None,
            technique_coverage: HashMap::new(),
        };
        let val = report.to_value();
        assert_eq!(val["summary"]["mean_time_to_detect"], "N/A");
    }
}
