//! Alert clustering: groups related alerts by shared IOCs.

use std::collections::{HashMap, HashSet};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// A cluster of related alerts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertCluster {
    pub cluster_id: String,
    pub alerts: Vec<Value>,
    pub common_hosts: HashSet<String>,
    pub common_users: HashSet<String>,
    pub common_ips: HashSet<String>,
    pub techniques: HashSet<String>,
    pub time_range: Option<(DateTime<Utc>, DateTime<Utc>)>,
    pub operation_id: Option<String>,
}

impl AlertCluster {
    /// Create a new empty cluster.
    pub fn new(cluster_id: String) -> Self {
        Self {
            cluster_id,
            alerts: Vec::new(),
            common_hosts: HashSet::new(),
            common_users: HashSet::new(),
            common_ips: HashSet::new(),
            techniques: HashSet::new(),
            time_range: None,
            operation_id: None,
        }
    }

    /// Add an alert to the cluster, extracting shared IOCs.
    pub fn add_alert(&mut self, alert: &Value) {
        self.alerts.push(alert.clone());

        let labels = alert.get("labels").and_then(|v| v.as_object());
        let annotations = alert.get("annotations").and_then(|v| v.as_object());

        // Extract hosts
        if let Some(labels) = labels {
            for key in &["hostname", "host", "computer"] {
                if let Some(val) = labels.get(*key).and_then(|v| v.as_str()) {
                    self.common_hosts.insert(val.to_lowercase());
                }
            }
            // Instance often contains host:port
            if let Some(instance) = labels.get("instance").and_then(|v| v.as_str()) {
                let host = instance.split(':').next().unwrap_or("");
                if !host.is_empty() && !host.starts_with(|c: char| c.is_ascii_digit()) {
                    self.common_hosts.insert(host.to_lowercase());
                }
            }

            // Extract users
            for key in &[
                "user",
                "username",
                "account",
                "TargetUserName",
                "SubjectUserName",
            ] {
                if let Some(val) = labels.get(*key).and_then(|v| v.as_str()) {
                    self.common_users.insert(val.to_lowercase());
                }
            }

            // Extract IPs
            for key in &["ip", "source_ip", "src_ip", "IpAddress", "ClientAddress"] {
                if let Some(val) = labels.get(*key).and_then(|v| v.as_str()) {
                    self.common_ips.insert(val.to_string());
                }
            }

            // Extract techniques
            for key in &["mitre_technique", "technique", "technique_id"] {
                if let Some(val) = labels.get(*key) {
                    match val {
                        Value::Array(arr) => {
                            for item in arr {
                                if let Some(s) = item.as_str() {
                                    self.techniques.insert(s.to_string());
                                }
                            }
                        }
                        Value::String(s) => {
                            self.techniques.insert(s.clone());
                        }
                        _ => {}
                    }
                }
            }
        }

        // Also extract users from annotations
        if let Some(annotations) = annotations {
            for key in &[
                "user",
                "username",
                "account",
                "TargetUserName",
                "SubjectUserName",
            ] {
                if let Some(val) = annotations.get(*key).and_then(|v| v.as_str()) {
                    self.common_users.insert(val.to_lowercase());
                }
            }
        }

        // Update time range
        if let Some(starts_at) = alert.get("startsAt").and_then(|v| v.as_str()) {
            if let Ok(ts) = DateTime::parse_from_rfc3339(starts_at) {
                let ts = ts.with_timezone(&Utc);
                self.time_range = Some(match self.time_range {
                    None => (ts, ts),
                    Some((start, end)) => (start.min(ts), end.max(ts)),
                });
            }
        }

        // Extract operation_id from operation_context
        if let Some(op_id) = alert
            .get("operation_context")
            .and_then(|v| v.get("operation_id"))
            .and_then(|v| v.as_str())
        {
            self.operation_id = Some(op_id.to_string());
        }
    }

    /// Calculate similarity score between this cluster and an alert (0.0–1.0).
    pub fn similarity_score(&self, alert: &Value) -> f64 {
        let mut score: f64 = 0.0;

        // Operation ID match: small bonus, NOT enough to auto-cluster
        if let Some(alert_op_id) = alert
            .get("operation_context")
            .and_then(|v| v.get("operation_id"))
            .and_then(|v| v.as_str())
        {
            if let Some(ref cluster_op_id) = self.operation_id {
                if alert_op_id == cluster_op_id {
                    score += 0.1;
                }
            }
        }

        let labels = alert.get("labels").and_then(|v| v.as_object());

        if let Some(labels) = labels {
            // Host match: high weight
            let mut host_matched = false;
            for key in &["hostname", "host", "computer"] {
                if let Some(val) = labels.get(*key).and_then(|v| v.as_str()) {
                    if self.common_hosts.contains(&val.to_lowercase()) {
                        score += 0.4;
                        host_matched = true;
                        break;
                    }
                }
            }
            // Instance host check
            if !host_matched {
                if let Some(instance) = labels.get("instance").and_then(|v| v.as_str()) {
                    let host = instance.split(':').next().unwrap_or("").to_lowercase();
                    if self.common_hosts.contains(&host) {
                        score += 0.3;
                    }
                }
            }

            // User match: high weight
            for key in &["user", "username", "account"] {
                if let Some(val) = labels.get(*key).and_then(|v| v.as_str()) {
                    if self.common_users.contains(&val.to_lowercase()) {
                        score += 0.3;
                        break;
                    }
                }
            }

            // IP match: medium weight
            for key in &["ip", "source_ip", "src_ip", "IpAddress"] {
                if let Some(val) = labels.get(*key).and_then(|v| v.as_str()) {
                    if self.common_ips.contains(val) {
                        score += 0.2;
                        break;
                    }
                }
            }

            // Technique match: medium weight
            for key in &["mitre_technique", "technique"] {
                if let Some(val) = labels.get(*key) {
                    let matched = match val {
                        Value::Array(arr) => arr
                            .iter()
                            .filter_map(|v| v.as_str())
                            .any(|t| self.techniques.contains(t)),
                        Value::String(s) => self.techniques.contains(s.as_str()),
                        _ => false,
                    };
                    if matched {
                        score += 0.2;
                        break;
                    }
                }
            }
        }

        // Time proximity: bonus for recent alerts
        if let Some(starts_at) = alert.get("startsAt").and_then(|v| v.as_str()) {
            if let (Ok(ts), Some((start, end))) =
                (DateTime::parse_from_rfc3339(starts_at), self.time_range)
            {
                let ts = ts.with_timezone(&Utc);
                let window_start = start - chrono::Duration::hours(1);
                let window_end = end + chrono::Duration::hours(1);
                if ts >= window_start && ts <= window_end {
                    score += 0.1;
                }
            }
        }

        score.min(1.0)
    }

    /// Generate a summary for this cluster.
    pub fn to_summary(&self) -> HashMap<String, Value> {
        let mut summary = HashMap::new();
        summary.insert(
            "cluster_id".to_string(),
            Value::String(self.cluster_id.clone()),
        );
        summary.insert(
            "alert_count".to_string(),
            Value::Number(self.alerts.len().into()),
        );
        summary.insert(
            "operation_id".to_string(),
            self.operation_id
                .as_ref()
                .map_or(Value::Null, |id| Value::String(id.clone())),
        );
        summary.insert(
            "common_hosts".to_string(),
            Value::Array(
                self.common_hosts
                    .iter()
                    .take(10)
                    .map(|h| Value::String(h.clone()))
                    .collect(),
            ),
        );
        summary.insert(
            "common_users".to_string(),
            Value::Array(
                self.common_users
                    .iter()
                    .take(10)
                    .map(|u| Value::String(u.clone()))
                    .collect(),
            ),
        );
        summary.insert(
            "common_ips".to_string(),
            Value::Array(
                self.common_ips
                    .iter()
                    .take(10)
                    .map(|ip| Value::String(ip.clone()))
                    .collect(),
            ),
        );
        summary.insert(
            "techniques".to_string(),
            Value::Array(
                self.techniques
                    .iter()
                    .map(|t| Value::String(t.clone()))
                    .collect(),
            ),
        );

        let time_range = match self.time_range {
            Some((start, end)) => serde_json::json!({
                "start": start.to_rfc3339(),
                "end": end.to_rfc3339(),
            }),
            None => serde_json::json!({ "start": null, "end": null }),
        };
        summary.insert("time_range".to_string(), time_range);

        summary
    }
}
