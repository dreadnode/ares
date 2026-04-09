//! Alert correlation engine for grouping related alerts.
//!
//! Provides:
//! 1. Alert clustering based on shared characteristics (hosts, users, IPs, techniques)
//! 2. Similarity scoring between alerts
//! 3. Correlation context for investigations

use std::collections::{HashMap, HashSet};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tracing::info;

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

/// Correlates alerts into clusters for unified investigation.
///
/// Groups related alerts based on shared hosts, users, IPs, techniques,
/// and time proximity.
pub struct AlertCorrelator {
    /// Minimum similarity to join a cluster.
    pub cluster_threshold: f64,
    clusters: Vec<AlertCluster>,
    cluster_counter: usize,
    alert_to_cluster: HashMap<String, String>,
}

impl Default for AlertCorrelator {
    fn default() -> Self {
        Self::new()
    }
}

impl AlertCorrelator {
    /// Default minimum similarity score to join a cluster.
    pub const DEFAULT_THRESHOLD: f64 = 0.3;

    pub fn new() -> Self {
        Self {
            cluster_threshold: Self::DEFAULT_THRESHOLD,
            clusters: Vec::new(),
            cluster_counter: 0,
            alert_to_cluster: HashMap::new(),
        }
    }

    /// Create a correlator with a custom similarity threshold.
    pub fn with_threshold(threshold: f64) -> Self {
        Self {
            cluster_threshold: threshold,
            ..Self::new()
        }
    }

    /// Add an alert, either to the best matching cluster or a new one.
    ///
    /// Returns a reference to the cluster the alert was added to.
    pub fn add_alert(&mut self, alert: &Value) -> &AlertCluster {
        let mut best_idx = None;
        let mut best_score = 0.0_f64;

        for (i, cluster) in self.clusters.iter().enumerate() {
            let score = cluster.similarity_score(alert);
            if score > best_score {
                best_score = score;
                best_idx = Some(i);
            }
        }

        let fingerprint = alert
            .get("fingerprint")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();

        if let Some(idx) = best_idx {
            if best_score >= self.cluster_threshold {
                self.clusters[idx].add_alert(alert);
                let cluster_id = self.clusters[idx].cluster_id.clone();
                self.alert_to_cluster
                    .insert(fingerprint.clone(), cluster_id.clone());
                info!(
                    fingerprint = %&fingerprint[..fingerprint.len().min(8)],
                    cluster_id = %cluster_id,
                    similarity = %format!("{best_score:.2}"),
                    "Alert added to existing cluster"
                );
                return &self.clusters[idx];
            }
        }

        // Create new cluster
        self.cluster_counter += 1;
        let cluster_id = format!("cluster-{:04}", self.cluster_counter);
        let mut new_cluster = AlertCluster::new(cluster_id.clone());
        new_cluster.add_alert(alert);
        self.clusters.push(new_cluster);
        self.alert_to_cluster
            .insert(fingerprint.clone(), cluster_id.clone());
        info!(
            cluster_id = %cluster_id,
            fingerprint = %&fingerprint[..fingerprint.len().min(8)],
            "Created new cluster for alert"
        );
        self.clusters.last().unwrap()
    }

    /// Get correlation context for an alert.
    pub fn get_cluster_context(&self, alert: &Value) -> Value {
        let fingerprint = alert
            .get("fingerprint")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");

        let Some(cluster_id) = self.alert_to_cluster.get(fingerprint) else {
            return serde_json::json!({
                "cluster_id": null,
                "message": "Alert not in any cluster"
            });
        };

        let Some(cluster) = self.clusters.iter().find(|c| &c.cluster_id == cluster_id) else {
            return serde_json::json!({
                "cluster_id": cluster_id,
                "message": "Cluster not found"
            });
        };

        let time_range = match cluster.time_range {
            Some((start, end)) => serde_json::json!({
                "start": start.to_rfc3339(),
                "end": end.to_rfc3339(),
            }),
            None => serde_json::json!({ "start": null, "end": null }),
        };

        serde_json::json!({
            "cluster_id": cluster_id,
            "related_alerts": cluster.alerts.len() - 1,
            "common_hosts": cluster.common_hosts.iter().take(10).collect::<Vec<_>>(),
            "common_users": cluster.common_users.iter().take(10).collect::<Vec<_>>(),
            "common_ips": cluster.common_ips.iter().take(10).collect::<Vec<_>>(),
            "techniques_in_cluster": cluster.techniques.iter().collect::<Vec<_>>(),
            "time_range": time_range,
        })
    }

    /// Get the cluster for a specific alert.
    pub fn get_cluster_for_alert(&self, alert: &Value) -> Option<&AlertCluster> {
        let fingerprint = alert
            .get("fingerprint")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        let cluster_id = self.alert_to_cluster.get(fingerprint)?;
        self.clusters.iter().find(|c| &c.cluster_id == cluster_id)
    }

    /// Get summary of all clusters.
    pub fn get_all_clusters_summary(&self) -> Vec<HashMap<String, Value>> {
        self.clusters.iter().map(|c| c.to_summary()).collect()
    }

    /// Get alerts related to a given alert (same cluster, excluding itself).
    pub fn get_related_alerts(&self, alert: &Value) -> Vec<&Value> {
        let fingerprint = alert
            .get("fingerprint")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");

        let Some(cluster) = self.get_cluster_for_alert(alert) else {
            return Vec::new();
        };

        cluster
            .alerts
            .iter()
            .filter(|a| a.get("fingerprint").and_then(|v| v.as_str()).unwrap_or("") != fingerprint)
            .collect()
    }

    /// Get all clusters.
    pub fn clusters(&self) -> &[AlertCluster] {
        &self.clusters
    }

    /// Reset the correlator state.
    pub fn reset(&mut self) {
        self.clusters.clear();
        self.cluster_counter = 0;
        self.alert_to_cluster.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn make_alert(fingerprint: &str, host: &str, user: &str, technique: &str) -> Value {
        json!({
            "fingerprint": fingerprint,
            "labels": {
                "hostname": host,
                "username": user,
                "mitre_technique": technique,
            },
            "startsAt": "2026-04-08T12:00:00Z",
        })
    }

    #[test]
    fn test_cluster_add_alert_extracts_iocs() {
        let mut cluster = AlertCluster::new("test-001".to_string());
        let alert = json!({
            "fingerprint": "abc123",
            "labels": {
                "hostname": "DC01",
                "username": "admin",
                "source_ip": "192.168.58.10",
                "mitre_technique": "T1003",
            },
            "annotations": {
                "TargetUserName": "krbtgt",
            },
            "startsAt": "2026-04-08T12:00:00Z",
        });

        cluster.add_alert(&alert);

        assert_eq!(cluster.alerts.len(), 1);
        assert!(cluster.common_hosts.contains("dc01"));
        assert!(cluster.common_users.contains("admin"));
        assert!(cluster.common_users.contains("krbtgt"));
        assert!(cluster.common_ips.contains("192.168.58.10"));
        assert!(cluster.techniques.contains("T1003"));
        assert!(cluster.time_range.is_some());
    }

    #[test]
    fn test_cluster_similarity_host_match() {
        let mut cluster = AlertCluster::new("test-001".to_string());
        cluster.add_alert(&make_alert("a1", "dc01", "admin", "T1003"));

        // Same host → high similarity
        let similar = make_alert("a2", "dc01", "other_user", "T1110");
        assert!(cluster.similarity_score(&similar) >= 0.4);

        // Different host → lower similarity
        let different = make_alert("a3", "web01", "other_user", "T1110");
        assert!(cluster.similarity_score(&different) < 0.3);
    }

    #[test]
    fn test_cluster_similarity_user_match() {
        let mut cluster = AlertCluster::new("test-001".to_string());
        cluster.add_alert(&make_alert("a1", "dc01", "admin", "T1003"));

        let same_user = make_alert("a2", "web01", "admin", "T1110");
        let score = cluster.similarity_score(&same_user);
        assert!(score >= 0.3, "User match should score >= 0.3, got {score}");
    }

    #[test]
    fn test_cluster_similarity_technique_match() {
        let mut cluster = AlertCluster::new("test-001".to_string());
        cluster.add_alert(&make_alert("a1", "dc01", "admin", "T1003"));

        let same_tech = make_alert("a2", "web01", "other", "T1003");
        let score = cluster.similarity_score(&same_tech);
        assert!(
            score >= 0.2,
            "Technique match should score >= 0.2, got {score}"
        );
    }

    #[test]
    fn test_cluster_similarity_operation_id() {
        let mut cluster = AlertCluster::new("test-001".to_string());
        let alert1 = json!({
            "fingerprint": "a1",
            "labels": { "hostname": "dc01" },
            "operation_context": { "operation_id": "op-1234" },
            "startsAt": "2026-04-08T12:00:00Z",
        });
        cluster.add_alert(&alert1);

        let alert2 = json!({
            "fingerprint": "a2",
            "labels": { "hostname": "web01" },
            "operation_context": { "operation_id": "op-1234" },
            "startsAt": "2026-04-08T12:30:00Z",
        });

        // Same operation_id gives small bonus, NOT enough to auto-cluster
        let score = cluster.similarity_score(&alert2);
        assert!(
            score < AlertCorrelator::DEFAULT_THRESHOLD,
            "Operation ID alone should not auto-cluster, got {score}"
        );
    }

    #[test]
    fn test_correlator_creates_new_cluster() {
        let mut correlator = AlertCorrelator::new();
        let alert = make_alert("a1", "dc01", "admin", "T1003");
        correlator.add_alert(&alert);

        assert_eq!(correlator.clusters().len(), 1);
        assert_eq!(correlator.clusters()[0].cluster_id, "cluster-0001");
    }

    #[test]
    fn test_correlator_groups_similar_alerts() {
        let mut correlator = AlertCorrelator::new();

        // Two alerts sharing the same host should cluster
        let a1 = make_alert("a1", "dc01", "admin", "T1003");
        let a2 = make_alert("a2", "dc01", "admin", "T1003.006");
        correlator.add_alert(&a1);
        correlator.add_alert(&a2);

        assert_eq!(
            correlator.clusters().len(),
            1,
            "Similar alerts should join the same cluster"
        );
        assert_eq!(correlator.clusters()[0].alerts.len(), 2);
    }

    #[test]
    fn test_correlator_separates_dissimilar_alerts() {
        let mut correlator = AlertCorrelator::new();

        let a1 = make_alert("a1", "dc01", "admin", "T1003");
        let a2 = make_alert("a2", "web99", "nobody", "T1595");
        correlator.add_alert(&a1);
        correlator.add_alert(&a2);

        assert_eq!(
            correlator.clusters().len(),
            2,
            "Dissimilar alerts should create separate clusters"
        );
    }

    #[test]
    fn test_correlator_get_related_alerts() {
        let mut correlator = AlertCorrelator::new();

        let a1 = make_alert("a1", "dc01", "admin", "T1003");
        let a2 = make_alert("a2", "dc01", "admin", "T1003.006");
        correlator.add_alert(&a1);
        correlator.add_alert(&a2);

        let related = correlator.get_related_alerts(&a1);
        assert_eq!(related.len(), 1);
        assert_eq!(related[0]["fingerprint"], "a2");
    }

    #[test]
    fn test_correlator_cluster_context() {
        let mut correlator = AlertCorrelator::new();

        let alert = make_alert("a1", "dc01", "admin", "T1003");
        correlator.add_alert(&alert);

        let ctx = correlator.get_cluster_context(&alert);
        assert_eq!(ctx["cluster_id"], "cluster-0001");
        assert_eq!(ctx["related_alerts"], 0);
    }

    #[test]
    fn test_correlator_reset() {
        let mut correlator = AlertCorrelator::new();
        correlator.add_alert(&make_alert("a1", "dc01", "admin", "T1003"));
        assert_eq!(correlator.clusters().len(), 1);

        correlator.reset();
        assert_eq!(correlator.clusters().len(), 0);
    }

    #[test]
    fn test_cluster_summary() {
        let mut cluster = AlertCluster::new("test-001".to_string());
        cluster.add_alert(&make_alert("a1", "dc01", "admin", "T1003"));

        let summary = cluster.to_summary();
        assert_eq!(summary["cluster_id"], Value::String("test-001".to_string()));
        assert_eq!(summary["alert_count"], Value::Number(1.into()));
    }

    #[test]
    fn test_cluster_technique_array_labels() {
        let mut cluster = AlertCluster::new("test-001".to_string());
        let alert = json!({
            "fingerprint": "a1",
            "labels": {
                "mitre_technique": ["T1003", "T1078"],
            },
            "startsAt": "2026-04-08T12:00:00Z",
        });
        cluster.add_alert(&alert);

        assert!(cluster.techniques.contains("T1003"));
        assert!(cluster.techniques.contains("T1078"));
    }
}
