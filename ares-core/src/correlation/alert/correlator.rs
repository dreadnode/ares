//! Alert correlator: assigns alerts to clusters.

use std::collections::HashMap;

use serde_json::Value;
use tracing::info;

use super::cluster::AlertCluster;

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
