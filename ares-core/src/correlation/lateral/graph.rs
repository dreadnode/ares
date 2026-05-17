//! Lateral movement graph: host connections and traversal.

use std::collections::{HashMap, HashSet};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tracing::info;

/// A connection between two hosts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostConnection {
    pub source_host: String,
    pub destination_host: String,
    /// Connection type: "smb", "rdp", "wmi", "psexec", "ssh", "winrm", "dcom", etc.
    pub connection_type: String,
    pub timestamp: Option<DateTime<Utc>>,
    pub user: Option<String>,
    pub evidence_ids: Vec<String>,
    pub mitre_technique: Option<String>,
}

/// Parameters for [`LateralGraph::add_connection`].
#[derive(Debug, Clone)]
pub struct AddConnectionParams<'a> {
    pub source: &'a str,
    pub destination: &'a str,
    pub conn_type: &'a str,
    pub timestamp: Option<DateTime<Utc>>,
    pub user: Option<&'a str>,
    pub evidence_id: Option<&'a str>,
    pub mitre_technique: Option<&'a str>,
}

/// Graph of host connections for lateral movement analysis.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LateralGraph {
    pub connections: Vec<HostConnection>,
    pub investigated_hosts: HashSet<String>,
    pub pending_hosts: HashSet<String>,
}

impl LateralGraph {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a connection to the graph. Returns `None` for self-connections.
    pub fn add_connection(&mut self, params: AddConnectionParams<'_>) -> Option<&HostConnection> {
        let AddConnectionParams {
            source,
            destination,
            conn_type,
            timestamp,
            user,
            evidence_id,
            mitre_technique,
        } = params;
        let source = source.to_lowercase();
        let destination = destination.to_lowercase();

        if source == destination {
            return None;
        }

        let conn = HostConnection {
            source_host: source,
            destination_host: destination.clone(),
            connection_type: conn_type.to_string(),
            timestamp,
            user: user.map(|s| s.to_string()),
            evidence_ids: evidence_id.map_or_else(Vec::new, |id| vec![id.to_string()]),
            mitre_technique: mitre_technique.map(|s| s.to_string()),
        };
        self.connections.push(conn);

        // Mark destination as pending if not yet investigated
        if !self.investigated_hosts.contains(&destination) {
            self.pending_hosts.insert(destination.clone());
            info!(host = %destination, "Added pending host for lateral investigation");
        }

        self.connections.last()
    }

    /// Mark a host as investigated.
    pub fn mark_investigated(&mut self, host: &str) {
        let host = host.to_lowercase();
        self.investigated_hosts.insert(host.clone());
        self.pending_hosts.remove(&host);
        info!(host = %host, "Marked host as investigated");
    }

    /// Get hosts connected to but not yet investigated.
    pub fn get_uninvestigated_targets(&self, limit: usize) -> Vec<&str> {
        self.pending_hosts
            .iter()
            .take(limit)
            .map(|s| s.as_str())
            .collect()
    }

    /// Get all connections involving a specific host (as source or destination).
    pub fn get_host_connections(&self, host: &str) -> Vec<&HostConnection> {
        let host = host.to_lowercase();
        self.connections
            .iter()
            .filter(|c| c.source_host == host || c.destination_host == host)
            .collect()
    }

    /// Get outgoing connections from a host.
    pub fn get_outgoing_connections(&self, host: &str) -> Vec<&HostConnection> {
        let host = host.to_lowercase();
        self.connections
            .iter()
            .filter(|c| c.source_host == host)
            .collect()
    }

    /// Get incoming connections to a host.
    pub fn get_incoming_connections(&self, host: &str) -> Vec<&HostConnection> {
        let host = host.to_lowercase();
        self.connections
            .iter()
            .filter(|c| c.destination_host == host)
            .collect()
    }

    /// Get all unique users involved in lateral movement.
    pub fn get_unique_users(&self) -> HashSet<&str> {
        self.connections
            .iter()
            .filter_map(|c| c.user.as_deref())
            .collect()
    }

    /// Generate a summary for reports.
    pub fn to_summary(&self) -> serde_json::Value {
        let mut connection_types: HashMap<&str, usize> = HashMap::new();
        for c in &self.connections {
            *connection_types.entry(&c.connection_type).or_insert(0) += 1;
        }

        serde_json::json!({
            "total_connections": self.connections.len(),
            "hosts_investigated": self.investigated_hosts.len(),
            "hosts_pending": self.pending_hosts.len(),
            "connection_types": connection_types,
            "unique_users": self.get_unique_users().into_iter().collect::<Vec<_>>(),
            "investigated_hosts_list": self.investigated_hosts.iter().take(10).collect::<Vec<_>>(),
            "pending_hosts_list": self.pending_hosts.iter().take(10).collect::<Vec<_>>(),
        })
    }
}

/// Look up the MITRE technique ID for a lateral movement connection type.
///
/// Delegates to [`crate::detection::mitre_for_connection_type`] which derives
/// mappings from `detections.yaml` at runtime, so new templates are picked up
/// automatically without hardcoding here.
pub fn mitre_for_connection(conn_type: &str) -> Option<&'static str> {
    crate::detection::mitre_for_connection_type(conn_type)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_graph_is_empty() {
        let g = LateralGraph::new();
        assert!(g.connections.is_empty());
        assert!(g.investigated_hosts.is_empty());
        assert!(g.pending_hosts.is_empty());
    }

    #[test]
    fn add_connection_stores_and_returns() {
        let mut g = LateralGraph::new();
        let conn = g.add_connection(AddConnectionParams {
            source: "host-a",
            destination: "host-b",
            conn_type: "smb",
            timestamp: None,
            user: Some("admin"),
            evidence_id: Some("ev1"),
            mitre_technique: Some("T1021"),
        });
        let conn = conn.expect("add_connection should return connection");
        assert_eq!(conn.source_host, "host-a");
        assert_eq!(conn.destination_host, "host-b");
        assert_eq!(conn.connection_type, "smb");
        assert_eq!(conn.user.as_deref(), Some("admin"));
        assert_eq!(conn.evidence_ids, vec!["ev1"]);
        assert_eq!(conn.mitre_technique.as_deref(), Some("T1021"));
        assert_eq!(g.connections.len(), 1);
    }

    fn basic<'a>(
        source: &'a str,
        destination: &'a str,
        conn_type: &'a str,
    ) -> AddConnectionParams<'a> {
        AddConnectionParams {
            source,
            destination,
            conn_type,
            timestamp: None,
            user: None,
            evidence_id: None,
            mitre_technique: None,
        }
    }

    #[test]
    fn add_connection_lowercases_hosts() {
        let mut g = LateralGraph::new();
        g.add_connection(basic("HOST-A", "HOST-B", "rdp"));
        assert_eq!(g.connections[0].source_host, "host-a");
        assert_eq!(g.connections[0].destination_host, "host-b");
    }

    #[test]
    fn add_connection_self_loop_returns_none() {
        let mut g = LateralGraph::new();
        let result = g.add_connection(basic("host-a", "HOST-A", "smb"));
        assert!(result.is_none());
        assert!(g.connections.is_empty());
    }

    #[test]
    fn add_connection_marks_destination_pending() {
        let mut g = LateralGraph::new();
        g.add_connection(basic("host-a", "host-b", "smb"));
        assert!(g.pending_hosts.contains("host-b"));
    }

    #[test]
    fn add_connection_skips_pending_if_investigated() {
        let mut g = LateralGraph::new();
        g.mark_investigated("host-b");
        g.add_connection(basic("host-a", "host-b", "smb"));
        assert!(!g.pending_hosts.contains("host-b"));
    }

    #[test]
    fn mark_investigated_removes_from_pending() {
        let mut g = LateralGraph::new();
        g.add_connection(basic("host-a", "host-b", "smb"));
        assert!(g.pending_hosts.contains("host-b"));
        g.mark_investigated("host-b");
        assert!(!g.pending_hosts.contains("host-b"));
        assert!(g.investigated_hosts.contains("host-b"));
    }

    #[test]
    fn get_uninvestigated_targets_respects_limit() {
        let mut g = LateralGraph::new();
        g.add_connection(basic("a", "b", "smb"));
        g.add_connection(basic("a", "c", "smb"));
        g.add_connection(basic("a", "d", "smb"));
        let targets = g.get_uninvestigated_targets(2);
        assert_eq!(targets.len(), 2);
    }

    #[test]
    fn get_host_connections_both_directions() {
        let mut g = LateralGraph::new();
        g.add_connection(basic("a", "b", "smb"));
        g.add_connection(basic("c", "b", "rdp"));
        let conns = g.get_host_connections("b");
        assert_eq!(conns.len(), 2);
    }

    #[test]
    fn get_outgoing_connections_filters() {
        let mut g = LateralGraph::new();
        g.add_connection(basic("a", "b", "smb"));
        g.add_connection(basic("b", "c", "rdp"));
        let out = g.get_outgoing_connections("a");
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].destination_host, "b");
    }

    #[test]
    fn get_incoming_connections_filters() {
        let mut g = LateralGraph::new();
        g.add_connection(basic("a", "b", "smb"));
        g.add_connection(basic("c", "b", "rdp"));
        let inc = g.get_incoming_connections("b");
        assert_eq!(inc.len(), 2);
    }

    #[test]
    fn get_unique_users_collects_all() {
        let mut g = LateralGraph::new();
        g.add_connection(AddConnectionParams {
            user: Some("admin"),
            ..basic("a", "b", "smb")
        });
        g.add_connection(AddConnectionParams {
            user: Some("svc_sql"),
            ..basic("b", "c", "rdp")
        });
        g.add_connection(basic("c", "d", "wmi"));
        let users = g.get_unique_users();
        assert_eq!(users.len(), 2);
        assert!(users.contains("admin"));
        assert!(users.contains("svc_sql"));
    }

    #[test]
    fn to_summary_has_expected_fields() {
        let mut g = LateralGraph::new();
        g.add_connection(AddConnectionParams {
            user: Some("admin"),
            ..basic("a", "b", "smb")
        });
        g.mark_investigated("a");
        let summary = g.to_summary();
        assert_eq!(summary["total_connections"], 1);
        assert_eq!(summary["hosts_investigated"], 1);
        assert_eq!(summary["hosts_pending"], 1);
    }

    #[test]
    fn add_connection_no_evidence_id() {
        let mut g = LateralGraph::new();
        let conn = g.add_connection(basic("a", "b", "smb"));
        assert!(conn
            .expect("add_connection should return connection")
            .evidence_ids
            .is_empty());
    }
}
