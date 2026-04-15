//! Lateral movement graph: host connections and traversal.

use std::collections::{HashMap, HashSet};
use std::sync::LazyLock;

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
    #[allow(clippy::too_many_arguments)]
    pub fn add_connection(
        &mut self,
        source: &str,
        destination: &str,
        conn_type: &str,
        timestamp: Option<DateTime<Utc>>,
        user: Option<&str>,
        evidence_id: Option<&str>,
        mitre_technique: Option<&str>,
    ) -> Option<&HostConnection> {
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

/// MITRE technique mappings for lateral movement connection types.
pub static TECHNIQUE_MAPPINGS: LazyLock<HashMap<&'static str, &'static str>> =
    LazyLock::new(|| {
        HashMap::from([
            ("smb", "T1021.002"),
            ("rdp", "T1021.001"),
            ("wmi", "T1047"),
            ("psexec", "T1569.002"),
            ("winrm", "T1021.006"),
            ("ssh", "T1021.004"),
            ("dcom", "T1021.003"),
            ("scheduled_task", "T1053.005"),
        ])
    });
