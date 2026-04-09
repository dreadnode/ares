//! Lateral movement analysis for investigation scope expansion.
//!
//! Provides:
//! 1. Graph representation of host-to-host connections
//! 2. Detection of lateral movement patterns
//! 3. Pivot suggestions for investigation scope expansion
//! 4. Attack path reconstruction

use std::collections::{HashMap, HashSet};

use chrono::{DateTime, Utc};
use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;
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
    pub fn to_summary(&self) -> Value {
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
static TECHNIQUE_MAPPINGS: Lazy<HashMap<&'static str, &'static str>> = Lazy::new(|| {
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

/// Regex patterns for detecting lateral movement types.
struct LateralPatterns {
    patterns: Vec<(&'static str, Vec<Regex>)>,
}

impl LateralPatterns {
    fn new() -> Self {
        let patterns = vec![
            (
                "smb",
                vec![
                    Regex::new(r"(?i)smb|445|admin\$|c\$|ipc\$").unwrap(),
                    Regex::new(r"(?i)tree.*connect|share.*access").unwrap(),
                    Regex::new(r"(?i)5140|5145").unwrap(),
                ],
            ),
            (
                "rdp",
                vec![
                    Regex::new(r"(?i)rdp|3389|remote.*desktop").unwrap(),
                    Regex::new(r"(?i)4624.*logon.*type.*10").unwrap(),
                    Regex::new(r"(?i)termsrv|mstsc").unwrap(),
                ],
            ),
            (
                "wmi",
                vec![
                    Regex::new(r"(?i)wmi|135|win32_process|root\\cimv2").unwrap(),
                    Regex::new(r"(?i)wmic|wmiprvse").unwrap(),
                ],
            ),
            (
                "psexec",
                vec![
                    Regex::new(r"(?i)psexec|7045|service.*install").unwrap(),
                    Regex::new(r"(?i)psexesvc|remcom").unwrap(),
                ],
            ),
            (
                "winrm",
                vec![
                    Regex::new(r"(?i)winrm|5985|5986|powershell.*session").unwrap(),
                    Regex::new(r"(?i)wsman|enter-pssession").unwrap(),
                ],
            ),
            (
                "ssh",
                vec![Regex::new(r"(?i)ssh|22/tcp|publickey|openssh").unwrap()],
            ),
            (
                "dcom",
                vec![
                    Regex::new(r"(?i)dcom|135/tcp|mmc20|shellwindows").unwrap(),
                    Regex::new(r"(?i)dcomexec|ole32").unwrap(),
                ],
            ),
            (
                "scheduled_task",
                vec![
                    Regex::new(r"(?i)4698|schtasks|taskscheduler").unwrap(),
                    Regex::new(r"(?i)at.*exec|scheduled.*task").unwrap(),
                ],
            ),
        ];
        Self { patterns }
    }

    fn detect(&self, text: &str) -> &'static str {
        for (conn_type, regexes) in &self.patterns {
            for re in regexes {
                if re.is_match(text) {
                    return conn_type;
                }
            }
        }
        "unknown"
    }
}

static HOSTNAME_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\b([a-zA-Z][a-zA-Z0-9-]*\.[a-zA-Z0-9.-]+)\b").unwrap());

static IP_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$").unwrap());

/// Analyzes query results for lateral movement patterns.
///
/// Automatically detects lateral movement indicators and builds a graph
/// of host connections.
pub struct LateralMovementAnalyzer {
    pub graph: LateralGraph,
    patterns: LateralPatterns,
}

impl Default for LateralMovementAnalyzer {
    fn default() -> Self {
        Self::new(None)
    }
}

impl LateralMovementAnalyzer {
    pub fn new(graph: Option<LateralGraph>) -> Self {
        Self {
            graph: graph.unwrap_or_default(),
            patterns: LateralPatterns::new(),
        }
    }

    /// Analyze query results for lateral movement indicators.
    ///
    /// Returns newly discovered connections.
    pub fn analyze_query_result(
        &mut self,
        result_data: &Value,
        source_host: Option<&str>,
    ) -> Vec<&HostConnection> {
        let result_str = result_data.to_string();
        let mut hosts: HashSet<String> = HashSet::new();

        // Extract values that look like hostnames
        Self::extract_searchable_values(result_data, &mut hosts);

        // Also scan raw string for hostnames
        for cap in HOSTNAME_RE.captures_iter(&result_str) {
            let candidate = &cap[1];
            if looks_like_hostname(candidate) {
                hosts.insert(candidate.to_lowercase());
            }
        }

        let conn_type = self.patterns.detect(&result_str);

        let start_idx = self.graph.connections.len();

        if let Some(source) = source_host {
            let source = source.to_lowercase();
            for dest in &hosts {
                if *dest != source {
                    self.graph.add_connection(
                        &source,
                        dest,
                        conn_type,
                        None,
                        None,
                        None,
                        TECHNIQUE_MAPPINGS.get(conn_type).copied(),
                    );
                }
            }
        }

        // Return references to newly added connections
        self.graph.connections[start_idx..].iter().collect()
    }

    /// Extract searchable string values from a JSON value.
    fn extract_searchable_values(value: &Value, out: &mut HashSet<String>) {
        match value {
            Value::String(s) => {
                if looks_like_hostname(s) {
                    out.insert(s.to_lowercase());
                }
            }
            Value::Object(map) => {
                for v in map.values() {
                    Self::extract_searchable_values(v, out);
                }
            }
            Value::Array(arr) => {
                for v in arr {
                    Self::extract_searchable_values(v, out);
                }
            }
            _ => {}
        }
    }

    /// Get suggestions for investigating pending hosts.
    pub fn get_pivot_suggestions(&self) -> Vec<Value> {
        let pending = self.graph.get_uninvestigated_targets(10);
        let mut suggestions: Vec<Value> = pending
            .iter()
            .map(|&host| {
                let conns = self.graph.get_host_connections(host);
                let sources: HashSet<&str> = conns
                    .iter()
                    .filter(|c| c.destination_host == host)
                    .map(|c| c.source_host.as_str())
                    .collect();
                let conn_types: HashSet<&str> =
                    conns.iter().map(|c| c.connection_type.as_str()).collect();

                serde_json::json!({
                    "host": host,
                    "discovered_from": sources.into_iter().collect::<Vec<_>>(),
                    "connection_types": conn_types.into_iter().collect::<Vec<_>>(),
                    "priority": conns.len(),
                    "suggested_queries": [
                        format!(r#"{{hostname=~".*{host}.*"}} |~ "(?i)4624|4625|logon""#),
                        format!(r#"{{job="windows-security"}} |~ "(?i){host}""#),
                    ],
                    "suggested_actions": [
                        format!("Call track_host_investigation('{host}')"),
                        format!("Run detect_lateral_movement(source_host='{host}')"),
                        format!("Run get_host_activity('{host}')"),
                    ],
                })
            })
            .collect();

        // Sort by priority (most connections first)
        suggestions.sort_by(|a, b| {
            let pa = a["priority"].as_u64().unwrap_or(0);
            let pb = b["priority"].as_u64().unwrap_or(0);
            pb.cmp(&pa)
        });

        suggestions
    }

    /// Reconstruct the likely attack path based on connections.
    pub fn get_attack_path(&self) -> Vec<String> {
        if self.graph.connections.is_empty() {
            return Vec::new();
        }

        let destinations: HashSet<&str> = self
            .graph
            .connections
            .iter()
            .map(|c| c.destination_host.as_str())
            .collect();
        let sources: HashSet<&str> = self
            .graph
            .connections
            .iter()
            .map(|c| c.source_host.as_str())
            .collect();

        // Entry points: sources that are not destinations
        let mut entry_points: Vec<&str> = sources.difference(&destinations).copied().collect();
        if entry_points.is_empty() {
            entry_points = sources.into_iter().collect();
        }
        entry_points.sort();

        let mut path = Vec::new();
        let mut visited = HashSet::new();

        fn dfs<'a>(
            host: &'a str,
            graph: &'a LateralGraph,
            visited: &mut HashSet<String>,
            path: &mut Vec<String>,
        ) {
            if visited.contains(host) {
                return;
            }
            visited.insert(host.to_string());
            path.push(host.to_string());

            for conn in graph.get_outgoing_connections(host) {
                dfs(&conn.destination_host, graph, visited, path);
            }
        }

        for entry in entry_points {
            dfs(entry, &self.graph, &mut visited, &mut path);
        }

        path
    }
}

/// Check if a string looks like a hostname.
fn looks_like_hostname(value: &str) -> bool {
    if !value.contains('.') || value.starts_with(|c: char| c.is_ascii_digit()) {
        return false;
    }
    if IP_RE.is_match(value) {
        return false;
    }
    (4..=255).contains(&value.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_graph_add_connection() {
        let mut graph = LateralGraph::new();
        let conn = graph.add_connection("DC01", "WEB01", "smb", None, Some("admin"), None, None);
        assert!(conn.is_some());
        assert_eq!(graph.connections.len(), 1);
        assert_eq!(graph.connections[0].source_host, "dc01");
        assert_eq!(graph.connections[0].destination_host, "web01");
        assert!(graph.pending_hosts.contains("web01"));
    }

    #[test]
    fn test_graph_self_connection_rejected() {
        let mut graph = LateralGraph::new();
        let conn = graph.add_connection("DC01", "dc01", "smb", None, None, None, None);
        assert!(conn.is_none());
        assert_eq!(graph.connections.len(), 0);
    }

    #[test]
    fn test_graph_mark_investigated() {
        let mut graph = LateralGraph::new();
        graph.add_connection("DC01", "WEB01", "smb", None, None, None, None);
        assert!(graph.pending_hosts.contains("web01"));

        graph.mark_investigated("WEB01");
        assert!(!graph.pending_hosts.contains("web01"));
        assert!(graph.investigated_hosts.contains("web01"));
    }

    #[test]
    fn test_graph_get_host_connections() {
        let mut graph = LateralGraph::new();
        graph.add_connection("dc01", "web01", "smb", None, None, None, None);
        graph.add_connection("dc01", "sql01", "wmi", None, None, None, None);
        graph.add_connection("web01", "sql01", "rdp", None, None, None, None);

        let dc01_conns = graph.get_host_connections("DC01");
        assert_eq!(dc01_conns.len(), 2);

        let sql01_conns = graph.get_host_connections("sql01");
        assert_eq!(sql01_conns.len(), 2);
    }

    #[test]
    fn test_graph_outgoing_incoming() {
        let mut graph = LateralGraph::new();
        graph.add_connection("dc01", "web01", "smb", None, None, None, None);
        graph.add_connection("web01", "sql01", "rdp", None, None, None, None);

        assert_eq!(graph.get_outgoing_connections("dc01").len(), 1);
        assert_eq!(graph.get_incoming_connections("web01").len(), 1);
        assert_eq!(graph.get_outgoing_connections("web01").len(), 1);
    }

    #[test]
    fn test_graph_unique_users() {
        let mut graph = LateralGraph::new();
        graph.add_connection("dc01", "web01", "smb", None, Some("admin"), None, None);
        graph.add_connection("dc01", "sql01", "wmi", None, Some("admin"), None, None);
        graph.add_connection("web01", "sql01", "rdp", None, Some("svc_sql"), None, None);

        let users = graph.get_unique_users();
        assert_eq!(users.len(), 2);
        assert!(users.contains("admin"));
        assert!(users.contains("svc_sql"));
    }

    #[test]
    fn test_graph_summary() {
        let mut graph = LateralGraph::new();
        graph.add_connection("dc01", "web01", "smb", None, None, None, None);
        graph.mark_investigated("dc01");

        let summary = graph.to_summary();
        assert_eq!(summary["total_connections"], 1);
        assert_eq!(summary["hosts_investigated"], 1);
        assert_eq!(summary["hosts_pending"], 1);
    }

    #[test]
    fn test_looks_like_hostname() {
        assert!(looks_like_hostname("dc01.contoso.local"));
        assert!(looks_like_hostname("web.example.com"));
        assert!(!looks_like_hostname("192.168.1.1"));
        assert!(!looks_like_hostname("abc"));
        assert!(!looks_like_hostname("1.2.3.4"));
    }

    #[test]
    fn test_analyzer_detect_connection_type() {
        let analyzer = LateralMovementAnalyzer::new(None);

        assert_eq!(
            analyzer.patterns.detect("SMB connection on port 445"),
            "smb"
        );
        assert_eq!(analyzer.patterns.detect("RDP session via 3389"), "rdp");
        assert_eq!(analyzer.patterns.detect("WMI process create"), "wmi");
        assert_eq!(
            analyzer.patterns.detect("PsExec service installed"),
            "psexec"
        );
        assert_eq!(analyzer.patterns.detect("WinRM session on 5985"), "winrm");
        assert_eq!(analyzer.patterns.detect("SSH login publickey"), "ssh");
        assert_eq!(analyzer.patterns.detect("nothing relevant here"), "unknown");
    }

    #[test]
    fn test_analyzer_query_result() {
        let mut analyzer = LateralMovementAnalyzer::new(None);

        let result = json!({
            "log_line": "SMB connection from dc01.contoso.local to web01.contoso.local on port 445",
            "hostname": "web01.contoso.local",
        });

        let new_conns = analyzer.analyze_query_result(&result, Some("dc01.contoso.local"));
        assert!(
            !new_conns.is_empty(),
            "Should detect lateral movement connections"
        );
    }

    #[test]
    fn test_analyzer_attack_path_linear() {
        let mut analyzer = LateralMovementAnalyzer::new(None);
        analyzer
            .graph
            .add_connection("dc01", "web01", "smb", None, None, None, None);
        analyzer
            .graph
            .add_connection("web01", "sql01", "rdp", None, None, None, None);

        let path = analyzer.get_attack_path();
        assert_eq!(path, vec!["dc01", "web01", "sql01"]);
    }

    #[test]
    fn test_analyzer_attack_path_empty() {
        let analyzer = LateralMovementAnalyzer::new(None);
        assert!(analyzer.get_attack_path().is_empty());
    }

    #[test]
    fn test_analyzer_pivot_suggestions() {
        let mut analyzer = LateralMovementAnalyzer::new(None);
        analyzer
            .graph
            .add_connection("dc01", "web01", "smb", None, None, None, None);
        analyzer
            .graph
            .add_connection("dc01", "sql01", "wmi", None, None, None, None);
        analyzer.graph.mark_investigated("dc01");

        let suggestions = analyzer.get_pivot_suggestions();
        assert_eq!(suggestions.len(), 2);
        // All suggestions should have required fields
        for s in &suggestions {
            assert!(s.get("host").is_some());
            assert!(s.get("priority").is_some());
            assert!(s.get("suggested_queries").is_some());
        }
    }
}
