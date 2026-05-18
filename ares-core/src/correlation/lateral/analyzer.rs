//! Lateral movement analyzer: detects connections in query results and suggests pivots.

use std::collections::HashSet;

use serde_json::Value;

use super::graph::{mitre_for_connection, AddConnectionParams, HostConnection, LateralGraph};
use super::patterns::{LateralPatterns, HOSTNAME_RE, IP_RE};

/// Analyzes query results for lateral movement patterns.
///
/// Automatically detects lateral movement indicators and builds a graph
/// of host connections.
pub struct LateralMovementAnalyzer {
    pub graph: LateralGraph,
    pub patterns: LateralPatterns,
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
                    self.graph.add_connection(AddConnectionParams {
                        source: &source,
                        destination: dest,
                        conn_type,
                        timestamp: None,
                        user: None,
                        evidence_id: None,
                        mitre_technique: mitre_for_connection(conn_type),
                    });
                }
            }
        }

        self.graph.connections[start_idx..].iter().collect()
    }

    /// Extract searchable string values from a JSON value.
    fn extract_searchable_values(value: &Value, out: &mut HashSet<String>) {
        match value {
            Value::String(s) if looks_like_hostname(s) => {
                out.insert(s.to_lowercase());
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

                // Derive relevant detection templates from connection types
                let detection_templates: Vec<&str> = conn_types
                    .iter()
                    .flat_map(|ct| crate::detection::templates_for_connection_type(ct))
                    .collect();

                serde_json::json!({
                    "host": host,
                    "discovered_from": sources.into_iter().collect::<Vec<_>>(),
                    "connection_types": conn_types.into_iter().collect::<Vec<_>>(),
                    "priority": conns.len(),
                    "suggested_queries": [
                        format!(r#"{{computer=~".*{host}.*"}} |~ "(?i)4624|4625|logon""#),
                        format!(r#"{{job="windows-security"}} |~ "(?i){host}""#),
                    ],
                    "suggested_actions": [
                        format!("Call track_host_investigation('{host}')"),
                        format!("Run get_host_activity('{host}')"),
                    ],
                    "suggested_detections": detection_templates,
                })
            })
            .collect();

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
pub fn looks_like_hostname(value: &str) -> bool {
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
    fn looks_like_hostname_valid() {
        assert!(looks_like_hostname("dc01.contoso.local"));
        assert!(looks_like_hostname("web.contoso.local"));
    }

    #[test]
    fn looks_like_hostname_no_dot() {
        assert!(!looks_like_hostname("localhost"));
    }

    #[test]
    fn looks_like_hostname_ip_address() {
        assert!(!looks_like_hostname("192.168.58.1"));
        assert!(!looks_like_hostname("192.168.58.100"));
    }

    #[test]
    fn looks_like_hostname_starts_with_digit() {
        assert!(!looks_like_hostname("1host.contoso.local"));
    }

    #[test]
    fn looks_like_hostname_too_short() {
        assert!(!looks_like_hostname("a.b"));
    }

    #[test]
    fn analyzer_default_creates_empty_graph() {
        let analyzer = LateralMovementAnalyzer::default();
        assert!(analyzer.graph.connections.is_empty());
    }

    #[test]
    fn analyze_query_result_extracts_hosts() {
        let mut analyzer = LateralMovementAnalyzer::default();
        let data = json!({
            "computer": "dc01.contoso.local",
            "message": "logon from ws01.contoso.local"
        });
        let conns = analyzer.analyze_query_result(&data, Some("ws01.contoso.local"));
        // Should find dc01 as destination from ws01
        assert!(!conns.is_empty());
    }

    #[test]
    fn analyze_query_result_no_source_no_connections() {
        let mut analyzer = LateralMovementAnalyzer::default();
        let data = json!({"computer": "dc01.contoso.local"});
        let conns = analyzer.analyze_query_result(&data, None);
        assert!(conns.is_empty());
    }

    #[test]
    fn analyze_query_result_same_host_no_self_connection() {
        let mut analyzer = LateralMovementAnalyzer::default();
        let data = json!({"computer": "dc01.contoso.local"});
        let conns = analyzer.analyze_query_result(&data, Some("dc01.contoso.local"));
        assert!(conns.is_empty());
    }

    #[test]
    fn get_attack_path_empty_graph() {
        let analyzer = LateralMovementAnalyzer::default();
        let path = analyzer.get_attack_path();
        assert!(path.is_empty());
    }

    #[test]
    fn get_attack_path_linear_chain() {
        let mut analyzer = LateralMovementAnalyzer::default();
        // ws01 -> dc01
        let data1 = json!({"computer": "dc01.contoso.local"});
        analyzer.analyze_query_result(&data1, Some("ws01.contoso.local"));
        let path = analyzer.get_attack_path();
        assert!(!path.is_empty());
        // ws01 should be the entry point
        assert_eq!(path[0], "ws01.contoso.local");
    }

    #[test]
    fn get_pivot_suggestions_returns_uninvestigated() {
        let mut analyzer = LateralMovementAnalyzer::default();
        let data = json!({"computer": "dc01.contoso.local"});
        analyzer.analyze_query_result(&data, Some("ws01.contoso.local"));
        let suggestions = analyzer.get_pivot_suggestions();
        // dc01 is uninvestigated target
        assert!(suggestions
            .iter()
            .filter_map(|s| s["host"].as_str())
            .any(|h| h == "dc01.contoso.local"));
    }
}
