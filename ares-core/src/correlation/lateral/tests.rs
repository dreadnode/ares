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
    assert!(!looks_like_hostname("192.168.58.10"));
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
