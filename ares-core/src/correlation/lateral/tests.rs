use super::graph::AddConnectionParams;
use super::*;
use serde_json::json;

fn basic_conn<'a>(
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
fn graph_add_connection() {
    let mut graph = LateralGraph::new();
    let conn = graph.add_connection(AddConnectionParams {
        user: Some("admin"),
        ..basic_conn("DC01", "WEB01", "smb")
    });
    assert!(conn.is_some());
    assert_eq!(graph.connections.len(), 1);
    assert_eq!(graph.connections[0].source_host, "dc01");
    assert_eq!(graph.connections[0].destination_host, "web01");
    assert!(graph.pending_hosts.contains("web01"));
}

#[test]
fn graph_self_connection_rejected() {
    let mut graph = LateralGraph::new();
    let conn = graph.add_connection(basic_conn("DC01", "dc01", "smb"));
    assert!(conn.is_none());
    assert_eq!(graph.connections.len(), 0);
}

#[test]
fn graph_mark_investigated() {
    let mut graph = LateralGraph::new();
    graph.add_connection(basic_conn("DC01", "WEB01", "smb"));
    assert!(graph.pending_hosts.contains("web01"));

    graph.mark_investigated("WEB01");
    assert!(!graph.pending_hosts.contains("web01"));
    assert!(graph.investigated_hosts.contains("web01"));
}

#[test]
fn graph_get_host_connections() {
    let mut graph = LateralGraph::new();
    graph.add_connection(basic_conn("dc01", "web01", "smb"));
    graph.add_connection(basic_conn("dc01", "sql01", "wmi"));
    graph.add_connection(basic_conn("web01", "sql01", "rdp"));

    let dc01_conns = graph.get_host_connections("DC01");
    assert_eq!(dc01_conns.len(), 2);

    let sql01_conns = graph.get_host_connections("sql01");
    assert_eq!(sql01_conns.len(), 2);
}

#[test]
fn graph_outgoing_incoming() {
    let mut graph = LateralGraph::new();
    graph.add_connection(basic_conn("dc01", "web01", "smb"));
    graph.add_connection(basic_conn("web01", "sql01", "rdp"));

    assert_eq!(graph.get_outgoing_connections("dc01").len(), 1);
    assert_eq!(graph.get_incoming_connections("web01").len(), 1);
    assert_eq!(graph.get_outgoing_connections("web01").len(), 1);
}

#[test]
fn graph_unique_users() {
    let mut graph = LateralGraph::new();
    graph.add_connection(AddConnectionParams {
        user: Some("admin"),
        ..basic_conn("dc01", "web01", "smb")
    });
    graph.add_connection(AddConnectionParams {
        user: Some("admin"),
        ..basic_conn("dc01", "sql01", "wmi")
    });
    graph.add_connection(AddConnectionParams {
        user: Some("svc_sql"),
        ..basic_conn("web01", "sql01", "rdp")
    });

    let users = graph.get_unique_users();
    assert_eq!(users.len(), 2);
    assert!(users.contains("admin"));
    assert!(users.contains("svc_sql"));
}

#[test]
fn graph_summary() {
    let mut graph = LateralGraph::new();
    graph.add_connection(basic_conn("dc01", "web01", "smb"));
    graph.mark_investigated("dc01");

    let summary = graph.to_summary();
    assert_eq!(summary["total_connections"], 1);
    assert_eq!(summary["hosts_investigated"], 1);
    assert_eq!(summary["hosts_pending"], 1);
}

#[test]
fn looks_like_hostname_variants() {
    assert!(looks_like_hostname("dc01.contoso.local"));
    assert!(looks_like_hostname("web.contoso.local"));
    assert!(!looks_like_hostname("192.168.58.10"));
    assert!(!looks_like_hostname("abc"));
    assert!(!looks_like_hostname("1.2.3.4"));
}

#[test]
fn analyzer_detect_connection_type() {
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
fn analyzer_query_result() {
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
fn analyzer_attack_path_linear() {
    let mut analyzer = LateralMovementAnalyzer::new(None);
    analyzer
        .graph
        .add_connection(basic_conn("dc01", "web01", "smb"));
    analyzer
        .graph
        .add_connection(basic_conn("web01", "sql01", "rdp"));

    let path = analyzer.get_attack_path();
    assert_eq!(path, vec!["dc01", "web01", "sql01"]);
}

#[test]
fn analyzer_attack_path_empty() {
    let analyzer = LateralMovementAnalyzer::new(None);
    assert!(analyzer.get_attack_path().is_empty());
}

#[test]
fn analyzer_pivot_suggestions() {
    let mut analyzer = LateralMovementAnalyzer::new(None);
    analyzer
        .graph
        .add_connection(basic_conn("dc01", "web01", "smb"));
    analyzer
        .graph
        .add_connection(basic_conn("dc01", "sql01", "wmi"));
    analyzer.graph.mark_investigated("dc01");

    let suggestions = analyzer.get_pivot_suggestions();
    assert_eq!(suggestions.len(), 2);
    for s in &suggestions {
        assert!(s.get("host").is_some());
        assert!(s.get("priority").is_some());
        assert!(s.get("suggested_queries").is_some());
    }
}
