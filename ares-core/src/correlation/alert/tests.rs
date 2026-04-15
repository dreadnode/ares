use super::*;
use serde_json::{json, Value};

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
