use super::costs::estimate_cost;
use super::dataset::{EvaluationDataset, EvaluationScenario};
use super::runner::{evaluate_dataset, evaluate_scenario, save_evaluation_result};
use crate::eval::results::EvaluationResult;
use crate::eval::workflow::load_red_state_from_file;
use std::fs;
use std::io::Write;
use std::path::Path;
use tempfile::TempDir;

fn write_state_file(dir: &Path, name: &str, content: &str) -> std::path::PathBuf {
    let path = dir.join(name);
    let mut f = fs::File::create(&path).unwrap();
    f.write_all(content.as_bytes()).unwrap();
    path
}

fn sample_state_json() -> &'static str {
    r#"{
        "operation_id": "op-test-1",
        "target": {"ip": "192.168.58.10", "hostname": "dc01", "domain": "contoso.local"},
        "all_hosts": [
            {"ip": "192.168.58.10", "hostname": "dc01.contoso.local"}
        ],
        "all_users": [
            {"username": "admin", "domain": "contoso.local", "is_admin": true}
        ],
        "all_credentials": [
            {"username": "svc_sql", "domain": "contoso.local"}
        ],
        "all_hashes": [
            {"username": "admin", "hash_value": "aad3b435:abc", "hash_type": "NTLM"}
        ],
        "has_domain_admin": true,
        "identified_techniques": ["T1003", "T1046", "T1558.003"]
    }"#
}

#[test]
fn test_load_red_state_from_file() {
    let dir = TempDir::new().unwrap();
    let path = write_state_file(dir.path(), "state.json", sample_state_json());

    let (state, techniques) = load_red_state_from_file(&path).unwrap();
    assert_eq!(state.operation_id, "op-test-1");
    assert_eq!(state.all_hosts.len(), 1);
    assert_eq!(state.all_users.len(), 1);
    assert_eq!(state.all_credentials.len(), 1);
    assert_eq!(state.all_hashes.len(), 1);
    assert!(state.has_domain_admin);
    assert_eq!(techniques.len(), 3);
}

#[test]
fn test_evaluate_scenario_from_file() {
    let dir = TempDir::new().unwrap();
    let path = write_state_file(dir.path(), "state.json", sample_state_json());

    let scenario = EvaluationScenario {
        state_file: path,
        name: "test-scenario".to_string(),
        tags: Vec::new(),
        ground_truth: None,
    };

    let output = evaluate_scenario(&scenario).unwrap();
    assert_eq!(output.scenario_name, "test-scenario");
    assert!(!output.ground_truth.expected_iocs.is_empty());
    assert!(!output.ground_truth.expected_techniques.is_empty());
    // No investigation data → grade should be F
    assert_eq!(output.result.grade(), "F");
    assert!(!output.gap_analysis.detection_gaps.is_empty());
}

#[test]
fn test_dataset_from_directory() {
    let dir = TempDir::new().unwrap();
    write_state_file(dir.path(), "op1.json", sample_state_json());
    write_state_file(
        dir.path(),
        "op2.json",
        &sample_state_json().replace("op-test-1", "op-test-2"),
    );
    // Non-JSON file should be ignored
    write_state_file(dir.path(), "readme.txt", "ignore me");

    let dataset = EvaluationDataset::from_directory(dir.path(), Some("test-dataset")).unwrap();
    assert_eq!(dataset.name, "test-dataset");
    assert_eq!(dataset.scenarios.len(), 2);
}

#[test]
fn test_evaluate_dataset() {
    let dir = TempDir::new().unwrap();
    write_state_file(dir.path(), "op1.json", sample_state_json());

    let dataset = EvaluationDataset::from_directory(dir.path(), None).unwrap();
    let result = evaluate_dataset(&dataset).unwrap();

    assert_eq!(result.count(), 1);
    // No investigation data so pass rate should be 0
    assert!((result.pass_rate() - 0.0).abs() < f64::EPSILON);
}

#[test]
fn test_estimate_cost() {
    let cost = estimate_cost("claude-sonnet-4-20250514", 1_000_000, 500_000);
    // 1M * 3.0/1M + 500K * 15.0/1M = 3.0 + 7.5 = 10.5
    assert!((cost - 10.5).abs() < 0.01);

    // Unknown model uses defaults
    let cost2 = estimate_cost("unknown-model", 1_000_000, 0);
    assert!((cost2 - 5.0).abs() < 0.01);
}

#[test]
fn test_save_evaluation_result() {
    let dir = TempDir::new().unwrap();
    let result = EvaluationResult {
        evaluation_id: "eval-1".to_string(),
        operation_id: "op-1".to_string(),
        overall_score: 0.75,
        ..Default::default()
    };

    let path = save_evaluation_result(&result, dir.path()).unwrap();
    assert!(path.exists());

    let content = fs::read_to_string(&path).unwrap();
    assert!(content.contains("eval-1"));
}
