//! Evaluation workflow for offline blue team evaluation.
//!
//! Provides scenario/dataset loading and offline evaluation from saved
//! red team state files. Replaces the Python `EvaluationRunner` for
//! non-live evaluation use cases.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use chrono::Utc;
use serde::Deserialize;

use super::gap_analysis::{analyze_detection_gaps, GapAnalysisReport};
use super::ground_truth::{create_ground_truth_from_red_state, EvaluationGroundTruth};
use super::results::{DatasetEvaluationResult, EvaluationResult};
use super::scorers::{self, InvestigationSnapshot};
use crate::models::{SharedBlueTeamState, SharedRedTeamState};

/// Model cost rates per million tokens.
#[derive(Debug, Clone)]
pub struct ModelCost {
    pub input_per_million: f64,
    pub output_per_million: f64,
}

/// Estimate cost in USD for token usage.
pub fn estimate_cost(model: &str, prompt_tokens: u64, completion_tokens: u64) -> f64 {
    static MODEL_COSTS: once_cell::sync::Lazy<HashMap<&'static str, ModelCost>> =
        once_cell::sync::Lazy::new(|| {
            HashMap::from([
                (
                    "claude-sonnet-4-20250514",
                    ModelCost {
                        input_per_million: 3.0,
                        output_per_million: 15.0,
                    },
                ),
                (
                    "claude-opus-4-20250514",
                    ModelCost {
                        input_per_million: 15.0,
                        output_per_million: 75.0,
                    },
                ),
                (
                    "gpt-4o",
                    ModelCost {
                        input_per_million: 2.5,
                        output_per_million: 10.0,
                    },
                ),
                (
                    "gpt-4-turbo",
                    ModelCost {
                        input_per_million: 10.0,
                        output_per_million: 30.0,
                    },
                ),
            ])
        });

    let default_cost = ModelCost {
        input_per_million: 5.0,
        output_per_million: 15.0,
    };
    let costs = MODEL_COSTS.get(model).unwrap_or(&default_cost);

    (prompt_tokens as f64 * costs.input_per_million
        + completion_tokens as f64 * costs.output_per_million)
        / 1_000_000.0
}

/// A saved red team state file for offline evaluation.
#[derive(Debug, Clone)]
pub struct EvaluationScenario {
    /// Path to the red team state JSON file.
    pub state_file: PathBuf,
    /// Human-readable scenario name.
    pub name: String,
    /// Tags for filtering/grouping.
    pub tags: Vec<String>,
    /// Pre-computed ground truth (generated from state if not provided).
    pub ground_truth: Option<EvaluationGroundTruth>,
}

/// A dataset of evaluation scenarios.
#[derive(Debug, Clone)]
pub struct EvaluationDataset {
    pub name: String,
    pub description: String,
    pub scenarios: Vec<EvaluationScenario>,
}

impl EvaluationDataset {
    /// Load a dataset from a directory of red team state JSON files.
    pub fn from_directory(dir: &Path, name: Option<&str>) -> Result<Self> {
        if !dir.is_dir() {
            anyhow::bail!("Not a directory: {}", dir.display());
        }

        let dir_name = dir
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unnamed");

        let mut scenarios = Vec::new();
        let mut entries: Vec<_> = fs::read_dir(dir)
            .context("Failed to read directory")?
            .filter_map(|e| e.ok())
            .filter(|e| {
                e.path()
                    .extension()
                    .map(|ext| ext == "json")
                    .unwrap_or(false)
            })
            .collect();
        entries.sort_by_key(|e| e.path());

        for entry in entries {
            let path = entry.path();
            let stem = path
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("unknown")
                .to_string();
            scenarios.push(EvaluationScenario {
                state_file: path,
                name: stem,
                tags: Vec::new(),
                ground_truth: None,
            });
        }

        Ok(Self {
            name: name.unwrap_or(dir_name).to_string(),
            description: String::new(),
            scenarios,
        })
    }

    /// Load a dataset from a JSON manifest file.
    ///
    /// Expected format:
    /// ```json
    /// {
    ///   "name": "dataset-name",
    ///   "description": "optional",
    ///   "scenarios": [
    ///     {"state_file": "path/to/state.json", "name": "scenario-1", "tags": ["tag1"]}
    ///   ]
    /// }
    /// ```
    pub fn from_json(json_path: &Path) -> Result<Self> {
        let data: serde_json::Value = serde_json::from_str(
            &fs::read_to_string(json_path).context("Failed to read dataset JSON")?,
        )
        .context("Failed to parse dataset JSON")?;

        let base_dir = json_path.parent().unwrap_or(Path::new("."));

        let mut scenarios = Vec::new();
        if let Some(arr) = data.get("scenarios").and_then(|v| v.as_array()) {
            for item in arr {
                let state_file_str = item
                    .get("state_file")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let state_path = if Path::new(state_file_str).is_absolute() {
                    PathBuf::from(state_file_str)
                } else {
                    base_dir.join(state_file_str)
                };

                let name = item
                    .get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let tags: Vec<String> = item
                    .get("tags")
                    .and_then(|v| v.as_array())
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|v| v.as_str().map(String::from))
                            .collect()
                    })
                    .unwrap_or_default();

                scenarios.push(EvaluationScenario {
                    state_file: state_path,
                    name,
                    tags,
                    ground_truth: None,
                });
            }
        }

        Ok(Self {
            name: data
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("unnamed")
                .to_string(),
            description: data
                .get("description")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            scenarios,
        })
    }
}

/// Result of evaluating a single scenario offline.
#[derive(Debug)]
pub struct ScenarioEvaluationOutput {
    pub scenario_name: String,
    pub ground_truth: EvaluationGroundTruth,
    pub result: EvaluationResult,
    pub gap_analysis: GapAnalysisReport,
}

/// Minimal red state fields for JSON deserialization in offline evaluation.
///
/// Only deserializes the fields needed for ground truth generation from saved
/// state files. This is more lenient than full `SharedRedTeamState` loading.
#[derive(Debug, Deserialize)]
struct SavedRedState {
    #[serde(default)]
    operation_id: String,
    #[serde(default)]
    target: Option<SavedTarget>,
    #[serde(default)]
    all_hosts: Vec<SavedHost>,
    #[serde(default)]
    all_users: Vec<SavedUser>,
    #[serde(default)]
    all_credentials: Vec<SavedCredential>,
    #[serde(default)]
    all_hashes: Vec<SavedHash>,
    #[serde(default)]
    all_shares: Vec<SavedShare>,
    #[serde(default)]
    all_domains: Vec<String>,
    #[serde(default)]
    has_domain_admin: bool,
    #[serde(default)]
    has_golden_ticket: bool,
    #[serde(default)]
    domain_admin_path: Option<String>,
    #[serde(default)]
    identified_techniques: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct SavedTarget {
    #[serde(default)]
    ip: String,
    #[serde(default)]
    hostname: String,
    #[serde(default)]
    domain: String,
}

#[derive(Debug, Deserialize)]
struct SavedHost {
    #[serde(default)]
    ip: String,
    #[serde(default)]
    hostname: String,
    #[serde(default)]
    os: String,
    #[serde(default)]
    roles: Vec<String>,
    #[serde(default)]
    services: Vec<String>,
    #[serde(default)]
    is_dc: bool,
    #[serde(default)]
    owned: bool,
}

#[derive(Debug, Deserialize)]
struct SavedUser {
    #[serde(default)]
    username: String,
    #[serde(default)]
    domain: String,
    #[serde(default)]
    is_admin: bool,
    #[serde(default)]
    source: String,
}

#[derive(Debug, Deserialize)]
struct SavedCredential {
    #[serde(default)]
    username: String,
    #[serde(default)]
    domain: String,
    #[serde(default)]
    source: String,
    #[serde(default)]
    is_admin: bool,
}

#[derive(Debug, Deserialize)]
struct SavedHash {
    #[serde(default)]
    username: String,
    #[serde(default)]
    hash_value: String,
    #[serde(default)]
    hash_type: String,
    #[serde(default)]
    domain: String,
    #[serde(default)]
    source: String,
}

#[derive(Debug, Deserialize)]
struct SavedShare {
    #[serde(default)]
    host: String,
    #[serde(default)]
    name: String,
    #[serde(default)]
    permissions: String,
}

/// Load a `SharedRedTeamState` from a saved JSON file.
pub fn load_red_state_from_file(path: &Path) -> Result<(SharedRedTeamState, Vec<String>)> {
    let data = fs::read_to_string(path)
        .with_context(|| format!("Failed to read state file: {}", path.display()))?;
    let saved: SavedRedState = serde_json::from_str(&data)
        .with_context(|| format!("Failed to parse state file: {}", path.display()))?;

    let mut state = SharedRedTeamState::new(saved.operation_id);
    state.target = saved.target.map(|t| crate::models::Target {
        ip: t.ip,
        hostname: t.hostname,
        domain: t.domain,
        environment: String::new(),
    });

    for h in saved.all_hosts {
        state.all_hosts.push(crate::models::Host {
            ip: h.ip,
            hostname: h.hostname,
            os: h.os,
            roles: h.roles,
            services: h.services,
            is_dc: h.is_dc,
            owned: h.owned,
        });
    }

    for u in saved.all_users {
        state.all_users.push(crate::models::User {
            username: u.username,
            domain: u.domain,
            description: String::new(),
            is_admin: u.is_admin,
            source: u.source,
        });
    }

    for c in saved.all_credentials {
        state.all_credentials.push(crate::models::Credential {
            id: String::new(),
            username: c.username,
            password: String::new(),
            domain: c.domain,
            source: c.source,
            discovered_at: None,
            is_admin: c.is_admin,
            parent_id: None,
            attack_step: 0,
        });
    }

    for h in saved.all_hashes {
        state.all_hashes.push(crate::models::Hash {
            id: String::new(),
            username: h.username,
            hash_value: h.hash_value,
            hash_type: if h.hash_type.is_empty() {
                "NTLM".to_string()
            } else {
                h.hash_type
            },
            domain: h.domain,
            cracked_password: None,
            source: h.source,
            discovered_at: None,
            parent_id: None,
            attack_step: 0,
            aes_key: None,
        });
    }

    for s in saved.all_shares {
        state.all_shares.push(crate::models::Share {
            host: s.host,
            name: s.name,
            permissions: s.permissions,
            comment: String::new(),
        });
    }

    state.all_domains = saved.all_domains;
    state.has_domain_admin = saved.has_domain_admin;
    state.has_golden_ticket = saved.has_golden_ticket;
    state.domain_admin_path = saved.domain_admin_path;

    Ok((state, saved.identified_techniques))
}

/// Evaluate a completed live investigation against red team ground truth.
///
/// Called post-investigation with the blue team's state loaded from Redis
/// and the red team's state (also from Redis). Returns the scored result
/// and gap analysis.
pub fn evaluate_live_investigation(
    blue_state: &SharedBlueTeamState,
    red_state: &SharedRedTeamState,
    model: &str,
    duration_seconds: f64,
) -> LiveEvaluationOutput {
    let techniques: Vec<String> = red_state.all_techniques.clone();
    let ground_truth = create_ground_truth_from_red_state(red_state, &techniques);
    let snap = InvestigationSnapshot::from_blue_state(blue_state);

    let eval_id = format!(
        "live-eval-{}-{}",
        red_state.operation_id,
        blue_state
            .investigation_id
            .chars()
            .take(8)
            .collect::<String>()
    );

    let result = scorers::evaluate(
        &eval_id,
        &snap,
        &ground_truth,
        true,
        model,
        duration_seconds,
    );
    let gap_analysis = analyze_detection_gaps(&result);

    LiveEvaluationOutput {
        evaluation_id: eval_id,
        investigation_id: blue_state.investigation_id.clone(),
        operation_id: red_state.operation_id.clone(),
        ground_truth,
        result,
        gap_analysis,
    }
}

/// Output from a live post-investigation evaluation.
#[derive(Debug)]
pub struct LiveEvaluationOutput {
    pub evaluation_id: String,
    pub investigation_id: String,
    pub operation_id: String,
    pub ground_truth: EvaluationGroundTruth,
    pub result: EvaluationResult,
    pub gap_analysis: GapAnalysisReport,
}

/// Evaluate a single scenario from a saved red team state file.
///
/// Generates ground truth and a baseline evaluation result (no investigation data).
/// The gap analysis shows what the blue team should have detected.
pub fn evaluate_scenario(scenario: &EvaluationScenario) -> Result<ScenarioEvaluationOutput> {
    let (state, techniques) = load_red_state_from_file(&scenario.state_file)?;

    let ground_truth = scenario
        .ground_truth
        .clone()
        .unwrap_or_else(|| create_ground_truth_from_red_state(&state, &techniques));

    // Build a minimal snapshot (no investigation data — scores reflect baseline)
    let snap = scorers::InvestigationSnapshot::default();

    let eval_id = format!("eval-{}", &state.operation_id);
    let result = scorers::evaluate(&eval_id, &snap, &ground_truth, false, "", 0.0);

    let gap_analysis = analyze_detection_gaps(&result);

    Ok(ScenarioEvaluationOutput {
        scenario_name: scenario.name.clone(),
        ground_truth,
        result,
        gap_analysis,
    })
}

/// Evaluate all scenarios in a dataset.
pub fn evaluate_dataset(dataset: &EvaluationDataset) -> Result<DatasetEvaluationResult> {
    let mut results = Vec::new();

    for scenario in &dataset.scenarios {
        match evaluate_scenario(scenario) {
            Ok(output) => results.push(output.result),
            Err(e) => {
                let result = EvaluationResult {
                    evaluation_id: format!("eval-failed-{}", scenario.name),
                    error: Some(format!("{e:#}")),
                    ..Default::default()
                };
                results.push(result);
            }
        }
    }

    Ok(DatasetEvaluationResult {
        dataset_name: dataset.name.clone(),
        evaluated_at: Utc::now(),
        results,
    })
}

/// Save an evaluation result to a JSON file.
pub fn save_evaluation_result(result: &EvaluationResult, output_dir: &Path) -> Result<PathBuf> {
    fs::create_dir_all(output_dir)?;
    let filename = format!("eval_{}_{}.json", result.evaluation_id, result.operation_id);
    let filepath = output_dir.join(filename);
    let json = serde_json::to_string_pretty(&result.to_value())?;
    fs::write(&filepath, json)?;
    Ok(filepath)
}

/// Save a gap analysis report to a markdown file.
pub fn save_gap_analysis(report: &GapAnalysisReport, output_dir: &Path) -> Result<PathBuf> {
    fs::create_dir_all(output_dir)?;
    let filename = format!(
        "gap_analysis_{}_{}.md",
        report.evaluation_id, report.operation_id
    );
    let filepath = output_dir.join(filename);
    fs::write(&filepath, report.to_markdown())?;
    Ok(filepath)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::TempDir;

    fn write_state_file(dir: &Path, name: &str, content: &str) -> PathBuf {
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
}
