//! Scenario and dataset types for offline evaluation, plus saved-state deserialization.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::Deserialize;

use crate::eval::ground_truth::EvaluationGroundTruth;

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

/// Minimal red state fields for JSON deserialization in offline evaluation.
///
/// Only deserializes the fields needed for ground truth generation from saved
/// state files. This is more lenient than full `SharedRedTeamState` loading.
#[derive(Debug, Deserialize)]
pub(super) struct SavedRedState {
    #[serde(default)]
    pub operation_id: String,
    #[serde(default)]
    pub target: Option<SavedTarget>,
    #[serde(default)]
    pub all_hosts: Vec<SavedHost>,
    #[serde(default)]
    pub all_users: Vec<SavedUser>,
    #[serde(default)]
    pub all_credentials: Vec<SavedCredential>,
    #[serde(default)]
    pub all_hashes: Vec<SavedHash>,
    #[serde(default)]
    pub all_shares: Vec<SavedShare>,
    #[serde(default)]
    pub all_domains: Vec<String>,
    #[serde(default)]
    pub has_domain_admin: bool,
    #[serde(default)]
    pub has_golden_ticket: bool,
    #[serde(default)]
    pub domain_admin_path: Option<String>,
    #[serde(default)]
    pub identified_techniques: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub(super) struct SavedTarget {
    #[serde(default)]
    pub ip: String,
    #[serde(default)]
    pub hostname: String,
    #[serde(default)]
    pub domain: String,
}

#[derive(Debug, Deserialize)]
pub(super) struct SavedHost {
    #[serde(default)]
    pub ip: String,
    #[serde(default)]
    pub hostname: String,
    #[serde(default)]
    pub os: String,
    #[serde(default)]
    pub roles: Vec<String>,
    #[serde(default)]
    pub services: Vec<String>,
    #[serde(default)]
    pub is_dc: bool,
    #[serde(default)]
    pub owned: bool,
}

#[derive(Debug, Deserialize)]
pub(super) struct SavedUser {
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub domain: String,
    #[serde(default)]
    pub is_admin: bool,
    #[serde(default)]
    pub source: String,
}

#[derive(Debug, Deserialize)]
pub(super) struct SavedCredential {
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub domain: String,
    #[serde(default)]
    pub source: String,
    #[serde(default)]
    pub is_admin: bool,
}

#[derive(Debug, Deserialize)]
pub(super) struct SavedHash {
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub hash_value: String,
    #[serde(default)]
    pub hash_type: String,
    #[serde(default)]
    pub domain: String,
    #[serde(default)]
    pub source: String,
}

#[derive(Debug, Deserialize)]
pub(super) struct SavedShare {
    #[serde(default)]
    pub host: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub permissions: String,
}

/// Load a `SharedRedTeamState` from a saved JSON file.
pub fn load_red_state_from_file(
    path: &Path,
) -> anyhow::Result<(crate::models::SharedRedTeamState, Vec<String>)> {
    let data = fs::read_to_string(path)
        .with_context(|| format!("Failed to read state file: {}", path.display()))?;
    let saved: SavedRedState = serde_json::from_str(&data)
        .with_context(|| format!("Failed to parse state file: {}", path.display()))?;

    let mut state = crate::models::SharedRedTeamState::new(saved.operation_id);
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
