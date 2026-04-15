//! Investigation persistence for learning from past investigations.
//!
//! Stores completed investigation records in a JSON file at
//! `~/.ares/investigations.json` for cross-investigation learning:
//! false positive detection, effective query tracking, and similar
//! investigation lookup.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Mutex;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tracing::warn;

// ---------------------------------------------------------------------------
// Data models
// ---------------------------------------------------------------------------

/// A completed investigation record stored for learning.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredInvestigation {
    pub investigation_id: String,
    pub alert_name: String,
    pub alert_fingerprint: String,
    pub severity: String,
    pub technique_id: Option<String>,
    pub technique_name: Option<String>,
    pub started_at: DateTime<Utc>,
    pub completed_at: DateTime<Utc>,
    pub duration_seconds: f64,
    pub status: String,
    pub evidence_count: usize,
    pub highest_pyramid_level: i32,
    pub techniques_identified: Vec<String>,
    pub queries_executed: usize,
    pub query_success_rate: f64,
    pub effective_queries: Vec<String>,
    pub is_true_positive: Option<bool>,
    pub analyst_notes: Option<String>,
    #[serde(default)]
    pub metadata: HashMap<String, String>,
}

/// Query effectiveness tracking.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryEffectiveness {
    pub query_pattern: String,
    pub total_executions: usize,
    pub successful_executions: usize,
    pub evidence_producing: usize,
    pub alert_types: Vec<String>,
}

impl QueryEffectiveness {
    pub fn success_rate(&self) -> f64 {
        if self.total_executions == 0 {
            return 0.0;
        }
        self.successful_executions as f64 / self.total_executions as f64
    }

    pub fn evidence_rate(&self) -> f64 {
        if self.total_executions == 0 {
            return 0.0;
        }
        self.evidence_producing as f64 / self.total_executions as f64
    }
}

/// A similar investigation result with similarity score.
#[derive(Debug, Clone)]
pub struct SimilarInvestigation {
    pub investigation: StoredInvestigation,
    pub similarity_score: f64,
    pub matching_factors: Vec<String>,
}

/// False positive pattern detected across investigations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FalsePositivePattern {
    pub fingerprint: String,
    pub alert_name: String,
    pub occurrences: usize,
    pub fp_rate: f64,
}

// ---------------------------------------------------------------------------
// Store file format
// ---------------------------------------------------------------------------

#[derive(Debug, Default, Serialize, Deserialize)]
struct StoreData {
    investigations: Vec<StoredInvestigation>,
    query_effectiveness: Vec<QueryEffectiveness>,
}

// ---------------------------------------------------------------------------
// InvestigationStore
// ---------------------------------------------------------------------------

/// JSON file-backed investigation store for cross-investigation learning.
pub struct InvestigationStore {
    path: PathBuf,
    data: Mutex<StoreData>,
}

impl InvestigationStore {
    /// Open or create the investigation store.
    pub fn open(path: PathBuf) -> Self {
        let data = if path.exists() {
            match std::fs::read_to_string(&path) {
                Ok(contents) => serde_json::from_str(&contents).unwrap_or_else(|e| {
                    warn!("Failed to parse investigation store: {e}");
                    StoreData::default()
                }),
                Err(e) => {
                    warn!("Failed to read investigation store: {e}");
                    StoreData::default()
                }
            }
        } else {
            StoreData::default()
        };

        Self {
            path,
            data: Mutex::new(data),
        }
    }

    /// Get the default store path (~/.ares/investigations.json).
    pub fn default_path() -> PathBuf {
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
        PathBuf::from(home)
            .join(".ares")
            .join("investigations.json")
    }

    fn save(&self, data: &StoreData) {
        if let Some(parent) = self.path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        match serde_json::to_string_pretty(data) {
            Ok(json) => {
                if let Err(e) = std::fs::write(&self.path, json) {
                    warn!("Failed to save investigation store: {e}");
                }
            }
            Err(e) => warn!("Failed to serialize investigation store: {e}"),
        }
    }

    /// Store a completed investigation.
    pub fn store_investigation(&self, investigation: StoredInvestigation) {
        let mut data = self.data.lock().unwrap();
        // Replace if exists, otherwise append
        if let Some(pos) = data
            .investigations
            .iter()
            .position(|i| i.investigation_id == investigation.investigation_id)
        {
            data.investigations[pos] = investigation;
        } else {
            data.investigations.push(investigation);
        }
        self.save(&data);
    }

    /// Find similar investigations by alert name, fingerprint, technique, severity.
    pub fn find_similar_investigations(
        &self,
        alert_name: Option<&str>,
        alert_fingerprint: Option<&str>,
        technique_id: Option<&str>,
        severity: Option<&str>,
        limit: usize,
    ) -> Vec<SimilarInvestigation> {
        let data = self.data.lock().unwrap();

        let mut scored: Vec<SimilarInvestigation> = data
            .investigations
            .iter()
            .filter_map(|inv| {
                let mut score = 0.0_f64;
                let mut factors = Vec::new();

                if let Some(fp) = alert_fingerprint {
                    if inv.alert_fingerprint == fp {
                        score += 0.5;
                        factors.push("fingerprint".to_string());
                    }
                }
                if let Some(name) = alert_name {
                    if inv.alert_name.to_lowercase() == name.to_lowercase() {
                        score += 0.3;
                        factors.push("alert_name".to_string());
                    }
                }
                if let Some(tech) = technique_id {
                    if inv.technique_id.as_deref().is_some_and(|t| t == tech)
                        || inv.techniques_identified.iter().any(|t| t == tech)
                    {
                        score += 0.15;
                        factors.push("technique".to_string());
                    }
                }
                if let Some(sev) = severity {
                    if inv.severity.to_lowercase() == sev.to_lowercase() {
                        score += 0.05;
                        factors.push("severity".to_string());
                    }
                }

                if score > 0.0 {
                    Some(SimilarInvestigation {
                        investigation: inv.clone(),
                        similarity_score: score,
                        matching_factors: factors,
                    })
                } else {
                    None
                }
            })
            .collect();

        scored.sort_by(|a, b| {
            b.similarity_score
                .partial_cmp(&a.similarity_score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        scored.truncate(limit);
        scored
    }

    /// Update query effectiveness tracking.
    pub fn update_query_effectiveness(
        &self,
        query_pattern: &str,
        successful: bool,
        produced_evidence: bool,
        alert_type: Option<&str>,
    ) {
        let mut data = self.data.lock().unwrap();

        if let Some(qe) = data
            .query_effectiveness
            .iter_mut()
            .find(|q| q.query_pattern == query_pattern)
        {
            qe.total_executions += 1;
            if successful {
                qe.successful_executions += 1;
            }
            if produced_evidence {
                qe.evidence_producing += 1;
            }
            if let Some(at) = alert_type {
                if !qe.alert_types.contains(&at.to_string()) {
                    qe.alert_types.push(at.to_string());
                }
            }
        } else {
            data.query_effectiveness.push(QueryEffectiveness {
                query_pattern: query_pattern.to_string(),
                total_executions: 1,
                successful_executions: if successful { 1 } else { 0 },
                evidence_producing: if produced_evidence { 1 } else { 0 },
                alert_types: alert_type
                    .map(|at| vec![at.to_string()])
                    .unwrap_or_default(),
            });
        }

        self.save(&data);
    }

    /// Get effective queries filtered by minimum evidence rate.
    pub fn get_effective_queries(
        &self,
        alert_type: Option<&str>,
        min_evidence_rate: f64,
        limit: usize,
    ) -> Vec<QueryEffectiveness> {
        let data = self.data.lock().unwrap();

        let mut results: Vec<QueryEffectiveness> = data
            .query_effectiveness
            .iter()
            .filter(|q| {
                q.total_executions >= 3
                    && q.evidence_rate() >= min_evidence_rate
                    && alert_type
                        .map(|at| q.alert_types.iter().any(|t| t == at))
                        .unwrap_or(true)
            })
            .cloned()
            .collect();

        results.sort_by(|a, b| {
            b.evidence_rate()
                .partial_cmp(&a.evidence_rate())
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        results.truncate(limit);
        results
    }

    /// Get investigation statistics.
    pub fn get_statistics(&self) -> InvestigationStatistics {
        let data = self.data.lock().unwrap();
        let total = data.investigations.len();

        if total == 0 {
            return InvestigationStatistics::default();
        }

        let completed = data
            .investigations
            .iter()
            .filter(|i| i.status == "completed")
            .count();
        let escalated = data
            .investigations
            .iter()
            .filter(|i| i.status == "escalated")
            .count();
        let failed = data
            .investigations
            .iter()
            .filter(|i| i.status == "failed")
            .count();
        let true_positives = data
            .investigations
            .iter()
            .filter(|i| i.is_true_positive == Some(true))
            .count();
        let false_positives = data
            .investigations
            .iter()
            .filter(|i| i.is_true_positive == Some(false))
            .count();
        let labeled = true_positives + false_positives;

        let avg_duration = data
            .investigations
            .iter()
            .map(|i| i.duration_seconds)
            .sum::<f64>()
            / total as f64;
        let avg_evidence = data
            .investigations
            .iter()
            .map(|i| i.evidence_count)
            .sum::<usize>() as f64
            / total as f64;

        InvestigationStatistics {
            total_investigations: total,
            completed,
            escalated,
            failed,
            true_positives,
            false_positives,
            labeled,
            avg_duration_seconds: avg_duration,
            avg_evidence_count: avg_evidence,
        }
    }

    /// Get false positive patterns (fingerprints with multiple FPs).
    pub fn get_false_positive_patterns(&self, min_occurrences: usize) -> Vec<FalsePositivePattern> {
        let data = self.data.lock().unwrap();

        let mut fp_counts: HashMap<String, (String, usize, usize)> = HashMap::new(); // fingerprint -> (name, total, fp_count)
        for inv in &data.investigations {
            let entry = fp_counts
                .entry(inv.alert_fingerprint.clone())
                .or_insert_with(|| (inv.alert_name.clone(), 0, 0));
            entry.1 += 1;
            if inv.is_true_positive == Some(false) {
                entry.2 += 1;
            }
        }

        fp_counts
            .into_iter()
            .filter(|(_, (_, total, fp_count))| *total >= min_occurrences && *fp_count > 0)
            .map(
                |(fingerprint, (alert_name, total, fp_count))| FalsePositivePattern {
                    fingerprint,
                    alert_name,
                    occurrences: total,
                    fp_rate: fp_count as f64 / total as f64,
                },
            )
            .collect()
    }

    /// Label an investigation as true/false positive.
    pub fn label_investigation(
        &self,
        investigation_id: &str,
        is_true_positive: bool,
        analyst_notes: Option<&str>,
    ) -> bool {
        let mut data = self.data.lock().unwrap();
        if let Some(inv) = data
            .investigations
            .iter_mut()
            .find(|i| i.investigation_id == investigation_id)
        {
            inv.is_true_positive = Some(is_true_positive);
            if let Some(notes) = analyst_notes {
                inv.analyst_notes = Some(notes.to_string());
            }
            self.save(&data);
            true
        } else {
            false
        }
    }
}

/// Aggregate statistics across all stored investigations.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct InvestigationStatistics {
    pub total_investigations: usize,
    pub completed: usize,
    pub escalated: usize,
    pub failed: usize,
    pub true_positives: usize,
    pub false_positives: usize,
    pub labeled: usize,
    pub avg_duration_seconds: f64,
    pub avg_evidence_count: f64,
}

// ---------------------------------------------------------------------------
// Singleton
// ---------------------------------------------------------------------------

static STORE: std::sync::OnceLock<InvestigationStore> = std::sync::OnceLock::new();

/// Get the global investigation store singleton.
pub fn get_investigation_store() -> &'static InvestigationStore {
    STORE.get_or_init(|| InvestigationStore::open(InvestigationStore::default_path()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn make_investigation(id: &str, alert: &str, severity: &str) -> StoredInvestigation {
        StoredInvestigation {
            investigation_id: id.to_string(),
            alert_name: alert.to_string(),
            alert_fingerprint: format!("fp-{alert}"),
            severity: severity.to_string(),
            technique_id: Some("T1003".to_string()),
            technique_name: Some("OS Credential Dumping".to_string()),
            started_at: Utc::now(),
            completed_at: Utc::now(),
            duration_seconds: 120.0,
            status: "completed".to_string(),
            evidence_count: 5,
            highest_pyramid_level: 4,
            techniques_identified: vec!["T1003".to_string(), "T1003.006".to_string()],
            queries_executed: 10,
            query_success_rate: 0.7,
            effective_queries: vec!["detect_dcsync".to_string()],
            is_true_positive: None,
            analyst_notes: None,
            metadata: HashMap::new(),
        }
    }

    #[test]
    fn test_store_and_find() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test_investigations.json");
        let store = InvestigationStore::open(path);

        store.store_investigation(make_investigation("inv-1", "DCSync Alert", "critical"));
        store.store_investigation(make_investigation("inv-2", "DCSync Alert", "high"));
        store.store_investigation(make_investigation("inv-3", "Brute Force", "medium"));

        let similar = store.find_similar_investigations(Some("DCSync Alert"), None, None, None, 10);
        assert_eq!(similar.len(), 2);
        assert!(similar[0].similarity_score >= similar[1].similarity_score);
    }

    #[test]
    fn test_statistics() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test_stats.json");
        let store = InvestigationStore::open(path);

        store.store_investigation(make_investigation("inv-1", "Alert A", "high"));
        store.store_investigation(make_investigation("inv-2", "Alert B", "high"));

        let stats = store.get_statistics();
        assert_eq!(stats.total_investigations, 2);
        assert_eq!(stats.completed, 2);
    }

    #[test]
    fn test_label_investigation() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test_label.json");
        let store = InvestigationStore::open(path);

        store.store_investigation(make_investigation("inv-1", "Alert A", "high"));
        assert!(store.label_investigation("inv-1", false, Some("False positive")));
        assert!(!store.label_investigation("nonexistent", true, None));

        let patterns = store.get_false_positive_patterns(1);
        assert_eq!(patterns.len(), 1);
        assert_eq!(patterns[0].fp_rate, 1.0);
    }

    #[test]
    fn test_query_effectiveness() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test_qe.json");
        let store = InvestigationStore::open(path);

        for _ in 0..5 {
            store.update_query_effectiveness("detect_dcsync", true, true, Some("DCSync"));
        }
        store.update_query_effectiveness("detect_brute_force", true, false, Some("Brute"));

        let effective = store.get_effective_queries(None, 0.5, 10);
        assert_eq!(effective.len(), 1);
        assert_eq!(effective[0].query_pattern, "detect_dcsync");
    }
}
