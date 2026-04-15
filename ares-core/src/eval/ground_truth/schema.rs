//! Expected finding structs and the `EvaluationGroundTruth` aggregate.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::models::PyramidLevel;

pub(super) fn default_true() -> bool {
    true
}

fn default_min_pyramid() -> u32 {
    4
}
fn default_target_pyramid() -> u32 {
    6
}
fn default_min_technique_coverage() -> f64 {
    0.6
}
fn default_min_ioc_detection() -> f64 {
    0.5
}

/// An IOC that the blue team should discover.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExpectedIOC {
    /// Type: ip, hostname, user, hash, domain, process, tool
    pub ioc_type: String,
    pub value: String,
    pub pyramid_level: PyramidLevel,
    #[serde(default)]
    pub mitre_techniques: Vec<String>,
    #[serde(default = "default_true")]
    pub required: bool,
    #[serde(default)]
    pub source: String,
}

/// A MITRE technique that should be identified.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExpectedTechnique {
    pub technique_id: String,
    #[serde(default)]
    pub technique_name: String,
    #[serde(default = "default_true")]
    pub required: bool,
    pub parent_id: Option<String>,
}

impl ExpectedTechnique {
    /// Check if a found technique matches this expected technique.
    ///
    /// Supports parent/sub-technique matching:
    /// - T1003 matches T1003.001 (parent matches child)
    /// - T1003.001 matches T1003 (child matches parent)
    pub fn matches(&self, found: &str) -> bool {
        if found == self.technique_id {
            return true;
        }

        if self.technique_id.contains('.') {
            // This is a sub-technique; check if found is the parent
            let parent = self.technique_id.split('.').next().unwrap_or("");
            if found == parent {
                return true;
            }
        } else if found.starts_with(&format!("{}.", self.technique_id)) {
            // This is a parent; found is a sub-technique
            return true;
        }

        false
    }
}

/// A timeline event that should appear in the investigation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExpectedTimelineEvent {
    /// Regex or substring to match in event description.
    pub description_pattern: String,
    #[serde(default)]
    pub mitre_techniques: Vec<String>,
    pub timestamp_range: Option<(DateTime<Utc>, DateTime<Utc>)>,
    #[serde(default = "default_true")]
    pub required: bool,
}

/// A network share that should be identified.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExpectedShare {
    pub host: String,
    pub name: String,
    #[serde(default)]
    pub permissions: String,
    #[serde(default)]
    pub required: bool,
}

/// A vulnerability that should be identified.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExpectedVulnerability {
    pub vuln_type: String,
    pub target: String,
    #[serde(default)]
    pub mitre_techniques: Vec<String>,
    #[serde(default)]
    pub exploited: bool,
    #[serde(default = "default_true")]
    pub required: bool,
}

/// Complete ground truth for evaluating a blue team investigation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvaluationGroundTruth {
    pub operation_id: String,
    pub target_ip: String,
    #[serde(default)]
    pub expected_iocs: Vec<ExpectedIOC>,
    #[serde(default)]
    pub expected_techniques: Vec<ExpectedTechnique>,
    #[serde(default)]
    pub expected_timeline: Vec<ExpectedTimelineEvent>,
    #[serde(default)]
    pub expected_shares: Vec<ExpectedShare>,
    #[serde(default)]
    pub expected_vulnerabilities: Vec<ExpectedVulnerability>,

    /// Minimum acceptable highest pyramid level (default 4).
    #[serde(default = "default_min_pyramid")]
    pub min_pyramid_level: u32,
    /// Target highest pyramid level (default 6).
    #[serde(default = "default_target_pyramid")]
    pub target_pyramid_level: u32,
    /// Minimum acceptable technique coverage 0–1 (default 0.6).
    #[serde(default = "default_min_technique_coverage")]
    pub min_technique_coverage: f64,
    /// Minimum acceptable IOC detection rate 0–1 (default 0.5).
    #[serde(default = "default_min_ioc_detection")]
    pub min_ioc_detection_rate: f64,
}

impl EvaluationGroundTruth {
    /// Get only required IOCs.
    pub fn required_iocs(&self) -> Vec<&ExpectedIOC> {
        self.expected_iocs.iter().filter(|i| i.required).collect()
    }

    /// Get only optional IOCs.
    pub fn optional_iocs(&self) -> Vec<&ExpectedIOC> {
        self.expected_iocs.iter().filter(|i| !i.required).collect()
    }

    /// Get only required techniques.
    pub fn required_techniques(&self) -> Vec<&ExpectedTechnique> {
        self.expected_techniques
            .iter()
            .filter(|t| t.required)
            .collect()
    }

    /// Get only optional techniques.
    pub fn optional_techniques(&self) -> Vec<&ExpectedTechnique> {
        self.expected_techniques
            .iter()
            .filter(|t| !t.required)
            .collect()
    }
}
