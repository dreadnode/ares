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
    /// Groups of equivalent host identifiers (IP, hostname, short name) so a
    /// hostname finding can be credited against that host's IP IOC, and vice
    /// versa.
    #[serde(default)]
    pub host_aliases: Vec<Vec<String>>,

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

#[cfg(test)]
mod tests {
    use super::*;

    fn make_technique(id: &str, required: bool) -> ExpectedTechnique {
        ExpectedTechnique {
            technique_id: id.to_string(),
            technique_name: String::new(),
            required,
            parent_id: None,
        }
    }

    fn make_ioc(ioc_type: &str, value: &str, required: bool) -> ExpectedIOC {
        ExpectedIOC {
            ioc_type: ioc_type.to_string(),
            value: value.to_string(),
            pyramid_level: PyramidLevel::IpAddresses,
            mitre_techniques: vec![],
            required,
            source: String::new(),
        }
    }

    fn make_gt() -> EvaluationGroundTruth {
        EvaluationGroundTruth {
            operation_id: "op-1".to_string(),
            host_aliases: vec![],
            target_ip: "192.168.58.1".to_string(),
            expected_iocs: vec![
                make_ioc("ip", "192.168.58.1", true),
                make_ioc("user", "admin", true),
                make_ioc("hash", "abc", false),
            ],
            expected_techniques: vec![
                make_technique("T1003", true),
                make_technique("T1046", false),
            ],
            expected_timeline: vec![],
            expected_shares: vec![],
            expected_vulnerabilities: vec![],
            min_pyramid_level: 4,
            target_pyramid_level: 6,
            min_technique_coverage: 0.6,
            min_ioc_detection_rate: 0.5,
        }
    }

    #[test]
    fn matches_exact_technique_id() {
        let t = make_technique("T1003", true);
        assert!(t.matches("T1003"));
    }

    #[test]
    fn matches_parent_to_subtechnique() {
        let t = make_technique("T1003", true);
        assert!(t.matches("T1003.001"));
    }

    #[test]
    fn matches_subtechnique_to_parent() {
        let t = make_technique("T1003.001", true);
        assert!(t.matches("T1003"));
    }

    #[test]
    fn no_match_unrelated_technique() {
        let t = make_technique("T1003", true);
        assert!(!t.matches("T1046"));
    }

    #[test]
    fn no_match_different_subtechnique() {
        let t = make_technique("T1003.001", true);
        assert!(!t.matches("T1003.002"));
    }

    #[test]
    fn required_iocs_filters_correctly() {
        let gt = make_gt();
        let required = gt.required_iocs();
        assert_eq!(required.len(), 2);
        assert!(required.iter().all(|i| i.required));
    }

    #[test]
    fn optional_iocs_filters_correctly() {
        let gt = make_gt();
        let optional = gt.optional_iocs();
        assert_eq!(optional.len(), 1);
        assert!(optional.iter().all(|i| !i.required));
    }

    #[test]
    fn required_techniques_filters_correctly() {
        let gt = make_gt();
        let required = gt.required_techniques();
        assert_eq!(required.len(), 1);
        assert_eq!(required[0].technique_id, "T1003");
    }

    #[test]
    fn optional_techniques_filters_correctly() {
        let gt = make_gt();
        let optional = gt.optional_techniques();
        assert_eq!(optional.len(), 1);
        assert_eq!(optional[0].technique_id, "T1046");
    }

    #[test]
    fn empty_iocs_returns_empty() {
        let mut gt = make_gt();
        gt.expected_iocs.clear();
        assert!(gt.required_iocs().is_empty());
        assert!(gt.optional_iocs().is_empty());
    }

    #[test]
    fn empty_techniques_returns_empty() {
        let mut gt = make_gt();
        gt.expected_techniques.clear();
        assert!(gt.required_techniques().is_empty());
        assert!(gt.optional_techniques().is_empty());
    }
}
