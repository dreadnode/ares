//! Ground truth schema and transformation for blue team evaluation.
//!
//! Transforms red team operation state into expected findings that the
//! blue team investigation should detect.

use std::collections::{HashMap, HashSet};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::models::{PyramidLevel, SharedRedTeamState};

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

fn default_true() -> bool {
    true
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

/// Determine if a technique should be required for detection.
pub fn is_technique_required(technique_id: &str) -> bool {
    const REQUIRED_PREFIXES: &[&str] = &[
        "T1003", // OS Credential Dumping
        "T1078", // Valid Accounts
        "T1558", // Steal or Forge Kerberos Tickets
        "T1110", // Brute Force
        "T1021", // Remote Services
        "T1550", // Use Alternate Authentication Material
    ];
    REQUIRED_PREFIXES
        .iter()
        .any(|prefix| technique_id.starts_with(prefix))
}

/// Get MITRE techniques associated with a vulnerability type.
pub fn get_techniques_for_vuln_type(vuln_type: &str) -> Vec<String> {
    static VULN_MAP: std::sync::LazyLock<HashMap<&'static str, Vec<&'static str>>> =
        std::sync::LazyLock::new(|| {
            HashMap::from([
                ("ADCS_ESC1", vec!["T1649"]),
                ("ADCS_ESC2", vec!["T1649"]),
                ("ADCS_ESC3", vec!["T1649"]),
                ("ADCS_ESC4", vec!["T1649"]),
                ("ADCS_ESC6", vec!["T1649"]),
                ("ADCS_ESC7", vec!["T1649"]),
                ("ADCS_ESC8", vec!["T1649"]),
                ("UNCONSTRAINED_DELEGATION", vec!["T1558"]),
                ("CONSTRAINED_DELEGATION", vec!["T1558"]),
                ("RESOURCE_BASED_CONSTRAINED_DELEGATION", vec!["T1558"]),
                ("ACL_ABUSE", vec!["T1222", "T1484"]),
                ("DACL_ABUSE", vec!["T1222", "T1484"]),
                ("WRITEDACL", vec!["T1222"]),
                ("GENERICALL", vec!["T1222", "T1098"]),
                ("GENERICWRITE", vec!["T1222", "T1098"]),
                ("WRITEOWNER", vec!["T1222"]),
                ("KERBEROASTING", vec!["T1558.003"]),
                ("ASREPROASTING", vec!["T1558.004"]),
                ("GPO_ABUSE", vec!["T1484.001"]),
                ("DCSYNC", vec!["T1003.006"]),
                ("PASSWORD_SPRAY", vec!["T1110.003"]),
                ("CREDENTIAL_STUFFING", vec!["T1110.004"]),
            ])
        });

    let key = vuln_type.to_uppercase();
    VULN_MAP
        .get(key.as_str())
        .map(|v| v.iter().map(|s| s.to_string()).collect())
        .unwrap_or_else(|| vec!["T1068".to_string()])
}

/// Transform red team operation state into evaluation ground truth.
///
/// Extracts IOCs, techniques, shares, and vulnerabilities from the red team
/// state to create expected findings for blue team evaluation.
pub fn create_ground_truth_from_red_state(
    state: &SharedRedTeamState,
    identified_techniques: &[String],
) -> EvaluationGroundTruth {
    let mut expected_iocs: Vec<ExpectedIOC> = Vec::new();
    let mut expected_techniques: Vec<ExpectedTechnique> = Vec::new();

    let target_ip = state
        .target
        .as_ref()
        .map(|t| t.ip.clone())
        .unwrap_or_default();

    // Hosts → IP and hostname IOCs
    for host in &state.all_hosts {
        expected_iocs.push(ExpectedIOC {
            ioc_type: "ip".to_string(),
            value: host.ip.clone(),
            pyramid_level: PyramidLevel::IpAddresses,
            mitre_techniques: vec!["T1046".to_string()],
            required: true,
            source: "host_discovery".to_string(),
        });
        if !host.hostname.is_empty() {
            expected_iocs.push(ExpectedIOC {
                ioc_type: "hostname".to_string(),
                value: host.hostname.clone(),
                pyramid_level: PyramidLevel::DomainNames,
                mitre_techniques: vec!["T1046".to_string()],
                required: false,
                source: "host_discovery".to_string(),
            });
        }
    }

    // Users → user IOCs
    for user in &state.all_users {
        expected_iocs.push(ExpectedIOC {
            ioc_type: "user".to_string(),
            value: user.username.clone(),
            pyramid_level: PyramidLevel::NetworkHostArtifacts,
            mitre_techniques: vec!["T1087".to_string()],
            required: user.is_admin,
            source: "user_enumeration".to_string(),
        });
    }

    // Credentials → user IOCs
    for cred in &state.all_credentials {
        expected_iocs.push(ExpectedIOC {
            ioc_type: "user".to_string(),
            value: cred.username.clone(),
            pyramid_level: PyramidLevel::NetworkHostArtifacts,
            mitre_techniques: vec!["T1003".to_string(), "T1110".to_string()],
            required: cred.is_admin,
            source: "credential_harvesting".to_string(),
        });
    }

    // Hashes → hash IOCs
    for hash in &state.all_hashes {
        expected_iocs.push(ExpectedIOC {
            ioc_type: "hash".to_string(),
            value: hash.hash_value.clone(),
            pyramid_level: PyramidLevel::HashValues,
            mitre_techniques: vec!["T1003".to_string()],
            required: false,
            source: "hash_extraction".to_string(),
        });
    }

    // Identified techniques
    for tech_id in identified_techniques {
        let required = is_technique_required(tech_id);
        let parent_id = if tech_id.contains('.') {
            Some(tech_id.split('.').next().unwrap_or("").to_string())
        } else {
            None
        };
        expected_techniques.push(ExpectedTechnique {
            technique_id: tech_id.clone(),
            technique_name: String::new(),
            required,
            parent_id,
        });
    }

    // Domain admin flag → add T1078.002
    if state.has_domain_admin {
        expected_techniques.push(ExpectedTechnique {
            technique_id: "T1078.002".to_string(),
            technique_name: "Valid Accounts: Domain Accounts".to_string(),
            required: true,
            parent_id: None,
        });
    }

    // Golden ticket flag → add T1558.001
    if state.has_golden_ticket {
        expected_techniques.push(ExpectedTechnique {
            technique_id: "T1558.001".to_string(),
            technique_name: "Golden Ticket".to_string(),
            required: true,
            parent_id: None,
        });
    }

    // Shares → expected shares + IOCs
    let mut expected_shares: Vec<ExpectedShare> = Vec::new();
    for share in &state.all_shares {
        let is_writable = share.permissions == "WRITE" || share.permissions == "READ/WRITE";
        expected_shares.push(ExpectedShare {
            host: share.host.clone(),
            name: share.name.clone(),
            permissions: share.permissions.clone(),
            required: is_writable,
        });
        expected_iocs.push(ExpectedIOC {
            ioc_type: "ip".to_string(),
            value: share.host.clone(),
            pyramid_level: PyramidLevel::IpAddresses,
            mitre_techniques: vec!["T1021.002".to_string()],
            required: false,
            source: "share_enumeration".to_string(),
        });
    }

    // Vulnerabilities → expected vulns + techniques
    let mut expected_vulnerabilities: Vec<ExpectedVulnerability> = Vec::new();
    for (vuln_id, vuln) in &state.discovered_vulnerabilities {
        let vuln_techniques = get_techniques_for_vuln_type(&vuln.vuln_type);
        let exploited = state.exploited_vulnerabilities.contains(vuln_id);
        expected_vulnerabilities.push(ExpectedVulnerability {
            vuln_type: vuln.vuln_type.clone(),
            target: vuln.target.clone(),
            mitre_techniques: vuln_techniques.clone(),
            exploited,
            required: exploited,
        });
        for tech_id in &vuln_techniques {
            if !expected_techniques
                .iter()
                .any(|t| t.technique_id == *tech_id)
            {
                let parent_id = if tech_id.contains('.') {
                    Some(tech_id.split('.').next().unwrap_or("").to_string())
                } else {
                    None
                };
                expected_techniques.push(ExpectedTechnique {
                    technique_id: tech_id.clone(),
                    technique_name: String::new(),
                    required: exploited,
                    parent_id,
                });
            }
        }
    }

    // Deduplicate IOCs by value
    let mut seen_values: HashSet<String> = HashSet::new();
    let unique_iocs: Vec<ExpectedIOC> = expected_iocs
        .into_iter()
        .filter(|ioc| seen_values.insert(ioc.value.clone()))
        .collect();

    // Deduplicate techniques by ID
    let mut seen_techniques: HashSet<String> = HashSet::new();
    let unique_techniques: Vec<ExpectedTechnique> = expected_techniques
        .into_iter()
        .filter(|t| seen_techniques.insert(t.technique_id.clone()))
        .collect();

    EvaluationGroundTruth {
        operation_id: state.operation_id.clone(),
        target_ip,
        expected_iocs: unique_iocs,
        expected_techniques: unique_techniques,
        expected_timeline: Vec::new(),
        expected_shares,
        expected_vulnerabilities,
        min_pyramid_level: 4,
        target_pyramid_level: 6,
        min_technique_coverage: 0.6,
        min_ioc_detection_rate: 0.5,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_expected_technique_exact_match() {
        let tech = ExpectedTechnique {
            technique_id: "T1003".to_string(),
            technique_name: "".to_string(),
            required: true,
            parent_id: None,
        };
        assert!(tech.matches("T1003"));
        assert!(!tech.matches("T1110"));
    }

    #[test]
    fn test_expected_technique_parent_child_match() {
        let parent = ExpectedTechnique {
            technique_id: "T1003".to_string(),
            technique_name: "".to_string(),
            required: true,
            parent_id: None,
        };
        assert!(parent.matches("T1003.006"));
        assert!(!parent.matches("T1110.001"));

        let child = ExpectedTechnique {
            technique_id: "T1003.006".to_string(),
            technique_name: "".to_string(),
            required: true,
            parent_id: Some("T1003".to_string()),
        };
        assert!(child.matches("T1003"));
        assert!(!child.matches("T1110"));
    }

    #[test]
    fn test_is_technique_required() {
        assert!(is_technique_required("T1003"));
        assert!(is_technique_required("T1003.006"));
        assert!(is_technique_required("T1558.001"));
        assert!(!is_technique_required("T1046"));
        assert!(!is_technique_required("T1087"));
    }

    #[test]
    fn test_get_techniques_for_vuln_type() {
        assert_eq!(get_techniques_for_vuln_type("ADCS_ESC1"), vec!["T1649"]);
        assert_eq!(
            get_techniques_for_vuln_type("KERBEROASTING"),
            vec!["T1558.003"]
        );
        assert_eq!(get_techniques_for_vuln_type("UNKNOWN_TYPE"), vec!["T1068"]);
    }

    #[test]
    fn test_ground_truth_filters() {
        let gt = EvaluationGroundTruth {
            operation_id: "op-1".to_string(),
            target_ip: "192.168.58.10".to_string(),
            expected_iocs: vec![
                ExpectedIOC {
                    ioc_type: "ip".to_string(),
                    value: "192.168.58.10".to_string(),
                    pyramid_level: PyramidLevel::IpAddresses,
                    mitre_techniques: vec![],
                    required: true,
                    source: "".to_string(),
                },
                ExpectedIOC {
                    ioc_type: "hash".to_string(),
                    value: "abc123".to_string(),
                    pyramid_level: PyramidLevel::HashValues,
                    mitre_techniques: vec![],
                    required: false,
                    source: "".to_string(),
                },
            ],
            expected_techniques: vec![
                ExpectedTechnique {
                    technique_id: "T1003".to_string(),
                    technique_name: "".to_string(),
                    required: true,
                    parent_id: None,
                },
                ExpectedTechnique {
                    technique_id: "T1046".to_string(),
                    technique_name: "".to_string(),
                    required: false,
                    parent_id: None,
                },
            ],
            expected_timeline: vec![],
            expected_shares: vec![],
            expected_vulnerabilities: vec![],
            min_pyramid_level: 4,
            target_pyramid_level: 6,
            min_technique_coverage: 0.6,
            min_ioc_detection_rate: 0.5,
        };

        assert_eq!(gt.required_iocs().len(), 1);
        assert_eq!(gt.optional_iocs().len(), 1);
        assert_eq!(gt.required_techniques().len(), 1);
        assert_eq!(gt.optional_techniques().len(), 1);
    }

    #[test]
    fn test_create_ground_truth_from_red_state() {
        use crate::models::{Credential, Hash, Host, Target, User};

        let mut state = SharedRedTeamState::new("op-test".to_string());
        state.target = Some(Target {
            ip: "192.168.58.10".to_string(),
            hostname: "dc01".to_string(),
            domain: "contoso.local".to_string(),
            environment: String::new(),
        });
        state.all_hosts = vec![Host {
            ip: "192.168.58.10".to_string(),
            hostname: "dc01.contoso.local".to_string(),
            os: String::new(),
            roles: Vec::new(),
            services: Vec::new(),
            is_dc: false,
            owned: false,
        }];
        state.all_users = vec![User {
            username: "admin".to_string(),
            domain: "contoso.local".to_string(),
            description: String::new(),
            is_admin: true,
            source: String::new(),
        }];
        state.all_credentials = vec![Credential {
            id: String::new(),
            username: "svc_sql".to_string(),
            password: String::new(),
            domain: String::new(),
            source: String::new(),
            discovered_at: None,
            is_admin: false,
            parent_id: None,
            attack_step: 0,
        }];
        state.all_hashes = vec![Hash {
            id: String::new(),
            username: "admin".to_string(),
            hash_value: "aad3b435b51404eeaad3b435b51404ee:abc".to_string(),
            hash_type: "NTLM".to_string(),
            domain: String::new(),
            cracked_password: None,
            source: String::new(),
            discovered_at: None,
            parent_id: None,
            attack_step: 0,
            aes_key: None,
        }];
        state.has_domain_admin = true;

        let techniques = vec!["T1003".to_string(), "T1046".to_string()];
        let gt = create_ground_truth_from_red_state(&state, &techniques);

        assert_eq!(gt.operation_id, "op-test");
        assert_eq!(gt.target_ip, "192.168.58.10");

        // 1 host IP + 1 hostname + 1 user(admin) + 1 credential(svc_sql) + 1 hash
        assert!(
            gt.expected_iocs.len() >= 4,
            "Got {} IOCs",
            gt.expected_iocs.len()
        );

        // T1003, T1046, T1078.002 (from domain_admin flag)
        assert!(
            gt.expected_techniques.len() >= 3,
            "Got {} techniques",
            gt.expected_techniques.len()
        );

        // T1003 should be required, T1046 should not
        let t1003 = gt
            .expected_techniques
            .iter()
            .find(|t| t.technique_id == "T1003")
            .unwrap();
        assert!(t1003.required);
        let t1046 = gt
            .expected_techniques
            .iter()
            .find(|t| t.technique_id == "T1046")
            .unwrap();
        assert!(!t1046.required);

        // T1078.002 added from domain_admin flag
        assert!(gt
            .expected_techniques
            .iter()
            .any(|t| t.technique_id == "T1078.002"));
    }

    #[test]
    fn test_create_ground_truth_deduplicates() {
        use crate::models::{Credential, Host, User};

        let mut state = SharedRedTeamState::new("op-dedup".to_string());
        state.all_hosts = vec![Host {
            ip: "192.168.58.10".to_string(),
            hostname: "dc01".to_string(),
            os: String::new(),
            roles: Vec::new(),
            services: Vec::new(),
            is_dc: false,
            owned: false,
        }];
        state.all_users = vec![User {
            username: "admin".to_string(),
            domain: "contoso.local".to_string(),
            description: String::new(),
            is_admin: false,
            source: String::new(),
        }];
        state.all_credentials = vec![Credential {
            id: String::new(),
            username: "admin".to_string(),
            password: String::new(),
            domain: String::new(),
            source: String::new(),
            discovered_at: None,
            is_admin: false,
            parent_id: None,
            attack_step: 0,
        }];

        let gt = create_ground_truth_from_red_state(&state, &[]);
        // "admin" should appear only once due to dedup
        let admin_iocs: Vec<_> = gt
            .expected_iocs
            .iter()
            .filter(|i| i.value == "admin")
            .collect();
        assert_eq!(admin_iocs.len(), 1, "admin IOC should be deduplicated");
    }
}
