//! Transform red team operation state into evaluation ground truth.

use std::collections::HashSet;

use crate::models::{PyramidLevel, SharedRedTeamState};

use super::mappings::{get_techniques_for_vuln_type, is_technique_required};
use super::schema::{
    EvaluationGroundTruth, ExpectedIOC, ExpectedShare, ExpectedTechnique, ExpectedVulnerability,
};

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
