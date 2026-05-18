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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{Credential, Hash, Host, Share, SharedRedTeamState, User};

    fn empty_state() -> SharedRedTeamState {
        SharedRedTeamState::new("op-test".to_string())
    }

    // ── basic ──────────────────────────────────────────────────────

    #[test]
    fn empty_state_produces_empty_gt() {
        let state = empty_state();
        let gt = create_ground_truth_from_red_state(&state, &[]);
        assert_eq!(gt.operation_id, "op-test");
        assert!(gt.expected_iocs.is_empty());
        assert!(gt.expected_techniques.is_empty());
        assert!(gt.expected_shares.is_empty());
        assert!(gt.expected_vulnerabilities.is_empty());
    }

    // ── hosts → IOCs ───────────────────────────────────────────────

    #[test]
    fn hosts_produce_ip_iocs() {
        let mut state = empty_state();
        state.all_hosts.push(Host {
            ip: "192.168.58.1".to_string(),
            hostname: String::new(),
            os: String::new(),
            roles: vec![],
            services: vec![],
            is_dc: false,
            owned: false,
        });
        let gt = create_ground_truth_from_red_state(&state, &[]);
        assert_eq!(gt.expected_iocs.len(), 1);
        assert_eq!(gt.expected_iocs[0].ioc_type, "ip");
        assert_eq!(gt.expected_iocs[0].value, "192.168.58.1");
        assert!(gt.expected_iocs[0].required);
    }

    #[test]
    fn hosts_with_hostname_produce_two_iocs() {
        let mut state = empty_state();
        state.all_hosts.push(Host {
            ip: "192.168.58.1".to_string(),
            hostname: "dc01.contoso.local".to_string(),
            os: String::new(),
            roles: vec![],
            services: vec![],
            is_dc: false,
            owned: false,
        });
        let gt = create_ground_truth_from_red_state(&state, &[]);
        assert_eq!(gt.expected_iocs.len(), 2);
        let types: Vec<_> = gt.expected_iocs.iter().map(|i| &i.ioc_type).collect();
        assert!(types.contains(&&"ip".to_string()));
        assert!(types.contains(&&"hostname".to_string()));
    }

    // ── users → IOCs ───────────────────────────────────────────────

    #[test]
    fn users_produce_user_iocs() {
        let mut state = empty_state();
        state.all_users.push(User {
            username: "admin".to_string(),
            domain: "contoso.local".to_string(),
            description: String::new(),
            is_admin: true,
            source: String::new(),
        });
        let gt = create_ground_truth_from_red_state(&state, &[]);
        let user_iocs: Vec<_> = gt
            .expected_iocs
            .iter()
            .filter(|i| i.ioc_type == "user")
            .collect();
        assert_eq!(user_iocs.len(), 1);
        assert!(user_iocs[0].required); // admin → required
    }

    #[test]
    fn non_admin_user_not_required() {
        let mut state = empty_state();
        state.all_users.push(User {
            username: "jsmith".to_string(),
            domain: "contoso.local".to_string(),
            description: String::new(),
            is_admin: false,
            source: String::new(),
        });
        let gt = create_ground_truth_from_red_state(&state, &[]);
        let user_iocs: Vec<_> = gt
            .expected_iocs
            .iter()
            .filter(|i| i.ioc_type == "user")
            .collect();
        assert!(!user_iocs[0].required);
    }

    // ── credentials → IOCs ─────────────────────────────────────────

    #[test]
    fn credentials_produce_user_iocs() {
        let mut state = empty_state();
        state.all_credentials.push(Credential {
            id: "c1".to_string(),
            username: "svc_account".to_string(),
            password: "pass123".to_string(),
            domain: "contoso.local".to_string(),
            source: String::new(),
            discovered_at: None,
            is_admin: false,
            parent_id: None,
            attack_step: 0,
        });
        let gt = create_ground_truth_from_red_state(&state, &[]);
        let user_iocs: Vec<_> = gt
            .expected_iocs
            .iter()
            .filter(|i| i.ioc_type == "user")
            .collect();
        assert_eq!(user_iocs.len(), 1);
        assert_eq!(user_iocs[0].value, "svc_account");
    }

    // ── hashes → IOCs ──────────────────────────────────────────────

    #[test]
    fn hashes_produce_hash_iocs() {
        let mut state = empty_state();
        state.all_hashes.push(Hash {
            id: "h1".to_string(),
            username: "admin".to_string(),
            hash_value: "aabbccdd11223344".to_string(),
            hash_type: "ntlm".to_string(),
            domain: "contoso.local".to_string(),
            source: String::new(),
            cracked_password: None,
            discovered_at: None,
            parent_id: None,
            attack_step: 0,
            aes_key: None,
            is_previous: false,
            source_host: None,
            is_trust_key: false,
            trust_pair_label: None,
        });
        let gt = create_ground_truth_from_red_state(&state, &[]);
        let hash_iocs: Vec<_> = gt
            .expected_iocs
            .iter()
            .filter(|i| i.ioc_type == "hash")
            .collect();
        assert_eq!(hash_iocs.len(), 1);
        assert!(!hash_iocs[0].required);
    }

    // ── techniques ─────────────────────────────────────────────────

    #[test]
    fn identified_techniques_produce_expected() {
        let state = empty_state();
        let gt =
            create_ground_truth_from_red_state(&state, &["T1003".to_string(), "T1046".to_string()]);
        assert_eq!(gt.expected_techniques.len(), 2);
    }

    #[test]
    fn sub_technique_has_parent_id() {
        let state = empty_state();
        let gt = create_ground_truth_from_red_state(&state, &["T1003.006".to_string()]);
        assert_eq!(
            gt.expected_techniques[0].parent_id,
            Some("T1003".to_string())
        );
    }

    #[test]
    fn parent_technique_has_no_parent_id() {
        let state = empty_state();
        let gt = create_ground_truth_from_red_state(&state, &["T1003".to_string()]);
        assert!(gt.expected_techniques[0].parent_id.is_none());
    }

    // ── domain admin / golden ticket flags ──────────────────────────

    #[test]
    fn domain_admin_adds_technique() {
        let mut state = empty_state();
        state.has_domain_admin = true;
        let gt = create_ground_truth_from_red_state(&state, &[]);
        assert!(gt
            .expected_techniques
            .iter()
            .any(|t| t.technique_id == "T1078.002"));
    }

    #[test]
    fn golden_ticket_adds_technique() {
        let mut state = empty_state();
        state.has_golden_ticket = true;
        let gt = create_ground_truth_from_red_state(&state, &[]);
        assert!(gt
            .expected_techniques
            .iter()
            .any(|t| t.technique_id == "T1558.001"));
    }

    // ── shares ─────────────────────────────────────────────────────

    #[test]
    fn shares_produce_expected_shares() {
        let mut state = empty_state();
        state.all_shares.push(Share {
            host: "192.168.58.1".to_string(),
            name: "ADMIN$".to_string(),
            permissions: "READ/WRITE".to_string(),
            comment: String::new(),
            authenticated_as: None,
        });
        let gt = create_ground_truth_from_red_state(&state, &[]);
        assert_eq!(gt.expected_shares.len(), 1);
        assert!(gt.expected_shares[0].required); // writable → required
    }

    #[test]
    fn readonly_share_not_required() {
        let mut state = empty_state();
        state.all_shares.push(Share {
            host: "192.168.58.1".to_string(),
            name: "SYSVOL".to_string(),
            permissions: "READ".to_string(),
            comment: String::new(),
            authenticated_as: None,
        });
        let gt = create_ground_truth_from_red_state(&state, &[]);
        assert!(!gt.expected_shares[0].required);
    }

    // ── deduplication ──────────────────────────────────────────────

    #[test]
    fn deduplicates_iocs_by_value() {
        let mut state = empty_state();
        // Same IP from host and share
        state.all_hosts.push(Host {
            ip: "192.168.58.1".to_string(),
            hostname: String::new(),
            os: String::new(),
            roles: vec![],
            services: vec![],
            is_dc: false,
            owned: false,
        });
        state.all_shares.push(Share {
            host: "192.168.58.1".to_string(),
            name: "C$".to_string(),
            permissions: "READ".to_string(),
            comment: String::new(),
            authenticated_as: None,
        });
        let gt = create_ground_truth_from_red_state(&state, &[]);
        let ip_count = gt
            .expected_iocs
            .iter()
            .filter(|i| i.value == "192.168.58.1")
            .count();
        assert_eq!(ip_count, 1);
    }

    #[test]
    fn deduplicates_techniques_by_id() {
        let mut state = empty_state();
        state.has_domain_admin = true;
        // Also explicitly identified T1078.002
        let gt = create_ground_truth_from_red_state(&state, &["T1078.002".to_string()]);
        let t1078_count = gt
            .expected_techniques
            .iter()
            .filter(|t| t.technique_id == "T1078.002")
            .count();
        assert_eq!(t1078_count, 1);
    }
}
