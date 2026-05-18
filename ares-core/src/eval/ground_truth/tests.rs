use super::mappings::{get_techniques_for_vuln_type, is_technique_required};
use super::schema::{EvaluationGroundTruth, ExpectedIOC, ExpectedTechnique};
use super::transform::create_ground_truth_from_red_state;
use crate::models::PyramidLevel;

#[test]
fn expected_technique_exact_match() {
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
fn expected_technique_parent_child_match() {
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
fn technique_is_required() {
    assert!(is_technique_required("T1003"));
    assert!(is_technique_required("T1003.006"));
    assert!(is_technique_required("T1558.001"));
    assert!(!is_technique_required("T1046"));
    assert!(!is_technique_required("T1087"));
}

#[test]
fn techniques_for_vuln_type() {
    assert_eq!(get_techniques_for_vuln_type("ADCS_ESC1"), vec!["T1649"]);
    assert_eq!(
        get_techniques_for_vuln_type("KERBEROASTING"),
        vec!["T1558.003"]
    );
    assert_eq!(get_techniques_for_vuln_type("UNKNOWN_TYPE"), vec!["T1068"]);
}

#[test]
fn ground_truth_filters() {
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
fn creates_ground_truth_from_red_state() {
    use crate::models::{Credential, Hash, Host, SharedRedTeamState, Target, User};

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
        is_previous: false,
        source_host: None,
        is_trust_key: false,
        trust_pair_label: None,
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
fn create_ground_truth_deduplicates() {
    use crate::models::{Credential, Host, SharedRedTeamState, User};

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
    let admin_count = gt
        .expected_iocs
        .iter()
        .filter(|i| i.value == "admin")
        .count();
    assert_eq!(admin_count, 1, "admin IOC should be deduplicated");
}

#[test]
fn golden_ticket_adds_t1558_001_technique() {
    use crate::models::SharedRedTeamState;

    let mut state = SharedRedTeamState::new("op-gt".to_string());
    state.has_golden_ticket = true;

    let gt = create_ground_truth_from_red_state(&state, &[]);

    let golden = gt
        .expected_techniques
        .iter()
        .find(|t| t.technique_id == "T1558.001");
    assert!(
        golden.is_some(),
        "T1558.001 must be present when has_golden_ticket is true"
    );
    let golden = golden.unwrap();
    assert!(golden.required, "T1558.001 must be required");
    assert_eq!(golden.technique_name, "Golden Ticket");
}

#[test]
fn writable_share_is_marked_required() {
    use crate::models::{Share, SharedRedTeamState};

    let mut state = SharedRedTeamState::new("op-shares".to_string());
    state.all_shares = vec![
        Share {
            host: "192.168.58.20".to_string(),
            name: "NETLOGON".to_string(),
            permissions: "READ".to_string(),
            comment: String::new(),
            authenticated_as: None,
        },
        Share {
            host: "192.168.58.21".to_string(),
            name: "DATA".to_string(),
            permissions: "READ/WRITE".to_string(),
            comment: String::new(),
            authenticated_as: None,
        },
        Share {
            host: "192.168.58.22".to_string(),
            name: "BACKUP".to_string(),
            permissions: "WRITE".to_string(),
            comment: String::new(),
            authenticated_as: None,
        },
        Share {
            host: "192.168.58.23".to_string(),
            name: "PUBLIC".to_string(),
            permissions: "READ ONLY".to_string(),
            comment: String::new(),
            authenticated_as: None,
        },
    ];

    let gt = create_ground_truth_from_red_state(&state, &[]);
    assert_eq!(gt.expected_shares.len(), 4);

    let find = |name: &str| {
        gt.expected_shares
            .iter()
            .find(|s| s.name == name)
            .unwrap_or_else(|| panic!("share '{}' missing", name))
    };

    // READ alone is not writable in the codebase logic — only WRITE or READ/WRITE
    assert!(
        !find("NETLOGON").required,
        "READ-only share must not be required"
    );
    assert!(find("DATA").required, "READ/WRITE share must be required");
    assert!(find("BACKUP").required, "WRITE share must be required");
    assert!(
        !find("PUBLIC").required,
        "READ ONLY share must not be required"
    );
}

#[test]
fn technique_deduplication_across_vulns() {
    use crate::models::{SharedRedTeamState, VulnerabilityInfo};
    use std::collections::HashMap;

    let mut state = SharedRedTeamState::new("op-dedup-tech".to_string());

    // Two different vulns that both map to T1558.003 (KERBEROASTING)
    let mut vulns: HashMap<String, VulnerabilityInfo> = HashMap::new();
    vulns.insert(
        "vuln-1".to_string(),
        VulnerabilityInfo {
            vuln_id: "vuln-1".to_string(),
            vuln_type: "KERBEROASTING".to_string(),
            target: "svc_http".to_string(),
            discovered_by: String::new(),
            discovered_at: chrono::Utc::now(),
            details: HashMap::new(),
            recommended_agent: String::new(),
            priority: 1,
        },
    );
    vulns.insert(
        "vuln-2".to_string(),
        VulnerabilityInfo {
            vuln_id: "vuln-2".to_string(),
            vuln_type: "KERBEROASTING".to_string(),
            target: "svc_sql".to_string(),
            discovered_by: String::new(),
            discovered_at: chrono::Utc::now(),
            details: HashMap::new(),
            recommended_agent: String::new(),
            priority: 1,
        },
    );
    state.discovered_vulnerabilities = vulns;

    let gt = create_ground_truth_from_red_state(&state, &[]);

    // T1558.003 from both vulns must appear exactly once after deduplication
    let t1558_count = gt
        .expected_techniques
        .iter()
        .filter(|t| t.technique_id == "T1558.003")
        .count();
    assert_eq!(
        t1558_count, 1,
        "T1558.003 must be deduplicated across vulns: found {} copies",
        t1558_count
    );
}
