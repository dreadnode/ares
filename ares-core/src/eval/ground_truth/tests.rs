use super::mappings::{get_techniques_for_vuln_type, is_technique_required};
use super::schema::{EvaluationGroundTruth, ExpectedIOC, ExpectedTechnique};
use super::transform::create_ground_truth_from_red_state;
use crate::models::PyramidLevel;

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
    let admin_iocs: Vec<_> = gt
        .expected_iocs
        .iter()
        .filter(|i| i.value == "admin")
        .collect();
    assert_eq!(admin_iocs.len(), 1, "admin IOC should be deduplicated");
}
