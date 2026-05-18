use chrono::Utc;

use super::builders::build_technique_detections;
use super::credential::{
    build_t1003, build_t1003_001, build_t1003_006, build_t1078, build_t1078_002, build_t1110,
};
use super::kerberos::{build_t1558, build_t1558_001};
use super::lateral::{
    build_t1021, build_t1021_002, build_t1046, build_t1550, build_t1550_002, build_t1649,
};
use super::names::{get_technique_name, pyramid_level_name};
use ares_core::models::{Credential, Host, Share, SharedRedTeamState};

// ---------------------------------------------------------------------------
// names
// ---------------------------------------------------------------------------

#[test]
fn get_technique_name_known() {
    assert_eq!(get_technique_name("T1046"), "Network Service Discovery");
    assert_eq!(get_technique_name("T1003"), "OS Credential Dumping");
    assert_eq!(get_technique_name("T1003.001"), "LSASS Memory");
    assert_eq!(get_technique_name("T1003.006"), "DCSync");
    assert_eq!(get_technique_name("T1078"), "Valid Accounts");
    assert_eq!(get_technique_name("T1078.002"), "Domain Accounts");
    assert_eq!(get_technique_name("T1110"), "Brute Force");
    assert_eq!(
        get_technique_name("T1558"),
        "Steal or Forge Kerberos Tickets"
    );
    assert_eq!(get_technique_name("T1558.001"), "Golden Ticket");
    assert_eq!(get_technique_name("T1558.003"), "Kerberoasting");
    assert_eq!(get_technique_name("T1558.004"), "AS-REP Roasting");
    assert_eq!(get_technique_name("T1021"), "Remote Services");
    assert_eq!(get_technique_name("T1021.002"), "SMB/Windows Admin Shares");
    assert_eq!(get_technique_name("T1649"), "ADCS Certificate Theft");
    assert_eq!(
        get_technique_name("T1550"),
        "Use Alternate Authentication Material"
    );
    assert_eq!(get_technique_name("T1550.002"), "Pass the Hash");
    assert_eq!(get_technique_name("T1484"), "Domain Policy Modification");
    assert_eq!(get_technique_name("T1087"), "Account Discovery");
}

#[test]
fn get_technique_name_unknown() {
    assert_eq!(get_technique_name("T9999"), "");
    assert_eq!(get_technique_name(""), "");
}

#[test]
fn pyramid_level_name_all_levels() {
    assert_eq!(pyramid_level_name(1), "Hash Values (L1)");
    assert_eq!(pyramid_level_name(2), "IP Addresses (L2)");
    assert_eq!(pyramid_level_name(3), "Domain Names (L3)");
    assert_eq!(pyramid_level_name(4), "Network/Host Artifacts (L4)");
    assert_eq!(pyramid_level_name(5), "Tools (L5)");
    assert_eq!(pyramid_level_name(6), "TTPs (L6)");
}

#[test]
fn pyramid_level_name_unknown() {
    assert_eq!(pyramid_level_name(0), "Unknown");
    assert_eq!(pyramid_level_name(7), "Unknown");
    assert_eq!(pyramid_level_name(255), "Unknown");
}

// ---------------------------------------------------------------------------
// builders (router)
// ---------------------------------------------------------------------------

#[test]
fn build_technique_detections_known_techniques() {
    let state = SharedRedTeamState::new("test-op".to_string());
    let start = Utc::now() - chrono::Duration::hours(1);
    let end = Utc::now();
    let techniques = vec!["T1046".to_string(), "T1003".to_string()];
    let detections = build_technique_detections(&state, &techniques, &start, &end);
    assert_eq!(detections.len(), 2);
    assert!(detections.contains_key("T1046"));
    assert!(detections.contains_key("T1003"));
    assert_eq!(
        detections["T1046"].technique_name,
        "Network Service Discovery"
    );
    assert!(!detections["T1046"].detection_queries.is_empty());
}

#[test]
fn build_technique_detections_sub_technique() {
    let state = SharedRedTeamState::new("test-op".to_string());
    let start = Utc::now() - chrono::Duration::hours(1);
    let end = Utc::now();
    let techniques = vec!["T1003.006".to_string()];
    let detections = build_technique_detections(&state, &techniques, &start, &end);
    assert_eq!(detections.len(), 1);
    assert_eq!(detections["T1003.006"].technique_name, "DCSync");
}

#[test]
fn build_technique_detections_empty() {
    let state = SharedRedTeamState::new("test-op".to_string());
    let start = Utc::now();
    let end = Utc::now();
    let detections = build_technique_detections(&state, &[], &start, &end);
    assert!(detections.is_empty());
}

#[test]
fn technique_detection_has_event_ids() {
    let state = SharedRedTeamState::new("test-op".to_string());
    let start = Utc::now() - chrono::Duration::hours(1);
    let end = Utc::now();
    let techniques = vec!["T1558.003".to_string()];
    let detections = build_technique_detections(&state, &techniques, &start, &end);
    let det = &detections["T1558.003"];
    assert!(!det.windows_event_ids.is_empty());
    assert!(!det.log_sources.is_empty());
}

#[test]
fn build_technique_detections_unknown_technique_fallback() {
    let state = SharedRedTeamState::new("test-op".to_string());
    let start = Utc::now() - chrono::Duration::hours(1);
    let end = Utc::now();
    let techniques = vec!["T9999".to_string()];
    let detections = build_technique_detections(&state, &techniques, &start, &end);
    assert_eq!(detections.len(), 1);
    let det = &detections["T9999"];
    assert_eq!(det.technique_id, "T9999");
    // Unknown technique has no detection queries but does have guidance text
    assert!(det.detection_queries.is_empty());
    assert!(det.detection_guidance.contains("T9999"));
}

#[test]
fn build_technique_detections_unknown_sub_technique_fallback() {
    // A sub-technique whose parent is also unknown falls through to the generic branch.
    let state = SharedRedTeamState::new("test-op".to_string());
    let start = Utc::now() - chrono::Duration::hours(1);
    let end = Utc::now();
    let techniques = vec!["T9999.001".to_string()];
    let detections = build_technique_detections(&state, &techniques, &start, &end);
    assert_eq!(detections.len(), 1);
    let det = &detections["T9999.001"];
    assert_eq!(det.technique_id, "T9999.001");
    assert!(det.detection_queries.is_empty());
}

#[test]
fn build_technique_detections_unknown_sub_technique_known_parent() {
    // A sub-technique with known parent (e.g. T1003.099) delegates to parent builder.
    let state = SharedRedTeamState::new("test-op".to_string());
    let start = Utc::now() - chrono::Duration::hours(1);
    let end = Utc::now();
    let techniques = vec!["T1003.099".to_string()];
    let detections = build_technique_detections(&state, &techniques, &start, &end);
    assert_eq!(detections.len(), 1);
    let det = &detections["T1003.099"];
    // Routed to build_t1003, so it gets its real technique_id and queries.
    assert_eq!(det.technique_id, "T1003");
    assert!(!det.detection_queries.is_empty());
}

#[test]
fn build_technique_detections_all_lateral_techniques() {
    let state = SharedRedTeamState::new("test-op".to_string());
    let start = Utc::now() - chrono::Duration::hours(1);
    let end = Utc::now();
    let techniques = vec![
        "T1021".to_string(),
        "T1021.002".to_string(),
        "T1649".to_string(),
        "T1550".to_string(),
        "T1550.002".to_string(),
        "T1046".to_string(),
    ];
    let detections = build_technique_detections(&state, &techniques, &start, &end);
    assert_eq!(detections.len(), 6);
    for id in &techniques {
        assert!(detections.contains_key(id.as_str()), "missing {id}");
        assert!(!detections[id.as_str()].detection_queries.is_empty());
    }
}

#[test]
fn build_technique_detections_all_credential_techniques() {
    let state = SharedRedTeamState::new("test-op".to_string());
    let start = Utc::now() - chrono::Duration::hours(1);
    let end = Utc::now();
    let techniques = vec![
        "T1003".to_string(),
        "T1003.001".to_string(),
        "T1003.006".to_string(),
        "T1078".to_string(),
        "T1078.002".to_string(),
        "T1110".to_string(),
    ];
    let detections = build_technique_detections(&state, &techniques, &start, &end);
    assert_eq!(detections.len(), 6);
    for id in &techniques {
        assert!(detections.contains_key(id.as_str()), "missing {id}");
        assert!(!detections[id.as_str()].detection_queries.is_empty());
    }
}

#[test]
fn build_technique_detections_all_kerberos_techniques() {
    let state = SharedRedTeamState::new("test-op".to_string());
    let start = Utc::now() - chrono::Duration::hours(1);
    let end = Utc::now();
    let techniques = vec![
        "T1558".to_string(),
        "T1558.001".to_string(),
        "T1558.003".to_string(),
    ];
    let detections = build_technique_detections(&state, &techniques, &start, &end);
    assert_eq!(detections.len(), 3);
    for id in &techniques {
        assert!(detections.contains_key(id.as_str()), "missing {id}");
        assert!(!detections[id.as_str()].detection_queries.is_empty());
    }
}

// ---------------------------------------------------------------------------
// lateral.rs — direct builder tests
// ---------------------------------------------------------------------------

#[test]
fn build_t1021_empty_state() {
    let state = SharedRedTeamState::new("test-op".to_string());
    let start = Utc::now() - chrono::Duration::hours(1);
    let end = Utc::now();
    let det = build_t1021(&state, &start, &end);
    assert_eq!(det.technique_id, "T1021");
    assert_eq!(det.technique_name, "Remote Services");
    assert!(det.targets.is_empty());
    assert!(!det.detection_queries.is_empty());
    assert!(det.windows_event_ids.contains(&"4624".to_string()));
    assert!(det.log_sources.contains(&"windows-security".to_string()));
    assert_eq!(det.detection_queries[0].windows_event_ids, vec!["4624"]);
}

#[test]
fn build_t1021_populated_hosts() {
    let mut state = SharedRedTeamState::new("test-op".to_string());
    state.all_hosts.push(Host {
        ip: "192.168.58.10".to_string(),
        hostname: "dc01.contoso.local".to_string(),
        os: String::new(),
        roles: vec![],
        services: vec![],
        is_dc: true,
        owned: false,
    });
    state.all_hosts.push(Host {
        ip: "192.168.58.20".to_string(),
        hostname: "srv01.contoso.local".to_string(),
        os: String::new(),
        roles: vec![],
        services: vec![],
        is_dc: false,
        owned: false,
    });
    let start = Utc::now() - chrono::Duration::hours(1);
    let end = Utc::now();
    let det = build_t1021(&state, &start, &end);
    assert_eq!(det.targets.len(), 2);
    assert!(det.targets.contains(&"192.168.58.10".to_string()));
    assert!(det.targets.contains(&"192.168.58.20".to_string()));
}

#[test]
fn build_t1021_002_empty_state() {
    let state = SharedRedTeamState::new("test-op".to_string());
    let start = Utc::now() - chrono::Duration::hours(1);
    let end = Utc::now();
    let det = build_t1021_002(&state, &start, &end);
    assert_eq!(det.technique_id, "T1021.002");
    assert_eq!(det.technique_name, "SMB/Windows Admin Shares");
    assert!(det.targets.is_empty());
    assert!(!det.detection_queries.is_empty());
    assert!(det.windows_event_ids.contains(&"5140".to_string()));
    assert!(det.windows_event_ids.contains(&"5145".to_string()));
    assert!(det.log_sources.contains(&"windows-security".to_string()));
    // No shares in state → expected_evidence is empty
    assert!(det.detection_queries[0].expected_evidence.is_empty());
}

#[test]
fn build_t1021_002_populated_hosts_and_shares() {
    let mut state = SharedRedTeamState::new("test-op".to_string());
    state.all_hosts.push(Host {
        ip: "192.168.58.10".to_string(),
        hostname: "dc01.contoso.local".to_string(),
        os: String::new(),
        roles: vec![],
        services: vec![],
        is_dc: true,
        owned: false,
    });
    state.all_shares.push(Share {
        host: "192.168.58.10".to_string(),
        name: "C$".to_string(),
        permissions: "READ".to_string(),
        comment: String::new(),
        authenticated_as: None,
    });
    state.all_shares.push(Share {
        host: "192.168.58.10".to_string(),
        name: "ADMIN$".to_string(),
        permissions: "READ".to_string(),
        comment: String::new(),
        authenticated_as: None,
    });
    let start = Utc::now() - chrono::Duration::hours(1);
    let end = Utc::now();
    let det = build_t1021_002(&state, &start, &end);
    assert_eq!(det.targets.len(), 1);
    assert_eq!(
        det.detection_queries[0].expected_evidence.len(),
        2,
        "expected one evidence entry per share"
    );
    assert!(det.detection_queries[0].expected_evidence[0].contains("192.168.58.10"));
}

#[test]
fn build_t1021_002_share_evidence_capped_at_five() {
    let mut state = SharedRedTeamState::new("test-op".to_string());
    for i in 0..8u8 {
        state.all_shares.push(Share {
            host: format!("192.168.58.{i}"),
            name: format!("SHARE{i}"),
            permissions: "READ".to_string(),
            comment: String::new(),
            authenticated_as: None,
        });
    }
    let start = Utc::now() - chrono::Duration::hours(1);
    let end = Utc::now();
    let det = build_t1021_002(&state, &start, &end);
    // build_t1021_002 takes at most 5 shares
    assert_eq!(det.detection_queries[0].expected_evidence.len(), 5);
}

#[test]
fn build_t1649_properties() {
    let start = Utc::now() - chrono::Duration::hours(1);
    let end = Utc::now();
    let det = build_t1649(&start, &end);
    assert_eq!(det.technique_id, "T1649");
    assert_eq!(
        det.technique_name,
        "Steal or Forge Authentication Certificates"
    );
    assert!(det.targets.is_empty());
    assert!(!det.detection_queries.is_empty());
    assert!(det.windows_event_ids.contains(&"4886".to_string()));
    assert!(det.windows_event_ids.contains(&"4887".to_string()));
    assert!(det.windows_event_ids.contains(&"4768".to_string()));
    assert!(det.log_sources.contains(&"windows-security".to_string()));
    assert!(det.log_sources.contains(&"ad-cs".to_string()));
    assert_eq!(det.detection_queries[0].priority, "critical");
}

#[test]
fn build_t1550_properties() {
    let start = Utc::now() - chrono::Duration::hours(1);
    let end = Utc::now();
    let det = build_t1550(&start, &end);
    assert_eq!(det.technique_id, "T1550");
    assert_eq!(det.technique_name, "Use Alternate Authentication Material");
    assert!(!det.detection_queries.is_empty());
    assert!(det.windows_event_ids.contains(&"4624".to_string()));
    assert!(det.windows_event_ids.contains(&"4648".to_string()));
    assert!(det.log_sources.contains(&"windows-security".to_string()));
    assert_eq!(det.detection_queries[0].priority, "critical");
}

#[test]
fn build_t1550_002_properties() {
    let start = Utc::now() - chrono::Duration::hours(1);
    let end = Utc::now();
    let det = build_t1550_002(&start, &end);
    assert_eq!(det.technique_id, "T1550.002");
    assert_eq!(det.technique_name, "Pass the Hash");
    assert!(!det.detection_queries.is_empty());
    assert!(det.windows_event_ids.contains(&"4624".to_string()));
    assert!(det.log_sources.contains(&"windows-security".to_string()));
    assert_eq!(det.detection_queries[0].priority, "critical");
    assert!(!det.detection_queries[0].expected_evidence.is_empty());
}

#[test]
fn build_t1046_empty_state() {
    let state = SharedRedTeamState::new("test-op".to_string());
    let start = Utc::now() - chrono::Duration::hours(1);
    let end = Utc::now();
    let det = build_t1046(&state, &start, &end);
    assert_eq!(det.technique_id, "T1046");
    assert_eq!(det.technique_name, "Network Service Discovery");
    assert!(det.targets.is_empty());
    assert!(!det.detection_queries.is_empty());
    assert!(det.windows_event_ids.contains(&"5156".to_string()));
    assert!(det.windows_event_ids.contains(&"5157".to_string()));
    assert!(det.log_sources.contains(&"firewall".to_string()));
    assert!(det.log_sources.contains(&"windows-security".to_string()));
    assert!(det.log_sources.contains(&"netflow".to_string()));
    assert_eq!(det.detection_queries[0].priority, "medium");
}

#[test]
fn build_t1046_populated_hosts() {
    let mut state = SharedRedTeamState::new("test-op".to_string());
    state.all_hosts.push(Host {
        ip: "192.168.58.5".to_string(),
        hostname: "srv05".to_string(),
        os: String::new(),
        roles: vec![],
        services: vec![],
        is_dc: false,
        owned: false,
    });
    let start = Utc::now() - chrono::Duration::hours(1);
    let end = Utc::now();
    let det = build_t1046(&state, &start, &end);
    assert_eq!(det.targets, vec!["192.168.58.5".to_string()]);
}

// ---------------------------------------------------------------------------
// credential.rs — direct builder tests
// ---------------------------------------------------------------------------

#[test]
fn build_t1003_empty_state() {
    let state = SharedRedTeamState::new("test-op".to_string());
    let start = Utc::now() - chrono::Duration::hours(1);
    let end = Utc::now();
    let det = build_t1003(&state, &start, &end);
    assert_eq!(det.technique_id, "T1003");
    assert_eq!(det.technique_name, "OS Credential Dumping");
    assert!(det.credentials_used.is_empty());
    assert!(!det.detection_queries.is_empty());
    assert!(det.windows_event_ids.contains(&"4624".to_string()));
    assert!(det.windows_event_ids.contains(&"10".to_string()));
    assert!(det.log_sources.contains(&"windows-security".to_string()));
    assert!(det.log_sources.contains(&"sysmon".to_string()));
    assert_eq!(det.detection_queries[0].priority, "critical");
}

#[test]
fn build_t1003_includes_credentials_from_state() {
    let mut state = SharedRedTeamState::new("test-op".to_string());
    state.all_credentials.push(Credential {
        id: "c1".to_string(),
        username: "administrator".to_string(),
        password: "P@ssw0rd!".to_string(), // pragma: allowlist secret
        domain: "contoso.local".to_string(),
        source: "secretsdump".to_string(),
        discovered_at: None,
        is_admin: true,
        parent_id: None,
        attack_step: 1,
    });
    state.all_credentials.push(Credential {
        id: "c2".to_string(),
        username: "svc_backup".to_string(),
        password: "Backup1!".to_string(), // pragma: allowlist secret
        domain: String::new(),
        source: "lsassy".to_string(),
        discovered_at: None,
        is_admin: false,
        parent_id: None,
        attack_step: 2,
    });
    let start = Utc::now() - chrono::Duration::hours(1);
    let end = Utc::now();
    let det = build_t1003(&state, &start, &end);
    assert_eq!(det.credentials_used.len(), 2);
    // Domain-qualified credential
    assert!(det
        .credentials_used
        .iter()
        .any(|c| c.contains("contoso.local")));
    // Local (no domain) credential — should just be the username
    assert!(det.credentials_used.iter().any(|c| c == "svc_backup"));
}

#[test]
fn build_t1003_credentials_capped_at_five() {
    let mut state = SharedRedTeamState::new("test-op".to_string());
    for i in 0..8u8 {
        state.all_credentials.push(Credential {
            id: format!("c{i}"),
            username: format!("user{i}"),
            password: format!("pass{i}"), // pragma: allowlist secret
            domain: "contoso.local".to_string(),
            source: "secretsdump".to_string(),
            discovered_at: None,
            is_admin: false,
            parent_id: None,
            attack_step: 1,
        });
    }
    let start = Utc::now() - chrono::Duration::hours(1);
    let end = Utc::now();
    let det = build_t1003(&state, &start, &end);
    assert_eq!(det.credentials_used.len(), 5);
}

#[test]
fn build_t1003_001_properties() {
    let start = Utc::now() - chrono::Duration::hours(1);
    let end = Utc::now();
    let det = build_t1003_001(&start, &end);
    assert_eq!(det.technique_id, "T1003.001");
    assert_eq!(det.technique_name, "LSASS Memory");
    assert!(det.credentials_used.is_empty());
    assert!(!det.detection_queries.is_empty());
    assert!(det.windows_event_ids.contains(&"10".to_string()));
    assert!(det.log_sources.contains(&"sysmon".to_string()));
    assert_eq!(det.detection_queries[0].priority, "critical");
    // LogQL targets lsass.exe via sysmon event 10
    assert!(det.detection_queries[0].logql.contains("lsass.exe"));
}

#[test]
fn build_t1003_006_properties() {
    let start = Utc::now() - chrono::Duration::hours(1);
    let end = Utc::now();
    let det = build_t1003_006(&start, &end);
    assert_eq!(det.technique_id, "T1003.006");
    assert_eq!(det.technique_name, "DCSync");
    assert!(!det.detection_queries.is_empty());
    assert!(det.windows_event_ids.contains(&"4662".to_string()));
    assert!(det.log_sources.contains(&"windows-security".to_string()));
    assert_eq!(det.detection_queries[0].priority, "critical");
    // Expected evidence mentions directory replication
    assert!(!det.detection_queries[0].expected_evidence.is_empty());
    // LogQL targets replication GUIDs
    assert!(det.detection_queries[0].logql.contains("1131f6aa"));
}

#[test]
fn build_t1078_empty_state() {
    let state = SharedRedTeamState::new("test-op".to_string());
    let start = Utc::now() - chrono::Duration::hours(1);
    let end = Utc::now();
    let det = build_t1078(&state, &start, &end);
    assert_eq!(det.technique_id, "T1078");
    assert_eq!(det.technique_name, "Valid Accounts");
    assert!(det.credentials_used.is_empty());
    assert!(!det.detection_queries.is_empty());
    assert!(det.windows_event_ids.contains(&"4624".to_string()));
    assert!(det.windows_event_ids.contains(&"4625".to_string()));
    assert!(det.windows_event_ids.contains(&"4648".to_string()));
    assert!(det.log_sources.contains(&"windows-security".to_string()));
    assert_eq!(det.detection_queries[0].priority, "high");
}

#[test]
fn build_t1078_includes_credentials_from_state() {
    let mut state = SharedRedTeamState::new("test-op".to_string());
    state.all_credentials.push(Credential {
        id: "c1".to_string(),
        username: "da_user".to_string(),
        password: "DomainAdmin1!".to_string(), // pragma: allowlist secret
        domain: "fabrikam.local".to_string(),
        source: "spray".to_string(),
        discovered_at: None,
        is_admin: true,
        parent_id: None,
        attack_step: 1,
    });
    let start = Utc::now() - chrono::Duration::hours(1);
    let end = Utc::now();
    let det = build_t1078(&state, &start, &end);
    assert_eq!(det.credentials_used.len(), 1);
    assert!(det.credentials_used[0].contains("fabrikam.local"));
}

#[test]
fn build_t1078_credentials_capped_at_ten() {
    let mut state = SharedRedTeamState::new("test-op".to_string());
    for i in 0..15u8 {
        state.all_credentials.push(Credential {
            id: format!("c{i}"),
            username: format!("user{i}"),
            password: format!("pass{i}"), // pragma: allowlist secret
            domain: "contoso.local".to_string(),
            source: "spray".to_string(),
            discovered_at: None,
            is_admin: false,
            parent_id: None,
            attack_step: 1,
        });
    }
    let start = Utc::now() - chrono::Duration::hours(1);
    let end = Utc::now();
    let det = build_t1078(&state, &start, &end);
    assert_eq!(det.credentials_used.len(), 10);
}

#[test]
fn build_t1078_002_properties() {
    let start = Utc::now() - chrono::Duration::hours(1);
    let end = Utc::now();
    let det = build_t1078_002(&start, &end);
    assert_eq!(det.technique_id, "T1078.002");
    assert_eq!(det.technique_name, "Domain Accounts");
    assert!(det.credentials_used.is_empty());
    assert!(!det.detection_queries.is_empty());
    assert!(det.windows_event_ids.contains(&"4672".to_string()));
    assert!(det.windows_event_ids.contains(&"4624".to_string()));
    assert!(det.windows_event_ids.contains(&"4648".to_string()));
    assert!(det.log_sources.contains(&"windows-security".to_string()));
    assert_eq!(det.detection_queries[0].priority, "critical");
}

#[test]
fn build_t1110_properties() {
    let start = Utc::now() - chrono::Duration::hours(1);
    let end = Utc::now();
    let det = build_t1110(&start, &end);
    assert_eq!(det.technique_id, "T1110");
    assert_eq!(det.technique_name, "Brute Force");
    assert!(det.credentials_used.is_empty());
    assert!(!det.detection_queries.is_empty());
    assert!(det.windows_event_ids.contains(&"4625".to_string()));
    assert!(det.windows_event_ids.contains(&"4771".to_string()));
    assert!(det.log_sources.contains(&"windows-security".to_string()));
    assert_eq!(det.detection_queries[0].priority, "high");
    assert!(!det.detection_queries[0].expected_evidence.is_empty());
}

// ---------------------------------------------------------------------------
// kerberos.rs — direct builder tests
// ---------------------------------------------------------------------------

#[test]
fn build_t1558_properties() {
    let start = Utc::now() - chrono::Duration::hours(1);
    let end = Utc::now();
    let det = build_t1558(&start, &end);
    assert_eq!(det.technique_id, "T1558");
    assert_eq!(det.technique_name, "Steal or Forge Kerberos Tickets");
    assert!(!det.detection_queries.is_empty());
    assert!(det.windows_event_ids.contains(&"4768".to_string()));
    assert!(det.windows_event_ids.contains(&"4769".to_string()));
    assert!(det.windows_event_ids.contains(&"4770".to_string()));
    assert!(det.log_sources.contains(&"windows-security".to_string()));
    assert_eq!(det.detection_queries[0].priority, "critical");
    // LogQL should target RC4 / 0x17 patterns (Kerberoasting/AS-REP signals)
    assert!(det.detection_queries[0].logql.contains("0x17"));
}

#[test]
fn build_t1558_001_properties() {
    let start = Utc::now() - chrono::Duration::hours(1);
    let end = Utc::now();
    let det = build_t1558_001(&start, &end);
    assert_eq!(det.technique_id, "T1558.001");
    assert_eq!(det.technique_name, "Golden Ticket");
    assert!(!det.detection_queries.is_empty());
    assert!(det.windows_event_ids.contains(&"4768".to_string()));
    assert!(det.windows_event_ids.contains(&"4769".to_string()));
    assert!(det.log_sources.contains(&"windows-security".to_string()));
    assert_eq!(det.detection_queries[0].priority, "critical");
    // Expected evidence mentions krbtgt
    assert!(!det.detection_queries[0].expected_evidence.is_empty());
    assert!(det.detection_queries[0]
        .expected_evidence
        .iter()
        .any(|e| e.to_lowercase().contains("krbtgt")));
}

// ---------------------------------------------------------------------------
// time window plumbing
// ---------------------------------------------------------------------------

#[test]
fn detection_query_time_window_is_set() {
    let state = SharedRedTeamState::new("test-op".to_string());
    let start = Utc::now() - chrono::Duration::hours(2);
    let end = Utc::now();
    let det = build_t1046(&state, &start, &end);
    let tw = &det.detection_queries[0].time_window;
    assert!(tw.start.is_some());
    assert!(tw.end.is_some());
    // RFC-3339 strings should contain the hour component
    assert!(tw.start.as_ref().unwrap().contains('T'));
    assert!(tw.end.as_ref().unwrap().contains('T'));
}

#[test]
fn build_technique_detections_sub_technique_parent_t1046() {
    // T1046.999 → parent T1046 → build_t1046
    let state = SharedRedTeamState::new("test-op".to_string());
    let start = Utc::now() - chrono::Duration::hours(1);
    let end = Utc::now();
    let detections = build_technique_detections(&state, &["T1046.999".to_string()], &start, &end);
    let det = &detections["T1046.999"];
    assert!(!det.detection_queries.is_empty());
}

#[test]
fn build_technique_detections_sub_technique_parent_t1078() {
    // T1078.999 → parent T1078 → build_t1078
    let state = SharedRedTeamState::new("test-op".to_string());
    let start = Utc::now() - chrono::Duration::hours(1);
    let end = Utc::now();
    let detections = build_technique_detections(&state, &["T1078.999".to_string()], &start, &end);
    let det = &detections["T1078.999"];
    assert!(!det.detection_queries.is_empty());
}

#[test]
fn build_technique_detections_sub_technique_parent_t1558() {
    // T1558.999 → parent T1558 → build_t1558
    let state = SharedRedTeamState::new("test-op".to_string());
    let start = Utc::now() - chrono::Duration::hours(1);
    let end = Utc::now();
    let detections = build_technique_detections(&state, &["T1558.999".to_string()], &start, &end);
    let det = &detections["T1558.999"];
    assert!(!det.detection_queries.is_empty());
}

#[test]
fn build_technique_detections_sub_technique_parent_t1021() {
    // T1021.999 → parent T1021 → build_t1021
    let state = SharedRedTeamState::new("test-op".to_string());
    let start = Utc::now() - chrono::Duration::hours(1);
    let end = Utc::now();
    let detections = build_technique_detections(&state, &["T1021.999".to_string()], &start, &end);
    let det = &detections["T1021.999"];
    assert!(!det.detection_queries.is_empty());
}

#[test]
fn build_technique_detections_sub_technique_parent_t1550() {
    // T1550.999 → parent T1550 → build_t1550
    let state = SharedRedTeamState::new("test-op".to_string());
    let start = Utc::now() - chrono::Duration::hours(1);
    let end = Utc::now();
    let detections = build_technique_detections(&state, &["T1550.999".to_string()], &start, &end);
    let det = &detections["T1550.999"];
    assert!(!det.detection_queries.is_empty());
}

#[test]
fn build_technique_detections_unknown_with_known_name() {
    // A technique that has a known name (not empty) in get_technique_name
    // The T9999 was used in unknown_technique_fallback; use a known one that still
    // hits the fallback branch (T1484 is in the names table but not the match arms)
    let state = SharedRedTeamState::new("test-op".to_string());
    let start = Utc::now() - chrono::Duration::hours(1);
    let end = Utc::now();
    let detections = build_technique_detections(&state, &["T1484".to_string()], &start, &end);
    let det = &detections["T1484"];
    // T1484 hits the final fallback; name comes from get_technique_name
    assert_eq!(det.technique_id, "T1484");
    assert_eq!(det.technique_name, "Domain Policy Modification");
}
