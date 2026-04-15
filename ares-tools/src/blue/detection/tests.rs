use super::templates::build_detection_template;
use super::{build_event_filter, build_pattern_filter, build_selector, WIN_SECURITY};

#[test]
fn build_selector_no_host() {
    let sel = build_selector(WIN_SECURITY, None);
    assert_eq!(sel, r#"{job="windows-security"}"#);
}

#[test]
fn build_selector_with_host() {
    let sel = build_selector(WIN_SECURITY, Some("dc01"));
    assert_eq!(sel, r#"{job="windows-security", hostname=~"dc01"}"#);
}

#[test]
fn event_filter_single() {
    assert_eq!(build_event_filter(&["4624"]), r#" |= "4624""#);
}

#[test]
fn event_filter_multiple() {
    assert_eq!(
        build_event_filter(&["4624", "4625"]),
        r#" |~ "(4624|4625)""#
    );
}

#[test]
fn event_filter_empty() {
    assert_eq!(build_event_filter(&[]), "");
}

#[test]
fn pattern_filter_builds_case_insensitive() {
    let filter = build_pattern_filter(&["nmap", "masscan"]);
    assert_eq!(filter, r#" |~ "(?i)(nmap|masscan)""#);
}

#[test]
fn pattern_filter_empty() {
    assert_eq!(build_pattern_filter(&[]), "");
}

#[test]
fn all_templates_resolve() {
    let names = [
        "detect_port_scanning",
        "detect_user_enumeration",
        "detect_account_enumeration",
        "detect_share_enumeration",
        "detect_secretsdump",
        "detect_dcsync",
        "detect_dcsync_replication",
        "detect_kerberoasting",
        "detect_asrep_roasting",
        "detect_asrep_roasting_bulk",
        "detect_brute_force",
        "detect_password_spray",
        "detect_s4u_delegation",
        "detect_lsa_secrets_access",
        "detect_ntlm_relay",
        "detect_certificate_authentication",
        "detect_pass_the_hash",
        "detect_lateral_movement",
        "detect_smb_file_access",
        "detect_adcs_exploitation",
        "detect_certificate_abuse",
        "detect_delegation_abuse",
        "detect_golden_ticket",
        "detect_suspicious_execution",
        "detect_service_creation",
        "detect_scheduled_task",
        "detect_remote_registry_start",
        "detect_certipy_enumeration",
        "detect_esc1_attack",
        "detect_esc4_attack",
        "detect_esc8_attack",
        "detect_bloodhound",
        "detect_bloodhound_collection",
        "detect_bloodhound_domain_enum",
        "detect_bloodhound_acl_enum",
        "detect_bloodhound_session_enum",
        "detect_bloodhound_gpo_enum",
        "detect_bloodhound_computer_enum",
        "detect_impacket_wmiexec",
        "detect_impacket_psexec",
        "detect_impacket_smbexec",
        "detect_impacket_atexec",
        "detect_impacket_dcomexec",
        "detect_impacket_secretsdump_sam",
        "detect_impacket_secretsdump_lsa",
        "detect_impacket_ntlmrelayx",
        "detect_impacket_smbclient",
    ];
    for name in &names {
        assert!(
            build_detection_template(name, None).is_some(),
            "template {name} should resolve"
        );
    }
}

#[test]
fn unknown_template_returns_none() {
    assert!(build_detection_template("detect_nonexistent", None).is_none());
}

#[test]
fn template_with_host_includes_hostname() {
    let tmpl = build_detection_template("detect_kerberoasting", Some("dc01")).unwrap();
    assert!(tmpl.logql.contains(r#"hostname=~"dc01""#));
}

#[test]
fn remote_registry_uses_system_log() {
    let tmpl = build_detection_template("detect_remote_registry_start", None).unwrap();
    assert!(tmpl.logql.contains("windows-system"));
    assert!(!tmpl.logql.contains("windows-security"));
}

#[test]
fn aliases_produce_same_queries() {
    let a = build_detection_template("detect_brute_force", None).unwrap();
    let b = build_detection_template("detect_password_spray", None).unwrap();
    assert_eq!(a.logql, b.logql);

    let a = build_detection_template("detect_bloodhound", None).unwrap();
    let b = build_detection_template("detect_bloodhound_collection", None).unwrap();
    assert_eq!(a.logql, b.logql);

    let a = build_detection_template("detect_adcs_exploitation", None).unwrap();
    let b = build_detection_template("detect_certificate_abuse", None).unwrap();
    assert_eq!(a.logql, b.logql);
}

#[test]
fn critical_templates_have_critical_severity() {
    let critical = [
        "detect_secretsdump",
        "detect_dcsync",
        "detect_dcsync_replication",
        "detect_s4u_delegation",
        "detect_golden_ticket",
        "detect_esc1_attack",
        "detect_esc8_attack",
    ];
    for name in &critical {
        let tmpl = build_detection_template(name, None).unwrap();
        assert_eq!(
            tmpl.severity, "critical",
            "{name} should be critical severity"
        );
    }
}

#[test]
fn auto_pivot_templates() {
    let pivots = [
        "detect_pass_the_hash",
        "detect_lateral_movement",
        "detect_service_creation",
        "detect_impacket_wmiexec",
        "detect_impacket_psexec",
        "detect_impacket_smbexec",
        "detect_impacket_dcomexec",
    ];
    for name in &pivots {
        let tmpl = build_detection_template(name, None).unwrap();
        assert!(tmpl.auto_pivot, "{name} should have auto_pivot=true");
    }
}

#[test]
fn header_format_includes_metadata() {
    let tmpl = build_detection_template("detect_kerberoasting", None).unwrap();
    let header = tmpl.format_header();
    assert!(header.contains("T1558.003"));
    assert!(header.contains("high"));
    assert!(header.contains("credential_access"));
    assert!(header.contains("kerberoast"));
}
