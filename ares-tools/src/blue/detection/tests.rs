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
    assert_eq!(sel, r#"{job="windows-security", computer=~"dc01"}"#);
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
fn pattern_filter_ors_multiple_literals() {
    // 2+ literals in one stage are OR alternatives → regex alternation, NOT
    // chained |= (which ANDs them: a line would have to contain BOTH, so the
    // stage matches nothing).
    let filter = build_pattern_filter(&["nmap", "masscan"]);
    assert_eq!(filter, r#" |~ "(?i)(nmap|masscan)""#);
}

#[test]
fn pattern_filter_uses_regex_for_many_literals() {
    let filter = build_pattern_filter(&["nmap", "masscan", "rustscan", "zmap"]);
    assert_eq!(filter, r#" |~ "(?i)(nmap|masscan|rustscan|zmap)""#);
}

#[test]
fn pattern_filter_uses_regex_for_metacharacters() {
    let filter = build_pattern_filter(&["golden.*ticket"]);
    assert_eq!(filter, r#" |~ "(?i)(golden.*ticket)""#);
}

#[test]
fn pattern_filter_single_literal_uses_contains() {
    let filter = build_pattern_filter(&["drsuapi"]);
    assert_eq!(filter, r#" |= "drsuapi""#);
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
        "detect_smb_signing_disabled",
        "detect_mass_share_enumeration",
        "detect_mssql_linked_server",
        "detect_mssql_xp_cmdshell",
        "detect_mssql_impersonation",
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
fn template_with_host_includes_computer() {
    let tmpl = build_detection_template("detect_kerberoasting", Some("dc01")).unwrap();
    assert!(tmpl.logql.contains(r#"computer=~"dc01""#));
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
        "detect_mssql_linked_server",
        "detect_mssql_xp_cmdshell",
        "detect_delegation_abuse",
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
        "detect_s4u_delegation",
        "detect_smb_signing_disabled",
        "detect_mssql_linked_server",
        "detect_mssql_xp_cmdshell",
        "detect_delegation_abuse",
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

#[test]
fn s4u_template_has_exclude_patterns() {
    let tmpl = build_detection_template("detect_s4u_delegation", None).unwrap();
    // Should contain negative filter for machine accounts and empty TransmittedServices
    assert!(
        tmpl.logql.contains("!~"),
        "S4U template should have exclusion filters"
    );
    assert!(
        tmpl.logql.contains("TransmittedServices"),
        "S4U template should filter on TransmittedServices field"
    );
}

#[test]
fn multi_literal_stages_or_not_and() {
    // Regression: OR alternatives within one stage must compile to a single
    // `(?i)(a|b)` regex, never a chain of `|=` (which ANDs them so the stage
    // matches lines containing every term at once — i.e. nothing). This
    // previously blackholed RBCD delegation (attribute casings) and
    // remote-registry (service state) detections.
    let rbcd = build_detection_template("detect_delegation_abuse", None)
        .unwrap()
        .logql;
    assert!(
        rbcd.contains("(?i)(") && rbcd.contains("|rbcd)"),
        "RBCD attribute casings must OR into one regex, got: {rbcd}"
    );
    assert!(
        !rbcd.contains(r#"|= "rbcd""#),
        "RBCD must not chain |= for OR alternatives, got: {rbcd}"
    );

    let regsvc = build_detection_template("detect_remote_registry_start", None)
        .unwrap()
        .logql;
    assert!(
        regsvc.contains("(?i)(running|started|start)"),
        "remote-registry service states must OR, got: {regsvc}"
    );
}

#[test]
fn golden_ticket_keys_on_ticket_encryption_type() {
    // Golden-ticket stage 1 must match the ACTUAL TicketEncryptionType field, not a
    // bare '0x17'/'rc4'. Live Loki showed bare 'rc4' hits ~90% of 4769 (RC4 in the
    // capability-enumeration fields) and bare '0x17' hits AES tickets via
    // SessionKeyEncryptionType — both flood golden with false positives.
    let golden = build_detection_template("detect_golden_ticket", None)
        .unwrap()
        .logql;
    assert!(
        golden.contains("TicketEncryptionType"),
        "golden must key on the TicketEncryptionType field, got: {golden}"
    );
    assert!(
        !golden.contains(r#""(?i)(0x17|rc4)""#),
        "golden must not match bare 0x17/rc4 (capability-field false positives), got: {golden}"
    );
}

#[test]
fn kerberoasting_keys_on_ticket_encryption_type() {
    // Same failure as golden, on the rule that actually fires. The old patterns
    // let `encryption.*type` span the field NAME (ServiceSupportedEncryptionTypes)
    // into a capability value, so `.*rc4` matched almost everything: live Loki over
    // 24h gave 690/870 4769 events matched where only 28 were real RC4 tickets.
    let roast = build_detection_template("detect_kerberoasting", None)
        .unwrap()
        .logql;
    assert!(
        roast.contains("TicketEncryptionType"),
        "kerberoast must key on the TicketEncryptionType field, got: {roast}"
    );
    assert!(
        !roast.contains("encryption.*type"),
        "kerberoast must not use a name-spanning encryption.*type pattern, got: {roast}"
    );
    // ServiceName is a SAM account name, never an SPN — this stage matched 0 live.
    assert!(
        !roast.contains("servicename"),
        "kerberoast must not filter on SPN-shaped ServiceName (matches nothing), got: {roast}"
    );
}

#[test]
fn asrep_roasting_keys_on_preauthtype_zero() {
    // Third instance of the same span bug. `preauthtype.*0` reaches any later zero
    // on the line, so PreAuthType 2/15/16/17 all matched; live Loki over 24h gave
    // 411/590 4768 events where only 12 were real no-pre-auth TGTs.
    let asrep = build_detection_template("detect_asrep_roasting", None)
        .unwrap()
        .logql;
    assert!(
        asrep.contains("PreAuthType..u003e0.u003c"),
        "asrep must match PreAuthType=0 with the closing tag anchored, got: {asrep}"
    );
    for bad in ["preauthtype.*0", "encryption.*type", "ticket.*options"] {
        assert!(
            !asrep.contains(bad),
            "asrep must not use over-broad pattern {bad}, got: {asrep}"
        );
    }
}

#[test]
fn dcsync_template_excludes_machine_accounts() {
    let tmpl = build_detection_template("detect_dcsync", None).unwrap();
    assert!(
        tmpl.logql.contains("!~"),
        "DCSync template should have exclusion filter for machine accounts"
    );
    assert!(
        tmpl.logql.contains("SubjectUserName"),
        "DCSync exclusion should filter on SubjectUserName"
    );
    assert!(
        tmpl.logql.contains("[$]"),
        "DCSync exclusion should match machine account $ suffix"
    );
    assert!(
        tmpl.logql.contains(".u003e"),
        "DCSync exclusion must use .u003e (not >) because Loki stores XML > as JSON-escaped \\u003e"
    );
}

#[test]
fn dcsync_replication_template_excludes_machine_accounts() {
    let tmpl = build_detection_template("detect_dcsync_replication", None).unwrap();
    assert!(
        tmpl.logql.contains("!~"),
        "DCSync replication template should have exclusion filter"
    );
    assert!(
        tmpl.logql.contains("SubjectUserName"),
        "DCSync replication exclusion should filter on SubjectUserName"
    );
    assert!(
        tmpl.logql.contains(".u003e"),
        "DCSync replication exclusion must use .u003e for Loki JSON-escaped XML"
    );
}

#[test]
fn mssql_templates_exist_and_resolve() {
    let names = [
        "detect_mssql_linked_server",
        "detect_mssql_xp_cmdshell",
        "detect_mssql_impersonation",
    ];
    for name in &names {
        let tmpl = build_detection_template(name, None).unwrap();
        assert!(
            !tmpl.logql.is_empty(),
            "{name} should produce a LogQL query"
        );
    }
}

#[test]
fn lateral_patterns_load_from_yaml() {
    let cfg = ares_core::detection::detection_config();
    assert!(
        !cfg.lateral_patterns.is_empty(),
        "lateral_patterns should not be empty"
    );
    assert!(
        cfg.lateral_patterns.contains_key("smb"),
        "should have smb patterns"
    );
    assert!(
        cfg.lateral_patterns.contains_key("mssql"),
        "should have mssql patterns"
    );
}

#[test]
fn brute_force_no_host_line_filter() {
    let tmpl = build_detection_template("detect_brute_force", Some("192.168.58.10")).unwrap();
    // host_as_filter should be false — computer label selector is sufficient
    assert!(
        !tmpl.logql.contains(r#"|= "192.168.58.10""#),
        "brute_force should not use host as line filter"
    );
}
