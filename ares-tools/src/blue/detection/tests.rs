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
    assert_eq!(filter, " |~ `(?i)(nmap|masscan)`");
}

#[test]
fn pattern_filter_uses_regex_for_many_literals() {
    let filter = build_pattern_filter(&["nmap", "masscan", "rustscan", "zmap"]);
    assert_eq!(filter, " |~ `(?i)(nmap|masscan|rustscan|zmap)`");
}

#[test]
fn pattern_filter_uses_regex_for_metacharacters() {
    let filter = build_pattern_filter(&["golden.*ticket"]);
    assert_eq!(filter, " |~ `(?i)(golden.*ticket)`");
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

/// The exclude must be written in the JSON-escaped XML shape Loki actually
/// stores. A plain-text `TransmittedServices: -` form matched nothing, so every
/// 4769 passed through and T1550.003 was credited on every operation — measured
/// live at 3824 events in and 3824 out, i.e. the exclude did nothing.
#[test]
fn s4u_exclude_uses_the_escaped_xml_shape_loki_stores() {
    let tmpl = build_detection_template("detect_s4u_delegation", None).unwrap();
    let exclude = tmpl
        .logql
        .split("!~")
        .nth(1)
        .expect("S4U template carries an exclusion");

    assert!(
        exclude.contains("u003e"),
        "the exclude must match escaped XML, not plain text: {exclude}"
    );
    assert!(
        !exclude.contains(r"\s*:\s*"),
        "a `Field: value` form never appears in the stored event: {exclude}"
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

/// `detect_silver_ticket` is a grounding anchor, not a firing rule.
///
/// The blue write path refuses any MITRE ID no catalog template covers, and the
/// coverage join matches exact or parent/child but never siblings — so T1558.002
/// needs its own entry or the correlation in the blue orchestrator's sweep can
/// record nothing. The entry must NOT be satisfiable: its candidate shape (4624,
/// logon type 3, Kerberos) is every legitimate SMB/LDAP/MSSQL access in the
/// domain, so a firing version would stamp T1558.002 on every investigation. The
/// third stage requires a KDC ticket field that no 4624 carries — because by
/// definition the DC never saw the forged ticket — which is exactly why the real
/// rule has to be a cross-host correlation.
#[test]
fn silver_ticket_template_anchors_t1558_002_without_being_satisfiable() {
    let (_, entry) = ares_core::detection::find_template("detect_silver_ticket")
        .expect("T1558.002 needs a catalog template to ground blue writes");
    assert_eq!(entry.mitre_id, "T1558.002");

    let silver = build_detection_template("detect_silver_ticket", None)
        .unwrap()
        .logql;
    assert!(
        silver.contains(r#"|= "4624""#),
        "silver must pre-filter to the logon event, got: {silver}"
    );
    assert!(
        silver.contains("LogonType..u003e3.u003c"),
        "silver must anchor LogonType to exactly 3, got: {silver}"
    );
    assert!(
        silver.contains("AuthenticationPackageName..u003eKerberos"),
        "silver must exclude NTLM logons (T1550.002, not a forged ticket), got: {silver}"
    );
    assert!(
        silver.contains("TicketEncryptionType"),
        "silver must keep the KDC-issuance stage that makes it non-firing, got: {silver}"
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
fn unsecured_credentials_template_uses_base_technique() {
    let (_, entry) = ares_core::detection::find_template("detect_unsecured_credentials")
        .expect("detect_unsecured_credentials must exist");
    assert_eq!(
        entry.mitre_id, "T1552",
        "must be the base ID: coverage matches parent/child but not siblings, so a \
         T1552.006 template would leave red's T1552 and T1552.001 uncovered"
    );

    let tmpl = build_detection_template("detect_unsecured_credentials", None).unwrap();
    for indicator in ["groups\\.xml", "cpassword", "autologon", "unattend\\.xml"] {
        assert!(
            tmpl.logql.contains(indicator),
            "GPP/credential-file indicator {indicator} missing from {}",
            tmpl.logql
        );
    }

    for id in ["5145", "4663", "4656"] {
        assert!(
            tmpl.logql.contains(id),
            "event id {id} must scope the query — without it the label selector is \
             the only pre-filter: {}",
            tmpl.logql
        );
    }
}

/// A third of every windows-security line matched this rule (796,922 of
/// 2,409,887 in 24h) because bare path words and script extensions are normal
/// domain traffic — every domain-joined machine reads SYSVOL for GPO. T1552 was
/// then always "detected", which fabricates coverage instead of losing it.
#[test]
fn unsecured_credentials_template_does_not_match_ordinary_file_access() {
    let tmpl = build_detection_template("detect_unsecured_credentials", None).unwrap();
    for overbroad in [
        "object.*access",
        "share.*access",
        "file.*access",
        "sysvol",
        "netlogon",
        "\\.ps1",
        "\\.bat",
        "\\.vbs",
    ] {
        assert!(
            !tmpl.logql.contains(overbroad),
            "'{overbroad}' matches routine domain traffic, not credential discovery: {}",
            tmpl.logql
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

/// Return the first invalid escape sequence inside a double-quoted string
/// literal of `logql`, if any. Backtick (raw) strings are skipped — they do no
/// escape processing, which is exactly why regex filters use them.
///
/// LogQL double-quoted strings follow Go's escape rules, so `\.` is a hard
/// parse error rather than a literal dot.
fn first_invalid_double_quoted_escape(logql: &str) -> Option<String> {
    let c: Vec<char> = logql.chars().collect();
    let mut i = 0;
    while i < c.len() {
        match c[i] {
            '`' => {
                i += 1;
                while i < c.len() && c[i] != '`' {
                    i += 1;
                }
                i += 1;
            }
            '"' => {
                i += 1;
                while i < c.len() && c[i] != '"' {
                    if c[i] == '\\' {
                        let next = c.get(i + 1).copied().unwrap_or('\0');
                        if !matches!(
                            next,
                            'a' | 'b'
                                | 'f'
                                | 'n'
                                | 'r'
                                | 't'
                                | 'v'
                                | '\\'
                                | '"'
                                | '\''
                                | 'x'
                                | 'u'
                                | 'U'
                                | '0'..='7'
                        ) {
                            return Some(format!("\\{next}"));
                        }
                        i += 2;
                        continue;
                    }
                    i += 1;
                }
                i += 1;
            }
            _ => i += 1,
        }
    }
    None
}

#[test]
fn every_catalog_template_emits_parseable_logql() {
    // Regression: `filter_stages` patterns carry regex escapes (e.g.
    // `cmd\.exe`). Emitted into a double-quoted LogQL string they became the
    // invalid escape `\.`, and Loki rejected the query with 400 — which is
    // non-retryable, so all 15 such templates (impacket, lateral movement,
    // ADCS, delegation, trust-key exfil) failed on every sweep while the
    // plain-`patterns` templates kept working. Blue ran half-blind and the
    // only symptom was a WARN line.
    //
    // The old tests asserted templates *built*, never that they *parsed*.
    let config = ares_core::detection::detection_config();
    let mut broken: Vec<String> = Vec::new();

    for name in config.templates.keys() {
        let tmpl = build_detection_template(name, None)
            .unwrap_or_else(|| panic!("template {name} failed to build"));
        if let Some(bad) = first_invalid_double_quoted_escape(&tmpl.logql) {
            broken.push(format!("{name}: invalid escape `{bad}` in {}", tmpl.logql));
        }
    }

    assert!(
        broken.is_empty(),
        "{} template(s) emit LogQL Loki will reject with 400:\n{}",
        broken.len(),
        broken.join("\n")
    );
}

#[test]
fn regex_filters_use_raw_strings_so_escapes_survive() {
    // The concrete shape that broke: a stage carrying a regex metacharacter
    // must be emitted as a backtick raw string, not a double-quoted one.
    let f = build_pattern_filter(&["4688", "powershell", r"cmd\.exe"]);
    assert!(
        f.contains('`') && !f.contains('"'),
        "regex filter must use a backtick raw string, got: {f}"
    );
    assert!(
        f.contains(r"cmd\.exe"),
        "the escape must reach Loki intact, got: {f}"
    );
    assert_eq!(first_invalid_double_quoted_escape(&f), None);
}

#[test]
fn escape_validator_catches_the_original_bug() {
    // Negative control: the exact string the old code produced must be
    // rejected, otherwise the test above proves nothing.
    let old = r#"{job="windows-security"} |~ "(?i)(4688|powershell|cmd\.exe)""#;
    assert_eq!(
        first_invalid_double_quoted_escape(old).as_deref(),
        Some(r"\."),
        "validator must flag the escape that caused the 400s"
    );
    // ...and a legitimately-escaped double-quoted string must pass.
    assert_eq!(
        first_invalid_double_quoted_escape(r#"{job="x"} |= "a\\b" |~ `c\.d`"#),
        None
    );
}

#[test]
fn nopac_template_carries_the_technique_red_records() {
    let (_, entry) = ares_core::detection::find_template("detect_nopac_samaccountname_spoof")
        .expect("detect_nopac_samaccountname_spoof must exist");
    assert_eq!(
        entry.mitre_id, "T1210",
        "red records NoPac as T1210; coverage is an exact-or-parent/child join, so a \
         sibling or a privesc ID would leave T1210 permanently missed"
    );

    let tmpl = build_detection_template("detect_nopac_samaccountname_spoof", None).unwrap();
    for id in ["4781", "5136"] {
        assert!(
            tmpl.logql.contains(id),
            "event id {id} carries the rename that defines NoPac: {}",
            tmpl.logql
        );
    }
    assert!(
        !tmpl.logql.contains("4741"),
        "4741 is every computer-account creation, including the ones ares makes for its own \
         RBCD and ADCS work, and it carries a SamAccountName field so the filter stage cannot \
         narrow it: {}",
        tmpl.logql
    );
    assert!(
        tmpl.logql.contains("samaccountname"),
        "5136 must stay pinned to the sAMAccountName attribute or it matches the \
         msDS-AllowedToActOnBehalfOfOtherIdentity write that RBCD already owns: {}",
        tmpl.logql
    );
}
