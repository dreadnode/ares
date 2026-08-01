use super::*;
use ares_core::models::Credential;
use ares_core::models::Host;

fn sample_state() -> StateSnapshot {
    StateSnapshot {
        credentials: vec![Credential {
            id: "cred-1".into(),
            username: "admin".into(),
            password: "P@ss1".into(),
            domain: "contoso.local".into(),
            source: String::new(),
            discovered_at: None,
            is_admin: true,
            parent_id: None,
            attack_step: 0,
        }],
        hosts: vec![Host {
            ip: "192.168.58.10".into(),
            hostname: "dc01.contoso.local".into(),
            os: String::new(),
            roles: vec!["AD DS".into()],
            services: Vec::new(),
            is_dc: true,
            owned: false,
        }],
        domains: vec!["contoso.local".into()],
        ..Default::default()
    }
}

#[test]
fn generate_recon_prompt() {
    let payload = serde_json::json!({
        "target_ip": "192.168.58.0/24",
        "domain": "contoso.local",
        "techniques": ["nmap_scan", "enumerate_users"]
    });
    let state = sample_state();
    let prompt = generate_task_prompt("recon", "task-001", &payload, Some(&state)).unwrap();
    assert!(prompt.contains("Recon Task: task-001"));
    assert!(prompt.contains("192.168.58.0/24"));
    assert!(prompt.contains("contoso.local"));
    assert!(prompt.contains("- nmap_scan"));
    assert!(prompt.contains("Invalid credentials (49)"));
    assert!(prompt.contains("null_session=true"));
}

#[test]
fn generate_crack_prompt() {
    let payload = serde_json::json!({
        "hash_type": "ntlm",
        "hash_value": "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0\n$krb5tgs$23$*svc_sql$CONTOSO.LOCAL$spn*$aa$bb",
        "username": "admin",
        "domain": "contoso.local"
    });
    let prompt = generate_task_prompt("crack", "task-002", &payload, None).unwrap();
    assert!(prompt.contains("Crack Task: task-002"));
    assert!(prompt.contains("ntlm"));
    assert!(prompt.contains("```text\naad3b435b51404eeaad3b435b51404ee"));
    assert!(prompt.contains("\n$krb5tgs$23$*svc_sql$CONTOSO.LOCAL$spn*$aa$bb\n```"));
    assert!(prompt.contains("entire multi-line value"));
    assert!(prompt.contains("admin"));
}

#[test]
fn generate_credential_access_prompt() {
    let payload = serde_json::json!({
        "technique": "secretsdump",
        "target_ip": "192.168.58.10",
        "domain": "contoso.local",
        "credential": {
            "username": "admin",
            "password": "P@ss1",
            "domain": "contoso.local"
        }
    });
    let prompt = generate_task_prompt("credential_access", "task-003", &payload, None).unwrap();
    assert!(prompt.contains("secretsdump"));
    assert!(prompt.contains("admin"));
    assert!(prompt.contains("contoso.local"));
}

#[test]
fn generate_lateral_prompt() {
    let payload = serde_json::json!({
        "technique": "psexec",
        "target_ip": "192.168.58.20",
        "credential": {
            "username": "admin",
            "password": "P@ss1",
            "domain": "contoso.local"
        }
    });
    let prompt = generate_task_prompt("lateral_movement", "task-004", &payload, None).unwrap();
    assert!(prompt.contains("Lateral Movement"));
    assert!(prompt.contains("psexec"));
}

#[test]
fn generate_exploit_prompt() {
    let payload = serde_json::json!({
        "vuln_type": "constrained_delegation",
        "target": "192.168.58.30",
        "account": "svc_sql",
        "target_spn": "MSSQLSvc/db01.contoso.local",
        "domain": "contoso.local"
    });
    let prompt = generate_task_prompt("exploit", "task-005", &payload, None).unwrap();
    assert!(prompt.contains("CONSTRAINED DELEGATION"));
    assert!(prompt.contains("svc_sql"));
    assert!(prompt.contains("MSSQLSvc/db01.contoso.local"));
    assert!(prompt.contains("s4u_attack"));
}

#[test]
fn generate_coercion_prompt() {
    let payload = serde_json::json!({
        "target_ip": "192.168.58.10",
        "listener_ip": "192.168.58.100",
        "techniques": ["petitpotam", "coercer"]
    });
    let prompt = generate_task_prompt("coercion", "task-006", &payload, None).unwrap();
    assert!(prompt.contains("Coercion Task: task-006"));
    assert!(prompt.contains("192.168.58.10"));
    assert!(prompt.contains("- petitpotam"));
}

#[test]
fn generate_privesc_prompt() {
    let payload = serde_json::json!({
        "technique": "find_delegation",
        "target_ip": "192.168.58.10",
        "domain": "contoso.local"
    });
    let prompt = generate_task_prompt("privesc_enumeration", "task-007", &payload, None).unwrap();
    assert!(prompt.contains("Privilege Escalation"));
    assert!(prompt.contains("find_delegation"));
}

#[test]
fn generate_acl_prompt() {
    let payload = serde_json::json!({
        "chain": [{"source": "user1", "target": "admin", "right": "GenericAll"}]
    });
    let prompt = generate_task_prompt("acl_analysis", "task-008", &payload, None).unwrap();
    assert!(prompt.contains("ACL Analysis"));
    assert!(prompt.contains("GenericAll"));
}

#[test]
fn generate_command_prompt() {
    let payload = serde_json::json!({"command": "whoami"});
    let prompt = generate_task_prompt("command", "task-009", &payload, None).unwrap();
    assert!(prompt.contains("whoami"));
    assert!(prompt.contains("Command Task: task-009"));
}

#[test]
fn format_state_context_truncation() {
    let mut state = StateSnapshot::default();
    for i in 0..20 {
        state.credentials.push(Credential {
            id: format!("cred-{i}"),
            username: format!("user{i}"),
            password: "pass".into(),
            domain: "contoso.local".into(),
            source: String::new(),
            discovered_at: None,
            is_admin: false,
            parent_id: None,
            attack_step: 0,
        });
    }
    let ctx = format_state_context(&state, "credential_access", None);
    assert!(ctx.contains("and 12 more"));
}

#[test]
fn unknown_task_type_returns_none() {
    let payload = serde_json::json!({});
    assert!(generate_task_prompt("unknown_type", "task-x", &payload, None).is_none());
}

#[test]
fn state_context_injected_into_template() {
    let payload = serde_json::json!({
        "technique": "secretsdump",
        "target_ip": "192.168.58.10",
        "domain": "contoso.local"
    });
    let state = sample_state();
    let prompt =
        generate_task_prompt("credential_access", "task-010", &payload, Some(&state)).unwrap();
    // State context includes the domain
    assert!(prompt.contains("Discovered Domains"));
    assert!(prompt.contains("contoso.local"));
}

#[test]
fn pth_compatible_lm_nt() {
    assert!(helpers::is_pass_the_hash_compatible(Some(
        "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0"
    )));
}

#[test]
fn pth_compatible_nt_only() {
    assert!(helpers::is_pass_the_hash_compatible(Some(
        "31d6cfe0d16ae931b73c59d7e0c089c0"
    )));
}

#[test]
fn pth_rejects_kerberos_hash() {
    assert!(!helpers::is_pass_the_hash_compatible(Some(
        "$krb5tgs$23$*svc_sql$"
    )));
}

#[test]
fn pth_rejects_empty() {
    assert!(!helpers::is_pass_the_hash_compatible(None));
    assert!(!helpers::is_pass_the_hash_compatible(Some("")));
}

#[test]
fn pth_rejects_triple_colon() {
    assert!(!helpers::is_pass_the_hash_compatible(Some("aaa:bbb:ccc")));
}

#[test]
fn credaccess_kerberos_ticket_secretsdump() {
    let payload = serde_json::json!({
        "techniques": ["secretsdump"],
        "target_ips": ["192.168.58.10"],
        "domain": "contoso.local",
        "username": "Administrator",
        "ticket_path": "/tmp/admin.ccache",
        "no_pass": true,
        "dc_ip": "192.168.58.10"
    });
    let prompt = generate_task_prompt("credential_access", "t-1", &payload, None).unwrap();
    assert!(prompt.contains("KERBEROS TICKET-BASED SECRETSDUMP"));
    assert!(prompt.contains("/tmp/admin.ccache"));
    assert!(prompt.contains("no_pass=True"));
    assert!(prompt.contains("dc_ip='192.168.58.10'"));
    assert!(prompt.contains("Administrator"));
}

#[test]
fn credaccess_low_hanging_fruit_with_creds() {
    let payload = serde_json::json!({
        "domain": "contoso.local",
        "dc_ip": "192.168.58.10",
        "username": "admin",
        "password": "P@ss1",
        "techniques": ["gpp_password_finder", "sysvol_script_search"],
        "reason": "low_hanging_fruit"
    });
    let prompt = generate_task_prompt("credential_access", "t-2", &payload, None).unwrap();
    assert!(prompt.contains("LOW HANGING FRUIT credential harvesting"));
    assert!(prompt.contains("gpp_password_finder"));
    assert!(prompt.contains("sysvol_script_search"));
    // Worker auto-resolves credentials at dispatch — the password value must
    // never appear in the LLM-facing prompt.
    assert!(
        !prompt.contains("P@ss1"),
        "password value leaked into prompt:\n{prompt}"
    );
    assert!(prompt.contains("auto-resolved at dispatch"));
}

#[test]
fn credaccess_username_as_password_spray() {
    let payload = serde_json::json!({
        "domain": "contoso.local",
        "dc_ip": "192.168.58.10",
        "techniques": ["username_as_password"],
        "reason": "new_users discovered"
    });
    let prompt = generate_task_prompt("credential_access", "t-3", &payload, None).unwrap();
    assert!(prompt.contains("USERNAME_AS_PASSWORD spray"));
    assert!(prompt.contains("save_users_to_file"));
    assert!(prompt.contains("users_file='/tmp/users.txt'"));
}

#[test]
fn credaccess_share_spider() {
    let payload = serde_json::json!({
        "domain": "contoso.local",
        "username": "admin",
        "password": "P@ss1",
        "target_ips": ["192.168.58.10"],
        "techniques": ["share_spider"],
        "reason": "auto_share_spider_SYSVOL"
    });
    let prompt = generate_task_prompt("credential_access", "t-4", &payload, None).unwrap();
    assert!(prompt.contains("SHARE SPIDER TASK"));
    assert!(prompt.contains("smbclient_spider"));
    assert!(prompt.contains("*.txt"));
    assert!(prompt.contains("smbclient_spider"));
}

#[test]
fn credaccess_no_cred_techniques() {
    let payload = serde_json::json!({
        "domain": "contoso.local",
        "dc_ip": "192.168.58.10",
        "techniques": ["asrep_roast", "kerberos_user_enum_noauth"]
    });
    let prompt = generate_task_prompt("credential_access", "t-5", &payload, None).unwrap();
    assert!(prompt.contains("MANDATORY TECHNIQUE EXECUTION (NO CREDENTIALS)"));
    assert!(prompt.contains("asrep_roast"));
    assert!(prompt.contains("kerberos_user_enum_noauth"));
    assert!(prompt.contains("DO NOT run smb_sweep"));
}

#[test]
fn credaccess_low_hanging_no_creds() {
    let payload = serde_json::json!({
        "domain": "contoso.local",
        "dc_ip": "192.168.58.10",
        "techniques": ["username_as_password", "password_spray"],
        "reason": "low_hanging_fruit initial"
    });
    let prompt = generate_task_prompt("credential_access", "t-6", &payload, None).unwrap();
    assert!(prompt.contains("LOW HANGING FRUIT credential discovery (NO CREDENTIALS)"));
    assert!(prompt.contains("username_as_password"));
    assert!(prompt.contains("password_spray"));
}

#[test]
fn credaccess_technique_enforcement_with_creds() {
    let payload = serde_json::json!({
        "domain": "contoso.local",
        "dc_ip": "192.168.58.10",
        "username": "admin",
        "password": "P@ss1",
        "techniques": ["secretsdump", "kerberoast", "laps_dump"]
    });
    let prompt = generate_task_prompt("credential_access", "t-7", &payload, None).unwrap();
    assert!(prompt.contains("MANDATORY TECHNIQUE EXECUTION"));
    assert!(!prompt.contains("(NO CREDENTIALS)"));
    assert!(prompt.contains("secretsdump(target="));
    assert!(prompt.contains("kerberoast(domain="));
    assert!(prompt.contains("laps_dump(target="));
    // Password must never appear in LLM-facing prompts. The schema strip plus
    // worker resolver inject the credential at dispatch.
    assert!(
        !prompt.contains("P@ss1"),
        "password value leaked into prompt:\n{prompt}"
    );
    assert!(!prompt.contains("password='"));
    assert!(prompt.contains("Auth: password (auto-resolved at dispatch"));
}

#[test]
fn credaccess_technique_enforcement_with_hash() {
    let payload = serde_json::json!({
        "domain": "contoso.local",
        "dc_ip": "192.168.58.10",
        "username": "admin",
        "hash_value": "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0",
        "techniques": ["secretsdump"]
    });
    let prompt = generate_task_prompt("credential_access", "t-8", &payload, None).unwrap();
    assert!(prompt.contains("MANDATORY TECHNIQUE EXECUTION"));
    // Hash values are auto-resolved by the worker — the prompt must not echo
    // the hash, and signatures must not include `hashes=` / `nthash=` params.
    assert!(!prompt.contains("aad3b435b51404eeaad3b435b51404ee"));
    assert!(!prompt.contains("hashes="));
    assert!(!prompt.contains("nthash="));
    assert!(prompt.contains("Auth: nthash (auto-resolved at dispatch"));
    assert!(prompt.contains("secretsdump"));
}

#[test]
fn credaccess_non_pth_hash_strips_techniques() {
    let payload = serde_json::json!({
        "domain": "contoso.local",
        "dc_ip": "192.168.58.10",
        "username": "admin",
        "hash_value": "$krb5tgs$23$*svc_sql$CONTOSO",
        "techniques": ["secretsdump", "kerberoast"]
    });
    let prompt = generate_task_prompt("credential_access", "t-9", &payload, None).unwrap();
    assert!(prompt.contains("kerberoast"));
    assert!(!prompt.contains("secretsdump(target="));
}

#[test]
fn credaccess_generic_fallback() {
    let payload = serde_json::json!({
        "domain": "contoso.local",
        "username": "admin",
        "password": "P@ss1",
        "target_ips": ["192.168.58.10"],
        "dc_ip": "192.168.58.10"
    });
    let prompt = generate_task_prompt("credential_access", "t-10", &payload, None).unwrap();
    assert!(prompt.contains("Perform credential access against the target environment"));
    assert!(prompt.contains("PRIORITY ORDER when creds available"));
    assert!(prompt.contains("gpp_password_finder"));
}

#[test]
fn credaccess_generic_fallback_non_pth_hash() {
    let payload = serde_json::json!({
        "domain": "contoso.local",
        "username": "admin",
        "hash_value": "$krb5tgs$23$*svc_sql$CONTOSO",
        "hash_type": "Kerberos TGS",
        "target_ips": ["192.168.58.10"]
    });
    let prompt = generate_task_prompt("credential_access", "t-11", &payload, None).unwrap();
    assert!(prompt.contains("hash (non-NTLM)"));
    assert!(prompt.contains("not NTLM pass-the-hash compatible"));
}

#[test]
fn exploit_adcs_enumerate() {
    let payload = serde_json::json!({
        "vuln_type": "adcs_enumerate",
        "target": "192.168.58.15",
        "domain": "contoso.local",
        "dc_ip": "192.168.58.10",
        "username": "admin",
        "password": "P@ss1"
    });
    let prompt = generate_task_prompt("exploit", "t-20", &payload, None).unwrap();
    assert!(prompt.contains("ADCS ENUMERATION TASK"));
    assert!(prompt.contains("certipy_find"));
    assert!(prompt.contains("ESC1-ESC15"));
    assert!(prompt.contains("192.168.58.15"));
}

#[test]
fn exploit_mssql() {
    let payload = serde_json::json!({
        "vuln_type": "mssql_impersonation",
        "target": "192.168.58.30",
        "domain": "contoso.local",
        "available_credentials": [
            {"username": "svc_sql", "password": "SqlPass1", "domain": "contoso.local", "is_sql_account": "True"}
        ]
    });
    let prompt = generate_task_prompt("exploit", "t-21", &payload, None).unwrap();
    assert!(prompt.contains("MSSQL EXPLOITATION WORKFLOW"));
    assert!(prompt.contains("mssql_enum_impersonation"));
    assert!(prompt.contains("mssql_impersonate"));
    assert!(prompt.contains("xp_cmdshell"));
    assert!(prompt.contains("svc_sql"));
    assert!(prompt.contains("[SQL SERVICE ACCOUNT]"));
}

#[test]
fn exploit_constrained_delegation_with_state() {
    let state = StateSnapshot {
        credentials: vec![Credential {
            id: "c1".into(),
            username: "svc_sql".into(),
            password: "SqlPass1".into(),
            domain: "contoso.local".into(),
            source: String::new(),
            discovered_at: None,
            is_admin: false,
            parent_id: None,
            attack_step: 0,
        }],
        ..Default::default()
    };
    let payload = serde_json::json!({
        "vuln_type": "constrained_delegation",
        "target": "svc_sql",
        "account": "svc_sql",
        "target_spn": "cifs/dc01.contoso.local",
        "domain": "contoso.local",
        "dc_ip": "192.168.58.10"
    });
    let prompt = generate_task_prompt("exploit", "t-22", &payload, Some(&state)).unwrap();
    assert!(prompt.contains("CONSTRAINED DELEGATION"));
    assert!(prompt.contains("s4u_attack"));
    assert!(prompt.contains("cifs/dc01.contoso.local"));
    assert!(prompt.contains("dc01.contoso.local"));
}

#[test]
fn exploit_unconstrained_delegation() {
    let payload = serde_json::json!({
        "vuln_type": "unconstrained_delegation",
        "target": "192.168.58.30",
        "account": "WEB01$",
        "domain": "contoso.local"
    });
    let prompt = generate_task_prompt("exploit", "t-23", &payload, None).unwrap();
    assert!(prompt.contains("UNCONSTRAINED DELEGATION EXPLOITATION"));
    assert!(prompt.contains("WEB01$"));
    assert!(prompt.contains("unconstrained_coerce_and_capture"));
    assert!(prompt.contains("unconstrained_tgt_dump"));
    assert!(prompt.contains("DCSync"));
}

#[test]
fn exploit_adcs_esc1() {
    let payload = serde_json::json!({
        "vuln_type": "adcs_esc1",
        "target": "192.168.58.15",
        "ca_server": "CA01.contoso.local",
        "template": "VulnTemplate",
        "domain": "contoso.local"
    });
    let prompt = generate_task_prompt("exploit", "t-24", &payload, None).unwrap();
    assert!(prompt.contains("ADCS ADCS_ESC1 EXPLOITATION"));
    assert!(prompt.contains("certipy_request"));
    assert!(prompt.contains("certipy_auth"));
    assert!(prompt.contains("VulnTemplate"));
    assert!(!prompt.contains("ntlmrelayx"));
}

#[test]
fn exploit_adcs_esc8() {
    let payload = serde_json::json!({
        "vuln_type": "adcs_esc8",
        "target": "192.168.58.15",
        "ca_server": "CA01.contoso.local",
        "domain": "contoso.local"
    });
    let prompt = generate_task_prompt("exploit", "t-25", &payload, None).unwrap();
    assert!(prompt.contains("ADCS ADCS_ESC8 EXPLOITATION"));
    assert!(prompt.contains("ntlmrelayx"));
    assert!(prompt.contains("web enrollment"));
    assert!(!prompt.contains("certipy_request"));
    // No coerce_target field provided -> no "Coerce Target:" header rendered
    assert!(!prompt.contains("Coerce Target:"));
}

#[test]
fn exploit_adcs_esc8_renders_coerce_target_when_present() {
    let payload = serde_json::json!({
        "vuln_type": "adcs_esc8",
        "target": "192.168.58.15",
        "ca_server": "192.168.58.10",
        "domain": "contoso.local",
        "coerce_target": "192.168.58.20",
        "listener_ip": "192.168.58.50",
    });
    let prompt = generate_task_prompt("exploit", "t-26", &payload, None).unwrap();
    assert!(prompt.contains("Coerce Target (primary): 192.168.58.20"));
    assert!(prompt.contains("Relay Listener: 192.168.58.50"));
    assert!(prompt.contains("Coerce 192.168.58.20"));
}

#[test]
fn exploit_adcs_esc8_renders_fallback_targets() {
    let payload = serde_json::json!({
        "vuln_type": "adcs_esc8",
        "target": "192.168.58.15",
        "ca_server": "192.168.58.10",
        "domain": "contoso.local",
        "coerce_target": "192.168.58.20",
        "coerce_targets": ["192.168.58.20", "192.168.58.30", "192.168.58.51"],
        "listener_ip": "192.168.58.50",
    });
    let prompt = generate_task_prompt("exploit", "t-26b", &payload, None).unwrap();
    assert!(prompt.contains("Fallback Coerce Targets"));
    assert!(prompt.contains("192.168.58.30"));
    assert!(prompt.contains("192.168.58.51"));
}

#[test]
fn exploit_adcs_esc8_omits_fallback_block_when_only_one_candidate() {
    let payload = serde_json::json!({
        "vuln_type": "adcs_esc8",
        "target": "192.168.58.15",
        "ca_server": "192.168.58.10",
        "domain": "contoso.local",
        "coerce_target": "192.168.58.20",
        "coerce_targets": ["192.168.58.20"],
        "listener_ip": "192.168.58.50",
    });
    let prompt = generate_task_prompt("exploit", "t-26c", &payload, None).unwrap();
    assert!(!prompt.contains("Fallback Coerce Targets"));
}

#[test]
fn exploit_adcs_esc9_renders_the_victim_account() {
    let payload = serde_json::json!({
        "vuln_type": "adcs_esc9",
        "target": "192.168.58.15",
        "ca_server": "192.168.58.50",
        "template": "ESC9Tmpl",
        "domain": "contoso.local",
        "username": "alice",
        "password": "P@ssw0rd!",
        "victim_account": "bob",
        "victim_write_source": "alice",
        "victim_write_right": "genericwrite",
        "victim_credential_known": false,
    });
    let prompt = generate_task_prompt("exploit", "t-27", &payload, None).unwrap();
    assert!(prompt.contains("Victim Account (rewrite THIS account's userPrincipalName): bob"));
    assert!(prompt.contains("write held by alice via genericwrite"));
    assert!(prompt.contains("`user` for certipy_account_update = bob, NEVER alice"));
    assert!(prompt.contains("certipy_shadow it first"));
}

#[test]
fn exploit_adcs_esc9_without_a_victim_renders_no_victim_block() {
    let payload = serde_json::json!({
        "vuln_type": "adcs_esc9",
        "target": "192.168.58.15",
        "ca_server": "192.168.58.50",
        "template": "ESC9Tmpl",
        "domain": "contoso.local",
        "username": "alice",
    });
    let prompt = generate_task_prompt("exploit", "t-28", &payload, None).unwrap();
    assert!(!prompt.contains("Victim Account"));
    assert!(!prompt.contains("certipy_account_update ="));
}

#[test]
fn exploit_trust_key_extraction() {
    let payload = serde_json::json!({
        "vuln_type": "trust_key",
        "target": "192.168.58.10",
        "domain": "contoso.local",
        "trusted_domain": "fabrikam.local",
        "username": "Administrator",
        "password": "P@ss1",
        "dc_ip": "192.168.58.10"
    });
    let prompt = generate_task_prompt("exploit", "t-30", &payload, None).unwrap();
    assert!(prompt.contains("TRUST KEY EXTRACTION"));
    assert!(prompt.contains("extract_trust_key"));
    assert!(prompt.contains("fabrikam.local"));
}

/// The inter-forest branch must not steer the model at the trust-key forge:
/// SID filtering on the receiving DC strips the injected claim regardless of
/// RID, so no forge variant escalates. It has to route to a credential native
/// to the target forest driving a native escalation.
#[test]
fn exploit_cross_forest_steers_to_native_escalation_not_forge() {
    let payload = serde_json::json!({
        "vuln_type": "trust_key",
        "target": "192.168.58.10",
        "domain": "contoso.local",
        "trusted_domain": "fabrikam.local",
        "username": "Administrator",
        "password": "P@ss1",
        "dc_ip": "192.168.58.10"
    });
    let prompt = generate_task_prompt("exploit", "t-30b", &payload, None).unwrap();
    assert!(prompt.contains("THE TRUST KEY DOES NOT ESCALATE HERE"));
    assert!(prompt.contains("Take fabrikam.local from inside fabrikam.local"));
    assert!(prompt.contains("ESC13"));
    assert!(prompt.contains("AS-REP roastable accounts"));
    assert!(prompt.contains("MSSQL linked servers"));
    assert!(prompt.contains("Foreign security principals"));
    assert!(!prompt.contains("forge_inter_realm_and_dump"));
    assert!(!prompt.contains("impacket-ticketer"));
    assert!(!prompt.contains("always try"));
}

#[test]
fn exploit_child_to_parent_describes_automatic_forge() {
    let payload = serde_json::json!({
        "vuln_type": "child_to_parent",
        "target": "192.168.58.10",
        "domain": "child.contoso.local",
        "trusted_domain": "contoso.local",
        "username": "Administrator",
        "password": "P@ss1",
        "dc_ip": "192.168.58.10"
    });
    let prompt = generate_task_prompt("exploit", "t-31", &payload, None).unwrap();
    assert!(prompt.contains("TRUST KEY EXTRACTION"));
    assert!(prompt.contains("forge_inter_realm_and_dump"));
    assert!(prompt.contains("Enterprise Admins"));
    assert!(prompt.contains("SID filtering is not applied inside a forest"));
    assert!(prompt.contains("impacket-ticketer"));
    assert!(!prompt.contains("raise_child"));
    assert!(!prompt.contains("THE TRUST KEY DOES NOT ESCALATE HERE"));
}

#[test]
fn exploit_child_to_parent_renders_trust_template() {
    let payload = serde_json::json!({
        "vuln_type": "child_to_parent",
        "target": "192.168.58.10",
        "domain": "child.contoso.local",
        "trusted_domain": "contoso.local",
        "username": "Administrator",
        "password": "P@ss1",
        "dc_ip": "192.168.58.10",
        "source_sid": "S-1-5-21-1111-2222-3333",
        "target_sid": "S-1-5-21-4444-5555-6666",
        "child_krbtgt_hash": "8c6d94541dbc90f085e86828428d2cbf",
    });
    let prompt = generate_task_prompt("exploit", "t-32", &payload, None).unwrap();
    assert!(prompt.contains("contoso.local"));
    assert!(prompt.contains("child.contoso.local"));
}

#[test]
fn exploit_mssql_lateral_enumeration() {
    let state = StateSnapshot {
        credentials: vec![Credential {
            id: "c1".into(),
            username: "svc_sql".into(),
            password: "SqlPass1".into(),
            domain: "contoso.local".into(),
            source: String::new(),
            discovered_at: None,
            is_admin: false,
            parent_id: None,
            attack_step: 0,
        }],
        ..Default::default()
    };
    let payload = serde_json::json!({
        "vuln_type": "mssql_access",
        "target": "192.168.58.30",
        "domain": "contoso.local"
    });
    let prompt = generate_task_prompt("exploit", "t-32", &payload, Some(&state)).unwrap();
    assert!(prompt.contains("MSSQL LATERAL ENUMERATION"));
    assert!(prompt.contains("mssql_enum_impersonation"));
    assert!(prompt.contains("mssql_enum_linked_servers"));
    assert!(prompt.contains("mssql_ntlm_coerce"));
    assert!(prompt.contains("svc_sql"));
}

#[test]
fn exploit_mssql_lateral_renders_objectives() {
    let payload = serde_json::json!({
        "vuln_type": "mssql_access",
        "target": "192.168.58.30",
        "domain": "contoso.local",
        "objectives": [
            "STOP CONDITION: call `task_complete` as soon as any win lands.",
            "1. Enable xp_cmdshell, run `whoami` to confirm code execution.",
        ]
    });
    let prompt = generate_task_prompt("exploit", "t-33", &payload, None).unwrap();
    assert!(prompt.contains("TASK OBJECTIVES"));
    assert!(prompt.contains("STOP CONDITION: call `task_complete` as soon as any win lands."));
    assert!(prompt.contains("1. Enable xp_cmdshell, run `whoami` to confirm code execution."));
}

#[test]
fn exploit_mssql_lateral_omits_objectives_block_when_absent() {
    let payload = serde_json::json!({
        "vuln_type": "mssql_access",
        "target": "192.168.58.30",
        "domain": "contoso.local"
    });
    let prompt = generate_task_prompt("exploit", "t-34", &payload, None).unwrap();
    assert!(!prompt.contains("TASK OBJECTIVES"));
    assert!(prompt.contains("MSSQL LATERAL ENUMERATION"));
}

#[test]
fn exploit_generic_fallback() {
    let payload = serde_json::json!({
        "vuln_type": "unknown_vuln",
        "target": "192.168.58.30",
        "vuln_id": "v-99"
    });
    let prompt = generate_task_prompt("exploit", "t-26", &payload, None).unwrap();
    assert!(prompt.contains("unknown_vuln"));
    assert!(prompt.contains("Execute the exploitation technique"));
    assert!(prompt.contains("\"credential\""));
    assert!(prompt.contains("\"hash\""));
}
