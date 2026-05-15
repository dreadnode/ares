use super::admin_checks::{
    extract_ip_from_line, has_golden_ticket_indicator, parse_pwned_line, resolve_da_path,
};
use super::parsing::{has_domain_admin_indicator, parse_discoveries, resolve_parent_id};
use super::timeline::{credential_techniques, hash_techniques, is_critical_hash};
use super::{result_has_credential_evidence, result_has_parser_evidence};
use ares_core::models::{Credential, Hash};
use serde_json::json;

#[test]
fn parser_evidence_requires_discoveries_key() {
    // No payload at all → no evidence
    assert!(!result_has_parser_evidence(&None));
    // Payload without discoveries → no evidence
    assert!(!result_has_parser_evidence(&Some(json!({"summary": "ok"}))));
    // Empty discoveries object → no evidence
    assert!(!result_has_parser_evidence(&Some(
        json!({"discoveries": {}})
    )));
    // Empty arrays → no evidence
    assert!(!result_has_parser_evidence(&Some(
        json!({"discoveries": {"credentials": [], "hashes": []}})
    )));
}

#[test]
fn parser_evidence_accepts_any_populated_array() {
    for key in [
        "credentials",
        "hashes",
        "hosts",
        "shares",
        "vulnerabilities",
        "delegations",
        "trusts",
        "users",
        "spns",
    ] {
        let payload = json!({"discoveries": {key: [{"placeholder": true}]}});
        assert!(
            result_has_parser_evidence(&Some(payload)),
            "key {key} should count as parser evidence"
        );
    }
}

#[test]
fn credential_evidence_only_credentials_or_hashes() {
    // Only hosts → not credential evidence
    assert!(!result_has_credential_evidence(&Some(
        json!({"discoveries": {"hosts": [{"ip": "192.168.58.10"}]}})
    )));
    // Credentials present → credential evidence
    assert!(result_has_credential_evidence(&Some(
        json!({"discoveries": {"credentials": [{"username": "admin"}]}})
    )));
    // Hashes present → credential evidence
    assert!(result_has_credential_evidence(&Some(
        json!({"discoveries": {"hashes": [{"username": "admin"}]}})
    )));
    // Vulnerabilities alone are NOT credential evidence (would be parser evidence)
    assert!(!result_has_credential_evidence(&Some(
        json!({"discoveries": {"vulnerabilities": [{"vuln_id": "v1"}]}})
    )));
}

#[test]
fn llm_findings_field_is_not_treated_as_evidence() {
    // LLM-fabricated findings live under `llm_findings`, never `discoveries`.
    // The grounding check must IGNORE them.
    let payload = json!({
        "summary": "claimed exploit success",
        "llm_findings": [{
            "vulnerabilities": [{
                "vuln_id": "finding_kerberoastable_account_192_168_58_10",
                "vuln_type": "kerberoastable_account",
            }]
        }]
    });
    assert!(!result_has_parser_evidence(&Some(payload.clone())));
    assert!(!result_has_credential_evidence(&Some(payload)));
}

#[test]
fn parse_credentials_array() {
    let payload = json!({
        "credentials": [
            {"id": "c1", "username": "admin", "password": "P@ss1",
             "domain": "contoso.local", "source": "kerberoast", "is_admin": false, "attack_step": 0},
            {"id": "c2", "username": "svc_sql", "password": "SqlPass1",
             "domain": "contoso.local", "source": "secretsdump", "is_admin": false, "attack_step": 0}
        ]
    });
    let parsed = parse_discoveries(&payload);
    assert_eq!(parsed.credentials.len(), 2);
    assert_eq!(parsed.credentials[0].username, "admin");
    assert_eq!(parsed.credentials[1].username, "svc_sql");
}

#[test]
fn parse_single_credential() {
    let payload = json!({
        "credential": {
            "id": "c1", "username": "admin", "password": "P@ss1",
            "domain": "contoso.local", "source": "ntlm_relay", "is_admin": false, "attack_step": 0
        }
    });
    let parsed = parse_discoveries(&payload);
    assert_eq!(parsed.credentials.len(), 1);
    assert_eq!(parsed.credentials[0].source, "ntlm_relay");
}

#[test]
fn parse_cracked_password() {
    let payload =
        json!({"cracked_password": "Summer2024!", "username": "jdoe", "domain": "contoso.local"});
    let parsed = parse_discoveries(&payload);
    assert_eq!(parsed.credentials.len(), 1);
    assert_eq!(parsed.credentials[0].username, "jdoe");
    assert_eq!(parsed.credentials[0].password, "Summer2024!");
    assert_eq!(parsed.credentials[0].source, "cracked");
}

#[test]
fn parse_cracked_password_without_username_ignored() {
    let payload = json!({"cracked_password": "Summer2024!"});
    let parsed = parse_discoveries(&payload);
    assert!(parsed.credentials.is_empty());
}

#[test]
fn parse_hashes() {
    let payload = json!({
        "hashes": [{"id": "h1", "username": "Administrator", "hash_value": "aad3b435:abcdef123456",
                    "hash_type": "NTLM", "domain": "contoso.local", "source": "secretsdump",
                    "is_cracked": false, "attack_step": 0}]
    });
    let parsed = parse_discoveries(&payload);
    assert_eq!(parsed.hashes.len(), 1);
    assert_eq!(parsed.hashes[0].username, "Administrator");
    assert_eq!(parsed.hashes[0].hash_type, "NTLM");
}

#[test]
fn parse_hosts() {
    let payload = json!({
        "hosts": [{"ip": "192.168.58.10", "hostname": "dc01.contoso.local",
                   "os": "Windows Server 2019", "is_dc": true, "open_ports": [88, 389, 445]}]
    });
    let parsed = parse_discoveries(&payload);
    assert_eq!(parsed.hosts.len(), 1);
    assert_eq!(parsed.hosts[0].ip, "192.168.58.10");
    assert!(parsed.hosts[0].is_dc);
}

#[test]
fn parse_users_with_trusted_source() {
    let payload = json!({
        "discovered_users": [{"username": "jdoe", "domain": "contoso.local",
                              "source": "kerberos_enum", "is_admin": false}]
    });
    let parsed = parse_discoveries(&payload);
    assert_eq!(parsed.users.len(), 1);
    assert_eq!(parsed.users[0].username, "jdoe");
}

#[test]
fn parse_users_rejects_untrusted_source() {
    let payload = json!({
        "discovered_users": [
            {"username": "fake_admin", "domain": "contoso.local", "is_admin": false},
            {"username": "also_fake", "domain": "contoso.local",
             "source": "llm_hallucination", "is_admin": false}
        ]
    });
    let parsed = parse_discoveries(&payload);
    assert_eq!(parsed.users.len(), 0);
}

#[test]
fn parse_vulnerabilities() {
    let payload = json!({
        "vulnerabilities": [{"vuln_id": "vuln-001", "vuln_type": "constrained_delegation",
                             "target": "192.168.58.20", "discovered_by": "recon",
                             "details": {"account": "svc_sql"}, "recommended_agent": "privesc",
                             "priority": 3}]
    });
    let parsed = parse_discoveries(&payload);
    assert_eq!(parsed.vulnerabilities.len(), 1);
    assert_eq!(
        parsed.vulnerabilities[0].vuln_type,
        "constrained_delegation"
    );
}

#[test]
fn parse_shares() {
    let payload = json!({
        "shares": [
            {"host": "192.168.58.10", "name": "SYSVOL", "permissions": "READ", "comment": "Logon server share"},
            {"host": "192.168.58.10", "name": "ADMIN$", "permissions": "READ,WRITE"}
        ]
    });
    let parsed = parse_discoveries(&payload);
    assert_eq!(parsed.shares.len(), 2);
    assert_eq!(parsed.shares[0].name, "SYSVOL");
    assert_eq!(parsed.shares[1].name, "ADMIN$");
}

#[test]
fn parse_empty_payload() {
    let payload = json!({});
    let parsed = parse_discoveries(&payload);
    assert!(parsed.credentials.is_empty());
    assert!(parsed.hashes.is_empty());
    assert!(parsed.hosts.is_empty());
    assert!(parsed.users.is_empty());
    assert!(parsed.vulnerabilities.is_empty());
    assert!(parsed.shares.is_empty());
}

#[test]
fn parse_malformed_entries_skipped() {
    let payload = json!({
        "credentials": [
            {"username": "valid", "id": "c1", "password": "x", "domain": "d",
             "source": "s", "is_admin": false, "attack_step": 0},
            {"bad_field": "not a credential"}
        ],
        "hashes": [{"not_a_hash": true}]
    });
    let parsed = parse_discoveries(&payload);
    assert_eq!(parsed.credentials.len(), 1);
    assert!(parsed.hashes.is_empty());
}

#[test]
fn parse_mixed_payload() {
    let payload = json!({
        "credentials": [{"id": "c1", "username": "admin", "password": "P@ss",
                         "domain": "contoso.local", "source": "test", "is_admin": true, "attack_step": 0}],
        "hashes": [{"id": "h1", "username": "krbtgt", "hash_value": "abc123", "hash_type": "NTLM",
                    "domain": "contoso.local", "source": "secretsdump", "is_cracked": false, "attack_step": 0}],
        "hosts": [{"ip": "192.168.58.10", "hostname": "dc01.contoso.local", "is_dc": true}],
        "has_domain_admin": true, "domain_admin_path": "secretsdump -> Administrator"
    });
    let parsed = parse_discoveries(&payload);
    assert_eq!(parsed.credentials.len(), 1);
    assert_eq!(parsed.hashes.len(), 1);
    assert_eq!(parsed.hosts.len(), 1);
}

#[test]
fn da_indicator_explicit_flag_ignored() {
    // Agent self-report is not accepted without a krbtgt hash.
    assert!(!has_domain_admin_indicator(
        &json!({"has_domain_admin": true})
    ));
}

#[test]
fn da_indicator_false_flag() {
    assert!(!has_domain_admin_indicator(
        &json!({"has_domain_admin": false})
    ));
}

#[test]
fn da_indicator_krbtgt_hash() {
    assert!(has_domain_admin_indicator(
        &json!({"hashes": [{"username": "krbtgt", "hash_value": "abc"}]})
    ));
}

#[test]
fn da_indicator_krbtgt_case_insensitive() {
    assert!(has_domain_admin_indicator(
        &json!({"hashes": [{"username": "KRBTGT", "hash_value": "abc"}]})
    ));
}

#[test]
fn da_indicator_non_krbtgt_hash() {
    assert!(!has_domain_admin_indicator(
        &json!({"hashes": [{"username": "Administrator", "hash_value": "abc"}]})
    ));
}

#[test]
fn da_indicator_empty_payload() {
    assert!(!has_domain_admin_indicator(&json!({})));
}

#[test]
fn da_indicator_multiple_hashes_one_krbtgt() {
    assert!(has_domain_admin_indicator(&json!({"hashes": [
        {"username": "Administrator", "hash_value": "abc"},
        {"username": "krbtgt", "hash_value": "def"},
        {"username": "jdoe", "hash_value": "ghi"}
    ]})));
}

#[test]
fn da_indicator_empty_hashes_array() {
    assert!(!has_domain_admin_indicator(&json!({"hashes": []})));
}

#[test]
fn da_indicator_non_bool_value() {
    // has_domain_admin is a string "true" instead of bool true -- should NOT trigger
    assert!(!has_domain_admin_indicator(
        &json!({"has_domain_admin": "true"})
    ));
}

#[test]
fn da_indicator_null_value() {
    assert!(!has_domain_admin_indicator(
        &json!({"has_domain_admin": null})
    ));
}

#[test]
fn da_indicator_hashes_missing_username() {
    // Hash entry without a username field should not cause a panic
    assert!(!has_domain_admin_indicator(
        &json!({"hashes": [{"hash_value": "abc"}]})
    ));
}

#[test]
fn da_indicator_hashes_not_array() {
    // hashes is not an array -- should be safely ignored
    assert!(!has_domain_admin_indicator(
        &json!({"hashes": "not_an_array"})
    ));
}

fn make_test_credential(id: &str, username: &str, domain: &str, attack_step: i32) -> Credential {
    Credential {
        id: id.to_string(),
        username: username.to_string(),
        password: "P@ss1".to_string(),
        domain: domain.to_string(),
        source: String::new(),
        discovered_at: None,
        is_admin: false,
        parent_id: None,
        attack_step,
    }
}

fn make_test_hash(id: &str, username: &str, domain: &str, attack_step: i32) -> Hash {
    Hash {
        id: id.to_string(),
        username: username.to_string(),
        hash_value: "aabbccdd".to_string(),
        hash_type: "NTLM".to_string(),
        domain: domain.to_string(),
        source: String::new(),
        cracked_password: None,
        discovered_at: None,
        parent_id: None,
        attack_step,
        aes_key: None,
        is_previous: false,
        source_host: None,
        is_trust_key: false,
        trust_pair_label: None,
    }
}

#[test]
fn resolve_parent_cracked_source_finds_hash() {
    let creds: Vec<Credential> = vec![];
    let hashes = vec![make_test_hash("h1", "jdoe", "contoso.local", 1)];

    let (parent_id, step) = resolve_parent_id(
        &creds,
        &hashes,
        "cracked",
        "jdoe",
        "contoso.local",
        None,
        None,
    );

    assert_eq!(parent_id, Some("h1".to_string()));
    assert_eq!(step, 2); // hash.attack_step + 1
}

#[test]
fn resolve_parent_cracked_source_case_insensitive() {
    let creds: Vec<Credential> = vec![];
    let hashes = vec![make_test_hash("h1", "JDoe", "CONTOSO.LOCAL", 0)];

    let (parent_id, step) = resolve_parent_id(
        &creds,
        &hashes,
        "cracked:hashcat",
        "jdoe",
        "contoso.local",
        None,
        None,
    );

    assert_eq!(parent_id, Some("h1".to_string()));
    assert_eq!(step, 1);
}

#[test]
fn resolve_parent_cracked_source_empty_domain_matches() {
    let creds: Vec<Credential> = vec![];
    let hashes = vec![make_test_hash("h1", "jdoe", "contoso.local", 2)];

    // When discovered domain is empty, it should still match
    let (parent_id, step) = resolve_parent_id(&creds, &hashes, "cracked", "jdoe", "", None, None);

    assert_eq!(parent_id, Some("h1".to_string()));
    assert_eq!(step, 3);
}

#[test]
fn resolve_parent_cracked_source_no_matching_hash() {
    let creds: Vec<Credential> = vec![];
    let hashes = vec![make_test_hash("h1", "other_user", "contoso.local", 0)];

    let (parent_id, step) = resolve_parent_id(
        &creds,
        &hashes,
        "cracked",
        "jdoe",
        "contoso.local",
        None,
        None,
    );

    assert_eq!(parent_id, None);
    assert_eq!(step, 0);
}

#[test]
fn resolve_parent_cracked_picks_last_matching_hash() {
    let creds: Vec<Credential> = vec![];
    let hashes = vec![
        make_test_hash("h1", "jdoe", "contoso.local", 0),
        make_test_hash("h2", "jdoe", "contoso.local", 1),
    ];

    let (parent_id, _step) = resolve_parent_id(
        &creds,
        &hashes,
        "cracked",
        "jdoe",
        "contoso.local",
        None,
        None,
    );

    // .rev().find() means it should find h2 (last one)
    assert_eq!(parent_id, Some("h2".to_string()));
}

#[test]
fn resolve_parent_input_username_differs_finds_credential() {
    let creds = vec![make_test_credential("c1", "svc_sql", "contoso.local", 0)];
    let hashes: Vec<Hash> = vec![];

    // Discovered admin via svc_sql's credential (lateral move)
    let (parent_id, step) = resolve_parent_id(
        &creds,
        &hashes,
        "secretsdump",
        "administrator",
        "contoso.local",
        Some("svc_sql"),
        Some("contoso.local"),
    );

    assert_eq!(parent_id, Some("c1".to_string()));
    assert_eq!(step, 1);
}

#[test]
fn resolve_parent_input_username_differs_finds_hash_when_no_cred() {
    let creds: Vec<Credential> = vec![];
    let hashes = vec![make_test_hash("h1", "svc_sql", "contoso.local", 1)];

    // No credential for svc_sql, but there's a hash
    let (parent_id, step) = resolve_parent_id(
        &creds,
        &hashes,
        "secretsdump",
        "administrator",
        "contoso.local",
        Some("svc_sql"),
        Some("contoso.local"),
    );

    assert_eq!(parent_id, Some("h1".to_string()));
    assert_eq!(step, 2);
}

#[test]
fn resolve_parent_input_username_same_as_discovered_returns_none() {
    let creds = vec![make_test_credential("c1", "jdoe", "contoso.local", 0)];
    let hashes: Vec<Hash> = vec![];

    // input_username == discovered username (same user, same domain) => is_same == true => skip
    let (parent_id, step) = resolve_parent_id(
        &creds,
        &hashes,
        "kerberoast",
        "jdoe",
        "contoso.local",
        Some("jdoe"),
        Some("contoso.local"),
    );

    assert_eq!(parent_id, None);
    assert_eq!(step, 0);
}

#[test]
fn resolve_parent_no_parent_returns_none_zero() {
    let creds: Vec<Credential> = vec![];
    let hashes: Vec<Hash> = vec![];

    let (parent_id, step) = resolve_parent_id(
        &creds,
        &hashes,
        "kerberoast",
        "jdoe",
        "contoso.local",
        None,
        None,
    );

    assert_eq!(parent_id, None);
    assert_eq!(step, 0);
}

#[test]
fn resolve_parent_empty_input_username_skipped() {
    let creds = vec![make_test_credential("c1", "", "contoso.local", 0)];
    let hashes: Vec<Hash> = vec![];

    // Empty input_username should be filtered out by the .filter(|u| !u.is_empty())
    let (parent_id, step) = resolve_parent_id(
        &creds,
        &hashes,
        "secretsdump",
        "admin",
        "contoso.local",
        Some(""),
        Some("contoso.local"),
    );

    assert_eq!(parent_id, None);
    assert_eq!(step, 0);
}

#[test]
fn resolve_parent_input_username_case_insensitive() {
    let creds = vec![make_test_credential("c1", "SVC_SQL", "contoso.local", 0)];
    let hashes: Vec<Hash> = vec![];

    let (parent_id, step) = resolve_parent_id(
        &creds,
        &hashes,
        "secretsdump",
        "administrator",
        "contoso.local",
        Some("svc_sql"),
        Some("CONTOSO.LOCAL"),
    );

    assert_eq!(parent_id, Some("c1".to_string()));
    assert_eq!(step, 1);
}

#[test]
fn resolve_parent_input_domain_empty_still_matches() {
    let creds = vec![make_test_credential("c1", "svc_sql", "contoso.local", 0)];
    let hashes: Vec<Hash> = vec![];

    // input_domain is empty, so domain matching is relaxed
    let (parent_id, step) = resolve_parent_id(
        &creds,
        &hashes,
        "secretsdump",
        "administrator",
        "contoso.local",
        Some("svc_sql"),
        Some(""),
    );

    assert_eq!(parent_id, Some("c1".to_string()));
    assert_eq!(step, 1);
}

#[test]
fn resolve_parent_non_cracked_source_with_input_username() {
    let creds = vec![make_test_credential("c1", "svc_web", "fabrikam.local", 2)];
    let hashes: Vec<Hash> = vec![];

    let (parent_id, step) = resolve_parent_id(
        &creds,
        &hashes,
        "lsassy",
        "admin",
        "fabrikam.local",
        Some("svc_web"),
        Some("fabrikam.local"),
    );

    assert_eq!(parent_id, Some("c1".to_string()));
    assert_eq!(step, 3);
}

#[test]
fn resolve_parent_prefers_credential_over_hash() {
    // When both a credential and hash match, credential should be found first
    let creds = vec![make_test_credential("c1", "svc_sql", "contoso.local", 1)];
    let hashes = vec![make_test_hash("h1", "svc_sql", "contoso.local", 0)];

    let (parent_id, step) = resolve_parent_id(
        &creds,
        &hashes,
        "secretsdump",
        "administrator",
        "contoso.local",
        Some("svc_sql"),
        Some("contoso.local"),
    );

    // Should find the credential first, not the hash
    assert_eq!(parent_id, Some("c1".to_string()));
    assert_eq!(step, 2);
}

#[test]
fn parse_single_vulnerability() {
    // Test the singular "vulnerability" key (fallback when "vulnerabilities" is empty)
    let payload = json!({
        "vulnerability": {
            "vuln_id": "vuln-002",
            "vuln_type": "unconstrained_delegation",
            "target": "192.168.58.30",
            "discovered_by": "recon",
            "details": {},
            "recommended_agent": "privesc",
            "priority": 5
        }
    });
    let parsed = parse_discoveries(&payload);
    assert_eq!(parsed.vulnerabilities.len(), 1);
    assert_eq!(
        parsed.vulnerabilities[0].vuln_type,
        "unconstrained_delegation"
    );
}

#[test]
fn parse_singular_vulnerability_not_used_when_array_present() {
    // When "vulnerabilities" array is present, "vulnerability" singular should be ignored
    let payload = json!({
        "vulnerabilities": [{
            "vuln_id": "vuln-001",
            "vuln_type": "esc1",
            "target": "192.168.58.10",
            "discovered_by": "recon",
            "details": {},
            "recommended_agent": "exploit",
            "priority": 4
        }],
        "vulnerability": {
            "vuln_id": "vuln-002",
            "vuln_type": "esc4",
            "target": "192.168.58.20",
            "discovered_by": "recon",
            "details": {},
            "recommended_agent": "exploit",
            "priority": 3
        }
    });
    let parsed = parse_discoveries(&payload);
    assert_eq!(parsed.vulnerabilities.len(), 1);
    assert_eq!(parsed.vulnerabilities[0].vuln_type, "esc1");
}

#[test]
fn parse_users_with_netexec_source() {
    let payload = json!({
        "discovered_users": [
            {"username": "jdoe", "domain": "contoso.local", "source": "netexec_user_enum", "is_admin": false}
        ]
    });
    let parsed = parse_discoveries(&payload);
    assert_eq!(parsed.users.len(), 1);
}

#[test]
fn parse_cracked_password_with_domain() {
    let payload = json!({
        "cracked_password": "Winter2025!",
        "username": "svc_sql",
        "domain": "fabrikam.local"
    });
    let parsed = parse_discoveries(&payload);
    assert_eq!(parsed.credentials.len(), 1);
    assert_eq!(parsed.credentials[0].domain, "fabrikam.local");
    assert_eq!(parsed.credentials[0].source, "cracked");
}

#[test]
fn parse_cracked_password_without_domain_defaults_empty() {
    let payload = json!({
        "cracked_password": "Winter2025!",
        "username": "svc_sql"
    });
    let parsed = parse_discoveries(&payload);
    assert_eq!(parsed.credentials.len(), 1);
    assert_eq!(parsed.credentials[0].domain, "");
}

#[test]
fn parse_hashes_malformed_skipped() {
    let payload = json!({
        "hashes": [
            {"id": "h1", "username": "admin", "hash_value": "aabb", "hash_type": "NTLM",
             "domain": "contoso.local", "source": "secretsdump", "is_cracked": false, "attack_step": 0},
            {"not_a_hash_field": 123}
        ]
    });
    let parsed = parse_discoveries(&payload);
    assert_eq!(parsed.hashes.len(), 1);
}

#[test]
fn parse_shares_with_comment() {
    let payload = json!({
        "shares": [
            {"host": "192.168.58.10", "name": "NETLOGON", "permissions": "READ", "comment": "Logon server share"}
        ]
    });
    let parsed = parse_discoveries(&payload);
    assert_eq!(parsed.shares.len(), 1);
    assert_eq!(parsed.shares[0].comment, "Logon server share");
}

// --- parse_pwned_line tests ---

#[test]
fn pwned_line_standard_format() {
    let line = "[+] CONTOSO\\admin:P@ssw0rd! (Pwn3d!)";
    let result = parse_pwned_line(line);
    assert_eq!(result, Some(("contoso".to_string(), "admin".to_string())));
}

#[test]
fn pwned_line_without_password() {
    let line = "[+] CONTOSO\\admin (Pwn3d!)";
    let result = parse_pwned_line(line);
    assert_eq!(result, Some(("contoso".to_string(), "admin".to_string())));
}

#[test]
fn pwned_line_with_ip_prefix() {
    let line = "SMB 192.168.58.10 [+] CONTOSO\\svc_sql:Summer2024! (Pwn3d!)";
    let result = parse_pwned_line(line);
    assert_eq!(result, Some(("contoso".to_string(), "svc_sql".to_string())));
}

#[test]
fn pwned_line_no_pwn3d_marker() {
    let line = "[+] CONTOSO\\admin:P@ssw0rd!";
    assert_eq!(parse_pwned_line(line), None);
}

#[test]
fn pwned_line_no_plus_marker() {
    let line = "CONTOSO\\admin:P@ssw0rd! (Pwn3d!)";
    assert_eq!(parse_pwned_line(line), None);
}

#[test]
fn pwned_line_empty_string() {
    assert_eq!(parse_pwned_line(""), None);
}

#[test]
fn pwned_line_no_backslash() {
    let line = "[+] admin:P@ssw0rd! (Pwn3d!)";
    assert_eq!(parse_pwned_line(line), None);
}

#[test]
fn pwned_line_empty_domain() {
    let line = "[+] \\admin:P@ssw0rd! (Pwn3d!)";
    assert_eq!(parse_pwned_line(line), None);
}

#[test]
fn pwned_line_empty_username() {
    let line = "[+] CONTOSO\\:P@ssw0rd! (Pwn3d!)";
    assert_eq!(parse_pwned_line(line), None);
}

#[test]
fn pwned_line_domain_lowercased() {
    let line = "[+] FABRIKAM.LOCAL\\Administrator:Pass1 (Pwn3d!)";
    let result = parse_pwned_line(line);
    assert_eq!(
        result,
        Some(("fabrikam.local".to_string(), "Administrator".to_string()))
    );
}

#[test]
fn pwned_line_username_with_special_chars() {
    let line = "[+] CONTOSO\\svc_web$:P@ss! (Pwn3d!)";
    let result = parse_pwned_line(line);
    assert_eq!(
        result,
        Some(("contoso".to_string(), "svc_web$".to_string()))
    );
}

// --- extract_ip_from_line tests ---

#[test]
fn extract_ip_basic() {
    let line = "SMB 192.168.58.10 445 DC01 [+] CONTOSO\\admin (Pwn3d!)";
    assert_eq!(
        extract_ip_from_line(line),
        Some("192.168.58.10".to_string())
    );
}

#[test]
fn extract_ip_no_ip_present() {
    let line = "[+] CONTOSO\\admin:P@ssw0rd! (Pwn3d!)";
    assert_eq!(extract_ip_from_line(line), None);
}

#[test]
fn extract_ip_empty_string() {
    assert_eq!(extract_ip_from_line(""), None);
}

#[test]
fn extract_ip_invalid_octets() {
    let line = "address 999.999.999.999 is invalid";
    assert_eq!(extract_ip_from_line(line), None);
}

#[test]
fn extract_ip_not_enough_octets() {
    let line = "host 192.168.58 partial";
    assert_eq!(extract_ip_from_line(line), None);
}

#[test]
fn extract_ip_first_match_returned() {
    let line = "192.168.58.1 and 192.168.58.1 are both IPs";
    assert_eq!(extract_ip_from_line(line), Some("192.168.58.1".to_string()));
}

#[test]
fn extract_ip_boundary_values() {
    let line = "host 0.0.0.0 and 255.255.255.255";
    assert_eq!(extract_ip_from_line(line), Some("0.0.0.0".to_string()));
}

// --- has_golden_ticket_indicator tests ---

#[test]
fn golden_ticket_indicator_present() {
    let text = "Saving ticket in administrator.ccache";
    assert!(has_golden_ticket_indicator(text));
}

#[test]
fn golden_ticket_indicator_missing_saving() {
    let text = "Wrote ticket to administrator.ccache";
    assert!(!has_golden_ticket_indicator(text));
}

#[test]
fn golden_ticket_indicator_missing_ccache() {
    let text = "Saving ticket in administrator.kirbi";
    assert!(!has_golden_ticket_indicator(text));
}

#[test]
fn golden_ticket_indicator_empty() {
    assert!(!has_golden_ticket_indicator(""));
}

#[test]
fn golden_ticket_indicator_both_present_not_adjacent() {
    let text = "Saving ticket in /tmp/krbtgt@CONTOSO.LOCAL.ccache\nDone";
    assert!(has_golden_ticket_indicator(text));
}

// --- resolve_da_path tests ---

#[test]
fn da_path_always_krbtgt() {
    // Agent-provided path fields are ignored.
    let payload = json!({
        "has_domain_admin": true,
        "domain_admin_path": "secretsdump -> Administrator"
    });
    assert_eq!(
        resolve_da_path(&payload),
        Some("secretsdump -> krbtgt hash".to_string())
    );
}

#[test]
fn da_path_no_fields_defaults_to_krbtgt() {
    let payload = json!({"has_domain_admin": true});
    assert_eq!(
        resolve_da_path(&payload),
        Some("secretsdump -> krbtgt hash".to_string())
    );
}

#[test]
fn da_path_no_flag_defaults_to_krbtgt() {
    let payload = json!({});
    assert_eq!(
        resolve_da_path(&payload),
        Some("secretsdump -> krbtgt hash".to_string())
    );
}

#[test]
fn da_path_false_flag_defaults_to_krbtgt() {
    let payload = json!({"has_domain_admin": false});
    assert_eq!(
        resolve_da_path(&payload),
        Some("secretsdump -> krbtgt hash".to_string())
    );
}

#[test]
fn da_path_null_flag_defaults_to_krbtgt() {
    let payload = json!({"has_domain_admin": null});
    assert_eq!(
        resolve_da_path(&payload),
        Some("secretsdump -> krbtgt hash".to_string())
    );
}

// --- credential_techniques tests ---

#[test]
fn credential_techniques_admin_base() {
    let t = credential_techniques("manual", true);
    assert_eq!(t, vec!["T1078"]);
}

#[test]
fn credential_techniques_non_admin_base() {
    let t = credential_techniques("manual", false);
    assert_eq!(t, vec!["T1552"]);
}

#[test]
fn credential_techniques_kerberoast() {
    let t = credential_techniques("kerberoast", false);
    assert!(t.contains(&"T1558.003".to_string()));
    assert!(t.contains(&"T1552".to_string()));
}

#[test]
fn credential_techniques_asrep() {
    let t = credential_techniques("asreproast", false);
    assert!(t.contains(&"T1558.004".to_string()));
}

#[test]
fn credential_techniques_as_rep_hyphenated() {
    let t = credential_techniques("as-rep roast", false);
    assert!(t.contains(&"T1558.004".to_string()));
}

#[test]
fn credential_techniques_cracked() {
    let t = credential_techniques("cracked:hashcat", false);
    assert!(t.contains(&"T1110".to_string()));
}

#[test]
fn credential_techniques_multiple_sources() {
    let t = credential_techniques("kerberoast_cracked", false);
    assert!(t.contains(&"T1552".to_string()));
    assert!(t.contains(&"T1558.003".to_string()));
    assert!(t.contains(&"T1110".to_string()));
}

#[test]
fn credential_techniques_case_insensitive() {
    let t = credential_techniques("KERBEROAST", false);
    assert!(t.contains(&"T1558.003".to_string()));
}

#[test]
fn credential_techniques_empty_source() {
    let t = credential_techniques("", false);
    assert_eq!(t, vec!["T1552"]);
}

// --- hash_techniques tests ---

#[test]
fn hash_techniques_base() {
    let t = hash_techniques("aabbccdd", "ntlm", "manual");
    assert_eq!(t, vec!["T1003"]);
}

#[test]
fn hash_techniques_kerberoast_by_hash_value() {
    let t = hash_techniques("$krb5tgs$23$*svc_sql$", "unknown", "manual");
    assert!(t.contains(&"T1558.003".to_string()));
}

#[test]
fn hash_techniques_kerberoast_by_hash_type() {
    let t = hash_techniques("aabb", "kerberoast", "manual");
    assert!(t.contains(&"T1558.003".to_string()));
}

#[test]
fn hash_techniques_kerberoast_by_source() {
    let t = hash_techniques("aabb", "unknown", "kerberoast_output");
    assert!(t.contains(&"T1558.003".to_string()));
}

#[test]
fn hash_techniques_asrep_by_hash_value() {
    let t = hash_techniques("$krb5asrep$23$jdoe@", "unknown", "manual");
    assert!(t.contains(&"T1558.004".to_string()));
}

#[test]
fn hash_techniques_asrep_by_hash_type() {
    let t = hash_techniques("aabb", "asrep", "manual");
    assert!(t.contains(&"T1558.004".to_string()));
}

#[test]
fn hash_techniques_asrep_by_source() {
    let t = hash_techniques("aabb", "unknown", "asrep_roast");
    assert!(t.contains(&"T1558.004".to_string()));
}

#[test]
fn hash_techniques_ntlm_secretsdump() {
    let t = hash_techniques("aabb", "ntlm", "secretsdump");
    assert!(t.contains(&"T1003.006".to_string()));
}

#[test]
fn hash_techniques_ntlm_dcsync() {
    let t = hash_techniques("aabb", "ntlm", "dcsync");
    assert!(t.contains(&"T1003.006".to_string()));
}

#[test]
fn hash_techniques_ntlm_without_dump_source() {
    let t = hash_techniques("aabb", "ntlm", "manual");
    assert!(!t.contains(&"T1003.006".to_string()));
}

#[test]
fn hash_techniques_non_ntlm_secretsdump() {
    // hash_type is not ntlm, so T1003.006 should not appear even with secretsdump source
    let t = hash_techniques("aabb", "des", "secretsdump");
    assert!(!t.contains(&"T1003.006".to_string()));
}

#[test]
fn hash_techniques_tgs_rep_type() {
    let t = hash_techniques("aabb", "tgs-rep", "manual");
    assert!(t.contains(&"T1558.003".to_string()));
}

#[test]
fn hash_techniques_krb5asrep_type() {
    let t = hash_techniques("aabb", "krb5asrep", "manual");
    assert!(t.contains(&"T1558.004".to_string()));
}

#[test]
fn hash_techniques_as_rep_hyphenated_source() {
    let t = hash_techniques("aabb", "unknown", "as-rep_roast");
    assert!(t.contains(&"T1558.004".to_string()));
}

// --- is_critical_hash tests ---

#[test]
fn critical_hash_krbtgt() {
    assert!(is_critical_hash("krbtgt"));
}

#[test]
fn critical_hash_administrator() {
    assert!(is_critical_hash("administrator"));
}

#[test]
fn critical_hash_case_insensitive() {
    assert!(is_critical_hash("KRBTGT"));
    assert!(is_critical_hash("Administrator"));
}

#[test]
fn critical_hash_regular_user() {
    assert!(!is_critical_hash("jdoe"));
}

#[test]
fn critical_hash_empty() {
    assert!(!is_critical_hash(""));
}

#[test]
fn critical_hash_partial_match() {
    assert!(!is_critical_hash("krbtgt_backup"));
    assert!(!is_critical_hash("admin"));
}

#[test]
fn extract_locked_users_basic_netexec_format() {
    use super::extract_locked_usernames_from_result;
    let payload = json!({
        "tool_outputs": [
            "SMB    192.168.58.10  445  DC01  [-] CONTOSO\\testuser1:testuser1 STATUS_ACCOUNT_LOCKED_OUT\n\
             SMB    192.168.58.10  445  DC01  [+] CONTOSO\\testuser3:testuser3 (Pwn3d!)\n\
             SMB    192.168.58.10  445  DC01  [-] CONTOSO\\testuser2:testuser2 STATUS_ACCOUNT_LOCKED_OUT"
        ]
    });
    let mut locked = extract_locked_usernames_from_result(&Some(payload));
    locked.sort();
    assert_eq!(
        locked,
        vec![
            ("testuser1".to_string(), Some("contoso".to_string())),
            ("testuser2".to_string(), Some("contoso".to_string())),
        ]
    );
}

#[test]
fn extract_locked_users_kdc_revoked_format() {
    use super::extract_locked_usernames_from_result;
    let payload = json!({
        "summary": "[-] CONTOSO\\testuser1:testuser1 KDC_ERR_CLIENT_REVOKED"
    });
    let locked = extract_locked_usernames_from_result(&Some(payload));
    assert_eq!(
        locked,
        vec![("testuser1".to_string(), Some("contoso".to_string()))]
    );
}

#[test]
fn extract_locked_users_skips_disabled_builtins() {
    use super::extract_locked_usernames_from_result;
    let payload = json!({
        "tool_outputs": [
            "[-] CONTOSO\\Guest:Guest STATUS_ACCOUNT_LOCKED_OUT\n\
             [-] CONTOSO\\krbtgt:krbtgt STATUS_ACCOUNT_LOCKED_OUT\n\
             [-] CONTOSO\\testuser1:testuser1 STATUS_ACCOUNT_LOCKED_OUT"
        ]
    });
    let locked = extract_locked_usernames_from_result(&Some(payload));
    assert_eq!(
        locked,
        vec![("testuser1".to_string(), Some("contoso".to_string()))]
    );
}

#[test]
fn extract_locked_users_dedups_repeats() {
    use super::extract_locked_usernames_from_result;
    let payload = json!({
        "tool_outputs": [
            "[-] CONTOSO\\testuser1:testuser1 STATUS_ACCOUNT_LOCKED_OUT\n\
             [-] CONTOSO\\testuser1:testuser1 STATUS_ACCOUNT_LOCKED_OUT"
        ]
    });
    let locked = extract_locked_usernames_from_result(&Some(payload));
    assert_eq!(locked.len(), 1);
}

#[test]
fn extract_locked_users_no_matches_returns_empty() {
    use super::extract_locked_usernames_from_result;
    let payload = json!({
        "tool_outputs": ["[+] CONTOSO\\testuser1:testuser1 (Pwn3d!)"]
    });
    let locked = extract_locked_usernames_from_result(&Some(payload));
    assert!(locked.is_empty());
}

#[test]
fn extract_locked_users_rejects_bare_principal() {
    use super::extract_locked_usernames_from_result;
    // Bare `user:pass` (no DOMAIN\ prefix) is rejected — netexec always
    // emits the canonical `DOMAIN\user:pass` form on auth events.
    let payload = json!({
        "summary": "[-] testuser1:testuser1 STATUS_ACCOUNT_LOCKED_OUT"
    });
    let locked = extract_locked_usernames_from_result(&Some(payload));
    assert!(locked.is_empty());
}

#[test]
fn extract_locked_users_rejects_llm_narrative_tokens() {
    use super::extract_locked_usernames_from_result;
    // LLM summary text often contains `word:` tokens (technique names,
    // password values, list bullets) that are not principals. The
    // backslash gate prevents these from being misclassified.
    let payload = json!({
        "summary": "1) username_as_password: returned STATUS_ACCOUNT_LOCKED_OUT\n\
                    Notable: P@ssw0rd1 spray got STATUS_ACCOUNT_LOCKED_OUT\n\
                    auth: failed with STATUS_ACCOUNT_LOCKED_OUT"
    });
    let locked = extract_locked_usernames_from_result(&Some(payload));
    assert!(locked.is_empty(), "got false positives: {locked:?}");
}

#[test]
fn is_ticket_grant_vuln_recognizes_delegation_prefixes() {
    use super::is_ticket_grant_vuln;
    assert!(is_ticket_grant_vuln("constrained_delegation_alice"));
    assert!(is_ticket_grant_vuln("UNCONSTRAINED_DELEGATION_WEB01$"));
    assert!(is_ticket_grant_vuln("rbcd_dc01_target"));
    assert!(is_ticket_grant_vuln("s4u_admin_at_contoso"));
}

#[test]
fn is_ticket_grant_vuln_rejects_non_ticket_primitives() {
    use super::is_ticket_grant_vuln;
    assert!(!is_ticket_grant_vuln("kerberoast_svc_sql"));
    assert!(!is_ticket_grant_vuln("adcs_esc1_192.168.58.50"));
    assert!(!is_ticket_grant_vuln("mssql_impersonation_192.168.58.51"));
    assert!(!is_ticket_grant_vuln(""));
}

#[test]
fn ccache_evidence_detects_saving_ticket_line() {
    use super::result_has_ccache_evidence;
    let payload = json!({
        "output": "[*] Impersonating Administrator\n\
                   [*] Requesting S4U2self\n\
                   [*] Requesting S4U2Proxy\n\
                   [*] Saving ticket in Administrator@cifs_dc01@CONTOSO.LOCAL.ccache"
    });
    assert!(result_has_ccache_evidence(&Some(payload)));
}

#[test]
fn ccache_evidence_detects_in_tool_outputs_array() {
    use super::result_has_ccache_evidence;
    let payload = json!({
        "tool_outputs": [
            {"output": "[*] Saving ticket in alice@CIFS.ccache"}
        ]
    });
    assert!(result_has_ccache_evidence(&Some(payload)));
}

#[test]
fn ccache_evidence_rejects_bare_mention() {
    use super::result_has_ccache_evidence;
    // LLM commentary that mentions a ticket path but doesn't prove a save.
    let payload = json!({
        "summary": "S4U2Proxy returned an error before saving the .ccache"
    });
    assert!(!result_has_ccache_evidence(&Some(payload)));
}

#[test]
fn ccache_evidence_empty_payload() {
    use super::result_has_ccache_evidence;
    assert!(!result_has_ccache_evidence(&None));
    assert!(!result_has_ccache_evidence(&Some(json!({}))));
}

#[test]
fn is_gmsa_principal_matches_trailing_dollar_with_gmsa_name() {
    use super::is_gmsa_principal;
    assert!(is_gmsa_principal("gmsaDragon$"));
    assert!(is_gmsa_principal("GMSA_WEB$"));
    assert!(is_gmsa_principal("svc_gmsa$"));
}

#[test]
fn is_gmsa_principal_rejects_machine_account_without_gmsa_substring() {
    use super::is_gmsa_principal;
    // Plain machine accounts end with $ but are not gMSA.
    assert!(!is_gmsa_principal("DC01$"));
    assert!(!is_gmsa_principal("WEB01$"));
}

#[test]
fn is_gmsa_principal_rejects_user_without_trailing_dollar() {
    use super::is_gmsa_principal;
    // A user named "gmsa_admin" (no trailing $) is a regular user, not gMSA.
    assert!(!is_gmsa_principal("gmsa_admin"));
    assert!(!is_gmsa_principal(""));
    assert!(!is_gmsa_principal("$"));
}

#[test]
fn gmsa_exploit_token_strips_dollar_and_lowercases() {
    use super::gmsa_exploit_token;
    assert_eq!(gmsa_exploit_token("gmsaDragon$"), "gmsa_gmsadragon");
    assert_eq!(gmsa_exploit_token("GMSA_WEB$"), "gmsa_gmsa_web");
    assert_eq!(gmsa_exploit_token("svc_gmsa$"), "gmsa_svc_gmsa");
}

#[test]
fn gmsa_exploit_token_converges_with_enumeration_format() {
    // Enumeration path emits `gmsa_{name}` lowercased; secretsdump-surfaced
    // path must produce the same key so the exploited-set entry deduplicates
    // across paths and the scoreboard counts the primitive once.
    use super::gmsa_exploit_token;
    assert_eq!(gmsa_exploit_token("gmsaDragon$"), "gmsa_gmsadragon");
}

mod emit_gmsa_exploit_token {
    use super::super::emit_gmsa_exploit_token_if_gmsa;
    use crate::orchestrator::state::SharedState;
    use crate::orchestrator::task_queue::TaskQueueCore;
    use ares_core::state::mock_redis::MockRedisConnection;

    fn mock_queue() -> TaskQueueCore<MockRedisConnection> {
        TaskQueueCore::from_connection(MockRedisConnection::new())
    }

    #[tokio::test]
    async fn marks_exploited_for_gmsa_principal() {
        let state = SharedState::new("op-1".to_string());
        let q = mock_queue();
        emit_gmsa_exploit_token_if_gmsa(&state, &q, "gmsaDragon$").await;
        let s = state.read().await;
        assert!(s.exploited_vulnerabilities.contains("gmsa_gmsadragon"));
    }

    #[tokio::test]
    async fn no_op_for_plain_machine_account() {
        // DC01$ ends with `$` but is not a gMSA — no token should be emitted.
        let state = SharedState::new("op-1".to_string());
        let q = mock_queue();
        emit_gmsa_exploit_token_if_gmsa(&state, &q, "DC01$").await;
        let s = state.read().await;
        assert!(s.exploited_vulnerabilities.is_empty());
    }

    #[tokio::test]
    async fn no_op_for_regular_user() {
        let state = SharedState::new("op-1".to_string());
        let q = mock_queue();
        emit_gmsa_exploit_token_if_gmsa(&state, &q, "alice").await;
        let s = state.read().await;
        assert!(s.exploited_vulnerabilities.is_empty());
    }

    #[tokio::test]
    async fn token_normalized_lowercase_for_mixed_case_input() {
        let state = SharedState::new("op-1".to_string());
        let q = mock_queue();
        emit_gmsa_exploit_token_if_gmsa(&state, &q, "GMSA_WEB$").await;
        let s = state.read().await;
        assert!(s.exploited_vulnerabilities.contains("gmsa_gmsa_web"));
    }
}

#[test]
fn seimpersonate_signal_detects_enabled_in_whoami_priv_output() {
    use super::result_has_seimpersonate_signal;
    // Real-world `whoami /priv` row format from a service account context.
    let payload = json!({
        "output": "PRIVILEGES INFORMATION\n\
                   ----------------------\n\
                   Privilege Name                Description                                 State\n\
                   ============================= =========================================== ========\n\
                   SeAssignPrimaryTokenPrivilege Replace a process level token               Disabled\n\
                   SeImpersonatePrivilege        Impersonate a client after authentication   Enabled\n\
                   SeIncreaseQuotaPrivilege      Adjust memory quotas for a process          Disabled"
    });
    assert!(result_has_seimpersonate_signal(&Some(payload)));
}

#[test]
fn seimpersonate_signal_ignores_disabled_priv() {
    use super::result_has_seimpersonate_signal;
    let payload = json!({
        "output": "SeImpersonatePrivilege  Impersonate a client after authentication  Disabled"
    });
    assert!(!result_has_seimpersonate_signal(&Some(payload)));
}

#[test]
fn seimpersonate_signal_ignores_bare_mention_without_state() {
    use super::result_has_seimpersonate_signal;
    // LLM commentary that names the privilege but doesn't prove it's held.
    let payload = json!({
        "summary": "Plan: check for SeImpersonatePrivilege if we get xp_cmdshell working"
    });
    assert!(!result_has_seimpersonate_signal(&Some(payload)));
}

#[test]
fn seimpersonate_signal_detects_in_tool_outputs_array() {
    use super::result_has_seimpersonate_signal;
    let payload = json!({
        "tool_outputs": [
            {"output": "whoami output:\nSeImpersonatePrivilege Impersonate a client Enabled"}
        ]
    });
    assert!(result_has_seimpersonate_signal(&Some(payload)));
}

#[test]
fn seimpersonate_signal_empty_payload() {
    use super::result_has_seimpersonate_signal;
    assert!(!result_has_seimpersonate_signal(&None));
    assert!(!result_has_seimpersonate_signal(&Some(json!({}))));
}

#[test]
fn seimpersonate_signal_case_insensitive() {
    use super::result_has_seimpersonate_signal;
    // Some shells/agents may upper- or lower-case the row.
    let payload = json!({
        "output": "seimpersonateprivilege   description text   ENABLED"
    });
    assert!(result_has_seimpersonate_signal(&Some(payload)));
}

#[test]
fn ntlmv1_signal_detects_explicit_verdict() {
    use super::result_has_ntlmv1_signal;
    let payload = json!({
        "output": "[+] NTLMv1 is allowed (LmCompatibilityLevel registry value indicates vulnerable config)"
    });
    assert!(result_has_ntlmv1_signal(&Some(payload)));
}

#[test]
fn ntlmv1_signal_detects_lmcompat_le_2() {
    use super::result_has_ntlmv1_signal;
    for value in [0, 1, 2] {
        let payload = json!({
            "output": format!("LmCompatibilityLevel: {value}")
        });
        assert!(
            result_has_ntlmv1_signal(&Some(payload)),
            "should match LmCompatibilityLevel={value}"
        );
    }
}

#[test]
fn ntlmv1_signal_rejects_lmcompat_ge_3() {
    use super::result_has_ntlmv1_signal;
    for value in [3, 4, 5] {
        let payload = json!({
            "output": format!("LmCompatibilityLevel: {value}")
        });
        assert!(
            !result_has_ntlmv1_signal(&Some(payload)),
            "should NOT match LmCompatibilityLevel={value}"
        );
    }
}

#[test]
fn ntlmv1_signal_recognizes_reg_dword_format() {
    use super::result_has_ntlmv1_signal;
    let payload = json!({
        "output": "LmCompatibilityLevel    REG_DWORD    0x2"
    });
    assert!(result_has_ntlmv1_signal(&Some(payload)));
}

#[test]
fn ntlmv1_signal_rejects_bare_mention() {
    use super::result_has_ntlmv1_signal;
    let payload = json!({
        "summary": "Plan: check whether the DC permits NTLMv1 downgrade by reading LmCompatibilityLevel"
    });
    assert!(!result_has_ntlmv1_signal(&Some(payload)));
}

#[test]
fn ntlmv1_signal_empty_payload() {
    use super::result_has_ntlmv1_signal;
    assert!(!result_has_ntlmv1_signal(&None));
    assert!(!result_has_ntlmv1_signal(&Some(json!({}))));
}

#[test]
fn ntlmv1_signal_detects_in_tool_outputs_array() {
    use super::result_has_ntlmv1_signal;
    let payload = json!({
        "tool_outputs": [
            {"output": "Registry probe returned LmCompatibilityLevel: 1"}
        ]
    });
    assert!(result_has_ntlmv1_signal(&Some(payload)));
}

#[test]
fn error_indicates_stall_recognises_canonical_strings() {
    use super::error_indicates_stall;
    assert!(error_indicates_stall(Some(
        "Agent ended turn without task_complete or request_assistance"
    )));
    assert!(error_indicates_stall(Some("Agent hit max steps")));
    assert!(error_indicates_stall(Some("Agent hit max tokens")));
    assert!(error_indicates_stall(Some(
        "Budget exceeded: input_tokens=1000000"
    )));
    // Case-insensitive
    assert!(error_indicates_stall(Some(
        "AGENT ENDED TURN WITHOUT TASK_COMPLETE"
    )));
}

#[test]
fn error_indicates_stall_rejects_real_failures() {
    use super::error_indicates_stall;
    // Substantive failures must not be treated as stalls — the underlying
    // primitive really did fail and the vuln must stay unexplodited.
    assert!(!error_indicates_stall(Some("rpc_s_access_denied")));
    assert!(!error_indicates_stall(Some(
        "KDC_ERR_PREAUTH_FAILED — credential rejected"
    )));
    assert!(!error_indicates_stall(Some("LDAP bind failed: 0x52e")));
    assert!(!error_indicates_stall(Some("")));
    assert!(!error_indicates_stall(None));
}

#[test]
fn roast_token_recognises_kerberoast_hash() {
    use super::roast_exploit_token;
    assert_eq!(
        roast_exploit_token(
            "$krb5tgs$23$*sql_svc$CONTOSO.LOCAL$cifs/dc01...",
            "sql_svc",
            "contoso.local",
        ),
        Some("kerberoast_sql_svc".to_string())
    );
}

#[test]
fn roast_token_recognises_asrep_hash() {
    use super::roast_exploit_token;
    assert_eq!(
        roast_exploit_token(
            "$krb5asrep$23$alice@CONTOSO.LOCAL:abc...",
            "alice",
            "contoso.local",
        ),
        Some("asrep_roast_contoso.local".to_string())
    );
}

#[test]
fn roast_token_falls_back_to_username_when_domain_empty() {
    use super::roast_exploit_token;
    assert_eq!(
        roast_exploit_token("$krb5asrep$23$alice@DOMAIN:abc...", "alice", "",),
        Some("asrep_roast_alice".to_string())
    );
}

#[test]
fn roast_token_ignores_non_roast_hashes() {
    use super::roast_exploit_token;
    // NTLM hash from secretsdump — not a roast, no token.
    assert_eq!(
        roast_exploit_token(
            "aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c",
            "administrator",
            "contoso.local",
        ),
        None
    );
    // Empty hash value
    assert_eq!(roast_exploit_token("", "user", "dom"), None);
}

#[test]
fn roast_token_returns_none_when_both_user_and_domain_empty() {
    use super::roast_exploit_token;
    assert_eq!(roast_exploit_token("$krb5asrep$23$...", "", ""), None);
    assert_eq!(roast_exploit_token("$krb5tgs$23$...", "", "dom"), None);
}

#[test]
fn roast_token_lowercases_account_and_domain() {
    use super::roast_exploit_token;
    assert_eq!(
        roast_exploit_token("$krb5tgs$23$*", "SQL_SVC", "CONTOSO.LOCAL"),
        Some("kerberoast_sql_svc".to_string())
    );
    assert_eq!(
        roast_exploit_token("$krb5asrep$23$", "Alice", "Contoso.Local"),
        Some("asrep_roast_contoso.local".to_string())
    );
}

// ── result_has_ntlmv1_signal ──────────────────────────────────────────

#[test]
fn ntlmv1_signal_none_payload_is_false() {
    use super::result_has_ntlmv1_signal;
    assert!(!result_has_ntlmv1_signal(&None));
}

#[test]
fn ntlmv1_signal_recognises_explicit_positives() {
    use super::result_has_ntlmv1_signal;
    let positives = [
        "NTLMv1 allowed",
        "NTLMv1 is allowed",
        "ntlmv1_allowed",
        "LmCompatibilityLevel is vulnerable",
        "NTLMv1 downgrade confirmed",
    ];
    for line in &positives {
        let p = json!({"summary": line});
        assert!(
            result_has_ntlmv1_signal(&Some(p)),
            "{line} should be a positive signal",
        );
    }
}

#[test]
fn ntlmv1_signal_recognises_lmcompatibilitylevel_low_value() {
    use super::result_has_ntlmv1_signal;
    for n in &['0', '1', '2'] {
        let line = format!("Found LmCompatibilityLevel = {n}");
        let p = json!({"tool_output": line});
        assert!(
            result_has_ntlmv1_signal(&Some(p)),
            "LmCompatibilityLevel = {n} should be a positive",
        );
    }
}

#[test]
fn ntlmv1_signal_rejects_lmcompatibilitylevel_safe_values() {
    use super::result_has_ntlmv1_signal;
    let p = json!({"tool_output": "LmCompatibilityLevel = 5"});
    assert!(!result_has_ntlmv1_signal(&Some(p)));
    let p = json!({"tool_output": "LmCompatibilityLevel = 3"});
    assert!(!result_has_ntlmv1_signal(&Some(p)));
}

#[test]
fn ntlmv1_signal_does_not_match_commentary() {
    use super::result_has_ntlmv1_signal;
    // The narrow regex must NOT match prose that merely mentions NTLMv1.
    let p = json!({"summary": "checking whether NTLMv1 is in use"});
    assert!(!result_has_ntlmv1_signal(&Some(p)));
    let p = json!({"summary": "NTLMv1 (LmCompatibilityLevel) is set"});
    assert!(!result_has_ntlmv1_signal(&Some(p)));
}

#[test]
fn ntlmv1_signal_walks_tool_outputs_array() {
    use super::result_has_ntlmv1_signal;
    let p = json!({
        "tool_outputs": [
            "no signal here",
            "NTLMv1 allowed: yes",
        ]
    });
    assert!(result_has_ntlmv1_signal(&Some(p)));
}

// ── result_has_seimpersonate_signal ────────────────────────────────────

#[test]
fn seimpersonate_signal_recognises_enabled_row() {
    use super::result_has_seimpersonate_signal;
    let p = json!({
        "summary": "SeImpersonatePrivilege  Impersonate a client after authentication  Enabled"
    });
    assert!(result_has_seimpersonate_signal(&Some(p)));
}

#[test]
fn seimpersonate_signal_rejects_disabled_row() {
    use super::result_has_seimpersonate_signal;
    let p = json!({
        "summary": "SeImpersonatePrivilege  Impersonate a client after authentication  Disabled"
    });
    assert!(!result_has_seimpersonate_signal(&Some(p)));
}

#[test]
fn seimpersonate_signal_rejects_mention_without_state() {
    use super::result_has_seimpersonate_signal;
    let p = json!({"summary": "plan: check for SeImpersonatePrivilege next"});
    assert!(!result_has_seimpersonate_signal(&Some(p)));
}

#[test]
fn seimpersonate_signal_walks_tool_outputs_object_form() {
    use super::result_has_seimpersonate_signal;
    let p = json!({
        "tool_outputs": [
            {"name": "whoami", "output": "SeImpersonatePrivilege ... Enabled"}
        ]
    });
    assert!(result_has_seimpersonate_signal(&Some(p)));
}

#[test]
fn seimpersonate_signal_none_payload_false() {
    use super::result_has_seimpersonate_signal;
    assert!(!result_has_seimpersonate_signal(&None));
}

// ── result_has_ccache_evidence ─────────────────────────────────────────

#[test]
fn ccache_evidence_recognises_canonical_saving_line() {
    use super::result_has_ccache_evidence;
    let p = json!({"summary": "Saving ticket in admin.ccache"});
    assert!(result_has_ccache_evidence(&Some(p)));
}

#[test]
fn ccache_evidence_walks_tool_outputs() {
    use super::result_has_ccache_evidence;
    let p = json!({
        "tool_outputs": [
            {"output": "Saving ticket in /tmp/svc.ccache"},
        ]
    });
    assert!(result_has_ccache_evidence(&Some(p)));
}

#[test]
fn ccache_evidence_requires_both_phrases() {
    use super::result_has_ccache_evidence;
    let p = json!({"summary": "Saving ticket in memory"});
    assert!(!result_has_ccache_evidence(&Some(p)));
    let p = json!({"summary": "found a .ccache file"});
    assert!(!result_has_ccache_evidence(&Some(p)));
}

#[test]
fn ccache_evidence_none_payload_false() {
    use super::result_has_ccache_evidence;
    assert!(!result_has_ccache_evidence(&None));
}

// ── result_text_indicates_failure ──────────────────────────────────────

#[test]
fn text_failure_recognises_summary_failure_prefixes() {
    use super::result_text_indicates_failure;
    let p = json!({"summary": "failed: account is locked out"});
    assert!(result_text_indicates_failure(&Some(p)));
    let p = json!({"summary": "FAILED ESC1 against template VulnTmpl"});
    assert!(result_text_indicates_failure(&Some(p)));
}

#[test]
fn text_failure_recognises_missing_parameter_errors() {
    use super::result_text_indicates_failure;
    let p = json!({"summary": "missing required ca_name field"});
    assert!(result_text_indicates_failure(&Some(p)));
    let p = json!({"summary": "missing CA"});
    assert!(result_text_indicates_failure(&Some(p)));
}

#[test]
fn text_failure_recognises_kerberos_errors() {
    use super::result_text_indicates_failure;
    let p = json!({"summary": "STATUS_ACCOUNT_LOCKED for alice"});
    assert!(result_text_indicates_failure(&Some(p)));
    let p = json!({"summary": "rpc_s_access_denied at DRSUAPI"});
    assert!(result_text_indicates_failure(&Some(p)));
    let p = json!({"summary": "invalidCredentials returned by DC"});
    assert!(result_text_indicates_failure(&Some(p)));
}

#[test]
fn text_failure_rejects_success_messages() {
    use super::result_text_indicates_failure;
    let p = json!({"summary": "credential captured: P@ssw0rd!"});
    assert!(!result_text_indicates_failure(&Some(p)));
    let p = json!({"summary": "ticket forged successfully"});
    assert!(!result_text_indicates_failure(&Some(p)));
}

#[test]
fn text_failure_falls_back_to_full_json_when_summary_missing() {
    use super::result_text_indicates_failure;
    // No summary field — fn serialises the whole value and looks for
    // failure markers within.
    let p = json!({"reason": "ept_s_not_registered on target"});
    assert!(result_text_indicates_failure(&Some(p)));
}

#[test]
fn text_failure_none_payload_false() {
    use super::result_text_indicates_failure;
    assert!(!result_text_indicates_failure(&None));
}

// ── parse_lockout_principal ─────────────────────────────────────────────

#[test]
fn parse_lockout_principal_canonical_netexec_line() {
    use super::parse_lockout_principal;
    let line = "[-] CONTOSO\\alice:Pw1! STATUS_ACCOUNT_LOCKED_OUT";
    let (user, dom) = parse_lockout_principal(line).unwrap();
    assert_eq!(user, "alice");
    assert_eq!(dom.as_deref(), Some("CONTOSO"));
}

#[test]
fn parse_lockout_principal_kdc_err_client_revoked_form() {
    use super::parse_lockout_principal;
    let line = "[*] CONTOSO\\bob:Welcome1 KDC_ERR_CLIENT_REVOKED";
    let (user, dom) = parse_lockout_principal(line).unwrap();
    assert_eq!(user, "bob");
    assert_eq!(dom.as_deref(), Some("CONTOSO"));
}

#[test]
fn parse_lockout_principal_rejects_bare_user_form() {
    use super::parse_lockout_principal;
    // `bob:pass` without `DOMAIN\` — must NOT be parsed (the contract is
    // that lockout extraction only fires for canonical DOMAIN\user tokens).
    let line = "[-] bob:Welcome1 STATUS_ACCOUNT_LOCKED_OUT";
    assert!(parse_lockout_principal(line).is_none());
}

#[test]
fn parse_lockout_principal_no_lockout_marker_returns_none() {
    use super::parse_lockout_principal;
    let line = "[+] CONTOSO\\alice:Pw1! Pwn3d!";
    assert!(parse_lockout_principal(line).is_none());
}

#[test]
fn parse_lockout_principal_empty_user_or_domain_rejected() {
    use super::parse_lockout_principal;
    // Domain-less or user-less prefixes return None.
    let line = "[-] \\alice:pw STATUS_ACCOUNT_LOCKED_OUT";
    assert!(parse_lockout_principal(line).is_none());
    let line = "[-] CONTOSO\\:pw STATUS_ACCOUNT_LOCKED_OUT";
    assert!(parse_lockout_principal(line).is_none());
}

// ── extract_locked_usernames_from_result ────────────────────────────────

#[test]
fn locked_usernames_walks_tool_outputs_strings() {
    use super::extract_locked_usernames_from_result;
    let p = json!({
        "tool_outputs": [
            "[-] CONTOSO\\alice:Pw STATUS_ACCOUNT_LOCKED_OUT",
            "[-] CONTOSO\\bob:Pw KDC_ERR_CLIENT_REVOKED",
        ]
    });
    let mut out = extract_locked_usernames_from_result(&Some(p));
    out.sort();
    assert_eq!(
        out,
        vec![
            ("alice".to_string(), Some("contoso".to_string())),
            ("bob".to_string(), Some("contoso".to_string())),
        ]
    );
}

#[test]
fn locked_usernames_skips_built_in_disabled_principals() {
    use super::extract_locked_usernames_from_result;
    let p = json!({
        "tool_outputs": [
            "[-] CONTOSO\\guest:Pw STATUS_ACCOUNT_LOCKED_OUT",
            "[-] CONTOSO\\krbtgt:Pw STATUS_ACCOUNT_LOCKED_OUT",
            "[-] CONTOSO\\alice:Pw STATUS_ACCOUNT_LOCKED_OUT",
        ]
    });
    let out = extract_locked_usernames_from_result(&Some(p));
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].0, "alice");
}

#[test]
fn locked_usernames_dedupes_repeated_lines() {
    use super::extract_locked_usernames_from_result;
    let p = json!({
        "tool_outputs": [
            "[-] CONTOSO\\alice:Pw STATUS_ACCOUNT_LOCKED_OUT",
            "[-] CONTOSO\\alice:Pw STATUS_ACCOUNT_LOCKED_OUT",
        ]
    });
    let out = extract_locked_usernames_from_result(&Some(p));
    assert_eq!(out.len(), 1);
}

#[test]
fn locked_usernames_lowercases_user_and_domain() {
    use super::extract_locked_usernames_from_result;
    let p = json!({"summary": "[-] CONTOSO\\Alice:pw STATUS_ACCOUNT_LOCKED_OUT"});
    let out = extract_locked_usernames_from_result(&Some(p));
    assert_eq!(
        out,
        vec![("alice".to_string(), Some("contoso".to_string()))]
    );
}

#[test]
fn locked_usernames_none_payload_empty() {
    use super::extract_locked_usernames_from_result;
    assert!(extract_locked_usernames_from_result(&None).is_empty());
}

#[test]
fn locked_usernames_no_lockout_lines_empty() {
    use super::extract_locked_usernames_from_result;
    let p = json!({"summary": "[+] CONTOSO\\alice:Pw Pwn3d!"});
    assert!(extract_locked_usernames_from_result(&Some(p)).is_empty());
}

mod reconcile_extracted_credential_domain {
    use super::super::reconcile_extracted_credential_domain;
    use ares_core::models::User;

    fn user(username: &str, domain: &str) -> User {
        User {
            username: username.to_string(),
            domain: domain.to_string(),
            description: String::new(),
            is_admin: false,
            source: "kerberos_enum".to_string(),
        }
    }

    #[test]
    fn corrects_when_username_unique_in_other_domain() {
        let users = vec![user("alice", "child.contoso.local")];
        let got = reconcile_extracted_credential_domain(&users, "alice", "contoso.local");
        assert_eq!(got, Some("child.contoso.local".to_string()));
    }

    #[test]
    fn case_insensitive_username_match() {
        let users = vec![user("Alice", "child.contoso.local")];
        let got = reconcile_extracted_credential_domain(&users, "ALICE", "contoso.local");
        assert_eq!(got, Some("child.contoso.local".to_string()));
    }

    #[test]
    fn no_correction_when_extracted_matches_known_domain() {
        let users = vec![user("alice", "child.contoso.local")];
        let got = reconcile_extracted_credential_domain(&users, "alice", "CHILD.contoso.local");
        assert_eq!(got, None);
    }

    #[test]
    fn no_correction_when_user_unknown() {
        let users = vec![user("bob", "contoso.local")];
        let got = reconcile_extracted_credential_domain(&users, "alice", "contoso.local");
        assert_eq!(got, None);
    }

    #[test]
    fn no_correction_when_user_ambiguous_across_domains() {
        // Same username in two domains (e.g. Administrator in parent + child) —
        // can't disambiguate, so the extractor's guess stands.
        let users = vec![
            user("administrator", "contoso.local"),
            user("administrator", "child.contoso.local"),
        ];
        let got = reconcile_extracted_credential_domain(&users, "administrator", "contoso.local");
        assert_eq!(got, None);
    }

    #[test]
    fn ignores_state_users_with_empty_domain() {
        // An anomalous user row with no domain is not a usable signal.
        let users = vec![user("alice", "")];
        let got = reconcile_extracted_credential_domain(&users, "alice", "contoso.local");
        assert_eq!(got, None);
    }

    #[test]
    fn duplicate_domains_collapse_to_one_match() {
        // Two state.users rows for the same principal (e.g. discovered via two
        // different enumeration tools) should still be treated as a unique
        // domain assignment.
        let users = vec![
            user("alice", "child.contoso.local"),
            user("alice", "CHILD.contoso.local"),
        ];
        let got = reconcile_extracted_credential_domain(&users, "alice", "contoso.local");
        assert_eq!(got, Some("child.contoso.local".to_string()));
    }
}
