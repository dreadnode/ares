use super::parsing::{has_domain_admin_indicator, parse_discoveries, resolve_parent_id};
use ares_core::models::{Credential, Hash};
use serde_json::json;

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
fn da_indicator_explicit_flag() {
    assert!(has_domain_admin_indicator(
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
