use super::admin_checks::{
    extract_ip_from_line, has_golden_ticket_indicator, parse_pwned_line, resolve_da_path,
};
use super::parsing::{has_domain_admin_indicator, parse_discoveries, resolve_parent_id};
use super::timeline::{
    admin_upgrade_description, credential_techniques, hash_techniques, is_critical_hash,
};
use super::{
    extract_asrep_roastable_users, result_has_credential_evidence, result_has_parser_evidence,
};
use crate::orchestrator::state::StateInner;
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
    // The credential is kept, but `ntlm_relay` is no parser's label, so the
    // provenance claim does not survive into state.
    assert_eq!(parsed.credentials[0].source, "llm_reported");
}

/// A payload can claim any `source` it likes; only labels a parser actually
/// emits are carried through. Without this, emitting `"source": "secretsdump"`
/// bought the top trust tier and, with it, the right to displace a realm a
/// real dump had pinned.
#[test]
fn parse_credential_strips_an_unearned_provenance_claim() {
    let payload = json!({
        "credential": {
            "id": "c1", "username": "admin", "password": "P@ss1",
            "domain": "contoso.local", "source": "secretsdump", "is_admin": false,
            "attack_step": 0
        }
    });
    let parsed = parse_discoveries(&payload);
    assert_eq!(parsed.credentials.len(), 1);
    assert_eq!(parsed.credentials[0].source, "llm_reported");
}

/// A label a parser really does emit passes through untouched.
#[test]
fn parse_credential_keeps_a_real_parser_source() {
    let payload = json!({
        "credentials": [{
            "id": "c1", "username": "admin", "password": "P@ss1",
            "domain": "contoso.local", "source": "laps_dump", "is_admin": false,
            "attack_step": 0
        }]
    });
    let parsed = parse_discoveries(&payload);
    assert_eq!(parsed.credentials[0].source, "laps_dump");
}

#[test]
fn parse_cracked_password() {
    let payload =
        json!({"cracked_password": "Summer2024!", "username": "jdoe", "domain": "contoso.local"});
    let parsed = parse_discoveries(&payload);
    assert_eq!(parsed.credentials.len(), 1);
    assert_eq!(parsed.credentials[0].username, "jdoe");
    assert_eq!(parsed.credentials[0].password, "Summer2024!");
    // Minted from free text in the payload, not a cracker's stdout — it must
    // not share a tier with regex-verified `cracked:hashcat`.
    assert_eq!(parsed.credentials[0].source, "llm_reported");
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
    assert_eq!(parsed.credentials[0].source, "llm_reported");
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

fn state_with_krbtgt_from(source: &str) -> StateInner {
    let mut state = StateInner::new("op-test".to_string());
    let mut hash = make_test_hash("h-krbtgt", "krbtgt", "contoso.local", 0);
    hash.source = source.to_string();
    state.hashes.push(hash);
    state
}

#[test]
fn da_path_names_the_capturing_tool() {
    let state = state_with_krbtgt_from("certipy_esc1_full_chain");
    assert_eq!(
        resolve_da_path(&state),
        Some("certipy_esc1_full_chain → krbtgt NTLM hash".to_string())
    );
}

#[test]
fn da_path_reports_secretsdump_only_when_secretsdump_ran() {
    let state = state_with_krbtgt_from("secretsdump");
    assert_eq!(
        resolve_da_path(&state),
        Some("secretsdump → krbtgt NTLM hash".to_string())
    );
}

#[test]
fn da_path_is_none_without_a_krbtgt_capture() {
    let state = StateInner::new("op-test".to_string());
    assert_eq!(resolve_da_path(&state), None);
}

#[test]
fn da_path_ignores_an_unsourced_krbtgt_hash() {
    let state = state_with_krbtgt_from("");
    assert_eq!(resolve_da_path(&state), None);
}

#[test]
fn da_path_does_not_read_agent_authored_claims() {
    let mut state = state_with_krbtgt_from("secretsdump");
    state.domain_admin_path = Some("spray → Administrator".to_string());
    assert_eq!(
        resolve_da_path(&state),
        Some("secretsdump → krbtgt NTLM hash".to_string())
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
        "tool_outputs": [
            "[-] CONTOSO\\testuser1:testuser1 KDC_ERR_CLIENT_REVOKED"
        ]
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

/// A silver ticket's only product is an SPN-scoped ccache — the same shape the
/// delegation primitives have. Without the prefix here, a clean
/// `generate_silver_ticket` run against an injected/queued `silver_ticket_*`
/// vuln is recorded as a FAILED exploit despite ticketer exiting 0.
#[test]
fn is_ticket_grant_vuln_recognizes_silver_ticket() {
    use super::is_ticket_grant_vuln;
    assert!(is_ticket_grant_vuln("silver_ticket_192.168.58.51_SQL01$"));
    assert!(is_ticket_grant_vuln("SILVER_TICKET_sql01_svc_sql"));
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
        "tool_outputs": [
            {"output": "[*] Impersonating Administrator\n\
                        [*] Requesting S4U2self\n\
                        [*] Requesting S4U2Proxy\n\
                        [*] Saving ticket in Administrator@cifs_dc01@CONTOSO.LOCAL.ccache"}
        ]
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
fn exploit_failure_reason_prefers_explicit_error() {
    use super::exploit_failure_reason;
    let result = Some(json!({ "summary": "fallback summary" }));
    assert_eq!(
        exploit_failure_reason(Some("rpc_s_access_denied"), &result),
        "rpc_s_access_denied"
    );
}

#[test]
fn exploit_failure_reason_falls_back_to_summary() {
    use super::exploit_failure_reason;
    let result = Some(json!({
        "summary": "S4U failed for WS01$ -> HTTP/dc01: KDC_ERR_BADOPTION (KDC cannot accommodate requested option)"
    }));
    let reason = exploit_failure_reason(None, &result);
    assert!(
        reason.contains("KDC_ERR_BADOPTION"),
        "an LLM-reported diagnosis must survive into the timeline event, got {reason:?}"
    );
}

#[test]
fn exploit_failure_reason_ignores_blank_error_and_summary() {
    use super::exploit_failure_reason;
    assert_eq!(
        exploit_failure_reason(Some("   "), &Some(json!({ "summary": "  " }))),
        "unknown error"
    );
    assert_eq!(exploit_failure_reason(None, &None), "unknown error");
}

#[test]
fn is_acl_mutation_vuln_recognizes_acl_prefixes() {
    use super::is_acl_mutation_vuln;
    assert!(is_acl_mutation_vuln("acl_writeproperty_alice_bob"));
    assert!(is_acl_mutation_vuln("acl_genericall_alice_krbtgt"));
    assert!(is_acl_mutation_vuln("ACL_ALLEXTENDEDRIGHTS_ALICE_ADMIN"));
    assert!(is_acl_mutation_vuln("acl_genericwrite_alice_dc01"));
}

#[test]
fn is_acl_mutation_vuln_recognizes_gpo_prefixes() {
    use super::is_acl_mutation_vuln;
    assert!(is_acl_mutation_vuln(
        "gpo_genericall_alice_default_domain_policy"
    ));
    assert!(is_acl_mutation_vuln(
        "gpo_writeproperty_alice_default_domain_policy"
    ));
    assert!(is_acl_mutation_vuln(
        "GPO_WRITEDACL_ALICE_DEFAULT_DOMAIN_CONTROLLERS_POLICY"
    ));
    assert!(is_acl_mutation_vuln(
        "gpo_writeowner_alice_default_domain_policy"
    ));
}

#[test]
fn is_acl_mutation_vuln_rejects_non_acl_primitives() {
    use super::is_acl_mutation_vuln;
    assert!(!is_acl_mutation_vuln("adcs_esc1_192.168.58.50"));
    assert!(!is_acl_mutation_vuln("rbcd_dc01_target"));
    assert!(!is_acl_mutation_vuln("dc_secretsdump_192.168.58.240"));
    assert!(!is_acl_mutation_vuln("golden_ticket_child.contoso.local"));
    assert!(!is_acl_mutation_vuln(""));
}

#[test]
fn is_ticket_grant_vuln_recognizes_golden_ticket_prefix() {
    use super::is_ticket_grant_vuln;
    assert!(is_ticket_grant_vuln("golden_ticket_child.contoso.local"));
    assert!(is_ticket_grant_vuln("golden_ticket_contoso.local"));
    assert!(is_ticket_grant_vuln("GOLDEN_TICKET_CONTOSO.LOCAL"));
}

#[test]
fn is_exploit_scoped_task_id_recognizes_all_exploit_families() {
    use super::is_exploit_scoped_task_id;
    assert!(is_exploit_scoped_task_id("exploit_abcdef123456"));
    assert!(is_exploit_scoped_task_id("lateral_abcdef123456"));
    assert!(is_exploit_scoped_task_id("privesc_abcdef123456"));
}

#[test]
fn is_exploit_scoped_task_id_rejects_unrelated_task_types() {
    use super::is_exploit_scoped_task_id;
    assert!(!is_exploit_scoped_task_id("recon_abcdef123456"));
    assert!(!is_exploit_scoped_task_id("credential_access_abcdef123456"));
    assert!(!is_exploit_scoped_task_id("coercion_abcdef123456"));
    assert!(!is_exploit_scoped_task_id("acl_chain_step_abcdef123456"));
    assert!(!is_exploit_scoped_task_id(""));
}

#[test]
fn acl_evidence_rejects_pywhisker_keycredlink_write() {
    use super::{result_has_acl_mutation_evidence, result_has_shadow_cred_stage_one};
    let payload = json!({
        "tool_outputs": [
            {"output": "[+] KeyCredential generated with DeviceID: 4b1c9f2a-1234-4a2b-9c3d-abcdef012345\n\
                        [+] Updated the msDS-KeyCredentialLink attribute of the target object\n\
                        [+] Saved PFX (#PKCS12) certificate & key at path: /tmp/ws01.pfx"}
        ]
    });
    assert!(
        !result_has_acl_mutation_evidence(&Some(payload.clone())),
        "the write is stage one of a two-stage chain and proves no credential was recovered"
    );
    assert!(result_has_shadow_cred_stage_one(&Some(payload)));
}

#[test]
fn shadow_cred_stage_one_lines_are_recognised_but_never_credit() {
    use super::{result_has_acl_mutation_evidence, result_has_shadow_cred_stage_one};
    for line in [
        "[+] Updated the msDS-KeyCredentialLink attribute of the target object",
        "[+] Saved PFX (#PKCS12) certificate & key at path: /tmp/ws01.pfx",
        "[+] Successfully added msDS-KeyCredentialLink to the target",
    ] {
        let payload = json!({ "tool_outputs": [{"output": line}] });
        assert!(
            !result_has_acl_mutation_evidence(&Some(payload.clone())),
            "stage-one line must not credit on its own: {line}"
        );
        assert!(
            result_has_shadow_cred_stage_one(&Some(payload)),
            "stage-one line must stay detectable for the log: {line}"
        );
    }
}

fn certipy_shadow_result(transcript: &str) -> serde_json::Value {
    let params = json!({"domain": "contoso.local", "target": "dc01$", "dc_ip": "192.168.58.10"});
    let discoveries =
        ares_tools::parsers::merge_discoveries(&[ares_tools::parsers::parse_tool_output(
            "certipy_shadow",
            transcript,
            &params,
        )]);
    json!({
        "summary": "Successfully exploited shadow_credentials (GenericAll) as alice against dc01$",
        "vuln_id": "acl_genericall_alice_dc01$",
        "discoveries": discoveries,
        "tool_outputs": [{"name": "certipy_shadow", "output": transcript}],
    })
}

const CERTIPY_SHADOW_RECOVERED_HASH: &str = "\
[*] Targeting user 'DC01$'\n\
[*] Generating Key Credential\n\
[*] Adding Key Credential with device ID '4b1c9f2a-1234-4a2b-9c3d-abcdef012345' to the Key Credentials for 'DC01$'\n\
[*] Successfully added Key Credential with device ID '4b1c9f2a-1234-4a2b-9c3d-abcdef012345' to the Key Credentials for 'DC01$'\n\
[*] Authenticating as 'DC01$' with the certificate\n\
[*] Got TGT\n\
[*] Wrote credential cache to 'dc01.ccache'\n\
[*] Successfully restored the old Key Credentials for 'DC01$'\n\
[*] NT hash for 'DC01$': 0123456789abcdef0123456789abcdef";

const CERTIPY_SHADOW_STAGE_ONE_ONLY: &str = "\
[*] Targeting user 'DC01$'\n\
[*] Generating Key Credential\n\
[*] Adding Key Credential with device ID '4b1c9f2a-1234-4a2b-9c3d-abcdef012345' to the Key Credentials for 'DC01$'\n\
[*] Successfully added Key Credential with device ID '4b1c9f2a-1234-4a2b-9c3d-abcdef012345' to the Key Credentials for 'DC01$'\n\
[*] Authenticating as 'DC01$' with the certificate\n\
[-] Got error while trying to request TGT: KDC_ERR_CLIENT_NAME_MISMATCH\n\
[*] Successfully restored the old Key Credentials for 'DC01$'\n\
[*] NT hash for 'DC01$': None";

#[test]
fn completed_shadow_cred_chain_satisfies_the_exploit_evidence_gate() {
    let payload = Some(certipy_shadow_result(CERTIPY_SHADOW_RECOVERED_HASH));
    assert!(
        result_has_parser_evidence(&payload),
        "a recovered NT hash is parser-grounded evidence and must credit the vulnerability"
    );
    assert!(
        result_has_credential_evidence(&payload),
        "the recovered hash must also count as credential evidence for host ownership"
    );
    let parsed = parse_discoveries(payload.as_ref().unwrap().get("discoveries").unwrap());
    assert_eq!(parsed.hashes.len(), 1, "{parsed:?}");
    assert_eq!(parsed.hashes[0].username, "dc01$");
    assert_eq!(parsed.hashes[0].domain, "contoso.local");
    assert_eq!(
        parsed.hashes[0].hash_value,
        "aad3b435b51404eeaad3b435b51404ee:0123456789abcdef0123456789abcdef"
    );
}

#[test]
fn stage_one_only_shadow_cred_chain_is_still_not_credited() {
    use super::{result_has_acl_mutation_evidence, result_has_shadow_cred_stage_one};
    let payload = Some(certipy_shadow_result(CERTIPY_SHADOW_STAGE_ONE_ONLY));
    assert!(
        !result_has_parser_evidence(&payload),
        "a Key Credential write with no recovered credential must not credit"
    );
    assert!(
        !result_has_acl_mutation_evidence(&payload),
        "certipy_shadow status lines must not stand in for a recovered credential"
    );
    assert!(
        result_has_shadow_cred_stage_one(&payload),
        "certipy's own wording must make the half-finished chain countable in the log"
    );
}

#[test]
fn acl_evidence_detects_bloodyad_grant_and_group_add() {
    use super::result_has_acl_mutation_evidence;
    let genericall = json!({
        "tool_outputs": [{"output": "[+] alice has now GenericAll on dc01"}]
    });
    assert!(result_has_acl_mutation_evidence(&Some(genericall)));

    let group = json!({
        "tool_outputs": [{
            "name": "bloodyad_add_group_member",
            "output": "[+] alice added to Domain Admins"
        }]
    });
    assert!(result_has_acl_mutation_evidence(&Some(group)));
}

/// "added to" and "has been updated" are ordinary English that unrelated tools
/// print. Crediting them anywhere in the task lets any co-running tool mark the
/// ACL vulnerability EXPLOITED — the same metric lie as "ACL success is
/// structurally impossible", just inverted.
#[test]
fn acl_evidence_ignores_generic_markers_from_unrelated_tools() {
    use super::result_has_acl_mutation_evidence;
    for output in [
        "[*] 192.168.58.60 added to the target scope",
        "[+] Kerberos ticket cache has been updated",
        "[+] svc_sql added to the roastable SPN list",
    ] {
        let payload = json!({
            "tool_outputs": [{"name": "enumerate_users", "output": output}]
        });
        assert!(
            !result_has_acl_mutation_evidence(&Some(payload)),
            "an unrelated tool must not credit an ACL edge: {output}"
        );
    }
}

/// An unnamed entry cannot be attributed, so the generic markers must not fire
/// for it either. The specific ones still do — they name the primitive.
#[test]
fn acl_evidence_requires_attribution_for_generic_markers() {
    use super::result_has_acl_mutation_evidence;

    let unattributed = json!({
        "tool_outputs": [{"output": "[+] alice added to Domain Admins"}]
    });
    assert!(!result_has_acl_mutation_evidence(&Some(unattributed)));

    let specific = json!({
        "tool_outputs": [{"output": "[+] alice has now GenericAll on dc01"}]
    });
    assert!(
        result_has_acl_mutation_evidence(&Some(specific)),
        "a marker naming the primitive stands on its own"
    );
}

/// The generic markers are still needed: bloodyAD's group-add and attribute
/// write print nothing more distinctive than these.
#[test]
fn acl_evidence_credits_generic_markers_from_the_acl_tool_itself() {
    use super::result_has_acl_mutation_evidence;
    for (tool, output) in [
        (
            "bloodyad_add_group_member",
            "[+] alice added to Domain Admins",
        ),
        (
            "bloodyad_set_object_attr",
            "[+] servicePrincipalName has been updated",
        ),
    ] {
        let payload = json!({ "tool_outputs": [{"name": tool, "output": output}] });
        assert!(
            result_has_acl_mutation_evidence(&Some(payload)),
            "{tool} must still credit its own success line"
        );
    }
}

#[test]
fn acl_evidence_credits_llm_driven_gpo_abuse() {
    use super::result_has_acl_mutation_evidence;
    let pygpoabuse = json!({
        "tool_outputs": [{
            "name": "pygpoabuse_immediate_task",
            "output": "[+] Version updated\n[+] ScheduledTask AresProbe created!"
        }]
    });
    assert!(result_has_acl_mutation_evidence(&Some(pygpoabuse)));

    let sharpgpoabuse = json!({
        "tool_outputs": [{
            "name": "sharpgpoabuse",
            "output": "[+] versionNumber attribute changed successfully\n[+] Done!"
        }]
    });
    assert!(result_has_acl_mutation_evidence(&Some(sharpgpoabuse)));
}

#[test]
fn acl_evidence_ignores_gpo_markers_from_unrelated_tools() {
    use super::result_has_acl_mutation_evidence;
    for output in [
        "[+] ScheduledTask enumeration complete",
        "[*] Done!",
        "[+] Version updated",
    ] {
        let payload = json!({
            "tool_outputs": [{"name": "enumerate_users", "output": output}]
        });
        assert!(
            !result_has_acl_mutation_evidence(&Some(payload)),
            "an unrelated tool must not credit a GPO write: {output}"
        );
    }
}

#[test]
fn acl_evidence_ignores_gpo_failure_output() {
    use super::result_has_acl_mutation_evidence;
    for output in [
        "[-] Unable to write to the GPO: insufficient access rights",
        "[!] Failed to open connection: KDC_ERR_PREAUTH_FAILED",
        "[+] GUID of the GPO is {31B2F340-016D-11D2-945F-00C04FB984F9}",
    ] {
        let payload = json!({
            "tool_outputs": [{"name": "pygpoabuse_immediate_task", "output": output}]
        });
        assert!(
            !result_has_acl_mutation_evidence(&Some(payload)),
            "a GPO run without a write marker must not be credited: {output}"
        );
    }
}

#[test]
fn acl_evidence_detects_dacledit_and_password_reset() {
    use super::result_has_acl_mutation_evidence;
    let dacl = json!({
        "tool_outputs": [
            {"output": "[*] DACL backed up to dacledit-20260728.bak\n[*] DACL modified successfully!"}
        ]
    });
    assert!(result_has_acl_mutation_evidence(&Some(dacl)));

    let reset = json!({
        "tool_outputs": [{"output": "[+] Password changed successfully!"}]
    });
    assert!(result_has_acl_mutation_evidence(&Some(reset)));
}

#[test]
fn acl_evidence_rejects_insufficient_access_rights() {
    use super::result_has_acl_mutation_evidence;
    let payload = json!({
        "tool_outputs": [
            {"output": "[-] pywhisker error: INSUFF_ACCESS_RIGHTS when writing msDS-KeyCredentialLink for target WS01$"}
        ]
    });
    assert!(!result_has_acl_mutation_evidence(&Some(payload)));
}

#[test]
fn acl_evidence_rejects_llm_prose_without_tool_marker() {
    use super::result_has_acl_mutation_evidence;
    let payload = json!({
        "tool_outputs": [
            {"output": "I would have added to the group once the DACL modified successfully, but auth failed."}
        ]
    });
    assert!(!result_has_acl_mutation_evidence(&Some(payload)));
}

#[test]
fn shadow_cred_stage_one_alone_does_not_credit() {
    use super::{
        is_acl_mutation_vuln, result_has_acl_mutation_evidence, result_has_parser_evidence,
        result_has_shadow_cred_stage_one, result_text_indicates_failure,
    };
    let vuln_id = "acl_genericall_alice_krbtgt";
    let result = Some(json!({
        "vuln_id": vuln_id,
        "summary": "Added shadow credentials to krbtgt and exported the PFX.",
        "tool_outputs": [
            {"name": "pywhisker",
             "output": "[+] KeyCredential generated with DeviceID: 4b1c9f2a-1234-4a2b-9c3d-abcdef012345\n\
                        [+] Updated the msDS-KeyCredentialLink attribute of the target object\n\
                        [+] Saved PFX (#PKCS12) certificate & key at path: /tmp/krbtgt.pfx"}
        ]
    }));

    assert!(
        !result_has_parser_evidence(&result),
        "no hash was recovered, so nothing reaches discoveries"
    );
    assert!(
        result_has_shadow_cred_stage_one(&result),
        "the write itself must still be detectable, so the gap can be logged"
    );

    let task_reported_success = true;
    let has_acl_evidence =
        is_acl_mutation_vuln(vuln_id) && result_has_acl_mutation_evidence(&result);
    let actually_succeeded = task_reported_success
        && !result_text_indicates_failure(&result)
        && (result_has_parser_evidence(&result) || has_acl_evidence);

    assert!(
        !actually_succeeded,
        "a msDS-KeyCredentialLink write with no PKINIT stage recovers no credential and must not be credited"
    );
}

#[test]
fn shadow_cred_stage_two_credits_via_parser_evidence() {
    use super::{
        is_acl_mutation_vuln, result_has_acl_mutation_evidence, result_has_parser_evidence,
        result_text_indicates_failure,
    };
    let vuln_id = "acl_genericall_alice_krbtgt";
    let result = Some(json!({
        "vuln_id": vuln_id,
        "summary": "Wrote msDS-KeyCredentialLink, then authenticated with the PFX.",
        "discoveries": {
            "hashes": [{"username": "krbtgt", "domain": "contoso.local",
                        "hash": "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0"}]
        },
        "tool_outputs": [
            {"name": "pywhisker",
             "output": "[+] Saved PFX (#PKCS12) certificate & key at path: /tmp/krbtgt.pfx"},
            {"name": "certipy_auth",
             "output": "[*] Got hash for 'krbtgt@contoso.local': aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0"}
        ]
    }));

    let has_acl_evidence =
        is_acl_mutation_vuln(vuln_id) && result_has_acl_mutation_evidence(&result);
    let actually_succeeded = !result_text_indicates_failure(&result)
        && (result_has_parser_evidence(&result) || has_acl_evidence);

    assert!(
        actually_succeeded,
        "the completed chain must credit — and via parser evidence, not the ACL carve-out"
    );
    assert!(
        !has_acl_evidence,
        "credit must come from the recovered hash, so the carve-out stays narrow"
    );
}

#[test]
fn pywhisker_generic_success_line_does_not_credit() {
    use super::result_has_acl_mutation_evidence;
    let result = Some(json!({
        "tool_outputs": [
            {"name": "pywhisker",
             "output": "[*] Certificate added to the target object\n[+] Done!"}
        ]
    }));
    assert!(
        !result_has_acl_mutation_evidence(&result),
        "generic attributed markers must not credit a stage-one-only tool"
    );
}

#[test]
fn error_indicates_assistance_matches_submission_format() {
    use super::error_indicates_assistance;
    assert!(error_indicates_assistance(Some(
        "Assistance needed: Shadow credentials PFX generated (context: ...)"
    )));
    assert!(error_indicates_assistance(Some(
        "assistance needed: lower case variant"
    )));
    assert!(!error_indicates_assistance(Some("rpc_s_access_denied")));
    assert!(!error_indicates_assistance(Some("Agent hit max steps")));
    assert!(!error_indicates_assistance(Some("")));
    assert!(!error_indicates_assistance(None));
}

#[test]
fn assisted_shadow_cred_stage_one_does_not_credit() {
    use super::{
        error_indicates_assistance, is_acl_mutation_vuln, result_has_acl_mutation_evidence,
        result_text_indicates_failure,
    };
    let vuln_id = "acl_genericall_alice_krbtgt";
    let err = "Assistance needed: Shadow credentials PFX generated for krbtgt (context: need PKINIT to convert)";
    let result = Some(json!({
        "vuln_id": vuln_id,
        "summary": "Wrote msDS-KeyCredentialLink and exported the PFX; need help converting it.",
        "tool_outputs": [
            {"name": "pywhisker",
             "output": "[+] Updated the msDS-KeyCredentialLink attribute of the target object\n\
                        [+] Saved PFX (#PKCS12) certificate & key at path: /tmp/krbtgt.pfx"}
        ]
    }));

    let has_acl_evidence =
        is_acl_mutation_vuln(vuln_id) && result_has_acl_mutation_evidence(&result);
    let assisted_with_evidence = error_indicates_assistance(Some(err))
        && !result_text_indicates_failure(&result)
        && has_acl_evidence;

    assert!(
        !assisted_with_evidence,
        "this is the live op-20260730-213328 failure: the agent said it could not convert the PFX, so there is nothing to credit"
    );
}

#[test]
fn assisted_terminal_acl_write_still_credits() {
    use super::{
        error_indicates_assistance, is_acl_mutation_vuln, result_has_acl_mutation_evidence,
        result_text_indicates_failure,
    };
    let vuln_id = "acl_genericall_alice_bob";
    let err = "Assistance needed: granted rights but cannot pick the next edge (context: ...)";
    let result = Some(json!({
        "vuln_id": vuln_id,
        "summary": "Granted GenericAll on the target.",
        "tool_outputs": [
            {"name": "bloodyad_add_genericall",
             "output": "[+] alice has now GenericAll on bob"}
        ]
    }));

    let has_acl_evidence =
        is_acl_mutation_vuln(vuln_id) && result_has_acl_mutation_evidence(&result);
    let assisted_with_evidence = error_indicates_assistance(Some(err))
        && !result_text_indicates_failure(&result)
        && has_acl_evidence;

    assert!(
        assisted_with_evidence,
        "an ACL write that is itself the objective must keep crediting — the marker split must not undo #327"
    );
}

#[test]
fn assisted_acl_write_without_evidence_stays_failed() {
    use super::{
        error_indicates_assistance, is_acl_mutation_vuln, result_has_acl_mutation_evidence,
    };
    let vuln_id = "acl_genericall_alice_krbtgt";
    let err =
        "Assistance needed: pywhisker shadow credentials failed: invalidCredentials (context: ...)";
    let result = Some(json!({
        "vuln_id": vuln_id,
        "tool_outputs": [
            {"name": "pywhisker",
             "output": "[-] pywhisker error: invalidCredentials binding to LDAP"}
        ]
    }));

    let has_acl_evidence =
        is_acl_mutation_vuln(vuln_id) && result_has_acl_mutation_evidence(&result);
    assert!(error_indicates_assistance(Some(err)));
    assert!(
        !has_acl_evidence,
        "an assistance request with no confirmed write must NOT be credited"
    );
}

#[test]
fn acl_evidence_empty_payload() {
    use super::result_has_acl_mutation_evidence;
    assert!(!result_has_acl_mutation_evidence(&None));
    assert!(!result_has_acl_mutation_evidence(&Some(json!({}))));
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
    async fn marks_exploited_for_gmsa_principal_read_by_a_gmsa_tool() {
        let state = SharedState::new("op-1".to_string());
        let q = mock_queue();
        emit_gmsa_exploit_token_if_gmsa(&state, &q, "gmsaDragon$", "gmsa_dump_passwords").await;
        let s = state.read().await;
        assert!(s.exploited_vulnerabilities.contains("gmsa_gmsadragon"));
    }

    #[tokio::test]
    async fn marks_exploited_for_bloodyad_managed_password_read() {
        let state = SharedState::new("op-1".to_string());
        let q = mock_queue();
        emit_gmsa_exploit_token_if_gmsa(&state, &q, "gmsaDragon$", "gmsa_read_password_bloodyad")
            .await;
        let s = state.read().await;
        assert!(s.exploited_vulnerabilities.contains("gmsa_gmsadragon"));
    }

    #[tokio::test]
    async fn no_op_for_gmsa_hash_arriving_from_dcsync() {
        let state = SharedState::new("op-1".to_string());
        let q = mock_queue();
        emit_gmsa_exploit_token_if_gmsa(&state, &q, "gmsaDragon$", "secretsdump").await;
        let s = state.read().await;
        assert!(s.exploited_vulnerabilities.is_empty());
    }

    #[tokio::test]
    async fn no_op_for_plain_machine_account() {
        // DC01$ ends with `$` but is not a gMSA — no token should be emitted.
        let state = SharedState::new("op-1".to_string());
        let q = mock_queue();
        emit_gmsa_exploit_token_if_gmsa(&state, &q, "DC01$", "gmsa_dump_passwords").await;
        let s = state.read().await;
        assert!(s.exploited_vulnerabilities.is_empty());
    }

    #[tokio::test]
    async fn no_op_for_regular_user() {
        let state = SharedState::new("op-1".to_string());
        let q = mock_queue();
        emit_gmsa_exploit_token_if_gmsa(&state, &q, "alice", "gmsa_dump_passwords").await;
        let s = state.read().await;
        assert!(s.exploited_vulnerabilities.is_empty());
    }

    #[tokio::test]
    async fn token_normalized_lowercase_for_mixed_case_input() {
        let state = SharedState::new("op-1".to_string());
        let q = mock_queue();
        emit_gmsa_exploit_token_if_gmsa(&state, &q, "GMSA_WEB$", "gmsa_dump_passwords").await;
        let s = state.read().await;
        assert!(s.exploited_vulnerabilities.contains("gmsa_gmsa_web"));
    }
}

mod seimpersonate_publish_only_contract {
    use super::super::build_seimpersonate_vuln;
    use crate::orchestrator::state::SharedState;
    use crate::orchestrator::task_queue::TaskQueueCore;
    use ares_core::state::mock_redis::MockRedisConnection;

    fn mock_queue() -> TaskQueueCore<MockRedisConnection> {
        TaskQueueCore::from_connection(MockRedisConnection::new())
    }

    #[tokio::test]
    async fn publish_records_vuln_without_marking_exploited() {
        let state = SharedState::new("op-1".to_string());
        let q = mock_queue();

        let vuln = build_seimpersonate_vuln("web01", Some("192.168.58.10"));
        let vuln_id = vuln.vuln_id.clone();
        assert_eq!(vuln_id, "seimpersonate_web01");
        assert_eq!(vuln.vuln_type, "seimpersonate");
        assert_eq!(vuln.recommended_agent, "privesc");

        let added = state.publish_vulnerability(&q, vuln).await.unwrap();
        assert!(added, "seimpersonate vuln should publish cleanly");

        let s = state.read().await;
        assert!(
            s.discovered_vulnerabilities.contains_key(&vuln_id),
            "vuln must be discoverable as a lead for the privesc agent"
        );
        assert!(
            !s.exploited_vulnerabilities.contains(&vuln_id),
            "publishing a seimpersonate lead MUST NOT credit exploitation \
             (no on-target primitive can actually escalate to SYSTEM here)"
        );
    }

    #[tokio::test]
    async fn vuln_id_falls_back_to_host_label_when_ip_missing() {
        let vuln = build_seimpersonate_vuln("web01", None);
        assert_eq!(vuln.vuln_id, "seimpersonate_web01");
        assert_eq!(vuln.target, "web01");
        assert!(!vuln.details.contains_key("target_ip"));
    }

    #[tokio::test]
    async fn note_documents_lead_only_status() {
        let vuln = build_seimpersonate_vuln("web01", Some("192.168.58.20"));
        let note = vuln
            .details
            .get("note")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_lowercase();
        assert!(
            note.contains("lead") && !note.contains("potato"),
            "note should mark the vuln as a lead-only observation and MUST NOT \
             promise potato-family exploitation (no on-target execution primitive \
             exists) — got: {note}"
        );
    }
}

#[test]
fn seimpersonate_signal_detects_enabled_in_whoami_priv_output() {
    use super::result_has_seimpersonate_signal;
    // Real-world `whoami /priv` row format from a service account context.
    let payload = json!({
        "tool_outputs": [
            {"output": "PRIVILEGES INFORMATION\n\
                        ----------------------\n\
                        Privilege Name                Description                                 State\n\
                        ============================= =========================================== ========\n\
                        SeAssignPrimaryTokenPrivilege Replace a process level token               Disabled\n\
                        SeImpersonatePrivilege        Impersonate a client after authentication   Enabled\n\
                        SeIncreaseQuotaPrivilege      Adjust memory quotas for a process          Disabled"}
        ]
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
        "tool_outputs": [
            {"output": "seimpersonateprivilege   description text   ENABLED"}
        ]
    });
    assert!(result_has_seimpersonate_signal(&Some(payload)));
}

#[test]
fn ntlmv1_signal_detects_explicit_verdict() {
    use super::result_has_ntlmv1_signal;
    let payload = json!({
        "tool_outputs": [
            {"output": "[+] NTLMv1 is allowed (LmCompatibilityLevel registry value indicates vulnerable config)"}
        ]
    });
    assert!(result_has_ntlmv1_signal(&Some(payload)));
}

#[test]
fn ntlmv1_signal_detects_lmcompat_le_2() {
    use super::result_has_ntlmv1_signal;
    for value in [0, 1, 2] {
        let payload = json!({
            "tool_outputs": [
                {"output": format!("LmCompatibilityLevel: {value}")}
            ]
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
            "tool_outputs": [
                {"output": format!("LmCompatibilityLevel: {value}")}
            ]
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
        "tool_outputs": [
            {"output": "LmCompatibilityLevel    REG_DWORD    0x2"}
        ]
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
        Some("kerberoast_contoso.local_sql_svc".to_string())
    );
}

#[test]
fn kerberoast_token_separates_the_same_account_in_two_forests() {
    use super::roast_exploit_token;
    let child = roast_exploit_token(
        "$krb5tgs$23$*svc_sql$CHILD.CONTOSO.LOCAL$cifs/dc02...",
        "svc_sql",
        "child.contoso.local",
    );
    let forest_b = roast_exploit_token(
        "$krb5tgs$23$*svc_sql$FABRIKAM.LOCAL$cifs/dc01...",
        "svc_sql",
        "fabrikam.local",
    );
    assert_eq!(
        child,
        Some("kerberoast_child.contoso.local_svc_sql".to_string())
    );
    assert_eq!(
        forest_b,
        Some("kerberoast_fabrikam.local_svc_sql".to_string())
    );
    assert_ne!(child, forest_b);
}

#[test]
fn kerberoast_token_falls_back_to_the_bare_account_without_a_realm() {
    use super::roast_exploit_token;
    assert_eq!(
        roast_exploit_token("$krb5tgs$23$*svc_sql$", "svc_sql", "   "),
        Some("kerberoast_svc_sql".to_string())
    );
}

#[test]
fn kerberoast_token_keeps_the_scoreboard_prefix() {
    use super::roast_exploit_token;
    let token = roast_exploit_token("$krb5tgs$23$*", "svc_sql", "contoso.local").unwrap();
    assert!(
        token.starts_with("kerberoast_"),
        "dreadgoad credits on the `kerberoast_` prefix — {token} would score as `other`"
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

#[tokio::test]
async fn roast_token_realm_folds_a_flat_name_onto_the_fqdn() {
    use super::{roast_exploit_token, roast_token_realm};
    use crate::orchestrator::state::SharedState;

    let state = SharedState::new("op-1".to_string());
    state
        .write()
        .await
        .domains
        .push("child.contoso.local".to_string());

    let from_fqdn = roast_token_realm(&state, "CHILD.CONTOSO.LOCAL").await;
    let from_flat = roast_token_realm(&state, "CHILD").await;
    assert_eq!(from_fqdn, "child.contoso.local");
    assert_eq!(
        from_flat, from_fqdn,
        "a NetBIOS capture and an FQDN capture of the same realm must key one token"
    );
    assert_eq!(
        roast_exploit_token("$krb5tgs$23$*", "svc_sql", &from_flat),
        roast_exploit_token("$krb5tgs$23$*", "svc_sql", &from_fqdn)
    );
}

#[tokio::test]
async fn roast_token_realm_keeps_an_unknown_label_rather_than_guessing() {
    use super::roast_token_realm;
    use crate::orchestrator::state::SharedState;

    let state = SharedState::new("op-1".to_string());
    assert_eq!(roast_token_realm(&state, " FABRIKAM ").await, "fabrikam");
    assert_eq!(roast_token_realm(&state, "  ").await, "");
}

#[test]
fn roast_credit_record_is_keyed_by_the_token_it_witnesses() {
    use super::{roast_credit_record, roast_exploit_token};
    let token = roast_exploit_token("$krb5tgs$23$*", "svc_sql", "contoso.local").unwrap();
    let record = roast_credit_record(&token, "svc_sql", "contoso.local", "kerberoast", "netexec");
    assert_eq!(
        record.vuln_id, token,
        "the record only closes the orphan credit if its id is the credited id"
    );
}

#[test]
fn roast_credit_record_carries_the_capture_evidence() {
    use super::roast_credit_record;
    let record = roast_credit_record(
        "kerberoast_contoso.local_svc_sql",
        "svc_sql",
        "contoso.local",
        "kerberoast",
        "impacket_getuserspns",
    );
    assert_eq!(record.vuln_type, "kerberoast");
    assert_eq!(record.target, "svc_sql");
    assert_eq!(record.details["account"], "svc_sql");
    assert_eq!(record.details["domain"], "contoso.local");
    assert_eq!(record.details["hash_type"], "kerberoast");
    assert_eq!(record.details["captured_by"], "impacket_getuserspns");
}

#[test]
fn asrep_credit_record_targets_the_domain_the_token_names() {
    use super::{roast_credit_record, roast_exploit_token};
    let token = roast_exploit_token("$krb5asrep$23$alice@", "alice", "contoso.local").unwrap();
    let record = roast_credit_record(&token, "alice", "contoso.local", "asrep_roast", "netexec");
    assert_eq!(token, "asrep_roast_contoso.local");
    assert_eq!(record.vuln_type, "asrep_roast");
    assert_eq!(record.target, "contoso.local");
    assert_eq!(record.details["account"], "alice");
}

#[test]
fn asrep_credit_record_targets_the_account_without_a_realm() {
    use super::roast_credit_record;
    let record = roast_credit_record("asrep_roast_alice", "alice", "", "asrep_roast", "netexec");
    assert_eq!(record.target, "alice");
}

#[test]
fn roast_credit_record_is_a_witness_not_a_work_item() {
    use super::roast_credit_record;
    let record = roast_credit_record(
        "kerberoast_contoso.local_svc_sql",
        "svc_sql",
        "contoso.local",
        "kerberoast",
        "netexec",
    );
    assert!(
        record.priority > 3,
        "priority must stay above ops loot's EXPLOITABLE_PRIORITY_MAX so an \
         already-proven primitive is not tabled as outstanding work, and above \
         the head of the exploitation ZSET so nothing pops it before the \
         caller marks it exploited"
    );
    assert!(
        crate::orchestrator::exploitation::is_automation_owned_vuln(&record.vuln_type),
        "{} would be dispatched by the generic exploitation workflow, \
         re-attacking a primitive that already succeeded",
        record.vuln_type
    );
}

#[test]
fn roast_token_lowercases_account_and_domain() {
    use super::roast_exploit_token;
    assert_eq!(
        roast_exploit_token("$krb5tgs$23$*", "SQL_SVC", "CONTOSO.LOCAL"),
        Some("kerberoast_contoso.local_sql_svc".to_string())
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
        let p = json!({"tool_outputs": [line]});
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
        let p = json!({"tool_outputs": [line]});
        assert!(
            result_has_ntlmv1_signal(&Some(p)),
            "LmCompatibilityLevel = {n} should be a positive",
        );
    }
}

#[test]
fn ntlmv1_signal_rejects_lmcompatibilitylevel_safe_values() {
    use super::result_has_ntlmv1_signal;
    let p = json!({"tool_outputs": ["LmCompatibilityLevel = 5"]});
    assert!(!result_has_ntlmv1_signal(&Some(p)));
    let p = json!({"tool_outputs": ["LmCompatibilityLevel = 3"]});
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

#[test]
fn ntlmv1_signal_ignores_scalar_output_field() {
    use super::result_has_ntlmv1_signal;
    let p = json!({"output": "LmCompatibilityLevel = 1"});
    assert!(!result_has_ntlmv1_signal(&Some(p)));
}

// ── result_has_seimpersonate_signal ────────────────────────────────────

#[test]
fn seimpersonate_signal_recognises_enabled_row() {
    use super::result_has_seimpersonate_signal;
    let p = json!({
        "tool_outputs": [
            "SeImpersonatePrivilege  Impersonate a client after authentication  Enabled"
        ]
    });
    assert!(result_has_seimpersonate_signal(&Some(p)));
}

#[test]
fn seimpersonate_signal_rejects_disabled_row() {
    use super::result_has_seimpersonate_signal;
    let p = json!({
        "tool_outputs": [
            "SeImpersonatePrivilege  Impersonate a client after authentication  Disabled"
        ]
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

#[test]
fn seimpersonate_signal_ignores_scalar_output_field() {
    use super::result_has_seimpersonate_signal;
    let p = json!({
        "output": "SeImpersonatePrivilege  Impersonate a client after authentication  Enabled"
    });
    assert!(!result_has_seimpersonate_signal(&Some(p)));
}

// ── result_has_ccache_evidence ─────────────────────────────────────────

#[test]
fn ccache_evidence_recognises_canonical_saving_line() {
    use super::result_has_ccache_evidence;
    let p = json!({"tool_outputs": ["Saving ticket in admin.ccache"]});
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

#[test]
fn ccache_evidence_ignores_scalar_output_field() {
    use super::result_has_ccache_evidence;
    let p = json!({"output": "Saving ticket in admin.ccache"});
    assert!(!result_has_ccache_evidence(&Some(p)));
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
    let p = json!({"tool_outputs": ["[-] CONTOSO\\Alice:pw STATUS_ACCOUNT_LOCKED_OUT"]});
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
fn locked_usernames_ignores_scalar_output_field() {
    use super::extract_locked_usernames_from_result;
    let p = json!({"output": "[-] CONTOSO\\alice:Pw STATUS_ACCOUNT_LOCKED_OUT"});
    assert!(extract_locked_usernames_from_result(&Some(p)).is_empty());
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
            member_of: Vec::new(),
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

mod reconcile_low_trust_credential_domain {
    use super::super::reconcile_low_trust_credential_domain;
    use ares_core::models::{Credential, User};

    fn user(username: &str, domain: &str) -> User {
        User {
            username: username.to_string(),
            domain: domain.to_string(),
            description: String::new(),
            is_admin: false,
            source: "kerberos_enum".to_string(),
            member_of: Vec::new(),
        }
    }

    fn cred(username: &str, domain: &str, source: &str) -> Credential {
        Credential {
            id: "c1".to_string(),
            username: username.to_string(),
            password: "P@ssw0rd!".to_string(),
            domain: domain.to_string(),
            source: source.to_string(),
            discovered_at: None,
            is_admin: false,
            parent_id: None,
            attack_step: 0,
        }
    }

    #[test]
    fn corrects_low_trust_sysvol_realm() {
        let users = vec![user("alice", "child.contoso.local")];
        let mut cred = cred("alice", "contoso.local", "sysvol_script");

        let got = reconcile_low_trust_credential_domain(&mut cred, &users);

        assert_eq!(got, Some("child.contoso.local".to_string()));
        assert_eq!(cred.domain, "child.contoso.local");
    }

    #[test]
    fn leaves_high_trust_source_unchanged() {
        let users = vec![user("alice", "child.contoso.local")];
        let mut cred = cred("alice", "contoso.local", "secretsdump");

        let got = reconcile_low_trust_credential_domain(&mut cred, &users);

        assert_eq!(got, None);
        assert_eq!(cred.domain, "contoso.local");
    }

    #[test]
    fn leaves_ambiguous_low_trust_realm_unchanged() {
        let users = vec![
            user("administrator", "child.contoso.local"),
            user("administrator", "contoso.local"),
        ];
        let mut cred = cred("administrator", "contoso.local", "sysvol_script");

        let got = reconcile_low_trust_credential_domain(&mut cred, &users);

        assert_eq!(got, None);
        assert_eq!(cred.domain, "contoso.local");
    }
}

// ── collect_result_text_parts ─────────────────────────────────────────────
//
// `collect_result_text_parts` pulls trusted tool stdout out of the
// `tool_outputs` array, ignoring top-level `output` / `summary` prose fields
// that may contain LLM-generated text.

#[test]
fn collect_result_text_parts_from_string_array() {
    use super::collect_result_text_parts;
    let payload = serde_json::json!({
        "tool_outputs": ["first line", "second line"],
    });
    let parts = collect_result_text_parts(&payload);
    assert_eq!(parts, vec!["first line", "second line"]);
}

#[test]
fn collect_result_text_parts_from_object_array() {
    use super::collect_result_text_parts;
    let payload = serde_json::json!({
        "tool_outputs": [
            {"name": "nmap", "output": "PORT 445/tcp open"},
            {"name": "smb", "output": "Shares: C$, IPC$"},
        ],
    });
    let parts = collect_result_text_parts(&payload);
    assert_eq!(parts, vec!["PORT 445/tcp open", "Shares: C$, IPC$"]);
}

#[test]
fn collect_result_text_parts_ignores_top_level_scalar_fields() {
    use super::collect_result_text_parts;
    // The top-level `output` and `summary` fields are LLM prose — they
    // must NOT be ingested by regex extractors.
    let payload = serde_json::json!({
        "output": "Summary: found credentials",
        "summary": "Task complete",
        "tool_outputs": ["DC01$ aabbccddeeff00112233445566778899:aabbccddeeff00112233445566778899"],
    });
    let parts = collect_result_text_parts(&payload);
    // Only the tool_outputs entry should appear.
    assert_eq!(parts.len(), 1);
    assert!(parts[0].contains("DC01$"));
}

#[test]
fn collect_result_text_parts_empty_when_no_tool_outputs() {
    use super::collect_result_text_parts;
    let payload = serde_json::json!({ "summary": "no tool outputs here" });
    assert!(collect_result_text_parts(&payload).is_empty());
}

#[test]
fn collect_result_text_parts_empty_array_produces_nothing() {
    use super::collect_result_text_parts;
    let payload = serde_json::json!({ "tool_outputs": [] });
    assert!(collect_result_text_parts(&payload).is_empty());
}

#[test]
fn collect_result_text_parts_skips_non_string_and_non_object_entries() {
    use super::collect_result_text_parts;
    let payload = serde_json::json!({
        "tool_outputs": [42, true, null, "kept"],
    });
    let parts = collect_result_text_parts(&payload);
    assert_eq!(parts, vec!["kept"]);
}

// ── is_low_trust_realm_inferred_credential_source ──────────────────────────

#[test]
fn low_trust_sources_are_recognised() {
    use super::is_low_trust_realm_inferred_credential_source;
    let low_trust = [
        "description_field",
        "autologon_registry",
        "sysvol_script",
        "user_description_leak",
        "netexec_password",
        "ldap_description",
    ];
    for src in &low_trust {
        assert!(
            is_low_trust_realm_inferred_credential_source(src),
            "{src} should be low-trust"
        );
    }
}

#[test]
fn high_trust_sources_are_not_recognised() {
    use super::is_low_trust_realm_inferred_credential_source;
    let high_trust = [
        "secretsdump",
        "kerberoast",
        "asrep_roast",
        "lsassy",
        "certipy_auth",
        "impacket",
        "",
    ];
    for src in &high_trust {
        assert!(
            !is_low_trust_realm_inferred_credential_source(src),
            "{src} should not be low-trust"
        );
    }
}

// ── is_dcsync_chain_blocked_by_sid_filter (Bug C) ──────────────────────────

#[test]
fn auto_trust_follow_skips_dcsync_chain_for_sid_filtered_target() {
    use super::is_dcsync_chain_blocked_by_sid_filter;
    use crate::orchestrator::state::StateInner;
    let mut state = StateInner::new("op-test".into());
    state.trusted_domains.insert(
        "fabrikam.local".into(),
        ares_core::models::TrustInfo {
            domain: "fabrikam.local".into(),
            flat_name: "FABRIKAM".into(),
            direction: "bidirectional".into(),
            trust_type: "forest".into(),
            sid_filtering: true,
            security_identifier: None,
        },
    );
    assert!(is_dcsync_chain_blocked_by_sid_filter(
        &state,
        "fabrikam.local"
    ));
    // Case-insensitive lookup.
    assert!(is_dcsync_chain_blocked_by_sid_filter(
        &state,
        "FABRIKAM.LOCAL"
    ));
}

#[test]
fn dcsync_chain_not_blocked_when_sid_filter_off() {
    use super::is_dcsync_chain_blocked_by_sid_filter;
    use crate::orchestrator::state::StateInner;
    let mut state = StateInner::new("op-test".into());
    state.trusted_domains.insert(
        "fabrikam.local".into(),
        ares_core::models::TrustInfo {
            domain: "fabrikam.local".into(),
            flat_name: "FABRIKAM".into(),
            direction: "bidirectional".into(),
            trust_type: "forest".into(),
            sid_filtering: false,
            security_identifier: None,
        },
    );
    assert!(!is_dcsync_chain_blocked_by_sid_filter(
        &state,
        "fabrikam.local"
    ));
}

#[test]
fn dcsync_chain_not_blocked_for_intra_forest_trust() {
    // child→parent intra-forest trusts may have sid_filtering=true logically
    // but `is_cross_forest()` is false, so DCSync chain is fine.
    use super::is_dcsync_chain_blocked_by_sid_filter;
    use crate::orchestrator::state::StateInner;
    let mut state = StateInner::new("op-test".into());
    state.trusted_domains.insert(
        "child.contoso.local".into(),
        ares_core::models::TrustInfo {
            domain: "child.contoso.local".into(),
            flat_name: "CHILD".into(),
            direction: "bidirectional".into(),
            trust_type: "parent_child".into(),
            sid_filtering: true,
            security_identifier: None,
        },
    );
    assert!(!is_dcsync_chain_blocked_by_sid_filter(
        &state,
        "child.contoso.local"
    ));
}

#[test]
fn dcsync_chain_not_blocked_when_no_trust_metadata() {
    // Unlike trust-follow (which is conservative re: missing metadata), the
    // S4U chain has the LDAP-bind ticket regardless — so we only skip the
    // DCSync when we have *positive evidence* of SID filtering.
    use super::is_dcsync_chain_blocked_by_sid_filter;
    use crate::orchestrator::state::StateInner;
    let state = StateInner::new("op-test".into());
    assert!(!is_dcsync_chain_blocked_by_sid_filter(
        &state,
        "fabrikam.local"
    ));
}

// ── Bug E: AES kerberoast retry + SPN lockout propagation ──────────────────

#[test]
fn etype_nosupp_detector_matches_canonical_marker() {
    use super::result_text_indicates_etype_nosupp;
    let result = Some(serde_json::json!({
        "tool_outputs": [
            "Kerberos SessionError: KDC_ERR_ETYPE_NOSUPP(KDC has no support for encryption type)"
        ]
    }));
    assert!(result_text_indicates_etype_nosupp(&result));
}

#[test]
fn etype_nosupp_detector_negative() {
    use super::result_text_indicates_etype_nosupp;
    let result = Some(serde_json::json!({
        "tool_outputs": ["TGS-REP captured: $krb5tgs$18$*svc_sql$..."]
    }));
    assert!(!result_text_indicates_etype_nosupp(&result));
}

#[test]
fn kerberoast_retries_with_aes_after_etype_nosupp() {
    use super::should_retry_kerberoast_with_aes;
    let result = Some(serde_json::json!({
        "tool_outputs": ["[-] KDC_ERR_ETYPE_NOSUPP for svc_sql@fabrikam.local"]
    }));
    assert!(should_retry_kerberoast_with_aes(
        Some("kerberoast"),
        &result
    ));
    assert!(should_retry_kerberoast_with_aes(
        Some("targeted_kerberoast"),
        &result
    ));
    // Non-kerberoast technique: no retry.
    assert!(!should_retry_kerberoast_with_aes(
        Some("password_spray"),
        &result
    ));
    // No technique at all: no retry.
    assert!(!should_retry_kerberoast_with_aes(None, &result));
}

#[test]
fn build_aes_kerberoast_retry_payload_includes_etype_hint() {
    use crate::orchestrator::automation::credential_access::build_aes_kerberoast_retry_payload;
    let cred = ares_core::models::Credential {
        id: "c1".into(),
        username: "carol".into(),
        password: "P@ssw0rd!".into(), // pragma: allowlist secret
        domain: "fabrikam.local".into(),
        source: "test".into(),
        discovered_at: None,
        is_admin: false,
        parent_id: None,
        attack_step: 0,
    };
    let payload = build_aes_kerberoast_retry_payload(
        "fabrikam.local",
        "192.168.58.20",
        &cred,
        Some("sql_svc"),
    );
    assert_eq!(payload["technique"], "kerberoast");
    assert_eq!(payload["target_user"], "sql_svc");
    let etypes = payload["etype_hint"].as_array().expect("etype_hint array");
    assert!(etypes.iter().any(|v| v == "aes256-cts-hmac-sha1-96"));
    assert!(etypes.iter().any(|v| v == "aes128-cts-hmac-sha1-96"));
    assert_eq!(payload["retry_reason"], "kdc_err_etype_nosupp");
}

#[test]
fn lockout_on_spn_account_propagates_to_spray_exclusion() {
    use crate::orchestrator::automation::credential_access::{
        is_kerberoastable_principal, SPN_LOCKOUT_QUARANTINE_SECS,
    };
    use crate::orchestrator::state::StateInner;
    let mut state = StateInner::new("op-test".into());

    // Register a SPN-bearing account via a kerberoastable_account vuln.
    let mut details = std::collections::HashMap::new();
    details.insert(
        "account_name".into(),
        serde_json::Value::String("sql_svc".into()),
    );
    details.insert(
        "domain".into(),
        serde_json::Value::String("fabrikam.local".into()),
    );
    state.discovered_vulnerabilities.insert(
        "v-spn-1".into(),
        ares_core::models::VulnerabilityInfo {
            vuln_id: "v-spn-1".into(),
            vuln_type: "kerberoastable_account".into(),
            target: "192.168.58.20".into(),
            discovered_by: "test".into(),
            discovered_at: chrono::Utc::now(),
            details,
            recommended_agent: "credential_access".into(),
            priority: 2,
        },
    );
    assert!(is_kerberoastable_principal(
        &state,
        "sql_svc",
        "fabrikam.local"
    ));
    // Plain non-SPN principal: not flagged.
    assert!(!is_kerberoastable_principal(
        &state,
        "alice",
        "fabrikam.local"
    ));

    // Quarantine with the SPN window — verify the expiry is longer than the
    // 5-min default (300s). 1800s expiry should still be present after a
    // hypothetical 600s probe.
    state.quarantine_principal_for("sql_svc", "fabrikam.local", SPN_LOCKOUT_QUARANTINE_SECS);
    let excluded = state.quarantined_principals_in_domain("fabrikam.local");
    assert!(
        excluded.iter().any(|u| u == "sql_svc"),
        "SPN-bearing principal must land in spray exclusion list, got: {:?}",
        excluded
    );

    // Subsequent shorter quarantine must not shrink the 30-min window.
    state.quarantine_principal("sql_svc", "fabrikam.local"); // 5-min
    let now = chrono::Utc::now();
    let key = "sql_svc@fabrikam.local".to_string();
    let expiry = state
        .quarantined_principals
        .get(&key)
        .copied()
        .expect("entry");
    let remaining = (expiry - now).num_seconds();
    assert!(
        remaining > 900,
        "30-min quarantine should still have >15min remaining, got {}s",
        remaining
    );
}

// ── shadow-cred pre-flight helpers ─────────────────────────────────────

use super::{
    grants_dacl_write, is_shadow_cred_vuln_type, result_indicates_keycredlink_access_denied,
};

#[test]
fn shadow_cred_vuln_type_matches_dispatch_shapes() {
    for t in [
        "genericall",
        "GenericAll",
        "genericwrite",
        "writeproperty",
        "shadow_credentials",
        "acl_genericall",
        "acl_writeproperty",
    ] {
        assert!(is_shadow_cred_vuln_type(t), "should match: {t}");
    }
}

#[test]
fn shadow_cred_vuln_type_rejects_non_acl_shapes() {
    for t in [
        "rbcd",
        "esc1",
        "constrained_delegation",
        "unconstrained_delegation",
        "forcechangepassword",
        "allextendedrights", // deliberately excluded — not a valid shadow-cred primitive
        "acl_allextendedrights",
        // WriteDacl/WriteOwner never dispatch shadow creds (no property
        // write); abandoning them here would kill the dacl_edit escalation.
        "writedacl",
        "writeowner",
        "acl_writedacl",
        "acl_writeowner",
        "",
    ] {
        assert!(!is_shadow_cred_vuln_type(t), "should NOT match: {t}");
    }
}

#[test]
fn grants_dacl_write_only_for_rights_carrying_write_dac() {
    // GenericAll is full control, so a source denied on
    // msDS-KeyCredentialLink can still write itself an explicit ACE via
    // dacl_edit and retry — abandoning it forecloses a live path.
    assert!(grants_dacl_write("genericall"));
    assert!(grants_dacl_write("GenericAll"));
    assert!(grants_dacl_write("acl_genericall"));
    assert!(grants_dacl_write("writedacl"));
    assert!(grants_dacl_write("writeowner"));

    // GenericWrite and WriteProperty grant property writes only. A source
    // denied on the attribute cannot widen its own access, so the denial is
    // genuinely terminal and abandoning is correct.
    assert!(!grants_dacl_write("genericwrite"));
    assert!(!grants_dacl_write("acl_genericwrite"));
    assert!(!grants_dacl_write("writeproperty"));
    assert!(!grants_dacl_write("acl_writeproperty"));
    assert!(!grants_dacl_write("shadow_credentials"));
    assert!(!grants_dacl_write(""));
}

#[test]
fn keycredlink_denied_detects_impacket_insuff_access_rights() {
    let payload = json!({
        "tool_outputs": [
            "[+] Connecting to LDAP",
            "[!] Result: ldap.INSUFFICIENTACCESSRIGHTS: 00002098: LdapErr: DSID-0C09075A, comment: 000020BD: SecErr on msDS-KeyCredentialLink write"
        ]
    });
    assert!(result_indicates_keycredlink_access_denied(
        &Some(payload),
        "operation failed"
    ));
}

#[test]
fn keycredlink_denied_detects_bare_insuff_access_rights_with_attribute() {
    let payload = json!({
        "tool_outputs": [
            "[-] pywhisker error: INSUFF_ACCESS_RIGHTS when writing msDS-KeyCredentialLink for target CB-ATTK1$"
        ]
    });
    assert!(result_indicates_keycredlink_access_denied(
        &Some(payload),
        ""
    ));
}

#[test]
fn keycredlink_denied_detects_certipy_no_permission_phrase() {
    // certipy_shadow surfaces a plain-English refusal without naming the
    // attribute — treat that phrase alone as a shadow-cred deny.
    let payload = json!({
        "tool_outputs": [
            "[!] certipy: The user has no permission to add a certificate to this account"
        ]
    });
    assert!(result_indicates_keycredlink_access_denied(
        &Some(payload),
        ""
    ));
}

#[test]
fn keycredlink_denied_ignores_unrelated_access_denied() {
    // INSUFF_ACCESS_RIGHTS on a different attribute (servicePrincipalName)
    // must NOT flip the shadow-cred flag — that's a DACL edge for a
    // different primitive.
    let payload = json!({
        "tool_outputs": [
            "[-] INSUFF_ACCESS_RIGHTS writing servicePrincipalName"
        ]
    });
    assert!(!result_indicates_keycredlink_access_denied(
        &Some(payload),
        ""
    ));
}

#[test]
fn keycredlink_denied_ignores_success_output() {
    let payload = json!({
        "tool_outputs": [
            "[+] Successfully added msDS-KeyCredentialLink to target CB-ATTK1$"
        ]
    });
    assert!(!result_indicates_keycredlink_access_denied(
        &Some(payload),
        ""
    ));
}

#[test]
fn keycredlink_denied_accepts_worker_error_string() {
    // `result.error` at this call site is worker-authored (tool_executor /
    // result_handler), not LLM-authored — so a worker-reported deny in the
    // error field IS a real signal and the pre-flight should honor it.
    assert!(result_indicates_keycredlink_access_denied(
        &None,
        "INSUFF_ACCESS_RIGHTS on msDS-KeyCredentialLink for target CB-ATTK1$"
    ));
}

// ── extract_asrep_roastable_users ──

/// Shape a `report_finding` payload the way `merge_result_extras` / the
/// `report_finding` callback produce it: an `llm_findings` array of
/// `{vulnerabilities: [{vuln_type, target, details}]}` objects.
fn asrep_finding(vuln: serde_json::Value) -> serde_json::Value {
    json!({ "llm_findings": [ { "vulnerabilities": [vuln] } ] })
}

#[test]
fn asrep_finding_target_names_account() {
    let payload = asrep_finding(json!({
        "vuln_type": "asrep_roastable",
        "target": "alice",
        "details": {"description": "DoesNotRequirePreAuth set"},
    }));
    let users = extract_asrep_roastable_users(&payload, "contoso.local");
    assert_eq!(users.len(), 1);
    assert_eq!(users[0].username, "alice");
    assert_eq!(users[0].domain, "contoso.local");
    assert_eq!(users[0].source, "asrep_roastable_finding");
}

#[test]
fn asrep_finding_details_domain_overrides_default() {
    let payload = asrep_finding(json!({
        "vuln_type": "asrep_roastable",
        "target": "bob",
        "details": {"domain": "fabrikam.local"},
    }));
    let users = extract_asrep_roastable_users(&payload, "contoso.local");
    assert_eq!(users.len(), 1);
    assert_eq!(users[0].username, "bob");
    assert_eq!(users[0].domain, "fabrikam.local");
}

#[test]
fn asrep_finding_upn_target_yields_sam_and_realm() {
    let payload = asrep_finding(json!({
        "vuln_type": "asrep_roastable",
        "target": "carol@fabrikam.local",
    }));
    let users = extract_asrep_roastable_users(&payload, "contoso.local");
    assert_eq!(users.len(), 1);
    assert_eq!(users[0].username, "carol");
    assert_eq!(users[0].domain, "fabrikam.local");
}

#[test]
fn asrep_finding_netbios_qualified_target_strips_domain_prefix() {
    let payload = asrep_finding(json!({
        "vuln_type": "asrep_roastable",
        "target": "CONTOSO\\alice",
    }));
    let users = extract_asrep_roastable_users(&payload, "contoso.local");
    assert_eq!(users.len(), 1);
    assert_eq!(users[0].username, "alice");
    // NetBIOS prefix is not a DNS realm — fall back to the task domain.
    assert_eq!(users[0].domain, "contoso.local");
}

#[test]
fn asrep_finding_ip_target_falls_back_to_description() {
    // The agent put the DC IP in `target`; recover the account from the prose.
    let payload = asrep_finding(json!({
        "vuln_type": "asrep_roastable",
        "target": "192.168.58.10",
        "details": {"description": "User alice has DoesNotRequirePreAuth enabled."},
    }));
    let users = extract_asrep_roastable_users(&payload, "contoso.local");
    assert_eq!(users.len(), 1);
    assert_eq!(users[0].username, "alice");
    assert_eq!(users[0].domain, "contoso.local");
}

#[test]
fn asrep_finding_structured_account_field_preferred() {
    let payload = asrep_finding(json!({
        "vuln_type": "asrep_roastable",
        "target": "192.168.58.10",
        "details": {"account_name": "svc_backup", "domain": "contoso.local"},
    }));
    let users = extract_asrep_roastable_users(&payload, "contoso.local");
    assert_eq!(users.len(), 1);
    assert_eq!(users[0].username, "svc_backup");
    assert_eq!(users[0].domain, "contoso.local");
}

#[test]
fn asrep_finding_ignores_non_asrep_vuln_types() {
    let payload = asrep_finding(json!({
        "vuln_type": "kerberoastable",
        "target": "svc_sql",
    }));
    assert!(extract_asrep_roastable_users(&payload, "contoso.local").is_empty());
}

#[test]
fn asrep_finding_machine_account_target_rejected() {
    // No structured account field and no prose principal; the `$`-suffixed
    // target is not a roastable user.
    let payload = asrep_finding(json!({
        "vuln_type": "asrep_roastable",
        "target": "DC01$",
    }));
    assert!(extract_asrep_roastable_users(&payload, "contoso.local").is_empty());
}

#[test]
fn asrep_finding_unresolvable_principal_skipped() {
    let payload = asrep_finding(json!({
        "vuln_type": "asrep_roastable",
        "target": "192.168.58.10",
        "details": {"description": "Domain controller allows AS-REP roasting."},
    }));
    assert!(extract_asrep_roastable_users(&payload, "contoso.local").is_empty());
}

#[test]
fn asrep_finding_no_llm_findings_key() {
    let payload = json!({"discoveries": {"hashes": []}});
    assert!(extract_asrep_roastable_users(&payload, "contoso.local").is_empty());
}

#[test]
fn asrep_finding_case_insensitive_vuln_type() {
    let payload = asrep_finding(json!({
        "vuln_type": "ASREP_Roastable",
        "target": "alice",
    }));
    assert_eq!(
        extract_asrep_roastable_users(&payload, "contoso.local").len(),
        1
    );
}

#[test]
fn asrep_finding_multiple_findings_all_recovered() {
    let payload = json!({
        "llm_findings": [
            {"vulnerabilities": [{"vuln_type": "asrep_roastable", "target": "alice"}]},
            {"vulnerabilities": [
                {"vuln_type": "kerberoastable", "target": "svc_sql"},
                {"vuln_type": "asrep_roastable", "target": "bob@fabrikam.local"},
            ]},
        ]
    });
    let users = extract_asrep_roastable_users(&payload, "contoso.local");
    assert_eq!(users.len(), 2);
    assert_eq!(users[0].username, "alice");
    assert_eq!(users[0].domain, "contoso.local");
    assert_eq!(users[1].username, "bob");
    assert_eq!(users[1].domain, "fabrikam.local");
}

// ── Hash-credit convergence ─────────────────────────────────────────────────
//
// Two paths publish hashes — the parser path in `mod.rs` and the realtime
// discovery channel in `discovery_polling.rs` — and for the whole life of the
// corpus they did different amounts of work on success. The realtime channel
// emitted no timeline event (so `T1558.004` appears zero times in 92 ops
// despite 145 AS-REP captures), and after that was fixed it still emitted no
// roast or gMSA exploit token. `credit_published_hash` is the single place all
// three steps live; these tests fail if a path starts doing its own thing
// again. Read as source-level parity guards, not behaviour tests — the
// behaviour needs a live `Dispatcher`, which this module cannot build.

/// Source of the realtime discovery channel, read at compile time.
const DISCOVERY_POLLING_SRC: &str = include_str!("discovery_polling.rs");

/// Source of the parser path.
const RESULT_PROCESSING_SRC: &str = include_str!("mod.rs");

#[test]
fn realtime_hash_publish_routes_through_the_shared_credit_helper() {
    assert!(
        DISCOVERY_POLLING_SRC.contains("credit_published_hash("),
        "the realtime channel stopped routing hash credit through the shared helper"
    );
}

#[test]
fn realtime_hash_publish_does_not_hand_roll_part_of_the_credit() {
    for partial in [
        "create_hash_timeline_event(",
        "emit_gmsa_exploit_token_if_gmsa(",
        "roast_exploit_token(",
        "roast_credit_record(",
    ] {
        assert!(
            !DISCOVERY_POLLING_SRC.contains(partial),
            "the realtime channel calls {partial} directly — that is the drift \
             that lost AS-REP attribution and roast credit; call \
             credit_published_hash instead"
        );
    }
}

#[test]
fn every_hash_credit_step_lives_in_the_shared_helper() {
    assert!(
        RESULT_PROCESSING_SRC.contains("pub(crate) async fn credit_published_hash("),
        "credit_published_hash moved or was renamed"
    );

    for step in [
        "create_hash_timeline_event(",
        "emit_gmsa_exploit_token_if_gmsa(",
        "roast_exploit_token(",
        "roast_credit_record(",
    ] {
        let calls = RESULT_PROCESSING_SRC.matches(step).count();
        assert!(
            calls > 0,
            "{step} vanished from the credit path entirely — hash credit is now incomplete"
        );
    }
}

#[test]
fn roast_credit_publishes_its_record_before_it_claims_the_credit() {
    let publish = RESULT_PROCESSING_SRC
        .find("roast_credit_record(&token")
        .expect("credit_published_hash no longer publishes a roast vulnerability record");
    let mark = RESULT_PROCESSING_SRC
        .find("mark_exploited(&dispatcher.queue, &token)")
        .expect("credit_published_hash no longer marks the roast token exploited");
    assert!(
        publish < mark,
        "the record must be published before mark_exploited so the credit is \
         never an orphan, not even transiently"
    );
}

// ── Credential publish credit parity ────────────────────────────────────────

const ACL_GRANTS_SRC: &str = include_str!("acl_grants.rs");

const TIMELINE_SRC: &str = include_str!("timeline.rs");

#[test]
fn every_credential_publish_path_routes_through_the_shared_helper() {
    for (name, src) in [
        ("mod.rs", RESULT_PROCESSING_SRC),
        ("discovery_polling.rs", DISCOVERY_POLLING_SRC),
    ] {
        assert!(
            src.contains("publish_credential_credited("),
            "{name} stopped routing credential publishes through the shared helper"
        );
    }

    // acl_grants.rs is not on the positive list: it publishes no credentials at
    // all. `bloodyad_set_password` is the only credential a DACL takeover could
    // mint, and bloodyAD never echoes the value it wrote — the password existed
    // solely as a tool *argument*, which is model-authored input rather than
    // parsed output. The negative guards below still apply, so a future edit
    // cannot quietly reopen that route.
    for (name, src) in [
        ("mod.rs", RESULT_PROCESSING_SRC),
        ("acl_grants.rs", ACL_GRANTS_SRC),
        ("discovery_polling.rs", DISCOVERY_POLLING_SRC),
    ] {
        assert!(
            !src.contains(".publish_credential("),
            "{name} publishes a credential directly — that path emits no timeline \
             event; call publish_credential_credited instead"
        );
        assert!(
            !src.contains("create_credential_timeline_event("),
            "{name} emits the credential timeline event by hand — the event and the \
             publish must stay welded together in publish_credential_credited"
        );
    }
}

/// The reset path must not come back by copying `new_password` out of the tool
/// call. bloodyAD confirms only *that* the password changed, never *to what*.
///
/// Matches the argument *read*, not the bare word — the fixture in
/// `acl_grants.rs` passes `new_password` on purpose, to prove that a confirmed
/// reset carrying one still yields no credential.
#[test]
fn acl_grants_never_reads_a_credential_out_of_tool_arguments() {
    assert!(
        !ACL_GRANTS_SRC.contains(r#"arg("new_password")"#),
        "acl_grants.rs reads new_password out of the tool arguments again — that is \
         model-authored input, not parsed tool output, and it lands in state.credentials"
    );
}

#[test]
fn credential_publish_and_credit_are_welded_in_one_helper() {
    assert!(
        TIMELINE_SRC.contains("pub(crate) async fn publish_credential_credited("),
        "publish_credential_credited moved or was renamed"
    );
    assert!(
        TIMELINE_SRC.contains("\nasync fn create_credential_timeline_event("),
        "create_credential_timeline_event is no longer private to timeline.rs — \
         publish paths can call it directly again, which is the drift these \
         guards exist to prevent"
    );
    assert_eq!(
        TIMELINE_SRC.matches(".publish_credential(").count(),
        1,
        "credential publishing escaped the single credited call site"
    );
}

// ── Admin-upgrade host scope ────────────────────────────────────────────────

#[test]
fn admin_upgrade_description_names_the_host_the_grant_was_proven_on() {
    let d = admin_upgrade_description("alice", "contoso.local", Some("192.168.58.20"));
    assert_eq!(
        d,
        "Admin access confirmed: contoso.local\\alice on 192.168.58.20 (Pwn3d!)"
    );
    assert!(
        d.starts_with("Admin access confirmed: "),
        "the corpus reproduction greps key off this prefix: {d}"
    );
}

#[test]
fn admin_upgrade_description_falls_back_when_the_host_is_unknown() {
    // `extract_ip_from_line` returns None on a Pwn3d! line with no IP; the
    // event must still fire rather than losing the grant entirely.
    let d = admin_upgrade_description("alice", "contoso.local", None);
    assert_eq!(d, "Admin access confirmed: contoso.local\\alice (Pwn3d!)");
    assert!(d.starts_with("Admin access confirmed: "), "{d}");
}
