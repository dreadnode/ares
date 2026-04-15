use super::parsing::{has_domain_admin_indicator, parse_discoveries};
use serde_json::json;

#[test]
fn test_parse_credentials_array() {
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
fn test_parse_single_credential() {
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
fn test_parse_cracked_password() {
    let payload =
        json!({"cracked_password": "Summer2024!", "username": "jdoe", "domain": "contoso.local"});
    let parsed = parse_discoveries(&payload);
    assert_eq!(parsed.credentials.len(), 1);
    assert_eq!(parsed.credentials[0].username, "jdoe");
    assert_eq!(parsed.credentials[0].password, "Summer2024!");
    assert_eq!(parsed.credentials[0].source, "cracked");
}

#[test]
fn test_parse_cracked_password_without_username_ignored() {
    let payload = json!({"cracked_password": "Summer2024!"});
    let parsed = parse_discoveries(&payload);
    assert!(parsed.credentials.is_empty());
}

#[test]
fn test_parse_hashes() {
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
fn test_parse_hosts() {
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
fn test_parse_users_with_trusted_source() {
    let payload = json!({
        "discovered_users": [{"username": "jdoe", "domain": "contoso.local",
                              "source": "kerberos_enum", "is_admin": false}]
    });
    let parsed = parse_discoveries(&payload);
    assert_eq!(parsed.users.len(), 1);
    assert_eq!(parsed.users[0].username, "jdoe");
}

#[test]
fn test_parse_users_rejects_untrusted_source() {
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
fn test_parse_vulnerabilities() {
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
fn test_parse_shares() {
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
fn test_parse_empty_payload() {
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
fn test_parse_malformed_entries_skipped() {
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
fn test_parse_mixed_payload() {
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
fn test_da_indicator_explicit_flag() {
    assert!(has_domain_admin_indicator(
        &json!({"has_domain_admin": true})
    ));
}

#[test]
fn test_da_indicator_false_flag() {
    assert!(!has_domain_admin_indicator(
        &json!({"has_domain_admin": false})
    ));
}

#[test]
fn test_da_indicator_krbtgt_hash() {
    assert!(has_domain_admin_indicator(
        &json!({"hashes": [{"username": "krbtgt", "hash_value": "abc"}]})
    ));
}

#[test]
fn test_da_indicator_krbtgt_case_insensitive() {
    assert!(has_domain_admin_indicator(
        &json!({"hashes": [{"username": "KRBTGT", "hash_value": "abc"}]})
    ));
}

#[test]
fn test_da_indicator_non_krbtgt_hash() {
    assert!(!has_domain_admin_indicator(
        &json!({"hashes": [{"username": "Administrator", "hash_value": "abc"}]})
    ));
}

#[test]
fn test_da_indicator_empty_payload() {
    assert!(!has_domain_admin_indicator(&json!({})));
}
