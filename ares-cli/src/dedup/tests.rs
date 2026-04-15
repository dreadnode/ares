use std::collections::HashMap;

use ares_core::models::{Credential, Hash, User};

use super::credentials::{dedup_credentials, sanitize_credentials};
use super::domains::normalize_state_domains;
use super::hashes::dedup_hashes;
use super::labels::normalize_source_label;
use super::users::dedup_users;

fn make_user(domain: &str, username: &str) -> User {
    User {
        username: username.to_string(),
        domain: domain.to_string(),
        description: String::new(),
        is_admin: false,
        source: String::new(),
    }
}

fn make_cred(domain: &str, username: &str, password: &str) -> Credential {
    Credential {
        id: String::new(),
        username: username.to_string(),
        password: password.to_string(),
        domain: domain.to_string(),
        source: String::new(),
        discovered_at: None,
        is_admin: false,
        parent_id: None,
        attack_step: 0,
    }
}

fn make_hash(domain: &str, username: &str, hash_type: &str, hash_value: &str) -> Hash {
    Hash {
        id: String::new(),
        username: username.to_string(),
        hash_value: hash_value.to_string(),
        hash_type: hash_type.to_string(),
        domain: domain.to_string(),
        source: String::new(),
        cracked_password: None,
        discovered_at: None,
        parent_id: None,
        attack_step: 0,
        aes_key: None,
    }
}

#[test]
fn test_dedup_users_basic() {
    let nb = HashMap::new();
    let users = vec![
        make_user("contoso.local", "admin"),
        make_user("contoso.local", "admin"), // dup
        make_user("contoso.local", "jdoe"),
    ];
    let deduped = dedup_users(&users, &nb);
    assert_eq!(deduped.len(), 2);
}

#[test]
fn test_dedup_users_case_insensitive() {
    let nb = HashMap::new();
    let users = vec![
        make_user("CONTOSO.LOCAL", "Admin"),
        make_user("contoso.local", "admin"),
    ];
    let deduped = dedup_users(&users, &nb);
    assert_eq!(deduped.len(), 1);
}

#[test]
fn test_dedup_users_different_domains() {
    let nb = HashMap::new();
    let users = vec![
        make_user("contoso.local", "admin"),
        make_user("fabrikam.local", "admin"),
    ];
    let deduped = dedup_users(&users, &nb);
    assert_eq!(deduped.len(), 2);
}

#[test]
fn test_dedup_credentials_basic() {
    let creds = vec![
        make_cred("contoso.local", "admin", "P@ss1"),
        make_cred("contoso.local", "admin", "P@ss1"), // dup
        make_cred("contoso.local", "admin", "P@ss2"), // different password
    ];
    let deduped = dedup_credentials(&creds);
    assert_eq!(deduped.len(), 2);
}

#[test]
fn test_dedup_credentials_case_insensitive_username() {
    let creds = vec![
        make_cred("contoso.local", "Admin", "P@ss1"),
        make_cred("CONTOSO.LOCAL", "admin", "P@ss1"),
    ];
    let deduped = dedup_credentials(&creds);
    assert_eq!(deduped.len(), 1);
}

#[test]
fn test_dedup_hashes_basic() {
    let hashes = vec![
        make_hash("contoso.local", "admin", "ntlm", "aabbccdd"),
        make_hash("contoso.local", "admin", "ntlm", "aabbccdd"), // dup
        make_hash("contoso.local", "admin", "aes256", "eeff0011"), // different type
    ];
    let deduped = dedup_hashes(&hashes);
    assert_eq!(deduped.len(), 2);
}

#[test]
fn test_dedup_hashes_case_insensitive() {
    let hashes = vec![
        make_hash("contoso.local", "Admin", "NTLM", "AABBCCDD"),
        make_hash("CONTOSO.LOCAL", "admin", "ntlm", "aabbccdd"),
    ];
    let deduped = dedup_hashes(&hashes);
    assert_eq!(deduped.len(), 1);
}

#[test]
fn test_normalize_source_label_empty() {
    assert_eq!(normalize_source_label(""), "Unknown");
}

#[test]
fn test_normalize_source_label_exact_match() {
    assert_eq!(normalize_source_label("recon"), "Reconnaissance");
    assert_eq!(normalize_source_label("privesc"), "Privilege Escalation");
    assert_eq!(normalize_source_label("bloodhound"), "BloodHound");
    assert_eq!(normalize_source_label("secretsdump"), "Secretsdump");
}

#[test]
fn test_normalize_source_label_case_insensitive() {
    assert_eq!(normalize_source_label("RECON"), "Reconnaissance");
    assert_eq!(normalize_source_label("BloodHound"), "BloodHound");
}

#[test]
fn test_normalize_source_label_dedup_colon() {
    assert_eq!(normalize_source_label("recon:recon"), "Reconnaissance");
}

#[test]
fn test_normalize_source_label_prefix_match() {
    assert_eq!(
        normalize_source_label("privesc_enumeration"),
        "Privesc Enumeration"
    );
    assert_eq!(
        normalize_source_label("credential_access_foo"),
        "Credential Access"
    );
}

#[test]
fn test_normalize_source_label_task_suffix() {
    assert_eq!(
        normalize_source_label("recon_abc12345678"),
        "Reconnaissance"
    );
}

#[test]
fn test_normalize_source_label_fallback() {
    assert_eq!(
        normalize_source_label("some_custom_source"),
        "Some Custom Source"
    );
}

#[test]
fn test_normalize_state_domains_corrects_cred_domain() {
    let users = vec![make_user("contoso.local", "admin")];
    let mut creds = vec![make_cred("WRONG.local", "admin", "P@ss1")];
    let mut hashes = vec![];
    let mut domains = vec!["contoso.local".to_string(), "WRONG.local".to_string()];
    let hosts = vec![];

    normalize_state_domains(&users, &mut creds, &mut hashes, &mut domains, &hosts, None);

    assert_eq!(creds.len(), 1);
    assert_eq!(creds[0].domain, "contoso.local");
    // WRONG.local should be cleaned up since no users/hosts reference it
    assert!(!domains.iter().any(|d| d.to_lowercase() == "wrong.local"));
}

#[test]
fn test_normalize_state_domains_dedupes_cross_domain_creds() {
    let users = vec![make_user("contoso.local", "admin")];
    let mut creds = vec![
        make_cred("contoso.local", "admin", "P@ss1"),
        make_cred("child.contoso.local", "admin", "P@ss1"),
    ];
    let mut hashes = vec![];
    let mut domains = vec!["contoso.local".to_string()];
    let hosts = vec![];

    normalize_state_domains(&users, &mut creds, &mut hashes, &mut domains, &hosts, None);

    assert_eq!(creds.len(), 1);
    assert_eq!(creds[0].domain, "contoso.local");
}

#[test]
fn test_normalize_state_domains_preserves_well_known() {
    let users = vec![
        make_user("contoso.local", "administrator"),
        make_user("child.contoso.local", "administrator"),
    ];
    let mut creds = vec![
        make_cred("contoso.local", "administrator", "P@ss1"),
        make_cred("child.contoso.local", "administrator", "P@ss2"),
    ];
    let mut hashes = vec![];
    let mut domains = vec![
        "contoso.local".to_string(),
        "child.contoso.local".to_string(),
    ];
    let hosts = vec![];

    normalize_state_domains(&users, &mut creds, &mut hashes, &mut domains, &hosts, None);

    // Well-known accounts should all be preserved
    assert_eq!(creds.len(), 2);
}

#[test]
fn test_sanitize_strips_password_prefix() {
    let mut creds = vec![
        make_cred("contoso.local", "jdoe", "Password: jdoe"),
        make_cred("contoso.local", "admin", "password:secret"),
        make_cred("contoso.local", "user1", "PASSWORD: MyPass123"),
    ];
    sanitize_credentials(&mut creds);
    // "Password: jdoe" → "jdoe" → kept (password == username is valid)
    // "password:secret" → "secret" → kept
    // "PASSWORD: MyPass123" → "MyPass123" → kept
    assert_eq!(creds.len(), 3);
    assert_eq!(creds[0].password, "jdoe");
    assert_eq!(creds[1].password, "secret");
    assert_eq!(creds[2].password, "MyPass123");
}

#[test]
fn test_sanitize_removes_password_only() {
    let mut creds = vec![
        make_cred("contoso.local", "jdoe", "Password"),
        make_cred("contoso.local", "admin", "password"),
        make_cred("contoso.local", "user1", "RealPassword"),
    ];
    sanitize_credentials(&mut creds);
    // "Password" and "password" should be removed, "RealPassword" kept
    assert_eq!(creds.len(), 1);
    assert_eq!(creds[0].username, "user1");
    assert_eq!(creds[0].password, "RealPassword");
}

#[test]
fn test_sanitize_strips_trailing_paren_metadata() {
    let mut creds = vec![
        make_cred("contoso.local", "svc_test", "svc_test (Guest)"),
        make_cred("contoso.local", "admin", "P@ss1 (Pwn3d!)"),
    ];
    sanitize_credentials(&mut creds);
    // "svc_test (Guest)" → "svc_test" → kept (password == username is valid)
    // "P@ss1 (Pwn3d!)" → "P@ss1" → kept
    assert_eq!(creds.len(), 2);
    assert_eq!(creds[0].password, "svc_test");
    assert_eq!(creds[1].password, "P@ss1");
}

#[test]
fn test_sanitize_normalizes_username_with_at_domain() {
    let mut creds = vec![
        make_cred(
            "fabrikam.local",
            "sam.wilson@child.contoso.local@fabrikam.local",
            "Summer2025",
        ),
        make_cred(
            "fabrikam.local",
            "sam.wilson@child.contoso.local",
            "Summer2025",
        ),
    ];
    sanitize_credentials(&mut creds);
    // Both should resolve to username=sam.wilson, domain=child.contoso.local
    assert_eq!(creds[0].username, "sam.wilson");
    assert_eq!(creds[0].domain, "child.contoso.local");
    assert_eq!(creds[1].username, "sam.wilson");
    assert_eq!(creds[1].domain, "child.contoso.local");
}

#[test]
fn test_sanitize_preserves_clean_credentials() {
    let mut creds = vec![
        make_cred("contoso.local", "admin", "P@ss1"),
        make_cred("contoso.local", "user1", "Secret123!"),
    ];
    let orig_len = creds.len();
    sanitize_credentials(&mut creds);
    assert_eq!(creds.len(), orig_len);
    assert_eq!(creds[0].password, "P@ss1");
    assert_eq!(creds[1].password, "Secret123!");
}

#[test]
fn test_sanitize_removes_empty_password_after_strip() {
    let mut creds = vec![
        make_cred("contoso.local", "jdoe", "Password: "),
        make_cred("contoso.local", "admin", ""),
    ];
    sanitize_credentials(&mut creds);
    assert!(creds.is_empty());
}

#[test]
fn test_sanitize_then_dedup_collapses_variants() {
    // jdoe:jdoe is a valid credential; "Password: jdoe" strips to "jdoe" (dup);
    // "Password" is filtered as noise
    let mut creds = vec![
        make_cred("contoso.local", "jdoe", "jdoe"),
        make_cred("contoso.local", "jdoe", "Password: jdoe"),
        make_cred("contoso.local", "jdoe", "Password"),
    ];
    sanitize_credentials(&mut creds);
    let deduped = dedup_credentials(&creds);
    assert_eq!(deduped.len(), 1);
    assert_eq!(deduped[0].password, "jdoe");
}

#[test]
fn test_sanitize_keeps_password_equals_username() {
    // password == username is valid (e.g. jdoe:jdoe in GOAD)
    let mut creds = vec![
        make_cred("contoso.local", "admin", "admin"),
        make_cred("contoso.local", "user1", "DifferentPass"),
        make_cred("contoso.local", "jdoe", "Discovered"),
    ];
    sanitize_credentials(&mut creds);
    assert_eq!(creds.len(), 2);
    assert_eq!(creds[0].username, "admin");
    assert_eq!(creds[0].password, "admin");
    assert_eq!(creds[1].username, "user1");
}
