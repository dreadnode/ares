use std::collections::HashMap;

use ares_core::models::{Credential, Hash, Host, User};

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
        is_previous: false,
        source_host: None,
        is_trust_key: false,
        trust_pair_label: None,
    }
}

#[test]
fn dedup_users_basic() {
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
fn dedup_users_case_insensitive() {
    let nb = HashMap::new();
    let users = vec![
        make_user("CONTOSO.LOCAL", "Admin"),
        make_user("contoso.local", "admin"),
    ];
    let deduped = dedup_users(&users, &nb);
    assert_eq!(deduped.len(), 1);
}

#[test]
fn dedup_users_different_domains() {
    let nb = HashMap::new();
    let users = vec![
        make_user("contoso.local", "admin"),
        make_user("fabrikam.local", "admin"),
    ];
    let deduped = dedup_users(&users, &nb);
    assert_eq!(deduped.len(), 2);
}

#[test]
fn dedup_credentials_basic() {
    let creds = vec![
        make_cred("contoso.local", "admin", "P@ss1"),
        make_cred("contoso.local", "admin", "P@ss1"), // dup
        make_cred("contoso.local", "admin", "P@ss2"), // different password
    ];
    let deduped = dedup_credentials(&creds);
    assert_eq!(deduped.len(), 2);
}

#[test]
fn dedup_credentials_case_insensitive_username() {
    let creds = vec![
        make_cred("contoso.local", "Admin", "P@ss1"),
        make_cred("CONTOSO.LOCAL", "admin", "P@ss1"),
    ];
    let deduped = dedup_credentials(&creds);
    assert_eq!(deduped.len(), 1);
}

#[test]
fn dedup_hashes_basic() {
    let hashes = vec![
        make_hash("contoso.local", "admin", "ntlm", "aabbccdd"),
        make_hash("contoso.local", "admin", "ntlm", "aabbccdd"), // dup
        make_hash("contoso.local", "admin", "aes256", "eeff0011"), // different type
    ];
    let deduped = dedup_hashes(&hashes);
    assert_eq!(deduped.len(), 2);
}

#[test]
fn dedup_hashes_case_insensitive() {
    let hashes = vec![
        make_hash("contoso.local", "Admin", "NTLM", "AABBCCDD"),
        make_hash("CONTOSO.LOCAL", "admin", "ntlm", "aabbccdd"),
    ];
    let deduped = dedup_hashes(&hashes);
    assert_eq!(deduped.len(), 1);
}

#[test]
fn normalize_source_label_empty() {
    assert_eq!(normalize_source_label(""), "Unknown");
}

#[test]
fn normalize_source_label_exact_match() {
    assert_eq!(normalize_source_label("recon"), "Reconnaissance");
    assert_eq!(normalize_source_label("privesc"), "Privilege Escalation");
    assert_eq!(normalize_source_label("bloodhound"), "BloodHound");
    assert_eq!(normalize_source_label("secretsdump"), "Secretsdump");
}

#[test]
fn normalize_source_label_case_insensitive() {
    assert_eq!(normalize_source_label("RECON"), "Reconnaissance");
    assert_eq!(normalize_source_label("BloodHound"), "BloodHound");
}

#[test]
fn normalize_source_label_dedup_colon() {
    assert_eq!(normalize_source_label("recon:recon"), "Reconnaissance");
}

#[test]
fn normalize_source_label_prefix_match() {
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
fn normalize_source_label_task_suffix() {
    assert_eq!(
        normalize_source_label("recon_abc12345678"),
        "Reconnaissance"
    );
}

#[test]
fn normalize_source_label_fallback() {
    assert_eq!(
        normalize_source_label("some_custom_source"),
        "Some Custom Source"
    );
}

#[test]
fn normalize_state_domains_corrects_cred_domain() {
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
fn normalize_state_domains_dedupes_cross_domain_creds() {
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
fn normalize_state_domains_preserves_well_known() {
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
fn sanitize_strips_password_prefix() {
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
fn sanitize_removes_password_only() {
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
fn sanitize_strips_trailing_paren_metadata() {
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
fn sanitize_normalizes_username_with_at_domain() {
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
fn sanitize_preserves_clean_credentials() {
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
fn sanitize_removes_empty_password_after_strip() {
    let mut creds = vec![
        make_cred("contoso.local", "jdoe", "Password: "),
        make_cred("contoso.local", "admin", ""),
    ];
    sanitize_credentials(&mut creds);
    assert!(creds.is_empty());
}

#[test]
fn sanitize_then_dedup_collapses_variants() {
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
fn sanitize_keeps_password_equals_username() {
    // password == username is valid (e.g. jdoe:jdoe)
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

#[test]
fn strip_trailing_dot_removes_dot() {
    use super::strip_trailing_dot;
    assert_eq!(strip_trailing_dot("contoso.local."), "contoso.local");
    assert_eq!(strip_trailing_dot("contoso.local"), "contoso.local");
    assert_eq!(strip_trailing_dot(""), "");
    assert_eq!(strip_trailing_dot("."), "");
}

#[test]
fn strip_trailing_dot_removes_netexec_zero_artifact() {
    use super::strip_trailing_dot;
    // NetExec appends "0" or "0." to domain names
    assert_eq!(strip_trailing_dot("contoso.local0"), "contoso.local");
    assert_eq!(strip_trailing_dot("contoso.local0."), "contoso.local");
    assert_eq!(
        strip_trailing_dot("child.contoso.local0"),
        "child.contoso.local"
    );
    assert_eq!(strip_trailing_dot("fabrikam.local0."), "fabrikam.local");
    // Must NOT strip real trailing 0 from hostnames like "host10"
    assert_eq!(strip_trailing_dot("host10"), "host10");
    assert_eq!(
        strip_trailing_dot("dc10.contoso.local"),
        "dc10.contoso.local"
    );
}

#[test]
fn strip_ansi_removes_escape_sequences() {
    use super::credentials::strip_ansi;
    let input = "\x1b[31mred text\x1b[0m";
    assert_eq!(strip_ansi(input), "red text");
    assert_eq!(strip_ansi("plain"), "plain");
    assert_eq!(strip_ansi(""), "");
}

#[test]
fn dedup_credentials_skips_empty_password() {
    let creds = vec![
        make_cred("contoso.local", "admin", ""),
        make_cred("contoso.local", "admin", "P@ss1"),
    ];
    let deduped = dedup_credentials(&creds);
    assert_eq!(deduped.len(), 1);
    assert_eq!(deduped[0].password, "P@ss1");
}

#[test]
fn dedup_credentials_normalizes_domain_case() {
    let creds = vec![make_cred("CONTOSO.LOCAL", "admin", "P@ss1")];
    let deduped = dedup_credentials(&creds);
    assert_eq!(deduped[0].domain, "contoso.local");
}

fn make_host(ip: &str, hostname: &str) -> Host {
    Host {
        ip: ip.to_string(),
        hostname: hostname.to_string(),
        os: String::new(),
        roles: vec![],
        services: vec![],
        is_dc: false,
        owned: false,
    }
}

#[test]
fn normalize_state_domains_empty_inputs() {
    let users: Vec<User> = vec![];
    let mut creds: Vec<Credential> = vec![];
    let mut hashes: Vec<Hash> = vec![];
    let mut domains: Vec<String> = vec![];
    let hosts: Vec<Host> = vec![];

    normalize_state_domains(&users, &mut creds, &mut hashes, &mut domains, &hosts, None);

    assert!(creds.is_empty());
    assert!(hashes.is_empty());
    assert!(domains.is_empty());
}

#[test]
fn normalize_state_domains_strips_trailing_dots() {
    let users = vec![make_user("contoso.local", "admin")];
    let mut creds = vec![make_cred("contoso.local.", "admin", "P@ss1")];
    let mut hashes = vec![make_hash("contoso.local.", "admin", "NTLM", "aabb")];
    let mut domains = vec!["contoso.local.".to_string()];
    let hosts = vec![];

    normalize_state_domains(&users, &mut creds, &mut hashes, &mut domains, &hosts, None);

    assert_eq!(creds[0].domain, "contoso.local");
    assert_eq!(hashes[0].domain, "contoso.local");
    assert_eq!(domains[0], "contoso.local");
}

#[test]
fn normalize_state_domains_hash_dedup_same_user_same_hash_different_domains() {
    // Same user+hash appears with two different domain labels; user is known in one domain.
    // The unknown-domain hash should be corrected then deduped away.
    let users = vec![make_user("contoso.local", "jdoe")];
    let mut creds = vec![];
    let mut hashes = vec![
        make_hash("contoso.local", "jdoe", "NTLM", "aabbccdd"),
        make_hash("UNKNOWN", "jdoe", "NTLM", "aabbccdd"),
    ];
    let mut domains = vec!["contoso.local".to_string()];
    let hosts = vec![];

    normalize_state_domains(&users, &mut creds, &mut hashes, &mut domains, &hosts, None);

    // After domain correction the second hash becomes a duplicate, so only one should remain.
    assert_eq!(hashes.len(), 1);
    assert_eq!(hashes[0].domain, "contoso.local");
}

#[test]
fn normalize_state_domains_hash_domain_correction_single_known_domain() {
    // User exists in exactly one domain; hash has wrong domain not in known_domains.
    let users = vec![make_user("fabrikam.local", "svc_sql")];
    let mut creds = vec![];
    let mut hashes = vec![make_hash("WRONG", "svc_sql", "NTLM", "11223344")];
    let mut domains = vec!["fabrikam.local".to_string()];
    let hosts = vec![];

    normalize_state_domains(
        &users,
        &mut creds,
        &mut hashes,
        &mut domains,
        &hosts,
        Some("fabrikam.local"),
    );

    assert_eq!(hashes.len(), 1);
    assert_eq!(hashes[0].domain, "fabrikam.local");
}

#[test]
fn normalize_state_domains_well_known_hashes_kept_across_all_domains() {
    // krbtgt and administrator hashes should be kept even when they appear in multiple domains.
    let users = vec![
        make_user("contoso.local", "krbtgt"),
        make_user("fabrikam.local", "krbtgt"),
    ];
    let mut creds = vec![];
    let mut hashes = vec![
        make_hash("contoso.local", "krbtgt", "NTLM", "aaaa"),
        make_hash("fabrikam.local", "krbtgt", "NTLM", "bbbb"),
        make_hash("contoso.local", "administrator", "NTLM", "cccc"),
        make_hash("fabrikam.local", "administrator", "NTLM", "dddd"),
    ];
    let mut domains = vec!["contoso.local".to_string(), "fabrikam.local".to_string()];
    let hosts = vec![];

    normalize_state_domains(&users, &mut creds, &mut hashes, &mut domains, &hosts, None);

    // All well-known account hashes should be preserved (unique domain:user:hash combos)
    assert_eq!(hashes.len(), 4);
}

#[test]
fn normalize_state_domains_well_known_hash_duplicate_same_domain_deduped() {
    // krbtgt hash appearing twice with the same domain+hash should be deduped to one.
    let users = vec![make_user("contoso.local", "krbtgt")];
    let mut creds = vec![];
    let mut hashes = vec![
        make_hash("contoso.local", "krbtgt", "NTLM", "aaaa"),
        make_hash("contoso.local", "krbtgt", "NTLM", "aaaa"),
    ];
    let mut domains = vec!["contoso.local".to_string()];
    let hosts = vec![];

    normalize_state_domains(&users, &mut creds, &mut hashes, &mut domains, &hosts, None);

    assert_eq!(hashes.len(), 1);
}

#[test]
fn normalize_state_domains_cred_dedup_user_in_exactly_one_domain() {
    // User is known in exactly one domain. Two creds with same password but different domains
    // should collapse to one with the correct domain.
    let users = vec![make_user("contoso.local", "jdoe")];
    let mut creds = vec![
        make_cred("contoso.local", "jdoe", "P@ss1"),
        make_cred("WRONG.local", "jdoe", "P@ss1"),
    ];
    let mut hashes = vec![];
    let mut domains = vec!["contoso.local".to_string()];
    let hosts = vec![];

    normalize_state_domains(&users, &mut creds, &mut hashes, &mut domains, &hosts, None);

    assert_eq!(creds.len(), 1);
    assert_eq!(creds[0].domain, "contoso.local");
}

#[test]
fn normalize_state_domains_cred_dedup_user_in_multiple_domains() {
    // User exists in two domains. Creds matching known domains should be kept, others dropped.
    let users = vec![
        make_user("contoso.local", "admin"),
        make_user("fabrikam.local", "admin"),
    ];
    let mut creds = vec![
        make_cred("contoso.local", "admin", "P@ss1"),
        make_cred("fabrikam.local", "admin", "P@ss1"),
        make_cred("WRONG.local", "admin", "P@ss1"),
    ];
    let mut hashes = vec![];
    let mut domains = vec!["contoso.local".to_string(), "fabrikam.local".to_string()];
    let hosts = vec![];

    normalize_state_domains(&users, &mut creds, &mut hashes, &mut domains, &hosts, None);

    // Only the two matching known domains should be kept
    assert_eq!(creds.len(), 2);
    let cred_domains: Vec<&str> = creds.iter().map(|c| c.domain.as_str()).collect();
    assert!(cred_domains.contains(&"contoso.local"));
    assert!(cred_domains.contains(&"fabrikam.local"));
}

#[test]
fn normalize_state_domains_cred_no_known_user_keeps_longest_domain() {
    // User not in any known user domain. Multiple creds with different domains:
    // keep the one with the longest domain (most specific).
    let users: Vec<User> = vec![];
    let mut creds = vec![
        make_cred("a", "mystery", "P@ss1"),
        make_cred("child.contoso.local", "mystery", "P@ss1"),
    ];
    let mut hashes = vec![];
    let mut domains = vec![];
    let hosts = vec![];

    normalize_state_domains(&users, &mut creds, &mut hashes, &mut domains, &hosts, None);

    assert_eq!(creds.len(), 1);
    assert_eq!(creds[0].domain, "child.contoso.local");
}

#[test]
fn normalize_state_domains_cred_well_known_accounts_always_kept() {
    // Well-known accounts (krbtgt, administrator, guest, defaultaccount) should always be kept.
    let users = vec![make_user("contoso.local", "administrator")];
    let mut creds = vec![
        make_cred("contoso.local", "administrator", "P@ss1"),
        make_cred("fabrikam.local", "administrator", "P@ss1"),
        make_cred("contoso.local", "guest", "guest"),
        make_cred("fabrikam.local", "guest", "guest"),
    ];
    let mut hashes = vec![];
    let mut domains = vec!["contoso.local".to_string(), "fabrikam.local".to_string()];
    let hosts = vec![
        make_host("192.168.58.10", "dc01.contoso.local"),
        make_host("192.168.58.20", "dc02.fabrikam.local"),
    ];

    normalize_state_domains(&users, &mut creds, &mut hashes, &mut domains, &hosts, None);

    assert_eq!(creds.len(), 4);
}

#[test]
fn normalize_state_domains_domain_filtering_based_on_host_fqdns() {
    // Domains should be retained only if they match a host FQDN, user domain, or target_domain.
    let users = vec![make_user("contoso.local", "admin")];
    let mut creds = vec![];
    let mut hashes = vec![];
    let mut domains = vec![
        "contoso.local".to_string(),
        "fabrikam.local".to_string(),
        "orphan.local".to_string(),
    ];
    let hosts = vec![make_host("192.168.58.20", "dc02.fabrikam.local")];

    normalize_state_domains(&users, &mut creds, &mut hashes, &mut domains, &hosts, None);

    // contoso.local: kept (user domain)
    // fabrikam.local: kept (host FQDN)
    // orphan.local: dropped (no evidence)
    assert_eq!(domains.len(), 2);
    assert!(domains.contains(&"contoso.local".to_string()));
    assert!(domains.contains(&"fabrikam.local".to_string()));
    assert!(!domains.contains(&"orphan.local".to_string()));
}

#[test]
fn normalize_state_domains_drops_host_fqdn_masquerading_as_domain() {
    // A parser/credential publish path sometimes pushes a DC's FQDN
    // (e.g. `WIN-30DZ5NGFA7M.c26h.local`) into the domain set. The dedup
    // filter must drop entries that exactly match a known host hostname,
    // even when a user or credential has the FQDN in its `domain` field.
    let users = vec![make_user("win-30dz5ngfa7m.c26h.local", "admin")];
    let mut creds = vec![];
    let mut hashes = vec![];
    let mut domains = vec![
        "c26h.local".to_string(),
        "win-30dz5ngfa7m.c26h.local".to_string(),
    ];
    let hosts = vec![make_host("192.168.58.10", "win-30dz5ngfa7m.c26h.local")];

    normalize_state_domains(&users, &mut creds, &mut hashes, &mut domains, &hosts, None);

    assert_eq!(domains, vec!["c26h.local".to_string()]);
}

#[test]
fn normalize_state_domains_domain_kept_when_hostname_matches_but_subdomain_host_exists() {
    // A DC whose hostname field equals the domain name (e.g. the DC for
    // child.contoso.local is stored as hostname="child.contoso.local") must NOT be
    // excluded when another host confirms it is a real domain
    // (dc01.child.contoso.local → suffix = child.contoso.local).
    let users = vec![make_user("contoso.local", "admin")];
    let mut creds = vec![];
    let mut hashes = vec![];
    let mut domains = vec![
        "contoso.local".to_string(),
        "child.contoso.local".to_string(),
    ];
    let hosts = vec![
        make_host("192.168.58.150", "child.contoso.local"),
        make_host("192.168.58.51", "dc01.child.contoso.local"),
    ];

    normalize_state_domains(&users, &mut creds, &mut hashes, &mut domains, &hosts, None);

    assert!(
        domains.contains(&"child.contoso.local".to_string()),
        "child domain should survive: dc01.child.* confirms it is a real domain"
    );
}

#[test]
fn normalize_state_domains_domain_kept_from_target_domain() {
    // target_domain should cause that domain to be retained even without hosts/users.
    let users: Vec<User> = vec![];
    let mut creds = vec![];
    let mut hashes = vec![];
    let mut domains = vec!["fabrikam.local".to_string()];
    let hosts: Vec<Host> = vec![];

    normalize_state_domains(
        &users,
        &mut creds,
        &mut hashes,
        &mut domains,
        &hosts,
        Some("fabrikam.local"),
    );

    assert_eq!(domains.len(), 1);
    assert_eq!(domains[0], "fabrikam.local");
}

#[test]
fn normalize_state_domains_child_domain_kept_when_parent_valid() {
    // A child domain (3+ labels) should survive the filter when its
    // suffix parent is already in valid_domains, even if no users/hosts
    // have been enumerated in the child domain yet.
    let users = vec![make_user("contoso.local", "admin")];
    let mut creds = vec![];
    let mut hashes = vec![];
    let mut domains = vec![
        "contoso.local".to_string(),
        "child.contoso.local".to_string(),
        "orphan.other".to_string(),
    ];
    let hosts: Vec<Host> = vec![];

    normalize_state_domains(
        &users,
        &mut creds,
        &mut hashes,
        &mut domains,
        &hosts,
        Some("contoso.local"),
    );

    assert!(domains.contains(&"contoso.local".to_string()));
    assert!(
        domains.contains(&"child.contoso.local".to_string()),
        "child domain should survive when parent is valid"
    );
    // orphan.other has no parent in valid_domains — dropped
    assert!(!domains.contains(&"orphan.other".to_string()));
}

#[test]
fn normalize_state_domains_hash_not_corrected_when_domain_is_known() {
    // When hash domain IS in known_domains, it should NOT be corrected even if user
    // is only known in one domain.
    let users = vec![make_user("contoso.local", "jdoe")];
    let mut creds = vec![];
    let mut hashes = vec![make_hash("fabrikam.local", "jdoe", "NTLM", "aabb")];
    let mut domains = vec!["contoso.local".to_string(), "fabrikam.local".to_string()];
    let hosts = vec![make_host("192.168.58.20", "dc02.fabrikam.local")];

    normalize_state_domains(&users, &mut creds, &mut hashes, &mut domains, &hosts, None);

    // fabrikam.local is in known_domains (from host FQDN), so hash domain should be preserved.
    assert_eq!(hashes.len(), 1);
    assert_eq!(hashes[0].domain, "fabrikam.local");
}

#[test]
fn normalize_state_domains_single_cred_domain_corrected() {
    // A single credential for a user known in one domain should have its domain corrected.
    let users = vec![make_user("contoso.local", "svc_web")];
    let mut creds = vec![make_cred("BADDOM", "svc_web", "Summer2025!")];
    let mut hashes = vec![];
    let mut domains = vec!["contoso.local".to_string()];
    let hosts = vec![];

    normalize_state_domains(&users, &mut creds, &mut hashes, &mut domains, &hosts, None);

    assert_eq!(creds.len(), 1);
    assert_eq!(creds[0].domain, "contoso.local");
}

#[test]
fn normalize_state_domains_cred_one_domain_no_matching_corrects_best() {
    // User in one domain, multiple creds with same password but none matching.
    // Should correct the longest-domain one and keep only it.
    let users = vec![make_user("contoso.local", "svc_sql")];
    let mut creds = vec![
        make_cred("x", "svc_sql", "DbPass!"),
        make_cred("longer.wrong.local", "svc_sql", "DbPass!"),
    ];
    let mut hashes = vec![];
    let mut domains = vec!["contoso.local".to_string()];
    let hosts = vec![];

    normalize_state_domains(&users, &mut creds, &mut hashes, &mut domains, &hosts, None);

    assert_eq!(creds.len(), 1);
    assert_eq!(creds[0].domain, "contoso.local");
}

#[test]
fn dedup_hashes_normalizes_hash_type() {
    let hashes = vec![
        make_hash("contoso.local", "admin", "ntlm", "aabb"),
        make_hash("contoso.local", "admin", "NTLM", "aabb"),
    ];
    let deduped = dedup_hashes(&hashes);
    assert_eq!(deduped.len(), 1);
    assert_eq!(deduped[0].hash_type, "NTLM");
}

#[test]
fn dedup_hashes_normalizes_asrep_variants() {
    // The dedup key uses raw lowercase hash_type, so "asrep", "as-rep", "asreproast" are
    // all distinct keys. Each one is kept but normalized in output.
    let hashes = vec![
        make_hash("contoso.local", "jdoe", "asrep", "hash1"),
        make_hash("contoso.local", "jdoe", "as-rep", "hash1"),
        make_hash("contoso.local", "jdoe", "asreproast", "hash1"),
    ];
    let deduped = dedup_hashes(&hashes);
    assert_eq!(deduped.len(), 3);
    // All should have normalized hash_type
    for h in &deduped {
        assert_eq!(h.hash_type, "AS-REP");
    }
}

#[test]
fn dedup_hashes_normalizes_aes_variants() {
    // "aes256" and "aes-256" have different raw lowercase keys, so both are kept.
    // But both get normalized hash_type in output.
    let hashes = vec![
        make_hash("contoso.local", "admin", "aes256", "key1"),
        make_hash("contoso.local", "admin", "aes-256", "key1"),
    ];
    let deduped = dedup_hashes(&hashes);
    assert_eq!(deduped.len(), 2);
    assert_eq!(deduped[0].hash_type, "AES256");
    assert_eq!(deduped[1].hash_type, "AES256");
}

#[test]
fn dedup_hashes_strips_trailing_dot_from_domain() {
    let hashes = vec![
        make_hash("contoso.local.", "admin", "NTLM", "aabb"),
        make_hash("contoso.local", "admin", "NTLM", "aabb"),
    ];
    let deduped = dedup_hashes(&hashes);
    assert_eq!(deduped.len(), 1);
    assert_eq!(deduped[0].domain, "contoso.local");
}

#[test]
fn dedup_hashes_empty_input() {
    let hashes: Vec<Hash> = vec![];
    let deduped = dedup_hashes(&hashes);
    assert!(deduped.is_empty());
}

#[test]
fn dedup_hashes_different_hash_values_same_user() {
    let hashes = vec![
        make_hash("contoso.local", "admin", "NTLM", "aabb"),
        make_hash("contoso.local", "admin", "NTLM", "ccdd"),
    ];
    let deduped = dedup_hashes(&hashes);
    assert_eq!(deduped.len(), 2);
}

#[test]
fn dedup_hashes_strips_ansi_from_hash_value() {
    let hashes = vec![
        make_hash("contoso.local", "admin", "NTLM", "\x1b[31maabb\x1b[0m"),
        make_hash("contoso.local", "admin", "NTLM", "aabb"),
    ];
    let deduped = dedup_hashes(&hashes);
    assert_eq!(deduped.len(), 1);
    assert_eq!(deduped[0].hash_value, "aabb");
}

#[test]
fn dedup_hashes_strips_ansi_from_username() {
    // strip_ansi is applied to the output username, but the dedup key uses raw
    // h.username.trim().to_lowercase() (before ANSI stripping). So an ANSI-decorated
    // username and a plain username produce different keys and are both kept.
    // However the output username is ANSI-stripped.
    let hashes = vec![make_hash(
        "contoso.local",
        "\x1b[32madmin\x1b[0m",
        "NTLM",
        "aabb",
    )];
    let deduped = dedup_hashes(&hashes);
    assert_eq!(deduped.len(), 1);
    assert_eq!(deduped[0].username, "admin");
}

#[test]
fn dedup_hashes_trims_whitespace() {
    let hashes = vec![
        make_hash(" contoso.local ", " admin ", " NTLM ", " aabb "),
        make_hash("contoso.local", "admin", "NTLM", "aabb"),
    ];
    let deduped = dedup_hashes(&hashes);
    assert_eq!(deduped.len(), 1);
}

#[test]
fn dedup_hashes_unknown_hash_type_preserved() {
    let hashes = vec![make_hash("contoso.local", "admin", "des-cbc-md5", "aabb")];
    let deduped = dedup_hashes(&hashes);
    assert_eq!(deduped.len(), 1);
    assert_eq!(deduped[0].hash_type, "des-cbc-md5");
}

#[test]
fn normalize_source_label_task_input_pattern() {
    assert_eq!(
        normalize_source_label("task input (recon_abc12345)"),
        "Reconnaissance"
    );
    assert_eq!(
        normalize_source_label("task input (exploit_deadbeef)"),
        "Exploitation"
    );
}

#[test]
fn normalize_source_label_all_label_map_entries() {
    assert_eq!(normalize_source_label("exploit"), "Exploitation");
    assert_eq!(normalize_source_label("lateral"), "Lateral Movement");
    assert_eq!(
        normalize_source_label("credential_access"),
        "Credential Access"
    );
    assert_eq!(normalize_source_label("acl_analysis"), "ACL Analysis");
    assert_eq!(normalize_source_label("crack"), "Password Cracking");
    assert_eq!(
        normalize_source_label("netexec_user_enum"),
        "NetExec User Enum"
    );
    assert_eq!(normalize_source_label("netexec_smb"), "NetExec SMB");
    assert_eq!(normalize_source_label("kerberoast"), "Kerberoasting");
    assert_eq!(normalize_source_label("asreproast"), "AS-REP Roasting");
    assert_eq!(normalize_source_label("lsassy"), "LSASSY");
    assert_eq!(normalize_source_label("share_spider"), "Share Spider");
    assert_eq!(normalize_source_label("gpp_password"), "GPP Passwords");
    assert_eq!(normalize_source_label("ldap_search"), "LDAP Search");
    assert_eq!(normalize_source_label("kerberos_noauth"), "Kerberos Enum");
    assert_eq!(
        normalize_source_label("user_description"),
        "LDAP Description"
    );
    assert_eq!(normalize_source_label("manual-inject"), "Manual Injection");
    assert_eq!(normalize_source_label("worker"), "Agent Discovery");
    assert_eq!(normalize_source_label("task"), "Task Output");
    assert_eq!(normalize_source_label("unknown"), "Unknown");
}

#[test]
fn normalize_source_label_colon_non_duplicate_preserved() {
    // When parts[0] != parts[1], the source string is kept as-is (not deduped).
    // Then "recon:exploit" lowercased starts with "recon", so prefix match fires.
    let result = normalize_source_label("recon:exploit");
    assert_eq!(result, "Reconnaissance");
}

#[test]
fn normalize_source_label_task_suffix_unknown_type() {
    // Task suffix with a type that's not in the label map
    let result = normalize_source_label("customthing_abcdef12");
    assert_eq!(result, "Customthing Abcdef12");
}

#[test]
fn normalize_source_label_mixed_case_prefix_match() {
    assert_eq!(normalize_source_label("Exploit_something"), "Exploitation");
}

#[test]
fn dedup_users_filters_noise_usernames() {
    let nb = HashMap::new();
    let users = vec![
        make_user("contoso.local", "none"),
        make_user("contoso.local", "null"),
        make_user("contoso.local", "anonymous"),
        make_user("contoso.local", "guest"),
        make_user("contoso.local", "krbtgt"),
        make_user("contoso.local", "valid_user"),
    ];
    let deduped = dedup_users(&users, &nb);
    assert_eq!(deduped.len(), 1);
    assert_eq!(deduped[0].username, "valid_user");
}

#[test]
fn dedup_users_filters_noise_username_prefixes() {
    let nb = HashMap::new();
    let users = vec![
        make_user("contoso.local", "sqlserver2005browser"),
        make_user("contoso.local", "mssqlservice"),
        make_user("contoso.local", "healthmailbox123"),
        make_user("contoso.local", "real_user"),
    ];
    let deduped = dedup_users(&users, &nb);
    assert_eq!(deduped.len(), 1);
    assert_eq!(deduped[0].username, "real_user");
}

#[test]
fn dedup_users_filters_short_usernames() {
    let nb = HashMap::new();
    let users = vec![
        make_user("contoso.local", "a"), // too short (len <= 1)
        make_user("contoso.local", "ab"),
    ];
    let deduped = dedup_users(&users, &nb);
    assert_eq!(deduped.len(), 1);
    assert_eq!(deduped[0].username, "ab");
}

#[test]
fn dedup_users_filters_usernames_with_slashes() {
    let nb = HashMap::new();
    let users = vec![
        make_user("contoso.local", "domain/admin"),
        make_user("contoso.local", "jdoe"),
    ];
    let deduped = dedup_users(&users, &nb);
    assert_eq!(deduped.len(), 1);
    assert_eq!(deduped[0].username, "jdoe");
}

#[test]
fn dedup_users_filters_underscore_prefix_usernames() {
    let nb = HashMap::new();
    let users = vec![
        make_user("contoso.local", "_internal"),
        make_user("contoso.local", "jdoe"),
    ];
    let deduped = dedup_users(&users, &nb);
    assert_eq!(deduped.len(), 1);
}

#[test]
fn dedup_users_filters_empty_domain() {
    let nb = HashMap::new();
    let users = vec![make_user("", "admin"), make_user("contoso.local", "admin")];
    let deduped = dedup_users(&users, &nb);
    // Empty domain is filtered out
    assert_eq!(deduped.len(), 1);
    assert_eq!(deduped[0].domain.to_lowercase(), "contoso.local");
}

#[test]
fn dedup_users_filters_underscore_prefix_domain() {
    let nb = HashMap::new();
    let users = vec![
        make_user("_internal", "admin"),
        make_user("contoso.local", "admin"),
    ];
    let deduped = dedup_users(&users, &nb);
    assert_eq!(deduped.len(), 1);
}

#[test]
fn dedup_users_resolves_netbios_to_fqdn() {
    let mut nb = HashMap::new();
    nb.insert("CONTOSO".to_string(), "contoso.local".to_string());
    let users = vec![
        make_user("CONTOSO", "admin"),
        make_user("contoso.local", "admin"),
    ];
    let deduped = dedup_users(&users, &nb);
    assert_eq!(deduped.len(), 1);
    assert_eq!(deduped[0].domain.to_lowercase(), "contoso.local");
}

#[test]
fn dedup_users_strips_trailing_dot() {
    let nb = HashMap::new();
    let users = vec![
        make_user("contoso.local.", "admin"),
        make_user("contoso.local", "admin"),
    ];
    let deduped = dedup_users(&users, &nb);
    assert_eq!(deduped.len(), 1);
}

#[test]
fn dedup_users_rejects_untrusted_source() {
    let nb = HashMap::new();
    let mut u = make_user("contoso.local", "admin");
    u.source = "llm_hallucination".to_string();
    let users = vec![u];
    let deduped = dedup_users(&users, &nb);
    assert_eq!(deduped.len(), 0);
}

#[test]
fn dedup_users_accepts_trusted_sources() {
    let nb = HashMap::new();
    let mut u1 = make_user("contoso.local", "admin");
    u1.source = "kerberos_enum".to_string();
    let mut u2 = make_user("contoso.local", "jdoe");
    u2.source = "netexec_user_enum".to_string();
    let users = vec![u1, u2];
    let deduped = dedup_users(&users, &nb);
    assert_eq!(deduped.len(), 2);
}

#[test]
fn dedup_users_empty_source_accepted() {
    // Empty source means no source filter applied
    let nb = HashMap::new();
    let u = make_user("contoso.local", "admin");
    assert!(u.source.is_empty());
    let users = vec![u];
    let deduped = dedup_users(&users, &nb);
    assert_eq!(deduped.len(), 1);
}

#[test]
fn dedup_credentials_strips_trailing_dot_domains() {
    let creds = vec![
        make_cred("contoso.local.", "admin", "P@ss1"),
        make_cred("contoso.local", "admin", "P@ss1"),
    ];
    let deduped = dedup_credentials(&creds);
    // dedup_credentials uses domain.trim().to_lowercase() — trailing dot is NOT
    // stripped by dedup_credentials itself (that's sanitize_credentials' job),
    // so these would be seen as different keys. Testing actual behavior.
    // After checking the code: dedup_credentials does trim() but not strip_trailing_dot
    // so "contoso.local." and "contoso.local" are different keys.
    assert_eq!(deduped.len(), 2);
}

#[test]
fn dedup_credentials_preserves_different_passwords_same_user() {
    let creds = vec![
        make_cred("contoso.local", "admin", "OldPass"),
        make_cred("contoso.local", "admin", "NewPass"),
    ];
    let deduped = dedup_credentials(&creds);
    assert_eq!(deduped.len(), 2);
}

#[test]
fn dedup_credentials_empty_input() {
    let creds: Vec<Credential> = vec![];
    let deduped = dedup_credentials(&creds);
    assert!(deduped.is_empty());
}

#[test]
fn dedup_credentials_normalizes_username_case() {
    let creds = vec![make_cred("contoso.local", "ADMIN", "P@ss1")];
    let deduped = dedup_credentials(&creds);
    assert_eq!(deduped[0].username, "admin");
}

#[test]
fn is_ghost_machine_account_matches_nopac_pattern() {
    use super::is_ghost_machine_account;
    assert!(is_ghost_machine_account("WIN-G9FWV8ZNSCL$"));
    assert!(is_ghost_machine_account("WIN-4D75DLR6UCC$"));
    assert!(is_ghost_machine_account("win-bjak8xunhgd$"));
    // without trailing $
    assert!(is_ghost_machine_account("WIN-3KSGCLTS7NX"));
}

#[test]
fn is_ghost_machine_account_rejects_real_hosts() {
    use super::is_ghost_machine_account;
    assert!(!is_ghost_machine_account("DC01$"));
    assert!(!is_ghost_machine_account("WS01$"));
    assert!(!is_ghost_machine_account("WIN-2019$")); // wrong length
    assert!(!is_ghost_machine_account("administrator"));
    assert!(!is_ghost_machine_account(""));
}

#[test]
fn sanitize_credentials_drops_ghost_machine_accounts() {
    let mut creds = vec![
        make_cred("contoso.local", "WIN-G9FWV8ZNSCL$", "P@ss1"),
        make_cred("contoso.local", "jdoe", "P@ss1"),
    ];
    sanitize_credentials(&mut creds);
    assert_eq!(creds.len(), 1);
    assert_eq!(creds[0].username, "jdoe");
}

#[test]
fn dedup_hashes_collapses_bare_and_prefixed_same_user() {
    // Parsers emit the same hash twice when secretsdump output mixes
    // `Administrator:RID:...` (bare) and `DOMAIN\Administrator:RID:...` (prefixed)
    // — bare gets empty domain, prefixed gets the resolved FQDN.
    // The bare row should be folded into the prefixed one.
    let hashes = vec![
        make_hash("", "Administrator", "NTLM", "aabbccdd"),
        make_hash("contoso.local", "Administrator", "NTLM", "aabbccdd"),
    ];
    let deduped = dedup_hashes(&hashes);
    assert_eq!(deduped.len(), 1);
    assert_eq!(deduped[0].domain, "contoso.local");
}

#[test]
fn dedup_hashes_keeps_distinct_users_sharing_hash() {
    // Two different users can end up with identical NTLMs (shared password).
    // They must NOT be folded together — dedup keys on
    // (username, hash_type, hash_value), not just (hash_type, hash_value).
    let hashes = vec![
        make_hash("contoso.local", "Administrator", "NTLM", "deadbeefcafe"),
        make_hash("contoso.local", "svc_backup", "NTLM", "deadbeefcafe"),
    ];
    let deduped = dedup_hashes(&hashes);
    assert_eq!(deduped.len(), 2);
}

#[test]
fn dedup_hashes_bare_with_no_domain_sibling_kept() {
    // If we only ever saw the bare form, we cannot infer a domain — keep it as-is.
    let hashes = vec![make_hash("", "Administrator", "NTLM", "aabbccdd")];
    let deduped = dedup_hashes(&hashes);
    assert_eq!(deduped.len(), 1);
    assert_eq!(deduped[0].domain, "");
}

#[test]
fn dedup_hashes_picks_longest_domain_when_multiple_known() {
    // If the same user+hash appears with both a parent and a child domain (rare
    // cross-forest replication artifact), prefer the longer/more-specific FQDN
    // when filling in a bare entry.
    let hashes = vec![
        make_hash("", "krbtgt", "NTLM", "deadbeef"),
        make_hash("contoso.local", "krbtgt", "NTLM", "deadbeef"),
        make_hash("child.contoso.local", "krbtgt", "NTLM", "deadbeef"),
    ];
    let deduped = dedup_hashes(&hashes);
    // The bare entry folds into the longest sibling; the two populated entries stay distinct.
    assert_eq!(deduped.len(), 2);
    let domains: Vec<&str> = deduped.iter().map(|h| h.domain.as_str()).collect();
    assert!(domains.contains(&"contoso.local"));
    assert!(domains.contains(&"child.contoso.local"));
}

#[test]
fn dedup_hashes_drops_ghost_machine_accounts() {
    let hashes = vec![
        make_hash(
            "contoso.local",
            "WIN-4D75DLR6UCC$",
            "NTLM",
            "aad3b435b51404eeaad3b435b51404ee:da118ed665879916ceaacfb98e3ee74e",
        ),
        make_hash("contoso.local", "admin", "NTLM", "aabb"),
    ];
    let deduped = dedup_hashes(&hashes);
    assert_eq!(deduped.len(), 1);
    assert_eq!(deduped[0].username, "admin");
}

#[test]
fn dedup_users_drops_ghost_machine_accounts() {
    let nb = HashMap::new();
    let mut ghost = make_user("contoso.local", "WIN-BJAK8XUNHGD$");
    ghost.source = "kerberos_enum".to_string();
    let mut real = make_user("contoso.local", "jdoe");
    real.source = "kerberos_enum".to_string();
    let users = vec![ghost, real];
    let deduped = dedup_users(&users, &nb);
    assert_eq!(deduped.len(), 1);
    assert_eq!(deduped[0].username, "jdoe");
}
