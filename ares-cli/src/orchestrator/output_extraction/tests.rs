use super::*;

/// Test-only wrappers that synthesize an empty `ToolOutputCtx` so legacy tests
/// (predating tool-aware extraction) can keep their `(output, domain)` shape.
fn extract_plaintext_passwords(output: &str, default_domain: &str) -> Vec<Credential> {
    let ctx = ToolOutputCtx {
        arguments: None,
        output,
    };
    super::passwords::extract_plaintext_passwords(&ctx, default_domain)
}

fn extract_from_output_text(output: &str, default_domain: &str) -> TextExtractions {
    let ctx = ToolOutputCtx {
        arguments: None,
        output,
    };
    super::extract_from_output_text(&ctx, default_domain)
}

#[test]
fn extract_ntlm_with_domain() {
    let output =
        "CONTOSO\\Administrator:500:aad3b435b51404eeaad3b435b51404ee:e19ccf75ee54e06b06a5907af13cef42:::";
    let hashes = extract_hashes(output, "contoso.local");
    assert_eq!(hashes.len(), 1);
    assert_eq!(hashes[0].username, "Administrator");
    assert_eq!(hashes[0].domain, "CONTOSO");
    assert_eq!(hashes[0].hash_type, "ntlm");
    assert!(hashes[0]
        .hash_value
        .contains("e19ccf75ee54e06b06a5907af13cef42"));
}

#[test]
fn extract_ntlm_without_domain() {
    // Administrator (RID 500) is a well-known local SAM account; an unprefixed
    // dump row must not inherit the AD `default_domain`. Tagging it would
    // create a phantom AD record that collides cross-domain in seeded labs.
    let output =
        "Administrator:500:aad3b435b51404eeaad3b435b51404ee:e19ccf75ee54e06b06a5907af13cef42:::";
    let hashes = extract_hashes(output, "contoso.local");
    assert_eq!(hashes.len(), 1);
    assert_eq!(hashes[0].username, "Administrator");
    assert_eq!(hashes[0].domain, "");
}

#[test]
fn extract_ntlm_without_domain_custom_user_inherits_default() {
    // RID 1000+ unprefixed users (e.g. `-just-dc-ntlm` output) are AD
    // accounts and SHOULD inherit default_domain.
    let output = "alice:1103:aad3b435b51404eeaad3b435b51404ee:209c6174da490caeb422f3fa5a7ae634:::";
    let hashes = extract_hashes(output, "contoso.local");
    assert_eq!(hashes.len(), 1);
    assert_eq!(hashes[0].username, "alice");
    assert_eq!(hashes[0].domain, "contoso.local");
}

#[test]
fn extract_tgs_hash() {
    let output = "$krb5tgs$23$*svc_sql$CONTOSO.LOCAL$contoso.local/svc_sql*$abc123def456";
    let hashes = extract_hashes(output, "contoso.local");
    assert_eq!(hashes.len(), 1);
    assert_eq!(hashes[0].username, "svc_sql");
    assert_eq!(hashes[0].domain, "CONTOSO.LOCAL");
    assert_eq!(hashes[0].hash_type, "kerberoast");
}

#[test]
fn extract_asrep_hash() {
    let output = "$krb5asrep$23$jdoe@CONTOSO.LOCAL:abc123def456789012345678901234567890abcdef";
    let hashes = extract_hashes(output, "contoso.local");
    assert_eq!(hashes.len(), 1);
    assert_eq!(hashes[0].username, "jdoe");
    assert_eq!(hashes[0].domain, "CONTOSO.LOCAL");
    assert_eq!(hashes[0].hash_type, "asrep");
}

#[test]
fn extract_line_wrapped_ntlm() {
    let output =
        "Administrator:500:aad3b435b51404eeaad3b435b51404ee:e19ccf75\nee54e06b06a5907af13cef42:::";
    let hashes = extract_hashes(output, "contoso.local");
    assert_eq!(hashes.len(), 1);
    assert_eq!(hashes[0].username, "Administrator");
}

#[test]
fn extract_hashes_dedup() {
    let output = "\
CONTOSO\\admin:500:aad3b435b51404eeaad3b435b51404ee:e19ccf75ee54e06b06a5907af13cef42:::\n\
CONTOSO\\admin:500:aad3b435b51404eeaad3b435b51404ee:e19ccf75ee54e06b06a5907af13cef42:::";
    let hashes = extract_hashes(output, "contoso.local");
    assert_eq!(hashes.len(), 1, "Should dedup identical hashes");
}

#[test]
fn extract_hosts_banner() {
    let output = "SMB  192.168.58.10  445  DC01  [*] Windows Server 2019 (name:DC01) (domain:contoso.local) (signing:True)";
    let hosts = extract_hosts(output);
    assert_eq!(hosts.len(), 1);
    assert_eq!(hosts[0].ip, "192.168.58.10");
    assert_eq!(hosts[0].hostname, "dc01.contoso.local"); // FQDN constructed from name+domain
    assert!(hosts[0].is_dc);
}

#[test]
fn extract_hosts_banner_fqdn_construction() {
    // Verify FQDN is built from (name:X)(domain:Y) → x.y
    let output = "SMB  192.168.58.11  445  DC02  [*] Windows Server 2019 (name:DC02) (domain:child.contoso.local) (signing:True)";
    let hosts = extract_hosts(output);
    assert_eq!(hosts.len(), 1);
    assert_eq!(hosts[0].hostname, "dc02.child.contoso.local");
    assert!(hosts[0].is_dc);
}

#[test]
fn extract_hosts_banner_domain_trailing_zero() {
    // netexec sometimes appends "0." to domain — verify it's stripped
    let output = "SMB  192.168.58.11  445  DC02  [*] Windows Server 2019 (name:DC02) (domain:contoso.local0.) (signing:True)";
    let hosts = extract_hosts(output);
    assert_eq!(hosts.len(), 1);
    assert_eq!(hosts[0].hostname, "dc02.contoso.local");
}

#[test]
fn extract_hosts_simple() {
    let output = "SMB  192.168.58.20  445  SRV01  some output";
    let hosts = extract_hosts(output);
    assert_eq!(hosts.len(), 1);
    assert_eq!(hosts[0].ip, "192.168.58.20");
    assert_eq!(hosts[0].hostname, "SRV01");
}

#[test]
fn extract_hosts_dedup() {
    let output = "\
SMB  192.168.58.10  445  DC01  [*] Windows (name:DC01) (domain:contoso.local)\n\
SMB  192.168.58.10  445  DC01  something else";
    let hosts = extract_hosts(output);
    assert_eq!(hosts.len(), 1, "Should dedup by IP");
    assert_eq!(hosts[0].hostname, "dc01.contoso.local");
}

#[test]
fn extract_users_domain_backslash() {
    let output = "CONTOSO\\alice.johnson (SidTypeUser)";
    let users = extract_users(output, "contoso.local");
    assert_eq!(users.len(), 1);
    assert_eq!(users[0].username, "alice.johnson");
    assert_eq!(users[0].domain, "CONTOSO");
}

#[test]
fn extract_users_upn() {
    let output = "Found user: bob@contoso.local";
    let users = extract_users(output, "contoso.local");
    assert_eq!(users.len(), 1);
    assert_eq!(users[0].username, "bob");
    assert_eq!(users[0].domain, "contoso.local");
}

#[test]
fn extract_users_rpc_format() {
    let output = "user:[admin] rid:[0x1f4]";
    let users = extract_users(output, "contoso.local");
    assert_eq!(users.len(), 1);
    assert_eq!(users[0].username, "admin");
    assert_eq!(users[0].domain, "contoso.local");
}

#[test]
fn extract_users_samaccountname() {
    let output = "sAMAccountName: svc_sql";
    let users = extract_users(output, "contoso.local");
    assert_eq!(users.len(), 1);
    assert_eq!(users[0].username, "svc_sql");
}

#[test]
fn extract_users_skip_machine_accounts() {
    let output = "CONTOSO\\DC01$ (SidTypeUser)";
    let users = extract_users(output, "contoso.local");
    assert!(
        users.is_empty(),
        "Machine accounts (ending in $) should be skipped"
    );
}

#[test]
fn extract_users_skip_anonymous() {
    let output = "user:[anonymous] rid:[0x1f5]";
    let users = extract_users(output, "contoso.local");
    assert!(users.is_empty());
}

#[test]
fn extract_users_smb_timestamp() {
    let output = "SMB  192.168.58.10  445  DC01  alice.johnson  2026-03-25 23:21:09 0  Alice";
    let users = extract_users(output, "contoso.local");
    assert!(users.iter().any(|u| u.username == "alice.johnson"));
}

#[test]
fn extract_users_domain_context_propagation() {
    let output = "\
[*] Windows (name:DC01) (domain:child.contoso.local)\n\
user:[alice] rid:[0x1f4]";
    let users = extract_users(output, "contoso.local");
    let alice = users.iter().find(|u| u.username == "alice").unwrap();
    assert_eq!(alice.domain, "child.contoso.local");
}

#[test]
fn extract_password_from_description() {
    let output =
        "SMB  192.168.58.10  445  DC01  dave.miller  2026-03-25 23:22:25 0  Dave Miller (Password : Summer2026!)";
    let creds = extract_plaintext_passwords(output, "contoso.local");
    assert_eq!(creds.len(), 1);
    assert_eq!(creds[0].username, "dave.miller");
    assert_eq!(creds[0].password, "Summer2026!");
}

#[test]
fn extract_default_password() {
    let output = "\
[*] DefaultPassword\n\
CONTOSO\\svc_backup:BackupPass123!";
    let creds = extract_plaintext_passwords(output, "contoso.local");
    assert_eq!(creds.len(), 1);
    assert_eq!(creds[0].username, "svc_backup");
    assert_eq!(creds[0].password, "BackupPass123!");
    assert_eq!(creds[0].domain, "CONTOSO");
}

#[test]
fn extract_password_rejects_paths() {
    let output = "Password : /tmp/users.txt";
    let creds = extract_plaintext_passwords(output, "contoso.local");
    assert!(creds.is_empty());
}

/// Regression: stale current_user must never be used for password attribution.
/// Previously, CHILD\john.smith on an earlier line would set current_user, and a
/// later "Password: Summer2025" (belonging to sam.wilson) would be falsely
/// attributed to john.smith.
///
/// Fix: password lines without a same-line username are skipped entirely.
/// Per-tool parsers handle structured extraction (LDIF, nxc table format).
#[test]
fn stale_context_does_not_leak_across_passwords() {
    // Simulate secretsdump output followed by LDAP description output
    let output = "\
CHILD\\john.smith:1103:aad3b435b51404eeaad3b435b51404ee:abc123def456abc123def456abc123de:::\n\
Password: Summer2025";
    let creds = extract_plaintext_passwords(output, "contoso.local");
    // The password line has no same-line username, so it must be skipped.
    // Per-tool parsers handle the structured extraction correctly.
    assert!(
        creds.is_empty(),
        "bare Password: line must not produce credentials"
    );
}

/// Regression: LDAP attribute order is NOT guaranteed.
/// description may appear BEFORE sAMAccountName within an entry.
/// extract_plaintext_passwords must never misattribute passwords from
/// a previous entry's username context.
#[test]
fn ldif_attribute_order_no_misattribution() {
    // ldapsearch output where description comes BEFORE sAMAccountName
    // and john.smith's entry appears before sam.wilson's
    let output = "\
# john.smith, Users, child.contoso.local\n\
dn: CN=John Smith,CN=Users,DC=child,DC=contoso,DC=local\n\
sAMAccountName: john.smith\n\
description: John Smith\n\
userPrincipalName: john.smith@child.contoso.local\n\
\n\
# sam.wilson, Users, child.contoso.local\n\
dn: CN=Sam Wilson,CN=Users,DC=child,DC=contoso,DC=local\n\
description: Sam Wilson (Password : Summer2025)\n\
sAMAccountName: sam.wilson\n\
userPrincipalName: sam.wilson@child.contoso.local";

    let creds = extract_plaintext_passwords(output, "child.contoso.local");
    // The description line has no same-line username — must be skipped.
    // john.smith:Summer2025 must NEVER be produced.
    assert!(
        creds.is_empty(),
        "LDIF description without same-line username must not produce credentials, got: {:?}",
        creds
    );
}

/// nxc SMB lines without timestamps should still extract via RE_SMB_LINE_PASSWORD.
#[test]
fn smb_line_without_timestamp() {
    let output =
        "SMB  192.168.58.10  445  DC01  svc_test  0  Service Account (Password : TestPass!)";
    let creds = extract_plaintext_passwords(output, "contoso.local");
    assert_eq!(creds.len(), 1);
    assert_eq!(creds[0].username, "svc_test");
    assert_eq!(creds[0].password, "TestPass!");
}

/// Ensure that two separate tool outputs processed independently don't
/// cross-contaminate username context.
#[test]
fn separate_outputs_no_cross_contamination() {
    // Tool output 1: secretsdump mentions john.smith
    let output1 = "CHILD\\john.smith:1103:aad3b435b51404eeaad3b435b51404ee:abc123:::\n";
    // Tool output 2: LDAP description with password for sam.wilson
    let output2 = "SMB  192.168.58.22  445  DC02  sam.wilson  2026-04-13 Password: Summer2025";

    // Process separately (as the fix does)
    let creds1 = extract_plaintext_passwords(output1, "contoso.local");
    let creds2 = extract_plaintext_passwords(output2, "contoso.local");

    // output1 should not produce a plaintext credential (it's a hash line)
    assert!(creds1.is_empty());

    // output2 should attribute Summer2025 to sam.wilson, not john.smith
    assert_eq!(creds2.len(), 1);
    assert_eq!(creds2[0].username, "sam.wilson");
    assert_eq!(creds2[0].password, "Summer2025");
}

#[test]
fn extracts_shares() {
    let output = "\
SMB  192.168.58.10  445  DC01  Share           Permissions  Remark\n\
SMB  192.168.58.10  445  DC01  -----           -----------  ------\n\
SMB  192.168.58.10  445  DC01  SYSVOL          READ         Logon server share\n\
SMB  192.168.58.10  445  DC01  ADMIN$          READ,WRITE\n\
SMB  192.168.58.10  445  DC01  [*] Enumerated 2 shares";
    let shares = extract_shares(output);
    assert_eq!(shares.len(), 2);
    assert_eq!(shares[0].name, "SYSVOL");
    assert_eq!(shares[0].permissions, "READ");
    assert_eq!(shares[0].host, "192.168.58.10");
    assert_eq!(shares[1].name, "ADMIN$");
    assert_eq!(shares[1].permissions, "READ,WRITE");
}

#[test]
fn full_extraction() {
    let output = "\
SMB  192.168.58.10  445  DC01  [*] Windows Server 2019 (name:DC01) (domain:contoso.local) (signing:True)\n\
SMB  192.168.58.10  445  DC01  [+] contoso.local\\:\n\
SMB  192.168.58.10  445  DC01  -Username-  -Last PW Set-  -BadPW- -Description-\n\
SMB  192.168.58.10  445  DC01  alice       2026-03-25 23:21:09 0  Alice (Password : Welcome1!)\n\
SMB  192.168.58.10  445  DC01  bob         2026-03-25 23:21:09 0  Bob\n\
CONTOSO\\krbtgt:502:aad3b435b51404eeaad3b435b51404ee:313b6f423a71d74c0a1b8a2f43b22d4c:::";

    let result = extract_from_output_text(output, "contoso.local");
    assert!(!result.hosts.is_empty(), "Should extract hosts");
    assert!(!result.users.is_empty(), "Should extract users");
    assert!(!result.credentials.is_empty(), "Should extract credentials");
    assert!(!result.hashes.is_empty(), "Should extract hashes");
}

#[test]
fn empty_output() {
    let result = extract_from_output_text("", "contoso.local");
    assert!(result.is_empty());
}

#[test]
fn extract_netexec_success_credential() {
    let output = "\
SMB  192.168.58.11  445  DC02  [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC02) (domain:child.contoso.local) (signing:True)\n\
SMB  192.168.58.11  445  DC02  [-] child.contoso.local\\admin:admin STATUS_LOGON_FAILURE\n\
SMB  192.168.58.11  445  DC02  [+] child.contoso.local\\jdoe:jdoe";

    let result = extract_from_output_text(output, "child.contoso.local");
    assert_eq!(result.credentials.len(), 1);
    assert_eq!(result.credentials[0].username, "jdoe");
    assert_eq!(result.credentials[0].password, "jdoe");
    assert_eq!(result.credentials[0].domain, "child.contoso.local");
    assert_eq!(result.credentials[0].source, "netexec_auth");
}

#[test]
fn extract_netexec_skips_hash_auth_echo() {
    let output =
        "SMB  192.168.58.11  445  DC01  [+] contoso.local\\frank:6dccf1c567c56a40e56691a723a49664 (Pwn3d!)";
    let args = serde_json::json!({"hashes": "6dccf1c567c56a40e56691a723a49664"});
    let ctx = ToolOutputCtx {
        arguments: Some(&args),
        output,
    };
    let result = super::extract_from_output_text(&ctx, "contoso.local");
    assert!(
        result.credentials.is_empty(),
        "hash echo must not become a credential: {:?}",
        result.credentials
    );
}

#[test]
fn extract_netexec_password_auth_still_extracted() {
    let output = "SMB  192.168.58.11  445  DC01  [+] contoso.local\\jdoe:RealPass1 (Pwn3d!)";
    let args = serde_json::json!({"password": "RealPass1"});
    let ctx = ToolOutputCtx {
        arguments: Some(&args),
        output,
    };
    let result = super::extract_from_output_text(&ctx, "contoso.local");
    assert_eq!(result.credentials.len(), 1);
    assert_eq!(result.credentials[0].password, "RealPass1");
}

#[test]
fn extract_netexec_success_with_pwned() {
    let output = "SMB  192.168.58.11  445  DC01  [+] contoso.local\\Administrator:P@ssw0rd(Pwn3d!)";

    let result = extract_from_output_text(output, "contoso.local");
    assert_eq!(result.credentials.len(), 1);
    assert_eq!(result.credentials[0].username, "Administrator");
    assert_eq!(result.credentials[0].password, "P@ssw0rd");
}

#[test]
fn extract_netexec_guest_filtered() {
    let output = "\
SMB  192.168.58.11  445  DC02  [+] child.contoso.local\\admin:admin (Guest)\n\
SMB  192.168.58.11  445  DC02  [+] child.contoso.local\\jdoe:jdoe (Guest)\n\
SMB  192.168.58.11  445  DC02  [+] child.contoso.local\\realuser:realpass";

    let result = extract_from_output_text(output, "child.contoso.local");
    assert_eq!(
        result.credentials.len(),
        1,
        "Guest lines should be filtered out"
    );
    assert_eq!(result.credentials[0].username, "realuser");
    assert_eq!(result.credentials[0].password, "realpass");
}

#[test]
fn valid_credential_rejects_null_usernames() {
    assert!(!is_valid_credential("(none)", "pass"));
    assert!(!is_valid_credential("none", "pass"));
    assert!(!is_valid_credential("null", "pass"));
    assert!(!is_valid_credential("(null)", "pass"));
    assert!(!is_valid_credential("(None)", "pass"));
}

#[test]
fn valid_credential_rejects_evil_artifacts() {
    assert!(!is_valid_credential("EVIL625686$", "pass"));
    assert!(!is_valid_credential("evil12345$", "pass"));
    // Non-numeric middle should pass
    assert!(is_valid_credential("EVILBOT$", "pass"));
}

#[test]
fn valid_credential_rejects_noise_passwords() {
    assert!(!is_valid_credential("user", "(null)"));
    assert!(!is_valid_credential("user", "*BLANK*"));
    assert!(!is_valid_credential("user", "<BLANK>"));
    assert!(!is_valid_credential("user", "N/A"));
    assert!(!is_valid_credential("user", "[+]"));
    assert!(!is_valid_credential("user", "Password"));
    assert!(!is_valid_credential("user", "password"));
}

#[test]
fn valid_credential_accepts_real_passwords() {
    assert!(is_valid_credential("admin", "P@ss1"));
    assert!(is_valid_credential("jdoe", "jdoe"));
    assert!(is_valid_credential("svc_test", "svc_test"));
}

#[test]
fn extract_cracked_tgs_hashcat() {
    let output =
        "$krb5tgs$23$*svc_sql$CONTOSO.LOCAL$contoso.local/svc_sql*$abc123def456:Summer2024!";
    let creds = extract_cracked_passwords(output, "contoso.local");
    assert_eq!(creds.len(), 1);
    assert_eq!(creds[0].username, "svc_sql");
    assert_eq!(creds[0].domain, "CONTOSO.LOCAL");
    assert_eq!(creds[0].password, "Summer2024!");
    assert_eq!(creds[0].source, "cracked:hashcat");
}

#[test]
fn extract_cracked_asrep_hashcat() {
    let output = "$krb5asrep$23$jdoe@CONTOSO.LOCAL:abc123def456:Winter2024!";
    let creds = extract_cracked_passwords(output, "contoso.local");
    assert_eq!(creds.len(), 1);
    assert_eq!(creds[0].username, "jdoe");
    assert_eq!(creds[0].domain, "CONTOSO.LOCAL");
    assert_eq!(creds[0].password, "Winter2024!");
    assert_eq!(creds[0].source, "cracked:hashcat");
}

#[test]
fn extract_cracked_john_show() {
    let output = "svc_sql:Summer2024!::::::::\n1 password hash cracked, 0 left";
    let creds = extract_cracked_passwords(output, "contoso.local");
    assert_eq!(creds.len(), 1);
    assert_eq!(creds[0].username, "svc_sql");
    assert_eq!(creds[0].password, "Summer2024!");
    assert_eq!(creds[0].source, "cracked:john");
}

#[test]
fn extract_cracked_dedup() {
    let output = "\
$krb5tgs$23$*svc_sql$CONTOSO.LOCAL$contoso.local/svc_sql*$abc:Summer2024!\n\
$krb5tgs$23$*svc_sql$CONTOSO.LOCAL$contoso.local/svc_sql*$def:Summer2024!";
    let creds = extract_cracked_passwords(output, "contoso.local");
    assert_eq!(creds.len(), 1, "Should dedup same user@domain");
}

#[test]
fn extract_cracked_no_false_positives_on_uncracked() {
    // Uncracked TGS hash should NOT produce a cracked credential
    let output = "$krb5tgs$23$*svc_sql$CONTOSO.LOCAL$contoso.local/svc_sql*$abc123def456";
    let creds = extract_cracked_passwords(output, "contoso.local");
    assert!(
        creds.is_empty(),
        "Uncracked hash should not produce credential"
    );
}

#[test]
fn extract_cracked_john_not_triggered_without_context() {
    // john --show format should only match if "password hash cracked" context is present
    let output = "svc_sql:Summer2024!::::::::";
    let creds = extract_cracked_passwords(output, "contoso.local");
    assert!(
        creds.is_empty(),
        "John format without context should not match"
    );
}

#[test]
fn extract_cracked_asrep_john_show_no_hex() {
    // John --show for AS-REP omits the hex hash section
    let output = "--- john --show ---\n\
        $krb5asrep$23$brian.davis@CHILD.CONTOSO.LOCAL:letmein2025\n\n\
        1 password hash cracked, 0 left\n";
    let creds = extract_cracked_passwords(output, "child.contoso.local");
    assert_eq!(creds.len(), 1);
    assert_eq!(creds[0].username, "brian.davis");
    assert_eq!(creds[0].password, "letmein2025");
    assert_eq!(creds[0].domain, "CHILD.CONTOSO.LOCAL");
}

#[test]
fn extract_cracked_tgs_john_show_unknown_user() {
    // John --show for TGS shows ?:password — extract user from TGS hash in same output
    let output = "Loaded 1 password hash (krb5tgs)\n\
        $krb5tgs$23$*john.smith$CHILD.CONTOSO.LOCAL$CIFS/filesvr01*$abcdef$123456\n\
        --- john --show ---\n\
        ?:P@ssw0rd!\n\n\
        1 password hash cracked, 0 left\n";
    let creds = extract_cracked_passwords(output, "child.contoso.local");
    assert_eq!(creds.len(), 1);
    assert_eq!(creds[0].username, "john.smith");
    assert_eq!(creds[0].password, "P@ssw0rd!");
    assert_eq!(creds[0].domain, "CHILD.CONTOSO.LOCAL");
    assert_eq!(creds[0].source, "cracked:john");
}

#[test]
fn extract_cracked_tgs_john_unknown_user_no_hash_context() {
    // Without a TGS hash line in the output, ?:password is skipped
    let output = "--- john --show ---\n\
        ?:P@ssw0rd!\n\n\
        1 password hash cracked, 0 left\n";
    let creds = extract_cracked_passwords(output, "contoso.local");
    assert!(creds.is_empty(), "No TGS hash context = no credential");
}

#[test]
fn extract_cracked_no_false_positive_on_raw_asrep_hash() {
    // Raw GetNPUsers AS-REP hash should NOT produce a cracked credential.
    // The hash body is long hex+$ which is_valid_credential must reject.
    let output = "$krb5asrep$23$brian.davis@CHILD.CONTOSO.LOCAL:7dae198e2c2fd940e1cbb59d7817c755$ef0c20c7d3abaaf411eb7c9bfe28c6aeae8410170fd08daf198b9269344aa64b9ad78f3f5b807dee0e8573e3bdec9fd90d0b46fa56baba08708f716d9b43a9f9bb2481ab56453d7a340f60ac478f6114f4fb0db7a424fd075f4cef9061954bf53ac6ac6dc3b0cc153b1bc909cac6cdcad9337022bf24ad2069d1991e9ca6eced54eb31f0016f3d9a2983c7f95c7f92261a8a1c435300576a98943a34046f4c08ecc4c6e81d9ca7aa3ae9a4baeb0e4071cd27c82203a225e741f4867afd15405552a47145ec3d79f1d5d19a90109b24ea593c26169fbccc54816f288a30c08ff34dc11bc105366685769b3edf9027be1dbad2f770edfa3ccd3f9524e93de40033464f07cdefb0";
    let creds = extract_cracked_passwords(output, "child.contoso.local");
    assert!(
        creds.is_empty(),
        "Raw AS-REP hash body should not be treated as cracked password"
    );
}

/// rpcclient queryuser output puts User Name and Description on separate lines.
/// The block-aware parser should extract the password from the Description field.
#[test]
fn extract_rpcclient_queryuser_description_password() {
    let output = "\
\tUser Name   :\tjdoe\n\
\tFull Name   :\t\n\
\tHome Drive  :\t\n\
\tDir Drive   :\t\n\
\tProfile Path:\t\n\
\tLogon Script:\t\n\
\tDescription :\tJohn Doe (Password : Summer2024!)\n\
\tWorkstations:\t\n\
\tComment     :\t\n\
\tRemote Dial :\n";
    let creds = extract_plaintext_passwords(output, "child.contoso.local");
    assert_eq!(
        creds.len(),
        1,
        "Should extract credential from rpcclient queryuser block"
    );
    assert_eq!(creds[0].username, "jdoe");
    assert_eq!(creds[0].password, "Summer2024!");
    assert_eq!(creds[0].domain, "child.contoso.local");
    assert_eq!(creds[0].source, "description_field");
}

/// Multiple rpcclient queryuser blocks — only users WITH passwords should produce creds.
#[test]
fn extract_rpcclient_queryuser_multiple_users() {
    let output = "\
\tUser Name   :\tasmith\n\
\tDescription :\tAlice Smith\n\
\n\
\tUser Name   :\tjdoe\n\
\tDescription :\tJohn Doe (Password : Summer2024!)\n\
\n\
\tUser Name   :\tbjones\n\
\tDescription :\tBob Jones\n";
    let creds = extract_plaintext_passwords(output, "child.contoso.local");
    assert_eq!(creds.len(), 1, "Only jdoe has a password in description");
    assert_eq!(creds[0].username, "jdoe");
    assert_eq!(creds[0].password, "Summer2024!");
}

#[test]
fn valid_credential_rejects_hash_body_password() {
    // Long hex+$ strings should be rejected as hash fragments
    assert!(!is_valid_credential(
        "brian.davis",
        "7dae198e2c2fd940e1cbb59d7817c755$ef0c20c7d3abaaf411eb7c9bfe28c6aeae"
    ));
    // Short real passwords should still pass
    assert!(is_valid_credential("brian.davis", "letmein2025"));
}
