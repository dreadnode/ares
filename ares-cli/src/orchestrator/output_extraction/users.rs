use regex::Regex;
use std::sync::LazyLock;

use ares_core::models::User;

static RE_DOMAIN_CONTEXT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\(domain:([^)]+)\)").unwrap());

static RE_NAME_CONTEXT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\(name:([^)]+)\)").unwrap());

/// True when a `(domain:Y)` value paired with `(name:X)` on an SMB banner line
/// is a workgroup or self-named pseudo-domain rather than a real Kerberos
/// realm. Mirrors the heuristic in `ares-tools::parsers::smb` — kept local to
/// avoid a cross-crate dep just for one helper. Non-domain-joined Windows
/// hosts emit `(domain:WORKGROUP)` or `(domain:WIN-XXX.AUTOGEN.LOCAL)` where
/// the first label of the domain is the host's own NetBIOS name; pinning
/// `current_domain` to that string later attributes extracted users (and any
/// hashes that get tagged from this context) to a phantom AD domain.
fn is_workgroup_domain(name: &str, domain: &str) -> bool {
    let domain = domain.trim().trim_end_matches('.');
    if domain.is_empty() {
        return false;
    }
    if domain.eq_ignore_ascii_case("WORKGROUP") || domain.eq_ignore_ascii_case("MSHOME") {
        return true;
    }
    if !name.is_empty() {
        let first_label = domain.split('.').next().unwrap_or("");
        if first_label.eq_ignore_ascii_case(name) {
            return true;
        }
    }
    false
}

pub(crate) static RE_DOMAIN_BACKSLASH: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"([A-Za-z0-9_.\-]+)\\([A-Za-z0-9_.\-$]+)").unwrap());

pub(crate) static RE_UPN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"([A-Za-z0-9_.\-]+)@([A-Za-z0-9_.\-]+\.[A-Za-z0-9_.\-]+)").unwrap()
});

pub(crate) static RE_USER_BRACKET: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)user:\[([^\]]+)\]").unwrap());

pub(crate) static RE_ACCOUNT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"Account:\s*([A-Za-z0-9_.\-]+)").unwrap());

// Capture the trailing `$` too: a computer's sAMAccountName is `HOSTNAME$`,
// and `is_valid_extracted_user` rejects `$`-suffixed names. Dropping the `$`
// from the capture let machine accounts (DC01$, WIN-XXXX$) masquerade as
// users in the `ldap_extraction` source.
static RE_SAM: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)samaccountname:\s*([A-Za-z0-9_.\-]+\$?)").unwrap());

static RE_SMB_TIMESTAMP: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"SMB\s+\S+\s+\d+\s+\S+\s+([A-Za-z0-9_.\-]+)\s+\d{4}-\d{2}-\d{2}").unwrap()
});

// An LDIF `objectClass: group` / `objectClass: computer` line. Marks the
// enclosing record as a non-user so its `sAMAccountName` is not mistaken for
// a user in the `ldap_extraction` source. Matches only the exact group /
// computer classes — `user`, `person`, and `msDS-GroupManagedServiceAccount`
// stay users.
static RE_OBJECTCLASS_NONUSER: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)^\s*objectclass:\s*(?:group|computer)\s*$").unwrap());

/// Check if a domain string looks like a machine hostname rather than an AD domain.
///
/// Machine FQDNs like `win-g7fpa5zzxzv.w5an.local` or NetBIOS machine names like
/// `WIN-G7FPA5ZZXZV` pollute domain tracking when they appear in SMB banners or
/// UPN suffixes (e.g., null session enum on a DC reports the Kali box's own domain).
pub fn is_machine_hostname_domain(domain: &str) -> bool {
    let first_label = domain.split('.').next().unwrap_or(domain);
    let lower = first_label.to_lowercase();
    // Windows auto-generated hostnames: WIN-XXXXXXXX, DESKTOP-XXXXXXX
    if lower.starts_with("win-") || lower.starts_with("desktop-") {
        return true;
    }
    false
}

/// Reject garbage usernames and invalid domains from regex extraction.
pub fn is_valid_extracted_user(username: &str, domain: &str) -> bool {
    if username.is_empty() || username.ends_with('$') {
        return false;
    }
    if username.bytes().any(|b| b < 0x20) || domain.bytes().any(|b| b < 0x20) {
        return false;
    }
    if username.len() <= 1 {
        return false;
    }
    let lower = username.to_lowercase();
    const NOISE: &[&str] = &[
        "anonymous",
        "none",
        "null",
        "unknown",
        "n/a",
        "default",
        "test",
        "local",
        "localhost",
        "domain",
        "workgroup",
    ];
    if NOISE.contains(&lower.as_str()) {
        return false;
    }
    if username.starts_with('_') || domain.starts_with('_') {
        return false;
    }
    // Windows auto-generated machine NetBIOS names (WIN-XXXX, DESKTOP-XXXX)
    // carry a `sAMAccountName` and would otherwise land in the user table.
    if lower.starts_with("win-") || lower.starts_with("desktop-") {
        return false;
    }
    if !domain.contains('.') {
        if domain.len() > 15 || domain.is_empty() {
            return false;
        }
        if !domain
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        {
            return false;
        }
    }
    if !username.bytes().all(|b| b.is_ascii_graphic()) {
        return false;
    }
    true
}

/// Emit buffered `sAMAccountName` finds for one completed LDIF record as
/// `ldap_extraction` users — unless the record was flagged a group/computer,
/// in which case they are discarded. Buffering to a record boundary makes the
/// group/computer decision independent of whether `objectClass:` appears
/// before or after `sAMAccountName:` in the entry.
fn flush_ldap_record(
    pending: &mut Vec<(String, String)>,
    record_is_non_user: bool,
    users: &mut Vec<User>,
    seen: &mut std::collections::HashSet<String>,
) {
    let drained = std::mem::take(pending);
    if record_is_non_user {
        return;
    }
    for (raw_username, raw_domain) in drained {
        let username = raw_username.trim().trim_end_matches('.').to_string();
        let domain = raw_domain.trim().trim_end_matches('.').to_string();
        if !is_valid_extracted_user(&username, &domain) {
            continue;
        }
        let key = format!("{}@{}", username.to_lowercase(), domain.to_lowercase());
        if seen.insert(key) {
            users.push(User {
                username,
                domain,
                description: String::new(),
                is_admin: false,
                // High-confidence: sAMAccountName attribute is only
                // emitted by an LDAP server, not by tool prose.
                source: "ldap_extraction".to_string(),
                member_of: Vec::new(),
            });
        }
    }
}

pub fn extract_users(output: &str, default_domain: &str) -> Vec<User> {
    let mut users = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let mut current_domain = default_domain.to_string();

    // LDAP record buffering: `sAMAccountName` finds are held until the record
    // ends (blank line or the next `dn:`), then emitted only if the record was
    // not a group/computer. netexec/rpcclient output has neither `dn:` lines
    // nor blank-line-delimited records, so its users flow straight through the
    // final flush unaffected.
    let mut pending_ldap: Vec<(String, String)> = Vec::new();
    let mut record_is_non_user = false;

    for line in output.lines() {
        let stripped = line.trim();

        // Record boundary: a new `dn:` entry or a blank separator flushes the
        // record that just ended and resets the group/computer flag.
        if stripped.is_empty() || stripped.len() >= 3 && stripped[..3].eq_ignore_ascii_case("dn:") {
            flush_ldap_record(&mut pending_ldap, record_is_non_user, &mut users, &mut seen);
            record_is_non_user = false;
        }

        if RE_OBJECTCLASS_NONUSER.is_match(stripped) {
            record_is_non_user = true;
        }

        if let Some(caps) = RE_DOMAIN_CONTEXT.captures(stripped) {
            let candidate = caps
                .get(1)
                .unwrap()
                .as_str()
                .trim_end_matches('.')
                .to_string();
            let line_name = RE_NAME_CONTEXT
                .captures(stripped)
                .map(|c| c.get(1).unwrap().as_str().trim().to_string())
                .unwrap_or_default();
            // Don't let machine hostnames (Kali's own SMB banner) or workgroup
            // self-named pseudo-domains override the task's default domain.
            if !is_machine_hostname_domain(&candidate)
                && !is_workgroup_domain(&line_name, &candidate)
            {
                current_domain = candidate;
            }
        }

        let mut found = Vec::new();

        if let Some(caps) = RE_DOMAIN_BACKSLASH.captures(stripped) {
            let dom = caps.get(1).unwrap().as_str();
            let user = caps.get(2).unwrap().as_str();
            found.push((user.to_string(), dom.to_string()));
        }

        if let Some(caps) = RE_UPN.captures(stripped) {
            let user = caps.get(1).unwrap().as_str();
            let dom = caps.get(2).unwrap().as_str();
            // If UPN suffix is a machine hostname (e.g. user@win-xxx.w5an.local),
            // substitute the default domain to avoid storing garbage domains.
            if is_machine_hostname_domain(dom) {
                found.push((user.to_string(), default_domain.to_string()));
            } else {
                found.push((user.to_string(), dom.to_string()));
            }
        }

        for caps in RE_USER_BRACKET.captures_iter(stripped) {
            let user = caps.get(1).unwrap().as_str();
            found.push((user.to_string(), current_domain.clone()));
        }

        if let Some(caps) = RE_ACCOUNT.captures(stripped) {
            let user = caps.get(1).unwrap().as_str();
            found.push((user.to_string(), current_domain.clone()));
        }

        // Track high-confidence matches separately. `sAMAccountName: foo`
        // only appears in genuine LDAP/ldapsearch output (the attribute is
        // server-emitted, not user-generated), so RE_SAM matches survive the
        // kerbrute/asrep wordlist false-positive guard at the publishing
        // layer. Other regexes match prose like "User foo doesn't have ..."
        // which iterates wordlist failures and must stay gated. Buffered to
        // the record boundary so group/computer entries are dropped.
        if let Some(caps) = RE_SAM.captures(stripped) {
            let m = caps.get(1).unwrap();
            let user = m.as_str();
            // Embedded-space guard. RE_SAM stops at the first space, so a
            // multi-word sAMAccountName ("Backup Operators", "Domain Admins")
            // is captured truncated ("Backup"). User accounts never carry a
            // space in sAMAccountName; groups routinely do. Detecting the
            // truncation drops group leaks even when the record has no
            // `objectClass: group` line for flush_ldap_record to catch —
            // e.g. an `ldap_search` that requested only sAMAccountName.
            let value_continues = stripped[m.end()..]
                .strip_prefix(|c: char| c == ' ' || c == '\t')
                .is_some_and(|rest| rest.starts_with(|c: char| c.is_ascii_alphanumeric()));
            if !value_continues {
                pending_ldap.push((user.to_string(), current_domain.clone()));
            }
        }

        if let Some(caps) = RE_SMB_TIMESTAMP.captures(stripped) {
            let user = caps.get(1).unwrap().as_str();
            found.push((user.to_string(), current_domain.clone()));
        }

        for (raw_username, raw_domain) in found {
            let username = raw_username.trim().trim_end_matches('.').to_string();
            let domain = raw_domain.trim().trim_end_matches('.').to_string();
            if !is_valid_extracted_user(&username, &domain) {
                continue;
            }
            let key = format!("{}@{}", username.to_lowercase(), domain.to_lowercase());
            if seen.insert(key) {
                users.push(User {
                    username,
                    domain,
                    description: String::new(),
                    is_admin: false,
                    source: "output_extraction".to_string(),
                    member_of: Vec::new(),
                });
            }
        }
    }

    // Flush the final record (output that doesn't end on a blank line, or
    // netexec/rpcclient output with no record delimiters at all).
    flush_ldap_record(&mut pending_ldap, record_is_non_user, &mut users, &mut seen);

    users
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_valid_extracted_user_accepts_normal() {
        assert!(is_valid_extracted_user("alice", "contoso.local"));
    }

    #[test]
    fn is_valid_extracted_user_rejects_machine_account() {
        assert!(!is_valid_extracted_user("DC01$", "contoso.local"));
    }

    #[test]
    fn is_valid_extracted_user_rejects_empty() {
        assert!(!is_valid_extracted_user("", "contoso.local"));
    }

    #[test]
    fn is_valid_extracted_user_rejects_single_char() {
        assert!(!is_valid_extracted_user("a", "contoso.local"));
    }

    #[test]
    fn is_valid_extracted_user_rejects_noise_names() {
        for name in &["anonymous", "none", "null", "unknown", "local"] {
            assert!(
                !is_valid_extracted_user(name, "contoso.local"),
                "should reject: {name}"
            );
        }
    }

    #[test]
    fn is_valid_extracted_user_rejects_underscore_domain() {
        assert!(!is_valid_extracted_user("alice", "_contoso.local"));
    }

    #[test]
    fn is_valid_extracted_user_rejects_long_netbios() {
        // NetBIOS names > 15 chars without a dot are invalid
        assert!(!is_valid_extracted_user("alice", "TOOLONGNETBIOSNAME"));
    }

    #[test]
    fn extract_users_domain_backslash() {
        let users = extract_users("CONTOSO\\alice (SidTypeUser)", "contoso.local");
        assert_eq!(users.len(), 1);
        assert_eq!(users[0].username, "alice");
        assert_eq!(users[0].domain, "CONTOSO");
    }

    #[test]
    fn extract_users_upn_format() {
        let users = extract_users("bob@contoso.local", "contoso.local");
        assert!(users.iter().any(|u| u.username == "bob"));
    }

    #[test]
    fn extract_users_skips_machine_accounts() {
        let users = extract_users("CONTOSO\\DC01$", "contoso.local");
        assert!(users.is_empty());
    }

    #[test]
    fn is_valid_extracted_user_rejects_win_netbios_name() {
        // A raw WIN-xxxx sAMAccountName (computer) must not become a user.
        assert!(!is_valid_extracted_user("WIN-G7FPA5ZZXZV", "contoso.local"));
        assert!(!is_valid_extracted_user("desktop-abc123", "contoso.local"));
        assert!(is_valid_extracted_user("winston", "contoso.local"));
    }

    #[test]
    fn extract_users_empty_output() {
        assert!(extract_users("", "contoso.local").is_empty());
    }

    #[test]
    fn machine_hostname_win_prefix() {
        assert!(is_machine_hostname_domain("WIN-G7FPA5ZZXZV"));
        assert!(is_machine_hostname_domain("win-abc123"));
    }

    #[test]
    fn machine_hostname_win_fqdn() {
        assert!(is_machine_hostname_domain("win-g7fpa5zzxzv.w5an.local"));
        assert!(is_machine_hostname_domain("WIN-ABC123.contoso.local"));
    }

    #[test]
    fn machine_hostname_desktop_prefix() {
        assert!(is_machine_hostname_domain("DESKTOP-ABC1234"));
        assert!(is_machine_hostname_domain("desktop-xyz.fabrikam.local"));
    }

    #[test]
    fn real_domain_not_machine_hostname() {
        assert!(!is_machine_hostname_domain("contoso.local"));
        assert!(!is_machine_hostname_domain("child.contoso.local"));
        assert!(!is_machine_hostname_domain("CONTOSO"));
        assert!(!is_machine_hostname_domain("CHILD"));
    }

    #[test]
    fn extract_users_samaccountname_tagged_ldap_extraction() {
        // sAMAccountName: <name> only appears in LDAP/ldapsearch output (server-
        // emitted attribute), so the matched user is tagged as a verified
        // ldap_extraction discovery and survives the kerbrute false-positive
        // guard at the publishing layer.
        let output = "\
sAMAccountName: alice
distinguishedName: CN=alice,DC=contoso,DC=local
";
        let users = extract_users(output, "contoso.local");
        let alice = users.iter().find(|u| u.username == "alice").unwrap();
        assert_eq!(alice.source, "ldap_extraction");
    }

    #[test]
    fn extract_users_ldap_skips_group_object() {
        // A group's sAMAccountName must NOT be recorded as a user. objectClass
        // precedes sAMAccountName in a real ldapsearch entry.
        let output = "\
dn: CN=Domain Admins,CN=Users,DC=contoso,DC=local
objectClass: top
objectClass: group
sAMAccountName: itstaff

dn: CN=alice,CN=Users,DC=contoso,DC=local
objectClass: top
objectClass: person
objectClass: user
sAMAccountName: alice
";
        let users = extract_users(output, "contoso.local");
        assert!(
            users.iter().any(|u| u.username == "alice"),
            "real user must survive"
        );
        assert!(
            !users.iter().any(|u| u.username == "itstaff"),
            "group sAMAccountName must be dropped"
        );
    }

    #[test]
    fn extract_users_ldap_skips_group_when_objectclass_after_sam() {
        // Order-independence: buffering to the record boundary means the group
        // is dropped even when objectClass appears after sAMAccountName.
        let output = "\
dn: CN=Dev Team,CN=Users,DC=contoso,DC=local
sAMAccountName: devteam
objectClass: group
";
        let users = extract_users(output, "contoso.local");
        assert!(!users.iter().any(|u| u.username == "devteam"));
    }

    #[test]
    fn extract_users_ldap_skips_computer_object() {
        let output = "\
dn: CN=DC01,OU=Domain Controllers,DC=contoso,DC=local
objectClass: computer
sAMAccountName: DC01$
";
        let users = extract_users(output, "contoso.local");
        assert!(users.is_empty(), "computer account must be dropped");
    }

    #[test]
    fn extract_users_ldap_drops_spaced_group_without_objectclass() {
        // Regression: an ldap_search that requested only sAMAccountName (no
        // objectClass) dumps group names with no `objectClass: group` line for
        // flush_ldap_record to catch. RE_SAM truncates "Backup Operators" to
        // "Backup"; the embedded-space guard must drop it while keeping the
        // real single-word user.
        let output = "\
sAMAccountName: Backup Operators
sAMAccountName: alice
";
        let users = extract_users(output, "contoso.local");
        assert!(
            users.iter().any(|u| u.username == "alice"),
            "single-word user must survive"
        );
        assert!(
            !users.iter().any(|u| u.username == "Backup"),
            "truncated multi-word group name must be dropped"
        );
    }

    #[test]
    fn extract_users_ldap_keeps_gmsa_object() {
        // gMSA (msDS-GroupManagedServiceAccount) is a service identity, not a
        // "group" — its "group"-containing objectClass must not gate it out.
        let output = "\
dn: CN=svc_gmsa,CN=Managed Service Accounts,DC=contoso,DC=local
objectClass: msDS-GroupManagedServiceAccount
sAMAccountName: svc_gmsa
";
        let users = extract_users(output, "contoso.local");
        assert!(users.iter().any(|u| u.username == "svc_gmsa"));
    }

    #[test]
    fn extract_users_domain_backslash_tagged_output_extraction() {
        // DOMAIN\user matches wordlist iterations in kerbrute output and stays
        // tagged with the lower-confidence `output_extraction` source so
        // result_processing can drop them.
        let users = extract_users("CONTOSO\\bob (SidTypeUser)", "contoso.local");
        let bob = users.iter().find(|u| u.username == "bob").unwrap();
        assert_eq!(bob.source, "output_extraction");
    }

    #[test]
    fn extract_users_smb_banner_machine_domain_ignored() {
        let output = concat!(
            "SMB  192.168.58.10  445  DC01  (domain:WIN-G7FPA5ZZXZV) ...\n",
            "user:[jdoe] rid:[0x44e]\n",
        );
        let users = extract_users(output, "contoso.local");
        assert_eq!(users.len(), 1);
        assert_eq!(users[0].username, "jdoe");
        assert_eq!(users[0].domain, "contoso.local");
    }

    #[test]
    fn extract_users_upn_machine_domain_substituted() {
        let output = "jdoe@win-g7fpa5zzxzv.w5an.local\n";
        let users = extract_users(output, "contoso.local");
        assert_eq!(users.len(), 1);
        assert_eq!(users[0].username, "jdoe");
        assert_eq!(users[0].domain, "contoso.local");
    }

    #[test]
    fn extract_users_real_upn_preserved() {
        let output = "jdoe@contoso.local\n";
        let users = extract_users(output, "contoso.local");
        assert_eq!(users.len(), 1);
        assert_eq!(users[0].domain, "contoso.local");
    }

    #[test]
    fn extract_users_ignores_workgroup_domain_context() {
        // SMB banner from a non-domain-joined host (the attacker's own kali
        // box) appears in the same enumeration output as a real target. The
        // workgroup `(domain:WIN-ABCDEFGHIJK.WGRP.LOCAL)` must NOT overwrite
        // `current_domain`, so the user extracted on the next line stays
        // attributed to the operator's intended `default_domain` rather than
        // a phantom AD realm.
        let output = "\
SMB  192.168.58.178  445  WIN-ABCDEFGHIJK  [*] Windows 10 (name:WIN-ABCDEFGHIJK) (domain:WIN-ABCDEFGHIJK.WGRP.LOCAL) (signing:False)
SMB  192.168.58.178  445  WIN-ABCDEFGHIJK  [+] user:[svc_local]";
        let users = extract_users(output, "contoso.local");
        let svc = users
            .iter()
            .find(|u| u.username == "svc_local")
            .expect("svc_local should be extracted");
        assert_eq!(
            svc.domain, "contoso.local",
            "workgroup banner must not overwrite default_domain"
        );
    }

    #[test]
    fn extract_users_keeps_real_domain_context() {
        let output = "\
SMB  192.168.58.10  445  DC01  [*] Windows Server 2019 (name:DC01) (domain:contoso.local) (signing:True)
SMB  192.168.58.10  445  DC01  [+] user:[alice]";
        let users = extract_users(output, "");
        let alice = users.iter().find(|u| u.username == "alice").unwrap();
        assert_eq!(alice.domain, "contoso.local");
    }

    #[test]
    fn is_workgroup_domain_detects_self_named() {
        assert!(is_workgroup_domain(
            "WIN-ABCDEFGHIJK",
            "WIN-ABCDEFGHIJK.WGRP.LOCAL"
        ));
        assert!(is_workgroup_domain("anything", "WORKGROUP"));
        assert!(!is_workgroup_domain("DC01", "contoso.local"));
        assert!(!is_workgroup_domain("DC01", ""));
    }
}
