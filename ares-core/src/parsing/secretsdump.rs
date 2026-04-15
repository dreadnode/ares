//! Secretsdump output parser.

use regex::Regex;
use std::sync::LazyLock;

use super::types::ParsedHash;

/// Empty password NT hash constant.
const EMPTY_NT_HASH: &str = "31d6cfe0d16ae931b73c59d7e0c089c0";

static SECRETSDUMP_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^(?:([^\\:\s]+)\\)?([^:]+):(\d+):([a-fA-F0-9]{32}):([a-fA-F0-9]{32}):::$")
        .expect("secretsdump regex")
});

/// Parse secretsdump output and return a list of [`ParsedHash`] entries.
///
/// Lines that do not match the expected `user:rid:lm:nt:::` format are
/// silently skipped. Entries whose NT hash equals the empty-password hash
/// (`31d6cfe0d16ae931b73c59d7e0c089c0`) are also skipped.
pub fn parse_secretsdump(output: &str) -> Vec<ParsedHash> {
    let mut results = Vec::new();

    for line in output.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('[') {
            continue;
        }

        if let Some(caps) = SECRETSDUMP_RE.captures(line) {
            let domain = caps
                .get(1)
                .map_or(String::new(), |m| m.as_str().to_string());
            let username = caps[2].to_string();
            let rid: u32 = match caps[3].parse() {
                Ok(v) => v,
                Err(_) => continue,
            };
            let lm_hash = caps[4].to_lowercase();
            let nt_hash = caps[5].to_lowercase();

            // Skip empty password hashes
            if nt_hash == EMPTY_NT_HASH {
                continue;
            }

            let hash_value = format!("{}:{}", lm_hash, nt_hash);
            let username_lower = username.to_lowercase();

            results.push(ParsedHash {
                is_krbtgt: rid == 502 || username_lower == "krbtgt",
                is_administrator: rid == 500 || username_lower == "administrator",
                is_machine_account: username.ends_with('$'),
                username,
                domain,
                rid,
                lm_hash,
                nt_hash,
                hash_value,
            });
        }
    }

    results
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_secretsdump_basic() {
        let output = r#"[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:209c6174da490caeb422f3fa5a7ae634:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
CONTOSO\krbtgt:502:aad3b435b51404eeaad3b435b51404ee:e3c61a68f7b313e24acee19ba61cf4dd:::
CONTOSO\svc_sql:1105:aad3b435b51404eeaad3b435b51404ee:a87f3a337d73085c45f9416be5787d86:::
DC01$:1000:aad3b435b51404eeaad3b435b51404ee:7c4f7e73b23d56a3c48c0c8c1e4b8a6f:::
"#;
        let hashes = parse_secretsdump(output);

        // Guest should be skipped (empty NT hash)
        assert_eq!(hashes.len(), 4);

        // Administrator
        let admin = &hashes[0];
        assert_eq!(admin.username, "Administrator");
        assert_eq!(admin.domain, "");
        assert_eq!(admin.rid, 500);
        assert!(admin.is_administrator);
        assert!(!admin.is_krbtgt);
        assert!(!admin.is_machine_account);
        assert_eq!(admin.nt_hash, "209c6174da490caeb422f3fa5a7ae634");

        // krbtgt
        let krbtgt = &hashes[1];
        assert_eq!(krbtgt.username, "krbtgt");
        assert_eq!(krbtgt.domain, "CONTOSO");
        assert_eq!(krbtgt.rid, 502);
        assert!(krbtgt.is_krbtgt);
        assert!(!krbtgt.is_administrator);

        // svc_sql
        let svc = &hashes[2];
        assert_eq!(svc.username, "svc_sql");
        assert_eq!(svc.domain, "CONTOSO");
        assert_eq!(svc.rid, 1105);
        assert!(!svc.is_krbtgt);
        assert!(!svc.is_administrator);
        assert!(!svc.is_machine_account);

        // Machine account
        let machine = &hashes[3];
        assert_eq!(machine.username, "DC01$");
        assert!(machine.is_machine_account);
    }

    #[test]
    fn test_parse_secretsdump_empty() {
        let hashes = parse_secretsdump("");
        assert!(hashes.is_empty());
    }

    #[test]
    fn test_parse_secretsdump_hash_value_format() {
        let output =
            "Administrator:500:aad3b435b51404eeaad3b435b51404ee:209c6174da490caeb422f3fa5a7ae634:::\n";
        let hashes = parse_secretsdump(output);
        assert_eq!(hashes.len(), 1);
        assert_eq!(
            hashes[0].hash_value,
            "aad3b435b51404eeaad3b435b51404ee:209c6174da490caeb422f3fa5a7ae634"
        );
    }

    #[test]
    fn test_parse_secretsdump_skips_non_matching() {
        let output = "[*] Service RemoteRegistry is in stopped state\n[*] Starting service\nAdministrator:500:aad3b435b51404eeaad3b435b51404ee:209c6174da490caeb422f3fa5a7ae634:::\n[*] Cleaning up...\n";
        let hashes = parse_secretsdump(output);
        assert_eq!(hashes.len(), 1);
    }

    #[test]
    fn test_parse_secretsdump_administrator_by_name() {
        let output =
            "CONTOSO\\administrator:9999:aad3b435b51404eeaad3b435b51404ee:abcdef1234567890abcdef1234567890:::\n";
        let hashes = parse_secretsdump(output);
        assert_eq!(hashes.len(), 1);
        assert!(hashes[0].is_administrator);
    }

    #[test]
    fn test_secretsdump_case_insensitive_krbtgt() {
        let output =
            "CONTOSO\\KRBTGT:502:aad3b435b51404eeaad3b435b51404ee:e3c61a68f7b313e24acee19ba61cf4dd:::\n";
        let hashes = parse_secretsdump(output);
        assert_eq!(hashes.len(), 1);
        assert!(hashes[0].is_krbtgt);
    }

    #[test]
    fn test_secretsdump_no_domain() {
        let output =
            "localuser:1001:aad3b435b51404eeaad3b435b51404ee:abcdef0123456789abcdef0123456789:::\n";
        let hashes = parse_secretsdump(output);
        assert_eq!(hashes.len(), 1);
        assert_eq!(hashes[0].domain, "");
        assert_eq!(hashes[0].username, "localuser");
    }
}
