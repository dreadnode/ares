//! NetExec user and share enumeration parsers.

use serde_json::{json, Value};

/// Parse netexec user enumeration output.
///
/// Handles two formats:
/// 1. `DOMAIN\username` lines (e.g. from `--rid-brute`)
/// 2. Table format from `--users`:
///    ```text
///    SMB  192.168.58.10  445  DC01  -Username-  -Last PW Set-  -BadPW- -Description-
///    SMB  192.168.58.10  445  DC01  alice.johnson  2026-03-25 23:21:09  0  Alice Johnson
///    ```
///
/// Also extracts embedded passwords from description fields like
/// `(Password : Summer2026!)`.
pub fn parse_netexec_users(output: &str) -> Vec<Value> {
    /// True if `s` is a `YYYY-MM-DD` date token (the netexec "Last PW Set"
    /// column) — used to reject wrapped rows where a date lands in the
    /// username slot.
    fn is_date_token(s: &str) -> bool {
        let b = s.as_bytes();
        b.len() == 10
            && b[4] == b'-'
            && b[7] == b'-'
            && b[..4].iter().all(u8::is_ascii_digit)
            && b[5..7].iter().all(u8::is_ascii_digit)
            && b[8..10].iter().all(u8::is_ascii_digit)
    }

    let mut users = Vec::new();
    let mut credentials = Vec::new();
    let mut seen = std::collections::HashSet::new();

    // Extract domain from SMB banner: (domain:contoso.local)
    let mut detected_domain = String::new();
    for line in output.lines() {
        if let Some(start) = line.find("(domain:") {
            let rest = &line[start + 8..];
            if let Some(end) = rest.find(')') {
                detected_domain = rest[..end].trim().to_string();
                break;
            }
        }
    }

    let mut in_table = false;

    for line in output.lines() {
        let line = line.trim();

        if line.is_empty() {
            continue;
        }

        // Format 1: DOMAIN\username lines (rid-brute style)
        if line.contains('\\')
            && !line.contains("[*]")
            && !line.contains("[+]")
            && !line.contains("[-]")
        {
            if let Some(user_str) = line.split_whitespace().find(|p| p.contains('\\')) {
                let parts: Vec<&str> = user_str.splitn(2, '\\').collect();
                if parts.len() == 2 {
                    let domain = parts[0].to_string();
                    let username = parts[1].to_string();
                    let key = format!("{}\\{}", domain.to_lowercase(), username.to_lowercase());
                    if seen.insert(key) {
                        users.push(json!({
                            "username": username,
                            "domain": domain,
                            "source": "netexec_user_enum",
                        }));
                    }
                }
            }
            continue;
        }

        // Detect table header: "-Username-"
        if line.contains("-Username-") {
            in_table = true;
            continue;
        }

        // Format 2: Table rows after header
        // SMB  192.168.58.10  445  DC01  alice.johnson  2026-03-25 23:21:09  0  Alice Johnson
        if in_table && line.starts_with("SMB") {
            // Skip bracket lines
            if line.contains("[*]") || line.contains("[+]") || line.contains("[-]") {
                continue;
            }

            let parts: Vec<&str> = line.split_whitespace().collect();
            // Layout: SMB IP PORT HOSTNAME USERNAME <Last PW Set> BADPW [DESC..]
            // parts:  0   1  2    3        4        5[..6]        .     ..
            //
            // "Last PW Set" is either "<never>" (1 token) or "DATE TIME"
            // (2 tokens), so the BADPW column and the description float. Only
            // the username column (index 4) is fixed. Require just username +
            // the PW-set column (>= 6) so accounts with an empty description
            // and a "<never>" PW set (7 fields) — or an empty description and
            // a normal date (8 fields) — are not silently dropped by a rigid
            // ">= 8" gate. Missing these dropped real users (e.g. service
            // accounts, freshly-reset admins) from netexec enumeration.
            if parts.len() >= 6 {
                let username = parts[4].to_string();

                // Skip header remnants and rows whose username column is a
                // date or "<never>" (wrapped / malformed output).
                if username.starts_with('-') || username == "<never>" || is_date_token(&username) {
                    continue;
                }

                let domain = if !detected_domain.is_empty() {
                    detected_domain.clone()
                } else {
                    parts[3].to_string() // hostname as fallback
                };

                let key = format!("{}\\{}", domain.to_lowercase(), username.to_lowercase());
                if seen.insert(key) {
                    // Description begins after the BADPW column, which sits one
                    // slot past a "<never>" PW set or two past "DATE TIME".
                    let desc_start = if parts.get(5) == Some(&"<never>") {
                        7
                    } else {
                        8
                    };
                    let description = if parts.len() > desc_start {
                        parts[desc_start..].join(" ")
                    } else {
                        String::new()
                    };

                    users.push(json!({
                        "username": username,
                        "domain": domain,
                        "source": "netexec_user_enum",
                    }));

                    // Check for embedded passwords in description: (Password : XXX)
                    if let Some(pw_start) = description.find("(Password") {
                        let rest = &description[pw_start..];
                        if let Some(colon) = rest.find(':') {
                            let after_colon = &rest[colon + 1..];
                            let pw = if let Some(paren) = after_colon.find(')') {
                                after_colon[..paren].trim()
                            } else {
                                after_colon.trim()
                            };
                            if !pw.is_empty() {
                                credentials.push(json!({
                                    "id": format!("leaked-{}-{}", domain, username),
                                    "username": username,
                                    "password": pw,
                                    "domain": domain,
                                    "source": "user_description_leak",
                                    "is_admin": false,
                                    "attack_step": 0,
                                }));
                            }
                        }
                    }
                }
            }
        }
    }

    // If we found credentials from description leaks, append them as a special entry
    // so the caller can extract them. We use a convention: last element has _credentials key.
    if !credentials.is_empty() {
        users.push(json!({
            "_credentials": credentials,
        }));
    }

    users
}

pub fn parse_netexec_shares(output: &str) -> Vec<Value> {
    // Netexec --shares output format (after the header/separator rows):
    //   SMB  192.168.58.10  445  DC01  SHARENAME  READ,WRITE  Remark text
    //   [0]  [1]            [2]  [3]   [4]        [5]         [6..]
    let mut shares = Vec::new();
    let mut seen = std::collections::HashSet::new();

    for line in output.lines() {
        if !(line.contains("READ") || line.contains("WRITE")) {
            continue;
        }
        let parts: Vec<&str> = line.split_whitespace().collect();
        // Minimum: SMB IP PORT HOST SHARE PERM
        if parts.len() < 6 {
            continue;
        }
        if parts[0] != "SMB" {
            continue;
        }
        let host = parts[1];
        let share_name = parts[4];
        let perm = parts[5].to_uppercase();
        if !(perm.contains("READ") || perm.contains("WRITE")) {
            continue;
        }
        // Skip header/separator rows
        if share_name.starts_with('-') || share_name.to_lowercase() == "share" {
            continue;
        }
        let comment = if parts.len() > 6 {
            parts[6..].join(" ")
        } else {
            String::new()
        };
        let key = format!("{}:{}", host.to_lowercase(), share_name.to_lowercase());
        if seen.insert(key) {
            shares.push(json!({
                "host": host,
                "name": share_name,
                "permissions": perm,
                "comment": comment,
            }));
        }
    }

    shares
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_netexec_users_rid_brute() {
        let output = "\
SMB  192.168.58.10  445  DC01  [*] Enumerating users
CONTOSO\\Administrator  (SidTypeUser)
CONTOSO\\jdoe  (SidTypeUser)
CONTOSO\\svc_sql  (SidTypeUser)";
        let users = parse_netexec_users(output);
        assert_eq!(users.len(), 3);
        assert_eq!(users[0]["username"], "Administrator");
        assert_eq!(users[0]["domain"], "CONTOSO");
        assert_eq!(users[1]["username"], "jdoe");
        assert_eq!(users[2]["username"], "svc_sql");
    }

    #[test]
    fn parse_netexec_users_table_format() {
        let output = "\
SMB  192.168.58.10  445  DC01  [*] (domain:contoso.local) Enumerated
SMB  192.168.58.10  445  DC01  -Username-  -Last PW Set-  -BadPW- -Description-
SMB  192.168.58.10  445  DC01  alice.j  2026-03-25 23:21:09  0  Alice Johnson
SMB  192.168.58.10  445  DC01  bob.s    2026-03-20 10:00:00  0  Bob Smith";
        let users = parse_netexec_users(output);
        assert_eq!(users.len(), 2);
        assert_eq!(users[0]["username"], "alice.j");
        assert_eq!(users[0]["domain"], "contoso.local"); // from domain: banner
        assert_eq!(users[1]["username"], "bob.s");
    }

    #[test]
    fn parse_netexec_users_with_password_leak() {
        let output = "\
SMB  192.168.58.10  445  DC01  [*] (domain:contoso.local) Enumerated
SMB  192.168.58.10  445  DC01  -Username-  -Last PW Set-  -BadPW- -Description-
SMB  192.168.58.10  445  DC01  svc_test  2026-01-01 00:00:00  0  Service (Password : Summer2026!)";
        let users = parse_netexec_users(output);
        // Should have user + _credentials marker
        assert!(users.len() >= 2);
        let last = users.last().unwrap();
        let creds = last["_credentials"].as_array().unwrap();
        assert_eq!(creds.len(), 1);
        assert_eq!(creds[0]["username"], "svc_test");
        assert_eq!(creds[0]["password"], "Summer2026!");
        assert_eq!(creds[0]["source"], "user_description_leak");
    }

    #[test]
    fn parse_netexec_users_dedup() {
        let output = "\
CONTOSO\\jdoe  (SidTypeUser)
CONTOSO\\jdoe  (SidTypeUser)
CONTOSO\\JDOE  (SidTypeUser)";
        let users = parse_netexec_users(output);
        assert_eq!(users.len(), 1); // all three are the same user
    }

    #[test]
    fn parse_netexec_users_empty() {
        let users = parse_netexec_users("[*] No users found");
        assert!(users.is_empty());
    }

    #[test]
    fn parses_netexec_shares() {
        let output = "\
SMB  192.168.58.10  445  DC01  Share           Permissions     Remark
SMB  192.168.58.10  445  DC01  ------          -----------     ------
SMB  192.168.58.10  445  DC01  ADMIN$                          Remote Admin
SMB  192.168.58.10  445  DC01  C$                              Default share
SMB  192.168.58.10  445  DC01  SYSVOL          READ            Logon server share
SMB  192.168.58.10  445  DC01  NETLOGON        READ            Logon server share
SMB  192.168.58.10  445  DC01  IT_Share        READ,WRITE";
        let shares = parse_netexec_shares(output);
        assert_eq!(shares.len(), 3);
        assert_eq!(shares[0]["name"], "SYSVOL");
        assert_eq!(shares[0]["host"], "192.168.58.10");
        assert_eq!(shares[0]["permissions"], "READ");
        assert_eq!(shares[0]["comment"], "Logon server share");
        assert_eq!(shares[2]["name"], "IT_Share");
        assert_eq!(shares[2]["permissions"], "READ,WRITE");
    }

    #[test]
    fn parse_netexec_shares_empty() {
        let shares = parse_netexec_shares("[*] No shares enumerated");
        assert!(shares.is_empty());
    }

    #[test]
    fn parse_netexec_shares_dedup() {
        let output = "\
SMB  192.168.58.10  445  DC01  SYSVOL  READ  Logon server share
SMB  192.168.58.10  445  DC01  SYSVOL  READ  Logon server share";
        let shares = parse_netexec_shares(output);
        assert_eq!(shares.len(), 1);
    }

    #[test]
    fn parse_netexec_shares_write_only() {
        let output = "SMB  192.168.58.10  445  DC01  Data  WRITE  Data share";
        let shares = parse_netexec_shares(output);
        assert_eq!(shares.len(), 1);
        assert_eq!(shares[0]["permissions"], "WRITE");
    }

    #[test]
    fn parse_netexec_shares_skips_header_rows() {
        let output = "\
SMB  192.168.58.10  445  DC01  Share  READ  header
SMB  192.168.58.10  445  DC01  ------  READ  separator
SMB  192.168.58.10  445  DC01  -Perms-  READ  also header";
        let shares = parse_netexec_shares(output);
        // "Share" header word should be skipped, dashes skipped
        assert_eq!(shares.len(), 0);
    }

    #[test]
    fn parse_netexec_shares_no_comment() {
        let output = "SMB  192.168.58.10  445  DC01  TestShare  READ";
        let shares = parse_netexec_shares(output);
        assert_eq!(shares.len(), 1);
        assert_eq!(shares[0]["comment"], "");
    }

    #[test]
    fn parse_netexec_users_table_no_domain_banner() {
        let output = "\
SMB  192.168.58.10  445  DC01  -Username-  -Last PW Set-  -BadPW- -Description-
SMB  192.168.58.10  445  DC01  alice.j  2026-03-25 23:21:09  0  Alice";
        let users = parse_netexec_users(output);
        assert_eq!(users.len(), 1);
        // Falls back to hostname (DC01) when no domain: banner
        assert_eq!(users[0]["domain"], "DC01");
    }

    #[test]
    fn parse_netexec_users_skips_bracket_lines_in_table() {
        let output = "\
SMB  192.168.58.10  445  DC01  -Username-  -Last PW Set-  -BadPW- -Description-
SMB  192.168.58.10  445  DC01  [*] Enumerated 5 users
SMB  192.168.58.10  445  DC01  alice.j  2026-03-25 23:21:09  0  Alice";
        let users = parse_netexec_users(output);
        assert_eq!(users.len(), 1);
        assert_eq!(users[0]["username"], "alice.j");
    }

    #[test]
    fn parse_netexec_users_table_no_description() {
        let output = "\
SMB  192.168.58.10  445  DC01  [*] (domain:contoso.local) Enumerated
SMB  192.168.58.10  445  DC01  -Username-  -Last PW Set-  -BadPW- -Description-
SMB  192.168.58.10  445  DC01  bob  2026-01-01 00:00:00  0";
        let users = parse_netexec_users(output);
        assert_eq!(users.len(), 1);
        assert_eq!(users[0]["username"], "bob");
    }

    #[test]
    fn parse_netexec_users_never_pw_set_with_description() {
        // "<never>" Last PW Set is a single token; the built-in Guest account
        // must still parse (previously dropped by the fixed ">= 8" gate only
        // when the description was also empty — this pins the shift math).
        let output = "\
SMB  192.168.58.10  445  DC01  [*] (domain:contoso.local) Enumerated
SMB  192.168.58.10  445  DC01  -Username-  -Last PW Set-  -BadPW- -Description-
SMB  192.168.58.10  445  DC01  Guest  <never>  0  Built-in account for guest access";
        let users = parse_netexec_users(output);
        assert_eq!(users.len(), 1);
        assert_eq!(users[0]["username"], "Guest");
    }

    #[test]
    fn parse_netexec_users_never_pw_set_empty_description() {
        // 7-field row: SMB IP PORT HOST USER <never> BADPW — no description.
        // The old ">= 8" gate silently dropped these accounts.
        let output = "\
SMB  192.168.58.10  445  DC01  [*] (domain:contoso.local) Enumerated
SMB  192.168.58.10  445  DC01  -Username-  -Last PW Set-  -BadPW- -Description-
SMB  192.168.58.10  445  DC01  svc_never  <never>  0";
        let users = parse_netexec_users(output);
        assert_eq!(users.len(), 1);
        assert_eq!(users[0]["username"], "svc_never");
        assert_eq!(users[0]["domain"], "contoso.local");
    }

    #[test]
    fn parse_netexec_users_dated_pw_set_empty_description() {
        // 8-field row with a real date but no description word.
        let output = "\
SMB  192.168.58.10  445  DC01  [*] (domain:contoso.local) Enumerated
SMB  192.168.58.10  445  DC01  -Username-  -Last PW Set-  -BadPW- -Description-
SMB  192.168.58.10  445  DC01  ansible  2026-06-25 22:30:43  0";
        let users = parse_netexec_users(output);
        assert_eq!(users.len(), 1);
        assert_eq!(users[0]["username"], "ansible");
    }

    #[test]
    fn parse_netexec_users_full_dc_roster_not_truncated() {
        // Real `netexec smb <dc> -u user -p pass --users` output shape:
        // mixed empty descriptions, "<never>", and multi-word descriptions.
        // Every non-header, non-bracket row must be captured.
        let output = "\
SMB  192.168.58.240  445  DC01  [*] Windows 10 / Server 2019 (name:DC01) (domain:contoso.local) (signing:True)
SMB  192.168.58.240  445  DC01  [+] contoso.local\\alice:P@ssw0rd!
SMB  192.168.58.240  445  DC01  -Username-  -Last PW Set-  -BadPW- -Description-
SMB  192.168.58.240  445  DC01  Administrator  2026-07-02 23:22:23  0  Built-in account for administering the computer/domain
SMB  192.168.58.240  445  DC01  Guest  <never>  0  Built-in account for guest access to the computer/domain
SMB  192.168.58.240  445  DC01  svc_sql  2026-06-25 22:30:43  0
SMB  192.168.58.240  445  DC01  alice  2026-06-26 22:11:39  0  Alice Adams
SMB  192.168.58.240  445  DC01  bob  2026-06-26 22:12:03  0  Bob Baker
SMB  192.168.58.240  445  DC01  [*] Enumerated 5 local users: CONTOSO";
        let users: Vec<_> = parse_netexec_users(output)
            .into_iter()
            .filter(|u| u.get("username").is_some())
            .collect();
        let names: Vec<String> = users
            .iter()
            .map(|u| u["username"].as_str().unwrap().to_string())
            .collect();
        assert_eq!(
            names,
            vec!["Administrator", "Guest", "svc_sql", "alice", "bob"],
            "all rows including empty-desc and <never> must parse"
        );
    }
}
