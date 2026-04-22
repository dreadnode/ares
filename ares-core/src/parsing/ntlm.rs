//! NTLM hash extraction from various tool outputs.

use regex::Regex;
use std::sync::LazyLock;

use super::types::ParsedHash;

/// Empty password NT hash constant.
const EMPTY_NT_HASH: &str = "31d6cfe0d16ae931b73c59d7e0c089c0";

static NTLM_DOMAIN_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"([^\\:\s]+)\\([^:\\]+):(\d+):([a-fA-F0-9]{32}):([a-fA-F0-9]{32}):::")
        .expect("ntlm domain regex")
});

static NTLM_PLAIN_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"([^:\\\s]+):(\d+):([a-fA-F0-9]{32}):([a-fA-F0-9]{32}):::")
        .expect("ntlm plain regex")
});

// Regex for NT hash that may be split across two lines (first 16 hex chars on
// one line, remaining 16 on the next).
static PARTIAL_NT_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"([a-fA-F0-9]{16})\s*$").expect("partial nt regex"));

static CONTINUATION_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^\s*([a-fA-F0-9]{16})\s*$").expect("continuation regex"));

/// Extract NTLM hashes from various tool outputs.
///
/// Supports domain-prefixed (`DOMAIN\user:rid:lm:nt:::`) and plain
/// (`user:rid:lm:nt:::`) formats, as well as line-wrapped NT hashes where the
/// 32-char NT hash is split across two consecutive lines.
pub fn extract_ntlm_hashes(output: &str) -> Vec<ParsedHash> {
    let mut results = Vec::new();
    let lines: Vec<&str> = output.lines().collect();
    let mut i = 0;

    while i < lines.len() {
        let line = lines[i].trim();
        i += 1;

        if line.is_empty() {
            continue;
        }

        // Try domain-prefixed pattern first
        if let Some(caps) = NTLM_DOMAIN_RE.captures(line) {
            let domain = caps[1].to_string();
            let username = caps[2].to_string();
            let rid: u32 = match caps[3].parse() {
                Ok(v) => v,
                Err(_) => continue,
            };
            let lm_hash = caps[4].to_lowercase();
            let nt_hash = caps[5].to_lowercase();

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
            continue;
        }

        // Try plain pattern
        if let Some(caps) = NTLM_PLAIN_RE.captures(line) {
            let username = caps[1].to_string();
            let rid: u32 = match caps[2].parse() {
                Ok(v) => v,
                Err(_) => continue,
            };
            let lm_hash = caps[3].to_lowercase();
            let nt_hash = caps[4].to_lowercase();

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
                domain: String::new(),
                rid,
                lm_hash,
                nt_hash,
                hash_value,
            });
            continue;
        }

        // Handle line-wrapped NT hash: a line ending with 16 hex chars
        // followed by a continuation line of exactly 16 hex chars.
        if i < lines.len() {
            if let Some(partial_caps) = PARTIAL_NT_RE.captures(line) {
                let next_line = lines[i].trim();
                if let Some(cont_caps) = CONTINUATION_RE.captures(next_line) {
                    let first_half = partial_caps[1].to_lowercase();
                    let second_half = cont_caps[1].to_lowercase();
                    let combined_nt = format!("{}{}", first_half, second_half);

                    if combined_nt.len() == 32 && combined_nt != EMPTY_NT_HASH {
                        // Try to extract context from the line before the partial hash
                        let prefix = &line[..line.len() - 16].trim_end();
                        // Try domain\user:rid:lm: pattern on the prefix + combined
                        let reconstructed = format!("{}{}:::", prefix, combined_nt);
                        if let Some(rcaps) = NTLM_DOMAIN_RE.captures(&reconstructed) {
                            let domain = rcaps[1].to_string();
                            let username = rcaps[2].to_string();
                            let rid: u32 = rcaps[3].parse().unwrap_or(0);
                            let lm_hash = rcaps[4].to_lowercase();
                            let nt_hash_full = rcaps[5].to_lowercase();
                            let hash_value = format!("{}:{}", lm_hash, nt_hash_full);
                            let username_lower = username.to_lowercase();

                            results.push(ParsedHash {
                                is_krbtgt: rid == 502 || username_lower == "krbtgt",
                                is_administrator: rid == 500 || username_lower == "administrator",
                                is_machine_account: username.ends_with('$'),
                                username,
                                domain,
                                rid,
                                lm_hash,
                                nt_hash: nt_hash_full,
                                hash_value,
                            });
                            i += 1; // skip continuation line
                            continue;
                        }

                        // Try plain user:rid:lm: pattern
                        if let Some(rcaps) = NTLM_PLAIN_RE.captures(&reconstructed) {
                            let username = rcaps[1].to_string();
                            let rid: u32 = rcaps[2].parse().unwrap_or(0);
                            let lm_hash = rcaps[3].to_lowercase();
                            let nt_hash_full = rcaps[4].to_lowercase();
                            let hash_value = format!("{}:{}", lm_hash, nt_hash_full);
                            let username_lower = username.to_lowercase();

                            results.push(ParsedHash {
                                is_krbtgt: rid == 502 || username_lower == "krbtgt",
                                is_administrator: rid == 500 || username_lower == "administrator",
                                is_machine_account: username.ends_with('$'),
                                username,
                                domain: String::new(),
                                rid,
                                lm_hash,
                                nt_hash: nt_hash_full,
                                hash_value,
                            });
                            i += 1;
                            continue;
                        }
                    }
                }
            }
        }
    }

    results
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_ntlm_domain_prefixed() {
        let output =
            "CONTOSO\\Administrator:500:aad3b435b51404eeaad3b435b51404ee:209c6174da490caeb422f3fa5a7ae634:::\n";
        let hashes = extract_ntlm_hashes(output);
        assert_eq!(hashes.len(), 1);
        assert_eq!(hashes[0].domain, "CONTOSO");
        assert_eq!(hashes[0].username, "Administrator");
        assert!(hashes[0].is_administrator);
    }

    #[test]
    fn extract_ntlm_plain() {
        let output =
            "Administrator:500:aad3b435b51404eeaad3b435b51404ee:209c6174da490caeb422f3fa5a7ae634:::\n";
        let hashes = extract_ntlm_hashes(output);
        assert_eq!(hashes.len(), 1);
        assert_eq!(hashes[0].domain, "");
        assert_eq!(hashes[0].username, "Administrator");
        assert!(hashes[0].is_administrator);
    }

    #[test]
    fn extract_ntlm_skips_empty() {
        let output =
            "Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::\n";
        let hashes = extract_ntlm_hashes(output);
        assert!(hashes.is_empty());
    }

    #[test]
    fn extract_ntlm_line_wrapped() {
        let output =
            "CONTOSO\\svc_sql:1105:aad3b435b51404eeaad3b435b51404ee:a87f3a337d73085c\n45f9416be5787d86\n";
        let hashes = extract_ntlm_hashes(output);
        assert_eq!(hashes.len(), 1);
        assert_eq!(hashes[0].username, "svc_sql");
        assert_eq!(hashes[0].nt_hash, "a87f3a337d73085c45f9416be5787d86");
    }

    #[test]
    fn extract_ntlm_machine_account() {
        let output =
            "DC01$:1000:aad3b435b51404eeaad3b435b51404ee:7c4f7e73b23d56a3c48c0c8c1e4b8a6f:::\n";
        let hashes = extract_ntlm_hashes(output);
        assert_eq!(hashes.len(), 1);
        assert!(hashes[0].is_machine_account);
    }

    #[test]
    fn ntlm_multiple_hashes() {
        let output = "CONTOSO\\Administrator:500:aad3b435b51404eeaad3b435b51404ee:209c6174da490caeb422f3fa5a7ae634:::\nCONTOSO\\krbtgt:502:aad3b435b51404eeaad3b435b51404ee:e3c61a68f7b313e24acee19ba61cf4dd:::\nCONTOSO\\DC01$:1000:aad3b435b51404eeaad3b435b51404ee:7c4f7e73b23d56a3c48c0c8c1e4b8a6f:::\n";
        let hashes = extract_ntlm_hashes(output);
        assert_eq!(hashes.len(), 3);
        assert!(hashes[0].is_administrator);
        assert!(hashes[1].is_krbtgt);
        assert!(hashes[2].is_machine_account);
    }

    #[test]
    fn extract_ntlm_empty_input() {
        assert!(extract_ntlm_hashes("").is_empty());
    }

    #[test]
    fn extract_ntlm_no_match_lines() {
        let output = "[*] Starting dump\n[*] Done\nrandom text\n";
        assert!(extract_ntlm_hashes(output).is_empty());
    }

    #[test]
    fn extract_ntlm_hash_value_format() {
        let output =
            "CONTOSO\\svc_sql:1105:aad3b435b51404eeaad3b435b51404ee:a87f3a337d73085c45f9416be5787d86:::\n";
        let hashes = extract_ntlm_hashes(output);
        assert_eq!(hashes.len(), 1);
        assert_eq!(
            hashes[0].hash_value,
            "aad3b435b51404eeaad3b435b51404ee:a87f3a337d73085c45f9416be5787d86"
        );
    }

    #[test]
    fn extract_ntlm_krbtgt_by_rid() {
        let output =
            "CONTOSO\\someuser:502:aad3b435b51404eeaad3b435b51404ee:abcdef0123456789abcdef0123456789:::\n";
        let hashes = extract_ntlm_hashes(output);
        assert_eq!(hashes.len(), 1);
        assert!(hashes[0].is_krbtgt);
    }

    #[test]
    fn extract_ntlm_krbtgt_by_name() {
        let output =
            "CONTOSO\\krbtgt:9999:aad3b435b51404eeaad3b435b51404ee:abcdef0123456789abcdef0123456789:::\n";
        let hashes = extract_ntlm_hashes(output);
        assert_eq!(hashes.len(), 1);
        assert!(hashes[0].is_krbtgt);
    }

    #[test]
    fn extract_ntlm_uppercase_hashes_lowered() {
        let output =
            "CONTOSO\\admin:500:AAD3B435B51404EEAAD3B435B51404EE:ABCDEF0123456789ABCDEF0123456789:::\n";
        let hashes = extract_ntlm_hashes(output);
        assert_eq!(hashes.len(), 1);
        assert_eq!(hashes[0].lm_hash, "aad3b435b51404eeaad3b435b51404ee");
        assert_eq!(hashes[0].nt_hash, "abcdef0123456789abcdef0123456789");
    }

    #[test]
    fn extract_ntlm_plain_line_wrapped() {
        let output =
            "localuser:1001:aad3b435b51404eeaad3b435b51404ee:a87f3a337d73085c\n45f9416be5787d86\n";
        let hashes = extract_ntlm_hashes(output);
        assert_eq!(hashes.len(), 1);
        assert_eq!(hashes[0].username, "localuser");
        assert_eq!(hashes[0].domain, "");
        assert_eq!(hashes[0].nt_hash, "a87f3a337d73085c45f9416be5787d86");
    }
}
