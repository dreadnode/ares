//! Regex-based output parsing for security tool outputs.
//!
//! This module replaces the Python `result_processing.py` parsing functions,
//! providing parsers for secretsdump, Kerberos hashes, NTLM hashes, host
//! discovery, delegation enumeration, domain SIDs, and share enumeration.

use once_cell::sync::Lazy;
use regex::Regex;

// ---------------------------------------------------------------------------
// Empty password NT hash constant
// ---------------------------------------------------------------------------

const EMPTY_NT_HASH: &str = "31d6cfe0d16ae931b73c59d7e0c089c0";

// ---------------------------------------------------------------------------
// Data structures
// ---------------------------------------------------------------------------

/// A parsed NTLM hash entry from secretsdump or similar tool output.
#[derive(Debug, Clone, PartialEq)]
pub struct ParsedHash {
    pub username: String,
    pub domain: String,
    pub rid: u32,
    pub lm_hash: String,
    pub nt_hash: String,
    /// Combined `LM:NT` hash value.
    pub hash_value: String,
    /// `true` when RID is 502 or username is `krbtgt` (case-insensitive).
    pub is_krbtgt: bool,
    /// `true` when RID is 500 or username is `administrator` (case-insensitive).
    pub is_administrator: bool,
    /// `true` when the username ends with `$`.
    pub is_machine_account: bool,
}

/// Type of Kerberos hash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KerberosHashType {
    /// TGS (`$krb5tgs$`) hash from Kerberoasting.
    TGS,
    /// AS-REP (`$krb5asrep$`) hash from AS-REP roasting.
    AsRep,
}

/// A parsed Kerberos hash entry.
#[derive(Debug, Clone, PartialEq)]
pub struct KerberosHash {
    pub username: String,
    pub domain: String,
    pub hash_value: String,
    pub hash_type: KerberosHashType,
}

/// A parsed host from netexec/crackmapexec SMB output.
#[derive(Debug, Clone, PartialEq)]
pub struct ParsedHost {
    pub ip: String,
    pub hostname: String,
    pub os: String,
    pub domain: String,
}

/// Type of Kerberos delegation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DelegationType {
    Unconstrained,
    Constrained,
    RBCD,
}

/// A parsed delegation entry from impacket-findDelegation output.
#[derive(Debug, Clone, PartialEq)]
pub struct DelegationEntry {
    pub account: String,
    pub account_type: String,
    pub delegation_type: DelegationType,
    pub target_spn: Option<String>,
}

/// A parsed SMB share.
#[derive(Debug, Clone, PartialEq)]
pub struct ParsedShare {
    pub host: String,
    pub name: String,
    pub permissions: String,
    pub comment: String,
}

// ---------------------------------------------------------------------------
// Compiled regex patterns (compiled once, reused)
// ---------------------------------------------------------------------------

static SECRETSDUMP_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^(?:([^\\:\s]+)\\)?([^:]+):(\d+):([a-fA-F0-9]{32}):([a-fA-F0-9]{32}):::$")
        .expect("secretsdump regex")
});

static KRB_TGS_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\$krb5tgs\$\d+\$\*([^$*]+)\$([^$*]+)\$[^$]+\$[a-fA-F0-9$]+")
        .expect("krb5tgs regex")
});

static KRB_ASREP_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\$krb5asrep\$\d+\$([^@:]+)@([^:]+):[a-fA-F0-9$]+").expect("krb5asrep regex")
});

static NTLM_DOMAIN_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"([^\\:\s]+)\\([^:\\]+):(\d+):([a-fA-F0-9]{32}):([a-fA-F0-9]{32}):::")
        .expect("ntlm domain regex")
});

static NTLM_PLAIN_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"([^:\\\s]+):(\d+):([a-fA-F0-9]{32}):([a-fA-F0-9]{32}):::")
        .expect("ntlm plain regex")
});

static SMB_BANNER_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"SMB\s+(\d{1,3}(?:\.\d{1,3}){3})\s+\d+\s+([A-Za-z0-9_.\-]+)\s+\[\*\]\s+(.+)")
        .expect("smb banner regex")
});

static SMB_SIMPLE_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^SMB\s+(\d{1,3}(?:\.\d{1,3}){3})\s+\d+\s+([A-Za-z0-9_\-]+)\s+")
        .expect("smb simple regex")
});

static SMB_NAME_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\(name:([^)]+)\)").expect("smb name regex"));

static SMB_DOMAIN_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\(domain:([^)]+)\)").expect("smb domain regex"));

static SMB_OS_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^\s*([^(]+?)\s+\(name:").expect("smb os regex"));

static DOMAIN_SID_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"S-1-5-21-\d+-\d+-\d+").expect("domain sid regex"));

static SMB_SHARE_PREFIX_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^SMB\s+(\d+\.\d+\.\d+\.\d+)\s+").expect("smb share prefix regex"));

static SHARE_LINE_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^\s*(\S+)\s+(READ,\s*WRITE|READ|WRITE|NO ACCESS)\s*(.*)?$")
        .expect("share line regex")
});

// Regex for NT hash that may be split across two lines (first 16 hex chars on
// one line, remaining 16 on the next).
static PARTIAL_NT_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"([a-fA-F0-9]{16})\s*$").expect("partial nt regex"));

static CONTINUATION_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^\s*([a-fA-F0-9]{16})\s*$").expect("continuation regex"));

// ---------------------------------------------------------------------------
// 1. Secretsdump Hash Parsing
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// 2. Kerberos Hash Extraction
// ---------------------------------------------------------------------------

/// Extract Kerberos TGS and AS-REP hashes from tool output.
pub fn extract_kerberos_hashes(output: &str) -> Vec<KerberosHash> {
    let mut results = Vec::new();

    for line in output.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        // Try TGS first
        if let Some(caps) = KRB_TGS_RE.captures(line) {
            results.push(KerberosHash {
                username: caps[1].to_string(),
                domain: caps[2].to_string(),
                hash_value: line.to_string(),
                hash_type: KerberosHashType::TGS,
            });
            continue;
        }

        // Try AS-REP
        if let Some(caps) = KRB_ASREP_RE.captures(line) {
            results.push(KerberosHash {
                username: caps[1].to_string(),
                domain: caps[2].to_string(),
                hash_value: line.to_string(),
                hash_type: KerberosHashType::AsRep,
            });
        }
    }

    results
}

// ---------------------------------------------------------------------------
// 3. NTLM Hash Extraction
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// 4. Host Extraction (netexec SMB output)
// ---------------------------------------------------------------------------

/// Extract host information from netexec/crackmapexec SMB output.
pub fn extract_hosts(output: &str) -> Vec<ParsedHost> {
    let mut results = Vec::new();

    for line in output.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        // Try detailed banner pattern first
        if let Some(caps) = SMB_BANNER_RE.captures(line) {
            let ip = caps[1].to_string();
            let hostname_from_header = caps[2].to_string();
            let details = &caps[3];

            let hostname = SMB_NAME_RE
                .captures(details)
                .map(|c| c[1].to_string())
                .unwrap_or_else(|| hostname_from_header.clone());

            let domain = SMB_DOMAIN_RE
                .captures(details)
                .map(|c| c[1].to_string())
                .unwrap_or_default();

            let os = SMB_OS_RE
                .captures(details)
                .map(|c| c[1].trim().to_string())
                .unwrap_or_default();

            results.push(ParsedHost {
                ip,
                hostname,
                os,
                domain,
            });
            continue;
        }

        // Try simple pattern
        if let Some(caps) = SMB_SIMPLE_RE.captures(line) {
            results.push(ParsedHost {
                ip: caps[1].to_string(),
                hostname: caps[2].to_string(),
                os: String::new(),
                domain: String::new(),
            });
        }
    }

    results
}

// ---------------------------------------------------------------------------
// 5. Delegation Extraction
// ---------------------------------------------------------------------------

/// Extract delegation entries from impacket-findDelegation table output.
///
/// Expects a table with columns: AccountName, AccountType, DelegationType,
/// DelegationRightsTo. The parser auto-detects the header row and skips
/// separator lines (lines of dashes).
pub fn extract_delegations(output: &str) -> Vec<DelegationEntry> {
    let mut results = Vec::new();
    let mut header_found = false;
    let mut col_indices: Option<(usize, usize, usize, usize)> = None;

    for line in output.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        // Detect header row
        if !header_found {
            let lower = trimmed.to_lowercase();
            if lower.contains("accountname") && lower.contains("delegationtype") {
                // Parse column start positions from the header
                let account_name_idx = lower.find("accountname").unwrap_or(0);
                let account_type_idx = lower.find("accounttype").unwrap_or(0);
                let delegation_type_idx = lower.find("delegationtype").unwrap_or(0);
                let rights_idx = lower.find("delegationrightsto").unwrap_or(0);
                col_indices = Some((
                    account_name_idx,
                    account_type_idx,
                    delegation_type_idx,
                    rights_idx,
                ));
                header_found = true;
            }
            continue;
        }

        // Skip separator line (dashes)
        if trimmed.chars().all(|c| c == '-' || c.is_whitespace()) {
            continue;
        }

        // Parse data row using whitespace splitting (more robust than column positions
        // for variable-width columns).
        let cols: Vec<&str> = trimmed.split_whitespace().collect();
        if cols.len() < 3 {
            continue;
        }

        let _col_indices = match col_indices {
            Some(ci) => ci,
            None => continue,
        };

        // For the table format, the columns may have multi-word values
        // (e.g., "Constrained w/ Protocol Trans."). Use fixed-width column
        // parsing based on the header positions when possible.
        // Extract column values using fixed-width positions from the header.
        // Fall back to whitespace splitting for short lines.
        let (account_str, account_type_string, delegation_type_string, target_spn_string);
        if line.len() >= _col_indices.3 {
            account_str = line
                .get(_col_indices.0.._col_indices.1)
                .unwrap_or("")
                .trim()
                .to_string();
            account_type_string = line
                .get(_col_indices.1.._col_indices.2)
                .unwrap_or("")
                .trim()
                .to_string();
            delegation_type_string = line
                .get(_col_indices.2.._col_indices.3)
                .unwrap_or("")
                .trim()
                .to_string();
            target_spn_string = line.get(_col_indices.3..).unwrap_or("").trim().to_string();
        } else {
            account_str = cols[0].to_string();
            account_type_string = cols.get(1).unwrap_or(&"").to_string();
            delegation_type_string = cols[2..].join(" ");
            target_spn_string = cols.last().unwrap_or(&"").to_string();
        }

        let account = account_str.as_str();
        let account_type_str = account_type_string.as_str();
        let delegation_type_str = delegation_type_string.as_str();
        let target_spn_str = target_spn_string.as_str();

        let delegation_type = {
            let lower = delegation_type_str.to_lowercase();
            if lower.contains("unconstrained") {
                DelegationType::Unconstrained
            } else if lower.contains("resource") || lower.contains("rbcd") {
                DelegationType::RBCD
            } else if lower.contains("constrained") {
                DelegationType::Constrained
            } else {
                continue; // Unknown delegation type, skip
            }
        };

        let account_type = if account_type_str.to_lowercase().contains("computer") {
            "computer".to_string()
        } else {
            "user".to_string()
        };

        let target_spn = if target_spn_str.is_empty() || target_spn_str.to_uppercase() == "N/A" {
            None
        } else {
            Some(target_spn_str.to_string())
        };

        results.push(DelegationEntry {
            account: account.to_string(),
            account_type,
            delegation_type,
            target_spn,
        });
    }

    results
}

// ---------------------------------------------------------------------------
// 6. Domain SID Extraction
// ---------------------------------------------------------------------------

/// Extract the first domain SID (`S-1-5-21-...`) found in the output.
pub fn extract_domain_sid(output: &str) -> Option<String> {
    DOMAIN_SID_RE.find(output).map(|m| m.as_str().to_string())
}

// ---------------------------------------------------------------------------
// 7. Share Extraction
// ---------------------------------------------------------------------------

/// Extract SMB shares from netexec/crackmapexec output.
///
/// Lines are expected to start with `SMB  <ip>` followed by share information.
pub fn extract_shares(output: &str) -> Vec<ParsedShare> {
    let mut results = Vec::new();

    for line in output.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        // Extract host IP from SMB prefix
        let host = match SMB_SHARE_PREFIX_RE.captures(line) {
            Some(caps) => caps[1].to_string(),
            None => continue,
        };

        // Remove the SMB prefix to get share details
        let after_prefix = SMB_SHARE_PREFIX_RE.replace(line, "");
        let rest = after_prefix.trim();

        // Skip non-share lines (banners, status lines)
        if rest.starts_with('[') || rest.is_empty() {
            continue;
        }

        // Remove the hostname column that follows the port
        // Format after prefix removal: "445  HOSTNAME  share_info"
        // We already stripped the "SMB <ip>" prefix. The remaining format is:
        // "<port>  <hostname>  <share_details>"
        // But our prefix regex consumed "SMB <ip> ", so rest starts with port.
        // Actually, let's re-examine. The share prefix is `SMB\s+<ip>\s+`.
        // After that comes: `<port>\s+<hostname>\s+<share_info>`
        // But the regex already matched `SMB\s+<ip>\s+`, so `rest` is everything after.

        // For share lines, the format after SMB <ip> is typically:
        // 445    HOSTNAME    SHARENAME    PERMISSIONS    COMMENT
        // But the exact format varies. Let's look for known share patterns.

        // Skip lines that have [*] or [+] or [-] markers (status lines, not shares)
        if rest.contains("[*]") || rest.contains("[+]") || rest.contains("[-]") {
            continue;
        }

        // Try to parse share line: after "port hostname" we have "sharename perms comment"
        let tokens: Vec<&str> = rest.split_whitespace().collect();
        if tokens.len() < 3 {
            continue;
        }

        // tokens[0] = port (e.g., "445"), tokens[1] = hostname
        // tokens[2..] = share name, permissions, comment
        let remaining = tokens[2..].join(" ");

        // Try to match: SHARENAME  PERMISSIONS  COMMENT
        if let Some(caps) = SHARE_LINE_RE.captures(&remaining) {
            let name = caps[1].to_string();
            let permissions = caps[2].to_string();
            let comment = caps
                .get(3)
                .map(|m| m.as_str().trim().to_string())
                .unwrap_or_default();

            results.push(ParsedShare {
                host: host.clone(),
                name,
                permissions,
                comment,
            });
        }
    }

    results
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // === Secretsdump ===

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
        // Case-insensitive "administrator" detection
        let output =
            "CONTOSO\\administrator:9999:aad3b435b51404eeaad3b435b51404ee:abcdef1234567890abcdef1234567890:::\n";
        let hashes = parse_secretsdump(output);
        assert_eq!(hashes.len(), 1);
        assert!(hashes[0].is_administrator);
    }

    // === Kerberos Hashes ===

    #[test]
    fn test_extract_kerberos_tgs() {
        let output = "$krb5tgs$23$*svc_sql$CONTOSO.LOCAL$cifs/dc01.contoso.local@CONTOSO.LOCAL$abc123def456\n";
        let hashes = extract_kerberos_hashes(output);
        assert_eq!(hashes.len(), 1);
        assert_eq!(hashes[0].username, "svc_sql");
        assert_eq!(hashes[0].domain, "CONTOSO.LOCAL");
        assert_eq!(hashes[0].hash_type, KerberosHashType::TGS);
        assert!(hashes[0].hash_value.starts_with("$krb5tgs$"));
    }

    #[test]
    fn test_extract_kerberos_asrep() {
        let output = "$krb5asrep$23$jsmith@CONTOSO.LOCAL:abc123def456\n";
        let hashes = extract_kerberos_hashes(output);
        assert_eq!(hashes.len(), 1);
        assert_eq!(hashes[0].username, "jsmith");
        assert_eq!(hashes[0].domain, "CONTOSO.LOCAL");
        assert_eq!(hashes[0].hash_type, KerberosHashType::AsRep);
    }

    #[test]
    fn test_extract_kerberos_mixed() {
        let output = "Some preamble text\n$krb5tgs$23$*svc_http$CONTOSO.LOCAL$http/web01.contoso.local@CONTOSO.LOCAL$aabbccdd\n[*] Some status line\n$krb5asrep$23$nopreauth@FABRIKAM.LOCAL:11223344\n";
        let hashes = extract_kerberos_hashes(output);
        assert_eq!(hashes.len(), 2);
        assert_eq!(hashes[0].hash_type, KerberosHashType::TGS);
        assert_eq!(hashes[0].username, "svc_http");
        assert_eq!(hashes[1].hash_type, KerberosHashType::AsRep);
        assert_eq!(hashes[1].username, "nopreauth");
        assert_eq!(hashes[1].domain, "FABRIKAM.LOCAL");
    }

    #[test]
    fn test_extract_kerberos_empty() {
        assert!(extract_kerberos_hashes("").is_empty());
        assert!(extract_kerberos_hashes("no hashes here\n").is_empty());
    }

    // === NTLM Hashes ===

    #[test]
    fn test_extract_ntlm_domain_prefixed() {
        let output =
            "CONTOSO\\Administrator:500:aad3b435b51404eeaad3b435b51404ee:209c6174da490caeb422f3fa5a7ae634:::\n";
        let hashes = extract_ntlm_hashes(output);
        assert_eq!(hashes.len(), 1);
        assert_eq!(hashes[0].domain, "CONTOSO");
        assert_eq!(hashes[0].username, "Administrator");
        assert!(hashes[0].is_administrator);
    }

    #[test]
    fn test_extract_ntlm_plain() {
        let output =
            "Administrator:500:aad3b435b51404eeaad3b435b51404ee:209c6174da490caeb422f3fa5a7ae634:::\n";
        let hashes = extract_ntlm_hashes(output);
        assert_eq!(hashes.len(), 1);
        assert_eq!(hashes[0].domain, "");
        assert_eq!(hashes[0].username, "Administrator");
        assert!(hashes[0].is_administrator);
    }

    #[test]
    fn test_extract_ntlm_skips_empty() {
        let output =
            "Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::\n";
        let hashes = extract_ntlm_hashes(output);
        assert!(hashes.is_empty());
    }

    #[test]
    fn test_extract_ntlm_line_wrapped() {
        // NT hash split across two lines
        let output =
            "CONTOSO\\svc_sql:1105:aad3b435b51404eeaad3b435b51404ee:a87f3a337d73085c\n45f9416be5787d86\n";
        let hashes = extract_ntlm_hashes(output);
        assert_eq!(hashes.len(), 1);
        assert_eq!(hashes[0].username, "svc_sql");
        assert_eq!(hashes[0].nt_hash, "a87f3a337d73085c45f9416be5787d86");
    }

    #[test]
    fn test_extract_ntlm_machine_account() {
        let output =
            "DC01$:1000:aad3b435b51404eeaad3b435b51404ee:7c4f7e73b23d56a3c48c0c8c1e4b8a6f:::\n";
        let hashes = extract_ntlm_hashes(output);
        assert_eq!(hashes.len(), 1);
        assert!(hashes[0].is_machine_account);
    }

    // === Host Extraction ===

    #[test]
    fn test_extract_hosts_banner() {
        let output = "SMB  192.168.58.10  445  DC01  [*]  Windows Server 2019 Standard (name:DC01) (domain:contoso.local) (signing:True)\nSMB  192.168.58.11  445  SRV01  [*]  Windows Server 2019 Standard (name:SRV01) (domain:contoso.local)\n";
        let hosts = extract_hosts(output);
        assert_eq!(hosts.len(), 2);

        assert_eq!(hosts[0].ip, "192.168.58.10");
        assert_eq!(hosts[0].hostname, "DC01");
        assert_eq!(hosts[0].domain, "contoso.local");
        assert_eq!(hosts[0].os, "Windows Server 2019 Standard");

        assert_eq!(hosts[1].ip, "192.168.58.11");
        assert_eq!(hosts[1].hostname, "SRV01");
        assert_eq!(hosts[1].domain, "contoso.local");
    }

    #[test]
    fn test_extract_hosts_simple() {
        let output = "SMB  10.0.0.1  445  HOST01  some other data\n";
        let hosts = extract_hosts(output);
        // The banner regex should match because "some other data" doesn't have [*]
        // so it falls through to simple regex
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0].ip, "10.0.0.1");
        assert_eq!(hosts[0].hostname, "HOST01");
    }

    #[test]
    fn test_extract_hosts_empty() {
        assert!(extract_hosts("").is_empty());
        assert!(extract_hosts("no smb output here\n").is_empty());
    }

    // === Delegation ===

    #[test]
    fn test_extract_delegations() {
        let output = r#"Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies

AccountName    AccountType  DelegationType                  DelegationRightsTo
-----------    -----------  ---------------                 ------------------
svc_sql        Person       Constrained w/ Protocol Trans.  cifs/dc01.contoso.local
DC01$          Computer     Unconstrained                   N/A
"#;
        let delegations = extract_delegations(output);
        assert_eq!(delegations.len(), 2);

        assert_eq!(delegations[0].account, "svc_sql");
        assert_eq!(delegations[0].account_type, "user");
        assert_eq!(delegations[0].delegation_type, DelegationType::Constrained);
        assert_eq!(
            delegations[0].target_spn,
            Some("cifs/dc01.contoso.local".to_string())
        );

        assert_eq!(delegations[1].account, "DC01$");
        assert_eq!(delegations[1].account_type, "computer");
        assert_eq!(
            delegations[1].delegation_type,
            DelegationType::Unconstrained
        );
        assert_eq!(delegations[1].target_spn, None);
    }

    #[test]
    fn test_extract_delegations_rbcd() {
        let output = r#"AccountName    AccountType  DelegationType                          DelegationRightsTo
-----------    -----------  ---------------                         ------------------
WEB01$         Computer     Resource-Based Constrained Delegation   SRV01$
"#;
        let delegations = extract_delegations(output);
        assert_eq!(delegations.len(), 1);
        assert_eq!(delegations[0].account, "WEB01$");
        assert_eq!(delegations[0].delegation_type, DelegationType::RBCD);
    }

    #[test]
    fn test_extract_delegations_empty() {
        assert!(extract_delegations("").is_empty());
        assert!(extract_delegations("No entries found.\n").is_empty());
    }

    // === Domain SID ===

    #[test]
    fn test_extract_domain_sid() {
        let output = "[*] Domain SID is: S-1-5-21-1328384573-4090356449-2552632942\n[*] Done.\n";
        let sid = extract_domain_sid(output);
        assert_eq!(
            sid,
            Some("S-1-5-21-1328384573-4090356449-2552632942".to_string())
        );
    }

    #[test]
    fn test_extract_domain_sid_embedded() {
        let output = "some prefix S-1-5-21-111-222-333 suffix\n";
        let sid = extract_domain_sid(output);
        assert_eq!(sid, Some("S-1-5-21-111-222-333".to_string()));
    }

    #[test]
    fn test_extract_domain_sid_none() {
        assert_eq!(extract_domain_sid("no SID here"), None);
        assert_eq!(extract_domain_sid(""), None);
    }

    #[test]
    fn test_extract_domain_sid_first_match() {
        let output = "SID1: S-1-5-21-100-200-300\nSID2: S-1-5-21-400-500-600\n";
        let sid = extract_domain_sid(output);
        assert_eq!(sid, Some("S-1-5-21-100-200-300".to_string()));
    }

    // === Shares ===

    #[test]
    fn test_extract_shares() {
        let output = "SMB  192.168.58.10  445  DC01  ADMIN$  READ  Remote Admin\nSMB  192.168.58.10  445  DC01  C$  READ,WRITE  Default share\nSMB  192.168.58.10  445  DC01  IPC$  READ  Remote IPC\nSMB  192.168.58.10  445  DC01  NETLOGON  READ  Logon server share\n";
        let shares = extract_shares(output);
        assert_eq!(shares.len(), 4);

        assert_eq!(shares[0].host, "192.168.58.10");
        assert_eq!(shares[0].name, "ADMIN$");
        assert_eq!(shares[0].permissions, "READ");
        assert_eq!(shares[0].comment, "Remote Admin");

        assert_eq!(shares[1].name, "C$");
        assert_eq!(shares[1].permissions, "READ,WRITE");
    }

    #[test]
    fn test_extract_shares_skips_banners() {
        let output = "SMB  192.168.58.10  445  DC01  [*]  Windows Server 2019\nSMB  192.168.58.10  445  DC01  SYSVOL  READ  Logon server share\n";
        let shares = extract_shares(output);
        assert_eq!(shares.len(), 1);
        assert_eq!(shares[0].name, "SYSVOL");
    }

    #[test]
    fn test_extract_shares_empty() {
        assert!(extract_shares("").is_empty());
    }

    // === Edge cases ===

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

    #[test]
    fn test_ntlm_multiple_hashes() {
        let output = "CONTOSO\\Administrator:500:aad3b435b51404eeaad3b435b51404ee:209c6174da490caeb422f3fa5a7ae634:::\nCONTOSO\\krbtgt:502:aad3b435b51404eeaad3b435b51404ee:e3c61a68f7b313e24acee19ba61cf4dd:::\nCONTOSO\\DC01$:1000:aad3b435b51404eeaad3b435b51404ee:7c4f7e73b23d56a3c48c0c8c1e4b8a6f:::\n";
        let hashes = extract_ntlm_hashes(output);
        assert_eq!(hashes.len(), 3);
        assert!(hashes[0].is_administrator);
        assert!(hashes[1].is_krbtgt);
        assert!(hashes[2].is_machine_account);
    }

    #[test]
    fn test_kerberos_tgs_full_hash() {
        // Longer, more realistic TGS hash
        let output = "$krb5tgs$23$*svc_sql$CONTOSO.LOCAL$cifs/dc01.contoso.local@CONTOSO.LOCAL$abcdef1234567890abcdef1234567890abcdef1234567890\n";
        let hashes = extract_kerberos_hashes(output);
        assert_eq!(hashes.len(), 1);
        assert_eq!(hashes[0].username, "svc_sql");
        assert_eq!(hashes[0].domain, "CONTOSO.LOCAL");
    }

    #[test]
    fn test_hosts_with_signing_info() {
        let output = "SMB  192.168.58.10  445  DC01  [*]  Windows Server 2022 (name:DC01) (domain:contoso.local) (signing:True) (SMBv1:False)\n";
        let hosts = extract_hosts(output);
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0].hostname, "DC01");
        assert_eq!(hosts[0].os, "Windows Server 2022");
        assert_eq!(hosts[0].domain, "contoso.local");
    }

    #[test]
    fn test_delegations_with_preamble() {
        let output = r#"Impacket v0.12.0 - Copyright 2023 Fortra

AccountName     AccountType   DelegationType     DelegationRightsTo
-----------     -----------   ---------------    ------------------
web_svc         Person        Unconstrained      N/A
"#;
        let delegations = extract_delegations(output);
        assert_eq!(delegations.len(), 1);
        assert_eq!(delegations[0].account, "web_svc");
        assert_eq!(
            delegations[0].delegation_type,
            DelegationType::Unconstrained
        );
        assert_eq!(delegations[0].target_spn, None);
    }
}
