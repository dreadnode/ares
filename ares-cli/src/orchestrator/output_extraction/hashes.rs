use regex::Regex;
use std::sync::LazyLock;

use ares_core::models::{Credential, Hash};

use super::{is_valid_credential, make_credential};

static RE_TGS_HASH: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(\$krb5tgs\$\d+\$\*([^$*]+)\$([^$*]+)\$[^$]+\$[a-fA-F0-9$]+)").unwrap()
});

static RE_ASREP_HASH: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(\$krb5asrep\$\d+\$([^@:]+)@([^:]+):[a-fA-F0-9$]+)").unwrap());

// domain\user:rid:lmhash:nthash:::
static RE_NTLM_DOMAIN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"([^\\:\s]+)\\([^:\\]+):\d+:([a-fA-F0-9]{32}):([a-fA-F0-9]{32}):::").unwrap()
});

// user:rid:lmhash:nthash:::
static RE_NTLM_PLAIN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^([^:\\$\s]+):(\d+):([a-fA-F0-9]{32}):([a-fA-F0-9]{32}):::").unwrap()
});

// Partial NTLM line (line-wrapped secretsdump)
static RE_NTLM_PARTIAL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[^:\s]+:\d+:[a-fA-F0-9]{32}:[a-fA-F0-9]+$").unwrap());

static RE_NTLM_CONTINUATION: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[a-fA-F0-9]+:::$").unwrap());

pub fn extract_hashes(output: &str, default_domain: &str) -> Vec<Hash> {
    let mut hashes = Vec::new();
    let mut seen = std::collections::HashSet::new();

    // First pass: unwrap line-wrapped NTLM hashes
    let lines: Vec<&str> = output.lines().collect();
    let mut unwrapped: Vec<String> = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        let line = lines[i].trim();
        if RE_NTLM_PARTIAL.is_match(line) && i + 1 < lines.len() {
            let next = lines[i + 1].trim();
            if RE_NTLM_CONTINUATION.is_match(next) {
                unwrapped.push(format!("{}{}", line, next));
                i += 2;
                continue;
            }
        }
        unwrapped.push(line.to_string());
        i += 1;
    }

    // Pre-scan: infer the dump's actual realm from `DOMAIN\user:rid:lm:nt:::`
    // rows in the same output. The task's `default_domain` is *intent* (what
    // the orchestrator aimed at); domain-prefixed rows are *evidence* of what
    // was really dumped. Trusting `default_domain` over the prefixed evidence
    // creates phantom krbtgt entries whenever a credential_access task
    // dispatched at e.g. fabrikam.local actually re-dumped a different realm's
    // NTDS — every unprefixed `krbtgt:502:...:::` then gets attributed to the
    // intended realm and dreadgoad falsely promotes it to "compromised".
    // Take the most-common prefix; if none, fall back to default_domain.
    let inferred_domain: Option<String> = {
        let mut counts: std::collections::HashMap<String, u32> = std::collections::HashMap::new();
        for line in &unwrapped {
            if let Some(caps) = RE_NTLM_DOMAIN.captures(line) {
                let dom = caps.get(1).unwrap().as_str().trim().to_string();
                if !dom.is_empty() {
                    *counts.entry(dom).or_insert(0) += 1;
                }
            }
        }
        counts.into_iter().max_by_key(|(_, c)| *c).map(|(d, _)| d)
    };

    for line in &unwrapped {
        // Priority: TGS → AS-REP → NTLM (first match wins)

        // TGS (Kerberoast)
        if let Some(caps) = RE_TGS_HASH.captures(line) {
            let hash_value = caps.get(1).unwrap().as_str();
            let username = caps.get(2).unwrap().as_str();
            let domain = caps.get(3).unwrap().as_str();
            let key = format!("tgs:{}@{}", username.to_lowercase(), domain.to_lowercase());
            if seen.insert(key) {
                hashes.push(Hash {
                    id: uuid::Uuid::new_v4().to_string(),
                    username: username.to_string(),
                    hash_value: hash_value.to_string(),
                    hash_type: "kerberoast".to_string(),
                    domain: domain.to_string(),
                    cracked_password: None,
                    source: "output_extraction".to_string(),
                    discovered_at: Some(chrono::Utc::now()),
                    parent_id: None,
                    attack_step: 0,
                    aes_key: None,
                });
            }
            continue;
        }

        // AS-REP
        if let Some(caps) = RE_ASREP_HASH.captures(line) {
            let hash_value = caps.get(1).unwrap().as_str();
            let username = caps.get(2).unwrap().as_str();
            let domain = caps.get(3).unwrap().as_str();
            let key = format!(
                "asrep:{}@{}",
                username.to_lowercase(),
                domain.to_lowercase()
            );
            if seen.insert(key) {
                hashes.push(Hash {
                    id: uuid::Uuid::new_v4().to_string(),
                    username: username.to_string(),
                    hash_value: hash_value.to_string(),
                    hash_type: "asrep".to_string(),
                    domain: domain.to_string(),
                    cracked_password: None,
                    source: "output_extraction".to_string(),
                    discovered_at: Some(chrono::Utc::now()),
                    parent_id: None,
                    attack_step: 0,
                    aes_key: None,
                });
            }
            continue;
        }

        // NTLM with domain prefix
        if let Some(caps) = RE_NTLM_DOMAIN.captures(line) {
            let domain = caps.get(1).unwrap().as_str();
            let username = caps.get(2).unwrap().as_str();
            let lm = caps.get(3).unwrap().as_str();
            let nt = caps.get(4).unwrap().as_str();
            let hash_value = format!("{lm}:{nt}");
            let key = format!("ntlm:{}@{}", username.to_lowercase(), domain.to_lowercase());
            if seen.insert(key) {
                hashes.push(Hash {
                    id: uuid::Uuid::new_v4().to_string(),
                    username: username.to_string(),
                    hash_value,
                    hash_type: "ntlm".to_string(),
                    domain: domain.to_string(),
                    cracked_password: None,
                    source: "output_extraction".to_string(),
                    discovered_at: Some(chrono::Utc::now()),
                    parent_id: None,
                    attack_step: 0,
                    aes_key: None,
                });
            }
            continue;
        }

        // NTLM without domain prefix
        if let Some(caps) = RE_NTLM_PLAIN.captures(line) {
            let username = caps.get(1).unwrap().as_str();
            let rid = caps.get(2).unwrap().as_str();
            let lm = caps.get(3).unwrap().as_str();
            let nt = caps.get(4).unwrap().as_str();
            let hash_value = format!("{lm}:{nt}");
            // Well-known local SAM accounts (Administrator/500, Guest/501,
            // DefaultAccount/503, WDAGUtilityAccount/504) and LSA pseudo-rows
            // ($MACHINE.ACC, NL$KM, _SC_*) are machine-local — don't tag them
            // with the AD `default_domain` or they masquerade as domain
            // accounts and collide cross-domain. krbtgt (RID 502) is excluded
            // because it's always an AD account.
            //
            // Domain attribution preference: dump-evidence (`inferred_domain`
            // from any DOMAIN-prefixed rows in the same output) outranks
            // task-intent (`default_domain`). See pre-scan above.
            let domain = if is_well_known_local_sam(username, rid) {
                String::new()
            } else if let Some(ref inferred) = inferred_domain {
                inferred.clone()
            } else {
                default_domain.to_string()
            };
            let key = format!("ntlm:{}@{}", username.to_lowercase(), domain.to_lowercase());
            if seen.insert(key) {
                hashes.push(Hash {
                    id: uuid::Uuid::new_v4().to_string(),
                    username: username.to_string(),
                    hash_value,
                    hash_type: "ntlm".to_string(),
                    domain,
                    cracked_password: None,
                    source: "output_extraction".to_string(),
                    discovered_at: Some(chrono::Utc::now()),
                    parent_id: None,
                    attack_step: 0,
                    aes_key: None,
                });
            }
        }
    }

    hashes
}

/// Mirror of `parsers::secrets::is_local_sam_account` for the regex fallback.
/// We don't track section context here (the fallback runs over arbitrary tool
/// output, not just secretsdump), so attribution is purely name/RID-based.
fn is_well_known_local_sam(username: &str, rid: &str) -> bool {
    if matches!(rid, "500" | "501" | "503" | "504") {
        let name = username.to_ascii_lowercase();
        if matches!(
            name.as_str(),
            "administrator" | "guest" | "defaultaccount" | "wdagutilityaccount"
        ) {
            return true;
        }
    }
    username.starts_with('$') || username.starts_with("_SC_") || username.starts_with("NL$")
}

/// Hashcat cracked TGS: $krb5tgs$23$*user$DOMAIN$spn*$hash:plaintext
static RE_CRACKED_TGS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\$krb5tgs\$\d+\$\*([^$*]+)\$([^$*]+)\$[^*]+\*\$[a-fA-F0-9$]+:(.+)$").unwrap()
});

/// Cracked AS-REP: $krb5asrep$23$user@DOMAIN:hash:plaintext (hashcat)
/// or $krb5asrep$23$user@DOMAIN:plaintext (john --show, no hex section)
static RE_CRACKED_ASREP: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\$krb5asrep\$\d+\$([^@:]+)@([^:]+):(?:[a-fA-F0-9$]+:)?(.+)$").unwrap()
});

/// John --show output: user:plaintext (with optional trailing :::... fields)
/// Only matches lines that look like john --show format — username followed by
/// password, then optional RID and empty LM/NT fields.
static RE_JOHN_SHOW: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^([^:\s$][^:]*):([^:]+):\d*:(?:[a-fA-F0-9]*:){0,3}:*\s*$").unwrap()
});

/// John --show unknown user: ?:plaintext (john can't determine username from TGS hashes)
static RE_JOHN_UNKNOWN_USER: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^\?:(.+)$").unwrap());

/// Extract username/domain from a TGS hash in the output text.
static RE_TGS_HASH_USER: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\$krb5tgs\$\d+\$\*([^$*]+)\$([^$*]+)").unwrap());

pub fn extract_cracked_passwords(output: &str, default_domain: &str) -> Vec<Credential> {
    let mut credentials = Vec::new();
    let mut seen = std::collections::HashSet::new();

    // Detect john --show context (john outputs "N password hash cracked")
    let is_john_output =
        output.contains("password hash cracked") || output.contains("password hashes cracked");

    for line in output.lines() {
        let stripped = line.trim();
        if stripped.is_empty() {
            continue;
        }

        // Hashcat cracked TGS (Kerberoast)
        if let Some(caps) = RE_CRACKED_TGS.captures(stripped) {
            let username = caps.get(1).unwrap().as_str();
            let domain = caps.get(2).unwrap().as_str();
            let password = caps.get(3).unwrap().as_str();
            if is_valid_credential(username, password) {
                let key = format!(
                    "cracked:{}@{}",
                    username.to_lowercase(),
                    domain.to_lowercase()
                );
                if seen.insert(key) {
                    credentials.push(make_credential(
                        username,
                        password,
                        domain,
                        "cracked:hashcat",
                    ));
                }
            }
            continue;
        }

        // Hashcat cracked AS-REP
        if let Some(caps) = RE_CRACKED_ASREP.captures(stripped) {
            let username = caps.get(1).unwrap().as_str();
            let domain = caps.get(2).unwrap().as_str();
            let password = caps.get(3).unwrap().as_str();
            if is_valid_credential(username, password) {
                let key = format!(
                    "cracked:{}@{}",
                    username.to_lowercase(),
                    domain.to_lowercase()
                );
                if seen.insert(key) {
                    credentials.push(make_credential(
                        username,
                        password,
                        domain,
                        "cracked:hashcat",
                    ));
                }
            }
            continue;
        }

        // John --show output (only if we detected john context)
        if is_john_output {
            // John --show unknown user: ?:password (TGS hashes)
            // Try to extract username from a $krb5tgs$ line in the same output.
            if let Some(caps) = RE_JOHN_UNKNOWN_USER.captures(stripped) {
                let password = caps.get(1).unwrap().as_str().trim();
                if is_valid_credential("?", password) {
                    // Scan output for a TGS hash line to get username/domain
                    if let Some(tgs_caps) = RE_TGS_HASH_USER.captures(output) {
                        let username = tgs_caps.get(1).unwrap().as_str();
                        let domain = tgs_caps.get(2).unwrap().as_str();
                        let key = format!(
                            "cracked:{}@{}",
                            username.to_lowercase(),
                            domain.to_lowercase()
                        );
                        if seen.insert(key) {
                            credentials.push(make_credential(
                                username,
                                password,
                                domain,
                                "cracked:john",
                            ));
                        }
                    }
                }
                continue;
            }

            if let Some(caps) = RE_JOHN_SHOW.captures(stripped) {
                let username = caps.get(1).unwrap().as_str();
                let password = caps.get(2).unwrap().as_str();
                // Skip john summary lines
                if username.chars().all(|c| c.is_ascii_digit()) {
                    continue;
                }
                if is_valid_credential(username, password) {
                    let key = format!(
                        "cracked:{}@{}",
                        username.to_lowercase(),
                        default_domain.to_lowercase()
                    );
                    if seen.insert(key) {
                        credentials.push(make_credential(
                            username,
                            password,
                            default_domain,
                            "cracked:john",
                        ));
                    }
                }
            }
        }
    }

    credentials
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_hashes_ntlm_plain() {
        // Custom user (RID >= 1000) without a domain prefix should inherit
        // the operation's default_domain — these are AD accounts dumped from
        // NTDS via `-just-dc-ntlm`.
        let output =
            "alice:1103:aad3b435b51404eeaad3b435b51404ee:209c6174da490caeb422f3fa5a7ae634:::";
        let hashes = extract_hashes(output, "CONTOSO");
        assert_eq!(hashes.len(), 1);
        assert_eq!(hashes[0].username, "alice");
        assert_eq!(hashes[0].hash_type, "ntlm");
        assert_eq!(hashes[0].domain, "CONTOSO");
    }

    #[test]
    fn extract_hashes_ntlm_local_sam_unattributed() {
        // Well-known local SAM accounts (Administrator/500, Guest/501,
        // DefaultAccount/503, WDAGUtilityAccount/504) must NOT inherit the
        // AD default_domain — they're machine-local and tagging them with the
        // AD domain causes phantom duplicates across DCs in seeded labs.
        let output = "\
Administrator:500:aad3b435b51404eeaad3b435b51404ee:e19ccf75ee54e06b06a5907af13cef42:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:abcdef1234567890abcdef1234567890:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:1234567890abcdef1234567890abcdef:::";
        let hashes = extract_hashes(output, "CONTOSO");
        assert_eq!(hashes.len(), 3);
        for h in &hashes {
            assert_eq!(h.domain, "");
        }
    }

    #[test]
    fn extract_hashes_ntlm_with_domain() {
        let output =
            "CONTOSO\\jdoe:1001:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::";
        let hashes = extract_hashes(output, "DEFAULT");
        assert_eq!(hashes.len(), 1);
        assert_eq!(hashes[0].username, "jdoe");
        assert_eq!(hashes[0].domain, "CONTOSO");
    }

    #[test]
    fn extract_hashes_tgs_kerberoast() {
        let output = "$krb5tgs$23$*svc_sql$CONTOSO.LOCAL$MSSQLSvc/db01*$aabb$ccdd";
        let hashes = extract_hashes(output, "CONTOSO.LOCAL");
        assert_eq!(hashes.len(), 1);
        assert_eq!(hashes[0].hash_type, "kerberoast");
        assert_eq!(hashes[0].username, "svc_sql");
    }

    #[test]
    fn extract_hashes_asrep() {
        let output = "$krb5asrep$23$jdoe@CONTOSO.LOCAL:aabbccddeeff00112233445566778899";
        let hashes = extract_hashes(output, "CONTOSO.LOCAL");
        assert_eq!(hashes.len(), 1);
        assert_eq!(hashes[0].hash_type, "asrep");
        assert_eq!(hashes[0].username, "jdoe");
    }

    #[test]
    fn extract_hashes_dedup_same_user_domain() {
        let line =
            "alice:1103:aad3b435b51404eeaad3b435b51404ee:209c6174da490caeb422f3fa5a7ae634:::";
        let output = format!("{line}\n{line}");
        let hashes = extract_hashes(&output, "CONTOSO");
        assert_eq!(hashes.len(), 1);
    }

    #[test]
    fn extract_hashes_empty_output() {
        assert!(extract_hashes("", "CONTOSO").is_empty());
    }

    #[test]
    fn extract_cracked_passwords_hashcat_tgs() {
        let output = "$krb5tgs$23$*svc_sql$CONTOSO.LOCAL$MSSQLSvc/db01*$aabb$ccdd:Summer2024!";
        let creds = extract_cracked_passwords(output, "CONTOSO.LOCAL");
        assert_eq!(creds.len(), 1);
        assert_eq!(creds[0].username, "svc_sql");
        assert_eq!(creds[0].password, "Summer2024!");
        assert_eq!(creds[0].source, "cracked:hashcat");
    }

    #[test]
    fn extract_cracked_passwords_empty() {
        assert!(extract_cracked_passwords("", "CONTOSO").is_empty());
    }

    #[test]
    fn unprefixed_krbtgt_inherits_dump_realm_not_default_domain() {
        // Real-world bug: a credential_access task dispatched against
        // `fabrikam.local` actually re-dumped a different DC's NTDS. The dump
        // output has unprefixed `krbtgt:502:...` alongside
        // `CHILD.CONTOSO.LOCAL\alice:...:::` rows.
        // Pre-fix: krbtgt got tagged with `fabrikam.local` (task intent),
        // creating a phantom krbtgt entry that flipped dreadgoad's "domain
        // owned" for fabrikam. Post-fix: the prefixed rows in the same output
        // are evidence the dump came from `CHILD.CONTOSO.LOCAL`, so the
        // unprefixed krbtgt inherits THAT realm.
        let output = "\
[*] Dumping the NTDS, this could take a while
Administrator:500:aad3b435b51404eeaad3b435b51404ee:2e993405ab82e4454afc9c9bb0939a25:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:8c6d94541dbc90f085e86828428d2cbf:::
CHILD.CONTOSO.LOCAL\\alice:1119:aad3b435b51404eeaad3b435b51404ee:4f622f4cd4284a887228940e2ff4e709:::
CHILD.CONTOSO.LOCAL\\bob:1106:aad3b435b51404eeaad3b435b51404ee:d977b98c6c9282c5c478be1d97b237b8:::";
        let hashes = extract_hashes(output, "fabrikam.local");
        let krbtgt = hashes
            .iter()
            .find(|h| h.username == "krbtgt")
            .expect("krbtgt should be extracted");
        assert_eq!(
            krbtgt.domain, "CHILD.CONTOSO.LOCAL",
            "krbtgt must inherit the realm proven by the prefixed rows, NOT the task's default_domain"
        );
        assert_ne!(
            krbtgt.domain, "fabrikam.local",
            "krbtgt must NOT be tagged with the task's intent domain when the dump is from another realm"
        );
    }

    #[test]
    fn unprefixed_krbtgt_uses_default_domain_when_no_prefixed_rows() {
        // Sanity: when there are NO domain-prefixed rows, fall back to
        // default_domain (existing behavior — covers older impacket dumps,
        // `-just-dc-user krbtgt`, etc.).
        let output = "\
Administrator:500:aad3b435b51404eeaad3b435b51404ee:e19ccf75ee54e06b06a5907af13cef42:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:8c6d94541dbc90f085e86828428d2cbf:::";
        let hashes = extract_hashes(output, "contoso.local");
        let krbtgt = hashes.iter().find(|h| h.username == "krbtgt").unwrap();
        assert_eq!(krbtgt.domain, "contoso.local");
    }

    #[test]
    fn inferred_domain_picks_most_common_prefix() {
        // When multiple distinct prefixes appear, prefer the most common —
        // that's the realm being dumped; the others are likely trust account
        // references or stale rows from other contexts.
        let output = "\
CHILD.CONTOSO.LOCAL\\alice:1119:aad3b435b51404eeaad3b435b51404ee:4f622f4cd4284a887228940e2ff4e709:::
CHILD.CONTOSO.LOCAL\\bob:1106:aad3b435b51404eeaad3b435b51404ee:d977b98c6c9282c5c478be1d97b237b8:::
CHILD.CONTOSO.LOCAL\\carol:1107:aad3b435b51404eeaad3b435b51404ee:cba36eccfd9d949c73bc73715364aff5:::
CONTOSO\\Administrator:500:aad3b435b51404eeaad3b435b51404ee:abcdef0011223344556677889900aabb:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:8c6d94541dbc90f085e86828428d2cbf:::";
        let hashes = extract_hashes(output, "fabrikam.local");
        let krbtgt = hashes.iter().find(|h| h.username == "krbtgt").unwrap();
        assert_eq!(krbtgt.domain, "CHILD.CONTOSO.LOCAL");
    }
}
