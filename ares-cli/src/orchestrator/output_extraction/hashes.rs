use regex::Regex;
use std::sync::LazyLock;

use ares_core::models::{Credential, Hash};

use super::{is_valid_credential, make_credential};

// `\*?`: the `*` after the etype is present only in impacket's RC4 layout
// (`$krb5tgs$23$*user$…`); AES tickets (etype 17/18) omit it
// (`$krb5tgs$17$user$…`). Requiring it drops every AES kerberoast hash.
static RE_TGS_HASH: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(\$krb5tgs\$\d+\$\*?([^$*]+)\$([^$*]+)\$[^$]+\$[a-fA-F0-9$]+)").unwrap()
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

// Shadow Credentials / certipy auth — `Got hash for 'user@REALM': lm:nt`
// Emitted by `certipy shadow auto`, `certipy auth`, and the pywhisker→gettgtpkinit
// chain. Format is stable across recent certipy versions; principal may be
// quoted or unquoted. Hash half is `lm:nt` or just `nt`.
static RE_CERTIPY_GOT_HASH: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"Got hash for ['"]?([^@'"\s:]+)@([^'"\s:]+)['"]?:\s*([a-fA-F0-9]{32}):([a-fA-F0-9]{32})"#,
    )
    .unwrap()
});

// Alternate shadow-creds NTLM extraction line shapes the orchestrator and
// LLM-driven summaries surface. None of these are matched by the secretsdump
// NTDS regexes above, so they need their own pass or the credential never
// lands in Redis.
//   `Retrieved NTLM for fabrikam.local\bob: 739120ebc...`
//   `Retrieved NTLM hash for fabrikam.local\user: aad3...:nt...`
//   `Retrieved NT hash for fabrikam.local\user: nt...`
//   `NT hash: nt...` lines preceded by a `Got TGT for user@domain` context line.
static RE_RETRIEVED_NTLM_FOR: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"Retrieved\s+(?:NTLM(?:\s+hash)?|NT\s+hash)\s+for\s+([^\\:\s]+)\\([^\s:]+):\s*([a-fA-F0-9]{32}(?::[a-fA-F0-9]{32})?)",
    )
    .unwrap()
});

// AES256 trust/account key from secretsdump:
//   DOMAIN\\user:aes256-cts-hmac-sha1-96:<hex>
//   contoso.local/user:aes256-cts-hmac-sha1-96:<hex>
//   user:aes256-cts-hmac-sha1-96:<hex>
static RE_AES256_KEY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?:[^\\/\s:]+[\\/])?([^:\s\\/]+):aes256-cts-hmac-sha1-96:([a-fA-F0-9]+)").unwrap()
});

// $MACHINE.ACC markers reveal the dump's source domain (NetBIOS prefix):
//   CHILD\DC01$:aes256-cts-hmac-sha1-96:<hex>
//   CHILD\DC01$:plain_password_hex:<hex>
//   CHILD\DC01$:aad3...:<nthash>:::
// The captured prefix authoritatively identifies the dump's actual domain,
// which may differ from the task's params.domain (e.g. a cross-forest task
// targeting fabrikam.local that ended up dumping a child DC).
static RE_MACHINE_ACCT_DOMAIN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?m)^([A-Za-z0-9_-]+)\\[A-Za-z0-9_.-]+\$:(?:aes256-cts-hmac-sha1-96|aes128-cts-hmac-sha1-96|plain_password_hex|des-cbc-md5|aad3b435b51404eeaad3b435b51404ee:[a-fA-F0-9]{32}:::)",
    )
    .unwrap()
});

// NTLM from a RID-less LSA `$MACHINE.ACC` row: `DOMAIN\HOST$:LM:NT:::`.
// `RE_NTLM_DOMAIN`/`RE_NTLM_PLAIN` both require a numeric RID (`:\d+:`), so the
// dumped host's own machine account — the key that unlocks gMSA reads / RBCD on
// member servers — is otherwise never emitted by this fallback.
static RE_NTLM_MACHINE_ACCT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^([^\\:\s]+)\\([A-Za-z0-9_.-]+\$):([a-fA-F0-9]{32}):([a-fA-F0-9]{32}):::").unwrap()
});

pub fn extract_hashes(output: &str, default_domain: &str) -> Vec<Hash> {
    let mut hashes = Vec::new();
    let mut seen = std::collections::HashSet::new();

    // Pre-scan for AES256 keys; these are emitted on separate lines from the
    // NTLM hash by impacket-secretsdump. Win2016+ DCs reject RC4-only
    // inter-realm tickets (KDC_ERR_TGT_REVOKED), so we attach the AES256 key
    // to the matching Hash entry by username.
    let mut aes_by_user: std::collections::HashMap<String, String> =
        std::collections::HashMap::new();
    for caps in RE_AES256_KEY.captures_iter(output) {
        let user = caps.get(1).unwrap().as_str().to_lowercase();
        let aes = caps.get(2).unwrap().as_str().to_lowercase();
        aes_by_user.insert(user, aes);
    }

    // Detect the dump's actual NetBIOS domain from $MACHINE.ACC markers.
    // If found and it conflicts with default_domain (the task's params.domain),
    // we suppress plain-format NTLM lines to prevent phantom mislabels — the
    // discoveries blob from the tool's own parser will have already captured
    // these hashes with the correct domain.
    let default_netbios = default_domain
        .split('.')
        .next()
        .unwrap_or("")
        .to_lowercase();
    let mut detected_netbios: Option<String> = None;
    let mut detected_ambiguous = false;
    for caps in RE_MACHINE_ACCT_DOMAIN.captures_iter(output) {
        let nb = caps.get(1).unwrap().as_str().to_lowercase();
        match detected_netbios {
            None => detected_netbios = Some(nb),
            Some(ref existing) if *existing == nb => {}
            Some(_) => {
                detected_ambiguous = true;
                break;
            }
        }
    }
    let suppress_plain_ntlm = !detected_ambiguous
        && !default_netbios.is_empty()
        && detected_netbios
            .as_deref()
            .is_some_and(|nb| nb != default_netbios);

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
        // Priority: shadow-creds → TGS → AS-REP → NTLM (first match wins)

        // Shadow credentials / certipy auth: `Got hash for 'user@REALM': lm:nt`
        if let Some(caps) = RE_CERTIPY_GOT_HASH.captures(line) {
            let username = caps.get(1).unwrap().as_str();
            let domain = caps.get(2).unwrap().as_str();
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
                    source: "output_extraction:shadow_credentials".to_string(),
                    discovered_at: Some(chrono::Utc::now()),
                    parent_id: None,
                    attack_step: 0,
                    aes_key: aes_by_user.get(&username.to_lowercase()).cloned(),
                    is_previous: false,
                    source_host: None,
                    is_trust_key: false,
                    trust_pair_label: None,
                });
            }
            continue;
        }

        // LLM/orchestrator summary: `Retrieved NTLM for DOMAIN\user: <hash>`
        if let Some(caps) = RE_RETRIEVED_NTLM_FOR.captures(line) {
            let domain = caps.get(1).unwrap().as_str();
            let username = caps.get(2).unwrap().as_str();
            let raw = caps.get(3).unwrap().as_str();
            // Normalise to lm:nt — fill empty LM half when only NT was emitted.
            let hash_value = if raw.contains(':') {
                raw.to_string()
            } else {
                format!("aad3b435b51404eeaad3b435b51404ee:{raw}")
            };
            let key = format!("ntlm:{}@{}", username.to_lowercase(), domain.to_lowercase());
            if seen.insert(key) {
                hashes.push(Hash {
                    id: uuid::Uuid::new_v4().to_string(),
                    username: username.to_string(),
                    hash_value,
                    hash_type: "ntlm".to_string(),
                    domain: domain.to_string(),
                    cracked_password: None,
                    source: "output_extraction:shadow_credentials".to_string(),
                    discovered_at: Some(chrono::Utc::now()),
                    parent_id: None,
                    attack_step: 0,
                    aes_key: aes_by_user.get(&username.to_lowercase()).cloned(),
                    is_previous: false,
                    source_host: None,
                    is_trust_key: false,
                    trust_pair_label: None,
                });
            }
            continue;
        }

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
                    aes_key: aes_by_user.get(&username.to_lowercase()).cloned(),
                    is_previous: false,
                    source_host: None,
                    is_trust_key: false,
                    trust_pair_label: None,
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
                    aes_key: aes_by_user.get(&username.to_lowercase()).cloned(),
                    is_previous: false,
                    source_host: None,
                    is_trust_key: false,
                    trust_pair_label: None,
                });
            }
            continue;
        }

        // NTLM machine account from a RID-less `$MACHINE.ACC` row
        // (`DOMAIN\HOST$:LM:NT:::`). Attribute to the row's own prefix exactly
        // as the domain-prefixed NTLM case does; it's the host's own account,
        // never trust material.
        if let Some(caps) = RE_NTLM_MACHINE_ACCT.captures(line) {
            let domain = caps.get(1).unwrap().as_str();
            let username = caps.get(2).unwrap().as_str();
            let lm = caps.get(3).unwrap().as_str();
            let nt = caps.get(4).unwrap().as_str();
            if nt != "31d6cfe0d16ae931b73c59d7e0c089c0" {
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
                        aes_key: aes_by_user.get(&username.to_lowercase()).cloned(),
                        is_previous: false,
                        source_host: None,
                        is_trust_key: false,
                        trust_pair_label: None,
                    });
                }
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
                    aes_key: aes_by_user.get(&username.to_lowercase()).cloned(),
                    is_previous: false,
                    source_host: None,
                    is_trust_key: false,
                    trust_pair_label: None,
                });
            }
            continue;
        }

        // NTLM without domain prefix
        if let Some(caps) = RE_NTLM_PLAIN.captures(line) {
            // Skip plain NTLM lines when the dump came from a domain that
            // differs from default_domain — applying default_domain would
            // create phantom entries (e.g. fabrikam.local:krbtgt mislabel of
            // a child DC dump done under a cross-forest task).
            if suppress_plain_ntlm {
                continue;
            }
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
            let has_domain_dump_evidence = inferred_domain.is_some()
                || (!detected_ambiguous
                    && !default_netbios.is_empty()
                    && detected_netbios
                        .as_deref()
                        .is_some_and(|nb| nb == default_netbios));
            let domain = if is_well_known_local_sam(username, rid, has_domain_dump_evidence) {
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
                    aes_key: aes_by_user.get(&username.to_lowercase()).cloned(),
                    is_previous: false,
                    source_host: None,
                    is_trust_key: false,
                    trust_pair_label: None,
                });
            }
        }
    }

    hashes
}

/// Mirror of `parsers::secrets::is_local_sam_account` for the regex fallback.
/// We don't track section context here (the fallback runs over arbitrary tool
/// output, not just secretsdump), so we combine name/RID heuristics with
/// same-output evidence that the dump is really NTDS/domain material.
fn is_well_known_local_sam(username: &str, rid: &str, has_domain_dump_evidence: bool) -> bool {
    if username.starts_with('$') || username.starts_with("_SC_") || username.starts_with("NL$") {
        return true;
    }
    if matches!(rid, "500" | "501" | "503" | "504") {
        let name = username.to_ascii_lowercase();
        if matches!(
            name.as_str(),
            "administrator" | "guest" | "defaultaccount" | "wdagutilityaccount"
        ) {
            // If the same output also proves we're parsing an NTDS/domain dump
            // (prefixed AD rows or a matching $MACHINE.ACC marker), these
            // unprefixed built-ins are domain principals, not local SAM rows.
            if has_domain_dump_evidence {
                return false;
            }
            return true;
        }
    }
    false
}

/// Hashcat cracked TGS line, in the format hashcat itself *emits* (outfile /
/// `--show`) — which differs by mode:
///   RC4 (13100): `$krb5tgs$23$*user$realm$spn*$checksum$edata:plaintext`
///   AES (17/18): `$krb5tgs$17$user$realm$checksum$edata:plaintext`  (no spn, no stars)
/// hashcat normalizes AES tickets and strips the SPN in its output, so the
/// whole `spn*$` segment must be optional, not just its leading star. Verified
/// against hashcat's own example-hash cracked output for -m 19600 and -m 13100.
static RE_CRACKED_TGS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\$krb5tgs\$\d+\$\*?([^$*]+)\$([^$*]+)\$(?:[^*:]+\*\$)?[a-fA-F0-9$]+:(.+)$")
        .unwrap()
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

/// Extract username/domain from a TGS hash in the output text. `\*?` tolerates
/// both RC4 (`$krb5tgs$23$*user…`) and AES (`$krb5tgs$17$user…`) layouts.
static RE_TGS_HASH_USER: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\$krb5tgs\$\d+\$\*?([^$*]+)\$([^$*]+)").unwrap());

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
    fn extract_hashes_ridless_machine_account() {
        // RID-less LSA `$MACHINE.ACC` row: `DOMAIN\HOST$:LM:NT:::`. The domain
        // and plain NTLM regexes both require a numeric RID, so this dedicated
        // pass is what captures the dumped host's own machine account (the key
        // that unlocks gMSA reads / RBCD on member servers).
        let output =
            "CONTOSO\\WEB01$:aad3b435b51404eeaad3b435b51404ee:abcdef1234567890abcdef1234567890:::";
        let hashes = extract_hashes(output, "CONTOSO.LOCAL");
        assert_eq!(hashes.len(), 1);
        assert_eq!(hashes[0].username, "WEB01$");
        assert_eq!(hashes[0].domain, "CONTOSO");
        assert_eq!(
            hashes[0].hash_value,
            "aad3b435b51404eeaad3b435b51404ee:abcdef1234567890abcdef1234567890"
        );
        assert!(!hashes[0].is_trust_key);
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
    fn extract_hashes_tgs_kerberoast_aes() {
        // AES128 (etype 17) kerberoast from impacket. The real layout has NO `*`
        // before the user and `$*spn*$` around the SPN (impacket format string
        // `$krb5tgs$%d$%s$%s$*%s*$%s$%s`). Must be extracted so AES-capable SPN
        // accounts reach the cracker.
        let output = "$krb5tgs$17$svc_sql$CONTOSO.LOCAL$*MSSQLSvc/db01*$aabb$ccdd";
        let hashes = extract_hashes(output, "CONTOSO.LOCAL");
        assert_eq!(hashes.len(), 1);
        assert_eq!(hashes[0].hash_type, "kerberoast");
        assert_eq!(hashes[0].username, "svc_sql");
        assert_eq!(hashes[0].domain, "CONTOSO.LOCAL");
    }

    #[test]
    fn extract_cracked_passwords_hashcat_tgs_aes() {
        // Cracked AES kerberoast line as hashcat EMITS it for -m 19600/19700:
        // the SPN is stripped/normalized away, leaving `$krb5tgs$17$user$realm$
        // checksum$edata:plaintext` — no `*` anywhere. (Captured live on the T4.)
        let output = "$krb5tgs$17$svc_sql$CONTOSO.LOCAL$aabb0000000000000000aabb$ccdd1234567890abcdef:Summer2024!";
        let creds = extract_cracked_passwords(output, "CONTOSO.LOCAL");
        assert_eq!(creds.len(), 1);
        assert_eq!(creds[0].username, "svc_sql");
        assert_eq!(creds[0].password, "Summer2024!");
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
    fn extract_hashes_suppresses_plain_ntlm_on_domain_mismatch() {
        // Regression test for Bug F: a cross-forest task with default_domain=fabrikam.local
        // dumped a CHILD DC (dc01). The output's $MACHINE.ACC marker
        // (CHILD\DC01$:aes256-...) reveals the real domain is CHILD, so plain
        // NTLM lines (krbtgt:502:..., Administrator:500:...) must NOT be labeled fabrikam.local.
        let output = "\
Administrator:500:aad3b435b51404eeaad3b435b51404ee:2e993405ab82e4454afc9c9bb0939a25:::
[*] $MACHINE.ACC
CHILD\\DC01$:aes256-cts-hmac-sha1-96:583938786f0a9459ced10e35f5803be6d4017c6fd4ba21b6e7479f9bce851d6b
CHILD\\DC01$:aad3b435b51404eeaad3b435b51404ee:a3f11b5a18f97db9a3d4f16aed85a1b6:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:8c6d94541dbc90f085e86828428d2cbf:::
krbtgt:aes256-cts-hmac-sha1-96:86eebe21a5af32061e42ef050c447d4467648e54884a92d91a3f97fbfa0114a4";
        let hashes = extract_hashes(output, "fabrikam.local");
        // Plain NTLM lines must be suppressed — no hashes should carry the
        // mismatched fabrikam.local label.
        assert!(
            !hashes
                .iter()
                .any(|h| h.domain.eq_ignore_ascii_case("fabrikam.local")),
            "no hashes should be labeled fabrikam.local when dump is from CHILD"
        );
        // The phantom mislabel was specifically of krbtgt and Administrator —
        // make sure neither slipped through with the wrong domain.
        assert!(
            !hashes.iter().any(|h| h.username == "krbtgt"),
            "plain-format krbtgt must be suppressed on domain mismatch"
        );
        assert!(
            !hashes
                .iter()
                .any(|h| h.username.eq_ignore_ascii_case("Administrator")),
            "plain-format Administrator must be suppressed on domain mismatch"
        );
    }

    #[test]
    fn extract_hashes_keeps_plain_ntlm_when_domain_matches() {
        // When default_domain matches the detected NetBIOS prefix, plain NTLM
        // lines are still extracted (the common case: a domain-targeted task).
        let output = "\
Administrator:500:aad3b435b51404eeaad3b435b51404ee:2e993405ab82e4454afc9c9bb0939a25:::
CHILD\\DC01$:aes256-cts-hmac-sha1-96:5839387800000000000000000000000000000000000000000000000000000000
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:8c6d94541dbc90f085e86828428d2cbf:::";
        let hashes = extract_hashes(output, "child.contoso.local");
        assert!(hashes.iter().any(|h| h.username == "krbtgt"));
        let admin = hashes
            .iter()
            .find(|h| h.username == "Administrator")
            .expect("Administrator should be extracted");
        assert_eq!(
            admin.domain, "child.contoso.local",
            "Administrator should inherit the target domain when the dump evidence matches it"
        );
    }

    #[test]
    fn extract_hashes_keeps_plain_ntlm_when_no_machine_acct_marker() {
        // When the output has no $MACHINE.ACC marker and no domain-prefixed
        // rows to infer from, custom RIDs (>= 1000) fall back to default_domain.
        // (Well-known local SAM accounts like Administrator/500 are handled
        // separately by `extract_hashes_ntlm_local_sam_unattributed`.)
        let output =
            "alice:1103:aad3b435b51404eeaad3b435b51404ee:209c6174da490caeb422f3fa5a7ae634:::";
        let hashes = extract_hashes(output, "contoso.local");
        assert_eq!(hashes.len(), 1);
        assert_eq!(hashes[0].domain, "contoso.local");
    }

    #[test]
    fn extract_hashes_attaches_aes256_to_trust_account() {
        let output = "\
FABRIKAM\\CONTOSO$:1107:aad3b435b51404eeaad3b435b51404ee:33333333333333333333333333333333:::
FABRIKAM\\CONTOSO$:aes256-cts-hmac-sha1-96:4444444444444444444444444444444444444444444444444444444444444444";
        let hashes = extract_hashes(output, "fabrikam.local");
        assert_eq!(hashes.len(), 1);
        assert_eq!(hashes[0].username, "CONTOSO$");
        assert_eq!(
            hashes[0].aes_key.as_deref(),
            Some("4444444444444444444444444444444444444444444444444444444444444444")
        );
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
    fn extract_cracked_passwords_batch_distinct_accounts() {
        // Batch crack: one hashcat run over several same-mode tickets emits a
        // cracked line per account. Each must attribute to its own principal
        // (the SPN account is embedded in the `$krb5tgs$` line), so a batched
        // crack recovers every crackable ticket, not just the first.
        let output = "\
$krb5tgs$18$svc_web$CONTOSO.LOCAL$aabb0000000000000000aabb$ccdd:WebPass1\n\
$krb5tgs$18$svc_sql$CONTOSO.LOCAL$eeff0000000000000000eeff$1122:SqlPass2";
        let creds = extract_cracked_passwords(output, "CONTOSO.LOCAL");
        assert_eq!(creds.len(), 2, "both cracked accounts must be extracted");
        let by_user: std::collections::HashMap<_, _> = creds
            .iter()
            .map(|c| (c.username.as_str(), c.password.as_str()))
            .collect();
        assert_eq!(by_user.get("svc_web"), Some(&"WebPass1"));
        assert_eq!(by_user.get("svc_sql"), Some(&"SqlPass2"));
    }

    #[test]
    fn extract_cracked_passwords_empty() {
        assert!(extract_cracked_passwords("", "CONTOSO").is_empty());
    }

    #[test]
    fn unprefixed_krbtgt_inherits_dump_realm_not_default_domain() {
        // A credential_access task dispatched against `fabrikam.local` may
        // actually re-dump a different DC's NTDS. When the output has
        // unprefixed `krbtgt:502:...` alongside `CHILD.CONTOSO.LOCAL\alice:...`
        // rows, the prefixed rows are evidence the dump came from
        // `CHILD.CONTOSO.LOCAL`, so the unprefixed krbtgt inherits THAT realm
        // instead of the task-intent domain.
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
        let admin = hashes
            .iter()
            .find(|h| h.username == "Administrator")
            .expect("Administrator should be extracted");
        assert_eq!(
            krbtgt.domain, "CHILD.CONTOSO.LOCAL",
            "krbtgt must inherit the realm proven by the prefixed rows, NOT the task's default_domain"
        );
        assert_ne!(
            krbtgt.domain, "fabrikam.local",
            "krbtgt must NOT be tagged with the task's intent domain when the dump is from another realm"
        );
        assert_eq!(
            admin.domain, "CHILD.CONTOSO.LOCAL",
            "Administrator should inherit the same proven dump realm as krbtgt"
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

    #[test]
    fn is_well_known_local_sam_dollar_prefix() {
        // Username starting with $ is well-known local SAM
        assert!(is_well_known_local_sam("$MACHINE.ACC", "502", false));
        // Username ending with $ (machine account) does NOT start with $ so not matched by this branch
        assert!(!is_well_known_local_sam("DC01$", "1101", false));
    }

    #[test]
    fn is_well_known_local_sam_sc_prefix() {
        // Service controller accounts
        assert!(is_well_known_local_sam("_SC_SERVICE1", "1105", false));
    }

    #[test]
    fn is_well_known_local_sam_nl_prefix() {
        // NL$ accounts
        assert!(is_well_known_local_sam("NL$KM", "65534", false));
    }

    #[test]
    fn is_well_known_local_sam_rid_503_504() {
        assert!(is_well_known_local_sam("defaultaccount", "503", false));
        assert!(is_well_known_local_sam("WDAGUtilityAccount", "504", false));
    }

    #[test]
    fn is_well_known_local_sam_admin_with_domain_dump_evidence() {
        // Administrator at RID 500 with domain dump evidence is NOT a local SAM account
        assert!(!is_well_known_local_sam("administrator", "500", true));
    }

    #[test]
    fn is_well_known_local_sam_custom_rid_not_well_known() {
        // Regular AD user with high RID is NOT a well-known local SAM account
        assert!(!is_well_known_local_sam("jdoe", "1103", false));
    }

    #[test]
    fn is_well_known_local_sam_admin_rid500_no_domain_evidence() {
        // Administrator at RID 500 without domain dump evidence IS a local SAM account
        assert!(is_well_known_local_sam("administrator", "500", false));
        assert!(is_well_known_local_sam("guest", "501", false));
    }

    #[test]
    fn is_well_known_local_sam_non_builtin_name_at_rid_500() {
        // Non-built-in name at RID 500 is NOT matched (renamed administrator)
        assert!(!is_well_known_local_sam("localadmin", "500", false));
    }

    #[test]
    fn extract_hashes_dollar_sign_machine_account_from_output() {
        // Machine accounts starting with $ are suppressed as well-known local SAM
        // $MACHINE.ACC marker lines use $ prefix and are filtered out
        let output =
            "$MACHINE.ACC:502:aad3b435b51404eeaad3b435b51404ee:e19ccf75ee54e06b06a5907af13cef42:::";
        let hashes = extract_hashes(output, "contoso.local");
        // $MACHINE.ACC is a well-known local SAM marker — suppressed (no domain)
        // Whether it appears in output depends on parser details; test for no crash
        let _ = hashes;
    }

    #[test]
    fn extract_cracked_passwords_asrep_hashcat() {
        // AS-REP hashcat format: $krb5asrep$23$user@DOMAIN:hexhash:password
        let output = "$krb5asrep$23$jdoe@CONTOSO.LOCAL:aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899:P@ssw0rd!";
        let creds = extract_cracked_passwords(output, "CONTOSO.LOCAL");
        assert_eq!(creds.len(), 1);
        assert_eq!(creds[0].username, "jdoe");
        assert_eq!(creds[0].password, "P@ssw0rd!");
    }

    #[test]
    fn shadow_creds_ntlm_hash_extracted_and_published() {
        // certipy shadow auto / certipy auth typical success line:
        //   [*] Got hash for 'bob@fabrikam.local': aad3b435b51404eeaad3b435b51404ee:739120ebc4dd940310bc4bb5c9d37021
        let output = "[*] Targeting user 'bob'\n[*] Generating certificate\n[*] Saved credential cache to 'bob.ccache'\n[*] Got hash for 'bob@fabrikam.local': aad3b435b51404eeaad3b435b51404ee:739120ebc4dd940310bc4bb5c9d37021";
        let hashes = extract_hashes(output, "fabrikam.local");
        assert_eq!(hashes.len(), 1, "expected exactly one shadow-cred hash");
        assert_eq!(hashes[0].username, "bob");
        assert_eq!(hashes[0].domain, "fabrikam.local");
        assert_eq!(hashes[0].hash_type, "ntlm");
        assert_eq!(
            hashes[0].hash_value,
            "aad3b435b51404eeaad3b435b51404ee:739120ebc4dd940310bc4bb5c9d37021"
        );
        assert_eq!(hashes[0].source, "output_extraction:shadow_credentials");
    }

    #[test]
    fn shadow_creds_retrieved_ntlm_for_short_form_extracted() {
        // Orchestrator/LLM summary lines like the op2 evidence:
        //   "Retrieved NTLM for fabrikam.local\bob: 739120ebc4dd940310bc4bb5c9d37021"
        // Only NT half present — LM should be filled with the empty-LM sentinel.
        let output = "Shadow credentials succeeded against fabrikam.local DC 192.168.58.20. Retrieved NTLM for fabrikam.local\\bob: 739120ebc4dd940310bc4bb5c9d37021. Certipy restored original KeyCredentialLink.";
        let hashes = extract_hashes(output, "fabrikam.local");
        assert_eq!(hashes.len(), 1);
        assert_eq!(hashes[0].username, "bob");
        assert_eq!(hashes[0].domain, "fabrikam.local");
        assert_eq!(
            hashes[0].hash_value,
            "aad3b435b51404eeaad3b435b51404ee:739120ebc4dd940310bc4bb5c9d37021"
        );
    }

    #[test]
    fn extract_cracked_passwords_john_show_format() {
        // John --show output: username:password:RID:LM:NT:::
        let output = "alice:Summer2024!:1103:aad3b435b51404eeaad3b435b51404ee:aabbccddeeff00112233445566778899:::
1 password hash cracked, 0 left";
        let creds = extract_cracked_passwords(output, "contoso.local");
        assert_eq!(creds.len(), 1);
        assert_eq!(creds[0].username, "alice");
        assert_eq!(creds[0].password, "Summer2024!");
    }
}
