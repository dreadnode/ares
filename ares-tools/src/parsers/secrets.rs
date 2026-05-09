//! Secretsdump, Kerberoast, and AS-REP roast output parsers.

use serde_json::{json, Value};

/// Section context tracked while scanning secretsdump output. The dump emits
/// `[*] Dumping local SAM hashes ...` for the local SAM section, then
/// `[*] Dumping Domain Credentials ...` (or NTDS markers) for AD accounts.
/// Lines without an explicit `DOMAIN\` prefix in the local SAM section are
/// machine-local accounts and must NOT be attributed to the AD `target_domain`
/// — doing so creates phantom AD records (e.g. an `Administrator` hash from
/// each DC's local SAM tagged with that DC's AD domain, which then collides
/// across domains in lab environments where local creds are seeded uniformly).
#[derive(Clone, Copy, PartialEq, Eq)]
enum DumpSection {
    Unknown,
    LocalSam,
    Domain,
}

pub fn parse_secretsdump(output: &str, params: &Value) -> (Vec<Value>, Vec<Value>) {
    // Prefer target_domain (the domain being dumped) over domain (auth credential's domain)
    // to correctly attribute hashes when authenticating cross-domain.
    let domain = params
        .get("target_domain")
        .or_else(|| params.get("domain"))
        .and_then(|v| v.as_str())
        .unwrap_or("");

    let mut hashes = Vec::new();
    let creds = Vec::new();
    let mut section = DumpSection::Unknown;

    for line in output.lines() {
        let line = line.trim();

        // Section markers — secretsdump emits these as informational lines
        // before each block. Recognize them so we can tell SAM rows from NTDS
        // rows when the row itself has no `DOMAIN\` prefix.
        if line.starts_with('[') {
            if line.contains("Dumping local SAM") {
                section = DumpSection::LocalSam;
            } else if line.contains("Dumping Domain Credentials")
                || line.contains("Dumping cached domain")
                || line.contains("NTDS")
                || line.contains("Searching for pekList")
            {
                section = DumpSection::Domain;
            }
            continue;
        }

        // NTLM hash format: "username:RID:LMhash:NThash:::"
        // or "DOMAIN\username:RID:LMhash:NThash:::"
        if line.contains(":::") && !line.starts_with('#') {
            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() >= 4 {
                let raw_user = parts[0];
                let rid = parts.get(1).copied().unwrap_or("");
                let (user_domain, username) = if raw_user.contains('\\') {
                    let split: Vec<&str> = raw_user.splitn(2, '\\').collect();
                    let netbios = split[0];
                    // Resolve NetBIOS domain prefix to FQDN using target_domain.
                    // e.g. "CONTOSO" → "contoso.local" when target_domain="contoso.local"
                    let resolved = resolve_netbios_to_fqdn(netbios, domain);
                    (resolved, split[1].to_string())
                } else if is_local_sam_account(raw_user, rid, section) {
                    // Local SAM account dumped without a domain prefix —
                    // leave domain empty so it doesn't masquerade as AD.
                    (String::new(), raw_user.to_string())
                } else {
                    (domain.to_string(), raw_user.to_string())
                };

                let nt_hash = parts[3];
                if nt_hash.len() == 32 && nt_hash != "31d6cfe0d16ae931b73c59d7e0c089c0" {
                    // Skip empty/disabled hashes
                    let lm_hash = parts[2];
                    let hash_value = format!("{}:{}", lm_hash, nt_hash);

                    hashes.push(json!({
                        "username": username,
                        "domain": user_domain,
                        "hash_value": hash_value,
                        "hash_type": "ntlm",
                        "source": "secretsdump",
                    }));
                }
            }
        }

        // Cleartext passwords: "[*] Dumping DPAPI creds..." then "username:password"
        // or from LSA: "[*] DefaultPassword\n  username = ...\n  password = ..."
    }

    (hashes, creds)
}

/// Decide whether an unprefixed dump row is a local SAM account.
///
/// Two signals: (1) the dump section we're currently parsing and (2) the
/// well-known RID/name pairs that are always machine-local
/// (Administrator/500, Guest/501, DefaultAccount/503, WDAGUtilityAccount/504,
/// plus secretsdump's pseudo-rows like `$MACHINE.ACC` and `_SC_*` service
/// secrets emitted in the LSA section). Note that `krbtgt` is NOT in this
/// list: krbtgt is always an AD account, never local.
fn is_local_sam_account(raw_user: &str, rid: &str, section: DumpSection) -> bool {
    if section == DumpSection::LocalSam {
        return true;
    }
    // RID-based: 500/501/503/504 are well-known built-ins. Don't include 502
    // (krbtgt) — it's a domain account that happens to share a fixed RID.
    if matches!(rid, "500" | "501" | "503" | "504") {
        let name = raw_user.to_ascii_lowercase();
        if matches!(
            name.as_str(),
            "administrator" | "guest" | "defaultaccount" | "wdagutilityaccount"
        ) {
            return true;
        }
    }
    // LSA pseudo-rows from `[*] Dumping LSA Secrets` — `$MACHINE.ACC`, etc.
    if raw_user.starts_with('$') || raw_user.starts_with("_SC_") || raw_user.starts_with("NL$") {
        return true;
    }
    false
}

/// Resolve a NetBIOS domain name to FQDN using the target domain as reference.
///
/// When secretsdump outputs `CONTOSO\username`, the domain prefix is the NetBIOS
/// name. If we know the target FQDN is `contoso.local`, we can resolve it by
/// matching the first label. Returns the original name if no match is found.
fn resolve_netbios_to_fqdn(netbios: &str, target_domain: &str) -> String {
    if target_domain.is_empty() || netbios.is_empty() {
        return netbios.to_string();
    }

    // If the NetBIOS name already looks like an FQDN, keep it
    if netbios.contains('.') {
        return netbios.to_string();
    }

    // Match NetBIOS against the first label of the target FQDN.
    // e.g. "CONTOSO" matches "contoso.local", "CHILD" matches "child.contoso.local"
    let first_label = target_domain.split('.').next().unwrap_or("");
    if netbios.eq_ignore_ascii_case(first_label) {
        return target_domain.to_string();
    }

    // No match — keep the raw NetBIOS name (recovery normalization will resolve it later)
    netbios.to_string()
}

pub fn parse_kerberoast(output: &str, params: &Value) -> Vec<Value> {
    let domain = params.get("domain").and_then(|v| v.as_str()).unwrap_or("");

    let mut hashes = Vec::new();

    for line in output.lines() {
        let line = line.trim();
        // "$krb5tgs$23$*username$DOMAIN$..." format
        if line.starts_with("$krb5tgs$") {
            // Extract username from the hash
            let parts: Vec<&str> = line.split('$').collect();
            let username = if parts.len() > 3 {
                parts[3].trim_start_matches('*').to_string()
            } else {
                "unknown".to_string()
            };

            hashes.push(json!({
                "username": username,
                "domain": domain,
                "hash_value": line,
                "hash_type": "kerberoast",
                "source": "kerberoast",
            }));
        }
    }

    hashes
}

pub fn parse_asrep_roast(output: &str, params: &Value) -> Vec<Value> {
    let domain = params.get("domain").and_then(|v| v.as_str()).unwrap_or("");

    let mut hashes = Vec::new();

    for line in output.lines() {
        let line = line.trim();
        if line.starts_with("$krb5asrep$") {
            let parts: Vec<&str> = line.split('$').collect();
            let username = if parts.len() > 3 {
                parts[3]
                    .trim_start_matches('*')
                    .split('@')
                    .next()
                    .unwrap_or("unknown")
                    .to_string()
            } else {
                "unknown".to_string()
            };

            hashes.push(json!({
                "username": username,
                "domain": domain,
                "hash_value": line,
                "hash_type": "asrep",
                "source": "asrep_roast",
            }));
        }
    }

    hashes
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parse_secretsdump_ntlm_hashes() {
        // Local SAM section: rows must NOT inherit `target_domain` — these
        // are machine-local accounts, not AD. Tagging them with the AD domain
        // creates phantom AD records that collide cross-domain in seeded labs.
        let output = "\
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:e19ccf75ee54e06b06a5907af13cef42:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
svc_sql:1001:aad3b435b51404eeaad3b435b51404ee:abcdef1234567890abcdef1234567890:::
[*] Cleaning up...";
        let params = json!({"domain": "contoso.local"});
        let (hashes, creds) = parse_secretsdump(output, &params);

        // Guest hash (31d6cf...) should be skipped (empty/disabled)
        assert_eq!(hashes.len(), 2);
        assert_eq!(hashes[0]["username"], "Administrator");
        assert_eq!(hashes[0]["domain"], "");
        assert_eq!(hashes[0]["hash_type"], "ntlm");
        assert!(hashes[0]["hash_value"]
            .as_str()
            .unwrap()
            .contains("e19ccf75"));
        assert_eq!(hashes[1]["username"], "svc_sql");
        assert_eq!(hashes[1]["domain"], "");
        assert!(creds.is_empty());
    }

    #[test]
    fn parse_secretsdump_ntds_section_uses_target_domain() {
        // NTDS section: unprefixed rows (e.g. from `-just-dc-ntlm` output)
        // are AD accounts and SHOULD inherit target_domain. Distinguished
        // from the local SAM case by the section marker emitted earlier.
        let output = "\
[*] Dumping the NTDS, this could take a while
[*] Searching for pekList, be patient
[*] PEK # 0 found and decrypted: abcdef
[*] Reading and decrypting hashes from /tmp/ntds.dit
alice:1103:aad3b435b51404eeaad3b435b51404ee:abcdef1234567890abcdef1234567890:::
WIN-XYZ$:1001:aad3b435b51404eeaad3b435b51404ee:1234567890abcdef1234567890abcdef:::
[*] Kerberos keys grabbed";
        let params = json!({"target_domain": "contoso.local"});
        let (hashes, _) = parse_secretsdump(output, &params);
        assert_eq!(hashes.len(), 2);
        assert_eq!(hashes[0]["username"], "alice");
        assert_eq!(hashes[0]["domain"], "contoso.local");
        assert_eq!(hashes[1]["username"], "WIN-XYZ$");
        assert_eq!(hashes[1]["domain"], "contoso.local");
    }

    #[test]
    fn parse_secretsdump_well_known_sam_in_unknown_section() {
        // No section marker before the rows — fall back to the well-known
        // RID/name signal. Administrator/500 and DefaultAccount/503 are
        // always local; svc_custom/1001 stays attributed to target_domain.
        let output = "\
Administrator:500:aad3b435b51404eeaad3b435b51404ee:e19ccf75ee54e06b06a5907af13cef42:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:abcdef1234567890abcdef1234567890:::
svc_custom:1001:aad3b435b51404eeaad3b435b51404ee:1234567890abcdef1234567890abcdef:::";
        let params = json!({"target_domain": "contoso.local"});
        let (hashes, _) = parse_secretsdump(output, &params);
        assert_eq!(hashes.len(), 3);
        assert_eq!(hashes[0]["username"], "Administrator");
        assert_eq!(hashes[0]["domain"], "");
        assert_eq!(hashes[1]["username"], "DefaultAccount");
        assert_eq!(hashes[1]["domain"], "");
        assert_eq!(hashes[2]["username"], "svc_custom");
        assert_eq!(hashes[2]["domain"], "contoso.local");
    }

    #[test]
    fn parse_secretsdump_lsa_pseudo_rows_unattributed() {
        // LSA secrets emit `$MACHINE.ACC`, `NL$KM`, `_SC_*` rows — none of
        // these are AD principals; they must not inherit target_domain.
        let output = "\
[*] Dumping LSA Secrets
$MACHINE.ACC:plain_password:aad3b435b51404eeaad3b435b51404ee:1111111111111111aaaaaaaaaaaaaaaa:::
[*] DPAPI_SYSTEM
NL$KM:0:aad3b435b51404eeaad3b435b51404ee:2222222222222222bbbbbbbbbbbbbbbb:::";
        let params = json!({"target_domain": "contoso.local"});
        let (hashes, _) = parse_secretsdump(output, &params);
        assert_eq!(hashes.len(), 2);
        for h in &hashes {
            assert_eq!(h["domain"], "");
        }
    }

    #[test]
    fn parse_secretsdump_krbtgt_keeps_target_domain() {
        // krbtgt has the well-known RID 502 but is ALWAYS an AD account, never
        // local SAM. Don't strip target_domain from unprefixed krbtgt rows.
        let output = "\
[*] Dumping the NTDS, this could take a while
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:8c6d94541dbc90f085e86828428d2cbf:::";
        let params = json!({"target_domain": "contoso.local"});
        let (hashes, _) = parse_secretsdump(output, &params);
        assert_eq!(hashes.len(), 1);
        assert_eq!(hashes[0]["username"], "krbtgt");
        assert_eq!(hashes[0]["domain"], "contoso.local");
    }

    #[test]
    fn parse_secretsdump_domain_prefix() {
        let output = "CONTOSO\\Administrator:500:aad3b435b51404eeaad3b435b51404ee:e19ccf75ee54e06b06a5907af13cef42:::";
        let params = json!({"domain": "contoso.local"});
        let (hashes, _) = parse_secretsdump(output, &params);
        assert_eq!(hashes.len(), 1);
        assert_eq!(hashes[0]["username"], "Administrator");
        // NetBIOS "CONTOSO" resolved to FQDN "contoso.local" via target_domain
        assert_eq!(hashes[0]["domain"], "contoso.local");
    }

    #[test]
    fn parse_secretsdump_netbios_resolved_to_fqdn() {
        // NetBIOS prefix should be resolved to FQDN via target_domain
        let output = "\
FABRIKAM\\alice:1103:aad3b435b51404eeaad3b435b51404ee:abcdef1234567890abcdef1234567890:::
FABRIKAM\\bob:1104:aad3b435b51404eeaad3b435b51404ee:1234567890abcdef1234567890abcdef:::";
        let params = json!({"target_domain": "fabrikam.local"});
        let (hashes, _) = parse_secretsdump(output, &params);
        assert_eq!(hashes.len(), 2);
        assert_eq!(hashes[0]["username"], "alice");
        assert_eq!(hashes[0]["domain"], "fabrikam.local");
        assert_eq!(hashes[1]["username"], "bob");
        assert_eq!(hashes[1]["domain"], "fabrikam.local");
    }

    #[test]
    fn parse_secretsdump_target_domain_preferred() {
        // target_domain should take precedence over domain for attribution
        let output = "FABRIKAM\\svc_sql:1105:aad3b435b51404eeaad3b435b51404ee:abcdef1234567890abcdef1234567890:::";
        let params = json!({"domain": "contoso.local", "target_domain": "fabrikam.local"});
        let (hashes, _) = parse_secretsdump(output, &params);
        assert_eq!(hashes.len(), 1);
        assert_eq!(hashes[0]["domain"], "fabrikam.local");
    }

    #[test]
    fn parse_secretsdump_mismatched_netbios_kept() {
        // If NetBIOS doesn't match target_domain's first label, keep it raw
        let output = "CHILD\\jsmith:1001:aad3b435b51404eeaad3b435b51404ee:abcdef1234567890abcdef1234567890:::";
        let params = json!({"target_domain": "fabrikam.local"});
        let (hashes, _) = parse_secretsdump(output, &params);
        assert_eq!(hashes.len(), 1);
        assert_eq!(hashes[0]["username"], "jsmith");
        // "CHILD" doesn't match "fabrikam" so it stays as-is
        assert_eq!(hashes[0]["domain"], "CHILD");
    }

    #[test]
    fn resolves_netbios_to_fqdn() {
        assert_eq!(
            resolve_netbios_to_fqdn("FABRIKAM", "fabrikam.local"),
            "fabrikam.local"
        );
        assert_eq!(
            resolve_netbios_to_fqdn("CHILD", "child.contoso.local"),
            "child.contoso.local"
        );
        assert_eq!(resolve_netbios_to_fqdn("CHILD", "fabrikam.local"), "CHILD"); // no match
        assert_eq!(
            resolve_netbios_to_fqdn("fabrikam.local", "fabrikam.local"),
            "fabrikam.local"
        ); // already FQDN
        assert_eq!(resolve_netbios_to_fqdn("", "fabrikam.local"), "");
        assert_eq!(resolve_netbios_to_fqdn("FABRIKAM", ""), "FABRIKAM");
    }

    #[test]
    fn parse_secretsdump_skips_comments_and_brackets() {
        let output = "\
[*] Service RemoteRegistry is in stopped state
# This is a comment
[*] SAM hashes extracted";
        let params = json!({"domain": "contoso.local"});
        let (hashes, _) = parse_secretsdump(output, &params);
        assert!(hashes.is_empty());
    }

    #[test]
    fn parse_secretsdump_empty_output() {
        let (hashes, creds) = parse_secretsdump("", &json!({}));
        assert!(hashes.is_empty());
        assert!(creds.is_empty());
    }

    #[test]
    fn parse_kerberoast_hashes() {
        let output = "\
[*] Getting TGS for SPN accounts
$krb5tgs$23$*svc_sql$CONTOSO.LOCAL$contoso.local/svc_sql*$abc123def456
$krb5tgs$23$*svc_http$CONTOSO.LOCAL$contoso.local/svc_http*$789xyz
[*] Done";
        let params = json!({"domain": "contoso.local"});
        let hashes = parse_kerberoast(output, &params);
        assert_eq!(hashes.len(), 2);
        assert_eq!(hashes[0]["username"], "svc_sql");
        assert_eq!(hashes[0]["hash_type"], "kerberoast");
        assert_eq!(hashes[0]["domain"], "contoso.local");
        assert!(hashes[0]["hash_value"]
            .as_str()
            .unwrap()
            .starts_with("$krb5tgs$"));
        assert_eq!(hashes[1]["username"], "svc_http");
    }

    #[test]
    fn parse_kerberoast_no_hashes() {
        let hashes = parse_kerberoast("[*] No SPN accounts found", &json!({}));
        assert!(hashes.is_empty());
    }

    #[test]
    fn parses_asrep_roast() {
        let output = "\
$krb5asrep$23$jdoe@CONTOSO.LOCAL:abc123def456
$krb5asrep$23$svc_backup@CONTOSO.LOCAL:789xyz";
        let params = json!({"domain": "contoso.local"});
        let hashes = parse_asrep_roast(output, &params);
        assert_eq!(hashes.len(), 2);
        assert_eq!(hashes[0]["username"], "jdoe");
        assert_eq!(hashes[0]["hash_type"], "asrep");
        assert_eq!(hashes[0]["source"], "asrep_roast");
        assert_eq!(hashes[1]["username"], "svc_backup");
    }

    #[test]
    fn parse_asrep_roast_empty() {
        let hashes = parse_asrep_roast("[-] No AS-REP roastable accounts", &json!({}));
        assert!(hashes.is_empty());
    }
}
