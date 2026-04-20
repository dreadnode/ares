//! Secretsdump, Kerberoast, and AS-REP roast output parsers.

use serde_json::{json, Value};

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

    for line in output.lines() {
        let line = line.trim();

        // NTLM hash format: "username:RID:LMhash:NThash:::"
        // or "DOMAIN\username:RID:LMhash:NThash:::"
        if line.contains(":::") && !line.starts_with('[') && !line.starts_with('#') {
            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() >= 4 {
                let raw_user = parts[0];
                let (user_domain, username) = if raw_user.contains('\\') {
                    let split: Vec<&str> = raw_user.splitn(2, '\\').collect();
                    let netbios = split[0];
                    // Resolve NetBIOS domain prefix to FQDN using target_domain.
                    // e.g. "CONTOSO" → "contoso.local" when target_domain="contoso.local"
                    let resolved = resolve_netbios_to_fqdn(netbios, domain);
                    (resolved, split[1].to_string())
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
    fn test_parse_secretsdump_ntlm_hashes() {
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
        assert_eq!(hashes[0]["domain"], "contoso.local");
        assert_eq!(hashes[0]["hash_type"], "ntlm");
        assert!(hashes[0]["hash_value"]
            .as_str()
            .unwrap()
            .contains("e19ccf75"));
        assert_eq!(hashes[1]["username"], "svc_sql");
        assert!(creds.is_empty());
    }

    #[test]
    fn test_parse_secretsdump_domain_prefix() {
        let output = "CONTOSO\\Administrator:500:aad3b435b51404eeaad3b435b51404ee:e19ccf75ee54e06b06a5907af13cef42:::";
        let params = json!({"domain": "contoso.local"});
        let (hashes, _) = parse_secretsdump(output, &params);
        assert_eq!(hashes.len(), 1);
        assert_eq!(hashes[0]["username"], "Administrator");
        // NetBIOS "CONTOSO" resolved to FQDN "contoso.local" via target_domain
        assert_eq!(hashes[0]["domain"], "contoso.local");
    }

    #[test]
    fn test_parse_secretsdump_netbios_resolved_to_fqdn() {
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
    fn test_parse_secretsdump_target_domain_preferred() {
        // target_domain should take precedence over domain for attribution
        let output = "FABRIKAM\\svc_sql:1105:aad3b435b51404eeaad3b435b51404ee:abcdef1234567890abcdef1234567890:::";
        let params = json!({"domain": "contoso.local", "target_domain": "fabrikam.local"});
        let (hashes, _) = parse_secretsdump(output, &params);
        assert_eq!(hashes.len(), 1);
        assert_eq!(hashes[0]["domain"], "fabrikam.local");
    }

    #[test]
    fn test_parse_secretsdump_mismatched_netbios_kept() {
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
    fn test_resolve_netbios_to_fqdn() {
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
    fn test_parse_secretsdump_skips_comments_and_brackets() {
        let output = "\
[*] Service RemoteRegistry is in stopped state
# This is a comment
[*] SAM hashes extracted";
        let params = json!({"domain": "contoso.local"});
        let (hashes, _) = parse_secretsdump(output, &params);
        assert!(hashes.is_empty());
    }

    #[test]
    fn test_parse_secretsdump_empty_output() {
        let (hashes, creds) = parse_secretsdump("", &json!({}));
        assert!(hashes.is_empty());
        assert!(creds.is_empty());
    }

    #[test]
    fn test_parse_kerberoast_hashes() {
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
    fn test_parse_kerberoast_no_hashes() {
        let hashes = parse_kerberoast("[*] No SPN accounts found", &json!({}));
        assert!(hashes.is_empty());
    }

    #[test]
    fn test_parse_asrep_roast() {
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
    fn test_parse_asrep_roast_empty() {
        let hashes = parse_asrep_roast("[-] No AS-REP roastable accounts", &json!({}));
        assert!(hashes.is_empty());
    }
}
