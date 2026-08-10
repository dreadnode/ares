//! Kerberos hash extraction (TGS / AS-REP).

use regex::Regex;
use std::sync::LazyLock;

use super::types::{KerberosHash, KerberosHashType};

// The `*` after the etype is optional: impacket emits it only for RC4 tickets
// (`$krb5tgs$23$*user$realm$spn*$…`). AES tickets (etype 17/18, the AES-capable
// account default) omit it (`$krb5tgs$17$user$realm$spn*$…`). Requiring it drops
// every AES kerberoast hash, so those accounts never reach the cracker.
static KRB_TGS_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\$krb5tgs\$\d+\$\*?([^$*]+)\$([^$*]+)\$[^$]+\$[a-fA-F0-9$]+")
        .expect("krb5tgs regex")
});

static KRB_ASREP_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\$krb5asrep\$\d+\$([^@:]+)@([^:]+):[a-fA-F0-9$]+").expect("krb5asrep regex")
});

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_tgs_valid_line() {
        let output = "$krb5tgs$23$*svc_sql$CONTOSO.LOCAL$cifs/dc01.contoso.local@CONTOSO.LOCAL$abc123def456\n";
        let results = extract_kerberos_hashes(output);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].username, "svc_sql");
        assert_eq!(results[0].domain, "CONTOSO.LOCAL");
        assert_eq!(results[0].hash_type, KerberosHashType::TGS);
        assert!(results[0].hash_value.starts_with("$krb5tgs$"));
    }

    #[test]
    fn extract_tgs_aes_etype() {
        // AES128 (etype 17) kerberoast hash from impacket. Real layout: no `*`
        // before the user, `$*spn*$` around the SPN (format `$krb5tgs$%d$%s$%s$*%s*$…`).
        // Regression guard: these must be extracted, not silently dropped.
        let output =
            "$krb5tgs$17$svc_sql$CONTOSO.LOCAL$*MSSQLSvc/db01.contoso.local*$aabbccdd$eeff0011\n";
        let results = extract_kerberos_hashes(output);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].username, "svc_sql");
        assert_eq!(results[0].domain, "CONTOSO.LOCAL");
        assert_eq!(results[0].hash_type, KerberosHashType::TGS);
    }

    #[test]
    fn extract_tgs_multiple() {
        let output = "$krb5tgs$23$*svc_a$DOM.LOCAL$http/web@DOM.LOCAL$aabb1122\n\
                       $krb5tgs$23$*svc_b$DOM.LOCAL$cifs/fs@DOM.LOCAL$ccdd3344\n";
        let results = extract_kerberos_hashes(output);
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].username, "svc_a");
        assert_eq!(results[1].username, "svc_b");
    }

    #[test]
    fn extract_tgs_empty_input() {
        assert!(extract_kerberos_hashes("").is_empty());
    }

    #[test]
    fn extract_tgs_no_match() {
        let output = "some random output\nno hashes here\n";
        assert!(extract_kerberos_hashes(output).is_empty());
    }

    #[test]
    fn extract_asrep_valid() {
        let output = "$krb5asrep$23$user1@CONTOSO.LOCAL:abcdef0123456789\n";
        let results = extract_kerberos_hashes(output);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].username, "user1");
        assert_eq!(results[0].domain, "CONTOSO.LOCAL");
        assert_eq!(results[0].hash_type, KerberosHashType::AsRep);
        assert_eq!(results[0].hash_value, output.trim());
    }

    #[test]
    fn extract_mixed_tgs_and_asrep() {
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
    fn extract_tgs_hash_value_preserved() {
        let line =
            "$krb5tgs$23$*svc_sql$CONTOSO.LOCAL$cifs/dc01.contoso.local@CONTOSO.LOCAL$abc123def456";
        let output = format!("{}\n", line);
        let results = extract_kerberos_hashes(&output);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].hash_value, line);
    }

    #[test]
    fn extract_asrep_domain_parsed() {
        let output = "$krb5asrep$23$jdoe@CONTOSO.LOCAL:aabbccdd11223344\n";
        let results = extract_kerberos_hashes(output);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].username, "jdoe");
        assert_eq!(results[0].domain, "CONTOSO.LOCAL");
    }

    #[test]
    fn extract_kerberos_whitespace_lines_skipped() {
        let output = "  \n\n  \n$krb5tgs$23$*svc_a$DOM.LOCAL$http/web@DOM.LOCAL$aabb\n  \n";
        let results = extract_kerberos_hashes(output);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].username, "svc_a");
    }

    #[test]
    fn extract_kerberos_status_lines_ignored() {
        let output = "[*] Getting TGT for user\n[*] Requesting service ticket\nno hashes\n";
        assert!(extract_kerberos_hashes(output).is_empty());
    }
}
