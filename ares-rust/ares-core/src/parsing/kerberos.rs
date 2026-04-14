//! Kerberos hash extraction (TGS / AS-REP).

use regex::Regex;
use std::sync::LazyLock;

use super::types::{KerberosHash, KerberosHashType};

static KRB_TGS_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\$krb5tgs\$\d+\$\*([^$*]+)\$([^$*]+)\$[^$]+\$[a-fA-F0-9$]+")
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

    #[test]
    fn test_kerberos_tgs_full_hash() {
        let output = "$krb5tgs$23$*svc_sql$CONTOSO.LOCAL$cifs/dc01.contoso.local@CONTOSO.LOCAL$abcdef1234567890abcdef1234567890abcdef1234567890\n";
        let hashes = extract_kerberos_hashes(output);
        assert_eq!(hashes.len(), 1);
        assert_eq!(hashes[0].username, "svc_sql");
        assert_eq!(hashes[0].domain, "CONTOSO.LOCAL");
    }
}
