//! Domain SID extraction.

use regex::Regex;
use std::sync::LazyLock;

static DOMAIN_SID_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"S-1-5-21-\d+-\d+-\d+").expect("domain sid regex"));

/// Regex to extract the RID-500 account name from lookupsid output.
/// Matches lines like: `500: DOMAIN\AccountName (SidTypeUser)`
static RID500_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?m)^500:\s+[^\\]+\\(.+?)\s+\(SidTypeUser\)").expect("rid500 regex")
});

/// Extract the first domain SID (`S-1-5-21-...`) found in the output.
pub fn extract_domain_sid(output: &str) -> Option<String> {
    DOMAIN_SID_RE.find(output).map(|m| m.as_str().to_string())
}

/// Extract the account name for RID 500 from lookupsid output.
///
/// The built-in Administrator account can be renamed via Group Policy.
/// Post-KB5008380 (October 2022), golden tickets must use the real account
/// name — the KDC validates the `cname` against `PAC_REQUESTOR` and rejects
/// tickets with a mismatched username (`KDC_ERR_TGT_REVOKED`).
pub fn extract_rid500_name(output: &str) -> Option<String> {
    RID500_RE.captures(output).map(|c| c[1].to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

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

    // --- extract_rid500_name ---

    #[test]
    fn test_extract_rid500_name_standard() {
        let output = "[*] Domain SID is: S-1-5-21-1328384573-4090356449-2552632942\n\
                       500: CONTOSO\\Administrator (SidTypeUser)\n\
                       501: CONTOSO\\Guest (SidTypeUser)\n\
                       502: CONTOSO\\krbtgt (SidTypeUser)\n";
        assert_eq!(
            extract_rid500_name(output),
            Some("Administrator".to_string())
        );
    }

    #[test]
    fn test_extract_rid500_name_renamed() {
        let output = "[*] Domain SID is: S-1-5-21-111-222-333\n\
                       500: CONTOSO\\DomainAdmin01 (SidTypeUser)\n\
                       501: CONTOSO\\Guest (SidTypeUser)\n";
        assert_eq!(
            extract_rid500_name(output),
            Some("DomainAdmin01".to_string())
        );
    }

    #[test]
    fn test_extract_rid500_name_no_match() {
        assert_eq!(extract_rid500_name("no RID here"), None);
        assert_eq!(extract_rid500_name(""), None);
        // RID 501, not 500
        assert_eq!(
            extract_rid500_name("501: DOMAIN\\Guest (SidTypeUser)"),
            None
        );
    }

    #[test]
    fn test_extract_rid500_name_wrong_sid_type() {
        // SidTypeGroup should not match — only SidTypeUser
        assert_eq!(
            extract_rid500_name("500: DOMAIN\\DomainAdmins (SidTypeGroup)"),
            None
        );
    }
}
