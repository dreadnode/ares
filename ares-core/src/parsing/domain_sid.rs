//! Domain SID extraction.

use regex::Regex;
use std::sync::LazyLock;

static DOMAIN_SID_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"S-1-5-21-\d+-\d+-\d+").expect("domain sid regex"));

/// Match the impacket-lookupsid "Domain SID is:" announcement line — the
/// authoritative signal that the surrounding output is a genuine LSARPC SID
/// brute-force, not arbitrary recon text containing stray SIDs.
pub static LOOKUPSID_HEADER_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?m)^\[\*\]\s+Domain SID is:\s+(S-1-5-21-\d+-\d+-\d+)")
        .expect("lookupsid header regex")
});

/// Match `rpcclient -c lsaquery` output. Produces:
///
/// ```text
/// Domain Name: FABRIKAM
/// Domain Sid: S-1-5-21-3030751166-2423545109-3706592460
/// ```
///
/// Like impacket-lookupsid, this is an authoritative LSARPC response — the
/// flat name and SID together belong to the queried server's primary domain.
/// Often works with anonymous/null sessions where impacket-lookupsid fails,
/// so it's the primary unauth path for cross-forest target SID discovery.
pub static LSAQUERY_DOMAIN_SID_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?m)^Domain Name:\s+(\S+)\s*\r?\nDomain Sid:\s+(S-1-5-21-\d+-\d+-\d+)")
        .expect("lsaquery domain sid regex")
});

/// Regex to extract the RID-500 account name from lookupsid output.
/// Matches lines like: `500: DOMAIN\AccountName (SidTypeUser)`
static RID500_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?m)^500:\s+[^\\]+\\(.+?)\s+\(SidTypeUser\)").expect("rid500 regex")
});

/// Regex matching any RID line in lookupsid output to capture the flat/NetBIOS
/// domain name. Matches lines like: `500: DOMAIN\AccountName (SidType...)`.
static RID_FLAT_NAME_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?m)^\d+:\s+([^\\\s]+)\\.+?\s+\(SidType").expect("rid flat name regex")
});

/// Extract the first *bare* domain SID (`S-1-5-21-A-B-C`) found in the output.
///
/// "Bare" means the matched SID is **not** the prefix of a longer principal
/// SID like `S-1-5-21-A-B-C-RID`. Such longer SIDs appear in LDAP recon
/// output as Foreign Security Principals (e.g. `S-1-5-21-…-519` for a
/// foreign Enterprise Admins group) and previously caused this function to
/// truncate them into a fake "domain SID" that didn't belong to any domain
/// — which then misled the orchestrator into forging tickets with the wrong
/// ExtraSid.
pub fn extract_domain_sid(output: &str) -> Option<String> {
    let bytes = output.as_bytes();
    for m in DOMAIN_SID_RE.find_iter(output) {
        let end = m.end();
        let next = bytes.get(end).copied();
        let after_next = bytes.get(end + 1).copied();
        // Reject when the match is followed by `-<digit>` (truncated longer SID).
        if next == Some(b'-') && matches!(after_next, Some(b) if b.is_ascii_digit()) {
            continue;
        }
        return Some(m.as_str().to_string());
    }
    None
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

/// Extract `(flat_name, sid)` together from lookupsid output, anchoring the
/// SID to the NetBIOS/flat name visible on the same RID lines.
///
/// Returns `None` if either the SID or the flat name is missing — the caller
/// must then resolve the FQDN itself rather than guessing from task context.
///
/// Why this matters: a task targeting `child.contoso.local` can produce output
/// referencing `S-1-5-21-…` for the trusted forest's domain (e.g. via lookupsid
/// over a foreign trust). Anchoring to the flat name lets the caller map the
/// SID to the correct FQDN via `netbios_to_fqdn` instead of misattributing it
/// to the task's source domain.
pub fn extract_domain_sid_and_flat_name(output: &str) -> Option<(String, String)> {
    let sid = extract_domain_sid(output)?;
    let flat = RID_FLAT_NAME_RE
        .captures(output)
        .map(|c| c[1].to_uppercase())?;
    Some((flat, sid))
}

/// Extract `(flat_name, sid)` from `rpcclient lsaquery` output. Returns the
/// queried server's primary-domain flat name (uppercased) paired with the
/// authoritative LSARPC-reported domain SID. Returns `None` if the output is
/// not from `lsaquery` or only one of the two fields is present.
pub fn extract_lsaquery_domain_sid(output: &str) -> Option<(String, String)> {
    let caps = LSAQUERY_DOMAIN_SID_RE.captures(output)?;
    let flat = caps.get(1)?.as_str().to_uppercase();
    let sid = caps.get(2)?.as_str().to_string();
    Some((flat, sid))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_domain_sid() {
        let output = "[*] Domain SID is: S-1-5-21-1328384573-4090356449-2552632942\n[*] Done.\n";
        let sid = extract_domain_sid(output);
        assert_eq!(
            sid,
            Some("S-1-5-21-1328384573-4090356449-2552632942".to_string())
        );
    }

    #[test]
    fn extract_domain_sid_embedded() {
        let output = "some prefix S-1-5-21-111-222-333 suffix\n";
        let sid = extract_domain_sid(output);
        assert_eq!(sid, Some("S-1-5-21-111-222-333".to_string()));
    }

    #[test]
    fn extract_domain_sid_none() {
        assert_eq!(extract_domain_sid("no SID here"), None);
        assert_eq!(extract_domain_sid(""), None);
    }

    #[test]
    fn extract_domain_sid_first_match() {
        let output = "SID1: S-1-5-21-100-200-300\nSID2: S-1-5-21-400-500-600\n";
        let sid = extract_domain_sid(output);
        assert_eq!(sid, Some("S-1-5-21-100-200-300".to_string()));
    }

    #[test]
    fn extract_rid500_name_standard() {
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
    fn extract_rid500_name_renamed() {
        let output = "[*] Domain SID is: S-1-5-21-111-222-333\n\
                       500: CONTOSO\\DomainAdmin01 (SidTypeUser)\n\
                       501: CONTOSO\\Guest (SidTypeUser)\n";
        assert_eq!(
            extract_rid500_name(output),
            Some("DomainAdmin01".to_string())
        );
    }

    #[test]
    fn extract_rid500_name_no_match() {
        assert_eq!(extract_rid500_name("no RID here"), None);
        assert_eq!(extract_rid500_name(""), None);
        // RID 501, not 500
        assert_eq!(
            extract_rid500_name("501: DOMAIN\\Guest (SidTypeUser)"),
            None
        );
    }

    #[test]
    fn extract_rid500_name_wrong_sid_type() {
        // SidTypeGroup should not match — only SidTypeUser
        assert_eq!(
            extract_rid500_name("500: DOMAIN\\DomainAdmins (SidTypeGroup)"),
            None
        );
    }

    #[test]
    fn extracts_flat_name_alongside_sid() {
        let output = "[*] Brute forcing SIDs at 192.168.58.10\n\
                       [*] Domain SID is: S-1-5-21-100-200-300\n\
                       498: CONTOSO\\Enterprise Read-only Domain Controllers (SidTypeGroup)\n\
                       500: CONTOSO\\Administrator (SidTypeUser)\n";
        let result = extract_domain_sid_and_flat_name(output);
        assert_eq!(
            result,
            Some(("CONTOSO".to_string(), "S-1-5-21-100-200-300".to_string()))
        );
    }

    #[test]
    fn extract_flat_name_and_sid_uppercases() {
        let output = "[*] Domain SID is: S-1-5-21-1-2-3\n\
                       500: contoso\\Administrator (SidTypeUser)\n";
        let result = extract_domain_sid_and_flat_name(output);
        assert_eq!(result.as_ref().map(|(f, _)| f.as_str()), Some("CONTOSO"));
    }

    #[test]
    fn extract_flat_name_without_sid_returns_none() {
        let output = "500: CONTOSO\\Administrator (SidTypeUser)\n";
        assert_eq!(extract_domain_sid_and_flat_name(output), None);
    }

    #[test]
    fn extract_flat_name_without_rid_lines_returns_none() {
        let output = "[*] Domain SID is: S-1-5-21-1-2-3\n";
        assert_eq!(extract_domain_sid_and_flat_name(output), None);
    }

    #[test]
    fn extract_domain_sid_skips_truncated_principal_sid() {
        // Foreign-security-principal SID `…-519` (Enterprise Admins) must NOT
        // be silently truncated to a fake domain SID. This was the root cause
        // of op-20260429-164553 forging a ticket with the wrong ExtraSid.
        let output = "objectSid: S-1-5-21-3030751166-2423545109-3706592460-519\n";
        assert_eq!(extract_domain_sid(output), None);
    }

    #[test]
    fn extract_domain_sid_skips_principal_returns_later_bare_sid() {
        let output =
            "fsp: S-1-5-21-100-200-300-519\nDomain SID is: S-1-5-21-916080216-17955212-404331485\n";
        assert_eq!(
            extract_domain_sid(output),
            Some("S-1-5-21-916080216-17955212-404331485".to_string())
        );
    }

    #[test]
    fn extract_domain_sid_accepts_bare_sid_followed_by_dash_letter() {
        // A trailing `-<letter>` (e.g. inside a CN) is fine — only `-<digit>`
        // indicates a truncated longer principal SID.
        let output = "S-1-5-21-100-200-300-foo\n";
        assert_eq!(
            extract_domain_sid(output),
            Some("S-1-5-21-100-200-300".to_string())
        );
    }

    #[test]
    fn extract_domain_sid_accepts_bare_sid_at_end_of_input() {
        let output = "S-1-5-21-100-200-300";
        assert_eq!(
            extract_domain_sid(output),
            Some("S-1-5-21-100-200-300".to_string())
        );
    }

    #[test]
    fn extract_lsaquery_basic() {
        let output = "Domain Name: FABRIKAM\n\
                       Domain Sid: S-1-5-21-3030751166-2423545109-3706592460\n";
        assert_eq!(
            extract_lsaquery_domain_sid(output),
            Some((
                "FABRIKAM".to_string(),
                "S-1-5-21-3030751166-2423545109-3706592460".to_string()
            ))
        );
    }

    #[test]
    fn extract_lsaquery_with_preamble() {
        let output = "[*] Connecting to 192.168.58.58\n\
                       Domain Name: CONTOSO\n\
                       Domain Sid: S-1-5-21-100-200-300\n\
                       [*] Done.\n";
        assert_eq!(
            extract_lsaquery_domain_sid(output),
            Some(("CONTOSO".to_string(), "S-1-5-21-100-200-300".to_string()))
        );
    }

    #[test]
    fn extract_lsaquery_uppercases_flat_name() {
        let output = "Domain Name: contoso\nDomain Sid: S-1-5-21-1-2-3\n";
        assert_eq!(
            extract_lsaquery_domain_sid(output).map(|(f, _)| f),
            Some("CONTOSO".to_string())
        );
    }

    #[test]
    fn extract_lsaquery_handles_crlf() {
        let output = "Domain Name: FABRIKAM\r\nDomain Sid: S-1-5-21-1-2-3\r\n";
        assert_eq!(
            extract_lsaquery_domain_sid(output).map(|(_, s)| s),
            Some("S-1-5-21-1-2-3".to_string())
        );
    }

    #[test]
    fn extract_lsaquery_requires_both_lines() {
        // Missing Domain Sid line
        let no_sid = "Domain Name: FABRIKAM\n";
        assert_eq!(extract_lsaquery_domain_sid(no_sid), None);
        // Missing Domain Name line
        let no_name = "Domain Sid: S-1-5-21-1-2-3\n";
        assert_eq!(extract_lsaquery_domain_sid(no_name), None);
    }

    #[test]
    fn extract_lsaquery_requires_adjacency() {
        // Lines not adjacent — pattern intentionally requires them on
        // consecutive lines so we don't pair the wrong (flat, sid) when
        // multiple servers/responses are concatenated.
        let output = "Domain Name: FABRIKAM\nUnrelated line here\nDomain Sid: S-1-5-21-1-2-3\n";
        assert_eq!(extract_lsaquery_domain_sid(output), None);
    }
}
