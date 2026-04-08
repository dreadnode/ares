//! Domain SID extraction.

use once_cell::sync::Lazy;
use regex::Regex;

static DOMAIN_SID_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"S-1-5-21-\d+-\d+-\d+").expect("domain sid regex"));

/// Extract the first domain SID (`S-1-5-21-...`) found in the output.
pub fn extract_domain_sid(output: &str) -> Option<String> {
    DOMAIN_SID_RE.find(output).map(|m| m.as_str().to_string())
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
}
