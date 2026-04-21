//! Technique requirement rules and vulnerability-to-technique mappings.

use std::collections::HashMap;

/// Determine if a technique should be required for detection.
pub fn is_technique_required(technique_id: &str) -> bool {
    const REQUIRED_PREFIXES: &[&str] = &[
        "T1003", // OS Credential Dumping
        "T1078", // Valid Accounts
        "T1558", // Steal or Forge Kerberos Tickets
        "T1110", // Brute Force
        "T1021", // Remote Services
        "T1550", // Use Alternate Authentication Material
    ];
    REQUIRED_PREFIXES
        .iter()
        .any(|prefix| technique_id.starts_with(prefix))
}

/// Get MITRE techniques associated with a vulnerability type.
pub fn get_techniques_for_vuln_type(vuln_type: &str) -> Vec<String> {
    static VULN_MAP: std::sync::LazyLock<HashMap<&'static str, Vec<&'static str>>> =
        std::sync::LazyLock::new(|| {
            HashMap::from([
                ("ADCS_ESC1", vec!["T1649"]),
                ("ADCS_ESC2", vec!["T1649"]),
                ("ADCS_ESC3", vec!["T1649"]),
                ("ADCS_ESC4", vec!["T1649"]),
                ("ADCS_ESC6", vec!["T1649"]),
                ("ADCS_ESC7", vec!["T1649"]),
                ("ADCS_ESC8", vec!["T1649"]),
                ("UNCONSTRAINED_DELEGATION", vec!["T1558"]),
                ("CONSTRAINED_DELEGATION", vec!["T1558"]),
                ("RESOURCE_BASED_CONSTRAINED_DELEGATION", vec!["T1558"]),
                ("ACL_ABUSE", vec!["T1222", "T1484"]),
                ("DACL_ABUSE", vec!["T1222", "T1484"]),
                ("WRITEDACL", vec!["T1222"]),
                ("GENERICALL", vec!["T1222", "T1098"]),
                ("GENERICWRITE", vec!["T1222", "T1098"]),
                ("WRITEOWNER", vec!["T1222"]),
                ("KERBEROASTING", vec!["T1558.003"]),
                ("ASREPROASTING", vec!["T1558.004"]),
                ("GPO_ABUSE", vec!["T1484.001"]),
                ("DCSYNC", vec!["T1003.006"]),
                ("PASSWORD_SPRAY", vec!["T1110.003"]),
                ("CREDENTIAL_STUFFING", vec!["T1110.004"]),
            ])
        });

    let key = vuln_type.to_uppercase();
    VULN_MAP
        .get(key.as_str())
        .map(|v| v.iter().map(|s| s.to_string()).collect())
        .unwrap_or_else(|| vec!["T1068".to_string()])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_technique_required_credential_dumping() {
        assert!(is_technique_required("T1003"));
        assert!(is_technique_required("T1003.001"));
        assert!(is_technique_required("T1003.006"));
    }

    #[test]
    fn is_technique_required_valid_accounts() {
        assert!(is_technique_required("T1078"));
        assert!(is_technique_required("T1078.002"));
    }

    #[test]
    fn is_technique_required_kerberos() {
        assert!(is_technique_required("T1558"));
        assert!(is_technique_required("T1558.003"));
    }

    #[test]
    fn is_technique_required_brute_force() {
        assert!(is_technique_required("T1110"));
    }

    #[test]
    fn is_technique_required_remote_services() {
        assert!(is_technique_required("T1021"));
    }

    #[test]
    fn is_technique_required_alternate_auth() {
        assert!(is_technique_required("T1550"));
    }

    #[test]
    fn is_technique_not_required_unknown() {
        assert!(!is_technique_required("T1046"));
        assert!(!is_technique_required("T9999"));
        assert!(!is_technique_required(""));
    }

    #[test]
    fn get_techniques_adcs_esc1() {
        let techs = get_techniques_for_vuln_type("ADCS_ESC1");
        assert_eq!(techs, vec!["T1649"]);
    }

    #[test]
    fn get_techniques_case_insensitive() {
        let techs = get_techniques_for_vuln_type("adcs_esc1");
        assert_eq!(techs, vec!["T1649"]);
    }

    #[test]
    fn get_techniques_kerberoasting() {
        let techs = get_techniques_for_vuln_type("KERBEROASTING");
        assert_eq!(techs, vec!["T1558.003"]);
    }

    #[test]
    fn get_techniques_acl_abuse_multiple() {
        let techs = get_techniques_for_vuln_type("ACL_ABUSE");
        assert_eq!(techs, vec!["T1222", "T1484"]);
    }

    #[test]
    fn get_techniques_unknown_returns_default() {
        let techs = get_techniques_for_vuln_type("UNKNOWN_VULN");
        assert_eq!(techs, vec!["T1068"]);
    }

    #[test]
    fn get_techniques_dcsync() {
        let techs = get_techniques_for_vuln_type("DCSYNC");
        assert_eq!(techs, vec!["T1003.006"]);
    }
}
