//! Parser for `enumerate_domain_trusts` (ldapsearch trustedDomain) output.

use serde_json::{json, Value};

/// LDAP trustDirection values (MS-ADTS 6.1.6.7.9).
const TRUST_DIRECTION_INBOUND: u32 = 1;
const TRUST_DIRECTION_OUTBOUND: u32 = 2;
const TRUST_DIRECTION_BIDIRECTIONAL: u32 = 3;

/// LDAP trustType values (MS-ADTS 6.1.6.7.10).
const TRUST_TYPE_PARENT_CHILD: u32 = 1; // same forest
const TRUST_TYPE_TREE_ROOT: u32 = 2; // tree root (also intra-forest)

/// LDAP trustAttributes (MS-ADTS 6.1.6.7.9) flag for forest transitive trust.
const TRUST_ATTR_FOREST_TRANSITIVE: u32 = 0x00000008;

/// Parse `enumerate_domain_trusts` ldapsearch output into TrustInfo-compatible JSON values.
///
/// Returns JSON objects matching the `TrustInfo` schema:
/// `{ "domain", "flat_name", "direction", "trust_type", "sid_filtering" }`
pub fn parse_domain_trusts(output: &str) -> Vec<Value> {
    let mut results = Vec::new();

    let mut cn = String::new();
    let mut trust_direction: u32 = 0;
    let mut trust_type: u32 = 0;
    let mut trust_attributes: u32 = 0;
    let mut flat_name = String::new();

    let flush = |cn: &str,
                 trust_direction: u32,
                 trust_type: u32,
                 trust_attributes: u32,
                 flat_name: &str|
     -> Option<Value> {
        if cn.is_empty() {
            return None;
        }

        let direction = match trust_direction {
            TRUST_DIRECTION_INBOUND => "inbound",
            TRUST_DIRECTION_OUTBOUND => "outbound",
            TRUST_DIRECTION_BIDIRECTIONAL => "bidirectional",
            _ => "unknown",
        };

        let classified_type = classify_trust_type(trust_type, trust_attributes, cn);

        let sid_filtering =
            trust_attributes & TRUST_ATTR_FOREST_TRANSITIVE != 0 || classified_type == "forest";

        Some(json!({
            "domain": cn.to_lowercase(),
            "flat_name": flat_name,
            "direction": direction,
            "trust_type": classified_type,
            "sid_filtering": sid_filtering,
        }))
    };

    for line in output.lines() {
        let line = line.trim();

        if line.is_empty() || line.starts_with('#') {
            if let Some(trust) = flush(
                &cn,
                trust_direction,
                trust_type,
                trust_attributes,
                &flat_name,
            ) {
                results.push(trust);
            }
            cn.clear();
            trust_direction = 0;
            trust_type = 0;
            trust_attributes = 0;
            flat_name.clear();
            continue;
        }

        if line.starts_with("dn:") || line.starts_with("objectClass:") {
            continue;
        }

        if let Some(val) = line.strip_prefix("cn: ") {
            cn = val.trim().to_string();
        } else if let Some(val) = line.strip_prefix("trustDirection: ") {
            trust_direction = val.trim().parse().unwrap_or(0);
        } else if let Some(val) = line.strip_prefix("trustType: ") {
            trust_type = val.trim().parse().unwrap_or(0);
        } else if let Some(val) = line.strip_prefix("trustAttributes: ") {
            trust_attributes = val.trim().parse().unwrap_or(0);
        } else if let Some(val) = line.strip_prefix("flatName: ") {
            flat_name = val.trim().to_string();
        }
    }

    // Flush last block
    if let Some(trust) = flush(
        &cn,
        trust_direction,
        trust_type,
        trust_attributes,
        &flat_name,
    ) {
        results.push(trust);
    }

    results
}

/// Classify trust type from LDAP trustType and trustAttributes values.
fn classify_trust_type(trust_type: u32, trust_attributes: u32, cn: &str) -> String {
    // Forest transitive flag → cross-forest trust
    if trust_attributes & TRUST_ATTR_FOREST_TRANSITIVE != 0 {
        return "forest".to_string();
    }

    match trust_type {
        TRUST_TYPE_PARENT_CHILD => "parent_child".to_string(),
        TRUST_TYPE_TREE_ROOT => {
            let parts: Vec<&str> = cn.split('.').collect();
            if parts.len() >= 3 {
                "parent_child".to_string()
            } else {
                "forest".to_string()
            }
        }
        _ => "external".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_cross_forest_trust() {
        let output = r#"dn: CN=fabrikam.local,CN=System,DC=contoso,DC=local
cn: fabrikam.local
trustDirection: 3
trustType: 2
trustAttributes: 8
flatName: FABRIKAM
"#;
        let trusts = parse_domain_trusts(output);
        assert_eq!(trusts.len(), 1);
        assert_eq!(trusts[0]["domain"], "fabrikam.local");
        assert_eq!(trusts[0]["flat_name"], "FABRIKAM");
        assert_eq!(trusts[0]["direction"], "bidirectional");
        assert_eq!(trusts[0]["trust_type"], "forest");
        assert!(trusts[0]["sid_filtering"].as_bool().unwrap());
    }

    #[test]
    fn test_parse_parent_child_trust() {
        let output = r#"dn: CN=north.contoso.local,CN=System,DC=contoso,DC=local
cn: north.contoso.local
trustDirection: 3
trustType: 1
trustAttributes: 0
flatName: CHILD
"#;
        let trusts = parse_domain_trusts(output);
        assert_eq!(trusts.len(), 1);
        assert_eq!(trusts[0]["domain"], "north.contoso.local");
        assert_eq!(trusts[0]["trust_type"], "parent_child");
        assert!(!trusts[0]["sid_filtering"].as_bool().unwrap());
    }

    #[test]
    fn test_parse_multiple_trusts() {
        let output = r#"dn: CN=fabrikam.local,CN=System,DC=contoso,DC=local
cn: fabrikam.local
trustDirection: 3
trustType: 2
trustAttributes: 8
flatName: FABRIKAM

dn: CN=north.contoso.local,CN=System,DC=contoso,DC=local
cn: north.contoso.local
trustDirection: 3
trustType: 1
trustAttributes: 0
flatName: CHILD
"#;
        let trusts = parse_domain_trusts(output);
        assert_eq!(trusts.len(), 2);
        assert_eq!(trusts[0]["trust_type"], "forest");
        assert_eq!(trusts[1]["trust_type"], "parent_child");
    }

    #[test]
    fn test_parse_inbound_trust() {
        let output =
            "cn: partner.com\ntrustDirection: 1\ntrustType: 3\ntrustAttributes: 0\nflatName: PARTNER\n";
        let trusts = parse_domain_trusts(output);
        assert_eq!(trusts.len(), 1);
        assert_eq!(trusts[0]["direction"], "inbound");
        assert_eq!(trusts[0]["trust_type"], "external");
    }

    #[test]
    fn test_parse_empty_output() {
        let trusts = parse_domain_trusts("");
        assert!(trusts.is_empty());
    }

    #[test]
    fn test_parse_no_trusts_search_result() {
        let output = "# search result\nsearch: 2\nresult: 0 Success\n";
        let trusts = parse_domain_trusts(output);
        assert!(trusts.is_empty());
    }
}
