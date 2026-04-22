//! Certipy (ADCS) output parser.

use serde_json::{json, Value};

/// All ESC types that certipy can detect.
const ESC_TYPES: &[&str] = &[
    "esc1", "esc2", "esc3", "esc4", "esc5", "esc6", "esc7", "esc8", "esc9", "esc10", "esc11",
    "esc13", "esc14", "esc15",
];

pub fn parse_certipy_find(output: &str, params: &Value) -> Vec<Value> {
    let target_ip = params
        .get("target")
        .or_else(|| params.get("target_ip"))
        .and_then(|v| v.as_str())
        .unwrap_or("");

    let domain = params.get("domain").and_then(|v| v.as_str()).unwrap_or("");

    // Extract CA name from output if present (e.g. "CA Name: ESSOS-CA")
    let ca_name = extract_ca_name(output);

    let mut vulns = Vec::new();
    let output_lower = output.to_lowercase();

    // Strategy 1: Look for "[!] Vulnerabilities" section (certipy text output)
    let has_vuln_header = output_lower.contains("[!] vulnerabilities");

    // Strategy 2: Look for "ESCn :" patterns (certipy find -vulnerable output)
    // These appear as "ESC1 : 'DOMAIN\\Group' can enroll..."
    for esc_type in ESC_TYPES {
        let found = if has_vuln_header {
            // Standard certipy output with vulnerability section
            output_lower.contains(esc_type)
        } else {
            // Also detect ESC patterns without the header — certipy sometimes
            // outputs vulnerability info inline with template details.
            // Look for "ESCn" followed by ":" or "vulnerability" on the same or
            // nearby lines.
            let esc_upper = esc_type.to_uppercase();
            output.contains(&format!("{esc_upper} :"))
                || output.contains(&format!("{esc_upper}:"))
                || (output_lower.contains(esc_type) && output_lower.contains("vulnerab"))
        };

        if found {
            // Extract template name if available (e.g., "Template Name : ESC1")
            let template_name = extract_template_for_esc(output, esc_type);

            let mut details = json!({
                "esc_type": esc_type,
            });
            if !domain.is_empty() {
                details["domain"] = json!(domain);
            }
            if let Some(ref ca) = ca_name {
                details["ca_name"] = json!(ca);
            }
            if let Some(ref tmpl) = template_name {
                details["template_name"] = json!(tmpl);
            }

            vulns.push(json!({
                "vuln_id": format!("adcs_{}_{}", esc_type, target_ip),
                "vuln_type": format!("adcs_{}", esc_type),
                "target": target_ip,
                "discovered_by": "certipy_find",
                "details": details,
                "recommended_agent": "privesc",
                "priority": esc_priority(esc_type),
            }));
        }
    }

    vulns
}

/// Extract CA name from certipy output.
fn extract_ca_name(output: &str) -> Option<String> {
    for line in output.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("CA Name") {
            let name = rest.trim_start_matches(|c: char| c == ':' || c.is_whitespace());
            if !name.is_empty() {
                return Some(name.to_string());
            }
        }
    }
    None
}

/// Extract template name associated with an ESC type.
fn extract_template_for_esc(output: &str, esc_type: &str) -> Option<String> {
    let esc_upper = esc_type.to_uppercase();
    let lines: Vec<&str> = output.lines().collect();
    for (i, line) in lines.iter().enumerate() {
        if line.contains(&esc_upper) {
            // Look backwards for "Template Name" line
            for j in (0..i).rev() {
                let prev = lines[j].trim();
                if let Some(rest) = prev.strip_prefix("Template Name") {
                    let name = rest.trim_start_matches(|c: char| c == ':' || c.is_whitespace());
                    if !name.is_empty() {
                        return Some(name.to_string());
                    }
                }
                // Don't look back more than 20 lines
                if i - j > 20 {
                    break;
                }
            }
        }
    }
    None
}

/// Priority for ESC types (lower = more urgent).
fn esc_priority(esc_type: &str) -> i32 {
    match esc_type {
        "esc1" | "esc6" => 1, // Direct enrollment → DA cert
        "esc4" | "esc8" => 2, // Template abuse / relay
        "esc2" | "esc3" => 3, // Certificate agent
        "esc7" | "esc9" => 4, // ManageCA / UPN spoof
        "esc5" => 5,          // Golden cert (requires CA compromise first)
        _ => 6,               // ESC10-15 and unknown
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parse_certipy_esc1() {
        let output = "[!] Vulnerabilities\nESC1: Template allows enrollment with low-priv";
        let params = json!({"target": "192.168.58.10", "domain": "contoso.local"});
        let vulns = parse_certipy_find(output, &params);
        assert_eq!(vulns.len(), 1);
        assert_eq!(vulns[0]["vuln_type"], "adcs_esc1");
        assert_eq!(vulns[0]["target"], "192.168.58.10");
        assert_eq!(vulns[0]["details"]["domain"], "contoso.local");
    }

    #[test]
    fn parse_certipy_multiple_esc_types() {
        let output =
            "[!] Vulnerabilities\nESC1: ...\nESC4: Template is misconfigured\nESC8: Web enrollment";
        let params = json!({"target_ip": "192.168.58.10"});
        let vulns = parse_certipy_find(output, &params);
        assert_eq!(vulns.len(), 3);
        let types: Vec<&str> = vulns
            .iter()
            .map(|v| v["vuln_type"].as_str().unwrap())
            .collect();
        assert!(types.contains(&"adcs_esc1"));
        assert!(types.contains(&"adcs_esc4"));
        assert!(types.contains(&"adcs_esc8"));
    }

    #[test]
    fn parse_certipy_no_vulnerabilities_keyword() {
        // Without [!] Vulnerabilities header, only "ESCn :" pattern matches
        let output = "ESC1 : Template allows enrollment";
        let vulns = parse_certipy_find(output, &json!({"target": "192.168.58.10"}));
        assert_eq!(vulns.len(), 1);
    }

    #[test]
    fn parse_certipy_no_esc_types() {
        let output = "[!] Vulnerabilities\nNo vulnerable templates found";
        let vulns = parse_certipy_find(output, &json!({"target": "192.168.58.10"}));
        assert!(vulns.is_empty());
    }

    #[test]
    fn parse_certipy_empty_output() {
        let vulns = parse_certipy_find("", &json!({}));
        assert!(vulns.is_empty());
    }

    #[test]
    fn parse_certipy_vuln_id_format() {
        let output = "[!] Vulnerabilities\nESC4: misconfigured template";
        let params = json!({"target": "192.168.58.20"});
        let vulns = parse_certipy_find(output, &params);
        assert_eq!(vulns[0]["vuln_id"], "adcs_esc4_192.168.58.20");
    }

    #[test]
    fn parse_certipy_extended_esc_types() {
        let output = "[!] Vulnerabilities\nESC1: ...\nESC6: EDITF flag\nESC9: UPN spoof\nESC13: issuance policy";
        let params = json!({"target_ip": "192.168.58.10"});
        let vulns = parse_certipy_find(output, &params);
        assert_eq!(vulns.len(), 4);
        let types: Vec<&str> = vulns
            .iter()
            .map(|v| v["vuln_type"].as_str().unwrap())
            .collect();
        assert!(types.contains(&"adcs_esc6"));
        assert!(types.contains(&"adcs_esc9"));
        assert!(types.contains(&"adcs_esc13"));
    }

    #[test]
    fn parse_certipy_with_ca_name() {
        let output = "CA Name                             : ESSOS-CA\n[!] Vulnerabilities\nESC1: enrollee supplies subject";
        let params = json!({"target": "192.168.58.10", "domain": "fabrikam.local"});
        let vulns = parse_certipy_find(output, &params);
        assert_eq!(vulns.len(), 1);
        assert_eq!(vulns[0]["details"]["ca_name"], "ESSOS-CA");
        assert_eq!(vulns[0]["details"]["domain"], "fabrikam.local");
    }

    #[test]
    fn parse_certipy_inline_pattern() {
        // certipy find -vulnerable output format
        let output =
            "  ESC1 : 'FABRIKAM.LOCAL\\Domain Users' can enroll, enrollee supplies subject";
        let params = json!({"target": "192.168.58.10"});
        let vulns = parse_certipy_find(output, &params);
        assert_eq!(vulns.len(), 1);
        assert_eq!(vulns[0]["vuln_type"], "adcs_esc1");
    }

    #[test]
    fn esc_priority_ordering() {
        assert!(esc_priority("esc1") < esc_priority("esc4"));
        assert!(esc_priority("esc4") < esc_priority("esc5"));
    }

    #[test]
    fn esc_priority_all_values() {
        assert_eq!(esc_priority("esc1"), 1);
        assert_eq!(esc_priority("esc6"), 1);
        assert_eq!(esc_priority("esc4"), 2);
        assert_eq!(esc_priority("esc8"), 2);
        assert_eq!(esc_priority("esc2"), 3);
        assert_eq!(esc_priority("esc3"), 3);
        assert_eq!(esc_priority("esc7"), 4);
        assert_eq!(esc_priority("esc9"), 4);
        assert_eq!(esc_priority("esc5"), 5);
        assert_eq!(esc_priority("esc10"), 6);
        assert_eq!(esc_priority("esc11"), 6);
        assert_eq!(esc_priority("esc13"), 6);
        assert_eq!(esc_priority("unknown"), 6);
    }

    #[test]
    fn extract_ca_name_standard() {
        let output =
            "CA Name                             : CONTOSO-CA\nDNS Name  : ca01.contoso.local";
        assert_eq!(extract_ca_name(output), Some("CONTOSO-CA".to_string()));
    }

    #[test]
    fn extract_ca_name_no_spaces() {
        let output = "CA Name:MYCA\nother line";
        assert_eq!(extract_ca_name(output), Some("MYCA".to_string()));
    }

    #[test]
    fn extract_ca_name_missing() {
        assert_eq!(extract_ca_name("No CA info here"), None);
        assert_eq!(extract_ca_name(""), None);
    }

    #[test]
    fn extract_ca_name_empty_value() {
        assert_eq!(extract_ca_name("CA Name : "), None);
    }

    #[test]
    fn extract_template_for_esc_basic() {
        let output = "Template Name                       : VulnTemplate\n    Permissions\n      ESC1 : 'DOMAIN\\Users' can enroll";
        assert_eq!(
            extract_template_for_esc(output, "esc1"),
            Some("VulnTemplate".to_string())
        );
    }

    #[test]
    fn extract_template_for_esc_not_found() {
        let output = "ESC1 : 'DOMAIN\\Users' can enroll";
        assert_eq!(extract_template_for_esc(output, "esc1"), None);
    }

    #[test]
    fn extract_template_for_esc_multiple_templates() {
        let output = "Template Name : Template1\n    ESC4 : misconfigured\nTemplate Name : Template2\n    ESC1 : enrollable";
        // ESC4 should get Template1
        assert_eq!(
            extract_template_for_esc(output, "esc4"),
            Some("Template1".to_string())
        );
        // ESC1 should get Template2
        assert_eq!(
            extract_template_for_esc(output, "esc1"),
            Some("Template2".to_string())
        );
    }

    #[test]
    fn esc_types_constant() {
        assert_eq!(ESC_TYPES.len(), 14);
        assert!(ESC_TYPES.contains(&"esc1"));
        assert!(ESC_TYPES.contains(&"esc8"));
        assert!(ESC_TYPES.contains(&"esc13"));
        assert!(ESC_TYPES.contains(&"esc15"));
        assert!(!ESC_TYPES.contains(&"esc12"));
        assert!(!ESC_TYPES.contains(&"esc16"));
    }

    #[test]
    fn parse_certipy_with_template_name() {
        let output = "Template Name                       : ESC1-Vuln\n    [!] Vulnerabilities\n    ESC1 : 'CONTOSO\\Users' can enroll";
        let params = json!({"target": "192.168.58.10", "domain": "contoso.local"});
        let vulns = parse_certipy_find(output, &params);
        assert_eq!(vulns.len(), 1);
        assert_eq!(vulns[0]["details"]["template_name"], "ESC1-Vuln");
    }

    #[test]
    fn parse_certipy_vulnerability_inline_keyword() {
        // "vulnerab" keyword present alongside ESC type but no [!] Vulnerabilities header
        let output = "Certificate template is vulnerable to ESC1 attack";
        let params = json!({"target": "192.168.58.10"});
        let vulns = parse_certipy_find(output, &params);
        assert_eq!(vulns.len(), 1);
    }

    #[test]
    fn parse_certipy_colon_format() {
        // "ESC8:" format without spaces
        let output = "ESC8:web enrollment enabled";
        let params = json!({"target": "192.168.58.10"});
        let vulns = parse_certipy_find(output, &params);
        assert_eq!(vulns.len(), 1);
        assert_eq!(vulns[0]["vuln_type"], "adcs_esc8");
    }
}
