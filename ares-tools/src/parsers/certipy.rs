//! Certipy (ADCS) output parser.

use serde_json::{json, Value};

pub fn parse_certipy_find(output: &str, params: &Value) -> Vec<Value> {
    let target_ip = params
        .get("target")
        .or_else(|| params.get("target_ip"))
        .and_then(|v| v.as_str())
        .unwrap_or("");

    let mut vulns = Vec::new();

    let output_lower = output.to_lowercase();

    for esc_type in &["esc1", "esc4", "esc8"] {
        if output_lower.contains("[!] vulnerabilities") && output_lower.contains(esc_type) {
            vulns.push(json!({
                "vuln_id": format!("adcs_{}_{}", esc_type, target_ip),
                "vuln_type": format!("adcs_{}", esc_type),
                "target": target_ip,
                "discovered_by": "certipy_find",
                "details": {
                    "esc_type": esc_type,
                },
                "recommended_agent": "privesc",
            }));
        }
    }

    vulns
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_parse_certipy_esc1() {
        let output = "[!] Vulnerabilities\nESC1: Template allows enrollment with low-priv";
        let params = json!({"target": "192.168.58.10"});
        let vulns = parse_certipy_find(output, &params);
        assert_eq!(vulns.len(), 1);
        assert_eq!(vulns[0]["vuln_type"], "adcs_esc1");
        assert_eq!(vulns[0]["target"], "192.168.58.10");
    }

    #[test]
    fn test_parse_certipy_multiple_esc_types() {
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
    fn test_parse_certipy_no_vulnerabilities_keyword() {
        let output = "ESC1: Template allows enrollment";
        let vulns = parse_certipy_find(output, &json!({"target": "192.168.58.10"}));
        assert!(vulns.is_empty());
    }

    #[test]
    fn test_parse_certipy_no_esc_types() {
        let output = "[!] Vulnerabilities\nNo vulnerable templates found";
        let vulns = parse_certipy_find(output, &json!({"target": "192.168.58.10"}));
        assert!(vulns.is_empty());
    }

    #[test]
    fn test_parse_certipy_empty_output() {
        let vulns = parse_certipy_find("", &json!({}));
        assert!(vulns.is_empty());
    }

    #[test]
    fn test_parse_certipy_vuln_id_format() {
        let output = "[!] Vulnerabilities\nESC4: misconfigured template";
        let params = json!({"target": "192.168.58.20"});
        let vulns = parse_certipy_find(output, &params);
        assert_eq!(vulns[0]["vuln_id"], "adcs_esc4_192.168.58.20");
    }
}
