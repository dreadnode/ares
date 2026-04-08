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
                "details": {
                    "esc_type": esc_type,
                },
                "recommended_agent": "privesc",
            }));
        }
    }

    vulns
}
