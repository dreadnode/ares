//! Delegation vulnerability parser.

use serde_json::{json, Value};

pub fn parse_delegation(output: &str, params: &Value) -> Vec<Value> {
    let domain = params.get("domain").and_then(|v| v.as_str()).unwrap_or("");
    let target_ip = params
        .get("target")
        .or_else(|| params.get("target_ip"))
        .and_then(|v| v.as_str())
        .unwrap_or("");

    let mut vulns = Vec::new();

    for line in output.lines() {
        let line_lower = line.to_lowercase();

        if line_lower.contains("constrained") && !line.trim().starts_with("AccountName") {
            let account = extract_delegation_account(line);
            if !account.is_empty() {
                vulns.push(json!({
                    "vuln_id": format!("constrained_delegation_{}", account),
                    "vuln_type": "constrained_delegation",
                    "target": target_ip,
                    "details": {
                        "account_name": account,
                        "domain": domain,
                        "delegation_type": "constrained",
                    },
                    "recommended_agent": "privesc",
                }));
            }
        }

        if line_lower.contains("unconstrained") && !line.trim().starts_with("AccountName") {
            let account = extract_delegation_account(line);
            if !account.is_empty() {
                vulns.push(json!({
                    "vuln_id": format!("unconstrained_delegation_{}", account),
                    "vuln_type": "unconstrained_delegation",
                    "target": target_ip,
                    "details": {
                        "account_name": account,
                        "domain": domain,
                        "delegation_type": "unconstrained",
                    },
                    "recommended_agent": "privesc",
                }));
            }
        }
    }

    vulns
}

pub fn extract_delegation_account(line: &str) -> String {
    // impacket-findDelegation output format varies, but account is typically first column
    let parts: Vec<&str> = line.split_whitespace().collect();
    if !parts.is_empty() {
        // Account might be "DOMAIN/account$" or just "account$"
        let account = parts[0];
        if account.contains('/') {
            account
                .split('/')
                .next_back()
                .unwrap_or(account)
                .to_string()
        } else {
            account.to_string()
        }
    } else {
        String::new()
    }
}
