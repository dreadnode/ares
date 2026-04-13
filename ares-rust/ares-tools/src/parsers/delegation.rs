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

        // Skip header line
        if line.trim().starts_with("AccountName") {
            continue;
        }

        // impacket-findDelegation output columns:
        // AccountName  AccountType  DelegationType  DelegationRightsTo
        let parts: Vec<&str> = line.split_whitespace().collect();

        if line_lower.contains("unconstrained") {
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
        } else if line_lower.contains("constrained") {
            let account = extract_delegation_account(line);
            // Extract delegation target (column 3+, may contain spaces for multiple SPNs)
            let delegation_target = if parts.len() >= 4 {
                parts[3..].join(" ")
            } else {
                String::new()
            };
            if !account.is_empty() {
                let mut details = json!({
                    "account_name": account,
                    "domain": domain,
                    "delegation_type": "constrained",
                });
                if !delegation_target.is_empty() {
                    details["delegation_target"] = json!(delegation_target);
                }
                vulns.push(json!({
                    "vuln_id": format!("constrained_delegation_{}", account),
                    "vuln_type": "constrained_delegation",
                    "target": target_ip,
                    "details": details,
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_parse_delegation_constrained() {
        let output = "\
AccountName                    AccountType  DelegationType       DelegationRightsTo
svc_sql$                       Computer     Constrained          CIFS/dc01.contoso.local";
        let params = json!({"domain": "contoso.local", "target_ip": "192.168.58.10"});
        let vulns = parse_delegation(output, &params);
        assert_eq!(vulns.len(), 1);
        assert_eq!(vulns[0]["vuln_type"], "constrained_delegation");
        assert_eq!(vulns[0]["target"], "192.168.58.10");
        assert_eq!(vulns[0]["details"]["account_name"], "svc_sql$");
        assert_eq!(vulns[0]["details"]["domain"], "contoso.local");
        assert_eq!(
            vulns[0]["details"]["delegation_target"],
            "CIFS/dc01.contoso.local"
        );
    }

    #[test]
    fn test_parse_delegation_unconstrained() {
        let output = "DC01$  Computer  Unconstrained  N/A";
        let params = json!({"domain": "contoso.local", "target": "192.168.58.10"});
        let vulns = parse_delegation(output, &params);
        assert_eq!(vulns.len(), 1);
        assert_eq!(vulns[0]["vuln_type"], "unconstrained_delegation");
    }

    #[test]
    fn test_parse_delegation_mixed() {
        let output = "\
AccountName  AccountType  DelegationType  DelegationRightsTo
svc_sql$     Computer     Constrained     CIFS/dc01.contoso.local
DC01$        Computer     Unconstrained   N/A";
        let params = json!({"domain": "contoso.local", "target_ip": "192.168.58.10"});
        let vulns = parse_delegation(output, &params);
        assert_eq!(vulns.len(), 2);
        assert_eq!(vulns[0]["vuln_type"], "constrained_delegation");
        assert_eq!(vulns[1]["vuln_type"], "unconstrained_delegation");
    }

    #[test]
    fn test_parse_delegation_no_results() {
        let vulns = parse_delegation("[*] No delegation found", &json!({}));
        assert!(vulns.is_empty());
    }

    #[test]
    fn test_extract_delegation_account_with_domain_prefix() {
        assert_eq!(
            extract_delegation_account("CONTOSO/svc_sql$  Computer  Constrained"),
            "svc_sql$"
        );
    }

    #[test]
    fn test_extract_delegation_account_without_prefix() {
        assert_eq!(
            extract_delegation_account("svc_sql$  Computer  Constrained"),
            "svc_sql$"
        );
    }

    #[test]
    fn test_extract_delegation_account_empty() {
        assert_eq!(extract_delegation_account(""), "");
    }
}
