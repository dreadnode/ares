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
    let mut seen = std::collections::HashSet::new();

    for line in output.lines() {
        let trimmed = line.trim();
        let line_lower = trimmed.to_lowercase();

        // Skip header, separator, and noise lines
        if trimmed.starts_with("AccountName")
            || trimmed.starts_with("---")
            || trimmed.starts_with("[")
            || trimmed.starts_with("Impacket")
            || trimmed.is_empty()
        {
            continue;
        }

        let parts: Vec<&str> = trimmed.split_whitespace().collect();
        if parts.len() < 3 {
            continue;
        }

        // Determine delegation type from keywords in the line
        let delegation_type = if line_lower.contains("unconstrained") {
            "unconstrained"
        } else if line_lower.contains("constrained") {
            "constrained"
        } else {
            continue;
        };

        let account = extract_delegation_account(trimmed);
        if account.is_empty() {
            continue;
        }

        // Extract delegation target SPN by scanning for "service/host" pattern.
        // This handles variable-width DelegationType columns like
        // "Constrained w/ Protocol Transition" that break simple column indexing.
        let delegation_target = extract_spn_from_parts(&parts);

        let vuln_type = format!("{}_delegation", delegation_type);
        let dedup_key = format!("{}:{}", account.to_lowercase(), vuln_type);
        if !seen.insert(dedup_key) {
            continue; // skip duplicate account+type
        }

        let mut details = json!({
            "account_name": account,
            "domain": domain,
            "delegation_type": delegation_type,
        });
        if let Some(ref spn) = delegation_target {
            details["delegation_target"] = json!(spn);
        }

        vulns.push(json!({
            "vuln_id": format!("{}_{}", vuln_type, account),
            "vuln_type": vuln_type,
            "target": target_ip,
            "discovered_by": "find_delegation",
            "details": details,
            "recommended_agent": "privesc",
            "priority": if delegation_type == "constrained" { 8 } else { 7 },
        }));
    }

    vulns
}

/// Extract `service/host` SPN from whitespace-split parts.
/// Skips tokens like "w/", "w/o", and bracket-prefixed items.
fn extract_spn_from_parts(parts: &[&str]) -> Option<String> {
    for part in parts {
        if !part.contains('/') {
            continue;
        }
        // Skip "w/" and "w/o"
        if *part == "w/" || *part == "w/o" {
            continue;
        }
        // Skip bracket-prefixed tokens like "[*]"
        if part.starts_with('[') {
            continue;
        }
        // Must look like service/host (alphabetic after the slash)
        if let Some(slash_idx) = part.find('/') {
            if slash_idx + 1 < part.len() && part.as_bytes()[slash_idx + 1].is_ascii_alphabetic() {
                return Some(part.to_string());
            }
        }
    }
    None
}

pub fn extract_delegation_account(line: &str) -> String {
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
        assert_eq!(vulns[0]["discovered_by"], "find_delegation");
    }

    #[test]
    fn test_parse_delegation_unconstrained() {
        let output = "DC01$  Computer  Unconstrained  N/A";
        let params = json!({"domain": "contoso.local", "target": "192.168.58.10"});
        let vulns = parse_delegation(output, &params);
        assert_eq!(vulns.len(), 1);
        assert_eq!(vulns[0]["vuln_type"], "unconstrained_delegation");
        assert_eq!(vulns[0]["discovered_by"], "find_delegation");
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

    /// Test with real GOAD lab output format including "SPN Exists" column
    /// and multi-word DelegationType like "Constrained w/ Protocol Transition".
    #[test]
    fn test_parse_delegation_goad_format() {
        let output = "\
Impacket v0.13.0.dev0+20251022.125034.d843881f - Copyright Fortra, LLC and its affiliated companies

AccountName   AccountType  DelegationType                       DelegationRightsTo                         SPN Exists
------------  -----------  -----------------------------------  -----------------------------------------  ----------
sansa.stark   Person       Unconstrained                        N/A                                        No
jon.snow      Person       Constrained w/ Protocol Transition   CIFS/winterfell                            No
jon.snow      Person       Constrained w/ Protocol Transition   CIFS/winterfell.north.sevenkingdoms.local  No
CASTELBLACK$  Computer     Constrained w/o Protocol Transition  HTTP/winterfell                            No
CASTELBLACK$  Computer     Constrained w/o Protocol Transition  HTTP/winterfell.north.sevenkingdoms.local  Yes
WINTERFELL$   Computer     Unconstrained                        N/A                                        Yes

";
        let params = json!({"domain": "north.sevenkingdoms.local", "target_ip": "10.1.2.150"});
        let vulns = parse_delegation(output, &params);

        // Dedup: sansa.stark unconstrained, jon.snow constrained,
        // CASTELBLACK$ constrained, WINTERFELL$ unconstrained = 4
        assert_eq!(vulns.len(), 4, "Expected 4 deduped vulns, got {:?}", vulns);

        // sansa.stark → unconstrained
        assert_eq!(vulns[0]["vuln_type"], "unconstrained_delegation");
        assert_eq!(vulns[0]["details"]["account_name"], "sansa.stark");

        // jon.snow → constrained with SPN
        assert_eq!(vulns[1]["vuln_type"], "constrained_delegation");
        assert_eq!(vulns[1]["details"]["account_name"], "jon.snow");
        let spn = vulns[1]["details"]["delegation_target"].as_str().unwrap();
        assert!(
            spn.starts_with("CIFS/winterfell"),
            "Expected CIFS/winterfell SPN, got {}",
            spn
        );

        // CASTELBLACK$ → constrained with HTTP SPN
        assert_eq!(vulns[2]["vuln_type"], "constrained_delegation");
        assert_eq!(vulns[2]["details"]["account_name"], "CASTELBLACK$");
        let spn = vulns[2]["details"]["delegation_target"].as_str().unwrap();
        assert!(
            spn.starts_with("HTTP/winterfell"),
            "Expected HTTP/winterfell SPN, got {}",
            spn
        );

        // WINTERFELL$ → unconstrained
        assert_eq!(vulns[3]["vuln_type"], "unconstrained_delegation");
        assert_eq!(vulns[3]["details"]["account_name"], "WINTERFELL$");

        // All should have discovered_by
        for v in &vulns {
            assert_eq!(v["discovered_by"], "find_delegation");
        }
    }
}
