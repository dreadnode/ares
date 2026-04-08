//! Delegation extraction from impacket-findDelegation output.

use super::types::{DelegationEntry, DelegationType};

/// Extract delegation entries from impacket-findDelegation table output.
///
/// Expects a table with columns: AccountName, AccountType, DelegationType,
/// DelegationRightsTo. The parser auto-detects the header row and skips
/// separator lines (lines of dashes).
pub fn extract_delegations(output: &str) -> Vec<DelegationEntry> {
    let mut results = Vec::new();
    let mut header_found = false;
    let mut col_indices: Option<(usize, usize, usize, usize)> = None;

    for line in output.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        // Detect header row
        if !header_found {
            let lower = trimmed.to_lowercase();
            if lower.contains("accountname") && lower.contains("delegationtype") {
                // Parse column start positions from the header
                let account_name_idx = lower.find("accountname").unwrap_or(0);
                let account_type_idx = lower.find("accounttype").unwrap_or(0);
                let delegation_type_idx = lower.find("delegationtype").unwrap_or(0);
                let rights_idx = lower.find("delegationrightsto").unwrap_or(0);
                col_indices = Some((
                    account_name_idx,
                    account_type_idx,
                    delegation_type_idx,
                    rights_idx,
                ));
                header_found = true;
            }
            continue;
        }

        // Skip separator line (dashes)
        if trimmed.chars().all(|c| c == '-' || c.is_whitespace()) {
            continue;
        }

        // Parse data row using whitespace splitting (more robust than column positions
        // for variable-width columns).
        let cols: Vec<&str> = trimmed.split_whitespace().collect();
        if cols.len() < 3 {
            continue;
        }

        let _col_indices = match col_indices {
            Some(ci) => ci,
            None => continue,
        };

        // For the table format, the columns may have multi-word values
        // (e.g., "Constrained w/ Protocol Trans."). Use fixed-width column
        // parsing based on the header positions when possible.
        // Extract column values using fixed-width positions from the header.
        // Fall back to whitespace splitting for short lines.
        let (account_str, account_type_string, delegation_type_string, target_spn_string);
        if line.len() >= _col_indices.3 {
            account_str = line
                .get(_col_indices.0.._col_indices.1)
                .unwrap_or("")
                .trim()
                .to_string();
            account_type_string = line
                .get(_col_indices.1.._col_indices.2)
                .unwrap_or("")
                .trim()
                .to_string();
            delegation_type_string = line
                .get(_col_indices.2.._col_indices.3)
                .unwrap_or("")
                .trim()
                .to_string();
            target_spn_string = line.get(_col_indices.3..).unwrap_or("").trim().to_string();
        } else {
            account_str = cols[0].to_string();
            account_type_string = cols.get(1).unwrap_or(&"").to_string();
            delegation_type_string = cols[2..].join(" ");
            target_spn_string = cols.last().unwrap_or(&"").to_string();
        }

        let account = account_str.as_str();
        let account_type_str = account_type_string.as_str();
        let delegation_type_str = delegation_type_string.as_str();
        let target_spn_str = target_spn_string.as_str();

        let delegation_type = {
            let lower = delegation_type_str.to_lowercase();
            if lower.contains("unconstrained") {
                DelegationType::Unconstrained
            } else if lower.contains("resource") || lower.contains("rbcd") {
                DelegationType::RBCD
            } else if lower.contains("constrained") {
                DelegationType::Constrained
            } else {
                continue; // Unknown delegation type, skip
            }
        };

        let account_type = if account_type_str.to_lowercase().contains("computer") {
            "computer".to_string()
        } else {
            "user".to_string()
        };

        let target_spn = if target_spn_str.is_empty() || target_spn_str.to_uppercase() == "N/A" {
            None
        } else {
            Some(target_spn_str.to_string())
        };

        results.push(DelegationEntry {
            account: account.to_string(),
            account_type,
            delegation_type,
            target_spn,
        });
    }

    results
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_delegations() {
        let output = r#"Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies

AccountName    AccountType  DelegationType                  DelegationRightsTo
-----------    -----------  ---------------                 ------------------
svc_sql        Person       Constrained w/ Protocol Trans.  cifs/dc01.contoso.local
DC01$          Computer     Unconstrained                   N/A
"#;
        let delegations = extract_delegations(output);
        assert_eq!(delegations.len(), 2);

        assert_eq!(delegations[0].account, "svc_sql");
        assert_eq!(delegations[0].account_type, "user");
        assert_eq!(delegations[0].delegation_type, DelegationType::Constrained);
        assert_eq!(
            delegations[0].target_spn,
            Some("cifs/dc01.contoso.local".to_string())
        );

        assert_eq!(delegations[1].account, "DC01$");
        assert_eq!(delegations[1].account_type, "computer");
        assert_eq!(
            delegations[1].delegation_type,
            DelegationType::Unconstrained
        );
        assert_eq!(delegations[1].target_spn, None);
    }

    #[test]
    fn test_extract_delegations_rbcd() {
        let output = r#"AccountName    AccountType  DelegationType                          DelegationRightsTo
-----------    -----------  ---------------                         ------------------
WEB01$         Computer     Resource-Based Constrained Delegation   SRV01$
"#;
        let delegations = extract_delegations(output);
        assert_eq!(delegations.len(), 1);
        assert_eq!(delegations[0].account, "WEB01$");
        assert_eq!(delegations[0].delegation_type, DelegationType::RBCD);
    }

    #[test]
    fn test_extract_delegations_empty() {
        assert!(extract_delegations("").is_empty());
        assert!(extract_delegations("No entries found.\n").is_empty());
    }

    #[test]
    fn test_delegations_with_preamble() {
        let output = r#"Impacket v0.12.0 - Copyright 2023 Fortra

AccountName     AccountType   DelegationType     DelegationRightsTo
-----------     -----------   ---------------    ------------------
web_svc         Person        Unconstrained      N/A
"#;
        let delegations = extract_delegations(output);
        assert_eq!(delegations.len(), 1);
        assert_eq!(delegations[0].account, "web_svc");
        assert_eq!(
            delegations[0].delegation_type,
            DelegationType::Unconstrained
        );
        assert_eq!(delegations[0].target_spn, None);
    }
}
