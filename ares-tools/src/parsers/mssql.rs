//! MSSQL tool output parsers.
//!
//! Extract structured vulnerability data from MSSQL enumeration output
//! (impersonation permissions, linked servers).

use serde_json::{json, Value};

/// Parse `mssql_enum_impersonation` output for impersonation privileges.
///
/// Looks for rows from `sys.server_permissions WHERE type = 'IM'` that
/// indicate IMPERSONATE permissions. When found, produces a
/// `mssql_impersonation` vulnerability record.
///
/// Also detects the common impacket-mssqlclient pattern where the tool
/// returns "GRANT" or "IMPERSONATE" in the tabular output.
pub fn parse_mssql_impersonation(output: &str, params: &Value) -> Vec<Value> {
    let target = params.get("target").and_then(|v| v.as_str()).unwrap_or("");
    let domain = params.get("domain").and_then(|v| v.as_str()).unwrap_or("");
    let username = params
        .get("username")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    let mut vulns = Vec::new();

    // Check for error conditions that mean no impersonation
    let lower = output.to_lowercase();
    if lower.contains("login failed") || lower.contains("error") && lower.contains("access denied")
    {
        return vulns;
    }

    // Look for IMPERSONATE permission rows in tabular output.
    // Impacket-mssqlclient formats SQL results as space-separated columns.
    // We look for lines containing "IMPERSONATE" or "IM" permission type
    // with a "GRANT" state.
    let has_impersonation = output.lines().any(|line| {
        let line = line.trim();
        // Skip header/separator lines
        if line.starts_with('-') || line.is_empty() || line.starts_with('[') {
            return false;
        }
        // Match on the permission type column containing "IM" and state "GRANT"
        let parts: Vec<&str> = line.split_whitespace().collect();
        // The sys.server_permissions output has columns like:
        // class class_desc major_id minor_id grantee_principal_id grantor_principal_id
        //   type permission_name state state_desc
        // We look for "IM" or "IMPERSONATE" anywhere in the row with "GRANT"
        let has_im = parts
            .iter()
            .any(|p| *p == "IM" || p.eq_ignore_ascii_case("IMPERSONATE"));
        let has_grant = parts
            .iter()
            .any(|p| p.eq_ignore_ascii_case("GRANT") || *p == "G");
        has_im && has_grant
    });

    if has_impersonation {
        vulns.push(json!({
            "vuln_id": format!("mssql_impersonation_{}", target),
            "vuln_type": "mssql_impersonation",
            "target": target,
            "discovered_by": "mssql_enum_impersonation",
            "priority": 3,
            "recommended_agent": "privesc",
            "details": {
                "account_name": username,
                "domain": domain,
                "hostname": target,
                "note": "MSSQL IMPERSONATE permission found — EXECUTE AS LOGIN escalation possible"
            }
        }));
    }

    vulns
}

/// Parse `mssql_enum_linked_servers` output for linked server connections.
///
/// Looks for linked server entries in `sp_linkedservers` output. When found,
/// produces a `mssql_linked_server` vulnerability record.
pub fn parse_mssql_linked_servers(output: &str, params: &Value) -> Vec<Value> {
    let target = params.get("target").and_then(|v| v.as_str()).unwrap_or("");
    let domain = params.get("domain").and_then(|v| v.as_str()).unwrap_or("");

    let mut vulns = Vec::new();

    // Check for error conditions
    let lower = output.to_lowercase();
    if lower.contains("login failed") || lower.contains("error") && lower.contains("access denied")
    {
        return vulns;
    }

    // sp_linkedservers output has columns: SRV_NAME, SRV_PROVIDERNAME, etc.
    // Each data row after the header represents a linked server.
    // The first row is always the local server itself, so we look for 2+.
    let mut server_names: Vec<String> = Vec::new();
    let mut in_data = false;

    for line in output.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('[') {
            continue;
        }
        // Skip separator lines (all dashes)
        if line.chars().all(|c| c == '-' || c == ' ') {
            in_data = true;
            continue;
        }
        // Header detection: SRV_NAME column
        if line.contains("SRV_NAME") || line.contains("srv_name") {
            continue;
        }
        if in_data {
            // First whitespace-separated token is the server name
            if let Some(name) = line.split_whitespace().next() {
                if !name.starts_with('-') && !name.starts_with('[') {
                    server_names.push(name.to_string());
                }
            }
        }
    }

    // Filter out the local server (first entry) — linked servers are entries
    // beyond the first one (which is always self).
    let linked: Vec<&String> = if server_names.len() > 1 {
        server_names[1..].iter().collect()
    } else {
        Vec::new()
    };

    for server in &linked {
        vulns.push(json!({
            "vuln_id": format!("mssql_linked_server_{}_{}", target, server),
            "vuln_type": "mssql_linked_server",
            "target": target,
            "discovered_by": "mssql_enum_linked_servers",
            "priority": 3,
            "recommended_agent": "privesc",
            "details": {
                "hostname": target,
                "domain": domain,
                "linked_server": server,
                "note": format!("Linked MSSQL server '{}' found — lateral movement via OPENQUERY possible", server)
            }
        }));
    }

    vulns
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_parse_impersonation_found() {
        let output = r#"Impacket v0.12.0 - Copyright Fortra, LLC
[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
SQL> SELECT * FROM sys.server_permissions WHERE type = 'IM';
class   class_desc   major_id   minor_id   grantee_principal_id   grantor_principal_id   type   permission_name   state   state_desc
-----   ----------   --------   --------   --------------------   --------------------   ----   ---------------   -----   ----------
101     SERVER_PRINCIPAL   261   0          267                    261                    IM     IMPERSONATE       G       GRANT
"#;
        let params = json!({"target": "192.168.58.12", "username": "svc_sql", "domain": "child.contoso.local"});
        let vulns = parse_mssql_impersonation(output, &params);
        assert_eq!(vulns.len(), 1);
        assert_eq!(vulns[0]["vuln_type"], "mssql_impersonation");
        assert_eq!(vulns[0]["target"], "192.168.58.12");
        assert_eq!(vulns[0]["priority"], 3);
    }

    #[test]
    fn test_parse_impersonation_none() {
        let output = r#"Impacket v0.12.0
SQL> SELECT * FROM sys.server_permissions WHERE type = 'IM';
class   class_desc   major_id   minor_id   grantee_principal_id   grantor_principal_id   type   permission_name   state   state_desc
-----   ----------   --------   --------   --------------------   --------------------   ----   ---------------   -----   ----------
"#;
        let params = json!({"target": "192.168.58.12", "username": "svc_sql"});
        let vulns = parse_mssql_impersonation(output, &params);
        assert!(vulns.is_empty());
    }

    #[test]
    fn test_parse_impersonation_login_failed() {
        let output = "[-] ERROR(SQL01): Login failed for user 'test'";
        let params = json!({"target": "192.168.58.12", "username": "test"});
        let vulns = parse_mssql_impersonation(output, &params);
        assert!(vulns.is_empty());
    }

    #[test]
    fn test_parse_linked_servers_found() {
        let output = r#"Impacket v0.12.0
SQL> EXEC sp_linkedservers;
SRV_NAME              SRV_PROVIDERNAME   SRV_PRODUCT   SRV_DATASOURCE
--------------------  ----------------   -----------   --------------
SQL01               SQLNCLI            SQL Server    SQL01
SRV01           SQLNCLI            SQL Server    SRV01\SQLEXPRESS
"#;
        let params = json!({"target": "192.168.58.12", "domain": "fabrikam.local"});
        let vulns = parse_mssql_linked_servers(output, &params);
        assert_eq!(vulns.len(), 1); // Only SRV01, not SQL01 (self)
        assert_eq!(vulns[0]["vuln_type"], "mssql_linked_server");
        assert_eq!(vulns[0]["details"]["linked_server"], "SRV01");
    }

    #[test]
    fn test_parse_linked_servers_self_only() {
        let output = r#"SQL> EXEC sp_linkedservers;
SRV_NAME   SRV_PROVIDERNAME
--------   ----------------
SQL01    SQLNCLI
"#;
        let params = json!({"target": "192.168.58.12"});
        let vulns = parse_mssql_linked_servers(output, &params);
        assert!(vulns.is_empty()); // Only self, no linked servers
    }
}
