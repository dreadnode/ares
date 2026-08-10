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

    // Preferred path: structured rows from the enriched query, tagged by a
    // literal `scope` column ("server"/"master"/"msdb"), then grantee, then the
    // impersonation TARGET login. One vuln per (grantee → target) pair so
    // multiple grants on the same host are tracked independently (a per-host
    // vuln_id would be collapsed by Redis HSETNX, hiding all but the first).
    let mut seen = std::collections::HashSet::new();
    for line in output.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 3 {
            continue;
        }
        let scope = parts[0];
        if !matches!(scope, "server" | "master" | "msdb") {
            continue;
        }
        let grantee = parts[1];
        let impersonate_target = parts[2];
        // Skip self-impersonation and obvious noise.
        if grantee.eq_ignore_ascii_case(impersonate_target) {
            continue;
        }
        let dedup_key = format!(
            "{}:{}:{}",
            scope,
            grantee.to_lowercase(),
            impersonate_target.to_lowercase()
        );
        if !seen.insert(dedup_key) {
            continue;
        }
        vulns.push(json!({
            "vuln_id": format!(
                "mssql_impersonation_{}_{}_{}_{}",
                target, scope, grantee.to_lowercase(), impersonate_target.to_lowercase()
            ),
            "vuln_type": "mssql_impersonation",
            "target": target,
            "discovered_by": "mssql_enum_impersonation",
            "priority": 3,
            "recommended_agent": "privesc",
            "details": {
                "account_name": grantee,
                "impersonate_target": impersonate_target,
                "scope": scope,
                "domain": domain,
                "hostname": target,
                "note": format!(
                    "MSSQL IMPERSONATE: {grantee} can EXECUTE AS {} '{impersonate_target}'",
                    if scope == "server" { "LOGIN" } else { "USER" }
                )
            }
        }));
    }
    if !vulns.is_empty() {
        return vulns;
    }

    // Legacy fallback: older `SELECT * FROM sys.server_permissions WHERE type='IM'`
    // output exposes no principal names. Emit a single grant keyed by the
    // authenticating user (not the host) so distinct credentials still produce
    // distinct vulns.
    let has_impersonation = output.lines().any(|line| {
        let line = line.trim();
        if line.starts_with('-') || line.is_empty() || line.starts_with('[') {
            return false;
        }
        let parts: Vec<&str> = line.split_whitespace().collect();
        let has_im = parts
            .iter()
            .any(|p| *p == "IM" || p.eq_ignore_ascii_case("IMPERSONATE"));
        let has_grant = parts
            .iter()
            .any(|p| p.eq_ignore_ascii_case("GRANT") || *p == "G");
        has_im && has_grant
    });

    if has_impersonation {
        let id_suffix = if username.is_empty() {
            "unknown"
        } else {
            username
        };
        vulns.push(json!({
            "vuln_id": format!("mssql_impersonation_{}_{}", target, id_suffix.to_lowercase()),
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

/// Is `s` shaped like a real SQL Server `sys.servers.name` (sysname)?
///
/// Linked-server names are a single token — a NetBIOS name (`SQL01`), an
/// instance (`SQL01\SQLEXPRESS`), or an FQDN/IP (`sql01.contoso.local`). None
/// contain whitespace or the punctuation that shows up in impacket crash
/// tracebacks (parens, quotes, commas, colons, tildes, carets). Accept only
/// `[A-Za-z0-9_.\-\\$]` so error text and traceback fragments can never be
/// promoted to a phantom linked-server vuln. Bounded to sysname's 128 chars.
fn is_plausible_linked_server_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-' | '\\' | '$'))
}

/// Parse `mssql_enum_linked_servers` output for linked server connections.
///
/// The tool runs `SELECT name FROM sys.servers WHERE is_linked = 1`, so the
/// result set is a single `name` column with exactly one linked server per data
/// row — the local server (`server_id = 0`, `is_linked = 0`) is excluded at the
/// source. Each remaining name becomes an `mssql_linked_server` vulnerability.
///
/// impacket-mssqlclient echoes its interactive prompt (`SQL (…)> `) inline on
/// the header row and emits a bare prompt line after the result set; both are
/// stripped so neither the `name` header nor the trailing prompt is mistaken
/// for a server name (the old `sp_linkedservers` parser turned that trailing
/// prompt into a phantom `SQL` link, and dropped the real first row as "self").
pub fn parse_mssql_linked_servers(output: &str, params: &Value) -> Vec<Value> {
    let target = params.get("target").and_then(|v| v.as_str()).unwrap_or("");
    let domain = params.get("domain").and_then(|v| v.as_str()).unwrap_or("");

    let mut vulns = Vec::new();

    let lower = output.to_lowercase();
    if lower.contains("login failed") || lower.contains("error") && lower.contains("access denied")
    {
        return vulns;
    }

    // Tool-crash guard: when impacket-mssqlclient dies mid-enum (e.g. a DNS
    // `getaddrinfo` failure resolving the linked server's host), it dumps a
    // Python traceback to the captured output. Without this, every traceback
    // LINE below survives the row filters and becomes a phantom
    // `mssql_linked_server` vuln (`"Traceback (most recent call last):"`,
    // `socket.gaierror…`, the `~~~^^^` caret underline). Bail on the crash
    // markers so a failed enum yields zero links, not garbage.
    if lower.contains("traceback (most recent call last)")
        || lower.contains("socket.gaierror")
        || lower.contains("--- stderr ---")
    {
        return vulns;
    }

    let mut seen = std::collections::HashSet::new();
    for raw in output.lines() {
        let line = strip_sql_prompt(raw).trim();
        if line.is_empty() {
            continue;
        }
        // impacket status/banner noise: `[*]`/`[-]`/`[!]` lines and the version
        // banner. A real linked-server name is never any of these.
        if line.starts_with('[') || line.to_lowercase().starts_with("impacket ") {
            continue;
        }
        // Separator row (dashes) and the single `name` column header.
        if line.chars().all(|c| c == '-' || c == ' ') || line.eq_ignore_ascii_case("name") {
            continue;
        }
        // A sys.servers.name (sysname) is a single token — reject anything that
        // isn't shaped like a server name. This is the per-line backstop to the
        // traceback guard above: stray error text, socket-module fragments, and
        // caret-underline rows all carry spaces or punctuation a real link name
        // never does.
        if !is_plausible_linked_server_name(line) {
            continue;
        }

        let server = line.to_string();
        if !seen.insert(server.to_lowercase()) {
            continue;
        }
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

/// Strip impacket-mssqlclient's inline interactive prompt from a line.
///
/// The client echoes `SQL (DOMAIN\user  scope@db)> ` before the header row and
/// emits a bare prompt line after the result set. Return whatever follows the
/// prompt (empty for a bare trailing prompt), or the line unchanged when no
/// prompt is present (plain data rows carry none).
fn strip_sql_prompt(line: &str) -> &str {
    if let Some((_, rest)) = line.split_once(")> ") {
        return rest;
    }
    if line.trim_end().ends_with(")>") {
        return "";
    }
    line
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parse_impersonation_found() {
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
    fn parse_impersonation_structured_per_grantee() {
        // Enriched query output: scope, grantee, impersonate_target columns.
        // Two distinct grants on one host must yield two distinct vulns with
        // the right impersonate_target captured.
        let output = r#"Impacket v0.12.0
SQL> SELECT 'server' AS scope, gr.name ...
scope   grantee          impersonate_target
------  ---------------  ------------------
server  alice            sa
server  bob              svc_sql
master  carol            dbo
"#;
        let params =
            json!({"target": "192.168.58.51", "domain": "contoso.local", "username": "alice"});
        let vulns = parse_mssql_impersonation(output, &params);
        assert_eq!(vulns.len(), 3, "got {vulns:?}");
        // Distinct vuln_ids (per grantee→target), not collapsed to one host key.
        let ids: std::collections::HashSet<_> = vulns
            .iter()
            .map(|v| v["vuln_id"].as_str().unwrap())
            .collect();
        assert_eq!(ids.len(), 3);
        // bob → svc_sql target captured (not hardcoded sa).
        let bob = vulns
            .iter()
            .find(|v| v["details"]["account_name"] == "bob")
            .unwrap();
        assert_eq!(bob["details"]["impersonate_target"], "svc_sql");
        // Database-scope grant captured.
        let carol = vulns
            .iter()
            .find(|v| v["details"]["account_name"] == "carol")
            .unwrap();
        assert_eq!(carol["details"]["scope"], "master");
        assert_eq!(carol["details"]["impersonate_target"], "dbo");
    }

    #[test]
    fn parse_impersonation_none() {
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
    fn parse_impersonation_login_failed() {
        let output = "[-] ERROR(SQL01): Login failed for user 'test'";
        let params = json!({"target": "192.168.58.12", "username": "test"});
        let vulns = parse_mssql_impersonation(output, &params);
        assert!(vulns.is_empty());
    }

    #[test]
    fn parse_linked_servers_found() {
        // `SELECT name FROM sys.servers WHERE is_linked = 1` — single `name`
        // column, local server already excluded server-side.
        let output = r#"SQL (CONTOSO\alice  guest@master)> name
-------
sql01
"#;
        let params = json!({"target": "192.168.58.12", "domain": "fabrikam.local"});
        let vulns = parse_mssql_linked_servers(output, &params);
        assert_eq!(vulns.len(), 1);
        assert_eq!(vulns[0]["vuln_type"], "mssql_linked_server");
        assert_eq!(vulns[0]["details"]["linked_server"], "sql01");
    }

    #[test]
    fn parse_linked_servers_none() {
        // No linked servers: is_linked = 1 returns an empty set; only the
        // header, separator, and the trailing bare prompt remain.
        let output = r#"SQL (CONTOSO\alice  guest@master)> name
-------
SQL (CONTOSO\alice  guest@master)>
"#;
        let params = json!({"target": "192.168.58.12"});
        let vulns = parse_mssql_linked_servers(output, &params);
        assert!(vulns.is_empty());
    }

    #[test]
    fn parse_linked_servers_cross_forest_link_captured() {
        // Regression: real impacket-mssqlclient output where the cross-forest
        // link is the ONLY row. The old sp_linkedservers parser dropped the
        // first data row as "self" and turned the trailing prompt into a
        // phantom `SQL` link — losing the actual remote link. The single-column
        // parser must capture the link and emit no phantom.
        let output = "[*] Encryption required, switching to TLS\n\
                      [!] Press help for extra shell commands\n\
                      SQL (CONTOSO\\alice  guest@master)> name      \n\
                      -------   \n\
                      sql01   \n\
                      SQL (CONTOSO\\alice  guest@master)> \n";
        let params = json!({"target": "192.168.58.12", "domain": "contoso.local"});
        let vulns = parse_mssql_linked_servers(output, &params);
        assert_eq!(vulns.len(), 1, "got {vulns:?}");
        assert_eq!(vulns[0]["details"]["linked_server"], "sql01");
        // No phantom `SQL` link from the trailing prompt, no `name` header row.
        assert!(!vulns
            .iter()
            .any(|v| v["details"]["linked_server"] == "SQL"
                || v["details"]["linked_server"] == "name"));
    }

    #[test]
    fn parse_linked_servers_ignores_crash_traceback() {
        // Regression: impacket-mssqlclient crashed on a DNS getaddrinfo failure
        // resolving the linked server's host and dumped a Python traceback into
        // the captured output. Every traceback line used to survive the row
        // filters and become a phantom `mssql_linked_server` vuln. The parser
        // must yield ZERO links for a crashed enum.
        let output = "SQL (CONTOSO\\alice  guest@master)> \n\
                      --- stderr ---\n\
                      Traceback (most recent call last):\n\
                        File \"/opt/impacket/examples/mssqlclient.py\", line 91, in <module>\n\
                          ms_sql.connect()\n\
                        File \"/opt/impacket/impacket/tds.py\", line 554, in connect\n\
                          af, socktype, proto, canonname, sa = socket.getaddrinfo(self.server, self.port)\n\
                          ~~~~~~~~~~~~~~~~~~^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\n\
                      socket.gaierror: [Errno -2] Name or service not known\n";
        let params = json!({"target": "sql01.contoso.local", "domain": "contoso.local"});
        let vulns = parse_mssql_linked_servers(output, &params);
        assert!(
            vulns.is_empty(),
            "crash traceback produced phantom links: {vulns:?}"
        );
    }

    #[test]
    fn parse_linked_servers_rejects_non_servername_rows() {
        // Even without the traceback header, individual error/junk lines must
        // not be promoted: only sysname-shaped tokens survive the per-line
        // filter. The real link on the same output is still captured.
        let output = "SQL (CONTOSO\\alice  guest@master)> name\n\
                      -------\n\
                      sql01\n\
                      for res in _socket.getaddrinfo(host, port, family):\n\
                      ~~~~~~~~~~~~~~^^\n\
                      SQL (CONTOSO\\alice  guest@master)>\n";
        let params = json!({"target": "192.168.58.12", "domain": "contoso.local"});
        let vulns = parse_mssql_linked_servers(output, &params);
        assert_eq!(vulns.len(), 1, "got {vulns:?}");
        assert_eq!(vulns[0]["details"]["linked_server"], "sql01");
    }

    #[test]
    fn plausible_linked_server_name_accepts_real_shapes_rejects_junk() {
        assert!(is_plausible_linked_server_name("SQL01"));
        assert!(is_plausible_linked_server_name("SQL01\\SQLEXPRESS"));
        assert!(is_plausible_linked_server_name("sql01.contoso.local"));
        assert!(is_plausible_linked_server_name("192.168.58.12"));
        assert!(!is_plausible_linked_server_name(""));
        assert!(!is_plausible_linked_server_name(
            "Traceback (most recent call last):"
        ));
        assert!(!is_plausible_linked_server_name("ms_sql.connect()"));
        assert!(!is_plausible_linked_server_name("~~~~^^^^"));
        assert!(!is_plausible_linked_server_name("--- stderr ---"));
        assert!(!is_plausible_linked_server_name(&"a".repeat(129)));
    }

    #[test]
    fn parse_linked_servers_multiple() {
        let output = "SQL (CONTOSO\\alice  guest@master)> name\n\
                      -------\n\
                      sql01\n\
                      web01\n\
                      SQL (CONTOSO\\alice  guest@master)>\n";
        let params = json!({"target": "192.168.58.12", "domain": "contoso.local"});
        let vulns = parse_mssql_linked_servers(output, &params);
        let names: std::collections::HashSet<_> = vulns
            .iter()
            .map(|v| v["details"]["linked_server"].as_str().unwrap())
            .collect();
        assert_eq!(names.len(), 2);
        assert!(names.contains("sql01"));
        assert!(names.contains("web01"));
    }

    #[test]
    fn strip_sql_prompt_variants() {
        assert_eq!(
            super::strip_sql_prompt("SQL (CONTOSO\\alice  guest@master)> name"),
            "name"
        );
        assert_eq!(
            super::strip_sql_prompt("SQL (CONTOSO\\alice  guest@master)> "),
            ""
        );
        assert_eq!(
            super::strip_sql_prompt("SQL (CONTOSO\\alice  guest@master)>"),
            ""
        );
        // Plain data row carries no prompt — returned unchanged.
        assert_eq!(super::strip_sql_prompt("sql01"), "sql01");
    }
}
