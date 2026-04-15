//! K8s and EC2 transport: re-exec ares-cli commands via kubectl or SSM.
//!
//! When `--k8s <namespace>` is passed, this module strips the transport flags
//! from argv and re-runs the command on the target pod. This eliminates ~25
//! boilerplate Taskfile wrappers that just do `kubectl exec ... ares-cli ...`.
//!
//! When `--ec2 <name>` is passed, this module resolves the EC2 instance by
//! Name tag and executes via AWS SSM send-command, polling for results.
//! This eliminates ~60 lines of SSM boilerplate per task.

use std::process::Command;

// ============================================================================
// Argv pre-scanning (runs before clap)
// ============================================================================

/// Scan raw argv for `--k8s <namespace>` and `--k8s-deploy <deploy>`.
/// Returns `(namespace, deploy)` if `--k8s` is present.
fn prescan_k8s_args() -> Option<(String, Option<String>)> {
    let args: Vec<String> = std::env::args().collect();
    let mut namespace = None;
    let mut deploy = None;
    let mut i = 0;
    while i < args.len() {
        if args[i] == "--k8s" {
            if i + 1 < args.len() {
                namespace = Some(args[i + 1].clone());
                i += 2;
                continue;
            }
        } else if args[i].starts_with("--k8s=") {
            namespace = args[i].strip_prefix("--k8s=").map(|s| s.to_string());
        } else if args[i] == "--k8s-deploy" {
            if i + 1 < args.len() {
                deploy = Some(args[i + 1].clone());
                i += 2;
                continue;
            }
        } else if args[i].starts_with("--k8s-deploy=") {
            deploy = args[i].strip_prefix("--k8s-deploy=").map(|s| s.to_string());
        }
        i += 1;
    }
    namespace.map(|ns| (ns, deploy))
}

/// Scan raw argv for `--ec2 <name>`, `--ec2-profile <profile>`, `--ec2-region <region>`.
/// Returns `(instance_name, profile, region)` if `--ec2` is present.
fn prescan_ec2_args() -> Option<(String, String, String)> {
    let args: Vec<String> = std::env::args().collect();
    let mut name = None;
    let mut profile = None;
    let mut region = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--ec2" if i + 1 < args.len() => {
                name = Some(args[i + 1].clone());
                i += 2;
                continue;
            }
            "--ec2-profile" if i + 1 < args.len() => {
                profile = Some(args[i + 1].clone());
                i += 2;
                continue;
            }
            "--ec2-region" if i + 1 < args.len() => {
                region = Some(args[i + 1].clone());
                i += 2;
                continue;
            }
            s if s.starts_with("--ec2=") => {
                name = s.strip_prefix("--ec2=").map(|v| v.to_string());
            }
            s if s.starts_with("--ec2-profile=") => {
                profile = s.strip_prefix("--ec2-profile=").map(|v| v.to_string());
            }
            s if s.starts_with("--ec2-region=") => {
                region = s.strip_prefix("--ec2-region=").map(|v| v.to_string());
            }
            _ => {}
        }
        i += 1;
    }
    name.map(|n| {
        (
            n,
            profile.unwrap_or_else(|| "lab".to_string()),
            region.unwrap_or_else(|| "us-west-1".to_string()),
        )
    })
}

// ============================================================================
// Argv stripping (shared by both transports)
// ============================================================================

/// Strip all transport and credential flags from argv.
/// Returns the remaining args (without the binary name).
fn strip_transport_args() -> Vec<String> {
    let args: Vec<String> = std::env::args().collect();
    let mut result = Vec::new();
    let mut i = 1; // skip binary name
    while i < args.len() {
        let arg = &args[i];
        // Skip flags that take a separate value
        if matches!(
            arg.as_str(),
            "--k8s"
                | "--k8s-deploy"
                | "--env-file"
                | "--secrets-from"
                | "--ec2"
                | "--ec2-profile"
                | "--ec2-region"
        ) {
            i += 2; // skip flag + value
            continue;
        }
        // Skip combined --flag=value forms
        if arg.starts_with("--k8s=")
            || arg.starts_with("--k8s-deploy=")
            || arg.starts_with("--env-file=")
            || arg.starts_with("--secrets-from=")
            || arg.starts_with("--ec2=")
            || arg.starts_with("--ec2-profile=")
            || arg.starts_with("--ec2-region=")
        {
            i += 1;
            continue;
        }
        result.push(arg.clone());
        i += 1;
    }
    result
}

// ============================================================================
// K8s transport (kubectl exec — synchronous)
// ============================================================================

/// Auto-detect the K8s deployment name from the subcommand.
fn detect_deploy(args: &[String]) -> &str {
    if args.iter().any(|a| a == "blue") {
        "ares-blue-orchestrator"
    } else {
        "ares-orchestrator"
    }
}

/// If `--k8s` is present in argv, exec via kubectl and return the exit code.
/// Returns `None` if `--k8s` is not present (normal local execution).
pub(crate) fn maybe_exec_k8s() -> Option<i32> {
    let (namespace, deploy_override) = prescan_k8s_args()?;
    let inner_args = strip_transport_args();
    let deploy = deploy_override
        .as_deref()
        .unwrap_or_else(|| detect_deploy(&inner_args));

    let mut cmd = Command::new("kubectl");
    cmd.args([
        "exec",
        "-i",
        "-n",
        &namespace,
        &format!("deploy/{deploy}"),
        "--",
        "env",
        "RUST_LOG=error",
        "ares-cli",
    ]);
    cmd.args(&inner_args);

    // Inherit stdin/stdout/stderr for interactive use
    match cmd.status() {
        Ok(status) => Some(status.code().unwrap_or(1)),
        Err(e) => {
            eprintln!("Failed to run kubectl: {e}");
            Some(1)
        }
    }
}

// ============================================================================
// EC2 transport (AWS SSM — async send/poll/fetch)
// ============================================================================

/// Resolve EC2 instance ID from a Name tag pattern.
fn resolve_ec2_instance(name: &str, profile: &str, region: &str) -> Result<String, String> {
    let output = Command::new("aws")
        .args([
            "ec2",
            "describe-instances",
            "--profile",
            profile,
            "--region",
            region,
            "--filters",
            "Name=instance-state-name,Values=running",
            &format!("Name=tag:Name,Values=*{name}*"),
            "--query",
            "Reservations[*].Instances[*].InstanceId",
            "--output",
            "text",
        ])
        .output()
        .map_err(|e| format!("Failed to run aws: {e}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("aws ec2 describe-instances failed: {stderr}"));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    stdout
        .split_whitespace()
        .next()
        .map(|s| s.to_string())
        .ok_or_else(|| format!("No running instance found matching Name tag: {name}"))
}

/// Shell-escape and join args for SSM command execution.
fn shell_join(args: &[String]) -> String {
    args.iter()
        .map(|a| {
            if a.is_empty()
                || a.contains(|c: char| {
                    c.is_whitespace()
                        || matches!(
                            c,
                            '\'' | '"'
                                | '$'
                                | '\\'
                                | '`'
                                | '!'
                                | '('
                                | ')'
                                | '{'
                                | '}'
                                | '|'
                                | '&'
                                | ';'
                                | '<'
                                | '>'
                                | '*'
                                | '?'
                        )
                })
            {
                format!("'{}'", a.replace('\'', "'\\''"))
            } else {
                a.clone()
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// JSON-escape a string for embedding in a JSON value.
fn json_escape(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
        .replace('\t', "\\t")
}

/// Send a shell command to an EC2 instance via SSM. Returns the command ID.
fn ssm_send_command(
    instance_id: &str,
    command: &str,
    profile: &str,
    region: &str,
) -> Result<String, String> {
    // Write params to a temp file so JSON escaping is correct
    let params_path = format!("/tmp/ares-ssm-{}.json", std::process::id());
    let params_json = format!(r#"{{"commands":["{}"]}}"#, json_escape(command));
    std::fs::write(&params_path, &params_json)
        .map_err(|e| format!("Failed to write params file: {e}"))?;

    let output = Command::new("aws")
        .args([
            "ssm",
            "send-command",
            "--profile",
            profile,
            "--region",
            region,
            "--instance-ids",
            instance_id,
            "--document-name",
            "AWS-RunShellScript",
            "--parameters",
            &format!("file://{params_path}"),
            "--query",
            "Command.CommandId",
            "--output",
            "text",
        ])
        .output();

    // Clean up temp file regardless of outcome
    let _ = std::fs::remove_file(&params_path);

    let output = output.map_err(|e| format!("Failed to run aws: {e}"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("SSM send-command failed: {stderr}"));
    }

    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

/// Poll SSM command invocation until it reaches a terminal state.
fn ssm_poll(cmd_id: &str, instance_id: &str, profile: &str, region: &str, max_secs: u32) -> String {
    for _ in 0..max_secs {
        if let Ok(output) = Command::new("aws")
            .args([
                "ssm",
                "get-command-invocation",
                "--profile",
                profile,
                "--region",
                region,
                "--command-id",
                cmd_id,
                "--instance-id",
                instance_id,
                "--query",
                "Status",
                "--output",
                "text",
            ])
            .output()
        {
            let status = String::from_utf8_lossy(&output.stdout).trim().to_string();
            match status.as_str() {
                "Success" | "Failed" | "Cancelled" | "TimedOut" => return status,
                _ => {}
            }
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
    "TimedOut".to_string()
}

/// Fetch a field (StandardOutputContent or StandardErrorContent) from a completed SSM invocation.
fn ssm_get_output(
    cmd_id: &str,
    instance_id: &str,
    profile: &str,
    region: &str,
    query_field: &str,
) -> Result<String, String> {
    let output = Command::new("aws")
        .args([
            "ssm",
            "get-command-invocation",
            "--profile",
            profile,
            "--region",
            region,
            "--command-id",
            cmd_id,
            "--instance-id",
            instance_id,
            "--query",
            query_field,
            "--output",
            "text",
        ])
        .output()
        .map_err(|e| format!("Failed to run aws: {e}"))?;

    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

/// If `--ec2` is present in argv, resolve the instance and exec via SSM.
/// Returns `None` if `--ec2` is not present (normal local execution).
pub(crate) fn maybe_exec_ec2() -> Option<i32> {
    let (instance_name, profile, region) = prescan_ec2_args()?;
    let inner_args = strip_transport_args();

    eprintln!("Resolving EC2 instance: {instance_name}...");
    let instance_id = match resolve_ec2_instance(&instance_name, &profile, &region) {
        Ok(id) => {
            eprintln!("Resolved to {id}");
            id
        }
        Err(e) => {
            eprintln!("{e}");
            return Some(1);
        }
    };

    let cli_cmd = format!("RUST_LOG=error ares-cli {}", shell_join(&inner_args));

    let cmd_id = match ssm_send_command(&instance_id, &cli_cmd, &profile, &region) {
        Ok(id) => id,
        Err(e) => {
            eprintln!("{e}");
            return Some(1);
        }
    };

    let status = ssm_poll(&cmd_id, &instance_id, &profile, &region, 120);

    if let Ok(stdout) = ssm_get_output(
        &cmd_id,
        &instance_id,
        &profile,
        &region,
        "StandardOutputContent",
    ) {
        print!("{stdout}");
    }

    if status != "Success" {
        if let Ok(stderr) = ssm_get_output(
            &cmd_id,
            &instance_id,
            &profile,
            &region,
            "StandardErrorContent",
        ) {
            eprint!("{stderr}");
        }
        return Some(1);
    }

    Some(0)
}
