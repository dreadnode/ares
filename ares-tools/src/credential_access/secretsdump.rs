//! Secretsdump credential access tool executor.

use anyhow::Result;
use serde_json::Value;

use crate::args::{optional_bool, optional_i64, optional_str, required_str};
use crate::credentials;
use crate::executor::CommandBuilder;
use crate::ToolOutput;

/// Dump secrets via `impacket-secretsdump` with password, hash, or Kerberos auth.
pub async fn secretsdump(args: &Value) -> Result<ToolOutput> {
    let domain = optional_str(args, "domain");
    let username = required_str(args, "username")?;
    let password = optional_str(args, "password");
    let hash = optional_str(args, "hash");
    let target = required_str(args, "target")?;
    let dc_ip = optional_str(args, "dc_ip");
    let use_kerberos = optional_bool(args, "no_pass").unwrap_or(false);
    let ticket_path = optional_str(args, "ticket_path");
    let timeout_minutes = optional_i64(args, "timeout_minutes");

    let timeout_secs = timeout_minutes.map(|m| (m * 60) as u64).unwrap_or(180);

    let (auth_string, extra_args) =
        credentials::impacket_auth(domain, username, password, hash, target);

    let mut cmd = CommandBuilder::new("impacket-secretsdump");

    cmd = cmd.flag_opt("-dc-ip", dc_ip);

    if use_kerberos {
        cmd = cmd.arg("-k").arg("-no-pass");
        if let Some(tp) = ticket_path {
            cmd = cmd.env("KRB5CCNAME", tp);
        }
    } else {
        cmd = cmd.args(extra_args);
    }

    cmd = cmd.arg(&auth_string);

    cmd.timeout_secs(timeout_secs).execute().await
}
