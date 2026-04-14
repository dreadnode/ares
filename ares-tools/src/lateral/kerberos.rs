//! Kerberos ticket tool executors.

use anyhow::Result;
use serde_json::Value;

use crate::args::{optional_str, required_str};
use crate::credentials;
use crate::executor::CommandBuilder;
use crate::ToolOutput;

/// Request a TGT via impacket-getTGT.
///
/// Required args: `domain`, `username`
/// Optional args: `password`, `hash`, `dc_ip`
pub async fn get_tgt(args: &Value) -> Result<ToolOutput> {
    let domain = required_str(args, "domain")?;
    let username = required_str(args, "username")?;
    let password = optional_str(args, "password");
    let hash = optional_str(args, "hash");
    let dc_ip = optional_str(args, "dc_ip");

    let user_string = match password {
        Some(p) => format!("{domain}/{username}:{p}"),
        None => format!("{domain}/{username}"),
    };

    let mut cmd = CommandBuilder::new("impacket-getTGT").arg(&user_string);

    if let Some(h) = hash {
        let hash_args = credentials::hash_args(h);
        cmd = cmd.args(hash_args);
    }

    cmd.flag_opt("-dc-ip", dc_ip)
        .timeout_secs(60)
        .execute()
        .await
}
