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

#[cfg(test)]
mod tests {
    use crate::args::{optional_str, required_str};
    use crate::credentials;
    use serde_json::json;

    #[test]
    fn get_tgt_requires_domain() {
        let args = json!({"username": "admin"});
        assert!(required_str(&args, "domain").is_err());
    }

    #[test]
    fn get_tgt_requires_username() {
        let args = json!({"domain": "contoso.local"});
        assert!(required_str(&args, "username").is_err());
    }

    #[test]
    fn get_tgt_format_with_password() {
        let domain = "contoso.local";
        let username = "admin";
        let password = Some("P@ssw0rd!");
        let user_string = match password {
            Some(p) => format!("{domain}/{username}:{p}"),
            None => format!("{domain}/{username}"),
        };
        assert_eq!(user_string, "contoso.local/admin:P@ssw0rd!");
    }

    #[test]
    fn get_tgt_format_without_password() {
        let domain = "contoso.local";
        let username = "admin";
        let password: Option<&str> = None;
        let user_string = match password {
            Some(p) => format!("{domain}/{username}:{p}"),
            None => format!("{domain}/{username}"),
        };
        assert_eq!(user_string, "contoso.local/admin");
    }

    #[test]
    fn get_tgt_hash_args_usage() {
        let args = json!({
            "domain": "contoso.local",
            "username": "admin",
            "hash": "31d6cfe0d16ae931b73c59d7e0c089c0"
        });
        let hash = optional_str(&args, "hash").unwrap();
        let hash_args = credentials::hash_args(hash);
        assert_eq!(
            hash_args,
            vec!["-hashes", ":31d6cfe0d16ae931b73c59d7e0c089c0"]
        );
    }

    #[test]
    fn get_tgt_hash_args_with_lm_nt() {
        let hash = "aad3b435:31d6cfe0d16ae931b73c59d7e0c089c0";
        let hash_args = credentials::hash_args(hash);
        assert_eq!(
            hash_args,
            vec!["-hashes", "aad3b435:31d6cfe0d16ae931b73c59d7e0c089c0"]
        );
    }

    #[test]
    fn get_tgt_optional_dc_ip_present() {
        let args = json!({
            "domain": "contoso.local",
            "username": "admin",
            "dc_ip": "192.168.58.1"
        });
        assert_eq!(optional_str(&args, "dc_ip"), Some("192.168.58.1"));
    }

    #[test]
    fn get_tgt_optional_dc_ip_absent() {
        let args = json!({
            "domain": "contoso.local",
            "username": "admin"
        });
        assert!(optional_str(&args, "dc_ip").is_none());
    }

    // --- mock executor tests ---

    use crate::executor::mock;

    #[tokio::test]
    async fn get_tgt_password_executes() {
        mock::push(mock::success());
        let args = json!({
            "domain": "contoso.local", "username": "admin", "password": "P@ss"
        });
        assert!(super::get_tgt(&args).await.is_ok());
    }

    #[tokio::test]
    async fn get_tgt_hash_executes() {
        mock::push(mock::success());
        let args = json!({
            "domain": "contoso.local", "username": "admin",
            "hash": "aabbccdd", "dc_ip": "192.168.58.1"
        });
        assert!(super::get_tgt(&args).await.is_ok());
    }
}
