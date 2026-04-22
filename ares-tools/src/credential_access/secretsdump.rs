//! Secretsdump credential access tool executor.

use anyhow::Result;
use serde_json::Value;

use crate::args::{optional_bool, optional_i64, optional_str, required_str};
use crate::credentials;
use crate::executor::CommandBuilder;
use crate::ToolOutput;

/// Dump secrets via `impacket-secretsdump` with password, hash, or Kerberos auth.
pub async fn secretsdump(args: &Value) -> Result<ToolOutput> {
    let domain = optional_str(args, "domain");
    let username = required_str(args, "username")?;
    let password = optional_str(args, "password");
    let hash = optional_str(args, "hash");
    let target = required_str(args, "target")?;
    let dc_ip = optional_str(args, "dc_ip");
    let use_kerberos = optional_bool(args, "no_pass").unwrap_or(false);
    let ticket_path = optional_str(args, "ticket_path");
    let timeout_minutes = optional_i64(args, "timeout_minutes");

    let timeout_secs = timeout_minutes.map(|m| (m * 60) as u64).unwrap_or(180);

    let (auth_string, extra_args) =
        credentials::impacket_auth(domain, username, password, hash, target);

    let mut cmd = CommandBuilder::new("impacket-secretsdump");

    cmd = cmd.flag_opt("-dc-ip", dc_ip);

    if use_kerberos {
        cmd = cmd.arg("-k").arg("-no-pass");
        if let Some(tp) = ticket_path {
            cmd = cmd.env("KRB5CCNAME", tp);
        }
    } else {
        cmd = cmd.args(extra_args);
    }

    cmd = cmd.arg(&auth_string);

    cmd.timeout_secs(timeout_secs).execute().await
}

#[cfg(test)]
mod tests {
    use crate::args::{optional_bool, optional_i64, optional_str, required_str};
    use crate::credentials;
    use serde_json::json;

    #[test]
    fn secretsdump_requires_username() {
        let args = json!({"target": "192.168.58.1"});
        assert!(required_str(&args, "username").is_err());
    }

    #[test]
    fn secretsdump_requires_target() {
        let args = json!({"username": "admin"});
        assert!(required_str(&args, "target").is_err());
    }

    #[test]
    fn secretsdump_timeout_default_180_secs() {
        let args = json!({
            "target": "192.168.58.1",
            "username": "admin"
        });
        let timeout_minutes = optional_i64(&args, "timeout_minutes");
        let timeout_secs = timeout_minutes.map(|m| (m * 60) as u64).unwrap_or(180);
        assert_eq!(timeout_secs, 180);
    }

    #[test]
    fn secretsdump_timeout_custom() {
        let args = json!({
            "target": "192.168.58.1",
            "username": "admin",
            "timeout_minutes": 5
        });
        let timeout_minutes = optional_i64(&args, "timeout_minutes");
        let timeout_secs = timeout_minutes.map(|m| (m * 60) as u64).unwrap_or(180);
        assert_eq!(timeout_secs, 300);
    }

    #[test]
    fn secretsdump_timeout_1_minute() {
        let timeout_minutes: Option<i64> = Some(1);
        let timeout_secs = timeout_minutes.map(|m| (m * 60) as u64).unwrap_or(180);
        assert_eq!(timeout_secs, 60);
    }

    #[test]
    fn secretsdump_kerberos_mode_default_false() {
        let args = json!({
            "target": "192.168.58.1",
            "username": "admin"
        });
        let use_kerberos = optional_bool(&args, "no_pass").unwrap_or(false);
        assert!(!use_kerberos);
    }

    #[test]
    fn secretsdump_kerberos_mode_enabled() {
        let args = json!({
            "target": "192.168.58.1",
            "username": "admin",
            "no_pass": true,
            "ticket_path": "/tmp/admin.ccache"
        });
        let use_kerberos = optional_bool(&args, "no_pass").unwrap_or(false);
        let ticket_path = optional_str(&args, "ticket_path");
        assert!(use_kerberos);
        assert_eq!(ticket_path, Some("/tmp/admin.ccache"));
    }

    #[test]
    fn secretsdump_auth_with_password() {
        let (auth_string, extra_args) = credentials::impacket_auth(
            Some("contoso.local"),
            "admin",
            Some("P@ss"),
            None,
            "192.168.58.1",
        );
        assert_eq!(auth_string, "contoso.local/admin:P@ss@192.168.58.1");
        assert!(extra_args.is_empty());
    }

    #[test]
    fn secretsdump_auth_with_hash() {
        let (auth_string, extra_args) = credentials::impacket_auth(
            Some("contoso.local"),
            "admin",
            None,
            Some("aabbccdd"),
            "192.168.58.1",
        );
        assert_eq!(auth_string, "contoso.local/admin@192.168.58.1");
        assert_eq!(extra_args, vec!["-hashes", ":aabbccdd"]);
    }

    #[test]
    fn secretsdump_optional_domain() {
        let args = json!({
            "target": "192.168.58.1",
            "username": "admin"
        });
        assert!(optional_str(&args, "domain").is_none());
    }

    #[test]
    fn secretsdump_optional_dc_ip() {
        let args = json!({
            "target": "192.168.58.1",
            "username": "admin",
            "dc_ip": "192.168.58.2"
        });
        assert_eq!(optional_str(&args, "dc_ip"), Some("192.168.58.2"));
    }

    // --- mock executor tests ---

    use crate::executor::mock;

    #[tokio::test]
    async fn secretsdump_password_auth_executes() {
        mock::push(mock::success());
        let args = json!({
            "target": "192.168.58.1", "username": "admin",
            "password": "P@ss", "domain": "contoso.local"
        });
        assert!(super::secretsdump(&args).await.is_ok());
    }

    #[tokio::test]
    async fn secretsdump_hash_auth_executes() {
        mock::push(mock::success());
        let args = json!({
            "target": "192.168.58.1", "username": "admin",
            "hash": "aabbccdd", "domain": "contoso.local"
        });
        assert!(super::secretsdump(&args).await.is_ok());
    }

    #[tokio::test]
    async fn secretsdump_kerberos_auth_executes() {
        mock::push(mock::success());
        let args = json!({
            "target": "192.168.58.1", "username": "admin",
            "no_pass": true, "ticket_path": "/tmp/admin.ccache"
        });
        assert!(super::secretsdump(&args).await.is_ok());
    }

    #[tokio::test]
    async fn secretsdump_with_dc_ip_executes() {
        mock::push(mock::success());
        let args = json!({
            "target": "192.168.58.1", "username": "admin",
            "password": "P@ss", "dc_ip": "192.168.58.2"
        });
        assert!(super::secretsdump(&args).await.is_ok());
    }

    #[tokio::test]
    async fn secretsdump_custom_timeout_executes() {
        mock::push(mock::success());
        let args = json!({
            "target": "192.168.58.1", "username": "admin",
            "password": "P@ss", "timeout_minutes": 10
        });
        assert!(super::secretsdump(&args).await.is_ok());
    }
}
