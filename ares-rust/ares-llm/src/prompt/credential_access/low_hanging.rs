//! Low-hanging fruit and share spider prompt branches.

use crate::prompt::state_context::format_state_context;
use crate::prompt::StateSnapshot;

use super::Params;

/// Generate low-hanging fruit prompt WITH credentials (Branch 2).
pub(super) fn generate_with_creds(
    task_id: &str,
    p: &Params<'_>,
    state: Option<&StateSnapshot>,
) -> anyhow::Result<String> {
    let dc_ip = p.dc_ip;
    let domain = p.domain;
    let username = p.username;
    let password = p.password;
    let mut prompt = format!(
        "Perform LOW HANGING FRUIT credential harvesting:\n\
         Domain: {domain}\n\
         DC IP: {dc_ip_display}\n\
         Username: {user_display}\n\
         Password: {password}\n\
         Task ID: {task_id}\n\n\
         **EXECUTE IN THIS ORDER:**\n\
         1. gpp_password_finder(target=DC_IP, username=USER, password=PASS, domain=DOMAIN)\n\
         2. sysvol_script_search(target=DC_IP, username=USER, password=PASS, domain=DOMAIN)\n\
         3. ldap_search_descriptions(...) - check for passwords in LDAP descriptions\n\
         4. username_as_password(...) - check for user=password accounts\n\n\
         These are HIGH SUCCESS RATE techniques that find hardcoded credentials.\n\
         Report any credentials found immediately.",
        dc_ip_display = if dc_ip.is_empty() { "N/A" } else { dc_ip },
        user_display = if username.is_empty() { "N/A" } else { username },
    );
    if let Some(s) = state {
        prompt.push_str(&format_state_context(s, "credential_access", Some(dc_ip)));
    }
    Ok(prompt)
}

/// Generate low-hanging fruit prompt WITHOUT credentials (Branch 6).
pub(super) fn generate_without_creds(
    task_id: &str,
    p: &Params<'_>,
    state: Option<&StateSnapshot>,
) -> anyhow::Result<String> {
    let dc_ip = p.dc_ip;
    let domain = p.domain;
    let mut prompt = format!(
        "Perform LOW HANGING FRUIT credential discovery (NO CREDENTIALS):\n\
         Domain: {domain}\n\
         DC IP: {dc_ip_display}\n\
         Task ID: {task_id}\n\n\
         **CRITICAL: These techniques work WITHOUT credentials to discover passwords:**\n\
         1. username_as_password(target=DC_IP, domain=DOMAIN) - HIGH SUCCESS RATE\n\
            Tests if users have username=password (e.g., testuser:testuser)\n\
            Zero lockout risk, one attempt per user\n\n\
         2. password_spray - YOU MUST CALL THIS ONCE FOR EACH PASSWORD:\n\
            password_spray(target=DC_IP, domain=DOMAIN, password='Password1')\n\
            password_spray(target=DC_IP, domain=DOMAIN, password='Welcome1')\n\
            password_spray(target=DC_IP, domain=DOMAIN, password='Summer2024')\n\
            password_spray(target=DC_IP, domain=DOMAIN, password='Company123')\n\
            password_spray(target=DC_IP, domain=DOMAIN, password='Passw0rd!')\n\
            **Call spray for EACH password above - common weak passwords**\n\n\
         3. password_policy(target=DC_IP, domain=DOMAIN) - Check lockout before spraying\n\n\
         These are the FIRST techniques to run when you have no credentials.\n\
         Report any credentials found immediately.",
        dc_ip_display = if dc_ip.is_empty() { "N/A" } else { dc_ip },
    );
    if let Some(s) = state {
        prompt.push_str(&format_state_context(s, "credential_access", Some(dc_ip)));
    }
    Ok(prompt)
}

/// Try to generate a share spider prompt (Branch 4).
/// Returns `Some` if conditions match, `None` otherwise.
pub(super) fn try_share_spider(
    task_id: &str,
    p: &Params<'_>,
    state: Option<&StateSnapshot>,
) -> Option<anyhow::Result<String>> {
    let is_share_spider = p.techniques.iter().any(|t| t == "share_spider");
    if !(is_share_spider && p.has_password) {
        return None;
    }

    let target_ip = p.targets.first().copied().unwrap_or("");
    let domain = p.domain;
    let username = p.username;
    let password = p.password;
    let reason = p.reason;
    let share_name = if reason.to_lowercase().contains("auto_share_spider_") {
        reason
            .to_lowercase()
            .split("auto_share_spider_")
            .last()
            .unwrap_or("")
            .to_string()
    } else {
        String::new()
    };
    let share_hint = if share_name.is_empty() {
        "enumerate all readable shares"
    } else {
        &share_name
    };
    let share_param = if share_name.is_empty() {
        "all"
    } else {
        &share_name
    };

    let mut prompt = format!(
        "**SHARE SPIDER TASK - Search SMB shares for credentials**\n\n\
         Target: {target_ip}\n\
         Domain: {domain}\n\
         Username: {username}\n\
         Password: {password}\n\
         Share hint: {share_hint}\n\
         Task ID: {task_id}\n\n\
         **INSTRUCTIONS:**\n\
         1. Use smbclient_spider(target='{target_ip}', share='{share_param}', \
            username='{username}', password='{password}', domain='{domain}')\n\
         2. Look for interesting files containing credentials:\n\
            - *.txt files (passwords, connection strings)\n\
            - *.xml, *.ini, *.config files (configuration with creds)\n\
            - *.ps1, *.bat, *.cmd files (scripts with hardcoded passwords)\n\
         3. If files are found, use smbclient_spider to retrieve them\n\
         4. Parse downloaded files for credentials\n\n\
         **COMMON FINDINGS:**\n\
         - Service account passwords in config files\n\
         - Database connection strings with credentials\n\
         - Admin passwords in deployment scripts\n\
         - User credentials in text files (e.g., secret.txt)\n\n\
         Report any credentials found immediately!"
    );
    if let Some(s) = state {
        prompt.push_str(&format_state_context(
            s,
            "credential_access",
            Some(target_ip),
        ));
    }
    Some(Ok(prompt))
}
