//! Technique enforcement prompt branch WITHOUT credentials.

use std::collections::HashMap;

use crate::prompt::state_context::format_state_context;
use crate::prompt::StateSnapshot;

use super::Params;

/// Try to generate a no-credential technique enforcement prompt (Branch 5).
/// Returns `Some` if conditions match, `None` otherwise.
pub(super) fn try_generate(
    task_id: &str,
    p: &Params<'_>,
    state: Option<&StateSnapshot>,
) -> Option<anyhow::Result<String>> {
    let no_cred_techniques = !p.has_password && !p.has_hash;
    if p.techniques.is_empty() || !no_cred_techniques {
        return None;
    }

    let dc_ip = p.dc_ip;
    let domain = p.domain;

    let no_cred_map: HashMap<&str, String> = [
        (
            "asrep_roast",
            format!(
                "asrep_roast(dc_ip='{dc_ip}', domain='{domain}') \
                 - find users without Kerberos pre-auth"
            ),
        ),
        (
            "username_as_password",
            format!(
                "username_as_password(target='{dc_ip}', domain='{domain}') \
                 - test if users have username=password (e.g., testuser:testuser)"
            ),
        ),
        (
            "password_spray",
            format!(
                "password_spray(target='{dc_ip}', domain='{domain}', \
                 password='Password1') - try common passwords"
            ),
        ),
        (
            "kerberos_user_enum_noauth",
            format!(
                "kerberos_user_enum_noauth(dc_ip='{dc_ip}', domain='{domain}') \
                 - enumerate valid usernames via Kerberos"
            ),
        ),
    ]
    .into_iter()
    .collect();

    let mut instructions = Vec::new();
    for (i, technique) in p.techniques.iter().enumerate() {
        let idx = i + 1;
        if let Some(desc) = no_cred_map.get(technique.as_str()) {
            instructions.push(format!("{idx}. {desc}"));
        } else {
            instructions.push(format!("{idx}. {technique}(...)"));
        }
    }

    if instructions.is_empty() {
        return None;
    }

    let targets_display = if p.targets.is_empty() {
        "N/A".to_string()
    } else {
        p.targets.join(", ")
    };
    let mut prompt = format!(
        "**MANDATORY TECHNIQUE EXECUTION (NO CREDENTIALS)**\n\n\
         Domain: {domain}\n\
         DC IP: {dc_ip_display}\n\
         Targets: {targets_display}\n\
         Task ID: {task_id}\n\n\
         **CRITICAL: YOU MUST EXECUTE THESE TECHNIQUES IN ORDER:**\n\
         **DO NOT run smb_sweep or other slow recon first!**\n\
         **Complete assigned techniques BEFORE doing anything else.**\n\n\
         {instructions_text}\n\n\
         **WORKFLOW:**\n\
         1. Execute EACH technique above in order\n\
         2. Report ANY credentials/hashes found immediately\n\
         3. Only after completing ALL assigned techniques, mark task complete\n\n\
         **DO NOT:**\n\
         - Run smb_sweep (wastes 5+ minutes, not your job)\n\
         - Do additional enumeration before completing assigned techniques\n",
        dc_ip_display = if dc_ip.is_empty() { "N/A" } else { dc_ip },
        instructions_text = instructions.join("\n"),
    );
    if let Some(s) = state {
        prompt.push_str(&format_state_context(s, "credential_access", Some(dc_ip)));
    }
    Some(Ok(prompt))
}
