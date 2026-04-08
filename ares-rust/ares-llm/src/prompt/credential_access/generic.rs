//! Generic fallback and technique-with-credentials prompt branches.

use std::collections::HashMap;
use std::fmt::Write;

use serde_json::Value;

use crate::prompt::helpers::{cred_display_str, cred_param_str};
use crate::prompt::state_context::format_state_context;
use crate::prompt::StateSnapshot;

use super::Params;

/// Try to generate a technique enforcement prompt WITH credentials (Branch 7).
/// Returns `Some` if conditions match, `None` otherwise.
pub(super) fn try_generate_with_creds(
    task_id: &str,
    payload: &Value,
    p: &Params<'_>,
    state: Option<&StateSnapshot>,
) -> Option<anyhow::Result<String>> {
    if p.techniques.is_empty() || !p.has_creds {
        return None;
    }

    let dc_ip = p.dc_ip;
    let domain = p.domain;
    let username = p.username;
    let cred_param = cred_param_str(payload, p.hash_value);
    let cred_display = cred_display_str(payload, p.hash_value);

    let technique_map: HashMap<&str, String> = [
        (
            "sysvol_script_search",
            format!(
                "sysvol_script_search(target='{dc_ip}', username='{username}', \
                 {cred_param}, domain='{domain}') \
                 - ~2 seconds, finds hardcoded passwords in login scripts"
            ),
        ),
        (
            "gpp_password_finder",
            format!(
                "gpp_password_finder(target='{dc_ip}', username='{username}', \
                 {cred_param}, domain='{domain}') \
                 - ~2 seconds, finds GPP/cpassword credentials"
            ),
        ),
        (
            "ldap_search_descriptions",
            format!(
                "ldap_search_descriptions(target='{dc_ip}', username='{username}', \
                 {cred_param}, domain='{domain}') \
                 - finds passwords in LDAP description fields"
            ),
        ),
        (
            "kerberoast",
            format!(
                "kerberoast(domain='{domain}', username='{username}', \
                 {cred_param}, dc_ip='{dc_ip}') \
                 - service account hashes (uses correct DC for the domain)"
            ),
        ),
        (
            "secretsdump",
            format!(
                "secretsdump(target='{dc_ip}', username='{username}', \
                 {cred_param}, domain='{domain}') \
                 - dump hashes (requires admin)"
            ),
        ),
        (
            "lsassy",
            format!(
                "lsassy(target='{dc_ip}', username='{username}', \
                 {cred_param}, domain='{domain}') \
                 - LSASS memory dump"
            ),
        ),
        (
            "laps_dump",
            format!(
                "laps_dump(target='{dc_ip}', username='{username}', \
                 {cred_param}, domain='{domain}') \
                 - LAPS local admin passwords"
            ),
        ),
    ]
    .into_iter()
    .collect();

    let mut instructions = Vec::new();
    for (i, technique) in p.techniques.iter().enumerate() {
        let idx = i + 1;
        if let Some(desc) = technique_map.get(technique.as_str()) {
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
        "**MANDATORY TECHNIQUE EXECUTION**\n\n\
         Domain: {domain}\n\
         DC IP: {dc_ip_display}\n\
         Targets: {targets_display}\n\
         Username: {user_display}\n\
         Credential: {cred_display}\n\
         Task ID: {task_id}\n\n\
         **CRITICAL: YOU MUST EXECUTE THESE TECHNIQUES IN ORDER:**\n\
         **DO NOT run smb_sweep, kerberos_user_enum, or other recon first!**\n\
         **These techniques are FAST (~2-5 seconds each) and HIGH VALUE.**\n\n\
         {instructions_text}\n\n\
         **WORKFLOW:**\n\
         1. Execute EACH technique above in order - they are FAST\n\
         2. Report ANY credentials found immediately\n\
         3. Only after completing ALL assigned techniques, mark task complete\n\n\
         **DO NOT:**\n\
         - Run smb_sweep (wastes 5+ minutes)\n\
         - Run kerberos_user_enum_noauth (not your job)\n\
         - Do additional recon before completing assigned techniques\n",
        dc_ip_display = if dc_ip.is_empty() { "N/A" } else { dc_ip },
        user_display = if username.is_empty() { "N/A" } else { username },
        instructions_text = instructions.join("\n"),
    );
    if let Some(s) = state {
        prompt.push_str(&format_state_context(s, "credential_access", Some(dc_ip)));
    }
    Some(Ok(prompt))
}

/// Generate the generic fallback prompt.
pub(super) fn generate_fallback(
    task_id: &str,
    payload: &Value,
    p: &Params<'_>,
    state: Option<&StateSnapshot>,
) -> anyhow::Result<String> {
    let dc_ip = p.dc_ip;
    let domain = p.domain;
    let username = p.username;
    let password = p.password;
    let reason = p.reason;

    let cred_type = if p.has_password {
        "password"
    } else if p.has_hash {
        if p.hash_is_pth {
            "hash"
        } else {
            "hash (non-NTLM)"
        }
    } else {
        "none"
    };
    let hash_note = if p.has_hash && !p.hash_is_pth {
        "NOTE: Provided hash is not NTLM pass-the-hash compatible; \
         do not attempt secretsdump/lsassy with it.\n"
    } else {
        ""
    };
    let cred_value = if p.has_password {
        password
    } else {
        p.hash_value.unwrap_or("N/A")
    };
    let source = payload
        .get("credential_source")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let hash_type = payload
        .get("hash_type")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let techniques_display = if p.techniques.is_empty() {
        "auto-select".to_string()
    } else {
        p.techniques.join(", ")
    };
    let targets_display = if p.targets.is_empty() {
        "N/A".to_string()
    } else {
        p.targets.join(", ")
    };

    let mut prompt = format!(
        "Perform credential access against the target environment:\n\
         Domain: {domain}\n\
         Targets: {targets_display}\n\
         DC IP: {dc_ip_display}\n\
         Username: {user_display}\n\
         Credential ({cred_type}): {cred_value}\n",
        dc_ip_display = if dc_ip.is_empty() { "N/A" } else { dc_ip },
        user_display = if username.is_empty() { "N/A" } else { username },
    );
    if !hash_type.is_empty() {
        let _ = writeln!(prompt, "Hash Type: {hash_type}");
    }
    if !source.is_empty() {
        let _ = writeln!(prompt, "Credential Source: {source}");
    }
    if !reason.is_empty() {
        let _ = writeln!(prompt, "Reason: {reason}");
    }
    let _ = writeln!(prompt, "Techniques: {techniques_display}");
    let _ = writeln!(prompt, "Task ID: {task_id}\n");
    if !hash_note.is_empty() {
        let _ = writeln!(prompt, "{hash_note}");
    }
    prompt.push_str(
        "Use the exact credential value above; do not substitute placeholders. \
         If DC IP is provided, pass -dc-ip to Kerberos/LDAP tools to avoid DNS issues. \
         **PRIORITY ORDER when creds available:**\n\
         1. gpp_password_finder + sysvol_script_search (LOW HANGING FRUIT - run first!)\n\
         2. Kerberoast for service account hashes\n\
         3. secretsdump if admin access exists\n\
         4. LSASS dumping if viable\n\
         Report any hashes or credentials found.",
    );
    if let Some(s) = state {
        prompt.push_str(&format_state_context(s, "credential_access", Some(dc_ip)));
    }
    Ok(prompt)
}
