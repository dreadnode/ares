//! Username-as-password spray prompt branch.

use std::fmt::Write;

use crate::prompt::state_context::format_state_context;
use crate::prompt::StateSnapshot;

use super::Params;

/// Try to generate a username-as-password spray prompt (Branch 3).
/// Returns `Some` if the conditions match, `None` otherwise.
pub(super) fn try_generate(
    task_id: &str,
    p: &Params<'_>,
    state: Option<&StateSnapshot>,
) -> Option<anyhow::Result<String>> {
    let is_username_spray = p.techniques.iter().any(|t| t == "username_as_password")
        && p.reason.to_lowercase().contains("new_users");
    if !is_username_spray {
        return None;
    }

    let dc_ip = p.dc_ip;
    let domain = p.domain;
    let username = p.username;
    let password = p.password;
    let mut cred_line = String::new();
    if !username.is_empty() && !password.is_empty() {
        write!(
            cred_line,
            "**Use these credentials for user enumeration:**\n\
             Username: {username}\n\
             Password: {password}\n\n"
        )
        .unwrap();
    }
    let mut prompt = format!(
        "Perform USERNAME_AS_PASSWORD spray to find weak credentials:\n\
         Domain: {domain}\n\
         DC IP: {dc_ip_display}\n\
         Task ID: {task_id}\n\n\
         {cred_line}\
         **EXECUTE username_as_password:**\n\
         1. First save users: save_users_to_file(target='{dc_ip}', username='{username}', \
            password='{password}', domain='{domain}')\n\
         2. Then spray: username_as_password(target='{dc_ip}', domain='{domain}', \
            users_file='/tmp/users.txt')\n\n\
         This tests if users have username=password (e.g., testuser:testuser).\n\
         Zero lockout risk, one attempt per user.\n\
         Report any credentials found immediately.",
        dc_ip_display = if dc_ip.is_empty() { "N/A" } else { dc_ip },
    );
    if let Some(s) = state {
        prompt.push_str(&format_state_context(s, "credential_access", Some(dc_ip)));
    }
    Some(Ok(prompt))
}
