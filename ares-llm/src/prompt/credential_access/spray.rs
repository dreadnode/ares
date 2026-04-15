//! Username-as-password spray prompt branch.

use std::fmt::Write;

use tera::Context;

use crate::prompt::helpers::insert_state_context;
use crate::prompt::templates::{render_template_with_context, TASK_CREDACCESS_SPRAY};
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
    let username = p.username;
    let password = p.password;
    let mut cred_line = String::new();
    if !username.is_empty() && !password.is_empty() {
        write!(
            cred_line,
            "**Use these credentials for user enumeration:**\n\
             Username: {username}\n\
             Password: {password}\n"
        )
        .unwrap();
    }

    let mut ctx = Context::new();
    ctx.insert("task_id", task_id);
    ctx.insert("domain", p.domain);
    ctx.insert("dc_ip", dc_ip);
    ctx.insert(
        "dc_ip_display",
        if dc_ip.is_empty() { "N/A" } else { dc_ip },
    );
    ctx.insert("username", username);
    ctx.insert("password", password);
    if !cred_line.is_empty() {
        ctx.insert("cred_line", &cred_line);
    }
    insert_state_context(&mut ctx, state, "credential_access", Some(dc_ip));

    Some(render_template_with_context(TASK_CREDACCESS_SPRAY, &ctx))
}
