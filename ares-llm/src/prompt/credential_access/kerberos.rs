//! Kerberos ticket-based secretsdump prompt branch.

use tera::Context;

use crate::prompt::helpers::insert_state_context;
use crate::prompt::templates::{render_template_with_context, TASK_CREDACCESS_KERBEROS};
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

    let mut ctx = Context::new();
    ctx.insert("task_id", task_id);
    ctx.insert("target", target);
    ctx.insert("domain", domain);
    ctx.insert("user", user);
    ctx.insert("ticket", ticket);
    ctx.insert(
        "dc_ip_display",
        if dc_ip.is_empty() { "N/A" } else { dc_ip },
    );
    if !dc_ip.is_empty() {
        ctx.insert("dc_ip", dc_ip);
    }
    insert_state_context(&mut ctx, state, "credential_access", Some(target));

    Some(render_template_with_context(TASK_CREDACCESS_KERBEROS, &ctx))
}
