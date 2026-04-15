//! Low-hanging fruit and share spider prompt branches.

use tera::Context;

use crate::prompt::helpers::insert_state_context;
use crate::prompt::templates::{
    render_template_with_context, TASK_CREDACCESS_LOW_HANGING_NO_CREDS,
    TASK_CREDACCESS_LOW_HANGING_WITH_CREDS, TASK_CREDACCESS_SHARE_SPIDER,
};
use crate::prompt::StateSnapshot;

use super::Params;

/// Generate low-hanging fruit prompt WITH credentials (Branch 2).
pub(super) fn generate_with_creds(
    task_id: &str,
    p: &Params<'_>,
    state: Option<&StateSnapshot>,
) -> anyhow::Result<String> {
    let dc_ip = p.dc_ip;

    let mut ctx = Context::new();
    ctx.insert("task_id", task_id);
    ctx.insert("domain", p.domain);
    ctx.insert(
        "dc_ip_display",
        if dc_ip.is_empty() { "N/A" } else { dc_ip },
    );
    ctx.insert(
        "user_display",
        if p.username.is_empty() {
            "N/A"
        } else {
            p.username
        },
    );
    ctx.insert("password", p.password);
    insert_state_context(&mut ctx, state, "credential_access", Some(dc_ip));

    render_template_with_context(TASK_CREDACCESS_LOW_HANGING_WITH_CREDS, &ctx)
}

/// Generate low-hanging fruit prompt WITHOUT credentials (Branch 6).
pub(super) fn generate_without_creds(
    task_id: &str,
    p: &Params<'_>,
    state: Option<&StateSnapshot>,
) -> anyhow::Result<String> {
    let dc_ip = p.dc_ip;

    let mut ctx = Context::new();
    ctx.insert("task_id", task_id);
    ctx.insert("domain", p.domain);
    ctx.insert(
        "dc_ip_display",
        if dc_ip.is_empty() { "N/A" } else { dc_ip },
    );
    insert_state_context(&mut ctx, state, "credential_access", Some(dc_ip));

    render_template_with_context(TASK_CREDACCESS_LOW_HANGING_NO_CREDS, &ctx)
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

    let mut ctx = Context::new();
    ctx.insert("task_id", task_id);
    ctx.insert("target_ip", target_ip);
    ctx.insert("domain", p.domain);
    ctx.insert("username", p.username);
    ctx.insert("password", p.password);
    ctx.insert("share_hint", share_hint);
    ctx.insert("share_param", share_param);
    insert_state_context(&mut ctx, state, "credential_access", Some(target_ip));

    Some(render_template_with_context(
        TASK_CREDACCESS_SHARE_SPIDER,
        &ctx,
    ))
}
