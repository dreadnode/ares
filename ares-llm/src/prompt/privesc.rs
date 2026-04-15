//! Privilege escalation enumeration task prompt generation.

use serde_json::Value;
use tera::Context;

use super::helpers::{insert_credential_context, insert_state_context};
use super::templates::{render_template_with_context, TASK_PRIVESC_ENUMERATION};
use super::StateSnapshot;

pub(crate) fn generate_privesc_enumeration_prompt(
    task_id: &str,
    payload: &Value,
    state: Option<&StateSnapshot>,
) -> anyhow::Result<String> {
    let mut ctx = Context::new();
    ctx.insert("task_id", task_id);
    ctx.insert(
        "technique",
        payload["technique"].as_str().unwrap_or("enumeration"),
    );
    ctx.insert(
        "target_ip",
        payload["target_ip"].as_str().unwrap_or("unknown"),
    );

    let domain = payload["domain"].as_str().unwrap_or("");
    if !domain.is_empty() {
        ctx.insert("domain", domain);
    }

    insert_credential_context(&mut ctx, payload);
    insert_state_context(
        &mut ctx,
        state,
        "privesc_enumeration",
        payload["target_ip"].as_str(),
    );

    render_template_with_context(TASK_PRIVESC_ENUMERATION, &ctx)
}
