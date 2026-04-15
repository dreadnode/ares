//! Recon task prompt generation.

use serde_json::Value;
use tera::Context;

use super::helpers::{insert_credential_context, insert_state_context};
use super::templates::{render_template_with_context, TASK_RECON};
use super::StateSnapshot;

pub(crate) fn generate_recon_prompt(
    task_id: &str,
    payload: &Value,
    state: Option<&StateSnapshot>,
) -> anyhow::Result<String> {
    let mut ctx = Context::new();
    ctx.insert("task_id", task_id);
    ctx.insert(
        "target_ip",
        payload["target_ip"].as_str().unwrap_or("unknown"),
    );

    let domain = payload["domain"].as_str().unwrap_or("");
    if !domain.is_empty() {
        ctx.insert("domain", domain);
    }

    insert_credential_context(&mut ctx, payload);

    let techniques: Vec<&str> = payload["techniques"]
        .as_array()
        .map(|arr| arr.iter().filter_map(|v| v.as_str()).collect())
        .unwrap_or_default();
    if !techniques.is_empty() {
        ctx.insert("techniques", &techniques);
    }

    insert_state_context(&mut ctx, state, "recon", payload["target_ip"].as_str());

    render_template_with_context(TASK_RECON, &ctx)
}
