//! Coercion task prompt generation.

use serde_json::Value;
use tera::Context;

use super::helpers::insert_state_context;
use super::templates::{render_template_with_context, TASK_COERCION};
use super::StateSnapshot;

pub(crate) fn generate_coercion_prompt(
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
    ctx.insert("listener_ip", payload["listener_ip"].as_str().unwrap_or(""));

    let techniques: Vec<&str> = payload["techniques"]
        .as_array()
        .map(|arr| arr.iter().filter_map(|v| v.as_str()).collect())
        .unwrap_or_default();
    if !techniques.is_empty() {
        ctx.insert("techniques", &techniques);
    }

    insert_state_context(&mut ctx, state, "coercion", payload["target_ip"].as_str());

    render_template_with_context(TASK_COERCION, &ctx)
}
