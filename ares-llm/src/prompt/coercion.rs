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
    let target_ip = coercion_target(payload);
    ctx.insert("target_ip", target_ip.unwrap_or("unknown"));
    ctx.insert("listener_ip", payload["listener_ip"].as_str().unwrap_or(""));

    let techniques = coercion_techniques(payload);
    if !techniques.is_empty() {
        ctx.insert("techniques", &techniques);
    }

    insert_state_context(&mut ctx, state, "coercion", target_ip);

    render_template_with_context(TASK_COERCION, &ctx)
}

fn coercion_target(payload: &Value) -> Option<&str> {
    payload["target_ip"]
        .as_str()
        .or_else(|| payload["relay_target"].as_str())
        .filter(|s| !s.is_empty())
}

fn coercion_techniques(payload: &Value) -> Vec<&str> {
    let mut techniques: Vec<&str> = payload["techniques"]
        .as_array()
        .map(|arr| arr.iter().filter_map(|v| v.as_str()).collect())
        .unwrap_or_default();
    if techniques.is_empty() {
        if let Some(single) = payload["technique"].as_str().filter(|s| !s.is_empty()) {
            techniques.push(single);
        }
    }
    techniques
}
