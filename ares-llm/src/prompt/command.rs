//! Command task prompt generation.

use serde_json::Value;
use tera::Context;

use super::templates::{render_template_with_context, TASK_COMMAND};

pub(crate) fn generate_command_prompt(task_id: &str, payload: &Value) -> anyhow::Result<String> {
    let mut ctx = Context::new();
    ctx.insert("task_id", task_id);
    ctx.insert("command", payload["command"].as_str().unwrap_or("unknown"));

    render_template_with_context(TASK_COMMAND, &ctx)
}
