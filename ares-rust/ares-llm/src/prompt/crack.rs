//! Crack task prompt generation.

use serde_json::Value;
use tera::Context;

use super::templates::{render_template_with_context, TASK_CRACK};

pub(crate) fn generate_crack_prompt(task_id: &str, payload: &Value) -> anyhow::Result<String> {
    let mut ctx = Context::new();
    ctx.insert("task_id", task_id);
    ctx.insert(
        "hash_type",
        payload["hash_type"].as_str().unwrap_or("unknown"),
    );
    ctx.insert("hash_value", payload["hash_value"].as_str().unwrap_or(""));

    let username = payload["username"].as_str().unwrap_or("");
    if !username.is_empty() {
        ctx.insert("username", username);
    }

    let domain = payload["domain"].as_str().unwrap_or("");
    if !domain.is_empty() {
        ctx.insert("domain", domain);
    }

    render_template_with_context(TASK_CRACK, &ctx)
}
