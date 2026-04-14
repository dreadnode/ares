//! ACL analysis task prompt generation.

use serde_json::Value;
use tera::Context;

use super::helpers::insert_state_context;
use super::templates::{render_template_with_context, TASK_ACL_ANALYSIS};
use super::StateSnapshot;

pub(crate) fn generate_acl_analysis_prompt(
    task_id: &str,
    payload: &Value,
    state: Option<&StateSnapshot>,
) -> anyhow::Result<String> {
    let mut ctx = Context::new();
    ctx.insert("task_id", task_id);

    if let Some(chain) = payload.get("chain") {
        ctx.insert(
            "chain_json",
            &serde_json::to_string_pretty(chain).unwrap_or_default(),
        );
    }

    insert_state_context(&mut ctx, state, "acl_analysis", None);

    render_template_with_context(TASK_ACL_ANALYSIS, &ctx)
}
