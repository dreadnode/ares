//! Task execution — run_agent_task dispatches to ares-tools.

use std::time::Duration;

use tracing::info;

use super::types::AgentResult;

/// Execute a tool natively in Rust via ares-tools.
///
/// The `task_type` is used as the tool name for dispatch. The `params` JSON
/// is passed directly as tool arguments.
pub async fn run_agent_task(
    task_type: &str,
    params: &serde_json::Value,
    _timeout: Duration,
) -> anyhow::Result<AgentResult> {
    info!(tool = task_type, "Executing tool natively");

    let output = ares_tools::dispatch(task_type, params).await?;

    let combined = output.combined();
    let error = if output.success {
        None
    } else {
        Some(format!("tool exited with code {:?}", output.exit_code))
    };

    Ok(AgentResult {
        output: combined,
        error,
        usage: None, // No LLM usage for direct tool execution
    })
}
