//! PyO3 bridge for calling into the Python ares agent.
//!
//! The worker binary delegates actual LLM agent execution to Python via PyO3.
//! This module handles GIL acquisition, Python module loading, timeout enforcement,
//! and result extraction.
//!
//! When compiled without the `python` feature, a mock implementation is used
//! that returns a placeholder result (useful for build verification and testing
//! the Rust task loop in isolation).

use std::time::Duration;

use serde_json::Value;
use tracing::{debug, info, warn};

/// Result from running a Python agent task.
#[derive(Debug, Clone)]
pub struct AgentResult {
    /// Raw text output from the agent.
    pub output: String,
    /// Whether the agent encountered an error.
    pub error: Option<String>,
    /// Token usage metrics from the LLM call.
    pub usage: Option<TokenUsage>,
}

/// LLM token usage counters.
#[derive(Debug, Clone, serde::Serialize)]
pub struct TokenUsage {
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub total_tokens: u64,
    /// Model name (e.g. "openai/gpt-4.1-mini"), extracted from the agent result.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
}

/// Run a Python agent task with timeout.
///
/// This is the main entry point called from the task loop. It:
/// 1. Acquires the GIL
/// 2. Calls `ares.core.worker.prompts.generate_prompt_from_task` to build the prompt
/// 3. Runs the agent via `agent.run(prompt)`
/// 4. Extracts the result text and usage metrics
/// 5. Releases the GIL
///
/// The timeout is enforced at the Rust level — if the Python call exceeds
/// `timeout`, the task is cancelled and an error is returned.
pub async fn run_agent_task(
    task_type: &str,
    params: &Value,
    timeout: Duration,
) -> anyhow::Result<AgentResult> {
    info!(
        task_type = task_type,
        timeout_secs = timeout.as_secs(),
        "Running agent task via Python bridge"
    );

    // The actual Python call is blocking (GIL), so we run it on a blocking
    // thread and wrap with a tokio timeout.
    let task_type = task_type.to_string();
    let params = params.clone();

    let result = tokio::time::timeout(
        timeout,
        tokio::task::spawn_blocking(move || call_python_agent(&task_type, &params)),
    )
    .await;

    match result {
        Ok(Ok(Ok(agent_result))) => Ok(agent_result),
        Ok(Ok(Err(e))) => Err(e),
        Ok(Err(join_err)) => Err(anyhow::anyhow!("Python task panicked: {join_err}")),
        Err(_) => Err(anyhow::anyhow!(
            "Task timeout: agent exceeded {}s limit",
            timeout.as_secs()
        )),
    }
}

// ─── Python feature: real PyO3 implementation ────────────────────────────────

#[cfg(feature = "python")]
fn call_python_agent(task_type: &str, params: &Value) -> anyhow::Result<AgentResult> {
    use pyo3::prelude::*;

    Python::with_gil(|py| {
        // Import the worker prompt generator
        let prompts_mod = py.import("ares.core.worker.prompts")?;
        let generate_fn = prompts_mod.getattr("generate_prompt_from_task_raw")?;

        // Build the prompt from task_type + params
        let params_json = serde_json::to_string(params)?;
        let prompt: Option<String> = generate_fn.call1((task_type, params_json))?.extract()?;

        let prompt = match prompt {
            Some(p) => p,
            None => {
                return Ok(AgentResult {
                    output: String::new(),
                    error: Some(format!("Unsupported task type: {task_type}")),
                    usage: None,
                });
            }
        };

        // Get the agent singleton and run it
        let worker_mod = py.import("ares.core.worker._worker")?;
        let get_agent_fn = worker_mod.getattr("get_current_agent")?;
        let agent = get_agent_fn.call0()?;

        // agent.run(prompt) is async — we need to run it in an event loop
        let asyncio = py.import("asyncio")?;
        let result = asyncio.call_method1("run", (agent.call_method1("run", (prompt,))?,))?;

        // Extract output text
        let output: String = result
            .getattr("output")
            .and_then(|o| o.extract())
            .unwrap_or_default();

        // Extract error if present
        let error: Option<String> = result
            .getattr("error")
            .and_then(|e| e.extract())
            .ok()
            .flatten();

        // Extract usage metrics
        let usage = extract_usage(py, &result);

        Ok(AgentResult {
            output,
            error,
            usage,
        })
    })
    .map_err(|e: PyErr| anyhow::anyhow!("Python error: {e}"))
}

#[cfg(feature = "python")]
fn extract_usage(py: pyo3::prelude::Python<'_>, result: &pyo3::PyAny) -> Option<TokenUsage> {
    let usage_obj = result.getattr("usage").ok()?;
    if usage_obj.is_none() {
        return None;
    }
    let input_tokens: u64 = usage_obj.getattr("input_tokens").ok()?.extract().ok()?;
    let output_tokens: u64 = usage_obj.getattr("output_tokens").ok()?.extract().ok()?;

    // Extract model name from result.agent.model (matches Python worker)
    let model: Option<String> = result
        .getattr("agent")
        .ok()
        .and_then(|agent| agent.getattr("model").ok())
        .and_then(|m| m.extract().ok());

    Some(TokenUsage {
        input_tokens,
        output_tokens,
        total_tokens: input_tokens + output_tokens,
        model,
    })
}

// ─── Mock fallback: no Python feature ────────────────────────────────────────

#[cfg(not(feature = "python"))]
fn call_python_agent(task_type: &str, params: &Value) -> anyhow::Result<AgentResult> {
    warn!(
        task_type = task_type,
        "Python feature not enabled — returning mock result"
    );
    debug!("Mock agent params: {params}");

    Ok(AgentResult {
        output: format!(
            "[MOCK] Would execute {task_type} task. \
             Python bridge not compiled (build with --features python)."
        ),
        error: None,
        usage: Some(TokenUsage {
            input_tokens: 0,
            output_tokens: 0,
            total_tokens: 0,
            model: None,
        }),
    })
}
