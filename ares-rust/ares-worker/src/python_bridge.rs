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
        let params_json = serde_json::to_string(params)
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(format!("JSON error: {e}")))?;
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
        let usage = extract_usage(&result);

        Ok(AgentResult {
            output,
            error,
            usage,
        })
    })
    .map_err(|e: PyErr| anyhow::anyhow!("Python error: {e}"))
}

#[cfg(feature = "python")]
fn extract_usage(result: &pyo3::Bound<'_, pyo3::types::PyAny>) -> Option<TokenUsage> {
    use pyo3::types::PyAnyMethods;

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
        .and_then(|agent: pyo3::Bound<'_, pyo3::types::PyAny>| agent.getattr("model").ok())
        .and_then(|m: pyo3::Bound<'_, pyo3::types::PyAny>| m.extract().ok());

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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    // ── Mock bridge tests (run without Python, default test suite) ────────

    #[tokio::test]
    async fn test_mock_agent_task_succeeds() {
        let result = run_agent_task(
            "recon_scan",
            &serde_json::json!({"target": "192.168.1.1"}),
            Duration::from_secs(30),
        )
        .await;
        assert!(
            result.is_ok(),
            "Mock agent task should succeed: {:?}",
            result.err()
        );
    }

    #[tokio::test]
    async fn test_mock_agent_task_returns_output() {
        let result = run_agent_task(
            "credential_access",
            &serde_json::json!({"method": "secretsdump"}),
            Duration::from_secs(30),
        )
        .await
        .unwrap();
        assert!(
            !result.output.is_empty(),
            "Mock result should have non-empty output"
        );
        assert!(
            result.error.is_none(),
            "Mock result should have no error, got: {:?}",
            result.error
        );
    }

    #[tokio::test]
    async fn test_mock_agent_task_includes_task_type() {
        let result = run_agent_task(
            "privesc",
            &serde_json::json!({"technique": "golden_ticket"}),
            Duration::from_secs(30),
        )
        .await
        .unwrap();
        assert!(
            result.output.contains("privesc"),
            "Mock output should reference the task type, got: {}",
            result.output
        );
    }

    #[tokio::test]
    async fn test_mock_agent_task_has_usage_metrics() {
        let result = run_agent_task("recon", &serde_json::json!({}), Duration::from_secs(30))
            .await
            .unwrap();
        assert!(
            result.usage.is_some(),
            "Mock result should include usage metrics"
        );
        let usage = result.usage.unwrap();
        assert_eq!(
            usage.total_tokens, 0,
            "Mock usage should report zero tokens"
        );
    }

    #[tokio::test]
    async fn test_mock_agent_task_empty_params() {
        let result = run_agent_task("recon", &serde_json::json!({}), Duration::from_secs(30)).await;
        assert!(result.is_ok(), "Should handle empty params");
    }

    #[tokio::test]
    async fn test_mock_agent_task_complex_params() {
        let params = serde_json::json!({
            "targets": ["192.168.1.1", "192.168.1.2"],
            "options": {
                "aggressive": true,
                "ports": [80, 443, 445, 3389]
            },
            "credentials": {
                "username": "admin",
                "domain": "contoso.local"
            }
        });
        let result = run_agent_task("recon_scan", &params, Duration::from_secs(30)).await;
        assert!(result.is_ok(), "Should handle complex params");
    }

    #[tokio::test]
    async fn test_mock_agent_task_different_types() {
        for task_type in &[
            "recon_scan",
            "credential_access",
            "privesc",
            "lateral_movement",
            "exploitation",
        ] {
            let result =
                run_agent_task(task_type, &serde_json::json!({}), Duration::from_secs(30)).await;
            assert!(
                result.is_ok(),
                "Task type '{task_type}' should succeed: {:?}",
                result.err()
            );
        }
    }

    #[tokio::test]
    async fn test_mock_agent_task_timeout_respected() {
        // The mock returns instantly, so even a short timeout should work.
        let result =
            run_agent_task("recon", &serde_json::json!({}), Duration::from_millis(100)).await;
        assert!(
            result.is_ok(),
            "Short timeout should not fail for instant mock: {:?}",
            result.err()
        );
    }

    // ── Struct tests ─────────────────────────────────────────────────────

    #[test]
    fn test_agent_result_clone() {
        let result = AgentResult {
            output: "test output".to_string(),
            error: None,
            usage: Some(TokenUsage {
                input_tokens: 100,
                output_tokens: 50,
                total_tokens: 150,
                model: Some("gpt-4.1".to_string()),
            }),
        };
        let cloned = result.clone();
        assert_eq!(cloned.output, result.output);
        assert_eq!(cloned.error, result.error);
        assert!(cloned.usage.is_some());
    }

    #[test]
    fn test_agent_result_debug() {
        let result = AgentResult {
            output: "test".to_string(),
            error: Some("oops".to_string()),
            usage: None,
        };
        // Debug trait should be implemented (derived).
        let debug_str = format!("{:?}", result);
        assert!(debug_str.contains("test"));
        assert!(debug_str.contains("oops"));
    }

    #[test]
    fn test_token_usage_serializes() {
        let usage = TokenUsage {
            input_tokens: 100,
            output_tokens: 50,
            total_tokens: 150,
            model: Some("openai/gpt-4.1-mini".to_string()),
        };
        let json = serde_json::to_string(&usage).unwrap();
        assert!(json.contains("\"input_tokens\":100"));
        assert!(json.contains("\"output_tokens\":50"));
        assert!(json.contains("\"total_tokens\":150"));
        assert!(json.contains("gpt-4.1-mini"));
    }

    #[test]
    fn test_token_usage_skips_none_model() {
        let usage = TokenUsage {
            input_tokens: 0,
            output_tokens: 0,
            total_tokens: 0,
            model: None,
        };
        let json = serde_json::to_string(&usage).unwrap();
        assert!(
            !json.contains("model"),
            "None model should be skipped in serialization, got: {json}"
        );
    }

    // ── Concurrency tests ────────────────────────────────────────────────

    #[tokio::test]
    async fn test_concurrent_mock_tasks_no_deadlock() {
        // Spawn several tasks concurrently to verify the mock bridge
        // does not introduce any deadlocks (e.g., from spawn_blocking).
        let mut handles = Vec::new();
        for i in 0..10 {
            let task_type = format!("task_{i}");
            handles.push(tokio::spawn(async move {
                run_agent_task(
                    &task_type,
                    &serde_json::json!({"index": i}),
                    Duration::from_secs(5),
                )
                .await
            }));
        }
        for (i, h) in handles.into_iter().enumerate() {
            let result = h.await.expect("Task should not panic");
            assert!(result.is_ok(), "Concurrent task {i} should succeed");
        }
    }

    // ── Feature-gated Python integration tests ───────────────────────────

    #[cfg(feature = "python")]
    mod python_integration {
        use super::*;

        #[tokio::test]
        #[ignore] // requires Python environment with ares package installed
        async fn test_worker_bridge_runs_task() {
            let result = run_agent_task(
                "recon_scan",
                &serde_json::json!({"target": "192.168.1.1"}),
                Duration::from_secs(60),
            )
            .await;
            assert!(
                result.is_ok(),
                "Real Python bridge should run a task: {:?}",
                result.err()
            );
            let agent_result = result.unwrap();
            assert!(
                !agent_result.output.is_empty(),
                "Real bridge should produce output"
            );
        }

        #[tokio::test]
        #[ignore] // requires Python environment with ares package installed
        async fn test_worker_bridge_timeout() {
            // Use an extremely short timeout to force a timeout error.
            let result = run_agent_task(
                "recon_scan",
                &serde_json::json!({"target": "192.168.1.1"}),
                Duration::from_nanos(1),
            )
            .await;
            assert!(result.is_err(), "Should timeout with nanosecond deadline");
            let err_msg = result.unwrap_err().to_string();
            assert!(
                err_msg.contains("timeout") || err_msg.contains("Timeout"),
                "Error should mention timeout, got: {err_msg}"
            );
        }

        #[tokio::test]
        #[ignore] // requires Python environment with ares package installed
        async fn test_concurrent_python_tasks_no_deadlock() {
            // Spawn multiple tasks concurrently to verify GIL doesn't deadlock.
            // This is the key integration test for GIL contention.
            let mut handles = Vec::new();
            for i in 0..4 {
                handles.push(tokio::spawn(async move {
                    run_agent_task(
                        "recon_scan",
                        &serde_json::json!({"target": format!("192.168.1.{}", i + 1)}),
                        Duration::from_secs(30),
                    )
                    .await
                }));
            }
            for (i, h) in handles.into_iter().enumerate() {
                let result = h.await.expect("Task should not panic");
                assert!(
                    result.is_ok(),
                    "Concurrent Python task {i} should succeed: {:?}",
                    result.err()
                );
            }
        }
    }
}
