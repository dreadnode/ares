//! Regression tests for the tracing spans emitted by the agent loop.
//!
//! These guard against silent loss of telemetry — e.g. someone removing a
//! span attribute, swapping `task.id` and `op.id`, or forgetting to record
//! token usage on the `llm.call` span.

mod common;

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use anyhow::Result;

use ares_llm::{
    run_agent_loop, AgentLoopConfig, LlmError, LlmProvider, LlmRequest, LlmResponse,
    RunAgentLoopParams, StopReason, TokenUsage, ToolCall, ToolDefinition, ToolDispatcher,
    ToolExecResult,
};

use common::span_capture::install_capture;

struct MockProvider {
    responses: Mutex<VecDeque<LlmResponse>>,
}

impl MockProvider {
    fn new(responses: Vec<LlmResponse>) -> Self {
        Self {
            responses: Mutex::new(VecDeque::from(responses)),
        }
    }
}

#[async_trait::async_trait]
impl LlmProvider for MockProvider {
    async fn chat(&self, _request: &LlmRequest) -> Result<LlmResponse, LlmError> {
        let mut q = self.responses.lock().unwrap();
        q.pop_front()
            .ok_or_else(|| LlmError::Other(anyhow::anyhow!("no responses queued")))
    }

    fn name(&self) -> &str {
        "mock"
    }
}

struct NoopDispatcher;

#[async_trait::async_trait]
impl ToolDispatcher for NoopDispatcher {
    async fn dispatch_tool(
        &self,
        _role: &str,
        _task_id: &str,
        _call: &ToolCall,
    ) -> Result<ToolExecResult> {
        Ok(ToolExecResult {
            output: "noop".into(),
            error: None,
            discoveries: None,
            failure_kind: None,
        })
    }
}

fn default_config() -> AgentLoopConfig {
    AgentLoopConfig {
        model: "mock-model".into(),
        max_steps: 5,
        max_tokens: 4096,
        temperature: None,
        retry: ares_llm::agent_loop::RetryConfig {
            max_retries: 0,
            base_delay_ms: 10,
            max_delay_ms: 100,
        },
        context: ares_llm::agent_loop::ContextConfig {
            max_context_tokens: 0,
            max_tool_output_chars: 0,
            min_recent_messages: 10,
            ..ares_llm::agent_loop::ContextConfig::default()
        },
        max_tool_calls_per_name: 10,
        ..AgentLoopConfig::default()
    }
}

fn ok_usage() -> TokenUsage {
    TokenUsage {
        input_tokens: 11,
        output_tokens: 23,
        cache_creation_input_tokens: 5,
        cache_read_input_tokens: 7,
    }
}

fn end_turn_response(content: &str) -> LlmResponse {
    LlmResponse {
        content: content.into(),
        tool_calls: vec![],
        stop_reason: StopReason::EndTurn,
        usage: ok_usage(),
    }
}

#[tokio::test]
async fn agent_loop_span_carries_op_id_and_task_id_separately() {
    // agent.loop must carry op.id and task_id as separate, distinct fields.
    let (_g, capture) = install_capture();

    std::env::set_var("ARES_OPERATION_ID", "op-test-span-1");

    let provider = MockProvider::new(vec![end_turn_response("done.")]);
    let dispatcher = Arc::new(NoopDispatcher);
    let config = default_config();
    let _ = run_agent_loop(RunAgentLoopParams {
        provider: &provider,
        dispatcher,
        config: &config,
        system_prompt: "system",
        task_prompt: "task",
        role: "recon",
        task_id: "task-span-1",
        tools: &Vec::<ToolDefinition>::new(),
        callback_handler: None,
        hostname_map: None,
    })
    .await;

    std::env::remove_var("ARES_OPERATION_ID");

    let span = capture
        .find("agent.loop")
        .expect("agent.loop span should be emitted");
    assert_eq!(span.field("task.id"), Some("task-span-1"));
    assert_eq!(span.field("op.id"), Some("op-test-span-1"));
    assert_eq!(span.field("agent.role"), Some("recon"));
    assert_eq!(span.field("agent.model"), Some("mock-model"));
    // op.id and task.id must not be conflated
    assert_ne!(span.field("op.id"), span.field("task.id"));
}

#[tokio::test]
async fn llm_call_span_records_tokens_duration_and_stop_reason() {
    let (_g, capture) = install_capture();

    let provider = MockProvider::new(vec![end_turn_response("hello")]);
    let dispatcher = Arc::new(NoopDispatcher);
    let config = default_config();
    let _ = run_agent_loop(RunAgentLoopParams {
        provider: &provider,
        dispatcher,
        config: &config,
        system_prompt: "system",
        task_prompt: "task",
        role: "recon",
        task_id: "task-llm-span",
        tools: &Vec::<ToolDefinition>::new(),
        callback_handler: None,
        hostname_map: None,
    })
    .await;

    let calls = capture.find_all("llm.call");
    assert!(!calls.is_empty(), "llm.call span should be emitted");
    let call = &calls[0];
    assert_eq!(call.field("llm.attempt"), Some("0"));
    assert_eq!(call.field("llm.input_tokens"), Some("11"));
    assert_eq!(call.field("llm.output_tokens"), Some("23"));
    assert_eq!(call.field("llm.cache_read_tokens"), Some("7"));
    assert_eq!(call.field("llm.cache_creation_tokens"), Some("5"));
    assert_eq!(call.field("task.id"), Some("task-llm-span"));
    assert!(
        call.field("llm.duration_ms").is_some(),
        "llm.duration_ms must be recorded"
    );
    let stop = call.field("llm.stop_reason").unwrap_or_default();
    assert!(
        stop.contains("EndTurn"),
        "expected stop_reason=EndTurn, got {stop:?}"
    );
    // Successful call should not record an error
    assert!(call.field("llm.error").is_none());
    assert_eq!(call.field("llm.tool_count"), Some("0"));
}

struct AlwaysAuthErrorProvider;

#[async_trait::async_trait]
impl LlmProvider for AlwaysAuthErrorProvider {
    async fn chat(&self, _request: &LlmRequest) -> Result<LlmResponse, LlmError> {
        Err(LlmError::AuthError("invalid key".into()))
    }
    fn name(&self) -> &str {
        "auth-err"
    }
}

#[tokio::test]
async fn llm_call_span_records_error_on_failure() {
    let (_g, capture) = install_capture();

    let provider = AlwaysAuthErrorProvider;
    let dispatcher = Arc::new(NoopDispatcher);
    let config = default_config();
    let _ = run_agent_loop(RunAgentLoopParams {
        provider: &provider,
        dispatcher,
        config: &config,
        system_prompt: "system",
        task_prompt: "task",
        role: "recon",
        task_id: "task-err",
        tools: &Vec::<ToolDefinition>::new(),
        callback_handler: None,
        hostname_map: None,
    })
    .await;

    let call = capture
        .find("llm.call")
        .expect("llm.call span emitted on failure too");
    let err = call
        .field("llm.error")
        .expect("llm.error must be recorded on failure");
    assert!(
        err.contains("invalid key") || err.contains("AuthError"),
        "expected error message in span, got: {err:?}"
    );
    // Token fields stay unset on error — they are recorded only on success.
    assert!(call.field("llm.input_tokens").is_none());
}

struct RateThenSuccessProvider {
    failures: std::sync::atomic::AtomicU32,
    cap: u32,
    success: Mutex<Option<LlmResponse>>,
}

#[async_trait::async_trait]
impl LlmProvider for RateThenSuccessProvider {
    async fn chat(&self, _request: &LlmRequest) -> Result<LlmResponse, LlmError> {
        let n = self
            .failures
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        if n < self.cap {
            Err(LlmError::RateLimited {
                retry_after_ms: Some(5),
            })
        } else {
            Ok(self.success.lock().unwrap().take().unwrap())
        }
    }
    fn name(&self) -> &str {
        "rate-then-ok"
    }
}

#[tokio::test]
async fn llm_call_span_per_retry_attempt() {
    // Each retry attempt must produce its own llm.call span — otherwise
    // wall-clock duration of the successful call gets inflated by retry waits.
    let (_g, capture) = install_capture();

    let provider = RateThenSuccessProvider {
        failures: std::sync::atomic::AtomicU32::new(0),
        cap: 2,
        success: Mutex::new(Some(end_turn_response("ok"))),
    };
    let dispatcher = Arc::new(NoopDispatcher);
    let mut config = default_config();
    config.retry = ares_llm::agent_loop::RetryConfig {
        max_retries: 5,
        base_delay_ms: 1,
        max_delay_ms: 10,
    };

    let _ = run_agent_loop(RunAgentLoopParams {
        provider: &provider,
        dispatcher,
        config: &config,
        system_prompt: "system",
        task_prompt: "task",
        role: "recon",
        task_id: "task-retry",
        tools: &Vec::<ToolDefinition>::new(),
        callback_handler: None,
        hostname_map: None,
    })
    .await;

    let calls = capture.find_all("llm.call");
    // 2 failures + 1 success = 3 spans
    assert_eq!(
        calls.len(),
        3,
        "expected one llm.call span per attempt, got {}",
        calls.len()
    );
    let attempts: Vec<&str> = calls
        .iter()
        .filter_map(|s| s.field("llm.attempt"))
        .collect();
    assert!(attempts.contains(&"0"));
    assert!(attempts.contains(&"1"));
    assert!(attempts.contains(&"2"));
}
