//! Integration tests for the agent loop using mock LLM and tool dispatcher.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use anyhow::Result;
use serde_json::json;

use ares_llm::{
    run_agent_loop, AgentLoopConfig, LlmError, LlmProvider, LlmRequest, LlmResponse, LoopEndReason,
    StopReason, TokenUsage, ToolCall, ToolDefinition, ToolDispatcher, ToolExecResult,
};

// ---------------------------------------------------------------------------
// Mock LLM provider
// ---------------------------------------------------------------------------

/// A mock LLM provider that returns pre-queued responses in order.
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
        let mut queue = self.responses.lock().unwrap();
        queue.pop_front().ok_or_else(|| {
            LlmError::Other(anyhow::anyhow!("MockProvider: no more queued responses"))
        })
    }

    fn name(&self) -> &str {
        "mock"
    }
}

// ---------------------------------------------------------------------------
// Mock tool dispatcher
// ---------------------------------------------------------------------------

/// A mock tool dispatcher that records calls and returns canned results.
struct MockDispatcher {
    dispatched: Mutex<Vec<ToolCall>>,
    results: Mutex<VecDeque<Result<ToolExecResult>>>,
}

impl MockDispatcher {
    fn new(results: Vec<Result<ToolExecResult>>) -> Self {
        Self {
            dispatched: Mutex::new(Vec::new()),
            results: Mutex::new(VecDeque::from(results)),
        }
    }

    fn dispatched_calls(&self) -> Vec<ToolCall> {
        self.dispatched.lock().unwrap().clone()
    }
}

#[async_trait::async_trait]
impl ToolDispatcher for MockDispatcher {
    async fn dispatch_tool(
        &self,
        _role: &str,
        _task_id: &str,
        call: &ToolCall,
    ) -> Result<ToolExecResult> {
        self.dispatched.lock().unwrap().push(call.clone());
        let mut queue = self.results.lock().unwrap();
        queue.pop_front().unwrap_or_else(|| {
            Ok(ToolExecResult {
                output: "default mock output".into(),
                error: None,
                discoveries: None,
            })
        })
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn default_config(max_steps: u32) -> AgentLoopConfig {
    AgentLoopConfig {
        model: "mock-model".into(),
        max_steps,
        max_tokens: 4096,
        temperature: None,
        retry: ares_llm::agent_loop::RetryConfig {
            max_retries: 0, // No retries in tests by default (fast failure)
            base_delay_ms: 10,
            max_delay_ms: 100,
        },
        context: ares_llm::agent_loop::ContextConfig {
            max_context_tokens: 0,    // No limit in tests by default
            max_tool_output_chars: 0, // No truncation in tests
            min_recent_messages: 10,
        },
        max_tool_calls_per_name: 10,
    }
}

fn default_usage() -> TokenUsage {
    TokenUsage {
        input_tokens: 10,
        output_tokens: 20,
        cache_creation_input_tokens: 0,
        cache_read_input_tokens: 0,
    }
}

/// Minimal tool definitions including the callback tools and nmap_scan.
fn test_tools() -> Vec<ToolDefinition> {
    vec![
        ToolDefinition {
            name: "nmap_scan".into(),
            description: "Run an nmap scan".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "target": {"type": "string"}
                },
                "required": ["target"]
            }),
        },
        ToolDefinition {
            name: "task_complete".into(),
            description: "Mark the current task as complete.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "task_id": {"type": "string"},
                    "result": {"type": "string"}
                },
                "required": ["task_id", "result"]
            }),
        },
        ToolDefinition {
            name: "request_assistance".into(),
            description: "Request help from the orchestrator.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "issue": {"type": "string"},
                    "context": {"type": "string"}
                },
                "required": ["issue"]
            }),
        },
    ]
}

fn tool_use_response(tool_calls: Vec<ToolCall>) -> LlmResponse {
    LlmResponse {
        content: String::new(),
        tool_calls,
        stop_reason: StopReason::ToolUse,
        usage: default_usage(),
    }
}

// ---------------------------------------------------------------------------
// Test 1: Multi-turn tool use -> task_complete
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_multi_turn_tool_use_then_task_complete() {
    // Turn 1: LLM requests nmap_scan
    let turn1 = tool_use_response(vec![ToolCall {
        id: "call_1".into(),
        name: "nmap_scan".into(),
        arguments: json!({"target": "192.168.58.0/24"}),
    }]);

    // Turn 2: LLM sees nmap result, calls task_complete
    let turn2 = tool_use_response(vec![ToolCall {
        id: "call_2".into(),
        name: "task_complete".into(),
        arguments: json!({
            "task_id": "task-recon-001",
            "result": "Found 5 hosts on 192.168.58.0/24"
        }),
    }]);

    let provider = MockProvider::new(vec![turn1, turn2]);
    let dispatcher = Arc::new(MockDispatcher::new(vec![Ok(ToolExecResult {
        output: "Host: 192.168.58.10 (open: 22,80,445)\nHost: 192.168.58.20 (open: 88,389,445)"
            .into(),
        error: None,
        discoveries: None,
    })]));

    let config = default_config(10);
    let outcome = run_agent_loop(
        &provider,
        dispatcher.clone(),
        &config,
        "You are a recon agent.",
        "Scan the 192.168.58.0/24 subnet.",
        "recon",
        "task-recon-001",
        &test_tools(),
        None,
    )
    .await;

    // Assert task completed
    match &outcome.reason {
        LoopEndReason::TaskComplete { task_id, result } => {
            assert_eq!(task_id, "task-recon-001");
            assert!(result.contains("Found 5 hosts"));
        }
        other => panic!("Expected TaskComplete, got: {:?}", other),
    }

    assert_eq!(outcome.steps, 2);
    // nmap_scan was dispatched; task_complete is a callback, not dispatched
    assert_eq!(outcome.tool_calls_dispatched, 1);

    // Verify the dispatcher saw the nmap call
    let calls = dispatcher.dispatched_calls();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].name, "nmap_scan");
}

// ---------------------------------------------------------------------------
// Test 2: Max steps limit
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_max_steps_limit() {
    // LLM always returns a tool call, never calls task_complete
    let responses: Vec<LlmResponse> = (0..5)
        .map(|i| {
            tool_use_response(vec![ToolCall {
                id: format!("call_{}", i),
                name: "nmap_scan".into(),
                arguments: json!({"target": format!("192.168.58.{}", i)}),
            }])
        })
        .collect();

    let dispatcher_results: Vec<Result<ToolExecResult>> = (0..5)
        .map(|_| {
            Ok(ToolExecResult {
                output: "scan complete".into(),
                error: None,
                discoveries: None,
            })
        })
        .collect();

    let provider = MockProvider::new(responses);
    let dispatcher = Arc::new(MockDispatcher::new(dispatcher_results));

    let config = default_config(3);
    let outcome = run_agent_loop(
        &provider,
        dispatcher,
        &config,
        "You are a recon agent.",
        "Keep scanning.",
        "recon",
        "task-recon-002",
        &test_tools(),
        None,
    )
    .await;

    match &outcome.reason {
        LoopEndReason::MaxSteps => {}
        other => panic!("Expected MaxSteps, got: {:?}", other),
    }

    assert_eq!(outcome.steps, 3);
    // Each step dispatches one nmap_scan
    assert_eq!(outcome.tool_calls_dispatched, 3);
}

// ---------------------------------------------------------------------------
// Test 3: End turn (no tool calls)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_end_turn_no_tool_calls() {
    let response = LlmResponse {
        content: "I have analyzed the network and there is nothing more to do.".into(),
        tool_calls: vec![],
        stop_reason: StopReason::EndTurn,
        usage: default_usage(),
    };

    let provider = MockProvider::new(vec![response]);
    let dispatcher = Arc::new(MockDispatcher::new(vec![]));

    let config = default_config(10);
    let outcome = run_agent_loop(
        &provider,
        dispatcher.clone(),
        &config,
        "You are a recon agent.",
        "Analyze the network.",
        "recon",
        "task-recon-003",
        &test_tools(),
        None,
    )
    .await;

    match &outcome.reason {
        LoopEndReason::EndTurn { content } => {
            assert!(content.contains("nothing more to do"));
        }
        other => panic!("Expected EndTurn, got: {:?}", other),
    }

    assert_eq!(outcome.steps, 1);
    assert_eq!(outcome.tool_calls_dispatched, 0);

    // Dispatcher should not have been called
    assert!(dispatcher.dispatched_calls().is_empty());
}

// ---------------------------------------------------------------------------
// Test 4: Tool dispatch error fed back to LLM
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_tool_dispatch_error_fed_back() {
    // Turn 1: LLM requests nmap_scan
    let turn1 = tool_use_response(vec![ToolCall {
        id: "call_1".into(),
        name: "nmap_scan".into(),
        arguments: json!({"target": "192.168.58.10"}),
    }]);

    // Turn 2: LLM receives the error and calls task_complete anyway
    let turn2 = tool_use_response(vec![ToolCall {
        id: "call_2".into(),
        name: "task_complete".into(),
        arguments: json!({
            "task_id": "task-recon-004",
            "result": "Scan failed due to connectivity error"
        }),
    }]);

    let provider = MockProvider::new(vec![turn1, turn2]);

    // Dispatcher returns an error for the tool call
    let dispatcher = Arc::new(MockDispatcher::new(vec![Ok(ToolExecResult {
        output: "partial scan data".into(),
        error: Some("Connection timed out after 30s".into()),
        discoveries: None,
    })]));

    let config = default_config(10);
    let outcome = run_agent_loop(
        &provider,
        dispatcher,
        &config,
        "You are a recon agent.",
        "Scan 192.168.58.10.",
        "recon",
        "task-recon-004",
        &test_tools(),
        None,
    )
    .await;

    match &outcome.reason {
        LoopEndReason::TaskComplete { task_id, result } => {
            assert_eq!(task_id, "task-recon-004");
            assert!(result.contains("failed"));
        }
        other => panic!("Expected TaskComplete, got: {:?}", other),
    }

    assert_eq!(outcome.steps, 2);
    // The nmap call was dispatched (even though it returned an error)
    assert_eq!(outcome.tool_calls_dispatched, 1);
}

// ---------------------------------------------------------------------------
// Test 4b: Tool dispatch hard failure (anyhow error) fed back to LLM
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_tool_dispatch_hard_error_fed_back() {
    // Turn 1: LLM requests nmap_scan
    let turn1 = tool_use_response(vec![ToolCall {
        id: "call_1".into(),
        name: "nmap_scan".into(),
        arguments: json!({"target": "192.168.58.10"}),
    }]);

    // Turn 2: LLM receives the error message and completes
    let turn2 = tool_use_response(vec![ToolCall {
        id: "call_2".into(),
        name: "task_complete".into(),
        arguments: json!({
            "task_id": "task-recon-004b",
            "result": "Tool execution failed"
        }),
    }]);

    let provider = MockProvider::new(vec![turn1, turn2]);

    // Dispatcher returns a hard anyhow error
    let dispatcher = Arc::new(MockDispatcher::new(vec![Err(anyhow::anyhow!(
        "Redis connection refused",
    ))]));

    let config = default_config(10);
    let outcome = run_agent_loop(
        &provider,
        dispatcher,
        &config,
        "You are a recon agent.",
        "Scan 192.168.58.10.",
        "recon",
        "task-recon-004b",
        &test_tools(),
        None,
    )
    .await;

    match &outcome.reason {
        LoopEndReason::TaskComplete { task_id, .. } => {
            assert_eq!(task_id, "task-recon-004b");
        }
        other => panic!("Expected TaskComplete, got: {:?}", other),
    }

    assert_eq!(outcome.steps, 2);
    assert_eq!(outcome.tool_calls_dispatched, 1);
}

// ---------------------------------------------------------------------------
// Test 5: request_assistance callback
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_request_assistance_callback() {
    let response = tool_use_response(vec![ToolCall {
        id: "call_1".into(),
        name: "request_assistance".into(),
        arguments: json!({
            "issue": "Cannot reach target host",
            "context": "Tried TCP SYN scan, ICMP ping, and ARP scan - all failed"
        }),
    }]);

    let provider = MockProvider::new(vec![response]);
    let dispatcher = Arc::new(MockDispatcher::new(vec![]));

    let config = default_config(10);
    let outcome = run_agent_loop(
        &provider,
        dispatcher.clone(),
        &config,
        "You are a recon agent.",
        "Scan target.",
        "recon",
        "task-recon-005",
        &test_tools(),
        None,
    )
    .await;

    match &outcome.reason {
        LoopEndReason::RequestAssistance { issue, context } => {
            assert_eq!(issue, "Cannot reach target host");
            assert!(context.contains("ARP scan"));
        }
        other => panic!("Expected RequestAssistance, got: {:?}", other),
    }

    assert_eq!(outcome.steps, 1);
    // request_assistance is a callback, not dispatched to workers
    assert_eq!(outcome.tool_calls_dispatched, 0);

    // Dispatcher should not have been called
    assert!(dispatcher.dispatched_calls().is_empty());
}

// ---------------------------------------------------------------------------
// Test 6: Token usage accumulates across steps
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_token_usage_accumulates() {
    let turn1 = LlmResponse {
        content: String::new(),
        tool_calls: vec![ToolCall {
            id: "call_1".into(),
            name: "nmap_scan".into(),
            arguments: json!({"target": "192.168.58.0/24"}),
        }],
        stop_reason: StopReason::ToolUse,
        usage: TokenUsage {
            input_tokens: 100,
            output_tokens: 50,
            cache_creation_input_tokens: 10,
            cache_read_input_tokens: 5,
        },
    };

    let turn2 = LlmResponse {
        content: String::new(),
        tool_calls: vec![ToolCall {
            id: "call_2".into(),
            name: "task_complete".into(),
            arguments: json!({
                "task_id": "task-recon-006",
                "result": "Done"
            }),
        }],
        stop_reason: StopReason::ToolUse,
        usage: TokenUsage {
            input_tokens: 200,
            output_tokens: 75,
            cache_creation_input_tokens: 0,
            cache_read_input_tokens: 15,
        },
    };

    let provider = MockProvider::new(vec![turn1, turn2]);
    let dispatcher = Arc::new(MockDispatcher::new(vec![Ok(ToolExecResult {
        output: "scan done".into(),
        error: None,
        discoveries: None,
    })]));

    let config = default_config(10);
    let outcome = run_agent_loop(
        &provider,
        dispatcher,
        &config,
        "System prompt.",
        "Task prompt.",
        "recon",
        "task-recon-006",
        &test_tools(),
        None,
    )
    .await;

    assert_eq!(outcome.total_usage.input_tokens, 300);
    assert_eq!(outcome.total_usage.output_tokens, 125);
    assert_eq!(outcome.total_usage.cache_creation_input_tokens, 10);
    assert_eq!(outcome.total_usage.cache_read_input_tokens, 20);
}

// ---------------------------------------------------------------------------
// Test 7: LLM error returns Error outcome
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_llm_error_returns_error_outcome() {
    // Provider with no responses queued -- will return an error
    let provider = MockProvider::new(vec![]);
    let dispatcher = Arc::new(MockDispatcher::new(vec![]));

    let config = default_config(10);
    let outcome = run_agent_loop(
        &provider,
        dispatcher,
        &config,
        "System prompt.",
        "Task prompt.",
        "recon",
        "task-recon-007",
        &test_tools(),
        None,
    )
    .await;

    match &outcome.reason {
        LoopEndReason::Error(msg) => {
            assert!(msg.contains("no more queued responses"));
        }
        other => panic!("Expected Error, got: {:?}", other),
    }

    assert_eq!(outcome.steps, 1);
    assert_eq!(outcome.tool_calls_dispatched, 0);
}

// ---------------------------------------------------------------------------
// Test 8: Rate limit retry succeeds on second attempt
// ---------------------------------------------------------------------------

/// Mock provider that fails with RateLimited on the first N calls, then succeeds.
struct RetryMockProvider {
    fail_count: std::sync::atomic::AtomicU32,
    failures_before_success: u32,
    success_response: Mutex<Option<LlmResponse>>,
}

impl RetryMockProvider {
    fn new(failures_before_success: u32, success_response: LlmResponse) -> Self {
        Self {
            fail_count: std::sync::atomic::AtomicU32::new(0),
            failures_before_success,
            success_response: Mutex::new(Some(success_response)),
        }
    }
}

#[async_trait::async_trait]
impl LlmProvider for RetryMockProvider {
    async fn chat(&self, _request: &LlmRequest) -> Result<LlmResponse, LlmError> {
        let attempt = self
            .fail_count
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        if attempt < self.failures_before_success {
            Err(LlmError::RateLimited {
                retry_after_ms: Some(10),
            })
        } else {
            let resp = self.success_response.lock().unwrap().take().unwrap();
            Ok(resp)
        }
    }

    fn name(&self) -> &str {
        "retry-mock"
    }
}

#[tokio::test]
async fn test_rate_limit_retry_succeeds() {
    // First call returns 429, second call returns EndTurn
    let success = LlmResponse {
        content: "Recovered after rate limit.".into(),
        tool_calls: vec![],
        stop_reason: StopReason::EndTurn,
        usage: default_usage(),
    };

    let provider = RetryMockProvider::new(2, success);
    let dispatcher = Arc::new(MockDispatcher::new(vec![]));

    let mut config = default_config(10);
    config.retry = ares_llm::agent_loop::RetryConfig {
        max_retries: 3,
        base_delay_ms: 10,
        max_delay_ms: 50,
    };

    let outcome = run_agent_loop(
        &provider,
        dispatcher,
        &config,
        "System prompt.",
        "Task prompt.",
        "recon",
        "task-recon-008",
        &test_tools(),
        None,
    )
    .await;

    match &outcome.reason {
        LoopEndReason::EndTurn { content } => {
            assert!(content.contains("Recovered"));
        }
        other => panic!("Expected EndTurn after retry, got: {:?}", other),
    }

    // Should have taken 1 step (the retry is transparent to the loop)
    assert_eq!(outcome.steps, 1);
}

// ---------------------------------------------------------------------------
// Test 9: Non-retryable error fails immediately
// ---------------------------------------------------------------------------

/// Mock provider that always returns AuthError.
struct AuthErrorMockProvider;

#[async_trait::async_trait]
impl LlmProvider for AuthErrorMockProvider {
    async fn chat(&self, _request: &LlmRequest) -> Result<LlmResponse, LlmError> {
        Err(LlmError::AuthError("Invalid API key".into()))
    }

    fn name(&self) -> &str {
        "auth-error-mock"
    }
}

#[tokio::test]
async fn test_auth_error_fails_immediately() {
    let provider = AuthErrorMockProvider;
    let dispatcher = Arc::new(MockDispatcher::new(vec![]));

    let mut config = default_config(10);
    config.retry = ares_llm::agent_loop::RetryConfig {
        max_retries: 5, // Even with retries configured, auth errors should not retry
        base_delay_ms: 10,
        max_delay_ms: 50,
    };

    let outcome = run_agent_loop(
        &provider,
        dispatcher,
        &config,
        "System prompt.",
        "Task prompt.",
        "recon",
        "task-recon-009",
        &test_tools(),
        None,
    )
    .await;

    match &outcome.reason {
        LoopEndReason::Error(msg) => {
            assert!(msg.contains("authentication failed"));
        }
        other => panic!("Expected Error with auth message, got: {:?}", other),
    }

    // Should have taken exactly 1 step (no retries for auth errors)
    assert_eq!(outcome.steps, 1);
}
