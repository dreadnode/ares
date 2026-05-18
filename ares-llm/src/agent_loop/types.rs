use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::provider::{TokenUsage, ToolCall};

/// Result of executing an external tool on a worker.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolExecResult {
    pub output: String,
    pub error: Option<String>,
    /// Structured discoveries parsed from the tool output (hosts, creds, hashes, vulns).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub discoveries: Option<serde_json::Value>,
}

/// Raw stdout from a single tool dispatch, paired with the tool name and
/// arguments that produced it. Carried through `AgentLoopOutcome` so secondary
/// regex extractors downstream can be tool-aware (e.g. skip `[+] DOMAIN\user:secret`
/// credential extraction when the tool was invoked with hash-auth flags — the
/// "secret" is just the hash echoed back, not a discovered password).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolOutput {
    pub name: String,
    pub arguments: serde_json::Value,
    pub output: String,
}

/// Trait for dispatching tool calls to external executors.
///
/// Implementers handle the Redis queue mechanics (LPUSH to tool_exec queue,
/// BRPOP for result).
#[async_trait::async_trait]
pub trait ToolDispatcher: Send + Sync {
    /// Dispatch a tool call to a worker and wait for the result.
    ///
    /// `role` is the agent role (e.g. "recon") used for queue routing.
    /// `task_id` is the parent task being executed.
    async fn dispatch_tool(
        &self,
        role: &str,
        task_id: &str,
        call: &ToolCall,
    ) -> Result<ToolExecResult>;
}

/// Result of handling a callback tool.
#[derive(Debug)]
pub enum CallbackResult {
    /// Task is complete — stop the loop.
    TaskComplete { task_id: String, result: String },
    /// Agent needs help — stop the loop.
    RequestAssistance { issue: String, context: String },
    /// Callback processed, continue the loop with this response.
    Continue(String),
    /// LLM-fabricated finding — continue the loop and route the structured
    /// payload into `llm_findings` (NOT `discoveries`). Reports may surface
    /// these for context, but they MUST NOT feed `publish_*` state writes;
    /// only parser-produced discoveries are authoritative.
    LlmFinding {
        response: String,
        finding: serde_json::Value,
    },
}

/// Trait for providing custom callback handlers to the agent loop.
///
/// The orchestrator implements this to handle state query tools
/// (get_hash_summary, get_all_credentials, etc.) and dispatch tools
/// (dispatch_recon, dispatch_lateral, etc.) that need Redis access.
///
/// Return `None` if the handler doesn't recognize the tool — the
/// built-in handler will be tried next.
#[async_trait::async_trait]
pub trait CallbackHandler: Send + Sync {
    async fn handle_callback(&self, call: &ToolCall) -> Option<Result<CallbackResult>>;

    /// Check if a tool name should be routed as a callback rather than
    /// dispatched to a worker. Default returns false for all tools.
    fn is_callback(&self, _tool_name: &str) -> bool {
        false
    }

    /// Called after each LLM API response with the incremental token usage.
    /// Default implementation is a no-op. Override this to record per-call
    /// token usage (e.g. persist to Redis so CLI shows live cost data).
    async fn on_token_usage(&self, _usage: &TokenUsage, _model: &str) {}
}

/// Outcome of running the agent loop.
#[derive(Debug)]
pub struct AgentLoopOutcome {
    /// How the loop ended.
    pub reason: LoopEndReason,
    /// Total token usage across all LLM calls.
    pub total_usage: TokenUsage,
    /// Number of LLM steps taken.
    pub steps: u32,
    /// Number of tool calls dispatched.
    pub tool_calls_dispatched: u32,
    /// Accumulated structured discoveries from all tool results.
    /// Only parser-produced — never LLM-fabricated. Safe to feed into
    /// `extract_discoveries` → `publish_*`.
    pub discoveries: Vec<serde_json::Value>,
    /// LLM-fabricated findings (`report_finding` / `report_lateral_success`).
    /// Surfaced in reports but never used as authoritative state — must never
    /// feed `publish_*` calls.
    pub llm_findings: Vec<serde_json::Value>,
    /// Raw tool outputs (name + args + stdout) for secondary regex extraction.
    pub tool_outputs: Vec<ToolOutput>,
}

/// Why the agent loop stopped.
#[derive(Debug)]
pub enum LoopEndReason {
    /// Agent called task_complete.
    TaskComplete { task_id: String, result: String },
    /// Agent called request_assistance.
    RequestAssistance { issue: String, context: String },
    /// Max steps reached.
    MaxSteps,
    /// LLM returned end_turn with no tool calls.
    EndTurn { content: String },
    /// LLM hit max_tokens.
    MaxTokens,
    /// Cumulative token budget exceeded — circuit breaker tripped before
    /// dispatching the next LLM call. Carries the human-readable reason
    /// (e.g. "input token budget exhausted (12000 >= 10000)").
    BudgetExceeded { reason: String },
    /// Error during execution.
    Error(String),
}
