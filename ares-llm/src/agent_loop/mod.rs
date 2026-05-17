//! Multi-step LLM agent loop with tool_use dispatch.
//!
//! The `AgentLoop` drives a conversation between the LLM and tool executors:
//!
//! 1. Build system prompt from template + task prompt from PromptBuilder
//! 2. Call LLM via the provider
//! 3. If the LLM requests tool_use:
//!    a. Callback tools (task_complete, report_finding) → handled in Rust
//!    b. External tools (nmap_scan, secretsdump) → dispatched to worker via Redis
//! 4. Feed tool result back to LLM, repeat
//! 5. Stop when: task_complete called, max steps reached, or end_turn with no tools

mod callbacks;
mod config;
mod context;
mod retry;
mod runner;
mod session_log;

#[cfg(test)]
mod tests;

pub use config::{AgentLoopConfig, BudgetConfig, ContextConfig, RetryConfig, SessionLogConfig};
pub use runner::{run_agent_loop, HostnameMap, RunAgentLoopParams};
pub use session_log::{replay_messages, SessionLog};
pub use types::{
    AgentLoopOutcome, CallbackHandler, CallbackResult, LoopEndReason, ToolDispatcher,
    ToolExecResult, ToolOutput,
};

mod types;
