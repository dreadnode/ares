//! Wire types and agent result structs for the task loop.

use chrono::Utc;
use serde::{Deserialize, Serialize};

// ─── Agent result types ──────────────────────────────────────────────────────

/// Result from running an agent task.
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
    /// Model name (e.g. "openai/gpt-4.1-mini").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
}

// ─── Wire types (match Python's Pydantic models exactly) ─────────────────────

/// Task message from the queue. Matches `TaskMessage` in `task_queue.py`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskMessage {
    pub task_id: String,
    pub task_type: String,
    pub source_agent: String,
    pub target_agent: String,
    pub payload: serde_json::Value,
    #[serde(default = "default_priority")]
    pub priority: i32,
    pub created_at: Option<String>,
    pub callback_queue: Option<String>,
}

fn default_priority() -> i32 {
    5
}

/// Task result pushed back to orchestrator. Matches `TaskResult` in `task_queue.py`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskResult {
    pub task_id: String,
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    pub completed_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub worker_pod: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_name: Option<String>,
}

impl TaskResult {
    pub fn success(
        task_id: &str,
        result: serde_json::Value,
        pod_name: &str,
        agent_name: &str,
    ) -> Self {
        Self {
            task_id: task_id.to_string(),
            success: true,
            result: Some(result),
            error: None,
            completed_at: Some(Utc::now().to_rfc3339()),
            worker_pod: Some(pod_name.to_string()),
            agent_name: Some(agent_name.to_string()),
        }
    }

    pub fn failure(
        task_id: &str,
        error: String,
        result: Option<serde_json::Value>,
        pod_name: &str,
        agent_name: &str,
    ) -> Self {
        Self {
            task_id: task_id.to_string(),
            success: false,
            result,
            error: Some(error),
            completed_at: Some(Utc::now().to_rfc3339()),
            worker_pod: Some(pod_name.to_string()),
            agent_name: Some(agent_name.to_string()),
        }
    }
}
