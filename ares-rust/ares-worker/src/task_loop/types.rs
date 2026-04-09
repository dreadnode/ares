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
    /// Structured discoveries parsed from tool output (hosts, creds, hashes, vulns).
    pub discoveries: Option<serde_json::Value>,
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_task_result_success() {
        let result = TaskResult::success("task-1", json!({"output": "done"}), "pod-1", "recon");
        assert!(result.success);
        assert!(result.error.is_none());
        assert_eq!(result.task_id, "task-1");
        assert!(result.result.is_some());
        assert_eq!(result.worker_pod.as_deref(), Some("pod-1"));
        assert_eq!(result.agent_name.as_deref(), Some("recon"));
        assert!(result.completed_at.is_some());
    }

    #[test]
    fn test_task_result_failure() {
        let result = TaskResult::failure(
            "task-2",
            "timeout".to_string(),
            Some(json!({"partial": true})),
            "pod-1",
            "lateral",
        );
        assert!(!result.success);
        assert_eq!(result.error.as_deref(), Some("timeout"));
        assert!(result.result.is_some());
    }

    #[test]
    fn test_task_result_failure_no_result() {
        let result = TaskResult::failure("task-3", "crash".to_string(), None, "pod-1", "recon");
        assert!(!result.success);
        assert!(result.result.is_none());
    }

    #[test]
    fn test_task_message_deserialize() {
        let json = json!({
            "task_id": "t-1",
            "task_type": "recon",
            "source_agent": "orchestrator",
            "target_agent": "recon-1",
            "payload": {"target_ip": "192.168.58.10"},
            "priority": 3,
            "created_at": "2026-04-08T12:00:00Z"
        });
        let msg: TaskMessage = serde_json::from_value(json).unwrap();
        assert_eq!(msg.task_id, "t-1");
        assert_eq!(msg.task_type, "recon");
        assert_eq!(msg.priority, 3);
        assert!(msg.callback_queue.is_none());
    }

    #[test]
    fn test_task_message_default_priority() {
        let json = json!({
            "task_id": "t-1",
            "task_type": "recon",
            "source_agent": "orchestrator",
            "target_agent": "recon-1",
            "payload": {}
        });
        let msg: TaskMessage = serde_json::from_value(json).unwrap();
        assert_eq!(msg.priority, 5); // default
    }

    #[test]
    fn test_task_result_serialization_skips_none() {
        let result = TaskResult::success("t-1", json!({"ok": true}), "pod-1", "recon");
        let serialized = serde_json::to_value(&result).unwrap();
        assert!(serialized.get("error").is_none());
    }
}
