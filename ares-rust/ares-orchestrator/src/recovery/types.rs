//! Types and constants for operation recovery.

use ares_core::models::{SharedRedTeamState, TaskStatus};

/// Maximum number of retries before a task is considered permanently failed.
pub const MAX_RETRIES: i32 = 3;

/// Statuses that indicate an interrupted task eligible for re-enqueue.
pub const INTERRUPTED_STATUSES: &[TaskStatus] = &[
    TaskStatus::Pending,
    TaskStatus::InProgress,
    TaskStatus::Retrying,
];

/// Keywords that signal a transient Redis connection error.
pub const CONNECTION_ERROR_KEYWORDS: &[&str] = &[
    "connection",
    "connect",
    "closed",
    "timeout",
    "broken pipe",
    "reset",
    "reading from",
];

/// Maximum number of retry attempts for transient Redis connection errors.
pub const MAX_CONNECTION_RETRIES: u32 = 3;

/// Check if an error looks like a transient Redis connection failure.
pub fn is_connection_error(err: &anyhow::Error) -> bool {
    let msg = err.to_string().to_lowercase();
    CONNECTION_ERROR_KEYWORDS.iter().any(|kw| msg.contains(kw))
}

/// Result of a recovery operation.
#[derive(Debug)]
pub struct RecoveredState {
    /// The full shared state loaded from Redis.
    pub state: SharedRedTeamState,
    /// Task IDs that were re-enqueued for retry.
    pub requeued_task_ids: Vec<String>,
    /// Task IDs that exceeded max retries and were marked failed.
    pub failed_task_ids: Vec<String>,
}

/// Info about a permanently failed task (exceeded max retries).
#[derive(Debug, Clone)]
pub struct InterruptedTask {
    pub task_id: String,
    pub task_type: String,
    pub assigned_agent: String,
    pub retry_count: i32,
    pub error: String,
}

/// Info about a task that was auto-requeued for retry.
#[derive(Debug, Clone)]
pub struct RetryingTask {
    pub task_id: String,
    pub task_type: String,
    pub assigned_agent: String,
    pub retry_count: i32,
    pub max_retries: i32,
}
