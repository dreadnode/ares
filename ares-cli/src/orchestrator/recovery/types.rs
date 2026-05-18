//! Types and constants for operation recovery.

use ares_core::models::TaskStatus;

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

/// A task that needs to be re-dispatched through the normal LLM submission
/// flow after recovery.
#[derive(Debug, Clone)]
pub struct RecoveryTask {
    pub task_type: String,
    pub target_role: String,
    pub payload: serde_json::Value,
    pub retry_count: i32,
}

/// Result of a recovery operation.
#[derive(Debug)]
pub struct RecoveredState {
    /// Tasks that need re-dispatch through the normal submission flow.
    pub tasks_to_redispatch: Vec<RecoveryTask>,
    /// Task IDs that were prepared for re-dispatch.
    pub requeued_task_ids: Vec<String>,
    /// Task IDs that exceeded max retries and were marked failed.
    pub failed_task_ids: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_connection_error_connection() {
        let err = anyhow::anyhow!("Redis connection refused");
        assert!(is_connection_error(&err));
    }

    #[test]
    fn is_connection_error_timeout() {
        let err = anyhow::anyhow!("Operation timeout after 30s");
        assert!(is_connection_error(&err));
    }

    #[test]
    fn is_connection_error_broken_pipe() {
        let err = anyhow::anyhow!("Broken pipe while writing");
        assert!(is_connection_error(&err));
    }

    #[test]
    fn is_connection_error_reset() {
        let err = anyhow::anyhow!("Connection reset by peer");
        assert!(is_connection_error(&err));
    }

    #[test]
    fn is_connection_error_closed() {
        let err = anyhow::anyhow!("Socket closed unexpectedly");
        assert!(is_connection_error(&err));
    }

    #[test]
    fn is_connection_error_case_insensitive() {
        let err = anyhow::anyhow!("TIMEOUT waiting for response");
        assert!(is_connection_error(&err));
    }

    #[test]
    fn is_not_connection_error() {
        let err = anyhow::anyhow!("Key not found in Redis");
        assert!(!is_connection_error(&err));
    }

    #[test]
    fn is_not_connection_error_parse() {
        let err = anyhow::anyhow!("Failed to parse JSON response");
        assert!(!is_connection_error(&err));
    }

    #[test]
    fn constants() {
        assert_eq!(MAX_RETRIES, 3);
        assert_eq!(MAX_CONNECTION_RETRIES, 3);
        assert_eq!(INTERRUPTED_STATUSES.len(), 3);
    }

    #[test]
    fn recovery_task_carries_payload_for_redispatch() {
        let task = RecoveryTask {
            task_type: "credential_access".to_string(),
            target_role: "credential_access".to_string(),
            payload: serde_json::json!({"target": "192.168.58.1"}),
            retry_count: 2,
        };
        assert_eq!(task.task_type, "credential_access");
        assert_eq!(task.target_role, "credential_access");
        assert_eq!(task.payload["target"], "192.168.58.1");
        assert_eq!(task.retry_count, 2);

        let cloned = task.clone();
        assert_eq!(cloned.task_type, task.task_type);
        let dbg = format!("{task:?}");
        assert!(dbg.contains("credential_access"));
    }
}
