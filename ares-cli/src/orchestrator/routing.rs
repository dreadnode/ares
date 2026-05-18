//! Task routing — decides which agent queue receives a task.
//!
//! Routes by role, respects per-role concurrency limits, tracks active tasks.

use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::Mutex;

/// Per-role tracking of in-flight tasks.
#[derive(Debug, Clone)]
pub struct ActiveTask {
    pub task_id: String,
    pub task_type: String,
    pub role: String,
    pub submitted_at: std::time::Instant,
    /// `"user@domain"` when the task is gated by `CredentialInflight`. The
    /// caller that successfully removes this task from the tracker is
    /// responsible for releasing the corresponding slot. Carrying it on the
    /// task makes the release happen even when stale-task cleanup evicts a
    /// task whose spawned future is still hung — otherwise the slot leaks
    /// and every subsequent task with the same credential gets deferred
    /// forever.
    pub credential_key: Option<String>,
}

/// Thread-safe tracker for all in-flight tasks.
#[derive(Debug, Clone)]
pub struct ActiveTaskTracker {
    inner: Arc<Mutex<TrackerInner>>,
}

#[derive(Debug, Default)]
struct TrackerInner {
    /// task_id -> ActiveTask
    tasks: HashMap<String, ActiveTask>,
    /// role -> count of active tasks
    role_counts: HashMap<String, usize>,
}

impl Default for ActiveTaskTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl ActiveTaskTracker {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(TrackerInner::default())),
        }
    }

    /// Register a newly submitted task.
    pub async fn add(&self, task: ActiveTask) {
        let mut inner = self.inner.lock().await;
        *inner.role_counts.entry(task.role.clone()).or_insert(0) += 1;
        inner.tasks.insert(task.task_id.clone(), task);
    }

    /// Remove a completed/failed task. Returns the task if it was tracked.
    pub async fn remove(&self, task_id: &str) -> Option<ActiveTask> {
        let mut inner = self.inner.lock().await;
        if let Some(task) = inner.tasks.remove(task_id) {
            if let Some(count) = inner.role_counts.get_mut(&task.role) {
                *count = count.saturating_sub(1);
            }
            Some(task)
        } else {
            None
        }
    }

    /// Number of active tasks for a role.
    pub async fn count_for_role(&self, role: &str) -> usize {
        let inner = self.inner.lock().await;
        inner.role_counts.get(role).copied().unwrap_or(0)
    }

    /// Total number of active LLM-consuming tasks (excludes `crack`, `command`).
    pub async fn llm_task_count(&self) -> usize {
        let inner = self.inner.lock().await;
        inner
            .tasks
            .values()
            .filter(|t| !is_non_llm_task(&t.task_type))
            .count()
    }

    /// Total active tasks across all roles.
    pub async fn total(&self) -> usize {
        let inner = self.inner.lock().await;
        inner.tasks.len()
    }

    /// Get all tracked task IDs (for result polling).
    pub async fn task_ids(&self) -> Vec<String> {
        let inner = self.inner.lock().await;
        inner.tasks.keys().cloned().collect()
    }

    /// Get tasks older than `age` that have not received a result.
    pub async fn stale_tasks(&self, max_age: std::time::Duration) -> Vec<ActiveTask> {
        let inner = self.inner.lock().await;
        let cutoff = std::time::Instant::now() - max_age;
        inner
            .tasks
            .values()
            .filter(|t| t.submitted_at < cutoff)
            .cloned()
            .collect()
    }
}

/// Task types that do not consume LLM tokens.
const NON_LLM_TYPES: &[&str] = &["crack", "command"];

pub fn is_non_llm_task(task_type: &str) -> bool {
    NON_LLM_TYPES.contains(&task_type)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn non_llm_task_classification() {
        assert!(is_non_llm_task("crack"));
        assert!(is_non_llm_task("command"));
        assert!(!is_non_llm_task("recon"));
        assert!(!is_non_llm_task("exploit"));
        assert!(!is_non_llm_task("privesc_enumeration"));
        assert!(!is_non_llm_task(""));
    }

    #[tokio::test]
    async fn tracker_add_remove() {
        let tracker = ActiveTaskTracker::new();
        assert_eq!(tracker.total().await, 0);

        tracker
            .add(ActiveTask {
                task_id: "t1".into(),
                task_type: "recon".into(),
                role: "recon".into(),
                submitted_at: std::time::Instant::now(),
                credential_key: None,
            })
            .await;

        assert_eq!(tracker.total().await, 1);
        assert_eq!(tracker.count_for_role("recon").await, 1);
        assert_eq!(tracker.count_for_role("lateral").await, 0);

        let removed = tracker.remove("t1").await;
        assert!(removed.is_some());
        assert_eq!(tracker.total().await, 0);
        assert_eq!(tracker.count_for_role("recon").await, 0);
    }

    #[tokio::test]
    async fn tracker_remove_nonexistent() {
        let tracker = ActiveTaskTracker::new();
        assert!(tracker.remove("nonexistent").await.is_none());
    }

    #[tokio::test]
    async fn llm_count_excludes_non_llm() {
        let tracker = ActiveTaskTracker::new();

        for (id, task_type, role) in [
            ("t1", "recon", "recon"),
            ("t2", "crack", "cracker"),
            ("t3", "command", "lateral"),
            ("t4", "exploit", "privesc"),
        ] {
            tracker
                .add(ActiveTask {
                    task_id: id.into(),
                    task_type: task_type.into(),
                    role: role.into(),
                    submitted_at: std::time::Instant::now(),
                    credential_key: None,
                })
                .await;
        }

        assert_eq!(tracker.total().await, 4);
        assert_eq!(tracker.llm_task_count().await, 2); // recon + exploit
    }

    #[tokio::test]
    async fn stale_tasks_detection() {
        let tracker = ActiveTaskTracker::new();

        tracker
            .add(ActiveTask {
                task_id: "old".into(),
                task_type: "recon".into(),
                role: "recon".into(),
                submitted_at: std::time::Instant::now() - std::time::Duration::from_secs(120),
                credential_key: None,
            })
            .await;

        tracker
            .add(ActiveTask {
                task_id: "new".into(),
                task_type: "recon".into(),
                role: "recon".into(),
                submitted_at: std::time::Instant::now(),
                credential_key: None,
            })
            .await;

        let stale = tracker
            .stale_tasks(std::time::Duration::from_secs(60))
            .await;
        assert_eq!(stale.len(), 1);
        assert_eq!(stale[0].task_id, "old");
    }

    #[tokio::test]
    async fn task_ids_collected() {
        let tracker = ActiveTaskTracker::new();
        tracker
            .add(ActiveTask {
                task_id: "a".into(),
                task_type: "recon".into(),
                role: "recon".into(),
                submitted_at: std::time::Instant::now(),
                credential_key: None,
            })
            .await;
        tracker
            .add(ActiveTask {
                task_id: "b".into(),
                task_type: "exploit".into(),
                role: "privesc".into(),
                submitted_at: std::time::Instant::now(),
                credential_key: None,
            })
            .await;

        let mut ids = tracker.task_ids().await;
        ids.sort();
        assert_eq!(ids, vec!["a", "b"]);
    }

    #[tokio::test]
    async fn role_count_saturating_sub() {
        let tracker = ActiveTaskTracker::new();
        // Double-remove shouldn't panic or underflow
        tracker
            .add(ActiveTask {
                task_id: "t1".into(),
                task_type: "recon".into(),
                role: "recon".into(),
                submitted_at: std::time::Instant::now(),
                credential_key: None,
            })
            .await;
        tracker.remove("t1").await;
        tracker.remove("t1").await; // second remove returns None
        assert_eq!(tracker.count_for_role("recon").await, 0);
    }
}
