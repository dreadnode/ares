//! Task routing — decides which agent queue receives a task.
//!
//! Mirrors the Python `ares.core.dispatcher.routing.RoutingMixin` logic:
//! route by role, respect per-role concurrency limits, track active tasks.

use std::collections::HashMap;
use std::sync::Arc;

use anyhow::Result;
use serde_json::Value;
use tokio::sync::Mutex;
use tracing::{debug, info};

use crate::config::OrchestratorConfig;
use crate::task_queue::TaskQueue;

// ---------------------------------------------------------------------------
// Active-task tracker (shared across routing + monitoring + throttling)
// ---------------------------------------------------------------------------

/// Per-role tracking of in-flight tasks.
#[derive(Debug, Clone)]
pub struct ActiveTask {
    pub task_id: String,
    pub task_type: String,
    pub role: String,
    pub submitted_at: std::time::Instant,
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

// ---------------------------------------------------------------------------
// Router — submits tasks to the correct queue with concurrency enforcement
// ---------------------------------------------------------------------------

/// Routes tasks to agent queues, respecting per-role concurrency limits.
pub struct TaskRouter {
    queue: TaskQueue,
    tracker: ActiveTaskTracker,
    config: Arc<OrchestratorConfig>,
}

impl TaskRouter {
    pub fn new(
        queue: TaskQueue,
        tracker: ActiveTaskTracker,
        config: Arc<OrchestratorConfig>,
    ) -> Self {
        Self {
            queue,
            tracker,
            config,
        }
    }

    /// Route a task to the appropriate role queue.
    ///
    /// Returns the task ID if submitted, `None` if the role is at capacity.
    pub async fn route(
        &self,
        task_type: &str,
        target_role: &str,
        payload: Value,
        source_agent: &str,
        priority: i32,
    ) -> Result<Option<String>> {
        // Check per-role concurrency limit
        let role_count = self.tracker.count_for_role(target_role).await;
        if role_count >= self.config.max_tasks_per_role {
            // Also check the Redis queue depth — if the queue is already long,
            // there is no point adding more work.
            let queue_depth = self.queue.queue_length(target_role).await.unwrap_or(0);
            if queue_depth > 0 {
                debug!(
                    role = target_role,
                    active = role_count,
                    queue_depth,
                    "Role at capacity, rejecting task"
                );
                return Ok(None);
            }
            // Queue empty but active count high — a task might be about to
            // finish, allow submission to keep workers busy.
            info!(
                role = target_role,
                active = role_count,
                "Role at capacity but queue empty — allowing submission"
            );
        }

        // Submit to Redis
        let task_id = self
            .queue
            .submit_task(task_type, target_role, payload, source_agent, priority)
            .await?;

        // Track it
        self.tracker
            .add(ActiveTask {
                task_id: task_id.clone(),
                task_type: task_type.to_string(),
                role: target_role.to_string(),
                submitted_at: std::time::Instant::now(),
            })
            .await;

        Ok(Some(task_id))
    }

    /// Access the underlying tracker (used by monitoring and throttling).
    pub fn tracker(&self) -> &ActiveTaskTracker {
        &self.tracker
    }

    /// Access the underlying queue (used by result consumer).
    pub fn queue(&self) -> &TaskQueue {
        &self.queue
    }
}
