//! Heartbeat monitoring and stale-task cleanup.
//!
//! Mirrors the Python `ares.core.dispatcher.monitoring.MonitoringMixin`:
//! - Periodic heartbeat sweep to detect dead agents
//! - Stale task cleanup to prevent throttle deadlock
//! - Operation lock TTL refresh

use anyhow::Result;
use chrono::{DateTime, Utc};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::watch;
use tracing::{debug, info, warn};

use crate::config::OrchestratorConfig;
use crate::routing::ActiveTaskTracker;
use crate::task_queue::TaskQueue;

// ---------------------------------------------------------------------------
// Agent registry
// ---------------------------------------------------------------------------

/// Live state for a registered agent.
#[derive(Debug, Clone)]
pub struct AgentState {
    pub name: String,
    pub role: String,
    pub status: String,
    pub last_heartbeat: DateTime<Utc>,
    pub current_task: Option<String>,
}

/// Registry of known agents with their health state.
#[derive(Debug, Clone)]
pub struct AgentRegistry {
    agents: Arc<tokio::sync::Mutex<HashMap<String, AgentState>>>,
}

impl AgentRegistry {
    pub fn new() -> Self {
        Self {
            agents: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
        }
    }

    /// Register an agent (or update it if already known).
    pub async fn register(&self, name: &str, role: &str) {
        let mut agents = self.agents.lock().await;
        agents
            .entry(name.to_string())
            .and_modify(|a| {
                a.role = role.to_string();
            })
            .or_insert_with(|| AgentState {
                name: name.to_string(),
                role: role.to_string(),
                status: "idle".to_string(),
                last_heartbeat: Utc::now(),
                current_task: None,
            });
    }

    /// Update heartbeat data from Redis.
    pub async fn update_heartbeat(
        &self,
        name: &str,
        status: &str,
        current_task: Option<&str>,
        timestamp: DateTime<Utc>,
    ) {
        let mut agents = self.agents.lock().await;
        if let Some(agent) = agents.get_mut(name) {
            agent.status = status.to_string();
            agent.current_task = current_task.map(|s| s.to_string());
            agent.last_heartbeat = timestamp;
        }
    }

    /// Return agents whose heartbeat is older than `timeout`.
    pub async fn stale_agents(&self, timeout: std::time::Duration) -> Vec<AgentState> {
        let agents = self.agents.lock().await;
        let cutoff = Utc::now() - chrono::Duration::from_std(timeout).unwrap_or_default();
        agents
            .values()
            .filter(|a| a.last_heartbeat < cutoff && a.status != "offline")
            .cloned()
            .collect()
    }

    /// Mark an agent offline.
    pub async fn mark_offline(&self, name: &str) {
        let mut agents = self.agents.lock().await;
        if let Some(agent) = agents.get_mut(name) {
            agent.status = "offline".to_string();
        }
    }

    /// List all registered agent names (for heartbeat sweep).
    pub async fn agent_names(&self) -> Vec<String> {
        let agents = self.agents.lock().await;
        agents.keys().cloned().collect()
    }
}

// ---------------------------------------------------------------------------
// Heartbeat monitor task
// ---------------------------------------------------------------------------

/// Spawn a background task that periodically:
/// 1. Reads heartbeat keys from Redis for all known agents
/// 2. Marks stale agents as offline
/// 3. Extends the operation lock TTL
///
/// Runs until `shutdown` is signalled.
pub fn spawn_heartbeat_monitor(
    queue: TaskQueue,
    registry: AgentRegistry,
    tracker: ActiveTaskTracker,
    config: Arc<OrchestratorConfig>,
    mut shutdown: watch::Receiver<bool>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(config.heartbeat_interval);
        let mut consecutive_failures: u32 = 0;

        loop {
            tokio::select! {
                _ = interval.tick() => {},
                _ = shutdown.changed() => {
                    info!("Heartbeat monitor shutting down");
                    break;
                }
            }

            if let Err(e) = run_heartbeat_sweep(&queue, &registry, &config).await {
                consecutive_failures += 1;
                warn!(
                    attempt = consecutive_failures,
                    err = %e,
                    "Heartbeat sweep failed"
                );
                // Exponential backoff on repeated failures
                let delay = std::time::Duration::from_secs(std::cmp::min(
                    15,
                    (consecutive_failures as u64) * 5,
                ));
                tokio::time::sleep(delay).await;
                continue;
            }
            consecutive_failures = 0;

            // Extend operation lock
            if let Err(e) = queue
                .extend_lock(&config.operation_id, config.lock_ttl)
                .await
            {
                warn!(err = %e, "Failed to extend operation lock");
            }

            // Clean up stale tasks
            if let Err(e) = cleanup_stale_tasks(&tracker, &config).await {
                warn!(err = %e, "Stale task cleanup failed");
            }
        }
    })
}

/// Read heartbeats from Redis and update the registry.
async fn run_heartbeat_sweep(
    queue: &TaskQueue,
    registry: &AgentRegistry,
    config: &OrchestratorConfig,
) -> Result<()> {
    let names = registry.agent_names().await;
    for name in &names {
        match queue.get_heartbeat(name).await {
            Ok(Some(hb)) => {
                let ts = DateTime::parse_from_rfc3339(&hb.timestamp)
                    .map(|dt| dt.with_timezone(&Utc))
                    .unwrap_or_else(|_| Utc::now());
                registry
                    .update_heartbeat(name, &hb.status, hb.current_task.as_deref(), ts)
                    .await;
            }
            Ok(None) => {
                debug!(agent = %name, "No heartbeat key in Redis");
            }
            Err(e) => {
                warn!(agent = %name, err = %e, "Failed to read heartbeat");
            }
        }
    }

    // Mark stale agents offline
    let stale = registry.stale_agents(config.heartbeat_timeout).await;
    for agent in &stale {
        warn!(
            agent = %agent.name,
            last_hb = %agent.last_heartbeat,
            "Agent heartbeat stale — marking offline"
        );
        registry.mark_offline(&agent.name).await;
    }

    Ok(())
}

/// Remove tasks that have been active longer than the configured stale timeout.
async fn cleanup_stale_tasks(
    tracker: &ActiveTaskTracker,
    config: &OrchestratorConfig,
) -> Result<()> {
    let llm_count = tracker.llm_task_count().await;
    let hard_cap = config.hard_cap();

    // Use shorter timeout when at hard cap to break deadlock faster
    let effective_timeout = if llm_count >= hard_cap {
        config.stale_task_timeout / 2
    } else {
        config.stale_task_timeout
    };

    let stale = tracker.stale_tasks(effective_timeout).await;
    for task in &stale {
        warn!(
            task_id = %task.task_id,
            role = %task.role,
            age_secs = task.submitted_at.elapsed().as_secs(),
            "Removing stale task"
        );
        tracker.remove(&task.task_id).await;
    }

    if !stale.is_empty() {
        info!(
            removed = stale.len(),
            llm_count, hard_cap, "Stale task cleanup complete"
        );
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn register_and_list() {
        let r = AgentRegistry::new();
        r.register("ares-recon-0", "recon").await;
        r.register("ares-lateral-0", "lateral").await;
        let mut names = r.agent_names().await;
        names.sort();
        assert_eq!(names, vec!["ares-lateral-0", "ares-recon-0"]);
    }

    #[tokio::test]
    async fn heartbeat_update_prevents_staleness() {
        let r = AgentRegistry::new();
        r.register("a1", "recon").await;
        r.update_heartbeat("a1", "busy", Some("task-42"), Utc::now())
            .await;
        assert!(r
            .stale_agents(std::time::Duration::from_secs(60))
            .await
            .is_empty());
    }

    #[tokio::test]
    async fn stale_agent_detected() {
        let r = AgentRegistry::new();
        r.register("old", "recon").await;
        let old_ts = Utc::now() - chrono::Duration::seconds(120);
        r.update_heartbeat("old", "idle", None, old_ts).await;
        let stale = r.stale_agents(std::time::Duration::from_secs(60)).await;
        assert_eq!(stale.len(), 1);
        assert_eq!(stale[0].name, "old");
    }

    #[tokio::test]
    async fn mark_offline_excludes_from_stale() {
        let r = AgentRegistry::new();
        r.register("dead", "recon").await;
        let old_ts = Utc::now() - chrono::Duration::seconds(300);
        r.update_heartbeat("dead", "idle", None, old_ts).await;
        r.mark_offline("dead").await;
        assert!(r
            .stale_agents(std::time::Duration::from_secs(60))
            .await
            .is_empty());
    }

    #[tokio::test]
    async fn re_register_updates_role() {
        let r = AgentRegistry::new();
        r.register("a1", "recon").await;
        r.register("a1", "lateral").await;
        let agents = r.agents.lock().await;
        assert_eq!(agents.get("a1").unwrap().role, "lateral");
    }
}
