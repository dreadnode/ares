//! Heartbeat monitoring and stale-task cleanup.
//!
//! - Periodic heartbeat sweep to detect dead agents
//! - Stale task cleanup to prevent throttle deadlock
//! - Operation lock TTL refresh

use anyhow::Result;
use chrono::{DateTime, Utc};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::watch;
use tracing::{debug, info, warn};

use crate::orchestrator::config::OrchestratorConfig;
use crate::orchestrator::dispatcher::CredentialInflight;
use crate::orchestrator::routing::{is_non_llm_task, ActiveTaskTracker};
use crate::orchestrator::state::SharedState;
use crate::orchestrator::task_queue::TaskQueue;

/// Live state for a registered agent.
#[derive(Debug, Clone)]
pub struct AgentState {
    pub name: String,
    #[cfg(test)]
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
    #[cfg(test)]
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

/// Spawn a dedicated task that extends the operation lock TTL every
/// `heartbeat_interval`. This is intentionally decoupled from the heartbeat
/// sweep so that a slow/hanging Redis call in the sweep cannot block lock
/// refresh and cause the lock to expire.
///
/// Creates its own Redis connection to avoid contention with the main
/// connection pool used for tool dispatch and result polling.
pub fn spawn_lock_keeper(
    queue: TaskQueue,
    config: Arc<OrchestratorConfig>,
    mut shutdown: watch::Receiver<bool>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        // Create a dedicated Redis connection for the lock keeper so that
        // EXPIRE commands are not queued behind heavy BRPOP/LPUSH traffic
        // on the shared connection manager.
        let dedicated_queue = match TaskQueue::connect_state_only(
            &config.redis_url,
            &config.nats_url,
        )
        .await
        {
            Ok(q) => {
                info!("Lock keeper using dedicated Redis connection");
                q
            }
            Err(e) => {
                warn!(err = %e, "Lock keeper failed to create dedicated connection, falling back to shared");
                queue.clone()
            }
        };

        let mut interval = tokio::time::interval(config.heartbeat_interval);

        loop {
            tokio::select! {
                _ = interval.tick() => {},
                _ = shutdown.changed() => {
                    debug!("Lock keeper shutting down");
                    break;
                }
            }

            // Wrap in a timeout so a hung Redis connection can't block us
            // for longer than the lock TTL.
            let extend_timeout = std::time::Duration::from_secs(10);
            let result = tokio::time::timeout(
                extend_timeout,
                dedicated_queue.extend_lock(&config.operation_id, config.lock_ttl),
            )
            .await;

            match result {
                Ok(Ok(true)) => {} // Lock TTL refreshed
                Ok(Ok(false)) => {
                    // Lock key disappeared or drifted to another holder —
                    // re-acquire. Same holder ID means we own it in Redis
                    // after Reclaimed; different holder means our TTL
                    // lapsed and someone else took over — we should stop.
                    warn!(
                        operation_id = %config.operation_id,
                        "Lock extend returned false, attempting re-acquisition"
                    );
                    match dedicated_queue
                        .try_acquire_lock(&config.operation_id, config.lock_ttl)
                        .await
                    {
                        Ok(crate::orchestrator::task_queue::LockAcquire::Acquired)
                        | Ok(crate::orchestrator::task_queue::LockAcquire::Reclaimed) => info!(
                            operation_id = %config.operation_id,
                            "Operation lock re-acquired"
                        ),
                        Ok(crate::orchestrator::task_queue::LockAcquire::TakenOver {
                            previous_holder,
                        }) => warn!(
                            operation_id = %config.operation_id,
                            previous_holder = %previous_holder,
                            "Operation lock forcibly re-acquired via ARES_LOCK_TAKEOVER"
                        ),
                        Ok(crate::orchestrator::task_queue::LockAcquire::Contested {
                            current_holder,
                        }) => warn!(
                            operation_id = %config.operation_id,
                            current_holder = %current_holder,
                            "Lock re-acquisition failed — another orchestrator holds it"
                        ),
                        Err(e) => warn!(err = %e, "Lock re-acquisition error"),
                    }
                }
                Ok(Err(e)) => {
                    warn!(err = %e, "Failed to extend operation lock");
                }
                Err(_) => {
                    warn!("Lock extend timed out (Redis unresponsive?)");
                }
            }

            // Same tick, same dedicated connection: refresh the operation
            // status record's `updated_at` so `ares ops status` can distinguish
            // a live run from a wedged one. Without this the record is written
            // once at bootstrap and again at finalize, so a hung orchestrator
            // and a working one are indistinguishable from the outside.
            let mut conn = dedicated_queue.connection();
            let beat = tokio::time::timeout(
                extend_timeout,
                ares_core::state::heartbeat_operation_status(
                    &mut conn,
                    &config.operation_id,
                    config.heartbeat_interval.as_secs(),
                ),
            )
            .await;
            match beat {
                Ok(Ok(_)) => {}
                Ok(Err(e)) => warn!(err = %e, "Failed to heartbeat operation status"),
                Err(_) => warn!("Operation status heartbeat timed out (Redis unresponsive?)"),
            }
        }
    })
}

/// Spawn a background task that periodically:
/// 1. Reads heartbeat keys from Redis for all known agents
/// 2. Marks stale agents as offline
/// 3. Cleans up stale tasks
///
/// Lock refresh is handled by the separate `spawn_lock_keeper` task.
///
/// Runs until `shutdown` is signalled.
pub fn spawn_heartbeat_monitor(
    queue: TaskQueue,
    registry: AgentRegistry,
    tracker: ActiveTaskTracker,
    credential_inflight: CredentialInflight,
    state: SharedState,
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

            match run_heartbeat_sweep(&queue, &registry, &config).await {
                Err(e) => {
                    consecutive_failures += 1;
                    warn!(
                        attempt = consecutive_failures,
                        err = %e,
                        "Heartbeat sweep failed"
                    );
                }
                Ok(()) => consecutive_failures = 0,
            }

            // Clean up stale tasks (salvage any pending results first)
            if let Err(e) =
                cleanup_stale_tasks(&tracker, &queue, &credential_inflight, &state, &config).await
            {
                warn!(err = %e, "Stale task cleanup failed");
            }

            if consecutive_failures > 0 {
                let delay = std::time::Duration::from_secs(std::cmp::min(
                    15,
                    (consecutive_failures as u64) * 5,
                ));
                tokio::time::sleep(delay).await;
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

/// Pick the stale-reap threshold for a task by class. Non-LLM tasks (`crack`,
/// `command`) run far longer than an LLM turn — a hashcat crack is budgeted at
/// 20 min, serialized behind the single GPU permit, with a 25-min dispatch
/// ceiling — so they get the longer, un-halved `non_llm_timeout`; everything
/// else gets the (possibly hard-cap-halved) LLM timeout.
fn stale_threshold_for(
    task_type: &str,
    llm_timeout: std::time::Duration,
    non_llm_timeout: std::time::Duration,
) -> std::time::Duration {
    if is_non_llm_task(task_type) {
        non_llm_timeout
    } else {
        llm_timeout
    }
}

async fn release_reaped_task(
    reaped: &crate::orchestrator::routing::ActiveTask,
    credential_inflight: &CredentialInflight,
) {
    if let Some(ref key) = reaped.credential_key {
        credential_inflight.release(key).await;
    }
    if let Some(ref abort) = reaped.abort {
        abort.abort();
    }
}

/// Remove tasks that have been active longer than the configured stale timeout.
async fn cleanup_stale_tasks(
    tracker: &ActiveTaskTracker,
    queue: &TaskQueue,
    credential_inflight: &CredentialInflight,
    state: &SharedState,
    config: &OrchestratorConfig,
) -> Result<()> {
    let llm_count = tracker.llm_task_count().await;
    let hard_cap = config.hard_cap();

    // LLM tasks: shorten under hard cap to break the throttle deadlock faster.
    let llm_timeout = if llm_count >= hard_cap {
        config.stale_task_timeout / 2
    } else {
        config.stale_task_timeout
    };
    // Non-LLM tasks (`crack`, `command`) are not part of any LLM deadlock, so
    // the hard-cap halving must not apply to them. A hashcat crack is budgeted
    // at 20 min, serialized behind the single GPU permit, and the dispatcher
    // waits up to 25 min for its result — reaping at the 5-min LLM timeout
    // throws away an in-flight crack the tool would have finished (observed: a
    // cross-forest AS-REP crack reaped at age_secs=329, costing the second
    // forest its only foothold credential).
    let non_llm_timeout = config.non_llm_task_timeout;

    // Scan at the smaller horizon, then reap each task against its own
    // threshold so a slow crack isn't collected on the LLM timeout.
    let scan_horizon = llm_timeout.min(non_llm_timeout);
    let candidates = tracker.stale_tasks(scan_horizon).await;
    let mut reaped = 0usize;
    for task in &candidates {
        let task_timeout = stale_threshold_for(&task.task_type, llm_timeout, non_llm_timeout);
        if task.submitted_at.elapsed() < task_timeout {
            continue;
        }
        reaped += 1;
        warn!(
            task_id = %task.task_id,
            role = %task.role,
            age_secs = task.submitted_at.elapsed().as_secs(),
            "Removing stale task"
        );
        // Release the per-credential inflight slot if the stale task held
        // one. Without this the slot leaks: the spawned LLM future may
        // still be running long after the task was declared stale, and
        // every subsequent task with the same credential gets deferred
        // until the future eventually returns.
        if let Some(removed) = tracker.remove(&task.task_id).await {
            release_reaped_task(&removed, credential_inflight).await;
        }

        let age_secs = task.submitted_at.elapsed().as_secs();
        let reason = format!("stale task evicted after {age_secs}s without a result");

        if let Err(e) = queue.set_task_status(&task.task_id, "failed").await {
            warn!(
                task_id = %task.task_id,
                err = %e,
                "Failed to mark stale task status as failed"
            );
        }

        let result = ares_core::models::TaskResult {
            task_id: task.task_id.clone(),
            success: false,
            result: None,
            error: Some(reason),
            worker_pod: None,
            completed_at: Utc::now(),
        };
        if let Err(e) = state.complete_task(queue, &task.task_id, result).await {
            warn!(
                task_id = %task.task_id,
                err = %e,
                "Failed to move stale task from pending to completed"
            );
        }
    }

    if reaped > 0 {
        info!(
            removed = reaped,
            llm_count, hard_cap, "Stale task cleanup complete"
        );
    }

    Ok(())
}

/// Critical tools per worker role. If any of these are missing, operations
/// will be severely degraded.
pub(crate) const CRITICAL_TOOLS: &[(&str, &[&str])] = &[
    ("recon", &["nmap", "netexec"]),
    (
        "credential_access",
        &[
            "impacket-GetUserSPNs",
            "impacket-GetNPUsers",
            "impacket-secretsdump",
        ],
    ),
    ("privesc", &["impacket-findDelegation", "impacket-getST"]),
    (
        "lateral_movement",
        &[
            "impacket-psexec",
            "impacket-smbexec",
            "impacket-secretsdump",
        ],
    ),
];

/// Check if a binary is available on the local PATH.
async fn is_in_path(binary: &str) -> bool {
    tokio::process::Command::new("which")
        .arg(binary)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .await
        .is_ok_and(|s| s.success())
}

/// Report any missing critical tools per role.
///
/// In local-dispatch mode (`ARES_TOOL_DISPATCH=local`) there are no separate
/// worker processes publishing inventory to Redis, so we probe the local
/// PATH directly. In remote mode we read each worker's published inventory
/// from `ares:tools:ares-{role}-agent`.
pub(crate) async fn preflight_tool_check(
    conn: &mut redis::aio::ConnectionManager,
) -> Vec<(String, Vec<String>)> {
    use redis::AsyncCommands;

    let local_dispatch = std::env::var("ARES_TOOL_DISPATCH").as_deref() == Ok("local");
    let mut problems = Vec::new();

    for &(role, critical) in CRITICAL_TOOLS {
        let missing: Vec<String> = if local_dispatch {
            let mut out = Vec::new();
            for &tool in critical {
                if !is_in_path(tool).await {
                    out.push(tool.to_string());
                }
            }
            out
        } else {
            // Worker publishes inventory under hyphenated agent name
            // (see ares-cli/src/worker/config.rs: agent_name = format!("ares-{}-agent", role.replace('_', "-"))).
            // Mirror that here so role names with underscores resolve correctly.
            let agent_key = format!("ares:tools:ares-{}-agent", role.replace('_', "-"));
            let available: Vec<String> = match conn.get::<_, Option<String>>(&agent_key).await {
                Ok(Some(json)) => serde_json::from_str(&json).unwrap_or_default(),
                _ => {
                    // No inventory published yet — worker may not have started
                    warn!(
                        role = role,
                        "No tool inventory found — worker may not be running"
                    );
                    problems.push((
                        role.to_string(),
                        critical.iter().map(|s| s.to_string()).collect(),
                    ));
                    continue;
                }
            };

            critical
                .iter()
                .filter(|&&tool| !available.iter().any(|a| a == tool))
                .map(|s| s.to_string())
                .collect()
        };

        if !missing.is_empty() {
            problems.push((role.to_string(), missing));
        }
    }

    problems
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

    #[tokio::test]
    async fn agent_names_empty_initially() {
        let r = AgentRegistry::new();
        assert!(r.agent_names().await.is_empty());
    }

    #[tokio::test]
    async fn update_heartbeat_unknown_agent_ignored() {
        let r = AgentRegistry::new();
        // Updating a non-existent agent should not panic or insert
        r.update_heartbeat("nonexistent", "busy", Some("task-1"), Utc::now())
            .await;
        assert!(r.agent_names().await.is_empty());
    }

    #[test]
    fn crack_tasks_get_the_long_un_halved_threshold() {
        use std::time::Duration;
        // Simulate the hard-cap case: LLM tasks halved to 150s, non-LLM 6000s.
        let llm = Duration::from_secs(150);
        let non_llm = Duration::from_secs(6000);

        // A crack task must use the long threshold — this is the fix: a crack
        // was being reaped mid-run before hashcat returned the password.
        assert_eq!(stale_threshold_for("crack", llm, non_llm), non_llm);
        assert_eq!(stale_threshold_for("command", llm, non_llm), non_llm);

        // LLM tasks keep the short (halved) threshold so a real deadlock still
        // clears fast.
        assert_eq!(stale_threshold_for("recon", llm, non_llm), llm);
        assert_eq!(stale_threshold_for("credential_access", llm, non_llm), llm);
        assert_eq!(stale_threshold_for("lateral_movement", llm, non_llm), llm);
    }

    #[test]
    fn a_329s_crack_survives_but_a_329s_llm_task_is_reaped() {
        use std::time::Duration;
        // Reproduces the observed regression: a cross-forest AS-REP crack was
        // reaped at age_secs=329. With the fix, a crack at 329s is below its
        // 6000s threshold (survives), while an LLM task at 329s exceeds its
        // 300s threshold (reaped) — the two classes no longer share a fuse.
        let llm = Duration::from_secs(300);
        let non_llm = Duration::from_secs(6000);
        let age = Duration::from_secs(329);

        assert!(age < stale_threshold_for("crack", llm, non_llm));
        assert!(age >= stale_threshold_for("recon", llm, non_llm));
    }

    #[tokio::test]
    async fn reaping_an_active_task_aborts_its_spawned_future() {
        let tracker = ActiveTaskTracker::new();
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let spawned = tokio::spawn(async move {
            let _ = rx.await;
        });

        tracker
            .add(crate::orchestrator::routing::ActiveTask {
                task_id: "hung".into(),
                task_type: "recon".into(),
                role: "recon".into(),
                submitted_at: std::time::Instant::now(),
                credential_key: None,
                abort: None,
            })
            .await;
        tracker.set_abort("hung", spawned.abort_handle()).await;

        let removed = tracker.remove("hung").await.expect("task was tracked");
        release_reaped_task(&removed, &CredentialInflight::new(1)).await;

        let joined = tokio::time::timeout(std::time::Duration::from_secs(5), spawned)
            .await
            .expect("reaped task's future must stop promptly, not outlive the reap");
        assert!(
            joined.is_err_and(|e| e.is_cancelled()),
            "reaped task's future must actually stop, not merely detach"
        );
        drop(tx);
    }

    #[tokio::test]
    async fn set_abort_on_an_already_removed_task_is_a_noop() {
        let tracker = ActiveTaskTracker::new();
        let spawned = tokio::spawn(async {});
        tracker
            .set_abort("never-tracked", spawned.abort_handle())
            .await;
        assert_eq!(tracker.total().await, 0);
        let _ = spawned.await;
    }

    #[tokio::test]
    async fn mark_offline_unknown_agent_ignored() {
        let r = AgentRegistry::new();
        // Marking a non-existent agent offline should not panic
        r.mark_offline("nonexistent").await;
        assert!(r.agent_names().await.is_empty());
    }

    #[tokio::test]
    async fn stale_agents_empty_registry() {
        let r = AgentRegistry::new();
        assert!(r
            .stale_agents(std::time::Duration::from_secs(60))
            .await
            .is_empty());
    }

    #[tokio::test]
    async fn multiple_agents_stale_detection() {
        let r = AgentRegistry::new();
        r.register("agent-1", "recon").await;
        r.register("agent-2", "lateral").await;
        r.register("agent-3", "privesc").await;

        let old_ts = Utc::now() - chrono::Duration::seconds(300);
        r.update_heartbeat("agent-1", "idle", None, old_ts).await;
        r.update_heartbeat("agent-2", "busy", Some("task-x"), old_ts)
            .await;
        // agent-3 keeps fresh heartbeat
        r.update_heartbeat("agent-3", "idle", None, Utc::now())
            .await;

        let stale = r.stale_agents(std::time::Duration::from_secs(60)).await;
        assert_eq!(stale.len(), 2);
        let stale_names: Vec<&str> = stale.iter().map(|a| a.name.as_str()).collect();
        assert!(stale_names.contains(&"agent-1"));
        assert!(stale_names.contains(&"agent-2"));
    }

    #[tokio::test]
    async fn agent_state_fields_preserved() {
        let r = AgentRegistry::new();
        r.register("a1", "recon").await;
        let now = Utc::now();
        r.update_heartbeat("a1", "busy", Some("task-42"), now).await;

        let agents = r.agents.lock().await;
        let a = agents.get("a1").unwrap();
        assert_eq!(a.name, "a1");
        assert_eq!(a.role, "recon");
        assert_eq!(a.status, "busy");
        assert_eq!(a.current_task, Some("task-42".to_string()));
        assert_eq!(a.last_heartbeat, now);
    }

    #[tokio::test]
    async fn re_register_preserves_heartbeat() {
        let r = AgentRegistry::new();
        r.register("a1", "recon").await;
        let ts = Utc::now();
        r.update_heartbeat("a1", "busy", Some("t1"), ts).await;

        // Re-register with new role — heartbeat should still be preserved
        r.register("a1", "lateral").await;
        let agents = r.agents.lock().await;
        let a = agents.get("a1").unwrap();
        assert_eq!(a.role, "lateral");
        assert_eq!(a.status, "busy"); // status preserved from update
    }

    #[test]
    fn critical_tools_not_empty() {
        assert!(!CRITICAL_TOOLS.is_empty());
    }

    #[test]
    fn critical_tools_have_valid_roles() {
        let known_roles = ["recon", "credential_access", "privesc", "lateral_movement"];
        for &(role, tools) in CRITICAL_TOOLS {
            assert!(
                known_roles.contains(&role),
                "Unknown role in CRITICAL_TOOLS: {role}"
            );
            assert!(!tools.is_empty(), "No tools listed for role: {role}");
        }
    }

    #[test]
    fn critical_tools_no_duplicates() {
        for &(role, tools) in CRITICAL_TOOLS {
            let mut seen = std::collections::HashSet::new();
            for &tool in tools {
                assert!(
                    seen.insert(tool),
                    "Duplicate tool '{tool}' in role '{role}'"
                );
            }
        }
    }

    #[tokio::test]
    async fn is_in_path_finds_which_itself() {
        // `which` is on PATH on every dev box and CI; a nonsense binary is not.
        // Used by the local-dispatch branch of preflight_tool_check.
        assert!(is_in_path("which").await);
        assert!(!is_in_path("nonexistent_binary_for_preflight_xyz_123").await);
    }

    #[test]
    fn critical_tools_secretsdump_in_cred_and_lateral() {
        // secretsdump is critical for both credential_access and lateral
        let has_cred = CRITICAL_TOOLS
            .iter()
            .find(|&&(r, _)| r == "credential_access")
            .map(|&(_, tools)| tools.contains(&"impacket-secretsdump"))
            .unwrap_or(false);
        let has_lateral = CRITICAL_TOOLS
            .iter()
            .find(|&&(r, _)| r == "lateral_movement")
            .map(|&(_, tools)| tools.contains(&"impacket-secretsdump"))
            .unwrap_or(false);
        assert!(has_cred);
        assert!(has_lateral);
    }

    #[tokio::test]
    async fn mark_offline_then_re_heartbeat() {
        let r = AgentRegistry::new();
        r.register("a1", "recon").await;
        let old_ts = Utc::now() - chrono::Duration::seconds(300);
        r.update_heartbeat("a1", "idle", None, old_ts).await;
        r.mark_offline("a1").await;

        // Offline agent should not appear as stale
        assert!(r
            .stale_agents(std::time::Duration::from_secs(60))
            .await
            .is_empty());

        // But if it heartbeats again with a fresh timestamp and new status,
        // it should be alive again
        r.update_heartbeat("a1", "idle", None, Utc::now()).await;
        let agents = r.agents.lock().await;
        assert_eq!(agents.get("a1").unwrap().status, "idle");
    }

    #[tokio::test]
    async fn zero_timeout_makes_all_stale() {
        let r = AgentRegistry::new();
        r.register("a1", "recon").await;
        r.update_heartbeat("a1", "idle", None, Utc::now()).await;

        // With a zero timeout, the cutoff is "now", so any agent whose
        // heartbeat is at or before now should be stale. Due to timing,
        // this may or may not catch the just-registered agent, so we
        // just verify no panic occurs.
        let _stale = r.stale_agents(std::time::Duration::from_secs(0)).await;
    }
}
