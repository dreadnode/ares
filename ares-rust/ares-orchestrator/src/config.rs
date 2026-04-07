//! Configuration loaded from environment variables.
//!
//! Mirrors the Python `ares.core.config` module. Every knob exposed to the
//! Python orchestrator is also configurable here so the Rust binary is a
//! drop-in replacement.

use std::env;
use std::time::Duration;

/// All tunables for the orchestrator, loaded once at startup.
#[derive(Debug, Clone)]
pub struct OrchestratorConfig {
    /// Redis connection URL (supports `redis://` and `redis+sentinel://`).
    pub redis_url: String,

    /// Operation ID this orchestrator instance manages.
    pub operation_id: String,

    /// Maximum number of concurrent LLM-consuming tasks across all roles.
    pub max_concurrent_tasks: usize,

    /// Interval between heartbeat sweeps.
    pub heartbeat_interval: Duration,

    /// How long before an agent with no heartbeat is considered dead.
    pub heartbeat_timeout: Duration,

    /// How often the result consumer polls Redis for completed tasks.
    pub result_poll_interval: Duration,

    /// TTL for the operation lock key (`ares:lock:{op_id}`).
    pub lock_ttl: Duration,

    /// How often the deferred-queue processor wakes up.
    pub deferred_poll_interval: Duration,

    /// Maximum number of tasks a single role can have in-flight.
    pub max_tasks_per_role: usize,

    /// Global rate-limit: minimum delay between consecutive task dispatches.
    pub dispatch_delay: Duration,

    /// How long before an in-progress task with no activity is considered stale.
    pub stale_task_timeout: Duration,

    /// Maximum age for deferred tasks before eviction (seconds).
    pub deferred_task_max_age: Duration,

    /// Maximum number of deferred tasks per task type.
    pub max_deferred_per_type: usize,

    /// Maximum total deferred tasks across all types.
    pub max_deferred_total: usize,
}

impl OrchestratorConfig {
    /// Load configuration from environment variables with sensible defaults.
    pub fn from_env() -> anyhow::Result<Self> {
        let redis_url =
            env::var("ARES_REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379/0".to_string());

        let operation_id = env::var("ARES_OPERATION_ID")
            .map_err(|_| anyhow::anyhow!("ARES_OPERATION_ID is required"))?;

        let max_concurrent_tasks = parse_env("ARES_MAX_CONCURRENT_TASKS", 8);
        let heartbeat_interval_secs = parse_env("ARES_HEARTBEAT_INTERVAL_SECS", 30);
        let heartbeat_timeout_secs = parse_env("ARES_HEARTBEAT_TIMEOUT_SECS", 120);
        let result_poll_interval_ms = parse_env("ARES_RESULT_POLL_INTERVAL_MS", 500);
        let lock_ttl_secs = parse_env("ARES_LOCK_TTL_SECS", 300);
        let deferred_poll_interval_secs = parse_env("ARES_DEFERRED_POLL_INTERVAL_SECS", 10);
        let max_tasks_per_role = parse_env("ARES_MAX_TASKS_PER_ROLE", 3);
        let dispatch_delay_ms = parse_env("ARES_DISPATCH_DELAY_MS", 200);
        let stale_task_timeout_secs = parse_env("ARES_STALE_TASK_TIMEOUT_SECS", 300);
        let deferred_task_max_age_secs = parse_env("ARES_DEFERRED_TASK_MAX_AGE_SECS", 300);
        let max_deferred_per_type = parse_env("ARES_MAX_DEFERRED_PER_TYPE", 5);
        let max_deferred_total = parse_env("ARES_MAX_DEFERRED_TOTAL", 20);

        Ok(Self {
            redis_url,
            operation_id,
            max_concurrent_tasks,
            heartbeat_interval: Duration::from_secs(heartbeat_interval_secs),
            heartbeat_timeout: Duration::from_secs(heartbeat_timeout_secs),
            result_poll_interval: Duration::from_millis(result_poll_interval_ms),
            lock_ttl: Duration::from_secs(lock_ttl_secs),
            deferred_poll_interval: Duration::from_secs(deferred_poll_interval_secs),
            max_tasks_per_role,
            dispatch_delay: Duration::from_millis(dispatch_delay_ms),
            stale_task_timeout: Duration::from_secs(stale_task_timeout_secs),
            deferred_task_max_age: Duration::from_secs(deferred_task_max_age_secs),
            max_deferred_per_type,
            max_deferred_total,
        })
    }

    /// Hard cap = 1.5x the soft concurrency limit. Tasks above this are deferred.
    pub fn hard_cap(&self) -> usize {
        (self.max_concurrent_tasks as f64 * 1.5) as usize
    }
}

/// Parse an environment variable into a numeric type, falling back to `default`.
fn parse_env<T: std::str::FromStr>(key: &str, default: T) -> T {
    env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper to create a config without env vars.
    pub(crate) fn make_config(max_tasks: usize) -> OrchestratorConfig {
        OrchestratorConfig {
            redis_url: "redis://localhost".into(),
            operation_id: "test-op".into(),
            max_concurrent_tasks: max_tasks,
            heartbeat_interval: Duration::from_secs(30),
            heartbeat_timeout: Duration::from_secs(120),
            result_poll_interval: Duration::from_millis(500),
            lock_ttl: Duration::from_secs(300),
            deferred_poll_interval: Duration::from_secs(10),
            max_tasks_per_role: 3,
            dispatch_delay: Duration::from_millis(0),
            stale_task_timeout: Duration::from_secs(300),
            deferred_task_max_age: Duration::from_secs(300),
            max_deferred_per_type: 5,
            max_deferred_total: 20,
        }
    }

    #[test]
    fn hard_cap_is_1_5x() {
        assert_eq!(make_config(8).hard_cap(), 12);
        assert_eq!(make_config(10).hard_cap(), 15);
        assert_eq!(make_config(1).hard_cap(), 1);
    }

    #[test]
    fn from_env_defaults_and_missing_op_id() {
        // Combined test to avoid env var race conditions between parallel tests.
        std::env::remove_var("ARES_OPERATION_ID");
        assert!(OrchestratorConfig::from_env().is_err());

        std::env::set_var("ARES_OPERATION_ID", "test-op-1");
        let c = OrchestratorConfig::from_env().unwrap();
        assert_eq!(c.max_concurrent_tasks, 8);
        assert_eq!(c.heartbeat_interval, Duration::from_secs(30));
        assert_eq!(c.max_tasks_per_role, 3);
        assert_eq!(c.dispatch_delay, Duration::from_millis(200));
        std::env::remove_var("ARES_OPERATION_ID");
    }
}
