//! Worker configuration from environment variables.
//!
//! Maps to the Python config module's `get_redis_url()`, `get_agent_task_timeout()`,
//! and worker-specific env vars used in `_worker.py`.

use std::env;
use std::time::Duration;

/// Worker execution mode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkerMode {
    /// Full task execution: consume from `ares:tasks:{role}`, expand composite
    /// tasks, run tools, push results. This is the default mode used when
    /// Python workers or standalone Rust workers handle entire tasks.
    Task,

    /// Thin tool executor: consume individual tool calls from
    /// `ares:tool_exec:{role}`, dispatch via `ares_tools::dispatch()`, push
    /// results to `ares:tool_results:{call_id}`. Used when the Rust
    /// orchestrator drives the LLM agent loop (ARES_LLM_MODEL).
    ToolExec,

    /// Blue team task execution: consume from `ares:blue:tasks:global:{role}`,
    /// run the blue team LLM agent loop with HTTP-based tools (Loki,
    /// Prometheus, detection queries), push results to `ares:blue:results:`.
    #[cfg(feature = "blue")]
    BlueTask,
}

/// Worker configuration parsed from environment variables.
#[derive(Debug, Clone)]
pub struct WorkerConfig {
    /// Redis connection URL (ARES_REDIS_URL).
    pub redis_url: String,

    /// Worker role matching `AgentRole` values: credential_access, cracker, lateral, acl, privesc, coercion.
    pub worker_role: String,

    /// Kubernetes pod name (HOSTNAME fallback).
    pub pod_name: String,

    /// Logical agent name derived from role (e.g., "ares-lateral-agent").
    pub agent_name: String,

    /// Active operation ID, if known at startup.
    pub operation_id: Option<String>,

    /// Worker mode: "task" (default) or "tool_exec" (ARES_WORKER_MODE).
    pub mode: WorkerMode,

    /// Maximum time for a single LLM agent task before kill (ARES_AGENT_TASK_TIMEOUT).
    /// Default: 600 seconds.
    pub task_timeout: Duration,

    /// Heartbeat interval — how often we refresh `ares:heartbeat:{agent}`.
    /// Default: 15 seconds.
    pub heartbeat_interval: Duration,

    /// Heartbeat TTL in Redis. Must be > heartbeat_interval.
    /// Default: 60 seconds (matches Python's HEARTBEAT_TTL).
    pub heartbeat_ttl: Duration,

    /// BLPOP timeout for polling the task queue.
    /// Default: 5 seconds (matches Python's poll_task default).
    pub poll_timeout: Duration,
}

impl WorkerConfig {
    /// Parse configuration from environment variables.
    ///
    /// Required:
    /// - `ARES_REDIS_URL` — Redis connection string
    /// - `ARES_WORKER_ROLE` — Worker role (credential_access, cracker, lateral, acl, privesc, coercion)
    ///
    /// Optional:
    /// - `ARES_POD_NAME` / `HOSTNAME` — Pod name (default: "unknown")
    /// - `ARES_OPERATION_ID` — Active operation ID
    /// - `ARES_WORKER_MODE` — "task" (default) or "tool_exec"
    /// - `ARES_AGENT_TASK_TIMEOUT` — Task timeout in seconds (default: 600)
    /// - `ARES_HEARTBEAT_INTERVAL` — Heartbeat interval in seconds (default: 15)
    /// - `ARES_HEARTBEAT_TTL` — Heartbeat TTL in seconds (default: 60)
    /// - `ARES_POLL_TIMEOUT` — BLPOP timeout in seconds (default: 5)
    pub fn from_env() -> anyhow::Result<Self> {
        let redis_url = env::var("ARES_REDIS_URL")
            .map_err(|_| anyhow::anyhow!("ARES_REDIS_URL is required"))?;

        let worker_role = env::var("ARES_WORKER_ROLE")
            .map_err(|_| anyhow::anyhow!("ARES_WORKER_ROLE is required"))?;

        let pod_name = env::var("ARES_POD_NAME")
            .or_else(|_| env::var("HOSTNAME"))
            .unwrap_or_else(|_| "unknown".to_string());

        let agent_name = format!("ares-{}-agent", worker_role.replace('_', "-"));

        let operation_id = env::var("ARES_OPERATION_ID").ok();

        let mode = match env::var("ARES_WORKER_MODE").as_deref() {
            Ok("tool_exec") => WorkerMode::ToolExec,
            #[cfg(feature = "blue")]
            Ok("blue_task") => WorkerMode::BlueTask,
            _ => WorkerMode::Task,
        };

        let task_timeout = Duration::from_secs(
            env::var("ARES_AGENT_TASK_TIMEOUT")
                .ok()
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(600),
        );

        let heartbeat_interval = Duration::from_secs(
            env::var("ARES_HEARTBEAT_INTERVAL")
                .ok()
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(15),
        );

        let heartbeat_ttl = Duration::from_secs(
            env::var("ARES_HEARTBEAT_TTL")
                .ok()
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(60),
        );

        let poll_timeout = Duration::from_secs(
            env::var("ARES_POLL_TIMEOUT")
                .ok()
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(5),
        );

        Ok(Self {
            redis_url,
            worker_role,
            pod_name,
            agent_name,
            operation_id,
            mode,
            task_timeout,
            heartbeat_interval,
            heartbeat_ttl,
            poll_timeout,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Combined test to avoid env var race conditions between parallel tests.
    #[test]
    fn from_env_all_scenarios() {
        // Missing redis URL fails
        std::env::remove_var("ARES_REDIS_URL");
        std::env::set_var("ARES_WORKER_ROLE", "recon");
        assert!(WorkerConfig::from_env().is_err());

        // Missing role fails
        std::env::set_var("ARES_REDIS_URL", "redis://localhost");
        std::env::remove_var("ARES_WORKER_ROLE");
        assert!(WorkerConfig::from_env().is_err());

        // Defaults applied
        std::env::set_var("ARES_WORKER_ROLE", "recon");
        std::env::remove_var("ARES_WORKER_MODE");
        let c = WorkerConfig::from_env().unwrap();
        assert_eq!(c.task_timeout, Duration::from_secs(600));
        assert_eq!(c.heartbeat_interval, Duration::from_secs(15));
        assert_eq!(c.heartbeat_ttl, Duration::from_secs(60));
        assert_eq!(c.poll_timeout, Duration::from_secs(5));
        assert!(c.operation_id.is_none());
        assert_eq!(c.mode, WorkerMode::Task);

        // Worker mode: tool_exec
        std::env::set_var("ARES_WORKER_MODE", "tool_exec");
        let c = WorkerConfig::from_env().unwrap();
        assert_eq!(c.mode, WorkerMode::ToolExec);

        // Worker mode: blue_task
        #[cfg(feature = "blue")]
        {
            std::env::set_var("ARES_WORKER_MODE", "blue_task");
            let c = WorkerConfig::from_env().unwrap();
            assert_eq!(c.mode, WorkerMode::BlueTask);
            std::env::remove_var("ARES_WORKER_MODE");
        }

        // Agent name from role
        std::env::set_var("ARES_WORKER_ROLE", "credential_access");
        let c = WorkerConfig::from_env().unwrap();
        assert_eq!(c.agent_name, "ares-credential-access-agent");
        assert_eq!(c.worker_role, "credential_access");

        std::env::remove_var("ARES_REDIS_URL");
        std::env::remove_var("ARES_WORKER_ROLE");
    }
}
