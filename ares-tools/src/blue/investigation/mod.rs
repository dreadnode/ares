//! Investigation state mutation tools for blue team LLM agents.
//!
//! These tools run in-process (not dispatched to workers) and write
//! directly to Redis, following the same key patterns as
//! `BlueStateWriter`.

pub mod analysis;
pub mod read;
pub mod write;

// Redis key constants (mirrored from ares-core/src/state/keys.rs to avoid
// adding ares-core as a dependency of ares-tools)

pub(super) const BLUE_KEY_PREFIX: &str = "ares:blue:inv";
pub(super) const BLUE_KEY_EVIDENCE: &str = "evidence";
pub(super) const BLUE_KEY_TIMELINE: &str = "timeline";
pub(super) const BLUE_KEY_TECHNIQUES: &str = "techniques";
pub(super) const BLUE_KEY_TECHNIQUE_NAMES: &str = "technique_names";
pub(super) const BLUE_KEY_LATERAL: &str = "lateral";
pub(super) const BLUE_KEY_HOSTS: &str = "hosts";
pub(super) const BLUE_KEY_USERS: &str = "users";
pub(super) const BLUE_KEY_META: &str = "meta";

pub(super) const TTL_SECS: i64 = 86400;

pub(super) fn blue_key(investigation_id: &str, suffix: &str) -> String {
    format!("{BLUE_KEY_PREFIX}:{investigation_id}:{suffix}")
}

pub(super) async fn get_redis_connection() -> anyhow::Result<redis::aio::MultiplexedConnection> {
    use anyhow::Context;
    let url = std::env::var("ARES_REDIS_URL")
        .or_else(|_| std::env::var("REDIS_URL"))
        .unwrap_or_else(|_| "redis://127.0.0.1:6379".to_string());

    let client = redis::Client::open(url.as_str()).context("failed to create Redis client")?;
    let conn = client
        .get_multiplexed_async_connection()
        .await
        .context("failed to connect to Redis")?;
    Ok(conn)
}

pub(super) fn make_output(body: &str) -> crate::ToolOutput {
    crate::ToolOutput {
        stdout: body.to_string(),
        stderr: String::new(),
        exit_code: Some(0),
        success: true,
    }
}

pub(super) fn make_error(msg: &str) -> crate::ToolOutput {
    crate::ToolOutput {
        stdout: String::new(),
        stderr: msg.to_string(),
        exit_code: Some(1),
        success: false,
    }
}

pub use write::{
    add_evidence, add_evidence_batch, add_lateral_connection, add_technique, record_timeline_event,
    track_host_investigation, track_user_investigation, transition_stage,
};

pub use read::{get_investigation_context, get_investigation_summary, list_evidence};

pub use analysis::{
    analyze_lateral_movement, get_correlated_alerts, get_formatted_summary, get_queued_queries,
    get_suggested_evidence, pop_all_queued,
};
