//! Redis-backed deferred task queue.
//!
//! When the throttler decides to defer a task, it lands here in a ZSET keyed
//! by `ares:deferred:{operation_id}:{task_type}`. A background tokio task
//! periodically checks for tasks whose score (priority-weighted timestamp)
//! qualifies them for re-dispatch once concurrency slots open up.
//!
//! Score formula: `(priority * 1_000_000_000) + (unix_millis)`
//! Lower score = higher priority = processed first.
//!
//! Stays on Redis (not NATS): this is operation-scoped throttling state owned
//! by a single orchestrator, not a broker/transport concern. Priority ordering
//! via ZSET score is non-trivial to model in JetStream and offers no benefit
//! here since the queue is in-process. Redis remains for state; NATS handles
//! cross-process queues.

use anyhow::{Context, Result};
use chrono::Utc;
use redis::AsyncCommands;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::watch;
use tracing::{debug, info, warn};

use crate::orchestrator::config::OrchestratorConfig;
use crate::orchestrator::dispatcher::Dispatcher;
use crate::orchestrator::task_queue::TaskQueue;
use crate::orchestrator::throttling::{ThrottleDecision, Throttler};

/// Redis key prefix for deferred queues (matches Python `DEFERRED_QUEUE_PREFIX`).
pub const DEFERRED_QUEUE_PREFIX: &str = "ares:deferred";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeferredTask {
    pub priority: i32,
    pub enqueue_time: f64,
    pub task_type: String,
    pub target_role: String,
    pub payload: serde_json::Value,
    pub source_agent: String,
}

impl DeferredTask {
    /// ZSET score: priority bucket * 1e9 + enqueue millis.
    pub fn score(&self) -> f64 {
        (self.priority as f64) * 1_000_000_000.0 + self.enqueue_time * 1000.0
    }
}

/// Manages the Redis ZSET-backed deferred queue.
pub struct DeferredQueue {
    queue: TaskQueue,
    config: Arc<OrchestratorConfig>,
}

impl DeferredQueue {
    pub fn new(queue: TaskQueue, config: Arc<OrchestratorConfig>) -> Self {
        Self { queue, config }
    }

    /// Redis key for the per-task-type deferred ZSET.
    fn zset_key(&self, task_type: &str) -> String {
        format!(
            "{}:{}:{}",
            DEFERRED_QUEUE_PREFIX, self.config.operation_id, task_type
        )
    }

    /// Enqueue a task for later dispatch.
    ///
    /// Returns `true` if the task was accepted, `false` if the queue is full.
    pub async fn enqueue(&self, task: &DeferredTask) -> Result<bool> {
        let key = self.zset_key(&task.task_type);

        // Check per-type limit
        let mut conn = self.queue_conn();
        let current_len: usize = conn.zcard(&key).await.unwrap_or(0);
        if current_len >= self.config.max_deferred_per_type {
            debug!(
                task_type = %task.task_type,
                len = current_len,
                max = self.config.max_deferred_per_type,
                "Deferred queue full for type"
            );
            return Ok(false);
        }

        let json = serde_json::to_string(task).context("Failed to serialize DeferredTask")?;
        let score = task.score();

        conn.zadd::<_, _, _, ()>(&key, &json, score)
            .await
            .with_context(|| format!("ZADD to {key}"))?;

        info!(
            task_type = %task.task_type,
            role = %task.target_role,
            priority = task.priority,
            score,
            "Task deferred"
        );
        Ok(true)
    }

    /// Pop the highest-priority (lowest-score) task from any type ZSET.
    ///
    /// Scans all known task-type keys for this operation and picks the
    /// globally lowest score.
    pub async fn pop_best(&self) -> Result<Option<DeferredTask>> {
        let pattern = format!("{}:{}:*", DEFERRED_QUEUE_PREFIX, self.config.operation_id);
        let mut conn = self.queue_conn();

        // SCAN for matching keys (avoids blocking Redis with KEYS)
        let keys: Vec<String> = scan_keys_async(&mut conn, &pattern).await;

        if keys.is_empty() {
            return Ok(None);
        }

        // Find the globally best candidate across all type ZSETs
        let mut best: Option<(String, String, f64)> = None; // (key, member, score)

        for key in &keys {
            // Peek at the lowest-score member
            let members: Vec<(String, f64)> = redis::cmd("ZRANGEBYSCORE")
                .arg(key)
                .arg("-inf")
                .arg("+inf")
                .arg("WITHSCORES")
                .arg("LIMIT")
                .arg(0)
                .arg(1)
                .query_async(&mut conn)
                .await
                .unwrap_or_default();

            if let Some((member, score)) = members.into_iter().next() {
                let dominated = best.as_ref().map(|(_, _, s)| score < *s).unwrap_or(true);
                if dominated {
                    best = Some((key.clone(), member, score));
                }
            }
        }

        match best {
            Some((key, member, _score)) => {
                // Atomically remove it
                let removed: usize = conn.zrem(&key, &member).await.unwrap_or(0);
                if removed == 0 {
                    // Someone else grabbed it (unlikely in single-orchestrator mode)
                    return Ok(None);
                }
                let task: DeferredTask =
                    serde_json::from_str(&member).context("Bad DeferredTask JSON")?;
                Ok(Some(task))
            }
            None => Ok(None),
        }
    }

    /// Evict tasks older than `max_age` from all deferred ZSETs.
    pub async fn evict_stale(&self) -> Result<usize> {
        let pattern = format!("{}:{}:*", DEFERRED_QUEUE_PREFIX, self.config.operation_id);
        let mut conn = self.queue_conn();
        let keys: Vec<String> = scan_keys_async(&mut conn, &pattern).await;

        let max_age = self.config.deferred_task_max_age;
        let cutoff = Utc::now().timestamp() as f64 - max_age.as_secs_f64();
        let mut total_evicted = 0_usize;

        for key in &keys {
            // All members, check enqueue_time
            let members: Vec<(String, f64)> = redis::cmd("ZRANGEBYSCORE")
                .arg(key)
                .arg("-inf")
                .arg("+inf")
                .arg("WITHSCORES")
                .query_async(&mut conn)
                .await
                .unwrap_or_default();

            for (member, _score) in members {
                if let Ok(task) = serde_json::from_str::<DeferredTask>(&member) {
                    if task.enqueue_time < cutoff {
                        let _: usize = conn.zrem(key, &member).await.unwrap_or(0);
                        total_evicted += 1;
                        debug!(
                            task_type = %task.task_type,
                            age_secs = Utc::now().timestamp() as f64 - task.enqueue_time,
                            "Evicted stale deferred task"
                        );
                    }
                }
            }
        }

        if total_evicted > 0 {
            info!(evicted = total_evicted, "Deferred queue stale eviction");
        }
        Ok(total_evicted)
    }

    fn queue_conn(&self) -> redis::aio::ConnectionManager {
        // TaskQueue wraps a ConnectionManager which implements Clone cheaply
        // We access it through an internal method.
        self.queue.connection()
    }
}

/// Scan Redis keys matching a pattern using cursor iteration (avoids KEYS).
async fn scan_keys_async(conn: &mut redis::aio::ConnectionManager, pattern: &str) -> Vec<String> {
    let mut all_keys = Vec::new();
    let mut cursor: u64 = 0;
    loop {
        let result: Result<(u64, Vec<String>), _> = redis::cmd("SCAN")
            .arg(cursor)
            .arg("MATCH")
            .arg(pattern)
            .arg("COUNT")
            .arg(100)
            .query_async(conn)
            .await;
        match result {
            Ok((next_cursor, keys)) => {
                all_keys.extend(keys);
                cursor = next_cursor;
                if cursor == 0 {
                    break;
                }
            }
            Err(_) => break,
        }
    }
    all_keys
}

/// Spawn a tokio task that periodically drains the deferred queue whenever
/// the throttler allows new submissions.
///
/// Uses `Dispatcher::do_submit()` to route tasks directly to the LLM agent
/// loop (not Redis task queues, which have no consumer in this process).
pub fn spawn_deferred_processor(
    deferred: Arc<DeferredQueue>,
    dispatcher: Arc<Dispatcher>,
    throttler: Arc<Throttler>,
    config: Arc<OrchestratorConfig>,
    mut shutdown: watch::Receiver<bool>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(config.deferred_poll_interval);

        loop {
            tokio::select! {
                _ = interval.tick() => {},
                _ = shutdown.changed() => {
                    info!("Deferred processor shutting down");
                    break;
                }
            }

            // Evict stale tasks first
            if let Err(e) = deferred.evict_stale().await {
                warn!(err = %e, "Deferred eviction error");
            }

            // Try to drain as many as possible while slots are open
            let mut dispatched = 0_u32;
            loop {
                let Some(task) = (match deferred.pop_best().await {
                    Ok(t) => t,
                    Err(e) => {
                        warn!(err = %e, "pop_best error");
                        break;
                    }
                }) else {
                    break; // queue empty
                };

                // Re-check throttle before submitting
                let decision = throttler
                    .check(&task.task_type, &task.target_role, Some(&task.payload))
                    .await;

                match decision {
                    ThrottleDecision::Allow => {
                        // Pre-check credential concurrency to avoid a hot
                        // re-enqueue loop: submit_to_llm would re-defer the
                        // task if the credential is at capacity, but this
                        // drain loop would immediately pop it again.
                        if let Some(cred_key) =
                            crate::orchestrator::dispatcher::credential_key_from_payload(
                                &task.payload,
                            )
                        {
                            if !dispatcher.credential_inflight.can_acquire(&cred_key).await {
                                let _ = deferred.enqueue(&task).await;
                                break;
                            }
                        }

                        // Route directly to the LLM agent loop via Dispatcher.
                        // do_submit handles tracker.add() and throttler.record_dispatch().
                        match dispatcher
                            .do_submit(
                                &task.task_type,
                                &task.target_role,
                                task.payload.clone(),
                                task.priority,
                            )
                            .await
                        {
                            Ok(Some(tid)) => {
                                dispatched += 1;
                                info!(
                                    task_id = %tid,
                                    task_type = %task.task_type,
                                    "Deferred task dispatched"
                                );
                            }
                            Ok(None) => {
                                // Credential concurrency block or no role mapping.
                                // Task may have been re-enqueued by submit_to_llm;
                                // break to avoid hot loop.
                                break;
                            }
                            Err(e) => {
                                warn!(err = %e, "Failed to dispatch deferred task");
                                // Re-enqueue so it is not lost
                                let _ = deferred.enqueue(&task).await;
                                break;
                            }
                        }
                    }
                    ThrottleDecision::Defer | ThrottleDecision::Wait(_) => {
                        // Put it back; stop draining since capacity is full.
                        let _ = deferred.enqueue(&task).await;
                        break;
                    }
                }
            }

            if dispatched > 0 {
                info!(dispatched, "Deferred queue drain cycle");
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_task(priority: i32, enqueue_time: f64) -> DeferredTask {
        DeferredTask {
            priority,
            enqueue_time,
            task_type: "recon".into(),
            target_role: "recon".into(),
            payload: serde_json::json!({}),
            source_agent: "orchestrator".into(),
        }
    }

    #[test]
    fn higher_priority_lower_score() {
        let high = make_task(1, 1000.0);
        let low = make_task(5, 1000.0);
        assert!(high.score() < low.score());
    }

    #[test]
    fn same_priority_fifo_ordering() {
        let earlier = make_task(5, 1000.0);
        let later = make_task(5, 1010.0);
        assert!(earlier.score() < later.score());
    }

    #[test]
    fn score_deterministic() {
        let t = make_task(3, 1700000000.0);
        assert_eq!(t.score(), t.score());
    }

    #[test]
    fn priority_dominates_time_within_bucket() {
        // With small time deltas (< 1s apart), priority bucket dominates
        let p1_late = make_task(1, 100.010);
        let p5_early = make_task(5, 100.000);
        assert!(p1_late.score() < p5_early.score());
    }

    #[test]
    fn deferred_task_roundtrip() {
        let t = make_task(3, 1700000000.0);
        let json = serde_json::to_string(&t).unwrap();
        let t2: DeferredTask = serde_json::from_str(&json).unwrap();
        assert_eq!(t.priority, t2.priority);
        assert_eq!(t.task_type, t2.task_type);
        assert!((t.enqueue_time - t2.enqueue_time).abs() < f64::EPSILON);
    }

    #[test]
    fn score_zero_priority() {
        let t = make_task(0, 1000.0);
        // priority 0 => score is purely time-based
        assert_eq!(t.score(), 1000.0 * 1000.0);
    }

    #[test]
    fn score_negative_priority() {
        // Negative priority (if ever used) should produce lower score than positive
        let neg = make_task(-1, 1000.0);
        let pos = make_task(1, 1000.0);
        assert!(neg.score() < pos.score());
    }

    #[test]
    fn score_large_time_can_overflow_bucket() {
        // With very large time differences, time component can overwhelm
        // the priority bucket (1e9). This is by design -- the ZSET score
        // guarantees ordering within reasonable time windows (< ~1000s).
        let p1_late = make_task(1, 999_999_999.0);
        let p2_early = make_task(2, 0.0);
        // Time component dominates: 999_999_999 * 1000 >> 1e9 priority gap
        assert!(p1_late.score() > p2_early.score());
    }

    #[test]
    fn score_identical_inputs() {
        let t1 = make_task(3, 500.0);
        let t2 = make_task(3, 500.0);
        assert_eq!(t1.score(), t2.score());
    }

    #[test]
    fn deferred_task_fields_populated() {
        let t = DeferredTask {
            priority: 2,
            enqueue_time: 1700000000.0,
            task_type: "credential_access".into(),
            target_role: "credential_access".into(),
            payload: serde_json::json!({"target_ip": "192.168.58.10", "domain": "contoso.local"}),
            source_agent: "orchestrator".into(),
        };
        assert_eq!(t.priority, 2);
        assert_eq!(t.task_type, "credential_access");
        assert_eq!(t.target_role, "credential_access");
        assert_eq!(t.source_agent, "orchestrator");
        assert_eq!(t.payload["target_ip"].as_str().unwrap(), "192.168.58.10");
        assert_eq!(t.payload["domain"].as_str().unwrap(), "contoso.local");
    }

    #[test]
    fn deferred_task_roundtrip_with_payload() {
        let t = DeferredTask {
            priority: 5,
            enqueue_time: 1700000000.0,
            task_type: "lateral".into(),
            target_role: "lateral".into(),
            payload: serde_json::json!({
                "target_ip": "192.168.58.30",
                "technique": "psexec",
                "credential": {
                    "username": "admin",
                    "domain": "contoso.local"
                }
            }),
            source_agent: "orchestrator".into(),
        };
        let json = serde_json::to_string(&t).unwrap();
        let t2: DeferredTask = serde_json::from_str(&json).unwrap();
        assert_eq!(t2.payload["target_ip"].as_str().unwrap(), "192.168.58.30");
        assert_eq!(t2.payload["technique"].as_str().unwrap(), "psexec");
        assert_eq!(
            t2.payload["credential"]["username"].as_str().unwrap(),
            "admin"
        );
    }

    #[test]
    fn deferred_task_empty_payload_roundtrip() {
        let t = make_task(1, 500.0);
        let json = serde_json::to_string(&t).unwrap();
        let t2: DeferredTask = serde_json::from_str(&json).unwrap();
        assert_eq!(t2.payload, serde_json::json!({}));
    }

    #[test]
    fn score_formula_matches_spec() {
        // Verify score = priority * 1e9 + enqueue_time * 1000
        let t = make_task(3, 1700000000.0);
        let expected = 3.0 * 1_000_000_000.0 + 1700000000.0 * 1000.0;
        assert!((t.score() - expected).abs() < f64::EPSILON);
    }

    #[test]
    fn score_ordering_across_many_priorities() {
        // Verify monotonic ordering: p1 < p2 < p3 < p4 < p5 at same time
        let time = 1700000000.0;
        let scores: Vec<f64> = (1..=5).map(|p| make_task(p, time).score()).collect();
        for i in 0..scores.len() - 1 {
            assert!(
                scores[i] < scores[i + 1],
                "score for p={} should be less than p={}",
                i + 1,
                i + 2
            );
        }
    }

    #[test]
    fn deferred_queue_prefix_constant() {
        assert_eq!(DEFERRED_QUEUE_PREFIX, "ares:deferred");
    }

    #[test]
    fn make_task_defaults() {
        let t = make_task(1, 100.0);
        assert_eq!(t.task_type, "recon");
        assert_eq!(t.target_role, "recon");
        assert_eq!(t.source_agent, "orchestrator");
    }

    #[test]
    fn different_task_types_same_score_when_same_priority_and_time() {
        let t1 = DeferredTask {
            priority: 3,
            enqueue_time: 1000.0,
            task_type: "recon".into(),
            target_role: "recon".into(),
            payload: serde_json::json!({}),
            source_agent: "orchestrator".into(),
        };
        let t2 = DeferredTask {
            priority: 3,
            enqueue_time: 1000.0,
            task_type: "lateral".into(),
            target_role: "lateral".into(),
            payload: serde_json::json!({}),
            source_agent: "orchestrator".into(),
        };
        // Score only depends on priority and time, not task type
        assert_eq!(t1.score(), t2.score());
    }
}
