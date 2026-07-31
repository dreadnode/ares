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
use std::sync::{Arc, LazyLock};
use tokio::sync::watch;
use tracing::{debug, info, warn};

use ares_core::blue_invalidation::ContainmentKind;

use crate::orchestrator::config::OrchestratorConfig;
use crate::orchestrator::dispatcher::Dispatcher;
use crate::orchestrator::diversity;
use crate::orchestrator::task_queue::TaskQueue;
use crate::orchestrator::throttling::{ThrottleDecision, Throttler};

/// Redis key prefix for deferred queues.
pub const DEFERRED_QUEUE_PREFIX: &str = "ares:deferred";

/// Atomic enqueue: signature dedup → per-type cap → global cap → ZADD →
/// INCR counter → SADD signature.
///
/// KEYS[1] = per-type ZSET
/// KEYS[2] = total counter
/// KEYS[3] = per-type signature SET
/// ARGV[1] = score
/// ARGV[2] = member JSON
/// ARGV[3] = max_per_type
/// ARGV[4] = max_total
/// ARGV[5] = signature (stable hash of task identity)
///
/// Returns: `1` accepted, `0` per-type full, `-1` global full,
/// `-2` member already present (timestamp-identical re-enqueue),
/// `-3` duplicate signature (logical duplicate already deferred — Bug J).
///
/// The signature dedup is the load-bearing change for Bug J: multiple
/// automation rules race to enqueue equivalent tasks every tick. Without
/// it, each call produces a JSON member with a distinct timestamp, ZADD
/// accepts every one, and the cred-gated queue saturates within minutes
/// against a tuple the worker pool is already happy to drain.
static ENQUEUE_SCRIPT: LazyLock<redis::Script> = LazyLock::new(|| {
    redis::Script::new(
        r"
        if redis.call('SISMEMBER', KEYS[3], ARGV[5]) == 1 then return -3 end
        if redis.call('ZCARD', KEYS[1]) >= tonumber(ARGV[3]) then return 0 end
        if tonumber(redis.call('GET', KEYS[2]) or '0') >= tonumber(ARGV[4]) then return -1 end
        local added = redis.call('ZADD', KEYS[1], ARGV[1], ARGV[2])
        if added == 0 then return -2 end
        redis.call('INCR', KEYS[2])
        redis.call('SADD', KEYS[3], ARGV[5])
        return 1
        ",
    )
});

/// Atomic ZREM + counter DECR + signature SREM. Fully removes a task and
/// releases its dedup signature — used by `evict_stale` where a stale task
/// is being discarded outright and a future re-enqueue of equivalent work
/// should succeed.
///
/// KEYS[1] = per-type ZSET
/// KEYS[2] = total counter
/// KEYS[3] = per-type signature SET
/// ARGV[1] = member
/// ARGV[2] = signature
///
/// Returns the number of elements removed (0 or 1). Counter never goes
/// negative; signature SET shrinks in lockstep with the ZSET so a future
/// enqueue of the same logical task is no longer treated as duplicate.
static REMOVE_SCRIPT: LazyLock<redis::Script> = LazyLock::new(|| {
    redis::Script::new(
        r"
        local removed = redis.call('ZREM', KEYS[1], ARGV[1])
        if removed > 0 then
            local cur = tonumber(redis.call('GET', KEYS[2]) or '0')
            if cur > 0 then redis.call('DECR', KEYS[2]) end
            redis.call('SREM', KEYS[3], ARGV[2])
        end
        return removed
        ",
    )
});

/// Atomic ZREM + counter DECR, keeping the signature in the SET. Used by
/// `pop_best` so the sig stays asserted while the caller decides whether
/// to dispatch the task or drop it as contained. Closes the race that
/// existed when the sig was released at pop-time and re-added post-drop:
/// a producer squeezing an equivalent enqueue into that window used to
/// slip past the tombstone and get counted as a second distinct drop.
/// Callers must invoke `release_signature` once dispatch is decided
/// (contained tasks leave the sig in place as the tombstone).
///
/// KEYS[1] = per-type ZSET
/// KEYS[2] = total counter
/// ARGV[1] = member
///
/// Returns the number of elements removed (0 or 1).
static POP_HOLD_SCRIPT: LazyLock<redis::Script> = LazyLock::new(|| {
    redis::Script::new(
        r"
        local removed = redis.call('ZREM', KEYS[1], ARGV[1])
        if removed > 0 then
            local cur = tonumber(redis.call('GET', KEYS[2]) or '0')
            if cur > 0 then redis.call('DECR', KEYS[2]) end
        end
        return removed
        ",
    )
});

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

    /// Stable signature used by the deferred queue's producer-side dedup
    /// (Bug J). Hashes the task-identity tuple `(task_type, target_role,
    /// technique, target_ip, credential_key, finding_key)` — explicitly
    /// excluding the timestamp so two automation rules dispatching
    /// equivalent work in the same tick produce the same signature and only
    /// the first reaches the ZSET.
    ///
    /// `finding_key` is `(vuln_id, acl_type, source_user, target_user)`,
    /// read from the payload root and from a nested `step` object. Without
    /// it every ACL edge in a domain — same technique, same DC, same
    /// credential, different principals — hashes identically, so paths
    /// 2..N collapse into path 1 and the callers retire them as
    /// successfully dispatched. That is the whole 19,453-collected /
    /// 1-acted-on gap.
    ///
    /// Priority stays out of the hash: a higher-priority duplicate isn't
    /// useful — the existing copy will run and produce the same outcome.
    pub fn signature(&self) -> String {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let technique = self
            .payload
            .get("technique")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let target_ip = self
            .payload
            .get("target_ip")
            .or_else(|| self.payload.get("dc_ip"))
            .or_else(|| self.payload.get("target"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let credential_key = self
            .payload
            .get("credential")
            .and_then(|c| {
                let user = c.get("username").and_then(|v| v.as_str()).unwrap_or("");
                let dom = c.get("domain").and_then(|v| v.as_str()).unwrap_or("");
                if user.is_empty() && dom.is_empty() {
                    None
                } else {
                    Some(format!("{}@{}", user.to_lowercase(), dom.to_lowercase()))
                }
            })
            .unwrap_or_default();
        let finding_key = self.finding_key();
        let mut h = DefaultHasher::new();
        self.task_type.hash(&mut h);
        self.target_role.hash(&mut h);
        technique.to_lowercase().hash(&mut h);
        target_ip.hash(&mut h);
        credential_key.hash(&mut h);
        finding_key.hash(&mut h);
        format!("{:x}", h.finish())
    }

    /// `(vuln_id, acl_type, source_user, target_user)` joined into one
    /// lowercase key, empty when the payload carries none of them.
    ///
    /// Looks at the payload root first, then at a nested `step` object —
    /// `auto_acl_chain_follow` wraps the whole edge under `step`, so a
    /// root-only lookup would leave every chain step signature-identical.
    fn finding_key(&self) -> String {
        let step = self.payload.get("step");
        let field = |name: &str| -> String {
            self.payload
                .get(name)
                .or_else(|| step.and_then(|s| s.get(name)))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_lowercase()
        };
        let first_of = |a: &str, b: &str| -> String {
            let v = field(a);
            if v.is_empty() {
                field(b)
            } else {
                v
            }
        };
        let parts = [
            field("vuln_id"),
            field("acl_type"),
            first_of("source_user", "source"),
            first_of("target_user", "target"),
        ];
        if parts.iter().all(String::is_empty) {
            return String::new();
        }
        parts.join("|")
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

    /// Redis key for the per-task-type signature SET — paired with the
    /// ZSET and maintained via Lua where they need to be atomic. Used by
    /// the producer-side dedup gate (Bug J): two automation rules racing
    /// to enqueue the same `(task_type, role, technique, target_ip, cred)`
    /// tuple both compute the same signature, and only the first one
    /// reaches the ZSET.
    ///
    /// Lifecycle:
    /// * `enqueue` — SADD sig atomically with the ZADD.
    /// * `pop_best` — leaves the sig in place while the caller decides.
    /// * `release_signature` — caller SREMs sig once the popped task is
    ///   headed for dispatch or being re-enqueued via `enqueue`.
    /// * Contained task — sig is never released, acting as a permanent
    ///   tombstone that blocks re-emission by producers.
    /// * `evict_stale` — SREMs sig alongside the ZREM (task fully gone).
    fn sig_key(&self, task_type: &str) -> String {
        format!(
            "{}:{}:{}:sigs",
            DEFERRED_QUEUE_PREFIX, self.config.operation_id, task_type
        )
    }

    /// Redis key for the global cardinality counter. Mutations to the ZSETs
    /// are paired with INCR/DECR via Lua so this stays consistent.
    fn total_key(&self) -> String {
        format!(
            "{}:{}:__total",
            DEFERRED_QUEUE_PREFIX, self.config.operation_id
        )
    }

    /// Enqueue a task for later dispatch.
    ///
    /// Returns `true` if the task was accepted (or already deferred under
    /// the same signature — idempotent), `false` if either cap is full.
    ///
    /// Producer-side dedup (Bug J): equivalent tasks racing across
    /// automation rules collapse to a single ZSET entry via the
    /// signature SET — see [`DeferredTask::signature`] for what's
    /// considered equivalent.
    pub async fn enqueue(&self, task: &DeferredTask) -> Result<bool> {
        let key = self.zset_key(&task.task_type);
        let total_key = self.total_key();
        let sig_key = self.sig_key(&task.task_type);
        let signature = task.signature();
        let json = serde_json::to_string(task).context("Failed to serialize DeferredTask")?;
        let score = task.score();
        let mut conn = self.queue_conn();

        let result: i64 = ENQUEUE_SCRIPT
            .key(&key)
            .key(&total_key)
            .key(&sig_key)
            .arg(score)
            .arg(&json)
            .arg(self.config.max_deferred_per_type)
            .arg(self.config.max_deferred_total)
            .arg(&signature)
            .invoke_async(&mut conn)
            .await
            .with_context(|| format!("Deferred enqueue script on {key}"))?;

        match result {
            1 => {
                info!(
                    task_type = %task.task_type,
                    role = %task.target_role,
                    priority = task.priority,
                    score,
                    signature = %signature,
                    "Task deferred"
                );
                Ok(true)
            }
            0 => {
                debug!(
                    task_type = %task.task_type,
                    max = self.config.max_deferred_per_type,
                    "Deferred queue full for type"
                );
                Ok(false)
            }
            -1 => {
                debug!(
                    task_type = %task.task_type,
                    max = self.config.max_deferred_total,
                    "Deferred queue full globally"
                );
                Ok(false)
            }
            -2 => {
                // ZADD returned 0 — member already present. Treat as accepted
                // (idempotent re-enqueue from the drain loop's retry paths).
                Ok(true)
            }
            -3 => {
                // Signature already present — a logically equivalent task is
                // already deferred (or recently dequeued without SREM lag).
                // Treat as accepted from the caller's perspective: the work
                // is already in the pipeline. Bug J.
                debug!(
                    task_type = %task.task_type,
                    signature = %signature,
                    "Deferred enqueue collapsed by signature dedup (Bug J)"
                );
                Ok(true)
            }
            other => {
                warn!(result = other, "Unexpected enqueue script result");
                Ok(false)
            }
        }
    }

    /// Pop a task from any type ZSET.
    ///
    /// Default behaviour: pick the globally lowest score (highest priority)
    /// across all per-type ZSETs. When `selection_temperature > 0`, softmax-
    /// sample among the per-type lowest candidates by priority instead, so the
    /// deferred drain order varies across runs (attack-path diversity). At
    /// temperature 0 the selection is exact argmin, identical to before.
    pub async fn pop_best(&self) -> Result<Option<DeferredTask>> {
        let pattern = format!("{}:{}:*", DEFERRED_QUEUE_PREFIX, self.config.operation_id);
        let total_key = self.total_key();
        let mut conn = self.queue_conn();

        // SCAN for matching keys (avoids blocking Redis with KEYS)
        let keys: Vec<String> = scan_keys_async(&mut conn, &pattern).await;

        if keys.is_empty() {
            return Ok(None);
        }

        // Peek the lowest-score member of each per-type ZSET — these are the
        // selection candidates.
        let mut candidates: Vec<(String, String, DeferredTask)> = Vec::new(); // (key, member, task)
        for key in &keys {
            if key == &total_key {
                continue;
            }
            // Skip the signature SETs — they share the queue prefix but
            // are not ZSETs (Bug J). ZRANGEBYSCORE on a SET returns
            // WRONGTYPE; better to skip cleanly than catch the error.
            if key.ends_with(":sigs") {
                continue;
            }
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

            if let Some((member, _score)) = members.into_iter().next() {
                if let Ok(task) = serde_json::from_str::<DeferredTask>(&member) {
                    candidates.push((key.clone(), member, task));
                }
            }
        }

        if candidates.is_empty() {
            return Ok(None);
        }

        let temperature = self.config.strategy.selection_temperature;
        let idx = if temperature > 0.0 {
            let priorities: Vec<f32> = candidates
                .iter()
                .map(|(_, _, t)| t.priority as f32)
                .collect();
            let mut rng = rand::rng();
            diversity::softmax_select_index(&priorities, temperature, &mut rng).unwrap_or(0)
        } else {
            // Exact argmin by score (previous behaviour; first minimum wins).
            candidates
                .iter()
                .enumerate()
                .min_by(|(_, a), (_, b)| {
                    a.2.score()
                        .partial_cmp(&b.2.score())
                        .unwrap_or(std::cmp::Ordering::Equal)
                })
                .map(|(i, _)| i)
                .unwrap_or(0)
        };

        let (key, member, task) = candidates
            .into_iter()
            .nth(idx)
            .expect("selection index within bounds");
        // Hold the signature in the SET across pop → decision. If the caller
        // drops the task as contained, the sig stays as the tombstone that
        // blocks re-emission. If it dispatches or re-enqueues, it must call
        // `release_signature` first.
        let removed: i64 = POP_HOLD_SCRIPT
            .key(&key)
            .key(&total_key)
            .arg(&member)
            .invoke_async(&mut conn)
            .await
            .unwrap_or(0);
        if removed == 0 {
            // Someone else grabbed it (unlikely in single-orchestrator mode)
            return Ok(None);
        }
        Ok(Some(task))
    }

    /// Evict tasks older than `max_age` from all deferred ZSETs.
    pub async fn evict_stale(&self) -> Result<usize> {
        let pattern = format!("{}:{}:*", DEFERRED_QUEUE_PREFIX, self.config.operation_id);
        let mut conn = self.queue_conn();
        let keys: Vec<String> = scan_keys_async(&mut conn, &pattern).await;
        let total_key = self.total_key();

        let max_age = self.config.deferred_task_max_age;
        let cutoff = Utc::now().timestamp() as f64 - max_age.as_secs_f64();
        let mut total_evicted = 0_usize;

        for key in &keys {
            if key == &total_key {
                continue;
            }
            // Skip signature SETs — they share the queue prefix but are
            // not ZSETs (Bug J). ZRANGEBYSCORE on a SET returns WRONGTYPE.
            if key.ends_with(":sigs") {
                continue;
            }
            let sig_key = format!("{key}:sigs");
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
                        let signature = task.signature();
                        let removed: i64 = REMOVE_SCRIPT
                            .key(key)
                            .key(&total_key)
                            .key(&sig_key)
                            .arg(&member)
                            .arg(&signature)
                            .invoke_async(&mut conn)
                            .await
                            .unwrap_or(0);
                        if removed > 0 {
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
        }

        if total_evicted > 0 {
            info!(evicted = total_evicted, "Deferred queue stale eviction");
        }
        Ok(total_evicted)
    }

    /// Total number of deferred tasks across all type ZSETs. O(1) — reads the
    /// counter maintained atomically by the enqueue/remove scripts.
    pub async fn total_count(&self) -> usize {
        let mut conn = self.queue_conn();
        let raw: Option<i64> = conn.get(self.total_key()).await.unwrap_or(None);
        raw.unwrap_or(0).max(0) as usize
    }

    /// Recompute the global counter from the underlying ZSETs and overwrite
    /// it. Use at startup or after recovering from an inconsistent state to
    /// repair any drift between the counter and the actual queues.
    pub async fn reconcile_total(&self) -> Result<usize> {
        let pattern = format!("{}:{}:*", DEFERRED_QUEUE_PREFIX, self.config.operation_id);
        let total_key = self.total_key();
        let mut conn = self.queue_conn();
        let keys: Vec<String> = scan_keys_async(&mut conn, &pattern).await;
        let mut total: usize = 0;
        for key in &keys {
            if key == &total_key {
                continue;
            }
            // Skip signature SETs — they're paired with the ZSETs but
            // don't contribute to the deferred-task count (Bug J).
            if key.ends_with(":sigs") {
                continue;
            }
            total = total.saturating_add(conn.zcard::<_, usize>(key).await.unwrap_or(0));
        }
        let _: () = conn
            .set(&total_key, total)
            .await
            .with_context(|| format!("SET {total_key}"))?;
        Ok(total)
    }

    /// Count one deferred task that blue containment removed from the queue.
    ///
    /// Best-effort: a Redis failure here must never stop the drain loop, since
    /// the task is being discarded either way. The counter is the only durable
    /// record that the work existed — the drop otherwise survives solely as a
    /// log line, which is what makes a contained red verification run
    /// indistinguishable from a driver that built nothing.
    pub async fn record_blue_invalidation(
        &self,
        task_type: &str,
        target_role: &str,
        kind: ContainmentKind,
    ) {
        let mut conn = self.queue_conn();
        if let Err(e) = ares_core::blue_invalidation::record_blue_invalidated_task(
            &mut conn,
            &self.config.operation_id,
            task_type,
            target_role,
            kind,
        )
        .await
        {
            warn!(err = %e, "Failed to record blue-invalidated deferred task");
        }
    }

    /// Release the signature that `pop_best` held across the pop → decision
    /// window, so a future equivalent enqueue is no longer treated as a
    /// duplicate. Call this once the popped task is on its way to dispatch
    /// or being re-enqueued through the size-capped `enqueue` path. Do NOT
    /// call it on the containment-drop path — leaving the sig in place is
    /// exactly what makes it act as a tombstone.
    pub async fn release_signature(&self, task: &DeferredTask) {
        let sig_key = self.sig_key(&task.task_type);
        let mut conn = self.queue_conn();
        if let Err(e) = conn.srem::<_, _, ()>(&sig_key, task.signature()).await {
            warn!(err = %e, "Failed to release deferred task signature");
        }
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

/// A deferred task's cause of death: the closed-set kind that the per-op
/// counter aggregates, plus the human-readable detail that names the revoked
/// principal, isolated host or rotated realm for the log line.
struct ContainmentDrop {
    kind: ContainmentKind,
    detail: String,
}

/// Return why a deferred task should be dropped from the queue because a
/// blue-team containment observation has invalidated its preconditions, or
/// `None` when the task remains viable.
///
/// Kept intentionally narrow: mirrors the checks in the exploitation
/// pre-dispatch filter (`orchestrator/exploitation.rs`) but limited to the
/// fields commonly present in deferred payloads — target IP, credential
/// tuple, and (for Kerberos-typed tasks) the target realm. Certificate
/// serial is not usually present at defer-time and is handled downstream
/// in exploitation.
async fn task_dropped_by_containment(
    task: &DeferredTask,
    state: &crate::orchestrator::state::SharedState,
) -> Option<ContainmentDrop> {
    let state = state.read().await;

    // Host isolated → drop any task pointing at that IP.
    let target_ip = task
        .payload
        .get("target_ip")
        .or_else(|| task.payload.get("dc_ip"))
        .or_else(|| task.payload.get("target"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if !target_ip.is_empty() && state.is_host_isolated(target_ip) {
        return Some(ContainmentDrop {
            kind: ContainmentKind::HostIsolated,
            detail: format!("host isolated ({target_ip})"),
        });
    }

    // Credential revoked → drop any task bound to that principal.
    if let Some(cred) = task.payload.get("credential") {
        let user = cred.get("username").and_then(|v| v.as_str()).unwrap_or("");
        let domain = cred.get("domain").and_then(|v| v.as_str()).unwrap_or("");
        if !user.is_empty() && !domain.is_empty() && state.is_credential_revoked(user, domain) {
            return Some(ContainmentDrop {
                kind: ContainmentKind::CredentialRevoked,
                detail: format!("credential revoked ({user}@{domain})"),
            });
        }
    }

    // krbtgt rotated → drop Kerberos-shaped tasks in that realm. Task-type
    // strings vary (`authentication`, `kerberos`, `lateral`) so gate on a
    // technique keyword or explicit realm field rather than a hardcoded
    // task_type list.
    let realm = task
        .payload
        .get("domain")
        .or_else(|| task.payload.get("realm"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let technique = task
        .payload
        .get("technique")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let kerberos_shaped = matches!(
        task.task_type.as_str(),
        "authentication" | "kerberos" | "kerberoast" | "asrep_roast"
    ) || technique.to_lowercase().contains("kerberos")
        || technique.to_lowercase().contains("kerberoast")
        || technique.to_lowercase().contains("golden");
    if !realm.is_empty() && kerberos_shaped && state.is_krbtgt_rotated(realm) {
        return Some(ContainmentDrop {
            kind: ContainmentKind::KrbtgtRotated,
            detail: format!("krbtgt rotated ({realm})"),
        });
    }

    None
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

                // Drop deferred tasks whose target/credential blue has
                // observably contained. Mirrors the pre-dispatch filter in
                // `exploitation.rs`: without this, tasks deferred before
                // blue took action get re-dispatched anyway, chew a
                // credential-inflight slot, and surface as noisy
                // STATUS_LOGON_FAILURE / STATUS_HOST_UNREACHABLE tool
                // errors — exactly the visual mess the containment loop is
                // supposed to prevent for the demo.
                if let Some(drop) = task_dropped_by_containment(&task, &dispatcher.state).await {
                    info!(
                        task_type = %task.task_type,
                        target_role = %task.target_role,
                        reason = %drop.detail,
                        "Dropping deferred task — invalidated by blue containment"
                    );
                    // Signature is left in the SET by pop_best (POP_HOLD_SCRIPT
                    // doesn't SREM it), so it now serves as the tombstone that
                    // blocks producers from re-emitting equivalent work. No
                    // explicit tombstone_signature call is needed.
                    deferred
                        .record_blue_invalidation(&task.task_type, &task.target_role, drop.kind)
                        .await;
                    continue;
                }

                // Not contained — the sig no longer needs to be held. Release
                // it before any dispatch or re-enqueue path so a future
                // equivalent enqueue (either by submit_to_llm internally, or by
                // a re-enqueue below) doesn't collapse on the held sig and
                // silently lose the task.
                deferred.release_signature(&task).await;

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
    use crate::orchestrator::state::SharedState;

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

    fn task_with_payload(task_type: &str, payload: serde_json::Value) -> DeferredTask {
        DeferredTask {
            priority: 5,
            enqueue_time: 1000.0,
            task_type: task_type.into(),
            target_role: "recon".into(),
            payload,
            source_agent: "orchestrator".into(),
        }
    }

    #[tokio::test]
    async fn drops_task_when_target_host_isolated() {
        let state = SharedState::new("op-x".into());
        state
            .publish_host_isolated(
                "192.168.58.20",
                "web01.contoso.local",
                "blue_simulated:inv-1",
            )
            .await;
        let task = task_with_payload(
            "credential_access",
            serde_json::json!({ "target_ip": "192.168.58.20" }),
        );
        let drop = task_dropped_by_containment(&task, &state)
            .await
            .expect("isolated host should drop the task");
        assert_eq!(drop.kind, ContainmentKind::HostIsolated);
        assert!(drop.detail.contains("host isolated"));
    }

    #[tokio::test]
    async fn keeps_task_when_host_not_isolated() {
        let state = SharedState::new("op-x".into());
        let task = task_with_payload(
            "credential_access",
            serde_json::json!({ "target_ip": "192.168.58.20" }),
        );
        assert!(task_dropped_by_containment(&task, &state).await.is_none());
    }

    #[tokio::test]
    async fn drops_task_when_credential_revoked() {
        let state = SharedState::new("op-x".into());
        state
            .publish_credential_revoked("svc_mssql", "contoso.local", "blue_simulated:inv-1")
            .await;
        let task = task_with_payload(
            "lateral",
            serde_json::json!({
                "target_ip": "192.168.58.21",
                "credential": { "username": "svc_mssql", "domain": "contoso.local" },
            }),
        );
        let drop = task_dropped_by_containment(&task, &state)
            .await
            .expect("revoked credential should drop the task");
        assert_eq!(drop.kind, ContainmentKind::CredentialRevoked);
        assert!(drop.detail.contains("credential revoked"));
    }

    #[tokio::test]
    async fn drops_kerberos_task_when_krbtgt_rotated() {
        let state = SharedState::new("op-x".into());
        state
            .publish_krbtgt_rotated("contoso.local", "blue_simulated:inv-1")
            .await;
        let task = task_with_payload(
            "kerberos",
            serde_json::json!({
                "target_ip": "192.168.58.240",
                "domain": "contoso.local",
            }),
        );
        let drop = task_dropped_by_containment(&task, &state)
            .await
            .expect("rotated krbtgt should drop the kerberos task");
        assert_eq!(drop.kind, ContainmentKind::KrbtgtRotated);
        assert!(drop.detail.contains("krbtgt rotated"));
    }

    #[tokio::test]
    async fn keeps_non_kerberos_task_when_only_krbtgt_rotated() {
        let state = SharedState::new("op-x".into());
        state
            .publish_krbtgt_rotated("contoso.local", "blue_simulated:inv-1")
            .await;
        // Plain SMB recon in the same realm should still be dispatched —
        // krbtgt rotation only kills Kerberos-shaped attacks.
        let task = task_with_payload(
            "recon",
            serde_json::json!({
                "target_ip": "192.168.58.240",
                "domain": "contoso.local",
                "technique": "smb_enumeration",
            }),
        );
        assert!(task_dropped_by_containment(&task, &state).await.is_none());
    }

    #[tokio::test]
    async fn drops_kerberoast_technique_when_krbtgt_rotated() {
        let state = SharedState::new("op-x".into());
        state
            .publish_krbtgt_rotated("contoso.local", "blue_simulated:inv-1")
            .await;
        // task_type is `credential_access` but technique gives it away.
        let task = task_with_payload(
            "credential_access",
            serde_json::json!({
                "dc_ip": "192.168.58.240",
                "domain": "contoso.local",
                "technique": "Kerberoasting",
            }),
        );
        let drop = task_dropped_by_containment(&task, &state)
            .await
            .expect("expected kerberoast to be dropped");
        assert_eq!(drop.kind, ContainmentKind::KrbtgtRotated);
        assert!(drop.detail.contains("krbtgt rotated"));
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

    // ── Bug J: signature dedup ────────────────────────────────────────

    fn make_signed_task(
        task_type: &str,
        role: &str,
        technique: &str,
        target_ip: &str,
        cred_user: &str,
        cred_domain: &str,
        enqueue_time: f64,
    ) -> DeferredTask {
        DeferredTask {
            priority: 5,
            enqueue_time,
            task_type: task_type.into(),
            target_role: role.into(),
            payload: serde_json::json!({
                "technique": technique,
                "target_ip": target_ip,
                "credential": {
                    "username": cred_user,
                    "domain": cred_domain,
                },
            }),
            source_agent: "orchestrator".into(),
        }
    }

    #[test]
    fn signature_excludes_timestamp() {
        // The same logical task at two different ticks must produce
        // identical signatures — that's how producer-side dedup
        // collapses repeated dispatches across the tick interval.
        let a = make_signed_task(
            "credential_access",
            "credential_access",
            "secretsdump",
            "192.168.58.20",
            "carol",
            "fabrikam.local",
            1000.0,
        );
        let b = make_signed_task(
            "credential_access",
            "credential_access",
            "secretsdump",
            "192.168.58.20",
            "carol",
            "fabrikam.local",
            2000.0,
        );
        assert_eq!(a.signature(), b.signature());
    }

    #[test]
    fn signature_differs_on_target_ip() {
        // Two different DCs should not dedup against each other even
        // when everything else matches.
        let a = make_signed_task(
            "credential_access",
            "credential_access",
            "secretsdump",
            "192.168.58.20",
            "carol",
            "fabrikam.local",
            1000.0,
        );
        let b = make_signed_task(
            "credential_access",
            "credential_access",
            "secretsdump",
            "192.168.58.30",
            "carol",
            "fabrikam.local",
            1000.0,
        );
        assert_ne!(a.signature(), b.signature());
    }

    #[test]
    fn signature_differs_on_technique() {
        let a = make_signed_task(
            "credential_access",
            "credential_access",
            "secretsdump",
            "192.168.58.20",
            "carol",
            "fabrikam.local",
            1000.0,
        );
        let b = make_signed_task(
            "credential_access",
            "credential_access",
            "kerberoast",
            "192.168.58.20",
            "carol",
            "fabrikam.local",
            1000.0,
        );
        assert_ne!(a.signature(), b.signature());
    }

    #[test]
    fn signature_differs_on_credential() {
        let a = make_signed_task(
            "credential_access",
            "credential_access",
            "secretsdump",
            "192.168.58.20",
            "carol",
            "fabrikam.local",
            1000.0,
        );
        let b = make_signed_task(
            "credential_access",
            "credential_access",
            "secretsdump",
            "192.168.58.20",
            "bob",
            "fabrikam.local",
            1000.0,
        );
        assert_ne!(a.signature(), b.signature());
    }

    fn make_acl_task(
        vuln_id: &str,
        acl_type: &str,
        source_user: &str,
        target_user: &str,
    ) -> DeferredTask {
        DeferredTask {
            priority: 3,
            enqueue_time: 1000.0,
            task_type: "acl_chain_step".into(),
            target_role: "acl".into(),
            payload: serde_json::json!({
                "technique": "dacl_abuse",
                "acl_type": acl_type,
                "vuln_id": vuln_id,
                "source_user": source_user,
                "target_user": target_user,
                "target_ip": "192.168.58.10",
                "domain": "contoso.local",
                "credential": {
                    "username": "alice",
                    "domain": "contoso.local",
                },
            }),
            source_agent: "orchestrator".into(),
        }
    }

    #[test]
    fn signature_differs_on_vuln_id() {
        let a = make_acl_task("acl_genericall_alice_bob", "genericall", "alice", "bob");
        let b = make_acl_task("acl_genericall_alice_carol", "genericall", "alice", "bob");
        assert_ne!(a.signature(), b.signature());
    }

    #[test]
    fn signature_differs_on_acl_type() {
        let a = make_acl_task("v1", "genericall", "alice", "bob");
        let b = make_acl_task("v1", "writedacl", "alice", "bob");
        assert_ne!(a.signature(), b.signature());
    }

    #[test]
    fn signature_differs_on_acl_source_user() {
        let a = make_acl_task("v1", "genericall", "alice", "bob");
        let b = make_acl_task("v1", "genericall", "carol", "bob");
        assert_ne!(a.signature(), b.signature());
    }

    #[test]
    fn signature_differs_on_acl_target_user() {
        let a = make_acl_task("v1", "genericall", "alice", "bob");
        let b = make_acl_task("v1", "genericall", "alice", "carol");
        assert_ne!(a.signature(), b.signature());
    }

    #[test]
    fn signature_differs_across_acl_edges_sharing_dc_and_credential() {
        let edges = [
            make_acl_task("acl_genericall_alice_bob", "genericall", "alice", "bob"),
            make_acl_task("acl_writedacl_alice_carol", "writedacl", "alice", "carol"),
            make_acl_task("acl_writeowner_alice_admin", "writeowner", "alice", "admin"),
        ];
        let sigs: std::collections::HashSet<String> =
            edges.iter().map(DeferredTask::signature).collect();
        assert_eq!(sigs.len(), edges.len());
    }

    #[test]
    fn signature_reads_acl_identity_from_nested_step() {
        let mut a = make_acl_task("", "", "", "");
        a.payload = serde_json::json!({
            "technique": "acl_chain_step",
            "step": {"source": "alice", "target": "bob", "acl_type": "genericall", "vuln_id": "v1"},
            "credential": {"username": "alice", "domain": "contoso.local"},
        });
        let mut b = a.clone();
        b.payload = serde_json::json!({
            "technique": "acl_chain_step",
            "step": {"source": "alice", "target": "carol", "acl_type": "genericall", "vuln_id": "v2"},
            "credential": {"username": "alice", "domain": "contoso.local"},
        });
        assert_ne!(a.signature(), b.signature());
    }

    #[test]
    fn signature_unchanged_for_payloads_without_acl_identity() {
        let a = make_signed_task(
            "credential_access",
            "credential_access",
            "secretsdump",
            "192.168.58.20",
            "carol",
            "fabrikam.local",
            1000.0,
        );
        let b = make_signed_task(
            "credential_access",
            "credential_access",
            "secretsdump",
            "192.168.58.20",
            "carol",
            "fabrikam.local",
            9000.0,
        );
        assert_eq!(a.signature(), b.signature());
    }

    #[test]
    fn signature_is_case_insensitive_on_credential_realm() {
        // Realm spelling should not split the signature — the worker
        // pool treats them as equivalent.
        let a = make_signed_task(
            "credential_access",
            "credential_access",
            "secretsdump",
            "192.168.58.20",
            "carol",
            "FABRIKAM.LOCAL",
            1000.0,
        );
        let b = make_signed_task(
            "credential_access",
            "credential_access",
            "secretsdump",
            "192.168.58.20",
            "carol",
            "fabrikam.local",
            1000.0,
        );
        assert_eq!(a.signature(), b.signature());
    }

    #[test]
    fn signature_is_stable_across_calls() {
        let t = make_signed_task(
            "credential_access",
            "credential_access",
            "secretsdump",
            "192.168.58.20",
            "carol",
            "fabrikam.local",
            1000.0,
        );
        let s1 = t.signature();
        let s2 = t.signature();
        let s3 = t.signature();
        assert_eq!(s1, s2);
        assert_eq!(s2, s3);
    }

    #[test]
    fn signature_handles_missing_payload_fields() {
        // Payload with no technique / target / credential — still
        // produces a stable signature derived from task_type/role only.
        let bare = DeferredTask {
            priority: 5,
            enqueue_time: 1000.0,
            task_type: "ad_recon".into(),
            target_role: "recon".into(),
            payload: serde_json::json!({}),
            source_agent: "orchestrator".into(),
        };
        let bare2 = DeferredTask {
            priority: 5,
            enqueue_time: 9999.0,
            task_type: "ad_recon".into(),
            target_role: "recon".into(),
            payload: serde_json::json!({}),
            source_agent: "orchestrator".into(),
        };
        assert_eq!(bare.signature(), bare2.signature());
        // ...and distinct from a task with the same skeleton but a
        // populated technique.
        let with_tech = DeferredTask {
            payload: serde_json::json!({ "technique": "ldap_enum" }),
            ..bare.clone()
        };
        assert_ne!(bare.signature(), with_tech.signature());
    }

    #[test]
    fn signature_falls_back_to_dc_ip_when_target_ip_absent() {
        // Some automation payloads use `dc_ip` instead of `target_ip`.
        // The signature must still cover those so they dedup correctly.
        let a = DeferredTask {
            priority: 5,
            enqueue_time: 1000.0,
            task_type: "credential_access".into(),
            target_role: "credential_access".into(),
            payload: serde_json::json!({
                "technique": "kerberoast",
                "dc_ip": "192.168.58.20",
                "credential": {"username": "alice", "domain": "fabrikam.local"},
            }),
            source_agent: "orchestrator".into(),
        };
        let b = DeferredTask {
            payload: serde_json::json!({
                "technique": "kerberoast",
                "dc_ip": "192.168.58.20",
                "credential": {"username": "alice", "domain": "fabrikam.local"},
            }),
            enqueue_time: 5000.0,
            ..a.clone()
        };
        assert_eq!(a.signature(), b.signature());
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
