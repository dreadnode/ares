//! Central dispatcher — ties together task submission, throttling, and state.
//!
//! All task submission goes through `Dispatcher::throttled_submit()` which checks
//! the throttler, submits or defers, and tracks active tasks. Convenience methods
//! like `request_recon()` etc. build the correct payloads.

pub(crate) mod submission;
pub(crate) mod task_builders;

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{Mutex, Notify};

use crate::orchestrator::config::OrchestratorConfig;
use crate::orchestrator::deferred::DeferredQueue;
use crate::orchestrator::llm_runner::LlmTaskRunner;
use crate::orchestrator::routing::ActiveTaskTracker;
use crate::orchestrator::state::SharedState;
use crate::orchestrator::task_queue::TaskQueue;
use crate::orchestrator::throttling::Throttler;

/// Limits how many concurrent LLM agent loops may be in-flight for the same
/// credential. Prevents thundering-herd when only one credential has been
/// discovered and both automation loops try to spawn many tasks with it.
#[derive(Clone)]
pub struct CredentialInflight {
    inner: Arc<Mutex<HashMap<String, usize>>>,
    max_per_credential: usize,
}

impl CredentialInflight {
    pub fn new(max_per_credential: usize) -> Self {
        Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
            max_per_credential,
        }
    }

    /// Try to acquire a slot. Returns `true` if under the limit.
    pub async fn try_acquire(&self, key: &str) -> bool {
        let mut map = self.inner.lock().await;
        let count = map.entry(key.to_string()).or_insert(0);
        if *count < self.max_per_credential {
            *count += 1;
            true
        } else {
            false
        }
    }

    /// Check if a slot is available WITHOUT acquiring it.
    pub async fn can_acquire(&self, key: &str) -> bool {
        let map = self.inner.lock().await;
        match map.get(key) {
            Some(count) => *count < self.max_per_credential,
            None => true,
        }
    }

    /// Release a slot when the task completes (success or failure).
    pub async fn release(&self, key: &str) {
        let mut map = self.inner.lock().await;
        if let Some(count) = map.get_mut(key) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                map.remove(key);
            }
        }
    }
}

/// How long a crack reservation survives without an explicit release. Purely a
/// backstop for a run whose completion never reported (worker OOM, pod
/// eviction, reaped task): both producers release explicitly on completion.
/// Sits above `CRACK_TASK_STALL_TTL` so it never fires ahead of the stall path,
/// and well below an op's runtime so a missed release self-heals in-op instead
/// of blocking the hash until the op ends.
pub const CRACK_INFLIGHT_TTL: Duration = Duration::from_secs(45 * 60);

/// Default ceiling on concurrently running crack tasks. hashcat serializes on
/// the GPU, so anything above this queues behind an already-saturated device.
pub const DEFAULT_MAX_ACTIVE_CRACK_TASKS: usize = 2;

/// Shared crack-scheduling guard: which hash dedup keys currently have a
/// hashcat run outstanding, and how many crack tasks that adds up to.
///
/// This lives on [`Dispatcher`] rather than inside `auto_crack_dispatch`
/// because there are two independent producers of crack work — the automation
/// tick and the orchestrator's `dispatch_crack` LLM tool — and a guard held in
/// one producer's local state cannot be enforced against the other. While this
/// was a local `HashMap` in the automation loop, the LLM path re-queued hashes
/// the automation already had running, so one hash held both hashcat slots for
/// ~50 minutes across five redundant runs while crackable hashes waited.
///
/// Reservations are grouped per dispatch and carry a timestamp, so `active` is
/// *derived* from the live groups rather than tracked in a separate counter. A
/// dispatch that dies without releasing therefore cannot wedge the cap
/// permanently — the group ages out at [`CRACK_INFLIGHT_TTL`].
#[derive(Clone)]
pub struct CrackInflight {
    groups: Arc<Mutex<HashMap<String, CrackReservation>>>,
    max_active: usize,
}

struct CrackReservation {
    keys: Vec<String>,
    reserved_at: Instant,
}

impl CrackInflight {
    pub fn new(max_active: usize) -> Self {
        Self {
            groups: Arc::new(Mutex::new(HashMap::new())),
            max_active: max_active.max(1),
        }
    }

    /// Read `ARES_MAX_ACTIVE_CRACK_TASKS`, falling back to the default cap.
    pub fn from_env() -> Self {
        let max_active = std::env::var("ARES_MAX_ACTIVE_CRACK_TASKS")
            .ok()
            .and_then(|s| s.parse::<usize>().ok())
            .filter(|&n| n > 0)
            .unwrap_or(DEFAULT_MAX_ACTIVE_CRACK_TASKS);
        Self::new(max_active)
    }

    pub fn max_active(&self) -> usize {
        self.max_active
    }

    /// Drop reservation groups whose dispatch never reported completion.
    pub async fn expire_stale(&self) {
        let now = Instant::now();
        self.groups
            .lock()
            .await
            .retain(|_, r| now.duration_since(r.reserved_at) < CRACK_INFLIGHT_TTL);
    }

    /// Number of crack dispatches currently holding a reservation.
    pub async fn active(&self) -> usize {
        let now = Instant::now();
        self.groups
            .lock()
            .await
            .values()
            .filter(|r| now.duration_since(r.reserved_at) < CRACK_INFLIGHT_TTL)
            .count()
    }

    pub async fn at_capacity(&self) -> bool {
        self.active().await >= self.max_active
    }

    /// Snapshot of every reserved key, for filtering a work list without
    /// holding this lock across the whole scan.
    pub async fn live_keys(&self) -> HashSet<String> {
        let now = Instant::now();
        self.groups
            .lock()
            .await
            .values()
            .filter(|r| now.duration_since(r.reserved_at) < CRACK_INFLIGHT_TTL)
            .flat_map(|r| r.keys.iter().cloned())
            .collect()
    }

    pub async fn is_inflight(&self, dedup_key: &str) -> bool {
        let now = Instant::now();
        self.groups.lock().await.values().any(|r| {
            now.duration_since(r.reserved_at) < CRACK_INFLIGHT_TTL
                && r.keys.iter().any(|k| k == dedup_key)
        })
    }

    /// Reserve the not-yet-in-flight subset of `dedup_keys` under `task_id` and
    /// take one of the `max_active` slots.
    ///
    /// The capacity check, the duplicate check and the reservation all happen
    /// under one lock, so two producers racing the same hash cannot both win.
    /// Keys another dispatch already holds are left with their original owner.
    /// Returns the keys actually reserved, or `None` when the cap is reached or
    /// every key was already in-flight.
    pub async fn try_reserve(&self, task_id: &str, dedup_keys: &[String]) -> Option<Vec<String>> {
        let mut groups = self.groups.lock().await;
        let now = Instant::now();
        groups.retain(|_, r| now.duration_since(r.reserved_at) < CRACK_INFLIGHT_TTL);
        if groups.len() >= self.max_active {
            return None;
        }
        let taken: HashSet<&String> = groups.values().flat_map(|r| r.keys.iter()).collect();
        let reserved: Vec<String> = dedup_keys
            .iter()
            .filter(|k| !taken.contains(*k))
            .cloned()
            .collect();
        if reserved.is_empty() {
            return None;
        }
        groups.insert(
            task_id.to_string(),
            CrackReservation {
                keys: reserved.clone(),
                reserved_at: now,
            },
        );
        Some(reserved)
    }

    /// Record a reservation for a dispatch that has already been decided on.
    ///
    /// Unlike [`Self::try_reserve`] this never refuses: the submission layer
    /// calls it after a task id exists, at which point declining to record
    /// would leave a real hashcat run untracked — the exact hole that let the
    /// same hash be queued twice. `active` may therefore briefly exceed
    /// `max_active`, which reports the true state rather than a capped guess.
    pub async fn reserve(&self, task_id: &str, dedup_keys: &[String]) {
        let mut groups = self.groups.lock().await;
        let now = Instant::now();
        groups.retain(|_, r| now.duration_since(r.reserved_at) < CRACK_INFLIGHT_TTL);
        let taken: HashSet<&String> = groups
            .iter()
            .filter(|(id, _)| *id != task_id)
            .flat_map(|(_, r)| r.keys.iter())
            .collect();
        let keys: Vec<String> = dedup_keys
            .iter()
            .filter(|k| !taken.contains(*k))
            .cloned()
            .collect();
        if keys.is_empty() {
            return;
        }
        groups.insert(
            task_id.to_string(),
            CrackReservation {
                keys,
                reserved_at: now,
            },
        );
    }

    /// Release the reservation held by `task_id`. Idempotent, and a no-op for
    /// task ids that never reserved anything — so the completion path can call
    /// it unconditionally.
    pub async fn release(&self, task_id: &str) {
        self.groups.lock().await.remove(task_id);
    }
}

/// Result of a submission attempt that distinguishes between "deferred and
/// safely enqueued" vs "dropped due to overflow / no role mapping".
///
/// Existing call sites use `throttled_submit` which collapses Deferred and
/// Dropped into `Ok(None)`. New automations that need to dedup deferred work
/// should use `throttled_submit_outcome` and only mark dedup on
/// `Submitted`/`Deferred`, never on `Dropped` (otherwise overflowed tasks are
/// lost forever and never retried by the deferred drain).
#[derive(Debug, Clone)]
pub enum SubmissionOutcome {
    /// Task is running (LLM agent loop spawned). String is the task_id.
    Submitted(String),
    /// Task is in the deferred ZSET; the deferred processor will retry when
    /// throttler/credential capacity opens up.
    Deferred,
    /// Task was lost: the deferred queue was at its per-type cap, or no role
    /// mapping exists for the task_type/target_role. Caller MUST NOT mark this
    /// item as dispatched; it will be re-considered on the next automation
    /// tick when capacity is available.
    Dropped,
}

/// Extract `"user@domain"` from a task payload's `credential` field.
pub fn credential_key_from_payload(payload: &serde_json::Value) -> Option<String> {
    let cred = payload.get("credential")?;
    let username = cred.get("username").and_then(|v| v.as_str())?;
    let domain = cred.get("domain").and_then(|v| v.as_str()).unwrap_or("");
    Some(format!("{}@{}", username, domain))
}

/// Central dispatcher for submitting tasks with throttling and routing.
pub struct Dispatcher {
    pub queue: TaskQueue,
    pub tracker: ActiveTaskTracker,
    pub throttler: Arc<Throttler>,
    pub deferred: Arc<DeferredQueue>,
    pub state: SharedState,
    pub config: Arc<OrchestratorConfig>,
    /// YAML config (agent roles, vulnerability priorities, context management).
    /// `None` if no YAML config file was found at startup.
    pub ares_config: Option<Arc<ares_core::config::AresConfig>>,
    /// Notifies auto_credential_access to wake up when new creds arrive.
    pub credential_access_notify: Arc<Notify>,
    /// Notifies auto_delegation_enumeration to wake up when new creds arrive.
    pub delegation_notify: Arc<Notify>,
    /// Notifies auto_orchestrator_planning that workers published discoveries.
    pub planning_notify: Arc<Notify>,
    /// LLM runner — drives tasks through the Rust agent loop.
    pub llm_runner: Arc<LlmTaskRunner>,
    /// Per-credential concurrency limiter.
    pub credential_inflight: CredentialInflight,
    /// Crack-scheduling guard shared by `auto_crack_dispatch` and the
    /// orchestrator's `dispatch_crack` tool, so neither can re-queue a hash the
    /// other already has running.
    pub crack_inflight: CrackInflight,
    /// Single-slot mutex shared by every dispatcher that submits a
    /// coercion-or-relay-bearing task. ntlmrelayx binds the loopback
    /// port-445 mutex on the listener host, so concurrent dispatches
    /// from `auto_ntlm_relay`, `auto_coercion`, and the ESC8 chain in
    /// `auto_adcs_exploitation` race the same OS lock and surface as
    /// `RELAY_BIND_BUSY` aborts. Holding this mutex around the dispatch
    /// serializes the dispatches at the
    /// orchestrator layer; the per-dispatch `RELAY_BIND_BUSY` handling
    /// in `adcs_exploitation.rs:1380-1394, 1429-1435` remains as a
    /// fallback for the rare race the mutex didn't prevent (a still-
    /// running ntlmrelayx from a prior dispatch).
    pub relay_slot: Arc<Mutex<()>>,
    pub proposals: Arc<crate::orchestrator::proposals::ProposalPool>,
    /// Set once the completion monitor decides the op is done (all forests
    /// dominated / max runtime). While true, `do_submit_outcome` drops every
    /// new red task so the swarm stops burning tokens on the exploit/ACL
    /// backlog during the post-completion blue-drain wait. Blue investigations
    /// run on their own runner and are unaffected.
    pub red_draining: Arc<AtomicBool>,
}

impl Dispatcher {
    /// Check if a technique is allowed by the active strategy.
    pub fn is_technique_allowed(&self, technique: &str) -> bool {
        self.config.strategy.is_technique_allowed(technique)
    }

    /// Get the effective priority for a vulnerability type from the strategy.
    pub fn effective_priority(&self, vuln_type: &str) -> i32 {
        self.config.strategy.effective_priority(vuln_type)
    }

    pub fn new(deps: DispatcherDeps) -> Self {
        let DispatcherDeps {
            queue,
            tracker,
            throttler,
            deferred,
            state,
            config,
            ares_config,
            llm_runner,
        } = deps;
        Self {
            queue,
            tracker,
            throttler,
            deferred,
            state,
            config,
            ares_config,
            credential_access_notify: Arc::new(Notify::new()),
            delegation_notify: Arc::new(Notify::new()),
            planning_notify: Arc::new(Notify::new()),
            llm_runner,
            // Allow up to 3 concurrent tasks per credential
            credential_inflight: CredentialInflight::new(3),
            crack_inflight: CrackInflight::from_env(),
            relay_slot: Arc::new(Mutex::new(())),
            red_draining: Arc::new(AtomicBool::new(false)),
            proposals: Arc::new(crate::orchestrator::proposals::ProposalPool::from_env()),
        }
    }

    /// Freeze new red-task dispatch. Called by the completion monitor the
    /// instant the op is deemed complete so the swarm stops burning tokens
    /// while blue investigations drain. Idempotent.
    pub fn mark_red_draining(&self) {
        self.red_draining.store(true, Ordering::SeqCst);
    }

    /// Whether red dispatch has been frozen by [`mark_red_draining`].
    pub fn is_red_draining(&self) -> bool {
        self.red_draining.load(Ordering::SeqCst)
    }
}

pub struct DispatcherDeps {
    pub queue: TaskQueue,
    pub tracker: ActiveTaskTracker,
    pub throttler: Arc<Throttler>,
    pub deferred: Arc<DeferredQueue>,
    pub state: SharedState,
    pub config: Arc<OrchestratorConfig>,
    pub ares_config: Option<Arc<ares_core::config::AresConfig>>,
    pub llm_runner: Arc<LlmTaskRunner>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[tokio::test]
    async fn reserve_blocks_a_second_producer_on_the_same_hash() {
        let inflight = CrackInflight::new(2);
        let k = keys(&["contoso.local:svc_sql:abc"]);

        assert!(inflight.try_reserve("crack_direct_1", &k).await.is_some());
        assert!(inflight.is_inflight(&k[0]).await);
        assert!(
            inflight.try_reserve("crack_llm_1", &k).await.is_none(),
            "the LLM dispatch_crack path must not re-queue a hash the automation is running"
        );

        inflight.release("crack_direct_1").await;
        assert!(!inflight.is_inflight(&k[0]).await);
        assert!(inflight.try_reserve("crack_llm_1", &k).await.is_some());
    }

    #[tokio::test]
    async fn reserve_enforces_the_active_task_cap() {
        let inflight = CrackInflight::new(2);
        assert!(inflight
            .try_reserve("t1", &keys(&["contoso.local:alice:a"]))
            .await
            .is_some());
        assert!(inflight
            .try_reserve("t2", &keys(&["contoso.local:bob:b"]))
            .await
            .is_some());
        assert_eq!(inflight.active().await, 2);
        assert!(inflight.at_capacity().await);
        assert!(
            inflight
                .try_reserve("t3", &keys(&["contoso.local:carol:c"]))
                .await
                .is_none(),
            "a third concurrent run would oversubscribe the single hashcat GPU"
        );

        inflight.release("t1").await;
        assert!(!inflight.at_capacity().await);
        assert!(inflight
            .try_reserve("t3", &keys(&["contoso.local:carol:c"]))
            .await
            .is_some());
    }

    #[tokio::test]
    async fn reserve_takes_only_the_free_subset_of_a_batch() {
        let inflight = CrackInflight::new(2);
        inflight
            .try_reserve("t1", &keys(&["contoso.local:alice:a"]))
            .await
            .unwrap();

        let reserved = inflight
            .try_reserve(
                "t2",
                &keys(&["contoso.local:alice:a", "contoso.local:bob:b"]),
            )
            .await
            .expect("a batch with one free key still dispatches");
        assert_eq!(reserved, keys(&["contoso.local:bob:b"]));

        inflight.release("t2").await;
        assert!(inflight.is_inflight("contoso.local:alice:a").await);
    }

    #[tokio::test]
    async fn release_is_idempotent_and_ignores_unknown_tasks() {
        let inflight = CrackInflight::new(2);
        inflight
            .try_reserve("t1", &keys(&["contoso.local:alice:a"]))
            .await
            .unwrap();

        inflight.release("recon_task_unrelated").await;
        assert_eq!(inflight.active().await, 1);

        inflight.release("t1").await;
        inflight.release("t1").await;
        assert_eq!(inflight.active().await, 0);
    }

    #[test]
    fn inflight_ttl_outlives_the_stall_ceiling() {
        assert!(CRACK_INFLIGHT_TTL > Duration::from_secs(30 * 60));
        assert!(CRACK_INFLIGHT_TTL < Duration::from_secs(2 * 60 * 60));
    }

    #[test]
    fn credential_key_basic() {
        let payload = serde_json::json!({
            "credential": {
                "username": "admin",
                "domain": "contoso.local"
            }
        });
        assert_eq!(
            credential_key_from_payload(&payload),
            Some("admin@contoso.local".to_string())
        );
    }

    #[test]
    fn credential_key_no_domain() {
        let payload = serde_json::json!({
            "credential": {
                "username": "admin"
            }
        });
        assert_eq!(
            credential_key_from_payload(&payload),
            Some("admin@".to_string())
        );
    }

    #[test]
    fn credential_key_no_credential_field() {
        let payload = serde_json::json!({"target_ip": "192.168.58.10"});
        assert_eq!(credential_key_from_payload(&payload), None);
    }

    #[test]
    fn credential_key_no_username() {
        let payload = serde_json::json!({
            "credential": {
                "domain": "contoso.local"
            }
        });
        assert_eq!(credential_key_from_payload(&payload), None);
    }

    #[test]
    fn credential_key_empty_payload() {
        let payload = serde_json::json!({});
        assert_eq!(credential_key_from_payload(&payload), None);
    }

    #[test]
    fn credential_key_null_credential() {
        let payload = serde_json::json!({"credential": null});
        assert_eq!(credential_key_from_payload(&payload), None);
    }

    #[test]
    fn credential_key_username_not_string() {
        let payload = serde_json::json!({
            "credential": {
                "username": 123,
                "domain": "contoso.local"
            }
        });
        assert_eq!(credential_key_from_payload(&payload), None);
    }

    #[test]
    fn credential_key_fabrikam_domain() {
        let payload = serde_json::json!({
            "credential": {
                "username": "svc_sql",
                "domain": "fabrikam.local"
            }
        });
        assert_eq!(
            credential_key_from_payload(&payload),
            Some("svc_sql@fabrikam.local".to_string())
        );
    }

    #[tokio::test]
    async fn inflight_acquire_and_release() {
        let ci = CredentialInflight::new(2);
        assert!(ci.try_acquire("admin@contoso.local").await);
        assert!(ci.try_acquire("admin@contoso.local").await);
        assert!(!ci.try_acquire("admin@contoso.local").await);

        ci.release("admin@contoso.local").await;
        assert!(ci.try_acquire("admin@contoso.local").await);
    }

    #[tokio::test]
    async fn inflight_can_acquire_check() {
        let ci = CredentialInflight::new(1);
        assert!(ci.can_acquire("admin@contoso.local").await);
        ci.try_acquire("admin@contoso.local").await;
        assert!(!ci.can_acquire("admin@contoso.local").await);
    }

    #[tokio::test]
    async fn inflight_different_credentials_independent() {
        let ci = CredentialInflight::new(1);
        assert!(ci.try_acquire("admin@contoso.local").await);
        assert!(ci.try_acquire("svc_sql@fabrikam.local").await);
        assert!(!ci.try_acquire("admin@contoso.local").await);
        assert!(!ci.try_acquire("svc_sql@fabrikam.local").await);
    }

    #[tokio::test]
    async fn inflight_release_unknown_key_noop() {
        let ci = CredentialInflight::new(2);
        ci.release("nobody@contoso.local").await;
    }

    #[tokio::test]
    async fn inflight_release_removes_zero_count() {
        let ci = CredentialInflight::new(2);
        ci.try_acquire("admin@contoso.local").await;
        ci.release("admin@contoso.local").await;
        assert!(ci.can_acquire("admin@contoso.local").await);
    }

    #[tokio::test]
    async fn inflight_double_release_saturates() {
        let ci = CredentialInflight::new(2);
        ci.try_acquire("admin@contoso.local").await;
        ci.release("admin@contoso.local").await;
        ci.release("admin@contoso.local").await;
        assert!(ci.can_acquire("admin@contoso.local").await);
    }

    #[tokio::test]
    async fn inflight_max_one() {
        let ci = CredentialInflight::new(1);
        assert!(ci.try_acquire("x@contoso.local").await);
        assert!(!ci.try_acquire("x@contoso.local").await);
        ci.release("x@contoso.local").await;
        assert!(ci.try_acquire("x@contoso.local").await);
    }

    #[tokio::test]
    async fn inflight_can_acquire_unknown_key() {
        let ci = CredentialInflight::new(5);
        assert!(ci.can_acquire("never_seen@contoso.local").await);
    }

    #[tokio::test]
    async fn inflight_acquire_up_to_max() {
        let ci = CredentialInflight::new(5);
        for _ in 0..5 {
            assert!(ci.try_acquire("user@domain").await);
        }
        assert!(!ci.try_acquire("user@domain").await);
    }

    #[tokio::test]
    async fn inflight_release_then_reacquire_cycle() {
        let ci = CredentialInflight::new(1);
        for _ in 0..10 {
            assert!(ci.try_acquire("cycle@test").await);
            assert!(!ci.try_acquire("cycle@test").await);
            ci.release("cycle@test").await;
        }
    }

    #[tokio::test]
    async fn inflight_many_independent_keys() {
        let ci = CredentialInflight::new(1);
        for i in 0..100 {
            let key = format!("user{}@domain", i);
            assert!(ci.try_acquire(&key).await);
        }
        // All at limit
        for i in 0..100 {
            let key = format!("user{}@domain", i);
            assert!(!ci.try_acquire(&key).await);
        }
    }

    #[tokio::test]
    async fn inflight_partial_release() {
        let ci = CredentialInflight::new(3);
        assert!(ci.try_acquire("a@b").await); // count=1
        assert!(ci.try_acquire("a@b").await); // count=2
        assert!(ci.try_acquire("a@b").await); // count=3
        assert!(!ci.try_acquire("a@b").await);

        ci.release("a@b").await; // count=2
        assert!(ci.try_acquire("a@b").await); // count=3 again
        assert!(!ci.try_acquire("a@b").await);

        ci.release("a@b").await; // count=2
        ci.release("a@b").await; // count=1
        assert!(ci.can_acquire("a@b").await);
    }

    #[tokio::test]
    async fn inflight_zero_max_always_rejects() {
        let ci = CredentialInflight::new(0);
        assert!(!ci.try_acquire("any@key").await);
        assert!(!ci.can_acquire("any@key").await);
    }
}
