//! Central dispatcher — ties together task submission, throttling, and state.
//!
//! All task submission goes through `Dispatcher::throttled_submit()` which checks
//! the throttler, submits or defers, and tracks active tasks. Convenience methods
//! like `request_crack()`, `request_recon()` etc. build the correct payloads.

mod submission;
mod task_builders;

use std::collections::HashMap;
use std::sync::Arc;
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
    /// LLM runner — drives tasks through the Rust agent loop.
    pub llm_runner: Arc<LlmTaskRunner>,
    /// Per-credential concurrency limiter.
    pub credential_inflight: CredentialInflight,
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
            llm_runner,
            // Allow up to 3 concurrent tasks per credential
            credential_inflight: CredentialInflight::new(3),
        }
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
