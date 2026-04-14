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

use crate::config::OrchestratorConfig;
use crate::deferred::DeferredQueue;
use crate::llm_runner::LlmTaskRunner;
use crate::routing::ActiveTaskTracker;
use crate::state::SharedState;
use crate::task_queue::TaskQueue;
use crate::throttling::Throttler;

// ---------------------------------------------------------------------------
// Per-credential in-flight limiter
// ---------------------------------------------------------------------------

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
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        queue: TaskQueue,
        tracker: ActiveTaskTracker,
        throttler: Arc<Throttler>,
        deferred: Arc<DeferredQueue>,
        state: SharedState,
        config: Arc<OrchestratorConfig>,
        ares_config: Option<Arc<ares_core::config::AresConfig>>,
        llm_runner: Arc<LlmTaskRunner>,
    ) -> Self {
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
