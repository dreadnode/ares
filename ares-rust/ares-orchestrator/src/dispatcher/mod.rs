//! Central dispatcher — ties together task submission, throttling, and state.
//!
//! All task submission goes through `Dispatcher::throttled_submit()` which checks
//! the throttler, submits or defers, and tracks active tasks. Convenience methods
//! like `request_crack()`, `request_recon()` etc. build the correct payloads.

mod submission;
mod task_builders;

use std::sync::Arc;
use tokio::sync::Notify;

use crate::config::OrchestratorConfig;
use crate::deferred::DeferredQueue;
use crate::llm_runner::LlmTaskRunner;
use crate::routing::ActiveTaskTracker;
use crate::state::SharedState;
use crate::task_queue::TaskQueue;
use crate::throttling::Throttler;

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
        }
    }
}
