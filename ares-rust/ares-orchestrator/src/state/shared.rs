//! SharedState — thread-safe wrapper around StateInner.

use std::sync::Arc;
use tokio::sync::RwLock;

use super::inner::StateInner;

/// Thread-safe shared state with read/write access.
#[derive(Clone)]
pub struct SharedState {
    pub(super) inner: Arc<RwLock<StateInner>>,
}

impl SharedState {
    /// Create a new empty state.
    pub fn new(operation_id: String) -> Self {
        Self {
            inner: Arc::new(RwLock::new(StateInner::new(operation_id))),
        }
    }

    /// Create a cheap snapshot of state for prompt generation.
    ///
    /// Clones the relevant fields so the RwLock is released before LLM calls.
    pub async fn snapshot(&self) -> ares_llm::prompt::StateSnapshot {
        let s = self.inner.read().await;
        ares_llm::prompt::StateSnapshot {
            credentials: s.credentials.clone(),
            hashes: s.hashes.clone(),
            hosts: s.hosts.clone(),
            shares: s.shares.clone(),
            domains: s.domains.clone(),
            discovered_vulnerabilities: s.discovered_vulnerabilities.clone(),
            exploited_vulnerabilities: s.exploited_vulnerabilities.clone(),
            domain_controllers: s.domain_controllers.clone(),
            netbios_to_fqdn: s.netbios_to_fqdn.clone(),
            has_domain_admin: s.has_domain_admin,
            has_golden_ticket: s.has_golden_ticket,
        }
    }

    /// Read-only access to the state.
    pub async fn read(&self) -> tokio::sync::RwLockReadGuard<'_, StateInner> {
        self.inner.read().await
    }

    /// Write access to the state.
    pub async fn write(&self) -> tokio::sync::RwLockWriteGuard<'_, StateInner> {
        self.inner.write().await
    }

    /// Get the vuln queue ZSET key.
    pub async fn vuln_queue_key(&self) -> String {
        let state = self.inner.read().await;
        format!(
            "{}:{}:{}",
            ares_core::state::KEY_PREFIX,
            state.operation_id,
            super::KEY_VULN_QUEUE
        )
    }

    /// Get the discovery list key.
    pub async fn discovery_key(&self) -> String {
        let state = self.inner.read().await;
        format!("{}:{}", super::DISCOVERY_KEY_PREFIX, state.operation_id)
    }

    /// Get the operation ID.
    pub async fn operation_id(&self) -> String {
        self.inner.read().await.operation_id.clone()
    }
}
