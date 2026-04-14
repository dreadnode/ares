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

        // Compute undominated forests inline (avoids re-acquiring lock)
        let undominated = crate::completion::compute_undominated_forests(
            s.target.as_ref().map(|t| t.domain.as_str()),
            s.domains.first().map(|d| d.as_str()),
            &s.trusted_domains,
            &s.dominated_domains,
        );

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
            undominated_forests: undominated,
            delegation_accounts: s
                .discovered_vulnerabilities
                .values()
                .filter(|v| {
                    let vt = v.vuln_type.to_lowercase();
                    vt == "constrained_delegation" || vt == "rbcd"
                })
                .filter_map(|v| {
                    v.details
                        .get("account_name")
                        .or_else(|| v.details.get("AccountName"))
                        .and_then(|x| x.as_str())
                        .map(|s| s.to_lowercase())
                })
                .collect(),
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

#[cfg(test)]
mod tests {
    use super::*;
    use ares_core::models::*;
    use std::collections::HashMap;

    #[tokio::test]
    async fn test_shared_state_new() {
        let state = SharedState::new("op-test".into());
        assert_eq!(state.operation_id().await, "op-test");
    }

    #[tokio::test]
    async fn test_snapshot_empty_state() {
        let state = SharedState::new("op-1".into());
        let snap = state.snapshot().await;
        assert!(snap.credentials.is_empty());
        assert!(snap.hashes.is_empty());
        assert!(snap.hosts.is_empty());
        assert!(snap.shares.is_empty());
        assert!(snap.domains.is_empty());
        assert!(snap.discovered_vulnerabilities.is_empty());
        assert!(snap.exploited_vulnerabilities.is_empty());
        assert!(snap.domain_controllers.is_empty());
        assert!(!snap.has_domain_admin);
        assert!(!snap.has_golden_ticket);
    }

    #[tokio::test]
    async fn test_snapshot_reflects_state_mutations() {
        let state = SharedState::new("op-1".into());

        // Mutate state directly
        {
            let mut inner = state.write().await;
            inner.credentials.push(Credential {
                id: "c1".into(),
                username: "admin".into(),
                password: "pass".into(),
                domain: "contoso.local".into(),
                source: "test".into(),
                discovered_at: None,
                is_admin: true,
                parent_id: None,
                attack_step: 0,
            });
            inner.domains.push("contoso.local".into());
            inner
                .domain_controllers
                .insert("contoso.local".into(), "192.168.58.10".into());
            inner.has_domain_admin = true;
        }

        let snap = state.snapshot().await;
        assert_eq!(snap.credentials.len(), 1);
        assert_eq!(snap.credentials[0].username, "admin");
        assert_eq!(snap.domains, vec!["contoso.local"]);
        assert_eq!(
            snap.domain_controllers.get("contoso.local"),
            Some(&"192.168.58.10".to_string())
        );
        assert!(snap.has_domain_admin);
    }

    #[tokio::test]
    async fn test_snapshot_is_independent_copy() {
        let state = SharedState::new("op-1".into());
        {
            let mut inner = state.write().await;
            inner.domains.push("contoso.local".into());
        }

        let snap = state.snapshot().await;
        assert_eq!(snap.domains.len(), 1);

        // Mutate state after snapshot
        {
            let mut inner = state.write().await;
            inner.domains.push("fabrikam.local".into());
        }

        // Snapshot should still have only 1 domain
        assert_eq!(snap.domains.len(), 1);

        // New snapshot should have 2
        let snap2 = state.snapshot().await;
        assert_eq!(snap2.domains.len(), 2);
    }

    #[tokio::test]
    async fn test_vuln_queue_key() {
        let state = SharedState::new("op-abc".into());
        let key = state.vuln_queue_key().await;
        assert!(key.contains("op-abc"));
        assert!(key.ends_with("vuln_queue"));
    }

    #[tokio::test]
    async fn test_discovery_key() {
        let state = SharedState::new("op-xyz".into());
        let key = state.discovery_key().await;
        assert!(key.contains("op-xyz"));
        assert!(key.starts_with("ares:discoveries:"));
    }

    #[tokio::test]
    async fn test_snapshot_with_vulnerabilities() {
        let state = SharedState::new("op-1".into());
        {
            let mut inner = state.write().await;
            let mut details = HashMap::new();
            details.insert("account".into(), serde_json::json!("svc_sql"));
            inner.discovered_vulnerabilities.insert(
                "vuln-001".into(),
                VulnerabilityInfo {
                    vuln_id: "vuln-001".into(),
                    vuln_type: "constrained_delegation".into(),
                    target: "192.168.58.20".into(),
                    discovered_by: "recon".into(),
                    discovered_at: chrono::Utc::now(),
                    details,
                    recommended_agent: "privesc".into(),
                    priority: 3,
                },
            );
            inner.exploited_vulnerabilities.insert("vuln-002".into());
        }

        let snap = state.snapshot().await;
        assert_eq!(snap.discovered_vulnerabilities.len(), 1);
        assert!(snap.discovered_vulnerabilities.contains_key("vuln-001"));
        assert_eq!(snap.exploited_vulnerabilities.len(), 1);
        assert!(snap.exploited_vulnerabilities.contains("vuln-002"));
    }
}
