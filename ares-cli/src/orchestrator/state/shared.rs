//! SharedState — thread-safe wrapper around StateInner.

use std::sync::Arc;
use tokio::sync::RwLock;

use ares_core::op_state_log::OpStateRecorder;

use super::inner::StateInner;

/// Thread-safe shared state with read/write access.
#[derive(Clone)]
pub struct SharedState {
    pub(super) inner: Arc<RwLock<StateInner>>,
    /// Sink for op-state events (Phase 2 dual-write). Defaults to
    /// [`OpStateRecorder::Disabled`] so existing call sites stay no-op until
    /// the orchestrator installs a Nats-backed recorder.
    pub(crate) recorder: Arc<OpStateRecorder>,
}

impl SharedState {
    /// Create a new empty state. Recorder defaults to [`OpStateRecorder::Disabled`].
    pub fn new(operation_id: String) -> Self {
        Self {
            inner: Arc::new(RwLock::new(StateInner::new(operation_id))),
            recorder: Arc::new(OpStateRecorder::Disabled),
        }
    }

    /// Create a new empty state with a specific event recorder installed.
    /// Production wires `OpStateRecorder::Nats(broker)`; tests use
    /// `OpStateRecorder::capturing()` to assert what was emitted.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn with_recorder(operation_id: String, recorder: Arc<OpStateRecorder>) -> Self {
        Self {
            inner: Arc::new(RwLock::new(StateInner::new(operation_id))),
            recorder,
        }
    }

    /// Replace the recorder on an existing state — useful when SharedState is
    /// built before the orchestrator has a NatsBroker handle ready.
    pub fn set_recorder(&mut self, recorder: Arc<OpStateRecorder>) {
        self.recorder = recorder;
    }

    /// Access the installed recorder. Internal — publishing methods call this
    /// to emit events after a successful Redis write.
    pub(crate) fn recorder(&self) -> &OpStateRecorder {
        &self.recorder
    }

    /// Create a cheap snapshot of state for prompt generation.
    ///
    /// Clones the relevant fields so the RwLock is released before LLM calls.
    pub async fn snapshot(&self) -> ares_llm::prompt::StateSnapshot {
        let s = self.inner.read().await;

        // Compute undominated forests inline (avoids re-acquiring lock)
        let undominated = crate::orchestrator::completion::compute_undominated_forests(
            s.target.as_ref().map(|t| t.domain.as_str()),
            s.domains.first().map(|d| d.as_str()),
            &s.trusted_domains,
            &s.dominated_domains,
            &s.domain_controllers,
        );

        // Hide quarantined principals from LLM agents. A locked-out account
        // can't authenticate during the quarantine window, and surfacing it
        // just invites more failed-auth attempts on the same principal
        // (which keep the badPwdCount climbing on shared lockout policies).
        // The state's own resolvers already filter is_principal_quarantined
        // for automation paths; this filter does the same for the LLM-facing
        // snapshot.
        let credentials: Vec<_> = s
            .credentials
            .iter()
            .filter(|c| !s.is_principal_quarantined(&c.username, &c.domain))
            .cloned()
            .collect();
        let hashes: Vec<_> = s
            .hashes
            .iter()
            .filter(|h| !s.is_principal_quarantined(&h.username, &h.domain))
            .cloned()
            .collect();

        let target_domain = s
            .target
            .as_ref()
            .map(|t| t.domain.clone())
            .filter(|d| !d.is_empty())
            .or_else(|| s.domains.first().cloned())
            .unwrap_or_default();
        // Prefer the DC IP for the primary target_domain; fall back to the
        // configured Target's IP (which is the seed IP from operation config).
        let target_dc_ip = s
            .domain_controllers
            .get(&target_domain)
            .cloned()
            .or_else(|| s.target.as_ref().map(|t| t.ip.clone()))
            .unwrap_or_default();
        // Prefer the configured Target's hostname (already an FQDN); else find
        // the first discovered DC host whose hostname matches target_domain.
        let target_dc_fqdn = s
            .target
            .as_ref()
            .map(|t| t.hostname.clone())
            .filter(|h| !h.is_empty() && h.contains('.'))
            .or_else(|| {
                s.hosts
                    .iter()
                    .find(|h| {
                        h.is_dc
                            && !h.hostname.is_empty()
                            && h.hostname.to_lowercase().ends_with(&target_domain)
                    })
                    .map(|h| h.hostname.to_lowercase())
            })
            .unwrap_or_else(|| target_domain.clone());

        ares_llm::prompt::StateSnapshot {
            credentials,
            hashes,
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
            target_domain,
            target_dc_ip,
            target_dc_fqdn,
            listener_ip: std::env::var("ARES_LISTENER_IP").unwrap_or_default(),
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

    /// Enumerate the orchestrator host's IPv4 interface addresses and stash
    /// them in `state.self_ips`. Used by `publish_host` to filter the
    /// attacker's own NIC out of host-discovery results — e.g. an SMB sweep
    /// from the Kali pivot will respond on the box's own address and would
    /// otherwise pollute the discovered-host list with a phantom entry.
    /// Failures (no permission, unsupported platform) degrade gracefully to
    /// an empty set: filtering is a polish concern, not a correctness gate.
    pub async fn initialize_self_ips(&self) {
        let ips: std::collections::HashSet<std::net::IpAddr> =
            match local_ip_address::list_afinet_netifas() {
                Ok(ifs) => ifs
                    .into_iter()
                    .map(|(_, ip)| ip)
                    .filter(|ip| matches!(ip, std::net::IpAddr::V4(_)))
                    .collect(),
                Err(e) => {
                    tracing::warn!(err = %e, "Failed to enumerate local interfaces — self-IP filtering disabled");
                    return;
                }
            };
        tracing::info!(
            count = ips.len(),
            "Discovered self IPv4 addresses for host-discovery filter"
        );
        self.inner.write().await.self_ips = ips;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ares_core::models::*;
    use std::collections::HashMap;

    #[tokio::test]
    async fn shared_state_new() {
        let state = SharedState::new("op-test".into());
        assert_eq!(state.operation_id().await, "op-test");
    }

    #[tokio::test]
    async fn snapshot_empty_state() {
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
    async fn snapshot_reflects_state_mutations() {
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
    async fn snapshot_is_independent_copy() {
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
    async fn returns_vuln_queue_key() {
        let state = SharedState::new("op-abc".into());
        let key = state.vuln_queue_key().await;
        assert!(key.contains("op-abc"));
        assert!(key.ends_with("vuln_queue"));
    }

    #[tokio::test]
    async fn returns_discovery_key() {
        let state = SharedState::new("op-xyz".into());
        let key = state.discovery_key().await;
        assert!(key.contains("op-xyz"));
        assert!(key.starts_with("ares:discoveries:"));
    }

    #[tokio::test]
    async fn snapshot_hides_quarantined_principals() {
        let state = SharedState::new("op-1".into());
        {
            let mut inner = state.write().await;
            inner.credentials.push(Credential {
                id: "c1".into(),
                username: "live_user".into(),
                password: "p1".into(),
                domain: "contoso.local".into(),
                source: "test".into(),
                discovered_at: None,
                is_admin: false,
                parent_id: None,
                attack_step: 0,
            });
            inner.credentials.push(Credential {
                id: "c2".into(),
                username: "locked_user".into(),
                password: "p2".into(),
                domain: "contoso.local".into(),
                source: "test".into(),
                discovered_at: None,
                is_admin: false,
                parent_id: None,
                attack_step: 0,
            });
            inner.hashes.push(Hash {
                id: "h1".into(),
                username: "locked_user".into(),
                hash_type: "NTLM".into(),
                hash_value: "aabbcc".into(),
                domain: "contoso.local".into(),
                source: "test".into(),
                cracked_password: None,
                aes_key: None,
                is_previous: false,
                source_host: None,
                is_trust_key: false,
                trust_pair_label: None,
                discovered_at: Some(chrono::Utc::now()),
                parent_id: None,
                attack_step: 0,
            });
            inner.hashes.push(Hash {
                id: "h2".into(),
                username: "live_user".into(),
                hash_type: "NTLM".into(),
                hash_value: "ddeeff".into(),
                domain: "contoso.local".into(),
                source: "test".into(),
                cracked_password: None,
                aes_key: None,
                is_previous: false,
                source_host: None,
                is_trust_key: false,
                trust_pair_label: None,
                discovered_at: Some(chrono::Utc::now()),
                parent_id: None,
                attack_step: 0,
            });
            inner.quarantine_principal("locked_user", "contoso.local");
        }

        let snap = state.snapshot().await;
        assert_eq!(snap.credentials.len(), 1, "quarantined cred must be hidden");
        assert_eq!(snap.credentials[0].username, "live_user");
        assert_eq!(snap.hashes.len(), 1, "quarantined hash must be hidden");
        assert_eq!(snap.hashes[0].username, "live_user");
    }

    #[tokio::test]
    async fn snapshot_with_vulnerabilities() {
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
