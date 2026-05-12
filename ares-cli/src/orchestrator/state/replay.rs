//! Replay operation state from the JetStream `ARES_OPSTATE` event log.
//!
//! Phase 4 cutover primitive. The pure
//! [`apply_event_to_state`] function knows how to mutate [`StateInner`] for
//! every [`OpStateEventPayload`] variant. The async
//! [`SharedState::load_from_event_log`] driver reads the stream up to the
//! current sequence and applies events in order.
//!
//! Scope limitations (see Phase 4 design doc):
//! - The current event types cover entities only (credentials, hashes,
//!   hosts, users, vulns, timeline). They do NOT carry derived state like
//!   `has_domain_admin`, `dominated_domains`, `domain_controllers`, or the
//!   `domains` list. Replay reconstructs the entity collections; derived
//!   state is re-computed by post-replay hooks or by re-running the publish
//!   methods (deferred to a follow-up).
//! - Replay is opt-in via `ARES_USE_EVENT_LOG_REPLAY=1`. The default startup
//!   path still loads from Redis.

use std::time::Duration;

use anyhow::{Context, Result};
use async_nats::jetstream::consumer::{pull::Config as PullConfig, AckPolicy, DeliverPolicy};
use futures::StreamExt;
use tracing::{info, warn};

use ares_core::models::{OpStateEvent, OpStateEventPayload};
use ares_core::nats::{op_state_filter_for_op, NatsBroker, OP_STATE_STREAM};

use super::inner::StateInner;
use super::SharedState;

/// How long to wait for the consumer to deliver the next message before
/// declaring the replay caught up. The stream is replayed from start to the
/// current sequence; an idle pause longer than this means we've drained it.
const REPLAY_IDLE_TIMEOUT: Duration = Duration::from_secs(2);

/// Apply a single [`OpStateEvent`] to [`StateInner`] in-place.
///
/// Pure function — no I/O. Used by both the live replay loop and by
/// replay-based tests. Idempotent in the sense that re-applying the same
/// event (same `event_id`) is safe: collections may grow with duplicates
/// since deduplication previously lived in Redis HSET-NX and is not yet
/// reproduced in-memory. Callers that need exact reconstruction should drop
/// duplicate event_ids before invoking — JetStream's `Nats-Msg-Id` dedup
/// usually makes this a non-issue.
pub fn apply_event_to_state(state: &mut StateInner, event: &OpStateEvent) {
    match &event.payload {
        OpStateEventPayload::CredentialCaptured { credential } => {
            state.credentials.push(credential.clone());
        }
        OpStateEventPayload::HashCaptured { hash } => {
            state.hashes.push(hash.clone());
        }
        OpStateEventPayload::HostDiscovered { host } => {
            state.hosts.push(host.clone());
        }
        OpStateEventPayload::HostOwned { ip, .. } => {
            if let Some(existing) = state.hosts.iter_mut().find(|h| h.ip == *ip) {
                existing.owned = true;
            }
        }
        OpStateEventPayload::UserDiscovered { user } => {
            state.users.push(user.clone());
        }
        OpStateEventPayload::VulnDiscovered { vuln } => {
            state
                .discovered_vulnerabilities
                .insert(vuln.vuln_id.clone(), vuln.clone());
        }
        OpStateEventPayload::VulnExploited { vuln_id, .. } => {
            state.exploited_vulnerabilities.insert(vuln_id.clone());
        }
        OpStateEventPayload::TimelineEvent { .. } => {
            // Red-team timeline replay is deferred until the timeline entries
            // carry an event_id. The projector skips these for the same
            // reason — keep replay symmetric.
        }
    }
}

impl SharedState {
    /// Replay all events for this operation from the `ARES_OPSTATE` stream
    /// into in-memory state. Returns the number of events applied.
    ///
    /// Uses an ephemeral consumer with `DeliverPolicy::All` so each call
    /// starts from the first retained message for the operation. Stops once
    /// no new messages arrive within [`REPLAY_IDLE_TIMEOUT`] — the stream is
    /// considered drained.
    ///
    /// Phase 4 entry point. Opt-in: orchestrator checks
    /// `ARES_USE_EVENT_LOG_REPLAY=1` before calling.
    pub async fn load_from_event_log(&self, nats: &NatsBroker) -> Result<usize> {
        let op_id = self.operation_id().await;
        let filter = op_state_filter_for_op(&op_id);

        let stream = nats
            .jetstream()
            .get_stream(OP_STATE_STREAM)
            .await
            .with_context(|| format!("get_stream({OP_STATE_STREAM})"))?;

        // Ephemeral consumer (no durable_name) — gets cleaned up automatically.
        // DeliverPolicy::All replays from the first retained message; we stop
        // when idle for REPLAY_IDLE_TIMEOUT.
        let cfg = PullConfig {
            filter_subject: filter.clone(),
            ack_policy: AckPolicy::None,
            deliver_policy: DeliverPolicy::All,
            ..Default::default()
        };
        let consumer = stream
            .create_consumer(cfg)
            .await
            .with_context(|| format!("create ephemeral replay consumer for {filter}"))?;

        let mut messages = consumer
            .messages()
            .await
            .context("ephemeral consumer.messages()")?;

        let mut count: usize = 0;
        loop {
            let next = tokio::time::timeout(REPLAY_IDLE_TIMEOUT, messages.next()).await;
            let item = match next {
                Err(_) => break,   // idle timeout — drained
                Ok(None) => break, // stream closed
                Ok(Some(item)) => item,
            };
            let msg = match item {
                Ok(m) => m,
                Err(e) => {
                    warn!(error = %e, "replay: stream error; aborting");
                    break;
                }
            };
            let event: OpStateEvent = match serde_json::from_slice(&msg.payload) {
                Ok(ev) => ev,
                Err(e) => {
                    warn!(error = %e, subject = %msg.subject, "replay: undecodable event; skipping");
                    continue;
                }
            };
            // Defensive: filter_subject should already do this, but skip
            // cross-operation events if any sneak through.
            if event.op_id != op_id {
                continue;
            }
            {
                let mut inner = self.write().await;
                apply_event_to_state(&mut inner, &event);
            }
            count += 1;
        }

        info!(op_id, events_applied = count, "Replayed op-state event log");
        Ok(count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ares_core::models::{
        Credential, Hash, Host, OpStateEvent, OpStateEventPayload, User, VulnerabilityInfo,
    };
    use chrono::Utc;
    use std::collections::HashMap;

    fn cred(username: &str, domain: &str) -> Credential {
        Credential {
            id: format!("{username}@{domain}"),
            username: username.to_string(),
            password: "P@ssw0rd!".to_string(), // pragma: allowlist secret
            domain: domain.to_string(),
            source: "replay-test".to_string(),
            discovered_at: None,
            is_admin: false,
            parent_id: None,
            attack_step: 0,
        }
    }

    fn host(ip: &str, hostname: &str) -> Host {
        Host {
            ip: ip.to_string(),
            hostname: hostname.to_string(),
            os: String::new(),
            roles: vec![],
            services: vec![],
            is_dc: false,
            owned: false,
        }
    }

    fn vuln(id: &str, vtype: &str) -> VulnerabilityInfo {
        VulnerabilityInfo {
            vuln_id: id.to_string(),
            vuln_type: vtype.to_string(),
            target: "192.168.58.10".to_string(),
            discovered_by: "test".to_string(),
            discovered_at: Utc::now(),
            details: HashMap::new(),
            recommended_agent: String::new(),
            priority: 5,
        }
    }

    fn apply(state: &mut StateInner, payload: OpStateEventPayload) {
        let ev = OpStateEvent::new(&state.operation_id, payload);
        apply_event_to_state(state, &ev);
    }

    #[test]
    fn credential_captured_pushes_to_credentials_vec() {
        let mut s = StateInner::new("op-1".into());
        apply(
            &mut s,
            OpStateEventPayload::CredentialCaptured {
                credential: cred("alice", "contoso.local"),
            },
        );
        assert_eq!(s.credentials.len(), 1);
        assert_eq!(s.credentials[0].username, "alice");
    }

    #[test]
    fn hash_captured_pushes_to_hashes_vec() {
        let mut s = StateInner::new("op-1".into());
        apply(
            &mut s,
            OpStateEventPayload::HashCaptured {
                hash: Hash {
                    id: "h1".into(),
                    username: "admin".into(),
                    hash_value: "deadbeef".into(),
                    hash_type: "NTLM".into(),
                    domain: "contoso.local".into(),
                    cracked_password: None,
                    source: "test".into(),
                    discovered_at: None,
                    parent_id: None,
                    attack_step: 0,
                    aes_key: None,
                },
            },
        );
        assert_eq!(s.hashes.len(), 1);
        assert_eq!(s.hashes[0].username, "admin");
    }

    #[test]
    fn host_discovered_then_owned_marks_existing_host() {
        let mut s = StateInner::new("op-1".into());
        apply(
            &mut s,
            OpStateEventPayload::HostDiscovered {
                host: host("192.168.58.10", "dc01.contoso.local"),
            },
        );
        apply(
            &mut s,
            OpStateEventPayload::HostOwned {
                ip: "192.168.58.10".into(),
                hostname: "dc01.contoso.local".into(),
                owned_by: "lateral".into(),
            },
        );
        assert_eq!(s.hosts.len(), 1);
        assert!(s.hosts[0].owned);
    }

    #[test]
    fn host_owned_for_unknown_ip_is_silent() {
        let mut s = StateInner::new("op-1".into());
        apply(
            &mut s,
            OpStateEventPayload::HostOwned {
                ip: "192.168.58.99".into(),
                hostname: String::new(),
                owned_by: String::new(),
            },
        );
        // No host to flip — state stays empty, no panic.
        assert!(s.hosts.is_empty());
    }

    #[test]
    fn user_discovered_pushes_to_users_vec() {
        let mut s = StateInner::new("op-1".into());
        apply(
            &mut s,
            OpStateEventPayload::UserDiscovered {
                user: User {
                    username: "bob".into(),
                    domain: "contoso.local".into(),
                    description: String::new(),
                    is_admin: false,
                    source: "ldap".into(),
                },
            },
        );
        assert_eq!(s.users.len(), 1);
        assert_eq!(s.users[0].username, "bob");
    }

    #[test]
    fn vuln_discovered_inserts_into_map_keyed_by_vuln_id() {
        let mut s = StateInner::new("op-1".into());
        apply(
            &mut s,
            OpStateEventPayload::VulnDiscovered {
                vuln: vuln("V-1", "esc1"),
            },
        );
        assert_eq!(s.discovered_vulnerabilities.len(), 1);
        assert!(s.discovered_vulnerabilities.contains_key("V-1"));
    }

    #[test]
    fn vuln_exploited_inserts_into_set() {
        let mut s = StateInner::new("op-1".into());
        apply(
            &mut s,
            OpStateEventPayload::VulnExploited {
                vuln_id: "V-1".into(),
                exploited_by: String::new(),
                result: None,
            },
        );
        assert!(s.exploited_vulnerabilities.contains("V-1"));
    }

    #[test]
    fn replay_reconstructs_collections_in_order() {
        // Apply a sequence of events and assert the final state matches what
        // the publishers would have written. This is the load-bearing test
        // for Phase 4 — if it diverges, replay is broken.
        let mut s = StateInner::new("op-replay".into());
        let events: Vec<OpStateEventPayload> = vec![
            OpStateEventPayload::HostDiscovered {
                host: host("192.168.58.10", "dc01.contoso.local"),
            },
            OpStateEventPayload::HostDiscovered {
                host: host("192.168.58.20", "ws01.contoso.local"),
            },
            OpStateEventPayload::CredentialCaptured {
                credential: cred("alice", "contoso.local"),
            },
            OpStateEventPayload::CredentialCaptured {
                credential: cred("bob", "contoso.local"),
            },
            OpStateEventPayload::VulnDiscovered {
                vuln: vuln("V-1", "esc1"),
            },
            OpStateEventPayload::VulnExploited {
                vuln_id: "V-1".into(),
                exploited_by: "privesc".into(),
                result: None,
            },
            OpStateEventPayload::HostOwned {
                ip: "192.168.58.10".into(),
                hostname: "dc01.contoso.local".into(),
                owned_by: "lateral".into(),
            },
        ];
        for payload in events {
            apply(&mut s, payload);
        }
        assert_eq!(s.hosts.len(), 2);
        assert_eq!(s.credentials.len(), 2);
        assert_eq!(s.discovered_vulnerabilities.len(), 1);
        assert!(s.exploited_vulnerabilities.contains("V-1"));
        // HostOwned applied AFTER HostDiscovered → dc01 is owned
        assert!(
            s.hosts
                .iter()
                .find(|h| h.ip == "192.168.58.10")
                .unwrap()
                .owned
        );
        assert!(
            !s.hosts
                .iter()
                .find(|h| h.ip == "192.168.58.20")
                .unwrap()
                .owned
        );
    }

    #[test]
    fn replay_does_not_reconstruct_derived_state() {
        // Documented limitation: domains / has_domain_admin / domain_controllers
        // are derived inside the publish methods and are NOT in the event
        // payload. Replay leaves them empty. A future change adds derived
        // event types or a publish-replay mode.
        let mut s = StateInner::new("op-1".into());
        apply(
            &mut s,
            OpStateEventPayload::CredentialCaptured {
                credential: cred("alice", "contoso.local"),
            },
        );
        assert_eq!(s.credentials.len(), 1);
        // Derived: domains list stays empty after replay (would be populated
        // if we re-ran publish_credential).
        assert!(
            s.domains.is_empty(),
            "domains is derived state, not replayed"
        );
        assert!(!s.has_domain_admin);
    }
}
