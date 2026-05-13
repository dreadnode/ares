//! Postgres projector for the operation state event log.
//!
//! Tails the `ARES_OPSTATE` JetStream stream with a durable pull consumer and
//! projects each [`OpStateEvent`] into the existing Postgres tables. Replaces
//! the manual batch [`super::PersistentStore::offload_operation`] path at the
//! end of an op — Postgres now stays always-current.
//!
//! Idempotency comes from the existing entity-level UNIQUE constraints
//! (`uq_cred`, `uq_hash`, `uq_user`, `uq_vuln`, `uq_host`). Redelivered events
//! upsert to the same row, so at-least-once delivery is safe. The
//! `operations` row is auto-created on first event for an op_id.

use std::time::Duration;

use anyhow::{Context, Result};
use async_nats::jetstream::consumer::{pull::Config as PullConfig, AckPolicy, Consumer};
use chrono::Utc;
use futures::StreamExt;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};
use uuid::Uuid;

use crate::models::{OpStateEvent, OpStateEventPayload};
use crate::nats::{NatsBroker, OP_STATE_STREAM, OP_STATE_SUBJECT_PREFIX};
use crate::persistent_store::PersistentStore;

/// Durable consumer name used by the Postgres projector. Stable — renaming
/// requires a manual `consumer delete` against the JetStream stream.
pub const PROJECTOR_CONSUMER_NAME: &str = "ares-projector-pg";

/// Default ack wait for projector messages. PG writes are usually fast, but
/// during a stop-the-world index rebuild we want a generous window.
const ACK_WAIT: Duration = Duration::from_secs(60);

/// Maximum redelivery attempts before JetStream gives up on a message.
const MAX_DELIVER: i64 = 5;

/// Projector: connects the JetStream event log to the Postgres archive.
#[derive(Clone)]
pub struct OpStateProjector {
    store: PersistentStore,
    nats: NatsBroker,
}

impl OpStateProjector {
    /// Build a new projector. Does not start the background task — call
    /// [`spawn`](Self::spawn) for that.
    pub fn new(store: PersistentStore, nats: NatsBroker) -> Self {
        Self { store, nats }
    }

    /// Apply a single event to Postgres synchronously. Used by the consumer
    /// loop and by replay tooling; tests can call this directly to avoid
    /// spinning up a NATS server.
    pub async fn apply_event(&self, event: &OpStateEvent) -> Result<()> {
        let op_uuid = self.ensure_operation_row(&event.op_id).await?;
        match &event.payload {
            OpStateEventPayload::CredentialCaptured { credential } => {
                upsert_credential(self.store.pool(), op_uuid, credential).await?;
            }
            OpStateEventPayload::HashCaptured { hash } => {
                upsert_hash(self.store.pool(), op_uuid, hash).await?;
            }
            OpStateEventPayload::HostDiscovered { host } => {
                upsert_host(self.store.pool(), op_uuid, host).await?;
            }
            OpStateEventPayload::HostOwned { ip, hostname, .. } => {
                mark_host_owned(self.store.pool(), op_uuid, ip, hostname.as_str()).await?;
            }
            OpStateEventPayload::UserDiscovered { user } => {
                upsert_user(self.store.pool(), op_uuid, user).await?;
            }
            OpStateEventPayload::VulnDiscovered { vuln } => {
                upsert_vulnerability(self.store.pool(), op_uuid, vuln, false).await?;
            }
            OpStateEventPayload::VulnExploited { vuln_id, .. } => {
                mark_vulnerability_exploited(self.store.pool(), op_uuid, vuln_id).await?;
            }
            OpStateEventPayload::TimelineEvent { .. } => {
                // Timeline events are written to `timeline_events` in a later
                // pass when the red-team timeline schema is wired in (no event_id
                // on the current red-team timeline). Tracked in the Phase 4
                // cutover; the projector currently no-ops on these to keep the
                // stream draining.
                debug!(op_id = %event.op_id, "skipping timeline event projection (schema pending)");
            }
        }
        Ok(())
    }

    /// Spawn the long-running consumer task that tails `ARES_OPSTATE` and
    /// applies each event via [`apply_event`](Self::apply_event). Returns the
    /// task handle; aborting it stops the projector.
    pub async fn spawn(self) -> Result<JoinHandle<()>> {
        let consumer = self.ensure_consumer().await?;
        let projector = self.clone();
        let handle = tokio::spawn(async move {
            projector.run_loop(consumer).await;
        });
        info!(
            consumer = PROJECTOR_CONSUMER_NAME,
            stream = OP_STATE_STREAM,
            "Postgres projector spawned"
        );
        Ok(handle)
    }

    async fn ensure_consumer(&self) -> Result<Consumer<PullConfig>> {
        let stream = self
            .nats
            .jetstream()
            .get_stream(OP_STATE_STREAM)
            .await
            .with_context(|| format!("get_stream({OP_STATE_STREAM})"))?;

        let cfg = PullConfig {
            durable_name: Some(PROJECTOR_CONSUMER_NAME.to_string()),
            filter_subject: format!("{OP_STATE_SUBJECT_PREFIX}.>"),
            ack_policy: AckPolicy::Explicit,
            ack_wait: ACK_WAIT,
            max_deliver: MAX_DELIVER,
            ..Default::default()
        };
        let consumer = stream
            .get_or_create_consumer(PROJECTOR_CONSUMER_NAME, cfg)
            .await
            .with_context(|| format!("ensure consumer {PROJECTOR_CONSUMER_NAME}"))?;
        Ok(consumer)
    }

    async fn run_loop(self, consumer: Consumer<PullConfig>) {
        let mut messages = match consumer.messages().await {
            Ok(m) => m,
            Err(e) => {
                warn!(error = %e, "projector: consumer.messages() failed at startup");
                return;
            }
        };
        while let Some(item) = messages.next().await {
            let msg = match item {
                Ok(m) => m,
                Err(e) => {
                    warn!(error = %e, "projector: stream error");
                    continue;
                }
            };
            let event: OpStateEvent = match serde_json::from_slice(&msg.payload) {
                Ok(ev) => ev,
                Err(e) => {
                    warn!(
                        error = %e,
                        subject = %msg.subject,
                        "projector: undecodable event payload; acking to skip",
                    );
                    let _ = msg.ack().await;
                    continue;
                }
            };
            match self.apply_event(&event).await {
                Ok(()) => {
                    if let Err(e) = msg.ack().await {
                        warn!(error = %e, "projector: ack failed");
                    }
                }
                Err(e) => {
                    // No ack — JetStream will redeliver up to max_deliver.
                    warn!(
                        error = %e,
                        op_id = %event.op_id,
                        event_id = %event.event_id,
                        "projector: apply_event failed; allowing redelivery"
                    );
                }
            }
        }
        warn!("projector: message stream ended");
    }

    /// Ensure an `operations` row exists for the given `operation_id`, returning
    /// its UUID. Uses `ON CONFLICT … DO UPDATE` so the RETURNING clause always
    /// produces a row, regardless of whether the insert or the conflict path
    /// fired.
    async fn ensure_operation_row(&self, operation_id: &str) -> Result<Uuid> {
        let row: (Uuid,) = sqlx::query_as(
            "INSERT INTO operations (operation_id, started_at)
             VALUES ($1, NOW())
             ON CONFLICT (operation_id) DO UPDATE SET operation_id = EXCLUDED.operation_id
             RETURNING id",
        )
        .bind(operation_id)
        .fetch_one(self.store.pool())
        .await
        .with_context(|| format!("ensure operations row for {operation_id}"))?;
        Ok(row.0)
    }
}

// =========================================================================
// Single-row upserts (no transaction; PG enforces per-row UNIQUE constraints)
// =========================================================================

async fn upsert_credential(
    pool: &PgPool,
    operation_uuid: Uuid,
    cred: &crate::models::Credential,
) -> Result<()> {
    let password_hash = if cred.password.is_empty() {
        None
    } else {
        Some(sha256_prefix(&cred.password, 16))
    };
    let domain = (!cred.domain.is_empty()).then_some(cred.domain.as_str());
    let source = (!cred.source.is_empty()).then_some(cred.source.as_str());

    sqlx::query(
        "INSERT INTO credentials (operation_id, credential_id, username, domain,
                                  password_hash, is_admin, source, attack_step, discovered_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
         ON CONFLICT ON CONSTRAINT uq_cred DO NOTHING",
    )
    .bind(operation_uuid)
    .bind(&cred.id)
    .bind(&cred.username)
    .bind(domain)
    .bind(password_hash.as_deref())
    .bind(cred.is_admin)
    .bind(source)
    .bind(cred.attack_step)
    .bind(cred.discovered_at)
    .execute(pool)
    .await
    .context("upsert credential")?;
    Ok(())
}

async fn upsert_hash(pool: &PgPool, operation_uuid: Uuid, h: &crate::models::Hash) -> Result<()> {
    let hash_prefix =
        (!h.hash_value.is_empty()).then_some(&h.hash_value[..h.hash_value.len().min(64)]);
    let cracked_hash = h
        .cracked_password
        .as_deref()
        .filter(|p| !p.is_empty())
        .map(|p| sha256_prefix(p, 16));
    let domain = (!h.domain.is_empty()).then_some(h.domain.as_str());
    let hash_type = (!h.hash_type.is_empty()).then_some(h.hash_type.as_str());
    let source = (!h.source.is_empty()).then_some(h.source.as_str());

    sqlx::query(
        "INSERT INTO hashes (operation_id, hash_id, username, domain, hash_type,
                             hash_value_prefix, cracked_password_hash, source,
                             attack_step, discovered_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
         ON CONFLICT ON CONSTRAINT uq_hash DO NOTHING",
    )
    .bind(operation_uuid)
    .bind(&h.id)
    .bind(&h.username)
    .bind(domain)
    .bind(hash_type)
    .bind(hash_prefix)
    .bind(cracked_hash.as_deref())
    .bind(source)
    .bind(h.attack_step)
    .bind(h.discovered_at)
    .execute(pool)
    .await
    .context("upsert hash")?;
    Ok(())
}

async fn upsert_host(
    pool: &PgPool,
    operation_uuid: Uuid,
    host: &crate::models::Host,
) -> Result<()> {
    if host.ip.is_empty() {
        warn!("projector: skipping host with empty IP");
        return Ok(());
    }
    let hostname = (!host.hostname.is_empty()).then_some(host.hostname.as_str());
    let os = (!host.os.is_empty()).then_some(host.os.as_str());
    let roles: Option<&[String]> = (!host.roles.is_empty()).then_some(host.roles.as_slice());
    let services: Option<&[String]> =
        (!host.services.is_empty()).then_some(host.services.as_slice());

    sqlx::query(
        "INSERT INTO hosts (operation_id, ip, hostname, os, is_dc, is_owned, roles, services)
         VALUES ($1, $2::inet, $3, $4, $5, $6, $7, $8)
         ON CONFLICT ON CONSTRAINT uq_host DO UPDATE SET
            hostname = COALESCE(EXCLUDED.hostname, hosts.hostname),
            os = COALESCE(EXCLUDED.os, hosts.os),
            is_dc = hosts.is_dc OR EXCLUDED.is_dc,
            is_owned = hosts.is_owned OR EXCLUDED.is_owned,
            roles = COALESCE(EXCLUDED.roles, hosts.roles),
            services = COALESCE(EXCLUDED.services, hosts.services)",
    )
    .bind(operation_uuid)
    .bind(&host.ip)
    .bind(hostname)
    .bind(os)
    .bind(host.is_dc)
    .bind(host.owned)
    .bind(roles)
    .bind(services)
    .execute(pool)
    .await
    .context("upsert host")?;
    Ok(())
}

async fn mark_host_owned(
    pool: &PgPool,
    operation_uuid: Uuid,
    ip: &str,
    _hostname: &str,
) -> Result<()> {
    sqlx::query(
        "UPDATE hosts SET is_owned = TRUE
         WHERE operation_id = $1 AND ip = $2::inet",
    )
    .bind(operation_uuid)
    .bind(ip)
    .execute(pool)
    .await
    .context("mark host owned")?;
    Ok(())
}

async fn upsert_user(
    pool: &PgPool,
    operation_uuid: Uuid,
    user: &crate::models::User,
) -> Result<()> {
    let domain = (!user.domain.is_empty()).then_some(user.domain.as_str());
    let description = (!user.description.is_empty()).then_some(user.description.as_str());
    let source = (!user.source.is_empty()).then_some(user.source.as_str());

    sqlx::query(
        "INSERT INTO users (operation_id, username, domain, description, is_admin, source)
         VALUES ($1, $2, $3, $4, $5, $6)
         ON CONFLICT ON CONSTRAINT uq_user DO NOTHING",
    )
    .bind(operation_uuid)
    .bind(&user.username)
    .bind(domain)
    .bind(description)
    .bind(user.is_admin)
    .bind(source)
    .execute(pool)
    .await
    .context("upsert user")?;
    Ok(())
}

async fn upsert_vulnerability(
    pool: &PgPool,
    operation_uuid: Uuid,
    vuln: &crate::models::VulnerabilityInfo,
    exploited: bool,
) -> Result<()> {
    let (target_ip, target_hostname) = if is_ip(&vuln.target) {
        (Some(vuln.target.as_str()), None)
    } else {
        (None, Some(vuln.target.as_str()))
    };
    let details = if vuln.details.is_empty() {
        None
    } else {
        Some(serde_json::to_value(&vuln.details)?)
    };
    let exploited_at = exploited.then(Utc::now);

    sqlx::query(
        "INSERT INTO vulnerabilities (operation_id, vuln_id, vuln_type, target_ip,
                                      target_hostname, priority, discovered_by,
                                      discovered_at, exploited_at, details)
         VALUES ($1, $2, $3, $4::inet, $5, $6, $7, $8, $9, $10)
         ON CONFLICT ON CONSTRAINT uq_vuln DO UPDATE SET
            details = COALESCE(EXCLUDED.details, vulnerabilities.details)",
    )
    .bind(operation_uuid)
    .bind(&vuln.vuln_id)
    .bind(&vuln.vuln_type)
    .bind(target_ip)
    .bind(target_hostname)
    .bind(vuln.priority)
    .bind(&vuln.discovered_by)
    .bind(vuln.discovered_at)
    .bind(exploited_at)
    .bind(details)
    .execute(pool)
    .await
    .context("upsert vulnerability")?;
    Ok(())
}

async fn mark_vulnerability_exploited(
    pool: &PgPool,
    operation_uuid: Uuid,
    vuln_id: &str,
) -> Result<()> {
    sqlx::query(
        "UPDATE vulnerabilities SET exploited_at = COALESCE(exploited_at, NOW())
         WHERE operation_id = $1 AND vuln_id = $2",
    )
    .bind(operation_uuid)
    .bind(vuln_id)
    .execute(pool)
    .await
    .context("mark vulnerability exploited")?;
    Ok(())
}

fn sha256_prefix(input: &str, len: usize) -> String {
    let hash = Sha256::digest(input.as_bytes());
    let hex: String = hash.iter().map(|b| format!("{b:02x}")).collect();
    hex[..hex.len().min(len)].to_string()
}

fn is_ip(value: &str) -> bool {
    if value.is_empty() {
        return false;
    }
    let parts: Vec<&str> = value.split('.').collect();
    if parts.len() != 4 {
        return false;
    }
    parts.iter().all(|p| p.parse::<u8>().is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_prefix_truncates_to_requested_len() {
        let s = sha256_prefix("P@ssw0rd!", 16);
        assert_eq!(s.len(), 16);
        assert!(s.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn sha256_prefix_deterministic() {
        assert_eq!(sha256_prefix("alice", 8), sha256_prefix("alice", 8));
        assert_ne!(sha256_prefix("alice", 8), sha256_prefix("bob", 8));
    }

    #[test]
    fn is_ip_accepts_dotted_quad() {
        assert!(is_ip("192.168.58.10"));
        assert!(is_ip("10.0.0.1"));
    }

    #[test]
    fn is_ip_rejects_hostname_and_short_quad() {
        assert!(!is_ip("dc01.contoso.local"));
        assert!(!is_ip("192.168.58"));
        assert!(!is_ip(""));
        assert!(!is_ip("999.999.999.999"));
    }

    #[test]
    fn projector_consumer_name_stable() {
        // Renaming this is a deployment break — the existing durable consumer
        // would be abandoned and a new one would start from the next message
        // rather than where the old one left off.
        assert_eq!(PROJECTOR_CONSUMER_NAME, "ares-projector-pg");
    }
}
