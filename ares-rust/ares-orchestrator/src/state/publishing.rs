//! Publishing methods — add credentials, hashes, hosts, and vulnerabilities
//! to both in-memory state and Redis.

use anyhow::Result;
use redis::AsyncCommands;

use ares_core::models::*;
use ares_core::state::{self, RedisStateReader};

use super::{SharedState, KEY_VULN_QUEUE};
use crate::task_queue::TaskQueue;

impl SharedState {
    /// Add a credential to state and Redis (with dedup).
    pub async fn publish_credential(&self, queue: &TaskQueue, cred: Credential) -> Result<bool> {
        let operation_id = {
            let state = self.inner.read().await;
            state.operation_id.clone()
        };
        let reader = RedisStateReader::new(operation_id);
        let mut conn = queue.connection();
        let added = reader.add_credential(&mut conn, &cred).await?;
        if added {
            let mut state = self.inner.write().await;
            state.credentials.push(cred);
        }
        Ok(added)
    }

    /// Add a hash to state and Redis (with dedup).
    pub async fn publish_hash(&self, queue: &TaskQueue, hash: Hash) -> Result<bool> {
        let operation_id = {
            let state = self.inner.read().await;
            state.operation_id.clone()
        };
        let reader = RedisStateReader::new(operation_id);
        let mut conn = queue.connection();
        let added = reader.add_hash(&mut conn, &hash).await?;
        if added {
            let mut state = self.inner.write().await;
            state.hashes.push(hash);
        }
        Ok(added)
    }

    /// Add a host to state and Redis.
    pub async fn publish_host(&self, queue: &TaskQueue, host: Host) -> Result<bool> {
        // Check for duplicate IP in memory
        {
            let state = self.inner.read().await;
            if state.hosts.iter().any(|h| h.ip == host.ip) {
                return Ok(false);
            }
        }

        let operation_id = {
            let state = self.inner.read().await;
            state.operation_id.clone()
        };
        let reader = RedisStateReader::new(operation_id);
        let mut conn = queue.connection();
        reader.add_host(&mut conn, &host).await?;

        // Update DC map if this is a domain controller
        if (host.is_dc || host.detect_dc()) && !host.hostname.is_empty() {
            let domain = host
                .hostname
                .split('.')
                .skip(1)
                .collect::<Vec<_>>()
                .join(".");
            if !domain.is_empty() {
                let dc_key = format!(
                    "{}:{}:{}",
                    state::KEY_PREFIX,
                    self.inner.read().await.operation_id,
                    state::KEY_DC_MAP
                );
                let _: () = conn.hset(&dc_key, &domain, &host.ip).await?;
            }
        }

        let mut state = self.inner.write().await;
        state.hosts.push(host);
        Ok(true)
    }

    /// Add a vulnerability to state and Redis.
    pub async fn publish_vulnerability(
        &self,
        queue: &TaskQueue,
        vuln: VulnerabilityInfo,
    ) -> Result<bool> {
        let operation_id = {
            let state = self.inner.read().await;
            state.operation_id.clone()
        };
        let reader = RedisStateReader::new(operation_id.clone());
        let mut conn = queue.connection();
        let added = reader.add_vulnerability(&mut conn, &vuln).await?;
        if added {
            // Also add to vuln queue ZSET for exploitation workflow
            let vuln_queue_key =
                format!("{}:{}:{}", state::KEY_PREFIX, operation_id, KEY_VULN_QUEUE);
            let vuln_json = serde_json::to_string(&vuln).unwrap_or_default();
            let score = vuln.priority as f64;
            let _: () = conn
                .zadd(&vuln_queue_key, &vuln_json, score)
                .await
                .unwrap_or(());
            let _: () = conn.expire(&vuln_queue_key, 86400).await.unwrap_or(());

            let mut state = self.inner.write().await;
            state
                .discovered_vulnerabilities
                .insert(vuln.vuln_id.clone(), vuln);
        }
        Ok(added)
    }

    /// Set has_domain_admin flag and persist to Redis.
    pub async fn set_domain_admin(&self, queue: &TaskQueue, path: Option<String>) -> Result<()> {
        let operation_id = {
            let state = self.inner.read().await;
            state.operation_id.clone()
        };
        let reader = RedisStateReader::new(operation_id);
        let mut conn = queue.connection();
        reader
            .set_meta_field(
                &mut conn,
                "has_domain_admin",
                &serde_json::Value::Bool(true),
            )
            .await?;
        if let Some(ref p) = path {
            reader
                .set_meta_field(
                    &mut conn,
                    "domain_admin_path",
                    &serde_json::Value::String(p.clone()),
                )
                .await?;
        }

        let mut state = self.inner.write().await;
        state.has_domain_admin = true;
        state.domain_admin_path = path;
        Ok(())
    }
}
