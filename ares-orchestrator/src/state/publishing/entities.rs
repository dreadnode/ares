//! Entity publishing: users, vulnerabilities, shares, timeline, tasks, netbios, trusts.

use anyhow::Result;
use redis::AsyncCommands;

use ares_core::models::{Share, User, VulnerabilityInfo};
use ares_core::state::{self, RedisStateReader};

use crate::state::{SharedState, KEY_VULN_QUEUE};
use crate::task_queue::TaskQueue;

impl SharedState {
    /// Add a user to state and Redis (with dedup).
    pub async fn publish_user(&self, queue: &TaskQueue, user: User) -> Result<bool> {
        // Check for duplicate in memory
        {
            let state = self.inner.read().await;
            let dedup = format!(
                "{}@{}",
                user.username.to_lowercase(),
                user.domain.to_lowercase()
            );
            if state.users.iter().any(|u| {
                format!("{}@{}", u.username.to_lowercase(), u.domain.to_lowercase()) == dedup
            }) {
                return Ok(false);
            }
        }

        let operation_id = {
            let state = self.inner.read().await;
            state.operation_id.clone()
        };
        let reader = RedisStateReader::new(operation_id);
        let mut conn = queue.connection();
        let added = reader.add_user(&mut conn, &user).await?;
        if added {
            let mut state = self.inner.write().await;
            state.users.push(user);
        }
        Ok(added)
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

    /// Add a share to state and Redis (with dedup).
    pub async fn publish_share(&self, queue: &TaskQueue, share: Share) -> Result<bool> {
        // Check for duplicate in memory
        {
            let state = self.inner.read().await;
            if state.shares.iter().any(|s| {
                s.host.to_lowercase() == share.host.to_lowercase()
                    && s.name.to_lowercase() == share.name.to_lowercase()
            }) {
                return Ok(false);
            }
        }

        let operation_id = {
            let state = self.inner.read().await;
            state.operation_id.clone()
        };
        let reader = RedisStateReader::new(operation_id);
        let mut conn = queue.connection();
        let added = reader.add_share(&mut conn, &share).await?;
        if added {
            let mut state = self.inner.write().await;
            state.shares.push(share);
        }
        Ok(added)
    }

    /// Persist a timeline event to Redis and add MITRE techniques.
    pub async fn persist_timeline_event(
        &self,
        queue: &TaskQueue,
        event: &serde_json::Value,
        mitre_techniques: &[String],
    ) -> Result<()> {
        let operation_id = {
            let state = self.inner.read().await;
            state.operation_id.clone()
        };
        let reader = RedisStateReader::new(operation_id);
        let mut conn = queue.connection();

        reader.add_timeline_event(&mut conn, event).await?;

        for technique in mitre_techniques {
            let _ = reader.add_technique(&mut conn, technique).await;
        }

        Ok(())
    }

    /// Record a pending task in memory and persist to Redis HASH.
    ///
    /// Key: `ares:op:{id}:pending_tasks` — matches Python's state_backend.
    pub async fn track_pending_task(
        &self,
        queue: &TaskQueue,
        task: ares_core::models::TaskInfo,
    ) -> Result<()> {
        let operation_id = {
            let state = self.inner.read().await;
            state.operation_id.clone()
        };
        let task_id = task.task_id.clone();
        let json = serde_json::to_string(&task).unwrap_or_default();

        // Persist to Redis
        let key = format!(
            "{}:{}:{}",
            state::KEY_PREFIX,
            operation_id,
            state::KEY_PENDING_TASKS,
        );
        let mut conn = queue.connection();
        let _: Result<(), _> = redis::AsyncCommands::hset(&mut conn, &key, &task_id, &json).await;
        let _: Result<(), _> = redis::AsyncCommands::expire(&mut conn, &key, 86400i64).await;

        // Update in-memory state
        let mut state = self.inner.write().await;
        state.pending_tasks.insert(task_id, task);
        Ok(())
    }

    /// Move a task from pending to completed, persisting both changes to Redis.
    ///
    /// Keys: `ares:op:{id}:pending_tasks`, `ares:op:{id}:completed_tasks`
    pub async fn complete_task(
        &self,
        queue: &TaskQueue,
        task_id: &str,
        result: ares_core::models::TaskResult,
    ) -> Result<()> {
        let operation_id = {
            let state = self.inner.read().await;
            state.operation_id.clone()
        };
        let result_json = serde_json::to_string(&result).unwrap_or_default();

        let pending_key = format!(
            "{}:{}:{}",
            state::KEY_PREFIX,
            operation_id,
            state::KEY_PENDING_TASKS,
        );
        let completed_key = format!(
            "{}:{}:{}",
            state::KEY_PREFIX,
            operation_id,
            state::KEY_COMPLETED_TASKS,
        );

        let mut conn = queue.connection();
        // Remove from pending, add to completed
        let _: Result<(), _> = redis::AsyncCommands::hdel(&mut conn, &pending_key, task_id).await;
        let _: Result<(), _> =
            redis::AsyncCommands::hset(&mut conn, &completed_key, task_id, &result_json).await;
        let _: Result<(), _> =
            redis::AsyncCommands::expire(&mut conn, &completed_key, 86400i64).await;

        // Update in-memory state
        let mut state = self.inner.write().await;
        state.pending_tasks.remove(task_id);
        state.completed_tasks.insert(task_id.to_string(), result);
        Ok(())
    }

    /// Persist a NetBIOS to FQDN mapping to Redis HASH.
    ///
    /// Key: `ares:op:{id}:netbios_map` — matches Python's `HSET` on netbios_map.
    pub async fn publish_netbios(
        &self,
        queue: &TaskQueue,
        netbios: &str,
        fqdn: &str,
    ) -> Result<()> {
        let operation_id = {
            let state = self.inner.read().await;
            state.operation_id.clone()
        };
        let key = format!(
            "{}:{}:{}",
            state::KEY_PREFIX,
            operation_id,
            state::KEY_NETBIOS_MAP,
        );
        let mut conn = queue.connection();
        let _: () = redis::AsyncCommands::hset(&mut conn, &key, netbios, fqdn).await?;
        let _: () = redis::AsyncCommands::expire(&mut conn, &key, 86400i64).await?;

        let mut state = self.inner.write().await;
        state
            .netbios_to_fqdn
            .insert(netbios.to_string(), fqdn.to_string());
        Ok(())
    }

    /// Add a trust relationship to state and Redis.
    pub async fn publish_trust_info(
        &self,
        queue: &TaskQueue,
        trust: ares_core::models::TrustInfo,
    ) -> Result<bool> {
        let operation_id = {
            let state = self.inner.read().await;
            state.operation_id.clone()
        };
        let reader = RedisStateReader::new(operation_id);
        let mut conn = queue.connection();
        let added = reader.add_trusted_domain(&mut conn, &trust).await?;
        if added {
            let domain_key = trust.domain.to_lowercase();
            let mut state = self.inner.write().await;
            state.trusted_domains.insert(domain_key, trust);
        }
        Ok(added)
    }
}
