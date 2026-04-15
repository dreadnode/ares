//! Blue team Redis state writer.
//!
//! Provides write operations for investigation state, matching the Python
//! `BlueStateBackend` key patterns and serialization format exactly.

use redis::AsyncCommands;

use crate::models::{BlueTaskInfo, Evidence, TimelineEvent, TriageRecord};

use super::keys::*;

/// Read-write Redis state backend for blue team investigations.
///
/// This provides methods to write investigation state to Redis, matching
/// the Python `BlueStateBackend` write operations exactly.
pub struct BlueStateWriter {
    investigation_id: String,
}

impl BlueStateWriter {
    pub fn new(investigation_id: String) -> Self {
        Self { investigation_id }
    }

    pub fn investigation_id(&self) -> &str {
        &self.investigation_id
    }

    fn key(&self, suffix: &str) -> String {
        super::build_blue_key(&self.investigation_id, suffix)
    }

    /// Add evidence to `ares:blue:inv:{id}:evidence` HASH.
    ///
    /// Uses HSETNX for O(1) deduplication. Returns true if new evidence was added.
    pub async fn add_evidence(
        &self,
        conn: &mut impl AsyncCommands,
        evidence: &Evidence,
    ) -> Result<bool, redis::RedisError> {
        let key = self.key(BLUE_KEY_EVIDENCE);
        let dedup_key = format!(
            "{}:{}:{}",
            evidence.evidence_type,
            evidence.value.to_lowercase(),
            evidence.source
        );
        let data = serde_json::to_string(evidence).unwrap_or_default();
        let added: bool = conn.hset_nx(&key, &dedup_key, &data).await?;
        if added {
            let _: () = conn.expire(&key, 86400).await?;
        }
        Ok(added)
    }

    /// Add a timeline event to `ares:blue:inv:{id}:timeline` LIST.
    pub async fn add_timeline_event(
        &self,
        conn: &mut impl AsyncCommands,
        event: &TimelineEvent,
    ) -> Result<(), redis::RedisError> {
        let key = self.key(BLUE_KEY_TIMELINE);
        let data = serde_json::to_string(event).unwrap_or_default();
        let _: () = conn.rpush(&key, &data).await?;
        let _: () = conn.expire(&key, 86400).await?;
        Ok(())
    }

    /// Add a MITRE ATT&CK technique to `ares:blue:inv:{id}:techniques` SET.
    pub async fn add_technique(
        &self,
        conn: &mut impl AsyncCommands,
        technique_id: &str,
    ) -> Result<bool, redis::RedisError> {
        let key = self.key(BLUE_KEY_TECHNIQUES);
        let added: i64 = conn.sadd(&key, technique_id).await?;
        let _: () = conn.expire(&key, 86400).await?;
        Ok(added > 0)
    }

    /// Add a MITRE ATT&CK tactic to `ares:blue:inv:{id}:tactics` SET.
    pub async fn add_tactic(
        &self,
        conn: &mut impl AsyncCommands,
        tactic_id: &str,
    ) -> Result<bool, redis::RedisError> {
        let key = self.key(BLUE_KEY_TACTICS);
        let added: i64 = conn.sadd(&key, tactic_id).await?;
        let _: () = conn.expire(&key, 86400).await?;
        Ok(added > 0)
    }

    /// Set a technique name mapping in `ares:blue:inv:{id}:technique_names` HASH.
    pub async fn set_technique_name(
        &self,
        conn: &mut impl AsyncCommands,
        technique_id: &str,
        name: &str,
    ) -> Result<(), redis::RedisError> {
        let key = self.key(BLUE_KEY_TECHNIQUE_NAMES);
        let _: () = conn.hset(&key, technique_id, name).await?;
        let _: () = conn.expire(&key, 86400).await?;
        Ok(())
    }

    /// Track a queried host in `ares:blue:inv:{id}:hosts` SET.
    pub async fn track_host(
        &self,
        conn: &mut impl AsyncCommands,
        hostname: &str,
    ) -> Result<bool, redis::RedisError> {
        let key = self.key(BLUE_KEY_HOSTS);
        let added: i64 = conn.sadd(&key, hostname.to_lowercase()).await?;
        let _: () = conn.expire(&key, 86400).await?;
        Ok(added > 0)
    }

    /// Track a queried user in `ares:blue:inv:{id}:users` SET.
    pub async fn track_user(
        &self,
        conn: &mut impl AsyncCommands,
        username: &str,
    ) -> Result<bool, redis::RedisError> {
        let key = self.key(BLUE_KEY_USERS);
        let added: i64 = conn.sadd(&key, username.to_lowercase()).await?;
        let _: () = conn.expire(&key, 86400).await?;
        Ok(added > 0)
    }

    /// Mark a query type as executed in `ares:blue:inv:{id}:query_types` SET.
    pub async fn mark_query_type(
        &self,
        conn: &mut impl AsyncCommands,
        query_type: &str,
    ) -> Result<(), redis::RedisError> {
        let key = self.key(BLUE_KEY_QUERY_TYPES);
        let _: () = conn.sadd(&key, query_type).await?;
        let _: () = conn.expire(&key, 86400).await?;
        Ok(())
    }

    /// Record an executed query in `ares:blue:inv:{id}:queries` LIST.
    pub async fn record_query(
        &self,
        conn: &mut impl AsyncCommands,
        query_json: &serde_json::Value,
    ) -> Result<(), redis::RedisError> {
        let key = self.key(BLUE_KEY_QUERIES);
        let data = serde_json::to_string(query_json).unwrap_or_default();
        let _: () = conn.rpush(&key, &data).await?;
        let _: () = conn.expire(&key, 86400).await?;
        Ok(())
    }

    /// Add a lateral movement connection in `ares:blue:inv:{id}:lateral` LIST.
    pub async fn add_lateral_connection(
        &self,
        conn: &mut impl AsyncCommands,
        connection: &serde_json::Value,
    ) -> Result<(), redis::RedisError> {
        let key = self.key(BLUE_KEY_LATERAL);
        let data = serde_json::to_string(connection).unwrap_or_default();
        let _: () = conn.rpush(&key, &data).await?;
        let _: () = conn.expire(&key, 86400).await?;
        Ok(())
    }

    /// Queue a pivot investigation target in `ares:blue:inv:{id}:pivot_queue` LIST.
    pub async fn queue_pivot(
        &self,
        conn: &mut impl AsyncCommands,
        target: &str,
    ) -> Result<(), redis::RedisError> {
        let key = self.key(BLUE_KEY_PIVOT_QUEUE);
        let _: () = conn.rpush(&key, target).await?;
        let _: () = conn.expire(&key, 86400).await?;
        Ok(())
    }

    /// Queue a chained detection method in `ares:blue:inv:{id}:chain_queue` LIST.
    pub async fn queue_chain(
        &self,
        conn: &mut impl AsyncCommands,
        detection_method: &str,
    ) -> Result<(), redis::RedisError> {
        let key = self.key(BLUE_KEY_CHAIN_QUEUE);
        let _: () = conn.rpush(&key, detection_method).await?;
        let _: () = conn.expire(&key, 86400).await?;
        Ok(())
    }

    /// Pop all pivot targets from `ares:blue:inv:{id}:pivot_queue` LIST.
    pub async fn pop_all_pivots(
        &self,
        conn: &mut impl AsyncCommands,
    ) -> Result<Vec<String>, redis::RedisError> {
        let key = self.key(BLUE_KEY_PIVOT_QUEUE);
        let items: Vec<String> = conn.lrange(&key, 0, -1).await?;
        if !items.is_empty() {
            let _: () = conn.del(&key).await?;
        }
        Ok(items)
    }

    /// Pop all chain detection methods from `ares:blue:inv:{id}:chain_queue` LIST.
    pub async fn pop_all_chains(
        &self,
        conn: &mut impl AsyncCommands,
    ) -> Result<Vec<String>, redis::RedisError> {
        let key = self.key(BLUE_KEY_CHAIN_QUEUE);
        let items: Vec<String> = conn.lrange(&key, 0, -1).await?;
        if !items.is_empty() {
            let _: () = conn.del(&key).await?;
        }
        Ok(items)
    }

    /// Add a recommendation to `ares:blue:inv:{id}:recommendations` LIST.
    pub async fn add_recommendation(
        &self,
        conn: &mut impl AsyncCommands,
        recommendation: &str,
    ) -> Result<(), redis::RedisError> {
        let key = self.key(BLUE_KEY_RECOMMENDATIONS);
        let _: () = conn.rpush(&key, recommendation).await?;
        let _: () = conn.expire(&key, 86400).await?;
        Ok(())
    }

    /// Set the triage decision in `ares:blue:inv:{id}:triage:decision` STRING.
    pub async fn set_triage_decision(
        &self,
        conn: &mut impl AsyncCommands,
        record: &TriageRecord,
    ) -> Result<(), redis::RedisError> {
        let key = self.key(BLUE_KEY_TRIAGE_DECISION);
        let data = serde_json::to_string(record).unwrap_or_default();
        let _: () = conn.set_ex(&key, &data, 86400).await?;
        Ok(())
    }

    /// Append a triage record to the audit trail in `ares:blue:inv:{id}:triage:records` LIST.
    pub async fn add_triage_record(
        &self,
        conn: &mut impl AsyncCommands,
        record: &TriageRecord,
    ) -> Result<(), redis::RedisError> {
        let key = self.key(BLUE_KEY_TRIAGE_RECORDS);
        let data = serde_json::to_string(record).unwrap_or_default();
        let _: () = conn.rpush(&key, &data).await?;
        let _: () = conn.expire(&key, 86400).await?;
        Ok(())
    }

    /// Register a pending task in `ares:blue:inv:{id}:tasks:pending` HASH.
    pub async fn add_pending_task(
        &self,
        conn: &mut impl AsyncCommands,
        task: &BlueTaskInfo,
    ) -> Result<(), redis::RedisError> {
        let key = self.key(BLUE_KEY_PENDING_TASKS);
        let data = serde_json::to_string(task).unwrap_or_default();
        let _: () = conn.hset(&key, &task.task_id, &data).await?;
        let _: () = conn.expire(&key, 86400).await?;
        Ok(())
    }

    /// Move a task from pending to completed.
    pub async fn complete_task(
        &self,
        conn: &mut impl AsyncCommands,
        task: &BlueTaskInfo,
    ) -> Result<(), redis::RedisError> {
        let pending_key = self.key(BLUE_KEY_PENDING_TASKS);
        let completed_key = self.key(BLUE_KEY_COMPLETED_TASKS);
        let _: () = conn.hdel(&pending_key, &task.task_id).await?;
        let data = serde_json::to_string(task).unwrap_or_default();
        let _: () = conn.hset(&completed_key, &task.task_id, &data).await?;
        let _: () = conn.expire(&completed_key, 86400).await?;
        Ok(())
    }

    /// Set a meta field in `ares:blue:inv:{id}:meta` HASH.
    ///
    /// Values are JSON-encoded to match Python's `json.dumps(value)`.
    pub async fn set_meta(
        &self,
        conn: &mut impl AsyncCommands,
        field: &str,
        value: &serde_json::Value,
    ) -> Result<(), redis::RedisError> {
        let key = self.key(BLUE_KEY_META);
        let serialized = serde_json::to_string(value).unwrap_or_default();
        let _: () = conn.hset(&key, field, &serialized).await?;
        let _: () = conn.expire(&key, 86400).await?;
        Ok(())
    }

    /// Initialize investigation metadata.
    ///
    /// Sets alert, stage, started_at in the meta HASH.
    pub async fn initialize(
        &self,
        conn: &mut impl AsyncCommands,
        alert: &serde_json::Value,
    ) -> Result<(), redis::RedisError> {
        let key = self.key(BLUE_KEY_META);
        let started_at = chrono::Utc::now().to_rfc3339();

        let _: () = conn
            .hset(
                &key,
                "alert",
                serde_json::to_string(alert).unwrap_or_default(),
            )
            .await?;
        let _: () = conn
            .hset(
                &key,
                "stage",
                serde_json::to_string(&serde_json::Value::String("triage".to_string()))
                    .unwrap_or_default(),
            )
            .await?;
        let _: () = conn
            .hset(
                &key,
                "started_at",
                serde_json::to_string(&serde_json::Value::String(started_at)).unwrap_or_default(),
            )
            .await?;
        let _: () = conn.expire(&key, 86400).await?;
        Ok(())
    }

    /// Acquire an investigation lock.
    pub async fn acquire_lock(
        &self,
        conn: &mut impl AsyncCommands,
        ttl_secs: u64,
    ) -> Result<bool, redis::RedisError> {
        let lock_key = super::build_blue_lock_key(&self.investigation_id);
        let set: bool = conn
            .set_nx(&lock_key, chrono::Utc::now().to_rfc3339())
            .await?;
        if set {
            let _: () = conn.expire(&lock_key, ttl_secs as i64).await?;
        }
        Ok(set)
    }

    /// Extend the investigation lock TTL.
    pub async fn extend_lock(
        &self,
        conn: &mut impl AsyncCommands,
        ttl_secs: u64,
    ) -> Result<bool, redis::RedisError> {
        let lock_key = super::build_blue_lock_key(&self.investigation_id);
        let exists: bool = conn.exists(&lock_key).await?;
        if exists {
            let _: () = conn.expire(&lock_key, ttl_secs as i64).await?;
        }
        Ok(exists)
    }

    /// Release the investigation lock.
    pub async fn release_lock(
        &self,
        conn: &mut impl AsyncCommands,
    ) -> Result<(), redis::RedisError> {
        let lock_key = super::build_blue_lock_key(&self.investigation_id);
        let _: () = conn.del(&lock_key).await?;
        Ok(())
    }

    /// Set the investigation status in `ares:blue:inv:{id}:status` STRING.
    ///
    /// Stores a JSON object with `status`, `started_at`, and optional
    /// `completed_at`/`error` fields so CLI readers can display them.
    pub async fn set_status(
        &self,
        conn: &mut impl AsyncCommands,
        status: &str,
        error: Option<&str>,
    ) -> Result<(), redis::RedisError> {
        let key = format!("{}:{}:status", BLUE_STATUS_PREFIX, self.investigation_id);
        let now = chrono::Utc::now().to_rfc3339();

        // Preserve started_at from previous status if it exists
        let started_at = if let Ok(existing) = conn.get::<_, Option<String>>(&key).await {
            existing
                .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok())
                .and_then(|v| {
                    v.get("started_at")
                        .and_then(|s| s.as_str())
                        .map(String::from)
                })
                .unwrap_or_else(|| now.clone())
        } else {
            now.clone()
        };

        let mut obj = serde_json::json!({
            "status": status,
            "started_at": started_at,
        });
        if matches!(status, "completed" | "escalated" | "failed") {
            obj["completed_at"] = serde_json::Value::String(now.clone());
        }
        if let Some(err) = error {
            obj["error"] = serde_json::Value::String(err.to_string());
        }
        let data = serde_json::to_string(&obj).unwrap_or_default();
        let _: () = conn.set_ex(&key, &data, 86400).await?;
        Ok(())
    }
}
