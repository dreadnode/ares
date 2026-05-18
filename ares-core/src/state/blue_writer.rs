//! Blue team Redis state writer — write operations for investigation state.

use redis::AsyncCommands;

use crate::models::{BlueTaskInfo, Evidence, TimelineEvent, TriageRecord};

use super::keys::*;

/// Read-write Redis state backend for blue team investigations.
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
    /// Values are JSON-encoded.
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{BlueTaskInfo, Evidence, TimelineEvent, TriageRecord};
    use crate::state::mock_redis::MockRedisConnection;
    use std::collections::HashMap;

    fn make_writer() -> BlueStateWriter {
        BlueStateWriter::new("inv-test".to_string())
    }

    fn make_evidence(etype: &str, value: &str, source: &str) -> Evidence {
        Evidence {
            id: format!("ev-{value}"),
            evidence_type: etype.to_string(),
            value: value.to_string(),
            source: source.to_string(),
            timestamp: None,
            pyramid_level: 2,
            mitre_techniques: vec![],
            confidence: 0.8,
            metadata: HashMap::new(),
            source_query_id: None,
            validated: false,
        }
    }

    fn make_timeline_event(desc: &str) -> TimelineEvent {
        TimelineEvent {
            id: format!("te-{desc}"),
            timestamp: "2026-01-01T00:00:00Z".to_string(),
            description: desc.to_string(),
            evidence_ids: vec![],
            mitre_techniques: vec![],
            confidence: 0.7,
            source: "investigation".to_string(),
            extra_data_json: None,
        }
    }

    fn make_task(task_id: &str, task_type: &str) -> BlueTaskInfo {
        BlueTaskInfo {
            task_id: task_id.to_string(),
            task_type: task_type.to_string(),
            agent: String::new(),
            status: "pending".to_string(),
            created_at: String::new(),
            completed_at: None,
            result: None,
            error: None,
        }
    }

    fn make_triage_record(decision: &str) -> TriageRecord {
        TriageRecord {
            triage_id: "tr-001".to_string(),
            investigation_id: "inv-test".to_string(),
            decision: decision.to_string(),
            reasoning: "test reasoning".to_string(),
            confidence: 0.9,
            routed_to: None,
            focus_areas: vec![],
            reinvestigation_cycle: 0,
            created_at: None,
        }
    }

    #[tokio::test]
    async fn add_evidence_returns_true_for_new() {
        let mut conn = MockRedisConnection::new();
        let w = make_writer();
        let ev = make_evidence("ip", "192.168.58.1", "nmap");

        let added = w.add_evidence(&mut conn, &ev).await.unwrap();
        assert!(added);
    }

    #[tokio::test]
    async fn add_evidence_deduplicates() {
        let mut conn = MockRedisConnection::new();
        let w = make_writer();
        let ev = make_evidence("ip", "192.168.58.1", "nmap");

        let first = w.add_evidence(&mut conn, &ev).await.unwrap();
        let second = w.add_evidence(&mut conn, &ev).await.unwrap();
        assert!(first);
        assert!(!second);
    }

    #[tokio::test]
    async fn add_timeline_event_appends() {
        let mut conn = MockRedisConnection::new();
        let w = make_writer();

        w.add_timeline_event(&mut conn, &make_timeline_event("first"))
            .await
            .unwrap();
        w.add_timeline_event(&mut conn, &make_timeline_event("second"))
            .await
            .unwrap();

        let key = w.key(BLUE_KEY_TIMELINE);
        let items: Vec<String> = redis::AsyncCommands::lrange(&mut conn, &key, 0, -1)
            .await
            .unwrap();
        assert_eq!(items.len(), 2);
    }

    #[tokio::test]
    async fn add_technique_deduplicates() {
        let mut conn = MockRedisConnection::new();
        let w = make_writer();

        let first = w.add_technique(&mut conn, "T1059").await.unwrap();
        let second = w.add_technique(&mut conn, "T1059").await.unwrap();
        let third = w.add_technique(&mut conn, "T1046").await.unwrap();

        assert!(first);
        assert!(!second);
        assert!(third);
    }

    #[tokio::test]
    async fn add_tactic_deduplicates() {
        let mut conn = MockRedisConnection::new();
        let w = make_writer();

        let first = w.add_tactic(&mut conn, "TA0001").await.unwrap();
        let second = w.add_tactic(&mut conn, "TA0001").await.unwrap();

        assert!(first);
        assert!(!second);
    }

    #[tokio::test]
    async fn set_technique_name_stores_mapping() {
        let mut conn = MockRedisConnection::new();
        let w = make_writer();

        w.set_technique_name(&mut conn, "T1059", "Command and Scripting Interpreter")
            .await
            .unwrap();

        let key = w.key(BLUE_KEY_TECHNIQUE_NAMES);
        let val: Option<String> = redis::AsyncCommands::hget(&mut conn, &key, "T1059")
            .await
            .unwrap();
        assert_eq!(val.as_deref(), Some("Command and Scripting Interpreter"));
    }

    #[tokio::test]
    async fn track_host_lowercases_and_deduplicates() {
        let mut conn = MockRedisConnection::new();
        let w = make_writer();

        let first = w.track_host(&mut conn, "DC01.CONTOSO.LOCAL").await.unwrap();
        let second = w.track_host(&mut conn, "dc01.contoso.local").await.unwrap();

        assert!(first);
        assert!(!second);
    }

    #[tokio::test]
    async fn track_user_lowercases_and_deduplicates() {
        let mut conn = MockRedisConnection::new();
        let w = make_writer();

        let first = w.track_user(&mut conn, "Admin").await.unwrap();
        let second = w.track_user(&mut conn, "admin").await.unwrap();

        assert!(first);
        assert!(!second);
    }

    #[tokio::test]
    async fn mark_query_type_and_record_query() {
        let mut conn = MockRedisConnection::new();
        let w = make_writer();

        w.mark_query_type(&mut conn, "process_events")
            .await
            .unwrap();
        w.record_query(
            &mut conn,
            &serde_json::json!({"query": "SELECT * FROM processes"}),
        )
        .await
        .unwrap();

        let qt_key = w.key(BLUE_KEY_QUERY_TYPES);
        let members: std::collections::HashSet<String> =
            redis::AsyncCommands::smembers(&mut conn, &qt_key)
                .await
                .unwrap();
        assert!(members.contains("process_events"));

        let q_key = w.key(BLUE_KEY_QUERIES);
        let queries: Vec<String> = redis::AsyncCommands::lrange(&mut conn, &q_key, 0, -1)
            .await
            .unwrap();
        assert_eq!(queries.len(), 1);
    }

    #[tokio::test]
    async fn add_lateral_connection_appends() {
        let mut conn = MockRedisConnection::new();
        let w = make_writer();
        let connection = serde_json::json!({"src": "192.168.58.1", "dst": "192.168.58.2"});

        w.add_lateral_connection(&mut conn, &connection)
            .await
            .unwrap();

        let key = w.key(BLUE_KEY_LATERAL);
        let items: Vec<String> = redis::AsyncCommands::lrange(&mut conn, &key, 0, -1)
            .await
            .unwrap();
        assert_eq!(items.len(), 1);
        let parsed: serde_json::Value = serde_json::from_str(&items[0]).unwrap();
        assert_eq!(parsed["src"], "192.168.58.1");
    }

    #[tokio::test]
    async fn pop_all_pivots_drains_queue() {
        let mut conn = MockRedisConnection::new();
        let w = make_writer();

        w.queue_pivot(&mut conn, "host-a").await.unwrap();
        w.queue_pivot(&mut conn, "host-b").await.unwrap();

        let pivots = w.pop_all_pivots(&mut conn).await.unwrap();
        assert_eq!(pivots, vec!["host-a", "host-b"]);

        let empty = w.pop_all_pivots(&mut conn).await.unwrap();
        assert!(empty.is_empty());
    }

    #[tokio::test]
    async fn pop_all_chains_drains_queue() {
        let mut conn = MockRedisConnection::new();
        let w = make_writer();

        w.queue_chain(&mut conn, "detect-a").await.unwrap();
        w.queue_chain(&mut conn, "detect-b").await.unwrap();

        let chains = w.pop_all_chains(&mut conn).await.unwrap();
        assert_eq!(chains, vec!["detect-a", "detect-b"]);

        let empty = w.pop_all_chains(&mut conn).await.unwrap();
        assert!(empty.is_empty());
    }

    #[tokio::test]
    async fn add_recommendation_appends() {
        let mut conn = MockRedisConnection::new();
        let w = make_writer();

        w.add_recommendation(&mut conn, "Block IP 192.168.58.5")
            .await
            .unwrap();
        w.add_recommendation(&mut conn, "Rotate credentials")
            .await
            .unwrap();

        let key = w.key(BLUE_KEY_RECOMMENDATIONS);
        let items: Vec<String> = redis::AsyncCommands::lrange(&mut conn, &key, 0, -1)
            .await
            .unwrap();
        assert_eq!(items.len(), 2);
        assert_eq!(items[0], "Block IP 192.168.58.5");
    }

    #[tokio::test]
    async fn set_triage_decision_and_add_triage_record() {
        let mut conn = MockRedisConnection::new();
        let w = make_writer();
        let record = make_triage_record("confirmed");

        w.set_triage_decision(&mut conn, &record).await.unwrap();
        w.add_triage_record(&mut conn, &record).await.unwrap();

        let dec_key = w.key(BLUE_KEY_TRIAGE_DECISION);
        let raw: Option<String> = redis::AsyncCommands::get(&mut conn, &dec_key)
            .await
            .unwrap();
        assert!(raw.is_some());
        let parsed: serde_json::Value = serde_json::from_str(&raw.unwrap()).unwrap();
        assert_eq!(parsed["decision"], "confirmed");

        let rec_key = w.key(BLUE_KEY_TRIAGE_RECORDS);
        let items: Vec<String> = redis::AsyncCommands::lrange(&mut conn, &rec_key, 0, -1)
            .await
            .unwrap();
        assert_eq!(items.len(), 1);
    }

    #[tokio::test]
    async fn add_pending_task_and_complete_task() {
        let mut conn = MockRedisConnection::new();
        let w = make_writer();
        let task = make_task("task-1", "query_logs");

        w.add_pending_task(&mut conn, &task).await.unwrap();

        let pending_key = w.key(BLUE_KEY_PENDING_TASKS);
        let pending_val: Option<String> =
            redis::AsyncCommands::hget(&mut conn, &pending_key, "task-1")
                .await
                .unwrap();
        assert!(pending_val.is_some());

        let mut completed_task = task.clone();
        completed_task.status = "completed".to_string();
        w.complete_task(&mut conn, &completed_task).await.unwrap();

        let removed: Option<String> = redis::AsyncCommands::hget(&mut conn, &pending_key, "task-1")
            .await
            .unwrap();
        assert!(removed.is_none());

        let completed_key = w.key(BLUE_KEY_COMPLETED_TASKS);
        let completed_val: Option<String> =
            redis::AsyncCommands::hget(&mut conn, &completed_key, "task-1")
                .await
                .unwrap();
        assert!(completed_val.is_some());
    }

    #[tokio::test]
    async fn set_meta_stores_json_value() {
        let mut conn = MockRedisConnection::new();
        let w = make_writer();

        w.set_meta(&mut conn, "escalated", &serde_json::Value::Bool(true))
            .await
            .unwrap();

        let key = w.key(BLUE_KEY_META);
        let raw: Option<String> = redis::AsyncCommands::hget(&mut conn, &key, "escalated")
            .await
            .unwrap();
        assert_eq!(raw.as_deref(), Some("true"));
    }

    #[tokio::test]
    async fn initialize_sets_meta_fields() {
        let mut conn = MockRedisConnection::new();
        let w = make_writer();
        let alert = serde_json::json!({"alert_id": "a-001", "severity": "high"});

        w.initialize(&mut conn, &alert).await.unwrap();

        let key = w.key(BLUE_KEY_META);
        let alert_raw: Option<String> = redis::AsyncCommands::hget(&mut conn, &key, "alert")
            .await
            .unwrap();
        assert!(alert_raw.is_some());
        let parsed: serde_json::Value = serde_json::from_str(&alert_raw.unwrap()).unwrap();
        assert_eq!(parsed["alert_id"], "a-001");

        let stage_raw: Option<String> = redis::AsyncCommands::hget(&mut conn, &key, "stage")
            .await
            .unwrap();
        assert!(stage_raw.is_some());
        let stage: String = serde_json::from_str(&stage_raw.unwrap()).unwrap();
        assert_eq!(stage, "triage");

        let started: Option<String> = redis::AsyncCommands::hget(&mut conn, &key, "started_at")
            .await
            .unwrap();
        assert!(started.is_some());
    }

    #[tokio::test]
    async fn acquire_and_release_lock() {
        let mut conn = MockRedisConnection::new();
        let w = make_writer();

        let acquired = w.acquire_lock(&mut conn, 300).await.unwrap();
        assert!(acquired);

        let duplicate = w.acquire_lock(&mut conn, 300).await.unwrap();
        assert!(!duplicate);

        w.release_lock(&mut conn).await.unwrap();

        let reacquired = w.acquire_lock(&mut conn, 300).await.unwrap();
        assert!(reacquired);
    }

    #[tokio::test]
    async fn extend_lock_returns_false_when_absent() {
        let mut conn = MockRedisConnection::new();
        let w = make_writer();

        let extended = w.extend_lock(&mut conn, 300).await.unwrap();
        assert!(!extended);

        w.acquire_lock(&mut conn, 300).await.unwrap();
        let extended = w.extend_lock(&mut conn, 600).await.unwrap();
        assert!(extended);
    }

    #[tokio::test]
    async fn set_status_running() {
        let mut conn = MockRedisConnection::new();
        let w = make_writer();

        w.set_status(&mut conn, "running", None).await.unwrap();

        let key = format!("{}:{}:status", BLUE_STATUS_PREFIX, "inv-test");
        let raw: Option<String> = redis::AsyncCommands::get(&mut conn, &key).await.unwrap();
        assert!(raw.is_some());
        let parsed: serde_json::Value = serde_json::from_str(&raw.unwrap()).unwrap();
        assert_eq!(parsed["status"], "running");
        assert!(parsed.get("started_at").is_some());
        assert!(parsed.get("completed_at").is_none());
    }

    #[tokio::test]
    async fn set_status_completed_includes_completed_at() {
        let mut conn = MockRedisConnection::new();
        let w = make_writer();

        w.set_status(&mut conn, "completed", None).await.unwrap();

        let key = format!("{}:{}:status", BLUE_STATUS_PREFIX, "inv-test");
        let raw: Option<String> = redis::AsyncCommands::get(&mut conn, &key).await.unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&raw.unwrap()).unwrap();
        assert_eq!(parsed["status"], "completed");
        assert!(parsed.get("completed_at").is_some());
    }

    #[tokio::test]
    async fn set_status_failed_includes_error() {
        let mut conn = MockRedisConnection::new();
        let w = make_writer();

        w.set_status(&mut conn, "failed", Some("timeout"))
            .await
            .unwrap();

        let key = format!("{}:{}:status", BLUE_STATUS_PREFIX, "inv-test");
        let raw: Option<String> = redis::AsyncCommands::get(&mut conn, &key).await.unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&raw.unwrap()).unwrap();
        assert_eq!(parsed["status"], "failed");
        assert_eq!(parsed["error"], "timeout");
        assert!(parsed.get("completed_at").is_some());
    }
}
