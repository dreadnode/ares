//! Blue team Redis state reader.

use std::collections::HashMap;

use redis::AsyncCommands;

use crate::models::{BlueTaskInfo, Evidence, SharedBlueTeamState, TimelineEvent, TriageRecord};

use super::keys::*;
use super::try_deserialize;

/// Read-only Redis state backend for blue team investigations.
pub struct BlueStateReader {
    investigation_id: String,
}

impl BlueStateReader {
    pub fn new(investigation_id: String) -> Self {
        Self { investigation_id }
    }

    fn key(&self, suffix: &str) -> String {
        super::build_blue_key(&self.investigation_id, suffix)
    }

    /// Check if the investigation exists in Redis.
    pub async fn exists(&self, conn: &mut impl AsyncCommands) -> Result<bool, redis::RedisError> {
        let exists: bool = conn.exists(self.key(BLUE_KEY_META)).await?;
        Ok(exists)
    }

    /// Load all evidence from `ares:blue:inv:{id}:evidence` HASH.
    ///
    /// Values are JSON-serialized Evidence objects; keys are dedup keys.
    pub async fn get_evidence(
        &self,
        conn: &mut impl AsyncCommands,
    ) -> Result<Vec<Evidence>, redis::RedisError> {
        let items: HashMap<String, String> = conn.hgetall(self.key(BLUE_KEY_EVIDENCE)).await?;
        let result = items
            .into_values()
            .filter_map(|json_str| try_deserialize(&json_str, "evidence"))
            .collect();
        Ok(result)
    }

    /// Load timeline events from `ares:blue:inv:{id}:timeline` LIST.
    pub async fn get_timeline(
        &self,
        conn: &mut impl AsyncCommands,
    ) -> Result<Vec<TimelineEvent>, redis::RedisError> {
        let items: Vec<String> = conn.lrange(self.key(BLUE_KEY_TIMELINE), 0, -1).await?;
        let result = items
            .iter()
            .filter_map(|json_str| try_deserialize(json_str, "timeline event"))
            .collect();
        Ok(result)
    }

    /// Load MITRE ATT&CK technique IDs from `ares:blue:inv:{id}:techniques` SET.
    pub async fn get_techniques(
        &self,
        conn: &mut impl AsyncCommands,
    ) -> Result<Vec<String>, redis::RedisError> {
        let items: std::collections::HashSet<String> =
            conn.smembers(self.key(BLUE_KEY_TECHNIQUES)).await?;
        Ok(items.into_iter().collect())
    }

    /// Load MITRE ATT&CK tactic IDs from `ares:blue:inv:{id}:tactics` SET.
    pub async fn get_tactics(
        &self,
        conn: &mut impl AsyncCommands,
    ) -> Result<Vec<String>, redis::RedisError> {
        let items: std::collections::HashSet<String> =
            conn.smembers(self.key(BLUE_KEY_TACTICS)).await?;
        Ok(items.into_iter().collect())
    }

    /// Load technique name mappings from `ares:blue:inv:{id}:technique_names` HASH.
    pub async fn get_technique_names(
        &self,
        conn: &mut impl AsyncCommands,
    ) -> Result<HashMap<String, String>, redis::RedisError> {
        let items: HashMap<String, String> =
            conn.hgetall(self.key(BLUE_KEY_TECHNIQUE_NAMES)).await?;
        Ok(items)
    }

    /// Load queried hosts from `ares:blue:inv:{id}:hosts` SET.
    pub async fn get_hosts(
        &self,
        conn: &mut impl AsyncCommands,
    ) -> Result<Vec<String>, redis::RedisError> {
        let items: std::collections::HashSet<String> =
            conn.smembers(self.key(BLUE_KEY_HOSTS)).await?;
        Ok(items.into_iter().collect())
    }

    /// Load queried users from `ares:blue:inv:{id}:users` SET.
    pub async fn get_users(
        &self,
        conn: &mut impl AsyncCommands,
    ) -> Result<Vec<String>, redis::RedisError> {
        let items: std::collections::HashSet<String> =
            conn.smembers(self.key(BLUE_KEY_USERS)).await?;
        Ok(items.into_iter().collect())
    }

    /// Load executed query types from `ares:blue:inv:{id}:query_types` SET.
    pub async fn get_query_types(
        &self,
        conn: &mut impl AsyncCommands,
    ) -> Result<Vec<String>, redis::RedisError> {
        let items: std::collections::HashSet<String> =
            conn.smembers(self.key(BLUE_KEY_QUERY_TYPES)).await?;
        Ok(items.into_iter().collect())
    }

    /// Load executed queries from `ares:blue:inv:{id}:queries` LIST.
    pub async fn get_queries(
        &self,
        conn: &mut impl AsyncCommands,
    ) -> Result<Vec<serde_json::Value>, redis::RedisError> {
        let items: Vec<String> = conn.lrange(self.key(BLUE_KEY_QUERIES), 0, -1).await?;
        Ok(items
            .iter()
            .filter_map(|s| serde_json::from_str(s).ok())
            .collect())
    }

    /// Load recommendations from `ares:blue:inv:{id}:recommendations` LIST.
    pub async fn get_recommendations(
        &self,
        conn: &mut impl AsyncCommands,
    ) -> Result<Vec<String>, redis::RedisError> {
        let items: Vec<String> = conn
            .lrange(self.key(BLUE_KEY_RECOMMENDATIONS), 0, -1)
            .await?;
        Ok(items)
    }

    /// Load the current triage decision from `ares:blue:inv:{id}:triage:decision` STRING.
    pub async fn get_triage_decision(
        &self,
        conn: &mut impl AsyncCommands,
    ) -> Result<Option<serde_json::Value>, redis::RedisError> {
        let raw: Option<String> = conn.get(self.key(BLUE_KEY_TRIAGE_DECISION)).await?;
        match raw {
            Some(json_str) => Ok(try_deserialize(&json_str, "triage decision")),
            None => Ok(None),
        }
    }

    /// Load triage records from `ares:blue:inv:{id}:triage:records` LIST.
    pub async fn get_triage_records(
        &self,
        conn: &mut impl AsyncCommands,
    ) -> Result<Vec<TriageRecord>, redis::RedisError> {
        let items: Vec<String> = conn
            .lrange(self.key(BLUE_KEY_TRIAGE_RECORDS), 0, -1)
            .await?;
        let result = items
            .iter()
            .filter_map(|json_str| try_deserialize(json_str, "triage record"))
            .collect();
        Ok(result)
    }

    /// Load pending tasks from `ares:blue:inv:{id}:tasks:pending` HASH.
    pub async fn get_pending_tasks(
        &self,
        conn: &mut impl AsyncCommands,
    ) -> Result<HashMap<String, BlueTaskInfo>, redis::RedisError> {
        let items: HashMap<String, String> = conn.hgetall(self.key(BLUE_KEY_PENDING_TASKS)).await?;
        let mut result = HashMap::with_capacity(items.len());
        for (task_id, json_str) in items {
            if let Some(task) =
                try_deserialize::<BlueTaskInfo>(&json_str, &format!("pending task {task_id}"))
            {
                result.insert(task_id, task);
            }
        }
        Ok(result)
    }

    /// Load completed tasks from `ares:blue:inv:{id}:tasks:completed` HASH.
    pub async fn get_completed_tasks(
        &self,
        conn: &mut impl AsyncCommands,
    ) -> Result<HashMap<String, BlueTaskInfo>, redis::RedisError> {
        let items: HashMap<String, String> =
            conn.hgetall(self.key(BLUE_KEY_COMPLETED_TASKS)).await?;
        let mut result = HashMap::with_capacity(items.len());
        for (task_id, json_str) in items {
            if let Some(task) =
                try_deserialize::<BlueTaskInfo>(&json_str, &format!("completed task {task_id}"))
            {
                result.insert(task_id, task);
            }
        }
        Ok(result)
    }

    /// Load meta fields from `ares:blue:inv:{id}:meta` HASH.
    ///
    /// Meta fields are stored as JSON-encoded values.
    pub async fn get_meta(
        &self,
        conn: &mut impl AsyncCommands,
    ) -> Result<HashMap<String, serde_json::Value>, redis::RedisError> {
        let raw: HashMap<String, String> = conn.hgetall(self.key(BLUE_KEY_META)).await?;
        let mut result = HashMap::with_capacity(raw.len());
        for (field, json_str) in raw {
            match serde_json::from_str::<serde_json::Value>(&json_str) {
                Ok(val) => {
                    result.insert(field, val);
                }
                Err(_) => {
                    // Fall back to treating it as a plain string
                    result.insert(field, serde_json::Value::String(json_str));
                }
            }
        }
        Ok(result)
    }

    /// Check if the investigation has an active lock.
    pub async fn is_running(
        &self,
        conn: &mut impl AsyncCommands,
    ) -> Result<bool, redis::RedisError> {
        let exists: bool = conn
            .exists(super::build_blue_lock_key(&self.investigation_id))
            .await?;
        Ok(exists)
    }

    /// Load the full SharedBlueTeamState from Redis.
    ///
    /// This is the Rust equivalent of `BlueStateBackend.snapshot()`.
    pub async fn load_state(
        &self,
        conn: &mut impl AsyncCommands,
    ) -> Result<Option<SharedBlueTeamState>, redis::RedisError> {
        if !self.exists(conn).await? {
            return Ok(None);
        }

        let meta = self.get_meta(conn).await?;
        let evidence = self.get_evidence(conn).await?;
        let timeline = self.get_timeline(conn).await?;
        let techniques = self.get_techniques(conn).await?;
        let tactics = self.get_tactics(conn).await?;
        let technique_names = self.get_technique_names(conn).await?;
        let hosts = self.get_hosts(conn).await?;
        let users = self.get_users(conn).await?;
        let query_types = self.get_query_types(conn).await?;
        let recommendations = self.get_recommendations(conn).await?;
        let triage_decision = self.get_triage_decision(conn).await?;
        let triage_records = self.get_triage_records(conn).await?;
        let pending_tasks = self.get_pending_tasks(conn).await?;
        let completed_tasks = self.get_completed_tasks(conn).await?;

        // Extract scalar meta fields
        let stage = meta
            .get("stage")
            .and_then(|v| v.as_str())
            .unwrap_or("triage")
            .to_string();
        let started_at = meta
            .get("started_at")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let escalated = meta
            .get("escalated")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let escalation_reason = meta
            .get("escalation_reason")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        let attack_synopsis = meta
            .get("attack_synopsis")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        let alert = meta
            .get("alert")
            .cloned()
            .unwrap_or(serde_json::Value::Null);

        let state = SharedBlueTeamState {
            investigation_id: self.investigation_id.clone(),
            alert,
            stage,
            started_at,
            evidence,
            timeline,
            identified_techniques: techniques,
            identified_tactics: tactics,
            technique_names,
            queried_hosts: hosts,
            queried_users: users,
            executed_query_types: query_types,
            escalated,
            escalation_reason,
            attack_synopsis,
            recommendations,
            triage_decision,
            triage_records,
            pending_tasks,
            completed_tasks,
        };

        Ok(Some(state))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{BlueTaskInfo, Evidence, TimelineEvent, TriageRecord};
    use crate::state::blue_writer::BlueStateWriter;
    use crate::state::mock_redis::MockRedisConnection;

    fn make_writer() -> BlueStateWriter {
        BlueStateWriter::new("inv-test".to_string())
    }

    fn make_reader() -> BlueStateReader {
        BlueStateReader::new("inv-test".to_string())
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
            focus_areas: vec!["lateral_movement".to_string()],
            reinvestigation_cycle: 0,
            created_at: None,
        }
    }

    #[tokio::test]
    async fn exists_false_when_empty() {
        let mut conn = MockRedisConnection::new();
        let r = make_reader();

        assert!(!r.exists(&mut conn).await.unwrap());
    }

    #[tokio::test]
    async fn exists_true_after_initialize() {
        let mut conn = MockRedisConnection::new();
        let w = make_writer();
        let r = make_reader();
        let alert = serde_json::json!({"alert_id": "a-001"});

        w.initialize(&mut conn, &alert).await.unwrap();
        assert!(r.exists(&mut conn).await.unwrap());
    }

    #[tokio::test]
    async fn get_evidence_empty_then_populated() {
        let mut conn = MockRedisConnection::new();
        let w = make_writer();
        let r = make_reader();

        let empty = r.get_evidence(&mut conn).await.unwrap();
        assert!(empty.is_empty());

        let ev1 = make_evidence("ip", "192.168.58.1", "nmap");
        let ev2 = make_evidence("domain", "evil.com", "dns");
        w.add_evidence(&mut conn, &ev1).await.unwrap();
        w.add_evidence(&mut conn, &ev2).await.unwrap();

        let evidence = r.get_evidence(&mut conn).await.unwrap();
        assert_eq!(evidence.len(), 2);
        let values: Vec<&str> = evidence.iter().map(|e| e.value.as_str()).collect();
        assert!(values.contains(&"192.168.58.1"));
        assert!(values.contains(&"evil.com"));
    }

    #[tokio::test]
    async fn get_timeline_preserves_order() {
        let mut conn = MockRedisConnection::new();
        let w = make_writer();
        let r = make_reader();

        w.add_timeline_event(&mut conn, &make_timeline_event("first"))
            .await
            .unwrap();
        w.add_timeline_event(&mut conn, &make_timeline_event("second"))
            .await
            .unwrap();

        let timeline = r.get_timeline(&mut conn).await.unwrap();
        assert_eq!(timeline.len(), 2);
        assert_eq!(timeline[0].description, "first");
        assert_eq!(timeline[1].description, "second");
    }

    #[tokio::test]
    async fn get_techniques_after_add() {
        let mut conn = MockRedisConnection::new();
        let w = make_writer();
        let r = make_reader();

        let empty = r.get_techniques(&mut conn).await.unwrap();
        assert!(empty.is_empty());

        w.add_technique(&mut conn, "T1059").await.unwrap();
        w.add_technique(&mut conn, "T1046").await.unwrap();

        let techs = r.get_techniques(&mut conn).await.unwrap();
        assert_eq!(techs.len(), 2);
        assert!(techs.contains(&"T1059".to_string()));
        assert!(techs.contains(&"T1046".to_string()));
    }

    #[tokio::test]
    async fn get_tactics_after_add() {
        let mut conn = MockRedisConnection::new();
        let w = make_writer();
        let r = make_reader();

        w.add_tactic(&mut conn, "TA0001").await.unwrap();
        w.add_tactic(&mut conn, "TA0002").await.unwrap();

        let tactics = r.get_tactics(&mut conn).await.unwrap();
        assert_eq!(tactics.len(), 2);
        assert!(tactics.contains(&"TA0001".to_string()));
    }

    #[tokio::test]
    async fn get_technique_names_after_set() {
        let mut conn = MockRedisConnection::new();
        let w = make_writer();
        let r = make_reader();

        let empty = r.get_technique_names(&mut conn).await.unwrap();
        assert!(empty.is_empty());

        w.set_technique_name(&mut conn, "T1059", "Command and Scripting Interpreter")
            .await
            .unwrap();
        w.set_technique_name(&mut conn, "T1046", "Network Service Discovery")
            .await
            .unwrap();

        let names = r.get_technique_names(&mut conn).await.unwrap();
        assert_eq!(names.len(), 2);
        assert_eq!(
            names.get("T1059").map(String::as_str),
            Some("Command and Scripting Interpreter")
        );
        assert_eq!(
            names.get("T1046").map(String::as_str),
            Some("Network Service Discovery")
        );
    }

    #[tokio::test]
    async fn get_hosts_lowercased() {
        let mut conn = MockRedisConnection::new();
        let w = make_writer();
        let r = make_reader();

        w.track_host(&mut conn, "DC01.CONTOSO.LOCAL").await.unwrap();

        let hosts = r.get_hosts(&mut conn).await.unwrap();
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0], "dc01.contoso.local");
    }

    #[tokio::test]
    async fn get_users_lowercased() {
        let mut conn = MockRedisConnection::new();
        let w = make_writer();
        let r = make_reader();

        w.track_user(&mut conn, "AdminUser").await.unwrap();

        let users = r.get_users(&mut conn).await.unwrap();
        assert_eq!(users.len(), 1);
        assert_eq!(users[0], "adminuser");
    }

    #[tokio::test]
    async fn get_query_types_after_mark() {
        let mut conn = MockRedisConnection::new();
        let w = make_writer();
        let r = make_reader();

        w.mark_query_type(&mut conn, "process_events")
            .await
            .unwrap();
        w.mark_query_type(&mut conn, "network_events")
            .await
            .unwrap();

        let types = r.get_query_types(&mut conn).await.unwrap();
        assert_eq!(types.len(), 2);
        assert!(types.contains(&"process_events".to_string()));
        assert!(types.contains(&"network_events".to_string()));
    }

    #[tokio::test]
    async fn get_queries_after_record() {
        let mut conn = MockRedisConnection::new();
        let w = make_writer();
        let r = make_reader();

        let empty = r.get_queries(&mut conn).await.unwrap();
        assert!(empty.is_empty());

        let q = serde_json::json!({"query": "SELECT * FROM logs", "type": "splunk"});
        w.record_query(&mut conn, &q).await.unwrap();

        let queries = r.get_queries(&mut conn).await.unwrap();
        assert_eq!(queries.len(), 1);
        assert_eq!(queries[0]["type"], "splunk");
    }

    #[tokio::test]
    async fn get_recommendations_preserves_order() {
        let mut conn = MockRedisConnection::new();
        let w = make_writer();
        let r = make_reader();

        w.add_recommendation(&mut conn, "Block IP").await.unwrap();
        w.add_recommendation(&mut conn, "Rotate creds")
            .await
            .unwrap();

        let recs = r.get_recommendations(&mut conn).await.unwrap();
        assert_eq!(recs, vec!["Block IP", "Rotate creds"]);
    }

    #[tokio::test]
    async fn get_triage_decision_none_then_some() {
        let mut conn = MockRedisConnection::new();
        let w = make_writer();
        let r = make_reader();

        let none = r.get_triage_decision(&mut conn).await.unwrap();
        assert!(none.is_none());

        let record = make_triage_record("confirmed");
        w.set_triage_decision(&mut conn, &record).await.unwrap();

        let decision = r.get_triage_decision(&mut conn).await.unwrap();
        assert!(decision.is_some());
        assert_eq!(decision.unwrap()["decision"], "confirmed");
    }

    #[tokio::test]
    async fn get_triage_records_after_add() {
        let mut conn = MockRedisConnection::new();
        let w = make_writer();
        let r = make_reader();

        let rec = make_triage_record("confirmed");
        w.add_triage_record(&mut conn, &rec).await.unwrap();

        let records = r.get_triage_records(&mut conn).await.unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].decision, "confirmed");
        assert_eq!(records[0].confidence, 0.9);
    }

    #[tokio::test]
    async fn get_pending_and_completed_tasks() {
        let mut conn = MockRedisConnection::new();
        let w = make_writer();
        let r = make_reader();

        let task = make_task("task-1", "query_logs");
        w.add_pending_task(&mut conn, &task).await.unwrap();

        let pending = r.get_pending_tasks(&mut conn).await.unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending["task-1"].task_type, "query_logs");

        let completed = r.get_completed_tasks(&mut conn).await.unwrap();
        assert!(completed.is_empty());

        let mut done = task.clone();
        done.status = "completed".to_string();
        w.complete_task(&mut conn, &done).await.unwrap();

        let pending_after = r.get_pending_tasks(&mut conn).await.unwrap();
        assert!(pending_after.is_empty());

        let completed_after = r.get_completed_tasks(&mut conn).await.unwrap();
        assert_eq!(completed_after.len(), 1);
        assert_eq!(completed_after["task-1"].status, "completed");
    }

    #[tokio::test]
    async fn get_meta_after_initialize() {
        let mut conn = MockRedisConnection::new();
        let w = make_writer();
        let r = make_reader();
        let alert = serde_json::json!({"alert_id": "a-001", "severity": "high"});

        w.initialize(&mut conn, &alert).await.unwrap();

        let meta = r.get_meta(&mut conn).await.unwrap();
        assert!(meta.contains_key("alert"));
        assert_eq!(meta["alert"]["alert_id"], "a-001");
        assert_eq!(meta["stage"].as_str(), Some("triage"));
        assert!(meta.contains_key("started_at"));
    }

    #[tokio::test]
    async fn is_running_reflects_lock_state() {
        let mut conn = MockRedisConnection::new();
        let w = make_writer();
        let r = make_reader();

        assert!(!r.is_running(&mut conn).await.unwrap());

        w.acquire_lock(&mut conn, 300).await.unwrap();
        assert!(r.is_running(&mut conn).await.unwrap());

        w.release_lock(&mut conn).await.unwrap();
        assert!(!r.is_running(&mut conn).await.unwrap());
    }

    #[tokio::test]
    async fn load_state_none_when_empty() {
        let mut conn = MockRedisConnection::new();
        let r = make_reader();

        let state = r.load_state(&mut conn).await.unwrap();
        assert!(state.is_none());
    }

    #[tokio::test]
    async fn load_state_full_round_trip() {
        let mut conn = MockRedisConnection::new();
        let w = make_writer();
        let r = make_reader();

        let alert = serde_json::json!({"alert_id": "a-001", "severity": "critical"});
        w.initialize(&mut conn, &alert).await.unwrap();

        w.add_evidence(&mut conn, &make_evidence("ip", "192.168.58.1", "nmap"))
            .await
            .unwrap();
        w.add_timeline_event(&mut conn, &make_timeline_event("initial scan"))
            .await
            .unwrap();
        w.add_technique(&mut conn, "T1059").await.unwrap();
        w.add_tactic(&mut conn, "TA0002").await.unwrap();
        w.set_technique_name(&mut conn, "T1059", "Command and Scripting Interpreter")
            .await
            .unwrap();
        w.track_host(&mut conn, "DC01").await.unwrap();
        w.track_user(&mut conn, "admin").await.unwrap();
        w.mark_query_type(&mut conn, "process_events")
            .await
            .unwrap();
        w.add_recommendation(&mut conn, "Block IP 192.168.58.1")
            .await
            .unwrap();

        let triage = make_triage_record("confirmed");
        w.set_triage_decision(&mut conn, &triage).await.unwrap();
        w.add_triage_record(&mut conn, &triage).await.unwrap();

        let task = make_task("task-1", "query_logs");
        w.add_pending_task(&mut conn, &task).await.unwrap();

        w.set_meta(&mut conn, "escalated", &serde_json::Value::Bool(true))
            .await
            .unwrap();
        w.set_meta(
            &mut conn,
            "escalation_reason",
            &serde_json::Value::String("confirmed threat".to_string()),
        )
        .await
        .unwrap();

        let state = r.load_state(&mut conn).await.unwrap().unwrap();

        assert_eq!(state.investigation_id, "inv-test");
        assert_eq!(state.alert["alert_id"], "a-001");
        assert_eq!(state.stage, "triage");
        assert!(!state.started_at.is_empty());
        assert_eq!(state.evidence.len(), 1);
        assert_eq!(state.evidence[0].value, "192.168.58.1");
        assert_eq!(state.timeline.len(), 1);
        assert_eq!(state.timeline[0].description, "initial scan");
        assert!(state.identified_techniques.contains(&"T1059".to_string()));
        assert!(state.identified_tactics.contains(&"TA0002".to_string()));
        assert_eq!(
            state.technique_names.get("T1059").map(String::as_str),
            Some("Command and Scripting Interpreter")
        );
        assert!(state.queried_hosts.contains(&"dc01".to_string()));
        assert!(state.queried_users.contains(&"admin".to_string()));
        assert!(state
            .executed_query_types
            .contains(&"process_events".to_string()));
        assert_eq!(state.recommendations, vec!["Block IP 192.168.58.1"]);
        assert!(state.triage_decision.is_some());
        assert_eq!(state.triage_records.len(), 1);
        assert_eq!(state.pending_tasks.len(), 1);
        assert!(state.completed_tasks.is_empty());
        assert!(state.escalated);
        assert_eq!(state.escalation_reason.as_deref(), Some("confirmed threat"));
    }
}
