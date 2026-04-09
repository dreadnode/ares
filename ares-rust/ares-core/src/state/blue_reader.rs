//! Blue team Redis state reader.

use std::collections::HashMap;

use redis::AsyncCommands;

use crate::models::{BlueTaskInfo, Evidence, SharedBlueTeamState, TimelineEvent, TriageRecord};

use super::keys::*;
use super::try_deserialize;

/// Read-only Redis state backend for blue team investigations.
///
/// This provides methods to read investigation state from Redis, matching
/// the Python `BlueStateBackend` key patterns exactly.
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
    /// Meta fields are stored as JSON-encoded values (via Python's `json.dumps()`).
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
