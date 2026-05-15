//! Task-related models: AgentRole, TaskStatus, TaskInfo, TaskResult, etc.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

use super::util::{
    default_agent_status, default_max_retries, default_priority, default_task_status,
};

/// Specialized roles for multi-agent red team operations.
///
/// Matches Python: `class AgentRole(Enum)`
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum AgentRole {
    Orchestrator,
    Recon,
    CredentialAccess,
    Cracker,
    Acl,
    Privesc,
    Lateral,
    Coercion,
}

impl std::fmt::Display for AgentRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AgentRole::Orchestrator => write!(f, "orchestrator"),
            AgentRole::Recon => write!(f, "recon"),
            AgentRole::CredentialAccess => write!(f, "credential_access"),
            AgentRole::Cracker => write!(f, "cracker"),
            AgentRole::Acl => write!(f, "acl"),
            AgentRole::Privesc => write!(f, "privesc"),
            AgentRole::Lateral => write!(f, "lateral"),
            AgentRole::Coercion => write!(f, "coercion"),
        }
    }
}

/// Status of a dispatched task.
///
/// Matches Python: `class TaskStatus(Enum)`
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TaskStatus {
    Pending,
    InProgress,
    Completed,
    Failed,
    Cancelled,
    Retrying,
}

impl std::fmt::Display for TaskStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TaskStatus::Pending => write!(f, "pending"),
            TaskStatus::InProgress => write!(f, "in_progress"),
            TaskStatus::Completed => write!(f, "completed"),
            TaskStatus::Failed => write!(f, "failed"),
            TaskStatus::Cancelled => write!(f, "cancelled"),
            TaskStatus::Retrying => write!(f, "retrying"),
        }
    }
}

/// Information about a dispatched task.
///
/// Matches Python: `class TaskInfo` dataclass
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskInfo {
    pub task_id: String,
    pub task_type: String,
    pub assigned_agent: String,
    #[serde(default = "default_task_status")]
    pub status: TaskStatus,
    #[serde(default = "chrono::Utc::now")]
    pub created_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub started_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub completed_at: Option<DateTime<Utc>>,
    #[serde(default = "chrono::Utc::now")]
    pub last_activity_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub params: HashMap<String, serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default)]
    pub retry_count: i32,
    #[serde(default = "default_max_retries")]
    pub max_retries: i32,
}

/// Result of a completed task.
///
/// Matches Python's completed-task payload shape with optional worker-side
/// provenance used by Rust orchestrator automations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskResult {
    pub task_id: String,
    pub success: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub worker_pod: Option<String>,
    #[serde(default = "chrono::Utc::now")]
    pub completed_at: DateTime<Utc>,
}

/// Information about a discovered vulnerability.
///
/// Matches Python: `class VulnerabilityInfo` dataclass
/// Redis serialization: `{"vuln_id","vuln_type","target","discovered_by","discovered_at","details","recommended_agent","priority"}`
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct VulnerabilityInfo {
    pub vuln_id: String,
    pub vuln_type: String,
    pub target: String,
    #[serde(default)]
    pub discovered_by: String,
    #[serde(default = "chrono::Utc::now")]
    pub discovered_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub details: HashMap<String, serde_json::Value>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub recommended_agent: String,
    #[serde(default = "default_priority")]
    pub priority: i32,
}

/// Metadata about a registered agent.
///
/// Matches Python: `class AgentInfo` dataclass
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentInfo {
    pub name: String,
    pub pod_name: String,
    pub role: AgentRole,
    #[serde(default, skip_serializing_if = "HashSet::is_empty")]
    pub capabilities: HashSet<String>,
    #[serde(default = "default_agent_status")]
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current_task: Option<String>,
    #[serde(default = "chrono::Utc::now")]
    pub registered_at: DateTime<Utc>,
    #[serde(default = "chrono::Utc::now")]
    pub last_heartbeat: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn agent_role_display() {
        assert_eq!(AgentRole::Orchestrator.to_string(), "orchestrator");
        assert_eq!(AgentRole::Recon.to_string(), "recon");
        assert_eq!(AgentRole::CredentialAccess.to_string(), "credential_access");
        assert_eq!(AgentRole::Cracker.to_string(), "cracker");
        assert_eq!(AgentRole::Acl.to_string(), "acl");
        assert_eq!(AgentRole::Privesc.to_string(), "privesc");
        assert_eq!(AgentRole::Lateral.to_string(), "lateral");
        assert_eq!(AgentRole::Coercion.to_string(), "coercion");
    }

    #[test]
    fn agent_role_serde_roundtrip() {
        let role = AgentRole::CredentialAccess;
        let json = serde_json::to_string(&role).unwrap();
        assert_eq!(json, r#""credential_access""#);
        let back: AgentRole = serde_json::from_str(&json).unwrap();
        assert_eq!(back, AgentRole::CredentialAccess);
    }

    #[test]
    fn agent_role_deserialize_all() {
        for (s, expected) in [
            (r#""orchestrator""#, AgentRole::Orchestrator),
            (r#""recon""#, AgentRole::Recon),
            (r#""credential_access""#, AgentRole::CredentialAccess),
            (r#""cracker""#, AgentRole::Cracker),
            (r#""acl""#, AgentRole::Acl),
            (r#""privesc""#, AgentRole::Privesc),
            (r#""lateral""#, AgentRole::Lateral),
            (r#""coercion""#, AgentRole::Coercion),
        ] {
            let role: AgentRole = serde_json::from_str(s).unwrap();
            assert_eq!(role, expected);
        }
    }

    #[test]
    fn task_status_display_all() {
        assert_eq!(TaskStatus::Pending.to_string(), "pending");
        assert_eq!(TaskStatus::InProgress.to_string(), "in_progress");
        assert_eq!(TaskStatus::Completed.to_string(), "completed");
        assert_eq!(TaskStatus::Failed.to_string(), "failed");
        assert_eq!(TaskStatus::Cancelled.to_string(), "cancelled");
        assert_eq!(TaskStatus::Retrying.to_string(), "retrying");
    }

    #[test]
    fn task_status_serde_roundtrip() {
        let status = TaskStatus::InProgress;
        let json = serde_json::to_string(&status).unwrap();
        assert_eq!(json, r#""in_progress""#);
        let back: TaskStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(back, TaskStatus::InProgress);
    }

    #[test]
    fn task_info_deserialize_minimal() {
        let json = json!({
            "task_id": "t-001",
            "task_type": "recon",
            "assigned_agent": "recon-1"
        });
        let info: TaskInfo = serde_json::from_value(json).unwrap();
        assert_eq!(info.task_id, "t-001");
        assert_eq!(info.task_type, "recon");
        assert_eq!(info.assigned_agent, "recon-1");
        assert_eq!(info.status, TaskStatus::Pending); // default
        assert_eq!(info.retry_count, 0);
        assert_eq!(info.max_retries, 3); // default
        assert!(info.result.is_none());
        assert!(info.error.is_none());
    }

    #[test]
    fn task_info_with_status() {
        let json = json!({
            "task_id": "t-002",
            "task_type": "crack",
            "assigned_agent": "cracker-1",
            "status": "completed",
            "retry_count": 1,
            "max_retries": 5,
            "result": {"cracked": true}
        });
        let info: TaskInfo = serde_json::from_value(json).unwrap();
        assert_eq!(info.status, TaskStatus::Completed);
        assert_eq!(info.retry_count, 1);
        assert_eq!(info.max_retries, 5);
        assert!(info.result.is_some());
    }

    #[test]
    fn task_info_serialization_skips_none() {
        let json = json!({
            "task_id": "t-003",
            "task_type": "lateral",
            "assigned_agent": "lateral-1"
        });
        let info: TaskInfo = serde_json::from_value(json).unwrap();
        let serialized = serde_json::to_value(&info).unwrap();
        // Optional None fields should be skipped
        assert!(serialized.get("started_at").is_none());
        assert!(serialized.get("completed_at").is_none());
        assert!(serialized.get("result").is_none());
        assert!(serialized.get("error").is_none());
    }

    #[test]
    fn task_result_deserialize() {
        let json = json!({
            "task_id": "t-010",
            "success": true,
            "result": {"output": "found 3 hosts"},
            "completed_at": "2025-01-28T12:00:00Z"
        });
        let result: TaskResult = serde_json::from_value(json).unwrap();
        assert!(result.success);
        assert!(result.result.is_some());
        assert!(result.error.is_none());
    }

    #[test]
    fn task_result_failure() {
        let json = json!({
            "task_id": "t-011",
            "success": false,
            "error": "connection refused"
        });
        let result: TaskResult = serde_json::from_value(json).unwrap();
        assert!(!result.success);
        assert_eq!(result.error.as_deref(), Some("connection refused"));
        assert!(result.result.is_none());
    }

    #[test]
    fn vulnerability_info_defaults() {
        let json = json!({
            "vuln_id": "esc1_192.168.58.10",
            "vuln_type": "ADCS_ESC1",
            "target": "192.168.58.10",
            "discovered_by": "recon-1"
        });
        let vuln: VulnerabilityInfo = serde_json::from_value(json).unwrap();
        assert_eq!(vuln.vuln_id, "esc1_192.168.58.10");
        assert_eq!(vuln.priority, 5); // default
        assert!(vuln.details.is_empty());
        assert!(vuln.recommended_agent.is_empty());
    }

    #[test]
    fn vulnerability_info_with_details() {
        let json = json!({
            "vuln_id": "deleg_svc_sql",
            "vuln_type": "constrained_delegation",
            "target": "192.168.58.20",
            "discovered_by": "recon-1",
            "details": {"account_name": "svc_sql", "target_spn": "MSSQL/dc01.contoso.local"},
            "recommended_agent": "privesc",
            "priority": 1
        });
        let vuln: VulnerabilityInfo = serde_json::from_value(json).unwrap();
        assert_eq!(vuln.priority, 1);
        assert_eq!(vuln.recommended_agent, "privesc");
        assert_eq!(vuln.details.len(), 2);
    }

    #[test]
    fn agent_info_deserialize() {
        let json = json!({
            "name": "recon-1",
            "pod_name": "ares-recon-abc123",
            "role": "recon"
        });
        let info: AgentInfo = serde_json::from_value(json).unwrap();
        assert_eq!(info.name, "recon-1");
        assert_eq!(info.role, AgentRole::Recon);
        assert_eq!(info.status, "idle"); // default
        assert!(info.capabilities.is_empty());
        assert!(info.current_task.is_none());
    }

    #[test]
    fn agent_info_with_capabilities() {
        let json = json!({
            "name": "privesc-1",
            "pod_name": "ares-privesc-def456",
            "role": "privesc",
            "capabilities": ["adcs", "kerberos", "delegation"],
            "status": "busy",
            "current_task": "t-100"
        });
        let info: AgentInfo = serde_json::from_value(json).unwrap();
        assert_eq!(info.role, AgentRole::Privesc);
        assert_eq!(info.capabilities.len(), 3);
        assert!(info.capabilities.contains("kerberos"));
        assert_eq!(info.status, "busy");
        assert_eq!(info.current_task.as_deref(), Some("t-100"));
    }
}

/// Task status record stored in Redis `ares:task_status:*` keys.
///
/// This is the JSON format used by the task queue, distinct from TaskInfo.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskStatusRecord {
    pub operation_id: String,
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub started_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ended_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pod_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub task_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<serde_json::Value>,
}

#[cfg(test)]
mod task_status_record_tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn task_status_record_minimal() {
        let json = json!({
            "operation_id": "op-001",
            "status": "running"
        });
        let rec: TaskStatusRecord = serde_json::from_value(json).unwrap();
        assert_eq!(rec.operation_id, "op-001");
        assert_eq!(rec.status, "running");
        assert!(rec.started_at.is_none());
        assert!(rec.ended_at.is_none());
        assert!(rec.pod_name.is_none());
        assert!(rec.role.is_none());
        assert!(rec.task_type.is_none());
        assert!(rec.error.is_none());
        assert!(rec.payload.is_none());
    }

    #[test]
    fn task_status_record_full() {
        let json = json!({
            "operation_id": "op-002",
            "status": "completed",
            "started_at": "2025-01-01T00:00:00Z",
            "ended_at": "2025-01-01T01:00:00Z",
            "pod_name": "ares-recon-xyz",
            "role": "recon",
            "task_type": "network_scan",
            "error": null,
            "payload": {"targets": ["192.168.58.0/24"]}
        });
        let rec: TaskStatusRecord = serde_json::from_value(json).unwrap();
        assert_eq!(rec.operation_id, "op-002");
        assert_eq!(rec.status, "completed");
        assert_eq!(rec.started_at.as_deref(), Some("2025-01-01T00:00:00Z"));
        assert_eq!(rec.ended_at.as_deref(), Some("2025-01-01T01:00:00Z"));
        assert_eq!(rec.pod_name.as_deref(), Some("ares-recon-xyz"));
        assert_eq!(rec.role.as_deref(), Some("recon"));
        assert_eq!(rec.task_type.as_deref(), Some("network_scan"));
        assert!(rec.error.is_none());
        assert!(rec.payload.is_some());
    }

    #[test]
    fn task_status_record_with_error() {
        let json = json!({
            "operation_id": "op-003",
            "status": "failed",
            "error": "connection timeout"
        });
        let rec: TaskStatusRecord = serde_json::from_value(json).unwrap();
        assert_eq!(rec.status, "failed");
        assert_eq!(rec.error.as_deref(), Some("connection timeout"));
    }

    #[test]
    fn task_status_record_roundtrip() {
        let rec = TaskStatusRecord {
            operation_id: "op-rt".to_string(),
            status: "pending".to_string(),
            started_at: Some("2025-06-01T12:00:00Z".to_string()),
            ended_at: None,
            pod_name: Some("pod-1".to_string()),
            role: Some("lateral".to_string()),
            task_type: Some("smb_relay".to_string()),
            error: None,
            payload: Some(json!({"key": "value"})),
        };
        let serialized = serde_json::to_value(&rec).unwrap();
        let deserialized: TaskStatusRecord = serde_json::from_value(serialized).unwrap();
        assert_eq!(deserialized.operation_id, "op-rt");
        assert_eq!(deserialized.status, "pending");
        assert!(deserialized.ended_at.is_none());
        assert!(deserialized.error.is_none());
        let json_str = serde_json::to_string(&rec).unwrap();
        assert!(!json_str.contains("ended_at"));
        assert!(!json_str.contains("\"error\""));
    }
}
