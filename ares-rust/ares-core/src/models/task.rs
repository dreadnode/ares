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
/// Matches Python: `class TaskResult` dataclass
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskResult {
    pub task_id: String,
    pub success: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default = "chrono::Utc::now")]
    pub completed_at: DateTime<Utc>,
}

/// Information about a discovered vulnerability.
///
/// Matches Python: `class VulnerabilityInfo` dataclass
/// Redis serialization: `{"vuln_id","vuln_type","target","discovered_by","discovered_at","details","recommended_agent","priority"}`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnerabilityInfo {
    pub vuln_id: String,
    pub vuln_type: String,
    pub target: String,
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
