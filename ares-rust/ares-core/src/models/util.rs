//! Utility helpers for the models module.

pub(crate) fn new_uuid() -> String {
    uuid::Uuid::new_v4().to_string()
}

pub(crate) fn default_hash_type() -> String {
    "NTLM".to_string()
}

pub(crate) fn default_task_status() -> super::TaskStatus {
    super::TaskStatus::Pending
}

pub(crate) fn default_max_retries() -> i32 {
    3
}

pub(crate) fn default_priority() -> i32 {
    5
}

pub(crate) fn default_agent_status() -> String {
    "idle".to_string()
}

pub(crate) fn default_confidence() -> f64 {
    0.5
}

pub(crate) fn default_timeline_source() -> String {
    "investigation".to_string()
}

pub(crate) fn default_blue_task_status() -> String {
    "pending".to_string()
}
