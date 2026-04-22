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

#[cfg(feature = "blue")]
pub(crate) fn default_confidence() -> f64 {
    0.5
}

#[cfg(feature = "blue")]
pub(crate) fn default_timeline_source() -> String {
    "investigation".to_string()
}

#[cfg(feature = "blue")]
pub(crate) fn default_blue_task_status() -> String {
    "pending".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_uuid_format() {
        let uuid = new_uuid();
        assert_eq!(uuid.len(), 36);
        assert_eq!(uuid.chars().filter(|c| *c == '-').count(), 4);
    }

    #[test]
    fn new_uuid_unique() {
        let u1 = new_uuid();
        let u2 = new_uuid();
        assert_ne!(u1, u2);
    }

    #[test]
    fn new_uuid_is_valid_v4() {
        let id = new_uuid();
        let parsed = uuid::Uuid::parse_str(&id).unwrap();
        assert_eq!(parsed.get_version_num(), 4);
    }

    #[test]
    fn defaults() {
        assert_eq!(default_hash_type(), "NTLM");
        assert_eq!(default_task_status().to_string(), "pending");
        assert_eq!(default_max_retries(), 3);
        assert_eq!(default_priority(), 5);
        assert_eq!(default_agent_status(), "idle");
    }

    #[cfg(feature = "blue")]
    #[test]
    fn blue_defaults() {
        assert!((default_confidence() - 0.5).abs() < f64::EPSILON);
        assert_eq!(default_timeline_source(), "investigation");
        assert_eq!(default_blue_task_status(), "pending");
    }
}
