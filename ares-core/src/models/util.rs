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
    fn test_new_uuid_format() {
        let uuid = new_uuid();
        assert_eq!(uuid.len(), 36); // standard UUID format: 8-4-4-4-12
        assert_eq!(uuid.chars().filter(|c| *c == '-').count(), 4);
    }

    #[test]
    fn test_new_uuid_unique() {
        let u1 = new_uuid();
        let u2 = new_uuid();
        assert_ne!(u1, u2);
    }

    #[test]
    fn test_default_hash_type() {
        assert_eq!(default_hash_type(), "NTLM");
    }

    #[test]
    fn test_default_task_status() {
        let status = default_task_status();
        assert_eq!(status.to_string(), "pending");
    }

    #[test]
    fn test_default_max_retries() {
        assert_eq!(default_max_retries(), 3);
    }

    #[test]
    fn test_default_priority() {
        assert_eq!(default_priority(), 5);
    }

    #[test]
    fn test_default_agent_status() {
        assert_eq!(default_agent_status(), "idle");
    }

    #[cfg(feature = "blue")]
    #[test]
    fn test_default_confidence() {
        assert!((default_confidence() - 0.5).abs() < f64::EPSILON);
    }

    #[cfg(feature = "blue")]
    #[test]
    fn test_default_timeline_source() {
        assert_eq!(default_timeline_source(), "investigation");
    }

    #[cfg(feature = "blue")]
    #[test]
    fn test_default_blue_task_status() {
        assert_eq!(default_blue_task_status(), "pending");
    }
}
