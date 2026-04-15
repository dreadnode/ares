//! Default value functions for serde deserialization.

pub fn default_checkpoint_interval() -> u64 {
    60
}
pub fn default_max_concurrent() -> u32 {
    8
}
pub fn default_max_steps() -> u32 {
    100
}
pub fn default_true() -> bool {
    true
}
pub fn default_max_retries() -> u32 {
    3
}
pub fn default_retry_delay() -> u64 {
    10
}
pub fn default_lateral_admin_creds() -> u32 {
    3
}
pub fn default_lateral_owned_hosts() -> u32 {
    5
}
pub fn default_min_slots() -> u32 {
    1
}
pub fn default_max_context_tokens() -> u64 {
    50000
}
pub fn default_min_messages() -> u32 {
    15
}
pub fn default_max_output_chars() -> u32 {
    3000
}
pub fn default_log_level() -> String {
    "INFO".to_string()
}
pub fn default_log_format() -> String {
    "%(asctime)s | %(levelname)s | %(name)s | %(message)s".to_string()
}
pub fn default_log_file() -> String {
    "/var/log/ares/operation.log".to_string()
}
pub fn default_max_size_mb() -> u32 {
    100
}
pub fn default_backup_count() -> u32 {
    5
}
pub fn default_max_concurrent_resources() -> u32 {
    10
}
pub fn default_max_creds_per_expansion() -> u32 {
    100
}
pub fn default_max_hosts_per_scan() -> u32 {
    50
}
pub fn default_cred_cache_ttl() -> u64 {
    3600
}
pub fn default_max_rpm() -> u32 {
    60
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_checkpoint_interval() {
        assert_eq!(default_checkpoint_interval(), 60);
    }

    #[test]
    fn test_default_max_concurrent() {
        assert_eq!(default_max_concurrent(), 8);
    }

    #[test]
    fn test_default_max_steps() {
        assert_eq!(default_max_steps(), 100);
    }

    #[test]
    fn test_default_true() {
        assert!(default_true());
    }

    #[test]
    fn test_default_max_retries() {
        assert_eq!(default_max_retries(), 3);
    }

    #[test]
    fn test_default_retry_delay() {
        assert_eq!(default_retry_delay(), 10);
    }

    #[test]
    fn test_default_lateral_admin_creds() {
        assert_eq!(default_lateral_admin_creds(), 3);
    }

    #[test]
    fn test_default_lateral_owned_hosts() {
        assert_eq!(default_lateral_owned_hosts(), 5);
    }

    #[test]
    fn test_default_min_slots() {
        assert_eq!(default_min_slots(), 1);
    }

    #[test]
    fn test_default_max_context_tokens() {
        assert_eq!(default_max_context_tokens(), 50000);
    }

    #[test]
    fn test_default_min_messages() {
        assert_eq!(default_min_messages(), 15);
    }

    #[test]
    fn test_default_max_output_chars() {
        assert_eq!(default_max_output_chars(), 3000);
    }

    #[test]
    fn test_default_log_level() {
        assert_eq!(default_log_level(), "INFO");
    }

    #[test]
    fn test_default_log_format() {
        let fmt = default_log_format();
        assert!(fmt.contains("asctime"));
        assert!(fmt.contains("levelname"));
    }

    #[test]
    fn test_default_log_file() {
        assert_eq!(default_log_file(), "/var/log/ares/operation.log");
    }

    #[test]
    fn test_default_max_size_mb() {
        assert_eq!(default_max_size_mb(), 100);
    }

    #[test]
    fn test_default_backup_count() {
        assert_eq!(default_backup_count(), 5);
    }

    #[test]
    fn test_default_max_concurrent_resources() {
        assert_eq!(default_max_concurrent_resources(), 10);
    }

    #[test]
    fn test_default_max_creds_per_expansion() {
        assert_eq!(default_max_creds_per_expansion(), 100);
    }

    #[test]
    fn test_default_max_hosts_per_scan() {
        assert_eq!(default_max_hosts_per_scan(), 50);
    }

    #[test]
    fn test_default_cred_cache_ttl() {
        assert_eq!(default_cred_cache_ttl(), 3600);
    }

    #[test]
    fn test_default_max_rpm() {
        assert_eq!(default_max_rpm(), 60);
    }
}
