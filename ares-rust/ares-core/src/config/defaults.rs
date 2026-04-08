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
