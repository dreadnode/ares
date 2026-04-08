//! Redis key constants for operation and investigation state.

/// Redis key prefix for all operation state.
pub const KEY_PREFIX: &str = "ares:op";

/// Redis key prefix for operation locks.
pub const LOCK_PREFIX: &str = "ares:lock";

/// Redis key prefix for task status records.
pub const TASK_STATUS_PREFIX: &str = "ares:task_status";

// Collection key suffixes (appended to `ares:op:{op_id}:`)
pub const KEY_CREDENTIALS: &str = "credentials";
pub const KEY_HASHES: &str = "hashes";
pub const KEY_HOSTS: &str = "hosts";
pub const KEY_USERS: &str = "users";
pub const KEY_SHARES: &str = "shares";
pub const KEY_WEAKNESSES: &str = "weaknesses";
pub const KEY_DOMAINS: &str = "domains";
pub const KEY_VULNS: &str = "vulns";
pub const KEY_EXPLOITED: &str = "exploited";
pub const KEY_META: &str = "meta";
pub const KEY_DC_MAP: &str = "dc_map";
pub const KEY_NETBIOS_MAP: &str = "netbios_map";
pub const KEY_ARTIFACTS: &str = "artifacts";
pub const KEY_TIMELINE: &str = "timeline";
pub const KEY_GOLDEN_TICKETS: &str = "golden_tickets";
pub const KEY_ADMINSD_BACKDOORS: &str = "adminsd_backdoors";
pub const KEY_ACL_CHAINS: &str = "acl_chains";
pub const KEY_GMSA_ACCOUNTS: &str = "gmsa_accounts";
pub const KEY_DEDUP_PREFIX: &str = "dedup";
pub const KEY_TECHNIQUES: &str = "techniques";
pub const KEY_MSSQL_ENUM_DISPATCHED: &str = "mssql_enum_dispatched";
pub const KEY_PENDING_TASKS: &str = "pending_tasks";
pub const KEY_COMPLETED_TASKS: &str = "completed_tasks";
pub const KEY_VULN_TYPE_FAILURES: &str = "vuln_type_failures";
pub const KEY_DOMAIN_SIDS: &str = "domain_sids";

/// Pub/Sub channel prefix for state update notifications.
pub const STATE_UPDATE_CHANNEL_PREFIX: &str = "ares:state:updates";

/// Redis key prefix for all blue team investigation state.
pub const BLUE_KEY_PREFIX: &str = "ares:blue:inv";

/// Redis lock key prefix for blue team investigations.
pub const BLUE_LOCK_PREFIX: &str = "ares:blue:lock";

// Blue team collection key suffixes (appended to `ares:blue:inv:{inv_id}:`)
pub const BLUE_KEY_EVIDENCE: &str = "evidence";
pub const BLUE_KEY_TIMELINE: &str = "timeline";
pub const BLUE_KEY_TECHNIQUES: &str = "techniques";
pub const BLUE_KEY_TACTICS: &str = "tactics";
pub const BLUE_KEY_HOSTS: &str = "hosts";
pub const BLUE_KEY_USERS: &str = "users";
pub const BLUE_KEY_QUERY_TYPES: &str = "query_types";
pub const BLUE_KEY_META: &str = "meta";
pub const BLUE_KEY_PENDING_TASKS: &str = "tasks:pending";
pub const BLUE_KEY_COMPLETED_TASKS: &str = "tasks:completed";
pub const BLUE_KEY_TECHNIQUE_NAMES: &str = "technique_names";
pub const BLUE_KEY_RECOMMENDATIONS: &str = "recommendations";
pub const BLUE_KEY_TRIAGE_DECISION: &str = "triage:decision";
pub const BLUE_KEY_TRIAGE_RECORDS: &str = "triage:records";
