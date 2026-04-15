//! Redis key constants for operation and investigation state.

/// Redis key prefix for all operation state.
pub const KEY_PREFIX: &str = "ares:op";

/// Redis key prefix for operation locks.
pub const LOCK_PREFIX: &str = "ares:lock";

/// Redis key prefix for task status records.
pub const TASK_STATUS_PREFIX: &str = "ares:task_status";

// Collection key suffixes (appended to `ares:op:{op_id}:`)
/// Redis SET key suffix for discovered credentials.
pub const KEY_CREDENTIALS: &str = "credentials";
/// Redis SET key suffix for discovered password hashes.
pub const KEY_HASHES: &str = "hashes";
/// Redis SET key suffix for discovered hosts.
pub const KEY_HOSTS: &str = "hosts";
/// Redis SET key suffix for discovered user accounts.
pub const KEY_USERS: &str = "users";
/// Redis SET key suffix for discovered SMB shares.
pub const KEY_SHARES: &str = "shares";
/// Redis SET key suffix for discovered domain names.
pub const KEY_DOMAINS: &str = "domains";
/// Redis SET key suffix for discovered vulnerabilities.
pub const KEY_VULNS: &str = "vulns";
/// Redis SET key suffix for exploited targets.
pub const KEY_EXPLOITED: &str = "exploited";
/// Redis HASH key suffix for operation metadata.
pub const KEY_META: &str = "meta";
/// Redis HASH key suffix mapping IP → DC hostname.
pub const KEY_DC_MAP: &str = "dc_map";
/// Redis HASH key suffix mapping IP → NetBIOS name.
pub const KEY_NETBIOS_MAP: &str = "netbios_map";
/// Redis SET key suffix for collected artifacts.
pub const KEY_ARTIFACTS: &str = "artifacts";
/// Redis LIST key suffix for the operation event timeline.
pub const KEY_TIMELINE: &str = "timeline";
/// Redis SET key suffix for forged Kerberos golden tickets.
pub const KEY_GOLDEN_TICKETS: &str = "golden_tickets";
/// Redis SET key suffix for AdminSDHolder ACL backdoors.
pub const KEY_ADMINSD_BACKDOORS: &str = "adminsd_backdoors";
/// Redis SET key suffix for exploitable ACL chains.
pub const KEY_ACL_CHAINS: &str = "acl_chains";
/// Redis SET key suffix for discovered gMSA accounts.
pub const KEY_GMSA_ACCOUNTS: &str = "gmsa_accounts";
/// Redis key prefix suffix for deduplication bloom-filter sets.
pub const KEY_DEDUP_PREFIX: &str = "dedup";
/// Redis SET key suffix for observed MITRE ATT&CK technique IDs.
pub const KEY_TECHNIQUES: &str = "techniques";
/// Redis SET key suffix tracking dispatched MSSQL enumeration tasks.
pub const KEY_MSSQL_ENUM_DISPATCHED: &str = "mssql_enum_dispatched";
/// Redis HASH key suffix for tasks currently pending execution.
pub const KEY_PENDING_TASKS: &str = "pending_tasks";
/// Redis HASH key suffix for tasks that have finished execution.
pub const KEY_COMPLETED_TASKS: &str = "completed_tasks";
/// Redis HASH key suffix tracking consecutive failures per vulnerability type.
pub const KEY_VULN_TYPE_FAILURES: &str = "vuln_type_failures";
/// Redis HASH key suffix mapping domain name → SID string.
pub const KEY_DOMAIN_SIDS: &str = "domain_sids";
/// Redis HASH key suffix mapping domain FQDN → RID-500 account name.
pub const KEY_ADMIN_NAMES: &str = "admin_names";
/// Redis HASH key suffix mapping domain FQDN → TrustInfo JSON.
pub const KEY_TRUSTED_DOMAINS: &str = "trusted_domains";

/// Redis STRING key suffix for operation status JSON.
pub const KEY_STATUS: &str = "status";

/// Redis STRING key suffix for the LLM model name used by the operation.
pub const KEY_MODEL: &str = "model";

/// Redis STRING key suffix for a stop request signal.
pub const KEY_STOP_REQUESTED: &str = "stop_requested";

/// Pub/Sub channel prefix for state update notifications.
pub const STATE_UPDATE_CHANNEL_PREFIX: &str = "ares:state:updates";

/// Redis key prefix for all blue team investigation state.
#[cfg(feature = "blue")]
pub const BLUE_KEY_PREFIX: &str = "ares:blue:inv";

/// Redis lock key prefix for blue team investigations.
#[cfg(feature = "blue")]
pub const BLUE_LOCK_PREFIX: &str = "ares:blue:lock";

// Blue team collection key suffixes (appended to `ares:blue:inv:{inv_id}:`)
/// Redis HASH key suffix for collected evidence items.
#[cfg(feature = "blue")]
pub const BLUE_KEY_EVIDENCE: &str = "evidence";
/// Redis LIST key suffix for the investigation timeline.
#[cfg(feature = "blue")]
pub const BLUE_KEY_TIMELINE: &str = "timeline";
/// Redis SET key suffix for identified MITRE ATT&CK technique IDs.
#[cfg(feature = "blue")]
pub const BLUE_KEY_TECHNIQUES: &str = "techniques";
/// Redis SET key suffix for identified MITRE ATT&CK tactic IDs.
#[cfg(feature = "blue")]
pub const BLUE_KEY_TACTICS: &str = "tactics";
/// Redis SET key suffix for queried host names/IPs.
#[cfg(feature = "blue")]
pub const BLUE_KEY_HOSTS: &str = "hosts";
/// Redis SET key suffix for queried user accounts.
#[cfg(feature = "blue")]
pub const BLUE_KEY_USERS: &str = "users";
/// Redis SET key suffix for executed query type identifiers.
#[cfg(feature = "blue")]
pub const BLUE_KEY_QUERY_TYPES: &str = "query_types";
/// Redis HASH key suffix for investigation metadata.
#[cfg(feature = "blue")]
pub const BLUE_KEY_META: &str = "meta";
/// Redis HASH key suffix for tasks currently pending execution.
#[cfg(feature = "blue")]
pub const BLUE_KEY_PENDING_TASKS: &str = "tasks:pending";
/// Redis HASH key suffix for tasks that have finished execution.
#[cfg(feature = "blue")]
pub const BLUE_KEY_COMPLETED_TASKS: &str = "tasks:completed";
/// Redis HASH key suffix mapping technique ID → human-readable name.
#[cfg(feature = "blue")]
pub const BLUE_KEY_TECHNIQUE_NAMES: &str = "technique_names";
/// Redis LIST key suffix for analyst recommendations.
#[cfg(feature = "blue")]
pub const BLUE_KEY_RECOMMENDATIONS: &str = "recommendations";
/// Redis key suffix for the current triage decision JSON blob.
#[cfg(feature = "blue")]
pub const BLUE_KEY_TRIAGE_DECISION: &str = "triage:decision";
/// Redis LIST key suffix for the ordered triage audit trail.
#[cfg(feature = "blue")]
pub const BLUE_KEY_TRIAGE_RECORDS: &str = "triage:records";
/// Redis LIST key suffix for executed query records.
#[cfg(feature = "blue")]
pub const BLUE_KEY_QUERIES: &str = "queries";
/// Redis LIST key suffix for lateral movement connections.
#[cfg(feature = "blue")]
pub const BLUE_KEY_LATERAL: &str = "lateral";
/// Redis LIST key suffix for queued pivot investigation targets.
#[cfg(feature = "blue")]
pub const BLUE_KEY_PIVOT_QUEUE: &str = "pivot_queue";
/// Redis LIST key suffix for queued chained detection methods.
#[cfg(feature = "blue")]
pub const BLUE_KEY_CHAIN_QUEUE: &str = "chain_queue";

/// Redis key prefix for blue team task queues.
#[cfg(feature = "blue")]
pub const BLUE_TASK_QUEUE_PREFIX: &str = "ares:blue:tasks";
/// Redis key prefix for blue team task results.
#[cfg(feature = "blue")]
pub const BLUE_RESULT_QUEUE_PREFIX: &str = "ares:blue:results";
/// Redis key prefix for blue team agent heartbeats.
#[cfg(feature = "blue")]
pub const BLUE_HEARTBEAT_PREFIX: &str = "ares:blue:heartbeat";
/// Redis SET key for active blue team investigations.
#[cfg(feature = "blue")]
pub const BLUE_ACTIVE_INVESTIGATIONS: &str = "ares:blue:active_investigations";
/// Redis LIST key for the investigation request queue.
#[cfg(feature = "blue")]
pub const BLUE_INVESTIGATION_QUEUE: &str = "ares:blue:investigations";
/// Redis key prefix for blue team operation tracking.
#[cfg(feature = "blue")]
pub const BLUE_OP_PREFIX: &str = "ares:blue:op";
/// Redis key prefix for investigation status.
#[cfg(feature = "blue")]
pub const BLUE_STATUS_PREFIX: &str = "ares:blue:inv";
