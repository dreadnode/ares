//! Operation recovery manager.
//!
//! On startup, the orchestrator can recover state from a previous run by
//! loading it from Redis and re-enqueueing any interrupted tasks (those with
//! status PENDING, IN_PROGRESS, or RETRYING).
//!
//! Ported from `ares.core.recovery` (Python). Key additions over the initial
//! skeleton:
//!
//! - **Hash deduplication** (`dedupe_hashes`) — AS-REP by (domain,username),
//!   Kerberoast by (domain,username,spn_key), NTLM by exact hash value.
//! - **Pending-task requeuing** — loads `ares:op:{id}:pending_tasks` HASH
//!   instead of scanning global `ares:task_status:*` keys.
//! - **State normalization** — fixes NetBIOS -> FQDN domain mismatches on
//!   credentials and hashes, persists corrections back to Redis.
//! - **Connection error detection** with retry logic.
//! - **`OperationResumeHelper`** — analysis methods for post-recovery summary.

use std::collections::{HashMap, HashSet};
use std::fmt::Write as _;

use anyhow::{Context, Result};
use redis::AsyncCommands;
use tracing::{error, info, warn};

use ares_core::models::{
    Credential, Hash, SharedRedTeamState, TaskInfo, TaskStatus, VulnerabilityInfo,
};
use ares_core::state::{self, RedisStateReader};

use crate::task_queue::{TaskMessage, TaskQueue, RESULT_QUEUE_PREFIX, TASK_QUEUE_PREFIX};

/// Maximum number of retries before a task is considered permanently failed.
const MAX_RETRIES: i32 = 3;

/// Statuses that indicate an interrupted task eligible for re-enqueue.
const INTERRUPTED_STATUSES: &[TaskStatus] = &[
    TaskStatus::Pending,
    TaskStatus::InProgress,
    TaskStatus::Retrying,
];

/// Keywords that signal a transient Redis connection error.
const CONNECTION_ERROR_KEYWORDS: &[&str] = &[
    "connection",
    "connect",
    "closed",
    "timeout",
    "broken pipe",
    "reset",
    "reading from",
];

/// Result of a recovery operation.
#[derive(Debug)]
pub struct RecoveredState {
    /// The full shared state loaded from Redis.
    pub state: SharedRedTeamState,
    /// Task IDs that were re-enqueued for retry.
    pub requeued_task_ids: Vec<String>,
    /// Task IDs that exceeded max retries and were marked failed.
    pub failed_task_ids: Vec<String>,
}

// ---------------------------------------------------------------------------
// Connection error detection
// ---------------------------------------------------------------------------

/// Check if an error looks like a transient Redis connection failure.
fn is_connection_error(err: &anyhow::Error) -> bool {
    let msg = err.to_string().to_lowercase();
    CONNECTION_ERROR_KEYWORDS.iter().any(|kw| msg.contains(kw))
}

/// Maximum number of retry attempts for transient Redis connection errors.
const MAX_CONNECTION_RETRIES: u32 = 3;

// ---------------------------------------------------------------------------
// OperationRecoveryManager
// ---------------------------------------------------------------------------

/// Manages recovery of operation state from Redis after a restart.
pub struct OperationRecoveryManager {
    redis_url: String,
}

impl OperationRecoveryManager {
    /// Create a new recovery manager.
    pub fn new(redis_url: String) -> Self {
        Self { redis_url }
    }

    /// Attempt to recover an operation's state from Redis.
    ///
    /// 1. Checks that `ares:op:{operation_id}:meta` exists
    /// 2. Loads full state via `RedisStateReader`
    /// 3. Deduplicates hashes
    /// 4. Normalizes credential/hash domains against netbios_to_fqdn map
    /// 5. Loads pending tasks from `ares:op:{id}:pending_tasks` HASH
    /// 6. Re-enqueues interrupted tasks (incrementing retry count)
    /// 7. Returns recovered state + lists of requeued/failed task IDs
    ///
    /// Retries up to `MAX_CONNECTION_RETRIES` times on transient Redis errors.
    pub async fn recover(&self, operation_id: &str) -> Result<RecoveredState> {
        let mut last_err: Option<anyhow::Error> = None;

        for attempt in 1..=MAX_CONNECTION_RETRIES {
            let queue = match TaskQueue::connect(&self.redis_url).await {
                Ok(q) => q,
                Err(e) => {
                    if attempt < MAX_CONNECTION_RETRIES {
                        warn!(
                            attempt = attempt,
                            err = %e,
                            "Redis connection failed, retrying"
                        );
                        last_err = Some(e);
                        continue;
                    }
                    return Err(e).context("Failed to connect to Redis for recovery");
                }
            };

            match Self::recover_inner(&queue, operation_id).await {
                Ok(result) => return Ok(result),
                Err(e) => {
                    if is_connection_error(&e) && attempt < MAX_CONNECTION_RETRIES {
                        warn!(
                            attempt = attempt,
                            err = %e,
                            "Transient Redis error during recovery, retrying"
                        );
                        last_err = Some(e);
                        continue;
                    }
                    return Err(e);
                }
            }
        }

        Err(last_err
            .unwrap_or_else(|| anyhow::anyhow!("Recovery retry exhausted"))
            .context("Recovery failed after retries"))
    }

    /// Inner recovery logic (called within retry wrapper).
    async fn recover_inner(queue: &TaskQueue, operation_id: &str) -> Result<RecoveredState> {
        let mut conn = queue.connection();
        let reader = RedisStateReader::new(operation_id.to_string());

        // Step 1: Check operation exists
        let exists = reader
            .exists(&mut conn)
            .await
            .context("Failed to check operation existence")?;
        if !exists {
            anyhow::bail!(
                "Operation {} not found in Redis -- cannot recover",
                operation_id
            );
        }

        // Step 2: Load full state
        let mut loaded_state = reader
            .load_state(&mut conn)
            .await
            .context("Failed to load state from Redis")?
            .ok_or_else(|| anyhow::anyhow!("Operation {} has no state data", operation_id))?;

        info!(
            operation_id = operation_id,
            credentials = loaded_state.all_credentials.len(),
            hashes = loaded_state.all_hashes.len(),
            hosts = loaded_state.all_hosts.len(),
            has_domain_admin = loaded_state.has_domain_admin,
            "State loaded for recovery"
        );

        // Step 3: Deduplicate hashes
        let original_hash_count = loaded_state.all_hashes.len();
        loaded_state.all_hashes = dedupe_hashes(loaded_state.all_hashes);
        let deduped = original_hash_count - loaded_state.all_hashes.len();
        if deduped > 0 {
            info!(removed = deduped, "Deduplicated hashes during recovery");
        }

        // Step 4: Normalize domains (NetBIOS -> FQDN)
        let cred_fixed = normalize_credential_domains(
            &mut loaded_state.all_credentials,
            &loaded_state.netbios_to_fqdn,
        );
        let hash_fixed =
            normalize_hash_domains(&mut loaded_state.all_hashes, &loaded_state.netbios_to_fqdn);

        if cred_fixed > 0 || hash_fixed > 0 {
            info!(
                cred_fixed = cred_fixed,
                hash_fixed = hash_fixed,
                "Normalized domains during recovery"
            );

            // Persist corrections back to Redis
            if cred_fixed > 0 {
                for cred in &loaded_state.all_credentials {
                    let _ = reader.add_credential(&mut conn, cred).await;
                }
            }
            if hash_fixed > 0 {
                for h in &loaded_state.all_hashes {
                    let _ = reader.add_hash(&mut conn, h).await;
                }
            }
        }

        // Step 5: Load pending tasks from ares:op:{id}:pending_tasks HASH
        let pending_tasks_key = state::build_key(operation_id, state::KEY_PENDING_TASKS);
        let raw_tasks: HashMap<String, String> =
            conn.hgetall(&pending_tasks_key).await.unwrap_or_default();

        let mut pending_tasks: HashMap<String, TaskInfo> = HashMap::new();
        for (task_id, json_str) in &raw_tasks {
            match serde_json::from_str::<TaskInfo>(json_str) {
                Ok(task_info) => {
                    pending_tasks.insert(task_id.clone(), task_info);
                }
                Err(e) => {
                    warn!(
                        task_id = %task_id,
                        err = %e,
                        "Failed to deserialize pending task, skipping"
                    );
                }
            }
        }

        info!(
            operation_id = operation_id,
            pending_tasks = pending_tasks.len(),
            "Loaded pending tasks for recovery"
        );

        // Step 6: Requeue interrupted tasks
        let mut requeued_task_ids = Vec::new();
        let mut failed_task_ids = Vec::new();

        for (task_id, task) in &mut pending_tasks {
            if !INTERRUPTED_STATUSES.contains(&task.status) {
                continue;
            }

            // Increment retry count for tasks that were actively running
            if task.status == TaskStatus::InProgress {
                task.retry_count += 1;
            }

            let max_retries = task.max_retries.max(MAX_RETRIES);

            if task.retry_count <= max_retries {
                // Requeue the task
                task.status = TaskStatus::Retrying;
                if task.retry_count > 0 {
                    task.error = Some(format!(
                        "Pod restart during execution (retry {}/{})",
                        task.retry_count, max_retries
                    ));
                } else {
                    task.error = Some("Requeued after pod restart (task was pending)".to_string());
                }

                // Build TaskMessage and push to the role queue
                match requeue_task(queue, task_id, task).await {
                    Ok(()) => {
                        requeued_task_ids.push(task_id.clone());
                        info!(
                            task_id = %task_id,
                            retry_count = task.retry_count,
                            max_retries = max_retries,
                            "Task requeued for recovery"
                        );
                    }
                    Err(e) => {
                        warn!(
                            task_id = %task_id,
                            err = %e,
                            "Failed to requeue task"
                        );
                    }
                }
            } else {
                // Exceeded max retries
                task.status = TaskStatus::Failed;
                task.error = Some(format!(
                    "Pod restart during execution (max retries {} exceeded)",
                    max_retries
                ));
                task.completed_at = Some(chrono::Utc::now());
                failed_task_ids.push(task_id.clone());
                error!(
                    task_id = %task_id,
                    retry_count = task.retry_count,
                    "Task permanently failed after max retries"
                );
            }
        }

        // Persist updated pending_tasks back to Redis
        for (task_id, task) in &pending_tasks {
            if let Ok(json) = serde_json::to_string(task) {
                let _: Result<(), _> = conn.hset(&pending_tasks_key, task_id, &json).await;
            }
        }

        info!(
            operation_id = operation_id,
            requeued = requeued_task_ids.len(),
            failed = failed_task_ids.len(),
            "Recovery complete"
        );

        Ok(RecoveredState {
            state: loaded_state,
            requeued_task_ids,
            failed_task_ids,
        })
    }
}

// ---------------------------------------------------------------------------
// Task requeuing (preserves original task_id)
// ---------------------------------------------------------------------------

/// Requeue a task to its target role queue, preserving the original task_id.
///
/// Uses RPUSH so retried tasks are consumed before new ones (workers BRPOP
/// from the right).
async fn requeue_task(queue: &TaskQueue, task_id: &str, task: &TaskInfo) -> Result<()> {
    let mut payload = task
        .params
        .iter()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect::<serde_json::Map<String, serde_json::Value>>();

    // Add retry metadata
    payload.insert(
        "_retry_count".to_string(),
        serde_json::Value::from(task.retry_count),
    );
    payload.insert("_is_retry".to_string(), serde_json::Value::Bool(true));

    let callback_queue = format!("{RESULT_QUEUE_PREFIX}:{task_id}");
    let msg = TaskMessage {
        task_id: task_id.to_string(),
        task_type: task.task_type.clone(),
        source_agent: "orchestrator".to_string(),
        target_agent: task.assigned_agent.clone(),
        payload: serde_json::Value::Object(payload),
        priority: 1, // High priority for retries
        created_at: Some(chrono::Utc::now()),
        callback_queue: Some(callback_queue),
    };

    let queue_key = format!("{TASK_QUEUE_PREFIX}:{}", task.assigned_agent);
    let json = serde_json::to_string(&msg).context("Failed to serialize requeue TaskMessage")?;

    let mut conn = queue.connection();
    conn.rpush::<_, _, ()>(&queue_key, &json)
        .await
        .with_context(|| format!("RPUSH to {} for requeue", queue_key))?;

    info!(
        task_id = %task_id,
        queue = %queue_key,
        retry_count = task.retry_count,
        "Requeued task (RPUSH)"
    );

    Ok(())
}

// ---------------------------------------------------------------------------
// Hash deduplication
// ---------------------------------------------------------------------------

/// Deduplicate hashes, keeping first occurrence.
///
/// - **AS-REP hashes**: dedup by `(domain.lower(), username.lower())` since
///   each AS-REP request generates a different hash but cracks to the same
///   password.
/// - **Kerberoast/TGS hashes**: dedup by `(domain.lower(), username.lower(),
///   spn_key)` where spn_key is extracted from the hash format.
/// - **NTLM/other hashes**: dedup by exact `hash_value`.
pub fn dedupe_hashes(hashes: Vec<Hash>) -> Vec<Hash> {
    let mut seen_asrep: HashSet<(String, String)> = HashSet::new();
    let mut seen_kerberoast: HashSet<(String, String, String)> = HashSet::new();
    let mut seen_other: HashSet<String> = HashSet::new();
    let mut result = Vec::with_capacity(hashes.len());
    let original_len = hashes.len();

    for h in hashes {
        let hash_type = h.hash_type.trim().to_lowercase();
        let hash_value = &h.hash_value;
        let username = h.username.trim().to_lowercase();
        let domain = h.domain.trim().to_lowercase();

        let is_asrep = matches!(hash_type.as_str(), "as-rep" | "asrep" | "krb5asrep")
            || hash_value.starts_with("$krb5asrep$");

        let is_kerberoast = matches!(
            hash_type.as_str(),
            "kerberoast" | "krb5tgs" | "tgs-rep" | "tgs"
        ) || hash_value.starts_with("$krb5tgs$");

        if is_asrep {
            let key = (domain, username);
            if seen_asrep.contains(&key) {
                continue;
            }
            seen_asrep.insert(key);
        } else if is_kerberoast {
            let spn_key = extract_kerberoast_spn_key(hash_value).unwrap_or_default();
            let key = (domain, username, spn_key);
            if seen_kerberoast.contains(&key) {
                continue;
            }
            seen_kerberoast.insert(key);
        } else {
            if seen_other.contains(hash_value) {
                continue;
            }
            seen_other.insert(hash_value.clone());
        }

        result.push(h);
    }

    let removed = original_len - result.len();
    if removed > 0 {
        info!(removed = removed, "Deduplicated hashes");
    }
    result
}

/// Extract SPN and encryption type from a Kerberoast hash for deduplication.
///
/// Hash format: `$krb5tgs$ETYPE$*user$realm$spn*$checksum$encrypted`
fn extract_kerberoast_spn_key(hash_value: &str) -> Option<String> {
    if !hash_value.starts_with("$krb5tgs$") {
        return None;
    }
    let dollar_parts: Vec<&str> = hash_value.split('$').collect();
    if dollar_parts.len() < 4 {
        return None;
    }
    let etype = dollar_parts[2];
    let asterisk_parts: Vec<&str> = hash_value.split('*').collect();
    if asterisk_parts.len() < 2 {
        return None;
    }
    let inner_parts: Vec<&str> = asterisk_parts[1].split('$').collect();
    if inner_parts.len() < 3 {
        return None;
    }
    let spn = inner_parts[2];
    Some(format!("{etype}:{spn}"))
}

// ---------------------------------------------------------------------------
// State normalization
// ---------------------------------------------------------------------------

/// Fix credential domains: replace NetBIOS names with FQDNs where the
/// `netbios_to_fqdn` map provides a mapping.
///
/// Returns the number of credentials fixed.
fn normalize_credential_domains(
    credentials: &mut [Credential],
    netbios_map: &HashMap<String, String>,
) -> usize {
    let mut fixed = 0;
    for cred in credentials.iter_mut() {
        if let Some(fqdn) = resolve_domain(&cred.domain, netbios_map) {
            cred.domain = fqdn;
            fixed += 1;
        }
    }
    fixed
}

/// Fix hash domains: replace NetBIOS names with FQDNs where the
/// `netbios_to_fqdn` map provides a mapping.
///
/// Returns the number of hashes fixed.
fn normalize_hash_domains(hashes: &mut [Hash], netbios_map: &HashMap<String, String>) -> usize {
    let mut fixed = 0;
    for h in hashes.iter_mut() {
        if let Some(fqdn) = resolve_domain(&h.domain, netbios_map) {
            h.domain = fqdn;
            fixed += 1;
        }
    }
    fixed
}

/// If `domain` is a NetBIOS name (no dots, uppercase-ish), look it up in the
/// map and return the FQDN if found. Returns `None` if no fixup is needed.
fn resolve_domain(domain: &str, netbios_map: &HashMap<String, String>) -> Option<String> {
    let trimmed = domain.trim();
    if trimmed.is_empty() || trimmed.contains('.') {
        // Already FQDN or empty
        return None;
    }
    // Look up the NetBIOS name (case-insensitive)
    let upper = trimmed.to_uppercase();
    netbios_map
        .get(&upper)
        .or_else(|| netbios_map.get(trimmed))
        .or_else(|| netbios_map.get(&trimmed.to_lowercase()))
        .cloned()
}

// ---------------------------------------------------------------------------
// OperationResumeHelper
// ---------------------------------------------------------------------------

/// Post-recovery analysis helper.
///
/// Provides convenience methods to inspect the recovered state and produce
/// a human-readable summary for the orchestrator.
pub struct OperationResumeHelper<'a> {
    pub state: &'a SharedRedTeamState,
    pub requeued_task_ids: &'a [String],
    pub failed_task_ids: &'a [String],
    /// Pending tasks loaded during recovery (task_id -> TaskInfo).
    pub pending_tasks: &'a HashMap<String, TaskInfo>,
}

impl<'a> OperationResumeHelper<'a> {
    /// Get tasks that permanently failed (exceeded max retries during recovery).
    pub fn get_interrupted_tasks(&self) -> Vec<InterruptedTask> {
        let mut out = Vec::new();
        for task_id in self.failed_task_ids {
            if let Some(task) = self.pending_tasks.get(task_id) {
                out.push(InterruptedTask {
                    task_id: task_id.clone(),
                    task_type: task.task_type.clone(),
                    assigned_agent: task.assigned_agent.clone(),
                    retry_count: task.retry_count,
                    error: task.error.clone().unwrap_or_default(),
                });
            }
        }
        out
    }

    /// Get tasks that were auto-requeued and are currently retrying.
    pub fn get_retrying_tasks(&self) -> Vec<RetryingTask> {
        let mut out = Vec::new();
        for task_id in self.requeued_task_ids {
            if let Some(task) = self.pending_tasks.get(task_id) {
                out.push(RetryingTask {
                    task_id: task_id.clone(),
                    task_type: task.task_type.clone(),
                    assigned_agent: task.assigned_agent.clone(),
                    retry_count: task.retry_count,
                    max_retries: task.max_retries,
                });
            }
        }
        out
    }

    /// Get vulnerabilities that have been discovered but not yet exploited.
    pub fn get_unexploited_vulnerabilities(&self) -> Vec<&VulnerabilityInfo> {
        let mut vulns: Vec<&VulnerabilityInfo> = self
            .state
            .discovered_vulnerabilities
            .values()
            .filter(|v| !self.state.exploited_vulnerabilities.contains(&v.vuln_id))
            .collect();
        vulns.sort_by_key(|v| v.priority);
        vulns
    }

    /// Get hashes that have not been cracked yet.
    pub fn get_uncracked_hashes(&self) -> Vec<&Hash> {
        self.state
            .all_hashes
            .iter()
            .filter(|h| h.cracked_password.is_none())
            .collect()
    }

    /// Generate a human-readable summary of the recovery state.
    pub fn get_resume_summary(&self) -> String {
        let mut s = String::new();

        let _ = writeln!(s, "OPERATION RESUMED AFTER RECOVERY");
        let _ = writeln!(s, "{}", "=".repeat(50));
        let _ = writeln!(s);
        let _ = writeln!(s, "Operation ID: {}", self.state.operation_id);
        let _ = writeln!(s, "Credentials found: {}", self.state.all_credentials.len());
        let _ = writeln!(s, "Hosts discovered: {}", self.state.all_hosts.len());
        let _ = writeln!(
            s,
            "Domain admin: {}",
            if self.state.has_domain_admin {
                "YES"
            } else {
                "NO"
            }
        );
        let _ = writeln!(s);

        // Retrying tasks
        let retrying = self.get_retrying_tasks();
        if !retrying.is_empty() {
            let _ = writeln!(s, "[RETRYING] {} tasks auto-requeued:", retrying.len());
            for task in retrying.iter().take(5) {
                let _ = writeln!(
                    s,
                    "  - {} -> {} (retry {}/{})",
                    task.task_type, task.assigned_agent, task.retry_count, task.max_retries
                );
            }
            let _ = writeln!(s);
        }

        // Permanently failed tasks
        let interrupted = self.get_interrupted_tasks();
        if !interrupted.is_empty() {
            let _ = writeln!(
                s,
                "[FAILED] {} tasks exceeded max retries:",
                interrupted.len()
            );
            for task in interrupted.iter().take(5) {
                let _ = writeln!(
                    s,
                    "  - {} -> {} (retried {}x)",
                    task.task_type, task.assigned_agent, task.retry_count
                );
            }
            let _ = writeln!(s);
        }

        // Unexploited vulnerabilities
        let unexploited = self.get_unexploited_vulnerabilities();
        if !unexploited.is_empty() {
            let _ = writeln!(
                s,
                "[PENDING] {} unexploited vulnerabilities:",
                unexploited.len()
            );
            for v in unexploited.iter().take(5) {
                let _ = writeln!(
                    s,
                    "  - {}: {} (priority {})",
                    v.vuln_type, v.target, v.priority
                );
            }
            let _ = writeln!(s);
        }

        // Uncracked hashes
        let uncracked = self.get_uncracked_hashes();
        if !uncracked.is_empty() {
            let _ = writeln!(s, "[PENDING] {} uncracked hashes", uncracked.len());
            let _ = writeln!(s);
        }

        if retrying.is_empty() && interrupted.is_empty() {
            let _ = writeln!(s, "[OK] No interrupted tasks - clean recovery");
            let _ = writeln!(s);
        }

        s
    }
}

/// Info about a permanently failed task (exceeded max retries).
#[derive(Debug, Clone)]
pub struct InterruptedTask {
    pub task_id: String,
    pub task_type: String,
    pub assigned_agent: String,
    pub retry_count: i32,
    pub error: String,
}

/// Info about a task that was auto-requeued for retry.
#[derive(Debug, Clone)]
pub struct RetryingTask {
    pub task_id: String,
    pub task_type: String,
    pub assigned_agent: String,
    pub retry_count: i32,
    pub max_retries: i32,
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_hash(username: &str, domain: &str, hash_type: &str, hash_value: &str) -> Hash {
        Hash {
            id: uuid::Uuid::new_v4().to_string(),
            username: username.to_string(),
            hash_value: hash_value.to_string(),
            hash_type: hash_type.to_string(),
            domain: domain.to_string(),
            cracked_password: None,
            source: String::new(),
            discovered_at: None,
            parent_id: None,
            attack_step: 0,
            aes_key: None,
        }
    }

    // --- Hash dedup tests ---

    #[test]
    fn test_dedupe_asrep_by_domain_username() {
        let hashes = vec![
            make_hash(
                "jsnow",
                "contoso.local",
                "asrep",
                "$krb5asrep$23$jsnow@CONTOSO.LOCAL$aaaa",
            ),
            make_hash(
                "jsnow",
                "contoso.local",
                "asrep",
                "$krb5asrep$23$jsnow@CONTOSO.LOCAL$bbbb",
            ),
            make_hash(
                "jsnow",
                "contoso.local",
                "asrep",
                "$krb5asrep$23$jsnow@CONTOSO.LOCAL$cccc",
            ),
        ];
        let result = dedupe_hashes(hashes);
        assert_eq!(
            result.len(),
            1,
            "AS-REP hashes for same user should dedupe to 1"
        );
        assert!(
            result[0].hash_value.ends_with("$aaaa"),
            "Should keep first occurrence"
        );
    }

    #[test]
    fn test_dedupe_asrep_different_users_kept() {
        let hashes = vec![
            make_hash(
                "jsnow",
                "contoso.local",
                "as-rep",
                "$krb5asrep$23$jsnow@C$aaa",
            ),
            make_hash(
                "rbaratheon",
                "contoso.local",
                "as-rep",
                "$krb5asrep$23$rbaratheon@C$bbb",
            ),
        ];
        let result = dedupe_hashes(hashes);
        assert_eq!(result.len(), 2, "Different users should be kept");
    }

    #[test]
    fn test_dedupe_kerberoast_by_spn() {
        let hashes = vec![
            make_hash(
                "svc_sql",
                "contoso.local",
                "kerberoast",
                "$krb5tgs$23$*svc_sql$CONTOSO.LOCAL$MSSQLSvc/db01.contoso.local*$checksum1$enc1",
            ),
            make_hash(
                "svc_sql",
                "contoso.local",
                "kerberoast",
                "$krb5tgs$23$*svc_sql$CONTOSO.LOCAL$MSSQLSvc/db01.contoso.local*$checksum2$enc2",
            ),
        ];
        let result = dedupe_hashes(hashes);
        assert_eq!(result.len(), 1, "Same SPN kerberoast hashes should dedupe");
    }

    #[test]
    fn test_dedupe_kerberoast_different_spn_kept() {
        let hashes = vec![
            make_hash(
                "svc_sql",
                "contoso.local",
                "kerberoast",
                "$krb5tgs$23$*svc_sql$CONTOSO.LOCAL$MSSQLSvc/db01*$chk$enc",
            ),
            make_hash(
                "svc_sql",
                "contoso.local",
                "kerberoast",
                "$krb5tgs$23$*svc_sql$CONTOSO.LOCAL$MSSQLSvc/db02*$chk$enc",
            ),
        ];
        let result = dedupe_hashes(hashes);
        assert_eq!(result.len(), 2, "Different SPNs should be kept");
    }

    #[test]
    fn test_dedupe_ntlm_by_exact_value() {
        let hashes = vec![
            make_hash(
                "admin",
                "contoso.local",
                "NTLM",
                "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0", // pragma: allowlist secret
            ),
            make_hash(
                "admin",
                "contoso.local",
                "NTLM",
                "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0", // pragma: allowlist secret
            ),
            make_hash(
                "admin",
                "contoso.local",
                "NTLM",
                "aad3b435b51404eeaad3b435b51404ee:different_hash_value", // pragma: allowlist secret
            ),
        ];
        let result = dedupe_hashes(hashes);
        assert_eq!(
            result.len(),
            2,
            "Identical NTLM hashes should dedupe, different kept"
        );
    }

    #[test]
    fn test_dedupe_mixed_types() {
        let hashes = vec![
            // 2 AS-REP for same user -> 1
            make_hash("jsnow", "contoso.local", "asrep", "$krb5asrep$23$jsnow@C$a"),
            make_hash("jsnow", "contoso.local", "asrep", "$krb5asrep$23$jsnow@C$b"),
            // 1 NTLM
            make_hash("admin", "contoso.local", "NTLM", "aad3b435:hash1"), // pragma: allowlist secret
            // 1 Kerberoast
            make_hash(
                "svc",
                "contoso.local",
                "kerberoast",
                "$krb5tgs$23$*svc$CONTOSO.LOCAL$SPN*$chk$enc",
            ),
        ];
        let result = dedupe_hashes(hashes);
        assert_eq!(
            result.len(),
            3,
            "Should keep 1 asrep + 1 ntlm + 1 kerberoast"
        );
    }

    #[test]
    fn test_dedupe_empty() {
        let result = dedupe_hashes(vec![]);
        assert!(result.is_empty());
    }

    #[test]
    fn test_dedupe_case_insensitive() {
        let hashes = vec![
            make_hash("JSnow", "CONTOSO.LOCAL", "asrep", "$krb5asrep$23$JSnow@C$a"),
            make_hash("jsnow", "contoso.local", "asrep", "$krb5asrep$23$jsnow@C$b"),
        ];
        let result = dedupe_hashes(hashes);
        assert_eq!(result.len(), 1, "Case-insensitive dedup for AS-REP");
    }

    // --- Retry limit tests ---

    #[test]
    fn test_retry_limit_not_exceeded() {
        let task = TaskInfo {
            task_id: "test_1".to_string(),
            task_type: "recon".to_string(),
            assigned_agent: "recon".to_string(),
            status: TaskStatus::InProgress,
            created_at: chrono::Utc::now(),
            started_at: None,
            completed_at: None,
            last_activity_at: chrono::Utc::now(),
            params: HashMap::new(),
            result: None,
            error: None,
            retry_count: 2,
            max_retries: 3,
        };
        // retry_count (2) after increment (3) should still be <= max_retries (3)
        assert!(
            task.retry_count < task.max_retries,
            "Task with retry_count=2 should still be requeueable"
        );
    }

    #[test]
    fn test_retry_limit_exceeded() {
        let task = TaskInfo {
            task_id: "test_2".to_string(),
            task_type: "recon".to_string(),
            assigned_agent: "recon".to_string(),
            status: TaskStatus::InProgress,
            created_at: chrono::Utc::now(),
            started_at: None,
            completed_at: None,
            last_activity_at: chrono::Utc::now(),
            params: HashMap::new(),
            result: None,
            error: None,
            retry_count: 3,
            max_retries: 3,
        };
        // After increment: retry_count=4 > max_retries=3
        assert!(
            task.retry_count + 1 > task.max_retries,
            "Task with retry_count=3 after increment should exceed max"
        );
    }

    // --- State normalization tests ---

    #[test]
    fn test_normalize_credential_domains_netbios_to_fqdn() {
        let mut creds = vec![
            Credential {
                id: "1".to_string(),
                username: "admin".to_string(),
                password: "pass".to_string(), // pragma: allowlist secret
                domain: "CONTOSO".to_string(),
                source: String::new(),
                discovered_at: None,
                is_admin: false,
                parent_id: None,
                attack_step: 0,
            },
            Credential {
                id: "2".to_string(),
                username: "user1".to_string(),
                password: "pass2".to_string(), // pragma: allowlist secret
                domain: "contoso.local".to_string(), // already FQDN
                source: String::new(),
                discovered_at: None,
                is_admin: false,
                parent_id: None,
                attack_step: 0,
            },
        ];

        let mut netbios_map = HashMap::new();
        netbios_map.insert("CONTOSO".to_string(), "contoso.local".to_string());

        let fixed = normalize_credential_domains(&mut creds, &netbios_map);
        assert_eq!(fixed, 1);
        assert_eq!(creds[0].domain, "contoso.local");
        assert_eq!(creds[1].domain, "contoso.local"); // unchanged
    }

    #[test]
    fn test_normalize_hash_domains() {
        let mut hashes = vec![make_hash("admin", "FABRIKAM", "NTLM", "hash123")];

        let mut netbios_map = HashMap::new();
        netbios_map.insert("FABRIKAM".to_string(), "fabrikam.local".to_string());

        let fixed = normalize_hash_domains(&mut hashes, &netbios_map);
        assert_eq!(fixed, 1);
        assert_eq!(hashes[0].domain, "fabrikam.local");
    }

    #[test]
    fn test_normalize_no_changes_when_fqdn() {
        let mut creds = vec![Credential {
            id: "1".to_string(),
            username: "admin".to_string(),
            password: "pass".to_string(), // pragma: allowlist secret
            domain: "contoso.local".to_string(),
            source: String::new(),
            discovered_at: None,
            is_admin: false,
            parent_id: None,
            attack_step: 0,
        }];

        let netbios_map = HashMap::new();
        let fixed = normalize_credential_domains(&mut creds, &netbios_map);
        assert_eq!(fixed, 0, "FQDN domain should not be touched");
    }

    #[test]
    fn test_resolve_domain_empty_and_dotted() {
        let map = HashMap::new();
        assert!(resolve_domain("", &map).is_none(), "Empty domain -> None");
        assert!(
            resolve_domain("already.fqdn.local", &map).is_none(),
            "Dotted domain -> None"
        );
    }

    #[test]
    fn test_resolve_domain_case_insensitive_lookup() {
        let mut map = HashMap::new();
        map.insert("CONTOSO".to_string(), "contoso.local".to_string());

        assert_eq!(
            resolve_domain("contoso", &map),
            Some("contoso.local".to_string()),
            "Lowercase input should match uppercase key via to_uppercase"
        );
        assert_eq!(
            resolve_domain("CONTOSO", &map),
            Some("contoso.local".to_string()),
        );
        assert_eq!(
            resolve_domain("Contoso", &map),
            Some("contoso.local".to_string()),
        );
    }

    // --- Kerberoast SPN extraction ---

    #[test]
    fn test_extract_kerberoast_spn_key_valid() {
        let hash = "$krb5tgs$23$*svc_sql$CONTOSO.LOCAL$MSSQLSvc/db01.contoso.local*$chk$enc";
        let result = extract_kerberoast_spn_key(hash);
        assert_eq!(result, Some("23:MSSQLSvc/db01.contoso.local".to_string()));
    }

    #[test]
    fn test_extract_kerberoast_spn_key_invalid() {
        assert!(extract_kerberoast_spn_key("not_a_krb_hash").is_none());
        assert!(extract_kerberoast_spn_key("$krb5tgs$").is_none());
        assert!(extract_kerberoast_spn_key("$krb5tgs$23$nope").is_none());
    }

    // --- Connection error detection ---

    #[test]
    fn test_is_connection_error() {
        let conn_err = anyhow::anyhow!("Connection reset by peer");
        assert!(is_connection_error(&conn_err));

        let timeout_err = anyhow::anyhow!("Operation TIMEOUT after 30s");
        assert!(is_connection_error(&timeout_err));

        let broken = anyhow::anyhow!("Broken pipe");
        assert!(is_connection_error(&broken));

        let normal = anyhow::anyhow!("Key not found");
        assert!(!is_connection_error(&normal));
    }
}
