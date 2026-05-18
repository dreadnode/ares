//! OperationRecoveryManager -- recovery of operation state from Redis.

use std::collections::HashMap;

use anyhow::{Context, Result};
use redis::AsyncCommands;
use tracing::{error, info, warn};

use ares_core::models::{TaskInfo, TaskStatus};
use ares_core::state::{self, RedisStateReader};

use crate::orchestrator::task_queue::TaskQueue;

use super::dedup::dedupe_hashes;
use super::normalize::{normalize_credential_domains, normalize_hash_domains};
use super::types::{
    is_connection_error, RecoveredState, INTERRUPTED_STATUSES, MAX_CONNECTION_RETRIES, MAX_RETRIES,
};

/// Manages recovery of operation state from Redis after a restart.
pub struct OperationRecoveryManager {
    redis_url: String,
    nats_url: String,
}

impl OperationRecoveryManager {
    /// Create a new recovery manager.
    pub fn new(redis_url: String, nats_url: String) -> Self {
        Self {
            redis_url,
            nats_url,
        }
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
            let queue = match TaskQueue::connect(&self.redis_url, &self.nats_url).await {
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

        let original_hash_count = loaded_state.all_hashes.len();
        loaded_state.all_hashes = dedupe_hashes(loaded_state.all_hashes);
        let deduped = original_hash_count - loaded_state.all_hashes.len();
        if deduped > 0 {
            info!(removed = deduped, "Deduplicated hashes during recovery");
        }

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

        let mut requeued_task_ids = Vec::new();
        let mut failed_task_ids = Vec::new();
        let mut tasks_to_redispatch = Vec::new();

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
                task.status = TaskStatus::Retrying;
                if task.retry_count > 0 {
                    task.error = Some(format!(
                        "Pod restart during execution (retry {}/{})",
                        task.retry_count, max_retries
                    ));
                } else {
                    task.error = Some("Requeued after pod restart (task was pending)".to_string());
                }

                let payload = task
                    .params
                    .iter()
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect::<serde_json::Map<String, serde_json::Value>>();

                tasks_to_redispatch.push(super::types::RecoveryTask {
                    task_type: task.task_type.clone(),
                    target_role: task.assigned_agent.clone(),
                    payload: serde_json::Value::Object(payload),
                    retry_count: task.retry_count,
                });

                requeued_task_ids.push(task_id.clone());
                info!(
                    task_id = %task_id,
                    retry_count = task.retry_count,
                    max_retries = max_retries,
                    "Task collected for re-dispatch via LLM submission"
                );
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

        // `loaded_state` is the recovered shared state. Only the requeue
        // counts and the redispatch payload list are surfaced to the caller;
        // the underlying state object is held while the recovery completes
        // and dropped here once redispatch is enqueued.
        drop(loaded_state);

        Ok(RecoveredState {
            tasks_to_redispatch,
            requeued_task_ids,
            failed_task_ids,
        })
    }
}
