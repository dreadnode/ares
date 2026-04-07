//! Central dispatcher — ties together task submission, throttling, and state.
//!
//! All task submission goes through `Dispatcher::throttled_submit()` which checks
//! the throttler, submits or defers, and tracks active tasks. Convenience methods
//! like `request_crack()`, `request_recon()` etc. build the correct payloads.

use anyhow::Result;
use chrono::Utc;
use serde_json::json;
use std::sync::Arc;
use tokio::sync::Notify;
use tracing::{debug, warn};

use crate::config::OrchestratorConfig;
use crate::deferred::{DeferredQueue, DeferredTask};
use crate::routing::{ActiveTask, ActiveTaskTracker};
use crate::state::SharedState;
use crate::task_queue::TaskQueue;
use crate::throttling::{ThrottleDecision, Throttler};

/// Central dispatcher for submitting tasks with throttling and routing.
pub struct Dispatcher {
    pub queue: TaskQueue,
    pub tracker: ActiveTaskTracker,
    pub throttler: Arc<Throttler>,
    pub deferred: Arc<DeferredQueue>,
    pub state: SharedState,
    pub config: Arc<OrchestratorConfig>,
    /// Notifies auto_credential_access to wake up when new creds arrive.
    pub credential_access_notify: Arc<Notify>,
}

impl Dispatcher {
    pub fn new(
        queue: TaskQueue,
        tracker: ActiveTaskTracker,
        throttler: Arc<Throttler>,
        deferred: Arc<DeferredQueue>,
        state: SharedState,
        config: Arc<OrchestratorConfig>,
    ) -> Self {
        Self {
            queue,
            tracker,
            throttler,
            deferred,
            state,
            config,
            credential_access_notify: Arc::new(Notify::new()),
        }
    }

    /// Submit a task with throttle checking. Returns the task_id if submitted,
    /// None if deferred or rejected.
    pub async fn throttled_submit(
        &self,
        task_type: &str,
        target_role: &str,
        payload: serde_json::Value,
        priority: i32,
    ) -> Result<Option<String>> {
        let decision = self
            .throttler
            .check(task_type, target_role, Some(&payload))
            .await;

        match decision {
            ThrottleDecision::Allow => {
                self.do_submit(task_type, target_role, payload, priority)
                    .await
            }
            ThrottleDecision::Defer => {
                let task = DeferredTask {
                    priority,
                    enqueue_time: Utc::now().timestamp() as f64,
                    task_type: task_type.to_string(),
                    target_role: target_role.to_string(),
                    payload,
                    source_agent: "orchestrator".to_string(),
                };
                match self.deferred.enqueue(&task).await {
                    Ok(true) => {
                        debug!(task_type, target_role, "Task deferred");
                        Ok(None)
                    }
                    Ok(false) => {
                        debug!(task_type, target_role, "Deferred queue full, task dropped");
                        Ok(None)
                    }
                    Err(e) => {
                        warn!(err = %e, "Failed to defer task, attempting direct submit");
                        self.do_submit(task_type, target_role, task.payload, priority)
                            .await
                    }
                }
            }
            ThrottleDecision::Wait(dur) => {
                // Sleep and retry once
                tokio::time::sleep(dur).await;
                let retry_decision = self
                    .throttler
                    .check(task_type, target_role, Some(&payload))
                    .await;
                match retry_decision {
                    ThrottleDecision::Allow => {
                        self.do_submit(task_type, target_role, payload, priority)
                            .await
                    }
                    _ => {
                        let task = DeferredTask {
                            priority,
                            enqueue_time: Utc::now().timestamp() as f64,
                            task_type: task_type.to_string(),
                            target_role: target_role.to_string(),
                            payload,
                            source_agent: "orchestrator".to_string(),
                        };
                        let _ = self.deferred.enqueue(&task).await;
                        Ok(None)
                    }
                }
            }
        }
    }

    /// Direct submit (bypasses throttle). Returns task_id.
    async fn do_submit(
        &self,
        task_type: &str,
        target_role: &str,
        payload: serde_json::Value,
        priority: i32,
    ) -> Result<Option<String>> {
        let task_id = self
            .queue
            .submit_task(task_type, target_role, payload, "orchestrator", priority)
            .await?;

        self.tracker
            .add(ActiveTask {
                task_id: task_id.clone(),
                task_type: task_type.to_string(),
                role: target_role.to_string(),
                submitted_at: std::time::Instant::now(),
            })
            .await;

        self.throttler.record_dispatch().await;
        Ok(Some(task_id))
    }

    // === Convenience methods for common task types ===

    /// Submit a crack task for a hash.
    pub async fn request_crack(&self, hash: &ares_core::models::Hash) -> Result<Option<String>> {
        let payload = json!({
            "hash_type": hash.hash_type,
            "hash_value": hash.hash_value,
            "username": hash.username,
            "domain": hash.domain,
        });
        // Crack tasks are non-LLM, normal priority
        self.throttled_submit("crack", "cracker", payload, 5).await
    }

    /// Submit a recon task.
    pub async fn request_recon(
        &self,
        target_ip: &str,
        domain: &str,
        techniques: &[&str],
        credential: Option<&ares_core::models::Credential>,
    ) -> Result<Option<String>> {
        let mut payload = json!({
            "target_ip": target_ip,
            "domain": domain,
            "techniques": techniques,
        });
        if let Some(cred) = credential {
            payload["credential"] = json!({
                "username": cred.username,
                "password": cred.password,
                "domain": cred.domain,
            });
        }
        self.throttled_submit("recon", "recon", payload, 5).await
    }

    /// Submit a credential access task (kerberoast, asrep, secretsdump, etc.).
    pub async fn request_credential_access(
        &self,
        technique: &str,
        target_ip: &str,
        domain: &str,
        credential: &ares_core::models::Credential,
        priority: i32,
    ) -> Result<Option<String>> {
        let payload = json!({
            "technique": technique,
            "target_ip": target_ip,
            "domain": domain,
            "credential": {
                "username": credential.username,
                "password": credential.password,
                "domain": credential.domain,
            },
        });
        self.throttled_submit("credential_access", "credential_access", payload, priority)
            .await
    }

    /// Submit a secretsdump task.
    pub async fn request_secretsdump(
        &self,
        target_ip: &str,
        credential: &ares_core::models::Credential,
        priority: i32,
    ) -> Result<Option<String>> {
        let payload = json!({
            "technique": "secretsdump",
            "target_ip": target_ip,
            "credential": {
                "username": credential.username,
                "password": credential.password,
                "domain": credential.domain,
            },
        });
        self.throttled_submit("credential_access", "credential_access", payload, priority)
            .await
    }

    /// Submit a lateral movement task.
    pub async fn request_lateral(
        &self,
        target_ip: &str,
        credential: &ares_core::models::Credential,
        technique: &str,
    ) -> Result<Option<String>> {
        let payload = json!({
            "technique": technique,
            "target_ip": target_ip,
            "credential": {
                "username": credential.username,
                "password": credential.password,
                "domain": credential.domain,
            },
        });
        self.throttled_submit("lateral_movement", "lateral", payload, 5)
            .await
    }

    /// Submit an exploit task for a vulnerability.
    pub async fn request_exploit(
        &self,
        vuln: &ares_core::models::VulnerabilityInfo,
        priority: i32,
    ) -> Result<Option<String>> {
        let payload = json!({
            "vuln_id": vuln.vuln_id,
            "vuln_type": vuln.vuln_type,
            "target": vuln.target,
            "details": vuln.details,
        });
        let role = if vuln.recommended_agent.is_empty() {
            "privesc"
        } else {
            &vuln.recommended_agent
        };
        self.throttled_submit("exploit", role, payload, priority)
            .await
    }

    /// Submit a BloodHound collection task.
    pub async fn request_bloodhound(
        &self,
        domain: &str,
        dc_ip: &str,
        credential: &ares_core::models::Credential,
    ) -> Result<Option<String>> {
        let payload = json!({
            "technique": "bloodhound_collect",
            "domain": domain,
            "target_ip": dc_ip,
            "credential": {
                "username": credential.username,
                "password": credential.password,
                "domain": credential.domain,
            },
        });
        self.throttled_submit("recon", "recon", payload, 7).await
    }

    /// Submit a delegation enumeration task.
    pub async fn request_delegation_enum(
        &self,
        domain: &str,
        dc_ip: &str,
        credential: &ares_core::models::Credential,
    ) -> Result<Option<String>> {
        let payload = json!({
            "technique": "find_delegation",
            "domain": domain,
            "target_ip": dc_ip,
            "credential": {
                "username": credential.username,
                "password": credential.password,
                "domain": credential.domain,
            },
        });
        self.throttled_submit("privesc_enumeration", "recon", payload, 5)
            .await
    }

    /// Submit a share spider task.
    pub async fn request_share_spider(
        &self,
        host_ip: &str,
        share_name: &str,
        credential: &ares_core::models::Credential,
    ) -> Result<Option<String>> {
        let payload = json!({
            "technique": "share_spider",
            "target_ip": host_ip,
            "share_name": share_name,
            "credential": {
                "username": credential.username,
                "password": credential.password,
                "domain": credential.domain,
            },
        });
        self.throttled_submit("credential_access", "credential_access", payload, 8)
            .await
    }

    /// Submit a coercion task.
    pub async fn request_coercion(
        &self,
        target_ip: &str,
        listener_ip: &str,
        techniques: &[&str],
    ) -> Result<Option<String>> {
        let payload = json!({
            "target_ip": target_ip,
            "listener_ip": listener_ip,
            "techniques": techniques,
        });
        self.throttled_submit("coercion", "coercion", payload, 3)
            .await
    }

    /// Submit a CERTIPY find task for ADCS enumeration.
    pub async fn request_certipy_find(
        &self,
        target_ip: &str,
        domain: &str,
        credential: &ares_core::models::Credential,
    ) -> Result<Option<String>> {
        let payload = json!({
            "technique": "certipy_find",
            "target_ip": target_ip,
            "domain": domain,
            "credential": {
                "username": credential.username,
                "password": credential.password,
                "domain": credential.domain,
            },
        });
        self.throttled_submit("recon", "recon", payload, 4).await
    }

    /// Refresh the operation lock TTL. Called periodically.
    pub async fn extend_lock(&self) -> Result<()> {
        let op_id = self.state.operation_id().await;
        self.queue.extend_lock(&op_id, self.config.lock_ttl).await?;
        Ok(())
    }

    /// Publish a state update notification via Redis PubSub.
    pub async fn notify_state_update(&self) -> Result<()> {
        let op_id = self.state.operation_id().await;
        self.queue.publish_state_update(&op_id).await?;
        Ok(())
    }

    /// Get estimated concurrent task count available.
    pub async fn available_slots(&self) -> usize {
        let llm_count = self.tracker.llm_task_count().await;
        self.config.max_concurrent_tasks.saturating_sub(llm_count)
    }
}
