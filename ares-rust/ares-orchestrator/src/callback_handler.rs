//! Orchestrator-specific callback handler for state query and dispatch tools.
//!
//! Implements `CallbackHandler` to handle tools that need in-memory state access:
//!
//! **Query tools** — read from SharedState (credentials, hashes, tasks, agent status)
//! **Dispatch tools** — submit sub-tasks via the Dispatcher (recon, credential_access, etc.)
//!
//! These tools are available only to the orchestrator agent role.

use std::collections::HashMap;
use std::sync::Arc;

use anyhow::Result;
use serde_json::json;
use tracing::{info, warn};

use ares_llm::provider::ToolCall;
use ares_llm::{CallbackHandler, CallbackResult};

use crate::dispatcher::Dispatcher;
use crate::state::SharedState;
use crate::task_queue::TaskQueue;

/// Callback handler for orchestrator LLM agent tools.
///
/// Provides direct access to shared state (for query tools) and the dispatcher
/// (for sub-task submission) without going through Redis tool queues.
pub struct OrchestratorCallbackHandler {
    state: SharedState,
    dispatcher: Option<Arc<Dispatcher>>,
    task_queue: Option<TaskQueue>,
}

impl OrchestratorCallbackHandler {
    pub fn new(state: SharedState, task_queue: TaskQueue) -> Self {
        Self {
            state,
            dispatcher: None,
            task_queue: Some(task_queue),
        }
    }

    #[cfg(test)]
    pub fn new_for_test(state: SharedState) -> Self {
        Self {
            state,
            dispatcher: None,
            task_queue: None,
        }
    }

    pub fn with_dispatcher(mut self, dispatcher: Arc<Dispatcher>) -> Self {
        self.dispatcher = Some(dispatcher);
        self
    }

    // -----------------------------------------------------------------------
    // Query tools — read from in-memory state
    // Static helpers exposed for testing without Redis.
    // -----------------------------------------------------------------------

    async fn get_credential_summary(&self) -> Result<CallbackResult> {
        let state = self.state.read().await;
        let mut by_domain: HashMap<&str, (usize, usize)> = HashMap::new();

        for cred in &state.credentials {
            let domain = if cred.domain.is_empty() {
                "unknown"
            } else {
                &cred.domain
            };
            let entry = by_domain.entry(domain).or_insert((0, 0));
            entry.0 += 1;
            if cred.is_admin {
                entry.1 += 1;
            }
        }

        let summary: Vec<serde_json::Value> = by_domain
            .iter()
            .map(|(domain, (total, admin))| {
                json!({
                    "domain": domain,
                    "total": total,
                    "admin": admin,
                })
            })
            .collect();

        let result = json!({
            "total_credentials": state.credentials.len(),
            "by_domain": summary,
            "has_domain_admin": state.has_domain_admin,
        });

        Ok(CallbackResult::Continue(serde_json::to_string_pretty(
            &result,
        )?))
    }

    async fn get_hash_summary(&self) -> Result<CallbackResult> {
        let state = self.state.read().await;
        let mut by_type: HashMap<&str, (usize, usize)> = HashMap::new();

        for hash in &state.hashes {
            let entry = by_type.entry(&hash.hash_type).or_insert((0, 0));
            entry.0 += 1;
            if hash.cracked_password.is_some() {
                entry.1 += 1;
            }
        }

        let summary: Vec<serde_json::Value> = by_type
            .iter()
            .map(|(hash_type, (total, cracked))| {
                json!({
                    "hash_type": hash_type,
                    "total": total,
                    "cracked": cracked,
                    "uncracked": total - cracked,
                })
            })
            .collect();

        let result = json!({
            "total_hashes": state.hashes.len(),
            "by_type": summary,
        });

        Ok(CallbackResult::Continue(serde_json::to_string_pretty(
            &result,
        )?))
    }

    async fn get_all_credentials(&self, call: &ToolCall) -> Result<CallbackResult> {
        let limit = call.arguments["limit"].as_u64().unwrap_or(30) as usize;
        let offset = call.arguments["offset"].as_u64().unwrap_or(0) as usize;

        let state = self.state.read().await;
        let total = state.credentials.len();
        let page: Vec<serde_json::Value> = state
            .credentials
            .iter()
            .skip(offset)
            .take(limit)
            .map(|c| {
                json!({
                    "username": c.username,
                    "domain": c.domain,
                    "has_password": !c.password.is_empty(),
                    "is_admin": c.is_admin,
                    "source": c.source,
                })
            })
            .collect();

        let result = json!({
            "credentials": page,
            "total": total,
            "offset": offset,
            "limit": limit,
        });

        Ok(CallbackResult::Continue(serde_json::to_string_pretty(
            &result,
        )?))
    }

    async fn get_all_hashes(&self, call: &ToolCall) -> Result<CallbackResult> {
        let limit = call.arguments["limit"].as_u64().unwrap_or(30) as usize;
        let offset = call.arguments["offset"].as_u64().unwrap_or(0) as usize;

        let state = self.state.read().await;
        let total = state.hashes.len();
        let page: Vec<serde_json::Value> = state
            .hashes
            .iter()
            .skip(offset)
            .take(limit)
            .map(|h| {
                json!({
                    "username": h.username,
                    "domain": h.domain,
                    "hash_type": h.hash_type,
                    "cracked": h.cracked_password.is_some(),
                    "source": h.source,
                    // Don't expose raw hash value to LLM — it doesn't need it
                    "has_aes_key": h.aes_key.is_some(),
                })
            })
            .collect();

        let result = json!({
            "hashes": page,
            "total": total,
            "offset": offset,
            "limit": limit,
        });

        Ok(CallbackResult::Continue(serde_json::to_string_pretty(
            &result,
        )?))
    }

    async fn get_hash_value(&self, call: &ToolCall) -> Result<CallbackResult> {
        let username = call.arguments["username"].as_str().unwrap_or("");
        let domain = call.arguments["domain"].as_str().unwrap_or("");
        let hash_type_filter = call.arguments["hash_type"].as_str();

        let state = self.state.read().await;
        let matches: Vec<serde_json::Value> = state
            .hashes
            .iter()
            .filter(|h| {
                h.username.eq_ignore_ascii_case(username)
                    && (domain.is_empty() || h.domain.eq_ignore_ascii_case(domain))
                    && hash_type_filter
                        .map(|t| h.hash_type.eq_ignore_ascii_case(t))
                        .unwrap_or(true)
            })
            .map(|h| {
                let mut entry = json!({
                    "username": h.username,
                    "domain": h.domain,
                    "hash_type": h.hash_type,
                    "hash_value": h.hash_value,
                    "cracked": h.cracked_password.is_some(),
                });
                if let Some(ref aes) = h.aes_key {
                    entry["aes_key"] = json!(aes);
                }
                entry
            })
            .collect();

        if matches.is_empty() {
            Ok(CallbackResult::Continue(format!(
                "No hashes found for {username}@{domain}"
            )))
        } else {
            Ok(CallbackResult::Continue(serde_json::to_string_pretty(
                &matches,
            )?))
        }
    }

    async fn get_pending_tasks(&self) -> Result<CallbackResult> {
        let state = self.state.read().await;
        let tasks: Vec<serde_json::Value> = state
            .pending_tasks
            .values()
            .map(|t| {
                json!({
                    "task_id": t.task_id,
                    "task_type": t.task_type,
                    "assigned_agent": t.assigned_agent,
                    "status": format!("{:?}", t.status),
                    "created_at": t.created_at.to_rfc3339(),
                })
            })
            .collect();

        let result = json!({
            "pending_tasks": tasks,
            "total": tasks.len(),
        });

        Ok(CallbackResult::Continue(serde_json::to_string_pretty(
            &result,
        )?))
    }

    async fn get_agent_status(&self) -> Result<CallbackResult> {
        let task_queue = self
            .task_queue
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("TaskQueue not configured"))?;
        // Read heartbeats from Redis to get agent status (SCAN to avoid blocking)
        let mut conn = task_queue.connection();
        let pattern = "ares:heartbeat:*";
        let keys = {
            let mut all_keys = Vec::new();
            let mut cursor: u64 = 0;
            loop {
                let result: Result<(u64, Vec<String>), redis::RedisError> = redis::cmd("SCAN")
                    .arg(cursor)
                    .arg("MATCH")
                    .arg(pattern)
                    .arg("COUNT")
                    .arg(100)
                    .query_async(&mut conn)
                    .await;
                match result {
                    Ok((next_cursor, keys)) => {
                        all_keys.extend(keys);
                        cursor = next_cursor;
                        if cursor == 0 {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
            all_keys
        };

        let mut agents: Vec<serde_json::Value> = Vec::new();
        for key in &keys {
            if let Ok(data) = redis::cmd("GET")
                .arg(key)
                .query_async::<String>(&mut conn)
                .await
            {
                if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&data) {
                    agents.push(parsed);
                }
            }
        }

        let result = json!({
            "agents": agents,
            "total": agents.len(),
        });

        Ok(CallbackResult::Continue(serde_json::to_string_pretty(
            &result,
        )?))
    }

    async fn get_operation_summary(&self) -> Result<CallbackResult> {
        let state = self.state.read().await;

        let cracked_count = state
            .hashes
            .iter()
            .filter(|h| h.cracked_password.is_some())
            .count();
        let admin_count = state.credentials.iter().filter(|c| c.is_admin).count();

        let result = json!({
            "operation_id": state.operation_id,
            "target_ips": state.target_ips,
            "domains": state.domains,
            "has_domain_admin": state.has_domain_admin,
            "credentials": {
                "total": state.credentials.len(),
                "admin": admin_count,
            },
            "hashes": {
                "total": state.hashes.len(),
                "cracked": cracked_count,
                "uncracked": state.hashes.len() - cracked_count,
            },
            "hosts": state.hosts.len(),
            "users": state.users.len(),
            "discovered_vulnerabilities": state.discovered_vulnerabilities.len(),
            "exploited_vulnerabilities": state.exploited_vulnerabilities.len(),
            "pending_tasks": state.pending_tasks.len(),
            "completed_tasks": state.completed_tasks.len(),
        });

        Ok(CallbackResult::Continue(serde_json::to_string_pretty(
            &result,
        )?))
    }

    // -----------------------------------------------------------------------
    // Dispatch tools — submit sub-tasks via Dispatcher
    // -----------------------------------------------------------------------

    async fn dispatch_recon(&self, call: &ToolCall) -> Result<CallbackResult> {
        let dispatcher = self
            .dispatcher
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Dispatcher not configured"))?;

        let target_ip = call.arguments["target_ip"].as_str().unwrap_or("");
        let domain = call.arguments["domain"].as_str().unwrap_or("");
        let techniques: Vec<&str> = call.arguments["techniques"]
            .as_array()
            .map(|arr| arr.iter().filter_map(|v| v.as_str()).collect())
            .unwrap_or_default();

        let task_id = dispatcher
            .request_recon(target_ip, domain, &techniques, None)
            .await?;

        info!(target_ip = target_ip, "Dispatched recon task");
        Ok(CallbackResult::Continue(format!(
            "Recon task dispatched: {}",
            task_id.as_deref().unwrap_or("queued")
        )))
    }

    async fn dispatch_credential_access(&self, call: &ToolCall) -> Result<CallbackResult> {
        let dispatcher = self
            .dispatcher
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Dispatcher not configured"))?;

        let technique = call.arguments["technique"]
            .as_str()
            .unwrap_or("secretsdump");
        let target_ip = call.arguments["target_ip"].as_str().unwrap_or("");
        let domain = call.arguments["domain"].as_str().unwrap_or("");
        let username = call.arguments["username"].as_str().unwrap_or("");
        let password = call.arguments["password"].as_str().unwrap_or("");
        let priority = call.arguments["priority"].as_i64().unwrap_or(5) as i32;

        let cred = ares_core::models::Credential {
            id: uuid::Uuid::new_v4().to_string(),
            username: username.to_string(),
            password: password.to_string(),
            domain: domain.to_string(),
            source: String::new(),
            discovered_at: None,
            is_admin: false,
            parent_id: None,
            attack_step: 0,
        };

        let task_id = dispatcher
            .request_credential_access(technique, target_ip, domain, &cred, priority)
            .await?;

        info!(
            technique = technique,
            target_ip = target_ip,
            "Dispatched credential access task"
        );
        Ok(CallbackResult::Continue(format!(
            "Credential access task ({technique}) dispatched: {}",
            task_id.as_deref().unwrap_or("queued")
        )))
    }

    async fn dispatch_lateral(&self, call: &ToolCall) -> Result<CallbackResult> {
        let dispatcher = self
            .dispatcher
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Dispatcher not configured"))?;

        let target_ip = call.arguments["target_ip"].as_str().unwrap_or("");
        let technique = call.arguments["technique"].as_str().unwrap_or("psexec");
        let username = call.arguments["username"].as_str().unwrap_or("");
        let password = call.arguments["password"].as_str().unwrap_or("");
        let domain = call.arguments["domain"].as_str().unwrap_or("");

        let cred = ares_core::models::Credential {
            id: uuid::Uuid::new_v4().to_string(),
            username: username.to_string(),
            password: password.to_string(),
            domain: domain.to_string(),
            source: String::new(),
            discovered_at: None,
            is_admin: false,
            parent_id: None,
            attack_step: 0,
        };

        let task_id = dispatcher
            .request_lateral(target_ip, &cred, technique)
            .await?;

        info!(
            technique = technique,
            target_ip = target_ip,
            "Dispatched lateral movement task"
        );
        Ok(CallbackResult::Continue(format!(
            "Lateral movement ({technique}) dispatched to {target_ip}: {}",
            task_id.as_deref().unwrap_or("queued")
        )))
    }

    async fn dispatch_exploit(&self, call: &ToolCall) -> Result<CallbackResult> {
        let dispatcher = self
            .dispatcher
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Dispatcher not configured"))?;

        let vuln_id = call.arguments["vuln_id"].as_str().unwrap_or("");
        let priority = call.arguments["priority"].as_i64().unwrap_or(3) as i32;

        // Look up vulnerability in state
        let state = self.state.read().await;
        let vuln = state.discovered_vulnerabilities.get(vuln_id);

        if let Some(vuln) = vuln {
            let vuln = vuln.clone();
            drop(state); // Release lock before async dispatch

            let task_id = dispatcher.request_exploit(&vuln, priority).await?;
            info!(vuln_id = vuln_id, "Dispatched exploit task");
            Ok(CallbackResult::Continue(format!(
                "Exploit task for {} dispatched: {}",
                vuln_id,
                task_id.as_deref().unwrap_or("queued")
            )))
        } else {
            drop(state);
            Ok(CallbackResult::Continue(format!(
                "Vulnerability {vuln_id} not found in discovered vulnerabilities"
            )))
        }
    }

    async fn dispatch_coercion(&self, call: &ToolCall) -> Result<CallbackResult> {
        let dispatcher = self
            .dispatcher
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Dispatcher not configured"))?;

        let target_ip = call.arguments["target_ip"].as_str().unwrap_or("");
        let listener_ip = call.arguments["listener_ip"].as_str().unwrap_or("");
        let techniques: Vec<&str> = call.arguments["techniques"]
            .as_array()
            .map(|arr| arr.iter().filter_map(|v| v.as_str()).collect())
            .unwrap_or_else(|| vec!["petitpotam", "printerbug"]);

        let task_id = dispatcher
            .request_coercion(target_ip, listener_ip, &techniques)
            .await?;

        info!(target_ip = target_ip, "Dispatched coercion task");
        Ok(CallbackResult::Continue(format!(
            "Coercion task dispatched to {target_ip}: {}",
            task_id.as_deref().unwrap_or("queued")
        )))
    }
    /// record_credential is disabled — credentials come only from tool output parsing.
    /// This handler exists as a safety net in case the LLM somehow invokes it.
    async fn record_credential(&self, _call: &ToolCall) -> Result<CallbackResult> {
        warn!("record_credential called but disabled — credentials are auto-extracted from tool output");
        Ok(CallbackResult::Continue(
            "This tool is disabled. Credentials are automatically extracted from tool output. \
             Focus on running tools that produce credential data (secretsdump, lsassy, netexec, etc.) \
             and the system will parse and store credentials automatically."
                .to_string(),
        ))
    }

    /// record_timeline_event is disabled — timeline events are auto-generated from
    /// state changes (credential/hash/host discoveries) in result_processing.rs.
    /// This handler exists as a safety net in case the LLM somehow invokes it.
    async fn record_timeline_event(&self, _call: &ToolCall) -> Result<CallbackResult> {
        warn!("record_timeline_event called but disabled — timeline events are auto-generated from discoveries");
        Ok(CallbackResult::Continue(
            "This tool is disabled. Timeline events are automatically generated when \
             credentials, hashes, and hosts are discovered from tool output. Focus on \
             running attack tools and the system will build the timeline automatically."
                .to_string(),
        ))
    }

    async fn dispatch_crack(&self, call: &ToolCall) -> Result<CallbackResult> {
        let dispatcher = self
            .dispatcher
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Dispatcher not configured"))?;

        let hash_value = call.arguments["hash_value"].as_str().unwrap_or("");
        let hash_type = call.arguments["hash_type"].as_str().unwrap_or("ntlm");
        let username = call.arguments["username"].as_str().unwrap_or("");
        let domain = call.arguments["domain"].as_str().unwrap_or("");

        let hash = ares_core::models::Hash {
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
        };

        let task_id = dispatcher.request_crack(&hash).await?;

        info!(hash_type = hash_type, "Dispatched crack task");
        Ok(CallbackResult::Continue(format!(
            "Crack task dispatched for {username}@{domain} ({hash_type}): {}",
            task_id.as_deref().unwrap_or("queued")
        )))
    }

    /// report_cracked_credential is disabled — cracked passwords are extracted from
    /// hashcat/john stdout via output_extraction.rs parsers. LLMs must never construct
    /// credential data directly.
    /// This handler exists as a safety net in case the LLM somehow invokes it.
    async fn report_cracked_credential(&self, _call: &ToolCall) -> Result<CallbackResult> {
        warn!("report_cracked_credential called but disabled — cracked passwords are auto-extracted from tool output");
        Ok(CallbackResult::Continue(
            "This tool is disabled. Cracked passwords are automatically extracted from \
             hashcat and john output. Run the cracking tools and the system will parse \
             and store cracked credentials automatically."
                .to_string(),
        ))
    }
}

#[async_trait::async_trait]
impl CallbackHandler for OrchestratorCallbackHandler {
    async fn handle_callback(&self, call: &ToolCall) -> Option<Result<CallbackResult>> {
        match call.name.as_str() {
            // Query tools
            "get_credential_summary" => Some(self.get_credential_summary().await),
            "get_hash_summary" => Some(self.get_hash_summary().await),
            "get_all_credentials" => Some(self.get_all_credentials(call).await),
            "get_all_hashes" => Some(self.get_all_hashes(call).await),
            "get_hash_value" => Some(self.get_hash_value(call).await),
            "get_pending_tasks" => Some(self.get_pending_tasks().await),
            "get_agent_status" => Some(self.get_agent_status().await),
            "get_operation_summary" => Some(self.get_operation_summary().await),
            // Recording tools — persist to state and Redis
            "record_credential" => Some(self.record_credential(call).await),
            "record_timeline_event" => Some(self.record_timeline_event(call).await),
            // Dispatch tools
            "dispatch_recon" => Some(self.dispatch_recon(call).await),
            "dispatch_credential_access" => Some(self.dispatch_credential_access(call).await),
            "dispatch_lateral_movement" => Some(self.dispatch_lateral(call).await),
            "dispatch_privesc_exploit" => Some(self.dispatch_exploit(call).await),
            "dispatch_coercion" => Some(self.dispatch_coercion(call).await),
            "dispatch_crack" => Some(self.dispatch_crack(call).await),
            // Cracker result — persist cracked credential and update hash
            "report_cracked_credential" => Some(self.report_cracked_credential(call).await),
            // Not ours — let built-in handler take over
            _ => None,
        }
    }

    async fn on_token_usage(&self, usage: &ares_llm::TokenUsage, model: &str) {
        if usage.input_tokens == 0 && usage.output_tokens == 0 {
            return;
        }
        if let Some(ref queue) = self.task_queue {
            let op_id = self.state.read().await.operation_id.clone();
            let mut conn = queue.connection();
            if let Err(e) = ares_core::token_usage::increment_token_usage(
                &mut conn,
                &op_id,
                usage.input_tokens.into(),
                usage.output_tokens.into(),
                model,
            )
            .await
            {
                warn!(err = %e, "Failed to record incremental token usage");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper to create a credential without Default.
    fn make_cred(
        username: &str,
        password: &str,
        domain: &str,
        is_admin: bool,
    ) -> ares_core::models::Credential {
        ares_core::models::Credential {
            id: uuid::Uuid::new_v4().to_string(),
            username: username.into(),
            password: password.into(),
            domain: domain.into(),
            source: String::new(),
            discovered_at: None,
            is_admin,
            parent_id: None,
            attack_step: 0,
        }
    }

    /// Helper to create a hash without Default.
    fn make_hash(
        username: &str,
        domain: &str,
        hash_type: &str,
        hash_value: &str,
        aes_key: Option<&str>,
    ) -> ares_core::models::Hash {
        ares_core::models::Hash {
            id: uuid::Uuid::new_v4().to_string(),
            username: username.into(),
            hash_value: hash_value.into(),
            hash_type: hash_type.into(),
            domain: domain.into(),
            cracked_password: None,
            source: String::new(),
            discovered_at: None,
            parent_id: None,
            attack_step: 0,
            aes_key: aes_key.map(|s| s.to_string()),
        }
    }

    fn make_handler() -> OrchestratorCallbackHandler {
        OrchestratorCallbackHandler::new_for_test(SharedState::new("test-op".to_string()))
    }

    #[tokio::test]
    async fn test_credential_summary_empty() {
        let handler = make_handler();
        let call = ToolCall {
            id: "c1".into(),
            name: "get_credential_summary".into(),
            arguments: json!({}),
        };
        let result = handler.handle_callback(&call).await.unwrap().unwrap();
        match result {
            CallbackResult::Continue(msg) => {
                let parsed: serde_json::Value = serde_json::from_str(&msg).unwrap();
                assert_eq!(parsed["total_credentials"], 0);
            }
            other => panic!("Expected Continue, got: {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_credential_summary_with_data() {
        let handler = make_handler();
        {
            let mut s = handler.state.write().await;
            s.credentials
                .push(make_cred("admin", "pass", "contoso.local", true));
            s.credentials
                .push(make_cred("user1", "pass1", "contoso.local", false));
        }

        let call = ToolCall {
            id: "c2".into(),
            name: "get_credential_summary".into(),
            arguments: json!({}),
        };
        let result = handler.handle_callback(&call).await.unwrap().unwrap();
        match result {
            CallbackResult::Continue(msg) => {
                let parsed: serde_json::Value = serde_json::from_str(&msg).unwrap();
                assert_eq!(parsed["total_credentials"], 2);
            }
            other => panic!("Expected Continue, got: {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_hash_summary_empty() {
        let handler = make_handler();
        let call = ToolCall {
            id: "c3".into(),
            name: "get_hash_summary".into(),
            arguments: json!({}),
        };
        let result = handler.handle_callback(&call).await.unwrap().unwrap();
        match result {
            CallbackResult::Continue(msg) => {
                let parsed: serde_json::Value = serde_json::from_str(&msg).unwrap();
                assert_eq!(parsed["total_hashes"], 0);
            }
            other => panic!("Expected Continue, got: {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_hash_value_lookup() {
        let handler = make_handler();
        {
            let mut s = handler.state.write().await;
            s.hashes.push(make_hash(
                "krbtgt",
                "contoso.local",
                "NTLM",
                "aad3b435b51404ee:313b6f423a71d74c",
                Some("f8b6c5e4d3a2b109"),
            ));
        }

        let call = ToolCall {
            id: "c4".into(),
            name: "get_hash_value".into(),
            arguments: json!({"username": "krbtgt", "domain": "contoso.local"}),
        };
        let result = handler.handle_callback(&call).await.unwrap().unwrap();
        match result {
            CallbackResult::Continue(msg) => {
                assert!(msg.contains("313b6f423a71d74c"));
                assert!(msg.contains("f8b6c5e4d3a2b109"));
            }
            other => panic!("Expected Continue, got: {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_hash_value_not_found() {
        let handler = make_handler();
        let call = ToolCall {
            id: "c5".into(),
            name: "get_hash_value".into(),
            arguments: json!({"username": "nobody", "domain": "contoso.local"}),
        };
        let result = handler.handle_callback(&call).await.unwrap().unwrap();
        match result {
            CallbackResult::Continue(msg) => assert!(msg.contains("No hashes found")),
            other => panic!("Expected Continue, got: {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_pending_tasks_empty() {
        let handler = make_handler();
        let call = ToolCall {
            id: "c6".into(),
            name: "get_pending_tasks".into(),
            arguments: json!({}),
        };
        let result = handler.handle_callback(&call).await.unwrap().unwrap();
        match result {
            CallbackResult::Continue(msg) => {
                let parsed: serde_json::Value = serde_json::from_str(&msg).unwrap();
                assert_eq!(parsed["total"], 0);
            }
            other => panic!("Expected Continue, got: {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_unknown_tool_returns_none() {
        let handler = make_handler();
        let call = ToolCall {
            id: "c7".into(),
            name: "nmap_scan".into(),
            arguments: json!({}),
        };
        assert!(handler.handle_callback(&call).await.is_none());
    }

    #[tokio::test]
    async fn test_dispatch_without_dispatcher() {
        let handler = make_handler();
        let call = ToolCall {
            id: "c8".into(),
            name: "dispatch_recon".into(),
            arguments: json!({"target_ip": "192.168.58.10"}),
        };
        let result = handler.handle_callback(&call).await.unwrap();
        assert!(result.is_err()); // No dispatcher configured
    }

    #[tokio::test]
    async fn test_operation_summary() {
        let handler = make_handler();
        {
            let mut s = handler.state.write().await;
            s.credentials
                .push(make_cred("admin", "pass", "contoso.local", true));
            s.hashes.push(make_hash(
                "krbtgt",
                "contoso.local",
                "NTLM",
                "aad3b435:313b6f42",
                None,
            ));
            s.has_domain_admin = true;
        }

        let call = ToolCall {
            id: "c10".into(),
            name: "get_operation_summary".into(),
            arguments: json!({}),
        };
        let result = handler.handle_callback(&call).await.unwrap().unwrap();
        match result {
            CallbackResult::Continue(msg) => {
                let parsed: serde_json::Value = serde_json::from_str(&msg).unwrap();
                assert_eq!(parsed["credentials"]["total"], 1);
                assert_eq!(parsed["credentials"]["admin"], 1);
                assert_eq!(parsed["hashes"]["total"], 1);
                assert_eq!(parsed["has_domain_admin"], true);
            }
            other => panic!("Expected Continue, got: {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_dispatch_crack_without_dispatcher() {
        let handler = make_handler();
        let call = ToolCall {
            id: "c11".into(),
            name: "dispatch_crack".into(),
            arguments: json!({"hash_value": "aad3b435:beef", "hash_type": "ntlm"}),
        };
        let result = handler.handle_callback(&call).await.unwrap();
        assert!(result.is_err()); // No dispatcher configured
    }

    #[tokio::test]
    async fn test_all_credentials_pagination() {
        let handler = make_handler();
        {
            let mut s = handler.state.write().await;
            for i in 0..10 {
                s.credentials.push(make_cred(
                    &format!("user{i}"),
                    "pass",
                    "contoso.local",
                    false,
                ));
            }
        }

        let call = ToolCall {
            id: "c9".into(),
            name: "get_all_credentials".into(),
            arguments: json!({"limit": 3, "offset": 2}),
        };
        let result = handler.handle_callback(&call).await.unwrap().unwrap();
        match result {
            CallbackResult::Continue(msg) => {
                let parsed: serde_json::Value = serde_json::from_str(&msg).unwrap();
                assert_eq!(parsed["total"], 10);
                assert_eq!(parsed["credentials"].as_array().unwrap().len(), 3);
                assert_eq!(parsed["offset"], 2);
            }
            other => panic!("Expected Continue, got: {:?}", other),
        }
    }

    // -------------------------------------------------------------------
    // Integration-style tests — verify full wiring with populated state
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn test_full_summary_with_populated_state() {
        let handler = make_handler();
        {
            let mut s = handler.state.write().await;
            s.credentials
                .push(make_cred("admin", "P@ss1", "contoso.local", true));
            s.credentials
                .push(make_cred("user1", "pass1", "contoso.local", false));
            s.credentials
                .push(make_cred("svc_sql", "SqlP@ss", "fabrikam.local", false));
            s.hashes.push(make_hash(
                "krbtgt",
                "contoso.local",
                "NTLM",
                "aad3b:beef",
                None,
            ));
            let mut h = make_hash("admin", "contoso.local", "NTLM", "aad3b:dead", None);
            h.cracked_password = Some("cracked123".into());
            s.hashes.push(h);
            s.has_domain_admin = true;
            s.domains.push("contoso.local".into());
            s.discovered_vulnerabilities.insert(
                "vuln-1".into(),
                ares_core::models::VulnerabilityInfo {
                    vuln_id: "vuln-1".into(),
                    vuln_type: "constrained_delegation".into(),
                    target: "192.168.58.30".into(),
                    discovered_by: "test".into(),
                    discovered_at: chrono::Utc::now(),
                    details: {
                        let mut m = std::collections::HashMap::new();
                        m.insert("account".into(), json!("svc_sql"));
                        m
                    },
                    recommended_agent: String::new(),
                    priority: 5,
                },
            );
        }

        let call = ToolCall {
            id: "int-1".into(),
            name: "get_operation_summary".into(),
            arguments: json!({}),
        };
        let result = handler.handle_callback(&call).await.unwrap().unwrap();
        match result {
            CallbackResult::Continue(msg) => {
                let p: serde_json::Value = serde_json::from_str(&msg).unwrap();
                assert_eq!(p["credentials"]["total"], 3);
                assert_eq!(p["credentials"]["admin"], 1);
                assert_eq!(p["hashes"]["total"], 2);
                assert_eq!(p["hashes"]["cracked"], 1);
                assert_eq!(p["has_domain_admin"], true);
                assert_eq!(p["discovered_vulnerabilities"], 1);
            }
            other => panic!("Expected Continue, got: {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_credential_summary_multi_domain() {
        let handler = make_handler();
        {
            let mut s = handler.state.write().await;
            s.credentials
                .push(make_cred("admin", "p1", "contoso.local", true));
            s.credentials
                .push(make_cred("user1", "p2", "contoso.local", false));
            s.credentials
                .push(make_cred("admin2", "p3", "fabrikam.local", true));
        }

        let call = ToolCall {
            id: "int-2".into(),
            name: "get_credential_summary".into(),
            arguments: json!({}),
        };
        let result = handler.handle_callback(&call).await.unwrap().unwrap();
        match result {
            CallbackResult::Continue(msg) => {
                let p: serde_json::Value = serde_json::from_str(&msg).unwrap();
                assert_eq!(p["total_credentials"], 3);
                let domains = p["by_domain"].as_array().unwrap();
                assert_eq!(domains.len(), 2);
            }
            other => panic!("Expected Continue, got: {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_hash_value_case_insensitive_lookup() {
        let handler = make_handler();
        {
            let mut s = handler.state.write().await;
            s.hashes.push(make_hash(
                "Administrator",
                "CONTOSO.LOCAL",
                "NTLM",
                "beef:dead",
                None,
            ));
        }

        let call = ToolCall {
            id: "int-3".into(),
            name: "get_hash_value".into(),
            arguments: json!({"username": "administrator", "domain": "contoso.local"}),
        };
        let result = handler.handle_callback(&call).await.unwrap().unwrap();
        match result {
            CallbackResult::Continue(msg) => assert!(msg.contains("beef:dead")),
            other => panic!("Expected Continue, got: {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_hash_value_filter_by_type() {
        let handler = make_handler();
        {
            let mut s = handler.state.write().await;
            s.hashes.push(make_hash(
                "admin",
                "contoso.local",
                "NTLM",
                "ntlm_hash",
                None,
            ));
            s.hashes.push(make_hash(
                "admin",
                "contoso.local",
                "aes256",
                "aes_hash",
                None,
            ));
        }

        let call = ToolCall {
            id: "int-4".into(),
            name: "get_hash_value".into(),
            arguments: json!({"username": "admin", "domain": "contoso.local", "hash_type": "aes256"}),
        };
        let result = handler.handle_callback(&call).await.unwrap().unwrap();
        match result {
            CallbackResult::Continue(msg) => {
                assert!(msg.contains("aes_hash"));
                assert!(!msg.contains("ntlm_hash"));
            }
            other => panic!("Expected Continue, got: {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_all_dispatch_tools_fail_without_dispatcher() {
        let handler = make_handler();
        let dispatch_tools = [
            ("dispatch_recon", json!({"target_ip": "192.168.58.10"})),
            (
                "dispatch_credential_access",
                json!({"technique": "secretsdump", "target_ip": "x", "domain": "x", "username": "x", "password": "x"}),
            ),
            (
                "dispatch_lateral_movement",
                json!({"target_ip": "x", "technique": "psexec", "username": "x", "password": "x", "domain": "x"}),
            ),
            ("dispatch_privesc_exploit", json!({"vuln_id": "v-1"})),
            (
                "dispatch_coercion",
                json!({"target_ip": "x", "listener_ip": "x"}),
            ),
            (
                "dispatch_crack",
                json!({"hash_value": "aad3b:beef", "hash_type": "ntlm"}),
            ),
        ];

        for (tool, args) in &dispatch_tools {
            let call = ToolCall {
                id: format!("disp-{tool}"),
                name: tool.to_string(),
                arguments: args.clone(),
            };
            let result = handler.handle_callback(&call).await;
            assert!(result.is_some(), "Should recognize: {tool}");
            assert!(
                result.unwrap().is_err(),
                "Should error without dispatcher: {tool}"
            );
        }
    }

    #[tokio::test]
    async fn test_all_callback_tools_recognized() {
        let handler = make_handler();
        let tools = [
            "get_credential_summary",
            "get_hash_summary",
            "get_all_credentials",
            "get_all_hashes",
            "get_hash_value",
            "get_pending_tasks",
            "get_operation_summary",
            "dispatch_recon",
            "dispatch_credential_access",
            "dispatch_lateral_movement",
            "dispatch_privesc_exploit",
            "dispatch_coercion",
            "dispatch_crack",
        ];

        for tool in &tools {
            let call = ToolCall {
                id: format!("route-{tool}"),
                name: tool.to_string(),
                arguments: json!({"username": "x", "domain": "x", "target_ip": "x",
                                "technique": "x", "password": "x", "hash_value": "x",
                                "hash_type": "x", "vuln_id": "x", "listener_ip": "x"}),
            };
            assert!(
                handler.handle_callback(&call).await.is_some(),
                "Handler should recognize: {tool}"
            );
        }

        // Unknown tool returns None
        let call = ToolCall {
            id: "route-unknown".into(),
            name: "nmap_scan".into(),
            arguments: json!({}),
        };
        assert!(handler.handle_callback(&call).await.is_none());
    }

    #[tokio::test]
    async fn test_all_hashes_pagination_large() {
        let handler = make_handler();
        {
            let mut s = handler.state.write().await;
            for i in 0..50 {
                s.hashes.push(make_hash(
                    &format!("user{i}"),
                    "contoso.local",
                    "NTLM",
                    &format!("hash_{i}"),
                    None,
                ));
            }
        }

        let call = ToolCall {
            id: "int-pg".into(),
            name: "get_all_hashes".into(),
            arguments: json!({"limit": 10, "offset": 40}),
        };
        let result = handler.handle_callback(&call).await.unwrap().unwrap();
        match result {
            CallbackResult::Continue(msg) => {
                let p: serde_json::Value = serde_json::from_str(&msg).unwrap();
                assert_eq!(p["total"], 50);
                assert_eq!(p["hashes"].as_array().unwrap().len(), 10);
            }
            other => panic!("Expected Continue, got: {:?}", other),
        }
    }
}
