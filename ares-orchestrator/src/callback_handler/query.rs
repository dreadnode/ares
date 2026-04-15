//! Query tools — read from in-memory state.

use std::collections::HashMap;

use anyhow::Result;
use serde_json::json;

use ares_llm::provider::ToolCall;
use ares_llm::CallbackResult;

use super::OrchestratorCallbackHandler;

impl OrchestratorCallbackHandler {
    pub(super) async fn get_credential_summary(&self) -> Result<CallbackResult> {
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

    pub(super) async fn get_hash_summary(&self) -> Result<CallbackResult> {
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

    pub(super) async fn get_all_credentials(&self, call: &ToolCall) -> Result<CallbackResult> {
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

    pub(super) async fn get_all_hashes(&self, call: &ToolCall) -> Result<CallbackResult> {
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

    pub(super) async fn get_hash_value(&self, call: &ToolCall) -> Result<CallbackResult> {
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

    pub(super) async fn get_pending_tasks(&self) -> Result<CallbackResult> {
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

    pub(super) async fn get_agent_status(&self) -> Result<CallbackResult> {
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

    pub(super) async fn get_operation_summary(&self) -> Result<CallbackResult> {
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
}
