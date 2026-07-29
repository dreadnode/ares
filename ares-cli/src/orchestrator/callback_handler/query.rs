//! Query tools — read from in-memory state.

use anyhow::Result;
use serde_json::json;

use ares_llm::provider::ToolCall;
use ares_llm::CallbackResult;

use super::OrchestratorCallbackHandler;

impl OrchestratorCallbackHandler {
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
