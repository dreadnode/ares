//! Dispatch tools — submit sub-tasks via the Dispatcher, and disabled record tools.

use anyhow::Result;
use tracing::{info, warn};

use ares_llm::provider::ToolCall;
use ares_llm::CallbackResult;

use super::OrchestratorCallbackHandler;

impl OrchestratorCallbackHandler {
    pub(super) async fn dispatch_recon(&self, call: &ToolCall) -> Result<CallbackResult> {
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

    pub(super) async fn dispatch_credential_access(
        &self,
        call: &ToolCall,
    ) -> Result<CallbackResult> {
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

    pub(super) async fn dispatch_lateral(&self, call: &ToolCall) -> Result<CallbackResult> {
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

    pub(super) async fn dispatch_exploit(&self, call: &ToolCall) -> Result<CallbackResult> {
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

    pub(super) async fn dispatch_coercion(&self, call: &ToolCall) -> Result<CallbackResult> {
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
    pub(super) async fn record_credential(&self, _call: &ToolCall) -> Result<CallbackResult> {
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
    pub(super) async fn record_timeline_event(&self, _call: &ToolCall) -> Result<CallbackResult> {
        warn!("record_timeline_event called but disabled — timeline events are auto-generated from discoveries");
        Ok(CallbackResult::Continue(
            "This tool is disabled. Timeline events are automatically generated when \
             credentials, hashes, and hosts are discovered from tool output. Focus on \
             running attack tools and the system will build the timeline automatically."
                .to_string(),
        ))
    }

    pub(super) async fn dispatch_crack(&self, call: &ToolCall) -> Result<CallbackResult> {
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
    pub(super) async fn report_cracked_credential(
        &self,
        _call: &ToolCall,
    ) -> Result<CallbackResult> {
        warn!("report_cracked_credential called but disabled — cracked passwords are auto-extracted from tool output");
        Ok(CallbackResult::Continue(
            "This tool is disabled. Cracked passwords are automatically extracted from \
             hashcat and john output. Run the cracking tools and the system will parse \
             and store cracked credentials automatically."
                .to_string(),
        ))
    }
}
