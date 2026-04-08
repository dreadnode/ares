//! Convenience methods for common task types (request_crack, request_recon, etc.).

use anyhow::Result;
use serde_json::json;

use super::Dispatcher;

impl Dispatcher {
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
