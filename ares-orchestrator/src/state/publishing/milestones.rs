//! Milestone publishing: golden ticket, domain admin.

use std::collections::HashMap;

use anyhow::Result;

use ares_core::models::VulnerabilityInfo;
use ares_core::state::RedisStateReader;

use crate::state::SharedState;
use crate::task_queue::TaskQueue;

impl SharedState {
    /// Set has_golden_ticket flag and persist to Redis.
    pub async fn set_golden_ticket(&self, queue: &TaskQueue, domain: &str) -> Result<()> {
        {
            let state = self.inner.read().await;
            if state.has_golden_ticket {
                return Ok(());
            }
        }
        let operation_id = {
            let state = self.inner.read().await;
            state.operation_id.clone()
        };
        let reader = RedisStateReader::new(operation_id);
        let mut conn = queue.connection();
        reader
            .set_meta_field(
                &mut conn,
                "has_golden_ticket",
                &serde_json::Value::Bool(true),
            )
            .await?;

        // Resolve DC IP for the vulnerability target
        let dc_target = {
            let state = self.inner.read().await;
            state
                .domain_controllers
                .get(&domain.to_lowercase())
                .cloned()
                .unwrap_or_else(|| domain.to_string())
        };

        let mut state = self.inner.write().await;
        state.has_golden_ticket = true;
        tracing::info!(domain = %domain, "🏆 Golden ticket flag set");
        drop(state);

        // Synthesize a golden_ticket vulnerability so loot reflects the achievement
        let vuln_id = format!("golden_ticket_{}", domain.to_lowercase());
        let mut details = HashMap::new();
        details.insert(
            "domain".into(),
            serde_json::Value::String(domain.to_string()),
        );
        details.insert(
            "note".into(),
            serde_json::Value::String(
                "Golden ticket forged — persistent domain access via krbtgt key".to_string(),
            ),
        );
        let vuln = VulnerabilityInfo {
            vuln_id: vuln_id.clone(),
            vuln_type: "golden_ticket".to_string(),
            target: dc_target,
            discovered_by: "golden_ticket_automation".to_string(),
            discovered_at: chrono::Utc::now(),
            details,
            recommended_agent: String::new(),
            priority: 1,
        };
        let _ = self.publish_vulnerability(queue, vuln).await;
        let _ = self.mark_exploited(queue, &vuln_id).await;
        Ok(())
    }

    /// Set has_domain_admin flag and persist to Redis.
    pub async fn set_domain_admin(&self, queue: &TaskQueue, path: Option<String>) -> Result<()> {
        let operation_id = {
            let state = self.inner.read().await;
            state.operation_id.clone()
        };
        let reader = RedisStateReader::new(operation_id);
        let mut conn = queue.connection();
        reader
            .set_meta_field(
                &mut conn,
                "has_domain_admin",
                &serde_json::Value::Bool(true),
            )
            .await?;
        if let Some(ref p) = path {
            reader
                .set_meta_field(
                    &mut conn,
                    "domain_admin_path",
                    &serde_json::Value::String(p.clone()),
                )
                .await?;
        }

        let mut state = self.inner.write().await;
        state.has_domain_admin = true;
        state.domain_admin_path = path.clone();

        // Emit OTel span recording domain admin achievement.
        // Walk parent_id chain from krbtgt hash to compute attack depth.
        let (attack_path_str, depth) = {
            let krbtgt = state.hashes.iter().find(|h| {
                h.username.eq_ignore_ascii_case("krbtgt")
                    && h.hash_type.to_lowercase().contains("ntlm")
            });
            let depth = match krbtgt {
                Some(h) => {
                    // Count chain depth by walking parent_id
                    let mut d = 1usize;
                    let mut current_id = h.parent_id.clone();
                    let mut seen = std::collections::HashSet::new();
                    while let Some(ref pid) = current_id {
                        if !seen.insert(pid.clone()) {
                            break;
                        }
                        d += 1;
                        // Check credentials then hashes for the parent
                        if let Some(c) = state.credentials.iter().find(|c| c.id == *pid) {
                            current_id = c.parent_id.clone();
                        } else if let Some(h2) = state.hashes.iter().find(|h2| h2.id == *pid) {
                            current_id = h2.parent_id.clone();
                        } else {
                            break;
                        }
                    }
                    d
                }
                None => 0,
            };
            let ap = path
                .as_deref()
                .filter(|s| !s.is_empty())
                .unwrap_or("domain_admin_achieved")
                .to_string();
            (ap, depth)
        };
        let op_id = state.operation_id.clone();
        drop(state);

        let span =
            ares_core::telemetry::spans::trace_domain_admin(&attack_path_str, depth, Some(&op_id));
        let _guard = span.enter();
        tracing::info!(attack_path = %attack_path_str, depth = depth, "🏆 Domain admin achieved");

        Ok(())
    }
}
