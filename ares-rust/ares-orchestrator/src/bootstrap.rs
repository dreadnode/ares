use std::sync::Arc;

use anyhow::Result;
use redis::AsyncCommands;
use tracing::{info, warn};

use crate::config::OrchestratorConfig;
use crate::dispatcher::Dispatcher;
use crate::task_queue::TaskQueue;

/// Write initial operation metadata to Redis so workers can discover the operation.
///
/// Mirrors the Python `_initialize_state_and_persist()` in `_orchestrator.py`.
pub(crate) async fn bootstrap_meta(queue: &TaskQueue, config: &OrchestratorConfig) -> Result<()> {
    use chrono::Utc;

    let mut conn = queue.connection();
    let meta_key = format!(
        "{}:{}:{}",
        ares_core::state::KEY_PREFIX,
        config.operation_id,
        "meta"
    );

    let now = Utc::now().to_rfc3339();
    let fields: Vec<(&str, String)> = vec![
        (
            "started_at",
            serde_json::to_string(&now).unwrap_or_default(),
        ),
        ("initialized", "true".to_string()),
        (
            "target_domain",
            serde_json::to_string(&config.target_domain).unwrap_or_default(),
        ),
        (
            "target_ip",
            serde_json::to_string(config.target_ips.first().unwrap_or(&String::new()))
                .unwrap_or_default(),
        ),
        (
            "target_ips",
            serde_json::to_string(&config.target_ips.join(",")).unwrap_or_default(),
        ),
    ];

    for (field, value) in &fields {
        let _: () = conn.hset(&meta_key, *field, value).await?;
    }
    // 24h TTL
    let _: () = conn.expire(&meta_key, 86400).await?;

    // Set active operation pointer for worker discovery
    let _: () = conn.set("ares:op:active", &config.operation_id).await?;

    info!(
        operation_id = %config.operation_id,
        meta_key = %meta_key,
        "Operation metadata written to Redis"
    );
    Ok(())
}

/// Dispatch initial recon tasks for each target IP.
///
/// This seeds the reactive automation pipeline — without these initial tasks,
/// all automation tasks have nothing to work with on a fresh operation.
pub(crate) async fn dispatch_initial_recon(
    dispatcher: &Arc<Dispatcher>,
    config: &OrchestratorConfig,
) -> usize {
    let mut count = 0;
    let domain = &config.target_domain;

    // Network scan + SMB signing check per target IP
    for ip in &config.target_ips {
        match dispatcher
            .request_recon(ip, domain, &["network_scan", "smb_signing_check"], None)
            .await
        {
            Ok(Some(task_id)) => {
                info!(task_id = %task_id, ip = %ip, "Dispatched initial recon");
                count += 1;
            }
            Ok(None) => {
                warn!(ip = %ip, "Initial recon throttled/deferred");
            }
            Err(e) => {
                warn!(ip = %ip, err = %e, "Failed to dispatch initial recon");
            }
        }
    }

    // User enumeration + AS-REP roast against first IP (likely DC)
    if let Some(first_ip) = config.target_ips.first() {
        match dispatcher
            .request_recon(first_ip, domain, &["user_enumeration"], None)
            .await
        {
            Ok(Some(task_id)) => {
                info!(task_id = %task_id, "Dispatched user enumeration");
                count += 1;
            }
            Ok(None) => warn!("User enumeration throttled/deferred"),
            Err(e) => warn!(err = %e, "Failed to dispatch user enumeration"),
        }
    }

    count
}
