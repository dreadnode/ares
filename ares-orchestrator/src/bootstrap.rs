use std::sync::Arc;

use anyhow::Result;
use redis::AsyncCommands;
use tracing::{info, warn};

use crate::config::OrchestratorConfig;
use crate::dispatcher::Dispatcher;
use crate::task_queue::TaskQueue;

/// Probe target IPs on port 88 (Kerberos) then 389 (LDAP) to find a real DC.
/// Returns the first IP that accepts a TCP connection within 500ms.
pub(crate) async fn probe_dc_port(ips: &[String]) -> Option<String> {
    for port in [88u16, 389] {
        for ip in ips {
            let addr = format!("{ip}:{port}");
            if let Ok(Ok(_)) = tokio::time::timeout(
                std::time::Duration::from_millis(500),
                tokio::net::TcpStream::connect(&addr),
            )
            .await
            {
                info!(ip = %ip, port = port, "DC probe: port open");
                return Some(ip.clone());
            }
        }
    }
    None
}

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

    // started_at must only be set once — use HSETNX so restarts/recoveries
    // don't overwrite the original start time (which would break runtime calc).
    let started_at_json = serde_json::to_string(&now).unwrap_or_default();
    let _: bool = conn
        .hset_nx(&meta_key, "started_at", &started_at_json)
        .await?;

    // Remaining fields are safe to overwrite on restart
    let fields: Vec<(&str, String)> = vec![
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

    // Write operation status key (matches Python's status tracking)
    ares_core::state::set_operation_status(&mut conn, &config.operation_id, "running").await?;

    // Store the LLM model name for worker discovery and recovery
    let model_key = format!(
        "{}:{}:{}",
        ares_core::state::KEY_PREFIX,
        config.operation_id,
        ares_core::state::KEY_MODEL,
    );
    let model_name = std::env::var("ARES_LLM_MODEL").unwrap_or_default();
    if !model_name.is_empty() {
        let _: () = conn.set_ex(&model_key, &model_name, 86400u64).await?;
    }

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

    // Network scan + SMB sweep + SMB signing check per target IP.
    // smb_sweep (NetExec) is critical: it discovers hostnames, OS, and DCs
    // from SMB banners — data that nmap alone may miss.
    for ip in &config.target_ips {
        match dispatcher
            .request_recon(
                ip,
                domain,
                &["network_scan", "smb_sweep", "smb_signing_check"],
                None,
            )
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

    // User enumeration against all target IPs — we don't know which are DCs yet,
    // and non-DC IPs may silently return no output. Null session for bootstrap.
    for ip in &config.target_ips {
        let payload = serde_json::json!({
            "target_ip": ip,
            "domain": domain,
            "techniques": ["user_enumeration"],
            "null_session": true,
        });
        match dispatcher
            .throttled_submit("recon", "recon", payload, 5)
            .await
        {
            Ok(Some(task_id)) => {
                info!(task_id = %task_id, ip = %ip, "Dispatched user enumeration");
                count += 1;
            }
            Ok(None) => warn!(ip = %ip, "User enumeration throttled/deferred"),
            Err(e) => warn!(ip = %ip, err = %e, "Failed to dispatch user enumeration"),
        }
    }

    count
}
