//! auto_mssql_detection -- detect MSSQL services on hosts.

use std::sync::Arc;
use std::time::Duration;

use serde_json::json;
use tokio::sync::watch;
use tracing::{info, warn};

use crate::dispatcher::Dispatcher;

/// Scans hosts for MSSQL services (port 1433) and queues exploitation vulns.
/// Interval: 30s. Matches Python `_auto_mssql_detection`.
pub async fn auto_mssql_detection(
    dispatcher: Arc<Dispatcher>,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut interval = tokio::time::interval(Duration::from_secs(30));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            _ = interval.tick() => {},
            _ = shutdown.changed() => break,
        }
        if *shutdown.borrow() {
            break;
        }

        let work: Vec<(String, String)> = {
            let state = dispatcher.state.read().await;
            state
                .hosts
                .iter()
                .filter(|h| {
                    h.services
                        .iter()
                        .any(|s| s.contains("1433") || s.to_lowercase().contains("mssql"))
                })
                .filter(|h| !state.mssql_enum_dispatched.contains(&h.ip))
                .map(|h| (h.ip.clone(), h.hostname.clone()))
                .collect()
        };

        for (ip, hostname) in work {
            let vuln = ares_core::models::VulnerabilityInfo {
                vuln_id: format!("mssql_{}", ip.replace('.', "_")),
                vuln_type: "mssql_access".to_string(),
                target: ip.clone(),
                discovered_by: "auto_mssql_detection".to_string(),
                discovered_at: chrono::Utc::now(),
                details: {
                    let mut d = std::collections::HashMap::new();
                    d.insert("target_ip".to_string(), json!(ip));
                    if !hostname.is_empty() {
                        d.insert("hostname".to_string(), json!(hostname));
                        // Extract domain from FQDN: "sql01.fabrikam.local" → "fabrikam.local"
                        if let Some(dot_pos) = hostname.find('.') {
                            let domain = &hostname[dot_pos + 1..];
                            if !domain.is_empty() {
                                d.insert("domain".to_string(), json!(domain));
                            }
                        }
                    }
                    d
                },
                recommended_agent: "lateral".to_string(),
                priority: 4,
            };

            match dispatcher
                .state
                .publish_vulnerability(&dispatcher.queue, vuln)
                .await
            {
                Ok(true) => {
                    info!(ip = %ip, "MSSQL service detected — vulnerability queued");
                    dispatcher
                        .state
                        .write()
                        .await
                        .mssql_enum_dispatched
                        .insert(ip.clone());
                    let _ = dispatcher
                        .state
                        .persist_mssql_dispatched(&dispatcher.queue, &ip)
                        .await;
                }
                Ok(false) => {} // already exists
                Err(e) => warn!(err = %e, "Failed to publish MSSQL vulnerability"),
            }
        }
    }
}
