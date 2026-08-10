//! auto_mssql_detection -- detect MSSQL services on hosts.

use std::sync::Arc;
use std::time::Duration;

use serde_json::json;
use tokio::sync::watch;
use tracing::{info, warn};

use crate::orchestrator::dispatcher::Dispatcher;

/// Collect `(target_ip, hostname)` pairs for hosts advertising MSSQL.
///
/// A host is sometimes discovered hostname-only — e.g. synthesized from an
/// `MSSQLSvc/<host>` SPN before its IP is resolved — and still carries the
/// MSSQL service tag with an empty `ip`. Queuing an `mssql_access` vuln for
/// such a record yields an empty `target` (`vuln_id=mssql_`), which strands
/// the whole lateral / linked-server pivot: the vuln can never be exploited
/// against a blank host, so the cross-forest hop never fires. Resolve the IP
/// by matching the hostname against an IP-bearing host record; drop the entry
/// when no IP can be recovered. Deduplicates on the resolved IP and honors the
/// already-dispatched set so a resolved duplicate is not re-queued.
fn collect_mssql_targets(
    hosts: &[ares_core::models::Host],
    dispatched: &std::collections::HashSet<String>,
) -> Vec<(String, String)> {
    let is_mssql = |h: &ares_core::models::Host| {
        h.services
            .iter()
            .any(|s| s.contains("1433") || s.to_lowercase().contains("mssql"))
    };

    let mut out: Vec<(String, String)> = Vec::new();
    for h in hosts.iter().filter(|h| is_mssql(h)) {
        let ip = if h.ip.is_empty() {
            hosts
                .iter()
                .find(|o| {
                    !o.ip.is_empty()
                        && !o.hostname.is_empty()
                        && o.hostname.eq_ignore_ascii_case(&h.hostname)
                })
                .map(|o| o.ip.clone())
        } else {
            Some(h.ip.clone())
        };
        let Some(ip) = ip else { continue };
        if dispatched.contains(&ip) || out.iter().any(|(existing, _)| existing == &ip) {
            continue;
        }
        out.push((ip, h.hostname.clone()));
    }
    out
}

/// Scans hosts for MSSQL services (port 1433) and queues exploitation vulns.
/// Interval: 30s.
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
            collect_mssql_targets(&state.hosts, &state.mssql_enum_dispatched)
        };

        for (ip, hostname) in work {
            // Check strategy filter before publishing
            if !dispatcher.is_technique_allowed("mssql_access") {
                continue;
            }

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
                priority: dispatcher.effective_priority("mssql_access"),
            };

            match dispatcher
                .state
                .publish_vulnerability_with_strategy(
                    &dispatcher.queue,
                    vuln,
                    Some(&dispatcher.config.strategy),
                )
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

#[cfg(test)]
mod tests {
    use super::collect_mssql_targets;
    use ares_core::models::Host;
    use std::collections::HashSet;

    fn host(ip: &str, hostname: &str, services: &[&str]) -> Host {
        Host {
            ip: ip.to_string(),
            hostname: hostname.to_string(),
            os: String::new(),
            roles: Vec::new(),
            services: services.iter().map(|s| s.to_string()).collect(),
            is_dc: false,
            owned: false,
        }
    }

    #[test]
    fn direct_ip_mssql_host_passes_through() {
        let hosts = vec![host(
            "192.168.58.51",
            "sql01.contoso.local",
            &["1433/tcp (ms-sql-s)"],
        )];
        let work = collect_mssql_targets(&hosts, &HashSet::new());
        assert_eq!(
            work,
            vec![(
                "192.168.58.51".to_string(),
                "sql01.contoso.local".to_string()
            )]
        );
    }

    #[test]
    fn resolves_ipless_mssql_host_by_hostname() {
        // The MSSQL service is tagged on an IP-less duplicate (SPN-derived);
        // the real IP lives on a separate record for the same hostname. The
        // vuln target must resolve to that real IP, never the empty string.
        let hosts = vec![
            host("192.168.58.51", "sql01.contoso.local", &[]),
            host("", "sql01.contoso.local", &["1433/tcp (ms-sql-s)"]),
        ];
        let work = collect_mssql_targets(&hosts, &HashSet::new());
        assert_eq!(
            work,
            vec![(
                "192.168.58.51".to_string(),
                "sql01.contoso.local".to_string()
            )]
        );
    }

    #[test]
    fn drops_ipless_mssql_host_when_unresolvable() {
        let hosts = vec![host("", "sql01.contoso.local", &["1433/tcp (ms-sql-s)"])];
        let work = collect_mssql_targets(&hosts, &HashSet::new());
        assert!(
            work.is_empty(),
            "empty-IP host with no IP peer must not queue a blank target"
        );
    }

    #[test]
    fn dedup_honors_resolved_ip() {
        let hosts = vec![
            host("192.168.58.51", "sql01.contoso.local", &[]),
            host("", "sql01.contoso.local", &["1433/tcp (ms-sql-s)"]),
        ];
        let mut dispatched = HashSet::new();
        dispatched.insert("192.168.58.51".to_string());
        let work = collect_mssql_targets(&hosts, &dispatched);
        assert!(
            work.is_empty(),
            "already-dispatched resolved IP must not re-queue"
        );
    }

    #[test]
    fn collapses_duplicate_records_to_single_resolved_target() {
        // Both the IP record and the SPN duplicate carry the service after a
        // later merge; only one work item should result.
        let hosts = vec![
            host(
                "192.168.58.51",
                "sql01.contoso.local",
                &["1433/tcp (ms-sql-s)"],
            ),
            host("", "sql01.contoso.local", &["1433/tcp (ms-sql-s)"]),
        ];
        let work = collect_mssql_targets(&hosts, &HashSet::new());
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].0, "192.168.58.51");
    }
}
