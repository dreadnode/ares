//! Background automation tasks.
//!
//! Each `auto_*` function is a long-running tokio task that periodically checks
//! the shared state and dispatches new tasks when conditions are met. All follow
//! the same pattern:
//!
//!   1. Sleep for an interval (configurable)
//!   2. Take a read lock, collect new work items
//!   3. Release lock, submit tasks via the dispatcher
//!   4. Mark items as processed (write lock + Redis persist)
//!
//! This mirrors the Python `_orchestrator.py` background tasks but eliminates
//! all threading hacks since tokio tasks are truly concurrent.

use std::sync::Arc;
use std::time::Duration;

use serde_json::json;
use tokio::sync::watch;
use tracing::{debug, info, warn};

use crate::dispatcher::Dispatcher;
use crate::state::*;

// ---------------------------------------------------------------------------
// auto_crack_dispatch — submit crack tasks for new hashes
// ---------------------------------------------------------------------------

/// Scans for uncracked hashes and submits crack tasks.
/// Interval: 15s. Matches Python `_auto_crack_dispatch`.
pub async fn auto_crack_dispatch(dispatcher: Arc<Dispatcher>, mut shutdown: watch::Receiver<bool>) {
    let mut interval = tokio::time::interval(Duration::from_secs(15));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            _ = interval.tick() => {},
            _ = shutdown.changed() => break,
        }
        if *shutdown.borrow() {
            break;
        }

        // Collect unprocessed hashes
        let work: Vec<(String, ares_core::models::Hash)> = {
            let state = dispatcher.state.read().await;
            state
                .hashes
                .iter()
                .filter(|h| h.cracked_password.is_none())
                .filter_map(|h| {
                    let dedup = crack_dedup_key(h);
                    if state.is_processed(DEDUP_CRACK_REQUESTS, &dedup) {
                        None
                    } else {
                        Some((dedup, h.clone()))
                    }
                })
                .collect()
        };

        for (dedup_key, hash) in work {
            match dispatcher.request_crack(&hash).await {
                Ok(Some(task_id)) => {
                    debug!(task_id = %task_id, hash_type = %hash.hash_type, "Crack task dispatched");
                    dispatcher
                        .state
                        .write()
                        .await
                        .mark_processed(DEDUP_CRACK_REQUESTS, dedup_key.clone());
                    let _ = dispatcher
                        .state
                        .persist_dedup(&dispatcher.queue, DEDUP_CRACK_REQUESTS, &dedup_key)
                        .await;
                }
                Ok(None) => {} // deferred or throttled
                Err(e) => warn!(err = %e, "Failed to dispatch crack task"),
            }
        }
    }
}

// ---------------------------------------------------------------------------
// auto_mssql_detection — detect MSSQL services on hosts
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// auto_adcs_enumeration — detect ADCS servers via CertEnroll share
// ---------------------------------------------------------------------------

/// Detects ADCS servers by looking for CertEnroll shares and dispatches certipy_find.
/// Interval: 30s. Matches Python `_auto_adcs_enumeration`.
pub async fn auto_adcs_enumeration(
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

        // Find CertEnroll shares on unprocessed hosts + get a credential
        let work: Vec<(String, String, ares_core::models::Credential)> = {
            let state = dispatcher.state.read().await;
            let cred = match state.credentials.first() {
                Some(c) => c.clone(),
                None => continue,
            };
            state
                .shares
                .iter()
                .filter(|s| s.name.to_lowercase() == "certenroll")
                .filter(|s| !state.is_processed(DEDUP_ADCS_SERVERS, &s.host))
                .map(|s| {
                    let domain = state.domains.first().cloned().unwrap_or_default();
                    (s.host.clone(), domain, cred.clone())
                })
                .collect()
        };

        for (host_ip, domain, cred) in work {
            match dispatcher
                .request_certipy_find(&host_ip, &domain, &cred)
                .await
            {
                Ok(Some(task_id)) => {
                    info!(task_id = %task_id, host = %host_ip, "ADCS enumeration dispatched");
                    dispatcher
                        .state
                        .write()
                        .await
                        .mark_processed(DEDUP_ADCS_SERVERS, host_ip.clone());
                    let _ = dispatcher
                        .state
                        .persist_dedup(&dispatcher.queue, DEDUP_ADCS_SERVERS, &host_ip)
                        .await;
                }
                Ok(None) => {}
                Err(e) => warn!(err = %e, "Failed to dispatch ADCS enumeration"),
            }
        }
    }
}

// ---------------------------------------------------------------------------
// auto_share_spider — spider readable shares for credentials
// ---------------------------------------------------------------------------

/// Spiders readable shares for credentials using available creds.
/// Interval: 30s. Matches Python `_auto_share_spider`.
pub async fn auto_share_spider(dispatcher: Arc<Dispatcher>, mut shutdown: watch::Receiver<bool>) {
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

        let work: Vec<(String, String, String, ares_core::models::Credential)> = {
            let state = dispatcher.state.read().await;
            let cred = match state.credentials.first() {
                Some(c) => c.clone(),
                None => continue,
            };

            state
                .shares
                .iter()
                .filter(|s| {
                    let perms = s.permissions.to_uppercase();
                    perms.contains("READ") && !s.name.to_uppercase().ends_with('$')
                })
                .filter_map(|s| {
                    let dedup = format!("{}:{}:{}:{}", s.host, s.name, cred.username, cred.domain);
                    if state.is_processed(DEDUP_SPIDERED_SHARES, &dedup) {
                        None
                    } else {
                        Some((dedup, s.host.clone(), s.name.clone(), cred.clone()))
                    }
                })
                .take(3) // limit batch size
                .collect()
        };

        for (dedup_key, host, share, cred) in work {
            match dispatcher.request_share_spider(&host, &share, &cred).await {
                Ok(Some(task_id)) => {
                    debug!(task_id = %task_id, host = %host, share = %share, "Share spider dispatched");
                    dispatcher
                        .state
                        .write()
                        .await
                        .mark_processed(DEDUP_SPIDERED_SHARES, dedup_key.clone());
                    let _ = dispatcher
                        .state
                        .persist_dedup(&dispatcher.queue, DEDUP_SPIDERED_SHARES, &dedup_key)
                        .await;
                }
                Ok(None) => {}
                Err(e) => warn!(err = %e, "Failed to dispatch share spider"),
            }
        }
    }
}

// ---------------------------------------------------------------------------
// auto_bloodhound — BloodHound collection per domain
// ---------------------------------------------------------------------------

/// Dispatches BloodHound collection for each discovered domain.
/// Interval: 30s. Matches Python `_auto_bloodhound`.
pub async fn auto_bloodhound(dispatcher: Arc<Dispatcher>, mut shutdown: watch::Receiver<bool>) {
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

        let work: Vec<(String, String, ares_core::models::Credential)> = {
            let state = dispatcher.state.read().await;
            let cred = match state.credentials.first() {
                Some(c) => c.clone(),
                None => continue,
            };

            state
                .domains
                .iter()
                .filter(|d| !state.is_processed(DEDUP_BLOODHOUND_DOMAINS, d))
                .filter_map(|domain| {
                    let dc_ip = state.domain_controllers.get(domain).cloned()?;
                    Some((domain.clone(), dc_ip, cred.clone()))
                })
                .collect()
        };

        for (domain, dc_ip, cred) in work {
            match dispatcher.request_bloodhound(&domain, &dc_ip, &cred).await {
                Ok(Some(task_id)) => {
                    info!(task_id = %task_id, domain = %domain, "BloodHound collection dispatched");
                    dispatcher
                        .state
                        .write()
                        .await
                        .mark_processed(DEDUP_BLOODHOUND_DOMAINS, domain.clone());
                    let _ = dispatcher
                        .state
                        .persist_dedup(&dispatcher.queue, DEDUP_BLOODHOUND_DOMAINS, &domain)
                        .await;
                }
                Ok(None) => {}
                Err(e) => warn!(err = %e, "Failed to dispatch BloodHound"),
            }
        }
    }
}

// ---------------------------------------------------------------------------
// auto_delegation_enumeration — find delegation for new creds
// ---------------------------------------------------------------------------

/// Dispatches delegation enumeration for new credentials.
/// Interval: 30s. Matches Python `_auto_delegation_enumeration`.
pub async fn auto_delegation_enumeration(
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

        let work: Vec<(String, String, String, ares_core::models::Credential)> = {
            let state = dispatcher.state.read().await;
            state
                .credentials
                .iter()
                .filter_map(|cred| {
                    if cred.domain.is_empty() {
                        return None;
                    }
                    let dedup = format!(
                        "{}:{}",
                        cred.domain.to_lowercase(),
                        cred.username.to_lowercase()
                    );
                    if state.is_processed(DEDUP_DELEGATION_CREDS, &dedup) {
                        return None;
                    }
                    let dc_ip = state
                        .domain_controllers
                        .get(&cred.domain.to_lowercase())
                        .cloned()?;
                    Some((dedup, cred.domain.clone(), dc_ip, cred.clone()))
                })
                .collect()
        };

        for (dedup_key, domain, dc_ip, cred) in work {
            match dispatcher
                .request_delegation_enum(&domain, &dc_ip, &cred)
                .await
            {
                Ok(Some(task_id)) => {
                    debug!(task_id = %task_id, domain = %domain, "Delegation enumeration dispatched");
                    dispatcher
                        .state
                        .write()
                        .await
                        .mark_processed(DEDUP_DELEGATION_CREDS, dedup_key.clone());
                    let _ = dispatcher
                        .state
                        .persist_dedup(&dispatcher.queue, DEDUP_DELEGATION_CREDS, &dedup_key)
                        .await;
                }
                Ok(None) => {}
                Err(e) => warn!(err = %e, "Failed to dispatch delegation enumeration"),
            }
        }
    }
}

// ---------------------------------------------------------------------------
// auto_coercion — trigger ESC8 relay and DC coercion
// ---------------------------------------------------------------------------

/// Triggers coercion attacks when ADCS ESC8 servers or unconstrained delegation hosts exist.
/// Interval: 30s. Matches Python `_auto_coercion`.
pub async fn auto_coercion(dispatcher: Arc<Dispatcher>, mut shutdown: watch::Receiver<bool>) {
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

        // Coerce DCs that haven't been coerced yet
        let work: Vec<(String, String)> = {
            let state = dispatcher.state.read().await;
            // Find any host with unconstrained delegation as a listener
            let _listener = state.hosts.iter().find(|h| {
                h.roles
                    .iter()
                    .any(|r| r.to_lowercase().contains("unconstrained"))
            });

            state
                .domain_controllers
                .iter()
                .filter(|(_, dc_ip)| !state.is_processed(DEDUP_COERCED_DCS, dc_ip))
                .map(|(domain, dc_ip)| (domain.clone(), dc_ip.clone()))
                .collect()
        };

        for (domain, dc_ip) in work {
            // Find a listener IP for the coercion (any host we own)
            let listener_ip = {
                let state = dispatcher.state.read().await;
                state.hosts.iter().find(|h| h.owned).map(|h| h.ip.clone())
            };

            let listener = match listener_ip {
                Some(ip) => ip,
                None => continue,
            };

            match dispatcher
                .request_coercion(&dc_ip, &listener, &["petitpotam", "printerbug"])
                .await
            {
                Ok(Some(task_id)) => {
                    info!(task_id = %task_id, dc = %dc_ip, domain = %domain, "DC coercion dispatched");
                    dispatcher
                        .state
                        .write()
                        .await
                        .mark_processed(DEDUP_COERCED_DCS, dc_ip.clone());
                    let _ = dispatcher
                        .state
                        .persist_dedup(&dispatcher.queue, DEDUP_COERCED_DCS, &dc_ip)
                        .await;
                }
                Ok(None) => {}
                Err(e) => warn!(err = %e, "Failed to dispatch coercion"),
            }
        }
    }
}

// ---------------------------------------------------------------------------
// auto_local_admin_secretsdump — secretsdump with admin creds
// ---------------------------------------------------------------------------

/// Dispatches secretsdump when admin credentials are detected.
/// Interval: 30s. Matches Python `_auto_local_admin_secretsdump`.
pub async fn auto_local_admin_secretsdump(
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

        // Collect admin creds + target DCs
        let work: Vec<(String, String, ares_core::models::Credential)> = {
            let state = dispatcher.state.read().await;
            let admin_creds: Vec<_> = state
                .credentials
                .iter()
                .filter(|c| c.is_admin && !c.domain.is_empty())
                .cloned()
                .collect();

            let mut items = Vec::new();
            for cred in &admin_creds {
                for dc_ip in state.domain_controllers.values() {
                    let dedup = format!(
                        "{}:{}:{}",
                        dc_ip,
                        cred.username.to_lowercase(),
                        cred.domain.to_lowercase()
                    );
                    if !state.is_processed(DEDUP_SECRETSDUMP, &dedup) {
                        items.push((dedup, dc_ip.clone(), cred.clone()));
                    }
                }
            }
            items
        };

        for (dedup_key, dc_ip, cred) in work.into_iter().take(3) {
            match dispatcher.request_secretsdump(&dc_ip, &cred, 3).await {
                Ok(Some(task_id)) => {
                    info!(task_id = %task_id, dc = %dc_ip, user = %cred.username, "Admin secretsdump dispatched");
                    dispatcher
                        .state
                        .write()
                        .await
                        .mark_processed(DEDUP_SECRETSDUMP, dedup_key.clone());
                    let _ = dispatcher
                        .state
                        .persist_dedup(&dispatcher.queue, DEDUP_SECRETSDUMP, &dedup_key)
                        .await;
                }
                Ok(None) => {}
                Err(e) => warn!(err = %e, "Failed to dispatch secretsdump"),
            }
        }
    }
}

// ---------------------------------------------------------------------------
// auto_credential_access — kerberoast, AS-REP roast, password spray
// ---------------------------------------------------------------------------

/// Complex credential access automation: kerberoast, AS-REP roast, password spray.
/// Interval: 15s + Notify wake. Matches Python `_auto_credential_access`.
pub async fn auto_credential_access(
    dispatcher: Arc<Dispatcher>,
    mut shutdown: watch::Receiver<bool>,
) {
    let notify = dispatcher.credential_access_notify.clone();
    let mut interval = tokio::time::interval(Duration::from_secs(15));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            _ = interval.tick() => {},
            _ = notify.notified() => {},
            _ = shutdown.changed() => break,
        }
        if *shutdown.borrow() {
            break;
        }

        // --- AS-REP Roast: one per domain ---
        let asrep_work: Vec<(String, String, ares_core::models::Credential)> = {
            let state = dispatcher.state.read().await;
            let cred = match state.credentials.first() {
                Some(c) => c.clone(),
                None => continue,
            };
            state
                .domains
                .iter()
                .filter(|d| !state.is_processed(DEDUP_ASREP_DOMAINS, d))
                .filter_map(|domain| {
                    let dc_ip = state.domain_controllers.get(domain).cloned()?;
                    Some((domain.clone(), dc_ip, cred.clone()))
                })
                .collect()
        };

        for (domain, dc_ip, cred) in asrep_work {
            match dispatcher
                .request_credential_access("asreproast", &dc_ip, &domain, &cred, 5)
                .await
            {
                Ok(Some(task_id)) => {
                    info!(task_id = %task_id, domain = %domain, "AS-REP roast dispatched");
                    dispatcher
                        .state
                        .write()
                        .await
                        .mark_processed(DEDUP_ASREP_DOMAINS, domain.clone());
                    let _ = dispatcher
                        .state
                        .persist_dedup(&dispatcher.queue, DEDUP_ASREP_DOMAINS, &domain)
                        .await;
                }
                Ok(None) => {}
                Err(e) => warn!(err = %e, "Failed to dispatch AS-REP roast"),
            }
        }

        // --- Kerberoast: one per domain + credential pair ---
        let kerberoast_work: Vec<(String, String, ares_core::models::Credential)> = {
            let state = dispatcher.state.read().await;
            state
                .credentials
                .iter()
                .filter(|c| !c.domain.is_empty())
                .filter_map(|cred| {
                    let dedup = format!(
                        "krb:{}:{}",
                        cred.domain.to_lowercase(),
                        cred.username.to_lowercase()
                    );
                    if state.is_processed(DEDUP_CRACK_REQUESTS, &dedup) {
                        return None;
                    }
                    let dc_ip = state
                        .domain_controllers
                        .get(&cred.domain.to_lowercase())
                        .cloned()?;
                    Some((dedup, dc_ip, cred.clone()))
                })
                .take(2)
                .collect()
        };

        for (dedup_key, dc_ip, cred) in kerberoast_work {
            match dispatcher
                .request_credential_access("kerberoast", &dc_ip, &cred.domain, &cred, 5)
                .await
            {
                Ok(Some(task_id)) => {
                    debug!(task_id = %task_id, domain = %cred.domain, "Kerberoast dispatched");
                    dispatcher
                        .state
                        .write()
                        .await
                        .mark_processed(DEDUP_CRACK_REQUESTS, dedup_key.clone());
                    let _ = dispatcher
                        .state
                        .persist_dedup(&dispatcher.queue, DEDUP_CRACK_REQUESTS, &dedup_key)
                        .await;
                }
                Ok(None) => {}
                Err(e) => warn!(err = %e, "Failed to dispatch kerberoast"),
            }
        }

        // --- Password spray: username-as-password ---
        let spray_work: Vec<(String, String, String)> = {
            let state = dispatcher.state.read().await;
            state
                .users
                .iter()
                .filter(|u| !u.domain.is_empty())
                .filter_map(|u| {
                    let dedup =
                        format!("{}:{}", u.domain.to_lowercase(), u.username.to_lowercase());
                    if state.is_processed(DEDUP_USERNAME_SPRAY, &dedup) {
                        return None;
                    }
                    let dc_ip = state
                        .domain_controllers
                        .get(&u.domain.to_lowercase())
                        .cloned()?;
                    Some((dedup, dc_ip, u.domain.clone()))
                })
                .take(5)
                .collect()
        };

        // Submit one spray task per domain (batched)
        let mut sprayed_domains = std::collections::HashSet::new();
        for (_dedup_key, dc_ip, domain) in &spray_work {
            if sprayed_domains.contains(domain) {
                continue;
            }
            sprayed_domains.insert(domain.clone());

            let payload = json!({
                "technique": "username_as_password",
                "target_ip": dc_ip,
                "domain": domain,
            });

            match dispatcher
                .throttled_submit("credential_access", "credential_access", payload, 8)
                .await
            {
                Ok(Some(task_id)) => {
                    debug!(task_id = %task_id, domain = %domain, "Password spray dispatched");
                    // Mark all users in this domain's batch as processed
                    for (dk, _, d) in &spray_work {
                        if d == domain {
                            dispatcher
                                .state
                                .write()
                                .await
                                .mark_processed(DEDUP_USERNAME_SPRAY, dk.clone());
                            let _ = dispatcher
                                .state
                                .persist_dedup(&dispatcher.queue, DEDUP_USERNAME_SPRAY, dk)
                                .await;
                        }
                    }
                }
                Ok(None) => {}
                Err(e) => warn!(err = %e, "Failed to dispatch password spray"),
            }
        }
    }
}

// ---------------------------------------------------------------------------
// auto_credential_expansion — lateral movement with new creds
// ---------------------------------------------------------------------------

/// Monitors for new credentials and dispatches lateral movement tasks.
/// Interval: 15s. Matches Python `_auto_credential_expansion`.
pub async fn auto_credential_expansion(
    dispatcher: Arc<Dispatcher>,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut interval = tokio::time::interval(Duration::from_secs(15));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            _ = interval.tick() => {},
            _ = shutdown.changed() => break,
        }
        if *shutdown.borrow() {
            break;
        }

        let work: Vec<(String, ares_core::models::Credential, Vec<String>)> = {
            let state = dispatcher.state.read().await;
            state
                .credentials
                .iter()
                .filter(|c| !c.domain.is_empty())
                .filter_map(|cred| {
                    let dedup = format!(
                        "{}:{}",
                        cred.domain.to_lowercase(),
                        cred.username.to_lowercase()
                    );
                    if state.is_processed(DEDUP_EXPANSION_CREDS, &dedup) {
                        return None;
                    }
                    // Get target IPs for this domain
                    let targets: Vec<String> = state.hosts.iter().map(|h| h.ip.clone()).collect();
                    if targets.is_empty() {
                        return None;
                    }
                    Some((dedup, cred.clone(), targets))
                })
                .take(3)
                .collect()
        };

        for (dedup_key, cred, targets) in work {
            // Try smbexec/wmiexec on first few targets
            let mut dispatched = false;
            for target_ip in targets.iter().take(3) {
                if let Ok(Some(_)) = dispatcher
                    .request_lateral(target_ip, &cred, "smbexec")
                    .await
                {
                    dispatched = true;
                }
            }

            if dispatched {
                dispatcher
                    .state
                    .write()
                    .await
                    .mark_processed(DEDUP_EXPANSION_CREDS, dedup_key.clone());
                let _ = dispatcher
                    .state
                    .persist_dedup(&dispatcher.queue, DEDUP_EXPANSION_CREDS, &dedup_key)
                    .await;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// auto_golden_ticket — monitor for krbtgt hash and forge golden ticket
// ---------------------------------------------------------------------------

/// Monitors for krbtgt hash and triggers golden ticket forging.
/// Interval: 30s. Matches Python `_auto_golden_ticket`.
pub async fn auto_golden_ticket(dispatcher: Arc<Dispatcher>, mut shutdown: watch::Receiver<bool>) {
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

        let state = dispatcher.state.read().await;

        // Skip if already have golden ticket
        if state.has_golden_ticket {
            continue;
        }

        // Skip if no domain admin yet
        if !state.has_domain_admin {
            continue;
        }

        // Look for krbtgt hash
        let krbtgt_hash = state
            .hashes
            .iter()
            .find(|h| h.username.to_lowercase() == "krbtgt");

        let krbtgt = match krbtgt_hash {
            Some(h) => h.clone(),
            None => continue,
        };

        let domain = if !krbtgt.domain.is_empty() {
            krbtgt.domain.clone()
        } else {
            match state.domains.first() {
                Some(d) => d.clone(),
                None => continue,
            }
        };

        // Check for domain SID
        let domain_sid = state.domain_sids.get(&domain.to_lowercase()).cloned();

        drop(state);

        // Submit golden ticket forging task
        let mut payload = json!({
            "technique": "golden_ticket",
            "domain": domain,
            "krbtgt_hash": krbtgt.hash_value,
            "username": "Administrator",
        });
        if let Some(sid) = domain_sid {
            payload["domain_sid"] = json!(sid);
        }
        if let Some(ref aes) = krbtgt.aes_key {
            payload["aes_key"] = json!(aes);
        }

        match dispatcher
            .throttled_submit("exploit", "privesc", payload, 1)
            .await
        {
            Ok(Some(task_id)) => {
                info!(task_id = %task_id, domain = %domain, "Golden ticket task dispatched");
            }
            Ok(None) => {}
            Err(e) => warn!(err = %e, "Failed to dispatch golden ticket"),
        }
    }
}

// ---------------------------------------------------------------------------
// auto_acl_chain_follow — dispatch ACL chain steps using available creds
// ---------------------------------------------------------------------------

/// Follows ACL chains from BloodHound results, dispatching each step when
/// credentials for the source user are available.
/// Interval: 30s. Each chain is a JSON array of steps; we find the first
/// undispatched step whose source user has known credentials and dispatch it.
pub async fn auto_acl_chain_follow(
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

        // Skip if domain admin already achieved
        {
            let state = dispatcher.state.read().await;
            if state.has_domain_admin {
                continue;
            }
        }

        // Collect work items: (dedup_key, chain_step, credential)
        let work: Vec<(String, serde_json::Value, ares_core::models::Credential)> = {
            let state = dispatcher.state.read().await;

            if state.acl_chains.is_empty() {
                continue;
            }

            let mut items = Vec::new();

            for (chain_idx, chain) in state.acl_chains.iter().enumerate() {
                // Each chain is expected to be a JSON array of step objects
                let steps = match chain.as_array() {
                    Some(s) => s,
                    None => {
                        // Or it might be an object with a "steps" field
                        match chain.get("steps").and_then(|v| v.as_array()) {
                            Some(s) => s,
                            None => continue,
                        }
                    }
                };

                for (step_idx, step) in steps.iter().enumerate() {
                    let dedup_key = format!("chain:{}:step:{}", chain_idx, step_idx);

                    // Skip already dispatched steps
                    if state.dispatched_acl_steps.contains(&dedup_key) {
                        continue;
                    }
                    if state.is_processed(DEDUP_ACL_STEPS, &dedup_key) {
                        continue;
                    }

                    // Get the source user for this step
                    let source_user = step
                        .get("source")
                        .or_else(|| step.get("source_user"))
                        .or_else(|| step.get("from"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    let source_domain = step
                        .get("source_domain")
                        .or_else(|| step.get("domain"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("");

                    if source_user.is_empty() {
                        continue;
                    }

                    // Find credential for the source user
                    let cred = state.credentials.iter().find(|c| {
                        c.username.to_lowercase() == source_user.to_lowercase()
                            && (source_domain.is_empty()
                                || c.domain.to_lowercase() == source_domain.to_lowercase())
                    });

                    if let Some(cred) = cred {
                        items.push((dedup_key, step.clone(), cred.clone()));
                    }

                    // Only dispatch the first undispatched step per chain
                    break;
                }
            }

            items
        };

        // Dispatch each collected step
        for (dedup_key, step, cred) in work {
            let payload = json!({
                "technique": "acl_chain_step",
                "step": step,
                "credential": {
                    "username": cred.username,
                    "password": cred.password,
                    "domain": cred.domain,
                },
            });

            match dispatcher
                .throttled_submit("acl_chain_step", "acl", payload, 4)
                .await
            {
                Ok(Some(task_id)) => {
                    info!(
                        task_id = %task_id,
                        step_key = %dedup_key,
                        "ACL chain step dispatched"
                    );
                    // Mark as dispatched in both in-memory set and dedup
                    {
                        let mut state = dispatcher.state.write().await;
                        state.dispatched_acl_steps.insert(dedup_key.clone());
                        state.mark_processed(DEDUP_ACL_STEPS, dedup_key.clone());
                    }
                    let _ = dispatcher
                        .state
                        .persist_dedup(&dispatcher.queue, DEDUP_ACL_STEPS, &dedup_key)
                        .await;
                }
                Ok(None) => {} // deferred or throttled
                Err(e) => warn!(err = %e, "Failed to dispatch ACL chain step"),
            }
        }
    }
}

// ---------------------------------------------------------------------------
// state_refresh — periodic refresh of state from Redis
// ---------------------------------------------------------------------------

/// Periodically refreshes state from Redis to pick up worker-published discoveries.
/// Interval: 10s.
pub async fn state_refresh(dispatcher: Arc<Dispatcher>, mut shutdown: watch::Receiver<bool>) {
    let mut interval = tokio::time::interval(Duration::from_secs(10));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // Skip first tick
    interval.tick().await;

    loop {
        tokio::select! {
            _ = interval.tick() => {},
            _ = shutdown.changed() => break,
        }
        if *shutdown.borrow() {
            break;
        }

        if let Err(e) = dispatcher.state.refresh_from_redis(&dispatcher.queue).await {
            warn!(err = %e, "State refresh failed");
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn crack_dedup_key(hash: &ares_core::models::Hash) -> String {
    let prefix = &hash.hash_value[..32.min(hash.hash_value.len())];
    format!(
        "{}:{}:{}",
        hash.domain.to_lowercase(),
        hash.username.to_lowercase(),
        prefix
    )
}
