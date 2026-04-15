use std::sync::Arc;

use tokio::sync::watch;
use tracing::info;

use crate::automation;
use crate::dispatcher::Dispatcher;

/// Spawn all automation background tasks. Returns their JoinHandles.
pub(crate) fn spawn_automation_tasks(
    dispatcher: Arc<Dispatcher>,
    shutdown_rx: watch::Receiver<bool>,
) -> Vec<tokio::task::JoinHandle<()>> {
    let mut handles = Vec::new();

    macro_rules! spawn_auto {
        ($name:ident) => {{
            let d = dispatcher.clone();
            let s = shutdown_rx.clone();
            handles.push(tokio::spawn(async move {
                automation::$name(d, s).await;
            }));
        }};
    }

    spawn_auto!(auto_crack_dispatch);
    spawn_auto!(auto_mssql_detection);
    spawn_auto!(auto_adcs_enumeration);
    spawn_auto!(auto_share_enumeration);
    spawn_auto!(auto_share_spider);
    spawn_auto!(auto_bloodhound);
    spawn_auto!(auto_delegation_enumeration);
    spawn_auto!(auto_coercion);
    spawn_auto!(auto_local_admin_secretsdump);
    spawn_auto!(auto_credential_access);
    spawn_auto!(auto_credential_expansion);
    spawn_auto!(auto_golden_ticket);
    spawn_auto!(auto_acl_chain_follow);
    spawn_auto!(auto_trust_follow);
    spawn_auto!(auto_s4u_exploitation);
    spawn_auto!(auto_gmsa_extraction);
    spawn_auto!(auto_unconstrained_exploitation);
    spawn_auto!(auto_stall_detection);

    info!(count = handles.len(), "Automation tasks spawned");
    handles
}
