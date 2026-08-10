//! Kerberos ticket publishing — store forged inter-realm ccache records in state
//! and Redis so downstream tools can find them when NTLM bind fails.

use anyhow::Result;

use ares_core::models::KerberosTicket;
use ares_core::state::RedisStateReader;

use redis::aio::ConnectionLike;

use crate::orchestrator::state::SharedState;
use crate::orchestrator::task_queue::TaskQueueCore;

impl SharedState {
    /// Store a forged Kerberos ticket in in-memory state and Redis.
    ///
    /// Uses `HSET` (not `HSETNX`) so a freshly-forged ticket always replaces a
    /// stale ccache path for the same `(source, target, username)` triple.
    pub async fn publish_kerberos_ticket(
        &self,
        queue: &TaskQueueCore<impl ConnectionLike + Clone + Send + Sync + 'static>,
        ticket: KerberosTicket,
    ) -> Result<()> {
        let operation_id = self.operation_id().await;
        let reader = RedisStateReader::new(operation_id);
        let mut conn = queue.connection();
        reader.add_kerberos_ticket(&mut conn, &ticket).await?;
        {
            let mut state = self.inner.write().await;
            // Replace any existing entry for the same (source, target, username).
            let key = ticket.dedup_key();
            state.kerberos_tickets.retain(|t| t.dedup_key() != key);
            state.kerberos_tickets.push(ticket);
        }
        Ok(())
    }
}
