//! Dedup persistence — mark_exploited, persist_dedup, persist_mssql.

use anyhow::Result;
use redis::AsyncCommands;

use ares_core::state;

use super::SharedState;
use crate::task_queue::TaskQueue;

impl SharedState {
    /// Mark a vulnerability as exploited.
    pub async fn mark_exploited(&self, queue: &TaskQueue, vuln_id: &str) -> Result<()> {
        let operation_id = {
            let state = self.inner.read().await;
            state.operation_id.clone()
        };
        let key = format!(
            "{}:{}:{}",
            state::KEY_PREFIX,
            operation_id,
            state::KEY_EXPLOITED
        );
        let mut conn = queue.connection();
        let _: () = conn.sadd(&key, vuln_id).await?;
        let _: () = conn.expire(&key, 86400).await?;

        let mut state = self.inner.write().await;
        state.exploited_vulnerabilities.insert(vuln_id.to_string());
        Ok(())
    }

    /// Persist a dedup set entry to Redis.
    pub async fn persist_dedup(&self, queue: &TaskQueue, set_name: &str, key: &str) -> Result<()> {
        let operation_id = {
            let state = self.inner.read().await;
            state.operation_id.clone()
        };
        let redis_key = format!(
            "{}:{}:{}:{}",
            state::KEY_PREFIX,
            operation_id,
            state::KEY_DEDUP_PREFIX,
            set_name
        );
        let mut conn = queue.connection();
        let _: () = conn.sadd(&redis_key, key).await?;
        let _: () = conn.expire(&redis_key, 86400).await?;
        Ok(())
    }

    /// Persist MSSQL enum dispatched entry to Redis.
    pub async fn persist_mssql_dispatched(&self, queue: &TaskQueue, ip: &str) -> Result<()> {
        let operation_id = {
            let state = self.inner.read().await;
            state.operation_id.clone()
        };
        let redis_key = format!(
            "{}:{}:{}",
            state::KEY_PREFIX,
            operation_id,
            state::KEY_MSSQL_ENUM_DISPATCHED
        );
        let mut conn = queue.connection();
        let _: () = conn.sadd(&redis_key, ip).await?;
        let _: () = conn.expire(&redis_key, 86400).await?;
        Ok(())
    }
}
