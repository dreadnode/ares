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

    /// Increment a vulnerability type failure counter in Redis.
    ///
    /// Returns the new failure count. Matches Python's `vuln_type_failures` HINCRBY.
    pub async fn increment_vuln_failure(&self, queue: &TaskQueue, vuln_type: &str) -> Result<i64> {
        let operation_id = {
            let state = self.inner.read().await;
            state.operation_id.clone()
        };
        let reader = ares_core::state::RedisStateReader::new(operation_id);
        let mut conn = queue.connection();
        let count = reader
            .increment_vuln_type_failure(&mut conn, vuln_type)
            .await?;
        Ok(count)
    }

    /// Check if a vulnerability type has exceeded its max failures.
    pub async fn vuln_type_exceeded_failures(
        &self,
        queue: &TaskQueue,
        vuln_type: &str,
        max_failures: i64,
    ) -> Result<bool> {
        let operation_id = {
            let state = self.inner.read().await;
            state.operation_id.clone()
        };
        let reader = ares_core::state::RedisStateReader::new(operation_id);
        let mut conn = queue.connection();
        let count = reader
            .get_vuln_type_failure_count(&mut conn, vuln_type)
            .await?;
        Ok(count >= max_failures)
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
