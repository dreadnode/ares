//! Dedup persistence — mark_exploited, persist_dedup, persist_mssql.

use anyhow::Result;
use redis::AsyncCommands;

use ares_core::models::OpStateEventPayload;
use ares_core::state;

use redis::aio::ConnectionLike;

use super::publishing::emit_op_state;
use super::SharedState;
use crate::orchestrator::task_queue::TaskQueueCore;

impl SharedState {
    /// Mark a vulnerability as exploited.
    pub async fn mark_exploited(
        &self,
        queue: &TaskQueueCore<impl ConnectionLike + Clone + Send + Sync + 'static>,
        vuln_id: &str,
    ) -> Result<()> {
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

        // Phase 2 dual-write: append vuln.exploited event.
        emit_op_state(
            self.recorder(),
            &operation_id,
            OpStateEventPayload::VulnExploited {
                vuln_id: vuln_id.to_string(),
                exploited_by: String::new(),
                result: None,
            },
        )
        .await;

        let mut state = self.inner.write().await;
        state.exploited_vulnerabilities.insert(vuln_id.to_string());
        Ok(())
    }

    /// Persist a dedup set entry to Redis.
    pub async fn persist_dedup(
        &self,
        queue: &TaskQueueCore<impl ConnectionLike + Clone + Send + Sync + 'static>,
        set_name: &str,
        key: &str,
    ) -> Result<()> {
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
    pub async fn persist_mssql_dispatched(
        &self,
        queue: &TaskQueueCore<impl ConnectionLike + Clone + Send + Sync + 'static>,
        ip: &str,
    ) -> Result<()> {
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

#[cfg(test)]
mod tests {
    use crate::orchestrator::state::SharedState;
    use crate::orchestrator::task_queue::TaskQueueCore;
    use ares_core::state::mock_redis::MockRedisConnection;

    fn mock_queue() -> TaskQueueCore<MockRedisConnection> {
        TaskQueueCore::from_connection(MockRedisConnection::new())
    }

    #[tokio::test]
    async fn mark_exploited_adds_to_state_and_redis() {
        let state = SharedState::new("op-1".to_string());
        let q = mock_queue();

        state.mark_exploited(&q, "VULN-001").await.unwrap();

        let s = state.inner.read().await;
        assert!(s.exploited_vulnerabilities.contains("VULN-001"));

        // Verify persisted to Redis
        let mut conn = q.connection();
        let key = "ares:op:op-1:exploited".to_string();
        let members: std::collections::HashSet<String> =
            redis::AsyncCommands::smembers(&mut conn, &key)
                .await
                .unwrap();
        assert!(members.contains("VULN-001"));
    }

    #[tokio::test]
    async fn persist_dedup_stores_in_redis() {
        let state = SharedState::new("op-1".to_string());
        let q = mock_queue();

        state
            .persist_dedup(&q, "cred_spray", "admin@192.168.58.1")
            .await
            .unwrap();

        let mut conn = q.connection();
        let key = "ares:op:op-1:dedup:cred_spray".to_string();
        let members: std::collections::HashSet<String> =
            redis::AsyncCommands::smembers(&mut conn, &key)
                .await
                .unwrap();
        assert!(members.contains("admin@192.168.58.1"));
    }

    #[tokio::test]
    async fn persist_mssql_dispatched_stores_in_redis() {
        let state = SharedState::new("op-1".to_string());
        let q = mock_queue();

        state
            .persist_mssql_dispatched(&q, "192.168.58.5")
            .await
            .unwrap();

        let mut conn = q.connection();
        let key = "ares:op:op-1:mssql_enum_dispatched".to_string();
        let members: std::collections::HashSet<String> =
            redis::AsyncCommands::smembers(&mut conn, &key)
                .await
                .unwrap();
        assert!(members.contains("192.168.58.5"));
    }

    #[tokio::test]
    async fn mark_exploited_emits_event_with_capturing_recorder() {
        use ares_core::models::OpStateEventPayload;
        let recorder = std::sync::Arc::new(ares_core::op_state_log::OpStateRecorder::capturing());
        let state = SharedState::with_recorder("op-ex".to_string(), recorder.clone());
        let q = mock_queue();

        state.mark_exploited(&q, "VULN-007").await.unwrap();

        let evs = recorder.captured().await;
        assert_eq!(evs.len(), 1);
        match &evs[0].payload {
            OpStateEventPayload::VulnExploited { vuln_id, .. } => {
                assert_eq!(vuln_id, "VULN-007");
            }
            other => panic!("expected VulnExploited, got {other:?}"),
        }
    }
}
