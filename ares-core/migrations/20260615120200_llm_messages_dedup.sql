-- Migration 003: dedup support for batch ingestion.
--
-- The JSONL → Postgres ingester runs on a timer and must be re-runnable
-- without producing duplicate rows. Add a unique index covering the
-- natural key (op_id, task_id, turn_idx, role, ts) so the ingester can
-- INSERT ... ON CONFLICT DO NOTHING safely. NULLS NOT DISTINCT (Postgres 15+)
-- makes the index treat NULL turn_idx / task_id as equal for dedup.

CREATE UNIQUE INDEX IF NOT EXISTS uq_llm_messages_natural
    ON llm_messages (op_id, task_id, turn_idx, role, ts) NULLS NOT DISTINCT;
