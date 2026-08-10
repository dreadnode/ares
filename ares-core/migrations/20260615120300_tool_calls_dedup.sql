-- Migration 004: dedup support for tool_calls batch ingestion.
--
-- The LLM-assigned tool_use_id is the natural unique key for an invocation
-- (assistant emits ToolUse{id, name, input}; the matching ToolResult
-- references the same id). Store it as a column and unique-index it per op
-- so the ingester can INSERT ... ON CONFLICT DO NOTHING.

ALTER TABLE tool_calls
    ADD COLUMN IF NOT EXISTS tool_use_id TEXT;

CREATE UNIQUE INDEX IF NOT EXISTS uq_tool_calls_tool_use
    ON tool_calls (op_id, tool_use_id)
    WHERE tool_use_id IS NOT NULL;
