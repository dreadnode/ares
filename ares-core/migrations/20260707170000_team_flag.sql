-- Add a red/blue team flag to the activity tables so red-team ops and blue-team
-- (benchmark investigation) activity are separable for statistical analysis —
-- e.g. `SELECT team, op_id, sum(total_tokens) FROM llm_messages GROUP BY 1,2`.
--
-- All existing rows are red-team activity, so DEFAULT 'red'. Blue rows are
-- stamped 'blue' by the SessionLog (ARES_SESSION_TEAM=blue) and carried through
-- by scripts/ingest_jsonl.py. Blue benchmark rows file under the *replayed*
-- op_id (join to red on op_id) with task_id = the run/investigation id (per-run
-- separability), so both cross-team correlation and per-run stats work.

ALTER TABLE llm_messages  ADD COLUMN IF NOT EXISTS team TEXT NOT NULL DEFAULT 'red';
ALTER TABLE tool_calls    ADD COLUMN IF NOT EXISTS team TEXT NOT NULL DEFAULT 'red';
ALTER TABLE worker_events ADD COLUMN IF NOT EXISTS team TEXT NOT NULL DEFAULT 'red';
ALTER TABLE log_lines     ADD COLUMN IF NOT EXISTS team TEXT NOT NULL DEFAULT 'red';
ALTER TABLE otel_spans    ADD COLUMN IF NOT EXISTS team TEXT NOT NULL DEFAULT 'red';

CREATE INDEX IF NOT EXISTS idx_llm_messages_team ON llm_messages (team);
CREATE INDEX IF NOT EXISTS idx_tool_calls_team ON tool_calls (team);
