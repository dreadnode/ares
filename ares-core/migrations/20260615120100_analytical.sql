-- Migration 002: analytical tables for cross-run statistical analysis.
--
-- Adds the per-event tables that make ares-history the canonical store for
-- Blackhat-talk-quality data: every LLM message, every tool call, every
-- worker event, every OTEL span, every log line, plus blob references for
-- artifacts too large to inline as JSONB.
--
-- All event tables index (op_id, ts) for dataframe extraction. JSONB for
-- payload flexibility + queryability via -> and ->> operators.

-- ============================================================================
-- LLM messages — every prompt/completion from every agent
-- ============================================================================

CREATE TABLE IF NOT EXISTS llm_messages (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    op_id               TEXT NOT NULL,
    task_id             TEXT,
    worker              TEXT,              -- recon / cracker / orchestrator / etc.
    turn_idx            INTEGER,           -- monotonic within (op_id, task_id)
    role                TEXT NOT NULL,     -- system / user / assistant / tool
    model               TEXT,              -- model id used for this turn
    request             JSONB,             -- raw request payload (messages, params)
    response            JSONB,             -- raw response payload (content, tool_calls)
    prompt_tokens       INTEGER,
    completion_tokens   INTEGER,
    total_tokens        INTEGER,
    latency_ms          INTEGER,
    cost_usd            NUMERIC(10, 6),
    ts                  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_llm_messages_op_ts ON llm_messages (op_id, ts);
CREATE INDEX IF NOT EXISTS idx_llm_messages_task ON llm_messages (op_id, task_id);
CREATE INDEX IF NOT EXISTS idx_llm_messages_worker ON llm_messages (worker, ts);
CREATE INDEX IF NOT EXISTS idx_llm_messages_model ON llm_messages (model);

-- ============================================================================
-- Tool calls — every netexec / nmap / impacket / etc. invocation
-- ============================================================================

CREATE TABLE IF NOT EXISTS tool_calls (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    op_id               TEXT NOT NULL,
    task_id             TEXT,
    worker              TEXT,
    tool_name           TEXT NOT NULL,
    arguments           JSONB,
    result              JSONB,
    duration_ms         INTEGER,
    exit_status         TEXT,              -- success / error / timeout / cancelled
    error_kind          TEXT,
    ts                  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_tool_calls_op_ts ON tool_calls (op_id, ts);
CREATE INDEX IF NOT EXISTS idx_tool_calls_worker_tool ON tool_calls (worker, tool_name, ts);
CREATE INDEX IF NOT EXISTS idx_tool_calls_status ON tool_calls (exit_status);

-- ============================================================================
-- Worker events — structured replacement for orchestrator.log freeform text
-- ============================================================================

CREATE TABLE IF NOT EXISTS worker_events (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    op_id               TEXT NOT NULL,
    task_id             TEXT,
    worker              TEXT,
    event_type          TEXT NOT NULL,     -- task_dispatched / task_completed / state_mutation / etc.
    payload             JSONB,
    ts                  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_worker_events_op_ts ON worker_events (op_id, ts);
CREATE INDEX IF NOT EXISTS idx_worker_events_type ON worker_events (event_type, ts);

-- ============================================================================
-- OTEL spans — denormalized for dataframe extraction
-- ============================================================================

CREATE TABLE IF NOT EXISTS otel_spans (
    span_id             TEXT PRIMARY KEY,
    trace_id            TEXT NOT NULL,
    parent_span_id      TEXT,
    op_id               TEXT,
    task_id             TEXT,
    name                TEXT NOT NULL,
    kind                TEXT,              -- internal / server / client / producer / consumer
    start_ts            TIMESTAMPTZ NOT NULL,
    end_ts              TIMESTAMPTZ,
    duration_ms         INTEGER,
    attributes          JSONB,
    events              JSONB,
    status_code         TEXT,
    status_message      TEXT
);

CREATE INDEX IF NOT EXISTS idx_otel_spans_trace ON otel_spans (trace_id);
CREATE INDEX IF NOT EXISTS idx_otel_spans_op_ts ON otel_spans (op_id, start_ts);
CREATE INDEX IF NOT EXISTS idx_otel_spans_name ON otel_spans (name, start_ts);

-- ============================================================================
-- Log lines — structured stderr from orchestrator + workers
-- ============================================================================

CREATE TABLE IF NOT EXISTS log_lines (
    id                  BIGSERIAL PRIMARY KEY,
    op_id               TEXT,
    task_id             TEXT,
    worker              TEXT,
    level               TEXT NOT NULL,     -- ERROR / WARN / INFO / DEBUG / TRACE
    target              TEXT,              -- tracing target (module path)
    message             TEXT,
    fields              JSONB,
    ts                  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_log_lines_op_ts ON log_lines (op_id, ts);
CREATE INDEX IF NOT EXISTS idx_log_lines_level_ts ON log_lines (level, ts);
CREATE INDEX IF NOT EXISTS idx_log_lines_worker_ts ON log_lines (worker, ts);

-- ============================================================================
-- Blob refs — S3 pointers for artifacts too large for JSONB
-- ============================================================================

CREATE TABLE IF NOT EXISTS blob_refs (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    op_id               TEXT NOT NULL,
    task_id             TEXT,
    kind                TEXT NOT NULL,     -- ntds / bloodhound / nxc_db / redis_rdb / report / etc.
    s3_uri              TEXT NOT NULL,
    content_hash        TEXT,              -- sha256 hex
    size_bytes          BIGINT,
    metadata            JSONB,
    ts                  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_blob_refs_s3uri ON blob_refs (s3_uri);
CREATE INDEX IF NOT EXISTS idx_blob_refs_op_kind ON blob_refs (op_id, kind);
