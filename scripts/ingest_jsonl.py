#!/usr/bin/env python3
"""Batch-ingest Ares session JSONL files into Postgres.

Reads `$SESSION_LOG_DIR/<op_id>/<task_id>.jsonl` files and inserts each
LLM message into the `llm_messages` table. Idempotent: re-runs against
the same data produce no duplicate rows (relies on uq_llm_messages_natural).

Connection: `ARES_DATABASE_URL` env var (postgresql://...).

Run modes:
  - default: scan SESSION_LOG_DIR, ingest all new lines
  - --files <path...>: ingest a specific list of files
  - --since <iso8601>: only consider files modified after the given time

Usage entries (kind=usage) update token counts on the matching assistant
row by (op_id, task_id, turn_idx).
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from pathlib import Path
from typing import Iterable

import psycopg2
import psycopg2.extras

logger = logging.getLogger("ares-ingest")

MESSAGE_KINDS = {"user", "assistant", "tool_result", "system"}


def iter_jsonl(path: Path) -> Iterable[dict]:
    """Yield parsed JSON objects from a .jsonl file, skipping bad lines."""
    try:
        with path.open("r", encoding="utf-8") as fh:
            for lineno, raw in enumerate(fh, start=1):
                raw = raw.strip()
                if not raw:
                    continue
                try:
                    yield json.loads(raw)
                except json.JSONDecodeError as e:
                    logger.warning("skip %s:%d (parse error: %s)", path, lineno, e)
    except OSError as e:
        logger.warning("skip %s (open error: %s)", path, e)


def map_role(kind: str, data: dict) -> str:
    """Map JSONL kind to llm_messages.role column."""
    if kind == "tool_result":
        return "tool"
    if kind in ("user", "assistant", "system"):
        # data may carry its own role; trust it when present, else fall back.
        return str(data.get("role", kind))
    return kind


def upsert_messages(conn, entries: list[dict]) -> tuple[int, int]:
    """Insert message rows from a single JSONL file.

    Returns (inserted_count, skipped_count). Skipped includes both
    on-conflict rows and non-message kinds.
    """
    inserted = 0
    skipped = 0
    rows = []
    for e in entries:
        kind = e.get("kind")
        if kind not in MESSAGE_KINDS:
            skipped += 1
            continue
        data = e.get("data") or {}
        rows.append(
            (
                e.get("op_id"),
                e.get("task_id"),
                e.get("role"),  # agent role (recon/cracker/etc.)
                e.get("step"),
                map_role(kind, data),
                e.get("model"),
                json.dumps(data) if data is not None else None,
                e.get("ts"),
                e.get("team", "red"),
            )
        )
    if not rows:
        return inserted, skipped

    # Use column-list form (not ON CONSTRAINT) — uq_llm_messages_natural is a
    # unique INDEX, not a CONSTRAINT, so name lookup fails. Postgres still uses
    # the matching unique index for arbitration with the column-list form.
    sql = """
        INSERT INTO llm_messages (
            op_id, task_id, worker, turn_idx, role, model, request, ts, team
        ) VALUES %s
        ON CONFLICT (op_id, task_id, turn_idx, role, ts) DO NOTHING
    """
    with conn.cursor() as cur:
        result = psycopg2.extras.execute_values(
            cur, sql, rows, template=None, fetch=False
        )
        inserted = cur.rowcount  # rows actually inserted (excludes conflicts)
    return inserted, skipped


def apply_usage(conn, entries: list[dict]) -> int:
    """Backfill token + cost columns from usage entries onto matching rows."""
    updates = []
    for e in entries:
        if e.get("kind") != "usage":
            continue
        d = e.get("data") or {}
        updates.append(
            (
                d.get("input_tokens"),
                d.get("output_tokens"),
                (d.get("input_tokens") or 0) + (d.get("output_tokens") or 0),
                e.get("op_id"),
                e.get("task_id"),
                e.get("step"),
            )
        )
    if not updates:
        return 0
    sql = """
        UPDATE llm_messages
           SET prompt_tokens = COALESCE(prompt_tokens, %s),
               completion_tokens = COALESCE(completion_tokens, %s),
               total_tokens = COALESCE(total_tokens, %s)
         WHERE op_id = %s AND task_id IS NOT DISTINCT FROM %s
           AND turn_idx = %s AND role = 'assistant'
    """
    touched = 0
    with conn.cursor() as cur:
        for u in updates:
            cur.execute(sql, u)
            touched += cur.rowcount
    return touched


def upsert_tool_calls(conn, entries: list[dict]) -> int:
    """Derive tool_calls rows by pairing assistant ToolUse with later ToolResult.

    Each pending ToolUse is keyed by (task_id, tool_use_id) and resolved on
    the next ToolResult referencing the same id. Unresolved ToolUses are
    still inserted with duration_ms=NULL — they remain queryable.
    """
    pending: dict[tuple[str | None, str], dict] = {}
    rows: list[tuple] = []

    from datetime import datetime, timezone

    def parse_ts(s: str | None):
        if not s:
            return None
        try:
            return datetime.fromisoformat(s.replace("Z", "+00:00"))
        except ValueError:
            return None

    def flush(call: dict, result_part: dict | None, result_ts: datetime | None):
        start_ts = parse_ts(call["ts"])
        duration_ms = None
        if start_ts and result_ts:
            duration_ms = max(0, int((result_ts - start_ts).total_seconds() * 1000))
        result_json = None
        if result_part is not None:
            # ToolResult.content is a free-form string; store as JSONB with a
            # consistent shape so it's queryable.
            result_json = json.dumps({
                "content": result_part.get("content"),
                "tool_use_id": result_part.get("tool_use_id"),
            })
        rows.append((
            call["op_id"],
            call["task_id"],
            call["worker"],
            call["tool_name"],
            json.dumps(call["arguments"]) if call["arguments"] is not None else None,
            result_json,
            duration_ms,
            None,  # exit_status — not directly available; left NULL
            None,  # error_kind
            call["ts"],
            call["tool_use_id"],
            call.get("team", "red"),
        ))

    for e in entries:
        kind = e.get("kind")
        data = e.get("data") or {}
        parts = data.get("parts") if isinstance(data, dict) else None
        if not isinstance(parts, list):
            continue
        op_id = e.get("op_id")
        task_id = e.get("task_id")
        worker = e.get("role")  # agent role
        ts = e.get("ts")
        if kind == "assistant":
            for part in parts:
                if not isinstance(part, dict):
                    continue
                if part.get("type") != "tool_use":
                    continue
                tool_use_id = part.get("id")
                if not tool_use_id:
                    continue
                pending[(task_id, tool_use_id)] = {
                    "op_id": op_id,
                    "task_id": task_id,
                    "worker": worker,
                    "team": e.get("team", "red"),
                    "tool_name": part.get("name"),
                    "arguments": part.get("input"),
                    "ts": ts,
                    "tool_use_id": tool_use_id,
                }
        elif kind == "tool_result":
            result_ts = parse_ts(ts)
            for part in parts:
                if not isinstance(part, dict):
                    continue
                if part.get("type") != "tool_result":
                    continue
                tu_id = part.get("tool_use_id")
                if not tu_id:
                    continue
                call = pending.pop((task_id, tu_id), None)
                if call is None:
                    continue
                flush(call, part, result_ts)

    # Flush any unresolved ToolUses (no matching result in this file).
    for call in pending.values():
        flush(call, None, None)

    if not rows:
        return 0

    # Column-list form for same reason as llm_messages above. The partial index
    # predicate (WHERE tool_use_id IS NOT NULL) is automatically matched by
    # Postgres since every row we insert here carries a non-null tool_use_id.
    sql = """
        INSERT INTO tool_calls (
            op_id, task_id, worker, tool_name, arguments, result,
            duration_ms, exit_status, error_kind, ts, tool_use_id, team
        ) VALUES %s
        ON CONFLICT (op_id, tool_use_id) WHERE tool_use_id IS NOT NULL DO NOTHING
    """
    with conn.cursor() as cur:
        psycopg2.extras.execute_values(cur, sql, rows, template=None, fetch=False)
        return cur.rowcount


def ingest_file(conn, path: Path) -> None:
    entries = list(iter_jsonl(path))
    if not entries:
        return
    inserted, skipped = upsert_messages(conn, entries)
    updated = apply_usage(conn, entries)
    tools_inserted = upsert_tool_calls(conn, entries)
    conn.commit()
    logger.info(
        "ingested %s: msg_inserted=%d msg_skipped=%d usage_updated=%d tool_calls_inserted=%d",
        path, inserted, skipped, updated, tools_inserted,
    )


def find_jsonl_files(root: Path, since_mtime: float | None) -> list[Path]:
    if not root.exists():
        return []
    out = []
    for p in root.rglob("*.jsonl"):
        if since_mtime is not None and p.stat().st_mtime < since_mtime:
            continue
        out.append(p)
    return sorted(out)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--dir",
        default=os.environ.get("SESSION_LOG_DIR", "/var/log/ares/session"),
        help="root directory of session logs",
    )
    parser.add_argument(
        "--files", nargs="*", default=None, help="explicit files to ingest"
    )
    parser.add_argument(
        "--since-seconds",
        type=int,
        default=None,
        help="only ingest files modified within the last N seconds",
    )
    parser.add_argument(
        "--log-level", default=os.environ.get("ARES_INGEST_LOG_LEVEL", "INFO")
    )
    args = parser.parse_args(argv)
    logging.basicConfig(
        level=args.log_level.upper(),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    db_url = os.environ.get("ARES_DATABASE_URL")
    if not db_url:
        logger.error("ARES_DATABASE_URL not set; cannot ingest")
        return 2

    if args.files:
        files = [Path(f) for f in args.files]
    else:
        since_mtime = None
        if args.since_seconds is not None:
            import time
            since_mtime = time.time() - args.since_seconds
        files = find_jsonl_files(Path(args.dir), since_mtime)

    if not files:
        logger.info("no JSONL files to ingest under %s", args.dir)
        return 0

    conn = psycopg2.connect(db_url)
    try:
        for f in files:
            try:
                ingest_file(conn, f)
            except Exception as e:
                conn.rollback()
                logger.exception("failed ingesting %s: %s", f, e)
    finally:
        conn.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
