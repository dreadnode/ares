#!/usr/bin/env python3
"""Archive per-op big-artifact files to S3 + record in blob_refs.

Scope: items NOT already captured in Postgres (NTDS dumps, BloodHound
JSON exports, netexec workspace SQLite DBs snapshotted at op completion).
JSONL session logs are intentionally skipped — they're already in
llm_messages / tool_calls via the ingester.

For each operation in `operations` table with `completed_at IS NOT NULL`
and no existing blob_refs row, scan known artifact directories for files
modified during the op's lifetime (started_at → completed_at + 1h grace),
upload to s3://ares-ops-archive-us-west-1/ops/<op_id>/<kind>/<basename>,
and write a blob_refs row.

Conn: ARES_DATABASE_URL env.
Bucket: ARES_OPS_ARCHIVE_BUCKET env (defaults to ares-ops-archive-us-west-1).
"""

from __future__ import annotations

import argparse
import hashlib
import logging
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import psycopg2
import psycopg2.extras

logger = logging.getLogger("ares-archive")

DEFAULT_BUCKET = "ares-ops-archive-us-west-1"

# Where to look for each artifact kind (host paths).
ARTIFACT_SOURCES: dict[str, list[Path]] = {
    "ntds": [Path("/root/.nxc/logs/ntds")],
    "bloodhound": [Path("/root/.nxc/logs/bloodhound"), Path("/root/.bloodhound")],
    "nxc_workspace": [Path("/root/.nxc/workspaces/default")],
}


def sha256_of(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def s3_cp(local: Path, s3_uri: str, region: str) -> None:
    cmd = ["aws", "s3", "cp", str(local), s3_uri, "--region", region, "--only-show-errors"]
    subprocess.run(cmd, check=True)


def find_op_artifacts(started_at, completed_at) -> list[tuple[str, Path]]:
    """Return [(kind, path), ...] of files mtime-within the op's lifetime."""
    grace_s = 3600
    start_ts = started_at.timestamp()
    end_ts = completed_at.timestamp() + grace_s
    out: list[tuple[str, Path]] = []
    for kind, roots in ARTIFACT_SOURCES.items():
        for root in roots:
            if not root.exists():
                continue
            for p in root.rglob("*"):
                if not p.is_file():
                    continue
                try:
                    mt = p.stat().st_mtime
                except OSError:
                    continue
                if start_ts <= mt <= end_ts:
                    out.append((kind, p))
    return out


def archive_op(conn, op_uuid, op_id: str, started_at, completed_at, bucket: str, region: str) -> int:
    """Archive all artifacts for one op. Returns number of files uploaded."""
    files = find_op_artifacts(started_at, completed_at)
    if not files:
        logger.info("op %s: no artifacts in window — recording empty marker", op_id)
        # Insert a marker so we don't keep re-scanning.
        with conn.cursor() as cur:
            cur.execute(
                """INSERT INTO blob_refs (op_id, kind, s3_uri, content_hash, size_bytes, metadata)
                       VALUES (%s, 'archive_empty', %s, NULL, 0, %s)
                       ON CONFLICT (s3_uri) DO NOTHING""",
                (op_id, f"s3://{bucket}/ops/{op_id}/_empty", '{"scanned": true}'),
            )
        conn.commit()
        return 0

    uploaded = 0
    for kind, path in files:
        try:
            size = path.stat().st_size
            sha = sha256_of(path)
            key = f"ops/{op_id}/{kind}/{path.name}"
            s3_uri = f"s3://{bucket}/{key}"
            logger.info("uploading %s (%d bytes, sha=%s) -> %s", path, size, sha[:12], s3_uri)
            s3_cp(path, s3_uri, region)
            with conn.cursor() as cur:
                cur.execute(
                    """INSERT INTO blob_refs (op_id, kind, s3_uri, content_hash, size_bytes, metadata)
                           VALUES (%s, %s, %s, %s, %s, %s)
                       ON CONFLICT (s3_uri) DO NOTHING""",
                    (op_id, kind, s3_uri, sha, size, '{"source_path": "%s"}' % path),
                )
            uploaded += 1
        except Exception:
            logger.exception("failed to upload %s", path)
            conn.rollback()
            continue
    conn.commit()
    return uploaded


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bucket", default=os.environ.get("ARES_OPS_ARCHIVE_BUCKET", DEFAULT_BUCKET))
    parser.add_argument("--region", default=os.environ.get("AWS_REGION", "us-west-1"))
    parser.add_argument("--log-level", default=os.environ.get("ARES_ARCHIVE_LOG_LEVEL", "INFO"))
    args = parser.parse_args(argv)
    logging.basicConfig(
        level=args.log_level.upper(),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    db_url = os.environ.get("ARES_DATABASE_URL")
    if not db_url:
        logger.error("ARES_DATABASE_URL not set")
        return 2

    if shutil.which("aws") is None:
        logger.error("aws CLI not found on PATH")
        return 2

    conn = psycopg2.connect(db_url)
    try:
        # Find completed ops with no blob_refs row yet.
        with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as cur:
            cur.execute(
                """SELECT o.id, o.operation_id, o.started_at, o.completed_at
                     FROM operations o
                    WHERE o.completed_at IS NOT NULL
                      AND NOT EXISTS (
                            SELECT 1 FROM blob_refs b
                             WHERE b.op_id = o.operation_id
                          )
                    ORDER BY o.completed_at ASC
                    LIMIT 25"""
            )
            ops = cur.fetchall()
        if not ops:
            logger.info("no unarchived completed ops")
            return 0
        for row in ops:
            archive_op(
                conn,
                row["id"],
                row["operation_id"],
                row["started_at"],
                row["completed_at"],
                args.bucket,
                args.region,
            )
    finally:
        conn.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
