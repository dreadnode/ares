"""
Investigation Persistence and Learning System.

Stores investigation results for learning and provides
similarity-based lookup for new alerts.
"""

from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any, ClassVar

if TYPE_CHECKING:
    from collections.abc import Generator

    from ares.core.models import InvestigationState

import dreadnode as dn
from loguru import logger


@dataclass
class StoredInvestigation:
    """A persisted investigation record."""

    investigation_id: str
    alert_name: str
    alert_fingerprint: str  # Unique identifier for this alert type
    severity: str
    technique_id: str | None
    technique_name: str | None

    # Timestamps
    started_at: datetime
    completed_at: datetime
    duration_seconds: float

    # Results
    status: str  # completed, escalated, timeout, failed
    evidence_count: int
    highest_pyramid_level: int
    techniques_identified: list[str]

    # Learning data
    queries_executed: list[dict]
    query_success_rate: float  # % of queries that returned results
    effective_queries: list[str]  # Queries that produced evidence

    # Outcome assessment
    is_true_positive: bool | None = None  # Manual label if available
    analyst_notes: str | None = None

    # Metadata
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for storage."""
        return {
            "investigation_id": self.investigation_id,
            "alert_name": self.alert_name,
            "alert_fingerprint": self.alert_fingerprint,
            "severity": self.severity,
            "technique_id": self.technique_id,
            "technique_name": self.technique_name,
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat(),
            "duration_seconds": self.duration_seconds,
            "status": self.status,
            "evidence_count": self.evidence_count,
            "highest_pyramid_level": self.highest_pyramid_level,
            "techniques_identified": self.techniques_identified,
            "queries_executed": self.queries_executed,
            "query_success_rate": self.query_success_rate,
            "effective_queries": self.effective_queries,
            "is_true_positive": self.is_true_positive,
            "analyst_notes": self.analyst_notes,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> StoredInvestigation:
        """Create from dictionary."""
        return cls(
            investigation_id=data["investigation_id"],
            alert_name=data["alert_name"],
            alert_fingerprint=data["alert_fingerprint"],
            severity=data["severity"],
            technique_id=data.get("technique_id"),
            technique_name=data.get("technique_name"),
            started_at=datetime.fromisoformat(data["started_at"]),
            completed_at=datetime.fromisoformat(data["completed_at"]),
            duration_seconds=data["duration_seconds"],
            status=data["status"],
            evidence_count=data["evidence_count"],
            highest_pyramid_level=data["highest_pyramid_level"],
            techniques_identified=data.get("techniques_identified", []),
            queries_executed=data.get("queries_executed", []),
            query_success_rate=data.get("query_success_rate", 0.0),
            effective_queries=data.get("effective_queries", []),
            is_true_positive=data.get("is_true_positive"),
            analyst_notes=data.get("analyst_notes"),
            metadata=data.get("metadata", {}),
        )


@dataclass
class QueryEffectiveness:
    """Statistics about query effectiveness."""

    query_pattern: str  # Normalized query pattern
    total_executions: int
    successful_executions: int  # Returned results
    evidence_producing: int  # Led to recorded evidence
    alert_types: list[str]  # Alert names where this query was used

    @property
    def success_rate(self) -> float:
        if self.total_executions == 0:
            return 0.0
        return self.successful_executions / self.total_executions

    @property
    def evidence_rate(self) -> float:
        if self.total_executions == 0:
            return 0.0
        return self.evidence_producing / self.total_executions


@dataclass
class SimilarInvestigation:
    """A similar past investigation."""

    investigation: StoredInvestigation
    similarity_score: float
    matching_factors: list[str]


class InvestigationStore:
    """SQLite-backed storage for investigations.

    Provides:
    - Persistence of investigation results
    - Query effectiveness tracking
    - Similar investigation lookup
    - False positive learning
    """

    SCHEMA_VERSION = 1

    # Table names
    TABLE_INVESTIGATIONS = "investigations"
    TABLE_QUERY_EFFECTIVENESS = "query_effectiveness"
    TABLE_SCHEMA_INFO = "schema_info"

    # Column definitions for investigations table
    INVESTIGATIONS_COLUMNS: ClassVar[list[str]] = [
        "investigation_id",
        "alert_name",
        "alert_fingerprint",
        "severity",
        "technique_id",
        "technique_name",
        "started_at",
        "completed_at",
        "duration_seconds",
        "status",
        "evidence_count",
        "highest_pyramid_level",
        "techniques_identified",
        "queries_executed",
        "query_success_rate",
        "effective_queries",
        "is_true_positive",
        "analyst_notes",
        "metadata",
    ]

    # Schema SQL
    SQL_CREATE_INVESTIGATIONS = """
        CREATE TABLE IF NOT EXISTS investigations (
            investigation_id TEXT PRIMARY KEY,
            alert_name TEXT NOT NULL,
            alert_fingerprint TEXT NOT NULL,
            severity TEXT,
            technique_id TEXT,
            technique_name TEXT,
            started_at TEXT NOT NULL,
            completed_at TEXT NOT NULL,
            duration_seconds REAL,
            status TEXT NOT NULL,
            evidence_count INTEGER DEFAULT 0,
            highest_pyramid_level INTEGER DEFAULT 0,
            techniques_identified TEXT,
            queries_executed TEXT,
            query_success_rate REAL DEFAULT 0.0,
            effective_queries TEXT,
            is_true_positive INTEGER,
            analyst_notes TEXT,
            metadata TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """

    SQL_CREATE_QUERY_EFFECTIVENESS = """
        CREATE TABLE IF NOT EXISTS query_effectiveness (
            query_pattern TEXT PRIMARY KEY,
            total_executions INTEGER DEFAULT 0,
            successful_executions INTEGER DEFAULT 0,
            evidence_producing INTEGER DEFAULT 0,
            alert_types TEXT,
            last_used TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """

    SQL_CREATE_SCHEMA_INFO = """
        CREATE TABLE IF NOT EXISTS schema_info (
            key TEXT PRIMARY KEY,
            value TEXT
        )
    """

    # Index SQL
    SQL_CREATE_INDEXES: ClassVar[list[str]] = [
        "CREATE INDEX IF NOT EXISTS idx_alert_fingerprint ON investigations(alert_fingerprint)",
        "CREATE INDEX IF NOT EXISTS idx_technique_id ON investigations(technique_id)",
        "CREATE INDEX IF NOT EXISTS idx_alert_name ON investigations(alert_name)",
    ]

    # Query SQL templates (columns are hardcoded constants, not user input)
    SQL_INSERT_INVESTIGATION = """
        INSERT OR REPLACE INTO investigations ({columns})
        VALUES ({placeholders})
    """.format(  # noqa: S608
        columns=", ".join(INVESTIGATIONS_COLUMNS),
        placeholders=", ".join("?" * len(INVESTIGATIONS_COLUMNS)),
    )

    SQL_SELECT_INVESTIGATION = "SELECT * FROM investigations WHERE investigation_id = ?"

    SQL_SELECT_RECENT_INVESTIGATIONS = (
        "SELECT * FROM investigations ORDER BY completed_at DESC LIMIT ?"
    )

    SQL_UPDATE_LABEL = """
        UPDATE investigations SET
            is_true_positive = ?,
            analyst_notes = COALESCE(?, analyst_notes)
        WHERE investigation_id = ?
    """

    SQL_SELECT_QUERY_EFFECTIVENESS = "SELECT * FROM query_effectiveness WHERE query_pattern = ?"

    SQL_UPDATE_QUERY_EFFECTIVENESS = """
        UPDATE query_effectiveness SET
            total_executions = total_executions + 1,
            successful_executions = successful_executions + ?,
            evidence_producing = evidence_producing + ?,
            alert_types = ?,
            last_used = ?
        WHERE query_pattern = ?
    """

    SQL_INSERT_QUERY_EFFECTIVENESS = """
        INSERT INTO query_effectiveness (
            query_pattern, total_executions, successful_executions,
            evidence_producing, alert_types, last_used
        ) VALUES (?, 1, ?, ?, ?, ?)
    """

    SQL_SELECT_EFFECTIVE_QUERIES = """
        SELECT *,
            CAST(evidence_producing AS REAL) / NULLIF(total_executions, 0) as evidence_rate
        FROM query_effectiveness
        WHERE total_executions >= 3
        ORDER BY evidence_rate DESC
        LIMIT ?
    """

    SQL_SELECT_FALSE_POSITIVE_PATTERNS = """
        SELECT
            alert_name,
            alert_fingerprint,
            technique_id,
            COUNT(*) as occurrences,
            AVG(evidence_count) as avg_evidence
        FROM investigations
        WHERE is_true_positive = 0
        GROUP BY alert_fingerprint
        HAVING COUNT(*) >= ?
        ORDER BY occurrences DESC
    """

    def __init__(self, db_path: Path | str):
        """Initialize the store.

        Args:
            db_path: Path to SQLite database file
        """
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    @contextmanager
    def _get_connection(self) -> Generator[sqlite3.Connection, None, None]:
        """Get a database connection."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()

    def _init_schema(self) -> None:
        """Initialize database schema."""
        with self._get_connection() as conn:
            cursor = conn.cursor()

            cursor.execute(self.SQL_CREATE_INVESTIGATIONS)
            cursor.execute(self.SQL_CREATE_QUERY_EFFECTIVENESS)
            cursor.execute(self.SQL_CREATE_SCHEMA_INFO)

            for index_sql in self.SQL_CREATE_INDEXES:
                cursor.execute(index_sql)

            cursor.execute(
                f"INSERT OR REPLACE INTO {self.TABLE_SCHEMA_INFO} (key, value) VALUES (?, ?)",  # noqa: S608
                ("version", str(self.SCHEMA_VERSION)),
            )

            conn.commit()

    def _investigation_to_row(self, investigation: StoredInvestigation) -> tuple:
        """Convert StoredInvestigation to a tuple for database insertion."""
        return (
            investigation.investigation_id,
            investigation.alert_name,
            investigation.alert_fingerprint,
            investigation.severity,
            investigation.technique_id,
            investigation.technique_name,
            investigation.started_at.isoformat(),
            investigation.completed_at.isoformat(),
            investigation.duration_seconds,
            investigation.status,
            investigation.evidence_count,
            investigation.highest_pyramid_level,
            json.dumps(investigation.techniques_identified),
            json.dumps(investigation.queries_executed),
            investigation.query_success_rate,
            json.dumps(investigation.effective_queries),
            1
            if investigation.is_true_positive
            else (0 if investigation.is_true_positive is False else None),
            investigation.analyst_notes,
            json.dumps(investigation.metadata),
        )

    def store_investigation(self, investigation: StoredInvestigation) -> None:
        """Store an investigation.

        Args:
            investigation: Investigation to store
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(self.SQL_INSERT_INVESTIGATION, self._investigation_to_row(investigation))
            conn.commit()
            logger.info(f"Stored investigation {investigation.investigation_id}")
            dn.log_metric("investigations_stored", 1, mode="count")

    def get_investigation(self, investigation_id: str) -> StoredInvestigation | None:
        """Retrieve an investigation by ID.

        Args:
            investigation_id: Investigation ID to retrieve

        Returns:
            StoredInvestigation or None if not found
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(self.SQL_SELECT_INVESTIGATION, (investigation_id,))
            row = cursor.fetchone()
            return self._row_to_investigation(row) if row else None

    def find_similar_investigations(
        self,
        alert_name: str | None = None,
        alert_fingerprint: str | None = None,
        technique_id: str | None = None,
        severity: str | None = None,
        limit: int = 10,
    ) -> list[SimilarInvestigation]:
        """Find similar past investigations.

        Args:
            alert_name: Alert name to match
            alert_fingerprint: Alert fingerprint to match
            technique_id: MITRE technique ID to match
            severity: Severity level to match
            limit: Maximum number of results

        Returns:
            List of SimilarInvestigation objects sorted by similarity
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()

            conditions = []
            params = []

            if alert_fingerprint:
                conditions.append("alert_fingerprint = ?")
                params.append(alert_fingerprint)

            if alert_name:
                conditions.append("alert_name = ?")
                params.append(alert_name)

            if technique_id:
                conditions.append("technique_id = ?")
                params.append(technique_id)

            if severity:
                conditions.append("severity = ?")
                params.append(severity)

            if not conditions:
                cursor.execute(self.SQL_SELECT_RECENT_INVESTIGATIONS, (limit,))
            else:
                where_clause = " OR ".join(conditions)
                query = f"SELECT * FROM investigations WHERE {where_clause} ORDER BY completed_at DESC LIMIT ?"  # noqa: S608  # nosec B608
                cursor.execute(query, (*params, limit * 2))  # nosec B608

            rows = cursor.fetchall()

            similar = []
            for row in rows:
                investigation = self._row_to_investigation(row)
                score, factors = self._calculate_similarity(
                    investigation,
                    alert_name=alert_name,
                    alert_fingerprint=alert_fingerprint,
                    technique_id=technique_id,
                    severity=severity,
                )
                if score > 0:
                    similar.append(
                        SimilarInvestigation(
                            investigation=investigation,
                            similarity_score=score,
                            matching_factors=factors,
                        )
                    )

            similar.sort(key=lambda x: x.similarity_score, reverse=True)
            return similar[:limit]

    def _calculate_similarity(
        self,
        investigation: StoredInvestigation,
        alert_name: str | None = None,
        alert_fingerprint: str | None = None,
        technique_id: str | None = None,
        severity: str | None = None,
    ) -> tuple[float, list[str]]:
        """Calculate similarity score for an investigation.

        Returns:
            Tuple of (score, list of matching factors)
        """
        score = 0.0
        factors = []

        # Fingerprint match is highest weight (same alert type)
        if alert_fingerprint and investigation.alert_fingerprint == alert_fingerprint:
            score += 0.5
            factors.append("same_alert_fingerprint")

        # Alert name match
        if alert_name and investigation.alert_name == alert_name:
            score += 0.3
            factors.append("same_alert_name")

        # Technique match
        if technique_id and investigation.technique_id == technique_id:
            score += 0.15
            factors.append("same_technique")

        # Severity match
        if severity and investigation.severity == severity:
            score += 0.05
            factors.append("same_severity")

        return score, factors

    def _row_to_investigation(self, row: sqlite3.Row) -> StoredInvestigation:
        """Convert a database row to StoredInvestigation."""
        return StoredInvestigation(
            investigation_id=row["investigation_id"],
            alert_name=row["alert_name"],
            alert_fingerprint=row["alert_fingerprint"],
            severity=row["severity"],
            technique_id=row["technique_id"],
            technique_name=row["technique_name"],
            started_at=datetime.fromisoformat(row["started_at"]),
            completed_at=datetime.fromisoformat(row["completed_at"]),
            duration_seconds=row["duration_seconds"],
            status=row["status"],
            evidence_count=row["evidence_count"],
            highest_pyramid_level=row["highest_pyramid_level"],
            techniques_identified=json.loads(row["techniques_identified"] or "[]"),
            queries_executed=json.loads(row["queries_executed"] or "[]"),
            query_success_rate=row["query_success_rate"],
            effective_queries=json.loads(row["effective_queries"] or "[]"),
            is_true_positive=None
            if row["is_true_positive"] is None
            else bool(row["is_true_positive"]),
            analyst_notes=row["analyst_notes"],
            metadata=json.loads(row["metadata"] or "{}"),
        )

    def update_query_effectiveness(
        self,
        query_pattern: str,
        successful: bool,
        produced_evidence: bool,
        alert_type: str,
    ) -> None:
        """Update query effectiveness statistics.

        Args:
            query_pattern: Normalized query pattern
            successful: Whether query returned results
            produced_evidence: Whether query led to recorded evidence
            alert_type: Alert name where query was used
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            now = datetime.now(timezone.utc).isoformat()

            cursor.execute(self.SQL_SELECT_QUERY_EFFECTIVENESS, (query_pattern,))
            row = cursor.fetchone()

            if row:
                alert_types = json.loads(row["alert_types"] or "[]")
                if alert_type not in alert_types:
                    alert_types.append(alert_type)

                cursor.execute(
                    self.SQL_UPDATE_QUERY_EFFECTIVENESS,
                    (
                        1 if successful else 0,
                        1 if produced_evidence else 0,
                        json.dumps(alert_types),
                        now,
                        query_pattern,
                    ),
                )
            else:
                cursor.execute(
                    self.SQL_INSERT_QUERY_EFFECTIVENESS,
                    (
                        query_pattern,
                        1 if successful else 0,
                        1 if produced_evidence else 0,
                        json.dumps([alert_type]),
                        now,
                    ),
                )

            conn.commit()

    def get_effective_queries(
        self,
        alert_type: str | None = None,
        min_evidence_rate: float = 0.3,
        limit: int = 20,
    ) -> list[QueryEffectiveness]:
        """Get most effective queries.

        Args:
            alert_type: Filter by alert type
            min_evidence_rate: Minimum evidence production rate
            limit: Maximum results

        Returns:
            List of QueryEffectiveness objects
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(self.SQL_SELECT_EFFECTIVE_QUERIES, (limit * 2,))

            results = []
            for row in cursor.fetchall():
                alert_types = json.loads(row["alert_types"] or "[]")

                if alert_type and alert_type not in alert_types:
                    continue

                qe = QueryEffectiveness(
                    query_pattern=row["query_pattern"],
                    total_executions=row["total_executions"],
                    successful_executions=row["successful_executions"],
                    evidence_producing=row["evidence_producing"],
                    alert_types=alert_types,
                )

                if qe.evidence_rate >= min_evidence_rate:
                    results.append(qe)

                if len(results) >= limit:
                    break

            return results

    def get_statistics(self) -> dict[str, Any]:
        """Get overall statistics.

        Returns:
            Dictionary with statistics
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()

            # Investigation stats
            cursor.execute("SELECT COUNT(*) as total FROM investigations")
            total_investigations = cursor.fetchone()["total"]

            cursor.execute("SELECT status, COUNT(*) as count FROM investigations GROUP BY status")
            status_counts = {row["status"]: row["count"] for row in cursor.fetchall()}

            cursor.execute("SELECT AVG(evidence_count) as avg_evidence FROM investigations")
            avg_evidence = cursor.fetchone()["avg_evidence"] or 0

            cursor.execute("SELECT AVG(highest_pyramid_level) as avg_pyramid FROM investigations")
            avg_pyramid = cursor.fetchone()["avg_pyramid"] or 0

            cursor.execute("SELECT AVG(duration_seconds) as avg_duration FROM investigations")
            avg_duration = cursor.fetchone()["avg_duration"] or 0

            # Query stats
            cursor.execute("SELECT COUNT(*) as total FROM query_effectiveness")
            total_queries = cursor.fetchone()["total"]

            cursor.execute(
                """
                SELECT AVG(CAST(evidence_producing AS REAL) / NULLIF(total_executions, 0))
                as avg_evidence_rate FROM query_effectiveness
                WHERE total_executions >= 3
                """
            )
            avg_query_evidence_rate = cursor.fetchone()["avg_evidence_rate"] or 0

            # True positive rate (if labeled)
            cursor.execute(
                """
                SELECT
                    COUNT(CASE WHEN is_true_positive = 1 THEN 1 END) as true_positives,
                    COUNT(CASE WHEN is_true_positive = 0 THEN 1 END) as false_positives,
                    COUNT(CASE WHEN is_true_positive IS NOT NULL THEN 1 END) as labeled
                FROM investigations
                """
            )
            tp_row = cursor.fetchone()
            true_positives = tp_row["true_positives"]
            false_positives = tp_row["false_positives"]
            labeled = tp_row["labeled"]

            tp_rate = true_positives / labeled if labeled > 0 else None

            return {
                "total_investigations": total_investigations,
                "status_distribution": status_counts,
                "avg_evidence_count": round(avg_evidence, 1),
                "avg_pyramid_level": round(avg_pyramid, 1),
                "avg_duration_seconds": round(avg_duration, 1),
                "total_query_patterns": total_queries,
                "avg_query_evidence_rate": round(avg_query_evidence_rate * 100, 1)
                if avg_query_evidence_rate
                else 0,
                "labeling": {
                    "true_positives": true_positives,
                    "false_positives": false_positives,
                    "unlabeled": total_investigations - labeled,
                    "true_positive_rate": round(tp_rate * 100, 1) if tp_rate is not None else None,
                },
            }

    def label_investigation(
        self,
        investigation_id: str,
        is_true_positive: bool,
        analyst_notes: str | None = None,
    ) -> bool:
        """Label an investigation as true/false positive.

        Args:
            investigation_id: Investigation to label
            is_true_positive: Whether it was a true positive
            analyst_notes: Optional analyst notes

        Returns:
            True if updated, False if investigation not found
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                self.SQL_UPDATE_LABEL,
                (1 if is_true_positive else 0, analyst_notes, investigation_id),
            )
            conn.commit()

            if cursor.rowcount > 0:
                logger.info(
                    f"Labeled investigation {investigation_id} as "
                    f"{'true' if is_true_positive else 'false'} positive"
                )
                return True
            return False

    def get_false_positive_patterns(self, min_occurrences: int = 3) -> list[dict[str, Any]]:
        """Get patterns from known false positives.

        Args:
            min_occurrences: Minimum occurrences to consider a pattern

        Returns:
            List of false positive patterns
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(self.SQL_SELECT_FALSE_POSITIVE_PATTERNS, (min_occurrences,))

            return [
                {
                    "alert_name": row["alert_name"],
                    "fingerprint": row["alert_fingerprint"],
                    "technique_id": row["technique_id"],
                    "occurrences": row["occurrences"],
                    "avg_evidence": round(row["avg_evidence"], 1),
                    "recommendation": "Consider tuning this alert rule",
                }
                for row in cursor.fetchall()
            ]


def create_stored_investigation_from_state(
    state: InvestigationState,
    status: str,
) -> StoredInvestigation:
    """Create a StoredInvestigation from InvestigationState.

    Args:
        state: Investigation state object
        status: Final status (completed, escalated, timeout, failed)

    Returns:
        StoredInvestigation ready for persistence
    """

    now = datetime.now(timezone.utc)

    # Generate alert fingerprint from labels
    labels = state.alert.get("labels", {})
    fingerprint = labels.get("__alert_rule_uid__") or labels.get("alertname", "unknown")

    queries = state.executed_queries
    if queries:
        successful = sum(1 for q in queries if q.get("result_count", 0) > 0)
        query_success_rate = successful / len(queries)
    else:
        query_success_rate = 0.0

    effective_queries = [
        q.get("query", "") for q in queries if q.get("result_count", 0) > 0 and q.get("query")
    ]

    technique_id = None
    technique_name = None
    if state.identified_techniques:
        technique_id = next(iter(state.identified_techniques))
        technique_name = state.technique_names.get(technique_id)

    return StoredInvestigation(
        investigation_id=state.investigation_id,
        alert_name=labels.get("alertname", "unknown"),
        alert_fingerprint=fingerprint,
        severity=labels.get("severity", "unknown"),
        technique_id=technique_id,
        technique_name=technique_name,
        started_at=state.started_at,
        completed_at=now,
        duration_seconds=(now - state.started_at).total_seconds(),
        status=status,
        evidence_count=len(state.evidence),
        highest_pyramid_level=state.highest_pyramid_level,
        techniques_identified=list(state.identified_techniques),
        queries_executed=queries,
        query_success_rate=query_success_rate,
        effective_queries=effective_queries,
        metadata={
            "escalated": state.escalated,
            "escalation_reason": state.escalation_reason,
            "hosts_investigated": list(state.queried_hosts),
            "users_investigated": list(state.queried_users),
        },
    )


# Global store instance
_store: InvestigationStore | None = None


def get_investigation_store(db_path: Path | str | None = None) -> InvestigationStore:
    """Get or create the global investigation store.

    Args:
        db_path: Path to database file (default: ~/.ares/investigations.db)

    Returns:
        InvestigationStore instance
    """
    global _store

    if _store is None:
        if db_path is None:
            db_path = Path.home() / ".ares" / "investigations.db"
        _store = InvestigationStore(db_path)

    return _store


def reset_investigation_store() -> None:
    """Reset the global store (for testing)."""
    global _store
    _store = None
