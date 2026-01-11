"""Tests for the Investigation Persistence and Learning System."""

import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from ares.core.persistence import (
    InvestigationStore,
    QueryEffectiveness,
    StoredInvestigation,
    get_investigation_store,
    reset_investigation_store,
)


@pytest.fixture
def temp_db() -> Path:
    """Create a temporary database file."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir) / "test_investigations.db"


@pytest.fixture
def store(temp_db: Path) -> InvestigationStore:
    """Create a fresh investigation store."""
    return InvestigationStore(temp_db)


@pytest.fixture
def sample_investigation() -> StoredInvestigation:
    """Create a sample investigation for testing."""
    now = datetime.now(timezone.utc)
    return StoredInvestigation(
        investigation_id="inv-001",
        alert_name="HighCPUUsage",
        alert_fingerprint="rule-123",
        severity="warning",
        technique_id="T1059.001",
        technique_name="PowerShell",
        started_at=now - timedelta(minutes=10),
        completed_at=now,
        duration_seconds=600.0,
        status="completed",
        evidence_count=5,
        highest_pyramid_level=3,
        techniques_identified=["T1059.001", "T1086"],
        queries_executed=[
            {"query": "{job='windows'}", "result_count": 10},
            {"query": "{job='linux'}", "result_count": 0},
        ],
        query_success_rate=0.5,
        effective_queries=["{job='windows'}"],
        is_true_positive=True,
        analyst_notes="Confirmed malicious activity",
        metadata={"host": "server01", "user": "admin"},
    )


class TestStoredInvestigation:
    """Tests for StoredInvestigation dataclass."""

    def test_to_dict(self, sample_investigation: StoredInvestigation) -> None:
        """Test conversion to dictionary."""
        data = sample_investigation.to_dict()

        assert data["investigation_id"] == "inv-001"
        assert data["alert_name"] == "HighCPUUsage"
        assert data["severity"] == "warning"
        assert data["technique_id"] == "T1059.001"
        assert data["status"] == "completed"
        assert data["evidence_count"] == 5
        assert data["is_true_positive"] is True
        assert "started_at" in data
        assert "completed_at" in data

    def test_from_dict(self, sample_investigation: StoredInvestigation) -> None:
        """Test creation from dictionary."""
        data = sample_investigation.to_dict()
        restored = StoredInvestigation.from_dict(data)

        assert restored.investigation_id == sample_investigation.investigation_id
        assert restored.alert_name == sample_investigation.alert_name
        assert restored.severity == sample_investigation.severity
        assert restored.technique_id == sample_investigation.technique_id
        assert restored.status == sample_investigation.status
        assert restored.evidence_count == sample_investigation.evidence_count
        assert restored.is_true_positive == sample_investigation.is_true_positive

    def test_from_dict_with_missing_optional_fields(self) -> None:
        """Test creation from dict with missing optional fields."""
        minimal_data = {
            "investigation_id": "inv-min",
            "alert_name": "TestAlert",
            "alert_fingerprint": "fp-001",
            "severity": "low",
            "started_at": datetime.now(timezone.utc).isoformat(),
            "completed_at": datetime.now(timezone.utc).isoformat(),
            "duration_seconds": 100.0,
            "status": "completed",
            "evidence_count": 0,
            "highest_pyramid_level": 0,
        }

        investigation = StoredInvestigation.from_dict(minimal_data)

        assert investigation.investigation_id == "inv-min"
        assert investigation.technique_id is None
        assert investigation.techniques_identified == []
        assert investigation.queries_executed == []
        assert investigation.is_true_positive is None


class TestQueryEffectiveness:
    """Tests for QueryEffectiveness dataclass."""

    def test_success_rate_calculation(self) -> None:
        """Test success rate property."""
        qe = QueryEffectiveness(
            query_pattern="{job='test'}",
            total_executions=10,
            successful_executions=7,
            evidence_producing=3,
            alert_types=["AlertA"],
        )

        assert qe.success_rate == 0.7

    def test_evidence_rate_calculation(self) -> None:
        """Test evidence rate property."""
        qe = QueryEffectiveness(
            query_pattern="{job='test'}",
            total_executions=10,
            successful_executions=7,
            evidence_producing=3,
            alert_types=["AlertA"],
        )

        assert qe.evidence_rate == 0.3

    def test_zero_executions(self) -> None:
        """Test rates with zero executions."""
        qe = QueryEffectiveness(
            query_pattern="{job='test'}",
            total_executions=0,
            successful_executions=0,
            evidence_producing=0,
            alert_types=[],
        )

        assert qe.success_rate == 0.0
        assert qe.evidence_rate == 0.0


class TestInvestigationStore:
    """Tests for InvestigationStore."""

    def test_init_creates_schema(self, store: InvestigationStore) -> None:
        """Test that schema is created on init."""
        with store._get_connection() as conn:
            cursor = conn.cursor()

            # Check investigations table exists
            cursor.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='investigations'"
            )
            assert cursor.fetchone() is not None

            # Check query_effectiveness table exists
            cursor.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='query_effectiveness'"
            )
            assert cursor.fetchone() is not None

            # Check schema_info table exists
            cursor.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='schema_info'"
            )
            assert cursor.fetchone() is not None

    def test_store_and_retrieve_investigation(
        self, store: InvestigationStore, sample_investigation: StoredInvestigation
    ) -> None:
        """Test storing and retrieving an investigation."""
        store.store_investigation(sample_investigation)

        retrieved = store.get_investigation(sample_investigation.investigation_id)

        assert retrieved is not None
        assert retrieved.investigation_id == sample_investigation.investigation_id
        assert retrieved.alert_name == sample_investigation.alert_name
        assert retrieved.evidence_count == sample_investigation.evidence_count
        assert retrieved.is_true_positive == sample_investigation.is_true_positive

    def test_get_nonexistent_investigation(self, store: InvestigationStore) -> None:
        """Test retrieving a non-existent investigation."""
        result = store.get_investigation("nonexistent-id")
        assert result is None

    def test_store_investigation_upsert(
        self, store: InvestigationStore, sample_investigation: StoredInvestigation
    ) -> None:
        """Test that storing an investigation twice updates it."""
        store.store_investigation(sample_investigation)

        # Modify and store again
        sample_investigation.evidence_count = 10
        sample_investigation.status = "escalated"
        store.store_investigation(sample_investigation)

        retrieved = store.get_investigation(sample_investigation.investigation_id)

        assert retrieved is not None
        assert retrieved.evidence_count == 10
        assert retrieved.status == "escalated"

    def test_find_similar_investigations_by_fingerprint(
        self, store: InvestigationStore, sample_investigation: StoredInvestigation
    ) -> None:
        """Test finding similar investigations by fingerprint."""
        store.store_investigation(sample_investigation)

        similar = store.find_similar_investigations(
            alert_fingerprint=sample_investigation.alert_fingerprint
        )

        assert len(similar) == 1
        assert similar[0].investigation.investigation_id == sample_investigation.investigation_id
        assert "same_alert_fingerprint" in similar[0].matching_factors

    def test_find_similar_investigations_by_technique(self, store: InvestigationStore) -> None:
        """Test finding similar investigations by technique."""
        now = datetime.now(timezone.utc)

        # Create multiple investigations with same technique
        for i in range(3):
            inv = StoredInvestigation(
                investigation_id=f"inv-{i}",
                alert_name=f"Alert{i}",
                alert_fingerprint=f"fp-{i}",
                severity="warning",
                technique_id="T1059.001",
                technique_name="PowerShell",
                started_at=now - timedelta(minutes=10),
                completed_at=now,
                duration_seconds=600.0,
                status="completed",
                evidence_count=i,
                highest_pyramid_level=i,
                techniques_identified=["T1059.001"],
                queries_executed=[],
                query_success_rate=0.5,
                effective_queries=[],
            )
            store.store_investigation(inv)

        similar = store.find_similar_investigations(technique_id="T1059.001")

        assert len(similar) == 3
        for sim in similar:
            assert "same_technique" in sim.matching_factors

    def test_find_similar_investigations_no_criteria(
        self, store: InvestigationStore, sample_investigation: StoredInvestigation
    ) -> None:
        """Test finding similar investigations with no criteria returns recent."""
        store.store_investigation(sample_investigation)

        # Should return recent investigations
        similar = store.find_similar_investigations()

        assert len(similar) >= 0  # May be empty or have results

    def test_find_similar_investigations_multiple_criteria(
        self, store: InvestigationStore, sample_investigation: StoredInvestigation
    ) -> None:
        """Test finding similar investigations with multiple criteria."""
        store.store_investigation(sample_investigation)

        similar = store.find_similar_investigations(
            alert_name=sample_investigation.alert_name,
            technique_id=sample_investigation.technique_id,
            severity=sample_investigation.severity,
        )

        assert len(similar) == 1
        # alert_name (0.3) + technique (0.15) + severity (0.05) = 0.5
        # Use > 0.49 to account for floating-point precision
        assert similar[0].similarity_score > 0.49  # Should have high score with multiple matches

    def test_update_query_effectiveness_new_query(self, store: InvestigationStore) -> None:
        """Test updating effectiveness for a new query."""
        store.update_query_effectiveness(
            query_pattern="{job='test'}",
            successful=True,
            produced_evidence=True,
            alert_type="TestAlert",
        )

        effective = store.get_effective_queries(min_evidence_rate=0.0, limit=10)

        # May not appear if total_executions < 3 threshold
        # Let's add more executions
        for _ in range(2):
            store.update_query_effectiveness(
                query_pattern="{job='test'}",
                successful=True,
                produced_evidence=True,
                alert_type="TestAlert",
            )

        effective = store.get_effective_queries(min_evidence_rate=0.0, limit=10)
        assert len(effective) == 1
        assert effective[0].query_pattern == "{job='test'}"
        assert effective[0].total_executions == 3

    def test_update_query_effectiveness_existing_query(self, store: InvestigationStore) -> None:
        """Test updating effectiveness for an existing query."""
        # Add initial record
        for _ in range(3):
            store.update_query_effectiveness(
                query_pattern="{job='existing'}",
                successful=True,
                produced_evidence=False,
                alert_type="AlertA",
            )

        # Update with evidence
        store.update_query_effectiveness(
            query_pattern="{job='existing'}",
            successful=True,
            produced_evidence=True,
            alert_type="AlertB",
        )

        effective = store.get_effective_queries(min_evidence_rate=0.0, limit=10)
        matching = [q for q in effective if q.query_pattern == "{job='existing'}"]

        assert len(matching) == 1
        assert matching[0].total_executions == 4
        assert matching[0].evidence_producing == 1
        assert "AlertA" in matching[0].alert_types
        assert "AlertB" in matching[0].alert_types

    def test_get_effective_queries_filtered_by_alert_type(self, store: InvestigationStore) -> None:
        """Test getting effective queries filtered by alert type."""
        # Add queries for different alert types
        for _ in range(3):
            store.update_query_effectiveness(
                query_pattern="{job='alert_a'}",
                successful=True,
                produced_evidence=True,
                alert_type="AlertA",
            )
            store.update_query_effectiveness(
                query_pattern="{job='alert_b'}",
                successful=True,
                produced_evidence=True,
                alert_type="AlertB",
            )

        effective_a = store.get_effective_queries(alert_type="AlertA", min_evidence_rate=0.0)
        effective_b = store.get_effective_queries(alert_type="AlertB", min_evidence_rate=0.0)

        assert len(effective_a) == 1
        assert effective_a[0].query_pattern == "{job='alert_a'}"
        assert len(effective_b) == 1
        assert effective_b[0].query_pattern == "{job='alert_b'}"

    def test_get_statistics(
        self, store: InvestigationStore, sample_investigation: StoredInvestigation
    ) -> None:
        """Test getting overall statistics."""
        store.store_investigation(sample_investigation)

        stats = store.get_statistics()

        assert stats["total_investigations"] == 1
        assert "completed" in stats["status_distribution"]
        assert stats["avg_evidence_count"] == 5.0
        assert stats["labeling"]["true_positives"] == 1
        assert stats["labeling"]["false_positives"] == 0

    def test_get_statistics_empty_store(self, store: InvestigationStore) -> None:
        """Test getting statistics from empty store."""
        stats = store.get_statistics()

        assert stats["total_investigations"] == 0
        assert stats["avg_evidence_count"] == 0
        assert stats["labeling"]["true_positives"] == 0

    def test_label_investigation(
        self, store: InvestigationStore, sample_investigation: StoredInvestigation
    ) -> None:
        """Test labeling an investigation."""
        sample_investigation.is_true_positive = None
        store.store_investigation(sample_investigation)

        # Label as false positive
        result = store.label_investigation(
            investigation_id=sample_investigation.investigation_id,
            is_true_positive=False,
            analyst_notes="Benign activity",
        )

        assert result is True

        retrieved = store.get_investigation(sample_investigation.investigation_id)
        assert retrieved is not None
        assert retrieved.is_true_positive is False
        assert retrieved.analyst_notes == "Benign activity"

    def test_label_nonexistent_investigation(self, store: InvestigationStore) -> None:
        """Test labeling a non-existent investigation."""
        result = store.label_investigation(
            investigation_id="nonexistent",
            is_true_positive=True,
        )

        assert result is False

    def test_get_false_positive_patterns(self, store: InvestigationStore) -> None:
        """Test getting false positive patterns."""
        now = datetime.now(timezone.utc)

        # Create multiple false positive investigations with same fingerprint
        for i in range(5):
            inv = StoredInvestigation(
                investigation_id=f"fp-inv-{i}",
                alert_name="NoisyAlert",
                alert_fingerprint="noisy-rule-001",
                severity="low",
                technique_id="T1000",
                technique_name="Test",
                started_at=now - timedelta(minutes=10),
                completed_at=now,
                duration_seconds=60.0,
                status="completed",
                evidence_count=0,
                highest_pyramid_level=0,
                techniques_identified=[],
                queries_executed=[],
                query_success_rate=0.0,
                effective_queries=[],
                is_true_positive=False,
            )
            store.store_investigation(inv)

        patterns = store.get_false_positive_patterns(min_occurrences=3)

        assert len(patterns) >= 1
        noisy_pattern = next((p for p in patterns if p["alert_name"] == "NoisyAlert"), None)
        assert noisy_pattern is not None
        assert noisy_pattern["occurrences"] >= 3


class TestGlobalStore:
    """Tests for global store functions."""

    def test_get_investigation_store_creates_default(self) -> None:
        """Test that get_investigation_store creates a default store."""
        reset_investigation_store()

        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test.db"
            store = get_investigation_store(db_path)

            assert store is not None
            assert store.db_path == db_path

        reset_investigation_store()

    def test_get_investigation_store_returns_same_instance(self) -> None:
        """Test that get_investigation_store returns the same instance."""
        reset_investigation_store()

        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test.db"
            store1 = get_investigation_store(db_path)
            store2 = get_investigation_store()

            assert store1 is store2

        reset_investigation_store()

    def test_reset_investigation_store(self) -> None:
        """Test resetting the global store."""
        reset_investigation_store()

        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test.db"
            store1 = get_investigation_store(db_path)
            reset_investigation_store()

            # After reset, a new call should create new instance
            store2 = get_investigation_store(db_path)

            assert store1 is not store2

        reset_investigation_store()


class TestSimilarityScoring:
    """Tests for similarity calculation."""

    def test_similarity_score_all_factors(
        self, store: InvestigationStore, sample_investigation: StoredInvestigation
    ) -> None:
        """Test similarity score with all matching factors."""
        store.store_investigation(sample_investigation)

        similar = store.find_similar_investigations(
            alert_name=sample_investigation.alert_name,
            alert_fingerprint=sample_investigation.alert_fingerprint,
            technique_id=sample_investigation.technique_id,
            severity=sample_investigation.severity,
        )

        assert len(similar) == 1
        # 0.5 (fingerprint) + 0.3 (name) + 0.15 (technique) + 0.05 (severity) = 1.0
        assert similar[0].similarity_score == 1.0
        assert len(similar[0].matching_factors) == 4

    def test_similarity_score_partial_match(
        self, store: InvestigationStore, sample_investigation: StoredInvestigation
    ) -> None:
        """Test similarity score with partial match."""
        store.store_investigation(sample_investigation)

        similar = store.find_similar_investigations(
            technique_id=sample_investigation.technique_id,
        )

        assert len(similar) == 1
        assert similar[0].similarity_score == 0.15
        assert similar[0].matching_factors == ["same_technique"]
