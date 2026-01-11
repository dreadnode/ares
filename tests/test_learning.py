"""Tests for the Learning Tools module."""

import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from ares.core.persistence import InvestigationStore, StoredInvestigation
from ares.tools.blue.learning import LearningTools


@pytest.fixture
def temp_db() -> Path:
    """Create a temporary database file."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir) / "test_learning.db"


@pytest.fixture
def store(temp_db: Path) -> InvestigationStore:
    """Create a fresh investigation store."""
    return InvestigationStore(temp_db)


@pytest.fixture
def learning_tools(store: InvestigationStore) -> LearningTools:
    """Create learning tools with test store."""
    return LearningTools(store=store)


@pytest.fixture
def populated_store(store: InvestigationStore) -> InvestigationStore:
    """Create a store with sample investigation data."""
    now = datetime.now(timezone.utc)

    # Create several investigations
    investigations = [
        StoredInvestigation(
            investigation_id=f"inv-{i}",
            alert_name="HighCPUUsage",
            alert_fingerprint="rule-cpu-001",
            severity="warning",
            technique_id="T1059.001",
            technique_name="PowerShell",
            started_at=now - timedelta(hours=i),
            completed_at=now - timedelta(hours=i) + timedelta(minutes=10),
            duration_seconds=600.0,
            status="completed",
            evidence_count=i + 1,
            highest_pyramid_level=min(i, 4),
            techniques_identified=["T1059.001"],
            queries_executed=[{"query": "{job='windows'}", "result_count": i}],
            query_success_rate=0.7,
            effective_queries=["{job='windows'} |= 'powershell'"],
            is_true_positive=i % 2 == 0,  # Alternating true/false
        )
        for i in range(5)
    ]

    # Add a different alert type
    investigations.append(
        StoredInvestigation(
            investigation_id="inv-different",
            alert_name="SuspiciousLogin",
            alert_fingerprint="rule-login-001",
            severity="high",
            technique_id="T1078",
            technique_name="Valid Accounts",
            started_at=now - timedelta(hours=1),
            completed_at=now - timedelta(minutes=50),
            duration_seconds=600.0,
            status="completed",
            evidence_count=3,
            highest_pyramid_level=2,
            techniques_identified=["T1078"],
            queries_executed=[{"query": "{job='auth'}", "result_count": 5}],
            query_success_rate=0.8,
            effective_queries=["{job='auth'} |= 'failed'"],
            is_true_positive=True,
        )
    )

    for inv in investigations:
        store.store_investigation(inv)

    # Add query effectiveness data
    for _ in range(5):
        store.update_query_effectiveness(
            query_pattern="{job='windows'} |= 'powershell'",
            successful=True,
            produced_evidence=True,
            alert_type="HighCPUUsage",
        )
        store.update_query_effectiveness(
            query_pattern="{job='auth'} |= 'failed'",
            successful=True,
            produced_evidence=True,
            alert_type="SuspiciousLogin",
        )

    return store


@pytest.fixture
def populated_learning_tools(populated_store: InvestigationStore) -> LearningTools:
    """Create learning tools with populated store."""
    return LearningTools(store=populated_store)


class TestLearningToolsInit:
    """Tests for LearningTools initialization."""

    def test_init_with_store(self, store: InvestigationStore) -> None:
        """Test initialization with provided store."""
        tools = LearningTools(store=store)

        assert tools.store is store

    def test_init_without_store(self) -> None:
        """Test initialization without store uses global."""
        tools = LearningTools()

        assert tools.store is None
        # Accessing get_store() should get/create global store
        # (but we won't test that to avoid side effects)

    def test_get_store_returns_provided_store(self, store: InvestigationStore) -> None:
        """Test that get_store() returns provided store."""
        tools = LearningTools(store=store)

        assert tools.get_store() is store


class TestFindSimilarInvestigations:
    """Tests for find_similar_investigations tool."""

    @pytest.mark.asyncio
    async def test_find_similar_no_results(self, learning_tools: LearningTools) -> None:
        """Test finding similar investigations with empty store."""
        result = await learning_tools.find_similar_investigations(alert_name="NonexistentAlert")

        assert result["found"] is False
        assert result["investigations"] == []
        assert "No similar investigations" in result["message"]

    @pytest.mark.asyncio
    async def test_find_similar_by_alert_name(
        self, populated_learning_tools: LearningTools
    ) -> None:
        """Test finding similar investigations by alert name."""
        result = await populated_learning_tools.find_similar_investigations(
            alert_name="HighCPUUsage"
        )

        assert result["found"] is True
        assert result["count"] >= 1
        assert len(result["investigations"]) >= 1

        # Check investigation structure
        inv = result["investigations"][0]
        assert "investigation_id" in inv
        assert "alert_name" in inv
        assert "similarity_score" in inv
        assert "matching_factors" in inv
        assert "outcome" in inv

    @pytest.mark.asyncio
    async def test_find_similar_by_technique(self, populated_learning_tools: LearningTools) -> None:
        """Test finding similar investigations by technique."""
        result = await populated_learning_tools.find_similar_investigations(
            technique_id="T1059.001"
        )

        assert result["found"] is True
        assert result["count"] >= 1

        # All results should have the matching technique
        for inv in result["investigations"]:
            assert inv["technique_id"] == "T1059.001"

    @pytest.mark.asyncio
    async def test_find_similar_returns_summary(
        self, populated_learning_tools: LearningTools
    ) -> None:
        """Test that find_similar returns summary statistics."""
        result = await populated_learning_tools.find_similar_investigations(
            alert_name="HighCPUUsage"
        )

        assert "summary" in result
        assert "completion_rate" in result["summary"]
        assert "avg_evidence_count" in result["summary"]
        assert "true_positives" in result["summary"]
        assert "false_positives" in result["summary"]

    @pytest.mark.asyncio
    async def test_find_similar_returns_guidance(
        self, populated_learning_tools: LearningTools
    ) -> None:
        """Test that find_similar returns investigation guidance."""
        result = await populated_learning_tools.find_similar_investigations(
            alert_name="HighCPUUsage"
        )

        assert "guidance" in result
        assert isinstance(result["guidance"], str)

    @pytest.mark.asyncio
    async def test_find_similar_respects_limit(
        self, populated_learning_tools: LearningTools
    ) -> None:
        """Test that find_similar respects the limit parameter."""
        result = await populated_learning_tools.find_similar_investigations(
            alert_name="HighCPUUsage",
            limit=2,
        )

        assert len(result["investigations"]) <= 2

    @pytest.mark.asyncio
    async def test_find_similar_includes_effective_queries(
        self, populated_learning_tools: LearningTools
    ) -> None:
        """Test that results include effective queries."""
        result = await populated_learning_tools.find_similar_investigations(
            alert_name="HighCPUUsage"
        )

        # At least one investigation should have effective queries
        has_queries = any(inv.get("effective_queries") for inv in result["investigations"])
        assert has_queries or result["count"] == 0


class TestGetEffectiveQueries:
    """Tests for get_effective_queries tool."""

    @pytest.mark.asyncio
    async def test_get_effective_no_data(self, learning_tools: LearningTools) -> None:
        """Test getting effective queries with no data."""
        result = await learning_tools.get_effective_queries()

        assert result["found"] is False
        assert result["queries"] == []
        assert "No query effectiveness data" in result["message"]

    @pytest.mark.asyncio
    async def test_get_effective_queries_returns_results(
        self, populated_learning_tools: LearningTools
    ) -> None:
        """Test getting effective queries with data."""
        result = await populated_learning_tools.get_effective_queries()

        assert result["found"] is True
        assert result["count"] >= 1
        assert len(result["queries"]) >= 1

        # Check query structure
        query = result["queries"][0]
        assert "query_pattern" in query
        assert "total_uses" in query
        assert "success_rate" in query
        assert "evidence_rate" in query

    @pytest.mark.asyncio
    async def test_get_effective_queries_filtered_by_alert(
        self, populated_learning_tools: LearningTools
    ) -> None:
        """Test getting effective queries filtered by alert type."""
        result = await populated_learning_tools.get_effective_queries(alert_name="HighCPUUsage")

        # Should only return queries used for this alert
        for query in result["queries"]:
            assert "HighCPUUsage" in query["used_for_alerts"]

    @pytest.mark.asyncio
    async def test_get_effective_queries_respects_limit(
        self, populated_learning_tools: LearningTools
    ) -> None:
        """Test that get_effective_queries respects the limit."""
        result = await populated_learning_tools.get_effective_queries(limit=1)

        assert len(result["queries"]) <= 1

    @pytest.mark.asyncio
    async def test_get_effective_queries_includes_recommendation(
        self, populated_learning_tools: LearningTools
    ) -> None:
        """Test that results include a recommendation."""
        result = await populated_learning_tools.get_effective_queries()

        if result["found"]:
            assert "recommendation" in result


class TestCheckFalsePositivePattern:
    """Tests for check_false_positive_pattern tool."""

    @pytest.mark.asyncio
    async def test_check_fp_no_history(self, learning_tools: LearningTools) -> None:
        """Test checking FP pattern with no history."""
        result = await learning_tools.check_false_positive_pattern(alert_name="NewAlert")

        assert result["is_known_pattern"] is False
        assert result["confidence"] == "low"
        assert "No historical data" in result["message"]

    @pytest.mark.asyncio
    async def test_check_fp_with_history(self, populated_learning_tools: LearningTools) -> None:
        """Test checking FP pattern with history."""
        result = await populated_learning_tools.check_false_positive_pattern(
            alert_name="HighCPUUsage"
        )

        assert "false_positive_rate" in result
        assert "true_positives" in result or "is_known_pattern" in result

    @pytest.mark.asyncio
    async def test_check_fp_high_rate_detection(self, store: InvestigationStore) -> None:
        """Test detection of high false positive rate."""
        now = datetime.now(timezone.utc)

        # Create mostly false positive investigations
        for i in range(10):
            inv = StoredInvestigation(
                investigation_id=f"fp-inv-{i}",
                alert_name="NoisyAlert",
                alert_fingerprint="noisy-rule",
                severity="low",
                technique_id="T1000",
                technique_name="Test",
                started_at=now - timedelta(minutes=i),
                completed_at=now,
                duration_seconds=60.0,
                status="completed",
                evidence_count=0,
                highest_pyramid_level=0,
                techniques_identified=[],
                queries_executed=[],
                query_success_rate=0.0,
                effective_queries=[],
                is_true_positive=i < 2,  # Only 2/10 true positives
            )
            store.store_investigation(inv)

        tools = LearningTools(store=store)
        result = await tools.check_false_positive_pattern(alert_name="NoisyAlert")

        # Should detect high FP rate (80%)
        assert "false_positive_rate" in result
        # Either known pattern or has rate info
        assert result.get("is_known_pattern") or "80%" in result.get("false_positive_rate", "")

    @pytest.mark.asyncio
    async def test_check_fp_with_fingerprint(self, populated_learning_tools: LearningTools) -> None:
        """Test checking FP pattern with fingerprint."""
        result = await populated_learning_tools.check_false_positive_pattern(
            alert_name="HighCPUUsage",
            alert_fingerprint="rule-cpu-001",
        )

        # Should use fingerprint for more accurate matching
        assert "confidence" in result


class TestGetInvestigationStatistics:
    """Tests for get_investigation_statistics tool."""

    @pytest.mark.asyncio
    async def test_get_statistics_empty_store(self, learning_tools: LearningTools) -> None:
        """Test getting statistics from empty store."""
        result = await learning_tools.get_investigation_statistics()

        assert result["total_investigations"] == 0

    @pytest.mark.asyncio
    async def test_get_statistics_with_data(self, populated_learning_tools: LearningTools) -> None:
        """Test getting statistics with data."""
        result = await populated_learning_tools.get_investigation_statistics()

        assert result["total_investigations"] >= 1
        assert "status_distribution" in result
        assert "performance" in result
        assert "query_insights" in result
        assert "labeling" in result

    @pytest.mark.asyncio
    async def test_get_statistics_performance_metrics(
        self, populated_learning_tools: LearningTools
    ) -> None:
        """Test that statistics include performance metrics."""
        result = await populated_learning_tools.get_investigation_statistics()

        perf = result["performance"]
        assert "avg_evidence_count" in perf
        assert "avg_pyramid_level" in perf
        assert "avg_duration_seconds" in perf

    @pytest.mark.asyncio
    async def test_get_statistics_labeling_info(
        self, populated_learning_tools: LearningTools
    ) -> None:
        """Test that statistics include labeling information."""
        result = await populated_learning_tools.get_investigation_statistics()

        labeling = result["labeling"]
        assert "true_positives" in labeling
        assert "false_positives" in labeling
        # true_positive_rate may be None or a value
        assert "true_positive_rate" in labeling


class TestGuidanceGeneration:
    """Tests for guidance generation helper."""

    @pytest.mark.asyncio
    async def test_guidance_with_effective_queries(
        self, populated_learning_tools: LearningTools
    ) -> None:
        """Test guidance includes effective query suggestions."""
        result = await populated_learning_tools.find_similar_investigations(
            alert_name="HighCPUUsage"
        )

        # Guidance should mention queries if available
        if result["found"]:
            guidance = result["guidance"]
            # Should have some guidance text
            assert len(guidance) > 0

    @pytest.mark.asyncio
    async def test_guidance_with_high_tp_rate(self, store: InvestigationStore) -> None:
        """Test guidance for high true positive rate alerts."""
        now = datetime.now(timezone.utc)

        # Create mostly true positive investigations
        for i in range(5):
            inv = StoredInvestigation(
                investigation_id=f"tp-inv-{i}",
                alert_name="CriticalAlert",
                alert_fingerprint="critical-rule",
                severity="critical",
                technique_id="T1000",
                technique_name="Test",
                started_at=now - timedelta(minutes=i),
                completed_at=now,
                duration_seconds=600.0,
                status="completed",
                evidence_count=5,
                highest_pyramid_level=3,
                techniques_identified=["T1000"],
                queries_executed=[],
                query_success_rate=0.8,
                effective_queries=["{job='test'}"],
                is_true_positive=True,  # All true positives
            )
            store.store_investigation(inv)

        tools = LearningTools(store=store)
        result = await tools.find_similar_investigations(alert_name="CriticalAlert")

        assert result["found"] is True
        # Should mention high TP rate in guidance
        guidance = result["guidance"]
        assert "true positive" in guidance.lower() or "thorough" in guidance.lower()


class TestEdgeCases:
    """Tests for edge cases."""

    @pytest.mark.asyncio
    async def test_find_similar_with_all_none_params(
        self, populated_learning_tools: LearningTools
    ) -> None:
        """Test find_similar with all None parameters."""
        result = await populated_learning_tools.find_similar_investigations()

        # Should still return results (recent investigations)
        # or indicate no similar found
        assert "found" in result

    @pytest.mark.asyncio
    async def test_unicode_in_alert_name(self, store: InvestigationStore) -> None:
        """Test handling of unicode in alert names."""
        now = datetime.now(timezone.utc)

        inv = StoredInvestigation(
            investigation_id="unicode-inv",
            alert_name="Alert \u2603 Snowman",  # Unicode snowman
            alert_fingerprint="unicode-rule",
            severity="low",
            technique_id=None,
            technique_name=None,
            started_at=now,
            completed_at=now,
            duration_seconds=60.0,
            status="completed",
            evidence_count=0,
            highest_pyramid_level=0,
            techniques_identified=[],
            queries_executed=[],
            query_success_rate=0.0,
            effective_queries=[],
        )
        store.store_investigation(inv)

        tools = LearningTools(store=store)
        result = await tools.find_similar_investigations(alert_name="Alert \u2603 Snowman")

        assert result["found"] is True

    @pytest.mark.asyncio
    async def test_very_long_query_pattern(self, store: InvestigationStore) -> None:
        """Test handling of very long query patterns."""
        long_query = "{job='test'}" + " |= 'x'" * 100

        for _ in range(3):
            store.update_query_effectiveness(
                query_pattern=long_query,
                successful=True,
                produced_evidence=True,
                alert_type="TestAlert",
            )

        tools = LearningTools(store=store)
        result = await tools.get_effective_queries()

        # Should handle long queries without error
        assert result["found"] is True


class TestGetStoreInitialization:
    """Tests for lazy store initialization."""

    def test_get_store_initializes_when_none(self) -> None:
        """Test that get_store initializes a store when none is provided."""
        tools = LearningTools(store=None)
        assert tools.store is None

        store = tools.get_store()
        assert store is not None
        assert tools.store is not None
        assert tools.store is store


class TestFalsePositivePatternEdgeCases:
    """Tests for edge cases in check_false_positive_pattern."""

    @pytest.mark.asyncio
    async def test_fp_rate_zero_when_no_labeled(self, store: InvestigationStore) -> None:
        """Test fp_rate is 0.0 when no investigations have is_true_positive set."""
        now = datetime.now(timezone.utc)

        # Create investigations with no labeling (is_true_positive=None)
        for i in range(5):
            inv = StoredInvestigation(
                investigation_id=f"unlabeled-inv-{i}",
                alert_name="UnlabeledAlert",
                alert_fingerprint="unlabeled-rule",
                severity="low",
                technique_id="T1000",
                technique_name="Test",
                started_at=now - timedelta(minutes=i),
                completed_at=now,
                duration_seconds=60.0,
                status="completed",
                evidence_count=0,
                highest_pyramid_level=0,
                techniques_identified=[],
                queries_executed=[],
                query_success_rate=0.0,
                effective_queries=[],
                is_true_positive=None,  # No labeling
            )
            store.store_investigation(inv)

        tools = LearningTools(store=store)
        result = await tools.check_false_positive_pattern(alert_name="UnlabeledAlert")

        # Should have 0% FP rate since no labeled investigations
        assert "false_positive_rate" in result
        assert result["false_positive_rate"] == "0%"
        assert result["is_known_pattern"] is False
        assert result["confidence"] == "low"  # Low confidence since none are labeled

    @pytest.mark.asyncio
    async def test_fp_rate_above_70_percent(self, store: InvestigationStore) -> None:
        """Test detection when fp_rate > 0.7 but not known pattern."""
        now = datetime.now(timezone.utc)

        # Create 10 investigations with 8 false positives (80% FP rate)
        for i in range(10):
            inv = StoredInvestigation(
                investigation_id=f"high-fp-inv-{i}",
                alert_name="HighFPAlert",
                alert_fingerprint=f"fp-rule-{i}",  # Different fingerprints so no known pattern
                severity="low",
                technique_id="T1000",
                technique_name="Test",
                started_at=now - timedelta(minutes=i),
                completed_at=now,
                duration_seconds=60.0,
                status="completed",
                evidence_count=0,
                highest_pyramid_level=0,
                techniques_identified=[],
                queries_executed=[],
                query_success_rate=0.0,
                effective_queries=[],
                is_true_positive=i < 2,  # Only 2 true positives = 80% FP rate
            )
            store.store_investigation(inv)

        tools = LearningTools(store=store)
        result = await tools.check_false_positive_pattern(alert_name="HighFPAlert")

        # Should detect high FP rate and return recommendation
        assert result["is_known_pattern"] is True
        assert result["confidence"] == "medium"
        assert "80%" in result["false_positive_rate"]
        assert "recommendation" in result
        assert "high false positive rate" in result["recommendation"]


class TestGuidanceGenerationEdgeCases:
    """Tests for edge cases in _generate_guidance."""

    def test_generate_guidance_empty_similar(self, store: InvestigationStore) -> None:
        """Test _generate_guidance returns fallback when similar is empty."""
        tools = LearningTools(store=store)
        # Call _generate_guidance directly with empty list
        guidance = tools._generate_guidance([])
        assert guidance == "No historical guidance available."

    @pytest.mark.asyncio
    async def test_guidance_no_similar_investigations(self, store: InvestigationStore) -> None:
        """Test guidance when no similar investigations found."""
        # Empty store - no similar investigations
        tools = LearningTools(store=store)
        result = await tools.find_similar_investigations(alert_name="NonexistentAlert")

        # When no similar investigations found, the function returns early without guidance
        # But the result should indicate nothing was found
        assert result["found"] is False
        assert "No similar investigations" in result["message"]
        assert result["investigations"] == []

    @pytest.mark.asyncio
    async def test_guidance_no_completed_investigations(self, store: InvestigationStore) -> None:
        """Test guidance when similar investigations exist but none completed."""
        now = datetime.now(timezone.utc)

        # Create investigations with non-completed status
        for i in range(3):
            inv = StoredInvestigation(
                investigation_id=f"failed-inv-{i}",
                alert_name="FailedAlert",
                alert_fingerprint="failed-rule",
                severity="high",
                technique_id="T1000",
                technique_name="Test",
                started_at=now - timedelta(minutes=i),
                completed_at=now,
                duration_seconds=60.0,
                status="failed",  # Not completed
                evidence_count=0,
                highest_pyramid_level=0,
                techniques_identified=[],
                queries_executed=[],
                query_success_rate=0.0,
                effective_queries=[],
            )
            store.store_investigation(inv)

        tools = LearningTools(store=store)
        result = await tools.find_similar_investigations(alert_name="FailedAlert")

        # Should return guidance about no successful completions
        assert "did not complete successfully" in result["guidance"]
