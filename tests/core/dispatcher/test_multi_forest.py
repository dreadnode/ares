"""Tests for multi-forest mode fixes.

Covers:
1. Trust key extraction task format (must include target_agent)
2. get_next_vulnerability() continues returning vulns after DA in multi-forest mode
3. Exploitation workflow falls through to vuln dispatch in multi-forest mode
"""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from ares.core.dispatcher import RedTeamDispatcher
from ares.core.models import Hash, Host, SharedRedTeamState, Target, VulnerabilityInfo


class MockRedisClient:
    """Mock Redis client for testing."""

    def __init__(self):
        self.calls = []
        self.data = {}

    async def lpush(self, key: str, value: str) -> int:
        """Push to list (used for normal priority task submission)."""
        self.calls.append(("lpush", key, value))
        if key not in self.data:
            self.data[key] = []
        self.data[key].insert(0, value)
        return len(self.data[key])

    async def rpush(self, key: str, value: str) -> int:
        """Push to end of list (used for high priority task submission)."""
        self.calls.append(("rpush", key, value))
        if key not in self.data:
            self.data[key] = []
        self.data[key].append(value)
        return len(self.data[key])

    async def xadd(self, key: str, fields: dict, **kwargs) -> str:
        """Add to stream (used for task submission)."""
        self.calls.append(("xadd", key, fields.get("data", "")))
        return "1-0"

    async def xgroup_create(self, key: str, group: str, **kwargs) -> bool:
        """Create consumer group."""
        self.calls.append(("xgroup_create", key, group))
        return True

    async def hset(self, key: str, field: str, value: str) -> int:
        self.calls.append(("hset", key, field, value))
        if key not in self.data:
            self.data[key] = {}
        self.data[key][field] = value
        return 1

    async def hget(self, key: str, field: str) -> str | None:
        self.calls.append(("hget", key, field))
        return self.data.get(key, {}).get(field)

    async def zrange(self, key: str, start: int, end: int, withscores: bool = False):
        """Return sorted set range."""
        self.calls.append(("zrange", key, start, end, withscores))
        return []

    async def set(self, key: str, value: str) -> bool:
        self.calls.append(("set", key, value))
        self.data[key] = value
        return True


class MockTaskQueue:
    """Mock task queue with Redis client."""

    def __init__(self):
        self.redis = MockRedisClient()


class TestTrustKeyExtractionTaskFormat:
    """Tests for trust key extraction task format.

    The task pushed to Redis MUST include target_agent field,
    otherwise workers cannot parse it as a valid TaskMessage.
    """

    @pytest.fixture
    def dispatcher(self):
        """Create a dispatcher with mocked internals."""
        d = RedTeamDispatcher()
        d._shared_state = SharedRedTeamState(
            operation_id="test-op-trust",
            target=Target(ip="192.168.58.10", domain="contoso.local"),
        )
        d._shared_state.has_domain_admin = True
        d._shared_state.domain_admin_domains = ["contoso.local"]
        # Add Administrator hash to enable trust key extraction
        d._shared_state.all_hashes.append(
            Hash(
                username="Administrator",
                domain="contoso.local",
                hash_value="aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0",
                hash_type="NTLM",
            )
        )
        return d

    @pytest.mark.asyncio
    async def test_trust_key_extraction_task_has_target_agent(self, dispatcher):
        """Trust key extraction task MUST include target_agent field.

        Regression test: tasks were missing target_agent, causing workers
        to fail parsing them as TaskMessage (which requires target_agent).
        """
        task_queue = MockTaskQueue()

        # Setup dispatcher for multi-forest mode
        dispatcher._shared_state.all_domains = ["contoso.local", "fabrikam.local"]
        dispatcher._shared_state._validated_domains = {"contoso.local", "fabrikam.local"}
        dispatcher._shared_state.domain_controllers["contoso.local"] = "192.168.58.10"
        dispatcher._shared_state.all_hosts.append(
            Host(ip="192.168.58.20", hostname="dc01.fabrikam.local")
        )

        with patch("ares.core.config.get_multi_forest_mode", return_value=True):
            # Call the auto-dispatch method
            await dispatcher._auto_dispatch_trust_key_extraction_threaded(
                da_domain="contoso.local",
                task_queue=task_queue,
                source_agent="ares-privesc",
            )

        # Verify xadd was called (tasks go to urgent stream)
        xadd_calls = [c for c in task_queue.redis.calls if c[0] == "xadd"]
        assert len(xadd_calls) == 1, "Expected one xadd call for trust extraction task"

        # Parse the task data
        _, _stream_key, task_json = xadd_calls[0]
        task_data = json.loads(task_json)

        # CRITICAL: target_agent must be present
        assert "target_agent" in task_data, (
            "Trust key extraction task missing target_agent field - "
            "workers cannot parse TaskMessage without it"
        )
        assert task_data["target_agent"] == "privesc", (
            f"Expected target_agent='privesc', got '{task_data.get('target_agent')}'"
        )

        # Verify other required fields
        assert task_data["task_type"] == "exploit"
        assert task_data["source_agent"] == "auto_trust_extraction"
        assert "trust_extraction_" in task_data["task_id"]
        assert task_data["payload"]["trusted_domain"] == "fabrikam.local"


class TestGetNextVulnerabilityMultiForest:
    """Tests for get_next_vulnerability() in multi-forest mode.

    When DA is achieved but multi-forest mode is active with undominated
    forests, get_next_vulnerability() should continue returning vulns
    instead of short-circuiting with None.
    """

    @pytest.fixture
    def dispatcher_with_vulns(self):
        """Create a dispatcher with DA achieved and vulns in queue."""
        d = RedTeamDispatcher()
        d._shared_state = SharedRedTeamState(
            operation_id="test-op-vuln",
            target=Target(ip="192.168.58.10", domain="contoso.local"),
        )
        # DA achieved on contoso.local
        d._shared_state.has_domain_admin = True
        d._shared_state.domain_admin_domains = ["contoso.local"]

        # Add fabrikam.local as discovered foreign domain
        d._shared_state.all_domains = ["contoso.local", "fabrikam.local"]
        d._shared_state._validated_domains = {"contoso.local", "fabrikam.local"}

        # Add a host from fabrikam.local to validate the domain
        d._shared_state.all_hosts.append(Host(ip="192.168.58.20", hostname="dc01.fabrikam.local"))

        # Add a vuln targeting fabrikam.local
        d._shared_state.discovered_vulnerabilities["vuln_fabrikam_1"] = VulnerabilityInfo(
            vuln_id="vuln_fabrikam_1",
            vuln_type="constrained_delegation",
            target="192.168.58.20",
            details={"domain": "fabrikam.local", "account": "svc_sql"},
            discovered_by="recon",
        )

        # Mock Redis client
        d._redis_client = MockRedisClient()
        d._task_queue = MockTaskQueue()

        return d

    @pytest.mark.asyncio
    async def test_returns_vulns_when_multi_forest_undominated(self, dispatcher_with_vulns):
        """get_next_vulnerability() should return vulns when foreign forests remain.

        Regression test: was returning None immediately when DA achieved,
        even in multi-forest mode with undominated forests.
        """
        dispatcher = dispatcher_with_vulns

        with (
            patch("ares.core.config.get_multi_forest_mode", return_value=True),
            patch.object(dispatcher, "_can_exploit_vulnerability", return_value=True),
            patch.object(
                dispatcher,
                "_is_vulnerability_exploited",
                new_callable=AsyncMock,
                return_value=False,
            ),
        ):
            # Mock all_forests_dominated to return False (fabrikam.local not dominated)
            dispatcher._shared_state.all_forests_dominated = MagicMock(return_value=False)

            from ares.core.dispatcher.vulnerability import VulnerabilityMixin

            # Call the method - should return the vuln since prerequisites are mocked
            result = await VulnerabilityMixin.get_next_vulnerability(dispatcher)

            # In multi-forest mode with undominated forests, should return the vuln
            assert result is not None, (
                "get_next_vulnerability() should return vulns when "
                "multi-forest mode active and forests remain undominated"
            )
            # Result is a dict with id field (internal representation)
            assert result.get("id") == "vuln_fabrikam_1"

    @pytest.mark.asyncio
    async def test_returns_none_when_single_forest_da(self, dispatcher_with_vulns):
        """get_next_vulnerability() should return None in single-forest mode after DA."""
        dispatcher = dispatcher_with_vulns

        with patch("ares.core.config.get_multi_forest_mode", return_value=False):
            from ares.core.dispatcher.vulnerability import VulnerabilityMixin

            result = await VulnerabilityMixin.get_next_vulnerability(dispatcher)

            # Single-forest mode with DA achieved should return None
            assert result is None, (
                "get_next_vulnerability() should return None in single-forest mode after DA"
            )

    @pytest.mark.asyncio
    async def test_returns_none_when_all_forests_dominated(self, dispatcher_with_vulns):
        """get_next_vulnerability() should return None when all forests dominated."""
        dispatcher = dispatcher_with_vulns

        # Mark fabrikam.local as also having DA
        dispatcher._shared_state.domain_admin_domains = ["contoso.local", "fabrikam.local"]

        with patch("ares.core.config.get_multi_forest_mode", return_value=True):
            dispatcher._shared_state.all_forests_dominated = MagicMock(return_value=True)

            from ares.core.dispatcher.vulnerability import VulnerabilityMixin

            result = await VulnerabilityMixin.get_next_vulnerability(dispatcher)

            # All forests dominated should return None
            assert result is None, (
                "get_next_vulnerability() should return None when all forests dominated"
            )


class TestWorkflowMultiForestFallthrough:
    """Tests for exploitation workflow multi-forest fallthrough.

    When DA is achieved but multi-forest mode is active with undominated
    forests, the workflow should fall through to vuln dispatch logic
    instead of breaking or continuing past it.
    """

    @pytest.mark.asyncio
    async def test_workflow_does_not_break_when_forests_remain(self):
        """Workflow should not break when multi-forest mode has undominated forests.

        Regression test: workflow was using 'continue' which skipped vuln dispatch,
        and later was breaking entirely. Should fall through to dispatch vulns.
        """
        # This is a structural test - verify the code path exists
        # The actual workflow is complex, so we test the conditional logic

        from ares.core.models import SharedRedTeamState, Target

        state = SharedRedTeamState(
            operation_id="test-workflow",
            target=Target(ip="192.168.58.10", domain="contoso.local"),
        )
        state.has_domain_admin = True
        state.domain_admin_domains = ["contoso.local"]
        state.all_domains = ["contoso.local", "fabrikam.local"]
        state._validated_domains = {"contoso.local", "fabrikam.local"}

        # Add a host from fabrikam.local to validate the domain
        state.all_hosts.append(Host(ip="192.168.58.20", hostname="dc01.fabrikam.local"))

        with patch("ares.core.config.get_multi_forest_mode", return_value=True):
            # Verify the condition that should trigger fallthrough
            from ares.core.config import get_multi_forest_mode

            multi_forest = get_multi_forest_mode()
            all_dominated = state.all_forests_dominated()

            # This is the condition in workflows.py that should NOT trigger break
            should_continue_exploiting = multi_forest and not all_dominated

            assert should_continue_exploiting, (
                "Workflow should continue exploiting when multi-forest mode active "
                "and forests remain undominated"
            )

            # Verify undominated forests are correctly identified
            undominated = state.get_undominated_forests()
            assert "fabrikam.local" in undominated, (
                f"fabrikam.local should be in undominated forests, got: {undominated}"
            )
