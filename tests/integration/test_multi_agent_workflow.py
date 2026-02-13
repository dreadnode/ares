"""Integration tests for multi-agent workflow orchestration.

Tests the complete multi-agent workflow including:
- Priority-based vulnerability queue
- Credential expansion loop
- Exploitation workflow orchestration
- Dispatcher message flow
"""

from __future__ import annotations

import asyncio
import os
import sys
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

pytestmark = pytest.mark.integration

if os.getenv("ARES_RUN_INTEGRATION_TESTS") != "1":
    pytest.skip(
        "Set ARES_RUN_INTEGRATION_TESTS=1 to run integration tests.",
        allow_module_level=True,
    )

pytest.importorskip("kubernetes")

# Create mock redis module if not installed
if "redis" not in sys.modules:
    mock_redis_module = MagicMock()
    mock_redis_asyncio = MagicMock()
    mock_redis_module.asyncio = mock_redis_asyncio
    sys.modules["redis"] = mock_redis_module
    sys.modules["redis.asyncio"] = mock_redis_asyncio

from ares.core.dispatcher import RedTeamDispatcher  # noqa: E402
from ares.core.models import (  # noqa: E402
    AgentInfo,
    AgentRole,
    Credential,
    Host,
    SharedRedTeamState,
)
from ares.core.workflows import (  # noqa: E402
    CredentialTestingTracker,
    credential_expansion_loop,
)

# Test fixtures


@pytest.fixture
def mock_redis():
    """Create a mock Redis client with ZSET support for vulnerability queue."""
    redis = AsyncMock()
    redis.ping = AsyncMock(return_value=True)
    redis.get = AsyncMock(return_value=None)
    redis.set = AsyncMock()
    redis.expire = AsyncMock()
    redis.exists = AsyncMock(return_value=0)
    redis.delete = AsyncMock()
    redis.lpush = AsyncMock(return_value=1)
    redis.brpop = AsyncMock(return_value=None)
    redis.rpop = AsyncMock(return_value=None)
    redis.llen = AsyncMock(return_value=0)
    redis.aclose = AsyncMock()

    # ZSET operations for vulnerability queue
    zset_data: dict[str, list[tuple[str, float]]] = {}

    async def mock_zadd(key, mapping):
        if key not in zset_data:
            zset_data[key] = []
        for member, score in mapping.items():
            # Remove existing entry with same member
            zset_data[key] = [(m, s) for m, s in zset_data[key] if m != member]
            zset_data[key].append((member, score))
        return len(mapping)

    async def mock_zrange(key, start, end, withscores=False):
        if key not in zset_data:
            return []
        # Sort by score (priority)
        sorted_items = sorted(zset_data[key], key=lambda x: x[1])
        if withscores:
            return sorted_items
        return [item[0] for item in sorted_items]

    async def mock_zrem(key, member):
        if key not in zset_data:
            return 0
        original_len = len(zset_data[key])
        zset_data[key] = [(m, s) for m, s in zset_data[key] if m != member]
        return original_len - len(zset_data[key])

    redis.zadd = mock_zadd
    redis.zrange = mock_zrange
    redis.zrem = mock_zrem

    return redis


@pytest.fixture
async def dispatcher(mock_redis):
    """Create a dispatcher instance with mocked Redis."""
    d = RedTeamDispatcher(redis_url="redis://localhost:6379")

    # Manually setup the mocked connections
    d._redis_client = mock_redis
    d._shared_state = SharedRedTeamState(operation_id="test-operation-001")
    d._running = True

    if d._task_queue:
        d._task_queue._client = mock_redis
        d._task_queue._connected = True

    yield d

    d._running = False
    if d._task_queue:
        d._task_queue._connected = False


@pytest.fixture
def sample_credentials():
    """Create sample credentials for testing."""
    return [
        Credential(
            username="user1",
            password="Password123",  # pragma: allowlist secret
            domain="contoso.local",
            source="test",
        ),
        Credential(
            username="admin",
            password="AdminPass!",  # pragma: allowlist secret
            domain="contoso.local",
            source="test",
            is_admin=True,
        ),
    ]


@pytest.fixture
def sample_hosts():
    """Create sample hosts for testing."""
    return [
        Host(ip="192.168.58.10", hostname="DC01", os="Windows Server 2019"),
        Host(ip="192.168.58.20", hostname="WEB01", os="Windows Server 2016"),
        Host(ip="192.168.58.30", hostname="DB01", os="Windows Server 2019"),
    ]


# CredentialTestingTracker Tests


class TestCredentialTestingTracker:
    """Tests for CredentialTestingTracker."""

    def test_empty_tracker(self):
        """Test empty tracker initialization."""
        tracker = CredentialTestingTracker()
        assert len(tracker.tested_pairs) == 0
        assert len(tracker.successful_pairs) == 0
        assert len(tracker.failed_pairs) == 0

    def test_has_tested_false_initially(self, sample_credentials, sample_hosts):
        """Test that untested pairs return False."""
        tracker = CredentialTestingTracker()
        cred = sample_credentials[0]
        host = sample_hosts[0]

        assert not tracker.has_tested(cred, host)

    def test_mark_tested(self, sample_credentials, sample_hosts):
        """Test marking a pair as tested."""
        tracker = CredentialTestingTracker()
        cred = sample_credentials[0]
        host = sample_hosts[0]

        tracker.mark_tested(cred, host)

        assert tracker.has_tested(cred, host)
        assert len(tracker.tested_pairs) == 1

    def test_mark_tested_success(self, sample_credentials, sample_hosts):
        """Test marking a pair as tested with success."""
        tracker = CredentialTestingTracker()
        cred = sample_credentials[0]
        host = sample_hosts[0]

        tracker.mark_tested(cred, host, success=True)

        assert tracker.has_tested(cred, host)
        assert len(tracker.successful_pairs) == 1
        assert len(tracker.failed_pairs) == 0

    def test_get_stats(self, sample_credentials, sample_hosts):
        """Test statistics calculation."""
        tracker = CredentialTestingTracker()

        # Mark some pairs
        tracker.mark_tested(sample_credentials[0], sample_hosts[0], success=True)
        tracker.mark_tested(sample_credentials[0], sample_hosts[1], success=False)
        tracker.mark_tested(sample_credentials[1], sample_hosts[0], success=True)

        stats = tracker.get_stats()

        assert stats["total_tested"] == 3
        assert stats["successful"] == 2
        assert stats["failed"] == 1


# Priority Vulnerability Queue Tests


class TestPriorityVulnerabilityQueue:
    """Tests for priority-based vulnerability queue."""

    @pytest.mark.asyncio
    async def test_queue_vulnerability(self, dispatcher):
        """Test queuing a vulnerability."""
        vuln_id = await dispatcher.queue_vulnerability(
            vuln_type="ADCS_ESC1",
            target="dc01.contoso.local",
            details={"template": "VulnerableTemplate"},
            discovered_by="recon-agent",
        )

        assert vuln_id is not None
        assert "adcs_esc1" in vuln_id  # vuln_type is normalized to lowercase
        assert vuln_id in dispatcher.shared_state.discovered_vulnerabilities

    @pytest.mark.asyncio
    async def test_vulnerability_priority_order(self, dispatcher):
        """Test that vulnerabilities are returned in priority order."""
        # Queue vulnerabilities in random order
        await dispatcher.queue_vulnerability(
            vuln_type="acl_abuse",
            target="user1",
            details={},
            discovered_by="acl-agent",
        )
        await dispatcher.queue_vulnerability(
            vuln_type="ADCS_ESC1",
            target="dc01",
            details={},
            discovered_by="privesc-agent",
        )
        await dispatcher.queue_vulnerability(
            vuln_type="krbtgt_hash",
            target="dc01",
            details={},
            discovered_by="lateral-agent",
        )

        # Get vulnerabilities in priority order
        vuln1 = await dispatcher.get_next_vulnerability()
        assert vuln1 is not None
        assert vuln1["type"] == "adcs_esc1"  # Priority 1 (normalized to lowercase)

        vuln2 = await dispatcher.get_next_vulnerability()
        assert vuln2 is not None
        assert vuln2["type"] == "krbtgt_hash"  # Priority 4

        vuln3 = await dispatcher.get_next_vulnerability()
        assert vuln3 is not None
        assert vuln3["type"] == "acl_abuse"  # Priority 6

    @pytest.mark.asyncio
    async def test_mark_vulnerability_exploited(self, dispatcher):
        """Test marking vulnerability as exploited."""
        vuln_id = await dispatcher.queue_vulnerability(
            vuln_type="ADCS_ESC1",
            target="dc01",
            details={},
            discovered_by="privesc-agent",
        )

        # Mark as exploited with credential result
        await dispatcher.mark_vulnerability_exploited(
            vuln_id,
            success=True,
            result={
                "credential": {
                    "username": "admin",
                    "password": "AdminPass!",  # pragma: allowlist secret
                    "domain": "contoso.local",
                    "is_admin": True,
                }
            },
        )

        # Verify it's marked as exploited
        assert vuln_id in dispatcher.shared_state.exploited_vulnerabilities

        # Verify credential was added
        assert len(dispatcher.shared_state.all_credentials) == 1
        cred = dispatcher.shared_state.all_credentials[0]
        assert cred.username == "admin"

    @pytest.mark.asyncio
    async def test_exploited_vulnerabilities_skipped(self, dispatcher):
        """Test that exploited vulnerabilities are skipped in queue."""
        vuln_id = await dispatcher.queue_vulnerability(
            vuln_type="ADCS_ESC1",
            target="dc01",
            details={},
            discovered_by="privesc-agent",
        )

        # Mark as exploited
        dispatcher.shared_state.mark_exploited(vuln_id)

        # Try to get next vulnerability
        result = await dispatcher.get_next_vulnerability()

        # Should return None since only vuln was exploited
        assert result is None


# Dispatcher Tests


class TestDispatcher:
    """Tests for RedTeamDispatcher."""

    @pytest.mark.asyncio
    async def test_agent_registration(self, dispatcher):
        """Test agent registration."""
        agent = AgentInfo(
            name="recon-agent",
            pod_name="recon-agent-0",
            role=AgentRole.RECON,
            capabilities={"nmap", "crackmapexec"},
        )

        await dispatcher.register(agent)

        assert "recon-agent" in dispatcher._agents
        assert dispatcher.get_agent_for_role(AgentRole.RECON) is not None

    @pytest.mark.asyncio
    async def test_credential_publishing(self, dispatcher, sample_credentials):
        """Test credential broadcasting."""
        cred = sample_credentials[0]

        # Register an agent to receive messages
        agent = AgentInfo(
            name="lateral-agent",
            pod_name="lateral-agent-0",
            role=AgentRole.LATERAL,
            capabilities={"psexec"},
        )
        await dispatcher.register(agent)

        # Publish credential
        added = await dispatcher.publish_credential(cred, "recon-agent")

        assert added is True
        assert len(dispatcher.shared_state.all_credentials) == 1

        # Check message was queued for lateral agent
        messages = await dispatcher.get_messages("lateral-agent")
        assert len(messages) > 0

    @pytest.mark.asyncio
    async def test_task_routing(self, dispatcher, mock_redis):
        """Test task routing to specialized agents via Redis."""
        # Register a cracker agent
        cracker = AgentInfo(
            name="cracker-agent",
            pod_name="cracker-agent-0",
            role=AgentRole.CRACKER,
            capabilities={"hashcat"},
        )
        await dispatcher.register(cracker)

        # Request crack
        task_id = await dispatcher.request_crack(
            hash_value="aad3b435b51404eeaad3b435b51404ee:500",
            hash_type="NTLM",
            source_agent="orchestrator",
            username="admin",
        )

        assert task_id != ""
        assert task_id in dispatcher.shared_state.pending_tasks

        # With Redis enabled, task goes to Redis queue, not in-memory queue
        # Verify Redis lpush was called with task for cracker queue
        mock_redis.lpush.assert_called()
        call_args = mock_redis.lpush.call_args
        assert "ares:tasks:cracker" in call_args[0][0]

    @pytest.mark.asyncio
    async def test_task_completion(self, dispatcher):
        """Test task completion handling."""
        # Register a cracker agent
        cracker = AgentInfo(
            name="cracker-agent",
            pod_name="cracker-agent-0",
            role=AgentRole.CRACKER,
            capabilities={"hashcat"},
        )
        await dispatcher.register(cracker)

        # Request crack
        task_id = await dispatcher.request_crack(
            hash_value="aad3b435b51404ee:test",
            hash_type="NTLM",
            source_agent="orchestrator",
        )

        # Complete task
        await dispatcher.complete_task(
            task_id=task_id,
            success=True,
            result={"cracked_password": "Password123"},  # pragma: allowlist secret
            source_agent="cracker-agent",
        )

        # Verify task moved to completed
        assert task_id not in dispatcher.shared_state.pending_tasks
        assert task_id in dispatcher.shared_state.completed_tasks

    @pytest.mark.asyncio
    async def test_wait_for_task(self, dispatcher):
        """Test waiting for task completion."""
        # Register a cracker agent
        cracker = AgentInfo(
            name="cracker-agent",
            pod_name="cracker-agent-0",
            role=AgentRole.CRACKER,
            capabilities={"hashcat"},
        )
        await dispatcher.register(cracker)

        # Request crack
        task_id = await dispatcher.request_crack(
            hash_value="test:hash",
            hash_type="NTLM",
            source_agent="orchestrator",
        )

        # Complete task in background
        async def complete_later():
            await asyncio.sleep(0.1)
            await dispatcher.complete_task(
                task_id=task_id,
                success=True,
                result={"password": "cracked"},  # pragma: allowlist secret
                source_agent="cracker-agent",
            )

        background_task = asyncio.create_task(complete_later())
        assert background_task is not None  # Keep reference to prevent garbage collection

        # Wait for task
        result = await dispatcher.wait_for_task(task_id, timeout=5.0)

        assert result["success"] is True
        assert result["result"]["password"] == "cracked"  # pragma: allowlist secret


# Credential Expansion Loop Tests


class TestCredentialExpansionLoop:
    """Tests for credential expansion loop."""

    @pytest.mark.asyncio
    async def test_expansion_no_credentials(self, dispatcher):
        """Test expansion with no credentials returns immediately."""
        tracker = await credential_expansion_loop(
            dispatcher,
            max_iterations=1,
            delay_between_tests=0.01,
        )

        assert tracker.get_stats()["total_tested"] == 0

    @pytest.mark.asyncio
    async def test_expansion_no_hosts(self, dispatcher, sample_credentials):
        """Test expansion with no hosts returns immediately."""
        # Add credentials but no hosts
        for cred in sample_credentials:
            dispatcher.shared_state.add_credential(cred, "test")

        tracker = await credential_expansion_loop(
            dispatcher,
            max_iterations=1,
            delay_between_tests=0.01,
        )

        assert tracker.get_stats()["total_tested"] == 0

    @pytest.mark.asyncio
    async def test_expansion_with_credentials_and_hosts(
        self, dispatcher, sample_credentials, sample_hosts
    ):
        """Test expansion with credentials and hosts."""
        dispatcher.wait_for_task = AsyncMock(return_value={"success": False})

        # Register lateral agent
        lateral = AgentInfo(
            name="lateral-agent",
            pod_name="lateral-agent-0",
            role=AgentRole.LATERAL,
            capabilities={"psexec"},
        )
        await dispatcher.register(lateral)

        # Add credentials and hosts
        for cred in sample_credentials:
            dispatcher.shared_state.add_credential(cred, "test")
        for host in sample_hosts:
            dispatcher.shared_state.add_host(host)

        # Run expansion (will dispatch tasks but not wait for completion in test)
        tracker = await credential_expansion_loop(
            dispatcher,
            max_iterations=1,
            delay_between_tests=0.01,
        )

        # Should have tested all combinations
        expected_tests = len(sample_credentials) * len(sample_hosts)
        assert tracker.get_stats()["total_tested"] == expected_tests


# Mock Kubernetes Tests


class TestKubernetesIntegration:
    """Tests for Kubernetes integration."""

    @pytest.mark.asyncio
    async def test_full_workflow_mock(self, mock_redis):
        """Test complete workflow with mocked infrastructure."""
        with patch("kubernetes.client.CoreV1Api") as mock_k8s:
            # Setup mock pods
            mock_pod = MagicMock()
            mock_pod.metadata.name = "recon-agent-0"
            mock_pod.metadata.labels = {"ares.dreadnode.io/role": "recon"}
            mock_pod.status.phase = "Running"

            mock_pods = MagicMock()
            mock_pods.items = [mock_pod]
            mock_k8s.return_value.list_namespaced_pod.return_value = mock_pods

            # Create dispatcher with manual mocking
            dispatcher = RedTeamDispatcher(redis_url="redis://localhost:6379")
            dispatcher._redis_client = mock_redis
            dispatcher._shared_state = SharedRedTeamState(operation_id="test-workflow-001")
            dispatcher._running = True
            if dispatcher._task_queue:
                dispatcher._task_queue._client = mock_redis
                dispatcher._task_queue._connected = True

            # Register agents
            for role in [AgentRole.RECON, AgentRole.CRACKER, AgentRole.LATERAL]:
                agent = AgentInfo(
                    name=f"{role.value}-agent",
                    pod_name=f"{role.value}-agent-0",
                    role=role,
                    capabilities=set(),
                )
                await dispatcher.register(agent)

            # Queue vulnerability
            vuln_id = await dispatcher.queue_vulnerability(
                vuln_type="ADCS_ESC1",
                target="dc01",
                details={},
                discovered_by="recon-agent",
            )

            # Verify state
            assert vuln_id is not None
            assert len(dispatcher._agents) == 3
            assert dispatcher.shared_state.operation_id == "test-workflow-001"

            # Clean up
            dispatcher._running = False
            if dispatcher._task_queue:
                dispatcher._task_queue._connected = False


# Domain Admin Achievement Tests


class TestDomainAdminAchievement:
    """Tests for domain admin achievement handling."""

    @pytest.mark.asyncio
    async def test_domain_admin_announcement(self, dispatcher):
        """Test domain admin announcement."""
        # Register agent to receive broadcast
        agent = AgentInfo(
            name="lateral-agent",
            pod_name="lateral-agent-0",
            role=AgentRole.LATERAL,
            capabilities={"psexec"},
        )
        await dispatcher.register(agent)

        # Announce domain admin
        await dispatcher.announce_domain_admin(
            username="Administrator",
            domain="contoso.local",
            attack_path="ADCS ESC1 -> Admin Certificate -> DCSync",
            credential_type="password",
            source_agent="orchestrator",
        )

        # Verify state updated
        assert dispatcher.shared_state.has_domain_admin is True
        assert dispatcher.shared_state.domain_admin_path is not None

        # Verify message broadcast
        messages = await dispatcher.get_messages("lateral-agent")
        assert any(m.type.value == "domain_admin_achieved" for m in messages)


# Recovery Tests


class TestRecovery:
    """Tests for operation recovery."""

    @pytest.mark.asyncio
    async def test_state_checkpoint(self, dispatcher, mock_redis):
        """Test state checkpointing."""
        # Add some state
        cred = Credential(
            username="test",
            password="pass",  # pragma: allowlist secret
            domain="contoso.local",
            source="test",
        )
        dispatcher.shared_state.add_credential(cred, "test")

        # Checkpoint should be called
        await dispatcher._checkpoint()

        # Verify Redis was called
        mock_redis.set.assert_called()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
