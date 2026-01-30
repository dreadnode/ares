"""Unit tests for RedTeamDispatcher request methods (in-memory mode)."""

from __future__ import annotations

import pytest

from ares.core.dispatcher import RedTeamDispatcher
from ares.core.messages import CredentialAccessRequest, ReconRequest
from ares.core.models import AgentInfo, AgentRole


@pytest.fixture
def dispatcher():
    """Create a dispatcher without Redis (in-memory mode)."""
    return RedTeamDispatcher()


@pytest.fixture
async def started_dispatcher(dispatcher):
    """Create and start a dispatcher."""
    await dispatcher.start("test-op")
    yield dispatcher
    await dispatcher.stop()


class TestReconRequestInMemory:
    """Tests for request_recon in-memory fallback."""

    @pytest.mark.asyncio
    async def test_request_recon_inmemory_queues_message(self, started_dispatcher):
        """request_recon should queue a ReconRequest message in-memory mode."""
        dispatcher = started_dispatcher

        # Register a recon agent
        agent_info = AgentInfo(
            name="recon-agent",
            pod_name="recon-0",
            role=AgentRole.RECON,
            capabilities={"nmap", "bloodhound"},
        )
        await dispatcher.register(agent_info)

        # Submit recon request
        task_id = await dispatcher.request_recon(
            source_agent="orchestrator",
            domain="contoso.local",
            target_ips=["192.168.58.1", "192.168.58.2"],
            username="testuser",
            password="testpass",  # pragma: allowlist secret  # pragma: allowlist secret
            reason="network_scan",
            techniques=["nmap", "bloodhound"],
        )

        assert task_id != ""
        assert task_id.startswith("task-")

        # Message should be in in-memory queue
        messages = await dispatcher.get_messages("recon-agent")
        assert len(messages) == 1

        msg = messages[0]
        assert isinstance(msg, ReconRequest)
        assert msg.type.value == "recon_request"
        assert msg.task_id == task_id
        assert msg.domain == "contoso.local"
        assert msg.target_ips == ["192.168.58.1", "192.168.58.2"]
        assert msg.username == "testuser"
        assert msg.password == "testpass"  # pragma: allowlist secret
        assert msg.reason == "network_scan"
        assert msg.techniques == ["nmap", "bloodhound"]
        assert msg.callback_agent == "orchestrator"

    @pytest.mark.asyncio
    async def test_request_recon_no_agent_returns_empty(self, started_dispatcher):
        """request_recon should return empty string if no recon agent registered."""
        dispatcher = started_dispatcher

        # Don't register any agent
        task_id = await dispatcher.request_recon(
            source_agent="orchestrator",
            domain="contoso.local",
        )

        assert task_id == ""

    @pytest.mark.asyncio
    async def test_request_recon_creates_pending_task(self, started_dispatcher):
        """request_recon should create a pending task entry."""
        dispatcher = started_dispatcher

        # Register a recon agent
        agent_info = AgentInfo(
            name="recon-agent",
            pod_name="recon-0",
            role=AgentRole.RECON,
            capabilities={"nmap"},
        )
        await dispatcher.register(agent_info)

        task_id = await dispatcher.request_recon(
            source_agent="orchestrator",
            domain="contoso.local",
            target_ips=["192.168.58.1"],
        )

        # Task should be in pending tasks
        assert task_id in dispatcher.shared_state.pending_tasks
        task_info = dispatcher.shared_state.pending_tasks[task_id]
        assert task_info.task_type == "recon"
        assert task_info.assigned_agent == "recon-agent"

    @pytest.mark.asyncio
    async def test_request_recon_with_hash_auth(self, started_dispatcher):
        """request_recon should support hash-based authentication."""
        dispatcher = started_dispatcher

        agent_info = AgentInfo(
            name="recon-agent",
            pod_name="recon-0",
            role=AgentRole.RECON,
            capabilities={"nmap"},
        )
        await dispatcher.register(agent_info)

        task_id = await dispatcher.request_recon(
            source_agent="orchestrator",
            domain="contoso.local",
            username="admin",
            hash_value="aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0",
        )
        assert task_id  # Verify task_id was returned

        messages = await dispatcher.get_messages("recon-agent")
        assert len(messages) == 1

        msg = messages[0]
        assert msg.username == "admin"
        assert msg.hash_value == "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0"
        assert msg.password is None


class TestCredentialAccessRequestInMemory:
    """Tests for request_credential_access in-memory fallback (for parity)."""

    @pytest.mark.asyncio
    async def test_request_credential_access_inmemory_queues_message(self, started_dispatcher):
        """request_credential_access should queue a CredentialAccessRequest in-memory."""
        dispatcher = started_dispatcher

        agent_info = AgentInfo(
            name="cred-agent",
            pod_name="cred-0",
            role=AgentRole.CREDENTIAL_ACCESS,
            capabilities={"secretsdump", "kerberoast"},
        )
        await dispatcher.register(agent_info)

        task_id = await dispatcher.request_credential_access(
            source_agent="orchestrator",
            domain="contoso.local",
            target_ips=["192.168.58.5"],
            username="testuser",
            password="testpass",  # pragma: allowlist secret
            reason="secretsdump",
            techniques=["secretsdump"],
        )

        assert task_id != ""

        messages = await dispatcher.get_messages("cred-agent")
        assert len(messages) == 1

        msg = messages[0]
        assert isinstance(msg, CredentialAccessRequest)
        assert msg.type.value == "credential_access_request"
        assert msg.task_id == task_id


class TestPrivescEnumerationRequestInMemory:
    """Tests for request_privesc_enumeration in-memory fallback."""

    @pytest.mark.asyncio
    async def test_request_privesc_enumeration_inmemory_queues_message(self, started_dispatcher):
        """request_privesc_enumeration should queue an ExploitRequest message in-memory mode."""
        from ares.core.messages import ExploitRequest
        from ares.core.models import Host

        dispatcher = started_dispatcher

        # Register a privesc agent
        agent_info = AgentInfo(
            name="privesc-agent",
            pod_name="privesc-0",
            role=AgentRole.PRIVESC,
            capabilities={"delegation_tools"},
        )
        await dispatcher.register(agent_info)

        # Add a DC to state so _find_domain_controller_ip works
        dispatcher.shared_state.all_hosts.append(
            Host(
                ip="192.168.58.240",
                hostname="dc01.contoso.local",
                services=["389/tcp ldap", "88/tcp kerberos"],
            )
        )

        # Submit privesc enumeration request
        task_id = await dispatcher.request_privesc_enumeration(
            source_agent="orchestrator",
            domain="contoso.local",
            username="testuser",
            password="testpass",  # pragma: allowlist secret
            techniques=["find_delegation"],
        )

        assert task_id != ""
        assert task_id.startswith("task-")

        # Message should be in in-memory queue
        messages = await dispatcher.get_messages("privesc-agent")
        assert len(messages) == 1

        msg = messages[0]
        assert isinstance(msg, ExploitRequest)
        assert msg.task_id == task_id
        assert msg.vuln_type == "PRIVESC_ENUMERATION"
        assert msg.params["domain"] == "contoso.local"
        assert msg.params["username"] == "testuser"
        assert msg.params["password"] == "testpass"  # pragma: allowlist secret
        assert msg.params["techniques"] == ["find_delegation"]
        assert msg.callback_agent == "orchestrator"

    @pytest.mark.asyncio
    async def test_request_privesc_enumeration_no_agent_returns_empty(self, started_dispatcher):
        """request_privesc_enumeration should return empty string if no privesc agent registered."""
        dispatcher = started_dispatcher

        # Don't register any agent
        task_id = await dispatcher.request_privesc_enumeration(
            source_agent="orchestrator",
            domain="contoso.local",
            username="testuser",
            password="testpass",  # pragma: allowlist secret
        )

        assert task_id == ""

    @pytest.mark.asyncio
    async def test_request_privesc_enumeration_creates_pending_task(self, started_dispatcher):
        """request_privesc_enumeration should create a pending task entry."""
        from ares.core.models import Host

        dispatcher = started_dispatcher

        # Register a privesc agent
        agent_info = AgentInfo(
            name="privesc-agent",
            pod_name="privesc-0",
            role=AgentRole.PRIVESC,
            capabilities={"delegation_tools"},
        )
        await dispatcher.register(agent_info)

        # Add a DC to state
        dispatcher.shared_state.all_hosts.append(
            Host(
                ip="192.168.58.240",
                hostname="dc01.contoso.local",
                services=["389/tcp ldap"],
            )
        )

        task_id = await dispatcher.request_privesc_enumeration(
            source_agent="orchestrator",
            domain="contoso.local",
            username="admin",
            password="P@ssw0rd!",  # pragma: allowlist secret
            techniques=["find_delegation"],
        )

        # Task should be in pending tasks
        assert task_id in dispatcher.shared_state.pending_tasks
        task_info = dispatcher.shared_state.pending_tasks[task_id]
        assert task_info.task_type == "privesc_enumeration"
        assert task_info.assigned_agent == "privesc-agent"

    @pytest.mark.asyncio
    async def test_request_privesc_enumeration_with_multiple_techniques(self, started_dispatcher):
        """request_privesc_enumeration should support multiple enumeration techniques."""
        from ares.core.messages import ExploitRequest
        from ares.core.models import Host

        dispatcher = started_dispatcher

        agent_info = AgentInfo(
            name="privesc-agent",
            pod_name="privesc-0",
            role=AgentRole.PRIVESC,
            capabilities={"delegation_tools"},
        )
        await dispatcher.register(agent_info)

        dispatcher.shared_state.all_hosts.append(
            Host(
                ip="192.168.58.10",
                hostname="dc01.contoso.local",
                services=["389/tcp ldap"],
            )
        )

        task_id = await dispatcher.request_privesc_enumeration(
            source_agent="orchestrator",
            domain="contoso.local",
            username="admin",
            password="P@ssw0rd!",  # pragma: allowlist secret
            techniques=["find_delegation", "find_trusts"],
        )

        assert task_id

        messages = await dispatcher.get_messages("privesc-agent")
        assert len(messages) == 1

        msg = messages[0]
        assert isinstance(msg, ExploitRequest)
        assert msg.params["techniques"] == ["find_delegation", "find_trusts"]
