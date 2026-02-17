"""Tests for cli_ops pub/sub notifications on state injection."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from ares.core.models import Credential, Host, SharedRedTeamState, Target


def _make_state(**kwargs) -> SharedRedTeamState:
    """Create a SharedRedTeamState and return it serialized."""
    state = SharedRedTeamState(operation_id=kwargs.pop("operation_id", "op-test-pubsub"))
    if "target" in kwargs:
        state.target = kwargs["target"]
    if "credentials" in kwargs:
        state.credentials.extend(kwargs["credentials"])
    if "hosts" in kwargs:
        state.all_hosts.extend(kwargs["hosts"])
    return state


def _mock_redis_client(state: SharedRedTeamState) -> AsyncMock:
    client = AsyncMock()
    client.get = AsyncMock(return_value=state.to_bytes())
    client.set = AsyncMock()
    client.aclose = AsyncMock()
    return client


def _mock_task_queue(subscriber_count: int = 3) -> MagicMock:
    tq = MagicMock()
    tq.connect = AsyncMock()
    tq.publish_state_update = AsyncMock(return_value=subscriber_count)
    tq.disconnect = AsyncMock()
    return tq


class TestInjectCredentialPubSub:
    """inject_credential should publish state update after writing to Redis."""

    @pytest.mark.asyncio
    async def test_publishes_state_update_on_new_credential(self):
        """A newly injected credential triggers pub/sub notification."""
        state = _make_state()
        client = _mock_redis_client(state)
        tq = _mock_task_queue(subscriber_count=5)

        with (
            patch("ares.cli_ops.create_redis_client", return_value=client),
            patch("ares.cli_ops.get_redis_url", return_value="redis://localhost:6379"),
            patch("ares.core.task_queue.RedisTaskQueue", return_value=tq) as mock_tq_cls,
        ):
            from ares.cli_ops import inject_credential

            await inject_credential(
                "op-test-pubsub",
                "admin",
                "P@ssw0rd!",  # pragma: allowlist secret
                domain="contoso.local",
            )

            # State was saved to Redis
            client.set.assert_called_once()

            # Pub/sub notification was sent
            mock_tq_cls.assert_called_once_with("redis://localhost:6379")
            tq.connect.assert_awaited_once()
            tq.publish_state_update.assert_awaited_once_with("op-test-pubsub")
            tq.disconnect.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_no_pubsub_when_credential_already_exists(self):
        """Duplicate credentials should NOT trigger pub/sub."""
        state = _make_state(
            credentials=[
                Credential(
                    username="admin",
                    password="P@ssw0rd!",  # pragma: allowlist secret
                    domain="contoso.local",
                    source="spray",
                )
            ]
        )
        client = _mock_redis_client(state)
        tq = _mock_task_queue()

        with (
            patch("ares.cli_ops.create_redis_client", return_value=client),
            patch("ares.cli_ops.get_redis_url", return_value="redis://localhost:6379"),
            patch("ares.core.task_queue.RedisTaskQueue", return_value=tq) as mock_tq_cls,
        ):
            from ares.cli_ops import inject_credential

            await inject_credential(
                "op-test-pubsub",
                "admin",
                "P@ssw0rd!",  # pragma: allowlist secret
                domain="contoso.local",
            )

            # State was NOT saved (duplicate)
            client.set.assert_not_called()

            # No pub/sub notification
            mock_tq_cls.assert_not_called()
            tq.publish_state_update.assert_not_awaited()


class TestInjectVulnerabilityPubSub:
    """inject_vulnerability should publish state update after writing to Redis."""

    @pytest.mark.asyncio
    async def test_publishes_state_update_on_new_vulnerability(self):
        """A newly injected vulnerability triggers pub/sub notification."""
        state = _make_state()
        client = _mock_redis_client(state)
        tq = _mock_task_queue(subscriber_count=4)

        with (
            patch("ares.cli_ops.create_redis_client", return_value=client),
            patch("ares.cli_ops.get_redis_url", return_value="redis://localhost:6379"),
            patch("ares.core.task_queue.RedisTaskQueue", return_value=tq) as mock_tq_cls,
        ):
            from ares.cli_ops import inject_vulnerability

            await inject_vulnerability(
                "op-test-pubsub",
                "constrained_delegation",
                "192.168.58.10",
                target_hostname="dc01.contoso.local",
                target_spn="cifs/dc01.contoso.local",
                account_name="svc_sql",
                domain="contoso.local",
            )

            # State was saved
            client.set.assert_called_once()

            # Pub/sub notification was sent
            mock_tq_cls.assert_called_once_with("redis://localhost:6379")
            tq.connect.assert_awaited_once()
            tq.publish_state_update.assert_awaited_once_with("op-test-pubsub")
            tq.disconnect.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_publishes_for_all_vuln_types(self):
        """All vulnerability types should trigger pub/sub."""
        vuln_types = [
            "constrained_delegation",
            "mssql_impersonation",
            "esc8",
            "smb_signing_disabled",
            "unconstrained_delegation",
        ]

        for vuln_type in vuln_types:
            state = _make_state()
            client = _mock_redis_client(state)
            tq = _mock_task_queue()

            with (
                patch("ares.cli_ops.create_redis_client", return_value=client),
                patch("ares.cli_ops.get_redis_url", return_value="redis://localhost:6379"),
                patch("ares.core.task_queue.RedisTaskQueue", return_value=tq),
            ):
                from ares.cli_ops import inject_vulnerability

                await inject_vulnerability(
                    "op-test-pubsub",
                    vuln_type,
                    "192.168.58.10",
                )

                (
                    tq.publish_state_update.assert_awaited_once_with("op-test-pubsub"),
                    (f"pub/sub not sent for {vuln_type}"),
                )


class TestBackfillDomainsPubSub:
    """backfill_domains should publish state update only when domains are actually added."""

    @pytest.mark.asyncio
    async def test_publishes_when_domains_added(self):
        """Backfilling new domains triggers pub/sub notification."""
        state = _make_state(
            target=Target(ip="192.168.58.10", domain="contoso.local"),
            hosts=[
                Host(ip="192.168.58.20", hostname="dc01.contoso.local"),
                Host(ip="192.168.58.30", hostname="sql01.fabrikam.local"),
            ],
        )
        # Force all_domains empty so backfill finds new ones.
        # We must also patch from_bytes to return this state directly,
        # because the real from_bytes auto-extracts domains.
        state.all_domains = []
        client = _mock_redis_client(state)
        tq = _mock_task_queue(subscriber_count=2)

        with (
            patch("ares.core.redis_client.create_redis_client", return_value=client),
            patch("ares.cli_ops.get_redis_url", return_value="redis://localhost:6379"),
            patch("ares.core.models.SharedRedTeamState.from_bytes", return_value=state),
            patch("ares.core.task_queue.RedisTaskQueue", return_value=tq) as mock_tq_cls,
        ):
            from ares.cli_ops import backfill_domains

            await backfill_domains("op-test-pubsub")

            # State was saved
            client.set.assert_called_once()

            # Pub/sub notification was sent
            mock_tq_cls.assert_called_once_with("redis://localhost:6379")
            tq.publish_state_update.assert_awaited_once_with("op-test-pubsub")

    @pytest.mark.asyncio
    async def test_no_pubsub_when_no_new_domains(self):
        """No pub/sub when all domains already exist in state."""
        state = _make_state(
            target=Target(ip="192.168.58.10", domain="contoso.local"),
        )
        # Domains already populated — backfill finds nothing new
        state.all_domains = ["contoso.local"]
        client = _mock_redis_client(state)
        tq = _mock_task_queue()

        with (
            patch("ares.core.redis_client.create_redis_client", return_value=client),
            patch("ares.cli_ops.get_redis_url", return_value="redis://localhost:6379"),
            patch("ares.core.models.SharedRedTeamState.from_bytes", return_value=state),
            patch("ares.core.task_queue.RedisTaskQueue", return_value=tq) as mock_tq_cls,
        ):
            from ares.cli_ops import backfill_domains

            await backfill_domains("op-test-pubsub")

            # State was still saved (backfill always writes)
            client.set.assert_called_once()

            # No pub/sub since no new domains
            mock_tq_cls.assert_not_called()
            tq.publish_state_update.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_no_pubsub_when_no_domains_found(self):
        """No pub/sub when state has no data to extract domains from."""
        state = _make_state(
            target=Target(ip="192.168.58.10"),  # No domain
        )
        client = _mock_redis_client(state)
        tq = _mock_task_queue()

        with (
            patch("ares.core.redis_client.create_redis_client", return_value=client),
            patch("ares.cli_ops.get_redis_url", return_value="redis://localhost:6379"),
            patch("ares.core.models.SharedRedTeamState.from_bytes", return_value=state),
            patch("ares.core.task_queue.RedisTaskQueue", return_value=tq) as mock_tq_cls,
        ):
            from ares.cli_ops import backfill_domains

            await backfill_domains("op-test-pubsub")

            # No domains found means no save and no pub/sub
            mock_tq_cls.assert_not_called()
