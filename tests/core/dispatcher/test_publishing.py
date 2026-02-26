"""Tests for dispatcher publishing module.

Covers credential, hash, and DA status persistence to Redis,
especially from the threaded result consumer context.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from ares.core.dispatcher import RedTeamDispatcher
from ares.core.models import Hash, SharedRedTeamState


class MockRedisClient:
    """Mock Redis client for testing direct persistence."""

    def __init__(self):
        self.calls = []
        self.data = {}

    async def hset(self, key: str, field: str, value: str) -> int:
        self.calls.append(("hset", key, field, value))
        if key not in self.data:
            self.data[key] = {}
        self.data[key][field] = value
        return 1

    async def hsetnx(self, key: str, field: str, value: str) -> int:
        """Set hash field only if not exists (returns 1 if set, 0 if exists)."""
        self.calls.append(("hsetnx", key, field, value))
        if key not in self.data:
            self.data[key] = {}
        if field in self.data[key]:
            return 0  # Already exists
        self.data[key][field] = value
        return 1

    async def set(self, key: str, value: str) -> bool:
        self.calls.append(("set", key, value))
        self.data[key] = value
        return True

    async def expire(self, key: str, seconds: int) -> bool:
        """Set key expiration (no-op for testing)."""
        self.calls.append(("expire", key, seconds))
        return True

    async def rpush(self, key: str, value: str) -> int:
        """Append value to a list."""
        self.calls.append(("rpush", key, value))
        if key not in self.data:
            self.data[key] = []
        self.data[key].append(value)
        return len(self.data[key])


class MockTaskQueue:
    """Mock task queue with Redis client for threaded consumer tests."""

    def __init__(self):
        self.redis = MockRedisClient()


class TestPublishHashDAPersistence:
    """Tests for Domain Admin status persistence when krbtgt hash is found.

    When the threaded result consumer discovers a krbtgt hash, it must
    persist the DA status directly to Redis using task_queue.redis,
    since _can_persist_to_backend() returns False for the threaded consumer.
    """

    @pytest.fixture
    def dispatcher(self):
        """Create a dispatcher with mocked internals."""
        d = RedTeamDispatcher()
        d._shared_state = SharedRedTeamState(operation_id="test-op-da")
        d._checkpoint_requested = MagicMock()
        d._credential_access_requested = MagicMock()
        d.signal_credential_access = MagicMock()
        return d

    @pytest.mark.asyncio
    async def test_krbtgt_hash_persists_da_to_redis_from_threaded_consumer(
        self, dispatcher, monkeypatch
    ):
        """Test that krbtgt NTLM hash triggers direct DA persistence to Redis.

        This is critical for reducing latency between DA achievement and
        orchestrator exit. Without direct Redis persist, the CLI wouldn't
        see DA status until the next checkpoint from the main thread.
        """
        task_queue = MockTaskQueue()

        # Create krbtgt hash
        krbtgt_hash = Hash(
            username="krbtgt",
            hash_value="aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0",
            hash_type="NTLM",
            domain="contoso.local",
            source="secretsdump",
        )

        # Mock threading to simulate threaded consumer context
        monkeypatch.setattr(
            "ares.core.dispatcher.publishing.threading.current_thread",
            lambda: MagicMock(name="ResultConsumer"),
        )
        monkeypatch.setattr(
            "ares.core.dispatcher.publishing.threading.main_thread",
            lambda: MagicMock(name="MainThread"),
        )

        # Call publish_hash
        await dispatcher.publish_hash(krbtgt_hash, "ares-credential-access", task_queue=task_queue)

        # Verify DA was set in memory
        assert dispatcher.shared_state.has_domain_admin is True

        # Verify Redis calls include DA status
        redis_calls = task_queue.redis.calls

        # Should have called set for DA status
        da_calls = [
            c
            for c in redis_calls
            if "domain_admin" in str(c).lower() or "meta" in str(c[1]).lower()
        ]
        assert len(da_calls) >= 1, f"Should persist DA status to Redis, got calls: {redis_calls}"

    @pytest.mark.asyncio
    async def test_non_krbtgt_hash_does_not_persist_da(self, dispatcher, monkeypatch):
        """Test that non-krbtgt hashes don't trigger DA persistence."""
        task_queue = MockTaskQueue()

        # Create non-krbtgt hash
        admin_hash = Hash(
            username="Administrator",
            hash_value="aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0",
            hash_type="NTLM",
            domain="contoso.local",
            source="secretsdump",
        )

        # Mock threading to simulate threaded consumer context
        monkeypatch.setattr(
            "ares.core.dispatcher.publishing.threading.current_thread",
            lambda: MagicMock(name="ResultConsumer"),
        )
        monkeypatch.setattr(
            "ares.core.dispatcher.publishing.threading.main_thread",
            lambda: MagicMock(name="MainThread"),
        )

        await dispatcher.publish_hash(admin_hash, "ares-credential-access", task_queue=task_queue)

        # DA should NOT be set for non-krbtgt
        assert dispatcher.shared_state.has_domain_admin is False

        # No DA-related Redis calls
        da_calls = [c for c in task_queue.redis.calls if "domain_admin" in str(c).lower()]
        assert len(da_calls) == 0, f"Should not persist DA for non-krbtgt, got: {da_calls}"

    @pytest.mark.asyncio
    async def test_kerberoast_hash_does_not_trigger_da(self, dispatcher, monkeypatch):
        """Test that Kerberoast hashes (non-NTLM) don't trigger DA."""
        task_queue = MockTaskQueue()

        # Kerberoast hash for krbtgt (unusual but possible)
        kerberoast_hash = Hash(
            username="krbtgt",
            hash_value="$krb5tgs$23$*krbtgt$CONTOSO.LOCAL$...",
            hash_type="Kerberoast",
            domain="contoso.local",
            source="kerberoast",
        )

        monkeypatch.setattr(
            "ares.core.dispatcher.publishing.threading.current_thread",
            lambda: MagicMock(name="ResultConsumer"),
        )
        monkeypatch.setattr(
            "ares.core.dispatcher.publishing.threading.main_thread",
            lambda: MagicMock(name="MainThread"),
        )

        await dispatcher.publish_hash(
            kerberoast_hash, "ares-credential-access", task_queue=task_queue
        )

        # Kerberoast hash should not trigger DA (only NTLM krbtgt does)
        assert dispatcher.shared_state.has_domain_admin is False

    @pytest.mark.asyncio
    async def test_main_thread_uses_checkpoint_for_da(self, dispatcher, monkeypatch):
        """Test that main thread uses checkpoint (not direct Redis) for DA persistence."""
        checkpoint_called = False

        async def mock_checkpoint():
            nonlocal checkpoint_called
            checkpoint_called = True

        dispatcher._checkpoint = mock_checkpoint

        # Simulate main thread context
        main_thread = MagicMock(name="MainThread")
        monkeypatch.setattr(
            "ares.core.dispatcher.publishing.threading.current_thread",
            lambda: main_thread,
        )
        monkeypatch.setattr(
            "ares.core.dispatcher.publishing.threading.main_thread",
            lambda: main_thread,
        )

        krbtgt_hash = Hash(
            username="krbtgt",
            hash_value="aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0",
            hash_type="NTLM",
            domain="contoso.local",
            source="secretsdump",
        )

        await dispatcher.publish_hash(krbtgt_hash, "ares-credential-access", task_queue=None)

        # Main thread should use checkpoint
        assert checkpoint_called, "Main thread should call _checkpoint()"
        assert dispatcher.shared_state.has_domain_admin is True


class TestPublishSharePersistence:
    """Tests for Share persistence to Redis from threaded consumers.

    When the threaded result consumer discovers shares, it must
    persist them directly to Redis using task_queue.redis.
    """

    @pytest.fixture
    def dispatcher(self):
        """Create a dispatcher with mocked internals."""
        d = RedTeamDispatcher()
        d._shared_state = SharedRedTeamState(operation_id="test-op-share")
        d._checkpoint_requested = MagicMock()
        return d

    @pytest.mark.asyncio
    async def test_share_persists_to_redis_from_threaded_consumer(self, dispatcher, monkeypatch):
        """Test that share discovery triggers direct Redis persistence from threaded consumer."""
        from ares.core.models import Share

        task_queue = MockTaskQueue()

        share = Share(
            host="dc01.contoso.local",
            name="SYSVOL",
            permissions="READ",
        )

        # Mock threading to simulate threaded consumer context
        monkeypatch.setattr(
            "ares.core.dispatcher.publishing.threading.current_thread",
            lambda: MagicMock(name="ResultConsumer"),
        )
        monkeypatch.setattr(
            "ares.core.dispatcher.publishing.threading.main_thread",
            lambda: MagicMock(name="MainThread"),
        )

        result = await dispatcher.publish_share(share, "ares-recon", task_queue=task_queue)

        assert result is True
        assert share in dispatcher.shared_state.all_shares

        # Verify Redis calls include share persistence (shares use hset to HASH for dedup)
        redis_calls = task_queue.redis.calls
        hset_calls = [c for c in redis_calls if c[0] == "hset" and "share" in c[1].lower()]
        assert len(hset_calls) >= 1, (
            f"Should persist share to Redis via hset, got calls: {redis_calls}"
        )

    @pytest.mark.asyncio
    async def test_share_without_task_queue_sets_checkpoint_requested(
        self, dispatcher, monkeypatch
    ):
        """Test that share discovery without task_queue sets checkpoint_requested flag."""
        from ares.core.models import Share

        share = Share(
            host="dc01.contoso.local",
            name="C$",
            permissions="READ,WRITE",
        )

        # Mock threading to simulate threaded consumer context (no main thread)
        monkeypatch.setattr(
            "ares.core.dispatcher.publishing.threading.current_thread",
            lambda: MagicMock(name="ResultConsumer"),
        )
        monkeypatch.setattr(
            "ares.core.dispatcher.publishing.threading.main_thread",
            lambda: MagicMock(name="MainThread"),
        )

        result = await dispatcher.publish_share(share, "ares-recon", task_queue=None)

        assert result is True
        assert share in dispatcher.shared_state.all_shares
        # Should request checkpoint since no task_queue for direct persist
        dispatcher._checkpoint_requested.set.assert_called()

    @pytest.mark.asyncio
    async def test_main_thread_uses_checkpoint_for_share(self, dispatcher, monkeypatch):
        """Test that main thread uses checkpoint (not direct Redis) for share persistence."""
        from ares.core.models import Share

        checkpoint_called = False

        async def mock_checkpoint():
            nonlocal checkpoint_called
            checkpoint_called = True

        dispatcher._checkpoint = mock_checkpoint

        share = Share(
            host="sql01.contoso.local",
            name="SQLData",
            permissions="READ",
        )

        # Simulate main thread context
        main_thread = MagicMock(name="MainThread")
        monkeypatch.setattr(
            "ares.core.dispatcher.publishing.threading.current_thread",
            lambda: main_thread,
        )
        monkeypatch.setattr(
            "ares.core.dispatcher.publishing.threading.main_thread",
            lambda: main_thread,
        )

        result = await dispatcher.publish_share(share, "ares-recon", task_queue=None)

        assert result is True
        assert checkpoint_called, "Main thread should call _checkpoint()"

    @pytest.mark.asyncio
    async def test_duplicate_share_not_added(self, dispatcher, monkeypatch):
        """Test that duplicate shares are not re-added."""
        from ares.core.models import Share

        share = Share(
            host="dc01.contoso.local",
            name="NETLOGON",
            permissions="READ",
        )

        # Simulate main thread
        main_thread = MagicMock(name="MainThread")
        monkeypatch.setattr(
            "ares.core.dispatcher.publishing.threading.current_thread",
            lambda: main_thread,
        )
        monkeypatch.setattr(
            "ares.core.dispatcher.publishing.threading.main_thread",
            lambda: main_thread,
        )

        async def mock_checkpoint():
            pass

        dispatcher._checkpoint = mock_checkpoint

        # Add share first time
        result1 = await dispatcher.publish_share(share, "ares-recon")
        assert result1 is True

        # Add same share again
        result2 = await dispatcher.publish_share(share, "ares-recon")
        assert result2 is False  # Duplicate should return False
