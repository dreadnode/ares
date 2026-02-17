"""State persistence via RedisStateBackend.

State persists directly on each mutation via RedisStateBackend when called from
the main event loop. When mutations happen in the threaded result consumer
(different event loop), direct persistence fails and _checkpoint() is called
to persist all in-memory state to Redis.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from loguru import logger

from ares.core.models import SharedRedTeamState

if TYPE_CHECKING:
    from collections.abc import Callable

    from ares.core.dispatcher._dispatcher import RedTeamDispatcher


class PersistenceMixin:
    """State persistence via RedisStateBackend.

    Direct persistence on mutation when in main event loop.
    Checkpoint fallback for threaded consumer mutations.
    """

    async def _persist_collection(
        self: RedTeamDispatcher,
        key: str,
        items: list[Any],
        serializer: Callable[[Any], str],
        ttl: int,
    ) -> None:
        """Persist a collection to Redis LIST using clear-and-rewrite."""
        if not items:
            return
        pipe = self._redis_client.pipeline()
        pipe.delete(key)
        for item in items:
            pipe.rpush(key, serializer(item))
        pipe.expire(key, ttl)
        await pipe.execute()

    async def _persist_hashes(
        self: RedTeamDispatcher,
        key: str,
        hashes: list[Any],
        serializer: Callable[[Any], str],
        ttl: int,
    ) -> None:
        """Persist hashes to Redis HASH using clear-and-rewrite with dedup keys."""
        if not hashes:
            return

        from ares.core.state_backend import RedisStateBackend

        # Create a temporary backend instance just for building dedup keys
        backend = RedisStateBackend(self._redis_client, self.shared_state.operation_id)

        pipe = self._redis_client.pipeline()
        pipe.delete(key)
        for h in hashes:
            hash_type = (h.hash_type or "").strip().lower()
            hash_value = h.hash_value or ""
            username = (h.username or "").strip().lower()
            domain = (h.domain or "").strip().lower()
            dedup_key = backend._build_hash_dedup_key(hash_type, hash_value, domain, username)
            pipe.hset(key, dedup_key, serializer(h))
        pipe.expire(key, ttl)
        await pipe.execute()

    async def _checkpoint(self: RedTeamDispatcher) -> None:
        """Persist all in-memory state to Redis.

        This is called when:
        1. Threaded result consumer adds new data (event loop mismatch prevents direct persist)
        2. Periodic checkpoint interval (safety net)

        Persists all collections: hosts, credentials, hashes, shares, users, etc.
        Uses clear-and-rewrite for simplicity and correctness.
        """
        if not self.shared_state or not self.shared_state._backend:
            return

        backend = self.shared_state._backend
        op_id = self.shared_state.operation_id

        try:
            from ares.core.state_backend import (
                _serialize_credential,
                _serialize_hash,
                _serialize_host,
                _serialize_share,
            )

            ttl = backend.DEFAULT_TTL

            # Persist all collections
            await self._persist_collection(
                f"ares:op:{op_id}:hosts",
                self.shared_state.all_hosts,
                _serialize_host,
                ttl,
            )
            await self._persist_collection(
                f"ares:op:{op_id}:shares",
                self.shared_state.all_shares,
                _serialize_share,
                ttl,
            )
            await self._persist_collection(
                f"ares:op:{op_id}:credentials",
                self.shared_state.all_credentials,
                _serialize_credential,
                ttl,
            )
            # Hashes use Redis HASH (not LIST) for O(1) deduplication
            await self._persist_hashes(
                f"ares:op:{op_id}:hashes",
                self.shared_state.all_hashes,
                _serialize_hash,
                ttl,
            )

            # Persist weaknesses (SET, not LIST)
            if self.shared_state.all_weaknesses:
                weaknesses_key = f"ares:op:{op_id}:weaknesses"
                pipe = self._redis_client.pipeline()
                pipe.delete(weaknesses_key)
                for w in self.shared_state.all_weaknesses:
                    pipe.sadd(weaknesses_key, w)
                pipe.expire(weaknesses_key, ttl)
                await pipe.execute()

            # Persist exploited_vulnerabilities (SET of vuln_ids)
            # Critical: This tracks which vulnerabilities have been exploited.
            # Without this, threaded consumer updates are lost (event loop mismatch).
            if self.shared_state.exploited_vulnerabilities:
                exploited_key = f"ares:op:{op_id}:exploited"
                pipe = self._redis_client.pipeline()
                pipe.delete(exploited_key)
                for vuln_id in self.shared_state.exploited_vulnerabilities:
                    pipe.sadd(exploited_key, vuln_id)
                pipe.expire(exploited_key, ttl)
                await pipe.execute()

            # Persist DC map
            for domain, dc_ip in self.shared_state.domain_controllers.items():
                await backend.set_dc(domain, dc_ip)

            # Meta flags - always persist current values
            await backend.set_meta("has_domain_admin", value=self.shared_state.has_domain_admin)
            await backend.set_meta("has_golden_ticket", value=self.shared_state.has_golden_ticket)
            if self.shared_state.domain_admin_path:
                await backend.set_meta("domain_admin_path", self.shared_state.domain_admin_path)

            logger.debug(
                f"Checkpoint complete: {len(self.shared_state.all_hosts)} hosts, "
                f"{len(self.shared_state.all_shares)} shares, "
                f"{len(self.shared_state.all_credentials)} creds, "
                f"{len(self.shared_state.all_hashes)} hashes, "
                f"{len(self.shared_state.exploited_vulnerabilities)} exploited"
            )

        except Exception as e:
            logger.error(f"Checkpoint failed: {e}")

    async def recover_state(
        self: RedTeamDispatcher, operation_id: str
    ) -> SharedRedTeamState | None:
        """Recover state from Redis-native storage.

        Args:
            operation_id: The operation ID to recover.

        Returns:
            Recovered state or None if not found.
        """
        if self._redis_client is None:
            return None

        try:
            from ares.core.state_backend import RedisStateBackend

            backend = RedisStateBackend(self._redis_client, operation_id)
            meta_key = f"ares:op:{operation_id}:meta"

            if not await self._redis_client.exists(meta_key):
                return None

            state = SharedRedTeamState(operation_id=operation_id)
            state.set_backend(backend)

            # Load state from backend
            from ares.core.recovery import OperationRecoveryManager

            manager = OperationRecoveryManager(redis_url=None)
            manager._redis_client = self._redis_client
            await manager._load_state_from_backend(state, backend)

            self._shared_state = state
            logger.info(f"Recovered state for operation {operation_id}")
            return state

        except Exception as e:
            logger.error(f"Failed to recover state: {e}")
            return None


__all__ = ["PersistenceMixin"]
