"""State persistence for checkpointing and recovery.

This module provides methods to checkpoint state to Redis and recover from checkpoints.
"""

from __future__ import annotations

import threading
from typing import TYPE_CHECKING

from loguru import logger

from ares.core.models import SharedRedTeamState
from ares.core.recovery import _merge_state

if TYPE_CHECKING:
    from ares.core.dispatcher._dispatcher import RedTeamDispatcher


class PersistenceMixin:
    """State persistence for checkpointing and recovery."""

    async def _checkpoint(self: RedTeamDispatcher) -> None:
        """Save state checkpoint to Redis if available.

        IMPORTANT: This method merges with existing Redis state before writing
        to prevent race conditions where multiple workers/orchestrator overwrite
        each other's discoveries. All state is additive (credentials, hosts, etc.)
        so merging is safe and ensures no discoveries are lost.

        NOTE: This method is a no-op when called from a non-main thread (e.g., the
        threaded result consumer). The Redis client is bound to the main event loop
        and will fail with "Future attached to a different loop" if used from a
        different thread. The maintenance loop handles periodic checkpointing for
        state changes made in background threads.
        """
        if self._redis_client is None:
            return

        # Skip if called from a non-main thread (e.g., threaded result consumer)
        # The maintenance loop will checkpoint periodically on the main thread
        if threading.current_thread() is not threading.main_thread():
            return

        try:
            key = f"ares:operation:{self.shared_state.operation_id}:state"

            # Merge with existing state to prevent overwrites from other workers
            existing_data = await self._redis_client.get(key)
            if existing_data:
                try:
                    existing_state = SharedRedTeamState.from_bytes(existing_data)
                    _merge_state(self.shared_state, existing_state)
                except Exception as exc:
                    logger.warning(f"Failed to merge existing checkpoint state: {exc}")

            # Debug: log state counts after merge
            logger.debug(
                f"[Dispatcher checkpoint] hosts={len(self.shared_state.all_hosts)}, "
                f"creds={len(self.shared_state.all_credentials)}, hashes={len(self.shared_state.all_hashes)}"
            )
            await self._redis_client.set(key, self.shared_state.to_bytes())
            await self._redis_client.expire(key, 86400)  # 24 hour TTL

            # Publish state update notification via pub/sub for real-time worker sync
            if self._task_queue:
                await self._task_queue.publish_state_update(self.shared_state.operation_id)
        except Exception as e:
            logger.warning(f"Failed to checkpoint state: {e}")

    async def recover_state(
        self: RedTeamDispatcher, operation_id: str
    ) -> SharedRedTeamState | None:
        """
        Recover state from Redis checkpoint.

        Args:
            operation_id: The operation ID to recover.

        Returns:
            Recovered state or None if not found.
        """
        if self._redis_client is None:
            return None

        try:
            key = f"ares:operation:{operation_id}:state"
            data = await self._redis_client.get(key)
            if data:
                state = SharedRedTeamState.from_bytes(data)
                self._shared_state = state
                logger.info(f"Recovered state for operation {operation_id}")
                return state
        except Exception as e:
            logger.error(f"Failed to recover state: {e}")

        return None


__all__ = ["PersistenceMixin"]
