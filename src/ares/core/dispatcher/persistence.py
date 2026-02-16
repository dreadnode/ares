"""State persistence via RedisStateBackend.

State now persists directly on each mutation via RedisStateBackend.
This mixin provides legacy checkpoint compatibility (no-op) and recovery.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from loguru import logger

from ares.core.models import SharedRedTeamState

if TYPE_CHECKING:
    from ares.core.dispatcher._dispatcher import RedTeamDispatcher


class PersistenceMixin:
    """State persistence via RedisStateBackend.

    Legacy checkpoint methods are no-ops since state persists on each mutation.
    """

    async def _checkpoint(self: RedTeamDispatcher) -> None:
        """No-op: State persists directly via RedisStateBackend on mutation."""

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
