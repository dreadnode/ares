"""State persistence via RedisStateBackend.

State persists directly on each mutation via RedisStateBackend when called from
the main event loop. When mutations happen in the threaded result consumer
(different event loop), direct persistence fails and _checkpoint() is called
to persist all in-memory state to Redis.
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import TYPE_CHECKING, Any

from loguru import logger

from ares.core.models import SharedRedTeamState, TaskInfo, TaskResult, TaskStatus

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

    async def _persist_credentials(
        self: RedTeamDispatcher,
        key: str,
        credentials: list[Any],
        serializer: Callable[[Any], str],
        ttl: int,
    ) -> None:
        """Persist credentials to Redis HASH using HSET (additive, no delete).

        Uses dedup key {domain}:{username}:{password_hash} to prevent duplicates.
        HSET is idempotent so no DELETE needed - same credential overwrites itself.

        CRITICAL: NO DELETE! Workers persist directly to Redis, orchestrator's
        in-memory state may not have worker credentials yet. DELETE would wipe them.
        """
        if not credentials:
            return

        from ares.core.state_backend import RedisStateBackend

        backend = RedisStateBackend(self._redis_client, self.shared_state.operation_id)

        pipe = self._redis_client.pipeline()
        # NO DELETE - additive HSET preserves worker-persisted credentials
        for cred in credentials:
            dedup_key = backend._build_credential_dedup_key(cred)
            pipe.hset(key, dedup_key, serializer(cred))
        pipe.expire(key, ttl)
        await pipe.execute()

    async def _persist_hashes(
        self: RedTeamDispatcher,
        key: str,
        hashes: list[Any],
        serializer: Callable[[Any], str],
        ttl: int,
    ) -> None:
        """Persist hashes to Redis HASH using HSET (additive, no delete).

        Uses dedup key to prevent duplicates. HSET is idempotent so no DELETE needed.

        CRITICAL: NO DELETE! Workers persist directly to Redis, orchestrator's
        in-memory state may not have worker hashes yet. DELETE would wipe them.
        """
        if not hashes:
            return

        from ares.core.state_backend import RedisStateBackend

        # Create a temporary backend instance just for building dedup keys
        backend = RedisStateBackend(self._redis_client, self.shared_state.operation_id)

        pipe = self._redis_client.pipeline()
        # NO DELETE - additive HSET preserves worker-persisted hashes
        for h in hashes:
            hash_type = (h.hash_type or "").strip().lower()
            hash_value = h.hash_value or ""
            username = (h.username or "").strip().lower()
            domain = (h.domain or "").strip().lower()
            dedup_key = backend._build_hash_dedup_key(hash_type, hash_value, domain, username)
            pipe.hset(key, dedup_key, serializer(h))
        pipe.expire(key, ttl)
        await pipe.execute()

    async def _persist_set_additive(
        self: RedTeamDispatcher, key: str, items: list | set, ttl: int
    ) -> None:
        """Persist items to a Redis SET using SADD (additive, no delete)."""
        if not items:
            return
        pipe = self._redis_client.pipeline()
        for item in items:
            pipe.sadd(key, item)
        pipe.expire(key, ttl)
        await pipe.execute()

    async def _persist_hash_additive(
        self: RedTeamDispatcher, key: str, items: dict, serializer: Callable, ttl: int
    ) -> None:
        """Persist items to a Redis HASH using HSET (additive, no delete)."""
        if not items:
            return
        pipe = self._redis_client.pipeline()
        for item_key, item in items.items():
            pipe.hset(key, item_key, serializer(item))
        pipe.expire(key, ttl)
        await pipe.execute()

    def _serialize_task_info(self: RedTeamDispatcher, task_info: TaskInfo) -> str:
        """Serialize TaskInfo to JSON string for Redis storage."""
        task_dict: dict[str, Any] = {
            "task_id": task_info.task_id,
            "task_type": task_info.task_type,
            "assigned_agent": task_info.assigned_agent,
            "status": task_info.status.value,
            "created_at": task_info.created_at.isoformat(),
            "last_activity_at": task_info.last_activity_at.isoformat(),
            "retry_count": task_info.retry_count,
        }
        if task_info.started_at:
            task_dict["started_at"] = task_info.started_at.isoformat()
        if task_info.params:
            task_dict["params"] = task_info.params
        return json.dumps(task_dict)

    async def _persist_task_info_to_redis(
        self: RedTeamDispatcher,
        task_id: str,
        task_info: TaskInfo,
        task_queue: Any = None,
    ) -> None:
        """Persist a single TaskInfo to Redis immediately on dispatch.

        This is called when a task is dispatched to ensure Redis is the source of truth.
        The in-memory pending_tasks dict becomes a cache.

        Args:
            task_id: The task ID.
            task_info: The TaskInfo to persist.
            task_queue: Optional task queue for threaded consumer (uses task_queue.redis).
        """
        if not self.shared_state:
            return

        pending_key = f"ares:op:{self.shared_state.operation_id}:pending_tasks"
        task_json = self._serialize_task_info(task_info)

        # Determine which Redis client to use
        redis_client = None
        if task_queue is not None:
            # Threaded consumer: use task_queue.redis
            redis_client = task_queue.redis
        elif self._redis_client is not None:
            # Main thread: use dispatcher's Redis client
            redis_client = self._redis_client

        if redis_client is None:
            logger.debug(f"No Redis client available to persist task {task_id}")
            return

        try:
            await redis_client.hset(pending_key, task_id, task_json)
            logger.debug(f"Persisted task {task_id} to Redis pending_tasks")
        except Exception as e:
            logger.warning(f"Failed to persist task {task_id} to Redis: {e}")

    async def _get_task_info_from_redis(
        self: RedTeamDispatcher,
        task_id: str,
        task_queue: Any = None,
    ) -> TaskInfo | None:
        """Retrieve TaskInfo from Redis (fallback when not in memory cache).

        This is called by complete_task() when the task is not found in the
        in-memory pending_tasks dict. Redis is the source of truth.

        Args:
            task_id: The task ID to retrieve.
            task_queue: Optional task queue for threaded consumer (uses task_queue.redis).

        Returns:
            TaskInfo if found in Redis, None otherwise.
        """
        if not self.shared_state:
            return None

        pending_key = f"ares:op:{self.shared_state.operation_id}:pending_tasks"

        # Determine which Redis client to use
        redis_client = None
        if task_queue is not None:
            # Threaded consumer: use task_queue.redis
            redis_client = task_queue.redis
        elif self._redis_client is not None:
            # Main thread: use dispatcher's Redis client
            redis_client = self._redis_client

        if redis_client is None:
            return None

        try:
            task_data_raw = await redis_client.hget(pending_key, task_id)
            if not task_data_raw:
                return None

            data = json.loads(task_data_raw)

            # Parse datetimes
            created_at = datetime.fromisoformat(data.get("created_at", ""))
            last_activity_at = datetime.fromisoformat(
                data.get("last_activity_at", data.get("created_at", ""))
            )
            started_at = None
            if data.get("started_at"):
                started_at = datetime.fromisoformat(data["started_at"])

            task_info = TaskInfo(
                task_id=task_id,
                task_type=data.get("task_type", "unknown"),
                assigned_agent=data.get("assigned_agent", "unknown"),
                status=TaskStatus(data.get("status", "pending")),
                created_at=created_at,
                started_at=started_at,
                last_activity_at=last_activity_at,
                retry_count=data.get("retry_count", 0),
                params=data.get("params", {}),
            )

            logger.debug(f"Retrieved task {task_id} from Redis (not in memory cache)")
            return task_info

        except Exception as e:
            logger.warning(f"Failed to get task {task_id} from Redis: {e}")
            return None

    async def _persist_pending_tasks(self: RedTeamDispatcher, op_id: str, ttl: int) -> None:
        """Persist pending_tasks to Redis (additive, no delete).

        CRITICAL: NO DELETE! Tasks are written to Redis immediately on dispatch.
        Checkpoint is additive to preserve tasks dispatched but not yet in memory.
        Completed tasks are removed from Redis in complete_task().
        """
        if not self.shared_state.pending_tasks:
            return

        pending_key = f"ares:op:{op_id}:pending_tasks"
        pipe = self._redis_client.pipeline()
        # NO DELETE - additive HSET preserves tasks already in Redis
        for task_id, task_info in self.shared_state.pending_tasks.items():
            pipe.hset(pending_key, task_id, self._serialize_task_info(task_info))
        pipe.expire(pending_key, ttl)
        await pipe.execute()

    async def _persist_completed_tasks(self: RedTeamDispatcher, op_id: str, ttl: int) -> None:
        """Persist completed_tasks to Redis (additive, no delete)."""
        if not self.shared_state.completed_tasks:
            return
        completed_key = f"ares:op:{op_id}:completed_tasks"
        pipe = self._redis_client.pipeline()
        for task_id, task_result in self.shared_state.completed_tasks.items():
            result_dict = {
                "task_id": task_result.task_id,
                "success": task_result.success,
                "result": task_result.result,
                "error": task_result.error,
                "completed_at": task_result.completed_at.isoformat(),
            }
            pipe.hset(completed_key, task_id, json.dumps(result_dict, default=str))
        pipe.expire(completed_key, ttl)
        await pipe.execute()

    async def _checkpoint(self: RedTeamDispatcher) -> None:
        """Persist all in-memory state to Redis.

        This is called when:
        1. Threaded result consumer adds new data (event loop mismatch prevents direct persist)
        2. Periodic checkpoint interval (safety net)

        Persists all collections: hosts, credentials, hashes, shares, users, etc.
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
                _serialize_vulnerability,
            )

            ttl = backend.DEFAULT_TTL

            # Persist list collections (clear-and-rewrite)
            await self._persist_collection(
                f"ares:op:{op_id}:hosts", self.shared_state.all_hosts, _serialize_host, ttl
            )
            await self._persist_collection(
                f"ares:op:{op_id}:shares", self.shared_state.all_shares, _serialize_share, ttl
            )

            # Persist credentials using HASH (additive, no delete - preserves worker data)
            await self._persist_credentials(
                f"ares:op:{op_id}:credentials",
                self.shared_state.all_credentials,
                _serialize_credential,
                ttl,
            )
            await self._persist_hashes(
                f"ares:op:{op_id}:hashes", self.shared_state.all_hashes, _serialize_hash, ttl
            )

            # Persist SET collections (additive, no delete - preserves worker data)
            await self._persist_set_additive(
                f"ares:op:{op_id}:weaknesses", self.shared_state.all_weaknesses, ttl
            )
            await self._persist_set_additive(
                f"ares:op:{op_id}:exploited", self.shared_state.exploited_vulnerabilities, ttl
            )

            # Persist HASH collections (additive, no delete - preserves worker data)
            await self._persist_hash_additive(
                f"ares:op:{op_id}:vulns",
                self.shared_state.discovered_vulnerabilities,
                _serialize_vulnerability,
                ttl,
            )
            await self._persist_hash_additive(
                f"ares:op:{op_id}:artifacts",
                self.shared_state.downloaded_artifacts,
                lambda x: x,
                ttl,
            )

            # Persist DC map and meta flags
            for domain, dc_ip in self.shared_state.domain_controllers.items():
                await backend.set_dc(domain, dc_ip)

            # ADDITIVE pattern: only upgrade False→True, never downgrade
            # Don't write False (it's the default and can't downgrade from True)
            if self.shared_state.has_domain_admin:
                current_da = await backend.get_meta("has_domain_admin", default=False)
                if not current_da:
                    await backend.set_meta("has_domain_admin", value=True)

            if self.shared_state.has_golden_ticket:
                current_gt = await backend.get_meta("has_golden_ticket", default=False)
                if not current_gt:
                    await backend.set_meta("has_golden_ticket", value=True)
            if self.shared_state.domain_admin_path:
                await backend.set_meta("domain_admin_path", self.shared_state.domain_admin_path)
            # Persist completed_at timestamp (set in-memory when DA achieved via add_hash)
            if self.shared_state.completed_at:
                await backend.set_meta("completed_at", self.shared_state.completed_at.isoformat())

            # Persist task tracking state
            await self._persist_pending_tasks(op_id, ttl)
            await self._persist_completed_tasks(op_id, ttl)

            logger.debug(
                f"Checkpoint complete: {len(self.shared_state.all_hosts)} hosts, "
                f"{len(self.shared_state.all_shares)} shares, "
                f"{len(self.shared_state.all_credentials)} creds, "
                f"{len(self.shared_state.all_hashes)} hashes, "
                f"{len(self.shared_state.discovered_vulnerabilities)} vulns, "
                f"{len(self.shared_state.exploited_vulnerabilities)} exploited, "
                f"{len(self.shared_state.downloaded_artifacts)} artifacts, "
                f"{len(self.shared_state.pending_tasks)} pending, "
                f"{len(self.shared_state.completed_tasks)} completed"
            )

        except Exception as e:
            logger.error(f"Checkpoint failed: {e}")

    async def _load_pending_tasks(self: RedTeamDispatcher) -> None:
        """Load pending tasks from Redis on startup.

        This recovers throttle state after orchestrator restart, preventing
        task dispatch storms when the orchestrator doesn't know about in-flight tasks.
        """
        if self._redis_client is None or not self.shared_state:
            return

        op_id = self.shared_state.operation_id
        pending_key = f"ares:op:{op_id}:pending_tasks"

        try:
            raw = await self._redis_client.hgetall(pending_key)
            if not raw:
                return

            loaded = 0
            for task_id_raw, task_data_raw in raw.items():
                task_id = task_id_raw if isinstance(task_id_raw, str) else task_id_raw.decode()
                try:
                    data = json.loads(task_data_raw)

                    # Parse datetimes
                    created_at = datetime.fromisoformat(data.get("created_at", ""))
                    last_activity_at = datetime.fromisoformat(
                        data.get("last_activity_at", data.get("created_at", ""))
                    )
                    started_at = None
                    if data.get("started_at"):
                        started_at = datetime.fromisoformat(data["started_at"])

                    task_info = TaskInfo(
                        task_id=task_id,
                        task_type=data.get("task_type", "unknown"),
                        assigned_agent=data.get("assigned_agent", "unknown"),
                        status=TaskStatus(data.get("status", "pending")),
                        created_at=created_at,
                        started_at=started_at,
                        last_activity_at=last_activity_at,
                        retry_count=data.get("retry_count", 0),
                    )
                    self.shared_state.pending_tasks[task_id] = task_info
                    loaded += 1
                except (json.JSONDecodeError, ValueError, KeyError) as e:
                    logger.warning(f"Failed to parse pending task {task_id}: {e}")

            if loaded:
                logger.info(f"Loaded {loaded} pending tasks from Redis for throttle recovery")

        except Exception as e:
            logger.warning(f"Failed to load pending tasks from Redis: {e}")

    async def _load_completed_tasks(self: RedTeamDispatcher) -> None:
        """Load completed tasks from Redis on startup.

        This is critical for:
        1. Task deduplication - prevents re-dispatching already-completed tasks
        2. Secretsdump dedup - workflows check completed_tasks to avoid re-dumping hosts
        3. wait_for_task() - returns cached results instead of hanging
        """
        if self._redis_client is None or not self.shared_state:
            return

        op_id = self.shared_state.operation_id
        completed_key = f"ares:op:{op_id}:completed_tasks"

        try:
            raw = await self._redis_client.hgetall(completed_key)
            if not raw:
                return

            loaded = 0
            for task_id_raw, task_data_raw in raw.items():
                task_id = task_id_raw if isinstance(task_id_raw, str) else task_id_raw.decode()
                try:
                    data = json.loads(task_data_raw)

                    # Parse completed_at datetime
                    completed_at = datetime.fromisoformat(data.get("completed_at", ""))

                    task_result = TaskResult(
                        task_id=task_id,
                        success=data.get("success", False),
                        result=data.get("result"),
                        error=data.get("error"),
                        completed_at=completed_at,
                    )
                    self.shared_state.completed_tasks[task_id] = task_result
                    loaded += 1
                except (json.JSONDecodeError, ValueError, KeyError) as e:
                    logger.warning(f"Failed to parse completed task {task_id}: {e}")

            if loaded:
                logger.info(f"Loaded {loaded} completed tasks from Redis for deduplication")

        except Exception as e:
            logger.warning(f"Failed to load completed tasks from Redis: {e}")

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
