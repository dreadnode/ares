"""Redis-native state backend for blue team investigations.

This module provides Redis-native storage for blue team investigation state,
mirroring the pattern established in state_backend.py (RedisStateBackend) for
red team operations.

Key design decisions:
- Evidence uses Redis HASH (dedup_key -> JSON) for O(1) deduplication via HSETNX
- Timeline and lateral connections use Redis LIST (ordered, append-only)
- Techniques, tactics, hosts, users, and query_types use Redis SET (auto-dedup)
- Technique names use Redis HASH (technique_id -> name)
- Meta scalars use Redis HASH (field -> JSON value)
- Queues (pivot, chain) use Redis LIST consumed via drain-all reads
- Tasks use Redis HASH (task_id -> JSON) split into pending/completed
- Recommendations use Redis LIST (ordered, append-only)

Redis key structure:
    ares:blue:inv:{id}:evidence          HASH (dedup_key -> JSON)
    ares:blue:inv:{id}:timeline          LIST (JSON events, ordered)
    ares:blue:inv:{id}:techniques        SET
    ares:blue:inv:{id}:tactics           SET
    ares:blue:inv:{id}:hosts             SET (queried hosts)
    ares:blue:inv:{id}:users             SET (queried users)
    ares:blue:inv:{id}:query_types       SET (executed detection method names)
    ares:blue:inv:{id}:queries           LIST (executed query records)
    ares:blue:inv:{id}:lateral           LIST (JSON connections)
    ares:blue:inv:{id}:pivot_queue       LIST
    ares:blue:inv:{id}:chain_queue       LIST
    ares:blue:inv:{id}:dedup:evidence    SET (evidence dedup keys)
    ares:blue:inv:{id}:meta              HASH (stage, escalated, synopsis, alert JSON, etc.)
    ares:blue:inv:{id}:tasks:pending     HASH (task_id -> JSON)
    ares:blue:inv:{id}:tasks:completed   HASH (task_id -> JSON)
    ares:blue:inv:{id}:technique_names   HASH (tech_id -> name)
    ares:blue:inv:{id}:recommendations   LIST

Resilience:
    All write operations use tenacity retry with exponential backoff + circuit breaker
    to handle transient Redis connection issues (e.g., Sentinel failover, pod restarts).
    Pattern matches redis-py's ExponentialBackoff(cap=10, base=1).
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

from loguru import logger

from ares.core.circuit_breaker import CircuitBreakerError
from ares.core.redis_backend_base import BaseRedisBackend

if TYPE_CHECKING:
    from redis.asyncio import Redis


class BlueStateBackend(BaseRedisBackend):
    """Redis-native state storage for blue team investigations.

    This backend stores investigation state directly in Redis using native data
    structures, eliminating the need for full JSON checkpoint serialization on
    every mutation.

    Thread Safety:
        This class is designed to be used from async contexts. All methods are
        async and use the provided Redis client.

    Key Prefix:
        All keys are prefixed with ``ares:blue:inv:{investigation_id}:`` to
        namespace state per investigation and allow multiple concurrent
        investigations.

    TTL:
        All keys are set with a 24-hour TTL to auto-cleanup completed
        investigations.
    """

    # Key prefix
    KEY_PREFIX = "ares:blue:inv"

    # Collection keys
    KEY_EVIDENCE = "evidence"
    KEY_TIMELINE = "timeline"
    KEY_TECHNIQUES = "techniques"
    KEY_TACTICS = "tactics"
    KEY_HOSTS = "hosts"
    KEY_USERS = "users"
    KEY_QUERY_TYPES = "query_types"
    KEY_QUERIES = "queries"
    KEY_LATERAL = "lateral"
    KEY_PIVOT_QUEUE = "pivot_queue"
    KEY_CHAIN_QUEUE = "chain_queue"
    KEY_META = "meta"
    KEY_PENDING_TASKS = "tasks:pending"
    KEY_COMPLETED_TASKS = "tasks:completed"
    KEY_TECHNIQUE_NAMES = "technique_names"
    KEY_RECOMMENDATIONS = "recommendations"
    KEY_TRIAGE_DECISION = "triage:decision"
    KEY_TRIAGE_RECORDS = "triage:records"

    # Dedup set prefix
    KEY_DEDUP_PREFIX = "dedup"

    def __init__(
        self,
        redis_client: Redis,
        investigation_id: str,
        *,
        use_circuit_breaker: bool = True,
    ) -> None:
        """Initialize the backend.

        Args:
            redis_client: Async Redis client (from create_redis_client).
            investigation_id: Unique investigation identifier.
            use_circuit_breaker: Enable circuit breaker + retry for resilience.
        """
        super().__init__(redis_client, investigation_id, use_circuit_breaker=use_circuit_breaker)
        # Keep _investigation_id for backward compatibility
        self._investigation_id = investigation_id

    def _build_key_prefix(self, entity_id: str) -> str:
        """Build key prefix for blue team investigations."""
        return f"{self.KEY_PREFIX}:{entity_id}"

    @property
    def _log_prefix(self) -> str:
        """Log prefix for error messages."""
        return "blue_state_backend"

    # =========================================================================
    # Evidence (Redis HASH with HSETNX for O(1) deduplication)
    # =========================================================================

    async def add_evidence(self, evidence_dict: dict) -> bool:
        """Add evidence to Redis HASH with O(1) deduplication via HSETNX.

        Deduplication key: ``{type}:{value_lower}`` derived from the evidence
        dict's ``type`` and ``value`` fields (case-insensitive).

        Uses circuit breaker + exponential backoff retry for resilience.

        Args:
            evidence_dict: JSON-serializable evidence data. Expected to contain
                at least ``type`` and ``value`` fields for dedup key generation.

        Returns:
            True if added (new), False if duplicate or error.
        """
        key = self._key(self.KEY_EVIDENCE)
        ev_type = str(evidence_dict.get("type", "unknown")).strip().lower()
        ev_value = str(evidence_dict.get("value", "")).strip().lower()
        dedup_field = f"{ev_type}:{ev_value}"
        data = json.dumps(evidence_dict, separators=(",", ":"), default=str)

        async def _do_add():
            # HSETNX returns 1 if field was set (new), 0 if already existed
            added = await self._redis.hsetnx(key, dedup_field, data)
            if not added:
                logger.debug(f"Evidence rejected (duplicate): {dedup_field}")
                return False
            await self._set_ttl(key)
            return True

        try:
            return await self._with_retry("add_evidence", _do_add)
        except CircuitBreakerError:
            logger.debug(f"Circuit breaker open, skipping add_evidence for {dedup_field}")
            return False
        except Exception as e:
            logger.warning(f"Failed to add evidence to Redis: {e}")
            return False

    # =========================================================================
    # Timeline (Redis LIST)
    # =========================================================================

    async def add_timeline_event(self, event_dict: dict) -> None:
        """Append a timeline event to the ordered list.

        Args:
            event_dict: JSON-serializable event data.
        """
        key = self._key(self.KEY_TIMELINE)
        try:
            data = json.dumps(event_dict, separators=(",", ":"), default=str)
            await self._redis.rpush(key, data)
            await self._set_ttl(key)
        except Exception as e:
            logger.warning(f"Failed to add timeline event to Redis: {e}")

    # =========================================================================
    # Techniques (Redis SET + HASH for names)
    # =========================================================================

    async def add_technique(self, technique_id: str, name: str = "") -> None:
        """Add a MITRE ATT&CK technique.

        Adds the technique ID to the techniques SET and, if a name is provided,
        stores the mapping in the technique_names HASH.

        Args:
            technique_id: MITRE technique ID (e.g., ``T1078``).
            name: Optional human-readable name for the technique.
        """
        tech_key = self._key(self.KEY_TECHNIQUES)
        try:
            await self._redis.sadd(tech_key, technique_id)
            await self._set_ttl(tech_key)
        except Exception as e:
            logger.warning(f"Failed to add technique {technique_id} to Redis: {e}")
            return

        if name:
            names_key = self._key(self.KEY_TECHNIQUE_NAMES)
            try:
                await self._redis.hset(names_key, technique_id, name)
                await self._set_ttl(names_key)
            except Exception as e:
                logger.warning(f"Failed to set technique name for {technique_id}: {e}")

    async def get_techniques(self) -> set[str]:
        """Get all technique IDs.

        Returns:
            Set of technique ID strings.
        """
        key = self._key(self.KEY_TECHNIQUES)
        try:
            items = await self._redis.smembers(key)
            return {item if isinstance(item, str) else item.decode() for item in items}
        except Exception as e:
            logger.warning(f"Failed to get techniques from Redis: {e}")
            return set()

    # =========================================================================
    # Tactics (Redis SET)
    # =========================================================================

    async def add_tactic(self, tactic_id: str) -> None:
        """Add a MITRE ATT&CK tactic.

        Args:
            tactic_id: MITRE tactic ID (e.g., ``TA0001``).
        """
        key = self._key(self.KEY_TACTICS)
        try:
            await self._redis.sadd(key, tactic_id)
            await self._set_ttl(key)
        except Exception as e:
            logger.warning(f"Failed to add tactic {tactic_id} to Redis: {e}")

    async def get_tactics(self) -> set[str]:
        """Get all tactic IDs.

        Returns:
            Set of tactic ID strings.
        """
        key = self._key(self.KEY_TACTICS)
        try:
            items = await self._redis.smembers(key)
            return {item if isinstance(item, str) else item.decode() for item in items}
        except Exception as e:
            logger.warning(f"Failed to get tactics from Redis: {e}")
            return set()

    # =========================================================================
    # Hosts (Redis SET)
    # =========================================================================

    async def track_host(self, name: str) -> None:
        """Track a queried host.

        Args:
            name: Hostname or IP address.
        """
        key = self._key(self.KEY_HOSTS)
        try:
            await self._redis.sadd(key, name)
            await self._set_ttl(key)
        except Exception as e:
            logger.warning(f"Failed to track host {name} in Redis: {e}")

    async def get_hosts(self) -> set[str]:
        """Get all tracked hosts.

        Returns:
            Set of host name strings.
        """
        key = self._key(self.KEY_HOSTS)
        try:
            items = await self._redis.smembers(key)
            return {item if isinstance(item, str) else item.decode() for item in items}
        except Exception as e:
            logger.warning(f"Failed to get hosts from Redis: {e}")
            return set()

    # =========================================================================
    # Users (Redis SET)
    # =========================================================================

    async def track_user(self, name: str) -> None:
        """Track a queried user.

        Args:
            name: Username or user principal name.
        """
        key = self._key(self.KEY_USERS)
        try:
            await self._redis.sadd(key, name)
            await self._set_ttl(key)
        except Exception as e:
            logger.warning(f"Failed to track user {name} in Redis: {e}")

    async def get_users(self) -> set[str]:
        """Get all tracked users.

        Returns:
            Set of user name strings.
        """
        key = self._key(self.KEY_USERS)
        try:
            items = await self._redis.smembers(key)
            return {item if isinstance(item, str) else item.decode() for item in items}
        except Exception as e:
            logger.warning(f"Failed to get users from Redis: {e}")
            return set()

    # =========================================================================
    # Meta (Scalars) — Redis HASH
    # =========================================================================

    async def set_meta(self, k: str, value: Any) -> None:
        """Set a scalar meta field.

        Values are JSON-serialized before storage.

        Args:
            k: Field name.
            value: Value (will be JSON serialized).
        """
        key = self._key(self.KEY_META)
        try:
            await self._redis.hset(key, k, json.dumps(value, separators=(",", ":"), default=str))
            await self._set_ttl(key)
        except Exception as e:
            logger.warning(f"Failed to set meta field {k}: {e}")

    async def get_meta(self, k: str) -> Any:
        """Get a scalar meta field.

        Args:
            k: Field name.

        Returns:
            Deserialized value, or None if not found.
        """
        key = self._key(self.KEY_META)
        try:
            value = await self._redis.hget(key, k)
            if value is None:
                return None
            return json.loads(value if isinstance(value, str) else value.decode())
        except Exception as e:
            logger.warning(f"Failed to get meta field {k}: {e}")
            return None

    # =========================================================================
    # Queues — Pivot & Chain (Redis LIST)
    # =========================================================================

    async def queue_pivot(self, data: dict) -> None:
        """Enqueue a pivot investigation target.

        Args:
            data: JSON-serializable pivot data.
        """
        key = self._key(self.KEY_PIVOT_QUEUE)
        try:
            await self._redis.rpush(key, json.dumps(data, separators=(",", ":"), default=str))
            await self._set_ttl(key)
        except Exception as e:
            logger.warning(f"Failed to queue pivot in Redis: {e}")

    async def queue_chain(self, method_name: str) -> None:
        """Enqueue a detection method for chain execution.

        Args:
            method_name: Name of the detection method to run.
        """
        key = self._key(self.KEY_CHAIN_QUEUE)
        try:
            await self._redis.rpush(key, method_name)
            await self._set_ttl(key)
        except Exception as e:
            logger.warning(f"Failed to queue chain method {method_name} in Redis: {e}")

    async def pop_pivot(self) -> list[dict]:
        """Drain the pivot queue and return all entries.

        Returns:
            List of pivot data dicts.
        """
        key = self._key(self.KEY_PIVOT_QUEUE)
        try:
            items = await self._redis.lrange(key, 0, -1)
            if items:
                await self._redis.delete(key)
            return [json.loads(item if isinstance(item, str) else item.decode()) for item in items]
        except Exception as e:
            logger.warning(f"Failed to pop pivot queue from Redis: {e}")
            return []

    async def pop_chain(self) -> list[str]:
        """Drain the chain queue and return all entries.

        Returns:
            List of detection method name strings.
        """
        key = self._key(self.KEY_CHAIN_QUEUE)
        try:
            items = await self._redis.lrange(key, 0, -1)
            if items:
                await self._redis.delete(key)
            return [item if isinstance(item, str) else item.decode() for item in items]
        except Exception as e:
            logger.warning(f"Failed to pop chain queue from Redis: {e}")
            return []

    # =========================================================================
    # Query Tracking (Redis LIST + SET)
    # =========================================================================

    async def record_query(self, query_dict: dict) -> None:
        """Record an executed query.

        Args:
            query_dict: JSON-serializable query record.
        """
        key = self._key(self.KEY_QUERIES)
        try:
            data = json.dumps(query_dict, separators=(",", ":"), default=str)
            await self._redis.rpush(key, data)
            await self._set_ttl(key)
        except Exception as e:
            logger.warning(f"Failed to record query in Redis: {e}")

    async def mark_query_type(self, method_name: str) -> None:
        """Mark a detection method as executed.

        Args:
            method_name: Detection method name (e.g., ``detect_brute_force``).
        """
        key = self._key(self.KEY_QUERY_TYPES)
        try:
            await self._redis.sadd(key, method_name)
            await self._set_ttl(key)
        except Exception as e:
            logger.warning(f"Failed to mark query type {method_name} in Redis: {e}")

    async def is_query_type_executed(self, method_name: str) -> bool:
        """Check if a detection method has been executed.

        Args:
            method_name: Detection method name.

        Returns:
            True if the method has already been executed.
        """
        key = self._key(self.KEY_QUERY_TYPES)
        try:
            return await self._redis.sismember(key, method_name) == 1
        except Exception as e:
            logger.warning(f"Failed to check query type {method_name} in Redis: {e}")
            return False

    # =========================================================================
    # Lateral Connections (Redis LIST)
    # =========================================================================

    async def add_lateral_connection(self, connection_dict: dict) -> None:
        """Record a lateral movement connection.

        Args:
            connection_dict: JSON-serializable connection data.
        """
        key = self._key(self.KEY_LATERAL)
        try:
            data = json.dumps(connection_dict, separators=(",", ":"), default=str)
            await self._redis.rpush(key, data)
            await self._set_ttl(key)
        except Exception as e:
            logger.warning(f"Failed to add lateral connection to Redis: {e}")

    async def get_lateral_connections(self) -> list[dict]:
        """Get all recorded lateral movement connections.

        Returns:
            List of connection dicts.
        """
        key = self._key(self.KEY_LATERAL)
        try:
            items = await self._redis.lrange(key, 0, -1)
            return [json.loads(item if isinstance(item, str) else item.decode()) for item in items]
        except Exception as e:
            logger.warning(f"Failed to get lateral connections from Redis: {e}")
            return []

    # =========================================================================
    # Recommendations (Redis LIST)
    # =========================================================================

    async def add_recommendation(self, text: str) -> None:
        """Add a recommendation to the investigation.

        Args:
            text: Recommendation text.
        """
        key = self._key(self.KEY_RECOMMENDATIONS)
        try:
            await self._redis.rpush(key, text)
            await self._set_ttl(key)
        except Exception as e:
            logger.warning(f"Failed to add recommendation to Redis: {e}")

    async def get_recommendations(self) -> list[str]:
        """Get all recommendations.

        Returns:
            List of recommendation strings.
        """
        key = self._key(self.KEY_RECOMMENDATIONS)
        try:
            items = await self._redis.lrange(key, 0, -1)
            return [item if isinstance(item, str) else item.decode() for item in items]
        except Exception as e:
            logger.warning(f"Failed to get recommendations from Redis: {e}")
            return []

    # =========================================================================
    # Tasks (Redis HASH — pending & completed)
    # =========================================================================

    async def add_pending_task(self, task_id: str, task_dict: dict) -> None:
        """Add a pending task.

        Args:
            task_id: Unique task identifier.
            task_dict: JSON-serializable task data.
        """
        key = self._key(self.KEY_PENDING_TASKS)
        try:
            data = json.dumps(task_dict, separators=(",", ":"), default=str)
            await self._redis.hset(key, task_id, data)
            await self._set_ttl(key)
        except Exception as e:
            logger.warning(f"Failed to add pending task {task_id} to Redis: {e}")

    async def complete_task(self, task_id: str, result_dict: dict) -> None:
        """Move a task from pending to completed.

        Removes the task from the pending HASH and adds the result to the
        completed HASH in a single pipeline.

        Args:
            task_id: Task identifier to complete.
            result_dict: JSON-serializable result data.
        """
        pending_key = self._key(self.KEY_PENDING_TASKS)
        completed_key = self._key(self.KEY_COMPLETED_TASKS)
        try:
            data = json.dumps(result_dict, separators=(",", ":"), default=str)
            pipe = self._redis.pipeline()
            pipe.hdel(pending_key, task_id)
            pipe.hset(completed_key, task_id, data)
            pipe.expire(pending_key, self.DEFAULT_TTL)
            pipe.expire(completed_key, self.DEFAULT_TTL)
            await pipe.execute()
        except Exception as e:
            logger.warning(f"Failed to complete task {task_id} in Redis: {e}")

    async def get_pending_tasks(self) -> dict[str, dict]:
        """Get all pending tasks.

        Returns:
            Dict mapping task_id to task data dict.
        """
        key = self._key(self.KEY_PENDING_TASKS)
        try:
            raw = await self._redis.hgetall(key)
            result: dict[str, dict] = {}
            for k, v in raw.items():
                task_id = k if isinstance(k, str) else k.decode()
                try:
                    result[task_id] = json.loads(v)
                except json.JSONDecodeError:
                    logger.warning(f"Invalid JSON for pending task {task_id}")
            return result
        except Exception as e:
            logger.warning(f"Failed to get pending tasks from Redis: {e}")
            return {}

    async def get_completed_tasks(self) -> dict[str, dict]:
        """Get all completed tasks.

        Returns:
            Dict mapping task_id to result data dict.
        """
        key = self._key(self.KEY_COMPLETED_TASKS)
        try:
            raw = await self._redis.hgetall(key)
            result: dict[str, dict] = {}
            for k, v in raw.items():
                task_id = k if isinstance(k, str) else k.decode()
                try:
                    result[task_id] = json.loads(v)
                except json.JSONDecodeError:
                    logger.warning(f"Invalid JSON for completed task {task_id}")
            return result
        except Exception as e:
            logger.warning(f"Failed to get completed tasks from Redis: {e}")
            return {}

    # =========================================================================
    # Triage (Redis STRING for decision, LIST for records)
    # =========================================================================

    async def set_triage_decision(
        self,
        decision: str,
        reasoning: str,
        confidence: float,
        routed_to: str | None = None,
        focus_areas: list[str] | None = None,
        reinvestigation_cycle: int = 0,
    ) -> None:
        """Set the current triage decision for the investigation.

        Also adds a triage record for audit trail.

        Args:
            decision: Triage decision (pending, confirmed, downgraded, reinvestigate, routed).
            reasoning: LLM-generated explanation for the decision.
            confidence: Confidence score 0.0-1.0.
            routed_to: Team/action if decision is "routed".
            focus_areas: Areas to focus on if decision is "reinvestigate".
            reinvestigation_cycle: Current reinvestigation cycle (0-2).
        """
        import uuid

        key = self._key(self.KEY_TRIAGE_DECISION)
        try:
            decision_data = {
                "decision": decision,
                "reasoning": reasoning,
                "confidence": confidence,
                "routed_to": routed_to,
                "focus_areas": focus_areas or [],
                "reinvestigation_cycle": reinvestigation_cycle,
            }
            await self._redis.set(
                key, json.dumps(decision_data, separators=(",", ":"), default=str)
            )
            await self._set_ttl(key)
        except Exception as e:
            logger.warning(f"Failed to set triage decision in Redis: {e}")

        # Also add a triage record for audit trail
        triage_id = f"triage-{uuid.uuid4().hex[:8]}"
        record = {
            "triage_id": triage_id,
            "investigation_id": self._investigation_id,
            "decision": decision,
            "reasoning": reasoning,
            "confidence": confidence,
            "routed_to": routed_to,
            "focus_areas": focus_areas or [],
            "reinvestigation_cycle": reinvestigation_cycle,
            "created_at": json.dumps(None, default=str),  # Will be set to current time
        }
        await self.add_triage_record(record)

    async def get_triage_decision(self) -> dict | None:
        """Get the current triage decision.

        Returns:
            Dict with decision data, or None if not set.
        """
        key = self._key(self.KEY_TRIAGE_DECISION)
        try:
            data = await self._redis.get(key)
            if data is None:
                return None
            return json.loads(data if isinstance(data, str) else data.decode())
        except Exception as e:
            logger.warning(f"Failed to get triage decision from Redis: {e}")
            return None

    async def add_triage_record(self, record: dict) -> None:
        """Add a triage record for audit trail.

        Args:
            record: Triage record dict.
        """
        from datetime import datetime, timezone

        key = self._key(self.KEY_TRIAGE_RECORDS)
        try:
            # Set created_at if not already set
            if "created_at" not in record or record["created_at"] is None:
                record["created_at"] = datetime.now(timezone.utc).isoformat()
            data = json.dumps(record, separators=(",", ":"), default=str)
            await self._redis.rpush(key, data)
            await self._set_ttl(key)
        except Exception as e:
            logger.warning(f"Failed to add triage record to Redis: {e}")

    async def get_triage_records(self) -> list[dict]:
        """Get all triage records for audit trail.

        Returns:
            List of triage record dicts.
        """
        key = self._key(self.KEY_TRIAGE_RECORDS)
        try:
            items = await self._redis.lrange(key, 0, -1)
            records = []
            for item in items:
                try:
                    records.append(json.loads(item if isinstance(item, str) else item.decode()))
                except json.JSONDecodeError:
                    logger.warning("Invalid JSON in triage records list")
            return records
        except Exception as e:
            logger.warning(f"Failed to get triage records from Redis: {e}")
            return []

    async def get_reinvestigation_cycle(self) -> int:
        """Get the current reinvestigation cycle count.

        Returns:
            Current cycle count (0 = no reinvestigations yet).
        """
        decision = await self.get_triage_decision()
        if decision:
            return decision.get("reinvestigation_cycle", 0)
        return 0

    # =========================================================================
    # Snapshot — read ALL keys into a single dict
    # =========================================================================

    async def snapshot(self) -> dict:
        """Read all investigation state from Redis and return as a raw dict.

        This method reconstitutes all Redis keys into a single dictionary that
        can be used to populate a ``SharedBlueTeamState`` object.

        Returns:
            Dict with all investigation state fields::

                {
                    "investigation_id": str,
                    "evidence": list[dict],
                    "timeline": list[dict],
                    "techniques": set[str],
                    "tactics": set[str],
                    "technique_names": dict[str, str],
                    "hosts": set[str],
                    "users": set[str],
                    "query_types": set[str],
                    "queries": list[dict],
                    "lateral_connections": list[dict],
                    "pivot_queue": list[dict],
                    "chain_queue": list[str],
                    "meta": dict[str, Any],
                    "pending_tasks": dict[str, dict],
                    "completed_tasks": dict[str, dict],
                    "recommendations": list[str],
                }
        """
        result: dict[str, Any] = {
            "investigation_id": self._investigation_id,
            "evidence": [],
            "timeline": [],
            "techniques": set(),
            "tactics": set(),
            "technique_names": {},
            "hosts": set(),
            "users": set(),
            "query_types": set(),
            "queries": [],
            "lateral_connections": [],
            "pivot_queue": [],
            "chain_queue": [],
            "meta": {},
            "pending_tasks": {},
            "completed_tasks": {},
            "recommendations": [],
            "triage_decision": None,
            "triage_records": [],
        }

        # Evidence (HASH values -> list[dict])
        try:
            ev_key = self._key(self.KEY_EVIDENCE)
            ev_raw = await self._redis.hgetall(ev_key)
            for v in ev_raw.values():
                try:
                    result["evidence"].append(json.loads(v if isinstance(v, str) else v.decode()))
                except json.JSONDecodeError:
                    logger.warning("Invalid JSON in evidence hash value")
        except Exception as e:
            logger.warning(f"Failed to snapshot evidence: {e}")

        # Timeline (LIST -> list[dict])
        try:
            tl_key = self._key(self.KEY_TIMELINE)
            tl_items = await self._redis.lrange(tl_key, 0, -1)
            for item in tl_items:
                try:
                    result["timeline"].append(
                        json.loads(item if isinstance(item, str) else item.decode())
                    )
                except json.JSONDecodeError:
                    logger.warning("Invalid JSON in timeline list")
        except Exception as e:
            logger.warning(f"Failed to snapshot timeline: {e}")

        # Techniques (SET)
        try:
            result["techniques"] = await self.get_techniques()
        except Exception as e:
            logger.warning(f"Failed to snapshot techniques: {e}")

        # Tactics (SET)
        try:
            result["tactics"] = await self.get_tactics()
        except Exception as e:
            logger.warning(f"Failed to snapshot tactics: {e}")

        # Technique names (HASH -> dict[str, str])
        try:
            tn_key = self._key(self.KEY_TECHNIQUE_NAMES)
            tn_raw = await self._redis.hgetall(tn_key)
            result["technique_names"] = {
                (k if isinstance(k, str) else k.decode()): (v if isinstance(v, str) else v.decode())
                for k, v in tn_raw.items()
            }
        except Exception as e:
            logger.warning(f"Failed to snapshot technique names: {e}")

        # Hosts (SET)
        try:
            result["hosts"] = await self.get_hosts()
        except Exception as e:
            logger.warning(f"Failed to snapshot hosts: {e}")

        # Users (SET)
        try:
            result["users"] = await self.get_users()
        except Exception as e:
            logger.warning(f"Failed to snapshot users: {e}")

        # Query types (SET)
        try:
            qt_key = self._key(self.KEY_QUERY_TYPES)
            qt_items = await self._redis.smembers(qt_key)
            result["query_types"] = {
                item if isinstance(item, str) else item.decode() for item in qt_items
            }
        except Exception as e:
            logger.warning(f"Failed to snapshot query types: {e}")

        # Queries (LIST -> list[dict])
        try:
            q_key = self._key(self.KEY_QUERIES)
            q_items = await self._redis.lrange(q_key, 0, -1)
            for item in q_items:
                try:
                    result["queries"].append(
                        json.loads(item if isinstance(item, str) else item.decode())
                    )
                except json.JSONDecodeError:
                    logger.warning("Invalid JSON in queries list")
        except Exception as e:
            logger.warning(f"Failed to snapshot queries: {e}")

        # Lateral connections (LIST -> list[dict])
        try:
            result["lateral_connections"] = await self.get_lateral_connections()
        except Exception as e:
            logger.warning(f"Failed to snapshot lateral connections: {e}")

        # Pivot queue (LIST -> list[dict]) — non-destructive read
        try:
            pq_key = self._key(self.KEY_PIVOT_QUEUE)
            pq_items = await self._redis.lrange(pq_key, 0, -1)
            for item in pq_items:
                try:
                    result["pivot_queue"].append(
                        json.loads(item if isinstance(item, str) else item.decode())
                    )
                except json.JSONDecodeError:
                    logger.warning("Invalid JSON in pivot queue")
        except Exception as e:
            logger.warning(f"Failed to snapshot pivot queue: {e}")

        # Chain queue (LIST -> list[str]) — non-destructive read
        try:
            cq_key = self._key(self.KEY_CHAIN_QUEUE)
            cq_items = await self._redis.lrange(cq_key, 0, -1)
            result["chain_queue"] = [
                item if isinstance(item, str) else item.decode() for item in cq_items
            ]
        except Exception as e:
            logger.warning(f"Failed to snapshot chain queue: {e}")

        # Meta (HASH -> dict[str, Any])
        try:
            meta_key = self._key(self.KEY_META)
            meta_raw = await self._redis.hgetall(meta_key)
            for k, v in meta_raw.items():
                field = k if isinstance(k, str) else k.decode()
                try:
                    result["meta"][field] = json.loads(v if isinstance(v, str) else v.decode())
                except json.JSONDecodeError:
                    logger.warning(f"Invalid JSON in meta field {field}")
        except Exception as e:
            logger.warning(f"Failed to snapshot meta: {e}")

        # Pending tasks (HASH -> dict[str, dict])
        try:
            result["pending_tasks"] = await self.get_pending_tasks()
        except Exception as e:
            logger.warning(f"Failed to snapshot pending tasks: {e}")

        # Completed tasks (HASH -> dict[str, dict])
        try:
            result["completed_tasks"] = await self.get_completed_tasks()
        except Exception as e:
            logger.warning(f"Failed to snapshot completed tasks: {e}")

        # Recommendations (LIST -> list[str])
        try:
            result["recommendations"] = await self.get_recommendations()
        except Exception as e:
            logger.warning(f"Failed to snapshot recommendations: {e}")

        # Triage decision (STRING -> dict)
        try:
            result["triage_decision"] = await self.get_triage_decision()
        except Exception as e:
            logger.warning(f"Failed to snapshot triage decision: {e}")

        # Triage records (LIST -> list[dict])
        try:
            result["triage_records"] = await self.get_triage_records()
        except Exception as e:
            logger.warning(f"Failed to snapshot triage records: {e}")

        return result


__all__ = [
    "BlueStateBackend",
]
