"""Redis-native state backend for SharedRedTeamState.

This module provides Redis-native storage for SharedRedTeamState collections,
eliminating the need for full JSON serialization/deserialization on every mutation.

Key design decisions:
- Most collections (credentials, hosts, etc.) use Redis LIST
- Hashes use Redis HASH (dedup_key -> JSON) for O(1) deduplication via HSETNX
- Vulnerabilities use Redis HASH (vuln_id -> JSON)
- Dedup tracking uses Redis SET
- Scalars (flags, paths) use Redis HASH (meta)
- Domain controller and NetBIOS maps use Redis HASH

Redis key structure:
    ares:op:{op_id}:credentials       HASH (dedup_key -> JSON) - additive, no DELETE
    ares:op:{op_id}:hashes            HASH (dedup_key -> JSON)
    ares:op:{op_id}:hosts             LIST
    ares:op:{op_id}:users             LIST
    ares:op:{op_id}:shares            LIST
    ares:op:{op_id}:weaknesses        SET
    ares:op:{op_id}:vulns             HASH
    ares:op:{op_id}:dedup:{set_name}  SET
    ares:op:{op_id}:meta              HASH
    ares:op:{op_id}:dc_map            HASH
    ares:op:{op_id}:netbios_map       HASH
    ares:op:{op_id}:artifacts         HASH
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

from loguru import logger

if TYPE_CHECKING:
    from redis.asyncio import Redis

    from ares.core.models import (
        Credential,
        Hash,
        Host,
        Share,
        User,
        VulnerabilityInfo,
    )


class RedisStateBackend:
    """Redis-native state storage for SharedRedTeamState.

    This backend stores state directly in Redis using native data structures,
    eliminating the need for full JSON checkpoint serialization on every mutation.

    Thread Safety:
        This class is designed to be used from async contexts. All methods are
        async and use the provided Redis client.

    Key Prefix:
        All keys are prefixed with `ares:op:{operation_id}:` to namespace
        state per operation and allow multiple concurrent operations.

    TTL:
        All keys are set with a 24-hour TTL to auto-cleanup completed operations.
    """

    # Key prefixes
    KEY_PREFIX = "ares:op"

    # Collection keys
    KEY_CREDENTIALS = "credentials"
    KEY_HASHES = "hashes"
    KEY_HOSTS = "hosts"
    KEY_USERS = "users"
    KEY_SHARES = "shares"
    KEY_WEAKNESSES = "weaknesses"
    KEY_DOMAINS = "domains"

    # Hash keys
    KEY_VULNS = "vulns"
    KEY_EXPLOITED = "exploited"
    KEY_META = "meta"
    KEY_DC_MAP = "dc_map"
    KEY_NETBIOS_MAP = "netbios_map"
    KEY_ARTIFACTS = "artifacts"

    # Persistence tracking keys (critical attack artifacts)
    KEY_GOLDEN_TICKETS = "golden_tickets"
    KEY_ADMINSD_BACKDOORS = "adminsd_backdoors"
    KEY_ACL_CHAINS = "acl_chains"
    KEY_GMSA_ACCOUNTS = "gmsa_accounts"

    # Dedup set prefix
    KEY_DEDUP_PREFIX = "dedup"

    # Dispatch tracking keys
    KEY_MSSQL_ENUM_DISPATCHED = "mssql_enum_dispatched"
    KEY_PENDING_TASKS = "pending_tasks"
    KEY_COMPLETED_TASKS = "completed_tasks"
    KEY_VULN_TYPE_FAILURES = "vuln_type_failures"

    # TTL for all keys (24 hours)
    DEFAULT_TTL = 86400

    def __init__(self, redis_client: Redis, operation_id: str):
        """Initialize the backend.

        Args:
            redis_client: Async Redis client (from create_redis_client)
            operation_id: Unique operation identifier
        """
        self._redis = redis_client
        self._operation_id = operation_id
        self._key_prefix = f"{self.KEY_PREFIX}:{operation_id}"

    def _key(self, suffix: str) -> str:
        """Build full Redis key."""
        return f"{self._key_prefix}:{suffix}"

    def _dedup_key(self, set_name: str) -> str:
        """Build dedup set key."""
        return f"{self._key_prefix}:{self.KEY_DEDUP_PREFIX}:{set_name}"

    async def _set_ttl(self, key: str) -> None:
        """Set TTL on a key."""
        await self._redis.expire(key, self.DEFAULT_TTL)

    # =========================================================================
    # Credentials (Redis HASH with HSETNX for O(1) deduplication)
    # =========================================================================

    async def add_credential(self, cred: Credential) -> bool:
        """Add a credential to Redis HASH with O(1) deduplication via HSETNX.

        Deduplication key: {domain}:{username}:{password} (case-insensitive)
        This ensures the same credential isn't stored twice.

        Args:
            cred: Credential to add

        Returns:
            True if added (new), False if duplicate
        """
        key = self._key(self.KEY_CREDENTIALS)
        try:
            dedup_field = self._build_credential_dedup_key(cred)
            data = _serialize_credential(cred)
            # HSETNX returns 1 if field was set (new), 0 if already existed
            added = await self._redis.hsetnx(key, dedup_field, data)
            if not added:
                logger.debug(f"Credential rejected (duplicate): {dedup_field}")
                return False
            await self._set_ttl(key)
            return True
        except Exception as e:
            logger.warning(f"Failed to add credential to Redis: {e}")
            return False

    def _build_credential_dedup_key(self, cred: Credential) -> str:
        """Build deduplication key for a credential.

        Key format: {domain}:{username}:{password_hash}
        Using password hash (first 16 chars) to keep keys shorter while still deduping.

        Args:
            cred: Credential object

        Returns:
            Deduplication key string
        """
        import hashlib

        domain = (cred.domain or "").strip().lower()
        username = (cred.username or "").strip().lower()
        # Hash password to keep key shorter and avoid special chars
        # MD5 is fine here - not used for security, just deduplication
        password = cred.password or ""
        password_hash = hashlib.md5(password.encode(), usedforsecurity=False).hexdigest()[:16]
        return f"cred:{domain}:{username}:{password_hash}"

    async def get_credentials(self) -> list[Credential]:
        """Get all credentials from Redis HASH.

        Includes fallback for legacy LIST format to support operations that were
        in-progress during deployment. Legacy LIST credentials are migrated to HASH
        on first read.

        Returns:
            List of Credential objects
        """
        key = self._key(self.KEY_CREDENTIALS)
        try:
            # Try HASH format first (new format)
            items = await self._redis.hgetall(key)
            if items:
                # Values are the serialized Credential objects, keys are dedup keys (ignored)
                return [_deserialize_credential(v) for v in items.values()]

            # Fallback: check for legacy LIST format (pre-migration operations)
            key_type = await self._redis.type(key)
            if key_type == "list" or (isinstance(key_type, bytes) and key_type == b"list"):
                legacy_items = await self._redis.lrange(key, 0, -1)
                if legacy_items:
                    logger.info(
                        f"Migrating {len(legacy_items)} credentials from LIST to HASH format"
                    )
                    credentials = [_deserialize_credential(item) for item in legacy_items]
                    # Migrate to HASH format (delete LIST, write as HASH)
                    pipe = self._redis.pipeline()
                    pipe.delete(key)
                    for cred in credentials:
                        dedup_key = self._build_credential_dedup_key(cred)
                        pipe.hset(key, dedup_key, _serialize_credential(cred))
                    pipe.expire(key, self.DEFAULT_TTL)
                    await pipe.execute()
                    return credentials

            return []
        except Exception as e:
            logger.warning(f"Failed to get credentials from Redis: {e}")
            return []

    # =========================================================================
    # Hashes (Redis HASH with HSETNX for O(1) deduplication)
    # =========================================================================

    async def add_hash(self, hash_obj: Hash) -> bool:
        """Add a hash to Redis HASH with O(1) deduplication via HSETNX.

        Deduplication keys by hash type:
        - AS-REP: {domain}:{username} (same user = same password)
        - Kerberoast: {domain}:{username}:{etype}:{spn}
        - NTLM/other: {domain}:{username}:{hash_value[:32]}

        Args:
            hash_obj: Hash to add

        Returns:
            True if added, False if duplicate
        """
        hash_type = (hash_obj.hash_type or "").strip().lower()
        hash_value = hash_obj.hash_value or ""
        username = (hash_obj.username or "").strip().lower()
        domain = (hash_obj.domain or "").strip().lower()

        # Build dedup key based on hash type
        dedup_field = self._build_hash_dedup_key(hash_type, hash_value, domain, username)

        key = self._key(self.KEY_HASHES)
        try:
            data = _serialize_hash(hash_obj)
            # HSETNX returns 1 if field was set (new), 0 if already existed
            added = await self._redis.hsetnx(key, dedup_field, data)
            if not added:
                logger.debug(f"Hash rejected (duplicate): {dedup_field}")
                return False
            await self._set_ttl(key)
            return True
        except Exception as e:
            logger.warning(f"Failed to add hash to Redis: {e}")
            return False

    def _build_hash_dedup_key(
        self, hash_type: str, hash_value: str, domain: str, username: str
    ) -> str:
        """Build deduplication key for a hash based on its type.

        Args:
            hash_type: Normalized hash type (lowercase)
            hash_value: The hash value
            domain: Domain (lowercase)
            username: Username (lowercase)

        Returns:
            Deduplication key string
        """
        # Detect AS-REP hashes
        is_asrep = hash_type in {"as-rep", "asrep", "krb5asrep"} or hash_value.startswith(
            "$krb5asrep$"
        )
        if is_asrep:
            # AS-REP: one hash per user+domain (each request generates different hash)
            return f"asrep:{domain}:{username}"

        # Detect Kerberoast hashes
        is_kerberoast = hash_type in {
            "kerberoast",
            "krb5tgs",
            "tgs-rep",
            "tgs",
        } or hash_value.startswith("$krb5tgs$")
        if is_kerberoast:
            # Kerberoast: one hash per user+domain+SPN+etype
            spn_key = self._extract_kerberoast_spn_key(hash_value)
            if spn_key:
                return f"krb:{domain}:{username}:{spn_key}"
            # Fallback if SPN extraction fails
            return f"krb:{domain}:{username}:{hash_value[:32]}"

        # NTLM and other hashes: dedupe by domain+username+hash prefix
        # Using first 32 chars of hash to handle slight variations
        return f"ntlm:{domain}:{username}:{hash_value[:32]}"

    def _extract_kerberoast_spn_key(self, hash_value: str) -> str | None:
        """Extract SPN and encryption type from Kerberoast hash for deduplication.

        Hash format: $krb5tgs$ETYPE$*user$realm$spn*$checksum$encrypted

        Returns:
            String like "23:MSSQLSvc/sql.contoso.local:1433" or None if parsing fails
        """
        if not hash_value.startswith("$krb5tgs$"):
            return None
        try:
            parts = hash_value.split("$")
            if len(parts) < 4:
                return None
            etype = parts[2]  # e.g., "23" for RC4
            # Extract SPN from *user$realm$spn* section
            asterisk_parts = hash_value.split("*")
            if len(asterisk_parts) < 2:
                return None
            inner = asterisk_parts[1]  # user$realm$spn
            inner_parts = inner.split("$")
            if len(inner_parts) < 3:
                return None
            spn = inner_parts[2]  # The SPN
            return f"{etype}:{spn}"
        except Exception:
            return None

    async def get_hashes(self) -> list[Hash]:
        """Get all hashes from Redis HASH.

        Returns:
            List of Hash objects
        """
        key = self._key(self.KEY_HASHES)
        try:
            items = await self._redis.hgetall(key)
            # Values are the serialized Hash objects, keys are dedup keys (ignored)
            return [_deserialize_hash(v) for v in items.values()]
        except Exception as e:
            logger.warning(f"Failed to get hashes from Redis: {e}")
            return []

    # =========================================================================
    # Hosts
    # =========================================================================

    async def add_host(self, host: Host) -> bool:
        """Add a host to Redis LIST.

        Note: Deduplication/merging should be done by the caller before calling this method.

        Args:
            host: Host to add

        Returns:
            True if added successfully
        """
        key = self._key(self.KEY_HOSTS)
        try:
            data = _serialize_host(host)
            await self._redis.rpush(key, data)
            await self._set_ttl(key)
            return True
        except Exception as e:
            logger.warning(f"Failed to add host to Redis: {e}")
            return False

    async def get_hosts(self) -> list[Host]:
        """Get all hosts from Redis LIST.

        Returns:
            List of Host objects
        """
        key = self._key(self.KEY_HOSTS)
        try:
            items = await self._redis.lrange(key, 0, -1)
            return [_deserialize_host(item) for item in items]
        except Exception as e:
            logger.warning(f"Failed to get hosts from Redis: {e}")
            return []

    async def update_host(self, ip: str, host: Host) -> bool:
        """Update an existing host in Redis LIST.

        Since Redis LIST doesn't support direct update by value, this method:
        1. Gets all hosts
        2. Finds the host with matching IP
        3. Replaces it with the new host
        4. Rewrites the list

        This is O(n) but host lists are typically small (<1000 hosts).

        Args:
            ip: IP address of host to update
            host: Updated Host object

        Returns:
            True if updated, False if not found
        """
        key = self._key(self.KEY_HOSTS)
        try:
            items = await self._redis.lrange(key, 0, -1)
            updated = False
            new_items = []

            for item in items:
                existing = _deserialize_host(item)
                if existing.ip == ip:
                    new_items.append(_serialize_host(host))
                    updated = True
                else:
                    new_items.append(item)

            if updated:
                # Atomic replace using pipeline
                pipe = self._redis.pipeline()
                pipe.delete(key)
                if new_items:
                    pipe.rpush(key, *new_items)
                pipe.expire(key, self.DEFAULT_TTL)
                await pipe.execute()

            return updated
        except Exception as e:
            logger.warning(f"Failed to update host in Redis: {e}")
            return False

    # =========================================================================
    # Users
    # =========================================================================

    async def add_user(self, user: User) -> bool:
        """Add a user to Redis LIST.

        Args:
            user: User to add

        Returns:
            True if added successfully
        """
        key = self._key(self.KEY_USERS)
        try:
            data = _serialize_user(user)
            await self._redis.rpush(key, data)
            await self._set_ttl(key)
            return True
        except Exception as e:
            logger.warning(f"Failed to add user to Redis: {e}")
            return False

    async def get_users(self) -> list[User]:
        """Get all users from Redis LIST.

        Returns:
            List of User objects
        """
        key = self._key(self.KEY_USERS)
        try:
            items = await self._redis.lrange(key, 0, -1)
            return [_deserialize_user(item) for item in items]
        except Exception as e:
            logger.warning(f"Failed to get users from Redis: {e}")
            return []

    # =========================================================================
    # Shares
    # =========================================================================

    async def add_share(self, share: Share) -> bool:
        """Add a share to Redis LIST.

        Args:
            share: Share to add

        Returns:
            True if added successfully
        """
        key = self._key(self.KEY_SHARES)
        try:
            data = _serialize_share(share)
            await self._redis.rpush(key, data)
            await self._set_ttl(key)
            return True
        except Exception as e:
            logger.warning(f"Failed to add share to Redis: {e}")
            return False

    async def get_shares(self) -> list[Share]:
        """Get all shares from Redis LIST.

        Returns:
            List of Share objects
        """
        key = self._key(self.KEY_SHARES)
        try:
            items = await self._redis.lrange(key, 0, -1)
            return [_deserialize_share(item) for item in items]
        except Exception as e:
            logger.warning(f"Failed to get shares from Redis: {e}")
            return []

    # =========================================================================
    # Weaknesses
    # =========================================================================

    async def add_weakness(self, weakness: str) -> bool:
        """Add a weakness string to Redis SET (auto-deduplicates).

        Args:
            weakness: Weakness description

        Returns:
            True if added (was new), False if already existed
        """
        key = self._key(self.KEY_WEAKNESSES)
        try:
            added = await self._redis.sadd(key, weakness)
            await self._set_ttl(key)
            return added > 0
        except Exception as e:
            logger.warning(f"Failed to add weakness to Redis: {e}")
            return False

    async def get_weaknesses(self) -> list[str]:
        """Get all weaknesses from Redis SET.

        Returns:
            List of weakness strings
        """
        key = self._key(self.KEY_WEAKNESSES)
        try:
            items = await self._redis.smembers(key)
            # Items may be bytes or str depending on decode_responses
            return [item if isinstance(item, str) else item.decode() for item in items]
        except Exception as e:
            logger.warning(f"Failed to get weaknesses from Redis: {e}")
            return []

    # =========================================================================
    # Domains
    # =========================================================================

    async def add_domain(self, domain: str) -> bool:
        """Add a domain to Redis SET.

        Args:
            domain: Domain name (lowercase)

        Returns:
            True if added (not already present)
        """
        key = self._key(self.KEY_DOMAINS)
        try:
            result = await self._redis.sadd(key, domain.lower())
            await self._set_ttl(key)
            return result > 0
        except Exception as e:
            logger.warning(f"Failed to add domain to Redis: {e}")
            return False

    async def get_domains(self) -> list[str]:
        """Get all domains from Redis SET.

        Returns:
            List of domain names
        """
        key = self._key(self.KEY_DOMAINS)
        try:
            items = await self._redis.smembers(key)
            return [item if isinstance(item, str) else item.decode() for item in items]
        except Exception as e:
            logger.warning(f"Failed to get domains from Redis: {e}")
            return []

    # =========================================================================
    # Vulnerabilities (Redis HASH)
    # =========================================================================

    async def add_vulnerability(self, vuln: VulnerabilityInfo) -> bool:
        """Add a vulnerability to Redis HASH.

        Args:
            vuln: VulnerabilityInfo to add

        Returns:
            True if added (new), False if already existed
        """
        key = self._key(self.KEY_VULNS)
        try:
            data = _serialize_vulnerability(vuln)
            # HSETNX returns 1 if field was set (new), 0 if already existed
            result = await self._redis.hsetnx(key, vuln.vuln_id, data)
            await self._set_ttl(key)
            return result == 1
        except Exception as e:
            logger.warning(f"Failed to add vulnerability to Redis: {e}")
            return False

    async def get_vulnerabilities(self) -> dict[str, VulnerabilityInfo]:
        """Get all vulnerabilities from Redis HASH.

        Returns:
            Dict mapping vuln_id -> VulnerabilityInfo
        """
        key = self._key(self.KEY_VULNS)
        try:
            items = await self._redis.hgetall(key)
            return {vuln_id: _deserialize_vulnerability(data) for vuln_id, data in items.items()}
        except Exception as e:
            logger.warning(f"Failed to get vulnerabilities from Redis: {e}")
            return {}

    async def mark_exploited(self, vuln_id: str) -> bool:
        """Mark a vulnerability as exploited.

        Args:
            vuln_id: Vulnerability ID to mark

        Returns:
            True if marked successfully
        """
        key = self._key(self.KEY_EXPLOITED)
        try:
            await self._redis.sadd(key, vuln_id)
            await self._set_ttl(key)
            return True
        except Exception as e:
            logger.warning(f"Failed to mark vulnerability exploited: {e}")
            return False

    async def get_exploited_vulnerabilities(self) -> set[str]:
        """Get set of exploited vulnerability IDs.

        Returns:
            Set of vuln_ids that have been exploited
        """
        key = self._key(self.KEY_EXPLOITED)
        try:
            items = await self._redis.smembers(key)
            return {item if isinstance(item, str) else item.decode() for item in items}
        except Exception as e:
            logger.warning(f"Failed to get exploited vulnerabilities: {e}")
            return set()

    # =========================================================================
    # Dedup Sets (Redis SET)
    # =========================================================================

    async def mark_processed(self, set_name: str, key: str) -> bool:
        """Mark a key as processed in a dedup set.

        Args:
            set_name: Name of the dedup set (e.g., "cred_expansion", "hash_lateral")
            key: The key to mark as processed

        Returns:
            True if newly added, False if already existed
        """
        redis_key = self._dedup_key(set_name)
        try:
            result = await self._redis.sadd(redis_key, key)
            await self._set_ttl(redis_key)
            return result > 0
        except Exception as e:
            logger.warning(f"Failed to mark processed in {set_name}: {e}")
            return False

    async def is_processed(self, set_name: str, key: str) -> bool:
        """Check if a key has been processed.

        Args:
            set_name: Name of the dedup set
            key: The key to check

        Returns:
            True if already processed, False otherwise
        """
        redis_key = self._dedup_key(set_name)
        try:
            return await self._redis.sismember(redis_key, key) == 1
        except Exception as e:
            logger.warning(f"Failed to check processed in {set_name}: {e}")
            return False

    async def get_processed_set(self, set_name: str) -> set[str]:
        """Get all processed keys in a dedup set.

        Args:
            set_name: Name of the dedup set

        Returns:
            Set of processed keys
        """
        redis_key = self._dedup_key(set_name)
        try:
            items = await self._redis.smembers(redis_key)
            return {item if isinstance(item, str) else item.decode() for item in items}
        except Exception as e:
            logger.warning(f"Failed to get processed set {set_name}: {e}")
            return set()

    # =========================================================================
    # Meta (Scalars) - Redis HASH
    # =========================================================================

    async def set_meta(self, field: str, value: Any) -> bool:
        """Set a scalar meta field.

        Args:
            field: Field name
            value: Value (will be JSON serialized)

        Returns:
            True if set successfully
        """
        key = self._key(self.KEY_META)
        try:
            await self._redis.hset(key, field, json.dumps(value, default=str))
            await self._set_ttl(key)
            return True
        except Exception as e:
            logger.warning(f"Failed to set meta field {field}: {e}")
            return False

    async def get_meta(self, field: str, default: Any = None) -> Any:
        """Get a scalar meta field.

        Args:
            field: Field name
            default: Default value if not found

        Returns:
            Field value or default
        """
        key = self._key(self.KEY_META)
        try:
            value = await self._redis.hget(key, field)
            if value is None:
                return default
            return json.loads(value if isinstance(value, str) else value.decode())
        except Exception as e:
            logger.warning(f"Failed to get meta field {field}: {e}")
            return default

    async def get_all_meta(self) -> dict[str, Any]:
        """Get all meta fields.

        Returns:
            Dict of all meta fields
        """
        key = self._key(self.KEY_META)
        try:
            items = await self._redis.hgetall(key)
            return {
                (k if isinstance(k, str) else k.decode()): json.loads(
                    v if isinstance(v, str) else v.decode()
                )
                for k, v in items.items()
            }
        except Exception as e:
            logger.warning(f"Failed to get all meta fields: {e}")
            return {}

    # Convenience methods for common meta fields

    async def set_domain_admin(self, achieved: bool, path: str | None = None) -> None:
        """Set domain admin achievement status.

        This method only persists the DA flag and path. It does NOT set completed_at,
        as that should only be set when the operation actually completes (controlled
        by stop_on_domain_admin or stop_on_golden_ticket config).

        Note: completed_at is set by announce_domain_admin() or announce_golden_ticket()
        in announcements.py when the appropriate stop condition is met.
        """
        await self.set_meta("has_domain_admin", achieved)
        if path:
            await self.set_meta("domain_admin_path", path)

    async def get_domain_admin(self) -> tuple[bool, str | None]:
        """Get domain admin status and path."""
        achieved = await self.get_meta("has_domain_admin", default=False)
        path = await self.get_meta("domain_admin_path")
        return achieved, path

    async def set_golden_ticket(self, achieved: bool) -> None:
        """Set golden ticket achievement status."""
        await self.set_meta("has_golden_ticket", achieved)

    async def get_golden_ticket(self) -> bool:
        """Get golden ticket status."""
        return await self.get_meta("has_golden_ticket", default=False)

    async def set_golden_ticket_capable_creds(self, creds: dict[str, list[dict]]) -> bool:
        """Set golden ticket capable credentials.

        Args:
            creds: Dict mapping "domain:username" to list of capability dicts

        Returns:
            True if set successfully
        """
        return await self.set_meta("golden_ticket_capable_creds", creds)

    async def get_golden_ticket_capable_creds(self) -> dict[str, list[dict]]:
        """Get golden ticket capable credentials.

        Returns:
            Dict mapping "domain:username" to list of capability dicts
        """
        result = await self.get_meta("golden_ticket_capable_creds", default={})
        return result if isinstance(result, dict) else {}

    async def add_golden_ticket_capable_cred(self, cred_key: str, capabilities: list[dict]) -> bool:
        """Add or update a credential's golden ticket capabilities.

        Args:
            cred_key: "domain:username" key
            capabilities: List of capability dicts

        Returns:
            True if updated successfully
        """
        try:
            current = await self.get_golden_ticket_capable_creds()
            current[cred_key] = capabilities
            return await self.set_golden_ticket_capable_creds(current)
        except Exception as e:
            logger.warning(f"Failed to add golden ticket capable cred {cred_key}: {e}")
            return False

    async def set_completed(self, completed: bool) -> None:
        """Set operation completion status."""
        await self.set_meta("completed", completed)
        if completed:
            await self.set_meta("completed_at", datetime.now(timezone.utc).isoformat())

    async def get_completed(self) -> bool:
        """Get operation completion status."""
        return await self.get_meta("completed", default=False)

    # =========================================================================
    # Domain Controller Map (Redis HASH)
    # =========================================================================

    async def set_dc(self, domain: str, ip: str) -> bool:
        """Set domain controller IP for a domain.

        Args:
            domain: Domain FQDN (lowercase)
            ip: DC IP address

        Returns:
            True if set successfully
        """
        key = self._key(self.KEY_DC_MAP)
        try:
            await self._redis.hset(key, domain.lower(), ip)
            await self._set_ttl(key)
            return True
        except Exception as e:
            logger.warning(f"Failed to set DC for {domain}: {e}")
            return False

    async def get_dc(self, domain: str) -> str | None:
        """Get domain controller IP for a domain.

        Args:
            domain: Domain FQDN

        Returns:
            DC IP or None if not found
        """
        key = self._key(self.KEY_DC_MAP)
        try:
            value = await self._redis.hget(key, domain.lower())
            if value is None:
                return None
            return value if isinstance(value, str) else value.decode()
        except Exception as e:
            logger.warning(f"Failed to get DC for {domain}: {e}")
            return None

    async def get_all_dcs(self) -> dict[str, str]:
        """Get all domain controller mappings.

        Returns:
            Dict mapping domain -> DC IP
        """
        key = self._key(self.KEY_DC_MAP)
        try:
            items = await self._redis.hgetall(key)
            return {
                k if isinstance(k, str) else k.decode(): v if isinstance(v, str) else v.decode()
                for k, v in items.items()
            }
        except Exception as e:
            logger.warning(f"Failed to get all DCs: {e}")
            return {}

    # =========================================================================
    # NetBIOS to FQDN Map (Redis HASH)
    # =========================================================================

    async def set_netbios_mapping(self, netbios: str, fqdn: str) -> bool:
        """Set NetBIOS to FQDN mapping.

        Args:
            netbios: NetBIOS name (lowercase)
            fqdn: FQDN (lowercase)

        Returns:
            True if set successfully
        """
        key = self._key(self.KEY_NETBIOS_MAP)
        try:
            await self._redis.hset(key, netbios.lower(), fqdn.lower())
            await self._set_ttl(key)
            return True
        except Exception as e:
            logger.warning(f"Failed to set NetBIOS mapping for {netbios}: {e}")
            return False

    async def get_netbios_mapping(self, netbios: str) -> str | None:
        """Get FQDN for NetBIOS name.

        Args:
            netbios: NetBIOS name

        Returns:
            FQDN or None if not found
        """
        key = self._key(self.KEY_NETBIOS_MAP)
        try:
            value = await self._redis.hget(key, netbios.lower())
            if value is None:
                return None
            return value if isinstance(value, str) else value.decode()
        except Exception as e:
            logger.warning(f"Failed to get NetBIOS mapping for {netbios}: {e}")
            return None

    async def get_all_netbios_mappings(self) -> dict[str, str]:
        """Get all NetBIOS to FQDN mappings.

        Returns:
            Dict mapping netbios -> fqdn
        """
        key = self._key(self.KEY_NETBIOS_MAP)
        try:
            items = await self._redis.hgetall(key)
            return {
                k if isinstance(k, str) else k.decode(): v if isinstance(v, str) else v.decode()
                for k, v in items.items()
            }
        except Exception as e:
            logger.warning(f"Failed to get all NetBIOS mappings: {e}")
            return {}

    # =========================================================================
    # Artifacts (Redis HASH)
    # =========================================================================

    async def store_artifact(self, artifact_key: str, content: str) -> bool:
        """Store a base64-encoded artifact.

        Args:
            artifact_key: Artifact key (e.g., "sysvol/login.bat")
            content: Base64-encoded content

        Returns:
            True if stored successfully
        """
        key = self._key(self.KEY_ARTIFACTS)
        try:
            await self._redis.hset(key, artifact_key, content)
            await self._set_ttl(key)
            return True
        except Exception as e:
            logger.warning(f"Failed to store artifact {artifact_key}: {e}")
            return False

    async def get_artifact(self, artifact_key: str) -> str | None:
        """Get a base64-encoded artifact.

        Args:
            artifact_key: Artifact key

        Returns:
            Base64-encoded content or None
        """
        key = self._key(self.KEY_ARTIFACTS)
        try:
            value = await self._redis.hget(key, artifact_key)
            if value is None:
                return None
            return value if isinstance(value, str) else value.decode()
        except Exception as e:
            logger.warning(f"Failed to get artifact {artifact_key}: {e}")
            return None

    async def list_artifacts(self, prefix: str = "") -> list[str]:
        """List artifact keys, optionally filtered by prefix.

        Args:
            prefix: Optional prefix filter

        Returns:
            List of artifact keys
        """
        key = self._key(self.KEY_ARTIFACTS)
        try:
            keys = await self._redis.hkeys(key)
            result = [k if isinstance(k, str) else k.decode() for k in keys]
            if prefix:
                result = [k for k in result if k.startswith(prefix)]
            return result
        except Exception as e:
            logger.warning(f"Failed to list artifacts: {e}")
            return []

    async def get_all_artifacts(self) -> dict[str, str]:
        """Get all artifacts as a dictionary.

        Returns:
            Dict of artifact_key -> base64-encoded content
        """
        key = self._key(self.KEY_ARTIFACTS)
        try:
            data = await self._redis.hgetall(key)
            return {
                (k if isinstance(k, str) else k.decode()): (v if isinstance(v, str) else v.decode())
                for k, v in data.items()
            }
        except Exception as e:
            logger.warning(f"Failed to get all artifacts: {e}")
            return {}

    # =========================================================================
    # Pending Tasks Tracking (Redis HASH)
    # =========================================================================

    async def add_pending_task(self, task_id: str, task_info: dict) -> bool:
        """Add a pending task to Redis HASH.

        Args:
            task_id: Unique task identifier
            task_info: Serialized TaskInfo dict

        Returns:
            True if added successfully
        """
        redis_key = self._key(self.KEY_PENDING_TASKS)
        try:
            data = json.dumps(task_info, separators=(",", ":"), default=str)
            await self._redis.hset(redis_key, task_id, data)
            await self._set_ttl(redis_key)
            return True
        except Exception as e:
            logger.warning(f"Failed to add pending task to Redis: {e}")
            return False

    async def remove_pending_task(self, task_id: str) -> bool:
        """Remove a pending task from Redis HASH.

        Args:
            task_id: Task ID to remove

        Returns:
            True if removed (or didn't exist)
        """
        redis_key = self._key(self.KEY_PENDING_TASKS)
        try:
            await self._redis.hdel(redis_key, task_id)
            return True
        except Exception as e:
            logger.warning(f"Failed to remove pending task from Redis: {e}")
            return False

    async def get_pending_tasks(self) -> dict[str, dict]:
        """Get all pending tasks from Redis HASH.

        Returns:
            Dict mapping task_id to task_info dict
        """
        redis_key = self._key(self.KEY_PENDING_TASKS)
        try:
            raw = await self._redis.hgetall(redis_key)
            result = {}
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

    async def update_pending_task_activity(self, task_id: str) -> bool:
        """Update last_activity_at for a pending task.

        Args:
            task_id: Task ID to update

        Returns:
            True if updated successfully
        """
        redis_key = self._key(self.KEY_PENDING_TASKS)
        try:
            raw = await self._redis.hget(redis_key, task_id)
            if not raw:
                return False
            data = json.loads(raw)
            data["last_activity_at"] = datetime.now(timezone.utc).isoformat()
            await self._redis.hset(
                redis_key, task_id, json.dumps(data, separators=(",", ":"), default=str)
            )
            return True
        except Exception as e:
            logger.warning(f"Failed to update pending task activity: {e}")
            return False

    # =========================================================================
    # Completed Tasks Tracking (Redis HASH)
    # =========================================================================

    async def add_completed_task(self, task_id: str, task_result: dict) -> bool:
        """Add a completed task to Redis HASH.

        Args:
            task_id: Unique task identifier
            task_result: Serialized TaskResult dict

        Returns:
            True if added successfully
        """
        redis_key = self._key(self.KEY_COMPLETED_TASKS)
        try:
            data = json.dumps(task_result, separators=(",", ":"), default=str)
            await self._redis.hset(redis_key, task_id, data)
            await self._set_ttl(redis_key)
            return True
        except Exception as e:
            logger.warning(f"Failed to add completed task to Redis: {e}")
            return False

    async def get_completed_tasks(self) -> dict[str, dict]:
        """Get all completed tasks from Redis HASH.

        Returns:
            Dict mapping task_id to task_result dict
        """
        redis_key = self._key(self.KEY_COMPLETED_TASKS)
        try:
            raw = await self._redis.hgetall(redis_key)
            result = {}
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
    # Vulnerability Type Failure Tracking (Redis HASH)
    # =========================================================================

    async def increment_vuln_type_failure(self, vuln_type: str) -> int:
        """Increment failure count for a vulnerability type.

        Args:
            vuln_type: The vulnerability type (e.g., "mssql_impersonation")

        Returns:
            New failure count after increment
        """
        redis_key = self._key(self.KEY_VULN_TYPE_FAILURES)
        try:
            count = await self._redis.hincrby(redis_key, vuln_type, 1)
            await self._set_ttl(redis_key)
            return count
        except Exception as e:
            logger.warning(f"Failed to increment vuln type failure count: {e}")
            return 0

    async def get_vuln_type_failure_count(self, vuln_type: str) -> int:
        """Get failure count for a vulnerability type.

        Args:
            vuln_type: The vulnerability type

        Returns:
            Current failure count (0 if not found)
        """
        redis_key = self._key(self.KEY_VULN_TYPE_FAILURES)
        try:
            count = await self._redis.hget(redis_key, vuln_type)
            return int(count) if count else 0
        except Exception as e:
            logger.warning(f"Failed to get vuln type failure count: {e}")
            return 0

    async def get_all_vuln_type_failures(self) -> dict[str, int]:
        """Get all vulnerability type failure counts.

        Returns:
            Dict mapping vuln_type to failure count
        """
        redis_key = self._key(self.KEY_VULN_TYPE_FAILURES)
        try:
            raw = await self._redis.hgetall(redis_key)
            result = {}
            for k, v in raw.items():
                vuln_type = k if isinstance(k, str) else k.decode()
                try:
                    result[vuln_type] = int(v)
                except (ValueError, TypeError):
                    result[vuln_type] = 0
            return result
        except Exception as e:
            logger.warning(f"Failed to get all vuln type failures: {e}")
            return {}

    # =========================================================================
    # MSSQL Enum Dispatch Tracking (Redis SET)
    # =========================================================================

    async def add_mssql_enum_dispatched(self, key: str) -> bool:
        """Mark a MSSQL enum as dispatched.

        Args:
            key: The dispatch key (e.g., "mssql_enum:{ip}:{domain}\\{username}")

        Returns:
            True if newly added, False if already existed
        """
        redis_key = self._key(self.KEY_MSSQL_ENUM_DISPATCHED)
        try:
            result = await self._redis.sadd(redis_key, key)
            await self._set_ttl(redis_key)
            return result > 0
        except Exception as e:
            logger.warning(f"Failed to add MSSQL enum dispatched: {e}")
            return False

    async def is_mssql_enum_dispatched(self, key: str) -> bool:
        """Check if a MSSQL enum has been dispatched.

        Args:
            key: The dispatch key to check

        Returns:
            True if already dispatched
        """
        redis_key = self._key(self.KEY_MSSQL_ENUM_DISPATCHED)
        try:
            return await self._redis.sismember(redis_key, key) == 1
        except Exception as e:
            logger.warning(f"Failed to check MSSQL enum dispatched: {e}")
            return False

    async def get_mssql_enum_dispatched(self) -> set[str]:
        """Get all dispatched MSSQL enum keys.

        Returns:
            Set of dispatched keys
        """
        redis_key = self._key(self.KEY_MSSQL_ENUM_DISPATCHED)
        try:
            items = await self._redis.smembers(redis_key)
            return {item if isinstance(item, str) else item.decode() for item in items}
        except Exception as e:
            logger.warning(f"Failed to get MSSQL enum dispatched: {e}")
            return set()

    # =========================================================================
    # Golden Tickets (Redis LIST)
    # =========================================================================

    async def add_golden_ticket(self, ticket: dict) -> bool:
        """Add a golden ticket record to Redis LIST.

        Args:
            ticket: Golden ticket dict with domain, ticket_path, status, etc.

        Returns:
            True if added successfully
        """
        key = self._key(self.KEY_GOLDEN_TICKETS)
        try:
            data = json.dumps(ticket, separators=(",", ":"), default=str)
            await self._redis.rpush(key, data)
            await self._set_ttl(key)
            return True
        except Exception as e:
            logger.warning(f"Failed to add golden ticket to Redis: {e}")
            return False

    async def get_golden_tickets(self) -> list[dict]:
        """Get all golden tickets from Redis LIST.

        Returns:
            List of golden ticket dicts
        """
        key = self._key(self.KEY_GOLDEN_TICKETS)
        try:
            items = await self._redis.lrange(key, 0, -1)
            return [json.loads(item if isinstance(item, str) else item.decode()) for item in items]
        except Exception as e:
            logger.warning(f"Failed to get golden tickets from Redis: {e}")
            return []

    # =========================================================================
    # AdminSD Holder Backdoors (Redis LIST)
    # =========================================================================

    async def add_adminsd_backdoor(self, backdoor_key: str) -> bool:
        """Add an AdminSD holder backdoor to Redis LIST.

        Args:
            backdoor_key: Backdoor identifier string

        Returns:
            True if added successfully
        """
        key = self._key(self.KEY_ADMINSD_BACKDOORS)
        try:
            await self._redis.rpush(key, backdoor_key)
            await self._set_ttl(key)
            return True
        except Exception as e:
            logger.warning(f"Failed to add AdminSD backdoor to Redis: {e}")
            return False

    async def get_adminsd_backdoors(self) -> list[str]:
        """Get all AdminSD holder backdoors from Redis LIST.

        Returns:
            List of backdoor identifier strings
        """
        key = self._key(self.KEY_ADMINSD_BACKDOORS)
        try:
            items = await self._redis.lrange(key, 0, -1)
            return [item if isinstance(item, str) else item.decode() for item in items]
        except Exception as e:
            logger.warning(f"Failed to get AdminSD backdoors from Redis: {e}")
            return []

    # =========================================================================
    # ACL Chains (Redis LIST)
    # =========================================================================

    async def add_acl_chain(self, chain: dict) -> bool:
        """Add an ACL chain to Redis LIST.

        Args:
            chain: ACL chain dict with chain_id, steps, goal, domain, etc.

        Returns:
            True if added successfully
        """
        key = self._key(self.KEY_ACL_CHAINS)
        try:
            data = json.dumps(chain, separators=(",", ":"), default=str)
            await self._redis.rpush(key, data)
            await self._set_ttl(key)
            return True
        except Exception as e:
            logger.warning(f"Failed to add ACL chain to Redis: {e}")
            return False

    async def get_acl_chains(self) -> list[dict]:
        """Get all ACL chains from Redis LIST.

        Returns:
            List of ACL chain dicts
        """
        key = self._key(self.KEY_ACL_CHAINS)
        try:
            items = await self._redis.lrange(key, 0, -1)
            return [json.loads(item if isinstance(item, str) else item.decode()) for item in items]
        except Exception as e:
            logger.warning(f"Failed to get ACL chains from Redis: {e}")
            return []

    async def update_acl_chain(self, chain_id: str, chain: dict) -> bool:
        """Update an existing ACL chain in Redis LIST.

        Since Redis LIST doesn't support direct update by value, this method:
        1. Gets all chains
        2. Finds the chain with matching chain_id
        3. Replaces it with the new chain
        4. Rewrites the list

        Args:
            chain_id: Chain ID to update
            chain: Updated chain dict

        Returns:
            True if updated, False if not found
        """
        key = self._key(self.KEY_ACL_CHAINS)
        try:
            items = await self._redis.lrange(key, 0, -1)
            updated = False
            new_items = []

            for item in items:
                existing = json.loads(item if isinstance(item, str) else item.decode())
                if existing.get("chain_id") == chain_id:
                    new_items.append(json.dumps(chain, separators=(",", ":"), default=str))
                    updated = True
                else:
                    new_items.append(item)

            if updated:
                pipe = self._redis.pipeline()
                pipe.delete(key)
                if new_items:
                    pipe.rpush(key, *new_items)
                pipe.expire(key, self.DEFAULT_TTL)
                await pipe.execute()

            return updated
        except Exception as e:
            logger.warning(f"Failed to update ACL chain in Redis: {e}")
            return False

    # =========================================================================
    # gMSA Accounts (Redis LIST)
    # =========================================================================

    async def add_gmsa_account(self, gmsa: dict) -> bool:
        """Add a gMSA account to Redis LIST.

        Args:
            gmsa: gMSA account dict with account, domain, principals_allowed, etc.

        Returns:
            True if added successfully
        """
        key = self._key(self.KEY_GMSA_ACCOUNTS)
        try:
            data = json.dumps(gmsa, separators=(",", ":"), default=str)
            await self._redis.rpush(key, data)
            await self._set_ttl(key)
            return True
        except Exception as e:
            logger.warning(f"Failed to add gMSA account to Redis: {e}")
            return False

    async def get_gmsa_accounts(self) -> list[dict]:
        """Get all gMSA accounts from Redis LIST.

        Returns:
            List of gMSA account dicts
        """
        key = self._key(self.KEY_GMSA_ACCOUNTS)
        try:
            items = await self._redis.lrange(key, 0, -1)
            return [json.loads(item if isinstance(item, str) else item.decode()) for item in items]
        except Exception as e:
            logger.warning(f"Failed to get gMSA accounts from Redis: {e}")
            return []

    # =========================================================================
    # Report Storage (Redis STRING)
    # =========================================================================

    async def store_report(self, report_markdown: str) -> bool:
        """Store the operation report in Redis.

        Args:
            report_markdown: The markdown report content

        Returns:
            True if stored successfully
        """
        try:
            key = f"{self._key_prefix}:report"
            await self._redis.set(key, report_markdown, ex=self.DEFAULT_TTL)
            logger.info(
                f"Stored report for operation {self._operation_id} ({len(report_markdown)} bytes)"
            )
            return True
        except Exception as e:
            logger.warning(f"Failed to store report: {e}")
            return False

    async def get_report(self) -> str | None:
        """Get the stored operation report.

        Returns:
            The markdown report content, or None if not found
        """
        try:
            key = f"{self._key_prefix}:report"
            report = await self._redis.get(key)
            if report:
                if isinstance(report, bytes):
                    return report.decode()
                return report
            return None
        except Exception as e:
            logger.warning(f"Failed to get report: {e}")
            return None

    async def delete_all_keys(self) -> int:
        """Delete all keys for this operation.

        Returns:
            Number of keys deleted
        """
        try:
            pattern = f"{self._key_prefix}:*"
            deleted = 0
            async for key in self._redis.scan_iter(pattern):
                await self._redis.delete(key)
                deleted += 1
            logger.info(f"Deleted {deleted} keys for operation {self._operation_id}")
            return deleted
        except Exception as e:
            logger.warning(f"Failed to delete keys: {e}")
            return 0


# =============================================================================
# Serialization Helpers
# =============================================================================


def _serialize_credential(cred: Credential) -> str:
    """Serialize a Credential to JSON string."""
    return json.dumps(
        {
            "id": cred.id,
            "username": cred.username,
            "password": cred.password,
            "domain": cred.domain,
            "source": cred.source,
            "parent_id": cred.parent_id,
            "attack_step": cred.attack_step,
        },
        separators=(",", ":"),
    )


def _deserialize_credential(data: str | bytes) -> Credential:
    """Deserialize a Credential from JSON string."""
    from ares.core.models import Credential

    if isinstance(data, bytes):
        data = data.decode()
    d = json.loads(data)
    # Use `or ""` instead of `get(key, "")` to handle JSON null values
    return Credential(
        id=d.get("id") or "",
        username=d.get("username") or "",
        password=d.get("password") or "",
        domain=d.get("domain") or "",
        source=d.get("source") or "",
        parent_id=d.get("parent_id"),
        attack_step=d.get("attack_step") or 0,
    )


def _serialize_hash(hash_obj: Hash) -> str:
    """Serialize a Hash to JSON string."""
    return json.dumps(
        {
            "id": hash_obj.id,
            "username": hash_obj.username,
            "hash_type": hash_obj.hash_type,
            "hash_value": hash_obj.hash_value,
            "domain": hash_obj.domain,
            "source": hash_obj.source,
            "cracked_password": hash_obj.cracked_password,
            "discovered_at": hash_obj.discovered_at.isoformat() if hash_obj.discovered_at else None,
            "parent_id": hash_obj.parent_id,
            "attack_step": hash_obj.attack_step,
        },
        separators=(",", ":"),
    )


def _deserialize_hash(data: str | bytes) -> Hash:
    """Deserialize a Hash from JSON string."""
    from ares.core.models import Hash

    if isinstance(data, bytes):
        data = data.decode()
    d = json.loads(data)
    discovered_at = None
    if d.get("discovered_at"):
        discovered_at = datetime.fromisoformat(d["discovered_at"])
    # Use `or ""` instead of `get(key, "")` to handle JSON null values
    return Hash(
        id=d.get("id") or "",
        username=d.get("username") or "",
        hash_type=d.get("hash_type") or "",
        hash_value=d.get("hash_value") or "",
        domain=d.get("domain") or "",
        source=d.get("source") or "",
        cracked_password=d.get("cracked_password"),
        discovered_at=discovered_at,
        parent_id=d.get("parent_id"),
        attack_step=d.get("attack_step") or 0,
    )


def _serialize_host(host: Host) -> str:
    """Serialize a Host to JSON string."""
    return json.dumps(
        {
            "ip": host.ip,
            "hostname": host.hostname,
            "os": host.os,
            "roles": host.roles,
            "services": host.services,
            "is_dc": host.is_dc,
        },
        separators=(",", ":"),
    )


def _deserialize_host(data: str | bytes) -> Host:
    """Deserialize a Host from JSON string."""
    from ares.core.models import Host

    if isinstance(data, bytes):
        data = data.decode()
    d = json.loads(data)
    # Use `or` instead of `get(key, default)` to handle JSON null values
    host = Host(
        ip=d.get("ip") or "",
        hostname=d.get("hostname") or "",
        os=d.get("os") or "",
        roles=d.get("roles") or [],
        services=d.get("services") or [],
    )
    host.is_dc = d.get("is_dc") or False
    return host


def _serialize_user(user: User) -> str:
    """Serialize a User to JSON string."""
    return json.dumps(
        {
            "username": user.username,
            "domain": user.domain,
            "source": user.source,
        },
        separators=(",", ":"),
    )


def _deserialize_user(data: str | bytes) -> User:
    """Deserialize a User from JSON string."""
    from ares.core.models import User

    if isinstance(data, bytes):
        data = data.decode()
    d = json.loads(data)
    # Use `or ""` instead of `get(key, "")` to handle JSON null values
    return User(
        username=d.get("username") or "",
        domain=d.get("domain") or "",
        source=d.get("source") or "",
    )


def _serialize_share(share: Share) -> str:
    """Serialize a Share to JSON string."""
    return json.dumps(
        {
            "host": share.host,
            "name": share.name,
            "permissions": share.permissions,
            "comment": share.comment,
        },
        separators=(",", ":"),
    )


def _deserialize_share(data: str | bytes) -> Share:
    """Deserialize a Share from JSON string."""
    from ares.core.models import Share

    if isinstance(data, bytes):
        data = data.decode()
    d = json.loads(data)
    # Use `or ""` instead of `get(key, "")` to handle JSON null values
    return Share(
        host=d.get("host") or "",
        name=d.get("name") or "",
        permissions=d.get("permissions") or "",
        comment=d.get("comment") or "",
    )


def _serialize_vulnerability(vuln: VulnerabilityInfo) -> str:
    """Serialize a VulnerabilityInfo to JSON string."""
    return json.dumps(
        {
            "vuln_id": vuln.vuln_id,
            "vuln_type": vuln.vuln_type,
            "target": vuln.target,
            "discovered_by": vuln.discovered_by,
            "discovered_at": vuln.discovered_at.isoformat() if vuln.discovered_at else None,
            "details": vuln.details,
            "recommended_agent": vuln.recommended_agent,
            "priority": vuln.priority,
        },
        separators=(",", ":"),
    )


def _deserialize_vulnerability(data: str | bytes) -> VulnerabilityInfo:
    """Deserialize a VulnerabilityInfo from JSON string."""
    from ares.core.models import VulnerabilityInfo

    if isinstance(data, bytes):
        data = data.decode()
    d = json.loads(data)
    discovered_at = datetime.now(timezone.utc)
    if d.get("discovered_at"):
        discovered_at = datetime.fromisoformat(d["discovered_at"])
    raw_details = d.get("details", {})
    details = raw_details if isinstance(raw_details, dict) else {}
    return VulnerabilityInfo(
        vuln_id=d.get("vuln_id", ""),
        vuln_type=d.get("vuln_type", ""),
        target=d.get("target", ""),
        discovered_by=d.get("discovered_by", ""),
        discovered_at=discovered_at,
        details=details,
        recommended_agent=d.get("recommended_agent", ""),
        priority=d.get("priority", 5),
    )


__all__ = [
    "RedisStateBackend",
]
