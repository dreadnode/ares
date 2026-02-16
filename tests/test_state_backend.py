"""Unit tests for Redis-native state backend.

Tests the RedisStateBackend class used for direct Redis storage
of SharedRedTeamState collections.
"""

from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock

import pytest

# Create a mock redis.asyncio module if redis is not installed
if "redis" not in sys.modules:
    mock_redis_module = MagicMock()
    mock_redis_asyncio = MagicMock()
    mock_redis_module.asyncio = mock_redis_asyncio
    sys.modules["redis"] = mock_redis_module
    sys.modules["redis.asyncio"] = mock_redis_asyncio

from ares.core.models import Credential, Hash, Host, Share, User, VulnerabilityInfo
from ares.core.state_backend import (
    RedisStateBackend,
    _deserialize_credential,
    _deserialize_hash,
    _deserialize_host,
    _deserialize_share,
    _deserialize_user,
    _deserialize_vulnerability,
    _serialize_credential,
    _serialize_hash,
    _serialize_host,
    _serialize_share,
    _serialize_user,
    _serialize_vulnerability,
)

# ============================================================================
# Serialization Tests
# ============================================================================


class TestSerializationHelpers:
    """Tests for serialization/deserialization helper functions."""

    def test_credential_roundtrip(self):
        """Test Credential serialization roundtrip."""
        cred = Credential(
            username="admin",
            password="P@ssw0rd!",  # pragma: allowlist secret
            domain="contoso.local",
            source="kerberoast",
            parent_id="hash-123",
            attack_step=2,
        )
        cred.id = "cred-abc"

        serialized = _serialize_credential(cred)
        assert isinstance(serialized, str)

        deserialized = _deserialize_credential(serialized)
        assert deserialized.username == "admin"
        assert deserialized.password == "P@ssw0rd!"  # pragma: allowlist secret
        assert deserialized.domain == "contoso.local"
        assert deserialized.source == "kerberoast"
        assert deserialized.parent_id == "hash-123"
        assert deserialized.attack_step == 2
        assert deserialized.id == "cred-abc"

    def test_credential_deserialize_bytes(self):
        """Test Credential deserialization from bytes."""
        cred = Credential(
            username="svc_backup",
            password="backup123",  # pragma: allowlist secret
            domain="fabrikam.local",
        )
        serialized = _serialize_credential(cred).encode()

        deserialized = _deserialize_credential(serialized)
        assert deserialized.username == "svc_backup"
        assert deserialized.domain == "fabrikam.local"

    def test_hash_roundtrip(self):
        """Test Hash serialization roundtrip."""
        hash_obj = Hash(
            username="krbtgt",
            hash_type="NTLM",
            hash_value="aad3b435b51404eeaad3b435b51404ee:abc123",
            domain="contoso.local",
            source="secretsdump",
            discovered_at=datetime(2024, 1, 15, 10, 30, 0, tzinfo=timezone.utc),
        )
        hash_obj.id = "hash-xyz"

        serialized = _serialize_hash(hash_obj)
        deserialized = _deserialize_hash(serialized)

        assert deserialized.username == "krbtgt"
        assert deserialized.hash_type == "NTLM"
        assert deserialized.hash_value == "aad3b435b51404eeaad3b435b51404ee:abc123"
        assert deserialized.domain == "contoso.local"
        assert deserialized.source == "secretsdump"
        assert deserialized.discovered_at is not None
        assert deserialized.id == "hash-xyz"

    def test_hash_with_cracked_password(self):
        """Test Hash with cracked password."""
        hash_obj = Hash(
            username="admin",
            hash_type="NTLM",
            hash_value="abc:def",
            domain="contoso.local",
            cracked_password="P@ssw0rd!",  # pragma: allowlist secret
        )

        serialized = _serialize_hash(hash_obj)
        deserialized = _deserialize_hash(serialized)

        assert deserialized.cracked_password == "P@ssw0rd!"  # pragma: allowlist secret

    def test_host_roundtrip(self):
        """Test Host serialization roundtrip."""
        host = Host(
            ip="192.168.58.10",
            hostname="dc01.contoso.local",
            os="Windows Server 2019",
            roles=["Domain Controller", "DNS"],
            services=["LDAP", "Kerberos", "SMB"],
        )
        host.is_dc = True

        serialized = _serialize_host(host)
        deserialized = _deserialize_host(serialized)

        assert deserialized.ip == "192.168.58.10"
        assert deserialized.hostname == "dc01.contoso.local"
        assert deserialized.os == "Windows Server 2019"
        assert "Domain Controller" in deserialized.roles
        assert "LDAP" in deserialized.services
        assert deserialized.is_dc is True

    def test_user_roundtrip(self):
        """Test User serialization roundtrip."""
        user = User(
            username="sql_svc",
            domain="contoso.local",
            source="ldap_enum",
        )

        serialized = _serialize_user(user)
        deserialized = _deserialize_user(serialized)

        assert deserialized.username == "sql_svc"
        assert deserialized.domain == "contoso.local"
        assert deserialized.source == "ldap_enum"

    def test_share_roundtrip(self):
        """Test Share serialization roundtrip."""
        share = Share(
            host="192.168.58.10",
            name="SYSVOL",
            permissions="read",
            comment="Logon server share",
        )

        serialized = _serialize_share(share)
        deserialized = _deserialize_share(serialized)

        assert deserialized.host == "192.168.58.10"
        assert deserialized.name == "SYSVOL"
        assert deserialized.permissions == "read"
        assert deserialized.comment == "Logon server share"

    def test_vulnerability_roundtrip(self):
        """Test VulnerabilityInfo serialization roundtrip."""
        vuln = VulnerabilityInfo(
            vuln_id="vuln-123",
            vuln_type="ADCS_ESC1",
            target="dc01.contoso.local",
            discovered_by="privesc-agent",
            discovered_at=datetime(2024, 1, 15, 10, 30, 0, tzinfo=timezone.utc),
            details={"template": "UserTemplate", "enrollee": "Domain Users"},
            recommended_agent="privesc",
            priority=1,
        )

        serialized = _serialize_vulnerability(vuln)
        deserialized = _deserialize_vulnerability(serialized)

        assert deserialized.vuln_id == "vuln-123"
        assert deserialized.vuln_type == "ADCS_ESC1"
        assert deserialized.target == "dc01.contoso.local"
        assert deserialized.discovered_by == "privesc-agent"
        assert deserialized.details["template"] == "UserTemplate"
        assert deserialized.priority == 1


# ============================================================================
# RedisStateBackend Tests
# ============================================================================


@pytest.fixture
def mock_redis():
    """Create a mock Redis client."""
    client = AsyncMock()
    client.rpush = AsyncMock(return_value=1)
    client.lrange = AsyncMock(return_value=[])
    client.sadd = AsyncMock(return_value=1)
    client.smembers = AsyncMock(return_value=set())
    client.sismember = AsyncMock(return_value=0)
    client.hset = AsyncMock(return_value=1)
    client.hsetnx = AsyncMock(return_value=1)
    client.hget = AsyncMock(return_value=None)
    client.hgetall = AsyncMock(return_value={})
    client.hkeys = AsyncMock(return_value=[])
    client.expire = AsyncMock(return_value=True)
    client.delete = AsyncMock(return_value=1)
    client.scan_iter = AsyncMock(return_value=iter([]))
    client.pipeline = MagicMock()
    return client


@pytest.fixture
def backend(mock_redis):
    """Create a RedisStateBackend with mock Redis client."""
    return RedisStateBackend(mock_redis, "op-test-123")


class TestRedisStateBackend:
    """Tests for RedisStateBackend class."""

    def test_key_construction(self, backend):
        """Test Redis key construction."""
        assert backend._key("credentials") == "ares:op:op-test-123:credentials"
        assert backend._key("meta") == "ares:op:op-test-123:meta"

    def test_dedup_key_construction(self, backend):
        """Test dedup set key construction."""
        assert backend._dedup_key("cred_expansion") == "ares:op:op-test-123:dedup:cred_expansion"

    @pytest.mark.asyncio
    async def test_add_credential(self, backend, mock_redis):
        """Test adding a credential to Redis."""
        cred = Credential(
            username="admin",
            password="P@ssw0rd!",  # pragma: allowlist secret
            domain="contoso.local",
        )

        result = await backend.add_credential(cred)

        assert result is True
        mock_redis.rpush.assert_called_once()
        call_args = mock_redis.rpush.call_args
        assert call_args[0][0] == "ares:op:op-test-123:credentials"
        # Verify it's valid JSON
        data = json.loads(call_args[0][1])
        assert data["username"] == "admin"

    @pytest.mark.asyncio
    async def test_get_credentials(self, backend, mock_redis):
        """Test getting credentials from Redis."""
        # Setup mock to return serialized credentials
        cred1 = Credential(username="admin", password="pass1", domain="contoso.local")
        cred2 = Credential(username="svc_sql", password="pass2", domain="contoso.local")
        mock_redis.lrange.return_value = [
            _serialize_credential(cred1),
            _serialize_credential(cred2),
        ]

        result = await backend.get_credentials()

        assert len(result) == 2
        assert result[0].username == "admin"
        assert result[1].username == "svc_sql"

    @pytest.mark.asyncio
    async def test_add_hash(self, backend, mock_redis):
        """Test adding a hash to Redis."""
        hash_obj = Hash(
            username="krbtgt",
            hash_type="NTLM",
            hash_value="abc:def",
            domain="contoso.local",
        )

        result = await backend.add_hash(hash_obj)

        assert result is True
        mock_redis.rpush.assert_called_once()

    @pytest.mark.asyncio
    async def test_add_host(self, backend, mock_redis):
        """Test adding a host to Redis."""
        host = Host(
            ip="192.168.58.10",
            hostname="dc01.contoso.local",
        )

        result = await backend.add_host(host)

        assert result is True
        mock_redis.rpush.assert_called_once()

    @pytest.mark.asyncio
    async def test_add_vulnerability(self, backend, mock_redis):
        """Test adding a vulnerability to Redis."""
        vuln = VulnerabilityInfo(
            vuln_id="vuln-123",
            vuln_type="ADCS_ESC1",
            target="dc01.contoso.local",
            discovered_by="privesc",
        )

        result = await backend.add_vulnerability(vuln)

        assert result is True
        mock_redis.hsetnx.assert_called_once()
        call_args = mock_redis.hsetnx.call_args
        assert call_args[0][0] == "ares:op:op-test-123:vulns"
        assert call_args[0][1] == "vuln-123"

    @pytest.mark.asyncio
    async def test_mark_exploited(self, backend, mock_redis):
        """Test marking a vulnerability as exploited."""
        result = await backend.mark_exploited("vuln-123")

        assert result is True
        mock_redis.sadd.assert_called_once()
        call_args = mock_redis.sadd.call_args
        assert call_args[0][0] == "ares:op:op-test-123:exploited"
        assert call_args[0][1] == "vuln-123"

    @pytest.mark.asyncio
    async def test_mark_processed(self, backend, mock_redis):
        """Test marking a key as processed in dedup set."""
        result = await backend.mark_processed("cred_expansion", "contoso.local:admin:hash123")

        assert result is True
        mock_redis.sadd.assert_called_once()
        call_args = mock_redis.sadd.call_args
        assert call_args[0][0] == "ares:op:op-test-123:dedup:cred_expansion"
        assert call_args[0][1] == "contoso.local:admin:hash123"

    @pytest.mark.asyncio
    async def test_is_processed_true(self, backend, mock_redis):
        """Test checking if key is processed (exists)."""
        mock_redis.sismember.return_value = 1

        result = await backend.is_processed("cred_expansion", "contoso.local:admin:hash123")

        assert result is True

    @pytest.mark.asyncio
    async def test_is_processed_false(self, backend, mock_redis):
        """Test checking if key is processed (not exists)."""
        mock_redis.sismember.return_value = 0

        result = await backend.is_processed("cred_expansion", "contoso.local:admin:hash123")

        assert result is False

    @pytest.mark.asyncio
    async def test_set_and_get_meta(self, backend, mock_redis):
        """Test setting and getting meta fields."""
        # Test set
        await backend.set_meta("has_domain_admin", value=True)
        mock_redis.hset.assert_called()

        # Test get
        mock_redis.hget.return_value = "true"
        result = await backend.get_meta("has_domain_admin", default=False)
        assert result is True

    @pytest.mark.asyncio
    async def test_set_domain_admin(self, backend, mock_redis):
        """Test setting domain admin status."""
        await backend.set_domain_admin(achieved=True, path="kerberoast -> secretsdump")

        # Should set has_domain_admin, domain_admin_path, and completed_at
        assert mock_redis.hset.call_count >= 2

    @pytest.mark.asyncio
    async def test_get_domain_admin(self, backend, mock_redis):
        """Test getting domain admin status."""
        mock_redis.hget.side_effect = [
            '"true"',  # has_domain_admin
            '"kerberoast -> secretsdump"',  # domain_admin_path
        ]

        achieved, path = await backend.get_domain_admin()

        assert achieved == "true"  # Note: JSON string, caller should parse
        assert path == "kerberoast -> secretsdump"

    @pytest.mark.asyncio
    async def test_set_dc(self, backend, mock_redis):
        """Test setting DC mapping."""
        result = await backend.set_dc("contoso.local", "192.168.58.10")

        assert result is True
        mock_redis.hset.assert_called_once()
        call_args = mock_redis.hset.call_args
        assert call_args[0][0] == "ares:op:op-test-123:dc_map"
        assert call_args[0][1] == "contoso.local"
        assert call_args[0][2] == "192.168.58.10"

    @pytest.mark.asyncio
    async def test_get_dc(self, backend, mock_redis):
        """Test getting DC mapping."""
        mock_redis.hget.return_value = "192.168.58.10"

        result = await backend.get_dc("contoso.local")

        assert result == "192.168.58.10"

    @pytest.mark.asyncio
    async def test_store_artifact(self, backend, mock_redis):
        """Test storing an artifact."""
        result = await backend.store_artifact("sysvol/login.bat", "YmF0Y2ggY29udGVudA==")

        assert result is True
        mock_redis.hset.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_artifact(self, backend, mock_redis):
        """Test getting an artifact."""
        mock_redis.hget.return_value = "YmF0Y2ggY29udGVudA=="

        result = await backend.get_artifact("sysvol/login.bat")

        assert result == "YmF0Y2ggY29udGVudA=="

    @pytest.mark.asyncio
    async def test_add_domain(self, backend, mock_redis):
        """Test adding a domain."""
        result = await backend.add_domain("contoso.local")

        assert result is True
        mock_redis.sadd.assert_called_once()
        call_args = mock_redis.sadd.call_args
        assert call_args[0][0] == "ares:op:op-test-123:domains"
        assert call_args[0][1] == "contoso.local"

    @pytest.mark.asyncio
    async def test_add_weakness(self, backend, mock_redis):
        """Test adding a weakness."""
        result = await backend.add_weakness("SMB signing disabled on 192.168.58.10")

        assert result is True
        mock_redis.rpush.assert_called_once()

    @pytest.mark.asyncio
    async def test_error_handling(self, backend, mock_redis):
        """Test that Redis errors are handled gracefully."""
        mock_redis.rpush.side_effect = Exception("Connection refused")

        cred = Credential(username="admin", password="pass", domain="contoso.local")
        result = await backend.add_credential(cred)

        assert result is False


# ============================================================================
# SharedRedTeamState Processed Set Helper Tests
# ============================================================================


class TestSharedStateProcessedSetHelpers:
    """Tests for mark_processed, is_processed, and load_processed_sets_from_backend."""

    def test_mark_processed_in_memory(self):
        """Test marking a key as processed updates in-memory set."""
        from ares.core.models import SharedRedTeamState

        state = SharedRedTeamState(operation_id="op-test")
        state.mark_processed("cred_expansion", "contoso.local:admin:abc123")

        assert "contoso.local:admin:abc123" in state.processed_cred_expansion

    def test_mark_processed_with_full_attr_name(self):
        """Test marking with full attribute name (processed_xxx)."""
        from ares.core.models import SharedRedTeamState

        state = SharedRedTeamState(operation_id="op-test")
        state.mark_processed("processed_hash_lateral", "contoso.local:admin:ntlmhash")

        assert "contoso.local:admin:ntlmhash" in state.processed_hash_lateral

    def test_is_processed_returns_false_for_new_key(self):
        """Test is_processed returns False for key not yet processed."""
        from ares.core.models import SharedRedTeamState

        state = SharedRedTeamState(operation_id="op-test")
        assert state.is_processed("cred_expansion", "contoso.local:admin:abc123") is False

    def test_is_processed_returns_true_after_mark(self):
        """Test is_processed returns True after key is marked."""
        from ares.core.models import SharedRedTeamState

        state = SharedRedTeamState(operation_id="op-test")
        state.mark_processed("cred_expansion", "contoso.local:admin:abc123")
        assert state.is_processed("cred_expansion", "contoso.local:admin:abc123") is True

    def test_mark_processed_all_set_types(self):
        """Test mark_processed works for all mapped set types."""
        from ares.core.models import _PROCESSED_SET_MAP, SharedRedTeamState

        state = SharedRedTeamState(operation_id="op-test")

        for attr_name, redis_name in _PROCESSED_SET_MAP.items():
            test_key = f"test_key_for_{redis_name}"

            # Mark using Redis name
            state.mark_processed(redis_name, test_key)

            # Verify in-memory set is updated
            if hasattr(state, attr_name):
                assert test_key in getattr(state, attr_name), f"Failed for {attr_name}"

    @pytest.mark.asyncio
    async def test_mark_processed_persists_to_backend(self):
        """Test mark_processed creates async task to persist to backend."""
        import asyncio
        from unittest.mock import AsyncMock, MagicMock

        from ares.core.models import SharedRedTeamState

        state = SharedRedTeamState(operation_id="op-test")

        # Mock backend
        mock_backend = MagicMock()
        mock_backend.mark_processed = AsyncMock()
        state.set_backend(mock_backend)

        # This should create a task (we're in an async context now)
        state.mark_processed("cred_expansion", "contoso.local:admin:abc123")

        # Give the task a chance to run
        await asyncio.sleep(0.01)

        # Verify backend method was called
        mock_backend.mark_processed.assert_called_once_with(
            "cred_expansion", "contoso.local:admin:abc123"
        )

    @pytest.mark.asyncio
    async def test_load_processed_sets_from_backend(self):
        """Test loading processed sets from backend into memory."""
        from ares.core.models import SharedRedTeamState

        state = SharedRedTeamState(operation_id="op-test")

        # Mock backend that returns some processed items
        mock_backend = AsyncMock()
        mock_backend.get_processed_set = AsyncMock(
            side_effect=lambda name: {
                "cred_expansion": {"contoso.local:user1:hash1", "contoso.local:user2:hash2"},
                "hash_lateral": {"contoso.local:admin:ntlmhash"},
            }.get(name, set())
        )

        state.set_backend(mock_backend)

        # Load from backend
        await state.load_processed_sets_from_backend()

        # Verify in-memory sets are populated
        assert "contoso.local:user1:hash1" in state.processed_cred_expansion
        assert "contoso.local:user2:hash2" in state.processed_cred_expansion
        assert "contoso.local:admin:ntlmhash" in state.processed_hash_lateral

    @pytest.mark.asyncio
    async def test_load_processed_sets_without_backend(self):
        """Test load_processed_sets_from_backend is no-op without backend."""
        from ares.core.models import SharedRedTeamState

        state = SharedRedTeamState(operation_id="op-test")

        # Should not raise, just return
        await state.load_processed_sets_from_backend()

        # Sets should remain empty
        assert len(state.processed_cred_expansion) == 0

    def test_is_processed_works_with_redis_set_name(self):
        """Test is_processed works when using Redis set name directly."""
        from ares.core.models import SharedRedTeamState

        state = SharedRedTeamState(operation_id="op-test")
        state.processed_bloodhound_domains.add("contoso.local")

        # Check using Redis name (without processed_ prefix)
        assert state.is_processed("bloodhound_domains", "contoso.local") is True
        assert state.is_processed("bloodhound_domains", "fabrikam.local") is False


# ============================================================================
# Persistence Tracking Backend Tests
# ============================================================================


class TestPersistenceTrackingBackend:
    """Tests for golden tickets, backdoors, ACL chains, and gMSA accounts backend."""

    @pytest.fixture
    def mock_redis(self):
        """Create a mock Redis client."""
        mock = MagicMock()
        mock.rpush = AsyncMock(return_value=1)
        mock.lrange = AsyncMock(return_value=[])
        mock.expire = AsyncMock()
        mock.pipeline = MagicMock()
        mock.pipeline.return_value.delete = MagicMock()
        mock.pipeline.return_value.rpush = MagicMock()
        mock.pipeline.return_value.expire = MagicMock()
        mock.pipeline.return_value.execute = AsyncMock()
        return mock

    @pytest.fixture
    def backend(self, mock_redis):
        """Create a backend instance with mocked Redis."""
        return RedisStateBackend(mock_redis, "op-test-123")

    @pytest.mark.asyncio
    async def test_add_golden_ticket(self, backend, mock_redis):
        """Test adding a golden ticket."""
        ticket = {
            "domain": "contoso.local",
            "ticket_path": "Administrator.ccache",
            "status": "success",
            "created_at": "2026-02-15T12:00:00+00:00",
        }

        result = await backend.add_golden_ticket(ticket)

        assert result is True
        mock_redis.rpush.assert_called_once()
        call_args = mock_redis.rpush.call_args
        assert call_args[0][0] == "ares:op:op-test-123:golden_tickets"
        # Verify JSON was serialized
        stored_data = json.loads(call_args[0][1])
        assert stored_data["domain"] == "contoso.local"
        assert stored_data["status"] == "success"

    @pytest.mark.asyncio
    async def test_get_golden_tickets(self, backend, mock_redis):
        """Test getting golden tickets."""
        mock_redis.lrange.return_value = [
            json.dumps({"domain": "contoso.local", "status": "success"}),
            json.dumps({"domain": "fabrikam.local", "status": "failed_no_dc"}),
        ]

        tickets = await backend.get_golden_tickets()

        assert len(tickets) == 2
        assert tickets[0]["domain"] == "contoso.local"
        assert tickets[1]["status"] == "failed_no_dc"

    @pytest.mark.asyncio
    async def test_add_adminsd_backdoor(self, backend, mock_redis):
        """Test adding an AdminSD holder backdoor."""
        result = await backend.add_adminsd_backdoor("contoso.local:svc_backup")

        assert result is True
        mock_redis.rpush.assert_called_once()
        call_args = mock_redis.rpush.call_args
        assert call_args[0][0] == "ares:op:op-test-123:adminsd_backdoors"
        assert call_args[0][1] == "contoso.local:svc_backup"

    @pytest.mark.asyncio
    async def test_get_adminsd_backdoors(self, backend, mock_redis):
        """Test getting AdminSD holder backdoors."""
        mock_redis.lrange.return_value = [
            "contoso.local:svc_backup",
            "fabrikam.local:admin",
        ]

        backdoors = await backend.get_adminsd_backdoors()

        assert len(backdoors) == 2
        assert "contoso.local:svc_backup" in backdoors
        assert "fabrikam.local:admin" in backdoors

    @pytest.mark.asyncio
    async def test_add_acl_chain(self, backend, mock_redis):
        """Test adding an ACL chain."""
        chain = {
            "chain_id": "chain-001",
            "steps": ["WriteOwner", "WriteDacl", "GenericAll"],
            "goal": "DCSync",
            "domain": "contoso.local",
        }

        result = await backend.add_acl_chain(chain)

        assert result is True
        mock_redis.rpush.assert_called_once()
        call_args = mock_redis.rpush.call_args
        assert call_args[0][0] == "ares:op:op-test-123:acl_chains"
        stored_data = json.loads(call_args[0][1])
        assert stored_data["chain_id"] == "chain-001"

    @pytest.mark.asyncio
    async def test_get_acl_chains(self, backend, mock_redis):
        """Test getting ACL chains."""
        mock_redis.lrange.return_value = [
            json.dumps({"chain_id": "chain-001", "goal": "DCSync"}),
            json.dumps({"chain_id": "chain-002", "goal": "Shadow Credentials"}),
        ]

        chains = await backend.get_acl_chains()

        assert len(chains) == 2
        assert chains[0]["chain_id"] == "chain-001"
        assert chains[1]["goal"] == "Shadow Credentials"

    @pytest.mark.asyncio
    async def test_add_gmsa_account(self, backend, mock_redis):
        """Test adding a gMSA account."""
        gmsa = {
            "account": "gMSA_SQL$",
            "domain": "contoso.local",
            "principals_allowed": "SQL Servers",
            "discovered_by": "recon-agent",
        }

        result = await backend.add_gmsa_account(gmsa)

        assert result is True
        mock_redis.rpush.assert_called_once()
        call_args = mock_redis.rpush.call_args
        assert call_args[0][0] == "ares:op:op-test-123:gmsa_accounts"
        stored_data = json.loads(call_args[0][1])
        assert stored_data["account"] == "gMSA_SQL$"

    @pytest.mark.asyncio
    async def test_get_gmsa_accounts(self, backend, mock_redis):
        """Test getting gMSA accounts."""
        mock_redis.lrange.return_value = [
            json.dumps({"account": "gMSA_SQL$", "domain": "contoso.local"}),
            json.dumps({"account": "gMSA_WEB$", "domain": "contoso.local"}),
        ]

        gmsas = await backend.get_gmsa_accounts()

        assert len(gmsas) == 2
        assert gmsas[0]["account"] == "gMSA_SQL$"
        assert gmsas[1]["account"] == "gMSA_WEB$"

    @pytest.mark.asyncio
    async def test_update_acl_chain(self, backend, mock_redis):
        """Test updating an ACL chain."""
        existing_chain = json.dumps({"chain_id": "chain-001", "progress": 0})
        mock_redis.lrange.return_value = [existing_chain]

        updated_chain = {"chain_id": "chain-001", "progress": 50, "is_complete": False}
        result = await backend.update_acl_chain("chain-001", updated_chain)

        assert result is True
        # Pipeline should have been used for atomic update
        mock_redis.pipeline.assert_called()


# ============================================================================
# SharedRedTeamState Persistence Tracking Helper Tests
# ============================================================================


class TestSharedStatePersistenceTrackingHelpers:
    """Tests for add_golden_ticket, add_adminsd_backdoor, add_acl_chain, add_gmsa_account."""

    def test_add_golden_ticket_appends_to_list(self):
        """Test add_golden_ticket appends to in-memory list."""
        from ares.core.models import SharedRedTeamState

        state = SharedRedTeamState(operation_id="op-test")
        ticket = {
            "domain": "contoso.local",
            "ticket_path": "Administrator.ccache",
            "status": "success",
        }

        result = state.add_golden_ticket(ticket)

        assert result is True
        assert len(state.golden_tickets) == 1
        assert state.golden_tickets[0]["domain"] == "contoso.local"

    def test_add_golden_ticket_allows_multiple_domains(self):
        """Test add_golden_ticket allows different domains."""
        from ares.core.models import SharedRedTeamState

        state = SharedRedTeamState(operation_id="op-test")
        state.add_golden_ticket({"domain": "contoso.local", "status": "success"})
        state.add_golden_ticket({"domain": "fabrikam.local", "status": "success"})

        assert len(state.golden_tickets) == 2

    def test_add_golden_ticket_rejects_duplicate_success(self):
        """Test add_golden_ticket rejects duplicate success for same domain."""
        from ares.core.models import SharedRedTeamState

        state = SharedRedTeamState(operation_id="op-test")
        state.add_golden_ticket({"domain": "contoso.local", "status": "success"})
        result = state.add_golden_ticket({"domain": "contoso.local", "status": "success"})

        assert result is False
        assert len(state.golden_tickets) == 1

    def test_add_adminsd_backdoor_appends_to_list(self):
        """Test add_adminsd_backdoor appends to in-memory list."""
        from ares.core.models import SharedRedTeamState

        state = SharedRedTeamState(operation_id="op-test")
        result = state.add_adminsd_backdoor("contoso.local:svc_backup")

        assert result is True
        assert "contoso.local:svc_backup" in state.adminsd_holder_backdoors

    def test_add_adminsd_backdoor_rejects_duplicate(self):
        """Test add_adminsd_backdoor rejects duplicate."""
        from ares.core.models import SharedRedTeamState

        state = SharedRedTeamState(operation_id="op-test")
        state.add_adminsd_backdoor("contoso.local:svc_backup")
        result = state.add_adminsd_backdoor("contoso.local:svc_backup")

        assert result is False
        assert len(state.adminsd_holder_backdoors) == 1

    def test_add_acl_chain_appends_to_list(self):
        """Test add_acl_chain appends to in-memory list."""
        from ares.core.models import SharedRedTeamState

        state = SharedRedTeamState(operation_id="op-test")
        chain = {"chain_id": "chain-001", "goal": "DCSync"}

        result = state.add_acl_chain(chain)

        assert result is True
        assert len(state.acl_chains) == 1
        assert state.acl_chains[0]["chain_id"] == "chain-001"

    def test_add_acl_chain_rejects_duplicate_id(self):
        """Test add_acl_chain rejects duplicate chain_id."""
        from ares.core.models import SharedRedTeamState

        state = SharedRedTeamState(operation_id="op-test")
        state.add_acl_chain({"chain_id": "chain-001", "goal": "DCSync"})
        result = state.add_acl_chain({"chain_id": "chain-001", "goal": "Other"})

        assert result is False
        assert len(state.acl_chains) == 1

    def test_update_acl_chain(self):
        """Test update_acl_chain updates existing chain."""
        from ares.core.models import SharedRedTeamState

        state = SharedRedTeamState(operation_id="op-test")
        state.add_acl_chain({"chain_id": "chain-001", "progress": 0})

        result = state.update_acl_chain("chain-001", {"chain_id": "chain-001", "progress": 75})

        assert result is True
        assert state.acl_chains[0]["progress"] == 75

    def test_update_acl_chain_not_found(self):
        """Test update_acl_chain returns False for non-existent chain."""
        from ares.core.models import SharedRedTeamState

        state = SharedRedTeamState(operation_id="op-test")
        result = state.update_acl_chain("chain-999", {"chain_id": "chain-999", "progress": 50})

        assert result is False

    def test_add_gmsa_account_appends_to_list(self):
        """Test add_gmsa_account appends to in-memory list."""
        from ares.core.models import SharedRedTeamState

        state = SharedRedTeamState(operation_id="op-test")
        gmsa = {"account": "gMSA_SQL$", "domain": "contoso.local"}

        result = state.add_gmsa_account(gmsa)

        assert result is True
        assert len(state.gmsa_accounts) == 1
        assert state.gmsa_accounts[0]["account"] == "gMSA_SQL$"

    def test_add_gmsa_account_rejects_duplicate(self):
        """Test add_gmsa_account rejects duplicate account (case-insensitive)."""
        from ares.core.models import SharedRedTeamState

        state = SharedRedTeamState(operation_id="op-test")
        state.add_gmsa_account({"account": "gMSA_SQL$", "domain": "contoso.local"})
        result = state.add_gmsa_account({"account": "GMSA_SQL$", "domain": "contoso.local"})

        assert result is False
        assert len(state.gmsa_accounts) == 1

    @pytest.mark.asyncio
    async def test_add_golden_ticket_persists_to_backend(self):
        """Test add_golden_ticket creates async task to persist to backend."""
        import asyncio

        from ares.core.models import SharedRedTeamState

        state = SharedRedTeamState(operation_id="op-test")

        mock_backend = MagicMock()
        mock_backend.add_golden_ticket = AsyncMock()
        state.set_backend(mock_backend)

        ticket = {"domain": "contoso.local", "status": "success"}
        state.add_golden_ticket(ticket)

        await asyncio.sleep(0.01)

        mock_backend.add_golden_ticket.assert_called_once_with(ticket)

    @pytest.mark.asyncio
    async def test_load_persistence_tracking_from_backend(self):
        """Test loading persistence tracking data from backend into memory."""
        from ares.core.models import SharedRedTeamState

        state = SharedRedTeamState(operation_id="op-test")

        mock_backend = AsyncMock()
        mock_backend.get_golden_tickets = AsyncMock(
            return_value=[{"domain": "contoso.local", "status": "success"}]
        )
        mock_backend.get_adminsd_backdoors = AsyncMock(return_value=["contoso.local:svc_backup"])
        mock_backend.get_acl_chains = AsyncMock(
            return_value=[{"chain_id": "chain-001", "goal": "DCSync"}]
        )
        mock_backend.get_gmsa_accounts = AsyncMock(
            return_value=[{"account": "gMSA_SQL$", "domain": "contoso.local"}]
        )

        state.set_backend(mock_backend)
        await state.load_persistence_tracking_from_backend()

        assert len(state.golden_tickets) == 1
        assert state.golden_tickets[0]["domain"] == "contoso.local"
        assert "contoso.local:svc_backup" in state.adminsd_holder_backdoors
        assert len(state.acl_chains) == 1
        assert len(state.gmsa_accounts) == 1

    @pytest.mark.asyncio
    async def test_load_persistence_tracking_without_backend(self):
        """Test load_persistence_tracking_from_backend is no-op without backend."""
        from ares.core.models import SharedRedTeamState

        state = SharedRedTeamState(operation_id="op-test")

        # Should not raise
        await state.load_persistence_tracking_from_backend()

        # Lists should remain empty
        assert len(state.golden_tickets) == 0
        assert len(state.gmsa_accounts) == 0


# ============================================================================
# MSSQL Enum Dispatch Tracking Tests
# ============================================================================


class TestMssqlEnumDispatchTracking:
    """Tests for MSSQL enum dispatch tracking backend."""

    @pytest.fixture
    def mock_redis(self):
        """Create a mock Redis client."""
        mock = MagicMock()
        mock.sadd = AsyncMock(return_value=1)
        mock.sismember = AsyncMock(return_value=0)
        mock.smembers = AsyncMock(return_value=set())
        mock.expire = AsyncMock()
        return mock

    @pytest.fixture
    def backend(self, mock_redis):
        """Create a backend instance with mocked Redis."""
        return RedisStateBackend(mock_redis, "op-test-123")

    @pytest.mark.asyncio
    async def test_add_mssql_enum_dispatched(self, backend, mock_redis):
        """Test adding MSSQL enum dispatch entry."""
        result = await backend.add_mssql_enum_dispatched(
            "mssql_enum:192.168.58.10:contoso.local\\sql_svc"
        )

        assert result is True
        mock_redis.sadd.assert_called_once()
        call_args = mock_redis.sadd.call_args
        assert call_args[0][0] == "ares:op:op-test-123:mssql_enum_dispatched"
        assert call_args[0][1] == "mssql_enum:192.168.58.10:contoso.local\\sql_svc"

    @pytest.mark.asyncio
    async def test_is_mssql_enum_dispatched_false(self, backend, mock_redis):
        """Test checking MSSQL enum not dispatched."""
        mock_redis.sismember.return_value = 0

        result = await backend.is_mssql_enum_dispatched(
            "mssql_enum:192.168.58.10:contoso.local\\sql_svc"
        )

        assert result is False

    @pytest.mark.asyncio
    async def test_is_mssql_enum_dispatched_true(self, backend, mock_redis):
        """Test checking MSSQL enum already dispatched."""
        mock_redis.sismember.return_value = 1

        result = await backend.is_mssql_enum_dispatched(
            "mssql_enum:192.168.58.10:contoso.local\\sql_svc"
        )

        assert result is True

    @pytest.mark.asyncio
    async def test_get_mssql_enum_dispatched(self, backend, mock_redis):
        """Test getting all MSSQL enum dispatch entries."""
        mock_redis.smembers.return_value = {
            "mssql_enum:192.168.58.10:contoso.local\\sql_svc",
            "mssql_enum:192.168.58.20:contoso.local\\admin",
        }

        result = await backend.get_mssql_enum_dispatched()

        assert len(result) == 2
        assert "mssql_enum:192.168.58.10:contoso.local\\sql_svc" in result
        assert "mssql_enum:192.168.58.20:contoso.local\\admin" in result


# ============================================================================
# Evidence Validation Redis Backing Tests
# ============================================================================


class TestEvidenceValidationRedis:
    """Tests for evidence validation Redis persistence."""

    def test_store_query_result_without_redis(self):
        """Test storing query result works without Redis."""
        from ares.core.evidence_validation import reset_evidence_validation, store_query_result

        reset_evidence_validation()

        query_id = store_query_result(
            query_type="query_loki_logs",
            query_string='{job="test"}',
            result_data=[{"message": "test log"}],
            result_count=1,
        )

        assert query_id == "q-0001"

    def test_serialize_deserialize_query_result(self):
        """Test query result serialization roundtrip."""
        from ares.core.evidence_validation import (
            StoredQueryResult,
            _deserialize_query_result,
            _serialize_query_result,
        )

        original = StoredQueryResult(
            query_id="q-0001",
            query_type="query_loki_logs",
            query_string='{job="test"}',
            timestamp=datetime(2026, 2, 15, 12, 0, 0, tzinfo=timezone.utc),
            result_data=[{"message": "test"}],
            result_count=1,
            extracted_values={"192.168.58.10", "admin"},
        )

        serialized = _serialize_query_result(original)
        deserialized = _deserialize_query_result(serialized)

        assert deserialized.query_id == original.query_id
        assert deserialized.query_type == original.query_type
        assert deserialized.result_count == original.result_count
        assert deserialized.extracted_values == original.extracted_values

    @pytest.mark.asyncio
    async def test_load_from_redis_empty(self):
        """Test loading from Redis when empty."""
        from ares.core.evidence_validation import (
            load_from_redis,
            reset_evidence_validation,
            set_redis_client,
        )

        reset_evidence_validation()

        # Mock Redis
        mock_redis = AsyncMock()
        mock_redis.zrange = AsyncMock(return_value=[])

        set_redis_client(mock_redis, "op-test")

        count = await load_from_redis()

        assert count == 0

    @pytest.mark.asyncio
    async def test_load_from_redis_with_data(self):
        """Test loading query results from Redis."""
        import ares.core.evidence_validation as ev_module

        ev_module.reset_evidence_validation()

        # Mock Redis with stored results
        mock_redis = AsyncMock()
        stored_data = json.dumps(
            {
                "query_id": "q-0005",
                "query_type": "query_loki_logs",
                "query_string": '{job="test"}',
                "timestamp": "2026-02-15T12:00:00+00:00",
                "result_data": [{"message": "test"}],
                "result_count": 1,
                "extracted_values": ["192.168.58.10"],
            }
        )
        mock_redis.zrange = AsyncMock(return_value=[stored_data])

        ev_module.set_redis_client(mock_redis, "op-test")

        count = await ev_module.load_from_redis()

        assert count == 1
        # Access via module to get the current deque (not the snapshot from import)
        assert len(ev_module._recent_results) == 1
        assert ev_module._recent_results[0].query_id == "q-0005"
