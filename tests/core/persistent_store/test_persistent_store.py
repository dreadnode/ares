"""Tests for persistent data store.

These tests verify the core functionality of the persistent store without
requiring an actual PostgreSQL database (uses mocking).
"""

import hashlib
import uuid
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest

from ares.core.persistent_store.config import (
    PersistentStoreConfig,
    RetentionConfig,
    clear_persistent_store_config_cache,
    get_persistent_store_config,
)
from ares.core.persistent_store.models import (
    CredentialRecord,
    HashRecord,
    HostRecord,
    OperationRecord,
)


class TestPersistentStoreConfig:
    """Tests for persistent store configuration."""

    def setup_method(self):
        """Clear config cache before each test."""
        clear_persistent_store_config_cache()

    def teardown_method(self):
        """Clear config cache after each test."""
        clear_persistent_store_config_cache()

    def test_config_defaults(self):
        """Test default configuration values."""
        config = PersistentStoreConfig()

        assert config.database_url == ""
        assert config.pool_min_size == 2
        assert config.pool_max_size == 10
        assert config.offload_mode == "async"
        assert config.offload_on_completion is True
        assert config.is_enabled is False

    def test_config_is_enabled(self):
        """Test is_enabled property."""
        config = PersistentStoreConfig()
        assert config.is_enabled is False

        config.database_url = "postgresql://localhost/ares"
        assert config.is_enabled is True

    def test_retention_config_defaults(self):
        """Test default retention configuration."""
        retention = RetentionConfig()

        assert retention.operations_default_days == 365
        assert retention.operations_with_da_days == 730
        assert retention.credentials_anonymize_after_days == 90
        assert retention.artifacts_max_size_bytes == 10 * 1024 * 1024

    @patch.dict(
        "os.environ",
        {
            "ARES_DATABASE_URL": "postgresql://localhost/test",
            "ARES_DB_POOL_MIN_SIZE": "5",
            "ARES_DB_POOL_MAX_SIZE": "20",
            "ARES_DB_OFFLOAD_MODE": "sync",
            "ARES_DB_RETENTION_OPERATIONS_DAYS": "180",
        },
    )
    def test_config_from_environment(self):
        """Test configuration loading from environment variables."""
        config = get_persistent_store_config()

        assert config.database_url == "postgresql://localhost/test"
        assert config.pool_min_size == 5
        assert config.pool_max_size == 20
        assert config.offload_mode == "sync"
        assert config.retention.operations_default_days == 180
        assert config.is_enabled is True


class TestSQLAlchemyModels:
    """Tests for SQLAlchemy model definitions."""

    def test_operation_record_creation(self):
        """Test creating an OperationRecord."""
        op = OperationRecord(
            operation_id="op-20260312-abc123",
            target_domain="contoso.local",
            target_ip="192.168.58.10",
            started_at=datetime.now(timezone.utc),
            has_domain_admin=True,
            has_golden_ticket=False,  # Explicitly set since default isn't applied until flush
        )

        assert op.operation_id == "op-20260312-abc123"
        assert op.target_domain == "contoso.local"
        assert op.has_domain_admin is True
        assert op.has_golden_ticket is False

    def test_credential_record_creation(self):
        """Test creating a CredentialRecord."""
        cred = CredentialRecord(
            username="administrator",
            domain="contoso.local",
            password_hash=hashlib.sha256(b"test").hexdigest()[:16],
            is_admin=True,
            source="secretsdump",
            attack_step=2,
        )

        assert cred.username == "administrator"
        assert cred.domain == "contoso.local"
        assert cred.is_admin is True
        assert cred.attack_step == 2

    def test_hash_record_creation(self):
        """Test creating a HashRecord."""
        hash_rec = HashRecord(
            username="svc_backup",
            domain="contoso.local",
            hash_type="ntlm",
            hash_value_prefix="aad3b435b51404eeaad3b435b51404ee:",
            source="secretsdump",
        )

        assert hash_rec.username == "svc_backup"
        assert hash_rec.hash_type == "ntlm"

    def test_host_record_creation(self):
        """Test creating a HostRecord."""
        host = HostRecord(
            ip="192.168.58.10",
            hostname="dc01",
            os="Windows Server 2019",
            is_dc=True,
            roles=["domain_controller"],
            services=["smb", "ldap", "kerberos"],
        )

        assert host.ip == "192.168.58.10"
        assert host.is_dc is True
        assert "domain_controller" in host.roles


class TestPersistentStore:
    """Tests for PersistentStore class."""

    def test_store_initialization_disabled(self):
        """Test store initialization when disabled."""
        from ares.core.persistent_store.store import PersistentStore

        config = PersistentStoreConfig()  # No database URL
        store = PersistentStore(config)

        assert store.is_enabled is False

    def test_store_initialization_enabled(self):
        """Test store initialization when enabled."""
        from ares.core.persistent_store.store import PersistentStore

        config = PersistentStoreConfig(database_url="postgresql://localhost/test")
        store = PersistentStore(config)

        assert store.is_enabled is True

    @pytest.mark.asyncio
    async def test_offload_operation_when_disabled(self):
        """Test offload_operation returns False when store is disabled."""
        from ares.core.persistent_store.store import PersistentStore

        config = PersistentStoreConfig()  # No database URL
        store = PersistentStore(config)

        # Create a mock state
        mock_state = MagicMock()
        mock_state.operation_id = "op-test-123"

        result = await store.offload_operation(mock_state)
        assert result is False


class TestHistoricalQueryService:
    """Tests for HistoricalQueryService class."""

    def test_service_initialization_disabled(self):
        """Test service initialization when disabled."""
        from ares.core.persistent_store.queries import HistoricalQueryService

        config = PersistentStoreConfig()  # No database URL
        service = HistoricalQueryService(config)

        assert service.is_enabled is False

    @pytest.mark.asyncio
    async def test_list_operations_when_disabled(self):
        """Test list_operations returns empty when service is disabled."""
        from ares.core.persistent_store.queries import HistoricalQueryService

        config = PersistentStoreConfig()  # No database URL
        service = HistoricalQueryService(config)

        result = await service.list_operations()
        assert result == []


class TestOperationSummary:
    """Tests for OperationSummary dataclass."""

    def test_duration_str_running(self):
        """Test duration_str for running operation."""
        from ares.core.persistent_store.queries import OperationSummary

        summary = OperationSummary(
            id=uuid.uuid4(),
            operation_id="op-test",
            target_domain="contoso.local",
            target_ip="192.168.58.10",
            started_at=datetime.now(timezone.utc),
            completed_at=None,
            has_domain_admin=False,
            has_golden_ticket=False,
            credential_count=10,
            hash_count=5,
            host_count=3,
            vulnerability_count=2,
            exploited_vulnerability_count=1,
            duration_seconds=None,
        )

        assert summary.duration_str == "running"

    def test_duration_str_completed(self):
        """Test duration_str for completed operation."""
        from ares.core.persistent_store.queries import OperationSummary

        summary = OperationSummary(
            id=uuid.uuid4(),
            operation_id="op-test",
            target_domain="contoso.local",
            target_ip="192.168.58.10",
            started_at=datetime.now(timezone.utc),
            completed_at=datetime.now(timezone.utc),
            has_domain_admin=True,
            has_golden_ticket=False,
            credential_count=10,
            hash_count=5,
            host_count=3,
            vulnerability_count=2,
            exploited_vulnerability_count=1,
            duration_seconds=3725,  # 1h 2m 5s
        )

        assert summary.duration_str == "1h 2m 5s"

    def test_duration_str_minutes(self):
        """Test duration_str for operations lasting minutes."""
        from ares.core.persistent_store.queries import OperationSummary

        summary = OperationSummary(
            id=uuid.uuid4(),
            operation_id="op-test",
            target_domain="contoso.local",
            target_ip=None,
            started_at=datetime.now(timezone.utc),
            completed_at=datetime.now(timezone.utc),
            has_domain_admin=False,
            has_golden_ticket=False,
            credential_count=0,
            hash_count=0,
            host_count=0,
            vulnerability_count=0,
            exploited_vulnerability_count=0,
            duration_seconds=125,  # 2m 5s
        )

        assert summary.duration_str == "2m 5s"

    def test_duration_str_seconds(self):
        """Test duration_str for short operations."""
        from ares.core.persistent_store.queries import OperationSummary

        summary = OperationSummary(
            id=uuid.uuid4(),
            operation_id="op-test",
            target_domain="contoso.local",
            target_ip=None,
            started_at=datetime.now(timezone.utc),
            completed_at=datetime.now(timezone.utc),
            has_domain_admin=False,
            has_golden_ticket=False,
            credential_count=0,
            hash_count=0,
            host_count=0,
            vulnerability_count=0,
            exploited_vulnerability_count=0,
            duration_seconds=45,
        )

        assert summary.duration_str == "45s"


class TestHelperFunctions:
    """Tests for helper functions in the store module."""

    def test_is_ip_valid(self):
        """Test _is_ip with valid IP addresses."""
        from ares.core.persistent_store.store import _is_ip

        assert _is_ip("192.168.58.10") is True
        assert _is_ip("192.168.58.20") is True
        assert _is_ip("255.255.255.255") is True

    def test_is_ip_invalid(self):
        """Test _is_ip with invalid inputs."""
        from ares.core.persistent_store.store import _is_ip

        assert _is_ip("dc01.contoso.local") is False
        assert _is_ip("contoso.local") is False
        assert _is_ip("") is False
        assert _is_ip("192.168.1") is False
        assert _is_ip("256.1.1.1") is False
