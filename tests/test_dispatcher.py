"""Unit tests for RedTeamDispatcher status helpers."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock

import pytest

from ares.core.dispatcher import RedTeamDispatcher
from ares.core.models import (
    Credential,
    Host,
    SharedRedTeamState,
    VulnerabilityInfo,
)


class FakeRedis:
    """Minimal async Redis stub for exploitation status tests."""

    def __init__(self, vuln_payloads: dict[bytes, str], exploit_payloads: dict[bytes, str]):
        self._vuln_payloads = vuln_payloads
        self._exploit_payloads = exploit_payloads

    async def scan_iter(self, pattern: str):
        if "vulns:" in pattern:
            for key in self._vuln_payloads:
                yield key
        else:
            for key in self._exploit_payloads:
                yield key

    async def get(self, key):
        return self._vuln_payloads.get(key) or self._exploit_payloads.get(key)


@pytest.mark.asyncio
async def test_get_exploitation_status_loads_redis_vulns():
    """Redis-stored vulnerabilities should be included in status."""
    dispatcher = RedTeamDispatcher()
    dispatcher._shared_state = SharedRedTeamState(operation_id="op-test-1")

    vuln_key = b"ares:operation:op-test-1:vulns:ADCS_ESC1_dc01"
    vuln_payload = json.dumps(
        {
            "type": "ADCS_ESC1",
            "target": "dc01",
            "details": {"template": "User"},
            "discovered_by": "recon",
            "queued_at": "2024-01-01T00:00:00+00:00",
        }
    )
    exploit_key = b"ares:operation:op-test-1:exploited:ADCS_ESC1_dc01"
    exploit_payload = json.dumps({"success": True})

    dispatcher._redis_client = FakeRedis(
        {vuln_key: vuln_payload},
        {exploit_key: exploit_payload},
    )

    status = await dispatcher.get_exploitation_status()

    assert status["total_discovered"] == 1
    assert status["total_succeeded"] == 1
    assert status["pending"] == []
    assert status["succeeded"][0]["id"] == "ADCS_ESC1_dc01"


class TestMssqlScanning:
    """Tests for MSSQL auto-detection and scanning functionality."""

    @pytest.mark.asyncio
    async def test_scan_hosts_for_mssql_no_hosts(self):
        """Test scanning when no hosts exist."""
        dispatcher = RedTeamDispatcher()
        dispatcher._shared_state = SharedRedTeamState(operation_id="op-test-mssql-1")

        queued = await dispatcher.scan_hosts_for_mssql()

        assert queued == 0

    @pytest.mark.asyncio
    async def test_scan_hosts_for_mssql_no_mssql_services(self):
        """Test scanning when hosts exist but none have MSSQL."""
        dispatcher = RedTeamDispatcher()
        dispatcher._shared_state = SharedRedTeamState(operation_id="op-test-mssql-2")
        dispatcher._shared_state.all_hosts.append(
            Host(ip="192.168.56.10", hostname="web01", services=["http/80", "https/443"])
        )

        queued = await dispatcher.scan_hosts_for_mssql()

        assert queued == 0

    @pytest.mark.asyncio
    async def test_scan_hosts_for_mssql_detects_mssql_port(self):
        """Test scanning detects MSSQL by port 1433."""
        dispatcher = RedTeamDispatcher()
        dispatcher._shared_state = SharedRedTeamState(operation_id="op-test-mssql-3")
        dispatcher._shared_state.all_hosts.append(
            Host(ip="192.168.56.20", hostname="sql01", services=["tcp/1433"])
        )
        dispatcher.queue_vulnerability = AsyncMock()

        queued = await dispatcher.scan_hosts_for_mssql()

        assert queued == 1
        dispatcher.queue_vulnerability.assert_awaited_once()
        call_kwargs = dispatcher.queue_vulnerability.call_args.kwargs
        assert call_kwargs["vuln_type"] == "mssql_linked_server"
        assert call_kwargs["target"] == "192.168.56.20"

    @pytest.mark.asyncio
    async def test_scan_hosts_for_mssql_detects_mssql_service_name(self):
        """Test scanning detects MSSQL by service name."""
        dispatcher = RedTeamDispatcher()
        dispatcher._shared_state = SharedRedTeamState(operation_id="op-test-mssql-4")
        dispatcher._shared_state.all_hosts.append(
            Host(ip="192.168.56.30", hostname="db01", services=["ms-sql-s"])
        )
        dispatcher.queue_vulnerability = AsyncMock()

        queued = await dispatcher.scan_hosts_for_mssql()

        assert queued == 1

    @pytest.mark.asyncio
    async def test_scan_hosts_for_mssql_skips_already_queued(self):
        """Test scanning skips hosts that already have MSSQL vuln queued."""
        dispatcher = RedTeamDispatcher()
        dispatcher._shared_state = SharedRedTeamState(operation_id="op-test-mssql-5")
        dispatcher._shared_state.all_hosts.append(
            Host(ip="192.168.56.40", hostname="sql02", services=["mssql/1433"])
        )
        # Add existing vulnerability for this host
        dispatcher._shared_state.discovered_vulnerabilities["mssql_linked_server_192.168.56.40"] = (
            VulnerabilityInfo(
                vuln_id="mssql_linked_server_192.168.56.40",
                vuln_type="mssql_linked_server",
                target="192.168.56.40",
                details={},
                discovered_by="recon",
            )
        )
        dispatcher.queue_vulnerability = AsyncMock()

        queued = await dispatcher.scan_hosts_for_mssql()

        assert queued == 0
        dispatcher.queue_vulnerability.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_scan_hosts_for_mssql_multiple_hosts(self):
        """Test scanning multiple hosts with some having MSSQL."""
        dispatcher = RedTeamDispatcher()
        dispatcher._shared_state = SharedRedTeamState(operation_id="op-test-mssql-6")
        dispatcher._shared_state.all_hosts.extend(
            [
                Host(ip="192.168.56.50", hostname="web01", services=["http/80"]),
                Host(ip="192.168.56.51", hostname="sql01", services=["mssql/1433"]),
                Host(ip="192.168.56.52", hostname="sql02", services=["sqlserver/1433"]),
                Host(ip="192.168.56.53", hostname="dc01", services=["ldap/389"]),
            ]
        )
        dispatcher.queue_vulnerability = AsyncMock()

        queued = await dispatcher.scan_hosts_for_mssql()

        assert queued == 2
        assert dispatcher.queue_vulnerability.await_count == 2

    @pytest.mark.asyncio
    async def test_scan_hosts_includes_sql_credentials(self):
        """Test scanning includes SQL-related credentials in vulnerability details."""
        dispatcher = RedTeamDispatcher()
        dispatcher._shared_state = SharedRedTeamState(operation_id="op-test-mssql-7")
        dispatcher._shared_state.all_hosts.append(
            Host(ip="192.168.56.60", hostname="sql03", services=["mssql/1433"])
        )
        # Add SQL service account credential
        dispatcher._shared_state.all_credentials.append(
            Credential(
                username="sql_svc",
                password="SqlP@ss123",  # pragma: allowlist secret
                domain="contoso.local",
                source="kerberoast",
            )
        )
        dispatcher.queue_vulnerability = AsyncMock()

        queued = await dispatcher.scan_hosts_for_mssql()

        assert queued == 1
        call_kwargs = dispatcher.queue_vulnerability.call_args.kwargs
        assert "available_credentials" in call_kwargs["details"]
        creds = call_kwargs["details"]["available_credentials"]
        assert any(c["username"] == "sql_svc" for c in creds)

    def test_find_sql_credentials_prioritizes_sql_accounts(self):
        """Test that SQL accounts are prioritized in credential list."""
        dispatcher = RedTeamDispatcher()
        dispatcher._shared_state = SharedRedTeamState(operation_id="op-test-mssql-8")
        dispatcher._shared_state.all_credentials.extend(
            [
                Credential(
                    username="regular_user",
                    password="UserP@ss",  # pragma: allowlist secret
                    domain="contoso.local",
                    source="secretsdump",
                ),
                Credential(
                    username="sql_admin",
                    password="SqlAdminP@ss",  # pragma: allowlist secret
                    domain="contoso.local",
                    source="kerberoast",
                ),
                Credential(
                    username="domain_admin",
                    password="DAP@ss",  # pragma: allowlist secret
                    domain="contoso.local",
                    source="dcsync",
                ),
            ]
        )

        creds = dispatcher._find_sql_credentials()

        # SQL accounts should be prioritized (sorted to top)
        assert len(creds) == 3
        # First credential should be the SQL account
        assert creds[0]["username"] == "sql_admin"
        assert creds[0]["is_sql_account"] == "True"

    def test_find_sql_credentials_dedupes(self):
        """Test that duplicate credentials are deduplicated."""
        dispatcher = RedTeamDispatcher()
        dispatcher._shared_state = SharedRedTeamState(operation_id="op-test-mssql-9")
        dispatcher._shared_state.all_credentials.extend(
            [
                Credential(
                    username="user1",
                    password="pass1",  # pragma: allowlist secret
                    domain="contoso.local",
                    source="source1",
                ),
                Credential(
                    username="user1",
                    password="pass1",  # pragma: allowlist secret
                    domain="contoso.local",
                    source="source2",  # same user, different source
                ),
            ]
        )

        creds = dispatcher._find_sql_credentials()

        assert len(creds) == 1

    def test_find_sql_credentials_limits_to_five(self):
        """Test that at most 5 credentials are returned."""
        dispatcher = RedTeamDispatcher()
        dispatcher._shared_state = SharedRedTeamState(operation_id="op-test-mssql-10")
        for i in range(10):
            dispatcher._shared_state.all_credentials.append(
                Credential(
                    username=f"user{i}",
                    password=f"pass{i}",  # pragma: allowlist secret
                    domain="contoso.local",
                    source="test",
                )
            )

        creds = dispatcher._find_sql_credentials()

        assert len(creds) == 5
