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
            Host(ip="192.168.58.10", hostname="web01", services=["http/80", "https/443"])
        )

        queued = await dispatcher.scan_hosts_for_mssql()

        assert queued == 0

    @pytest.mark.asyncio
    async def test_scan_hosts_for_mssql_detects_mssql_port(self):
        """Test scanning detects MSSQL by port 1433 and queues both vulnerabilities."""
        dispatcher = RedTeamDispatcher()
        dispatcher._shared_state = SharedRedTeamState(operation_id="op-test-mssql-3")
        dispatcher._shared_state.all_hosts.append(
            Host(ip="192.168.58.20", hostname="sql01", services=["tcp/1433"])
        )
        # Add SQL credentials (required for queueing MSSQL vulnerabilities)
        dispatcher._shared_state.all_credentials.append(
            Credential(
                username="sa",
                password="Password123!",  # pragma: allowlist secret
                domain="",
            )
        )
        dispatcher.queue_vulnerability = AsyncMock()

        queued = await dispatcher.scan_hosts_for_mssql()

        # Should queue 2 vulnerabilities: linked_server + impersonation
        assert queued == 2
        assert dispatcher.queue_vulnerability.await_count == 2

        # Verify both vulnerability types were queued
        call_args_list = [call.kwargs for call in dispatcher.queue_vulnerability.call_args_list]
        vuln_types = [call["vuln_type"] for call in call_args_list]
        assert "mssql_linked_server" in vuln_types
        assert "mssql_impersonation" in vuln_types

        # Verify both target the same host
        for call in call_args_list:
            assert call["target"] == "192.168.58.20"

    @pytest.mark.asyncio
    async def test_scan_hosts_for_mssql_detects_mssql_service_name(self):
        """Test scanning detects MSSQL by service name and queues both vulnerabilities."""
        dispatcher = RedTeamDispatcher()
        dispatcher._shared_state = SharedRedTeamState(operation_id="op-test-mssql-4")
        dispatcher._shared_state.all_hosts.append(
            Host(ip="192.168.58.30", hostname="db01", services=["ms-sql-s"])
        )
        # Add SQL credentials (required for queueing MSSQL vulnerabilities)
        dispatcher._shared_state.all_credentials.append(
            Credential(
                username="sa",
                password="Password123!",  # pragma: allowlist secret
                domain="",
            )
        )
        dispatcher.queue_vulnerability = AsyncMock()

        queued = await dispatcher.scan_hosts_for_mssql()

        # Should queue 2 vulnerabilities: linked_server + impersonation
        assert queued == 2

    @pytest.mark.asyncio
    async def test_scan_hosts_for_mssql_skips_already_queued(self):
        """Test scanning skips hosts that already have MSSQL vuln queued."""
        dispatcher = RedTeamDispatcher()
        dispatcher._shared_state = SharedRedTeamState(operation_id="op-test-mssql-5")
        dispatcher._shared_state.all_hosts.append(
            Host(ip="192.168.58.40", hostname="sql02", services=["mssql/1433"])
        )
        # Add existing vulnerability for this host
        dispatcher._shared_state.discovered_vulnerabilities["mssql_linked_server_192.168.58.40"] = (
            VulnerabilityInfo(
                vuln_id="mssql_linked_server_192.168.58.40",
                vuln_type="mssql_linked_server",
                target="192.168.58.40",
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
                Host(ip="192.168.58.50", hostname="web01", services=["http/80"]),
                Host(ip="192.168.58.51", hostname="sql01", services=["mssql/1433"]),
                Host(ip="192.168.58.52", hostname="sql02", services=["sqlserver/1433"]),
                Host(ip="192.168.58.53", hostname="dc01", services=["ldap/389"]),
            ]
        )
        # Add SQL credentials (required for queueing MSSQL vulnerabilities)
        dispatcher._shared_state.all_credentials.append(
            Credential(
                username="sa",
                password="Password123!",  # pragma: allowlist secret
                domain="",
            )
        )
        dispatcher.queue_vulnerability = AsyncMock()

        queued = await dispatcher.scan_hosts_for_mssql()

        # 2 MSSQL hosts x 2 vuln types each = 4 vulnerabilities
        assert queued == 4
        assert dispatcher.queue_vulnerability.await_count == 4

    @pytest.mark.asyncio
    async def test_scan_hosts_includes_sql_credentials(self):
        """Test scanning includes SQL-related credentials in vulnerability details."""
        dispatcher = RedTeamDispatcher()
        dispatcher._shared_state = SharedRedTeamState(operation_id="op-test-mssql-7")
        dispatcher._shared_state.all_hosts.append(
            Host(ip="192.168.58.60", hostname="sql03", services=["mssql/1433"])
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

        # Should queue 2 vulnerabilities (linked_server + impersonation)
        assert queued == 2
        assert dispatcher.queue_vulnerability.await_count == 2

        # Both should include credentials
        for call in dispatcher.queue_vulnerability.call_args_list:
            call_kwargs = call.kwargs
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


class TestFindDomainControllerIp:
    """Tests for DC IP detection to prevent substring matching bugs."""

    def test_does_not_match_3389_as_389(self):
        """Port 3389 (RDP) should NOT match as port 389 (LDAP)."""
        dispatcher = RedTeamDispatcher()
        dispatcher._shared_state = SharedRedTeamState(operation_id="op-test-dc-1")
        # sql01 has RDP (3389) but NOT LDAP (389)
        dispatcher._shared_state.all_hosts.append(
            Host(
                ip="10.1.2.146",
                hostname="sql01.contoso.local",
                services=["1433/tcp ms-sql-s", "3389/tcp ms-wbt-server", "445/tcp smb"],
            )
        )
        # dc01 is the actual DC with Kerberos services
        dispatcher._shared_state.all_hosts.append(
            Host(
                ip="10.1.2.240",
                hostname="dc01.contoso.local",
                services=["88/tcp kerberos-sec", "389/tcp ldap", "53/tcp domain"],
            )
        )

        dc_ip = dispatcher._find_domain_controller_ip("contoso.local")

        # Should return dc01 (the actual DC), NOT sql01
        assert dc_ip == "10.1.2.240"

    def test_matches_exact_port_389(self):
        """Port 389 should be detected as LDAP."""
        dispatcher = RedTeamDispatcher()
        dispatcher._shared_state = SharedRedTeamState(operation_id="op-test-dc-2")
        dispatcher._shared_state.all_hosts.append(
            Host(
                ip="192.168.58.1",
                hostname="dc01.contoso.local",
                services=["389/tcp ldap", "88/tcp kerberos"],
            )
        )

        dc_ip = dispatcher._find_domain_controller_ip("contoso.local")

        assert dc_ip == "192.168.58.1"

    def test_matches_kerberos_service_name(self):
        """Service containing 'kerberos' should match."""
        dispatcher = RedTeamDispatcher()
        dispatcher._shared_state = SharedRedTeamState(operation_id="op-test-dc-3")
        dispatcher._shared_state.all_hosts.append(
            Host(
                ip="192.168.58.2",
                hostname="dc02.contoso.local",
                services=["88/tcp kerberos-sec"],
            )
        )

        dc_ip = dispatcher._find_domain_controller_ip("contoso.local")

        assert dc_ip == "192.168.58.2"

    def test_matches_ldap_service_name(self):
        """Service containing 'ldap' should match."""
        dispatcher = RedTeamDispatcher()
        dispatcher._shared_state = SharedRedTeamState(operation_id="op-test-dc-4")
        dispatcher._shared_state.all_hosts.append(
            Host(
                ip="192.168.58.3",
                hostname="dc03.contoso.local",
                services=["389/tcp ldap"],
            )
        )

        dc_ip = dispatcher._find_domain_controller_ip("contoso.local")

        assert dc_ip == "192.168.58.3"

    def test_host_without_dc_services_not_selected(self):
        """Host with only RDP/SMB should not be selected as DC."""
        dispatcher = RedTeamDispatcher()
        dispatcher._shared_state = SharedRedTeamState(operation_id="op-test-dc-5")
        dispatcher._shared_state.all_hosts.append(
            Host(
                ip="192.168.58.4",
                hostname="workstation.contoso.local",
                services=["3389/tcp ms-wbt-server", "445/tcp smb", "135/tcp msrpc"],
            )
        )

        dc_ip = dispatcher._find_domain_controller_ip("contoso.local")

        # Should return empty - no DC found
        assert dc_ip == ""

    def test_prefers_host_with_dc_in_hostname(self):
        """Host with 'dc' in hostname should be preferred."""
        dispatcher = RedTeamDispatcher()
        dispatcher._shared_state = SharedRedTeamState(operation_id="op-test-dc-6")
        dispatcher._shared_state.all_hosts.append(
            Host(
                ip="192.168.58.5",
                hostname="app-srv01.contoso.local",
                services=["88/tcp kerberos", "389/tcp ldap"],
            )
        )
        dispatcher._shared_state.all_hosts.append(
            Host(
                ip="192.168.58.6",
                hostname="dc01.contoso.local",
                services=["445/tcp smb"],  # Even without DC services
            )
        )

        dc_ip = dispatcher._find_domain_controller_ip("contoso.local")

        # Should prefer dc01 due to hostname
        assert dc_ip == "192.168.58.6"

    def test_multi_domain_scenario(self):
        """Multi-domain scenario - ensure correct DC detection.

        The critical bug was that sql01 (with port 3389) was incorrectly
        detected as a DC because '389/tcp' matched as substring of '3389/tcp'.
        """
        dispatcher = RedTeamDispatcher()
        dispatcher._shared_state = SharedRedTeamState(operation_id="op-test-dc-multi")
        # Simulate multi-domain environment - sql01 first (has 3389 RDP, NOT a DC)
        dispatcher._shared_state.all_hosts.extend(
            [
                Host(
                    ip="10.1.2.146",
                    hostname="sql01.corp.contoso.local",
                    services=[
                        "1433/tcp ms-sql-s",
                        "139/tcp netbios-ssn",
                        "80/tcp http",
                        "135/tcp msrpc",
                        "445/tcp smb",
                        "3389/tcp ms-wbt-server",
                    ],
                ),
                Host(
                    ip="10.1.2.240",
                    hostname="dc01.corp.contoso.local",
                    services=[
                        "139/tcp netbios-ssn",
                        "88/tcp kerberos-sec",
                        "135/tcp msrpc",
                        "445/tcp smb",
                        "3389/tcp ms-wbt-server",
                        "53/tcp domain",
                        "389/tcp ldap",
                    ],
                ),
                Host(
                    ip="10.1.2.183",
                    hostname="dc01.contoso.local",
                    services=[
                        "139/tcp netbios-ssn",
                        "88/tcp kerberos-sec",
                        "80/tcp http",
                        "135/tcp msrpc",
                        "3389/tcp ms-wbt-server",
                        "445/tcp smb",
                        "53/tcp domain",
                        "389/tcp ldap",
                    ],
                ),
            ]
        )

        # Test corp.contoso.local -> must be dc01.corp.contoso.local, NOT sql01
        # This is the critical test - sql01 was incorrectly selected before the fix
        corp_dc = dispatcher._find_domain_controller_ip("corp.contoso.local")
        assert corp_dc == "10.1.2.240", (
            f"Expected dc01.corp.contoso.local (10.1.2.240), got {corp_dc}"
        )
        assert corp_dc != "10.1.2.146", "BUG: sql01 selected - 3389 matched as 389!"
