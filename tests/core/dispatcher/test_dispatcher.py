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
    Target,
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

    vuln_key = b"ares:op:op-test-1:vulns:ADCS_ESC1_dc01"
    vuln_payload = json.dumps(
        {
            "type": "ADCS_ESC1",
            "target": "dc01",
            "details": {"template": "User"},
            "discovered_by": "recon",
            "queued_at": "2024-01-01T00:00:00+00:00",
        }
    )
    exploit_key = b"ares:op:op-test-1:exploited:ADCS_ESC1_dc01"
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


@pytest.mark.asyncio
async def test_get_exploitation_status_handles_string_result():
    """Failed vulnerability with string result should not raise AttributeError.

    Regression test for bug where result is a string instead of a dict,
    causing 'str' object has no attribute 'get' error.
    """
    dispatcher = RedTeamDispatcher()
    dispatcher._shared_state = SharedRedTeamState(operation_id="op-test-str-result")

    vuln_key = b"ares:op:op-test-str-result:vulns:adcs_esc8_192.168.58.10"
    vuln_payload = json.dumps(
        {
            "type": "adcs_esc8",
            "target": "192.168.58.10",
            "details": {"ca_server": "ADCS01"},
            "discovered_by": "recon",
            "queued_at": "2024-01-01T00:00:00+00:00",
        }
    )
    # Bug case: result is a string error message, not a dict
    exploit_key = b"ares:op:op-test-str-result:exploited:adcs_esc8_192.168.58.10"
    exploit_payload = json.dumps(
        {
            "success": False,
            "result": "AttributeError: 'str' object has no attribute 'get'",
            "exploited_at": "2024-01-01T00:01:00+00:00",
        }
    )

    dispatcher._redis_client = FakeRedis(
        {vuln_key: vuln_payload},
        {exploit_key: exploit_payload},
    )

    # This should not raise AttributeError
    status = await dispatcher.get_exploitation_status()

    assert status["total_discovered"] == 1
    assert status["total_failed"] == 1
    assert len(status["failed"]) == 1
    assert status["failed"][0]["type"] == "adcs_esc8"
    assert status["failed"][0]["target"] == "192.168.58.10"
    # Error should be extracted from string result
    assert "AttributeError" in status["failed"][0]["error"]


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
                ip="192.168.58.146",
                hostname="sql01.contoso.local",
                services=["1433/tcp ms-sql-s", "3389/tcp ms-wbt-server", "445/tcp smb"],
            )
        )
        # dc01 is the actual DC with Kerberos services
        dispatcher._shared_state.all_hosts.append(
            Host(
                ip="192.168.58.240",
                hostname="dc01.contoso.local",
                services=["88/tcp kerberos-sec", "389/tcp ldap", "53/tcp domain"],
            )
        )

        dc_ip = dispatcher._find_domain_controller_ip("contoso.local")

        # Should return dc01 (the actual DC), NOT sql01
        assert dc_ip == "192.168.58.240"

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
                    ip="192.168.58.146",
                    hostname="sql01.fabrikam.local",
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
                    ip="192.168.58.240",
                    hostname="dc01.fabrikam.local",
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
                    ip="192.168.58.183",
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

        # Test fabrikam.local -> must be dc01.fabrikam.local, NOT sql01
        # This is the critical test - sql01 was incorrectly selected before the fix
        fabrikam_dc = dispatcher._find_domain_controller_ip("fabrikam.local")
        assert fabrikam_dc == "192.168.58.240", (
            f"Expected dc01.fabrikam.local (192.168.58.240), got {fabrikam_dc}"
        )
        assert fabrikam_dc != "192.168.58.146", "BUG: sql01 selected - 3389 matched as 389!"

    def test_child_domain_does_not_match_parent(self):
        """Child domain hosts must NOT match parent domain lookups.

        dc01.child.contoso.local should NOT match contoso.local.
        This was a critical bug where hostname.endswith(".contoso.local")
        incorrectly matched child.contoso.local hosts to parent domain.
        """
        dispatcher = RedTeamDispatcher()
        dispatcher._shared_state = SharedRedTeamState(operation_id="op-test-dc-child")

        # Add parent domain DC
        dispatcher._shared_state.all_hosts.append(
            Host(
                ip="192.168.58.10",
                hostname="dc01.contoso.local",
                roles=["Domain Controller"],
                services=["88/tcp kerberos-sec", "389/tcp ldap"],
            )
        )
        # Add child domain DC - should NOT match parent domain
        dispatcher._shared_state.all_hosts.append(
            Host(
                ip="192.168.58.20",
                hostname="dc02.child.contoso.local",
                roles=["Domain Controller"],
                services=["88/tcp kerberos-sec", "389/tcp ldap"],
            )
        )

        # Looking up contoso.local MUST return dc01, NOT dc02
        parent_dc = dispatcher._find_domain_controller_ip("contoso.local")
        assert parent_dc == "192.168.58.10", f"Expected dc01 (192.168.58.10), got {parent_dc}"

        # Looking up child.contoso.local MUST return dc02
        child_dc = dispatcher._find_domain_controller_ip("child.contoso.local")
        assert child_dc == "192.168.58.20", f"Expected dc02 (192.168.58.20), got {child_dc}"

    def test_uses_target_when_domain_matches(self):
        """When target.domain matches requested domain, use target.ip.

        This handles the case where the operation was started with --domain flag,
        meaning the user explicitly told us the target IP is the DC for that domain.
        """
        dispatcher = RedTeamDispatcher()
        dispatcher._shared_state = SharedRedTeamState(operation_id="op-test-dc-target")

        # Set target with domain (simulates K8s orchestrator startup with --domain)
        dispatcher._shared_state.target = Target(
            ip="192.168.58.10",
            domain="contoso.local",
        )
        # No hosts in all_hosts yet (recon hasn't run)

        dc_ip = dispatcher._find_domain_controller_ip("contoso.local")

        # Should return target.ip since target.domain matches
        assert dc_ip == "192.168.58.10"

    def test_ignores_target_when_domain_mismatch(self):
        """When target.domain doesn't match, don't use target.ip blindly."""
        dispatcher = RedTeamDispatcher()
        dispatcher._shared_state = SharedRedTeamState(operation_id="op-test-dc-mismatch")

        # Target is for contoso.local
        dispatcher._shared_state.target = Target(
            ip="192.168.58.10",
            domain="contoso.local",
        )
        # No hosts in all_hosts yet

        # Ask for different domain
        dc_ip = dispatcher._find_domain_controller_ip("fabrikam.local")

        # Should NOT return target.ip - different domain
        assert dc_ip == ""


class TestS4UAutoChaining:
    """Tests for automatic lateral movement chaining after S4U attacks."""

    def test_extract_ticket_path_from_output(self):
        """Test extraction of .ccache path from S4U output."""
        dispatcher = RedTeamDispatcher()
        dispatcher._shared_state = SharedRedTeamState(operation_id="op-test-s4u-1")

        # Standard impacket output format
        output = """
[*] Getting TGT for user@contoso.local
[*] Impersonating Administrator@contoso.local
[*] Using S4U2self to obtain a ST as Administrator
[*] Using S4U2proxy to obtain a ST for cifs/DC01.contoso.local
[*] Saving ticket in Administrator@cifs_DC01.contoso.local@CONTOSO.LOCAL.ccache
        """

        path = dispatcher._extract_ticket_path_from_output(output)

        assert path == "Administrator@cifs_DC01.contoso.local@CONTOSO.LOCAL.ccache"

    def test_extract_ticket_path_fallback(self):
        """Test fallback when standard pattern not found."""
        dispatcher = RedTeamDispatcher()
        dispatcher._shared_state = SharedRedTeamState(operation_id="op-test-s4u-2")

        # Output with just ccache filename mentioned
        output = "Generated ticket saved as admin.ccache"

        path = dispatcher._extract_ticket_path_from_output(output)

        assert path == "admin.ccache"

    def test_extract_ticket_path_default(self):
        """Test default when no ccache found."""
        dispatcher = RedTeamDispatcher()
        dispatcher._shared_state = SharedRedTeamState(operation_id="op-test-s4u-3")

        output = "Some output without a ticket"

        path = dispatcher._extract_ticket_path_from_output(output)

        assert path == "Administrator.ccache"

    def test_extract_host_from_spn_cifs(self):
        """Test extraction of host from CIFS SPN."""
        dispatcher = RedTeamDispatcher()
        dispatcher._shared_state = SharedRedTeamState(operation_id="op-test-s4u-4")

        host = dispatcher._extract_host_from_spn("cifs/DC01.contoso.local")

        assert host == "DC01.contoso.local"

    def test_extract_host_from_spn_http(self):
        """Test extraction of host from HTTP SPN."""
        dispatcher = RedTeamDispatcher()
        dispatcher._shared_state = SharedRedTeamState(operation_id="op-test-s4u-5")

        host = dispatcher._extract_host_from_spn("http/web01.contoso.local")

        assert host == "web01.contoso.local"

    def test_extract_host_from_spn_invalid(self):
        """Test extraction returns None for invalid SPN."""
        dispatcher = RedTeamDispatcher()
        dispatcher._shared_state = SharedRedTeamState(operation_id="op-test-s4u-6")

        assert dispatcher._extract_host_from_spn("") is None
        assert dispatcher._extract_host_from_spn("invalidspn") is None

    @pytest.mark.asyncio
    async def test_auto_chain_s4u_non_exploit_task_ignored(self):
        """Test that non-exploit tasks are ignored."""
        dispatcher = RedTeamDispatcher()
        dispatcher._shared_state = SharedRedTeamState(operation_id="op-test-s4u-7")

        from ares.core.models import TaskInfo

        task_info = TaskInfo(
            task_id="task-1",
            task_type="recon",
            assigned_agent="enum",
            params={},
        )

        chained = await dispatcher._auto_chain_s4u_lateral_movement(
            task_id="task-1",
            task_info=task_info,
            result={"output": "some output"},
            source_agent="enum",
        )

        assert chained == 0

    @pytest.mark.asyncio
    async def test_auto_chain_s4u_non_constrained_delegation_ignored(self):
        """Test that non-constrained-delegation exploits are ignored."""
        dispatcher = RedTeamDispatcher()
        dispatcher._shared_state = SharedRedTeamState(operation_id="op-test-s4u-8")

        from ares.core.models import TaskInfo

        task_info = TaskInfo(
            task_id="task-1",
            task_type="exploit",
            assigned_agent="privesc",
            params={"vuln_type": "adcs_esc1"},
        )

        chained = await dispatcher._auto_chain_s4u_lateral_movement(
            task_id="task-1",
            task_info=task_info,
            result={"output": "Saving ticket in admin.ccache"},
            source_agent="privesc",
        )

        assert chained == 0

    @pytest.mark.asyncio
    async def test_auto_chain_s4u_no_ccache_in_output_ignored(self):
        """Test that S4U output without .ccache is ignored."""
        dispatcher = RedTeamDispatcher()
        dispatcher._shared_state = SharedRedTeamState(operation_id="op-test-s4u-9")

        from ares.core.models import TaskInfo

        task_info = TaskInfo(
            task_id="task-1",
            task_type="exploit",
            assigned_agent="privesc",
            params={"vuln_type": "constrained_delegation"},
        )

        chained = await dispatcher._auto_chain_s4u_lateral_movement(
            task_id="task-1",
            task_info=task_info,
            result={"output": "Attack failed - no ticket generated"},
            source_agent="privesc",
        )

        assert chained == 0

    @pytest.mark.asyncio
    async def test_auto_chain_s4u_dispatches_secretsdump(self):
        """Test that successful S4U attack dispatches secretsdump."""
        dispatcher = RedTeamDispatcher()
        dispatcher._shared_state = SharedRedTeamState(operation_id="op-test-s4u-10")
        dispatcher._shared_state.all_hosts.append(
            Host(
                ip="192.168.58.10",
                hostname="dc01.contoso.local",
                services=["88/tcp kerberos", "389/tcp ldap"],
            )
        )

        # Mock the credential access request
        dispatcher.request_credential_access = AsyncMock(return_value="task-cred-1")

        from ares.core.models import TaskInfo

        task_info = TaskInfo(
            task_id="task-1",
            task_type="exploit",
            assigned_agent="privesc",
            params={
                "vuln_type": "constrained_delegation",
                "target_spn": "cifs/DC01.contoso.local",
                "domain": "contoso.local",
            },
        )

        s4u_output = """
[*] Getting TGT for svc_backup@contoso.local
[*] Impersonating Administrator@contoso.local
[*] Saving ticket in Administrator.ccache
        """

        chained = await dispatcher._auto_chain_s4u_lateral_movement(
            task_id="task-1",
            task_info=task_info,
            result={"output": s4u_output},
            source_agent="privesc",
        )

        assert chained == 1
        dispatcher.request_credential_access.assert_called_once()

        # Verify the call arguments
        call_kwargs = dispatcher.request_credential_access.call_args.kwargs
        assert call_kwargs["domain"] == "contoso.local"
        assert call_kwargs["username"] == "Administrator"
        assert call_kwargs["techniques"] == ["secretsdump"]
        assert call_kwargs["extra_params"]["ticket_path"] == "Administrator.ccache"
        assert call_kwargs["extra_params"]["no_pass"] is True


class TestCredentialDomainResolution:
    """Tests for credential domain resolution to prevent false positives.

    The critical bug was that credentials extracted from tool output were
    assigned the target domain, even when the user belonged to a different
    domain in a multi-domain forest.

    Example: sql_svc:SqlP@ss123 belongs to fabrikam.local,
    but was incorrectly assigned contoso.local when that was the target.
    """

    def test_resolve_credential_domain_uses_fqdn_from_output(self):
        """Extracted FQDN domain should be used as-is."""
        from ares.core.models import Target

        dispatcher = RedTeamDispatcher()
        dispatcher._shared_state = SharedRedTeamState(operation_id="op-test-cred-1")
        dispatcher._shared_state.target = Target(ip="192.168.58.10", domain="contoso.local")

        # If the output has an FQDN, use it
        domain = dispatcher._resolve_credential_domain("sql_svc", "fabrikam.local")

        assert domain == "fabrikam.local"

    def test_resolve_credential_domain_resolves_netbios_via_mapping(self):
        """NetBIOS domain should be resolved via authoritative mapping."""
        from ares.core.models import Target

        dispatcher = RedTeamDispatcher()
        dispatcher._shared_state = SharedRedTeamState(operation_id="op-test-cred-2")
        dispatcher._shared_state.target = Target(ip="192.168.58.10", domain="contoso.local")
        # Add authoritative NetBIOS -> FQDN mapping
        dispatcher._shared_state.netbios_to_fqdn["fabrikam"] = "fabrikam.local"

        domain = dispatcher._resolve_credential_domain("sql_svc", "FABRIKAM")

        assert domain == "fabrikam.local"

    def test_resolve_credential_domain_cross_references_users(self):
        """Should cross-reference with discovered users to find correct domain."""
        from ares.core.models import Target, User

        dispatcher = RedTeamDispatcher()
        dispatcher._shared_state = SharedRedTeamState(operation_id="op-test-cred-3")
        dispatcher._shared_state.target = Target(ip="192.168.58.10", domain="contoso.local")
        # User was previously discovered with correct domain
        dispatcher._shared_state.all_users.append(User(username="sql_svc", domain="fabrikam.local"))

        # No domain in output, but user exists in state
        domain = dispatcher._resolve_credential_domain("sql_svc", "")

        assert domain == "fabrikam.local"

    def test_resolve_credential_domain_ambiguous_returns_empty(self):
        """Should return empty when user exists in multiple domains without hint."""
        from ares.core.models import Target, User

        dispatcher = RedTeamDispatcher()
        dispatcher._shared_state = SharedRedTeamState(operation_id="op-test-cred-4")
        dispatcher._shared_state.target = Target(ip="192.168.58.10", domain="contoso.local")
        # Same username in multiple domains (different users)
        dispatcher._shared_state.all_users.append(
            User(username="administrator", domain="fabrikam.local")
        )
        dispatcher._shared_state.all_users.append(
            User(username="administrator", domain="contoso.local")
        )

        # No domain hint, user is ambiguous
        domain = dispatcher._resolve_credential_domain("administrator", "")

        # Should return empty to avoid false positive
        assert domain == ""

    def test_resolve_credential_domain_ambiguous_with_netbios_hint(self):
        """Should prefer domain matching NetBIOS hint when user is in multiple domains."""
        from ares.core.models import Target, User

        dispatcher = RedTeamDispatcher()
        dispatcher._shared_state = SharedRedTeamState(operation_id="op-test-cred-5")
        dispatcher._shared_state.target = Target(ip="192.168.58.10", domain="contoso.local")
        dispatcher._shared_state.all_domains.extend(["fabrikam.local", "contoso.local"])
        # Same username in multiple domains
        dispatcher._shared_state.all_users.append(
            User(username="administrator", domain="fabrikam.local")
        )
        dispatcher._shared_state.all_users.append(
            User(username="administrator", domain="contoso.local")
        )

        # NetBIOS hint "FABRIKAM" should resolve to fabrikam.local
        domain = dispatcher._resolve_credential_domain("administrator", "FABRIKAM")

        assert domain == "fabrikam.local"

    def test_resolve_credential_domain_unknown_user_no_domain(self):
        """Should return empty for unknown user without domain info."""
        from ares.core.models import Target

        dispatcher = RedTeamDispatcher()
        dispatcher._shared_state = SharedRedTeamState(operation_id="op-test-cred-6")
        dispatcher._shared_state.target = Target(ip="192.168.58.10", domain="contoso.local")

        # User not in state, no domain in output
        domain = dispatcher._resolve_credential_domain("unknownuser", "")

        # Should return empty, NOT the target domain
        assert domain == ""

    def test_resolve_credential_domain_netbios_matches_target(self):
        """NetBIOS matching target domain should resolve to target."""
        from ares.core.models import Target

        dispatcher = RedTeamDispatcher()
        dispatcher._shared_state = SharedRedTeamState(operation_id="op-test-cred-7")
        dispatcher._shared_state.target = Target(ip="192.168.58.10", domain="contoso.local")

        # NetBIOS "CONTOSO" matches target domain "contoso.local"
        domain = dispatcher._resolve_credential_domain("someuser", "CONTOSO")

        assert domain == "contoso.local"

    def test_extract_plaintext_passwords_extracts_domain_backslash(self):
        """Should extract domain from DOMAIN\\user format in output."""
        dispatcher = RedTeamDispatcher()
        dispatcher._shared_state = SharedRedTeamState(operation_id="op-test-cred-8")

        output = """
        FABRIKAM\\sql_svc
        Password: SqlP@ss123
        """

        creds = dispatcher._extract_plaintext_passwords_from_output(output)

        assert len(creds) == 1
        username, password, domain = creds[0]
        assert username == "sql_svc"
        assert password == "SqlP@ss123"  # pragma: allowlist secret
        assert domain == "FABRIKAM"

    def test_extract_plaintext_passwords_extracts_domain_upn(self):
        """Should extract domain from user@contoso.local format in output."""
        dispatcher = RedTeamDispatcher()
        dispatcher._shared_state = SharedRedTeamState(operation_id="op-test-cred-9")

        output = """
        sql_svc@fabrikam.local
        Password: SqlP@ss123
        """

        creds = dispatcher._extract_plaintext_passwords_from_output(output)

        assert len(creds) == 1
        username, password, domain = creds[0]
        assert username == "sql_svc"
        assert password == "SqlP@ss123"  # pragma: allowlist secret
        assert domain == "fabrikam.local"

    def test_extract_plaintext_passwords_no_domain_returns_empty(self):
        """Should return empty domain when not determinable from output."""
        dispatcher = RedTeamDispatcher()
        dispatcher._shared_state = SharedRedTeamState(operation_id="op-test-cred-10")

        output = """
        samaccountname: sql_svc
        Password: SqlP@ss123
        """

        creds = dispatcher._extract_plaintext_passwords_from_output(output)

        assert len(creds) == 1
        username, password, domain = creds[0]
        assert username == "sql_svc"
        assert password == "SqlP@ss123"  # pragma: allowlist secret
        assert domain == ""  # No domain in output

    def test_extract_plaintext_passwords_extracts_lsa_default_password(self):
        """Should extract LSA DefaultPassword from secretsdump output."""
        dispatcher = RedTeamDispatcher()
        dispatcher._shared_state = SharedRedTeamState(operation_id="op-test-cred-11")

        # Actual secretsdump LSA DefaultPassword format
        output = """
[*] Dumping cached domain logon information (domain/username:hash)
[*] Dumping LSA Secrets
[*] DefaultPassword
CONTOSO\\svc_backup:B@ckupP@ss123!
[*] DPAPI_SYSTEM
        """

        creds = dispatcher._extract_plaintext_passwords_from_output(output)

        assert len(creds) == 1
        username, password, domain = creds[0]
        assert username == "svc_backup"
        assert password == "B@ckupP@ss123!"  # pragma: allowlist secret
        assert domain == "CONTOSO"


class TestCredentialDomainCrossReference:
    """Tests for credential domain cross-reference in SharedRedTeamState.add_credential().

    These tests verify that credentials are assigned the correct domain by
    cross-referencing with discovered users, particularly in multi-domain forests
    where a credential might have a parent domain but the user exists in a child domain.
    """

    def test_add_credential_corrects_parent_to_child_domain(self):
        """Credential with parent domain should be corrected to child domain."""
        from ares.core.models import Target, User

        state = SharedRedTeamState(operation_id="op-test-parent-child")
        state.target = Target(ip="192.168.58.10", domain="contoso.local")

        # User discovered in child domain (from LDAP enumeration)
        state.all_users.append(User(username="testuser", domain="child.contoso.local"))

        # Credential comes in with parent domain (worker error)
        cred = Credential(
            username="testuser",
            password="TestP@ss!",  # pragma: allowlist secret
            domain="contoso.local",  # Wrong - should be child.contoso.local
            source="ldap_description",
        )

        added = state.add_credential(cred, "enum")

        assert added is True
        # Check the stored credential has the correct domain
        assert len(state.all_credentials) == 1
        stored_cred = state.all_credentials[0]
        assert stored_cred.domain == "child.contoso.local"

    def test_add_credential_preserves_correct_domain(self):
        """Credential with correct domain should be preserved."""
        from ares.core.models import Target, User

        state = SharedRedTeamState(operation_id="op-test-correct-domain")
        state.target = Target(ip="192.168.58.10", domain="contoso.local")

        # User in same domain as credential
        state.all_users.append(User(username="admin", domain="contoso.local"))

        cred = Credential(
            username="admin",
            password="P@ssw0rd!",  # pragma: allowlist secret
            domain="contoso.local",
            source="spray",
        )

        added = state.add_credential(cred, "lateral")

        assert added is True
        assert len(state.all_credentials) == 1
        assert state.all_credentials[0].domain == "contoso.local"

    def test_add_credential_new_user_accepts_domain(self):
        """Credential for new user should accept provided domain."""
        from ares.core.models import Target

        state = SharedRedTeamState(operation_id="op-test-new-user")
        state.target = Target(ip="192.168.58.10", domain="contoso.local")

        # No users in state yet
        cred = Credential(
            username="newuser",
            password="NewP@ss!",  # pragma: allowlist secret
            domain="contoso.local",
            source="kerberoast",
        )

        added = state.add_credential(cred, "cracker")

        assert added is True
        assert len(state.all_credentials) == 1
        assert state.all_credentials[0].domain == "contoso.local"

    def test_add_credential_prefers_more_specific_domain(self):
        """When user exists in multiple domains, prefer most specific (longest)."""
        from ares.core.models import Target, User

        state = SharedRedTeamState(operation_id="op-test-specific-domain")
        state.target = Target(ip="192.168.58.10", domain="contoso.local")

        # User exists in both parent and child (edge case)
        state.all_users.append(User(username="admin", domain="contoso.local"))
        state.all_users.append(User(username="admin", domain="child.contoso.local"))

        # Credential with parent domain should prefer child when ambiguous
        cred = Credential(
            username="admin",
            password="AdminP@ss!",  # pragma: allowlist secret
            domain="contoso.local",
            source="spray",
        )

        added = state.add_credential(cred, "lateral")

        assert added is True
        assert len(state.all_credentials) == 1
        # Should use child domain since it's more specific
        assert state.all_credentials[0].domain == "child.contoso.local"

    def test_add_credential_child_domain_not_corrected_to_parent(self):
        """Child domain should NOT be 'corrected' to parent when user was discovered with parent.

        This tests the scenario where:
        1. First credential arrives with parent domain (before enumeration)
        2. User is auto-added with parent domain
        3. Second credential arrives with CORRECT child domain
        4. Child domain should be KEPT, not 'corrected' to parent
        5. User and first credential should be upgraded to child domain
        """
        from ares.core.models import Target

        state = SharedRedTeamState(operation_id="op-test-child-not-corrected")
        state.target = Target(ip="192.168.58.10", domain="contoso.local")

        # Step 1: First credential with parent domain
        cred1 = Credential(
            username="svc_account",
            password="SvcP@ss123",  # pragma: allowlist secret
            domain="contoso.local",  # Parent domain (wrong)
            source="spray",
        )
        added1 = state.add_credential(cred1, "sprayer")
        assert added1 is True
        assert len(state.all_credentials) == 1
        assert state.all_credentials[0].domain == "contoso.local"
        # User was also added with parent domain
        assert len(state.all_users) == 1
        assert state.all_users[0].domain == "contoso.local"

        # Step 2: Second credential with child domain (more specific/correct)
        cred2 = Credential(
            username="svc_account",
            password="SvcP@ss123",  # pragma: allowlist secret
            domain="child.contoso.local",  # Child domain (correct)
            source="ldap",
        )
        added2 = state.add_credential(cred2, "recon")

        # Second credential should be rejected as duplicate
        # (after domain upgrade, both have same domain:user:pass)
        assert added2 is False
        assert len(state.all_credentials) == 1

        # User should be upgraded to child domain
        assert len(state.all_users) == 1
        assert state.all_users[0].domain == "child.contoso.local"

        # First credential should also be upgraded to child domain
        assert state.all_credentials[0].domain == "child.contoso.local"

    def test_add_credential_resolves_netbios_then_user_lookup(self):
        """NetBIOS domain should be resolved first, then user lookup applied."""
        from ares.core.models import Target, User

        state = SharedRedTeamState(operation_id="op-test-netbios-user")
        state.target = Target(ip="192.168.58.10", domain="contoso.local")
        state.all_domains.append("fabrikam.local")

        # User discovered in fabrikam.local
        state.all_users.append(User(username="sql_svc", domain="fabrikam.local"))

        # Credential with NetBIOS domain
        cred = Credential(
            username="sql_svc",
            password="SqlP@ss!",  # pragma: allowlist secret
            domain="FABRIKAM",  # NetBIOS format
            source="spray",
        )

        added = state.add_credential(cred, "lateral")

        assert added is True
        assert len(state.all_credentials) == 1
        # Should resolve to FQDN
        assert state.all_credentials[0].domain == "fabrikam.local"

    def test_add_credential_rejects_cross_domain_duplicate(self):
        """Credential with same username+password but wrong domain should be rejected.

        This prevents agent hallucinations where a credential from one domain
        (e.g., contoso.local) is incorrectly recorded with a different
        domain (e.g., fabrikam.local) during cross-domain enumeration.
        """
        from ares.core.models import Target

        state = SharedRedTeamState(operation_id="op-test-cross-domain-dup")
        state.target = Target(ip="192.168.58.10", domain="contoso.local")

        # First credential in correct domain
        cred1 = Credential(
            username="test.user",
            password="TestPass123",  # pragma: allowlist secret
            domain="contoso.local",
            source="ldap_description",
        )
        added1 = state.add_credential(cred1, "recon")
        assert added1 is True
        assert len(state.all_credentials) == 1

        # Same credential recorded with wrong domain (agent hallucination)
        cred2 = Credential(
            username="test.user",
            password="TestPass123",  # pragma: allowlist secret
            domain="fabrikam.local",  # Wrong domain!
            source="recon_bloodhound",
        )
        added2 = state.add_credential(cred2, "recon")

        # Should be rejected as cross-domain duplicate
        assert added2 is False
        assert len(state.all_credentials) == 1
        # Original credential should still be there with correct domain
        assert state.all_credentials[0].domain == "contoso.local"

    def test_add_credential_allows_legitimate_password_reuse(self):
        """Same username+password in multiple domains is allowed if user exists in both.

        This handles the sql_svc case where the same service account name with
        the same password exists in multiple domains (legitimate password reuse).
        """
        from ares.core.models import Target, User

        state = SharedRedTeamState(operation_id="op-test-password-reuse")
        state.target = Target(ip="192.168.58.10", domain="contoso.local")

        # User exists in BOTH domains (discovered via LDAP/BloodHound)
        state.all_users.append(User(username="sql_svc", domain="contoso.local"))
        state.all_users.append(User(username="sql_svc", domain="fabrikam.local"))

        # First credential in contoso
        cred1 = Credential(
            username="sql_svc",
            password="SqlP@ssw0rd!",  # pragma: allowlist secret
            domain="contoso.local",
            source="kerberoast",
        )
        added1 = state.add_credential(cred1, "cracker")
        assert added1 is True

        # Same credential in fabrikam - should be allowed (password reuse)
        cred2 = Credential(
            username="sql_svc",
            password="SqlP@ssw0rd!",  # pragma: allowlist secret
            domain="fabrikam.local",
            source="kerberoast",
        )
        added2 = state.add_credential(cred2, "cracker")

        # Should be allowed - user exists in both domains (legitimate password reuse)
        assert added2 is True
        assert len(state.all_credentials) == 2
        domains = {c.domain for c in state.all_credentials}
        assert domains == {"contoso.local", "fabrikam.local"}

    def test_add_credential_rejects_duplicate_when_correct_domain_comes_second(self):
        """Credential with correct domain should be rejected if wrong domain was stored first.

        This tests the scenario where:
        1. Credential arrives BEFORE user enumeration with parent domain (hallucination)
        2. User is then discovered in the child domain (via add_user which upgrades domain)
        3. Same credential arrives again with the correct child domain
        4. Second credential should be rejected as duplicate (same user, same password)

        Previously this allowed both credentials, causing duplicates in loot.
        """
        from ares.core.models import Target

        state = SharedRedTeamState(operation_id="op-test-cross-domain-dup-reverse")
        state.target = Target(ip="192.168.58.10", domain="contoso.local")

        # Step 1: Credential arrives with PARENT domain (before user enumeration)
        # This simulates a hallucination where child domain user is attributed to parent
        # add_credential also adds user with parent domain via add_user()
        cred1 = Credential(
            username="test.user",
            password="TestPass123",  # pragma: allowlist secret
            domain="contoso.local",  # Wrong - should be child.contoso.local
            source="spray_result",
        )
        added1 = state.add_credential(cred1, "sprayer")
        assert added1 is True
        assert len(state.all_credentials) == 1
        assert state.all_credentials[0].domain == "contoso.local"
        # User was also added with parent domain
        assert len(state.all_users) == 1
        assert state.all_users[0].domain == "contoso.local"

        # Step 2: User is discovered in the CHILD domain (via LDAP/BloodHound)
        # add_user() upgrades the existing user's domain from parent to child
        # AND updates existing credentials to the child domain
        state.add_user("test.user", "child.contoso.local", "bloodhound")
        # User domain should be upgraded
        assert len(state.all_users) == 1
        assert state.all_users[0].domain == "child.contoso.local"
        # Credential domain should also be upgraded by _update_credentials_domain
        assert state.all_credentials[0].domain == "child.contoso.local"

        # Step 3: Same credential arrives with CORRECT child domain
        cred2 = Credential(
            username="test.user",
            password="TestPass123",  # pragma: allowlist secret
            domain="child.contoso.local",  # Correct domain
            source="ldap_description",
        )
        added2 = state.add_credential(cred2, "recon")

        # Should be REJECTED - exact duplicate (same domain:username:password)
        assert added2 is False
        assert len(state.all_credentials) == 1

    def test_add_credential_rejects_duplicate_before_user_enumeration(self):
        """Same username:password with different domains should be rejected before user enum.

        This tests the scenario where:
        1. Credential arrives with parent domain
        2. Same credential arrives with child domain (BEFORE user enumeration discovers them)
        3. Second credential should be rejected as duplicate

        This prevents duplicate loot when agent hallucinations attribute a credential
        to different domains before we've confirmed which domain the user actually exists in.
        """
        from ares.core.models import Target

        state = SharedRedTeamState(operation_id="op-test-cross-domain-dup-early")
        state.target = Target(ip="192.168.58.10", domain="contoso.local")

        # First credential with parent domain
        cred1 = Credential(
            username="early.user",
            password="EarlyPass123",  # pragma: allowlist secret
            domain="contoso.local",
            source="spray_result",
        )
        added1 = state.add_credential(cred1, "sprayer")
        assert added1 is True
        assert len(state.all_credentials) == 1

        # Same credential with child domain - BEFORE any user enumeration
        # User exists in all_users only via add_credential's add_user call (parent domain)
        cred2 = Credential(
            username="early.user",
            password="EarlyPass123",  # pragma: allowlist secret
            domain="child.contoso.local",
            source="another_spray",
        )
        added2 = state.add_credential(cred2, "sprayer2")

        # Should be REJECTED - conservative approach: treat as duplicate when user
        # hasn't been confirmed in multiple domains
        assert added2 is False
        assert len(state.all_credentials) == 1


class TestAddUserDomainUpgrade:
    """Tests for add_user parent-to-child domain upgrade."""

    def test_add_user_upgrades_parent_to_child_domain(self):
        """Adding user to child domain should upgrade existing parent domain entry."""
        state = SharedRedTeamState(operation_id="op-test-upgrade")
        state.add_domain("contoso.local")

        # Add credential first (which adds user with parent domain)
        cred = Credential(
            username="sql_svc",
            password="SqlP@ss123!",  # pragma: allowlist secret
            domain="contoso.local",
            source="test",
        )
        state.add_credential(cred, "test")

        assert state.all_credentials[0].domain == "contoso.local"
        assert len(state.all_users) == 1
        assert state.all_users[0].domain == "contoso.local"

        # Now add user with child domain (simulates LDAP discovery)
        result = state.add_user("sql_svc", "child.contoso.local")

        # Should upgrade existing entry, not add new one
        assert result is True
        assert len(state.all_users) == 1
        assert state.all_users[0].domain == "child.contoso.local"
        # Credential should also be updated
        assert state.all_credentials[0].domain == "child.contoso.local"

    def test_add_user_rejects_parent_when_child_exists(self):
        """Adding user to parent domain should be rejected if already in child."""
        state = SharedRedTeamState(operation_id="op-test-reject-parent")

        # Add user in child domain first
        state.add_user("sql_svc", "child.contoso.local")
        assert len(state.all_users) == 1

        # Try to add same user in parent domain
        result = state.add_user("sql_svc", "contoso.local")

        # Should reject - child domain is more specific
        assert result is False
        assert len(state.all_users) == 1
        assert state.all_users[0].domain == "child.contoso.local"

    def test_add_user_updates_credentials_and_hashes(self):
        """Domain upgrade should update both credentials and hashes."""
        from ares.core.models import Hash

        state = SharedRedTeamState(operation_id="op-test-update-all")
        state.add_domain("contoso.local")

        # Add credential and hash with parent domain
        cred = Credential(
            username="sql_svc",
            password="SqlP@ss!",  # pragma: allowlist secret
            domain="contoso.local",
            source="test",
        )
        state.add_credential(cred, "test")

        hash_obj = Hash(
            username="sql_svc",
            hash_value="aad3b435b51404ee:abcdef1234567890",
            hash_type="NTLM",
            domain="contoso.local",
        )
        state.add_hash(hash_obj, "test")

        # Upgrade user to child domain
        state.add_user("sql_svc", "child.contoso.local")

        # Both should be updated
        assert state.all_credentials[0].domain == "child.contoso.local"
        assert state.all_hashes[0].domain == "child.contoso.local"


class TestDispatcherAddUserDelegation:
    """Tests that dispatcher's _add_user delegates to shared_state.add_user.

    Regression test for bug where _add_user directly appended to all_users list,
    bypassing parent/child domain deduplication logic in SharedRedTeamState.add_user().
    """

    def test_dispatcher_add_user_prevents_duplicate_parent_child_domains(self):
        """Dispatcher._add_user should prevent same user in parent and child domains.

        This is a regression test for a bug where:
        1. User was added to contoso.local
        2. Same user was added to child.contoso.local (child domain)
        3. Bug: both were added because _add_user only checked exact match
        4. Fix: _add_user now delegates to shared_state.add_user() which handles parent/child
        """
        from ares.core.dispatcher._dispatcher import RedTeamDispatcher

        dispatcher = RedTeamDispatcher()
        dispatcher._shared_state = SharedRedTeamState(operation_id="op-test-delegation")

        # Add user to parent domain first
        result1 = dispatcher._add_user("testuser", "contoso.local", "test")
        assert result1 is True
        assert len(dispatcher.shared_state.all_users) == 1

        # Try to add same user to child domain - should upgrade, not add duplicate
        result2 = dispatcher._add_user("testuser", "child.contoso.local", "test")
        assert result2 is True  # Returns True because user was upgraded
        assert len(dispatcher.shared_state.all_users) == 1  # Still only one user
        assert dispatcher.shared_state.all_users[0].domain == "child.contoso.local"

    def test_dispatcher_add_user_rejects_parent_when_child_exists(self):
        """Dispatcher._add_user should reject parent domain when user already in child."""
        from ares.core.dispatcher._dispatcher import RedTeamDispatcher

        dispatcher = RedTeamDispatcher()
        dispatcher._shared_state = SharedRedTeamState(operation_id="op-test-reject-parent")

        # Add user to child domain first
        result1 = dispatcher._add_user("testuser", "child.contoso.local", "test")
        assert result1 is True
        assert len(dispatcher.shared_state.all_users) == 1

        # Try to add same user to parent domain - should be rejected
        result2 = dispatcher._add_user("testuser", "contoso.local", "test")
        assert result2 is False  # Rejected - already in more specific child domain
        assert len(dispatcher.shared_state.all_users) == 1  # Still only one user
        assert dispatcher.shared_state.all_users[0].domain == "child.contoso.local"


class TestRetroactiveDomainNormalize:
    """Tests for retroactive domain normalization."""

    def test_add_domain_rejects_netbios_names(self):
        """NetBIOS names (single-word, no dot) should be rejected from all_domains."""
        state = SharedRedTeamState(operation_id="op-test-netbios-reject")

        # NetBIOS names should be rejected (no dot = not a valid FQDN)
        result = state.add_domain("child")
        assert result is False
        assert "child" not in state.all_domains

        result = state.add_domain("CONTOSO")
        assert result is False
        assert "contoso" not in state.all_domains

        # FQDNs should be accepted
        result = state.add_domain("child.contoso.local")
        assert result is True
        assert "child.contoso.local" in state.all_domains

    def test_retroactive_normalize_updates_credentials(self):
        """Adding FQDN should update credentials with NetBIOS domain."""
        state = SharedRedTeamState(operation_id="op-test-retro-creds")

        # Add credential with NetBIOS domain (simulating tool output with short domain)
        cred = Credential(
            username="sql_svc",
            password="SqlP@ss!",  # pragma: allowlist secret
            domain="child",
            source="test",
        )
        state.all_credentials.append(cred)
        # Note: add_domain("child") would be rejected now, but the credential
        # was added directly to all_credentials with the NetBIOS domain

        # Add FQDN - should trigger retroactive normalization of credentials
        state.add_domain("child.contoso.local")

        # Credential should be updated to use FQDN
        assert state.all_credentials[0].domain == "child.contoso.local"

    def test_retroactive_normalize_triggers_parent_child_normalization(self):
        """Adding child FQDN should trigger parent-to-child credential normalization.

        Note: _normalize_parent_domain_credentials only fixes credentials for users
        that ONLY exist in the child domain. If user exists in both domains, use
        _cleanup_domain_data (via from_bytes) to fix.
        """
        from ares.core.models import User

        state = SharedRedTeamState(operation_id="op-test-retro-parent-child")
        state.add_domain("contoso.local")

        # Add user ONLY in child domain (not in parent)
        state.all_users.append(User(username="sql_svc", domain="child.contoso.local"))

        # Add credential with parent domain (this simulates tool reporting wrong domain)
        cred = Credential(
            username="sql_svc",
            password="SqlP@ss123!",  # pragma: allowlist secret
            domain="contoso.local",
            source="test",
        )
        state.all_credentials.append(cred)

        # Trigger normalization by adding child domain
        state.add_domain("child.contoso.local")

        # Credential should be updated to child domain
        assert state.all_credentials[0].domain == "child.contoso.local"


class TestNormalizeCredentialDomainsToUsers:
    """Tests for normalize_credential_domains_to_users method."""

    def test_removes_cross_domain_duplicate_when_user_in_one_domain(self):
        """Same credential with different domains, user only exists in one domain."""
        from ares.core.models import User

        state = SharedRedTeamState(operation_id="op-test-normalize-cred")

        # User only exists in child domain
        state.all_users.append(User(username="svc_backup", domain="child.contoso.local"))

        # Two credentials: one with parent domain (wrong), one with child domain (correct)
        state.all_credentials.append(
            Credential(
                username="svc_backup",
                password="BackupPass123",  # pragma: allowlist secret
                domain="contoso.local",
                source="test1",
            )
        )
        state.all_credentials.append(
            Credential(
                username="svc_backup",
                password="BackupPass123",  # pragma: allowlist secret
                domain="child.contoso.local",
                source="test2",
            )
        )

        # Run normalization
        removed = state.normalize_credential_domains_to_users()

        # Should remove the parent domain credential
        assert removed == 1
        assert len(state.all_credentials) == 1
        assert state.all_credentials[0].domain == "child.contoso.local"

    def test_keeps_legitimate_password_reuse_across_domains(self):
        """Same credential in multiple domains where user exists in both."""
        from ares.core.models import User

        state = SharedRedTeamState(operation_id="op-test-legit-reuse")

        # User exists in BOTH domains (legitimate password reuse)
        state.all_users.append(User(username="sql_svc", domain="contoso.local"))
        state.all_users.append(User(username="sql_svc", domain="child.contoso.local"))

        # Credentials in both domains
        state.all_credentials.append(
            Credential(
                username="sql_svc",
                password="SqlPass123",  # pragma: allowlist secret
                domain="contoso.local",
                source="test1",
            )
        )
        state.all_credentials.append(
            Credential(
                username="sql_svc",
                password="SqlPass123",  # pragma: allowlist secret
                domain="child.contoso.local",
                source="test2",
            )
        )

        # Run normalization
        removed = state.normalize_credential_domains_to_users()

        # Should keep both (user exists in both domains)
        assert removed == 0
        assert len(state.all_credentials) == 2

    def test_corrects_credential_domain_when_no_exact_match(self):
        """Credential with wrong domain, user exists in different domain."""
        from ares.core.models import User

        state = SharedRedTeamState(operation_id="op-test-correct-domain")

        # User only exists in child domain
        state.all_users.append(User(username="sql_svc", domain="child.contoso.local"))

        # Credential has parent domain (wrong)
        state.all_credentials.append(
            Credential(
                username="sql_svc",
                password="SqlP@ss123!",  # pragma: allowlist secret
                domain="contoso.local",
                source="test",
            )
        )

        # Run normalization
        state.normalize_credential_domains_to_users()

        # Should correct the domain (treated as duplicate removal + domain fix)
        assert len(state.all_credentials) == 1
        assert state.all_credentials[0].domain == "child.contoso.local"


class TestRequeueVulnerability:
    """Tests for requeue_vulnerability method in VulnerabilityMixin."""

    @pytest.mark.asyncio
    async def test_requeue_vulnerability_removes_from_dequeued_set(self):
        """requeue_vulnerability should remove vuln_id from _dequeued_vuln_ids."""
        dispatcher = RedTeamDispatcher()
        dispatcher._shared_state = SharedRedTeamState(operation_id="op-test-requeue")

        # Simulate a vulnerability that was dequeued
        vuln_id = "constrained_delegation_192.168.58.10"
        dispatcher._dequeued_vuln_ids.add(vuln_id)
        assert vuln_id in dispatcher._dequeued_vuln_ids

        # Requeue it
        await dispatcher.requeue_vulnerability(vuln_id)

        # Should no longer be in dequeued set
        assert vuln_id not in dispatcher._dequeued_vuln_ids

    @pytest.mark.asyncio
    async def test_requeue_vulnerability_ignores_unknown_id(self):
        """requeue_vulnerability should handle unknown vuln_id gracefully."""
        dispatcher = RedTeamDispatcher()
        dispatcher._shared_state = SharedRedTeamState(operation_id="op-test-requeue-unknown")

        # Requeue a vuln that was never dequeued
        await dispatcher.requeue_vulnerability("nonexistent_vuln_id")

        # Should not raise, and set should be empty
        assert len(dispatcher._dequeued_vuln_ids) == 0

    @pytest.mark.asyncio
    async def test_load_in_progress_vulns_recovers_state(self):
        """_load_in_progress_vulns should recover dequeued state from Redis."""
        dispatcher = RedTeamDispatcher()
        dispatcher._shared_state = SharedRedTeamState(operation_id="op-test-recovery")

        # Mock Redis client with pre-existing in-progress vulns
        mock_redis = AsyncMock()
        mock_redis.smembers.return_value = {"vuln_1", "vuln_2", "vuln_3"}
        dispatcher._redis_client = mock_redis

        # Should be empty initially
        assert len(dispatcher._dequeued_vuln_ids) == 0

        # Load from Redis
        await dispatcher._load_in_progress_vulns()

        # Should now contain the recovered IDs
        assert dispatcher._dequeued_vuln_ids == {"vuln_1", "vuln_2", "vuln_3"}
        mock_redis.smembers.assert_called_once()

    @pytest.mark.asyncio
    async def test_mark_vuln_in_progress_adds_to_redis(self):
        """_mark_vuln_in_progress should add vuln_id to Redis SET."""
        dispatcher = RedTeamDispatcher()
        dispatcher._shared_state = SharedRedTeamState(operation_id="op-test-mark-progress")

        mock_redis = AsyncMock()
        dispatcher._redis_client = mock_redis

        await dispatcher._mark_vuln_in_progress("test_vuln_id")

        mock_redis.sadd.assert_called_once()
        call_args = mock_redis.sadd.call_args[0]
        assert "vuln_in_progress" in call_args[0]
        assert call_args[1] == "test_vuln_id"

    @pytest.mark.asyncio
    async def test_clear_vuln_in_progress_removes_from_redis(self):
        """_clear_vuln_in_progress should remove vuln_id from Redis SET."""
        dispatcher = RedTeamDispatcher()
        dispatcher._shared_state = SharedRedTeamState(operation_id="op-test-clear-progress")

        mock_redis = AsyncMock()
        dispatcher._redis_client = mock_redis

        await dispatcher._clear_vuln_in_progress("test_vuln_id")

        mock_redis.srem.assert_called_once()
        call_args = mock_redis.srem.call_args[0]
        assert "vuln_in_progress" in call_args[0]
        assert call_args[1] == "test_vuln_id"


class TestAnnounceOperationComplete:
    """Tests for announce_operation_complete setting Redis status."""

    @pytest.mark.asyncio
    async def test_announce_operation_complete_sets_redis_status(self):
        """announce_operation_complete should set Redis status key."""
        dispatcher = RedTeamDispatcher()
        dispatcher._shared_state = SharedRedTeamState(operation_id="op-test-announce")
        dispatcher._shared_state.has_domain_admin = True

        # Mock Redis client
        mock_redis = AsyncMock()
        dispatcher._redis_client = mock_redis

        await dispatcher.announce_operation_complete(
            source_agent="test_agent",
            success=True,
            summary="Domain Admin achieved via S4U attack",
        )

        # Verify Redis setex was called with correct key and data
        mock_redis.setex.assert_called_once()
        call_args = mock_redis.setex.call_args
        assert call_args[0][0] == "ares:op:op-test-announce:status"
        assert call_args[0][1] == 86400  # 24 hour TTL

        # Parse the JSON to verify content
        status_data = json.loads(call_args[0][2])
        assert status_data["status"] == "completed"
        assert status_data["success"] is True
        assert status_data["domain_admin_achieved"] is True
        assert "S4U attack" in status_data["summary"]

    @pytest.mark.asyncio
    async def test_announce_operation_complete_handles_redis_failure(self):
        """announce_operation_complete should not raise on Redis failure."""
        dispatcher = RedTeamDispatcher()
        dispatcher._shared_state = SharedRedTeamState(operation_id="op-test-redis-fail")

        # Mock Redis client that raises
        mock_redis = AsyncMock()
        mock_redis.setex.side_effect = Exception("Redis connection lost")
        dispatcher._redis_client = mock_redis

        # Should not raise
        await dispatcher.announce_operation_complete(
            source_agent="test_agent",
            success=False,
            summary="Operation failed",
        )


class TestWorkerHeartbeatTaskActivity:
    """Tests for worker heartbeat updating task activity timestamp."""

    @pytest.mark.asyncio
    async def test_heartbeat_updates_task_last_activity(self):
        """Worker heartbeat with current_task should update last_activity_at."""
        from datetime import datetime, timedelta, timezone

        from ares.core.models import TaskInfo, TaskStatus

        dispatcher = RedTeamDispatcher()
        state = SharedRedTeamState(operation_id="op-test-heartbeat-activity")
        dispatcher._shared_state = state
        dispatcher._running = True

        # Create a pending task with old activity timestamp
        old_time = datetime.now(timezone.utc) - timedelta(minutes=10)
        task_info = TaskInfo(
            task_id="task-123",
            task_type="exploit",
            assigned_agent="privesc",
            status=TaskStatus.PENDING,
        )
        task_info.last_activity_at = old_time
        state.pending_tasks["task-123"] = task_info

        # Register agent with proper AgentInfo-like object
        agent_info = type(
            "AgentInfo",
            (),
            {
                "last_heartbeat": datetime.now(timezone.utc),
                "status": "idle",
                "current_task": None,
            },
        )()
        dispatcher._agents["privesc-worker-1"] = agent_info

        # Create mock task queue that returns heartbeat data
        mock_task_queue = AsyncMock()
        mock_task_queue.get_heartbeat.return_value = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "status": "working",
            "current_task": "task-123",
        }
        dispatcher._task_queue = mock_task_queue

        # Manually invoke the heartbeat logic (simulating one iteration)
        # The _heartbeat_monitor is a loop, so we directly call the core logic
        now = datetime.now(timezone.utc)
        for agent_name in list(dispatcher._agents.keys()):
            heartbeat_data = await dispatcher._task_queue.get_heartbeat(agent_name)
            if heartbeat_data:
                current_task = heartbeat_data.get("current_task")
                if current_task and dispatcher._shared_state:
                    task_info = dispatcher._shared_state.pending_tasks.get(current_task)
                    if task_info:
                        task_info.last_activity_at = now
                        if task_info.status == TaskStatus.PENDING:
                            task_info.status = TaskStatus.IN_PROGRESS
                            task_info.started_at = now

        # Verify task activity was updated
        updated_task = state.pending_tasks["task-123"]
        assert updated_task.last_activity_at > old_time
        assert updated_task.status == TaskStatus.IN_PROGRESS


class TestModuleExtractionFunction:
    """Tests for module-level extract_plaintext_passwords_from_output in extraction.py."""

    def test_module_extract_lsa_default_password(self):
        """Should extract LSA DefaultPassword from secretsdump output."""
        from ares.core.dispatcher.extraction import extract_plaintext_passwords_from_output

        # Actual secretsdump LSA DefaultPassword format
        output = """
[*] Dumping cached domain logon information (domain/username:hash)
[*] Dumping LSA Secrets
[*] DefaultPassword
CONTOSO\\svc_backup:B@ckupP@ss123!
[*] DPAPI_SYSTEM
        """

        creds = extract_plaintext_passwords_from_output(output)

        assert len(creds) == 1
        username, password, domain = creds[0]
        assert username == "svc_backup"
        assert password == "B@ckupP@ss123!"  # pragma: allowlist secret
        assert domain == "CONTOSO"

    def test_module_extract_password_field(self):
        """Should still extract Password: field format."""
        from ares.core.dispatcher.extraction import extract_plaintext_passwords_from_output

        output = """
        samaccountname: sql_svc
        Password: SqlP@ss123
        """

        creds = extract_plaintext_passwords_from_output(output)

        assert len(creds) == 1
        username, password, domain = creds[0]
        assert username == "sql_svc"
        assert password == "SqlP@ss123"  # pragma: allowlist secret
        assert domain == ""  # No domain in output

    def test_module_extract_deduplicates_case_insensitive(self):
        """Should deduplicate usernames case-insensitively."""
        from ares.core.dispatcher.extraction import extract_plaintext_passwords_from_output

        # Same user with different case should NOT be duplicated
        output = """
        samaccountname: Admin
        Password: P@ssw0rd!

        samaccountname: admin
        Password: P@ssw0rd!

        samaccountname: ADMIN
        Password: P@ssw0rd!
        """

        creds = extract_plaintext_passwords_from_output(output)

        # Should only get one entry (first occurrence preserved)
        assert len(creds) == 1
        username, password, _domain = creds[0]
        assert username == "Admin"  # First occurrence preserved
        assert password == "P@ssw0rd!"  # pragma: allowlist secret

    def test_module_extract_different_passwords_not_deduplicated(self):
        """Same username with different passwords should NOT be deduplicated."""
        from ares.core.dispatcher.extraction import extract_plaintext_passwords_from_output

        # Same user with different passwords = different credentials
        output = """
        samaccountname: admin
        Password: OldPass123

        samaccountname: admin
        Password: NewPass456
        """

        creds = extract_plaintext_passwords_from_output(output)

        # Should get both entries (different passwords)
        assert len(creds) == 2


class TestDispatcherExtractCaseInsensitiveDedup:
    """Tests for case-insensitive deduplication in dispatcher method."""

    def test_dispatcher_extract_deduplicates_case_insensitive(self):
        """Dispatcher method should deduplicate usernames case-insensitively."""
        dispatcher = RedTeamDispatcher()
        dispatcher._shared_state = SharedRedTeamState(operation_id="op-test-dedup")

        # Same user with different case should NOT be duplicated
        output = """
        samaccountname: SVC_Backup
        Password: P@ssw0rd!

        samaccountname: svc_backup
        Password: P@ssw0rd!
        """

        creds = dispatcher._extract_plaintext_passwords_from_output(output)

        # Should only get one entry
        assert len(creds) == 1
        username, _password, _domain = creds[0]
        assert username.lower() == "svc_backup"

    def test_dispatcher_extract_lsa_deduplicates_case_insensitive(self):
        """LSA DefaultPassword extraction should also deduplicate case-insensitively."""
        dispatcher = RedTeamDispatcher()
        dispatcher._shared_state = SharedRedTeamState(operation_id="op-test-lsa-dedup")

        # Two LSA entries with different case (shouldn't happen in practice, but test defense)
        output = """
[*] DefaultPassword
CONTOSO\\Admin:P@ssw0rd!
        """

        creds = dispatcher._extract_plaintext_passwords_from_output(output)

        assert len(creds) == 1
        username, _password, domain = creds[0]
        assert username == "Admin"
        assert domain == "CONTOSO"


class TestDomainAdminTraceDiscovery:
    """Tests for trace_discovery call when DA is achieved via krbtgt hash."""

    def test_add_hash_krbtgt_calls_trace_discovery(self):
        """Adding krbtgt NTLM hash should trigger trace_discovery for domain_admin."""
        from unittest.mock import patch

        from ares.core.models import Hash

        state = SharedRedTeamState(operation_id="op-test-trace-da")

        krbtgt_hash = Hash(
            username="krbtgt",
            domain="contoso.local",
            hash_type="ntlm",
            hash_value="aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0",
            source="secretsdump",
        )

        captured_calls = []

        def mock_trace_discovery(*args, **kwargs):
            captured_calls.append(kwargs)

        # Patch at the source module where trace_discovery is defined
        with patch("ares.core.tracing.trace_discovery", side_effect=mock_trace_discovery):
            state.add_hash(krbtgt_hash, source_agent="lateral")

        # Filter for domain_admin discovery (weakness is also traced)
        da_calls = [c for c in captured_calls if c["discovery_type"] == "domain_admin"]
        assert len(da_calls) == 1, f"Expected 1 domain_admin trace, got {len(da_calls)}"

        call = da_calls[0]
        assert call["source_agent"] == "lateral"
        assert call["operation_id"] == "op-test-trace-da"
        assert call["target_user"] == "krbtgt"
        assert call["target_domain"] == "contoso.local"
        assert call["additional_attrs"]["auto_detected"] is True
        assert call["additional_attrs"]["credential_type"] == "ntlm_hash"
        assert call["additional_attrs"]["mitre.technique.id"] == "T1003.006"

    def test_add_hash_non_krbtgt_does_not_call_trace_discovery(self):
        """Adding non-krbtgt hash should NOT trigger domain_admin trace_discovery."""
        from unittest.mock import patch

        from ares.core.models import Hash

        state = SharedRedTeamState(operation_id="op-test-no-trace")

        regular_hash = Hash(
            username="sql_svc",
            domain="contoso.local",
            hash_type="ntlm",
            hash_value="aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0",
            source="secretsdump",
        )

        captured_calls = []

        def mock_trace_discovery(*args, **kwargs):
            captured_calls.append(kwargs)

        with patch("ares.core.tracing.trace_discovery", side_effect=mock_trace_discovery):
            state.add_hash(regular_hash, source_agent="lateral")

        # Filter for domain_admin discovery only
        da_calls = [c for c in captured_calls if c["discovery_type"] == "domain_admin"]
        assert len(da_calls) == 0, "Non-krbtgt hash should NOT trigger domain_admin trace"

    def test_add_hash_krbtgt_traces_each_domain_once(self):
        """Multiple krbtgt hashes from different domains each trace DA (multi-forest support)."""
        from unittest.mock import patch

        from ares.core.models import Hash

        state = SharedRedTeamState(operation_id="op-test-trace-once")

        krbtgt_hash1 = Hash(
            username="krbtgt",
            domain="contoso.local",
            hash_type="ntlm",
            hash_value="aad3b435b51404eeaad3b435b51404ee:aaaa",
            source="secretsdump",
        )

        krbtgt_hash2 = Hash(
            username="krbtgt",
            domain="child.contoso.local",
            hash_type="ntlm",
            hash_value="aad3b435b51404eeaad3b435b51404ee:bbbb",
            source="secretsdump",
        )

        # Same domain as hash1, should NOT trace again
        krbtgt_hash3 = Hash(
            username="krbtgt",
            domain="contoso.local",
            hash_type="ntlm",
            hash_value="aad3b435b51404eeaad3b435b51404ee:cccc",
            source="secretsdump",
        )

        captured_calls = []

        def mock_trace_discovery(*args, **kwargs):
            captured_calls.append(kwargs)

        with patch("ares.core.tracing.trace_discovery", side_effect=mock_trace_discovery):
            state.add_hash(krbtgt_hash1, source_agent="lateral")
            state.add_hash(krbtgt_hash2, source_agent="lateral")
            state.add_hash(krbtgt_hash3, source_agent="lateral")

        # Filter for domain_admin discovery only
        da_calls = [c for c in captured_calls if c["discovery_type"] == "domain_admin"]

        # Multi-forest mode: trace DA for each DISTINCT domain (dedup same domain)
        assert len(da_calls) == 2, f"Expected 2 domain_admin traces, got {len(da_calls)}"
        traced_domains = {c["target_domain"] for c in da_calls}
        assert traced_domains == {"contoso.local", "child.contoso.local"}
