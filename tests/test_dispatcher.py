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
        """Should extract domain from user@domain.local format in output."""
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
        (e.g., north.sevenkingdoms.local) is incorrectly recorded with a different
        domain (e.g., essos.local) during cross-domain enumeration.
        """
        from ares.core.models import Target

        state = SharedRedTeamState(operation_id="op-test-cross-domain-dup")
        state.target = Target(ip="192.168.58.10", domain="contoso.local")

        # First credential in correct domain
        cred1 = Credential(
            username="samwell.tarly",
            password="Heartsbane",  # pragma: allowlist secret
            domain="contoso.local",
            source="ldap_description",
        )
        added1 = state.add_credential(cred1, "recon")
        assert added1 is True
        assert len(state.all_credentials) == 1

        # Same credential recorded with wrong domain (agent hallucination)
        cred2 = Credential(
            username="samwell.tarly",
            password="Heartsbane",  # pragma: allowlist secret
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


class TestDomainCleanup:
    """Tests for domain cleanup and normalization."""

    def test_cleanup_removes_netbios_when_fqdn_exists(self):
        """NetBIOS domains should be removed when corresponding FQDN exists."""
        import json

        state_dict = {
            "operation_id": "op-test-cleanup-netbios",
            "all_domains": ["child", "contoso.local", "child.contoso.local"],
            "all_users": [],
            "all_credentials": [],
            "all_hashes": [],
            "all_hosts": [],
            "all_shares": [],
            "all_weaknesses": [],
        }
        data = json.dumps(state_dict).encode("utf-8")
        state = SharedRedTeamState.from_bytes(data)

        # "child" should be removed since "child.contoso.local" exists
        assert "child" not in state.all_domains
        assert "contoso.local" in state.all_domains
        assert "child.contoso.local" in state.all_domains
        assert len(state.all_domains) == 2

    def test_cleanup_dedupes_users_with_parent_child_domains(self):
        """Users with both parent and child domain entries should be deduplicated."""
        import json

        state_dict = {
            "operation_id": "op-test-cleanup-users",
            "all_domains": ["contoso.local", "child.contoso.local"],
            "all_users": [
                {"username": "sql_svc", "domain": "contoso.local"},
                {"username": "sql_svc", "domain": "child.contoso.local"},
                {"username": "domain_admin", "domain": "contoso.local"},
            ],
            "all_credentials": [],
            "all_hashes": [],
            "all_hosts": [],
            "all_shares": [],
            "all_weaknesses": [],
        }
        data = json.dumps(state_dict).encode("utf-8")
        state = SharedRedTeamState.from_bytes(data)

        # sql_svc should only exist in child domain
        assert len(state.all_users) == 2
        user_domains = {(u.username, u.domain) for u in state.all_users}
        assert ("sql_svc", "child.contoso.local") in user_domains
        assert ("sql_svc", "contoso.local") not in user_domains
        # domain_admin stays in parent domain (only exists there)
        assert ("domain_admin", "contoso.local") in user_domains

    def test_cleanup_fixes_credentials_with_parent_domain(self):
        """Credentials with parent domain should be fixed when user only in child."""
        import json

        state_dict = {
            "operation_id": "op-test-cleanup-creds",
            "all_domains": ["contoso.local", "child.contoso.local"],
            "all_users": [
                {"username": "sql_svc", "domain": "contoso.local"},
                {"username": "sql_svc", "domain": "child.contoso.local"},
            ],
            "all_credentials": [
                {
                    "username": "sql_svc",
                    "password": "SqlP@ss123!",  # pragma: allowlist secret
                    "domain": "contoso.local",
                    "source": "test",
                },
            ],
            "all_hashes": [],
            "all_hosts": [],
            "all_shares": [],
            "all_weaknesses": [],
        }
        data = json.dumps(state_dict).encode("utf-8")
        state = SharedRedTeamState.from_bytes(data)

        # Credential should be fixed to child domain
        assert len(state.all_credentials) == 1
        assert state.all_credentials[0].domain == "child.contoso.local"

    def test_cleanup_fixes_hashes_with_parent_domain(self):
        """Hashes with parent domain should be fixed when user only in child."""
        import json

        state_dict = {
            "operation_id": "op-test-cleanup-hashes",
            "all_domains": ["contoso.local", "child.contoso.local"],
            "all_users": [
                {"username": "sql_svc", "domain": "contoso.local"},
                {"username": "sql_svc", "domain": "child.contoso.local"},
            ],
            "all_credentials": [],
            "all_hashes": [
                {
                    "username": "sql_svc",
                    "hash_value": "aad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0",
                    "hash_type": "NTLM",
                    "domain": "contoso.local",
                },
            ],
            "all_hosts": [],
            "all_shares": [],
            "all_weaknesses": [],
        }
        data = json.dumps(state_dict).encode("utf-8")
        state = SharedRedTeamState.from_bytes(data)

        # Hash should be fixed to child domain
        assert len(state.all_hashes) == 1
        assert state.all_hashes[0].domain == "child.contoso.local"

    def test_cleanup_preserves_legitimate_parent_domain_users(self):
        """Users that only exist in parent domain should not be modified."""
        import json

        state_dict = {
            "operation_id": "op-test-cleanup-preserve",
            "all_domains": ["contoso.local", "child.contoso.local"],
            "all_users": [
                {"username": "domain_admin", "domain": "contoso.local"},
            ],
            "all_credentials": [
                {
                    "username": "domain_admin",
                    "password": "AdminP@ss1!",  # pragma: allowlist secret
                    "domain": "contoso.local",
                    "source": "test",
                },
            ],
            "all_hashes": [],
            "all_hosts": [],
            "all_shares": [],
            "all_weaknesses": [],
        }
        data = json.dumps(state_dict).encode("utf-8")
        state = SharedRedTeamState.from_bytes(data)

        # domain_admin stays in parent domain
        assert len(state.all_users) == 1
        assert state.all_users[0].domain == "contoso.local"
        assert len(state.all_credentials) == 1
        assert state.all_credentials[0].domain == "contoso.local"


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


class TestRetroactiveDomainNormalize:
    """Tests for retroactive domain normalization."""

    def test_retroactive_normalize_removes_netbios_from_domains(self):
        """Adding FQDN should remove corresponding NetBIOS from all_domains."""
        state = SharedRedTeamState(operation_id="op-test-retro-netbios")

        # Add NetBIOS domain first
        state.add_domain("child")
        assert "child" in state.all_domains

        # Add FQDN - should trigger retroactive normalization
        state.add_domain("child.contoso.local")

        # NetBIOS should be removed
        assert "child" not in state.all_domains
        assert "child.contoso.local" in state.all_domains

    def test_retroactive_normalize_updates_credentials(self):
        """Adding FQDN should update credentials with NetBIOS domain."""
        state = SharedRedTeamState(operation_id="op-test-retro-creds")

        # Add credential with NetBIOS domain
        cred = Credential(
            username="sql_svc",
            password="SqlP@ss!",  # pragma: allowlist secret
            domain="child",
            source="test",
        )
        state.all_credentials.append(cred)
        state.add_domain("child")

        # Add FQDN
        state.add_domain("child.contoso.local")

        # Credential should be updated
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


class TestHashDeduplication:
    """Tests for hash deduplication."""

    def test_kerberoast_deduped_by_spn_and_etype(self):
        """Kerberoast hashes with same user+SPN+etype should be deduplicated."""
        import json

        # Two Kerberoast hashes for same user, same SPN, same etype (23=RC4)
        # but different hash values (different request timestamps)
        state_dict = {
            "operation_id": "op-test-kerberoast-dedupe",
            "all_domains": ["contoso.local"],
            "all_users": [],
            "all_credentials": [],
            "all_hashes": [
                {
                    "username": "sql_svc",
                    "hash_value": "$krb5tgs$23$*sql_svc$CONTOSO.LOCAL$MSSQLSvc/sql01.contoso.local*$aaa$111",
                    "hash_type": "Kerberoast",
                    "domain": "contoso.local",
                },
                {
                    "username": "sql_svc",
                    "hash_value": "$krb5tgs$23$*sql_svc$CONTOSO.LOCAL$MSSQLSvc/sql01.contoso.local*$bbb$222",
                    "hash_type": "Kerberoast",
                    "domain": "contoso.local",
                },
            ],
            "all_hosts": [],
            "all_shares": [],
            "all_weaknesses": [],
        }
        data = json.dumps(state_dict).encode("utf-8")
        state = SharedRedTeamState.from_bytes(data)

        # Should dedupe to 1 hash
        assert len(state.all_hashes) == 1

    def test_kerberoast_different_spn_kept(self):
        """Kerberoast hashes with different SPNs should be kept."""
        import json

        state_dict = {
            "operation_id": "op-test-kerberoast-diff-spn",
            "all_domains": ["contoso.local"],
            "all_users": [],
            "all_credentials": [],
            "all_hashes": [
                {
                    "username": "sql_svc",
                    "hash_value": "$krb5tgs$23$*sql_svc$CONTOSO.LOCAL$MSSQLSvc/sql01.contoso.local*$aaa$111",
                    "hash_type": "Kerberoast",
                    "domain": "contoso.local",
                },
                {
                    "username": "sql_svc",
                    "hash_value": "$krb5tgs$23$*sql_svc$CONTOSO.LOCAL$MSSQLSvc/sql02.contoso.local*$bbb$222",
                    "hash_type": "Kerberoast",
                    "domain": "contoso.local",
                },
            ],
            "all_hosts": [],
            "all_shares": [],
            "all_weaknesses": [],
        }
        data = json.dumps(state_dict).encode("utf-8")
        state = SharedRedTeamState.from_bytes(data)

        # Should keep both (different SPNs)
        assert len(state.all_hashes) == 2

    def test_kerberoast_different_etype_kept(self):
        """Kerberoast hashes with different encryption types should be kept."""
        import json

        state_dict = {
            "operation_id": "op-test-kerberoast-diff-etype",
            "all_domains": ["contoso.local"],
            "all_users": [],
            "all_credentials": [],
            "all_hashes": [
                {
                    "username": "sql_svc",
                    "hash_value": "$krb5tgs$23$*sql_svc$CONTOSO.LOCAL$MSSQLSvc/sql01.contoso.local*$aaa$111",
                    "hash_type": "Kerberoast",
                    "domain": "contoso.local",
                },
                {
                    "username": "sql_svc",
                    "hash_value": "$krb5tgs$18$*sql_svc$CONTOSO.LOCAL$MSSQLSvc/sql01.contoso.local*$bbb$222",
                    "hash_type": "Kerberoast",
                    "domain": "contoso.local",
                },
            ],
            "all_hosts": [],
            "all_shares": [],
            "all_weaknesses": [],
        }
        data = json.dumps(state_dict).encode("utf-8")
        state = SharedRedTeamState.from_bytes(data)

        # Should keep both (RC4 vs AES256)
        assert len(state.all_hashes) == 2

    def test_asrep_deduped_by_user(self):
        """AS-REP hashes with same user should be deduplicated."""
        import json

        state_dict = {
            "operation_id": "op-test-asrep-dedupe",
            "all_domains": ["contoso.local"],
            "all_users": [],
            "all_credentials": [],
            "all_hashes": [
                {
                    "username": "nopreauth",
                    "hash_value": "$krb5asrep$23$nopreauth@CONTOSO.LOCAL:aaa$111",
                    "hash_type": "AS-REP",
                    "domain": "contoso.local",
                },
                {
                    "username": "nopreauth",
                    "hash_value": "$krb5asrep$23$nopreauth@CONTOSO.LOCAL:bbb$222",
                    "hash_type": "AS-REP",
                    "domain": "contoso.local",
                },
            ],
            "all_hosts": [],
            "all_shares": [],
            "all_weaknesses": [],
        }
        data = json.dumps(state_dict).encode("utf-8")
        state = SharedRedTeamState.from_bytes(data)

        # Should dedupe to 1 hash
        assert len(state.all_hashes) == 1

    def test_ntlm_deduped_by_value(self):
        """NTLM hashes should be deduplicated by exact hash value."""
        import json

        state_dict = {
            "operation_id": "op-test-ntlm-dedupe",
            "all_domains": ["contoso.local"],
            "all_users": [],
            "all_credentials": [],
            "all_hashes": [
                {
                    "username": "admin",
                    "hash_value": "aad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0",
                    "hash_type": "NTLM",
                    "domain": "contoso.local",
                },
                {
                    "username": "admin",
                    "hash_value": "aad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0",
                    "hash_type": "NTLM",
                    "domain": "contoso.local",
                },
            ],
            "all_hosts": [],
            "all_shares": [],
            "all_weaknesses": [],
        }
        data = json.dumps(state_dict).encode("utf-8")
        state = SharedRedTeamState.from_bytes(data)

        # Should dedupe to 1 hash
        assert len(state.all_hashes) == 1


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
        assert call_args[0][0] == "ares:operations:op-test-announce:status"
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


class TestCredentialAttachmentForDelegation:
    """Tests for credential lookup in routing for delegation exploits."""

    @pytest.mark.asyncio
    async def test_attach_credentials_for_constrained_delegation(self):
        """Should attach credentials from state when has_credentials=True but password missing."""
        dispatcher = RedTeamDispatcher()
        state = SharedRedTeamState(operation_id="op-test-cred-attach")
        state.target = Target(ip="192.168.58.10", domain="contoso.local")
        dispatcher._shared_state = state

        # Add credential to state
        cred = Credential(
            username="web_svc",
            password="WebSvcP@ss!",  # pragma: allowlist secret
            domain="contoso.local",
            source="kerberoast",
        )
        state.add_credential(cred, "cracker")

        # Mock task queue to capture submitted payloads
        submitted_payloads = []
        mock_task_queue = AsyncMock()

        async def capture_submit(task_type, target_role, payload, source_agent, priority=5):
            submitted_payloads.append(
                {"task_type": task_type, "target_role": target_role, "payload": payload}
            )
            return "task-123"

        mock_task_queue.submit_task.side_effect = capture_submit
        dispatcher._task_queue = mock_task_queue

        # Call request_exploit with delegation vuln that has has_credentials=True but no password
        await dispatcher.request_exploit(
            vuln_type="constrained_delegation",
            vuln_id="test-vuln-001",
            target="dc01.contoso.local",
            source_agent="test_agent",
            params={
                "account_name": "web_svc",
                "target_spn": "cifs/dc01.contoso.local",
                "domain": "contoso.local",
                "dc_ip": "192.168.58.10",
                "has_credentials": True,
                # No password in params - should be looked up from state
            },
        )

        # Verify task was submitted with attached credentials
        assert len(submitted_payloads) == 1
        payload = submitted_payloads[0]["payload"]
        assert payload["password"] == "WebSvcP@ss!"  # pragma: allowlist secret
        assert payload["username"] == "web_svc"
