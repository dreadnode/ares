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
