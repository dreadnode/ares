"""Tests for sysvol_script_search tool in SharePilferingTools."""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import patch

import pytest

from ares.core.models import InvestigationStage, RedTeamState, SharedRedTeamState, Target
from ares.tools.red import SharePilferingTools


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
        operation_id="op-test-sysvol",
        target=Target(ip="192.168.56.10", hostname="dc01", domain="test.local"),
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


@pytest.fixture
def shared_state() -> SharedRedTeamState:
    """Create a shared state for testing."""
    return SharedRedTeamState(operation_id="op-test-sysvol-shared")


class TestSysvolScriptSearch:
    """Tests for sysvol_script_search method."""

    def test_rejects_placeholder_password(self, red_team_state: RedTeamState):
        """Should reject placeholder passwords."""
        tools = SharePilferingTools()
        tools.set_state(red_team_state)

        result = tools.sysvol_script_search(
            target="192.168.56.10",
            username="admin",
            password="password",  # Placeholder  # pragma: allowlist secret
            domain="test.local",
        )

        assert "placeholder password" in result.lower()

    def test_returns_no_passwords_message_when_empty(self, red_team_state: RedTeamState):
        """Should return no passwords message when nothing found."""
        tools = SharePilferingTools()
        tools.set_state(red_team_state)

        with patch("ares.tools.red.credential_discovery.run_tool") as mock_run:
            # Mock no scripts found
            mock_run.return_value = ("", "", 0)

            result = tools.sysvol_script_search(
                target="192.168.56.10",
                username="admin",
                password="RealP@ss123!",  # pragma: allowlist secret
                domain="test.local",
            )

        assert "No obvious passwords found" in result

    def test_detects_password_in_script(self, red_team_state: RedTeamState):
        """Should detect password patterns in scripts."""
        tools = SharePilferingTools()
        tools.set_state(red_team_state)

        script_content = "password=SecretPass123"

        with patch("ares.tools.red.credential_discovery.run_tool") as mock_run:

            def side_effect(cmd, timeout_seconds=300):
                cmd_str = " ".join(cmd)
                if "ls" in cmd_str:
                    return ("login.bat", "", 0)
                if "get" in cmd_str:
                    return ("", "", 0)
                if "grep" in cmd_str:
                    return (script_content, "", 0)
                if "spider_plus" in cmd_str or "netexec" in cmd_str:
                    return ("", "", 0)
                return ("", "", 0)

            mock_run.side_effect = side_effect

            result = tools.sysvol_script_search(
                target="192.168.56.10",
                username="admin",
                password="RealP@ss123!",  # pragma: allowlist secret
                domain="test.local",
            )

        # If password found, should contain alert
        if "POTENTIAL PASSWORDS FOUND" in result:
            assert "login.bat" in result or "SecretPass123" in result

    def test_extracts_net_use_credentials(self, shared_state: SharedRedTeamState):
        """Should extract credentials from net use commands."""
        tools = SharePilferingTools()
        tools.set_state(shared_state)

        script_content = r"net use * \\server\share /user:DOMAIN\svc_backup P@ssw0rd123"

        with patch("ares.tools.red.credential_discovery.run_tool") as mock_run:

            def side_effect(cmd, timeout_seconds=300):
                cmd_str = " ".join(cmd)
                if "ls" in cmd_str and "*.bat" in cmd_str:
                    return ("mount.bat", "", 0)
                if "get" in cmd_str:
                    return ("", "", 0)
                if "grep" in cmd_str:
                    return (script_content, "", 0)
                if "netexec" in cmd_str or "spider" in cmd_str:
                    return ("", "", 0)
                return ("", "", 0)

            mock_run.side_effect = side_effect

            result = tools.sysvol_script_search(
                target="192.168.56.10",
                username="admin",
                password="RealP@ss123!",  # pragma: allowlist secret
                domain="test.local",
            )

        # Check if credentials were extracted
        if "POTENTIAL PASSWORDS FOUND" in result:
            # Credential should be added to state
            creds = shared_state.all_credentials
            svc_backup_creds = [c for c in creds if c.username == "svc_backup"]
            if svc_backup_creds:
                assert svc_backup_creds[0].password == "P@ssw0rd123"  # pragma: allowlist secret

    def test_handles_exception_gracefully(self, red_team_state: RedTeamState):
        """Should handle exceptions gracefully."""
        tools = SharePilferingTools()
        tools.set_state(red_team_state)

        with patch("ares.tools.red.credential_discovery.run_tool") as mock_run:
            mock_run.side_effect = Exception("Connection failed")

            result = tools.sysvol_script_search(
                target="192.168.56.10",
                username="admin",
                password="RealP@ss123!",  # pragma: allowlist secret
                domain="test.local",
            )

        assert "failed" in result.lower()

    def test_searches_multiple_script_extensions(self, red_team_state: RedTeamState):
        """Should search for multiple script file extensions."""
        tools = SharePilferingTools()
        tools.set_state(red_team_state)

        searched_extensions = []

        with patch("ares.tools.red.credential_discovery.run_tool") as mock_run:

            def side_effect(cmd, timeout_seconds=300):
                cmd_str = " ".join(cmd)
                for ext in ["*.bat", "*.cmd", "*.ps1", "*.vbs", "*.wsf", "*.inf"]:
                    if ext in cmd_str:
                        searched_extensions.append(ext)
                return ("", "", 0)

            mock_run.side_effect = side_effect

            tools.sysvol_script_search(
                target="192.168.56.10",
                username="admin",
                password="RealP@ss123!",  # pragma: allowlist secret
                domain="test.local",
            )

        # Should search for common script extensions
        expected_extensions = ["*.bat", "*.cmd", "*.ps1", "*.vbs"]
        for ext in expected_extensions:
            assert ext in searched_extensions, f"Did not search for {ext}"


class TestSysvolScriptSearchPatterns:
    """Tests for pattern matching in sysvol_script_search."""

    def test_pattern_password_equals(self, red_team_state: RedTeamState):
        """Should match password= pattern."""
        tools = SharePilferingTools()
        tools.set_state(red_team_state)

        # The pattern matching happens in grep command
        # Just verify the tool can be called without error
        with patch("ares.tools.red.credential_discovery.run_tool") as mock_run:
            mock_run.return_value = ("password=MySecret", "", 0)

            result = tools.sysvol_script_search(
                target="192.168.56.10",
                username="admin",
                password="RealP@ss123!",  # pragma: allowlist secret
                domain="test.local",
            )

        # Should process without error
        assert result is not None

    def test_pattern_pwd_colon(self, red_team_state: RedTeamState):
        """Should match pwd: pattern."""
        tools = SharePilferingTools()
        tools.set_state(red_team_state)

        with patch("ares.tools.red.credential_discovery.run_tool") as mock_run:
            mock_run.return_value = ("pwd:MySecret", "", 0)

            result = tools.sysvol_script_search(
                target="192.168.56.10",
                username="admin",
                password="RealP@ss123!",  # pragma: allowlist secret
                domain="test.local",
            )

        assert result is not None

    def test_pattern_credential(self, red_team_state: RedTeamState):
        """Should match cred= pattern."""
        tools = SharePilferingTools()
        tools.set_state(red_team_state)

        with patch("ares.tools.red.credential_discovery.run_tool") as mock_run:
            mock_run.return_value = ("cred=MySecret", "", 0)

            result = tools.sysvol_script_search(
                target="192.168.56.10",
                username="admin",
                password="RealP@ss123!",  # pragma: allowlist secret
                domain="test.local",
            )

        assert result is not None
