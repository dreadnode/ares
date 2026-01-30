"""Tests for certipy tool routing.

Verifies that certipy_find runs locally on privesc agent (where certipy is installed)
rather than routing to recon agent (which doesn't have certipy).
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest


class TestCertipyFindRouting:
    """Tests for certipy_find tool routing."""

    def test_certipy_find_runs_locally(self):
        """Test that certipy_find runs locally without target_role routing."""
        from ares.tools.red.kerberos_attacks import CertipyTools

        tools = CertipyTools()

        # Mock run_tool to capture how it's called
        with patch("ares.tools.red.kerberos_attacks.run_tool") as mock_run_tool:
            mock_run_tool.return_value = ("output", "", 0)

            tools.certipy_find(
                domain="domain.local",
                username="testuser",
                password="TestPass123",  # pragma: allowlist secret
                dc_ip="192.168.58.1",
            )

            # Verify run_tool was called
            mock_run_tool.assert_called_once()

            # Get the call arguments
            call_args = mock_run_tool.call_args

            # Verify NO target_role parameter (should run locally)
            # The key insight: if target_role is not in kwargs, it runs locally
            if call_args.kwargs:
                assert "target_role" not in call_args.kwargs, (
                    "certipy_find should NOT route to another worker - "
                    "certipy is installed on privesc, not recon"
                )

    def test_certipy_find_has_adequate_timeout(self):
        """Test that certipy_find has sufficient timeout."""
        from ares.tools.red.kerberos_attacks import CertipyTools

        tools = CertipyTools()

        with patch("ares.tools.red.kerberos_attacks.run_tool") as mock_run_tool:
            mock_run_tool.return_value = ("output", "", 0)

            tools.certipy_find(
                domain="domain.local",
                username="testuser",
                password="TestPass123",  # pragma: allowlist secret
                dc_ip="192.168.58.1",
            )

            call_args = mock_run_tool.call_args

            # Check timeout is at least 300 seconds (5 minutes)
            # This gives certipy enough time to enumerate large domains
            timeout = call_args.kwargs.get("timeout_seconds", 0)
            if call_args.args and len(call_args.args) > 1:
                timeout = call_args.args[1]

            assert timeout >= 300, f"certipy_find timeout should be at least 300s, got {timeout}s"

    def test_certipy_find_constructs_correct_command(self):
        """Test that certipy_find constructs the correct certipy command."""
        from ares.tools.red.kerberos_attacks import CertipyTools

        tools = CertipyTools()

        with patch("ares.tools.red.kerberos_attacks.run_tool") as mock_run_tool:
            mock_run_tool.return_value = ("output", "", 0)

            tools.certipy_find(
                domain="domain.local",
                username="testuser",
                password="TestPass123",  # pragma: allowlist secret
                dc_ip="192.168.58.1",
                vulnerable=True,
            )

            call_args = mock_run_tool.call_args
            cmd = call_args.args[0]

            # The command should be a list starting with bash
            assert cmd[0] == "bash"
            assert cmd[1] == "-lc"

            # The script should contain certipy find command
            script = cmd[2]
            assert "certipy" in script
            assert "find" in script
            assert "-u" in script
            assert "testuser@domain.local" in script
            assert "-dc-ip" in script
            assert "192.168.58.1" in script
            assert "-vulnerable" in script

    def test_certipy_find_detects_vulnerabilities(self):
        """Test that certipy_find properly detects ESC vulnerabilities."""
        from ares.tools.red.kerberos_attacks import CertipyTools

        tools = CertipyTools()
        mock_state = MagicMock()
        mock_state.weaknesses = []
        tools.state = mock_state

        # Simulate certipy output with ESC1 vulnerability
        esc1_output = """
Certificate Templates
  0
    Template Name                       : VulnTemplate
    Display Name                        : Vulnerable Template
    Enabled                             : True
    Client Authentication               : True
    Enrollment Rights                   : Domain Users
    [!] Vulnerabilities
      ESC1                              : 'DOMAIN\\Domain Users' can enroll
        """

        with patch("ares.tools.red.kerberos_attacks.run_tool") as mock_run_tool:
            mock_run_tool.return_value = (esc1_output, "", 0)

            result = tools.certipy_find(
                domain="domain.local",
                username="testuser",
                password="TestPass123",  # pragma: allowlist secret
                dc_ip="192.168.58.1",
            )

            # Should detect ESC1 vulnerability
            assert "ESC1" in result
            assert "ADCS VULNERABILITY DETECTED" in result

    def test_certipy_find_detects_esc8(self):
        """Test that certipy_find properly detects ESC8 (web enrollment)."""
        from ares.tools.red.kerberos_attacks import CertipyTools

        tools = CertipyTools()
        mock_state = MagicMock()
        mock_state.weaknesses = []
        tools.state = mock_state

        # Simulate certipy output with web enrollment (ESC8) but no explicit ESC# match
        # This triggers the secondary ESC8 detection via "web enrollment" text
        esc8_output = """
Certificate Authorities
  0
    CA Name                             : domain-CA
    DNS Name                            : ca.domain.local
    Web Enrollment                      : Enabled
        """

        with patch("ares.tools.red.kerberos_attacks.run_tool") as mock_run_tool:
            mock_run_tool.return_value = (esc8_output, "", 0)

            result = tools.certipy_find(
                domain="domain.local",
                username="testuser",
                password="TestPass123",  # pragma: allowlist secret
                dc_ip="192.168.58.1",
            )

            # Should detect ESC8 vulnerability via "web enrollment" text
            assert "ESC8" in result
            assert "RELAY" in result.upper()


class TestCertipyToolAvailability:
    """Tests verifying certipy is available on correct agent."""

    def test_certipy_in_privesc_tools(self):
        """Verify CertipyTools is assigned to privesc agent."""

        # This is more of a documentation/contract test
        # The actual tool assignment happens in create_specialized_agent
        # which reads from the role configuration

        # Check that CertipyTools exists and can be imported
        from ares.tools.red import CertipyTools

        assert CertipyTools is not None
        assert hasattr(CertipyTools, "certipy_find")
        assert hasattr(CertipyTools, "certipy_request")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
