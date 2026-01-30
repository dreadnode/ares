"""Tests for lateral movement tools, particularly MSSQL functionality."""

from unittest.mock import patch

import pytest

from ares.tools.red.lateral_movement import LateralMovementTools


class TestMSSQLEnumImpersonation:
    """Tests for mssql_enum_impersonation tool."""

    def test_mssql_enum_impersonation_finds_targets(self):
        """Test that mssql_enum_impersonation identifies impersonation targets."""
        tools = LateralMovementTools()

        mock_stdout = """
SQL>
ImpersonatableUser
----------------
sa
dbo
dbadmin
SQL>
        """

        with patch("ares.tools.red.lateral_movement.run_tool") as mock_run:
            mock_run.return_value = (mock_stdout, "", 0)

            result = tools.mssql_enum_impersonation(
                target="192.168.58.22",
                username="testuser",
                password="TestPass123",  # pragma: allowlist secret
                domain="contoso.local",
                windows_auth=True,
            )

        # Should detect impersonation targets
        assert "impersonatableuser" in result.lower()
        assert "sa" in result.lower()

    def test_mssql_enum_impersonation_highlights_high_value(self):
        """Test that high-value impersonation targets are highlighted."""
        tools = LateralMovementTools()

        mock_stdout = """
SQL>
ImpersonatableUser
----------------
sa
SQL>
        """

        with patch("ares.tools.red.lateral_movement.run_tool") as mock_run:
            mock_run.return_value = (mock_stdout, "", 0)

            result = tools.mssql_enum_impersonation(
                target="192.168.58.23",
                username="testuser",
                password="TestPass123",  # pragma: allowlist secret
                domain="contoso.local",
            )

        # Should highlight high-value targets
        assert "IMPERSONATION TARGETS FOUND" in result
        assert "sa" in result.lower()

    def test_mssql_enum_impersonation_handles_error(self):
        """Test error handling in mssql_enum_impersonation."""
        tools = LateralMovementTools()

        with patch("ares.tools.red.lateral_movement.run_tool") as mock_run:
            mock_run.side_effect = Exception("Connection failed")

            result = tools.mssql_enum_impersonation(
                target="192.168.58.24",
                username="testuser",
                password="TestPass123",  # pragma: allowlist secret
            )

        # Should return error message
        assert "failed" in result.lower()

    def test_mssql_enum_impersonation_formats_command_correctly(self):
        """Test that mssql_enum_impersonation formats the SQL command correctly."""
        tools = LateralMovementTools()

        with patch("ares.tools.red.lateral_movement.run_tool") as mock_run:
            mock_run.return_value = ("No results", "", 0)

            tools.mssql_enum_impersonation(
                target="192.168.58.25",
                username="testuser",
                password="TestPass123",  # pragma: allowlist secret
                domain="contoso.local",
                windows_auth=True,
            )

        # Verify command structure
        call_args = mock_run.call_args[0][0]
        assert "bash" in call_args
        assert "-c" in call_args

        # The SQL query should be in the command
        command_str = " ".join(call_args)
        assert "mssqlclient.py" in command_str
        assert "contoso.local/testuser:TestPass123@192.168.58.25" in command_str
        assert "-windows-auth" in command_str

    def test_mssql_enum_impersonation_finds_admin_accounts(self):
        """Test detection of admin-level impersonation targets."""
        tools = LateralMovementTools()

        mock_stdout = """
SQL>
ImpersonatableUser
----------------
##MS_PolicyEventProcessingLogin##
admin
dbowner
SQL>
        """

        with patch("ares.tools.red.lateral_movement.run_tool") as mock_run:
            mock_run.return_value = (mock_stdout, "", 0)

            result = tools.mssql_enum_impersonation(
                target="192.168.58.26",
                username="testuser",
                password="TestPass123",  # pragma: allowlist secret
            )

        # Should highlight admin accounts
        assert "IMPERSONATION TARGETS FOUND" in result
        assert "admin" in result.lower()


class TestMSSQLImpersonate:
    """Tests for mssql_impersonate tool."""

    def test_mssql_impersonate_executes_query(self):
        """Test that mssql_impersonate executes queries as impersonated user."""
        tools = LateralMovementTools()

        mock_stdout = """
SQL> EXECUTE AS LOGIN = 'sa'
SQL> SELECT SYSTEM_USER
SYSTEM_USER
------------
sa
SQL>
        """

        with patch("ares.tools.red.lateral_movement.run_tool") as mock_run:
            mock_run.return_value = (mock_stdout, "", 0)

            result = tools.mssql_impersonate(
                target="192.168.58.27",
                username="testuser",
                password="TestPass123",  # pragma: allowlist secret
                impersonate_user="sa",
                query="SELECT SYSTEM_USER",
                domain="contoso.local",
            )

        # Should show impersonation success
        assert "sa" in result.lower()

    def test_mssql_impersonate_formats_command_correctly(self):
        """Test that mssql_impersonate formats the impersonation command correctly."""
        tools = LateralMovementTools()

        with patch("ares.tools.red.lateral_movement.run_tool") as mock_run:
            mock_run.return_value = ("Success", "", 0)

            tools.mssql_impersonate(
                target="192.168.58.28",
                username="testuser",
                password="TestPass123",  # pragma: allowlist secret
                impersonate_user="sa",
                query="SELECT @@version",
                domain="contoso.local",
                windows_auth=True,
            )

        call_args = mock_run.call_args[0][0]
        command_str = " ".join(call_args)

        # Should contain impersonation SQL
        assert "EXECUTE AS LOGIN" in command_str
        assert "sa" in command_str
        assert "SELECT @@version" in command_str

    def test_mssql_impersonate_handles_error(self):
        """Test error handling in mssql_impersonate."""
        tools = LateralMovementTools()

        with patch("ares.tools.red.lateral_movement.run_tool") as mock_run:
            mock_run.side_effect = Exception("Impersonation failed")

            result = tools.mssql_impersonate(
                target="192.168.58.29",
                username="testuser",
                password="TestPass123",  # pragma: allowlist secret
                impersonate_user="sa",
                query="SELECT 1",
            )

        # Should return error message
        assert "failed" in result.lower()


class TestMSSQLXpCmdshellEnable:
    """Tests for mssql_xp_cmdshell_enable tool."""

    def test_mssql_xp_cmdshell_enable_succeeds(self):
        """Test successful xp_cmdshell enablement."""
        tools = LateralMovementTools()

        mock_stdout = """
SQL> EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
SQL> EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;
        """

        with patch("ares.tools.red.lateral_movement.run_tool") as mock_run:
            mock_run.return_value = (mock_stdout, "", 0)

            result = tools.mssql_xp_cmdshell_enable(
                target="192.168.58.30",
                username="sa",
                password="SaPass123",  # pragma: allowlist secret
            )

        # Should indicate success
        assert "xp_cmdshell" in result.lower() or "reconfigure" in result.lower()

    def test_mssql_xp_cmdshell_enable_handles_error(self):
        """Test error handling in xp_cmdshell enablement."""
        tools = LateralMovementTools()

        with patch("ares.tools.red.lateral_movement.run_tool") as mock_run:
            mock_run.side_effect = Exception("Permission denied")

            result = tools.mssql_xp_cmdshell_enable(
                target="192.168.58.31",
                username="testuser",
                password="TestPass123",  # pragma: allowlist secret
            )

        # Should return error message
        assert "failed" in result.lower()


class TestMSSQLIntegration:
    """Integration tests for MSSQL tool workflow."""

    def test_mssql_workflow_enum_then_impersonate(self):
        """Test the recommended workflow: enumerate impersonation targets, then impersonate."""
        tools = LateralMovementTools()

        # Step 1: Enumerate impersonation targets
        enum_stdout = """
ImpersonatableUser
----------------
sa
        """

        # Step 2: Impersonate and execute query
        impersonate_stdout = """
SQL> EXECUTE AS LOGIN = 'sa'
SQL> SELECT IS_SRVROLEMEMBER('sysadmin')
is_srvrolemember
----------------
1
        """

        with patch("ares.tools.red.lateral_movement.run_tool") as mock_run:
            # First call returns enumeration results
            mock_run.return_value = (enum_stdout, "", 0)

            enum_result = tools.mssql_enum_impersonation(
                target="192.168.58.32",
                username="testuser",
                password="TestPass123",  # pragma: allowlist secret
            )

            # Should find 'sa' as target
            assert "sa" in enum_result.lower()

            # Second call returns impersonation results
            mock_run.return_value = (impersonate_stdout, "", 0)

            impersonate_result = tools.mssql_impersonate(
                target="192.168.58.32",
                username="testuser",
                password="TestPass123",  # pragma: allowlist secret
                impersonate_user="sa",
                query="SELECT IS_SRVROLEMEMBER('sysadmin')",
            )

            # Should show sysadmin escalation
            assert "1" in impersonate_result or "is_srvrolemember" in impersonate_result.lower()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
