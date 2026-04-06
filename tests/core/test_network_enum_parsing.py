"""Tests for network enumeration parsing and state updates."""

from __future__ import annotations

from ares.core.models import SharedRedTeamState, Target
from ares.tools.red import NetworkEnumerationTools, reconnaissance


def test_enumerate_users_records_users_hosts_and_credentials(monkeypatch):
    tool = NetworkEnumerationTools()
    state = SharedRedTeamState(operation_id="op-test-enum")
    state.target = Target(ip="192.168.58.7", domain="contoso.local")
    tool.set_state(state)

    outputs = [
        (
            "netexec smb --users",
            "SMB 192.168.58.7 445 APP-SRV01 [*] Windows 10 / Server 2019 Build 17763 x64 (name:APP-SRV01) (domain:contoso.local) (signing:True) (SMBv1:None)\n"
            "SMB 192.168.58.7 445 APP-SRV01 danj 2026-01-13 21:03:31 0 Dan Jump (Password : P@ssw0rd123!)",
        ),
        (
            "rpcclient null session enumdomusers",
            "user:[adamb] rid:[0x45f]\nuser:[karimm] rid:[0x463]",
        ),
    ]

    monkeypatch.setattr(tool, "_run_user_enum_commands", lambda *_args, **_kwargs: outputs)

    tool.enumerate_users(
        target="192.168.58.7",
        username="svc",
        password="notreal",  # pragma: allowlist secret
        domain="contoso.local",
    )

    usernames = {user.username for user in state.users}
    assert {"adamb", "karimm", "danj"}.issubset(usernames)

    hostnames = {host.hostname for host in state.hosts}
    assert "app-srv01.contoso.local" in hostnames

    credentials = {(cred.username, cred.password, cred.domain) for cred in state.credentials}
    assert ("danj", "P@ssw0rd123!", "contoso.local") in credentials


def test_enumerate_users_uses_smb_domain_over_task_param(monkeypatch):
    """Domain from SMB output should take precedence over task parameter.

    Bug: When a recon task is dispatched with domain=contoso.local but
    the target is actually in corp.contoso.local, credentials should
    be recorded with the domain from the SMB output (corp.contoso.local),
    not the task parameter.
    """
    tool = NetworkEnumerationTools()
    state = SharedRedTeamState(operation_id="op-test-domain-priority")
    state.target = Target(ip="192.168.58.240", domain="contoso.local")
    tool.set_state(state)

    # SMB output shows domain:corp.contoso.local (the actual domain)
    outputs = [
        (
            "netexec smb --users",
            "SMB 192.168.58.240 445 DC01 [*] Windows 10 / Server 2019 Build 17763 x64 "
            "(name:DC01) (domain:corp.contoso.local) (signing:True) (SMBv1:None)\n"
            "SMB 192.168.58.240 445 DC01 karimm 2026-01-28 22:50:43 0 "
            "Karim Mahmoud (Password : C0ntr0ller#2024)",
        ),
    ]

    monkeypatch.setattr(tool, "_run_user_enum_commands", lambda *_args, **_kwargs: outputs)

    # Task is called with domain=contoso.local (wrong for this target)
    tool.enumerate_users(
        target="192.168.58.240",
        username="",
        password="",
        domain="contoso.local",  # Task parameter (should be overridden)
    )

    # Credential should use corp.contoso.local from SMB output, not contoso.local
    credentials = {(cred.username, cred.password, cred.domain) for cred in state.credentials}
    assert ("karimm", "C0ntr0ller#2024", "corp.contoso.local") in credentials

    # User should also have correct domain
    users = {(user.username, user.domain) for user in state.users}
    assert ("karimm", "corp.contoso.local") in users

    # Domain should be added to all_domains
    assert "corp.contoso.local" in state.all_domains


def test_smb_sweep_srv_lookup_and_smbclient_shares(monkeypatch):
    tool = NetworkEnumerationTools()
    state = SharedRedTeamState(operation_id="op-test-enum2")
    tool.set_state(state)

    def fake_run(cmd, timeout_seconds=300, target_role=None):
        if cmd[:2] == ["netexec", "smb"]:
            return (
                "SMB 192.168.58.240 445 DC01 [*] Windows Server 2019 Build 17763 x64 "
                "(name:DC01) (domain:contoso.local)\n",
                "",
                0,
            )
        if cmd[:2] == ["nslookup", "-type=srv"]:
            return (
                "_ldap._tcp.dc._msdcs.contoso.local\tservice = 0 100 389 dc01.contoso.local.\n",
                "",
                0,
            )
        if cmd[0] == "getent":
            return ("192.168.58.240 dc01.contoso.local\n", "", 0)
        if cmd[0] == "smbclient.py":
            return (
                "Sharename       Type      Comment\n"
                "---------       ----      -------\n"
                "SYSVOL          Disk      Logon server share\n"
                "NETLOGON        Disk      Logon server share\n",
                "",
                0,
            )
        return ("", "", 0)

    monkeypatch.setattr(reconnaissance, "run_tool", fake_run)

    tool.smb_sweep("192.168.58.240")
    tool.resolve_domain_controllers("contoso.local", "192.168.58.240")
    tool.smbclient_kerberos_shares("dc01.contoso.local")

    hostnames = {host.hostname for host in state.hosts}
    assert "dc01.contoso.local" in hostnames

    shares = {(share.host, share.name) for share in state.shares}
    assert ("dc01.contoso.local", "SYSVOL") in shares


def test_extract_users_filters_motd_garbage():
    """User extraction should filter out Kali MOTD garbage."""
    tool = NetworkEnumerationTools()

    # Simulate output that includes MOTD box-drawing characters
    outputs = [
        (
            "netexec smb --users",
            "SMB 192.168.58.1 445 DC [*] CONTOSO\\admin (SidTypeUser)\n"
            "┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓\n"
            "┃ This is a minimal installation of Kali Linux. ┃\n"
            "┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛\n"
            "SMB 192.168.58.1 445 DC CONTOSO\\john.doe (SidTypeUser)\n",
        ),
    ]

    users = tool._extract_users_from_outputs(outputs)

    # Valid users should be extracted
    assert "admin" in users
    assert "john.doe" in users

    # MOTD garbage should not be included
    for user in users:
        assert "┏" not in user
        assert "┃" not in user
        assert "minimal" not in user.lower()
        assert "kali" not in user.lower()


def test_extract_users_filters_motd_patterns():
    """User extraction should filter lines containing MOTD patterns."""
    tool = NetworkEnumerationTools()

    outputs = [
        (
            "rpcclient enumdomusers",
            "user:[administrator] rid:[0x1f4]\n"
            "message from kali developers\n"
            "user:[svc-sql] rid:[0x450]\n"
            "Visit kali.org for more information\n"
            "user:[jane.doe] rid:[0x451]\n",
        ),
    ]

    users = tool._extract_users_from_outputs(outputs)

    # Valid users should be extracted
    assert "administrator" in users
    assert "svc-sql" in users
    assert "jane.doe" in users

    # MOTD patterns should not create invalid users
    for user in users:
        assert "kali" not in user.lower()
        assert "message" not in user.lower()


def test_extract_users_filters_path_like_strings():
    """User extraction should filter path-like strings."""
    tool = NetworkEnumerationTools()

    outputs = [
        (
            "netexec smb --rid-brute",
            "SMB 192.168.58.1 445 DC CONTOSO\\bob_smith (SidTypeUser)\n"
            "/tmp/users.txt\n"
            "SMB 192.168.58.1 445 DC CONTOSO\\alice_jones (SidTypeUser)\n",
        ),
    ]

    users = tool._extract_users_from_outputs(outputs)

    # Valid users should be extracted
    assert "bob_smith" in users
    assert "alice_jones" in users

    # Path-like strings should not be included as users
    # (the /tmp/users.txt line is filtered by is_motd_line)
    for user in users:
        assert "/" not in user
        assert "tmp" not in user.lower()


def test_extract_users_handles_mixed_garbage_and_valid():
    """User extraction should correctly handle mixed valid and garbage content."""
    tool = NetworkEnumerationTools()

    outputs = [
        (
            "netexec smb --users",
            "SMB 192.168.58.1 445 DC [*] CONTOSO\\admin (SidTypeUser)\n",
        ),
        (
            "kali motd pollution",
            "┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓\n"
            "┃ message from kali developers about minimal     ┃\n"
            "┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛\n",
        ),
        (
            "rpcclient enumdomusers",
            "user:[svc-web] rid:[0x452]\n",
        ),
    ]

    users = tool._extract_users_from_outputs(outputs)

    # Should extract valid users from multiple sources
    assert "admin" in users
    assert "svc-web" in users

    # Should have filtered garbage
    assert len(users) == 2


def test_add_user_validates_against_motd_garbage():
    """The _add_user helper should reject MOTD garbage."""
    # Test with valid usernames
    users: set[str] = set()

    def _add_user(user: str) -> None:
        from ares.tools.red.common import is_motd_garbage

        if not user or user.lower() == "anonymous":
            return
        if is_motd_garbage(user):
            return
        users.add(user)

    # Valid usernames should be added
    _add_user("administrator")
    _add_user("john.doe")
    _add_user("svc-sql")

    # MOTD garbage should be rejected
    _add_user("┏━━━━━━━")
    _add_user("message from kali")
    _add_user("/tmp/users.txt")
    _add_user("")
    _add_user("   ")

    assert users == {"administrator", "john.doe", "svc-sql"}


class TestFilterEnumOutputNoise:
    """Tests for _filter_enum_output_noise that strips command-not-found noise."""

    def test_all_tools_failed_returns_concise_message(self):
        """When every sub-command produces only noise, return a short failure summary."""
        from ares.tools.red.reconnaissance import _filter_enum_output_noise

        outputs = [
            ("netexec smb --users", "bash: line 1: netexec: command not found\n"),
            ("nmap port 445", "bash: line 1: nmap: command not found\n"),
            ("nmap smb-enum-users", "bash: line 1: nmap: command not found\n"),
            ("netexec smb --rid-brute", "bash: line 1: netexec: command not found\n"),
        ]
        combined = "\n\n".join(f"===== {label} =====\n{content}" for label, content in outputs)

        result = _filter_enum_output_noise(combined, outputs)

        assert "command not found" not in result
        assert "tools not available" in result
        assert "netexec" in result
        assert "nmap" in result

    def test_partial_success_strips_noise_keeps_results(self):
        """When some tools succeed, strip noise but keep good output."""
        from ares.tools.red.reconnaissance import _filter_enum_output_noise

        good_output = "user:[administrator] rid:[0x1f4]\nuser:[svc-sql] rid:[0x450]"
        outputs = [
            ("netexec smb --users", "bash: line 1: netexec: command not found\n"),
            ("rpcclient null session enumdomusers", good_output),
            ("nmap port 445", "bash: line 1: nmap: command not found\n"),
        ]
        combined = "\n\n".join(f"===== {label} =====\n{content}" for label, content in outputs)

        result = _filter_enum_output_noise(combined, outputs)

        # Noise lines stripped
        assert "command not found" not in result
        # Good output preserved
        assert "administrator" in result
        assert "svc-sql" in result
        # Note about unavailable tools appended
        assert "some enumeration tools unavailable" in result
        assert "rpcclient" in result  # listed as successful

    def test_no_noise_passes_through_unchanged(self):
        """When there is no noise, output passes through without modification."""
        from ares.tools.red.reconnaissance import _filter_enum_output_noise

        good_output = (
            "SMB 192.168.58.10 445 DC01 [*] Windows Server 2019\n"
            "SMB 192.168.58.10 445 DC01 admin 2026-01-01"
        )
        outputs = [("netexec smb --users", good_output)]
        combined = f"===== netexec smb --users =====\n{good_output}"

        result = _filter_enum_output_noise(combined, outputs)

        assert result == combined
        assert "unavailable" not in result

    def test_empty_output_returns_empty(self):
        """Empty output should pass through."""
        from ares.tools.red.reconnaissance import _filter_enum_output_noise

        result = _filter_enum_output_noise("", [])
        assert result == ""

    def test_no_such_file_filtered(self):
        """'No such file or directory' lines should also be filtered."""
        from ares.tools.red.reconnaissance import _filter_enum_output_noise

        outputs = [
            ("netexec smb --users", "bash: netexec: No such file or directory\n"),
        ]
        combined = "===== netexec smb --users =====\nbash: netexec: No such file or directory"

        result = _filter_enum_output_noise(combined, outputs)

        assert "No such file or directory" not in result
        assert "tools not available" in result

    def test_enumerate_users_filters_noise_end_to_end(self, monkeypatch):
        """End-to-end: enumerate_users should not return command-not-found noise."""
        from ares.tools.red.reconnaissance import NetworkEnumerationTools

        tool = NetworkEnumerationTools()
        state = SharedRedTeamState(operation_id="op-test-noise-filter")
        state.target = Target(ip="192.168.58.10", domain="contoso.local")
        tool.set_state(state)

        outputs = [
            ("netexec smb --users", "bash: line 1: netexec: command not found\n"),
            (
                "rpcclient null session enumdomusers",
                "user:[administrator] rid:[0x1f4]\nuser:[svc-web] rid:[0x452]",
            ),
            ("nmap port 445", "bash: line 1: nmap: command not found\n"),
            ("nmap smb-enum-users", "bash: line 1: nmap: command not found\n"),
            ("netexec smb --rid-brute", "bash: line 1: netexec: command not found\n"),
        ]

        monkeypatch.setattr(tool, "_run_user_enum_commands", lambda *_a, **_kw: outputs)

        result = tool.enumerate_users(
            target="192.168.58.10",
            username="svc",
            password="notreal",  # pragma: allowlist secret
            domain="contoso.local",
        )

        assert "command not found" not in result
        assert "administrator" in result


class TestNmapParsingHostnameExtraction:
    """Test hostname extraction from nmap Service Info line."""

    def test_extracts_hostname_from_service_info_line(self, monkeypatch):
        """Host should be extracted from 'Service Info: Host: HOSTNAME; OS: ...'"""
        tool = NetworkEnumerationTools()
        state = SharedRedTeamState(operation_id="op-nmap-hostname")
        state.target = Target(ip="192.168.58.10", domain="contoso.local")
        tool.set_state(state)

        # Real nmap output format with Service Info line
        nmap_output = """Starting Nmap 7.94 ( https://nmap.org )
Nmap scan report for 192.168.58.10
Host is up (0.0023s latency).

PORT     STATE SERVICE
88/tcp   open  kerberos-sec
135/tcp  open  msrpc
389/tcp  open  ldap
445/tcp  open  microsoft-ds
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Nmap done: 1 IP address (1 host up)"""

        def fake_run(cmd, timeout_seconds=300, target_role=None):
            if "nmap" in cmd[0]:
                return (nmap_output, "", 0)
            return ("", "", 0)

        monkeypatch.setattr(reconnaissance, "run_tool", fake_run)

        result = tool.nmap_scan("192.168.58.10")

        # Verify hostname was extracted from Service Info
        hosts = result.get("discovered_hosts", [])
        assert len(hosts) == 1
        # Should be dc01 (lowercased), without FQDN since no domain in this output
        assert hosts[0]["hostname"].lower() == "dc01"
        assert hosts[0]["os"] == "Windows"

    def test_service_info_hostname_overrides_dns_reverse_lookup(self, monkeypatch):
        """Service Info hostname should override DNS reverse lookup name."""
        tool = NetworkEnumerationTools()
        state = SharedRedTeamState(operation_id="op-nmap-override")
        state.target = Target(ip="192.168.58.10", domain="contoso.local")
        tool.set_state(state)

        # When nmap resolves DNS, it shows hostname (IP) format
        # Service Info should override this ugly DNS name
        nmap_output = """Starting Nmap 7.94 ( https://nmap.org )
Nmap scan report for ip-192-168-58-10.compute.internal (192.168.58.10)
Host is up (0.0023s latency).

PORT     STATE SERVICE
88/tcp   open  kerberos-sec
389/tcp  open  ldap
445/tcp  open  microsoft-ds
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Nmap done: 1 IP address (1 host up)"""

        def fake_run(cmd, timeout_seconds=300, target_role=None):
            if "nmap" in cmd[0]:
                return (nmap_output, "", 0)
            return ("", "", 0)

        monkeypatch.setattr(reconnaissance, "run_tool", fake_run)

        result = tool.nmap_scan("192.168.58.10")

        hosts = result.get("discovered_hosts", [])
        assert len(hosts) == 1
        # Should use DC01 from Service Info, not the ugly DNS name
        assert "compute.internal" not in hosts[0]["hostname"]
        assert hosts[0]["hostname"].lower() == "dc01"


class TestNmapParsingOSExtraction:
    """Test OS extraction from nmap Service Info line."""

    def test_extracts_os_from_service_info(self, monkeypatch):
        """OS should be extracted from 'Service Info: Host: X; OS: Windows'"""
        tool = NetworkEnumerationTools()
        state = SharedRedTeamState(operation_id="op-nmap-os")
        state.target = Target(ip="192.168.58.20", domain="contoso.local")
        tool.set_state(state)

        nmap_output = """Nmap scan report for 192.168.58.20
Host is up.

PORT     STATE SERVICE
445/tcp  open  microsoft-ds
Service Info: Host: SQL01; OS: Windows; CPE: cpe:/o:microsoft:windows

Nmap done: 1 IP address (1 host up)"""

        def fake_run(cmd, timeout_seconds=300, target_role=None):
            if "nmap" in cmd[0]:
                return (nmap_output, "", 0)
            return ("", "", 0)

        monkeypatch.setattr(reconnaissance, "run_tool", fake_run)

        result = tool.nmap_scan("192.168.58.20")

        hosts = result.get("discovered_hosts", [])
        assert len(hosts) == 1
        assert hosts[0]["os"] == "Windows"

    def test_os_defaults_to_unknown_when_not_present(self, monkeypatch):
        """OS should default to 'Unknown' when Service Info has no OS field."""
        tool = NetworkEnumerationTools()
        state = SharedRedTeamState(operation_id="op-nmap-no-os")
        state.target = Target(ip="192.168.58.30", domain="contoso.local")
        tool.set_state(state)

        # Service Info without OS field
        nmap_output = """Nmap scan report for 192.168.58.30
Host is up.

PORT     STATE SERVICE
22/tcp   open  ssh
Service Info: Host: WEB01

Nmap done: 1 IP address (1 host up)"""

        def fake_run(cmd, timeout_seconds=300, target_role=None):
            if "nmap" in cmd[0]:
                return (nmap_output, "", 0)
            return ("", "", 0)

        monkeypatch.setattr(reconnaissance, "run_tool", fake_run)

        result = tool.nmap_scan("192.168.58.30")

        hosts = result.get("discovered_hosts", [])
        assert len(hosts) == 1
        assert hosts[0]["os"] == "Unknown"


class TestNmapParsingDomainExtraction:
    """Test domain extraction from LDAP service output."""

    def test_extracts_domain_from_ldap_line(self, monkeypatch):
        """Domain should be extracted from '(Domain: contoso.local, Site: ...)'"""
        tool = NetworkEnumerationTools()
        state = SharedRedTeamState(operation_id="op-nmap-domain")
        state.target = Target(ip="192.168.58.10", domain="contoso.local")
        tool.set_state(state)

        # Real nmap output with LDAP domain info (from version detection)
        nmap_output = """Nmap scan report for 192.168.58.10
Host is up.

PORT     STATE SERVICE       VERSION
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: contoso.local, Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds  Windows Server 2019 Build 17763
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Nmap done: 1 IP address (1 host up)"""

        def fake_run(cmd, timeout_seconds=300, target_role=None):
            if "nmap" in cmd[0]:
                return (nmap_output, "", 0)
            return ("", "", 0)

        monkeypatch.setattr(reconnaissance, "run_tool", fake_run)

        result = tool.nmap_scan("192.168.58.10")

        hosts = result.get("discovered_hosts", [])
        assert len(hosts) == 1
        # Hostname is short name from Service Info (nmap's Domain: field is NOT used
        # for FQDN construction because it reports forest root, not actual domain
        # for child domain DCs). The correct FQDN is built later by netexec SMB.
        assert hosts[0]["hostname"] == "DC01"


class TestNmapParsingFQDNBuilding:
    """Test FQDN construction from hostname + domain.

    NOTE: nmap's (Domain:...) from LDAP reports the forest root domain, not the
    actual domain a DC belongs to. For child domain DCs this produces wrong FQDNs
    (e.g., ws01.contoso.local instead of ws01.corp.contoso.local).
    Therefore we do NOT join hostname + domain from nmap. The correct FQDN is provided
    by netexec SMB and merged via add_host() hostname upgrade logic.
    """

    def test_keeps_short_hostname_from_nmap(self, monkeypatch):
        """Should keep short hostname from nmap (FQDN built later by netexec)."""
        tool = NetworkEnumerationTools()
        state = SharedRedTeamState(operation_id="op-nmap-fqdn")
        state.target = Target(ip="192.168.58.10", domain="contoso.local")
        tool.set_state(state)

        nmap_output = """Nmap scan report for 192.168.58.10
Host is up.

PORT     STATE SERVICE       VERSION
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: contoso.local, Site: Default)
445/tcp  open  microsoft-ds
Service Info: Host: DC01; OS: Windows

Nmap done: 1 IP address (1 host up)"""

        def fake_run(cmd, timeout_seconds=300, target_role=None):
            if "nmap" in cmd[0]:
                return (nmap_output, "", 0)
            return ("", "", 0)

        monkeypatch.setattr(reconnaissance, "run_tool", fake_run)

        result = tool.nmap_scan("192.168.58.10")

        hosts = result.get("discovered_hosts", [])
        assert len(hosts) == 1
        # Short hostname only - nmap's Domain: field is not used for FQDN construction
        assert hosts[0]["hostname"] == "DC01"

    def test_does_not_double_domain_if_hostname_already_fqdn(self, monkeypatch):
        """Should not append domain if hostname already contains a dot."""
        tool = NetworkEnumerationTools()
        state = SharedRedTeamState(operation_id="op-nmap-no-double")
        state.target = Target(ip="192.168.58.10", domain="contoso.local")
        tool.set_state(state)

        # When nmap resolves via DNS, hostname may already be FQDN
        nmap_output = """Nmap scan report for dc01.contoso.local (192.168.58.10)
Host is up.

PORT     STATE SERVICE
445/tcp  open  microsoft-ds
389/tcp  open  ldap          (Domain: contoso.local, Site: Default)

Nmap done: 1 IP address (1 host up)"""

        def fake_run(cmd, timeout_seconds=300, target_role=None):
            if "nmap" in cmd[0]:
                return (nmap_output, "", 0)
            return ("", "", 0)

        monkeypatch.setattr(reconnaissance, "run_tool", fake_run)

        result = tool.nmap_scan("192.168.58.10")

        hosts = result.get("discovered_hosts", [])
        assert len(hosts) == 1
        # Should NOT become dc01.contoso.local.contoso.local
        assert hosts[0]["hostname"] == "dc01.contoso.local"
        assert hosts[0]["hostname"].count("contoso.local") == 1

    def test_hostname_without_domain_stays_short(self, monkeypatch):
        """If no domain is found, hostname should remain as-is."""
        tool = NetworkEnumerationTools()
        state = SharedRedTeamState(operation_id="op-nmap-no-domain")
        state.target = Target(ip="192.168.58.50", domain="contoso.local")
        tool.set_state(state)

        # Non-DC host without LDAP service - no domain info
        nmap_output = """Nmap scan report for 192.168.58.50
Host is up.

PORT     STATE SERVICE
445/tcp  open  microsoft-ds
3389/tcp open  ms-wbt-server
Service Info: Host: WS01; OS: Windows

Nmap done: 1 IP address (1 host up)"""

        def fake_run(cmd, timeout_seconds=300, target_role=None):
            if "nmap" in cmd[0]:
                return (nmap_output, "", 0)
            return ("", "", 0)

        monkeypatch.setattr(reconnaissance, "run_tool", fake_run)

        result = tool.nmap_scan("192.168.58.50")

        hosts = result.get("discovered_hosts", [])
        assert len(hosts) == 1
        # Without domain, stays as short name
        assert hosts[0]["hostname"].lower() == "ws01"


class TestNmapParsingDCDetection:
    """Test domain controller detection via LDAP + Kerberos services."""

    def test_detects_dc_with_ldap_and_kerberos(self, monkeypatch):
        """Host with LDAP + Kerberos services should be marked as DC."""
        tool = NetworkEnumerationTools()
        state = SharedRedTeamState(operation_id="op-nmap-dc")
        state.target = Target(ip="192.168.58.10", domain="contoso.local")
        tool.set_state(state)

        nmap_output = """Nmap scan report for 192.168.58.10
Host is up.

PORT     STATE SERVICE
53/tcp   open  domain
88/tcp   open  kerberos-sec
135/tcp  open  msrpc
389/tcp  open  ldap
445/tcp  open  microsoft-ds
464/tcp  open  kpasswd5
636/tcp  open  ldapssl
Service Info: Host: DC01; OS: Windows

Nmap done: 1 IP address (1 host up)"""

        def fake_run(cmd, timeout_seconds=300, target_role=None):
            if "nmap" in cmd[0]:
                return (nmap_output, "", 0)
            return ("", "", 0)

        monkeypatch.setattr(reconnaissance, "run_tool", fake_run)

        result = tool.nmap_scan("192.168.58.10")

        hosts = result.get("discovered_hosts", [])
        assert len(hosts) == 1
        assert "AD DC" in hosts[0]["roles"]

    def test_does_not_detect_dc_with_only_ldap(self, monkeypatch):
        """Host with only LDAP (no Kerberos) should NOT be marked as DC."""
        tool = NetworkEnumerationTools()
        state = SharedRedTeamState(operation_id="op-nmap-no-dc-ldap")
        state.target = Target(ip="192.168.58.25", domain="contoso.local")
        tool.set_state(state)

        # LDAP-enabled server that is not a DC (e.g., LDAP proxy)
        nmap_output = """Nmap scan report for 192.168.58.25
Host is up.

PORT     STATE SERVICE
389/tcp  open  ldap
636/tcp  open  ldapssl
Service Info: Host: LDAP01; OS: Windows

Nmap done: 1 IP address (1 host up)"""

        def fake_run(cmd, timeout_seconds=300, target_role=None):
            if "nmap" in cmd[0]:
                return (nmap_output, "", 0)
            return ("", "", 0)

        monkeypatch.setattr(reconnaissance, "run_tool", fake_run)

        result = tool.nmap_scan("192.168.58.25")

        hosts = result.get("discovered_hosts", [])
        assert len(hosts) == 1
        assert "AD DC" not in hosts[0]["roles"]

    def test_does_not_detect_dc_with_only_kerberos(self, monkeypatch):
        """Host with only Kerberos (no LDAP) should NOT be marked as DC."""
        tool = NetworkEnumerationTools()
        state = SharedRedTeamState(operation_id="op-nmap-no-dc-kerb")
        state.target = Target(ip="192.168.58.26", domain="contoso.local")
        tool.set_state(state)

        # Kerberos KDC that is not a full DC
        nmap_output = """Nmap scan report for 192.168.58.26
Host is up.

PORT     STATE SERVICE
88/tcp   open  kerberos-sec
464/tcp  open  kpasswd5
Service Info: Host: KDC01; OS: Windows

Nmap done: 1 IP address (1 host up)"""

        def fake_run(cmd, timeout_seconds=300, target_role=None):
            if "nmap" in cmd[0]:
                return (nmap_output, "", 0)
            return ("", "", 0)

        monkeypatch.setattr(reconnaissance, "run_tool", fake_run)

        result = tool.nmap_scan("192.168.58.26")

        hosts = result.get("discovered_hosts", [])
        assert len(hosts) == 1
        assert "AD DC" not in hosts[0]["roles"]


class TestNmapParsingMultipleHosts:
    """Test parsing multiple hosts from single nmap output."""

    def test_parses_multiple_hosts(self, monkeypatch):
        """Should correctly parse multiple hosts in a single nmap scan."""
        tool = NetworkEnumerationTools()
        state = SharedRedTeamState(operation_id="op-nmap-multi")
        state.target = Target(ip="192.168.58.10", domain="contoso.local")
        tool.set_state(state)

        # Scan of multiple hosts with different characteristics
        nmap_output = """Starting Nmap 7.94 ( https://nmap.org )
Nmap scan report for 192.168.58.10
Host is up.

PORT     STATE SERVICE
88/tcp   open  kerberos-sec
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: contoso.local, Site: Default)
445/tcp  open  microsoft-ds
Service Info: Host: DC01; OS: Windows

Nmap scan report for 192.168.58.20
Host is up.

PORT     STATE SERVICE
445/tcp  open  microsoft-ds
1433/tcp open  ms-sql-s
Service Info: Host: SQL01; OS: Windows

Nmap scan report for 192.168.58.30
Host is up.

PORT     STATE SERVICE
80/tcp   open  http
443/tcp  open  https
Service Info: Host: WEB01; OS: Windows

Nmap done: 3 IP addresses (3 hosts up)"""

        def fake_run(cmd, timeout_seconds=300, target_role=None):
            if "nmap" in cmd[0]:
                return (nmap_output, "", 0)
            return ("", "", 0)

        monkeypatch.setattr(reconnaissance, "run_tool", fake_run)

        result = tool.nmap_scan("192.168.58.10 192.168.58.20 192.168.58.30")

        hosts = result.get("discovered_hosts", [])
        assert len(hosts) == 3

        # Find each host by IP
        hosts_by_ip = {h["ip"]: h for h in hosts}

        # DC01: should be marked as DC (short hostname - FQDN built later by netexec)
        dc = hosts_by_ip["192.168.58.10"]
        assert dc["hostname"] == "DC01"
        assert dc["os"] == "Windows"
        assert "AD DC" in dc["roles"]

        # SQL01: not a DC, no FQDN (no domain in its section)
        sql = hosts_by_ip["192.168.58.20"]
        assert sql["hostname"].lower() == "sql01"
        assert sql["os"] == "Windows"
        assert "AD DC" not in sql["roles"]

        # WEB01: not a DC, no FQDN
        web = hosts_by_ip["192.168.58.30"]
        assert web["hostname"].lower() == "web01"
        assert web["os"] == "Windows"
        assert "AD DC" not in web["roles"]


class TestNmapParsingServicesExtraction:
    """Test service extraction from nmap port lines."""

    def test_extracts_all_open_services(self, monkeypatch):
        """Should extract all open ports/services."""
        tool = NetworkEnumerationTools()
        state = SharedRedTeamState(operation_id="op-nmap-services")
        state.target = Target(ip="192.168.58.10", domain="contoso.local")
        tool.set_state(state)

        nmap_output = """Nmap scan report for 192.168.58.10
Host is up.

PORT     STATE SERVICE
53/tcp   open  domain
88/tcp   open  kerberos-sec
135/tcp  open  msrpc
389/tcp  open  ldap
445/tcp  open  microsoft-ds
464/tcp  open  kpasswd5
636/tcp  open  ldapssl
3268/tcp open  globalcatLDAP
3389/tcp open  ms-wbt-server
Service Info: Host: DC01; OS: Windows

Nmap done: 1 IP address (1 host up)"""

        def fake_run(cmd, timeout_seconds=300, target_role=None):
            if "nmap" in cmd[0]:
                return (nmap_output, "", 0)
            return ("", "", 0)

        monkeypatch.setattr(reconnaissance, "run_tool", fake_run)

        result = tool.nmap_scan("192.168.58.10")

        hosts = result.get("discovered_hosts", [])
        assert len(hosts) == 1

        services = hosts[0]["services"]
        # Should have all 9 services
        assert len(services) == 9

        # Check specific services are present
        service_strs = " ".join(services).lower()
        assert "88/tcp kerberos" in service_strs
        assert "389/tcp ldap" in service_strs
        assert "445/tcp microsoft-ds" in service_strs
        assert "3389/tcp ms-wbt-server" in service_strs


class TestNmapParsingEdgeCases:
    """Test edge cases in nmap parsing."""

    def test_handles_empty_output(self, monkeypatch):
        """Should handle empty nmap output gracefully."""
        tool = NetworkEnumerationTools()
        state = SharedRedTeamState(operation_id="op-nmap-empty")
        state.target = Target(ip="192.168.58.10", domain="contoso.local")
        tool.set_state(state)

        nmap_output = """Starting Nmap 7.94 ( https://nmap.org )
Nmap done: 0 IP addresses (0 hosts up)"""

        def fake_run(cmd, timeout_seconds=300, target_role=None):
            if "nmap" in cmd[0]:
                return (nmap_output, "", 0)
            return ("", "", 0)

        monkeypatch.setattr(reconnaissance, "run_tool", fake_run)

        result = tool.nmap_scan("192.168.58.10")

        hosts = result.get("discovered_hosts", [])
        assert len(hosts) == 0

    def test_handles_host_with_no_services(self, monkeypatch):
        """Should handle hosts with no open ports."""
        tool = NetworkEnumerationTools()
        state = SharedRedTeamState(operation_id="op-nmap-no-ports")
        state.target = Target(ip="192.168.58.99", domain="contoso.local")
        tool.set_state(state)

        nmap_output = """Nmap scan report for 192.168.58.99
Host is up.

All 100 scanned ports on 192.168.58.99 are closed

Nmap done: 1 IP address (1 host up)"""

        def fake_run(cmd, timeout_seconds=300, target_role=None):
            if "nmap" in cmd[0]:
                return (nmap_output, "", 0)
            return ("", "", 0)

        monkeypatch.setattr(reconnaissance, "run_tool", fake_run)

        result = tool.nmap_scan("192.168.58.99")

        hosts = result.get("discovered_hosts", [])
        # Host with no open ports should still be recorded
        assert len(hosts) == 1
        assert hosts[0]["ip"] == "192.168.58.99"
        assert hosts[0]["services"] == []

    def test_handles_ip_only_without_hostname(self, monkeypatch):
        """Should handle hosts where no hostname could be determined."""
        tool = NetworkEnumerationTools()
        state = SharedRedTeamState(operation_id="op-nmap-ip-only")
        state.target = Target(ip="192.168.58.77", domain="contoso.local")
        tool.set_state(state)

        # No Service Info, no DNS resolution
        nmap_output = """Nmap scan report for 192.168.58.77
Host is up.

PORT     STATE SERVICE
445/tcp  open  microsoft-ds

Nmap done: 1 IP address (1 host up)"""

        def fake_run(cmd, timeout_seconds=300, target_role=None):
            if "nmap" in cmd[0]:
                return (nmap_output, "", 0)
            return ("", "", 0)

        monkeypatch.setattr(reconnaissance, "run_tool", fake_run)

        result = tool.nmap_scan("192.168.58.77")

        hosts = result.get("discovered_hosts", [])
        assert len(hosts) == 1
        assert hosts[0]["ip"] == "192.168.58.77"
        # Hostname should be empty or the IP if none was found
        assert hosts[0]["hostname"] in ["", "192.168.58.77"]

    def test_handles_fabrikam_secondary_domain(self, monkeypatch):
        """Should correctly parse secondary domain (fabrikam.local)."""
        tool = NetworkEnumerationTools()
        state = SharedRedTeamState(operation_id="op-nmap-fabrikam")
        state.target = Target(ip="192.168.58.100", domain="fabrikam.local")
        tool.set_state(state)

        nmap_output = """Nmap scan report for 192.168.58.100
Host is up.

PORT     STATE SERVICE
88/tcp   open  kerberos-sec
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: fabrikam.local, Site: Default)
445/tcp  open  microsoft-ds
Service Info: Host: DC02; OS: Windows

Nmap done: 1 IP address (1 host up)"""

        def fake_run(cmd, timeout_seconds=300, target_role=None):
            if "nmap" in cmd[0]:
                return (nmap_output, "", 0)
            return ("", "", 0)

        monkeypatch.setattr(reconnaissance, "run_tool", fake_run)

        result = tool.nmap_scan("192.168.58.100")

        hosts = result.get("discovered_hosts", [])
        assert len(hosts) == 1
        # Short hostname only - FQDN built later by netexec
        assert hosts[0]["hostname"] == "DC02"
        assert hosts[0]["os"] == "Windows"
        assert "AD DC" in hosts[0]["roles"]

    def test_handles_child_domain(self, monkeypatch):
        """Should keep short hostname for child domain DC (FQDN built later by netexec)."""
        tool = NetworkEnumerationTools()
        state = SharedRedTeamState(operation_id="op-nmap-child")
        state.target = Target(ip="192.168.58.110", domain="child.contoso.local")
        tool.set_state(state)

        nmap_output = """Nmap scan report for 192.168.58.110
Host is up.

PORT     STATE SERVICE
88/tcp   open  kerberos-sec
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: child.contoso.local, Site: ChildSite)
445/tcp  open  microsoft-ds
Service Info: Host: CHILDDC; OS: Windows

Nmap done: 1 IP address (1 host up)"""

        def fake_run(cmd, timeout_seconds=300, target_role=None):
            if "nmap" in cmd[0]:
                return (nmap_output, "", 0)
            return ("", "", 0)

        monkeypatch.setattr(reconnaissance, "run_tool", fake_run)

        result = tool.nmap_scan("192.168.58.110")

        hosts = result.get("discovered_hosts", [])
        assert len(hosts) == 1
        # Short hostname - nmap's Domain: field not used for FQDN
        assert hosts[0]["hostname"] == "CHILDDC"
        assert "AD DC" in hosts[0]["roles"]
