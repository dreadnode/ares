"""Tests for network enumeration parsing and state updates."""

from __future__ import annotations

from ares.core.models import SharedRedTeamState, Target
from ares.tools.red import NetworkEnumerationTools, reconnaissance


def test_enumerate_users_records_users_hosts_and_credentials(monkeypatch):
    tool = NetworkEnumerationTools()
    state = SharedRedTeamState(operation_id="op-test-enum")
    state.target = Target(ip="10.9.8.7", domain="contoso.local")
    tool.set_state(state)

    outputs = [
        (
            "netexec smb --users",
            "SMB 10.9.8.7 445 APP-SRV01 [*] Windows 10 / Server 2019 Build 17763 x64 (name:APP-SRV01) (domain:contoso.local) (signing:True) (SMBv1:None)\n"
            "SMB 10.9.8.7 445 APP-SRV01 danj 2026-01-13 21:03:31 0 Dan Jump (Password : P@ssw0rd123!)",
        ),
        (
            "rpcclient null session enumdomusers",
            "user:[adamb] rid:[0x45f]\nuser:[karimm] rid:[0x463]",
        ),
    ]

    monkeypatch.setattr(tool, "_run_user_enum_commands", lambda *_args, **_kwargs: outputs)

    tool.enumerate_users(
        target="10.9.8.7",
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

    Bug: When a recon task is dispatched with domain=sevenkingdoms.local but
    the target is actually in north.sevenkingdoms.local, credentials should
    be recorded with the domain from the SMB output (north.sevenkingdoms.local),
    not the task parameter.
    """
    tool = NetworkEnumerationTools()
    state = SharedRedTeamState(operation_id="op-test-domain-priority")
    state.target = Target(ip="10.1.2.240", domain="sevenkingdoms.local")
    tool.set_state(state)

    # SMB output shows domain:north.sevenkingdoms.local (the actual domain)
    outputs = [
        (
            "netexec smb --users",
            "SMB 10.1.2.240 445 WINTERFELL [*] Windows 10 / Server 2019 Build 17763 x64 "
            "(name:WINTERFELL) (domain:north.sevenkingdoms.local) (signing:True) (SMBv1:None)\n"
            "SMB 10.1.2.240 445 WINTERFELL samwell.tarly 2026-01-28 22:50:43 0 "
            "Samwell Tarly (Password : Heartsbane)",
        ),
    ]

    monkeypatch.setattr(tool, "_run_user_enum_commands", lambda *_args, **_kwargs: outputs)

    # Task is called with domain=sevenkingdoms.local (wrong for this target)
    tool.enumerate_users(
        target="10.1.2.240",
        username="",
        password="",
        domain="sevenkingdoms.local",  # Task parameter (should be overridden)
    )

    # Credential should use north.sevenkingdoms.local from SMB output, not sevenkingdoms.local
    credentials = {(cred.username, cred.password, cred.domain) for cred in state.credentials}
    assert ("samwell.tarly", "Heartsbane", "north.sevenkingdoms.local") in credentials

    # User should also have correct domain
    users = {(user.username, user.domain) for user in state.users}
    assert ("samwell.tarly", "north.sevenkingdoms.local") in users

    # Domain should be added to all_domains
    assert "north.sevenkingdoms.local" in state.all_domains


def test_smb_sweep_srv_lookup_and_smbclient_shares(monkeypatch):
    tool = NetworkEnumerationTools()
    state = SharedRedTeamState(operation_id="op-test-enum2")
    tool.set_state(state)

    def fake_run(cmd, timeout_seconds=300, target_role=None):
        if cmd[:2] == ["netexec", "smb"]:
            return (
                "SMB 10.1.2.240 445 DC01 [*] Windows Server 2019 Build 17763 x64 "
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
            return ("10.1.2.240 dc01.contoso.local\n", "", 0)
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

    tool.smb_sweep("10.1.2.240")
    tool.resolve_domain_controllers("contoso.local", "10.1.2.240")
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
            "SMB 192.168.56.1 445 DC [*] CONTOSO\\admin (SidTypeUser)\n"
            "┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓\n"
            "┃ This is a minimal installation of Kali Linux. ┃\n"
            "┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛\n"
            "SMB 192.168.56.1 445 DC CONTOSO\\john.doe (SidTypeUser)\n",
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
            "SMB 192.168.56.1 445 DC CONTOSO\\bob_smith (SidTypeUser)\n"
            "/tmp/users.txt\n"
            "SMB 192.168.56.1 445 DC CONTOSO\\alice_jones (SidTypeUser)\n",
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
            "SMB 192.168.56.1 445 DC [*] CONTOSO\\admin (SidTypeUser)\n",
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

        if not user or user.lower() in ("anonymous",):
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
