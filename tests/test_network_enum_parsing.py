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
