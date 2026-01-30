"""Tests for command output parsing in the dispatcher."""

from __future__ import annotations

import pytest

from ares.core.dispatcher import RedTeamDispatcher
from ares.core.models import Host, SharedRedTeamState, Target, TaskInfo


@pytest.mark.asyncio
async def test_command_output_parses_users_hosts_and_passwords_from_output():
    dispatcher = RedTeamDispatcher()
    dispatcher._shared_state = SharedRedTeamState(operation_id="op-test-parse")
    dispatcher._shared_state.target = Target(
        ip="192.168.58.7",
        domain="contoso.local",
    )

    task_id = "command_parse_test"
    dispatcher._shared_state.pending_tasks[task_id] = TaskInfo(
        task_id=task_id,
        task_type="command",
        assigned_agent="recon",
    )

    output = """
SMB                      192.168.58.7        445    APP-SRV01        [*] Windows 10 / Server 2019 Build 17763 x64 (name:APP-SRV01) (domain:contoso.local) (signing:True) (SMBv1:None)
SMB                      192.168.58.7        445    APP-SRV01        danj                  2026-01-13 21:03:31 0       Dan Jump (Password : P@ssw0rd123!)
user:[adamb] rid:[0x45f]
Account: danj Name: (null) Desc: Dan Jump (Password : P@ssw0rd123!)
"""

    await dispatcher.complete_task(
        task_id=task_id,
        success=True,
        result={"output": output},
        source_agent="recon",
    )

    hostnames = {host.hostname for host in dispatcher.shared_state.all_hosts}
    assert "app-srv01.contoso.local" in hostnames

    usernames = {user.username for user in dispatcher.shared_state.all_users}
    assert "adamb" in usernames
    assert "danj" in usernames

    credentials = {
        (cred.username, cred.password, cred.domain)
        for cred in dispatcher.shared_state.all_credentials
    }
    assert ("danj", "P@ssw0rd123!", "contoso.local") in credentials


def test_add_host_prefers_fqdn_over_ptr_hostname():
    state = SharedRedTeamState(operation_id="op-test-hosts")

    state.add_host(
        Host(
            ip="192.168.58.10",
            hostname="IP-10-1-2-10.us-west-2.compute.internal",
            os="Unknown",
            roles=[],
            services=[],
        )
    )
    state.add_host(
        Host(
            ip="192.168.58.10",
            hostname="dc01.corp.contoso.local",
            os="Windows Server 2019",
            roles=[],
            services=[],
        )
    )

    assert state.all_hosts[0].hostname == "dc01.corp.contoso.local"
    assert state.all_hosts[0].os == "Windows Server 2019"


@pytest.mark.asyncio
async def test_recon_output_parses_users_hosts_and_passwords():
    dispatcher = RedTeamDispatcher()
    dispatcher._shared_state = SharedRedTeamState(operation_id="op-test-recon-parse")
    dispatcher._shared_state.target = Target(
        ip="192.168.58.7",
        domain="contoso.local",
    )

    task_id = "recon_parse_test"
    dispatcher._shared_state.pending_tasks[task_id] = TaskInfo(
        task_id=task_id,
        task_type="recon",
        assigned_agent="recon",
    )

    output = """
SMB                      192.168.58.7        445    APP-SRV01        [*] Windows 10 / Server 2019 Build 17763 x64 (name:APP-SRV01) (domain:contoso.local) (signing:True) (SMBv1:None)
SMB                      192.168.58.7        445    APP-SRV01        danj                  2026-01-13 21:03:31 0       Dan Jump (Password : P@ssw0rd123!)
user:[adamb] rid:[0x45f]
Account: danj Name: (null) Desc: Dan Jump (Password : P@ssw0rd123!)
"""

    await dispatcher.complete_task(
        task_id=task_id,
        success=True,
        result={"output": output},
        source_agent="recon",
    )

    hostnames = {host.hostname for host in dispatcher.shared_state.all_hosts}
    assert "app-srv01.contoso.local" in hostnames

    usernames = {user.username for user in dispatcher.shared_state.all_users}
    assert "adamb" in usernames
    assert "danj" in usernames

    credentials = {
        (cred.username, cred.password, cred.domain)
        for cred in dispatcher.shared_state.all_credentials
    }
    assert ("danj", "P@ssw0rd123!", "contoso.local") in credentials


@pytest.mark.asyncio
async def test_structured_credential_adds_user_to_shared_state():
    dispatcher = RedTeamDispatcher()
    dispatcher._shared_state = SharedRedTeamState(operation_id="op-test-cred-user")

    task_id = "cred_user_test"
    dispatcher._shared_state.pending_tasks[task_id] = TaskInfo(
        task_id=task_id,
        task_type="recon",
        assigned_agent="recon",
    )

    await dispatcher.complete_task(
        task_id=task_id,
        success=True,
        result={
            "credential": {
                "username": "karimm",
                "password": "Summer2024!",  # pragma: allowlist secret
                "domain": "contoso.local",
                "source": "user_description",
                "is_admin": False,
            }
        },
        source_agent="recon",
    )

    usernames = {(user.username, user.domain) for user in dispatcher.shared_state.all_users}
    assert ("karimm", "contoso.local") in usernames


@pytest.mark.asyncio
async def test_string_tool_result_updates_hosts():
    dispatcher = RedTeamDispatcher()
    dispatcher._shared_state = SharedRedTeamState(operation_id="op-test-string-output")
    dispatcher._shared_state.target = Target(
        ip="192.168.58.7",
        domain="contoso.local",
    )

    task_id = "string_output_test"
    dispatcher._shared_state.pending_tasks[task_id] = TaskInfo(
        task_id=task_id,
        task_type="recon",
        assigned_agent="recon",
    )

    output = (
        "SMB 192.168.58.7 445 APP-SRV01 [*] Windows 10 / Server 2019 "
        "Build 17763 x64 (name:APP-SRV01) (domain:contoso.local)"
    )

    await dispatcher.complete_task(
        task_id=task_id,
        success=True,
        result=output,
        source_agent="recon",
    )

    hostnames = {host.hostname for host in dispatcher.shared_state.all_hosts}
    assert "app-srv01.contoso.local" in hostnames
