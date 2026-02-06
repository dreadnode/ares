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


class TestExtractHashesFromOutput:
    """Tests for _extract_hashes_from_output including SAM dump format."""

    def _make_dispatcher(self) -> RedTeamDispatcher:
        dispatcher = RedTeamDispatcher()
        dispatcher._shared_state = SharedRedTeamState(operation_id="op-test-hashes")
        return dispatcher

    def test_extracts_domain_prefixed_ntlm_hashes(self):
        """Test extraction of domain\\user:rid:lmhash:nthash::: format."""
        dispatcher = self._make_dispatcher()
        output = (
            "contoso.local\\Administrator:500:"
            "aad3b435b51404eeaad3b435b51404ee:fc525c9683e8fe067095ba2ddc971889:::\n"
            "contoso.local\\krbtgt:502:"
            "aad3b435b51404eeaad3b435b51404ee:9d765b482771505cbe97411065964d5f:::"
        )

        hashes = dispatcher._extract_hashes_from_output(output)

        assert len(hashes) == 2
        usernames = {h.username for h in hashes}
        assert "Administrator" in usernames
        assert "krbtgt" in usernames
        for h in hashes:
            assert h.hash_type == "NTLM"
            assert h.domain == "contoso.local"
            assert ":" in h.hash_value  # lm:nt format

    def test_extracts_sam_dump_ntlm_hashes(self):
        """Test extraction of non-domain-prefixed SAM dump format: user:rid:lmhash:nthash:::"""
        dispatcher = self._make_dispatcher()
        output = (
            "Administrator:500:"
            "aad3b435b51404eeaad3b435b51404ee:fc525c9683e8fe067095ba2ddc971889:::\n"  # pragma: allowlist secret
            "Guest:501:"
            "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::\n"
            "DefaultAccount:503:"
            "aad3b435b51404eeaad3b435b51404ee:e2b07662e39b0a766c02db81f4e8d8f0:::"
        )

        hashes = dispatcher._extract_hashes_from_output(output)

        assert len(hashes) == 3
        usernames = {h.username for h in hashes}
        assert "Administrator" in usernames
        assert "Guest" in usernames
        assert "DefaultAccount" in usernames
        for h in hashes:
            assert h.hash_type == "NTLM"
            assert h.domain == ""  # SAM hashes have no domain

    def test_mixed_domain_and_sam_hashes(self):
        """Test output containing both domain-prefixed and SAM dump hashes."""
        dispatcher = self._make_dispatcher()
        output = (
            "[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)\n"
            "Administrator:500:"
            "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::\n"  # pragma: allowlist secret
            "[*] Dumping Domain Credentials (domain\\uid:rid:lmhash:nthash)\n"
            "contoso.local\\Administrator:500:"
            "aad3b435b51404eeaad3b435b51404ee:fc525c9683e8fe067095ba2ddc971889:::"
        )

        hashes = dispatcher._extract_hashes_from_output(output)

        assert len(hashes) == 2
        domains = {h.domain for h in hashes}
        assert "" in domains  # SAM entry
        assert "contoso.local" in domains  # Domain entry

    def test_deduplicates_identical_hashes(self):
        """Test that identical hash values are deduplicated."""
        dispatcher = self._make_dispatcher()
        output = (
            "Administrator:500:"
            "aad3b435b51404eeaad3b435b51404ee:fc525c9683e8fe067095ba2ddc971889:::\n"
            "Administrator:500:"
            "aad3b435b51404eeaad3b435b51404ee:fc525c9683e8fe067095ba2ddc971889:::"
        )

        hashes = dispatcher._extract_hashes_from_output(output)

        assert len(hashes) == 1

    def test_sam_hash_does_not_match_machine_accounts(self):
        """Test that machine accounts (ending in $) are not matched by SAM regex."""
        dispatcher = self._make_dispatcher()
        output = "DC01$:1000:aad3b435b51404eeaad3b435b51404ee:abcdef0123456789abcdef0123456789:::"

        hashes = dispatcher._extract_hashes_from_output(output)

        assert len(hashes) == 0

    def test_domain_prefixed_continues_past_sam_regex(self):
        """Test that domain-prefixed lines don't also match the SAM regex."""
        dispatcher = self._make_dispatcher()
        output = (
            "contoso.local\\admin:500:"
            "aad3b435b51404eeaad3b435b51404ee:fc525c9683e8fe067095ba2ddc971889:::"
        )

        hashes = dispatcher._extract_hashes_from_output(output)

        # Should match exactly once (domain-prefixed), not twice
        assert len(hashes) == 1
        assert hashes[0].domain == "contoso.local"
        assert hashes[0].username == "admin"

    def test_empty_output_returns_empty(self):
        """Test that empty output returns no hashes."""
        dispatcher = self._make_dispatcher()
        assert dispatcher._extract_hashes_from_output("") == []
        assert dispatcher._extract_hashes_from_output(None) == []

    def test_kerberoast_and_sam_hashes_coexist(self):
        """Test output with both Kerberoast TGS and SAM dump hashes."""
        dispatcher = self._make_dispatcher()
        output = (
            "$krb5tgs$23$*svc_sql$contoso.local$cifs/sql01.contoso.local*$"
            "aabbccdd$112233445566778899aabbccddeeff\n"
            "svc_sql:1105:"
            "aad3b435b51404eeaad3b435b51404ee:abcdef0123456789abcdef0123456789:::"
        )

        hashes = dispatcher._extract_hashes_from_output(output)

        assert len(hashes) == 2
        types = {h.hash_type for h in hashes}
        assert "TGS" in types
        assert "NTLM" in types
