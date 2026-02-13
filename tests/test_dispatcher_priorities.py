"""Tests for RedTeamDispatcher vulnerability priorities.

Priority scheme rationale:
- ADCS ESC1/4 are highest (1-2) - common in enterprise, high success rate
- ADCS ESC8 (3) - requires relay setup, slightly harder
- Delegation (4-6) - constrained delegation with creds boosted to 2 dynamically
- krbtgt/DA hash (7-8) - instant DA if obtained
- ACL abuse (9), MSSQL (10-11), GPO (12), etc.
"""

from __future__ import annotations

import pytest

from ares.core.dispatcher import RedTeamDispatcher


class TestVulnerabilityPriorities:
    """Tests for vulnerability priority mappings in the dispatcher."""

    def test_adcs_vulnerabilities_highest_priority(self):
        """ADCS vulnerabilities should have highest base priority (1-3)."""
        dispatcher = RedTeamDispatcher()
        priorities = dispatcher._vulnerability_priorities

        assert priorities["adcs_esc1"] == 1
        assert priorities["adcs_esc4"] == 2
        assert priorities["adcs_esc8"] == 3

    def test_delegation_base_priority(self):
        """Delegation attacks should have base priority 4-6.

        Note: constrained_delegation gets boosted to priority 2 when
        credentials are available (handled in queue_vulnerability).
        """
        dispatcher = RedTeamDispatcher()
        priorities = dispatcher._vulnerability_priorities

        assert priorities["constrained_delegation"] == 4
        assert priorities["unconstrained_delegation"] == 5
        assert priorities["rbcd"] == 6

    def test_kerberos_keys_priority(self):
        """Kerberos keys (krbtgt, DA hash) should have priority 7-8."""
        dispatcher = RedTeamDispatcher()
        priorities = dispatcher._vulnerability_priorities

        assert priorities["krbtgt_hash"] == 7
        assert priorities["domain_admin_hash"] == 8

    def test_acl_abuse_priority(self):
        """ACL abuse should have priority 9."""
        dispatcher = RedTeamDispatcher()
        priorities = dispatcher._vulnerability_priorities

        assert priorities["acl_abuse"] == 9

    def test_mssql_vulnerabilities_priority(self):
        """MSSQL vulnerabilities should have priority 10-11."""
        dispatcher = RedTeamDispatcher()
        priorities = dispatcher._vulnerability_priorities

        assert priorities["mssql_impersonation"] == 10
        assert priorities["mssql_linked"] == 11
        assert priorities["mssql_linked_server"] == 11  # Alias
        assert priorities["mssql_linked_xpcmdshell"] == 11  # Alias
        assert priorities["mssql_xp_cmdshell"] == 11  # Alias

    def test_mssql_linked_server_alias(self):
        """mssql_linked_server should be an alias for mssql_linked."""
        dispatcher = RedTeamDispatcher()
        priorities = dispatcher._vulnerability_priorities

        assert priorities["mssql_linked"] == priorities["mssql_linked_server"]

    def test_gpo_laps_dcsync_priority(self):
        """GPO, LAPS, DCSync should have priority 12-14."""
        dispatcher = RedTeamDispatcher()
        priorities = dispatcher._vulnerability_priorities

        assert priorities["gpo_abuse"] == 12
        assert priorities["gpo_write"] == 12  # Alias
        assert priorities["laps_abuse"] == 13
        assert priorities["dcsync"] == 14

    def test_shadow_credentials_and_gmsa_priority(self):
        """Shadow credentials and gMSA should have priority 15-16."""
        dispatcher = RedTeamDispatcher()
        priorities = dispatcher._vulnerability_priorities

        assert priorities["shadow_credentials"] == 15
        assert priorities["gmsa_readable"] == 16

    def test_acl_specific_priority(self):
        """ACL-specific attacks should have priority 17."""
        dispatcher = RedTeamDispatcher()
        priorities = dispatcher._vulnerability_priorities

        assert priorities["genericall_domain_admins"] == 17

    def test_kerberoast_priority(self):
        """Kerberoast/AS-REP roast should have lower priority (20-21)."""
        dispatcher = RedTeamDispatcher()
        priorities = dispatcher._vulnerability_priorities

        assert priorities["kerberoast"] == 20
        assert priorities["asreproast"] == 21

    def test_relay_and_persistence_priority(self):
        """Relay and persistence should have lower priority (22-23)."""
        dispatcher = RedTeamDispatcher()
        priorities = dispatcher._vulnerability_priorities

        assert priorities["smb_relay_target"] == 22
        assert priorities["adminsd_holder_writable"] == 23
        assert priorities["adminsd_holder_acl"] == 23  # Alias

    def test_all_priorities_are_unique_except_aliases(self):
        """All priorities should be unique except for known aliases."""
        dispatcher = RedTeamDispatcher()
        priorities = dispatcher._vulnerability_priorities

        # Known aliases (sharing the same priority)
        aliases = {
            ("mssql_linked", "mssql_linked_server", "mssql_linked_xpcmdshell", "mssql_xp_cmdshell"),
            ("adminsd_holder_writable", "adminsd_holder_acl"),
            ("gpo_abuse", "gpo_write"),
        }

        # Build set of alias keys
        alias_keys = set()
        for alias_group in aliases:
            alias_keys.update(alias_group)

        # Get non-alias items (or first from each alias group)
        seen_alias_groups: set[int] = set()
        non_alias_values = []
        for key, value in priorities.items():
            is_alias = False
            for i, alias_group in enumerate(aliases):
                if key in alias_group:
                    if i not in seen_alias_groups:
                        non_alias_values.append(value)
                        seen_alias_groups.add(i)
                    is_alias = True
                    break
            if not is_alias:
                non_alias_values.append(value)

        assert len(non_alias_values) == len(set(non_alias_values)), (
            f"Non-alias priorities should be unique. "
            f"Values: {sorted(non_alias_values)}, Unique: {sorted(set(non_alias_values))}"
        )

    def test_priority_ordering(self):
        """Priorities should follow a logical ordering."""
        dispatcher = RedTeamDispatcher()
        priorities = dispatcher._vulnerability_priorities

        # ADCS should be highest base priority
        assert priorities["adcs_esc1"] < priorities["constrained_delegation"]

        # Delegation should be higher than krbtgt (because we get krbtgt via delegation)
        assert priorities["constrained_delegation"] < priorities["krbtgt_hash"]

        # Kerberos keys higher than MSSQL
        assert priorities["krbtgt_hash"] < priorities["mssql_impersonation"]

        # MSSQL should be higher priority than GPO abuse
        assert priorities["mssql_impersonation"] < priorities["gpo_abuse"]

    def test_all_expected_vuln_types_present(self):
        """All expected vulnerability types should be present."""
        dispatcher = RedTeamDispatcher()
        priorities = dispatcher._vulnerability_priorities

        expected_types = [
            # Tier 1: ADCS
            "adcs_esc1",
            "adcs_esc4",
            "adcs_esc8",
            # Tier 2: Delegation
            "constrained_delegation",
            "unconstrained_delegation",
            "rbcd",
            # Tier 3: Kerberos keys
            "krbtgt_hash",
            "domain_admin_hash",
            # Tier 4: ACL
            "acl_abuse",
            # Tier 5: MSSQL
            "mssql_impersonation",
            "mssql_linked",
            "mssql_linked_server",
            "mssql_linked_xpcmdshell",
            "mssql_xp_cmdshell",
            # Tier 6: GPO/LAPS/DCSync
            "gpo_abuse",
            "gpo_write",
            "laps_abuse",
            "dcsync",
            "shadow_credentials",
            # Tier 7: Other
            "gmsa_readable",
            "genericall_domain_admins",
            "kerberoast",
            "asreproast",
            "smb_relay_target",
            "adminsd_holder_writable",
            "adminsd_holder_acl",
        ]

        for vuln_type in expected_types:
            assert vuln_type in priorities, f"Missing vulnerability type: {vuln_type}"


class TestDispatcherMSSQLIntegration:
    """Tests for MSSQL-specific dispatcher functionality."""

    def test_mssql_linked_and_linked_server_same_priority(self):
        """mssql_linked and mssql_linked_server should have same priority."""
        dispatcher = RedTeamDispatcher()

        # Both should be treated equivalently for priority queue ordering
        linked_priority = dispatcher._vulnerability_priorities["mssql_linked"]
        linked_server_priority = dispatcher._vulnerability_priorities["mssql_linked_server"]

        assert linked_priority == linked_server_priority == 11

    def test_mssql_priority_chain(self):
        """MSSQL attack chain should follow logical priority order."""
        dispatcher = RedTeamDispatcher()
        priorities = dispatcher._vulnerability_priorities

        # Impersonation (privilege escalation) should be highest MSSQL priority
        assert priorities["mssql_impersonation"] < priorities["mssql_linked"]

        # Linked server access enables xp_cmdshell on remote
        assert priorities["mssql_linked"] <= priorities["mssql_xp_cmdshell"]


class TestCredentialAwarePriorityBoost:
    """Tests for dynamic priority adjustment based on prerequisites."""

    def test_constrained_delegation_with_dc_spn_boosted(self):
        """Constrained delegation with creds + DC SPN should be boosted to priority 2."""
        dispatcher = RedTeamDispatcher()

        # Simulate boost logic from vulnerability.py
        base_priority = dispatcher._vulnerability_priorities["constrained_delegation"]
        assert base_priority == 4  # Base priority without creds

        # With creds + DC SPN, should boost to 2 (tested via _adjust_priority_for_prerequisites)
        boosted = dispatcher._adjust_priority_for_prerequisites(
            "constrained_delegation",
            base_priority,
            {"has_credentials": True, "target_spn": "cifs/dc01.contoso.local"},
        )
        assert boosted == 2

    def test_constrained_delegation_with_non_dc_spn_boosted(self):
        """Constrained delegation with creds + non-DC SPN should be boosted to priority 3."""
        dispatcher = RedTeamDispatcher()

        base_priority = dispatcher._vulnerability_priorities["constrained_delegation"]
        boosted = dispatcher._adjust_priority_for_prerequisites(
            "constrained_delegation",
            base_priority,
            {"has_credentials": True, "target_spn": "http/web01.contoso.local"},
        )
        assert boosted == 3

    def test_constrained_delegation_without_creds_not_boosted(self):
        """Constrained delegation without creds should keep base priority."""
        dispatcher = RedTeamDispatcher()

        base_priority = dispatcher._vulnerability_priorities["constrained_delegation"]
        not_boosted = dispatcher._adjust_priority_for_prerequisites(
            "constrained_delegation",
            base_priority,
            {"has_credentials": False, "target_spn": "cifs/dc01.contoso.local"},
        )
        assert not_boosted == base_priority

    def test_mssql_impersonation_with_sa_boosted(self):
        """MSSQL impersonation with sa access should be boosted to priority 3."""
        dispatcher = RedTeamDispatcher()

        base_priority = dispatcher._vulnerability_priorities["mssql_impersonation"]
        assert base_priority == 10

        boosted = dispatcher._adjust_priority_for_prerequisites(
            "mssql_impersonation",
            base_priority,
            {"can_impersonate_sa": True},
        )
        assert boosted == 3


class TestCredentialReEvaluationAtDequeue:
    """Tests for re-evaluating has_credentials when dequeuing delegation vulnerabilities.

    Bug fix: Constrained delegation exploits were dispatched with has_credentials: False
    when the account was discovered before being Kerberoasted/cracked. The system should
    re-evaluate has_credentials at dequeue time, not just at discovery time.
    """

    @pytest.mark.asyncio
    async def test_delegation_vuln_gets_credentials_at_dequeue(self):
        """Delegation vuln queued without creds should get creds at dequeue time."""
        from ares.core.models import Credential, SharedRedTeamState

        dispatcher = RedTeamDispatcher()
        dispatcher._shared_state = SharedRedTeamState(operation_id="op-test-cred-reeval-1")

        # Step 1: Queue delegation vulnerability WITHOUT credentials
        vuln_id = await dispatcher.queue_vulnerability(
            vuln_type="constrained_delegation",
            target="sql_svc",
            details={
                "account_name": "sql_svc",
                "target_spn": "cifs/dc01.contoso.local",
                "domain": "contoso.local",
                "dc_ip": "192.168.58.10",
                "has_credentials": False,  # No creds at discovery time
            },
            discovered_by="recon",
        )
        assert vuln_id

        # Verify vulnerability was queued without credentials
        assert vuln_id in dispatcher._shared_state.discovered_vulnerabilities
        queued_vuln = dispatcher._shared_state.discovered_vulnerabilities[vuln_id]
        assert queued_vuln.details.get("has_credentials") is False

        # Step 2: Credential arrives later (e.g., Kerberoast cracked)
        dispatcher._shared_state.add_credential(
            Credential(
                username="sql_svc",
                password="Password123!",  # pragma: allowlist secret
                domain="contoso.local",
                source="cracker",
            ),
            "cracker",
        )

        # Step 3: Dequeue vulnerability - should now have credentials
        dequeued = await dispatcher.get_next_vulnerability()

        assert dequeued is not None
        assert dequeued["id"] == vuln_id
        assert dequeued["details"]["has_credentials"] is True
        assert dequeued["details"]["username"] == "sql_svc"
        assert dequeued["details"]["password"] == "Password123!"  # pragma: allowlist secret
        assert dequeued["details"]["domain"] == "contoso.local"

    @pytest.mark.asyncio
    async def test_delegation_vuln_without_creds_stays_without_creds(self):
        """Delegation vuln without matching credential should stay has_credentials=False."""
        from ares.core.models import Credential, SharedRedTeamState

        dispatcher = RedTeamDispatcher()
        dispatcher._shared_state = SharedRedTeamState(operation_id="op-test-cred-reeval-2")

        # Queue delegation vulnerability WITHOUT credentials
        vuln_id = await dispatcher.queue_vulnerability(
            vuln_type="constrained_delegation",
            target="sql_svc",
            details={
                "account_name": "sql_svc",
                "target_spn": "cifs/dc01.contoso.local",
                "domain": "contoso.local",
                "dc_ip": "192.168.58.10",
                "has_credentials": False,
            },
            discovered_by="recon",
        )

        # Add credential for DIFFERENT user
        dispatcher._shared_state.add_credential(
            Credential(
                username="admin_svc",
                password="AdminPass123!",  # pragma: allowlist secret
                domain="contoso.local",
                source="cracker",
            ),
            "cracker",
        )

        # Dequeue - should still not have credentials
        dequeued = await dispatcher.get_next_vulnerability()

        assert dequeued is not None
        assert dequeued["id"] == vuln_id
        assert dequeued["details"]["has_credentials"] is False

    @pytest.mark.asyncio
    async def test_unconstrained_delegation_also_gets_credentials(self):
        """Unconstrained delegation should also get credentials re-evaluated."""
        from ares.core.models import Credential, SharedRedTeamState

        dispatcher = RedTeamDispatcher()
        dispatcher._shared_state = SharedRedTeamState(operation_id="op-test-cred-reeval-3")

        # Queue unconstrained delegation without credentials
        await dispatcher.queue_vulnerability(
            vuln_type="unconstrained_delegation",
            target="web_svc",
            details={
                "account_name": "web_svc",
                "domain": "contoso.local",
                "has_credentials": False,
            },
            discovered_by="recon",
        )

        # Add matching credential
        dispatcher._shared_state.add_credential(
            Credential(
                username="web_svc",
                password="WebPass123!",  # pragma: allowlist secret
                domain="contoso.local",
                source="cracker",
            ),
            "cracker",
        )

        # Dequeue - should now have credentials
        dequeued = await dispatcher.get_next_vulnerability()

        assert dequeued is not None
        assert dequeued["details"]["has_credentials"] is True
        assert dequeued["details"]["password"] == "WebPass123!"  # pragma: allowlist secret

    @pytest.mark.asyncio
    async def test_machine_account_credential_matching(self):
        """Machine account credentials should match (strip trailing $)."""
        from ares.core.models import Credential, SharedRedTeamState

        dispatcher = RedTeamDispatcher()
        dispatcher._shared_state = SharedRedTeamState(operation_id="op-test-cred-reeval-4")

        # Queue delegation for machine account (with $ in account_name)
        # Note: target must be a valid hostname, but account_name contains the $
        vuln_id = await dispatcher.queue_vulnerability(
            vuln_type="constrained_delegation",
            target="web01.contoso.local",  # Valid hostname as target
            details={
                "account_name": "WEB01$",  # Machine account with $ suffix
                "target_spn": "cifs/dc01.contoso.local",
                "domain": "contoso.local",
                "has_credentials": False,
            },
            discovered_by="recon",
        )
        assert vuln_id  # Ensure vulnerability was queued

        # Add credential without $ (e.g., from secretsdump)
        dispatcher._shared_state.add_credential(
            Credential(
                username="WEB01",
                password="MachinePass123!",  # pragma: allowlist secret
                domain="contoso.local",
                source="secretsdump",
            ),
            "privesc",
        )

        # Dequeue - should match (case-insensitive, $ stripped from account_name)
        dequeued = await dispatcher.get_next_vulnerability()

        assert dequeued is not None
        assert dequeued["details"]["has_credentials"] is True
        assert dequeued["details"]["username"] == "WEB01"

    @pytest.mark.asyncio
    async def test_non_delegation_vuln_not_affected(self):
        """Non-delegation vulnerabilities should not be modified."""
        from ares.core.models import Credential, SharedRedTeamState

        dispatcher = RedTeamDispatcher()
        dispatcher._shared_state = SharedRedTeamState(operation_id="op-test-cred-reeval-5")

        # Queue ADCS vulnerability (not delegation)
        await dispatcher.queue_vulnerability(
            vuln_type="adcs_esc1",
            target="dc01.contoso.local",
            details={
                "template_name": "User",
                "ca_name": "contoso-DC01-CA",
            },
            discovered_by="recon",
        )

        # Add some credential
        dispatcher._shared_state.add_credential(
            Credential(
                username="testuser",
                password="TestPass123!",  # pragma: allowlist secret
                domain="contoso.local",
                source="discovery",
            ),
            "recon",
        )

        # Dequeue - should not have has_credentials added
        dequeued = await dispatcher.get_next_vulnerability()

        assert dequeued is not None
        assert "has_credentials" not in dequeued["details"]
