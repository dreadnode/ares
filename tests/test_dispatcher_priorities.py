"""Tests for RedTeamDispatcher vulnerability priorities."""

from __future__ import annotations

from ares.core.dispatcher import RedTeamDispatcher


class TestVulnerabilityPriorities:
    """Tests for vulnerability priority mappings in the dispatcher."""

    def test_adcs_vulnerabilities_highest_priority(self):
        """ADCS vulnerabilities should have highest priority (1-3)."""
        dispatcher = RedTeamDispatcher()
        priorities = dispatcher._vulnerability_priorities

        assert priorities["ADCS_ESC1"] == 1
        assert priorities["ADCS_ESC4"] == 2
        assert priorities["ADCS_ESC8"] == 3

    def test_high_value_hashes_high_priority(self):
        """krbtgt and domain admin hashes should have high priority (4-5)."""
        dispatcher = RedTeamDispatcher()
        priorities = dispatcher._vulnerability_priorities

        assert priorities["krbtgt_hash"] == 4
        assert priorities["domain_admin_hash"] == 5

    def test_direct_da_acl_priority(self):
        """Direct DA via ACL should have priority 6-7."""
        dispatcher = RedTeamDispatcher()
        priorities = dispatcher._vulnerability_priorities

        assert priorities["genericall_domain_admins"] == 6
        assert priorities["gpo_write"] == 7

    def test_acl_abuse_priority(self):
        """ACL abuse should have priority 8."""
        dispatcher = RedTeamDispatcher()
        priorities = dispatcher._vulnerability_priorities

        assert priorities["acl_abuse"] == 8

    def test_delegation_vulnerabilities_priority(self):
        """Delegation vulnerabilities should have priority 9-11."""
        dispatcher = RedTeamDispatcher()
        priorities = dispatcher._vulnerability_priorities

        assert priorities["unconstrained_delegation"] == 9
        assert priorities["constrained_delegation"] == 10
        assert priorities["rbcd"] == 11

    def test_mssql_vulnerabilities_priority(self):
        """MSSQL vulnerabilities should have priority 12-15."""
        dispatcher = RedTeamDispatcher()
        priorities = dispatcher._vulnerability_priorities

        assert priorities["mssql_impersonation"] == 12
        assert priorities["mssql_linked_xpcmdshell"] == 13
        assert priorities["mssql_linked"] == 14
        assert priorities["mssql_linked_server"] == 14  # Alias
        assert priorities["mssql_xp_cmdshell"] == 15

    def test_mssql_linked_server_alias(self):
        """mssql_linked_server should be an alias for mssql_linked."""
        dispatcher = RedTeamDispatcher()
        priorities = dispatcher._vulnerability_priorities

        assert priorities["mssql_linked"] == priorities["mssql_linked_server"]

    def test_gpo_gmsa_laps_abuse_priority(self):
        """GPO, gMSA, and LAPS abuse should have priority 16-18."""
        dispatcher = RedTeamDispatcher()
        priorities = dispatcher._vulnerability_priorities

        assert priorities["gpo_abuse"] == 16
        assert priorities["gmsa_readable"] == 17
        assert priorities["laps_abuse"] == 18

    def test_dcsync_and_shadow_credentials_priority(self):
        """DCSync and shadow credentials should have priority 19-20."""
        dispatcher = RedTeamDispatcher()
        priorities = dispatcher._vulnerability_priorities

        assert priorities["dcsync"] == 19
        assert priorities["shadow_credentials"] == 20

    def test_relay_and_persistence_priority(self):
        """Relay and persistence should have priority 21-22."""
        dispatcher = RedTeamDispatcher()
        priorities = dispatcher._vulnerability_priorities

        assert priorities["smb_relay_target"] == 21
        assert priorities["adminsd_holder_writable"] == 22
        assert priorities["adminsd_holder_acl"] == 22  # Alias

    def test_all_priorities_are_unique_except_aliases(self):
        """All priorities should be unique except for known aliases."""
        dispatcher = RedTeamDispatcher()
        priorities = dispatcher._vulnerability_priorities

        # Known aliases (pairs sharing the same priority)
        aliases = {
            ("mssql_linked", "mssql_linked_server"),
            ("adminsd_holder_writable", "adminsd_holder_acl"),
        }

        # Get non-alias items
        non_alias_items = []
        for key, value in priorities.items():
            is_alias = False
            for alias_pair in aliases:
                if key in alias_pair:
                    # Only include one from each alias pair
                    if key == alias_pair[0]:
                        non_alias_items.append((key, value))
                    is_alias = True
                    break
            if not is_alias:
                non_alias_items.append((key, value))

        values = [v for _, v in non_alias_items]
        assert len(values) == len(set(values)), "Non-alias priorities should be unique"

    def test_priority_ordering(self):
        """Priorities should follow a logical ordering."""
        dispatcher = RedTeamDispatcher()
        priorities = dispatcher._vulnerability_priorities

        # ADCS should be higher priority than delegation
        assert priorities["ADCS_ESC1"] < priorities["unconstrained_delegation"]

        # Delegation should be higher priority than MSSQL
        assert priorities["unconstrained_delegation"] < priorities["mssql_impersonation"]

        # MSSQL should be higher priority than GPO abuse
        assert priorities["mssql_xp_cmdshell"] < priorities["gpo_abuse"]

    def test_all_expected_vuln_types_present(self):
        """All expected vulnerability types should be present."""
        dispatcher = RedTeamDispatcher()
        priorities = dispatcher._vulnerability_priorities

        expected_types = [
            # Tier 1: ADCS
            "ADCS_ESC1",
            "ADCS_ESC4",
            "ADCS_ESC8",
            # Tier 1: High-value hashes
            "krbtgt_hash",
            "domain_admin_hash",
            # Tier 2: Direct DA via ACL
            "genericall_domain_admins",
            "gpo_write",
            # Tier 3: ACL and delegation
            "acl_abuse",
            "unconstrained_delegation",
            "constrained_delegation",
            "rbcd",
            # Tier 4: MSSQL
            "mssql_impersonation",
            "mssql_linked_xpcmdshell",
            "mssql_linked",
            "mssql_linked_server",
            "mssql_xp_cmdshell",
            # Tier 5: Other privilege escalation
            "gpo_abuse",
            "gmsa_readable",
            "laps_abuse",
            "dcsync",
            "shadow_credentials",
            # Tier 6: Relay and persistence
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

        assert linked_priority == linked_server_priority == 14

    def test_mssql_priority_chain(self):
        """MSSQL attack chain should follow logical priority order."""
        dispatcher = RedTeamDispatcher()
        priorities = dispatcher._vulnerability_priorities

        # Impersonation (privilege escalation) should be highest MSSQL priority
        assert priorities["mssql_impersonation"] < priorities["mssql_linked"]

        # Linked server access enables xp_cmdshell on remote
        assert priorities["mssql_linked"] <= priorities["mssql_xp_cmdshell"]
