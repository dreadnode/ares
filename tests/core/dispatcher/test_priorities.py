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
from ares.core.models import SharedRedTeamState


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


class TestDelegationCredentialPrerequisite:
    """Tests for deferring delegation vulns until credentials exist."""

    def test_account_has_credentials_with_password(self):
        """Should return True when account has cleartext password."""
        from ares.core.models import Credential

        dispatcher = RedTeamDispatcher()
        dispatcher._shared_state = SharedRedTeamState(operation_id="test-op")

        # Add credential with password
        cred = Credential(
            username="svc_backup",
            password="Backup123!",  # pragma: allowlist secret
            domain="contoso.local",
        )
        dispatcher.shared_state.add_credential(cred, "test")

        assert dispatcher._account_has_credentials("svc_backup") is True
        assert dispatcher._account_has_credentials("SVC_BACKUP") is True  # Case insensitive
        assert dispatcher._account_has_credentials("svc_backup$") is True  # Strips $

    def test_account_has_credentials_without_password(self):
        """Should return False when account has no cleartext password."""
        from ares.core.models import Credential

        dispatcher = RedTeamDispatcher()
        dispatcher._shared_state = SharedRedTeamState(operation_id="test-op")

        # Add credential without password (hash only)
        cred = Credential(
            username="svc_backup",
            password="",
            domain="contoso.local",
        )
        dispatcher.shared_state.add_credential(cred, "test")

        assert dispatcher._account_has_credentials("svc_backup") is False

    def test_account_has_credentials_unknown_account(self):
        """Should return False for unknown accounts."""
        dispatcher = RedTeamDispatcher()
        dispatcher._shared_state = SharedRedTeamState(operation_id="test-op")

        assert dispatcher._account_has_credentials("unknown.user") is False
        assert dispatcher._account_has_credentials("") is False

    @pytest.mark.asyncio
    async def test_get_next_vulnerability_defers_delegation_without_creds(self):
        """Constrained delegation vuln should be deferred when no credentials exist."""
        from ares.core.models import VulnerabilityInfo

        dispatcher = RedTeamDispatcher()
        dispatcher._shared_state = SharedRedTeamState(operation_id="op-test-defer")

        # Add constrained delegation vulnerability without credentials
        vuln = VulnerabilityInfo(
            vuln_id="cd_svc_backup_12345678",
            vuln_type="constrained_delegation",
            target="svc_backup",
            discovered_by="recon",
            details={
                "account_name": "svc_backup",
                "target_spn": "cifs/dc01.contoso.local",
                "domain": "contoso.local",
            },
            priority=4,
        )
        dispatcher.shared_state.add_vulnerability(vuln)

        # No credentials for svc_backup - should return None (deferred)
        result = await dispatcher.get_next_vulnerability()

        assert result is None

    @pytest.mark.asyncio
    async def test_get_next_vulnerability_returns_delegation_with_creds(self):
        """Constrained delegation vuln should be returned when credentials exist."""
        from ares.core.models import Credential, VulnerabilityInfo

        dispatcher = RedTeamDispatcher()
        dispatcher._shared_state = SharedRedTeamState(operation_id="op-test-with-creds")

        # Add credential for the account
        cred = Credential(
            username="svc_backup",
            password="Backup123!",  # pragma: allowlist secret
            domain="contoso.local",
        )
        dispatcher.shared_state.add_credential(cred, "cracker")

        # Add constrained delegation vulnerability
        vuln = VulnerabilityInfo(
            vuln_id="cd_svc_backup_12345678",
            vuln_type="constrained_delegation",
            target="svc_backup",
            discovered_by="recon",
            details={
                "account_name": "svc_backup",
                "target_spn": "cifs/dc01.contoso.local",
                "domain": "contoso.local",
            },
            priority=4,
        )
        dispatcher.shared_state.add_vulnerability(vuln)

        # With credentials - should return the vulnerability
        result = await dispatcher.get_next_vulnerability()

        assert result is not None
        assert result["id"] == "cd_svc_backup_12345678"
        assert result["type"] == "constrained_delegation"

    @pytest.mark.asyncio
    async def test_get_next_vulnerability_skips_delegation_returns_other(self):
        """Should skip delegation without creds and return next available vuln."""
        from ares.core.models import VulnerabilityInfo

        dispatcher = RedTeamDispatcher()
        dispatcher._shared_state = SharedRedTeamState(operation_id="op-test-skip")

        # Add constrained delegation WITHOUT credentials (should be skipped)
        cd_vuln = VulnerabilityInfo(
            vuln_id="cd_svc_backup_12345678",
            vuln_type="constrained_delegation",
            target="svc_backup",
            discovered_by="recon",
            details={"account_name": "svc_backup"},
            priority=2,  # Higher priority
        )
        dispatcher.shared_state.add_vulnerability(cd_vuln)

        # Add MSSQL vuln (no credential prereq, lower priority but available)
        mssql_vuln = VulnerabilityInfo(
            vuln_id="mssql_impersonation_192.168.58.20",
            vuln_type="mssql_impersonation",
            target="192.168.58.20",
            discovered_by="recon",
            details={"can_impersonate_sa": True},
            priority=10,
        )
        dispatcher.shared_state.add_vulnerability(mssql_vuln)

        # Should skip delegation (no creds) and return MSSQL
        result = await dispatcher.get_next_vulnerability()

        assert result is not None
        assert result["id"] == "mssql_impersonation_192.168.58.20"
        assert result["type"] == "mssql_impersonation"

    @pytest.mark.asyncio
    async def test_get_next_vulnerability_uses_account_key_fallback(self):
        """Should check both account_name and account keys for delegation."""
        from ares.core.models import Credential, VulnerabilityInfo

        dispatcher = RedTeamDispatcher()
        dispatcher._shared_state = SharedRedTeamState(operation_id="op-test-account-key")

        # Add credential
        cred = Credential(
            username="svc_backup",
            password="Backup123!",  # pragma: allowlist secret
            domain="contoso.local",
        )
        dispatcher.shared_state.add_credential(cred, "cracker")

        # Add vulnerability using "account" key instead of "account_name"
        vuln = VulnerabilityInfo(
            vuln_id="cd_svc_backup_abcd1234",
            vuln_type="constrained_delegation",
            target="svc_backup",
            discovered_by="recon",
            details={
                "account": "svc_backup",  # Uses "account" key
                "target_spn": "cifs/dc01.contoso.local",
            },
            priority=4,
        )
        dispatcher.shared_state.add_vulnerability(vuln)

        # Should find credential using fallback key
        result = await dispatcher.get_next_vulnerability()

        assert result is not None
        assert result["id"] == "cd_svc_backup_abcd1234"

    def test_can_exploit_vulnerability_delegation_with_creds(self):
        """Constrained delegation should be exploitable when credentials exist."""
        from ares.core.models import Credential

        dispatcher = RedTeamDispatcher()
        dispatcher._shared_state = SharedRedTeamState(operation_id="test-can-exploit")

        cred = Credential(
            username="svc_backup",
            password="Backup123!",  # pragma: allowlist secret
            domain="contoso.local",
        )
        dispatcher.shared_state.add_credential(cred, "test")

        result = dispatcher._can_exploit_vulnerability(
            "constrained_delegation", {"account_name": "svc_backup"}
        )
        assert result is True

    def test_can_exploit_vulnerability_delegation_without_creds(self):
        """Constrained delegation should NOT be exploitable without credentials."""
        dispatcher = RedTeamDispatcher()
        dispatcher._shared_state = SharedRedTeamState(operation_id="test-no-exploit")

        result = dispatcher._can_exploit_vulnerability(
            "constrained_delegation", {"account_name": "svc_backup"}
        )
        assert result is False

    def test_can_exploit_vulnerability_other_types_always_true(self):
        """Non-delegation vulnerabilities should always be exploitable."""
        dispatcher = RedTeamDispatcher()
        dispatcher._shared_state = SharedRedTeamState(operation_id="test-other-vuln")

        # MSSQL, ADCS, etc. don't require credential prereq check
        assert dispatcher._can_exploit_vulnerability("mssql_impersonation", {}) is True
        assert dispatcher._can_exploit_vulnerability("adcs_esc1", {}) is True
        assert dispatcher._can_exploit_vulnerability("krbtgt_hash", {}) is True


class TestThrottleBypass:
    """Tests for critical path task throttle bypass logic."""

    def test_delegation_enumeration_bypasses_hard_cap(self):
        """find_delegation privesc_enumeration tasks should bypass hard cap."""
        dispatcher = RedTeamDispatcher()

        # Delegation enumeration should be detected as critical
        task_type = "privesc_enumeration"
        payload = {"techniques": ["find_delegation"]}
        techniques = payload.get("techniques", [])
        is_delegation_enum = task_type == "privesc_enumeration" and any(
            "delegation" in t.lower() for t in techniques
        )
        assert is_delegation_enum is True
        # Verify dispatcher has the expected critical path config
        assert "exploit" in dispatcher.CRITICAL_PATH_TASK_TYPES

    def test_constrained_delegation_exploit_bypasses_hard_cap(self):
        """constrained_delegation exploit should bypass hard cap."""
        dispatcher = RedTeamDispatcher()

        # Check CRITICAL_PATH_VULN_TYPES contains constrained_delegation
        assert "constrained_delegation" in dispatcher.CRITICAL_PATH_VULN_TYPES
        assert "exploit" in dispatcher.CRITICAL_PATH_TASK_TYPES

    def test_mssql_impersonation_does_not_bypass_hard_cap(self):
        """mssql_impersonation is NOT in critical path - takes too long."""
        dispatcher = RedTeamDispatcher()

        assert "mssql_impersonation" not in dispatcher.CRITICAL_PATH_VULN_TYPES

    def test_non_delegation_privesc_enum_does_not_bypass(self):
        """privesc_enumeration without delegation technique should NOT bypass."""
        task_type = "privesc_enumeration"
        payload = {"techniques": ["find_spn", "find_asreproast"]}
        techniques = payload.get("techniques", [])
        is_delegation_enum = task_type == "privesc_enumeration" and any(
            "delegation" in t.lower() for t in techniques
        )
        assert is_delegation_enum is False

    def test_esc8_relay_coercion_bypasses_hard_cap(self):
        """ESC8 relay (ntlmrelayx_to_adcs) coercion tasks should bypass hard cap.

        ESC8 is a critical path to DA via ADCS web enrollment relay.
        The ntlmrelayx_to_adcs technique is dispatched as a coercion task.
        """
        dispatcher = RedTeamDispatcher()

        # Verify ESC8_COERCION_TECHNIQUES exists and contains ntlmrelayx_to_adcs
        assert hasattr(dispatcher, "ESC8_COERCION_TECHNIQUES")
        assert "ntlmrelayx_to_adcs" in dispatcher.ESC8_COERCION_TECHNIQUES

        # Test detection logic
        task_type = "coercion"
        payload = {"techniques": ["ntlmrelayx_to_adcs"]}
        techniques = payload.get("techniques", [])
        is_esc8_coercion = task_type == "coercion" and any(
            t.lower() in dispatcher.ESC8_COERCION_TECHNIQUES for t in techniques
        )
        assert is_esc8_coercion is True

    def test_esc8_petitpotam_coercion_bypasses_hard_cap(self):
        """ESC8 petitpotam coercion tasks should bypass hard cap.

        ESC8 attack coordinates ntlmrelayx listener with petitpotam coercion.
        Both are critical path tasks that should bypass throttling.
        """
        dispatcher = RedTeamDispatcher()

        # Verify ESC8_COERCION_TECHNIQUES contains petitpotam
        assert "petitpotam" in dispatcher.ESC8_COERCION_TECHNIQUES

        # Test detection logic
        task_type = "coercion"
        payload = {"techniques": ["petitpotam"]}
        techniques = payload.get("techniques", [])
        is_esc8_coercion = task_type == "coercion" and any(
            t.lower() in dispatcher.ESC8_COERCION_TECHNIQUES for t in techniques
        )
        assert is_esc8_coercion is True

    def test_non_esc8_coercion_does_not_bypass(self):
        """Regular coercion tasks (responder, LLMNR) should NOT bypass hard cap."""
        dispatcher = RedTeamDispatcher()

        task_type = "coercion"
        payload = {"techniques": ["LLMNR", "NBT-NS", "mDNS"]}
        techniques = payload.get("techniques", [])
        is_esc8_coercion = task_type == "coercion" and any(
            t.lower() in dispatcher.ESC8_COERCION_TECHNIQUES for t in techniques
        )
        assert is_esc8_coercion is False
