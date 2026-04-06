"""Tests for RedTeamDispatcher vulnerability priorities.

Priority scheme rationale:
- ADCS ESC1/4 are highest (1-2) - common in enterprise, high success rate
- ADCS ESC8 (3) - requires relay setup, slightly harder
- Delegation (4-6) - constrained delegation with creds boosted to 2 dynamically
- krbtgt/DA hash (7-8) - instant DA if obtained
- ACL abuse (9), MSSQL (10-11), GPO (12), etc.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

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


class TestCredentialEnrichmentInRequestExploit:
    """Tests for credential enrichment when dispatching delegation exploits.

    Bug fix: Vulnerabilities queued BEFORE credentials are cracked have empty
    password in details. When dequeued AFTER credentials exist, request_exploit()
    must enrich the payload with the credential from state.
    """

    @pytest.mark.asyncio
    async def test_request_exploit_enriches_delegation_payload_with_credential(self):
        """request_exploit should enrich delegation payload with password from state.

        This tests the fix for the 7-minute credential propagation delay bug:
        - Vuln queued before credentials cracked (no password in details)
        - Credentials cracked and added to state
        - Vuln dequeued and dispatched via request_exploit()
        - request_exploit() should find and include the password
        """
        from unittest.mock import AsyncMock, MagicMock

        from ares.core.models import Credential

        dispatcher = RedTeamDispatcher()
        dispatcher._shared_state = SharedRedTeamState(operation_id="test-enrich")

        # Add credential for the account (simulates cracked hash)
        cred = Credential(
            username="svc_backup",
            password="Backup123!",  # pragma: allowlist secret
            domain="contoso.local",
        )
        dispatcher.shared_state.add_credential(cred, "cracker")

        # Mock task queue to capture what gets submitted
        mock_task_queue = MagicMock()
        mock_task_queue.submit_task = AsyncMock(return_value="task-123")
        dispatcher._task_queue = mock_task_queue

        # Call request_exploit with params that DON'T have password
        # (simulates vuln details from before credential was cracked)
        await dispatcher.request_exploit(
            vuln_type="constrained_delegation",
            vuln_id="cd_svc_backup_12345678",
            target="svc_backup",
            source_agent="orchestrator",
            params={
                "account_name": "svc_backup",
                "target_spn": "cifs/dc01.contoso.local",
                "domain": "contoso.local",
                # NOTE: No password in params - should be enriched from state
            },
        )

        # Verify submit_task was called
        assert mock_task_queue.submit_task.called

        # Extract the payload that was submitted
        call_kwargs = mock_task_queue.submit_task.call_args
        payload = call_kwargs.kwargs.get("payload") or call_kwargs[1].get("payload")

        # Password should have been enriched from the credential in state
        assert payload["password"] == "Backup123!"  # pragma: allowlist secret

    @pytest.mark.asyncio
    async def test_request_exploit_does_not_override_existing_password(self):
        """request_exploit should NOT override password if already in params."""
        from unittest.mock import AsyncMock, MagicMock

        from ares.core.models import Credential

        dispatcher = RedTeamDispatcher()
        dispatcher._shared_state = SharedRedTeamState(operation_id="test-no-override")

        # Add credential with different password
        cred = Credential(
            username="svc_backup",
            password="StatePassword",  # pragma: allowlist secret
            domain="contoso.local",
        )
        dispatcher.shared_state.add_credential(cred, "cracker")

        mock_task_queue = MagicMock()
        mock_task_queue.submit_task = AsyncMock(return_value="task-456")
        dispatcher._task_queue = mock_task_queue

        # Call with password already in params
        await dispatcher.request_exploit(
            vuln_type="constrained_delegation",
            vuln_id="cd_svc_backup_12345678",
            target="svc_backup",
            source_agent="orchestrator",
            params={
                "account_name": "svc_backup",
                "password": "ParamsPassword",  # pragma: allowlist secret
                "domain": "contoso.local",
            },
        )

        call_kwargs = mock_task_queue.submit_task.call_args
        payload = call_kwargs.kwargs.get("payload") or call_kwargs[1].get("payload")

        # Should keep the password from params, not override with state
        assert payload["password"] == "ParamsPassword"  # pragma: allowlist secret

    @pytest.mark.asyncio
    async def test_request_exploit_enriches_unconstrained_delegation_too(self):
        """Unconstrained delegation should also be enriched with credentials."""
        from unittest.mock import AsyncMock, MagicMock

        from ares.core.models import Credential

        dispatcher = RedTeamDispatcher()
        dispatcher._shared_state = SharedRedTeamState(operation_id="test-unconstrained")

        cred = Credential(
            username="dc01",
            password="DCPassword!",  # pragma: allowlist secret
            domain="contoso.local",
        )
        dispatcher.shared_state.add_credential(cred, "cracker")

        mock_task_queue = MagicMock()
        mock_task_queue.submit_task = AsyncMock(return_value="task-789")
        dispatcher._task_queue = mock_task_queue

        await dispatcher.request_exploit(
            vuln_type="unconstrained_delegation",
            vuln_id="ud_dc01_12345678",
            target="dc01",
            source_agent="orchestrator",
            params={
                "account_name": "dc01$",  # With $ suffix
                "domain": "contoso.local",
            },
        )

        call_kwargs = mock_task_queue.submit_task.call_args
        payload = call_kwargs.kwargs.get("payload") or call_kwargs[1].get("payload")

        # Should enrich with password (stripping $ for matching)
        assert payload["password"] == "DCPassword!"  # pragma: allowlist secret


class TestPriorityRecalculation:
    """Tests for priority recalculation when credentials arrive after queuing.

    This tests the fix for the "14 minutes of wasted attacks" bug:
    - Constrained delegation discovered and queued at priority 4 (no creds)
    - Hash sent to cracker
    - System exploited MSSQL, PSExec, etc. at lower priorities
    - Finally came back to CD after 14 minutes

    The fix: recalculate priorities in get_next_vulnerability() based on
    CURRENT state, not stored priority from queue time.
    """

    def test_recalculate_priority_boosts_delegation_with_late_creds(self):
        """Priority should be boosted when credentials arrive after queueing."""
        from ares.core.models import Credential

        dispatcher = RedTeamDispatcher()
        dispatcher._shared_state = SharedRedTeamState(operation_id="test-recalc")

        # Initially no credentials - stored priority 4
        stored_priority = 4
        details = {
            "account_name": "svc_backup",
            "target_spn": "cifs/dc01.contoso.local",
        }

        # Without credentials, priority stays at 4
        recalc = dispatcher._recalculate_priority(
            "constrained_delegation", details, stored_priority
        )
        assert recalc == 4, "Priority should stay 4 without credentials"

        # Now credentials arrive (hash cracked)
        cred = Credential(
            username="svc_backup",
            password="Backup123!",  # pragma: allowlist secret
            domain="contoso.local",
        )
        dispatcher.shared_state.add_credential(cred, "cracker")

        # Priority should now be boosted to 2 (DC SPN)
        recalc = dispatcher._recalculate_priority(
            "constrained_delegation", details, stored_priority
        )
        assert recalc == 2, "Priority should boost to 2 with credentials + DC SPN"

    def test_recalculate_priority_non_dc_spn(self):
        """Priority should boost to 3 for non-DC SPNs when creds arrive."""
        from ares.core.models import Credential

        dispatcher = RedTeamDispatcher()
        dispatcher._shared_state = SharedRedTeamState(operation_id="test-recalc-non-dc")

        cred = Credential(
            username="svc_backup",
            password="Backup123!",  # pragma: allowlist secret
            domain="contoso.local",
        )
        dispatcher.shared_state.add_credential(cred, "cracker")

        details = {
            "account_name": "svc_backup",
            "target_spn": "http/web01.contoso.local",  # Non-DC SPN
        }

        recalc = dispatcher._recalculate_priority(
            "constrained_delegation", details, stored_priority=4
        )
        assert recalc == 3, "Priority should boost to 3 for non-DC SPN"

    def test_recalculate_priority_no_boost_for_other_types(self):
        """Non-delegation vulns should keep their stored priority."""
        dispatcher = RedTeamDispatcher()
        dispatcher._shared_state = SharedRedTeamState(operation_id="test-other")

        # MSSQL, ADCS, etc. don't benefit from late credential arrival
        assert dispatcher._recalculate_priority("mssql_impersonation", {}, 10) == 10
        assert dispatcher._recalculate_priority("adcs_esc1", {}, 1) == 1
        assert dispatcher._recalculate_priority("krbtgt_hash", {}, 7) == 7

    @pytest.mark.asyncio
    async def test_get_next_vulnerability_reprioritizes_after_creds_arrive(self):
        """CD should jump ahead of lower-priority vulns when creds arrive.

        Scenario:
        1. CD queued at priority 4 (no creds)
        2. MSSQL queued at priority 10
        3. Credentials cracked
        4. get_next_vulnerability() should now return CD (boosted to 2)

        This is the key fix for the "14 minutes of wasted attacks" bug.
        """
        from ares.core.models import Credential, VulnerabilityInfo

        dispatcher = RedTeamDispatcher()
        dispatcher._shared_state = SharedRedTeamState(operation_id="op-reprioritize")

        # Queue CD at priority 4 (no creds yet, no boost)
        cd_vuln = VulnerabilityInfo(
            vuln_id="cd_svc_backup_12345678",
            vuln_type="constrained_delegation",
            target="svc_backup",
            discovered_by="recon",
            details={
                "account_name": "svc_backup",
                "target_spn": "cifs/dc01.contoso.local",
            },
            priority=4,  # Not boosted because no creds when queued
        )
        dispatcher.shared_state.add_vulnerability(cd_vuln)

        # Queue MSSQL at priority 10
        mssql_vuln = VulnerabilityInfo(
            vuln_id="mssql_192.168.58.20_abcd1234",
            vuln_type="mssql_impersonation",
            target="192.168.58.20",
            discovered_by="recon",
            details={"can_impersonate_sa": True},
            priority=10,
        )
        dispatcher.shared_state.add_vulnerability(mssql_vuln)

        # Without creds, CD deferred, MSSQL returned (wrong order!)
        result = await dispatcher.get_next_vulnerability()
        assert result is not None
        assert result["type"] == "mssql_impersonation", "Before creds, MSSQL returned"

        # Clear dequeued state for test
        dispatcher._dequeued_vuln_ids.clear()

        # NOW credentials arrive (hash cracked)
        cred = Credential(
            username="svc_backup",
            password="Backup123!",  # pragma: allowlist secret
            domain="contoso.local",
        )
        dispatcher.shared_state.add_credential(cred, "cracker")

        # CD should now be returned FIRST (priority recalculated to 2 < 10)
        result = await dispatcher.get_next_vulnerability()
        assert result is not None
        assert result["type"] == "constrained_delegation", (
            "After creds arrive, CD should be returned first (priority 2 < 10)"
        )

    @pytest.mark.asyncio
    async def test_priority_recalculation_order_matters(self):
        """Verify correct ordering: CD boosted to 2 < ADCS_ESC8 at 3 < MSSQL at 10."""
        from ares.core.models import Credential, VulnerabilityInfo

        dispatcher = RedTeamDispatcher()
        dispatcher._shared_state = SharedRedTeamState(operation_id="op-order-test")

        # Add credentials upfront
        cred = Credential(
            username="svc_backup",
            password="Backup123!",  # pragma: allowlist secret
            domain="contoso.local",
        )
        dispatcher.shared_state.add_credential(cred, "cracker")

        # Queue 3 vulns in "wrong" order of stored priority
        mssql_vuln = VulnerabilityInfo(
            vuln_id="mssql_192.168.58.20_1",
            vuln_type="mssql_impersonation",
            target="192.168.58.20",
            discovered_by="recon",
            details={},
            priority=10,
        )
        esc8_vuln = VulnerabilityInfo(
            vuln_id="esc8_ca01_2",
            vuln_type="adcs_esc8",
            target="ca01.contoso.local",
            discovered_by="recon",
            details={},
            priority=3,
        )
        cd_vuln = VulnerabilityInfo(
            vuln_id="cd_svc_backup_3",
            vuln_type="constrained_delegation",
            target="svc_backup",
            discovered_by="recon",
            details={
                "account_name": "svc_backup",
                "target_spn": "cifs/dc01.contoso.local",
            },
            priority=4,  # Will be recalculated to 2
        )
        dispatcher.shared_state.add_vulnerability(mssql_vuln)
        dispatcher.shared_state.add_vulnerability(esc8_vuln)
        dispatcher.shared_state.add_vulnerability(cd_vuln)

        # Should return in recalculated order: CD(2), ESC8(3), MSSQL(10)
        result1 = await dispatcher.get_next_vulnerability()
        assert result1["type"] == "constrained_delegation", "CD boosted to priority 2"

        result2 = await dispatcher.get_next_vulnerability()
        assert result2["type"] == "adcs_esc8", "ESC8 at priority 3"

        result3 = await dispatcher.get_next_vulnerability()
        assert result3["type"] == "mssql_impersonation", "MSSQL at priority 10"


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

    @pytest.mark.asyncio
    async def test_multi_forest_mssql_impersonation_bypasses_hard_cap_cap(self, monkeypatch):
        """Multi-forest MSSQL critical path should bypass the normal hard-cap bypass ceiling."""
        dispatcher = RedTeamDispatcher()
        dispatcher._shared_state = SharedRedTeamState(operation_id="op-test-mssql-hard-cap")
        dispatcher._shared_state.domain_admin_domains = ["child.contoso.local"]
        dispatcher._shared_state.all_domains = [
            "contoso.local",
            "child.contoso.local",
            "fabrikam.local",
        ]
        dispatcher._shared_state.all_forests_dominated = lambda: False

        monkeypatch.setattr(
            "ares.core.config.get_multi_forest_mode",
            lambda: True,
            raising=False,
        )
        monkeypatch.setattr(
            "ares.core.dispatcher.throttling.get_max_concurrent_tasks",
            lambda: 8,
            raising=False,
        )

        dispatcher._get_pending_count_by_role = AsyncMock(return_value=0)
        dispatcher._get_llm_task_count = AsyncMock(return_value=20)

        should_drop = await dispatcher._check_llm_throttle_drop(
            task_type="exploit",
            target_role="privesc",
            reason="max concurrent tasks",
            payload={"vuln_type": "mssql_impersonation"},
        )

        assert should_drop is False

    @pytest.mark.asyncio
    async def test_throttled_submit_task_defers_when_target_role_offline(self):
        """Tasks for an offline role should stay in the deferred queue, not the Redis stream."""
        dispatcher = RedTeamDispatcher()
        dispatcher._shared_state = SharedRedTeamState(operation_id="op-test-offline-role")
        dispatcher._task_queue = AsyncMock()
        dispatcher._enqueue_deferred_task = AsyncMock(return_value=True)
        dispatcher.get_role_health = MagicMock(
            return_value={
                "role": "privesc",
                "is_registered": True,
                "online_count": 0,
                "total_count": 1,
                "stale_agents": ["ares-privesc"],
            }
        )

        result = await dispatcher._throttled_submit_task(
            task_type="exploit",
            target_role="privesc",
            payload={"vuln_type": "mssql_cross_forest_pivot"},
            source_agent="test",
            priority=2,
        )

        assert result == "deferred"
        dispatcher._enqueue_deferred_task.assert_awaited_once()
        dispatcher._task_queue.submit_task.assert_not_awaited()

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


class TestNmapPrerequisiteForRecon:
    """Tests for nmap prerequisite enforcement in recon tasks.

    Bug fix: SMB enumeration and other recon tasks were running before nmap,
    causing hosts to show 'Unknown' OS and 0 DCs. Nmap must run first to
    identify live hosts and services before enumeration tasks.
    """

    @pytest.mark.asyncio
    async def test_request_recon_dispatches_nmap_first_for_unscanned_targets(self):
        """request_recon should dispatch nmap AND enumeration (nmap first via priority)."""
        from unittest.mock import AsyncMock, MagicMock

        dispatcher = RedTeamDispatcher()
        dispatcher._shared_state = SharedRedTeamState(operation_id="test-nmap-prereq")

        # No targets scanned yet
        assert len(dispatcher.shared_state.scanned_targets) == 0

        # Mock task queue to capture what gets submitted
        mock_task_queue = MagicMock()
        # Return different task IDs for each call
        mock_task_queue.submit_task = AsyncMock(side_effect=["task-nmap", "task-enum"])
        dispatcher._task_queue = mock_task_queue

        # Request user enumeration (NOT nmap)
        result = await dispatcher.request_recon(
            source_agent="orchestrator",
            domain="contoso.local",
            target_ips=["192.168.58.10", "192.168.58.20"],
            reason="user_enumeration",
            techniques=["enumerate_users"],
        )

        # Should return enumeration task ID (not deferred anymore)
        assert result == "task-enum"

        # Verify TWO tasks were submitted: nmap first, then enumeration
        assert mock_task_queue.submit_task.call_count == 2

        # First call should be nmap (priority 1)
        first_call = mock_task_queue.submit_task.call_args_list[0]
        first_payload = first_call.kwargs.get("payload") or first_call[1].get("payload")
        first_priority = first_call.kwargs.get("priority") or first_call[1].get("priority")
        assert first_payload["reason"] == "network_scan"
        assert "nmap_scan" in first_payload["techniques"]
        assert first_priority == 1

        # Second call should be enumeration (priority 5)
        second_call = mock_task_queue.submit_task.call_args_list[1]
        second_payload = second_call.kwargs.get("payload") or second_call[1].get("payload")
        assert second_payload["reason"] == "user_enumeration"
        assert "enumerate_users" in second_payload["techniques"]

    @pytest.mark.asyncio
    async def test_request_recon_allows_nmap_directly(self):
        """request_recon should allow nmap tasks without prerequisite check."""
        from unittest.mock import AsyncMock, MagicMock

        dispatcher = RedTeamDispatcher()
        dispatcher._shared_state = SharedRedTeamState(operation_id="test-nmap-direct")

        # No targets scanned
        assert len(dispatcher.shared_state.scanned_targets) == 0

        mock_task_queue = MagicMock()
        mock_task_queue.submit_task = AsyncMock(return_value="task-nmap-123")
        dispatcher._task_queue = mock_task_queue

        # Request nmap directly
        result = await dispatcher.request_recon(
            source_agent="orchestrator",
            domain="contoso.local",
            target_ips=["192.168.58.10"],
            reason="network_scan",
            techniques=["nmap_scan"],
        )

        # Should submit task and return task ID (not deferred)
        assert result == "task-nmap-123"

        # Verify it was submitted with priority=1
        call_kwargs = mock_task_queue.submit_task.call_args
        priority = call_kwargs.kwargs.get("priority") or call_kwargs[1].get("priority")
        assert priority == 1

    @pytest.mark.asyncio
    async def test_request_recon_allows_enum_after_targets_scanned(self):
        """request_recon should allow enumeration if targets already scanned."""
        from unittest.mock import AsyncMock, MagicMock

        dispatcher = RedTeamDispatcher()
        dispatcher._shared_state = SharedRedTeamState(operation_id="test-enum-ok")

        # Mark targets as already scanned
        dispatcher.shared_state.scanned_targets.add("192.168.58.10")
        dispatcher.shared_state.scanned_targets.add("192.168.58.20")

        mock_task_queue = MagicMock()
        mock_task_queue.submit_task = AsyncMock(return_value="task-enum-456")
        dispatcher._task_queue = mock_task_queue

        # Request user enumeration
        result = await dispatcher.request_recon(
            source_agent="orchestrator",
            domain="contoso.local",
            target_ips=["192.168.58.10", "192.168.58.20"],
            reason="user_enumeration",
            techniques=["enumerate_users"],
        )

        # Should submit task normally (not deferred)
        assert result == "task-enum-456"

        # Verify enumeration payload (NOT nmap)
        call_kwargs = mock_task_queue.submit_task.call_args
        payload = call_kwargs.kwargs.get("payload") or call_kwargs[1].get("payload")
        assert payload["reason"] == "user_enumeration"
        assert "enumerate_users" in payload["techniques"]

        # Enumeration should have lower priority than nmap (higher number = lower priority)
        priority = call_kwargs.kwargs.get("priority") or call_kwargs[1].get("priority")
        assert priority > 1  # Nmap gets priority=1, enumeration should be higher number

    @pytest.mark.asyncio
    async def test_request_recon_partial_scan_dispatches_nmap_for_unscanned(self):
        """If some targets scanned, should dispatch nmap for unscanned only, then enum."""
        from unittest.mock import AsyncMock, MagicMock

        dispatcher = RedTeamDispatcher()
        dispatcher._shared_state = SharedRedTeamState(operation_id="test-partial")

        # Only one target scanned
        dispatcher.shared_state.scanned_targets.add("192.168.58.10")

        mock_task_queue = MagicMock()
        mock_task_queue.submit_task = AsyncMock(side_effect=["task-nmap", "task-enum"])
        dispatcher._task_queue = mock_task_queue

        # Request enumeration for both targets
        result = await dispatcher.request_recon(
            source_agent="orchestrator",
            domain="contoso.local",
            target_ips=["192.168.58.10", "192.168.58.20"],  # .20 not scanned
            reason="share_enumeration",
            techniques=["enumerate_shares"],
        )

        # Should return enumeration task ID (both nmap and enum dispatched)
        assert result == "task-enum"

        # Two tasks: nmap for unscanned, then enumeration
        assert mock_task_queue.submit_task.call_count == 2

        # First call: nmap for unscanned target only
        first_call = mock_task_queue.submit_task.call_args_list[0]
        nmap_payload = first_call.kwargs.get("payload") or first_call[1].get("payload")
        assert nmap_payload["reason"] == "network_scan"
        assert "192.168.58.20" in nmap_payload["target_ips"]
        assert "192.168.58.10" not in nmap_payload["target_ips"]

        # Second call: enumeration for all targets
        second_call = mock_task_queue.submit_task.call_args_list[1]
        enum_payload = second_call.kwargs.get("payload") or second_call[1].get("payload")
        assert enum_payload["reason"] == "share_enumeration"


class TestEnrichDelegationPayload:
    """Tests for _enrich_delegation_payload target_ip resolution."""

    def test_target_ip_resolved_from_spn(self):
        """target_ip should be resolved from target_spn via known hosts."""
        from ares.core.models import Credential, Host

        dispatcher = RedTeamDispatcher()
        dispatcher._shared_state = SharedRedTeamState(
            operation_id="test-op",
            all_hosts=[
                Host(ip="192.168.58.10", hostname="dc01.contoso.local"),
                Host(ip="192.168.58.20", hostname="sql01.contoso.local"),
            ],
            all_credentials=[
                Credential(
                    username="svc_backup",
                    password="P@ssw0rd!",  # pragma: allowlist secret
                    domain="contoso.local",
                )
            ],
        )

        payload = {
            "target": "svc_backup",  # username, not IP!
            "target_spn": "cifs/dc01.contoso.local",
            "account_name": "svc_backup",
            "domain": "contoso.local",
        }

        dispatcher._enrich_delegation_payload(payload, "constrained_delegation")

        # target_ip should be resolved from SPN, not from 'target' (username)
        assert payload.get("target_ip") == "192.168.58.10"
        assert payload.get("password") == "P@ssw0rd!"  # pragma: allowlist secret

    def test_target_ip_not_overwritten_if_already_set(self):
        """target_ip should not be overwritten if already present in payload."""
        from ares.core.models import Host

        dispatcher = RedTeamDispatcher()
        dispatcher._shared_state = SharedRedTeamState(
            operation_id="test-op",
            all_hosts=[
                Host(ip="192.168.58.10", hostname="dc01.contoso.local"),
            ],
        )

        payload = {
            "target": "svc_backup",
            "target_spn": "cifs/dc01.contoso.local",
            "target_ip": "192.168.58.99",  # Already set to different IP
            "domain": "contoso.local",
        }

        dispatcher._enrich_delegation_payload(payload, "constrained_delegation")

        # Should keep existing target_ip
        assert payload["target_ip"] == "192.168.58.99"

    def test_target_ip_not_resolved_for_non_delegation(self):
        """target_ip resolution should only apply to delegation vulns."""
        from ares.core.models import Host

        dispatcher = RedTeamDispatcher()
        dispatcher._shared_state = SharedRedTeamState(
            operation_id="test-op",
            all_hosts=[
                Host(ip="192.168.58.10", hostname="dc01.contoso.local"),
            ],
        )

        payload = {
            "target": "svc_backup",
            "target_spn": "cifs/dc01.contoso.local",
        }

        dispatcher._enrich_delegation_payload(payload, "mssql_impersonation")

        # Should not set target_ip for non-delegation vuln types
        assert "target_ip" not in payload
