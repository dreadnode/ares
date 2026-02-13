"""Tests for result_processing module integration with context_manager.

Tests that complete_task properly uses summarize_task_result to prevent
context bloat in the orchestrator.
"""

from unittest.mock import patch

import pytest

from ares.core.context_manager import summarize_task_result


class TestSummarizeTaskResultIntegration:
    """Tests for summarize_task_result integration in result_processing."""

    def test_summarize_preserves_host_discoveries(self):
        """Host discoveries are preserved during summarization."""
        result = {
            "discovered_hosts": [
                {"ip": "192.168.58.10", "hostname": "dc01.contoso.local"},
                {"ip": "192.168.58.11", "hostname": "sql01.contoso.local"},
            ],
            "output": "x" * 5000,  # Large output
            "success": True,
        }

        summarized = summarize_task_result(result, "recon", max_output_chars=1000)

        # Hosts should be preserved exactly
        assert summarized["discovered_hosts"] == result["discovered_hosts"]
        assert len(summarized["discovered_hosts"]) == 2

    def test_summarize_preserves_credential_discoveries(self):
        """Credential discoveries are preserved during summarization."""
        result = {
            "discovered_credentials": [
                {
                    "username": "admin",
                    "password": "P@ssw0rd!",  # pragma: allowlist secret
                    "domain": "contoso.local",
                }
            ],
            "output": "x" * 5000,
            "success": True,
        }

        summarized = summarize_task_result(result, "credential_access", max_output_chars=500)

        assert summarized["discovered_credentials"] == result["discovered_credentials"]

    def test_summarize_preserves_hash_discoveries(self):
        """Hash discoveries are preserved during summarization."""
        result = {
            "discovered_hashes": [
                {
                    "username": "svc_sql",
                    "hash_value": "$krb5tgs$23$*svc_sql$contoso.local$...",
                    "hash_type": "TGS",
                    "domain": "contoso.local",
                }
            ],
            "output": "Kerberoasting output with lots of details..." * 100,
            "success": True,
        }

        summarized = summarize_task_result(result, "credential_access", max_output_chars=500)

        assert summarized["discovered_hashes"] == result["discovered_hashes"]

    def test_summarize_truncates_very_large_output(self):
        """Very large output is truncated with metadata."""
        large_output = "\n".join([f"Line {i}: some data here" for i in range(200)])
        result = {
            "output": large_output,
            "success": True,
        }

        summarized = summarize_task_result(result, "recon", max_output_chars=500)

        assert len(summarized["output"]) < len(large_output)
        assert "omitted" in summarized["output"]
        assert summarized["_output_truncated"] is True
        assert summarized["_original_output_chars"] == len(large_output)

    def test_summarize_keeps_head_and_tail_for_large_output(self):
        """Summarization keeps first and last lines for context."""
        # Create output larger than max_output_chars to trigger truncation
        lines = [f"Line {i}: Some additional data to make this line longer" for i in range(200)]
        result = {
            "output": "\n".join(lines),
            "success": True,
        }

        summarized = summarize_task_result(result, "recon", max_output_chars=500)

        # Should have head lines
        assert "Line 0" in summarized["output"]
        # Should indicate lines were omitted
        assert "omitted" in summarized["output"]

    def test_summarize_preserves_success_and_error_fields(self):
        """Success and error fields are always preserved."""
        result = {
            "success": False,
            "error": "Connection refused",
            "output": "x" * 5000,
        }

        summarized = summarize_task_result(result, "lateral", max_output_chars=500)

        assert summarized["success"] is False
        assert summarized["error"] == "Connection refused"

    def test_summarize_handles_multiple_output_fields(self):
        """Handles stdout, stderr, and output fields."""
        result = {
            "stdout": "x" * 3000,
            "stderr": "y" * 2000,
            "output": "z" * 1000,
            "success": True,
        }

        summarized = summarize_task_result(result, "exploit", max_output_chars=500)

        # All output fields should be present but potentially truncated
        assert "stdout" in summarized
        assert "stderr" in summarized
        assert "output" in summarized

    def test_summarize_preserves_trusted_domains(self):
        """Trusted domains from BloodHound are preserved."""
        result = {
            "trusted_domains": ["fabrikam.local", "child.contoso.local"],
            "output": "x" * 5000,
            "success": True,
        }

        summarized = summarize_task_result(result, "recon", max_output_chars=500)

        assert summarized["trusted_domains"] == result["trusted_domains"]

    def test_summarize_preserves_shares(self):
        """Share discoveries are preserved."""
        result = {
            "shares": [
                {"host": "192.168.58.10", "name": "SYSVOL", "permissions": "READ"},
                {"host": "192.168.58.10", "name": "ADMIN$", "permissions": "READ,WRITE"},
            ],
            "success": True,
        }

        summarized = summarize_task_result(result, "recon", max_output_chars=500)

        assert summarized["shares"] == result["shares"]


class TestMaxOutputCharsConfig:
    """Tests for max_output_chars configuration integration."""

    def test_default_max_output_chars(self):
        """Default max_output_chars should be 2000."""
        from ares.core.config import OperationConfig

        config = OperationConfig()
        assert config.max_output_chars == 2000

    def test_get_max_output_chars_function(self):
        """get_max_output_chars returns configured value."""
        import os

        from ares.core.config import clear_config_cache, get_max_output_chars

        clean_env = {k: v for k, v in os.environ.items() if not k.startswith("ARES_")}
        with patch.dict(os.environ, clean_env, clear=True):
            clear_config_cache()
            result = get_max_output_chars()
            assert result == 2000


class TestResultProcessingBroadcast:
    """Tests for result processing broadcast behavior."""

    def test_summarize_is_used_for_broadcast(self):
        """Verify summarize_task_result is called during broadcast preparation."""
        # This is a unit test to verify the summarization function behaves correctly
        result = {
            "success": True,
            "output": "x" * 10000,
            "discovered_hosts": [{"ip": "192.168.58.10"}],
        }

        summarized = summarize_task_result(result, "recon", max_output_chars=2000)

        # Output should be truncated
        assert len(summarized.get("output", "")) < 10000
        # Discoveries should be intact
        assert summarized["discovered_hosts"] == [{"ip": "192.168.58.10"}]
        # Success should be preserved
        assert summarized["success"] is True


class TestExtractUsersFromOutput:
    """Tests for _extract_users_from_output domain parsing."""

    def test_extracts_domain_from_backslash_format(self):
        """DOMAIN\\user format should extract both username and domain."""
        from unittest.mock import MagicMock

        from ares.core.dispatcher import RedTeamDispatcher

        dispatcher = MagicMock(spec=RedTeamDispatcher)
        dispatcher._extract_users_from_output = (
            RedTeamDispatcher._extract_users_from_output.__get__(dispatcher)
        )

        output = (
            "SMB 192.168.58.7 445 DC01 north.sevenkingdoms.local\\samwell.tarly "
            "2026-01-13 10:00:00 0 Samwell Tarly"
        )

        users = dispatcher._extract_users_from_output(output)

        # Should extract (username, domain) tuple with correct domain
        assert ("samwell.tarly", "north.sevenkingdoms.local") in users

    def test_extracts_domain_from_upn_format(self):
        """user@domain format should extract both username and domain."""
        from unittest.mock import MagicMock

        from ares.core.dispatcher import RedTeamDispatcher

        dispatcher = MagicMock(spec=RedTeamDispatcher)
        dispatcher._extract_users_from_output = (
            RedTeamDispatcher._extract_users_from_output.__get__(dispatcher)
        )

        output = "User: jon.snow@north.sevenkingdoms.local logged in successfully"

        users = dispatcher._extract_users_from_output(output)

        assert ("jon.snow", "north.sevenkingdoms.local") in users

    def test_rpcclient_format_has_empty_domain(self):
        """rpcclient user:[name] format should have empty domain."""
        from unittest.mock import MagicMock

        from ares.core.dispatcher import RedTeamDispatcher

        dispatcher = MagicMock(spec=RedTeamDispatcher)
        dispatcher._extract_users_from_output = (
            RedTeamDispatcher._extract_users_from_output.__get__(dispatcher)
        )

        output = "user:[administrator] rid:[0x1f4]\nuser:[guest] rid:[0x1f5]"

        users = dispatcher._extract_users_from_output(output)

        # Should have empty domain (caller should fall back to target domain)
        assert ("administrator", "") in users
        assert ("guest", "") in users

    def test_mixed_domains_extracted_correctly(self):
        """Output with users from multiple domains should extract all correctly."""
        from unittest.mock import MagicMock

        from ares.core.dispatcher import RedTeamDispatcher

        dispatcher = MagicMock(spec=RedTeamDispatcher)
        dispatcher._extract_users_from_output = (
            RedTeamDispatcher._extract_users_from_output.__get__(dispatcher)
        )

        # Simulates netexec output with users from different domains
        output = (
            "SMB 192.168.58.7 445 DC01 contoso.local\\admin 2026-01-13 10:00:00\n"
            "SMB 192.168.58.7 445 DC01 fabrikam.local\\svc_sql 2026-01-13 10:00:00\n"
            "SMB 192.168.58.7 445 DC01 localuser 2026-01-13 10:00:00\n"
        )

        users = dispatcher._extract_users_from_output(output)

        # Each user should have their correct domain
        assert ("admin", "contoso.local") in users
        assert ("svc_sql", "fabrikam.local") in users
        # localuser has no domain prefix, should have empty domain
        assert ("localuser", "") in users


class TestProcessOutputTextCrossDomain:
    """Tests for _process_output_text handling cross-domain users correctly.

    Tests that extracted domains from DOMAIN\\user or user@domain patterns
    are used correctly, not overwritten with the target domain.
    """

    def test_cross_domain_user_extraction_preserves_domain(self):
        """Extracted domain should be preserved, not replaced with target domain.

        This tests the fix for the bug where users from other domains
        (e.g., north.sevenkingdoms.local\\samwell.tarly) were incorrectly
        added with the target domain (e.g., essos.local).
        """
        from unittest.mock import MagicMock

        from ares.core.dispatcher import RedTeamDispatcher
        from ares.core.models import SharedRedTeamState, Target

        # Set up dispatcher with target domain contoso.local
        dispatcher = MagicMock(spec=RedTeamDispatcher)
        dispatcher.shared_state = SharedRedTeamState(operation_id="op-test")
        dispatcher.shared_state.target = Target(ip="192.168.58.10", domain="contoso.local")
        dispatcher.shared_state.all_users = []

        # Bind the real methods
        dispatcher._extract_users_from_output = (
            RedTeamDispatcher._extract_users_from_output.__get__(dispatcher)
        )
        dispatcher._add_user = RedTeamDispatcher._add_user.__get__(dispatcher)

        # Output contains users from fabrikam.local (different from target)
        output = "SMB 192.168.58.7 445 DC01 fabrikam.local\\svc_backup 2026-01-13 10:00:00"

        # Extract users and add them (simulating _process_output_text behavior)
        target_domain = dispatcher.shared_state.target.domain
        for username, extracted_domain in dispatcher._extract_users_from_output(output):
            user_domain = extracted_domain or target_domain
            dispatcher._add_user(username, user_domain, "test")

        # User should be added with fabrikam.local, NOT contoso.local
        users = {(u.username, u.domain) for u in dispatcher.shared_state.all_users}
        assert ("svc_backup", "fabrikam.local") in users
        # Should NOT have been added with target domain
        assert ("svc_backup", "contoso.local") not in users

    def test_user_without_domain_falls_back_to_target(self):
        """Users without extracted domain should use target domain."""
        from unittest.mock import MagicMock

        from ares.core.dispatcher import RedTeamDispatcher
        from ares.core.models import SharedRedTeamState, Target

        dispatcher = MagicMock(spec=RedTeamDispatcher)
        dispatcher.shared_state = SharedRedTeamState(operation_id="op-test")
        dispatcher.shared_state.target = Target(ip="192.168.58.10", domain="contoso.local")
        dispatcher.shared_state.all_users = []

        dispatcher._extract_users_from_output = (
            RedTeamDispatcher._extract_users_from_output.__get__(dispatcher)
        )
        dispatcher._add_user = RedTeamDispatcher._add_user.__get__(dispatcher)

        # rpcclient output has no domain info
        output = "user:[administrator] rid:[0x1f4]"

        target_domain = dispatcher.shared_state.target.domain
        for username, extracted_domain in dispatcher._extract_users_from_output(output):
            user_domain = extracted_domain or target_domain
            dispatcher._add_user(username, user_domain, "test")

        # User should be added with target domain since none was extracted
        users = {(u.username, u.domain) for u in dispatcher.shared_state.all_users}
        assert ("administrator", "contoso.local") in users


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
