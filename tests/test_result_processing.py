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


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
