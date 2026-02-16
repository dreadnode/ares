"""Tests for context_manager module.

Tests context offloading and summarization functionality to prevent
context window exhaustion in long-running agent operations.
"""

from unittest.mock import AsyncMock, MagicMock

import pytest

from ares.core.config import get_offload_threshold
from ares.core.context_manager import (
    ContextOffloader,
    _hash_content,
    estimate_tokens,
    offload_large_output,
    retrieve_offloaded_output,
    summarize_task_result,
)


class TestHashContent:
    """Tests for _hash_content function."""

    def test_hash_content_returns_12_chars(self):
        """Hash should be exactly 12 characters."""
        result = _hash_content("test content")
        assert len(result) == 12

    def test_hash_content_is_deterministic(self):
        """Same content should produce same hash."""
        content = "hello world"
        assert _hash_content(content) == _hash_content(content)

    def test_hash_content_different_for_different_content(self):
        """Different content should produce different hashes."""
        assert _hash_content("content a") != _hash_content("content b")

    def test_hash_content_handles_empty_string(self):
        """Empty string should produce a valid hash."""
        result = _hash_content("")
        assert len(result) == 12


class TestEstimateTokens:
    """Tests for estimate_tokens function."""

    def test_estimate_tokens_empty_string(self):
        """Empty string should return 0 tokens."""
        assert estimate_tokens("") == 0

    def test_estimate_tokens_short_text(self):
        """Short text should return expected token count."""
        # "hello world" is 11 chars, ~2.75 tokens, truncates to 2
        assert estimate_tokens("hello world") == 2

    def test_estimate_tokens_longer_text(self):
        """Longer text follows 4 chars per token rule."""
        text = "a" * 100
        assert estimate_tokens(text) == 25

    def test_estimate_tokens_with_code(self):
        """Code content uses same heuristic."""
        code = "def hello():\n    return 'world'"
        # 31 chars / 4 = 7 tokens
        assert estimate_tokens(code) == 7


class TestOffloadLargeOutput:
    """Tests for offload_large_output function."""

    @pytest.mark.asyncio
    async def test_offload_below_threshold_returns_original(self):
        """Content below threshold is returned unchanged."""
        redis = AsyncMock()
        output = "short output"

        result, was_offloaded = await offload_large_output(
            redis=redis,
            operation_id="op-123",
            task_id="task-456",
            output=output,
            threshold=100,
        )

        assert result == output
        assert was_offloaded is False
        redis.set.assert_not_called()

    @pytest.mark.asyncio
    async def test_offload_above_threshold_stores_in_redis(self):
        """Content above threshold is stored in Redis."""
        redis = AsyncMock()
        output = "x" * 200  # Above threshold

        _result, was_offloaded = await offload_large_output(
            redis=redis,
            operation_id="op-123",
            task_id="task-456",
            output=output,
            threshold=100,
        )

        assert was_offloaded is True
        redis.set.assert_called_once()

        # Check Redis key format
        call_args = redis.set.call_args
        key = call_args[0][0]
        assert key.startswith("ares:op:op-123:output:task-456:")

        # Check stored content
        stored_content = call_args[0][1]
        assert stored_content == output

    @pytest.mark.asyncio
    async def test_offload_creates_summary_with_preview(self):
        """Offloaded content includes preview and reference."""
        redis = AsyncMock()
        lines = [f"line {i}" for i in range(20)]
        output = "\n".join(lines)

        result, _ = await offload_large_output(
            redis=redis,
            operation_id="op-123",
            task_id="task-456",
            output=output,
            threshold=50,
        )

        # Summary should include first 10 lines preview
        assert "line 0" in result
        assert "[Output truncated" in result
        assert "task-456" in result
        assert "retrieve_task_output" in result

    @pytest.mark.asyncio
    async def test_offload_uses_correct_ttl(self):
        """Offloaded content uses 4 hour TTL."""
        from ares.core.config import get_offload_ttl

        redis = AsyncMock()
        output = "x" * 200

        await offload_large_output(
            redis=redis,
            operation_id="op-123",
            task_id="task-456",
            output=output,
            threshold=100,
        )

        # Check TTL is set
        call_kwargs = redis.set.call_args[1]
        assert call_kwargs["ex"] == get_offload_ttl()


class TestRetrieveOffloadedOutput:
    """Tests for retrieve_offloaded_output function."""

    @pytest.mark.asyncio
    async def test_retrieve_returns_none_when_no_keys(self):
        """Returns None when no matching keys found."""
        redis = AsyncMock()
        redis.scan_iter = MagicMock(return_value=AsyncIterator([]))

        result = await retrieve_offloaded_output(
            redis=redis,
            operation_id="op-123",
            task_id="task-456",
        )

        assert result is None

    @pytest.mark.asyncio
    async def test_retrieve_returns_content_from_redis(self):
        """Returns stored content from Redis."""
        redis = AsyncMock()
        keys = ["ares:op:op-123:output:task-456:abc123"]
        redis.scan_iter = MagicMock(return_value=AsyncIterator(keys))
        redis.get = AsyncMock(return_value=b"full output content")

        result = await retrieve_offloaded_output(
            redis=redis,
            operation_id="op-123",
            task_id="task-456",
        )

        assert result == "full output content"

    @pytest.mark.asyncio
    async def test_retrieve_handles_string_response(self):
        """Handles Redis returning string instead of bytes."""
        redis = AsyncMock()
        keys = ["ares:op:op-123:output:task-456:abc123"]
        redis.scan_iter = MagicMock(return_value=AsyncIterator(keys))
        redis.get = AsyncMock(return_value="full output content")

        result = await retrieve_offloaded_output(
            redis=redis,
            operation_id="op-123",
            task_id="task-456",
        )

        assert result == "full output content"

    @pytest.mark.asyncio
    async def test_retrieve_uses_most_recent_key(self):
        """When multiple keys exist, uses the last one alphabetically."""
        redis = AsyncMock()
        keys = [
            "ares:op:op-123:output:task-456:aaa",
            "ares:op:op-123:output:task-456:zzz",
            "ares:op:op-123:output:task-456:mmm",
        ]
        redis.scan_iter = MagicMock(return_value=AsyncIterator(keys))
        redis.get = AsyncMock(return_value=b"latest content")

        await retrieve_offloaded_output(
            redis=redis,
            operation_id="op-123",
            task_id="task-456",
        )

        # Should fetch the last key when sorted
        redis.get.assert_called_once_with("ares:op:op-123:output:task-456:zzz")


class TestSummarizeTaskResult:
    """Tests for summarize_task_result function."""

    def test_summarize_preserves_structured_discoveries(self):
        """Structured discovery fields are preserved intact."""
        result = {
            "discovered_hosts": [{"ip": "192.168.58.10", "hostname": "dc01"}],
            "discovered_credentials": [
                {"username": "admin", "password": "pass"}  # pragma: allowlist secret
            ],
            "discovered_hashes": [{"username": "user1", "hash_value": "abc123"}],
            "success": True,
            "output": "some output",
        }

        summarized = summarize_task_result(result, "recon")

        assert summarized["discovered_hosts"] == result["discovered_hosts"]
        assert summarized["discovered_credentials"] == result["discovered_credentials"]
        assert summarized["discovered_hashes"] == result["discovered_hashes"]
        assert summarized["success"] is True

    def test_summarize_truncates_large_output(self):
        """Large output field is truncated."""
        large_output = "\n".join([f"line {i}" for i in range(100)])
        result = {
            "success": True,
            "output": large_output,
        }

        summarized = summarize_task_result(result, "recon", max_output_chars=500)

        assert len(summarized["output"]) < len(large_output)
        assert "omitted" in summarized["output"]
        assert summarized["_output_truncated"] is True
        assert summarized["_original_output_chars"] == len(large_output)

    def test_summarize_few_long_lines_no_negative(self):
        """Few but very long lines should not show negative omitted count."""
        # 5 lines, each 200 chars = 1000 chars total, exceeds 500 max
        long_lines = "\n".join(["x" * 200 for _ in range(5)])
        result = {
            "success": True,
            "output": long_lines,
        }

        summarized = summarize_task_result(result, "recon", max_output_chars=500)

        # Should not contain negative numbers
        assert "-" not in summarized["output"] or "truncated" in summarized["output"]
        # Should mention truncation with char count, not negative lines
        assert "chars total" in summarized["output"]

    def test_summarize_exactly_20_lines(self):
        """Exactly 20 lines should use head-only format without negative count."""
        lines_20 = "\n".join([f"line {i}: " + "x" * 50 for i in range(20)])
        result = {
            "success": True,
            "output": lines_20,
        }

        summarized = summarize_task_result(result, "recon", max_output_chars=500)

        # Should show 5 lines omitted (20 - 15 head lines)
        assert "5 lines omitted" in summarized["output"]

    def test_summarize_keeps_small_output(self):
        """Small output is preserved unchanged."""
        result = {
            "success": True,
            "output": "small output",
        }

        summarized = summarize_task_result(result, "recon", max_output_chars=500)

        assert summarized["output"] == "small output"
        assert "_output_truncated" not in summarized

    def test_summarize_handles_stdout_stderr(self):
        """Handles stdout and stderr fields."""
        result = {
            "success": True,
            "stdout": "x" * 3000,
            "stderr": "error message",
        }

        summarized = summarize_task_result(result, "recon", max_output_chars=500)

        assert "stdout" in summarized
        assert "stderr" in summarized

    def test_summarize_handles_empty_result(self):
        """Handles empty result dict."""
        result = {}
        summarized = summarize_task_result(result, "recon")
        assert summarized == {}

    def test_summarize_preserves_error_field(self):
        """Error field is preserved."""
        result = {
            "success": False,
            "error": "Connection failed",
        }

        summarized = summarize_task_result(result, "exploit")

        assert summarized["error"] == "Connection failed"
        assert summarized["success"] is False

    def test_summarize_preserves_task_id(self):
        """Task ID field is preserved."""
        result = {
            "task_id": "task-123",
            "success": True,
        }

        summarized = summarize_task_result(result, "recon")
        assert summarized["task_id"] == "task-123"


class TestContextOffloader:
    """Tests for ContextOffloader class."""

    @pytest.fixture
    def mock_redis(self):
        """Create mock Redis client."""
        redis = AsyncMock()
        redis.set = AsyncMock()
        redis.get = AsyncMock(return_value=None)
        redis.scan_iter = MagicMock(return_value=AsyncIterator([]))
        return redis

    @pytest.fixture
    def offloader(self, mock_redis):
        """Create ContextOffloader instance."""
        return ContextOffloader(
            redis=mock_redis,
            operation_id="test-op",
            offload_threshold=100,
        )

    @pytest.mark.asyncio
    async def test_process_task_result_small_output(self, offloader, mock_redis):
        """Small outputs are summarized but not offloaded."""
        result = {
            "success": True,
            "output": "small",
        }

        processed = await offloader.process_task_result("task-1", result, "recon")

        assert processed["success"] is True
        mock_redis.set.assert_not_called()
        assert offloader.offloaded_task_count == 0

    @pytest.mark.asyncio
    async def test_process_task_result_large_output(self, offloader, mock_redis):
        """Large outputs are offloaded to Redis."""
        result = {
            "success": True,
            "output": "x" * 200,
        }

        processed = await offloader.process_task_result("task-1", result, "recon")

        mock_redis.set.assert_called_once()
        assert offloader.offloaded_task_count == 1
        assert processed.get("_full_output_available") is True

    @pytest.mark.asyncio
    async def test_process_task_result_preserves_discoveries(self, offloader):
        """Discoveries are preserved regardless of offloading."""
        result = {
            "success": True,
            "output": "x" * 200,
            "discovered_hosts": [{"ip": "192.168.58.10"}],
        }

        processed = await offloader.process_task_result("task-1", result, "recon")

        assert processed["discovered_hosts"] == [{"ip": "192.168.58.10"}]

    @pytest.mark.asyncio
    async def test_retrieve_output(self, offloader, mock_redis):
        """retrieve_output calls retrieve_offloaded_output."""
        mock_redis.scan_iter = MagicMock(
            return_value=AsyncIterator(["ares:op:test-op:output:task-1:abc"])
        )
        mock_redis.get = AsyncMock(return_value=b"full content")

        result = await offloader.retrieve_output("task-1")

        assert result == "full content"

    def test_offloaded_task_count(self, offloader):
        """offloaded_task_count returns correct count."""
        offloader._offloaded_tasks = {"task-1", "task-2", "task-3"}
        assert offloader.offloaded_task_count == 3


class TestDefaultOffloadThreshold:
    """Tests for default threshold constant."""

    def test_default_threshold_is_reasonable(self):
        """Default threshold should be 5000 characters."""
        assert get_offload_threshold() == 5000


# Helper for async iteration
class AsyncIterator:
    """Helper to create async iterator from list."""

    def __init__(self, items):
        self.items = items
        self.index = 0

    def __aiter__(self):
        return self

    async def __anext__(self):
        if self.index >= len(self.items):
            raise StopAsyncIteration
        item = self.items[self.index]
        self.index += 1
        return item


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
