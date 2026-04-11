"""Tests for the ares-ops runtime command token usage display."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest


@pytest.mark.asyncio
async def test_runtime_shows_token_usage_and_cost(capsys):
    """runtime command should display per-model token usage and estimated cost."""
    from ares.cli_ops import runtime

    started_at = datetime.now(timezone.utc) - timedelta(minutes=5)
    completed_at = started_at + timedelta(minutes=3)
    state = SimpleNamespace(
        started_at=started_at,
        completed_at=completed_at,
        all_credentials=[],
        all_hashes=[],
        all_hosts=[],
        all_shares=[],
        discovered_vulnerabilities=[],
        exploited_vulnerabilities=[],
        has_domain_admin=False,
        domain_admin_domains=[],
        domain_admin_path="",
        has_golden_ticket=False,
        golden_tickets=[],
    )

    redis_client = AsyncMock()
    redis_client.exists = AsyncMock(return_value=0)
    redis_client.aclose = AsyncMock()

    task_queue = AsyncMock()
    task_queue.connect = AsyncMock()
    task_queue.disconnect = AsyncMock()
    task_queue.get_token_usage = AsyncMock(
        return_value={
            "input_tokens": 300,
            "output_tokens": 120,
            "model": "openai/gpt-5-mini",
            "models": {
                "openai/gpt-4.1-mini": {"input_tokens": 100, "output_tokens": 20},
                "openai/gpt-5-mini": {"input_tokens": 200, "output_tokens": 100},
            },
        }
    )

    fake_litellm = SimpleNamespace(
        cost_per_token=lambda model, _prompt_tokens, _completion_tokens: {
            "openai/gpt-4.1-mini": (0.01, 0.02),
            "openai/gpt-5-mini": (0.03, 0.07),
        }[model]
    )

    with (
        patch(
            "ares.cli_ops.create_verified_redis_client",
            new=AsyncMock(return_value=redis_client),
        ),
        patch(
            "ares.cli_ops._load_state_from_redis",
            new=AsyncMock(return_value=state),
        ),
        patch(
            "ares.core.task_queue.RedisTaskQueue",
            return_value=task_queue,
        ),
        patch.dict("sys.modules", {"litellm": fake_litellm}),
    ):
        await runtime("op-contoso-cost-test")

    captured = capsys.readouterr().out
    assert "Tokens: 420" in captured
    assert "openai/gpt-4.1-mini" in captured
    assert "openai/gpt-5-mini" in captured
    assert "$" in captured
