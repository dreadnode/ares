"""Helpers for rendering and pricing operation token usage."""

from __future__ import annotations

from typing import Any


def get_usage_models(usage: dict[str, Any] | None) -> dict[str, dict[str, int]]:
    """Return per-model token usage, falling back to legacy single-model data."""
    if not usage:
        return {}

    models = usage.get("models") or {}
    if models:
        return {
            str(model): {
                "input_tokens": int(model_usage.get("input_tokens", 0)),
                "output_tokens": int(model_usage.get("output_tokens", 0)),
            }
            for model, model_usage in models.items()
        }

    model = str(usage.get("model", "") or "").strip()
    if not model:
        return {}

    return {
        model: {
            "input_tokens": int(usage.get("input_tokens", 0)),
            "output_tokens": int(usage.get("output_tokens", 0)),
        }
    }


def estimate_usage_cost(
    usage: dict[str, Any] | None,
) -> tuple[float | None, list[dict[str, Any]], list[str]]:
    """Estimate total token cost from per-model usage data.

    Returns:
        (total_cost, priced_breakdown, unpriced_models)
    """
    models = get_usage_models(usage)
    if not models:
        return None, [], []

    try:
        import litellm
    except Exception:
        return None, [], sorted(models)

    total_cost = 0.0
    breakdown: list[dict[str, Any]] = []
    unpriced_models: list[str] = []

    for model in sorted(models):
        input_tokens = models[model]["input_tokens"]
        output_tokens = models[model]["output_tokens"]
        try:
            input_cost, output_cost = litellm.cost_per_token(
                model,
                prompt_tokens=input_tokens,
                completion_tokens=output_tokens,
            )
        except Exception:
            unpriced_models.append(model)
            continue

        cost = input_cost + output_cost
        total_cost += cost
        breakdown.append(
            {
                "model": model,
                "input_tokens": input_tokens,
                "output_tokens": output_tokens,
                "total_tokens": input_tokens + output_tokens,
                "cost": cost,
            }
        )

    if not breakdown:
        return None, [], unpriced_models

    return total_cost, breakdown, unpriced_models
