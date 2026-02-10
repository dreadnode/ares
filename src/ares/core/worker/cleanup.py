"""Cleanup utilities for worker agents."""

from __future__ import annotations

from loguru import logger


async def close_litellm_clients() -> None:
    """Close LiteLLM's internal aiohttp client sessions.

    LiteLLM lazily creates aiohttp.ClientSession objects for async API calls.
    If these aren't explicitly closed before shutdown, Python's garbage collector
    logs warnings about unclosed sessions. This function cleanly closes them.
    """
    try:
        import litellm

        if hasattr(litellm, "close_litellm_async_clients"):
            await litellm.close_litellm_async_clients()
            logger.debug("Closed LiteLLM async HTTP clients")
    except Exception as e:
        # Non-critical - just log and continue shutdown
        logger.debug(f"Failed to close LiteLLM clients: {e}")
