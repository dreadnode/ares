"""Record/Replay system for deterministic red team runs.

This module enables deterministic replay of red team operations by capturing
and replaying external interactions:
- Tool command outputs (subprocess results)
- LLM responses (future)
- Deterministic helpers (UUIDs, timestamps, random values)

Usage:
    # Record mode - capture all interactions
    from ares.core.replay import initialize_replay
    initialize_replay(mode="record", path="/tmp/recording.jsonl")

    # Replay mode - use recorded responses
    initialize_replay(mode="replay", path="/tmp/recording.jsonl")

    # Check if replay is active
    from ares.core.replay import get_replay_store
    store = get_replay_store()
    if store and store.mode == "replay":
        ...

Environment Variables:
    ARES_REPLAY_MODE: "record" | "replay" | "" (off)
    ARES_REPLAY_FILE: Path to JSONL file
    ARES_REPLAY_SEED: Seed for deterministic generation (default: 42)
    ARES_REPLAY_FALLBACK: "error" | "live" | "skip" (default: error)
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Literal

from loguru import logger

from ares.core.replay.store import ReplayEntry, ReplayStore

# Global replay store instance
_replay_store: ReplayStore | None = None


def initialize_replay(
    mode: Literal["record", "replay", "off", ""] = "",
    path: str | Path = "",
    seed: int = 42,
    fallback: Literal["error", "live", "skip"] = "error",
) -> ReplayStore | None:
    """Initialize the global replay store.

    Args:
        mode: Operating mode ("record", "replay", or "" for off).
        path: Path to JSONL file for recording/replay.
        seed: Seed for deterministic value generation.
        fallback: Behavior on cache miss ("error", "live", "skip").

    Returns:
        The initialized ReplayStore, or None if mode is off.
    """
    global _replay_store

    # Close existing store if any
    if _replay_store:
        _replay_store.close()
        _replay_store = None

    # Resolve mode from env if not provided
    if not mode:
        mode = os.environ.get("ARES_REPLAY_MODE", "").lower()  # type: ignore[assignment]

    if mode not in ("record", "replay"):
        logger.debug("Replay mode is off")
        return None

    # Resolve path from env if not provided
    if not path:
        path = os.environ.get("ARES_REPLAY_FILE", "")

    if not path:
        logger.warning(f"Replay mode '{mode}' requested but no file path provided")
        return None

    # Resolve fallback from env
    env_fallback = os.environ.get("ARES_REPLAY_FALLBACK", "").lower()
    if env_fallback in ("error", "live", "skip"):
        fallback = env_fallback  # type: ignore[assignment]

    # Initialize deterministic context if seed provided
    env_seed = os.environ.get("ARES_REPLAY_SEED")
    if env_seed:
        try:
            seed = int(env_seed)
        except ValueError:
            pass

    # Import here to avoid circular deps
    from ares.core.replay.determinism import set_deterministic_context

    if mode in ("record", "replay"):
        set_deterministic_context(seed=seed)
        logger.info(f"Deterministic context initialized with seed={seed}")

    # Create store
    _replay_store = ReplayStore(
        path=Path(path),
        mode=mode,  # type: ignore[arg-type]
        fallback=fallback,
    )

    logger.info(f"Replay store initialized: mode={mode}, path={path}, fallback={fallback}")
    return _replay_store


def get_replay_store() -> ReplayStore | None:
    """Get the global replay store instance.

    Returns:
        The active ReplayStore, or None if not initialized.
    """
    return _replay_store


def shutdown_replay() -> None:
    """Shutdown the global replay store."""
    global _replay_store

    if _replay_store:
        _replay_store.close()
        _replay_store = None
        logger.info("Replay store shutdown")

    # Clear deterministic context
    from ares.core.replay.determinism import clear_deterministic_context

    clear_deterministic_context()


__all__ = [
    "ReplayEntry",
    "ReplayStore",
    "get_replay_store",
    "initialize_replay",
    "shutdown_replay",
]
