"""Deterministic value generation for replay mode.

This module provides deterministic alternatives to non-deterministic operations
(UUID generation, timestamps, random values) that can be used during replay
to ensure reproducible results.

When a DeterministicContext is active, functions like get_deterministic_uuid()
return values from a seeded sequence. When no context is active, they fall
back to the real implementations.

Usage:
    # Enable deterministic mode
    from ares.core.replay.determinism import set_deterministic_context
    set_deterministic_context(seed=42)

    # Use deterministic values
    from ares.core.replay.determinism import get_deterministic_uuid
    uuid = get_deterministic_uuid()  # Returns counter-based UUID

    # Without context, falls back to real uuid4()
    clear_deterministic_context()
    uuid = get_deterministic_uuid()  # Returns real uuid4()
"""

from __future__ import annotations

import random
import uuid
from contextvars import ContextVar
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone


@dataclass
class DeterministicContext:
    """Context for deterministic value generation.

    Provides seeded, reproducible values for UUIDs, timestamps, and random numbers.

    Attributes:
        seed: Random seed for reproducibility.
        uuid_counter: Counter for generating sequential UUIDs.
        time_offset: Seconds since virtual start time.
        random_gen: Seeded random generator.
    """

    seed: int = 42
    uuid_counter: int = field(default=0)
    time_offset: float = field(default=0.0)
    random_gen: random.Random = field(default=None)  # type: ignore[assignment]
    _start_time: datetime = field(default=None)  # type: ignore[assignment]

    def __post_init__(self) -> None:
        """Initialize the random generator and start time."""
        self.random_gen = random.Random(self.seed)  # noqa: S311  # nosec B311
        self._start_time = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)

    def next_uuid(self) -> str:
        """Generate the next deterministic UUID.

        Returns a UUID where the first 8 hex chars encode the counter value,
        making it easy to identify the sequence.
        """
        self.uuid_counter += 1
        # Format: counter in first 8 chars, then seeded random for rest
        counter_hex = f"{self.uuid_counter:08x}"
        # Use seeded random for remaining chars to ensure uniqueness with same counter
        random_hex = "".join(f"{self.random_gen.randint(0, 255):02x}" for _ in range(12))
        # Build UUID format: 8-4-4-4-12
        return f"{counter_hex}-{random_hex[:4]}-{random_hex[4:8]}-{random_hex[8:12]}-{random_hex[12:24]}"

    def now(self) -> datetime:
        """Get the current virtual time.

        Returns a timestamp that advances by 1 second each call.
        """
        current = self._start_time + timedelta(seconds=self.time_offset)
        self.time_offset += 1.0  # Advance 1 second per call
        return current

    def random(self) -> float:
        """Get a seeded random float [0.0, 1.0)."""
        return self.random_gen.random()

    def randint(self, a: int, b: int) -> int:
        """Get a seeded random integer [a, b]."""
        return self.random_gen.randint(a, b)

    def choice(self, seq: list) -> any:
        """Choose a random element from a sequence."""
        return self.random_gen.choice(seq)


# Context variable for thread isolation
_context: ContextVar[DeterministicContext | None] = ContextVar(
    "deterministic_context", default=None
)


def set_deterministic_context(seed: int = 42) -> DeterministicContext:
    """Set the deterministic context for the current async context.

    Args:
        seed: Random seed for reproducibility.

    Returns:
        The created DeterministicContext.
    """
    ctx = DeterministicContext(seed=seed)
    _context.set(ctx)
    return ctx


def get_deterministic_context() -> DeterministicContext | None:
    """Get the current deterministic context, if any."""
    return _context.get()


def clear_deterministic_context() -> None:
    """Clear the deterministic context."""
    _context.set(None)


def get_deterministic_uuid() -> str:
    """Get a UUID, deterministic if context is active.

    Returns:
        A deterministic UUID if context is active, otherwise uuid4().
    """
    ctx = _context.get()
    if ctx is not None:
        return ctx.next_uuid()
    return str(uuid.uuid4())


def get_deterministic_time() -> datetime:
    """Get a timestamp, deterministic if context is active.

    Returns:
        A deterministic timestamp if context is active, otherwise now().
    """
    ctx = _context.get()
    if ctx is not None:
        return ctx.now()
    return datetime.now(timezone.utc)


def get_deterministic_random() -> float:
    """Get a random float, deterministic if context is active.

    Returns:
        A seeded random float if context is active, otherwise random().
    """
    ctx = _context.get()
    if ctx is not None:
        return ctx.random()
    return random.random()  # noqa: S311  # nosec B311


__all__ = [
    "DeterministicContext",
    "clear_deterministic_context",
    "get_deterministic_context",
    "get_deterministic_random",
    "get_deterministic_time",
    "get_deterministic_uuid",
    "set_deterministic_context",
]
