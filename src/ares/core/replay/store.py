"""Thread-safe JSONL recording and playback for deterministic replay.

This module provides the core storage mechanism for recording and replaying
external interactions (tool commands, LLM responses) to enable deterministic
red team runs.

Recording Format (JSONL):
    {"entry_type":"tool","key_hash":"abc123","seq":1,"ts":"2026-02-17T10:00:00Z",
     "request":{"cmd":"nmap -sV 192.168.58.10"},"response":{"stdout":"...","rc":0}}
"""

from __future__ import annotations

import hashlib
import json
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Literal, Self

from loguru import logger

if TYPE_CHECKING:
    import types
    from pathlib import Path


@dataclass
class ReplayEntry:
    """A single recorded entry for replay.

    Attributes:
        entry_type: Type of entry ("tool", "llm").
        key_hash: SHA256 hash of normalized input for lookup.
        request: Original request data (for debugging).
        response: Recorded response to replay.
        timestamp: ISO timestamp of recording.
        sequence: Order in the recording session.
    """

    entry_type: str
    key_hash: str
    request: dict[str, Any]
    response: dict[str, Any]
    timestamp: str
    sequence: int

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "entry_type": self.entry_type,
            "key_hash": self.key_hash,
            "request": self.request,
            "response": self.response,
            "ts": self.timestamp,
            "seq": self.sequence,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ReplayEntry:
        """Create from dictionary (JSON deserialization)."""
        return cls(
            entry_type=data["entry_type"],
            key_hash=data["key_hash"],
            request=data.get("request", {}),
            response=data.get("response", {}),
            timestamp=data.get("ts", ""),
            sequence=data.get("seq", 0),
        )


@dataclass
class ReplayStore:
    """Thread-safe store for recording and replaying interactions.

    In record mode, writes entries to a JSONL file.
    In replay mode, loads entries and provides lookups by key hash.

    Attributes:
        path: Path to the JSONL file.
        mode: Operating mode ("record", "replay", "off").
        fallback: Behavior on cache miss in replay mode ("error", "live", "skip").
    """

    path: Path
    mode: Literal["record", "replay", "off"]
    fallback: Literal["error", "live", "skip"] = "error"

    # Internal state
    _lock: threading.Lock = field(default_factory=threading.Lock)
    _sequence: int = field(default=0)
    _cache: dict[str, ReplayEntry] = field(default_factory=dict)
    _file: Any = field(default=None)
    _loaded: bool = field(default=False)

    def __post_init__(self) -> None:
        """Initialize the store based on mode."""
        if self.mode == "record":
            self._open_for_write()
        elif self.mode == "replay":
            self._load_cache()

    def _open_for_write(self) -> None:
        """Open the file for writing (record mode)."""
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._file = open(self.path, "a", encoding="utf-8")  # noqa: SIM115
        logger.info(f"Replay store opened for recording: {self.path}")

    def _load_cache(self) -> None:
        """Load all entries into memory for replay lookups."""
        if self._loaded:
            return

        if not self.path.exists():
            logger.warning(f"Replay file not found: {self.path}")
            self._loaded = True
            return

        with self._lock:
            try:
                with open(self.path, encoding="utf-8") as f:
                    for line_num, raw_line in enumerate(f, 1):
                        line = raw_line.strip()
                        if not line:
                            continue
                        try:
                            data = json.loads(line)
                            entry = ReplayEntry.from_dict(data)
                            # Index by type+hash for lookup
                            cache_key = f"{entry.entry_type}:{entry.key_hash}"
                            self._cache[cache_key] = entry
                        except (json.JSONDecodeError, KeyError) as e:
                            logger.warning(f"Skipping malformed entry at line {line_num}: {e}")

                logger.info(f"Replay store loaded {len(self._cache)} entries from {self.path}")
                self._loaded = True
            except OSError as e:
                logger.error(f"Failed to load replay file: {e}")
                self._loaded = True

    def record(
        self,
        entry_type: str,
        key: str,
        request: dict[str, Any],
        response: dict[str, Any],
    ) -> None:
        """Record an interaction to the store.

        Args:
            entry_type: Type of entry ("tool", "llm").
            key: Normalized key for hashing.
            request: Original request data.
            response: Response data to record.
        """
        if self.mode != "record":
            return

        key_hash = self._hash_key(key)

        with self._lock:
            self._sequence += 1
            entry = ReplayEntry(
                entry_type=entry_type,
                key_hash=key_hash,
                request=request,
                response=response,
                timestamp=datetime.now(timezone.utc).isoformat(),
                sequence=self._sequence,
            )

            if self._file:
                self._file.write(json.dumps(entry.to_dict()) + "\n")
                self._file.flush()

            logger.debug(f"Recorded {entry_type} entry (seq={self._sequence}, hash={key_hash[:8]})")

    def lookup(self, entry_type: str, key: str) -> dict[str, Any] | None:
        """Look up a recorded response by type and key.

        Args:
            entry_type: Type of entry ("tool", "llm").
            key: Normalized key for lookup.

        Returns:
            Response dict if found, None otherwise.
        """
        if self.mode != "replay":
            return None

        if not self._loaded:
            self._load_cache()

        key_hash = self._hash_key(key)
        cache_key = f"{entry_type}:{key_hash}"

        with self._lock:
            entry = self._cache.get(cache_key)

        if entry:
            logger.debug(f"Replay cache hit: {entry_type} (hash={key_hash[:8]})")
            return entry.response

        logger.debug(f"Replay cache miss: {entry_type} (hash={key_hash[:8]})")
        return None

    def has_entry(self, entry_type: str, key: str) -> bool:
        """Check if an entry exists without returning it."""
        if self.mode != "replay":
            return False

        if not self._loaded:
            self._load_cache()

        key_hash = self._hash_key(key)
        cache_key = f"{entry_type}:{key_hash}"

        with self._lock:
            return cache_key in self._cache

    @staticmethod
    def _hash_key(key: str) -> str:
        """Hash a normalized key for lookup."""
        return hashlib.sha256(key.encode("utf-8")).hexdigest()

    def close(self) -> None:
        """Close the store and flush any pending writes."""
        with self._lock:
            if self._file:
                self._file.close()
                self._file = None
                logger.info(f"Replay store closed: {self.path}")

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: types.TracebackType | None,
    ) -> None:
        self.close()

    @property
    def entry_count(self) -> int:
        """Number of entries in the cache (replay mode) or recorded (record mode)."""
        with self._lock:
            if self.mode == "replay":
                return len(self._cache)
            return self._sequence
