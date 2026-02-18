"""Tests for the replay system.

Tests cover:
- ReplayStore recording and lookup
- Command normalization for stable hashing
- Deterministic context for UUIDs/timestamps
- Integration with run_remote
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path


class TestReplayStore:
    """Tests for ReplayStore recording and lookup."""

    def test_record_mode_writes_entries(self, tmp_path: Path) -> None:
        """Recording mode writes entries to JSONL file."""
        from ares.core.replay.store import ReplayStore

        replay_file = tmp_path / "test.jsonl"

        with ReplayStore(path=replay_file, mode="record") as store:
            store.record(
                entry_type="tool",
                key="nmap -sV {IP:0}",
                request={"cmd": "nmap -sV 192.168.58.10"},
                response={"stdout": "scan output", "return_code": 0},
            )
            store.record(
                entry_type="tool",
                key="secretsdump {IP:0}",
                request={"cmd": "secretsdump.py 192.168.58.10"},
                response={"stdout": "hashes", "return_code": 0},
            )

        # Verify file contents
        lines = replay_file.read_text().strip().split("\n")
        assert len(lines) == 2

        entry1 = json.loads(lines[0])
        assert entry1["entry_type"] == "tool"
        assert entry1["seq"] == 1
        assert "key_hash" in entry1
        assert entry1["response"]["stdout"] == "scan output"

        entry2 = json.loads(lines[1])
        assert entry2["seq"] == 2

    def test_replay_mode_loads_cache(self, tmp_path: Path) -> None:
        """Replay mode loads entries from file and provides lookups."""
        from ares.core.replay.store import ReplayStore

        replay_file = tmp_path / "test.jsonl"

        # First record some entries
        with ReplayStore(path=replay_file, mode="record") as store:
            store.record(
                entry_type="tool",
                key="test_key",
                request={"cmd": "test"},
                response={"stdout": "cached output", "return_code": 0},
            )

        # Now replay
        with ReplayStore(path=replay_file, mode="replay") as store:
            result = store.lookup("tool", "test_key")
            assert result is not None
            assert result["stdout"] == "cached output"

            # Non-existent key returns None
            assert store.lookup("tool", "nonexistent") is None

    def test_replay_mode_handles_missing_file(self, tmp_path: Path) -> None:
        """Replay mode handles missing file gracefully."""
        from ares.core.replay.store import ReplayStore

        replay_file = tmp_path / "nonexistent.jsonl"

        with ReplayStore(path=replay_file, mode="replay") as store:
            # Should not raise, just return None for lookups
            assert store.lookup("tool", "any_key") is None

    def test_has_entry_check(self, tmp_path: Path) -> None:
        """has_entry() checks existence without returning response."""
        from ares.core.replay.store import ReplayStore

        replay_file = tmp_path / "test.jsonl"

        with ReplayStore(path=replay_file, mode="record") as store:
            store.record("tool", "existing_key", {}, {"data": "value"})

        with ReplayStore(path=replay_file, mode="replay") as store:
            assert store.has_entry("tool", "existing_key") is True
            assert store.has_entry("tool", "missing_key") is False

    def test_off_mode_does_nothing(self, tmp_path: Path) -> None:
        """Off mode neither records nor replays."""
        from ares.core.replay.store import ReplayStore

        replay_file = tmp_path / "test.jsonl"

        store = ReplayStore(path=replay_file, mode="off")
        store.record("tool", "key", {}, {"data": "value"})
        store.close()

        # File should not exist
        assert not replay_file.exists()


class TestCommandNormalization:
    """Tests for command normalization."""

    def test_normalize_ip_addresses(self) -> None:
        """IP addresses are normalized to indexed placeholders."""
        from ares.core.replay.wrappers import NormalizationContext, normalize_command

        ctx = NormalizationContext()

        # First IP gets index 0
        result = normalize_command("nmap 192.168.58.10", ctx)
        assert result == "nmap {IP:0}"

        # Same IP maps to same index
        result = normalize_command("scan 192.168.58.10", ctx)
        assert result == "scan {IP:0}"

        # Different IP gets next index
        result = normalize_command("scan 192.168.58.20", ctx)
        assert result == "scan {IP:1}"

    def test_normalize_multiple_ips(self) -> None:
        """Multiple IPs in one command are all normalized."""
        from ares.core.replay.wrappers import NormalizationContext, normalize_command

        ctx = NormalizationContext()
        result = normalize_command("relay -t 192.168.58.10 -r 192.168.58.20", ctx)
        assert result == "relay -t {IP:0} -r {IP:1}"

    def test_normalize_preserves_localhost(self) -> None:
        """Localhost and 0.0.0.0 are not normalized."""
        from ares.core.replay.wrappers import NormalizationContext, normalize_command

        ctx = NormalizationContext()
        result = normalize_command("bind 127.0.0.1:8080 0.0.0.0:9090", ctx)
        assert result == "bind 127.0.0.1:8080 0.0.0.0:9090"

    def test_normalize_uuids(self) -> None:
        """UUIDs in commands are normalized."""
        from ares.core.replay.wrappers import normalize_command

        result = normalize_command("cat /tmp/abc12345-1234-5678-9abc-def012345678/output.txt")
        assert "{UUID}" in result
        assert "abc12345-1234-5678-9abc-def012345678" not in result

    def test_normalize_kerberos_cache(self) -> None:
        """Kerberos cache paths are normalized."""
        from ares.core.replay.wrappers import normalize_command

        result = normalize_command("export KRB5CCNAME=krb5cc_1234")
        assert "krb5cc_{PID}" in result
        assert "krb5cc_1234" not in result

        result = normalize_command("use admin.ccache")
        assert "{CCACHE}.ccache" in result

    def test_normalize_temp_paths(self) -> None:
        """Temp paths are normalized."""
        from ares.core.replay.wrappers import normalize_command

        result = normalize_command("cat /tmp/random_file_abc123")
        assert "/tmp/{TMP}" in result

        # Tool-specific prefixes are preserved
        result = normalize_command("cat /tmp/impacket_12345")
        assert "/tmp/{IMPACKET}" in result


class TestDeterministicContext:
    """Tests for deterministic value generation."""

    def test_deterministic_uuid_sequence(self) -> None:
        """UUIDs are generated in deterministic sequence."""
        from ares.core.replay.determinism import (
            clear_deterministic_context,
            get_deterministic_uuid,
            set_deterministic_context,
        )

        set_deterministic_context(seed=42)
        try:
            uuid1 = get_deterministic_uuid()
            uuid2 = get_deterministic_uuid()

            # Reset and verify same sequence
            clear_deterministic_context()
            set_deterministic_context(seed=42)

            uuid1_again = get_deterministic_uuid()
            uuid2_again = get_deterministic_uuid()

            assert uuid1 == uuid1_again
            assert uuid2 == uuid2_again
            assert uuid1 != uuid2
        finally:
            clear_deterministic_context()

    def test_deterministic_time_sequence(self) -> None:
        """Timestamps advance deterministically."""
        from ares.core.replay.determinism import (
            clear_deterministic_context,
            get_deterministic_time,
            set_deterministic_context,
        )

        set_deterministic_context(seed=42)
        try:
            time1 = get_deterministic_time()
            time2 = get_deterministic_time()

            # Times should advance by 1 second
            assert (time2 - time1).total_seconds() == 1.0
        finally:
            clear_deterministic_context()

    def test_no_context_falls_back(self) -> None:
        """Without context, real values are used."""
        from ares.core.replay.determinism import (
            clear_deterministic_context,
            get_deterministic_uuid,
        )

        clear_deterministic_context()
        uuid1 = get_deterministic_uuid()
        uuid2 = get_deterministic_uuid()

        # Real UUIDs should be different (with extremely high probability)
        assert uuid1 != uuid2
        # Should be valid UUID format
        assert len(uuid1.split("-")) == 5

    def test_different_seeds_different_sequences(self) -> None:
        """Different seeds produce different sequences."""
        from ares.core.replay.determinism import (
            clear_deterministic_context,
            get_deterministic_uuid,
            set_deterministic_context,
        )

        set_deterministic_context(seed=42)
        uuid_seed42 = get_deterministic_uuid()
        clear_deterministic_context()

        set_deterministic_context(seed=123)
        uuid_seed123 = get_deterministic_uuid()
        clear_deterministic_context()

        # First 8 chars are counter, rest is seeded random
        # So the random parts should differ
        assert uuid_seed42 != uuid_seed123


class TestReplayIntegration:
    """Integration tests for replay with run_remote."""

    def test_initialize_replay_record_mode(self, tmp_path: Path) -> None:
        """initialize_replay creates store in record mode."""
        from ares.core.replay import get_replay_store, initialize_replay, shutdown_replay

        try:
            replay_file = tmp_path / "recording.jsonl"
            store = initialize_replay(mode="record", path=str(replay_file))

            assert store is not None
            assert store.mode == "record"
            assert get_replay_store() is store
        finally:
            shutdown_replay()

    def test_initialize_replay_replay_mode(self, tmp_path: Path) -> None:
        """initialize_replay creates store in replay mode."""
        from ares.core.replay import initialize_replay, shutdown_replay

        try:
            # Create a recording first
            replay_file = tmp_path / "recording.jsonl"
            replay_file.write_text(
                '{"entry_type":"tool","key_hash":"abc","request":{},"response":{"stdout":"test"},"ts":"","seq":1}\n'
            )

            store = initialize_replay(mode="replay", path=str(replay_file))

            assert store is not None
            assert store.mode == "replay"
            assert store.entry_count == 1
        finally:
            shutdown_replay()

    def test_initialize_replay_empty_mode(self) -> None:
        """initialize_replay returns None for empty/off mode."""
        from ares.core.replay import get_replay_store, initialize_replay, shutdown_replay

        try:
            store = initialize_replay(mode="")
            assert store is None
            assert get_replay_store() is None
        finally:
            shutdown_replay()

    def test_intercept_run_remote_record(self, tmp_path: Path) -> None:
        """intercept_run_remote records command results."""
        from ares.core.remote import CommandResult
        from ares.core.replay import initialize_replay, shutdown_replay
        from ares.core.replay.wrappers import intercept_run_remote

        try:
            replay_file = tmp_path / "recording.jsonl"
            initialize_replay(mode="record", path=str(replay_file))

            # Mock the original function
            def mock_run_remote(*args, **kwargs):
                return CommandResult(
                    stdout="mock output",
                    stderr="",
                    return_code=0,
                    success=True,
                )

            result = intercept_run_remote(mock_run_remote, "echo test", 30, "/tmp", None)

            assert result.stdout == "mock output"
            assert result.success is True

            # Verify recording was written
            shutdown_replay()
            content = replay_file.read_text()
            assert "mock output" in content
        finally:
            shutdown_replay()

    def test_intercept_run_remote_replay(self, tmp_path: Path) -> None:
        """intercept_run_remote returns cached results in replay mode."""
        from ares.core.remote import CommandResult
        from ares.core.replay import initialize_replay, shutdown_replay
        from ares.core.replay.wrappers import (
            intercept_run_remote,
            reset_normalization_context,
        )

        try:
            # Create a recording with normalized key
            replay_file = tmp_path / "recording.jsonl"

            # First record
            reset_normalization_context()
            initialize_replay(mode="record", path=str(replay_file))

            def mock_run_remote(*args, **kwargs):
                return CommandResult(
                    stdout="recorded output",
                    stderr="",
                    return_code=0,
                    success=True,
                )

            intercept_run_remote(mock_run_remote, "echo test", 30, "/tmp", None)
            shutdown_replay()

            # Now replay
            reset_normalization_context()
            initialize_replay(mode="replay", path=str(replay_file))

            def should_not_be_called(*args, **kwargs):
                raise AssertionError("Original function should not be called in replay")

            result = intercept_run_remote(should_not_be_called, "echo test", 30, "/tmp", None)

            assert result.stdout == "recorded output"
            assert result.success is True
        finally:
            shutdown_replay()
            reset_normalization_context()

    def test_intercept_run_remote_cache_miss_error(self, tmp_path: Path) -> None:
        """Cache miss with fallback=error returns error result."""
        from ares.core.replay import initialize_replay, shutdown_replay
        from ares.core.replay.wrappers import (
            intercept_run_remote,
            reset_normalization_context,
        )

        try:
            # Empty recording file
            replay_file = tmp_path / "empty.jsonl"
            replay_file.write_text("")

            reset_normalization_context()
            initialize_replay(mode="replay", path=str(replay_file), fallback="error")

            def should_not_be_called(*args, **kwargs):
                raise AssertionError("Should not be called")

            result = intercept_run_remote(
                should_not_be_called, "nonexistent command", 30, "/tmp", None
            )

            assert result.success is False
            assert "cache miss" in result.stderr.lower()
        finally:
            shutdown_replay()
            reset_normalization_context()

    def test_intercept_run_remote_cache_miss_live(self, tmp_path: Path) -> None:
        """Cache miss with fallback=live calls original function."""
        from ares.core.remote import CommandResult
        from ares.core.replay import initialize_replay, shutdown_replay
        from ares.core.replay.wrappers import (
            intercept_run_remote,
            reset_normalization_context,
        )

        try:
            # Empty recording file
            replay_file = tmp_path / "empty.jsonl"
            replay_file.write_text("")

            reset_normalization_context()
            initialize_replay(mode="replay", path=str(replay_file), fallback="live")

            live_called = []

            def live_function(*args, **kwargs):
                live_called.append(True)
                return CommandResult(stdout="live output", stderr="", return_code=0, success=True)

            result = intercept_run_remote(live_function, "nonexistent command", 30, "/tmp", None)

            assert len(live_called) == 1
            assert result.stdout == "live output"
        finally:
            shutdown_replay()
            reset_normalization_context()


class TestModelDeterminism:
    """Tests for deterministic UUID generation in models."""

    def test_credential_uses_deterministic_uuid(self) -> None:
        """Credential.id uses deterministic UUID when context is active."""
        from ares.core.models import Credential
        from ares.core.replay.determinism import (
            clear_deterministic_context,
            set_deterministic_context,
        )

        set_deterministic_context(seed=42)
        try:
            cred1 = Credential(username="user1", password="pass1")
            cred2 = Credential(username="user2", password="pass2")

            # Reset and create again
            clear_deterministic_context()
            set_deterministic_context(seed=42)

            cred1_again = Credential(username="user1", password="pass1")
            cred2_again = Credential(username="user2", password="pass2")

            # Same seed produces same IDs
            assert cred1.id == cred1_again.id
            assert cred2.id == cred2_again.id
            assert cred1.id != cred2.id
        finally:
            clear_deterministic_context()

    def test_hash_uses_deterministic_uuid(self) -> None:
        """Hash.id uses deterministic UUID when context is active."""
        from ares.core.models import Hash
        from ares.core.replay.determinism import (
            clear_deterministic_context,
            set_deterministic_context,
        )

        set_deterministic_context(seed=42)
        try:
            hash1 = Hash(username="admin", hash_value="aad3b435...")
            hash2 = Hash(username="guest", hash_value="31d6cfe0...")

            # Reset and create again
            clear_deterministic_context()
            set_deterministic_context(seed=42)

            hash1_again = Hash(username="admin", hash_value="aad3b435...")
            hash2_again = Hash(username="guest", hash_value="31d6cfe0...")

            # Same seed produces same IDs
            assert hash1.id == hash1_again.id
            assert hash2.id == hash2_again.id
        finally:
            clear_deterministic_context()


class TestConfigReplay:
    """Tests for replay configuration."""

    def test_config_has_replay_fields(self) -> None:
        """OperationConfig includes replay settings."""
        from ares.core.config import OperationConfig

        config = OperationConfig()
        assert config.replay_mode == ""
        assert config.replay_file == ""
        assert config.replay_seed == 42
        assert config.replay_fallback == "error"

    def test_config_replay_getters(self) -> None:
        """Replay getter functions work."""
        from ares.core.config import (
            clear_config_cache,
            get_replay_fallback,
            get_replay_file,
            get_replay_mode,
            get_replay_seed,
        )

        clear_config_cache()

        # With no env vars, should return defaults
        assert get_replay_mode() == ""
        assert get_replay_file() == ""
        assert get_replay_seed() == 42
        assert get_replay_fallback() == "error"
