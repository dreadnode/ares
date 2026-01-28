"""Tests for MOTD garbage filtering in red team common utilities."""

from __future__ import annotations

from unittest.mock import patch

from ares.tools.red.common import (
    MOTD_GARBAGE_CHARS,
    MOTD_GARBAGE_PATTERNS,
    filter_motd_garbage,
    filter_users_file_remote,
    is_motd_garbage,
    is_motd_line,
    write_users_file_remote,
)


class MockRunResult:
    """Mock result for run_remote function."""

    def __init__(self, stdout: str = "", stderr: str = "", return_code: int = 0):
        self.stdout = stdout
        self.stderr = stderr
        self.return_code = return_code


class TestIsMOTDGarbage:
    """Tests for is_motd_garbage function."""

    def test_empty_string_is_garbage(self):
        """Empty strings should be considered garbage."""
        assert is_motd_garbage("") is True
        assert is_motd_garbage("   ") is True
        assert is_motd_garbage("\t\n") is True

    def test_none_like_values_are_garbage(self):
        """None-like empty values should be garbage."""
        assert is_motd_garbage("") is True

    def test_box_drawing_characters_are_garbage(self):
        """Box-drawing characters from Kali MOTD are garbage."""
        for char in MOTD_GARBAGE_CHARS:
            assert is_motd_garbage(f"test{char}string") is True
        assert is_motd_garbage("┏━━━━━━━━━━━━━━━━┓") is True
        assert is_motd_garbage("┃ Kali Linux    ┃") is True
        assert is_motd_garbage("╔══════════════╗") is True

    def test_motd_patterns_are_garbage(self):
        """Common MOTD patterns should be garbage."""
        for pattern in MOTD_GARBAGE_PATTERNS:
            assert is_motd_garbage(f"some text with {pattern} in it") is True

        assert is_motd_garbage("message from kali developers") is True
        assert is_motd_garbage("This is a minimal installation") is True
        assert is_motd_garbage("Visit kali.org for more info") is True
        assert is_motd_garbage("Create .hushlogin to disable") is True
        assert is_motd_garbage("/tmp/users.txt") is True
        assert is_motd_garbage("users.txt") is True

    def test_non_ascii_characters_are_garbage(self):
        """Non-ASCII characters indicate garbage."""
        assert is_motd_garbage("üser") is True
        assert is_motd_garbage("пользователь") is True
        assert is_motd_garbage("用户") is True

    def test_path_like_strings_are_garbage(self):
        """Strings containing path separators are garbage."""
        assert is_motd_garbage("/tmp/users") is True
        assert is_motd_garbage("C:\\Users\\admin") is True
        assert is_motd_garbage("../etc/passwd") is True

    def test_unusual_characters_are_garbage(self):
        """Strings with unusual characters are garbage."""
        assert is_motd_garbage("user@domain") is True
        assert is_motd_garbage("user:password") is True
        assert is_motd_garbage("user name") is True
        assert is_motd_garbage("user!special") is True

    def test_valid_usernames_are_not_garbage(self):
        """Valid AD usernames should not be garbage."""
        assert is_motd_garbage("administrator") is False
        assert is_motd_garbage("john.doe") is False
        assert is_motd_garbage("svc-sql") is False
        assert is_motd_garbage("user_name") is False
        assert is_motd_garbage("DOMAIN$") is False
        assert is_motd_garbage("PC01$") is False
        assert is_motd_garbage("Jane.Doe-Smith") is False

    def test_case_insensitive_pattern_matching(self):
        """MOTD pattern matching should be case-insensitive."""
        assert is_motd_garbage("MESSAGE FROM KALI") is True
        assert is_motd_garbage("Minimal Installation") is True
        assert is_motd_garbage("KALI.ORG") is True


class TestIsMOTDLine:
    """Tests for is_motd_line function (line-level filtering)."""

    def test_empty_line_is_not_garbage(self):
        """Empty lines should not be considered garbage (just skipped)."""
        assert is_motd_line("") is False
        assert is_motd_line("   ") is False

    def test_box_drawing_lines_are_garbage(self):
        """Lines with box-drawing characters are garbage."""
        assert is_motd_line("┏━━━━━━━━━━━━━━━━┓") is True
        assert is_motd_line("┃ Kali Linux    ┃") is True
        assert is_motd_line("╔══════════════╗") is True

    def test_motd_pattern_lines_are_garbage(self):
        """Lines containing MOTD patterns are garbage."""
        assert is_motd_line("This is a minimal installation") is True
        assert is_motd_line("message from kali developers") is True
        assert is_motd_line("Visit kali.org for more info") is True

    def test_valid_netexec_lines_are_not_garbage(self):
        """Valid tool output lines should not be garbage."""
        assert is_motd_line("SMB 192.168.56.1 445 DC [*] CONTOSO\\admin") is False
        assert is_motd_line("user:[administrator] rid:[0x1f4]") is False
        assert is_motd_line("SMB 10.0.0.1 445 DC01 john.doe (SidTypeUser)") is False

    def test_valid_nmap_lines_are_not_garbage(self):
        """Valid nmap output lines should not be garbage."""
        assert is_motd_line("PORT   STATE SERVICE") is False
        assert is_motd_line("22/tcp open  ssh") is False
        assert is_motd_line("Host is up (0.0010s latency).") is False

    def test_path_lines_are_not_automatically_garbage(self):
        """Path-like strings are allowed at line level."""
        # At line level, we allow paths since they might be in tool output
        assert is_motd_line("/etc/passwd") is False
        # But /tmp/users is still MOTD garbage pattern
        assert is_motd_line("/tmp/users.txt") is True


class TestFilterMOTDGarbage:
    """Tests for filter_motd_garbage function."""

    def test_filters_garbage_entries(self):
        """Should filter out garbage entries from list."""
        users = [
            "administrator",
            "┏━━━━━━━━━━━━━━━━┓",
            "john.doe",
            "message from kali",
            "svc-sql",
            "",
        ]
        filtered = filter_motd_garbage(users)
        assert filtered == ["administrator", "john.doe", "svc-sql"]

    def test_empty_list_returns_empty(self):
        """Empty input returns empty output."""
        assert filter_motd_garbage([]) == []

    def test_all_garbage_returns_empty(self):
        """All garbage input returns empty output."""
        users = ["┃ Kali Linux ┃", "", "/tmp/test.txt"]
        assert filter_motd_garbage(users) == []

    def test_preserves_valid_usernames(self):
        """Valid usernames are preserved."""
        users = ["admin", "user.name", "svc-account", "COMPUTER$"]
        filtered = filter_motd_garbage(users)
        assert filtered == users

    def test_mixed_valid_and_garbage(self):
        """Mixed list filters correctly."""
        users = [
            "admin",
            "┏━━━━━━━━━━━━━━━━┓",
            "jane.doe",
            "┃ minimal installation ┃",
            "bob_smith",
            "visit kali.org",
            "svc-web",
        ]
        filtered = filter_motd_garbage(users)
        assert filtered == ["admin", "jane.doe", "bob_smith", "svc-web"]


class TestWriteUsersFileRemote:
    """Tests for write_users_file_remote with MOTD filtering."""

    def test_empty_users_list_returns_error(self):
        """Empty users list should return error."""
        success, error = write_users_file_remote([], "/tmp/users.txt")
        assert success is False
        assert "no users provided" in error

    def test_all_garbage_users_returns_error(self):
        """All garbage users should return error."""
        users = ["┏━━━━━━━━━━━━━━━━┓", "", "message from kali"]
        success, error = write_users_file_remote(users, "/tmp/users.txt")
        assert success is False
        assert "no valid users after filtering" in error

    def test_filters_garbage_before_writing(self):
        """Should filter garbage before writing to remote."""
        users = ["admin", "┃ Kali Linux ┃", "john.doe"]

        with patch("ares.tools.red.common.run_remote") as mock_run:
            mock_run.return_value = MockRunResult(return_code=0)
            success, error = write_users_file_remote(users, "/tmp/users.txt")

        assert success is True
        assert error == ""
        # Verify only valid users were written
        call_args = mock_run.call_args[0][0]
        cmd_str = " ".join(call_args)
        assert "admin" in cmd_str
        assert "john.doe" in cmd_str
        assert "Kali" not in cmd_str

    def test_write_failure_returns_error(self):
        """Remote write failure should return error."""
        users = ["admin", "user"]

        with patch("ares.tools.red.common.run_remote") as mock_run:
            mock_run.return_value = MockRunResult(stderr="Permission denied", return_code=1)
            success, error = write_users_file_remote(users, "/tmp/users.txt")

        assert success is False
        assert "Permission denied" in error


class TestFilterUsersFileRemote:
    """Tests for filter_users_file_remote with MOTD filtering."""

    def test_filters_motd_garbage_from_file(self):
        """Should filter MOTD garbage when reading users file."""
        file_content = "admin\n┏━━━━━━━━━━━━━━━━┓\njohn.doe\nmessage from kali\n"

        with patch("ares.tools.red.common.run_remote") as mock_run:
            mock_run.return_value = MockRunResult(stdout=file_content, return_code=0)
            filtered_path, error = filter_users_file_remote("/tmp/users.txt", set())

        assert error is None
        assert filtered_path != "/tmp/users.txt"

    def test_filters_excluded_users(self):
        """Should filter both MOTD garbage and excluded users."""
        file_content = "admin\njohn.doe\nbob\n"
        exclude = {"john.doe"}

        with patch("ares.tools.red.common.run_remote") as mock_run:
            mock_run.side_effect = [
                MockRunResult(stdout=file_content, return_code=0),
                MockRunResult(return_code=0),  # Write call
            ]
            _filtered_path, error = filter_users_file_remote("/tmp/users.txt", exclude)

        assert error is None
        # Check write call excluded john.doe
        write_call = mock_run.call_args_list[1]
        cmd_str = " ".join(write_call[0][0])
        assert "john.doe" not in cmd_str
        assert "admin" in cmd_str
        assert "bob" in cmd_str

    def test_all_users_filtered_returns_error(self):
        """Should return error when all users are filtered out."""
        file_content = "┏━━━━━━━━━━━━━━━━┓\nmessage from kali\n"

        with patch("ares.tools.red.common.run_remote") as mock_run:
            mock_run.return_value = MockRunResult(stdout=file_content, return_code=0)
            filtered_path, error = filter_users_file_remote("/tmp/users.txt", set())

        assert filtered_path == ""
        assert "all users already have credentials" in error

    def test_deduplicates_users(self):
        """Should deduplicate users (case-insensitive)."""
        file_content = "admin\nAdmin\nADMIN\njohn.doe\n"

        with patch("ares.tools.red.common.run_remote") as mock_run:
            mock_run.side_effect = [
                MockRunResult(stdout=file_content, return_code=0),
                MockRunResult(return_code=0),
            ]
            filter_users_file_remote("/tmp/users.txt", set())

        # Check write call only has one admin
        write_call = mock_run.call_args_list[1]
        cmd_str = " ".join(write_call[0][0])
        # Should only appear once (the first occurrence)
        assert cmd_str.count("admin") == 1

    def test_read_failure_returns_original_path(self):
        """Should return original path on read failure."""
        with patch("ares.tools.red.common.run_remote") as mock_run:
            mock_run.return_value = MockRunResult(stderr="File not found", return_code=1)
            filtered_path, error = filter_users_file_remote("/tmp/users.txt", set())

        assert filtered_path == "/tmp/users.txt"
        assert "File not found" in error

    def test_filters_with_empty_exclude_set(self):
        """Should filter MOTD garbage even when exclude set is empty."""
        file_content = "admin\n┃ Kali Linux ┃\njohn.doe\n"

        with patch("ares.tools.red.common.run_remote") as mock_run:
            mock_run.side_effect = [
                MockRunResult(stdout=file_content, return_code=0),
                MockRunResult(return_code=0),
            ]
            _filtered_path, error = filter_users_file_remote("/tmp/users.txt", set())

        assert error is None
        # Verify garbage was filtered
        write_call = mock_run.call_args_list[1]
        cmd_str = " ".join(write_call[0][0])
        assert "Kali" not in cmd_str


class TestMOTDGarbageConstants:
    """Tests for MOTD garbage detection constants."""

    def test_garbage_chars_is_frozenset(self):
        """MOTD_GARBAGE_CHARS should be a frozenset for immutability."""
        assert isinstance(MOTD_GARBAGE_CHARS, frozenset)

    def test_garbage_chars_contains_box_drawing(self):
        """Should contain common box-drawing characters."""
        expected_chars = "┏┃┗┓┛━─│┌┐└┘├┤┬┴┼╔╗╚╝║═"
        for char in expected_chars:
            assert char in MOTD_GARBAGE_CHARS

    def test_garbage_patterns_is_tuple(self):
        """MOTD_GARBAGE_PATTERNS should be a tuple for immutability."""
        assert isinstance(MOTD_GARBAGE_PATTERNS, tuple)

    def test_garbage_patterns_contains_key_patterns(self):
        """Should contain key MOTD patterns."""
        expected_patterns = [
            "message from kali",
            "minimal installation",
            "kali.org",
            "hushlogin",
        ]
        for pattern in expected_patterns:
            assert pattern in MOTD_GARBAGE_PATTERNS
