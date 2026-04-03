"""Tests for BloodHound JSON ACL parsing and MSSQL linked server quote escaping."""

import json
import tempfile
from pathlib import Path

import pytest

from ares.tools.red.lateral_movement import MSSQLTools
from ares.tools.red.reconnaissance import BloodHoundTools


class TestParseBloodhoundJsonAcls:
    """Tests for _parse_bloodhound_json_acls static method."""

    def _write_json(self, tmpdir: str, filename: str, data: dict) -> str:
        path = Path(tmpdir) / filename
        with open(path, "w") as f:
            json.dump(data, f)
        return str(path)

    def _make_users_json(self, users: list[dict]) -> dict:
        return {"meta": {"type": "users"}, "data": users}

    def _make_groups_json(self, groups: list[dict]) -> dict:
        return {"meta": {"type": "groups"}, "data": groups}

    def _make_user_entry(self, name: str, sid: str, aces: list[dict] | None = None) -> dict:
        return {
            "ObjectIdentifier": sid,
            "Properties": {"name": name},
            "Aces": aces or [],
        }

    def _make_ace(self, principal_sid: str, right: str, inherited: bool = False) -> dict:
        return {
            "PrincipalSID": principal_sid,
            "RightName": right,
            "IsInherited": inherited,
            "PrincipalType": "User",
        }

    def test_empty_file_list(self):
        result = BloodHoundTools._parse_bloodhound_json_acls([])
        assert result == []

    def test_nonexistent_files(self):
        result = BloodHoundTools._parse_bloodhound_json_acls(
            ["/tmp/nonexistent_bloodhound_file.json"]
        )
        assert result == []

    def test_extracts_genericall_between_users(self):
        """Core test: missandei GenericAll on khal.drogo must be extracted."""
        with tempfile.TemporaryDirectory() as tmpdir:
            missandei_sid = "S-1-5-21-1606295247-3362563358-1415986617-1125"
            khal_sid = "S-1-5-21-1606295247-3362563358-1415986617-1123"

            users = self._make_users_json(
                [
                    self._make_user_entry("MISSANDEI@ESSOS.LOCAL", missandei_sid),
                    self._make_user_entry(
                        "KHAL.DROGO@ESSOS.LOCAL",
                        khal_sid,
                        aces=[self._make_ace(missandei_sid, "GenericAll")],
                    ),
                ]
            )
            path = self._write_json(tmpdir, "users.json", users)

            result = BloodHoundTools._parse_bloodhound_json_acls([path])

            assert len(result) == 1
            edge = result[0]
            assert edge["principal"] == "MISSANDEI@ESSOS.LOCAL"
            assert edge["target"] == "KHAL.DROGO@ESSOS.LOCAL"
            assert edge["right"] == "GenericAll"
            assert edge["target_type"] == "user"

    def test_filters_inherited_aces(self):
        """Inherited ACEs should be skipped."""
        with tempfile.TemporaryDirectory() as tmpdir:
            user_sid = "S-1-5-21-111-222-333-1001"
            target_sid = "S-1-5-21-111-222-333-1002"

            users = self._make_users_json(
                [
                    self._make_user_entry("USER1@CONTOSO.LOCAL", user_sid),
                    self._make_user_entry(
                        "USER2@CONTOSO.LOCAL",
                        target_sid,
                        aces=[self._make_ace(user_sid, "GenericAll", inherited=True)],
                    ),
                ]
            )
            path = self._write_json(tmpdir, "users.json", users)

            result = BloodHoundTools._parse_bloodhound_json_acls([path])
            assert result == []

    def test_filters_domain_admins_sid(self):
        """ACEs from Domain Admins (SID ending -512) should be filtered."""
        with tempfile.TemporaryDirectory() as tmpdir:
            da_sid = "S-1-5-21-111-222-333-512"
            target_sid = "S-1-5-21-111-222-333-1002"

            users = self._make_users_json(
                [
                    self._make_user_entry(
                        "USER2@CONTOSO.LOCAL",
                        target_sid,
                        aces=[self._make_ace(da_sid, "GenericAll")],
                    ),
                ]
            )
            path = self._write_json(tmpdir, "users.json", users)

            result = BloodHoundTools._parse_bloodhound_json_acls([path])
            assert result == []

    def test_filters_builtin_administrators(self):
        """ACEs from BUILTIN\\Administrators (S-1-5-32-544) should be filtered."""
        with tempfile.TemporaryDirectory() as tmpdir:
            target_sid = "S-1-5-21-111-222-333-1002"

            users = self._make_users_json(
                [
                    self._make_user_entry(
                        "USER@CONTOSO.LOCAL",
                        target_sid,
                        aces=[self._make_ace("S-1-5-32-544", "GenericWrite")],
                    ),
                ]
            )
            path = self._write_json(tmpdir, "users.json", users)

            result = BloodHoundTools._parse_bloodhound_json_acls([path])
            assert result == []

    def test_multiple_abuse_rights(self):
        """All abuse rights should be extracted."""
        with tempfile.TemporaryDirectory() as tmpdir:
            attacker_sid = "S-1-5-21-111-222-333-1001"
            target_sid = "S-1-5-21-111-222-333-1002"

            users = self._make_users_json(
                [
                    self._make_user_entry("ATTACKER@CONTOSO.LOCAL", attacker_sid),
                    self._make_user_entry(
                        "TARGET@CONTOSO.LOCAL",
                        target_sid,
                        aces=[
                            self._make_ace(attacker_sid, "GenericAll"),
                            self._make_ace(attacker_sid, "GenericWrite"),
                            self._make_ace(attacker_sid, "WriteDacl"),
                            self._make_ace(attacker_sid, "ForceChangePassword"),
                            # Non-abuse right should be skipped
                            self._make_ace(attacker_sid, "ReadProperty"),
                        ],
                    ),
                ]
            )
            path = self._write_json(tmpdir, "users.json", users)

            result = BloodHoundTools._parse_bloodhound_json_acls([path])
            rights = {e["right"] for e in result}
            assert "GenericAll" in rights
            assert "GenericWrite" in rights
            assert "WriteDacl" in rights
            assert "ForceChangePassword" in rights
            assert "ReadProperty" not in rights

    def test_cross_file_sid_resolution(self):
        """SIDs from users.json should resolve principals in groups.json."""
        with tempfile.TemporaryDirectory() as tmpdir:
            user_sid = "S-1-5-21-111-222-333-1001"
            group_sid = "S-1-5-21-111-222-333-1100"

            users = self._make_users_json(
                [
                    self._make_user_entry("ATTACKER@CONTOSO.LOCAL", user_sid),
                ]
            )
            groups = self._make_groups_json(
                [
                    {
                        "ObjectIdentifier": group_sid,
                        "Properties": {"name": "DOMAIN ADMINS@CONTOSO.LOCAL"},
                        "Aces": [self._make_ace(user_sid, "GenericAll")],
                    },
                ]
            )
            users_path = self._write_json(tmpdir, "users.json", users)
            groups_path = self._write_json(tmpdir, "groups.json", groups)

            result = BloodHoundTools._parse_bloodhound_json_acls([users_path, groups_path])
            assert len(result) == 1
            assert result[0]["principal"] == "ATTACKER@CONTOSO.LOCAL"
            assert result[0]["target"] == "DOMAIN ADMINS@CONTOSO.LOCAL"
            assert result[0]["target_type"] == "group"

    def test_unresolved_sid_kept_if_not_builtin(self):
        """Unresolved SIDs that aren't builtin should still appear."""
        with tempfile.TemporaryDirectory() as tmpdir:
            unknown_sid = "S-1-5-21-999-888-777-5555"
            target_sid = "S-1-5-21-111-222-333-1002"

            users = self._make_users_json(
                [
                    self._make_user_entry(
                        "TARGET@CONTOSO.LOCAL",
                        target_sid,
                        aces=[self._make_ace(unknown_sid, "GenericAll")],
                    ),
                ]
            )
            path = self._write_json(tmpdir, "users.json", users)

            result = BloodHoundTools._parse_bloodhound_json_acls([path])
            assert len(result) == 1
            assert result[0]["principal"] == unknown_sid


class TestMssqlExecLinkedQuoteEscaping:
    """Tests for MSSQL linked server query quote escaping."""

    def test_query_without_quotes(self):
        """Queries without quotes should pass through unchanged."""
        tools = MSSQLTools()

        with pytest.MonkeyPatch.context() as m:
            captured_sql = {}

            def mock_pipe_cmd(sql, connect):
                captured_sql["sql"] = sql
                return "echo test"

            m.setattr(MSSQLTools, "_mssql_pipe_cmd", staticmethod(mock_pipe_cmd))
            m.setattr(
                "ares.tools.red.lateral_movement.run_tool",
                lambda *_a, **_kw: ("", "", 0),
            )

            tools.mssql_exec_linked(
                target="192.168.58.10",
                username="user",
                password="pass",  # pragma: allowlist secret
                linked_server="BRAAVOS",
                query="SELECT SYSTEM_USER",
                domain="contoso.local",
            )

        assert captured_sql["sql"] == "EXEC ('SELECT SYSTEM_USER') AT [BRAAVOS];"

    def test_query_with_single_quotes_escaped(self):
        """Single quotes in query must be doubled for T-SQL EXEC wrapper."""
        tools = MSSQLTools()

        with pytest.MonkeyPatch.context() as m:
            captured_sql = {}

            def mock_pipe_cmd(sql, connect):
                captured_sql["sql"] = sql
                return "echo test"

            m.setattr(MSSQLTools, "_mssql_pipe_cmd", staticmethod(mock_pipe_cmd))
            m.setattr(
                "ares.tools.red.lateral_movement.run_tool",
                lambda *_a, **_kw: ("", "", 0),
            )

            tools.mssql_exec_linked(
                target="192.168.58.10",
                username="user",
                password="pass",  # pragma: allowlist secret
                linked_server="BRAAVOS",
                query="SELECT IS_SRVROLEMEMBER('sysadmin')",
                domain="contoso.local",
            )

        assert captured_sql["sql"] == "EXEC ('SELECT IS_SRVROLEMEMBER(''sysadmin'')') AT [BRAAVOS];"

    def test_sp_configure_quotes_escaped(self):
        """sp_configure with quoted option name must be properly escaped."""
        tools = MSSQLTools()

        with pytest.MonkeyPatch.context() as m:
            captured_sql = {}

            def mock_pipe_cmd(sql, connect):
                captured_sql["sql"] = sql
                return "echo test"

            m.setattr(MSSQLTools, "_mssql_pipe_cmd", staticmethod(mock_pipe_cmd))
            m.setattr(
                "ares.tools.red.lateral_movement.run_tool",
                lambda *_a, **_kw: ("", "", 0),
            )

            tools.mssql_exec_linked(
                target="192.168.58.10",
                username="user",
                password="pass",  # pragma: allowlist secret
                linked_server="SRV",
                query="sp_configure 'xp_cmdshell', 1; RECONFIGURE;",
                domain="contoso.local",
            )

        assert (
            captured_sql["sql"]
            == "EXEC ('sp_configure ''xp_cmdshell'', 1; RECONFIGURE;') AT [SRV];"
        )

    def test_xp_cmdshell_nested_quotes(self):
        """xp_cmdshell with command in quotes must escape correctly."""
        tools = MSSQLTools()

        with pytest.MonkeyPatch.context() as m:
            captured_sql = {}

            def mock_pipe_cmd(sql, connect):
                captured_sql["sql"] = sql
                return "echo test"

            m.setattr(MSSQLTools, "_mssql_pipe_cmd", staticmethod(mock_pipe_cmd))
            m.setattr(
                "ares.tools.red.lateral_movement.run_tool",
                lambda *_a, **_kw: ("", "", 0),
            )

            tools.mssql_exec_linked(
                target="192.168.58.10",
                username="user",
                password="pass",  # pragma: allowlist secret
                linked_server="BRAAVOS",
                query="xp_cmdshell 'whoami'",
                domain="contoso.local",
            )

        assert captured_sql["sql"] == "EXEC ('xp_cmdshell ''whoami''') AT [BRAAVOS];"
