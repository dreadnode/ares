"""Tests for exploit workflow timeout selection."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest


class TestExploitWorkflowTimeouts:
    """Ensure slow exploit classes get realistic workflow wait budgets."""

    @pytest.mark.asyncio
    async def test_mssql_impersonation_uses_extended_wait(self, monkeypatch):
        from ares.core.workflows import _exploit_vulnerability

        dispatcher = SimpleNamespace()
        wait_mock = AsyncMock(return_value={"success": True})

        monkeypatch.setattr(
            "ares.core.workflows._dispatch_exploit",
            AsyncMock(return_value="task-mssql-1"),
        )
        monkeypatch.setattr("ares.core.workflows._dispatch_acl", AsyncMock())
        monkeypatch.setattr("ares.core.workflows._dispatch_krbtgt", AsyncMock())
        monkeypatch.setattr("ares.core.workflows._wait_with_da_check", wait_mock)

        result = await _exploit_vulnerability(
            dispatcher,
            {
                "type": "mssql_impersonation",
                "id": "vuln-1",
                "target": "10.1.2.17",
                "details": {},
            },
        )

        assert result == {"success": True}
        wait_mock.assert_awaited_once_with(
            dispatcher,
            "task-mssql-1",
            timeout=600.0,
            check_interval=10.0,
        )

    @pytest.mark.asyncio
    async def test_mssql_cross_forest_pivot_uses_longest_wait(self, monkeypatch):
        from ares.core.workflows import _exploit_vulnerability

        dispatcher = SimpleNamespace()
        wait_mock = AsyncMock(return_value={"success": True})

        monkeypatch.setattr(
            "ares.core.workflows._dispatch_exploit",
            AsyncMock(return_value="task-mssql-xf-1"),
        )
        monkeypatch.setattr("ares.core.workflows._dispatch_acl", AsyncMock())
        monkeypatch.setattr("ares.core.workflows._dispatch_krbtgt", AsyncMock())
        monkeypatch.setattr("ares.core.workflows._wait_with_da_check", wait_mock)

        await _exploit_vulnerability(
            dispatcher,
            {
                "type": "mssql_cross_forest_pivot",
                "id": "vuln-2",
                "target": "10.1.2.17",
                "details": {},
            },
        )

        wait_mock.assert_awaited_once_with(
            dispatcher,
            "task-mssql-xf-1",
            timeout=900.0,
            check_interval=10.0,
        )

    @pytest.mark.asyncio
    async def test_non_mssql_exploit_keeps_default_wait(self, monkeypatch):
        from ares.core.workflows import _exploit_vulnerability

        dispatcher = SimpleNamespace()
        wait_mock = AsyncMock(return_value={"success": True})

        monkeypatch.setattr(
            "ares.core.workflows._dispatch_exploit",
            AsyncMock(return_value="task-adcs-1"),
        )
        monkeypatch.setattr("ares.core.workflows._dispatch_acl", AsyncMock())
        monkeypatch.setattr("ares.core.workflows._dispatch_krbtgt", AsyncMock())
        monkeypatch.setattr("ares.core.workflows._wait_with_da_check", wait_mock)

        await _exploit_vulnerability(
            dispatcher,
            {
                "type": "adcs_esc1",
                "id": "vuln-3",
                "target": "10.1.2.20",
                "details": {},
            },
        )

        wait_mock.assert_awaited_once_with(
            dispatcher,
            "task-adcs-1",
            timeout=180.0,
            check_interval=10.0,
        )
