"""Unit tests for RedTeamDispatcher status helpers."""

from __future__ import annotations

import json

import pytest

from ares.core.dispatcher import RedTeamDispatcher
from ares.core.models import SharedRedTeamState


class FakeRedis:
    """Minimal async Redis stub for exploitation status tests."""

    def __init__(self, vuln_payloads: dict[bytes, str], exploit_payloads: dict[bytes, str]):
        self._vuln_payloads = vuln_payloads
        self._exploit_payloads = exploit_payloads

    async def scan_iter(self, pattern: str):
        if "vulns:" in pattern:
            for key in self._vuln_payloads:
                yield key
        else:
            for key in self._exploit_payloads:
                yield key

    async def get(self, key):
        return self._vuln_payloads.get(key) or self._exploit_payloads.get(key)


@pytest.mark.asyncio
async def test_get_exploitation_status_loads_redis_vulns():
    """Redis-stored vulnerabilities should be included in status."""
    dispatcher = RedTeamDispatcher()
    dispatcher._shared_state = SharedRedTeamState(operation_id="op-test-1")

    vuln_key = b"ares:operation:op-test-1:vulns:ADCS_ESC1_dc01"
    vuln_payload = json.dumps(
        {
            "type": "ADCS_ESC1",
            "target": "dc01",
            "details": {"template": "User"},
            "discovered_by": "recon",
            "queued_at": "2024-01-01T00:00:00+00:00",
        }
    )
    exploit_key = b"ares:operation:op-test-1:exploited:ADCS_ESC1_dc01"
    exploit_payload = json.dumps({"success": True})

    dispatcher._redis_client = FakeRedis(
        {vuln_key: vuln_payload},
        {exploit_key: exploit_payload},
    )

    status = await dispatcher.get_exploitation_status()

    assert status["total_discovered"] == 1
    assert status["total_succeeded"] == 1
    assert status["pending"] == []
    assert status["succeeded"][0]["id"] == "ADCS_ESC1_dc01"
