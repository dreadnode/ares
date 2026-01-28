import io
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, mock_open

import pytest

from ares.core.models import AgentRole
from ares.core.task_queue import TaskMessage
from ares.core.worker import RedisWorkerAgent


@pytest.mark.asyncio
async def test_crack_task_resolves_relative_wordlist(monkeypatch):
    captured = {}

    class FakeCrackingTools:
        def set_state(self, _state):
            return None

        async def crack_with_hashcat(
            self, *, hash_value, hashcat_mode, wordlist_path, use_dynamic_wordlist
        ):
            captured["wordlist_path"] = wordlist_path
            return "ok"

    monkeypatch.setattr("ares.core.worker.CrackingTools", FakeCrackingTools)
    monkeypatch.setattr(
        "ares.core.worker.RedisWorkerAgent._extract_cracked_password", lambda *_: "pw"
    )

    def exists_side_effect(path):
        return path == "/usr/share/wordlists/rockyou.txt"

    monkeypatch.setattr("os.path.exists", exists_side_effect)

    task_queue = SimpleNamespace(send_result=AsyncMock())
    agent = AsyncMock()
    worker = RedisWorkerAgent(
        role=AgentRole.CRACKER,
        task_queue=task_queue,
        agent=agent,
        agent_name="ares-cracker",
    )

    task = TaskMessage(
        task_id="task-1",
        task_type="crack",
        source_agent="orchestrator",
        target_agent="cracker",
        payload={"hash_value": "hash", "hash_type": "NTLM", "wordlist": "rockyou.txt"},
    )

    await worker._execute_crack_task(task)

    assert captured["wordlist_path"] == "/usr/share/wordlists/rockyou.txt"
    task_queue.send_result.assert_awaited()


@pytest.mark.asyncio
async def test_crack_task_uses_gz_wordlist(monkeypatch):
    captured = {}
    tmp_wordlist = "/tmp/rockyou.txt"
    gz_wordlist = "/usr/share/wordlists/rockyou.txt.gz"

    class FakeCrackingTools:
        def set_state(self, _state):
            return None

        async def crack_with_hashcat(
            self, *, hash_value, hashcat_mode, wordlist_path, use_dynamic_wordlist
        ):
            captured["wordlist_path"] = wordlist_path
            return "ok"

    monkeypatch.setattr("ares.core.worker.CrackingTools", FakeCrackingTools)
    monkeypatch.setattr(
        "ares.core.worker.RedisWorkerAgent._extract_cracked_password", lambda *_: "pw"
    )

    tmp_seen = {"count": 0}

    def exists_side_effect(path):
        if path == gz_wordlist:
            return True
        if path == tmp_wordlist:
            tmp_seen["count"] += 1
            return tmp_seen["count"] > 1
        return False

    monkeypatch.setattr("os.path.exists", exists_side_effect)

    gzip_open = MagicMock()
    gzip_open.return_value.__enter__.return_value = io.BytesIO(b"data")
    monkeypatch.setattr("gzip.open", gzip_open)
    monkeypatch.setattr("shutil.copyfileobj", lambda *_: None)
    monkeypatch.setattr("builtins.open", mock_open())

    task_queue = SimpleNamespace(send_result=AsyncMock())
    agent = AsyncMock()
    worker = RedisWorkerAgent(
        role=AgentRole.CRACKER,
        task_queue=task_queue,
        agent=agent,
        agent_name="ares-cracker",
    )

    task = TaskMessage(
        task_id="task-2",
        task_type="crack",
        source_agent="orchestrator",
        target_agent="cracker",
        payload={"hash_value": "hash", "hash_type": "NTLM", "wordlist": "rockyou.txt"},
    )

    await worker._execute_crack_task(task)

    assert captured["wordlist_path"] == tmp_wordlist
    gzip_open.assert_called()
    task_queue.send_result.assert_awaited()
