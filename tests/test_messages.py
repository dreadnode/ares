"""Tests for inter-agent messaging primitives."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from ares.core.messages import (
    AgentMessage,
    CrackRequest,
    DomainAdminAchieved,
    MessageType,
    TaskComplete,
    create_message,
    generate_message_id,
    generate_task_id,
)


@pytest.mark.parametrize(
    "generator,prefix",
    [
        pytest.param(generate_message_id, "msg-", id="message-id"),
        pytest.param(generate_task_id, "task-", id="task-id"),
    ],
)
def test_id_generators_create_prefixed_unique_identifiers(generator, prefix: str):
    """ID generators return unique IDs with the expected prefixes."""
    first_value = generator()
    second_value = generator()

    assert first_value.startswith(prefix)
    assert second_value.startswith(prefix)
    assert first_value != second_value


def test_agent_message_uses_enum_values_in_dump():
    """AgentMessage serializes enum fields to their raw string values."""
    message = AgentMessage(type=MessageType.AGENT_HEARTBEAT, source_agent="dispatcher")

    payload = message.model_dump()

    assert payload["type"] == MessageType.AGENT_HEARTBEAT.value
    assert isinstance(message.timestamp, datetime)
    assert message.timestamp.tzinfo == timezone.utc


def test_crack_request_defaults_include_generated_task_id_and_wordlist():
    """CrackRequest fills in task defaults suitable for dispatcher workflows."""
    request = CrackRequest(
        source_agent="orchestrator",
        hash_value="deadbeef",
        hash_type="NTLM",
    )

    assert request.type is MessageType.CRACK_REQUEST
    assert request.task_id.startswith("task-")
    assert request.wordlist == "rockyou.txt"
    assert request.priority == 5


@pytest.mark.parametrize(
    "message_type,kwargs,expected_type",
    [
        pytest.param(
            MessageType.CRACK_REQUEST,
            {"hash_value": "cafebabe", "hash_type": "NTLM"},
            CrackRequest,
            id="specialized-crack-request",
        ),
        pytest.param(
            MessageType.DOMAIN_ADMIN_ACHIEVED,
            {"username": "alice", "domain": "CONTOSO", "attack_path": "Kerberoast", "credential_type": "hash"},
            DomainAdminAchieved,
            id="specialized-domain-admin-message",
        ),
    ],
)
def test_create_message_returns_specialized_message_classes(message_type, kwargs, expected_type):
    """create_message maps known message types to specialized models."""
    message = create_message(message_type, source_agent="agent-1", **kwargs)

    assert isinstance(message, expected_type)
    assert message.source_agent == "agent-1"


def test_create_message_falls_back_to_base_message_for_unmapped_type():
    """create_message returns AgentMessage for message types without dedicated models."""
    message = create_message(
        MessageType.USER_DISCOVERED,
        source_agent="recon-agent",
        type=MessageType.USER_DISCOVERED,
        data={"username": "bob"},
    )

    assert type(message) is AgentMessage
    assert message.type is MessageType.USER_DISCOVERED
    assert message.data == {"username": "bob"}


def test_task_complete_reports_successful_result_payload():
    """TaskComplete stores result details for completed asynchronous work."""
    message = TaskComplete(
        source_agent="worker-1",
        task_id="task-123",
        result={"cracked": True, "username": "alice"},
        execution_time=1.25,
    )

    assert message.success is True
    assert message.result["cracked"] is True
    assert message.execution_time == pytest.approx(1.25)
