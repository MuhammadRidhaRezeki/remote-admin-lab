"""Protocol schema and allowlist tests."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from shared.models import Envelope, MessageType, TaskType
from shared.protocol import decode_envelope, encode_envelope, make_envelope, sanitize_filename


def test_envelope_roundtrip() -> None:
    envelope = make_envelope(
        MessageType.PING, "device-1", {"value": 1}, request_id="req-1"
    )
    decoded = decode_envelope(encode_envelope(envelope))
    assert decoded == envelope
    assert decoded.request_id == "req-1"


def test_envelope_rejects_unknown_fields() -> None:
    with pytest.raises(ValidationError):
        Envelope(
            type=MessageType.PING,
            device_id="device-1",
            payload={},
            unexpected="nope",
        )


def test_task_allowlist_is_explicit() -> None:
    assert {item.value for item in TaskType} == {
        "system_info",
        "cpu_ram",
        "disk",
        "network",
        "agent_status",
        "transfer_file",
    }


def test_sanitize_filename() -> None:
    assert sanitize_filename("..\\..\\evil?.txt") == "evil.txt"
