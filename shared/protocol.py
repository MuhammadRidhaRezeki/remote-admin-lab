"""Envelope encoding and validation helpers."""

from __future__ import annotations

import json
from typing import Any

from .models import Envelope, MessageType, new_id

MAX_MESSAGE_BYTES = 64 * 1024 * 1024


def make_envelope(
    message_type: MessageType,
    device_id: str,
    payload: dict[str, Any] | None = None,
    request_id: str | None = None,
) -> Envelope:
    return Envelope(
        type=message_type,
        request_id=request_id or new_id("msg"),
        device_id=device_id,
        payload=payload or {},
    )


def encode_envelope(envelope: Envelope) -> str:
    return envelope.model_dump_json()


def decode_envelope(raw: str | bytes) -> Envelope:
    if isinstance(raw, bytes):
        if len(raw) > MAX_MESSAGE_BYTES:
            raise ValueError("pesan melebihi batas ukuran")
        raw = raw.decode("utf-8")
    return Envelope.model_validate(json.loads(raw))


def sanitize_filename(name: str) -> str:
    cleaned = name.replace("\\", "/").split("/")[-1].strip()
    forbidden = set('<>:"/\\|?*\x00')
    cleaned = "".join(ch for ch in cleaned if ch not in forbidden)
    return cleaned[:180] or "file.bin"
