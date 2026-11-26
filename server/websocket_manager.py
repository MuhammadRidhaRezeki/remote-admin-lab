"""Active WebSocket connection registry."""

from __future__ import annotations

import asyncio

from fastapi import WebSocket

from shared.protocol import decode_envelope, encode_envelope
from shared.models import Envelope


class ConnectionManager:
    def __init__(self) -> None:
        self._connections: dict[str, WebSocket] = {}
        self._lock = asyncio.Lock()

    async def connect(self, device_id: str, websocket: WebSocket) -> None:
        async with self._lock:
            previous = self._connections.get(device_id)
            if previous is not None and previous is not websocket:
                try:
                    await previous.close(code=4001, reason="sesi baru")
                except Exception:
                    pass
            self._connections[device_id] = websocket

    async def disconnect(self, device_id: str, websocket: WebSocket | None = None) -> None:
        async with self._lock:
            current = self._connections.get(device_id)
            if websocket is None or current is websocket:
                self._connections.pop(device_id, None)

    def is_connected(self, device_id: str) -> bool:
        return device_id in self._connections

    async def send(self, device_id: str, envelope: Envelope) -> bool:
        async with self._lock:
            websocket = self._connections.get(device_id)
        if websocket is None:
            return False
        try:
            await websocket.send_text(encode_envelope(envelope))
            return True
        except Exception:
            await self.disconnect(device_id, websocket)
            return False

    async def broadcast(self, envelope: Envelope) -> None:
        async with self._lock:
            targets = list(self._connections.items())
        for device_id, websocket in targets:
            try:
                await websocket.send_text(encode_envelope(envelope))
            except Exception:
                await self.disconnect(device_id, websocket)


def parse_client_message(raw: str) -> Envelope:
    return decode_envelope(raw)
