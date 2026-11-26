"""Explicit WebSocket client connection with TLS verification."""

from __future__ import annotations

import asyncio
import ssl
import threading
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlparse

from websockets.asyncio.client import connect

from shared.models import Envelope, MessageType
from shared.protocol import MAX_MESSAGE_BYTES, decode_envelope, encode_envelope, make_envelope

from .authentication import ClientIdentity
from .system_info import device_identity


class AgentConnection:
    def __init__(
        self,
        settings: dict[str, Any],
        identity: ClientIdentity,
        on_message: Callable[[Envelope], None],
        on_status: Callable[[str, str], None],
    ) -> None:
        self._settings = settings
        self._identity = identity
        self._on_message = on_message
        self._on_status = on_status
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._socket: Any = None
        self._connected = False

    @property
    def connected(self) -> bool:
        return self._connected

    def _ssl_context(self) -> ssl.SSLContext:
        ca_path = Path(str(self._settings["ca_cert"]))
        if not ca_path.is_file():
            raise FileNotFoundError(f"CA certificate tidak ditemukan: {ca_path}")
        context = ssl.create_default_context(cafile=str(ca_path))
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        return context

    def _hello(self) -> Envelope:
        identity = device_identity()
        identity.device_id = self._identity.device_id
        return make_envelope(
            MessageType.HELLO,
            self._identity.device_id,
            {
                "identity": identity.model_dump(mode="json"),
                "enrollment_code": self._identity.enrollment_code,
            },
        )

    async def _runner(self) -> None:
        url = str(self._settings["server_url"])
        parsed = urlparse(url)
        headers = {"Authorization": f"Bearer {self._identity.token}"}
        backoff = 1.0

        while not self._stop_event.is_set():
            try:
                async with connect(
                    url,
                    additional_headers=headers,
                    ssl=self._ssl_context(),
                    server_hostname=parsed.hostname,
                    max_size=MAX_MESSAGE_BYTES,
                    open_timeout=10,
                    ping_interval=None,
                ) as websocket:
                    self._socket = websocket
                    self._connected = True
                    self._on_status("online", "terhubung ke server")
                    await websocket.send(encode_envelope(self._hello()))
                    backoff = 1.0

                    while not self._stop_event.is_set():
                        raw = await websocket.recv()
                        envelope = decode_envelope(raw)
                        self._on_message(envelope)
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                self._on_status("offline", str(exc)[:240])
            finally:
                self._socket = None
                self._connected = False
                if not self._stop_event.is_set():
                    self._on_status("offline", "koneksi terputus")

            if self._stop_event.is_set():
                break
            await asyncio.sleep(backoff)
            backoff = min(backoff * 2, 30.0)

    def _thread_main(self) -> None:
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)
        try:
            self._loop.run_until_complete(self._runner())
        finally:
            self._loop.close()
            self._loop = None

    def start(self) -> None:
        if self._thread is not None and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._thread_main, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop_event.set()
        if self._loop is not None and self._socket is not None:
            try:
                asyncio.run_coroutine_threadsafe(self._socket.close(), self._loop).result(
                    timeout=5
                )
            except Exception:
                pass
        if self._thread is not None and self._thread.is_alive():
            self._thread.join(timeout=5)
        self._connected = False
        self._socket = None
        self._on_status("stopped", "agent dihentikan")

    def send(self, envelope: Envelope) -> bool:
        if self._loop is None or self._socket is None or not self._connected:
            return False
        try:
            future = asyncio.run_coroutine_threadsafe(
                self._socket.send(encode_envelope(envelope)), self._loop
            )
            future.result(timeout=8)
            return True
        except Exception:
            return False
