"""End-to-end TLS/WebSocket smoke check against a local server instance."""

from __future__ import annotations

import argparse
import tempfile
import threading
import time
from pathlib import Path

import requests
import uvicorn

from client.authentication import load_or_create_identity
from client.config import load_settings
from client.connection import AgentConnection
from server.api import create_app
from server.config import ServerConfig
from server.main import build_state, make_uvicorn_config
from shared.models import Envelope


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--enrollment-code", required=True)
    args = parser.parse_args()

    config = ServerConfig.load()
    health_host = "127.0.0.1" if config.host in {"0.0.0.0", "::"} else config.host
    state = build_state(config)
    server = uvicorn.Server(make_uvicorn_config(create_app(state), config))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()

    try:
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            try:
                response = requests.get(
                    f"https://{health_host}:{config.port}/health",
                    verify=config.ca_file,
                    timeout=2,
                )
                if response.status_code == 200:
                    break
            except requests.RequestException:
                time.sleep(0.2)
        else:
            raise RuntimeError("server tidak siap")

        root = Path(tempfile.mkdtemp(prefix="ral-e2e-"))
        identity = load_or_create_identity(root / "identity.blob")
        identity.enrollment_code = args.enrollment_code
        settings = load_settings()
        settings["ca_cert"] = config.ca_file

        received: list[Envelope] = []
        statuses: list[tuple[str, str]] = []
        connection = AgentConnection(
            settings,
            identity,
            received.append,
            lambda status, detail: statuses.append((status, detail)),
        )
        connection.start()
        try:
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline:
                if any(status == "online" for status, _ in statuses):
                    if any(row["status"] == "online" for row in state.db.list_clients()):
                        break
                time.sleep(0.2)
            else:
                raise RuntimeError("client tidak terhubung")

            print(
                "e2e-ok",
                f"status={statuses[-1]}",
                f"messages={[item.type.value for item in received]}",
                f"clients={[row['hostname'] for row in state.db.list_clients()]}",
                f"chain={state.db.verify_audit_chain()}",
            )
        finally:
            connection.stop()
    finally:
        server.should_exit = True
        thread.join(timeout=10)


if __name__ == "__main__":
    main()
