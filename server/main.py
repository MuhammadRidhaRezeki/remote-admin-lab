"""Server entry point: TLS API plus administration GUI."""

from __future__ import annotations

import argparse
import secrets
import threading

import uvicorn

from shared.protocol import MAX_MESSAGE_BYTES

from server.api import AppState, create_app
from server.authentication import AdminSessionStore, hash_password, hash_secret
from server.config import ServerConfig
from server.database import Database
from server.rate_limit import RateLimiter
from server.websocket_manager import ConnectionManager
from tools.dev_cert import generate_dev_certificate


def bootstrap(config: ServerConfig) -> None:
    changed = False
    if not config.admin_password_hash or not config.admin_salt:
        password = secrets.token_urlsafe(14)
        salt, digest = hash_password(password)
        config.admin_salt = salt
        config.admin_password_hash = digest
        print(f"[setup] admin password (ditampilkan sekali): {password}")
        changed = True
    if not config.enrollment_code_hash:
        code = secrets.token_urlsafe(14)
        config.enrollment_code_hash = hash_secret(code)
        print(f"[setup] enrollment code (ditampilkan sekali): {code}")
        changed = True
    if not config.cert_file or not config.key_file:
        raise ValueError("cert_file dan key_file wajib diisi")
    from pathlib import Path

    if not Path(config.cert_file).exists() or not Path(config.key_file).exists():
        generate_dev_certificate(
            Path(config.cert_file), Path(config.key_file), config.server_name
        )
        print("[setup] sertifikat dev self-signed dibuat")
        changed = True
    if changed:
        config.save()


def build_state(config: ServerConfig) -> AppState:
    return AppState(
        config=config,
        db=Database(config.database_path),
        manager=ConnectionManager(),
        limiter=RateLimiter(
            config.rate_limit_per_minute, 60.0
        ),
        sessions=AdminSessionStore(config.session_ttl_seconds),
    )


def make_uvicorn_config(app: object, config: ServerConfig) -> uvicorn.Config:
    return uvicorn.Config(
        app,
        host=config.host,
        port=config.port,
        ssl_certfile=config.cert_file,
        ssl_keyfile=config.key_file,
        ws_max_size=MAX_MESSAGE_BYTES,
        log_level="info",
        access_log=False,
    )


def serve_headless(config: ServerConfig) -> None:
    state = build_state(config)
    app = create_app(state)
    uvicorn.Server(make_uvicorn_config(app, config)).run()


def serve_with_gui(config: ServerConfig) -> None:
    state = build_state(config)
    app = create_app(state)
    server = uvicorn.Server(make_uvicorn_config(app, config))

    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()

    from server.gui.dashboard import ServerDashboard

    dashboard = ServerDashboard()

    def on_close() -> None:
        server.should_exit = True
        if dashboard._poll_after_id:
            dashboard.after_cancel(dashboard._poll_after_id)
        dashboard.update_idletasks()
        dashboard.destroy()

    dashboard.protocol("WM_DELETE_WINDOW", on_close)
    dashboard.mainloop()


def main() -> None:
    parser = argparse.ArgumentParser(description="Remote Administration Lab — Server")
    parser.add_argument("--config", default=None, help="path ke settings.json")
    parser.add_argument("--no-gui", action="store_true", help="jalankan API saja")
    parser.add_argument("--host", default=None)
    parser.add_argument("--port", type=int, default=None)
    args = parser.parse_args()

    config = ServerConfig.load(args.config)
    if args.host:
        config.host = args.host
    if args.port:
        config.port = args.port
    bootstrap(config)

    if args.no_gui:
        serve_headless(config)
    else:
        serve_with_gui(config)


if __name__ == "__main__":
    main()
