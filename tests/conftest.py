"""Pytest fixtures for an isolated lab instance."""

from __future__ import annotations

import tempfile
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from server.api import AppState, create_app
from server.authentication import AdminSessionStore, hash_password, hash_secret
from server.config import ServerConfig
from server.database import Database
from server.rate_limit import RateLimiter
from server.websocket_manager import ConnectionManager

ADMIN_PASSWORD = "AdminPass123!"
ENROLLMENT_CODE = "enroll-123"


@pytest.fixture()
def lab():
    root = Path(tempfile.mkdtemp(prefix="ral-test-"))
    salt, digest = hash_password(ADMIN_PASSWORD)
    config = ServerConfig(
        host="127.0.0.1",
        port=8443,
        db_path=str(root / "server.sqlite3"),
        inbox_dir=str(root / "inbox"),
        config_path=str(root / "settings.json"),
        cert_file=str(root / "certs" / "server.crt"),
        key_file=str(root / "certs" / "server.key"),
        ca_file=str(root / "certs" / "server.crt"),
        admin_salt=salt,
        admin_password_hash=digest,
        enrollment_code_hash=hash_secret(ENROLLMENT_CODE),
        rate_limit_per_minute=500,
    )
    state = AppState(
        config=config,
        db=Database(config.database_path),
        manager=ConnectionManager(),
        limiter=RateLimiter(500, 60.0),
        sessions=AdminSessionStore(3600),
    )
    app = create_app(state)
    client = TestClient(app)
    response = client.post(
        "/admin/login", json={"username": "admin", "password": ADMIN_PASSWORD}
    )
    assert response.status_code == 200
    token = response.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    return SimpleNamespace(
        root=root,
        config=config,
        state=state,
        app=app,
        client=client,
        headers=headers,
        token=token,
    )
