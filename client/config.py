"""Client settings stored locally in plain JSON (no secrets)."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path


def _home_dir() -> Path:
    override = os.environ.get("CLIENT_HOME")
    if override:
        return Path(override).resolve()
    if getattr(sys, "frozen", False):
        exe_dir = Path(sys.executable).resolve().parent
        return exe_dir.parent if (exe_dir.parent / "config").is_dir() else exe_dir
    return Path(__file__).resolve().parent.parent


HOME = _home_dir()
RELEASE_LAYOUT = bool(os.environ.get("CLIENT_HOME")) or getattr(sys, "frozen", False)
CONFIG_DIR = HOME / "config" if RELEASE_LAYOUT else HOME / "client" / "config"
SETTINGS_PATH = CONFIG_DIR / "settings.json"
IDENTITY_PATH = CONFIG_DIR / "identity.blob"
DATA_DIR = HOME / "data" if RELEASE_LAYOUT else HOME / "client" / "data"
CERT_PATH = (
    HOME / "certs" / "server.crt" if RELEASE_LAYOUT else HOME / "server" / "certs" / "server.crt"
)

DEFAULT_SETTINGS: dict[str, object] = {
    "server_url": "wss://127.0.0.1:8443/ws/client",
    "server_name": "remote-admin-lab.local",
    "ca_cert": str(CERT_PATH),
    "agent_version": "1.0.0",
    "data_dir": str(DATA_DIR),
    "allow_offline_recovery": True,
    "chunk_size_bytes": 262144,
}


def _resolve_paths(values: dict[str, object]) -> dict[str, object]:
    for key in ("ca_cert", "data_dir"):
        candidate = Path(str(values[key]))
        if not candidate.is_absolute():
            values[key] = str(HOME / candidate)
    return values


def load_settings(path: Path | str | None = None) -> dict[str, object]:
    target = Path(path) if path else SETTINGS_PATH
    values = dict(DEFAULT_SETTINGS)
    if target.exists():
        values.update(json.loads(target.read_text(encoding="utf-8")))
    return _resolve_paths(values)


def save_settings(settings: dict[str, object], path: Path | str | None = None) -> None:
    target = Path(path) if path else SETTINGS_PATH
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(settings, indent=2, ensure_ascii=False), encoding="utf-8")
