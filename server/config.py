"""Server configuration resolved from the project directory."""

from __future__ import annotations

import json
import os
import sys
from dataclasses import asdict, dataclass
from pathlib import Path


def _project_root() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent.parent.parent
    return Path(__file__).resolve().parent.parent


ROOT = _project_root()

CONFIG_DIR = ROOT / "server" / "config"
CONFIG_PATH = CONFIG_DIR / "settings.json"
DATA_DIR = ROOT / "server" / "data"
CERT_DIR = ROOT / "server" / "certs"
INBOX_DIR = ROOT / "server" / "inbox"


@dataclass
class ServerConfig:
    host: str = "127.0.0.1"
    port: int = 8443
    server_name: str = "remote-admin-lab.local"
    admin_username: str = "admin"
    admin_password_hash: str = ""
    admin_salt: str = ""
    enrollment_code_hash: str = ""
    cert_file: str = str(CERT_DIR / "server.crt")
    key_file: str = str(CERT_DIR / "server.key")
    ca_file: str = str(CERT_DIR / "server.crt")
    db_path: str = str(DATA_DIR / "server.sqlite3")
    inbox_dir: str = str(INBOX_DIR)
    session_ttl_seconds: int = 3600
    max_transfer_bytes: int = 25 * 1024 * 1024
    rate_limit_per_minute: int = 120
    config_path: str = ""

    @classmethod
    def load(cls, path: Path | str | None = None) -> "ServerConfig":
        target = Path(path) if path else CONFIG_PATH
        if not target.exists():
            return cls(config_path=str(target))
        data = json.loads(target.read_text(encoding="utf-8"))
        known = cls.__dataclass_fields__
        values = {key: value for key, value in data.items() if key in known}
        values["config_path"] = str(target)
        return cls(**values)

    def save(self, path: Path | str | None = None) -> None:
        target = Path(path) if path else Path(self.config_path or CONFIG_PATH)
        target.parent.mkdir(parents=True, exist_ok=True)
        temporary = target.with_suffix(target.suffix + ".tmp")
        temporary.write_text(
            json.dumps(asdict(self), indent=2, ensure_ascii=False), encoding="utf-8"
        )
        os.replace(temporary, target)

    @property
    def database_path(self) -> Path:
        return Path(self.db_path)

    @property
    def transfer_root(self) -> Path:
        return Path(self.inbox_dir)
