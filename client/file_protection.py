"""Explicit file selection, AES-GCM protection, and local DPAPI key storage."""

from __future__ import annotations

import json
import sqlite3
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from shared.crypto_utils import (
    ALGORITHM,
    b64e,
    decrypt_file,
    dpapi_protect,
    encrypt_file,
    generate_key,
)
from shared.models import new_id, utcnow

VAULT_ENTROPY = b"remote-admin-lab-vault-key-v1"


@dataclass(frozen=True)
class ProtectedFile:
    file_id: str
    client_id: str
    file_name: str
    original_path: str
    protected_path: str
    size_bytes: int
    sha256_plaintext: str
    nonce_b64: str
    tag_b64: str
    wrapped_key_b64: str
    algorithm: str
    created_at: str
    status: str


class Vault:
    def __init__(self, data_dir: Path | str, client_id: str) -> None:
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.protected_dir = self.data_dir / "protected"
        self.protected_dir.mkdir(parents=True, exist_ok=True)
        self.client_id = client_id
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(
            self.data_dir / "vault.sqlite3", check_same_thread=False, isolation_level=None
        )
        self._conn.row_factory = sqlite3.Row
        self._initialize()

    def _initialize(self) -> None:
        with self._lock:
            self._conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS vault_files (
                    file_id TEXT PRIMARY KEY,
                    client_id TEXT NOT NULL,
                    file_name TEXT NOT NULL,
                    original_path TEXT NOT NULL,
                    protected_path TEXT NOT NULL,
                    size_bytes INTEGER NOT NULL,
                    sha256_plaintext TEXT NOT NULL,
                    nonce_b64 TEXT NOT NULL,
                    tag_b64 TEXT NOT NULL,
                    wrapped_key_b64 TEXT NOT NULL,
                    algorithm TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    status TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS local_events (
                    event_id TEXT PRIMARY KEY,
                    ts TEXT NOT NULL,
                    action TEXT NOT NULL,
                    detail_json TEXT NOT NULL,
                    synced INTEGER NOT NULL DEFAULT 0
                );
                """
            )

    @staticmethod
    def expand_selection(paths: list[Path]) -> list[Path]:
        selected: list[Path] = []
        seen: set[str] = set()
        for raw in paths:
            path = Path(raw).expanduser().resolve()
            candidates = [path] if path.is_file() else list(path.rglob("*")) if path.is_dir() else []
            for candidate in candidates:
                if not candidate.is_file():
                    continue
                key = str(candidate).lower()
                if key not in seen:
                    seen.add(key)
                    selected.append(candidate)
        return selected

    @staticmethod
    def describe(paths: list[Path]) -> list[dict[str, Any]]:
        result = []
        for path in paths:
            try:
                size = path.stat().st_size
            except OSError:
                size = 0
            result.append({"name": path.name, "path": str(path), "size_bytes": size})
        return result

    def protect(self, paths: list[Path]) -> list[dict[str, Any]]:
        outputs: list[dict[str, Any]] = []
        for source in self.expand_selection(paths):
            file_id = new_id("file")
            destination = self.protected_dir / f"{file_id}.enc"
            key = generate_key()
            result = encrypt_file(source, destination, key)

            verify_path = self.protected_dir / f"{file_id}.verify"
            decrypt_file(
                destination,
                verify_path,
                key,
                result.nonce,
                result.tag,
                result.sha256_plaintext,
            )
            verify_path.unlink(missing_ok=True)

            wrapped_key = dpapi_protect(key, VAULT_ENTROPY)
            record = ProtectedFile(
                file_id=file_id,
                client_id=self.client_id,
                file_name=source.name,
                original_path=str(source),
                protected_path=str(destination),
                size_bytes=result.size_bytes,
                sha256_plaintext=result.sha256_plaintext,
                nonce_b64=b64e(result.nonce),
                tag_b64=b64e(result.tag),
                wrapped_key_b64=b64e(wrapped_key),
                algorithm=ALGORITHM,
                created_at=utcnow().isoformat(),
                status="protected",
            )
            with self._lock:
                self._conn.execute(
                    """
                    INSERT INTO vault_files (
                        file_id, client_id, file_name, original_path, protected_path,
                        size_bytes, sha256_plaintext, nonce_b64, tag_b64,
                        wrapped_key_b64, algorithm, created_at, status
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        record.file_id,
                        record.client_id,
                        record.file_name,
                        record.original_path,
                        record.protected_path,
                        record.size_bytes,
                        record.sha256_plaintext,
                        record.nonce_b64,
                        record.tag_b64,
                        record.wrapped_key_b64,
                        record.algorithm,
                        record.created_at,
                        record.status,
                    ),
                )
            self.append_event(
                "file_protected",
                {"file_id": file_id, "file_name": source.name, "size_bytes": result.size_bytes},
            )
            outputs.append(self.public_record(record))
        return outputs

    @staticmethod
    def public_record(record: ProtectedFile) -> dict[str, Any]:
        return {
            "file_id": record.file_id,
            "client_id": record.client_id,
            "file_name": record.file_name,
            "original_path": record.original_path,
            "protected_path": record.protected_path,
            "size_bytes": record.size_bytes,
            "sha256_plaintext": record.sha256_plaintext,
            "algorithm": record.algorithm,
            "created_at": record.created_at,
            "status": record.status,
        }

    def get_record(self, file_id: str) -> ProtectedFile | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM vault_files WHERE file_id=?", (file_id,)
            ).fetchone()
        return ProtectedFile(**dict(row)) if row else None

    def list_records(self) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM vault_files ORDER BY created_at DESC"
            ).fetchall()
        return [self.public_record(ProtectedFile(**dict(row))) for row in rows]

    def set_status(self, file_id: str, status: str) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE vault_files SET status=? WHERE file_id=?", (status, file_id)
            )

    def append_event(self, action: str, detail: dict[str, Any]) -> str:
        event_id = new_id("evt")
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO local_events (event_id, ts, action, detail_json, synced)
                VALUES (?, ?, ?, ?, 0)
                """,
                (
                    event_id,
                    utcnow().isoformat(),
                    action,
                    json.dumps(detail, sort_keys=True, ensure_ascii=False),
                ),
            )
        return event_id

    def list_events(self, limit: int = 200) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM local_events ORDER BY ts DESC LIMIT ?", (limit,)
            ).fetchall()
        return [
            {
                "event_id": row["event_id"],
                "ts": row["ts"],
                "action": row["action"],
                "detail": json.loads(row["detail_json"]),
                "synced": bool(row["synced"]),
            }
            for row in rows
        ]

    def unsynced_events(self) -> list[dict[str, Any]]:
        return [event for event in self.list_events(1000) if not event["synced"]]

    def mark_synced(self, event_id: str) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE local_events SET synced=1 WHERE event_id=?", (event_id,)
            )
