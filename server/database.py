"""SQLite persistence with an append-only, hash-chained audit log."""

from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Any, Iterator

from shared.models import new_id, utcnow

GENESIS_HASH = "0" * 64

SCHEMA = """
CREATE TABLE IF NOT EXISTS clients (
    client_id TEXT PRIMARY KEY,
    hostname TEXT NOT NULL,
    os_name TEXT NOT NULL,
    os_version TEXT NOT NULL,
    python_version TEXT NOT NULL,
    private_ips TEXT NOT NULL,
    agent_version TEXT NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    enrollment_code_hash TEXT NOT NULL,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'offline'
);

CREATE TABLE IF NOT EXISTS sessions (
    session_id TEXT PRIMARY KEY,
    client_id TEXT NOT NULL REFERENCES clients(client_id),
    connected_at TEXT NOT NULL,
    disconnected_at TEXT,
    remote_ip TEXT,
    last_ping TEXT
);

CREATE TABLE IF NOT EXISTS tasks (
    task_id TEXT PRIMARY KEY,
    client_id TEXT NOT NULL REFERENCES clients(client_id),
    task_type TEXT NOT NULL,
    status TEXT NOT NULL,
    reason TEXT,
    file_id TEXT,
    requested_by TEXT NOT NULL,
    created_at TEXT NOT NULL,
    decided_at TEXT,
    completed_at TEXT,
    result_json TEXT
);

CREATE TABLE IF NOT EXISTS file_records (
    file_id TEXT PRIMARY KEY,
    client_id TEXT NOT NULL REFERENCES clients(client_id),
    file_name TEXT NOT NULL,
    original_path TEXT NOT NULL,
    protected_path TEXT NOT NULL,
    size_bytes INTEGER NOT NULL,
    sha256_plaintext TEXT NOT NULL,
    algorithm TEXT NOT NULL,
    created_at TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'protected'
);

CREATE TABLE IF NOT EXISTS unlock_requests (
    request_id TEXT PRIMARY KEY,
    client_id TEXT NOT NULL REFERENCES clients(client_id),
    file_id TEXT NOT NULL REFERENCES file_records(file_id),
    file_name TEXT,
    reason TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    created_at TEXT NOT NULL,
    decided_at TEXT
);

CREATE TABLE IF NOT EXISTS approvals (
    approval_id TEXT PRIMARY KEY,
    subject_type TEXT NOT NULL,
    subject_id TEXT NOT NULL,
    decision TEXT NOT NULL,
    admin_id TEXT NOT NULL,
    admin_name TEXT NOT NULL,
    notes TEXT,
    created_at TEXT NOT NULL,
    decided_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_logs (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id TEXT NOT NULL UNIQUE,
    ts TEXT NOT NULL,
    actor_type TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    action TEXT NOT NULL,
    target_type TEXT,
    target_id TEXT,
    detail_json TEXT NOT NULL,
    prev_hash TEXT NOT NULL,
    row_hash TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_sessions_client ON sessions(client_id);
CREATE INDEX IF NOT EXISTS idx_tasks_client ON tasks(client_id);
CREATE INDEX IF NOT EXISTS idx_files_client ON file_records(client_id);
CREATE INDEX IF NOT EXISTS idx_unlock_client ON unlock_requests(client_id);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_logs(ts);

CREATE TRIGGER IF NOT EXISTS audit_no_update
BEFORE UPDATE ON audit_logs
BEGIN
    SELECT RAISE(ABORT, 'audit_logs adalah append-only');
END;

CREATE TRIGGER IF NOT EXISTS audit_no_delete
BEFORE DELETE ON audit_logs
BEGIN
    SELECT RAISE(ABORT, 'audit_logs adalah append-only');
END;
"""


def _iso(value: datetime | str | None) -> str | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value.isoformat()
    return value


def _loads(value: str | None) -> Any:
    return json.loads(value) if value else None


class Database:
    def __init__(self, path: Path | str) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(
            self.path, check_same_thread=False, isolation_level=None
        )
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._conn.execute("PRAGMA busy_timeout=5000")
        self._initialize()

    def _initialize(self) -> None:
        with self._lock:
            self._conn.executescript(SCHEMA)

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                yield self._conn
            except Exception:
                self._conn.execute("ROLLBACK")
                raise
            else:
                self._conn.execute("COMMIT")

    def query_one(self, sql: str, params: tuple[Any, ...] = ()) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute(sql, params).fetchone()
        return dict(row) if row else None

    def query_all(self, sql: str, params: tuple[Any, ...] = ()) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(sql, params).fetchall()
        return [dict(row) for row in rows]

    def upsert_client(
        self,
        *,
        client_id: str,
        hostname: str,
        os_name: str,
        os_version: str,
        python_version: str,
        private_ips: list[str],
        agent_version: str,
        token_hash: str,
        enrollment_code_hash: str,
    ) -> None:
        now = utcnow().isoformat()
        with self.transaction() as conn:
            conn.execute(
                """
                INSERT INTO clients (
                    client_id, hostname, os_name, os_version, python_version,
                    private_ips, agent_version, token_hash, enrollment_code_hash,
                    first_seen, last_seen, status
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'online')
                ON CONFLICT(client_id) DO UPDATE SET
                    hostname=excluded.hostname,
                    os_name=excluded.os_name,
                    os_version=excluded.os_version,
                    python_version=excluded.python_version,
                    private_ips=excluded.private_ips,
                    agent_version=excluded.agent_version,
                    token_hash=excluded.token_hash,
                    last_seen=excluded.last_seen,
                    status='online'
                """,
                (
                    client_id,
                    hostname,
                    os_name,
                    os_version,
                    python_version,
                    json.dumps(private_ips),
                    agent_version,
                    token_hash,
                    enrollment_code_hash,
                    now,
                    now,
                ),
            )

    def get_client(self, client_id: str) -> dict[str, Any] | None:
        return self.query_one("SELECT * FROM clients WHERE client_id=?", (client_id,))

    def list_clients(self) -> list[dict[str, Any]]:
        columns = (
            "client_id, hostname, os_name, os_version, python_version, "
            "private_ips, agent_version, status, first_seen, last_seen"
        )
        rows = self.query_all(f"SELECT {columns} FROM clients ORDER BY last_seen DESC")
        for row in rows:
            row["private_ips"] = _loads(row["private_ips"]) or []
        return rows

    def set_client_status(self, client_id: str, status: str) -> None:
        with self.transaction() as conn:
            conn.execute(
                "UPDATE clients SET status=?, last_seen=? WHERE client_id=?",
                (status, utcnow().isoformat(), client_id),
            )

    def touch_client(self, client_id: str) -> None:
        with self.transaction() as conn:
            conn.execute(
                "UPDATE clients SET last_seen=? WHERE client_id=?",
                (utcnow().isoformat(), client_id),
            )

    def open_session(self, session_id: str, client_id: str, remote_ip: str) -> None:
        with self.transaction() as conn:
            conn.execute(
                """
                INSERT INTO sessions (session_id, client_id, connected_at, remote_ip, last_ping)
                VALUES (?, ?, ?, ?, ?)
                """,
                (session_id, client_id, utcnow().isoformat(), remote_ip, utcnow().isoformat()),
            )

    def close_session(self, session_id: str) -> None:
        with self.transaction() as conn:
            conn.execute(
                "UPDATE sessions SET disconnected_at=? WHERE session_id=?",
                (utcnow().isoformat(), session_id),
            )

    def ping_session(self, session_id: str) -> None:
        now = utcnow().isoformat()
        with self.transaction() as conn:
            conn.execute("UPDATE sessions SET last_ping=? WHERE session_id=?", (now, session_id))
            conn.execute(
                "UPDATE clients SET last_seen=? WHERE client_id=(SELECT client_id FROM sessions WHERE session_id=?)",
                (now, session_id),
            )

    def create_task(
        self,
        *,
        client_id: str,
        task_type: str,
        reason: str | None,
        file_id: str | None,
        requested_by: str,
    ) -> str:
        task_id = new_id("task")
        with self.transaction() as conn:
            conn.execute(
                """
                INSERT INTO tasks (
                    task_id, client_id, task_type, status, reason, file_id,
                    requested_by, created_at
                ) VALUES (?, ?, ?, 'pending', ?, ?, ?, ?)
                """,
                (
                    task_id,
                    client_id,
                    task_type,
                    reason,
                    file_id,
                    requested_by,
                    utcnow().isoformat(),
                ),
            )
        return task_id

    def get_task(self, task_id: str) -> dict[str, Any] | None:
        return self.query_one("SELECT * FROM tasks WHERE task_id=?", (task_id,))

    def list_tasks(self, client_id: str | None = None, limit: int = 100) -> list[dict[str, Any]]:
        if client_id:
            return self.query_all(
                "SELECT * FROM tasks WHERE client_id=? ORDER BY created_at DESC LIMIT ?",
                (client_id, limit),
            )
        return self.query_all("SELECT * FROM tasks ORDER BY created_at DESC LIMIT ?", (limit,))

    def update_task(
        self,
        task_id: str,
        *,
        status: str,
        decided_at: datetime | str | None = None,
        completed_at: datetime | str | None = None,
        result: dict[str, Any] | None = None,
    ) -> None:
        with self.transaction() as conn:
            conn.execute(
                """
                UPDATE tasks
                SET status=?, decided_at=?, completed_at=?, result_json=?
                WHERE task_id=?
                """,
                (
                    status,
                    _iso(decided_at),
                    _iso(completed_at),
                    json.dumps(result) if result is not None else None,
                    task_id,
                ),
            )

    def create_file_record(
        self,
        *,
        file_id: str,
        client_id: str,
        file_name: str,
        original_path: str,
        protected_path: str,
        size_bytes: int,
        sha256_plaintext: str,
        algorithm: str,
        created_at: datetime | str,
        status: str = "protected",
    ) -> None:
        with self.transaction() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO file_records (
                    file_id, client_id, file_name, original_path, protected_path,
                    size_bytes, sha256_plaintext, algorithm, created_at, status
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    file_id,
                    client_id,
                    file_name,
                    original_path,
                    protected_path,
                    size_bytes,
                    sha256_plaintext,
                    algorithm,
                    _iso(created_at),
                    status,
                ),
            )

    def get_file_record(self, file_id: str) -> dict[str, Any] | None:
        return self.query_one("SELECT * FROM file_records WHERE file_id=?", (file_id,))

    def list_file_records(self, client_id: str | None = None, limit: int = 100) -> list[dict[str, Any]]:
        if client_id:
            return self.query_all(
                "SELECT * FROM file_records WHERE client_id=? ORDER BY created_at DESC LIMIT ?",
                (client_id, limit),
            )
        return self.query_all(
            "SELECT * FROM file_records ORDER BY created_at DESC LIMIT ?", (limit,)
        )

    def create_unlock_request(
        self,
        *,
        request_id: str,
        client_id: str,
        file_id: str,
        file_name: str,
        reason: str,
    ) -> None:
        with self.transaction() as conn:
            conn.execute(
                """
                INSERT INTO unlock_requests (
                    request_id, client_id, file_id, file_name, reason, status, created_at
                ) VALUES (?, ?, ?, ?, ?, 'pending', ?)
                """,
                (request_id, client_id, file_id, file_name, reason, utcnow().isoformat()),
            )

    def get_unlock_request(self, request_id: str) -> dict[str, Any] | None:
        return self.query_one(
            "SELECT * FROM unlock_requests WHERE request_id=?", (request_id,)
        )

    def list_unlock_requests(self, limit: int = 100) -> list[dict[str, Any]]:
        return self.query_all(
            "SELECT * FROM unlock_requests ORDER BY created_at DESC LIMIT ?", (limit,)
        )

    def update_unlock_request(self, request_id: str, *, status: str) -> None:
        with self.transaction() as conn:
            conn.execute(
                "UPDATE unlock_requests SET status=?, decided_at=? WHERE request_id=?",
                (status, utcnow().isoformat(), request_id),
            )

    def create_approval(
        self,
        *,
        subject_type: str,
        subject_id: str,
        decision: str,
        admin_id: str,
        admin_name: str,
        notes: str | None,
    ) -> str:
        approval_id = new_id("apr")
        now = utcnow().isoformat()
        with self.transaction() as conn:
            conn.execute(
                """
                INSERT INTO approvals (
                    approval_id, subject_type, subject_id, decision, admin_id,
                    admin_name, notes, created_at, decided_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    approval_id,
                    subject_type,
                    subject_id,
                    decision,
                    admin_id,
                    admin_name,
                    notes,
                    now,
                    now,
                ),
            )
        return approval_id

    def list_approvals(self, limit: int = 100) -> list[dict[str, Any]]:
        return self.query_all(
            "SELECT * FROM approvals ORDER BY decided_at DESC LIMIT ?", (limit,)
        )

    def append_audit(
        self,
        *,
        actor_type: str,
        actor_id: str,
        action: str,
        target_type: str | None = None,
        target_id: str | None = None,
        detail: dict[str, Any] | None = None,
    ) -> str:
        event_id = new_id("evt")
        ts = utcnow().isoformat()
        detail_json = json.dumps(detail or {}, sort_keys=True, separators=(",", ":"))
        with self.transaction() as conn:
            last = conn.execute(
                "SELECT row_hash FROM audit_logs ORDER BY seq DESC LIMIT 1"
            ).fetchone()
            prev_hash = last["row_hash"] if last else GENESIS_HASH
            canonical = json.dumps(
                {
                    "event_id": event_id,
                    "ts": ts,
                    "actor_type": actor_type,
                    "actor_id": actor_id,
                    "action": action,
                    "target_type": target_type,
                    "target_id": target_id,
                    "detail_json": detail_json,
                    "prev_hash": prev_hash,
                },
                sort_keys=True,
                separators=(",", ":"),
            )
            row_hash = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
            conn.execute(
                """
                INSERT INTO audit_logs (
                    event_id, ts, actor_type, actor_id, action, target_type,
                    target_id, detail_json, prev_hash, row_hash
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event_id,
                    ts,
                    actor_type,
                    actor_id,
                    action,
                    target_type,
                    target_id,
                    detail_json,
                    prev_hash,
                    row_hash,
                ),
            )
        return row_hash

    def list_audit(self, limit: int = 200) -> list[dict[str, Any]]:
        rows = self.query_all(
            "SELECT * FROM audit_logs ORDER BY seq DESC LIMIT ?", (limit,)
        )
        for row in rows:
            row["detail"] = _loads(row.pop("detail_json"))
        return rows

    def verify_audit_chain(self) -> bool:
        rows = self.query_all("SELECT * FROM audit_logs ORDER BY seq ASC")
        prev_hash = GENESIS_HASH
        for row in rows:
            canonical = json.dumps(
                {
                    "event_id": row["event_id"],
                    "ts": row["ts"],
                    "actor_type": row["actor_type"],
                    "actor_id": row["actor_id"],
                    "action": row["action"],
                    "target_type": row["target_type"],
                    "target_id": row["target_id"],
                    "detail_json": row["detail_json"],
                    "prev_hash": prev_hash,
                },
                sort_keys=True,
                separators=(",", ":"),
            )
            expected = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
            if expected != row["row_hash"]:
                return False
            prev_hash = row["row_hash"]
        return True
