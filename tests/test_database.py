"""Database schema and append-only audit tests."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from shared.models import utcnow

from server.database import Database


def test_database_crud_and_audit_chain(tmp_path: Path) -> None:
    db = Database(tmp_path / "server.sqlite3")
    db.upsert_client(
        client_id="dev-1",
        hostname="WS-01",
        os_name="Windows",
        os_version="11",
        python_version="3.14",
        private_ips=["10.0.0.5"],
        agent_version="1.0.0",
        token_hash="th",
        enrollment_code_hash="eh",
    )
    listed = db.list_clients()[0]
    assert listed["hostname"] == "WS-01"
    assert "token_hash" not in listed
    assert "enrollment_code_hash" not in listed

    task_id = db.create_task(
        client_id="dev-1",
        task_type="system_info",
        reason="check",
        file_id=None,
        requested_by="admin",
    )
    db.update_task(task_id, status="approved", decided_at=utcnow())
    assert db.get_task(task_id)["status"] == "approved"

    db.append_audit(actor_type="admin", actor_id="admin", action="task_created")
    db.append_audit(actor_type="admin", actor_id="admin", action="task_approved")
    assert db.verify_audit_chain()

    with sqlite3.connect(tmp_path / "server.sqlite3") as raw:
        with pytest.raises(sqlite3.IntegrityError):
            raw.execute("UPDATE audit_logs SET action='tampered' WHERE seq=1")
