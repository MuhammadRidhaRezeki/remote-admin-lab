"""API, WebSocket approval, and audit integration tests."""

from __future__ import annotations

import os
import time
from pathlib import Path

from shared.crypto_utils import ALGORITHM, encrypt_file, generate_key
from shared.models import DeviceIdentity, MessageType, RecoveryResultPayload, utcnow
from shared.protocol import decode_envelope, encode_envelope, make_envelope

ENROLLMENT_CODE = "enroll-123"
DEVICE_ID = "dev-1"
TOKEN = "device-token-123"


def _identity() -> DeviceIdentity:
    return DeviceIdentity(
        device_id=DEVICE_ID,
        hostname="WS-01",
        os_name="Windows",
        os_version="11",
        python_version="3.14",
        private_ips=["10.0.0.5"],
        agent_version="1.0.0",
    )


def _hello() -> str:
    return encode_envelope(
        make_envelope(
            MessageType.HELLO,
            DEVICE_ID,
            {
                "identity": _identity().model_dump(mode="json"),
                "enrollment_code": ENROLLMENT_CODE,
            },
        )
    )


def _wait_for(predicate, timeout: float = 3.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.05)
    raise AssertionError("kondisi tidak tercapai dalam batas waktu")


def test_admin_auth_is_required(lab) -> None:
    assert lab.client.get("/health").status_code == 200
    assert lab.client.get("/admin/clients").status_code == 401
    bad = lab.client.post(
        "/admin/login", json={"username": "admin", "password": "wrong-password"}
    )
    assert bad.status_code == 401


def test_task_approval_dispatch_and_result(lab) -> None:
    with lab.client.websocket_connect(
        "/ws/client", headers={"Authorization": f"Bearer {TOKEN}"}
    ) as websocket:
        websocket.send_text(_hello())
        ack = decode_envelope(websocket.receive_text())
        assert ack.type is MessageType.HELLO_ACK

        created = lab.client.post(
            "/admin/tasks",
            headers=lab.headers,
            json={
                "client_id": DEVICE_ID,
                "task_type": "system_info",
                "reason": "inventory",
            },
        )
        assert created.status_code == 201
        task_id = created.json()["task_id"]

        decision = lab.client.post(
            f"/admin/tasks/{task_id}/decision",
            headers=lab.headers,
            json={"decision": "approved"},
        )
        assert decision.status_code == 200
        assert decision.json()["delivered"] is True

        request = decode_envelope(websocket.receive_text())
        assert request.type is MessageType.TASK_REQUEST
        assert request.payload["task_id"] == task_id

        websocket.send_text(
            encode_envelope(
                make_envelope(
                    MessageType.TASK_RESULT,
                    DEVICE_ID,
                    {"task_id": task_id, "status": "completed", "result": {"cpu": 12}},
                )
            )
        )
        _wait_for(
            lambda: any(
                row["task_id"] == task_id and row["status"] == "completed"
                for row in lab.client.get("/admin/tasks", headers=lab.headers).json()
            )
        )
        assert lab.state.db.verify_audit_chain()


def test_unlock_approval_requires_local_confirmation(lab, tmp_path: Path) -> None:
    source = tmp_path / "rahasia.txt"
    source.write_bytes(b"rahasia perusahaan")
    key = generate_key()
    encrypted = tmp_path / "rahasia.enc"
    result = encrypt_file(source, encrypted, key)
    metadata = {
        "file_id": "file-1",
        "file_name": source.name,
        "original_path": str(source),
        "protected_path": str(encrypted),
        "size_bytes": result.size_bytes,
        "sha256_plaintext": result.sha256_plaintext,
        "algorithm": ALGORITHM,
        "created_at": utcnow().isoformat(),
        "status": "protected",
    }

    with lab.client.websocket_connect(
        "/ws/client", headers={"Authorization": f"Bearer {TOKEN}"}
    ) as websocket:
        websocket.send_text(_hello())
        decode_envelope(websocket.receive_text())

        websocket.send_text(
            encode_envelope(
                make_envelope(MessageType.FILE_RECORD, DEVICE_ID, metadata)
            )
        )
        _wait_for(lambda: bool(lab.client.get("/admin/file-records", headers=lab.headers).json()))

        websocket.send_text(
            encode_envelope(
                make_envelope(
                    MessageType.UNLOCK_REQUEST,
                    DEVICE_ID,
                    {"file_id": "file-1", "reason": "audit bulanan"},
                    request_id="unlock-1",
                )
            )
        )
        _wait_for(
            lambda: bool(lab.client.get("/admin/unlock-requests", headers=lab.headers).json())
        )

        decision = lab.client.post(
            "/admin/unlock-requests/unlock-1/decision",
            headers=lab.headers,
            json={"decision": "approved"},
        )
        assert decision.status_code == 200

        unlock_message = decode_envelope(websocket.receive_text())
        assert unlock_message.type is MessageType.UNLOCK_DECISION
        assert unlock_message.payload["decision"] == "approved"

        recovery = RecoveryResultPayload(
            request_id="unlock-1",
            file_id="file-1",
            success=True,
            destination=str(tmp_path / "restore" / "rahasia.txt"),
            sha256_plaintext=result.sha256_plaintext,
            verified=True,
        )
        websocket.send_text(
            encode_envelope(
                make_envelope(
                    MessageType.RECOVERY_RESULT,
                    DEVICE_ID,
                    recovery.model_dump(mode="json"),
                )
            )
        )
        _wait_for(
            lambda: any(
                event["action"] == "file_recovery"
                for event in lab.client.get(
                    "/admin/audit-logs", headers=lab.headers
                ).json()["events"]
            )
        )
        assert lab.state.db.verify_audit_chain()


def test_admin_clients_hides_secret_hashes(lab) -> None:
    with lab.client.websocket_connect(
        "/ws/client", headers={"Authorization": f"Bearer {TOKEN}"}
    ) as websocket:
        websocket.send_text(_hello())
        ack = decode_envelope(websocket.receive_text())
        assert ack.type is MessageType.HELLO_ACK

    response = lab.client.get("/admin/clients", headers=lab.headers)
    assert response.status_code == 200
    row = response.json()[0]
    assert row["client_id"] == DEVICE_ID
    assert "token_hash" not in row
    assert "enrollment_code_hash" not in row


def test_rate_limiter_blocks_excess() -> None:
    from server.rate_limit import RateLimitExceeded, RateLimiter

    limiter = RateLimiter(max_requests=2, window_seconds=60)
    limiter.check("key")
    limiter.check("key")
    try:
        limiter.check("key")
    except RateLimitExceeded:
        return
    raise AssertionError("rate limiter tidak menolak permintaan ketiga")
