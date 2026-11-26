"""FastAPI control plane and client WebSocket endpoint."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
from dataclasses import dataclass, field
from typing import Annotated, Any

from fastapi import (
    Depends,
    FastAPI,
    Header,
    HTTPException,
    Request,
    WebSocket,
    WebSocketDisconnect,
)
from fastapi import status as http_status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import ValidationError

from shared.models import (
    ClientInfo,
    DecisionRequest,
    DeviceIdentity,
    Envelope,
    FileMetadata,
    LoginRequest,
    MessageType,
    PasswordChangeRequest,
    RecoveryResultPayload,
    SystemSnapshot,
    TaskCreateRequest,
    UnlockRequestPayload,
    new_id,
    utcnow,
)
from shared.protocol import decode_envelope, make_envelope, sanitize_filename

from .approvals import ApprovalService
from .authentication import (
    AdminSessionStore,
    hash_password,
    hash_secret,
    verify_password,
    verify_secret,
)
from .config import ServerConfig
from .database import Database
from .rate_limit import RateLimitExceeded, RateLimiter
from .websocket_manager import ConnectionManager

bearer_scheme = HTTPBearer(auto_error=False)


@dataclass
class AppState:
    config: ServerConfig
    db: Database
    manager: ConnectionManager
    limiter: RateLimiter
    sessions: AdminSessionStore
    approvals: ApprovalService = field(init=False)
    transfers: dict[str, dict[str, Any]] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.approvals = ApprovalService(self.db, self.manager)


def _client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def _bearer_from_header(header: str | None) -> str | None:
    if not header or not header.lower().startswith("bearer "):
        return None
    return header.split(None, 1)[1].strip() or None


def _parse_json(value: str | None) -> dict[str, Any] | None:
    return json.loads(value) if value else None


def create_app(state: AppState) -> FastAPI:
    app = FastAPI(
        title="Remote Administration Lab",
        version="1.0.0",
        docs_url="/docs",
        redoc_url=None,
    )
    app.state.lab = state

    def require_admin(
        request: Request,
        credentials: Annotated[
            HTTPAuthorizationCredentials | None, Depends(bearer_scheme)
        ],
    ) -> str:
        try:
            state.limiter.check(f"admin:{_client_ip(request)}:{request.url.path}")
        except RateLimitExceeded as exc:
            raise HTTPException(
                status_code=http_status.HTTP_429_TOO_MANY_REQUESTS,
                detail="terlalu banyak permintaan",
            ) from exc
        if credentials is None or credentials.scheme.lower() != "bearer":
            raise HTTPException(
                status_code=http_status.HTTP_401_UNAUTHORIZED,
                detail="autentikasi admin diperlukan",
            )
        username = state.sessions.validate(credentials.credentials)
        if username is None:
            raise HTTPException(
                status_code=http_status.HTTP_401_UNAUTHORIZED,
                detail="sesi admin tidak valid atau kedaluwarsa",
            )
        return username

    async def heartbeat(device_id: str, session_id: str) -> None:
        while True:
            await asyncio.sleep(30)
            delivered = await state.manager.send(
                device_id,
                make_envelope(
                    MessageType.PING, device_id, {"session_id": session_id}
                ),
            )
            if not delivered:
                break
            state.db.ping_session(session_id)

    async def handle_chunk(envelope: Envelope, session_id: str) -> None:
        payload = envelope.payload
        task_id = str(payload.get("task_id", ""))
        task = state.db.get_task(task_id)
        session = state.db.query_one(
            "SELECT client_id FROM sessions WHERE session_id=?", (session_id,)
        )
        if not task or not session or task["client_id"] != session["client_id"]:
            state.db.append_audit(
                actor_type="client",
                actor_id=envelope.device_id,
                action="transfer_rejected",
                target_type="task",
                target_id=task_id,
                detail={"reason": "task tidak cocok dengan sesi"},
            )
            return
        if task["task_type"] != "transfer_file" or task["status"] not in {
            "dispatched",
            "in_progress",
        }:
            raise ValueError("task transfer tidak aktif")

        index = int(payload["chunk_index"])
        total = int(payload["total_chunks"])
        if index < 0 or total < 1 or index >= total:
            raise ValueError("indeks chunk tidak valid")
        data = base64.b64decode(str(payload["data_b64"]), validate=True)

        transfer = state.transfers.setdefault(
            task_id,
            {
                "file_name": sanitize_filename(str(payload.get("file_name", "file.bin"))),
                "chunks": {},
                "total": total,
                "size": 0,
            },
        )
        if transfer["total"] != total:
            raise ValueError("jumlah chunk berubah")
        if transfer["size"] + len(data) > state.config.max_transfer_bytes:
            raise ValueError("ukuran transfer melebihi batas")
        if index in transfer["chunks"]:
            raise ValueError("chunk duplikat")

        transfer["chunks"][index] = data
        transfer["size"] += len(data)
        state.db.update_task(task_id, status="in_progress")

        if len(transfer["chunks"]) == total:
            root = state.config.transfer_root / task_id
            root.mkdir(parents=True, exist_ok=True)
            destination = root / transfer["file_name"]
            digest = hashlib.sha256()
            with destination.open("wb") as output:
                for part in range(total):
                    chunk = transfer["chunks"][part]
                    digest.update(chunk)
                    output.write(chunk)
            result = {
                "transfer_path": str(destination),
                "file_name": transfer["file_name"],
                "size_bytes": transfer["size"],
                "sha256_ciphertext": digest.hexdigest(),
                "note": "berkas terenkripsi; kunci tetap di client",
            }
            state.db.update_task(
                task_id, status="completed", completed_at=utcnow(), result=result
            )
            state.db.append_audit(
                actor_type="client",
                actor_id=envelope.device_id,
                action="file_transfer_completed",
                target_type="task",
                target_id=task_id,
                detail=result,
            )
            state.transfers.pop(task_id, None)

    async def handle_client_message(
        envelope: Envelope, session_id: str, remote_ip: str
    ) -> None:
        session = state.db.query_one(
            "SELECT client_id FROM sessions WHERE session_id=?", (session_id,)
        )
        if not session or session["client_id"] != envelope.device_id:
            state.db.append_audit(
                actor_type="client",
                actor_id=envelope.device_id,
                action="message_rejected",
                target_type="session",
                target_id=session_id,
                detail={"type": envelope.type.value},
            )
            return

        if envelope.type is MessageType.PONG:
            state.db.ping_session(session_id)
            return

        if envelope.type is MessageType.SYSTEM_SNAPSHOT:
            snapshot = SystemSnapshot.model_validate(envelope.payload)
            state.db.append_audit(
                actor_type="client",
                actor_id=envelope.device_id,
                action="system_snapshot",
                target_type="client",
                target_id=envelope.device_id,
                detail=snapshot.model_dump(mode="json"),
            )
            return

        if envelope.type is MessageType.TASK_RESULT:
            task_id = str(envelope.payload.get("task_id", ""))
            if not state.db.get_task(task_id):
                raise ValueError("task_result untuk task yang tidak dikenal")
            result_status = str(envelope.payload.get("status", "completed"))
            state.db.update_task(
                task_id,
                status=result_status,
                completed_at=utcnow(),
                result=envelope.payload.get("result") or {},
            )
            state.db.append_audit(
                actor_type="client",
                actor_id=envelope.device_id,
                action=f"task_{result_status}",
                target_type="task",
                target_id=task_id,
                detail={"result": envelope.payload.get("result") or {}},
            )
            return

        if envelope.type is MessageType.FILE_CHUNK:
            await handle_chunk(envelope, session_id)
            return

        if envelope.type is MessageType.FILE_RECORD:
            metadata = FileMetadata.model_validate(
                {**envelope.payload, "client_id": envelope.device_id}
            )
            state.db.create_file_record(
                file_id=metadata.file_id,
                client_id=metadata.client_id,
                file_name=metadata.file_name,
                original_path=metadata.original_path,
                protected_path=metadata.protected_path,
                size_bytes=metadata.size_bytes,
                sha256_plaintext=metadata.sha256_plaintext,
                algorithm=metadata.algorithm,
                created_at=metadata.created_at,
                status=metadata.status,
            )
            state.db.append_audit(
                actor_type="client",
                actor_id=envelope.device_id,
                action="file_protected",
                target_type="file",
                target_id=metadata.file_id,
                detail=metadata.model_dump(mode="json"),
            )
            return

        if envelope.type is MessageType.UNLOCK_REQUEST:
            request_data = UnlockRequestPayload.model_validate(envelope.payload)
            record = state.db.get_file_record(request_data.file_id)
            if not record or record["client_id"] != envelope.device_id:
                raise ValueError("file_id tidak dikenal untuk client ini")
            state.db.create_unlock_request(
                request_id=envelope.request_id,
                client_id=envelope.device_id,
                file_id=request_data.file_id,
                file_name=record["file_name"],
                reason=request_data.reason,
            )
            state.db.append_audit(
                actor_type="client",
                actor_id=envelope.device_id,
                action="unlock_requested",
                target_type="unlock_request",
                target_id=envelope.request_id,
                detail={"file_id": request_data.file_id, "reason": request_data.reason},
            )
            return

        if envelope.type is MessageType.RECOVERY_RESULT:
            recovery = RecoveryResultPayload.model_validate(envelope.payload)
            status_value = (
                "completed_offline"
                if recovery.offline
                else ("completed" if recovery.success else "failed")
            )
            if not recovery.offline:
                state.db.update_unlock_request(recovery.request_id, status=status_value)
            state.db.append_audit(
                actor_type="client",
                actor_id=envelope.device_id,
                action="file_recovery",
                target_type="unlock_request",
                target_id=recovery.request_id,
                detail=recovery.model_dump(mode="json") | {"status": status_value},
            )
            return

        if envelope.type is MessageType.ERROR:
            state.db.append_audit(
                actor_type="client",
                actor_id=envelope.device_id,
                action="client_error",
                target_type="session",
                target_id=session_id,
                detail={"error": envelope.payload.get("message", "unknown")},
            )

    @app.get("/health")
    async def health() -> dict[str, Any]:
        return {
            "status": "ok",
            "service": "remote-admin-lab",
            "version": "1.0.0",
            "clients_online": sum(
                1 for row in state.db.list_clients() if row["status"] == "online"
            ),
        }

    @app.post("/admin/login")
    async def login(payload: LoginRequest, request: Request) -> dict[str, Any]:
        try:
            state.limiter.check(f"login:{_client_ip(request)}")
        except RateLimitExceeded as exc:
            raise HTTPException(
                status_code=http_status.HTTP_429_TOO_MANY_REQUESTS,
                detail="terlalu banyak percobaan login",
            ) from exc

        valid_user = hmac.compare_digest(payload.username, state.config.admin_username)
        valid_password = verify_password(
            payload.password, state.config.admin_salt, state.config.admin_password_hash
        )
        if not valid_user or not valid_password:
            state.db.append_audit(
                actor_type="unknown",
                actor_id=payload.username,
                action="admin_login_failed",
                target_type="admin",
                target_id=state.config.admin_username,
                detail={"remote_ip": _client_ip(request)},
            )
            raise HTTPException(
                status_code=http_status.HTTP_401_UNAUTHORIZED,
                detail="kredensial admin tidak valid",
            )

        token = state.sessions.create(payload.username)
        state.db.append_audit(
            actor_type="admin",
            actor_id=payload.username,
            action="admin_login",
            target_type="admin",
            target_id=payload.username,
            detail={"remote_ip": _client_ip(request)},
        )
        return {
            "access_token": token,
            "token_type": "bearer",
            "expires_in": state.config.session_ttl_seconds,
        }

    @app.post("/admin/change-password")
    async def change_password(
        payload: PasswordChangeRequest, admin: str = Depends(require_admin)
    ) -> dict[str, str]:
        if not verify_password(
            payload.current_password, state.config.admin_salt, state.config.admin_password_hash
        ):
            raise HTTPException(status_code=400, detail="kata sandi saat ini salah")
        salt, digest = hash_password(payload.new_password)
        state.config.admin_salt = salt
        state.config.admin_password_hash = digest
        state.config.save()
        state.db.append_audit(
            actor_type="admin",
            actor_id=admin,
            action="admin_password_changed",
            target_type="admin",
            target_id=admin,
            detail={},
        )
        return {"status": "updated"}

    @app.get("/admin/summary")
    async def summary(admin: str = Depends(require_admin)) -> dict[str, Any]:
        clients = state.db.list_clients()
        tasks = state.db.list_tasks(limit=1000)
        unlocks = state.db.list_unlock_requests(limit=1000)
        audit_count = state.db.query_one("SELECT COUNT(*) AS n FROM audit_logs")
        return {
            "clients_total": len(clients),
            "clients_online": sum(1 for row in clients if row["status"] == "online"),
            "tasks_pending": sum(1 for row in tasks if row["status"] == "pending"),
            "unlocks_pending": sum(1 for row in unlocks if row["status"] == "pending"),
            "audit_events": audit_count["n"] if audit_count else 0,
            "audit_chain_valid": state.db.verify_audit_chain(),
        }

    @app.get("/admin/clients", response_model=list[ClientInfo])
    async def clients(admin: str = Depends(require_admin)) -> list[dict[str, Any]]:
        return state.db.list_clients()

    @app.get("/admin/tasks")
    async def tasks(admin: str = Depends(require_admin)) -> list[dict[str, Any]]:
        rows = state.db.list_tasks(limit=200)
        for row in rows:
            row["result"] = _parse_json(row.pop("result_json", None))
        return rows

    @app.post("/admin/tasks", status_code=http_status.HTTP_201_CREATED)
    async def create_task(
        payload: TaskCreateRequest, admin: str = Depends(require_admin)
    ) -> dict[str, str]:
        if not state.db.get_client(payload.client_id):
            raise HTTPException(status_code=404, detail="client tidak ditemukan")
        if payload.file_id:
            record = state.db.get_file_record(payload.file_id)
            if not record or record["client_id"] != payload.client_id:
                raise HTTPException(status_code=400, detail="file_id tidak valid")
        task_id = state.db.create_task(
            client_id=payload.client_id,
            task_type=payload.task_type.value,
            reason=payload.reason,
            file_id=payload.file_id,
            requested_by=admin,
        )
        state.db.append_audit(
            actor_type="admin",
            actor_id=admin,
            action="task_created",
            target_type="task",
            target_id=task_id,
            detail=payload.model_dump(mode="json"),
        )
        return {"task_id": task_id, "status": "pending"}

    @app.post("/admin/tasks/{task_id}/decision")
    async def decide_task(
        task_id: str,
        payload: DecisionRequest,
        admin: str = Depends(require_admin),
    ) -> dict[str, Any]:
        try:
            outcome = await state.approvals.decide_task(
                task_id=task_id,
                decision=payload.decision,
                admin_name=admin,
                notes=payload.notes,
            )
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return {
            "approval_id": outcome.approval_id,
            "status": outcome.status,
            "delivered": outcome.delivered,
        }

    @app.get("/admin/file-records")
    async def file_records(admin: str = Depends(require_admin)) -> list[dict[str, Any]]:
        return state.db.list_file_records(limit=200)

    @app.get("/admin/file-records/{file_id}")
    async def file_record(
        file_id: str, admin: str = Depends(require_admin)
    ) -> dict[str, Any]:
        record = state.db.get_file_record(file_id)
        if not record:
            raise HTTPException(status_code=404, detail="file tidak ditemukan")
        return record

    @app.get("/admin/unlock-requests")
    async def unlock_requests(admin: str = Depends(require_admin)) -> list[dict[str, Any]]:
        return state.db.list_unlock_requests(limit=200)

    @app.post("/admin/unlock-requests/{request_id}/decision")
    async def decide_unlock(
        request_id: str,
        payload: DecisionRequest,
        admin: str = Depends(require_admin),
    ) -> dict[str, Any]:
        try:
            outcome = await state.approvals.decide_unlock(
                request_id=request_id,
                decision=payload.decision,
                admin_name=admin,
                notes=payload.notes,
            )
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return {
            "approval_id": outcome.approval_id,
            "status": outcome.status,
            "delivered": outcome.delivered,
        }

    @app.get("/admin/audit-logs")
    async def audit_logs(
        limit: int = 200, admin: str = Depends(require_admin)
    ) -> dict[str, Any]:
        return {
            "chain_valid": state.db.verify_audit_chain(),
            "events": state.db.list_audit(max(1, min(limit, 1000))),
        }

    @app.websocket("/ws/client")
    async def client_socket(
        websocket: WebSocket,
        authorization: Annotated[str | None, Header()] = None,
    ) -> None:
        remote_ip = websocket.client.host if websocket.client else "unknown"
        try:
            state.limiter.check(f"ws:{remote_ip}")
        except RateLimitExceeded:
            await websocket.close(code=1008, reason="rate limit")
            return

        await websocket.accept()
        session_id: str | None = None
        device_id: str | None = None
        heartbeat_task: asyncio.Task[None] | None = None

        try:
            raw = await asyncio.wait_for(websocket.receive_text(), timeout=30)
            hello = decode_envelope(raw)
            if hello.type is not MessageType.HELLO:
                await websocket.close(code=1008, reason="hello diperlukan")
                return

            token = _bearer_from_header(authorization)
            if not token:
                await websocket.close(code=1008, reason="token perangkat diperlukan")
                return

            identity = DeviceIdentity.model_validate(hello.payload.get("identity"))
            enrollment_code = str(hello.payload.get("enrollment_code", ""))
            device_id = identity.device_id
            token_hash = hash_secret(token)
            existing = state.db.get_client(device_id)

            if existing:
                if not hmac.compare_digest(existing["token_hash"], token_hash):
                    await websocket.close(code=1008, reason="token perangkat tidak cocok")
                    return
                if not verify_secret(enrollment_code, existing["enrollment_code_hash"]):
                    await websocket.close(code=1008, reason="kode enrolling tidak cocok")
                    return
            else:
                if not verify_secret(enrollment_code, state.config.enrollment_code_hash):
                    await websocket.close(code=1008, reason="kode enrolling tidak valid")
                    return
                state.db.upsert_client(
                    client_id=device_id,
                    hostname=identity.hostname,
                    os_name=identity.os_name,
                    os_version=identity.os_version,
                    python_version=identity.python_version,
                    private_ips=identity.private_ips,
                    agent_version=identity.agent_version,
                    token_hash=token_hash,
                    enrollment_code_hash=state.config.enrollment_code_hash,
                )

            await state.manager.connect(device_id, websocket)
            session_id = new_id("sess")
            state.db.open_session(session_id, device_id, remote_ip)
            state.db.set_client_status(device_id, "online")
            state.db.append_audit(
                actor_type="client",
                actor_id=device_id,
                action="client_connected",
                target_type="client",
                target_id=device_id,
                detail={
                    "hostname": identity.hostname,
                    "os": f"{identity.os_name} {identity.os_version}",
                    "python": identity.python_version,
                    "remote_ip": remote_ip,
                    "session_id": session_id,
                },
            )
            await state.manager.send(
                device_id,
                make_envelope(
                    MessageType.HELLO_ACK,
                    device_id,
                    {
                        "session_id": session_id,
                        "server_name": state.config.server_name,
                        "server_time": utcnow().isoformat(),
                    },
                ),
            )
            heartbeat_task = asyncio.create_task(heartbeat(device_id, session_id))

            while True:
                raw = await asyncio.wait_for(websocket.receive_text(), timeout=90)
                envelope = decode_envelope(raw)
                await handle_client_message(envelope, session_id, remote_ip)
        except WebSocketDisconnect:
            pass
        except asyncio.TimeoutError:
            pass
        except (ValidationError, ValueError, json.JSONDecodeError) as exc:
            try:
                await websocket.close(code=1008, reason="pesan tidak valid")
            except Exception:
                pass
            if device_id:
                state.db.append_audit(
                    actor_type="client",
                    actor_id=device_id,
                    action="client_message_invalid",
                    target_type="session",
                    target_id=session_id,
                    detail={"error": str(exc)},
                )
        except Exception as exc:
            if device_id:
                state.db.append_audit(
                    actor_type="server",
                    actor_id="server",
                    action="client_session_error",
                    target_type="session",
                    target_id=session_id,
                    detail={"error": str(exc)},
                )
        finally:
            if heartbeat_task is not None:
                heartbeat_task.cancel()
                await asyncio.gather(heartbeat_task, return_exceptions=True)
            if device_id:
                await state.manager.disconnect(device_id, websocket)
                state.db.set_client_status(device_id, "offline")
                if session_id:
                    state.db.close_session(session_id)
                state.db.append_audit(
                    actor_type="client",
                    actor_id=device_id,
                    action="client_disconnected",
                    target_type="client",
                    target_id=device_id,
                    detail={"session_id": session_id, "remote_ip": remote_ip},
                )

    return app
