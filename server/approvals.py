"""Approval decisions and dispatch of approved work to clients."""

from __future__ import annotations

from dataclasses import dataclass

from shared.models import MessageType, utcnow
from shared.protocol import make_envelope

from .database import Database
from .websocket_manager import ConnectionManager


@dataclass(frozen=True)
class DecisionOutcome:
    approval_id: str
    status: str
    delivered: bool


class ApprovalService:
    def __init__(self, db: Database, manager: ConnectionManager) -> None:
        self._db = db
        self._manager = manager

    async def decide_task(
        self,
        *,
        task_id: str,
        decision: str,
        admin_name: str,
        notes: str | None = None,
    ) -> DecisionOutcome:
        task = self._db.get_task(task_id)
        if not task:
            raise KeyError("task tidak ditemukan")
        if task["status"] not in {"pending"}:
            raise ValueError("task sudah diputuskan")

        approval_id = self._db.create_approval(
            subject_type="task",
            subject_id=task_id,
            decision=decision,
            admin_id=admin_name,
            admin_name=admin_name,
            notes=notes,
        )
        now = utcnow()
        self._db.update_task(task_id, status=decision, decided_at=now)
        self._db.append_audit(
            actor_type="admin",
            actor_id=admin_name,
            action=f"task_{decision}",
            target_type="task",
            target_id=task_id,
            detail={"approval_id": approval_id, "notes": notes},
        )

        delivered = False
        if decision == "approved":
            payload = {
                "task_id": task_id,
                "task_type": task["task_type"],
                "reason": task["reason"],
                "file_id": task["file_id"],
                "approval": {
                    "approval_id": approval_id,
                    "decided_by": admin_name,
                    "decided_at": now.isoformat(),
                    "notes": notes,
                },
            }
            delivered = await self._manager.send(
                task["client_id"],
                make_envelope(MessageType.TASK_REQUEST, task["client_id"], payload),
            )
            if delivered:
                self._db.update_task(task_id, status="dispatched")
                self._db.append_audit(
                    actor_type="server",
                    actor_id="server",
                    action="task_dispatched",
                    target_type="task",
                    target_id=task_id,
                    detail={"client_id": task["client_id"]},
                )
        else:
            payload = {"task_id": task_id, "status": "rejected"}
            delivered = await self._manager.send(
                task["client_id"],
                make_envelope(MessageType.TASK_RESULT, task["client_id"], payload),
            )

        return DecisionOutcome(approval_id, decision, delivered)

    async def decide_unlock(
        self,
        *,
        request_id: str,
        decision: str,
        admin_name: str,
        notes: str | None = None,
    ) -> DecisionOutcome:
        request = self._db.get_unlock_request(request_id)
        if not request:
            raise KeyError("permintaan pembukaan tidak ditemukan")
        if request["status"] != "pending":
            raise ValueError("permintaan sudah diputuskan")

        approval_id = self._db.create_approval(
            subject_type="unlock",
            subject_id=request_id,
            decision=decision,
            admin_id=admin_name,
            admin_name=admin_name,
            notes=notes,
        )
        now = utcnow()
        status = "approved" if decision == "approved" else "rejected"
        self._db.update_unlock_request(request_id, status=status)
        self._db.append_audit(
            actor_type="admin",
            actor_id=admin_name,
            action=f"unlock_{decision}",
            target_type="unlock_request",
            target_id=request_id,
            detail={"approval_id": approval_id, "notes": notes},
        )

        payload = {
            "request_id": request_id,
            "file_id": request["file_id"],
            "file_name": request["file_name"],
            "decision": decision,
            "approval_id": approval_id,
            "decided_by": admin_name,
            "decided_at": now.isoformat(),
            "notes": notes,
        }
        delivered = await self._manager.send(
            request["client_id"],
            make_envelope(MessageType.UNLOCK_DECISION, request["client_id"], payload),
        )
        return DecisionOutcome(approval_id, status, delivered)
