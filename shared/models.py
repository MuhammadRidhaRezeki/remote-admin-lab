"""Shared message schemas for the remote administration lab."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def new_id(prefix: str = "") -> str:
    value = uuid.uuid4().hex
    return f"{prefix}_{value}" if prefix else value


class MessageType(str, Enum):
    HELLO = "hello"
    HELLO_ACK = "hello_ack"
    PING = "ping"
    PONG = "pong"
    SYSTEM_SNAPSHOT = "system_snapshot"
    TASK_REQUEST = "task_request"
    TASK_RESULT = "task_result"
    FILE_CHUNK = "file_chunk"
    FILE_RECORD = "file_record"
    UNLOCK_REQUEST = "unlock_request"
    UNLOCK_DECISION = "unlock_decision"
    RECOVERY_RESULT = "recovery_result"
    ERROR = "error"


class TaskType(str, Enum):
    SYSTEM_INFO = "system_info"
    CPU_RAM = "cpu_ram"
    DISK = "disk"
    NETWORK = "network"
    AGENT_STATUS = "agent_status"
    TRANSFER_FILE = "transfer_file"


TASK_ALLOWLIST: frozenset[str] = frozenset(item.value for item in TaskType)


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Envelope(StrictModel):
    type: MessageType
    request_id: str = Field(default_factory=lambda: new_id("msg"))
    device_id: str = Field(min_length=1)
    timestamp: datetime = Field(default_factory=utcnow)
    payload: dict[str, Any] = Field(default_factory=dict)


class DeviceIdentity(StrictModel):
    device_id: str = Field(min_length=1)
    hostname: str = Field(min_length=1)
    os_name: str = Field(min_length=1)
    os_version: str = Field(min_length=1)
    python_version: str = Field(min_length=1)
    private_ips: list[str] = Field(default_factory=list)
    agent_version: str = Field(min_length=1)


class ClientInfo(StrictModel):
    client_id: str
    hostname: str
    os_name: str
    os_version: str
    python_version: str
    private_ips: list[str]
    agent_version: str
    status: str
    first_seen: datetime
    last_seen: datetime


class SystemSnapshot(StrictModel):
    hostname: str
    os_name: str
    os_version: str
    python_version: str
    private_ips: list[str]
    cpu_percent: float
    cpu_cores_logical: int
    memory_total_gb: float
    memory_used_gb: float
    disk_total_gb: float
    disk_free_gb: float
    network_interfaces: list[dict[str, Any]]
    agent_status: str
    uptime_seconds: int


class TaskCreateRequest(StrictModel):
    client_id: str = Field(min_length=1)
    task_type: TaskType
    reason: str | None = None
    file_id: str | None = None

    @model_validator(mode="after")
    def transfer_requires_file(self) -> "TaskCreateRequest":
        if self.task_type is TaskType.TRANSFER_FILE and not self.file_id:
            raise ValueError("file_id wajib diisi untuk task transfer_file")
        return self


class TaskRecord(StrictModel):
    task_id: str
    client_id: str
    task_type: TaskType
    status: str
    reason: str | None
    requested_by: str
    created_at: datetime
    decided_at: datetime | None
    completed_at: datetime | None
    result_json: dict[str, Any] | None


class FileMetadata(StrictModel):
    file_id: str
    client_id: str
    file_name: str
    original_path: str
    protected_path: str
    size_bytes: int
    sha256_plaintext: str
    algorithm: str
    created_at: datetime
    status: str


class UnlockRequestPayload(StrictModel):
    file_id: str = Field(min_length=1)
    reason: str = Field(min_length=3)


class UnlockRequestRecord(StrictModel):
    request_id: str
    client_id: str
    file_id: str
    file_name: str | None
    reason: str
    status: str
    created_at: datetime
    decided_at: datetime | None


class DecisionRequest(StrictModel):
    decision: Literal["approved", "rejected"]
    notes: str | None = None


class LoginRequest(StrictModel):
    username: str = Field(min_length=1)
    password: str = Field(min_length=1)


class PasswordChangeRequest(StrictModel):
    current_password: str = Field(min_length=1)
    new_password: str = Field(min_length=12)


class RecoveryResultPayload(StrictModel):
    request_id: str
    file_id: str
    success: bool
    destination: str
    sha256_plaintext: str
    verified: bool
    error: str | None = None
    offline: bool = False
