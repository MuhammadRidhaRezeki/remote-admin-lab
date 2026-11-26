"""DPAPI-protected local device identity and enrollment secret."""

from __future__ import annotations

import json
import secrets
from dataclasses import dataclass
from pathlib import Path

from shared.crypto_utils import dpapi_protect, dpapi_unprotect

from .config import IDENTITY_PATH

IDENTITY_ENTROPY = b"remote-admin-lab-client-identity-v1"


@dataclass
class ClientIdentity:
    device_id: str
    token: str
    enrollment_code: str = ""

    def to_dict(self) -> dict[str, str]:
        return {
            "device_id": self.device_id,
            "token": self.token,
            "enrollment_code": self.enrollment_code,
        }

    @classmethod
    def from_dict(cls, values: dict[str, str]) -> "ClientIdentity":
        return cls(
            device_id=values["device_id"],
            token=values["token"],
            enrollment_code=values.get("enrollment_code", ""),
        )


def load_identity(path: Path | str | None = None) -> ClientIdentity | None:
    target = Path(path) if path else IDENTITY_PATH
    if not target.exists():
        return None
    raw = dpapi_unprotect(target.read_bytes(), IDENTITY_ENTROPY)
    return ClientIdentity.from_dict(json.loads(raw.decode("utf-8")))


def save_identity(identity: ClientIdentity, path: Path | str | None = None) -> None:
    target = Path(path) if path else IDENTITY_PATH
    target.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(identity.to_dict(), ensure_ascii=False).encode("utf-8")
    target.write_bytes(dpapi_protect(payload, IDENTITY_ENTROPY))


def load_or_create_identity(path: Path | str | None = None) -> ClientIdentity:
    identity = load_identity(path)
    if identity is not None:
        return identity
    identity = ClientIdentity(
        device_id=f"client-{secrets.token_hex(8)}",
        token=secrets.token_urlsafe(32),
    )
    save_identity(identity, path)
    return identity
