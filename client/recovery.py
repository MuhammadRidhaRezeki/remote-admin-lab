"""Local-only recovery using the DPAPI-protected key held on this device."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Callable

from shared.crypto_utils import b64d, decrypt_file

from .file_protection import VAULT_ENTROPY, Vault
from shared.crypto_utils import dpapi_unprotect


class RecoveryService:
    def __init__(self, vault: Vault) -> None:
        self._vault = vault

    def recover(
        self,
        file_id: str,
        destination: Path | str,
        *,
        request_id: str = "",
        offline: bool = False,
    ) -> dict[str, Any]:
        record = self._vault.get_record(file_id)
        if record is None:
            raise KeyError("file tidak ditemukan di vault lokal")
        destination = Path(destination)
        if destination.resolve() == Path(record.protected_path).resolve():
            raise ValueError("tujuan tidak boleh sama dengan salinan terenkripsi")

        key = dpapi_unprotect(b64d(record.wrapped_key_b64), VAULT_ENTROPY)
        total = decrypt_file(
            Path(record.protected_path),
            destination,
            key,
            b64d(record.nonce_b64),
            b64d(record.tag_b64),
            record.sha256_plaintext,
        )
        self._vault.set_status(file_id, "recovered")
        action = "file_recovered_offline" if offline else "file_recovered"
        self._vault.append_event(
            action,
            {
                "request_id": request_id,
                "file_id": file_id,
                "destination": str(destination),
                "size_bytes": total,
                "verified": True,
            },
        )
        return {
            "request_id": request_id or f"offline-{file_id}",
            "file_id": file_id,
            "success": True,
            "destination": str(destination),
            "sha256_plaintext": record.sha256_plaintext,
            "verified": True,
            "error": None,
            "offline": offline,
        }

    def flush_offline_events(self, send: Callable[[dict[str, Any]], bool]) -> int:
        flushed = 0
        for event in self._vault.unsynced_events():
            if event["action"] != "file_recovered_offline":
                continue
            detail = event["detail"]
            payload = {
                "request_id": detail.get("request_id") or f"offline-{detail['file_id']}",
                "file_id": detail["file_id"],
                "success": bool(detail.get("verified")),
                "destination": detail.get("destination", ""),
                "sha256_plaintext": "",
                "verified": bool(detail.get("verified")),
                "error": None,
                "offline": True,
            }
            if send(payload):
                self._vault.mark_synced(event["event_id"])
                flushed += 1
        return flushed
