"""Client vault and offline recovery tests."""

from __future__ import annotations

from pathlib import Path

from client.file_protection import Vault
from client.recovery import RecoveryService


def test_vault_protect_and_offline_recovery(tmp_path: Path) -> None:
    source = tmp_path / "laporan.txt"
    original = b"laporan keuangan " * 200
    source.write_bytes(original)

    vault = Vault(tmp_path / "vault", "dev-1")
    records = vault.protect([source])
    assert len(records) == 1
    assert source.read_bytes() == original

    file_id = records[0]["file_id"]
    record = vault.get_record(file_id)
    assert record is not None
    assert record.wrapped_key_b64
    assert record.nonce_b64

    destination = tmp_path / "restore" / "laporan.txt"
    result = RecoveryService(vault).recover(file_id, destination, offline=True)
    assert result["verified"] is True
    assert destination.read_bytes() == original
    assert vault.get_record(file_id).status == "recovered"

    actions = [event["action"] for event in vault.list_events(100)]
    assert "file_protected" in actions
    assert "file_recovered_offline" in actions
