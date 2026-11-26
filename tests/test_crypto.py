"""Encryption, integrity, and DPAPI tests."""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from cryptography.exceptions import InvalidTag

from shared.crypto_utils import (
    IntegrityError,
    b64e,
    decrypt_file,
    dpapi_protect,
    dpapi_unprotect,
    encrypt_file,
    generate_key,
)


def test_encrypt_decrypt_roundtrip(tmp_path: Path) -> None:
    source = tmp_path / "data.bin"
    source.write_bytes(os.urandom(2_500_000))
    key = generate_key()
    result = encrypt_file(source, tmp_path / "data.enc", key)
    decrypt_file(
        tmp_path / "data.enc",
        tmp_path / "restored.bin",
        key,
        result.nonce,
        result.tag,
        result.sha256_plaintext,
    )
    assert (tmp_path / "restored.bin").read_bytes() == source.read_bytes()


def test_tampered_ciphertext_fails_integrity(tmp_path: Path) -> None:
    source = tmp_path / "note.txt"
    source.write_bytes(b"integrity matters")
    key = generate_key()
    result = encrypt_file(source, tmp_path / "note.enc", key)
    encrypted = bytearray((tmp_path / "note.enc").read_bytes())
    encrypted[0] ^= 0xFF
    (tmp_path / "note.enc").write_bytes(bytes(encrypted))

    with pytest.raises((InvalidTag, IntegrityError)):
        decrypt_file(
            tmp_path / "note.enc",
            tmp_path / "out.txt",
            key,
            result.nonce,
            result.tag,
            result.sha256_plaintext,
        )
    assert not (tmp_path / "out.txt.partial").exists()


def test_dpapi_roundtrip_and_entropy_binding() -> None:
    key = generate_key()
    protected = dpapi_protect(key, b"context-a")
    assert dpapi_unprotect(protected, b"context-a") == key
    with pytest.raises(OSError):
        dpapi_unprotect(protected, b"context-b")


def test_base64_helpers() -> None:
    assert b64e(b"vanta") == "dmFudGE="
