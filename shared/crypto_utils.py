"""File encryption, integrity checks, and Windows DPAPI key wrapping."""

from __future__ import annotations

import base64
import ctypes
import hashlib
import os
from ctypes import wintypes
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

CHUNK_SIZE = 1024 * 1024
KEY_SIZE = 32
NONCE_SIZE = 12
ALGORITHM = "AES-256-GCM"
DPAPI_DESCRIPTION = b"RemoteAdminLab v1"


class IntegrityError(RuntimeError):
    pass


@dataclass(frozen=True)
class EncryptionResult:
    nonce: bytes
    tag: bytes
    sha256_plaintext: str
    size_bytes: int


def b64e(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def b64d(value: str) -> bytes:
    return base64.b64decode(value.encode("ascii"), validate=True)


def generate_key() -> bytes:
    return os.urandom(KEY_SIZE)


def _validate_key(key: bytes) -> None:
    if len(key) != KEY_SIZE:
        raise ValueError("kunci AES harus 32 byte")


def encrypt_file(source: Path, destination: Path, key: bytes) -> EncryptionResult:
    _validate_key(key)
    source = Path(source)
    destination = Path(destination)
    if not source.is_file():
        raise FileNotFoundError(source)
    destination.parent.mkdir(parents=True, exist_ok=True)

    nonce = os.urandom(NONCE_SIZE)
    encryptor = Cipher(algorithms.AES(key), modes.GCM(nonce)).encryptor()
    digest = hashlib.sha256()
    total = 0

    with source.open("rb") as src, destination.open("wb") as dst:
        while chunk := src.read(CHUNK_SIZE):
            digest.update(chunk)
            dst.write(encryptor.update(chunk))
            total += len(chunk)
        dst.write(encryptor.finalize())

    return EncryptionResult(nonce, encryptor.tag, digest.hexdigest(), total)


def decrypt_file(
    source: Path,
    destination: Path,
    key: bytes,
    nonce: bytes,
    tag: bytes,
    expected_sha256: str,
) -> int:
    _validate_key(key)
    if len(nonce) != NONCE_SIZE:
        raise ValueError("nonce harus 12 byte")
    if len(tag) < 12:
        raise ValueError("tag GCM terlalu pendek")

    source = Path(source)
    destination = Path(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(destination.name + ".partial")

    decryptor = Cipher(algorithms.AES(key), modes.GCM(nonce, tag)).decryptor()
    digest = hashlib.sha256()
    total = 0

    try:
        with source.open("rb") as src, temporary.open("wb") as dst:
            while chunk := src.read(CHUNK_SIZE):
                plaintext = decryptor.update(chunk)
                digest.update(plaintext)
                dst.write(plaintext)
                total += len(chunk)
            dst.write(decryptor.finalize())

        if digest.hexdigest().lower() != expected_sha256.lower():
            raise IntegrityError("hash plaintext tidak cocok")
        os.replace(temporary, destination)
        return total
    except Exception:
        temporary.unlink(missing_ok=True)
        raise


class _DataBlob(ctypes.Structure):
    _fields_ = [
        ("cbData", wintypes.DWORD),
        ("pbData", ctypes.POINTER(ctypes.c_ubyte)),
    ]


def _make_blob(data: bytes) -> tuple[_DataBlob, ctypes.Array]:
    if data:
        buffer = (ctypes.c_ubyte * len(data)).from_buffer_copy(data)
    else:
        buffer = (ctypes.c_ubyte * 1)()
    blob = _DataBlob(len(data), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_ubyte)))
    return blob, buffer


def _crypt32() -> ctypes.WinDLL:
    if os.name != "nt":
        raise RuntimeError("DPAPI hanya tersedia di Windows")
    dll = ctypes.WinDLL("crypt32", use_last_error=True)
    dll.CryptProtectData.argtypes = [
        ctypes.POINTER(_DataBlob),
        wintypes.LPCSTR,
        ctypes.POINTER(_DataBlob),
        wintypes.LPVOID,
        wintypes.LPVOID,
        wintypes.DWORD,
        ctypes.POINTER(_DataBlob),
    ]
    dll.CryptProtectData.restype = wintypes.BOOL
    dll.CryptUnprotectData.argtypes = [
        ctypes.POINTER(_DataBlob),
        ctypes.POINTER(wintypes.LPSTR),
        ctypes.POINTER(_DataBlob),
        wintypes.LPVOID,
        wintypes.LPVOID,
        wintypes.DWORD,
        ctypes.POINTER(_DataBlob),
    ]
    dll.CryptUnprotectData.restype = wintypes.BOOL
    return dll


def dpapi_protect(data: bytes, entropy: bytes | None = None) -> bytes:
    dll = _crypt32()
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    input_blob, input_buffer = _make_blob(data)
    entropy_blob, entropy_buffer = _make_blob(entropy or b"")
    output_blob = _DataBlob()

    ok = dll.CryptProtectData(
        ctypes.byref(input_blob),
        DPAPI_DESCRIPTION,
        ctypes.byref(entropy_blob) if entropy else None,
        None,
        None,
        0,
        ctypes.byref(output_blob),
    )
    if not ok:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        return ctypes.string_at(output_blob.pbData, output_blob.cbData)
    finally:
        kernel32.LocalFree(output_blob.pbData)
        del input_buffer, entropy_buffer


def dpapi_unprotect(protected: bytes, entropy: bytes | None = None) -> bytes:
    dll = _crypt32()
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    input_blob, input_buffer = _make_blob(protected)
    entropy_blob, entropy_buffer = _make_blob(entropy or b"")
    output_blob = _DataBlob()
    description = wintypes.LPSTR()

    ok = dll.CryptUnprotectData(
        ctypes.byref(input_blob),
        ctypes.byref(description),
        ctypes.byref(entropy_blob) if entropy else None,
        None,
        None,
        0,
        ctypes.byref(output_blob),
    )
    if not ok:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        return ctypes.string_at(output_blob.pbData, output_blob.cbData)
    finally:
        if description:
            kernel32.LocalFree(description)
        kernel32.LocalFree(output_blob.pbData)
        del input_buffer, entropy_buffer
