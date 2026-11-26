"""Password hashing, device secrets, and short-lived admin sessions."""

from __future__ import annotations

import hashlib
import hmac
import secrets
import threading
import time
from dataclasses import dataclass

PBKDF2_ITERATIONS = 210_000


def hash_password(password: str, salt: bytes | None = None) -> tuple[str, str]:
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS
    )
    return salt.hex(), digest.hex()


def verify_password(password: str, salt_hex: str, digest_hex: str) -> bool:
    try:
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(digest_hex)
    except ValueError:
        return False
    actual = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS
    )
    return hmac.compare_digest(actual, expected)


def hash_secret(secret: str) -> str:
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()


def verify_secret(secret: str, expected_hash: str) -> bool:
    return hmac.compare_digest(hash_secret(secret), expected_hash)


@dataclass(frozen=True)
class _Session:
    username: str
    expires_at: float


class AdminSessionStore:
    def __init__(self, ttl_seconds: int = 3600) -> None:
        self._ttl = ttl_seconds
        self._lock = threading.Lock()
        self._sessions: dict[str, _Session] = {}

    def create(self, username: str) -> str:
        token = secrets.token_urlsafe(32)
        with self._lock:
            self._sessions[token] = _Session(username, time.time() + self._ttl)
        return token

    def validate(self, token: str) -> str | None:
        now = time.time()
        with self._lock:
            session = self._sessions.get(token)
            if not session:
                return None
            if session.expires_at <= now:
                self._sessions.pop(token, None)
                return None
            return session.username

    def revoke(self, token: str) -> None:
        with self._lock:
            self._sessions.pop(token, None)
