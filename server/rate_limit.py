"""Small in-memory sliding-window rate limiter."""

from __future__ import annotations

import threading
import time
from collections import defaultdict, deque


class RateLimitExceeded(RuntimeError):
    pass


class RateLimiter:
    def __init__(self, max_requests: int = 120, window_seconds: float = 60.0) -> None:
        self._max = max_requests
        self._window = window_seconds
        self._lock = threading.Lock()
        self._hits: dict[str, deque[float]] = defaultdict(deque)

    def check(self, key: str) -> None:
        now = time.monotonic()
        with self._lock:
            bucket = self._hits[key]
            while bucket and bucket[0] <= now - self._window:
                bucket.popleft()
            if len(bucket) >= self._max:
                raise RateLimitExceeded(key)
            bucket.append(now)
