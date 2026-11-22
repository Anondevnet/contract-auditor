"""Per-IP rate limit and global concurrency for the public demo."""

from __future__ import annotations

import sqlite3
import threading
import time
from pathlib import Path
from typing import Optional

from auditor.mode import data_dir, public_limits

_rate_lock = threading.Lock()
_semaphore: Optional[threading.BoundedSemaphore] = None
_sem_bind: Optional[int] = None


class RateLimited(Exception):
    def __init__(self, retry_after_s: int) -> None:
        super().__init__(f"rate limit exceeded; retry after {retry_after_s}s")
        self.retry_after_s = retry_after_s


class Busy(Exception):
    """Global concurrency limit reached."""


def _db() -> Path:
    path = data_dir() / "rate_limit.sqlite"
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(str(_db()), check_same_thread=False)
    conn.execute(
        "CREATE TABLE IF NOT EXISTS scan_events ("
        " ip TEXT NOT NULL,"
        " ts REAL NOT NULL"
        ")"
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_scan_events_ip_ts ON scan_events(ip, ts)")
    conn.commit()
    return conn


def client_ip(request, trust_forwarded: Optional[bool] = None) -> str:
    if trust_forwarded is None:
        trust_forwarded = bool(public_limits()["trust_x_forwarded_for"])
    if trust_forwarded:
        forwarded = request.headers.get("x-forwarded-for") or ""
        first = forwarded.split(",")[0].strip()
        if first:
            return first
    if request.client and request.client.host:
        return request.client.host
    return "unknown"


def check_rate_limit(ip: str, limit: Optional[int] = None, window_s: int = 3600) -> None:
    cap = int(limit if limit is not None else public_limits()["rate_limit_scans_per_hour"])
    now = time.time()
    cutoff = now - window_s
    with _rate_lock:
        conn = _connect()
        try:
            conn.execute("DELETE FROM scan_events WHERE ts < ?", (cutoff,))
            n = conn.execute(
                "SELECT COUNT(*) FROM scan_events WHERE ip=? AND ts>=?",
                (ip, cutoff),
            ).fetchone()[0]
            if n >= cap:
                oldest = conn.execute(
                    "SELECT MIN(ts) FROM scan_events WHERE ip=? AND ts>=?",
                    (ip, cutoff),
                ).fetchone()[0]
                retry = int(max(1, (oldest or cutoff) + window_s - now))
                conn.commit()
                raise RateLimited(retry)
            conn.execute("INSERT INTO scan_events(ip, ts) VALUES(?,?)", (ip, now))
            conn.commit()
        finally:
            conn.close()


def concurrency_semaphore() -> threading.BoundedSemaphore:
    global _semaphore, _sem_bind
    n = int(public_limits()["max_concurrent_scans"])
    n = max(1, n)
    if _semaphore is None or _sem_bind != n:
        _semaphore = threading.BoundedSemaphore(n)
        _sem_bind = n
    return _semaphore


class scan_slot:
    """Context manager that acquires the global scan semaphore or raises Busy."""

    def __init__(self, timeout_s: float = 0.0) -> None:
        self.timeout_s = timeout_s
        self._sem = concurrency_semaphore()
        self._held = False

    def __enter__(self) -> "scan_slot":
        if self.timeout_s and self.timeout_s > 0:
            acquired = self._sem.acquire(timeout=self.timeout_s)
        else:
            acquired = self._sem.acquire(blocking=False)
        if not acquired:
            raise Busy("too many scans in progress")
        self._held = True
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        if self._held:
            self._sem.release()
            self._held = False
