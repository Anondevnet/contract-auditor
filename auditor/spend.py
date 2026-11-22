"""Daily token / dollar spend cap. Tracked in a small SQLite file.

Public-demo default budget is $0: paid provider calls are refused until an
operator explicitly sets AUDITOR_DAILY_SPEND_USD. No network I/O lives here.
"""

from __future__ import annotations

import sqlite3
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from auditor.mode import data_dir, public_limits

# Conservative list prices used only when the operator has not supplied rates.
# Units: USD per 1M tokens.
DEFAULT_INPUT_PER_M = 2.0
DEFAULT_OUTPUT_PER_M = 10.0

_lock = threading.Lock()


class SpendCapExceeded(RuntimeError):
    """Raised before a provider call that would exceed the daily cap."""


@dataclass
class SpendStatus:
    day: str
    input_tokens: int
    output_tokens: int
    usd: float
    cap_usd: float
    remaining_usd: float

    def to_dict(self) -> dict:
        return {
            "day": self.day,
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "usd": round(self.usd, 6),
            "cap_usd": self.cap_usd,
            "remaining_usd": round(self.remaining_usd, 6),
        }


def _today() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def _db_path() -> Path:
    path = data_dir() / "spend.sqlite"
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


def _connect(path: Optional[Path] = None) -> sqlite3.Connection:
    conn = sqlite3.connect(str(path or _db_path()), check_same_thread=False)
    conn.execute(
        "CREATE TABLE IF NOT EXISTS daily_spend ("
        " day TEXT PRIMARY KEY,"
        " input_tokens INTEGER NOT NULL DEFAULT 0,"
        " output_tokens INTEGER NOT NULL DEFAULT 0,"
        " usd REAL NOT NULL DEFAULT 0.0"
        ")"
    )
    conn.commit()
    return conn


def cost_usd(input_tokens: int, output_tokens: int,
             input_per_m: float = DEFAULT_INPUT_PER_M,
             output_per_m: float = DEFAULT_OUTPUT_PER_M) -> float:
    return (input_tokens / 1_000_000.0) * input_per_m + (output_tokens / 1_000_000.0) * output_per_m


def status(cap_usd: Optional[float] = None, path: Optional[Path] = None) -> SpendStatus:
    cap = public_limits()["daily_spend_usd"] if cap_usd is None else float(cap_usd)
    day = _today()
    with _lock:
        conn = _connect(path)
        try:
            row = conn.execute(
                "SELECT input_tokens, output_tokens, usd FROM daily_spend WHERE day=?",
                (day,),
            ).fetchone()
        finally:
            conn.close()
    inp = int(row[0]) if row else 0
    out = int(row[1]) if row else 0
    usd = float(row[2]) if row else 0.0
    return SpendStatus(day=day, input_tokens=inp, output_tokens=out, usd=usd,
                       cap_usd=cap, remaining_usd=max(0.0, cap - usd))


def assert_can_spend(estimated_usd: float, cap_usd: Optional[float] = None,
                     path: Optional[Path] = None) -> SpendStatus:
    """Refuse before a call that would put today's total over the cap."""
    st = status(cap_usd=cap_usd, path=path)
    if estimated_usd < 0:
        estimated_usd = 0.0
    if st.usd + estimated_usd > st.cap_usd + 1e-12:
        raise SpendCapExceeded(
            f"daily spend cap ${st.cap_usd:.4f} would be exceeded "
            f"(spent ${st.usd:.4f}, requested ${estimated_usd:.4f})"
        )
    return st


def record(input_tokens: int, output_tokens: int, usd: float,
           path: Optional[Path] = None) -> SpendStatus:
    day = _today()
    with _lock:
        conn = _connect(path)
        try:
            conn.execute(
                "INSERT INTO daily_spend(day, input_tokens, output_tokens, usd) "
                "VALUES(?,?,?,?) "
                "ON CONFLICT(day) DO UPDATE SET "
                " input_tokens = input_tokens + excluded.input_tokens,"
                " output_tokens = output_tokens + excluded.output_tokens,"
                " usd = usd + excluded.usd",
                (day, int(input_tokens or 0), int(output_tokens or 0), float(usd or 0)),
            )
            conn.commit()
        finally:
            conn.close()
    return status(path=path)
