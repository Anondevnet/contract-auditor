"""Runtime mode: local (default) vs public demo.

``AUDITOR_MODE=public`` turns on the internet-facing paste/upload demo and
disables local-path, address, monitor, hunt, and other live-network surfaces.
Any other value (including unset) keeps the existing local-first behavior.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

PUBLIC_MODE = "public"
LOCAL_MODE = "local"

# CLI commands that must refuse to run in public mode.
PUBLIC_BLOCKED_COMMANDS = frozenset({
    "scan",  # local filesystem path
    "scan-address",
    "validate-address",
    "monitor",
    "monitor-status",
    "monitor-rescan",
    "hunt",
    "hunt-status",
    "exploitable",
    "simulate",
    "watch",
    "watchdog",
    "benchmark",
})


def mode_name() -> str:
    raw = (os.environ.get("AUDITOR_MODE") or LOCAL_MODE).strip().lower()
    return PUBLIC_MODE if raw == PUBLIC_MODE else LOCAL_MODE


def is_public() -> bool:
    return mode_name() == PUBLIC_MODE


def is_local() -> bool:
    return not is_public()


def env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None or not str(raw).strip():
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def env_float(name: str, default: float) -> float:
    raw = os.environ.get(name)
    if raw is None or not str(raw).strip():
        return default
    try:
        return float(raw)
    except ValueError:
        return default


def public_limits() -> dict[str, Any]:
    """Configurable public-demo limits. Safe defaults; env can tighten or raise."""
    return {
        "max_upload_bytes": env_int("AUDITOR_MAX_UPLOAD_BYTES", 200 * 1024),
        "rate_limit_scans_per_hour": env_int("AUDITOR_RATE_LIMIT_PER_HOUR", 10),
        "max_concurrent_scans": env_int("AUDITOR_MAX_CONCURRENT_SCANS", 2),
        "scan_timeout_seconds": env_int("AUDITOR_SCAN_TIMEOUT_SECONDS", 90),
        "daily_spend_usd": env_float("AUDITOR_DAILY_SPEND_USD", 0.0),
        "max_output_tokens": env_int("AUDITOR_MAX_OUTPUT_TOKENS", 1500),
        "bind_host": os.environ.get("AUDITOR_BIND_HOST") or "0.0.0.0",
        "bind_port": env_int("AUDITOR_BIND_PORT", 8080),
        "trust_x_forwarded_for": (os.environ.get("AUDITOR_TRUST_X_FORWARDED_FOR") or "").strip() == "1",
    }


def data_dir() -> Path:
    raw = os.environ.get("AUDITOR_PUBLIC_DATA_DIR")
    if raw:
        return Path(raw)
    return Path(__file__).resolve().parent.parent / "reports" / "public_demo"
