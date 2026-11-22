"""Filesystem paths used by the dashboard.

The database location itself lives in :mod:`auditor.scan_history` so the CLI
and the dashboard resolve it identically. ``AUDITOR_HISTORY_DB`` lets tests
(and only tests) point every history read/write at a throwaway database
instead of the production one.
"""
from __future__ import annotations

from pathlib import Path

from auditor.scan_history import default_history_db_path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent

DEFAULT_HISTORY_DB = PROJECT_ROOT / "audit_scan_history.db"


def history_db_path() -> Path:
    """Resolve the scan-history database path (env-overridable)."""
    return default_history_db_path()
