"""Contract Auditor Web Dashboard.

Local-first web interface for the smart-contract vulnerability auditor.
"""
from __future__ import annotations

from .app import create_app

__all__ = ["create_app"]