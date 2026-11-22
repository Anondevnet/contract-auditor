"""Jinja2 template wiring, kept separate so app and routes can both
import it without a circular dependency."""
from __future__ import annotations

from pathlib import Path

from fastapi.templating import Jinja2Templates

DASHBOARD_ROOT = Path(__file__).resolve().parent
TEMPLATES_DIR = DASHBOARD_ROOT / "templates"
STATIC_DIR = DASHBOARD_ROOT / "static"

templates = Jinja2Templates(directory=str(TEMPLATES_DIR))
