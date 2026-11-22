"""Configuration loading.

Config is read-only JSON from ``config/default.json`` plus optional
``--config`` overrides. No environment variable is trusted to point the
auditor at an endpoint or a model path without the loopback guard in
``auditor.ollama`` still applying.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

__all__ = ["Settings", "DEFAULT_CONFIG_PATH", "load_settings"]

DEFAULT_CONFIG_PATH = Path(__file__).resolve().parent.parent / "config" / "default.json"


def _defaults() -> dict[str, Any]:
    return {
        "schema_version": 1,
        "model": {
            "provider": "ollama",
            "name": None,
            "endpoint": "http://localhost:11434",
            "probe_on_status": True,
            "timeout_seconds": 3.0,
        },
        "limits": {
            "max_evidence_mb": 256,
            "max_source_mb": 256,
            "max_report_mb": 16,
            "max_disk_usage_mb": 1024,
            "max_tool_timeout_seconds": 15,
            "large_file_threshold_mb": 10,
        },
        "default_chain": "ethereum",
    }


@dataclass
class Settings:
    values: dict[str, Any] = field(default_factory=_defaults)
    source_path: str | None = None
    warnings: list[str] = field(default_factory=list)

    # -- accessors -------------------------------------------------------

    def get(self, dotted: str, fallback: Any = None) -> Any:
        node: Any = self.values
        for part in dotted.split("."):
            if not isinstance(node, dict) or part not in node:
                return fallback
            node = node[part]
        return node

    @property
    def model_name(self) -> str | None:
        value = self.get("model.name")
        return value if isinstance(value, str) and value else None

    @property
    def endpoint(self) -> str:
        value = self.get("model.endpoint", "http://localhost:11434")
        return value if isinstance(value, str) else "http://localhost:11434"

    @property
    def probe_on_status(self) -> bool:
        return bool(self.get("model.probe_on_status", True))

    @property
    def tool_timeout(self) -> float:
        value = self.get("limits.max_tool_timeout_seconds", 15)
        return float(value) if isinstance(value, (int, float)) and value > 0 else 15.0

    @property
    def limits(self) -> dict[str, int]:
        raw = self.get("limits", {})
        limits: dict[str, int] = {}
        if isinstance(raw, dict):
            for key, value in raw.items():
                if isinstance(value, (int, float)) and value > 0:
                    limits[key] = int(value)
        return limits

    @property
    def default_chain(self) -> str:
        value = self.get("default_chain", "ethereum")
        return value if isinstance(value, str) and value else "ethereum"

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_path": self.source_path,
            "values": self.values,
            "warnings": list(self.warnings),
        }


def _merge(base: dict[str, Any], overlay: dict[str, Any]) -> dict[str, Any]:
    """Recursive dict merge. Overlay wins for scalars and lists."""
    merged = dict(base)
    for key, value in overlay.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _merge(merged[key], value)
        else:
            merged[key] = value
    return merged


def load_settings(config_path: Path | str | None = None) -> Settings:
    """Load defaults, then the config file, then any override file."""
    values = _defaults()
    warnings: list[str] = []
    sources: list[Path] = []

    if config_path is not None:
        sources.append(Path(config_path))
    else:
        sources.append(DEFAULT_CONFIG_PATH)

    loaded_path: str | None = None
    for path in sources:
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            if path is DEFAULT_CONFIG_PATH:
                warnings.append(f"default config not found at {path}; using built-in defaults")
            else:
                warnings.append(f"config file not found: {path}")
            continue
        except json.JSONDecodeError as exc:
            warnings.append(f"config file {path} is not valid JSON ({exc}); using defaults")
            continue
        except OSError as exc:
            warnings.append(f"config file {path} unreadable ({type(exc).__name__}); using defaults")
            continue

        if not isinstance(raw, dict):
            warnings.append(f"config file {path} does not contain a JSON object; ignored")
            continue

        values = _merge(values, raw)
        loaded_path = str(path)

    return Settings(values=values, source_path=loaded_path, warnings=warnings)