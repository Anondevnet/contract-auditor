"""Storage intelligence.

This machine has roughly 17 GiB free, and the biggest consumers in a smart
contract workflow are compiler downloads and local models. So the auditor
measures continuously instead of trusting that it has room.

Measures only. Never deletes, prunes, or truncates anything.
"""

from __future__ import annotations

import os
import shutil
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

__all__ = [
    "DirectoryUsage",
    "DiskUsage",
    "StorageReport",
    "human_bytes",
    "measure_directory",
    "probe_storage",
]


def human_bytes(count: int | None) -> str:
    """Render a byte count. ``None`` renders as 'unknown', never as 0."""
    if count is None:
        return "unknown"
    step = 1024.0
    value = float(count)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if abs(value) < step or unit == "TiB":
            return f"{value:.0f} {unit}" if unit == "B" else f"{value:.2f} {unit}"
        value /= step
    return f"{value:.2f} TiB"


@dataclass(frozen=True)
class DiskUsage:
    total_bytes: int
    used_bytes: int
    free_bytes: int

    @property
    def percent_used(self) -> float:
        usable = self.used_bytes + self.free_bytes
        if usable <= 0:
            return 0.0
        return round(self.used_bytes * 100.0 / usable, 1)

    @property
    def free_human(self) -> str:
        return human_bytes(self.free_bytes)

    @property
    def total_human(self) -> str:
        return human_bytes(self.total_bytes)

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_bytes": self.total_bytes,
            "used_bytes": self.used_bytes,
            "free_bytes": self.free_bytes,
            "free_human": self.free_human,
            "total_human": self.total_human,
            "percent_used": self.percent_used,
        }


@dataclass(frozen=True)
class DirectoryUsage:
    path: str
    exists: bool
    bytes: int
    file_count: int
    error: str | None = None

    @property
    def human(self) -> str:
        return human_bytes(self.bytes)

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "exists": self.exists,
            "bytes": self.bytes,
            "human": self.human,
            "file_count": self.file_count,
            "error": self.error,
        }


def measure_directory(path: Path | str, skip_hidden: bool = False) -> DirectoryUsage:
    """Sum file sizes under a directory.

    Symlinks are never followed. Following them could walk outside the project
    root and silently inflate the measurement, which is both a path-traversal
    concern and a wrong-number concern.
    """
    target = Path(path)
    if not target.exists():
        return DirectoryUsage(str(target), False, 0, 0)

    total = 0
    count = 0
    errors: list[str] = []

    try:
        for root, dirnames, filenames in os.walk(target, followlinks=False):
            if skip_hidden:
                dirnames[:] = [d for d in dirnames if not d.startswith(".")]
            dirnames.sort()
            for name in sorted(filenames):
                file_path = Path(root) / name
                try:
                    stat = file_path.lstat()
                    total += stat.st_size
                    count += 1
                except OSError as exc:
                    if len(errors) < 5:
                        errors.append(f"{name}: {type(exc).__name__}")
    except OSError as exc:
        return DirectoryUsage(str(target), True, total, count, f"{type(exc).__name__}: {exc}")

    return DirectoryUsage(str(target), True, total, count, "; ".join(errors) or None)


def _largest_files(root: Path, limit: int, min_bytes: int) -> list[tuple[str, int]]:
    """Find files at or above ``min_bytes``. Bounded output, no follow."""
    found: list[tuple[str, int]] = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = [d for d in dirnames if d not in {".git", "__pycache__", ".pytest_cache"}]
        for name in filenames:
            file_path = Path(dirpath) / name
            try:
                size = file_path.lstat().st_size
            except OSError:
                continue
            if size >= min_bytes:
                found.append((str(file_path), size))
    found.sort(key=lambda item: item[1], reverse=True)
    return found[:limit]


def _temp_artifacts(prefixes: Iterable[str]) -> DirectoryUsage:
    """Shallow scan of the system temp dir for our own artifacts.

    Scoped to known prefixes and to the top level only, so it stays cheap and
    cannot be turned into a recursive walk of a large shared directory.
    """
    temp_dir = Path(tempfile.gettempdir())
    total = 0
    count = 0
    try:
        for entry in temp_dir.iterdir():
            if not any(entry.name.startswith(prefix) for prefix in prefixes):
                continue
            try:
                stat = entry.lstat()
                total += stat.st_size if entry.is_file() else 0
                count += 1
            except OSError:
                continue
    except OSError as exc:
        return DirectoryUsage(str(temp_dir), True, total, count, f"{type(exc).__name__}: {exc}")
    return DirectoryUsage(str(temp_dir), True, total, count)


@dataclass
class StorageReport:
    root: str
    disk: DiskUsage
    project: DirectoryUsage
    components: list[DirectoryUsage] = field(default_factory=list)
    temp_artifacts: DirectoryUsage | None = None
    largest_files: list[tuple[str, int]] = field(default_factory=list)
    limits: dict[str, int] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)

    def limit_checks(self) -> list[dict[str, Any]]:
        """Compare measured sizes against configured ceilings."""
        mapping = {
            "max_disk_usage_mb": self.project.bytes,
            "max_evidence_mb": self._component_bytes("evidence"),
            "max_source_mb": self._component_bytes("sources"),
            "max_report_mb": self._component_bytes("reports"),
        }
        checks: list[dict[str, Any]] = []
        for limit_name, limit_mb in self.limits.items():
            measured = mapping.get(limit_name)
            if measured is None:
                continue
            limit_bytes = limit_mb * 1024 * 1024
            checks.append(
                {
                    "limit": limit_name,
                    "limit_mb": limit_mb,
                    "measured_bytes": measured,
                    "measured_human": human_bytes(measured),
                    "within_limit": measured <= limit_bytes,
                }
            )
        return checks

    def _component_bytes(self, name: str) -> int:
        for component in self.components:
            if Path(component.path).name == name:
                return component.bytes
        return 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "root": self.root,
            "disk": self.disk.to_dict(),
            "project": self.project.to_dict(),
            "components": [component.to_dict() for component in self.components],
            "temp_artifacts": self.temp_artifacts.to_dict() if self.temp_artifacts else None,
            "largest_files": [
                {"path": path, "bytes": size, "human": human_bytes(size)}
                for path, size in self.largest_files
            ],
            "limits": dict(self.limits),
            "limit_checks": self.limit_checks(),
            "warnings": list(self.warnings),
        }


def probe_storage(
    root: Path | str,
    components: Iterable[str] = ("audits", "evidence", "reports", "schemas", "prompts", "tests"),
    limits: dict[str, int] | None = None,
    large_file_threshold_bytes: int = 10 * 1024 * 1024,
) -> StorageReport:
    """Measure the volume and the project tree. No writes, no cleanup."""
    root_path = Path(root)

    try:
        usage = shutil.disk_usage(root_path if root_path.exists() else Path("/"))
        disk = DiskUsage(usage.total, usage.used, usage.free)
    except OSError as exc:
        raise OSError(f"could not read disk usage for {root_path}: {exc}") from exc

    project = measure_directory(root_path)
    component_usages = [measure_directory(root_path / name) for name in components]

    warnings: list[str] = []
    if disk.free_bytes < 2 * 1024**3:
        warnings.append(
            f"only {disk.free_human} free; compiler downloads and model pulls are the "
            "usual consumers here"
        )

    largest = _largest_files(root_path, limit=10, min_bytes=large_file_threshold_bytes)
    if largest:
        warnings.append(
            f"{len(largest)} file(s) at or above "
            f"{human_bytes(large_file_threshold_bytes)} in the project tree"
        )

    return StorageReport(
        root=str(root_path),
        disk=disk,
        project=project,
        components=component_usages,
        temp_artifacts=_temp_artifacts(("contract_auditor", "contract-auditor")),
        largest_files=largest,
        limits=dict(limits or {}),
        warnings=warnings,
    )