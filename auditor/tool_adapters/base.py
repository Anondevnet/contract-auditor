from __future__ import annotations

import json
import os
import shutil
import subprocess
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional


class ToolStatus(str, Enum):
    NOT_SCHEDULED = "not_scheduled"
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED_WITH_FINDINGS = "completed_with_findings"
    COMPLETED_WITHOUT_FINDINGS = "completed_without_findings"
    FAILED = "failed"
    TIMEOUT = "timeout"
    UNSUPPORTED = "unsupported"
    INCONCLUSIVE = "inconclusive"
    NOT_APPLICABLE = "n/a"


@dataclass
class ToolResult:
    tool: str
    version: Optional[str]
    status: ToolStatus
    started_at: Optional[str] = None
    finished_at: Optional[str] = None
    exit_code: Optional[int] = None
    config: Dict[str, Any] = field(default_factory=dict)  # no secrets
    artifact_paths: List[str] = field(default_factory=list)
    findings_count: int = 0
    complete: bool = False
    error: Optional[str] = None
    notes: str = ""

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["status"] = self.status.value
        return d


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _ver(cmd: List[str]) -> Optional[str]:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        out = (p.stdout or p.stderr or "").strip().splitlines()
        return out[0][:200] if out else None
    except Exception as exc:  # noqa: BLE001
        return None


def probe_all() -> Dict[str, Dict[str, Any]]:
    """What is installed and usable on this host (no network)."""
    forge = shutil.which("forge")
    slither = shutil.which("slither")
    out = {
        "forge": {
            "present": bool(forge),
            "path": forge,
            "version": _ver(["forge", "--version"]) if forge else None,
            "status": ToolStatus.NOT_SCHEDULED.value if forge else ToolStatus.UNSUPPORTED.value,
        },
        "slither": {
            "present": bool(slither),
            "path": slither,
            "version": _ver(["slither", "--version"]) if slither else None,
            "status": ToolStatus.NOT_SCHEDULED.value if slither else ToolStatus.UNSUPPORTED.value,
        },
        "echidna": {
            "present": bool(shutil.which("echidna")),
            "status": ToolStatus.UNSUPPORTED.value,
            "blocker": "Not installed; evaluate before install (Haskell binary / CI image).",
        },
        "medusa": {
            "present": bool(shutil.which("medusa")),
            "status": ToolStatus.UNSUPPORTED.value,
            "blocker": "Not installed; Go binary — check Foundry corpus compatibility first.",
        },
        "halmos": {
            "present": bool(shutil.which("halmos")),
            "status": ToolStatus.UNSUPPORTED.value,
            "blocker": "Not installed; pip package may pin solc/python differently — evaluate first.",
        },
        "mythril": {
            "present": False,
            "status": ToolStatus.UNSUPPORTED.value,
            "blocker": "mythril not importable on Python 3.11.9 env; do not install without compat check.",
        },
        "invariant_fuzz": {
            "present": True,
            "path": "auditor.invariant_fuzz",
            "status": ToolStatus.NOT_SCHEDULED.value,
            "notes": "In-tree Foundry invariant-fuzz generator (pinned anvil fork).",
        },
        "fork_diff": {
            "present": True,
            "path": "auditor.fork_diff / fork_diffs table",
            "status": ToolStatus.NOT_SCHEDULED.value,
        },
        "proxy_init": {
            "present": True,
            "path": "auditor.proxy_init_sweep",
            "status": ToolStatus.NOT_SCHEDULED.value,
        },
        "known_exploits": {
            "present": True,
            "path": "auditor known-exploit matchers KX-001..",
            "status": ToolStatus.NOT_SCHEDULED.value,
        },
        "probed_at": _utcnow(),
        "python": os.environ.get("PYTHON_VERSION") or "3.11.9",
    }
    return out
