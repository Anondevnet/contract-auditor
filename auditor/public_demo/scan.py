"""Run a single uploaded Solidity file through Slither + the auditor analyzers."""

from __future__ import annotations

import hashlib
import tempfile
import time
from pathlib import Path
from typing import Any, Optional

from auditor.analysis.access_control import analyze as access_control_analyze
from auditor.analysis.base import AnalysisContext
from auditor.analysis.privileged_auth import analyze as privileged_auth_analyze
from auditor.analysis.reentrancy import analyze as reentrancy_analyze
from auditor.analysis.slither_generic import analyze as slither_generic_analyze
from auditor.analysis.slither_runner import get_slither_run
from auditor.compiler_select import CompilerSelectionError, plan_compile
from auditor.model import Epistemic, Finding

# Static analyzers only — no RPC, no fork, no hunt, no Keychain.
_ANALYZERS = (
    ("reentrancy", reentrancy_analyze),
    ("access_control", access_control_analyze),
    ("privileged_auth", privileged_auth_analyze),
    ("slither_generic", slither_generic_analyze),
)


def _severity_name(finding: Finding) -> str:
    sev = getattr(finding, "severity", None)
    if sev is None:
        return "UNKNOWN"
    return getattr(sev, "value", None) or str(sev) or "UNKNOWN"


def _finding_dict(finding: Finding) -> dict[str, Any]:
    evidence = []
    for item in getattr(finding, "evidence", None) or []:
        epi = getattr(item, "epistemic", Epistemic.FACT)
        evidence.append({
            "epistemic": getattr(epi, "value", None) or str(epi),
            "source": getattr(item, "source", None),
            "tool": getattr(item, "tool", None),
            "location": getattr(item, "location", None),
            "excerpt": getattr(item, "excerpt", None),
            "proves": list(getattr(item, "proves", None) or []),
            "does_not_prove": list(getattr(item, "does_not_prove", None) or []),
        })
    if not evidence:
        evidence.append({
            "epistemic": "FACT",
            "source": "slither",
            "tool": "slither",
            "location": None,
            "excerpt": getattr(finding, "title", "") or "detector finding",
            "proves": [],
            "does_not_prove": ["This is a static-analysis finding, not a confirmed exploit."],
        })
    return {
        "title": getattr(finding, "title", "") or "finding",
        "severity": _severity_name(finding),
        "confidence": getattr(getattr(finding, "confidence", None), "value", None),
        "contract": getattr(finding, "affected_contract", None),
        "function": getattr(finding, "affected_function", None),
        "lines": list(getattr(finding, "affected_lines", None) or []),
        "detector": (getattr(finding, "title", "") or "").split()[0] if getattr(finding, "title", None) else None,
        "evidence": evidence,
    }


def group_by_severity(findings: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN"]
    grouped = {k: [] for k in order}
    for item in findings:
        key = str(item.get("severity") or "UNKNOWN").upper()
        grouped.setdefault(key, []).append(item)
    return {k: v for k, v in grouped.items() if v}


def scan_source(
    source: str,
    *,
    filename: str = "upload.sol",
    timeout: float = 90.0,
    allow_install: bool = False,
) -> dict[str, Any]:
    """Write ``source`` to a temp dir, pragma-pick solc, run Slither, return JSON."""
    started = time.perf_counter()
    name = Path(filename or "upload.sol").name
    if not name.endswith(".sol"):
        name = "upload.sol"
    digest = hashlib.sha256(source.encode("utf-8", errors="replace")).hexdigest()
    result: dict[str, Any] = {
        "content_sha256": digest,
        "filename": name,
        "status": "failed",
        "solc_version": None,
        "findings": [],
        "findings_by_severity": {},
        "error": None,
        "duration_s": 0.0,
        "n_findings": 0,
    }
    tmp = tempfile.TemporaryDirectory(prefix="auditor-public-")
    try:
        root = Path(tmp.name)
        sol_path = root / name
        sol_path.write_text(source, encoding="utf-8")
        try:
            plan = plan_compile({}, [sol_path], root, allow_install=allow_install)
        except CompilerSelectionError as exc:
            result["status"] = "compile_failed"
            result["error"] = f"compiler selection: {exc}"
            return result
        except Exception as exc:  # noqa: BLE001
            result["status"] = "compile_failed"
            result["error"] = f"{type(exc).__name__}: {exc}"
            return result

        result["solc_version"] = plan.version
        ctx = AnalysisContext()
        ctx.audit_id = "public-demo"
        ctx.source_files = [sol_path]
        ctx.options = {
            "solc": plan.solc_path,
            "solc_args": plan.solc_args,
            "solc_remaps": plan.solc_remaps,
            "slither_target": plan.target,
            "slither_cwd": plan.cwd,
            "scope": "all",
        }
        try:
            run = get_slither_run(ctx, timeout=timeout)
        except Exception as exc:  # noqa: BLE001
            result["status"] = "slither_failed"
            result["error"] = f"{type(exc).__name__}: {exc}"
            return result
        if getattr(run, "status", None) == "timeout":
            result["status"] = "timeout"
            result["error"] = getattr(run, "error", None) or "slither timed out"
            return result

        findings: list[Finding] = []
        seen: set[tuple] = set()
        for _name, analyze in _ANALYZERS:
            try:
                outcome = analyze(ctx)
            except Exception:
                continue
            for finding in outcome.findings or []:
                key = (
                    getattr(finding, "title", None),
                    getattr(finding, "affected_function", None),
                    tuple(getattr(finding, "affected_lines", None) or ()),
                )
                if key in seen:
                    continue
                seen.add(key)
                findings.append(finding)
        payload = [_finding_dict(f) for f in findings]
        result["findings"] = payload
        result["findings_by_severity"] = group_by_severity(payload)
        result["n_findings"] = len(payload)
        result["status"] = "completed"
        slither_status = getattr(run, "status", None)
        if slither_status and slither_status not in {"completed", "success"} and not payload:
            result["status"] = "slither_failed"
            result["error"] = (getattr(run, "error", None) or slither_status)
        return result
    finally:
        result["duration_s"] = round(time.perf_counter() - started, 3)
        tmp.cleanup()
