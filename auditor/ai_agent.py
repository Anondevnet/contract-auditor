"""AI Audit Agent — staged, cancellable, timeout-bounded audit pipeline.

Stages: scan → collect → dedupe → prioritize → inspect → analyze → tests →
report → save.

Honesty rules enforced throughout:

* Every stage records status, detail, and elapsed time; cancellation and
  timeout abort between stages (and during long ones) with a clear message.
* Deterministic analyzer output is reported as scanner evidence. Anything an
  LLM produces is returned in a separate ``ai_analysis`` block labeled
  ``generated_ai_analysis`` (model + endpoint + timestamp), or explicitly
  skipped with the reason (unreachable daemon, disabled by request, failure).
* No prices, balances, dollar amounts, loss figures, bounty rewards, or
  timeline commitments are ever generated here.
* Subprocesses only run through ``auditor.procs.run`` with fixed, allowlisted
  argv lists (``shell=False``); no user text is ever interpolated into a
  command line.
* The result is recorded as a NEW scan; previous scans are never modified.
"""

from __future__ import annotations

import hashlib
import json
import re
import sys
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Iterator, List, Optional

from auditor import ollama as ollama_client
from auditor.analysis.access_control import analyze as access_control_analyze
from auditor.analysis.base import AnalysisContext
from auditor.analysis.reentrancy import analyze as reentrancy_analyze
from auditor.analysis.slither_generic import analyze as generic_analyze
from auditor.finding_store import get_review, open_store, set_metadata, set_state
from auditor.investigation import _locate_file, _snippet, build_investigation
from auditor.model import (
    Finding,
    deduplicate_findings,
    finding_fingerprint,
    validated_findings,
)
from auditor.procs import run as procs_run
from auditor.scan_history import ScanHistory, default_history_db_path

_PROJECT_ROOT = Path(__file__).resolve().parent.parent

STAGE_NAMES = (
    "scan",
    "collect",
    "dedupe",
    "prioritize",
    "inspect",
    "analyze",
    "tests",
    "report",
    "save",
)

DEFAULT_TIMEOUT_SECONDS = 600.0
DEFAULT_OLLAMA_ENDPOINT = ollama_client.DEFAULT_ENDPOINT
_MAX_LOG_LINES = 400
_MAX_LOG_LINE = 400
_MAX_SOURCE_CHARS_FOR_PROMPT = 3000
_MAX_AI_FINDINGS = 5


class PipelineAbort(Exception):
    """Raised when the pipeline is cancelled or runs past its deadline."""

    def __init__(self, reason: str, message: str) -> None:
        super().__init__(message)
        self.reason = reason  # "cancelled" | "timeout"


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# path validation
# ---------------------------------------------------------------------------

def validate_source_path(path: Any, content_hash: Optional[str] = None) -> Path:
    """Validate and resolve a Solidity file/directory or a stored source ref.

    ``etherscan://<network>/<address>`` refs (monitor/hunt/scan-address scans)
    resolve to the exact cached verified source for ``content_hash`` via
    :mod:`auditor.source_resolver`; nothing is fetched or substituted. Local
    paths are confined to the allowed roots. Raises ``ValueError`` with a
    user-facing, actionable reason on any problem.
    """
    from auditor.source_resolver import SourceResolutionError, resolve_source

    raw = str(path or "").strip()
    if not raw:
        raise ValueError("path is required")
    try:
        resolved = resolve_source(raw, content_hash).path
    except SourceResolutionError as exc:
        raise ValueError(str(exc)) from None
    if resolved.is_file():
        if resolved.suffix.lower() != ".sol":
            raise ValueError(f"Not a Solidity file: {resolved.name}")
        return resolved
    if resolved.is_dir():
        return resolved
    raise ValueError(f"Path is neither a file nor a directory: {resolved}")


def collect_sol_files(root: Path) -> List[Path]:
    """All ``.sol`` files under ``root`` (or the file itself)."""
    if root.is_file():
        return [root]
    return sorted(p for p in root.rglob("*.sol") if p.is_file())


def combined_content_hash(sol_files: List[Path]) -> Optional[str]:
    """SHA-256 over concatenated sources — same recipe the local scan uses."""
    combined = b""
    for path in sol_files:
        try:
            combined += path.read_bytes()
        except OSError:
            return None
    if not combined:
        return None
    return hashlib.sha256(combined).hexdigest()


# ---------------------------------------------------------------------------
# pipeline plumbing
# ---------------------------------------------------------------------------

class Pipeline:
    """Stage bookkeeping, logging, cancellation, and deadline enforcement."""

    def __init__(
        self,
        stages: List[Dict[str, Any]],
        log: Callable[[str], None],
        cancel_event: Any = None,
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    ) -> None:
        self.stages = stages
        self._log_fn = log
        self._cancel = cancel_event
        self._timeout = float(timeout_seconds)
        self._started = time.monotonic()
        self._log_count = 0

    @property
    def deadline(self) -> float:
        return self._started + self._timeout

    def elapsed(self) -> float:
        return time.monotonic() - self._started

    def remaining(self) -> float:
        return max(0.0, self.deadline - time.monotonic())

    def log(self, message: str) -> None:
        self._log_count += 1
        if self._log_count > _MAX_LOG_LINES:
            return
        text = str(message)
        if len(text) > _MAX_LOG_LINE:
            text = text[: _MAX_LOG_LINE - 1] + "…"
        try:
            self._log_fn(text)
        except Exception:  # noqa: BLE001 - logging must never break the audit
            pass

    def tick(self) -> None:
        """Abort when cancelled or out of time."""
        if self._cancel is not None and getattr(self._cancel, "is_set", lambda: False)():
            raise PipelineAbort("cancelled", "Cancelled by user")
        if time.monotonic() > self.deadline:
            raise PipelineAbort(
                "timeout", f"AI audit timed out after {self._timeout:g} seconds"
            )

    @contextmanager
    def stage(self, name: str) -> Iterator[Dict[str, Any]]:
        """Run one stage, recording status/detail/elapsed in ``self.stages``."""
        self.tick()
        entry: Dict[str, Any] = {
            "name": name,
            "status": "running",
            "detail": "",
            "started_at": _utcnow(),
            "finished_at": None,
            "elapsed_seconds": 0.0,
        }
        self.stages.append(entry)
        self.log(f"stage:{name}: started")
        t0 = time.monotonic()
        try:
            yield entry
            self.tick()
            if entry["status"] == "running":
                entry["status"] = "done"
            self.log(f"stage:{name}: {entry['status']} — {entry.get('detail', '')}")
        except PipelineAbort as exc:
            entry["status"] = "failed"
            entry["detail"] = f"aborted ({exc.reason}): {exc}"
            self.log(f"stage:{name}: aborted ({exc.reason})")
            raise
        except Exception as exc:  # noqa: BLE001 - surfaced to the job record
            entry["status"] = "failed"
            entry["detail"] = f"{type(exc).__name__}: {exc}"
            self.log(f"stage:{name}: failed — {entry['detail']}")
            raise
        finally:
            entry["finished_at"] = _utcnow()
            entry["elapsed_seconds"] = round(time.monotonic() - t0, 3)


# ---------------------------------------------------------------------------
# helper analyses
# ---------------------------------------------------------------------------

def _run_analyzers(sol_files: List[Path], options: Optional[Dict[str, Any]] = None,
                   verdict_out: Optional[Dict[str, Any]] = None) -> tuple[List[Finding], List[str]]:
    """Run the deterministic analyzers over ``sol_files``.

    Same analyzer set as the monitor pipeline (incl. privileged-auth and
    honeypot) so a retest/AI audit can reproduce every finding family.
    ``options`` carries the recorded compile plan (solc, remappings, target)
    for verified-source caches. ``verdict_out`` receives whether the required
    Slither run actually analyzed contracts; an empty run is never "clean".
    """
    from auditor.analysis.honeypot import analyze as honeypot_analyze
    from auditor.analysis.privileged_auth import analyze as privileged_auth_analyze
    from auditor.analysis.known_exploits import analyze as known_exploits_analyze
    from auditor.analysis.slither_runner import get_slither_run, required_analysis_verdict

    context = AnalysisContext()
    context.source_files = list(sol_files)
    if options:
        context.options = dict(options)
    notes: List[str] = []
    findings: List[Finding] = []
    from auditor.analysis.oracle_staleness import analyze as oracle_analyze
    from auditor.analysis.erc4626_inflation import analyze as erc4626_analyze
    from auditor.analysis.pool_accounting import analyze as pool_analyze

    try:
        run = get_slither_run(context)
    except Exception as exc:  # noqa: BLE001
        run = None
        notes.append(f"slither run could not start: {type(exc).__name__}: {exc}")
    for analyze in (
        reentrancy_analyze,
        access_control_analyze,
        generic_analyze,
        oracle_analyze,
        erc4626_analyze,
        pool_analyze,
        honeypot_analyze,
        privileged_auth_analyze,
        known_exploits_analyze,
    ):
        try:
            outcome = analyze(context)
        except Exception as exc:  # noqa: BLE001 - isolate broken analyzers
            notes.append(f"{analyze.__module__}: {type(exc).__name__}: {exc}")
            continue
        findings.extend(list(outcome.findings))
        notes.extend(str(n) for n in (outcome.notes or []))
    complete, reasons = required_analysis_verdict(run)
    if complete is not True:
        notes.extend(reasons or ["Slither (static analysis): execution was not observed"])
    if verdict_out is not None:
        verdict_out["complete"] = complete is True
        verdict_out["reasons"] = reasons
    return findings, notes


def _tool_version(binary: str, args: List[str], timeout: float = 10.0) -> str:
    """One allowlisted ``--version`` probe. Never raises."""
    result = procs_run([binary, *args], timeout=timeout)
    if getattr(result, "timed_out", False):
        return "timeout"
    if result.error:
        return f"not available ({result.error})"
    first = ""
    for line in (result.stdout or result.stderr or "").strip().splitlines():
        line = line.strip()
        if line:
            first = line
            break
    if not first:
        first = f"exit code {result.returncode}"
    return first[:160]


def _find_callers(sol_files: List[Path], function: str, limit: int = 20) -> List[str]:
    """Local text search for call sites of ``function`` (not a parsed graph)."""
    if not function:
        return []
    call_re = re.compile(r"\b" + re.escape(function) + r"\s*\(")
    def_re = re.compile(r"^\s*function\s+" + re.escape(function) + r"\s*\(")
    hits: List[str] = []
    for path in sol_files:
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        for number, line in enumerate(lines, start=1):
            if not call_re.search(line):
                continue
            if def_re.match(line):
                continue
            hits.append(f"{path.name}:{number}: {line.strip()[:140]}")
            if len(hits) >= limit:
                return hits
    return hits


# ---------------------------------------------------------------------------
# AI enrichment (optional, labeled)
# ---------------------------------------------------------------------------

_AI_PROMPT_TEMPLATE = """You are reviewing one potential issue in a smart contract codebase.

Finding title: {title}
Category: {category}
Severity: {severity}
Description: {description}
Scanner remediation hint: {remediation}

Source excerpt (verbatim):
```
{source}
```

Respond with JSON only, matching exactly this shape:
{{"risk_analysis": "...", "remediation": "...", "uncertainty": "..."}}

Rules:
- Plain English aimed at a security reviewer.
- Do NOT include dollar amounts, token quantities, prices, loss figures, or bounty rewards — not even as guesses.
- Do NOT give step-by-step exploitation instructions; discuss preconditions and trust assumptions instead.
- Mark anything speculative as speculation inside "uncertainty".
- Each field max 120 words."""


def _parse_ai_json(text: str) -> tuple[Optional[Dict[str, str]], Optional[str]]:
    """Extract a JSON object from a model response. Returns (data, error)."""
    stripped = text.strip()
    if stripped.startswith("```"):
        stripped = re.sub(r"^```[a-zA-Z]*\n?", "", stripped)
        stripped = re.sub(r"\n?```$", "", stripped.strip())
    try:
        data = json.loads(stripped)
        if isinstance(data, dict):
            return {str(k): str(v) for k, v in data.items() if isinstance(v, (str, int, float))}, None
    except json.JSONDecodeError:
        pass
    match = re.search(r"\{.*\}", text, re.DOTALL)
    if match:
        try:
            data = json.loads(match.group(0))
            if isinstance(data, dict):
                return {str(k): str(v) for k, v in data.items() if isinstance(v, (str, int, float))}, None
        except json.JSONDecodeError as exc:
            return None, f"JSON parse error: {exc}"
    return None, "no JSON object found in model response"


def _ai_enrich(
    entries: List[Dict[str, Any]],
    findings: List[Finding],
    *,
    endpoint: str,
    model: str,
    use_ai: bool,
    pipeline: Pipeline,
    source_root: Path,
) -> Dict[str, Any]:
    """Optional LLM enrichment. Never mixed into scanner evidence."""
    label = {
        "origin": "generated_ai_analysis",
        "label": "AI-generated analysis (model opinion, not scanner evidence)",
        "model": model,
        "endpoint": endpoint,
        "generated_at": None,
    }

    if not use_ai:
        return {**label, "status": "skipped", "reason": "disabled by request (use_ai=false)", "findings": []}

    probe = ollama_client.probe_ollama(endpoint, selected_model=model, timeout=3.0)
    if not probe.reachable:
        return {**label, "status": "skipped", "reason": f"Ollama unreachable: {probe.error}", "findings": []}
    if probe.selected_resolves is False:
        return {**label, "status": "skipped", "reason": f"model {model!r} not installed locally", "findings": []}

    results: List[Dict[str, Any]] = []
    by_fp = {str(finding_fingerprint(f)): f for f in findings}
    chosen = entries[:_MAX_AI_FINDINGS]
    completed = 0
    for entry in chosen:
        pipeline.tick()
        fp = entry.get("fingerprint")
        finding = by_fp.get(fp)
        if finding is None:
            continue
        pipeline.log(f"AI enrichment: analyzing finding {completed + 1}/{len(chosen)}: {finding.title[:50]}")
        source = _snippet(_locate_file(source_root, finding.affected_contract), finding.affected_lines or [])
        excerpt = "\n".join(f"{l['n']}: {l['text']}" for l in source.get("lines", []))[:_MAX_SOURCE_CHARS_FOR_PROMPT] or "(no source excerpt available)"
        prompt = _AI_PROMPT_TEMPLATE.format(
            title=finding.title,
            category=finding.category,
            severity=finding.severity.value,
            description=finding.description[:600],
            remediation=finding.remediation[:400] or "(none recorded)",
            source=excerpt,
        )
        timeout = max(5.0, min(90.0, pipeline.remaining() - 5))
        text, error = ollama_client.generate_completion(
            prompt, model, endpoint=endpoint, timeout=timeout, max_tokens=700
        )
        record: Dict[str, Any] = {
            "fingerprint": fp,
            "title": finding.title,
            "origin": "generated_ai_analysis",
            "model": model,
            "generated_at": _utcnow(),
        }
        if error is not None:
            record.update({"status": "failed", "reason": error})
        else:
            data, parse_error = _parse_ai_json(text or "")
            record.update(
                {
                    "status": "completed",
                    "parse_error": parse_error,
                    "risk_analysis": (data or {}).get("risk_analysis"),
                    "remediation": (data or {}).get("remediation"),
                    "uncertainty": (data or {}).get("uncertainty"),
                    "raw_excerpt": (text or "")[:400],
                }
            )
            completed += 1
        results.append(record)

    if completed == len(chosen) and chosen:
        status = "completed"
        reason = None
    elif completed:
        status = "partial"
        reason = "some findings could not be enriched"
    else:
        status = "failed"
        reason = "no enrichment succeeded"
    return {**label, "status": status, "reason": reason, "findings": results}


# ---------------------------------------------------------------------------
# main entry point
# ---------------------------------------------------------------------------

def run_ai_audit(
    source_path: Any,
    *,
    deep_tests: bool = False,
    use_ai: bool = True,
    metadata: Optional[Dict[str, Any]] = None,
    history_db: Optional[Path] = None,
    ollama_endpoint: str = DEFAULT_OLLAMA_ENDPOINT,
    ollama_model: str = "qwen3-8b-uncensored-16k:latest",
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    cancel_event: Any = None,
    log: Optional[Callable[[str], None]] = None,
    stages: Optional[List[Dict[str, Any]]] = None,
    compile_options: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Run the full AI audit pipeline and record the result as a NEW scan.

    ``report["outcome"]`` is ``"inconclusive"`` when the required static
    analysis did not actually analyze contracts; such a run is not a clean
    audit even though the pipeline itself finished."""
    stages = stages if stages is not None else []
    log_fn = log or (lambda _msg: None)
    pipeline = Pipeline(stages, log_fn, cancel_event=cancel_event, timeout_seconds=timeout_seconds)

    db_path = Path(history_db) if history_db else default_history_db_path()
    report: Dict[str, Any] = {
        "kind": "ai_audit",
        "generated_at": _utcnow(),
        "origin_label": (
            "Deterministic scanner evidence plus clearly separated "
            "AI-generated analysis (if any). No prices or loss figures are "
            "produced by this tool."
        ),
        "stages": stages,
    }

    # Record-first, same contract as dashboard/CLI scans: the source path
    # is validated BEFORE any row exists, then a `started` row is recorded
    # before the long analysis so a crash/timeout/cancel mid-pipeline
    # leaves an honest trace instead of no row at all.
    root = validate_source_path(source_path)
    sol_files = collect_sol_files(root)
    if not sol_files:
        raise ValueError(f"No .sol files found in {root}")
    source_hash = combined_content_hash(sol_files)
    history = ScanHistory(db_path)
    try:
        scan_id = history.record_scan(
            source_path=root,
            config_fingerprint="ai-audit",
            findings=[],
            content_hash=source_hash,
        )
    finally:
        history.close()
    report["scan_id"] = scan_id
    report["source_path"] = str(root)
    report["file_count"] = len(sol_files)
    report["source_hash"] = source_hash

    def _mark_terminal(status: str, error_info: str) -> None:
        """Best-effort terminal status; the original exception is primary."""
        history = ScanHistory(db_path)
        try:
            if status == "interrupted":
                history.mark_interrupted(scan_id, error_info, only_if_started=True)
            else:
                history.mark_failed(scan_id, error_info, only_if_started=True)
        except Exception:  # noqa: BLE001 - persistence is best-effort
            log_fn(f"could not persist terminal status {status} for scan {scan_id}")
        finally:
            history.close()

    findings: List[Finding] = []
    try:
        # --- scan -------------------------------------------------------------
        with pipeline.stage("scan") as entry:
            verdict: Dict[str, Any] = {}
            findings, notes = _run_analyzers(sol_files, compile_options, verdict)
            report["analyzer_notes"] = notes
            report["analysis_complete"] = bool(verdict.get("complete"))
            report["outcome"] = "analyzed" if verdict.get("complete") else "inconclusive"
            report["compile_options_used"] = bool(compile_options)
            # Same library-code / known-benign triage as the monitor, so an AI
            # audit does not resurface findings the monitor already dismissed.
            # Suppressed findings are kept in the report, labeled False positive.
            try:
                from auditor.triage import apply_to_pipeline
                tri = apply_to_pipeline(findings, sol_files, Path(root) if root else None,
                                        None, notes.append)
                report["suppressed_findings"] = [dict(d, verdict_label="False positive")
                                                 for d in tri.suppressed_dicts()]
                findings = list(tri.kept)
            except Exception as exc:  # noqa: BLE001
                notes.append(f"triage not applied: {type(exc).__name__}: {exc}")
            entry["detail"] = (
                f"{len(sol_files)} file(s), {len(findings)} raw finding(s); "
                f"scan {scan_id} recorded as started"
            )

        # --- collect ----------------------------------------------------------
        with pipeline.stage("collect") as entry:
            report["toolchain"] = {
                "slither": _tool_version("slither", ["--version"]),
                "solc": _tool_version("solc", ["--version"]),
                "forge": _tool_version("forge", ["--version"]),
                "python": sys.version.split()[0],
            }
            report["source_hash"] = combined_content_hash(sol_files)
            entry["detail"] = "tool versions and source hash recorded"

        # --- dedupe -----------------------------------------------------------
        with pipeline.stage("dedupe") as entry:
            unique, duplicate_count = deduplicate_findings(findings)
            findings = validated_findings(unique)
            dropped_invalid = len(unique) - len(findings)
            report["duplicates_merged"] = duplicate_count
            report["dropped_invalid_findings"] = dropped_invalid
            entry["detail"] = (
                f"{duplicate_count} duplicate(s) merged, "
                f"{dropped_invalid} invalid dropped, {len(findings)} unique"
            )

        # --- prioritize -------------------------------------------------------
        with pipeline.stage("prioritize") as entry:
            ordered = sorted(findings, key=lambda f: f.priority_score())
            report["prioritized"] = [
                {
                    "fingerprint": str(finding_fingerprint(f)),
                    "title": f.title,
                    "severity": f.severity.value,
                    "confidence": f.confidence.value,
                    "priority_score": list(f.priority_score()[:2]),
                }
                for f in ordered
            ]
            entry["detail"] = f"{len(ordered)} finding(s) ordered by severity/confidence"

        # --- inspect ----------------------------------------------------------
        inspections: List[Dict[str, Any]] = []
        with pipeline.stage("inspect") as entry:
            for f in ordered:
                pipeline.tick()
                source = _snippet(_locate_file(root, f.affected_contract), f.affected_lines or [])
                inspections.append(
                    {
                        "fingerprint": str(finding_fingerprint(f)),
                        "title": f.title,
                        "root_cause_location": {
                            "file": source.get("file"),
                            "line_range": source.get("line_range"),
                            "origin": source.get("origin"),
                        },
                        "callers_local_text_search": _find_callers(sol_files, f.affected_function or ""),
                        "callers_label": "local text search — not a parsed call graph",
                        "reasoning": (f.reasoning or "")[:500],
                        "benign_explanation": f.benign_explanation or "Not assessed",
                        "false_positive_risk": f.false_positive_risk or "Not assessed",
                    }
                )
            report["inspections"] = inspections
            entry["detail"] = f"inspected {len(inspections)} finding(s)"

        # --- analyze ----------------------------------------------------------
        with pipeline.stage("analyze") as entry:
            investigations = []
            for f in ordered:
                pipeline.tick()
                inv = build_investigation(
                    f.to_dict(),
                    {"scan_id": "(pending)", "timestamp": _utcnow(), "config_fingerprint": "ai-audit"},
                    metadata=metadata or {},
                    source_root=root,
                )
                investigations.append(
                    {
                        "fingerprint": str(finding_fingerprint(f)),
                        "attacker_summary": {
                            "plain_english": inv["attacker"]["plain_english"],
                            "preconditions": inv["attacker"]["preconditions"],
                            "reachability": inv["attacker"]["reachability"],
                        },
                        "defender_summary": {
                            "root_cause": inv["defender"]["root_cause"]["summary"],
                            "remediation": inv["defender"]["remediation"]["primary"],
                            "test_plan": [t["step"] for t in inv["defender"]["test_plan"]],
                        },
                        "exposure": inv["attacker"]["exposure"],
                        "difficulty": inv["attacker"]["difficulty"],
                        "origin": "deterministic_scanner_evidence",
                    }
                )
            report["deterministic_analysis"] = investigations
            report["ai_analysis"] = _ai_enrich(
                report["prioritized"],
                ordered,
                endpoint=ollama_endpoint,
                model=ollama_model,
                use_ai=use_ai,
                pipeline=pipeline,
                source_root=root,
            )
            entry["detail"] = (
                f"{len(investigations)} deterministic analysis block(s); "
                f"AI: {report['ai_analysis'].get('status')}"
            )

        # --- tests ------------------------------------------------------------
        with pipeline.stage("tests") as entry:
            reproduction: List[Dict[str, Any]] = []
            if findings:
                pipeline.log("re-running analyzers for reproduction check")
                rerun, _notes = _run_analyzers(sol_files, compile_options)
                rerun_fps = {str(finding_fingerprint(f)) for f in rerun}
                for f in ordered:
                    fp = str(finding_fingerprint(f))
                    reproduction.append(
                        {
                            "fingerprint": fp,
                            "title": f.title,
                            "persisted": fp in rerun_fps,
                            "method": "re-analysis of the same source with the same analyzers",
                            "label": "deterministic",
                        }
                    )
            unit_tests: Dict[str, Any] = {
                "ran": False,
                "reason": "not requested (deep_tests=false)",
                "label": "deterministic",
            }
            if deep_tests:
                pipeline.tick()
                pipeline.log("running allowlisted test suite (pytest)")
                result = procs_run(
                    [sys.executable, "-m", "pytest", "-q", "tests/"],
                    cwd=str(_PROJECT_ROOT),
                    timeout=max(30.0, min(300.0, pipeline.remaining())),
                )
                tail = (result.stdout or "").strip().splitlines()
                unit_tests = {
                    "ran": True,
                    "command": f"{sys.executable} -m pytest -q tests/ (fixed allowlist, no user input)",
                    "returncode": result.returncode,
                    "timed_out": bool(getattr(result, "timed_out", False)),
                    "summary": tail[-1][:300] if tail else "",
                    "label": "deterministic",
                }
            report["tests"] = {"reproduction": reproduction, "unit_tests": unit_tests}
            entry["detail"] = (
                f"reproduction: {sum(1 for r in reproduction if r['persisted'])}/"
                f"{len(reproduction)} persisted; unit tests: "
                f"{'ran' if unit_tests.get('ran') else 'not run'}"
            )

        # --- report -----------------------------------------------------------
        with pipeline.stage("report") as entry:
            conclusions = [
                {
                    "fingerprint": ins["fingerprint"],
                    "title": ins["title"],
                    "severity": next(
                        (p["severity"] for p in report["prioritized"] if p["fingerprint"] == ins["fingerprint"]),
                        "UNKNOWN",
                    ),
                    "verdict": "Unverified finding — analyst review required (no verdict is auto-assigned)",
                    "root_cause_location": ins["root_cause_location"],
                    "origin": "deterministic_scanner_evidence",
                }
                for ins in inspections
            ]
            report["conclusions"] = conclusions
            report["uncertainty"] = [
                "Whether deployed bytecode matches the reviewed source was not verified.",
                "No RPC endpoint was queried; balances, TVL, and USD figures are unknown.",
                "Analyzer coverage is limited to the installed detectors (see toolchain).",
            ]
            if report["ai_analysis"].get("status") == "skipped":
                report["uncertainty"].append(
                    f"AI analysis skipped: {report['ai_analysis'].get('reason')}"
                )
            report["next_steps"] = [
                "Review each conclusion against the source excerpt and call sites.",
                "Confirm or dismiss each finding explicitly in the investigation view.",
                "Run the reproduction/unit tests after any fix and retest the finding.",
            ]
            report["limitations"] = [
                "Conceptual analysis only — this tool does not execute exploits.",
                "Reachability comes from local source text, not a full call graph.",
                "Time and effort figures anywhere in this report are labeled approximate.",
            ]
            entry["detail"] = f"{len(conclusions)} conclusion(s) written"

        # --- save -------------------------------------------------------------
        with pipeline.stage("save") as entry:
            history = ScanHistory(db_path)
            try:
                report["stages"] = stages
                history.mark_completed(scan_id, findings, graph_snapshot=report)
            finally:
                history.close()
            if metadata:
                store = open_store(db_path)
                try:
                    set_metadata(store, scan_id, metadata)
                finally:
                    store.close()
            entry["detail"] = f"recorded as new scan {report['scan_id']}"

        report["elapsed_seconds"] = round(pipeline.elapsed(), 3)
        return report
    except PipelineAbort as exc:
        _mark_terminal(
            "interrupted" if getattr(exc, "reason", "") == "cancelled" else "failed",
            f"{getattr(exc, 'reason', 'abort')}: {exc}",
        )
        raise
    except Exception as exc:  # noqa: BLE001 - recorded, then re-raised
        _mark_terminal("failed", f"{type(exc).__name__}: {exc}")
        raise


# ---------------------------------------------------------------------------
# retest
# ---------------------------------------------------------------------------

def run_retest(
    scan_id: str,
    fingerprint: str,
    *,
    history_db: Optional[Path] = None,
    cancel_event: Any = None,
    timeout_seconds: float = 180.0,
    log: Optional[Callable[[str], None]] = None,
    stages: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """Re-run analysis on the original source and report if the finding persists.

    Records the re-analysis as a NEW scan (history is append-only). If the
    finding's state was ``Fixed`` — the only state a retest is meaningful
    from — the state advances to ``Retested``; nothing is ever auto-confirmed.
    """
    stages = stages if stages is not None else []
    pipeline = Pipeline(stages, log or (lambda _m: None), cancel_event=cancel_event, timeout_seconds=timeout_seconds)
    db_path = Path(history_db) if history_db else default_history_db_path()

    with pipeline.stage("load") as entry:
        history = ScanHistory(db_path)
        try:
            record = history.get_scan(scan_id)
            if not record:
                raise ValueError(f"scan not found: {scan_id}")
            stored = history.get_findings(scan_id)
        finally:
            history.close()
        target = next(
            (f for f in stored if str(f.get("fingerprint")) == fingerprint), None
        )
        if target is None:
            raise ValueError(f"finding {fingerprint} not found in scan {scan_id}")
        entry["detail"] = f"loaded finding {target.get('title')!r}"

    with pipeline.stage("reanalyze") as entry:
        root = validate_source_path(record.get("source_path"), record.get("content_hash"))
        sol_files = collect_sol_files(root)
        if not sol_files:
            raise ValueError(f"No .sol files found in {root}")
        from auditor.source_resolver import recorded_compile_options
        rt_verdict: Dict[str, Any] = {}
        new_findings, notes = _run_analyzers(sol_files, recorded_compile_options(Path(root)), rt_verdict)
        analysis_complete = bool(rt_verdict.get("complete"))
        # Same canonical dedupe as every other pipeline stage, so the
        # retest scan stores the same finding set a fresh scan would.
        new_findings, _merged = deduplicate_findings(new_findings)
        new_fps = {str(finding_fingerprint(f)) for f in new_findings}
        # Legacy fallback: fingerprints gained a file dimension (fifth
        # element) after some scans were recorded. A stored 4-tuple
        # fingerprint still matches a new finding whose 4-tuple prefix
        # (contract, function, lines, title prefix) is identical.
        legacy_projections = {
            str(tuple(finding_fingerprint(f))[:4]) for f in new_findings
        }
        persisted = fingerprint in new_fps or fingerprint in legacy_projections
        entry["detail"] = f"re-analysis produced {len(new_findings)} finding(s)"

    with pipeline.stage("compare") as entry:
        current_hash = combined_content_hash(sol_files)
        original_hash = record.get("content_hash")
        # Directory scans historically stored the empty-content hash, so treat
        # that sentinel as "unknown" rather than "changed".
        if original_hash == hashlib.sha256(b"").hexdigest():
            original_hash = None
        if not original_hash:
            # AI-audit scans record a real combined source hash in the report.
            graph = record.get("graph_snapshot")
            if isinstance(graph, dict):
                candidate = graph.get("source_hash")
                if isinstance(candidate, str) and candidate:
                    original_hash = candidate
        source_changed = bool(
            current_hash and original_hash and current_hash != original_hash
        )
        notes_out: List[str] = [
            "Retest method: re-analysis of the original source with the same "
            "deterministic analyzers. No exploit was executed."
        ]
        if source_changed:
            notes_out.append(
                "Source content hash differs from the original scan — the files "
                "changed since the original scan, so the comparison is not like-for-like."
            )
        if not analysis_complete:
            notes_out.append(
                "INCONCLUSIVE: the required static analysis did not complete ("
                + "; ".join(rt_verdict.get("reasons") or ["not observed"])
                + "). A missing finding here is not evidence of a fix.")
        if not persisted:
            notes_out.append(
                "The finding did not re-appear in re-analysis. This can mean it is "
                "fixed, that the inputs changed, or that analyzer behavior differs — "
                "confirm manually before closing it out."
            )
        entry["detail"] = ("persisted" if persisted else
                           ("inconclusive" if not analysis_complete else "not reproduced"))

    tested_at = _utcnow()
    result: Dict[str, Any] = {
        "kind": "retest",
        "scan_id": scan_id,
        "fingerprint": fingerprint,
        "retest_scan_id": None,
        "tested_at": tested_at,
        "persisted": persisted,
        "matches": [
            f.title
            for f in new_findings
            if str(finding_fingerprint(f)) == fingerprint
            or str(tuple(finding_fingerprint(f))[:4]) == fingerprint
        ],
        "notes": notes_out,
        "source_changed": source_changed,
        "state_change": None,
        "stages": stages,
        "elapsed_seconds": round(pipeline.elapsed(), 3),
        "origin": "deterministic_reanalysis",
    }

    with pipeline.stage("save") as entry:
        history = ScanHistory(db_path)
        try:
            retest_scan_id = history.record_scan(
                source_path=root,
                config_fingerprint="retest",
                findings=new_findings,
            )
            result["retest_scan_id"] = retest_scan_id
            result["stages"] = stages
            history.mark_completed(retest_scan_id, new_findings, graph_snapshot=result)
        finally:
            history.close()
        entry["detail"] = f"recorded re-analysis as scan {retest_scan_id}"

    state_note = (
        f"retest at {tested_at}: " + ("finding persisted" if persisted else "finding not reproduced")
    )
    store = open_store(db_path)
    try:
        review = get_review(store, scan_id, fingerprint)
        if review.get("state") == "Fixed":
            ok, message = set_state(
                store, scan_id, fingerprint, "Retested", note=state_note
            )
            result["state_change"] = message if ok else None
    finally:
        store.close()

    return result
