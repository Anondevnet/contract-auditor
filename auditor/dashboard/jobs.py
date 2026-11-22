"""Background job management for scan operations."""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from auditor.model import (
    Epistemic,
    EvidenceItem,
    deduplicate_findings,
)
from auditor.scan_history import ScanHistory

from .models import (
    Network,
    ScanJobRequest,
    ScanJobResponse,
    ScanStatus,
    ScanType,
    Severity,
)
from .paths import history_db_path

log = logging.getLogger("contract_auditor.dashboard.jobs")

_TOOL_FAIL_STATUSES = frozenset({"failed", "timeout", "not_found"})


def _dedupe_findings(findings: list) -> list:
    """Thin wrapper over the canonical merge in ``auditor.model``.

    Dashboard scans and the benchmark import this name; the actual merge
    logic (fingerprint keying, evidence union by content hash, severity
    upgrade, description append, deterministic first-seen order) lives in
    exactly one place so CLI, dashboard, AI audit, retest, and benchmark
    can never drift apart again.
    """
    return deduplicate_findings(findings)[0]


def _zero_findings_note(
    static_requested: bool,
    validation_ran: bool,
    scan_complete: bool,
) -> str:
    """Honest zero-findings wording — never 'safe', never 'clean'."""
    base = "No findings detected by the checks that completed."
    if not scan_complete:
        return (
            base
            + " Some checks did not complete (see tool status) — this is "
            "not a clean result."
        )
    if not static_requested:
        if validation_ran:
            return (
                base
                + " Static analysis was not requested; build/test results "
                "are compilation evidence, not security evidence."
            )
        return base + " No finding-producing checks were selected for this scan."
    if validation_ran:
        return (
            base
            + " Build/test results are compilation evidence, not security "
            "evidence."
        )
    return base


class JobCancelled(Exception):
    """Raised inside a job when the user cancelled it."""


@dataclass
class ScanJob:
    """Internal representation of a scan job."""
    job_id: str
    scan_type: str
    status: ScanStatus = ScanStatus.PENDING
    created_at: datetime = field(default_factory=datetime.now)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    progress: float = 0.0
    message: str = "Queued"
    result: Optional[dict] = None
    error: Optional[str] = None
    local_path: Optional[str] = None
    address: Optional[str] = None
    network: Optional[str] = None
    stages: list = field(default_factory=list)
    log_lines: list = field(default_factory=list)
    report: Optional[dict] = None
    ai_request: Optional[dict] = None
    retest_request: Optional[dict] = None
    metadata: Optional[dict] = None
    local_run_static: bool = True
    local_validate: bool = False
    local_run_tests: bool = False
    _future: Optional[asyncio.Future] = field(default=None, repr=False)
    _cancel_event: threading.Event = field(default_factory=threading.Event, repr=False)


class JobManager:
    """Manages background scan jobs."""

    def __init__(self):
        self._jobs: dict[str, ScanJob] = {}
        self._lock = threading.RLock()
        self._worker_task: Optional[asyncio.Task] = None
        self._running = False
        self._worker_loop: Optional[asyncio.AbstractEventLoop] = None
        self._load_persisted_jobs()

    def _cache_path(self) -> Path:
        override = os.environ.get("AUDITOR_JOBS_CACHE")
        if override:
            return Path(override)
        return Path(__file__).resolve().parents[2] / "reports" / "jobs_cache.json"

    def _persist_jobs(self) -> None:
        try:
            p = self._cache_path()
            p.parent.mkdir(parents=True, exist_ok=True)
            data = {}
            with self._lock:
                for jid, j in list(self._jobs.items())[-100:]:
                    data[jid] = {
                        "job_id": j.job_id,
                        "scan_type": j.scan_type,
                        "status": j.status.value if hasattr(j.status, "value") else str(j.status),
                        "created_at": j.created_at.isoformat() if j.created_at else None,
                        "started_at": j.started_at.isoformat() if j.started_at else None,
                        "completed_at": j.completed_at.isoformat() if j.completed_at else None,
                        "progress": j.progress,
                        "message": j.message,
                        "error": j.error,
                        "local_path": j.local_path,
                        "address": j.address,
                        "network": j.network,
                        "stages": j.stages,
                        "log_lines": j.log_lines[-200:],
                        "report": j.report,
                    }
            p.write_text(json.dumps(data), encoding="utf-8")
        except Exception:
            log.exception("failed to persist job cache to %s", p)

    def _load_persisted_jobs(self) -> None:
        try:
            p = self._cache_path()
            if not p.exists():
                return
            data = json.loads(p.read_text(encoding="utf-8"))
            for jid, d in data.items():
                if jid not in self._jobs:
                    st = d.get("status")
                    if st in ("pending", "running"):
                        st = "failed"
                        msg = "Server reloaded while job was in flight"
                    else:
                        msg = d.get("message")
                    job = ScanJob(
                        job_id=d["job_id"],
                        scan_type=d["scan_type"],
                        status=ScanStatus(st),
                        created_at=datetime.fromisoformat(d["created_at"]) if d.get("created_at") else datetime.now(),
                        started_at=datetime.fromisoformat(d["started_at"]) if d.get("started_at") else None,
                        completed_at=datetime.fromisoformat(d["completed_at"]) if d.get("completed_at") else None,
                        progress=d.get("progress", 0.0),
                        message=msg,
                        error=d.get("error"),
                        local_path=d.get("local_path"),
                        address=d.get("address"),
                        network=d.get("network"),
                        stages=d.get("stages") or [],
                        log_lines=d.get("log_lines") or [],
                        report=d.get("report"),
                    )
                    self._jobs[jid] = job
        except Exception:
            pass

    def start(self):
        """Start the job worker."""
        if self._running:
            return
        self._running = True
        # Worker will be started when first job is submitted
        log.info("Job manager started")

    def stop(self):
        """Stop the job worker and cancel all pending jobs."""
        self._running = False
        with self._lock:
            for job in self._jobs.values():
                if job.status in (ScanStatus.PENDING, ScanStatus.RUNNING):
                    job._cancel_event.set()
                    job.status = ScanStatus.CANCELLED
                    job.message = "Cancelled on shutdown"
        log.info("Job manager stopped")

    def submit_job(self, request: "ScanJobRequest") -> ScanJobResponse:
        """Submit a new scan job."""
        job_id = str(uuid.uuid4())
        job = ScanJob(
            job_id=job_id,
            scan_type=request.scan_type.value,
        )

        if request.scan_type.value == "local" and request.local:
            job.local_path = request.local.path
            job.local_run_static = bool(request.local.run_static_analysis)
            job.local_validate = bool(request.local.validate_project)
            job.local_run_tests = bool(request.local.run_tests)
            if request.local.metadata:
                job.metadata = request.local.metadata.model_dump(exclude_none=True)
        elif request.scan_type.value == "address" and request.address:
            job.address = request.address.address
            job.network = request.address.network.value
        elif request.scan_type.value == "ai_audit" and request.ai_audit:
            job.local_path = request.ai_audit.path
            job.ai_request = request.ai_audit.model_dump(exclude_none=True)
            if request.ai_audit.metadata:
                job.metadata = request.ai_audit.metadata.model_dump(exclude_none=True)
        elif request.scan_type.value == "retest" and request.retest:
            job.retest_request = request.retest.model_dump()
        else:
            raise ValueError(
                f"scan_type {request.scan_type.value!r} requires its matching request payload"
            )

        with self._lock:
            self._jobs[job_id] = job
        self._persist_jobs()

        # Schedule the job
        self._schedule_job(job)

        return ScanJobResponse(
            job_id=job_id,
            scan_type=ScanType(job.scan_type),
            status=job.status,
            created_at=job.created_at,
            progress=job.progress,
            message=job.message,
            local_path=job.local_path,
            address=job.address,
            network=Network(job.network) if job.network else None,
        )

    def _schedule_job(self, job: ScanJob):
        """Schedule a job for execution."""
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            # No running loop, create a new thread to run the job
            threading.Thread(target=self._run_job_sync, args=(job,), daemon=True).start()
            return

        # Schedule in the running loop
        asyncio.create_task(self._run_job_async(job))

    def _run_job_sync(self, job: ScanJob):
        """Run job in a synchronous context (separate thread)."""
        try:
            result = self._dispatch(job)
            with self._lock:
                if job.status == ScanStatus.CANCELLED:
                    job.result = result
                else:
                    job.status = ScanStatus.COMPLETED
                    job.completed_at = datetime.now()
                    job.progress = 1.0
                    if not str(job.message or "").startswith("AI audit inconclusive"):
                        job.message = "Completed"
                    job.result = result
            self._persist_jobs()
        except JobCancelled:
            with self._lock:
                job.status = ScanStatus.CANCELLED
                job.completed_at = datetime.now()
                job.message = "Cancelled by user"
            self._persist_jobs()
        except Exception as e:
            log.exception("Job failed")
            with self._lock:
                if job.status != ScanStatus.CANCELLED:
                    job.status = ScanStatus.FAILED
                    job.completed_at = datetime.now()
                    job.error = str(e)
                    job.message = f"Failed: {e}"
            self._persist_jobs()

    async def _run_job_async(self, job: ScanJob):
        """Run job asynchronously."""
        try:
            result = await asyncio.to_thread(self._dispatch, job)
            with self._lock:
                if job.status == ScanStatus.CANCELLED:
                    job.result = result
                else:
                    job.status = ScanStatus.COMPLETED
                    job.completed_at = datetime.now()
                    job.progress = 1.0
                    if not str(job.message or "").startswith("AI audit inconclusive"):
                        job.message = "Completed"
                    job.result = result
            self._persist_jobs()
        except JobCancelled:
            with self._lock:
                job.status = ScanStatus.CANCELLED
                job.completed_at = datetime.now()
                job.message = "Cancelled by user"
            self._persist_jobs()
        except Exception as e:
            log.exception("Job failed")
            with self._lock:
                if job.status != ScanStatus.CANCELLED:
                    job.status = ScanStatus.FAILED
                    job.completed_at = datetime.now()
                    job.error = str(e)
                    job.message = f"Failed: {e}"
            self._persist_jobs()

    def _dispatch(self, job: ScanJob) -> dict:
        if job.scan_type == "local":
            return self._run_local_scan(job)
        if job.scan_type == "address":
            return self._run_address_scan(job)
        if job.scan_type == "ai_audit":
            return self._run_ai_audit(job)
        if job.scan_type == "retest":
            return self._run_retest(job)
        raise ValueError(f"Unknown scan type: {job.scan_type}")

    # -- AI audit / retest -------------------------------------------------

    def _run_ai_audit(self, job: ScanJob) -> dict:
        """Run the staged AI audit agent for this job."""
        from auditor.ai_agent import PipelineAbort, run_ai_audit

        request = job.ai_request or {}
        job.status = ScanStatus.RUNNING
        job.started_at = datetime.now()
        job.progress = 0.05
        job.message = "AI audit running..."

        def _log(message: str) -> None:
            job.log_lines.append(message)

        settings_model, settings_endpoint = self._ollama_settings()
        try:
            report = run_ai_audit(
                request.get("path"),
                deep_tests=bool(request.get("deep_tests")),
                use_ai=bool(request.get("use_ai", True)),
                metadata=job.metadata,
                ollama_endpoint=settings_endpoint,
                ollama_model=settings_model,
                timeout_seconds=float(request.get("timeout_seconds") or 600),
                cancel_event=job._cancel_event,
                log=_log,
                stages=job.stages,
                compile_options=request.get("compile_options"),
            )
        except PipelineAbort as exc:
            if exc.reason == "cancelled":
                raise JobCancelled() from exc
            raise
        job.progress = 1.0
        if report.get("outcome") == "inconclusive":
            why = "; ".join(n for n in report.get("analyzer_notes", []) if "Slither" in n)[:300]
            job.message = f"AI audit inconclusive: static analysis did not analyze contracts ({why})"
        else:
            job.message = "AI audit completed"
        job.report = report
        return self._build_detail_from_record(report["scan_id"], report.get("source_hash") or "")

    @staticmethod
    def _execution_fields(execution: Optional[dict]) -> dict:
        """ScanDetail-shaped tool-execution fields (legacy scans → None)."""
        if not execution:
            return {
                "tool_runs": [],
                "validation": None,
                "scan_complete": None,
                "incomplete_reasons": [],
                "zero_findings_note": None,
            }
        return {
            "tool_runs": execution.get("tools") or [],
            "validation": execution.get("validation"),
            "scan_complete": execution.get("scan_complete"),
            "incomplete_reasons": execution.get("incomplete_reasons") or [],
            "zero_findings_note": execution.get("zero_findings_note"),
        }

    @staticmethod
    def _build_detail_from_record(scan_id: str, content_hash: str) -> dict:
        """Build a ScanDetail-shaped dict from the stored scan record."""
        history = ScanHistory(history_db_path())
        try:
            record = history.get_scan(scan_id) or {}
            stored = history.get_findings(scan_id)
        finally:
            history.close()

        findings_by_severity = {sev.value: 0 for sev in Severity}
        for fd in stored:
            sev = fd.get("severity")
            if sev in findings_by_severity:
                findings_by_severity[sev] += 1

        return {
            "scan_id": scan_id,
            "timestamp": record.get("timestamp") or datetime.now().isoformat(),
            "source_path": record.get("source_path") or "",
            "content_hash": content_hash or record.get("content_hash") or "",
            "config_fingerprint": record.get("config_fingerprint") or "ai-audit",
            "status": record.get("status") or "completed",
            "finding_count": len(stored),
            "findings_by_severity": findings_by_severity,
            "findings": stored,
            "finding_fingerprints": record.get("finding_fingerprints") or [],
            "finding_details": stored,
            "error_info": record.get("error_info"),
            "graph_snapshot": record.get("graph_snapshot"),
            **JobManager._execution_fields(record.get("execution")),
        }

    def _run_retest(self, job: ScanJob) -> Optional[dict]:
        """Re-analyze one stored finding and report if it persists."""
        from auditor.ai_agent import PipelineAbort, run_retest

        request = job.retest_request or {}
        job.status = ScanStatus.RUNNING
        job.started_at = datetime.now()
        job.progress = 0.1
        job.message = "Retest running..."

        def _log(message: str) -> None:
            job.log_lines.append(message)

        try:
            result = run_retest(
                request.get("scan_id", ""),
                request.get("fingerprint", ""),
                cancel_event=job._cancel_event,
                log=_log,
                stages=job.stages,
            )
        except PipelineAbort as exc:
            if exc.reason == "cancelled":
                raise JobCancelled() from exc
            raise
        job.progress = 1.0
        job.message = "Retest completed"
        # The retest payload is exposed via ``report``; returning it as
        # ``result`` would be coerced into an empty ScanDetail and fabricate
        # blank fields (finding_count 0, status "", ...) in API responses.
        job.report = result
        return None

    @staticmethod
    def _ollama_settings() -> tuple[str, str]:
        """Resolve the configured Ollama model/endpoint (no secrets involved)."""
        endpoint = "http://localhost:11434"
        model = "qwen3-8b-uncensored-16k:latest"
        try:
            import json as _json
            from pathlib import Path as _Path

            settings_file = _Path(__file__).resolve().parents[2] / "config" / "default.json"
            data = _json.loads(settings_file.read_text(encoding="utf-8"))
            ollama = data.get("ollama") or {}
            model = str(ollama.get("model") or model)
            endpoint = str(ollama.get("endpoint") or endpoint)
        except Exception:  # noqa: BLE001 - settings are optional
            pass
        return model, endpoint

    @staticmethod
    def _record_metadata(scan_id: str, metadata: Optional[dict]) -> None:
        """Persist scan-level metadata in the shared store (additive).

        Best-effort: metadata is enrichment, so a persistence failure is
        logged and never fails an otherwise valid scan.
        """
        if not metadata:
            return
        try:
            from auditor.finding_store import open_store, set_metadata

            store = open_store(history_db_path())
            try:
                set_metadata(store, scan_id, metadata)
            finally:
                store.close()
        except Exception:  # noqa: BLE001 - enrichment must not fail the job
            log.warning("could not persist metadata for scan %s", scan_id, exc_info=True)

    @staticmethod
    def _validated_for_history(findings: list) -> list:
        """Drop findings that fail their own validation before persistence.

        The API response drops these (see _build_scan_detail); history must
        agree so finding_count is identical whether it comes from the job
        result or from the stored record. Delegates to the shared
        ``auditor.model.validated_findings`` contract used by the CLI too.
        """
        from auditor.model import validated_findings

        return validated_findings(findings)

    @staticmethod
    def _record_started(source_path: "Path | str", config_fingerprint: str, content_hash: str) -> str:
        """Insert a STARTED history row before analysis runs.

        Recording first means a mid-analysis crash still leaves a history
        trace that ``_mark_scan`` can move to a terminal status.
        """
        history = ScanHistory(history_db_path())
        try:
            # scan_history's own ScanStatus default (STARTED) applies — the
            # dashboard job enum has no STARTED member.
            return history.record_scan(
                source_path=source_path,
                config_fingerprint=config_fingerprint,
                content_hash=content_hash,
            )
        finally:
            history.close()

    @staticmethod
    def _mark_scan(scan_id: str, status: str, error_info: str) -> None:
        """Best-effort terminal status write; never masks the original error.

        ``status`` is a scan-history status string (``"failed"`` or
        ``"interrupted"``) — the dashboard job ScanStatus enum deliberately
        has no member for history rows. ``only_if_started`` keeps a
        completed scan from ever being overwritten by a late failure.
        The message is redacted before it hits the database.
        """
        from auditor.analysis.slither_runner import redact

        error_info = redact(str(error_info))
        try:
            history = ScanHistory(history_db_path())
            try:
                if status == "interrupted":
                    history.mark_interrupted(scan_id, error_info, only_if_started=True)
                else:
                    history.mark_failed(scan_id, error_info, only_if_started=True)
            finally:
                history.close()
        except Exception:  # noqa: BLE001 - keep the original exception primary
            log.warning(
                "could not persist terminal status %s for scan %s",
                status,
                scan_id,
                exc_info=True,
            )

    @staticmethod
    def _stage(job: ScanJob, name: str, status: str, message: str) -> None:
        """Append one per-tool stage entry for live progress display."""
        from auditor.analysis.slither_runner import redact, truncate

        job.stages.append(
            {"name": name, "status": status, "message": truncate(redact(message or ""), 300)}
        )

    @staticmethod
    def _collect_static_findings(source_files: list) -> tuple[list, list, object]:
        """Run the three analyzers over ONE shared Slither execution."""
        from auditor.analysis.access_control import analyze as access_control_analyze
        from auditor.analysis.base import AnalysisContext
        from auditor.analysis.reentrancy import analyze as reentrancy_analyze
        from auditor.analysis.slither_generic import analyze as generic_analyze
        from auditor.analysis.oracle_staleness import analyze as oracle_analyze
        from auditor.analysis.erc4626_inflation import analyze as erc4626_analyze
        from auditor.analysis.pool_accounting import analyze as pool_analyze
        from auditor.analysis.honeypot import analyze as honeypot_analyze
        from auditor.analysis.privileged_auth import analyze as privileged_auth_analyze
        from auditor.triage import apply_to_pipeline

        context = AnalysisContext()
        context.source_files = list(source_files)

        outcomes = [
            reentrancy_analyze(context),
            access_control_analyze(context),
            generic_analyze(context),
            oracle_analyze(context),
            erc4626_analyze(context),
            pool_analyze(context),
            honeypot_analyze(context),
            privileged_auth_analyze(context),
        ]
        findings: list = []
        notes: list[str] = []
        for outcome in outcomes:
            findings.extend(outcome.findings or [])
            for note in outcome.notes or []:
                if note and note not in notes:
                    notes.append(note)
        run_result = getattr(context, "_slither_run", None)
        # Phase 19: library-code / known-benign suppression (reasons kept in notes).
        tri = apply_to_pipeline(_dedupe_findings(findings), list(source_files), None, None, notes.append)
        for f, rec in tri.suppressed:
            notes.append(f"suppressed ({rec.reason}: {rec.rule}): {getattr(f, 'title', '')}")
        return tri.kept, notes, run_result

    @staticmethod
    def _build_execution(
        tools: list,
        validation: dict,
        notes: list,
        static_requested: bool,
        validate_requested: bool,
        tests_requested: bool,
    ) -> dict:
        """Assemble the persisted tool-execution record for one scan."""
        from auditor.analysis.slither_runner import redact

        incomplete = [
            f"{t.label}: {redact(t.error or t.message)}"
            for t in tools
            if t.requested
            and t.kind in ("static-analysis", "validation")
            and t.status in _TOOL_FAIL_STATUSES
        ]
        scan_complete = not incomplete
        validation_ran = any(
            t.requested and t.kind == "validation" and t.status == "completed"
            for t in tools
        )
        clean_notes = []
        for n in notes:
            clean = redact(str(n)).strip()
            if clean and clean not in clean_notes:
                clean_notes.append(clean)
        return {
            "tools": [t.to_dict() for t in tools],
            "validation": validation or None,
            "scan_complete": scan_complete,
            "incomplete_reasons": incomplete,
            "zero_findings_note": None,
            "notes": clean_notes,
            "static_analysis_requested": static_requested,
            "foundry_validation_requested": validate_requested,
            "foundry_tests_requested": tests_requested,
        }

    def _run_local_scan(self, job: ScanJob) -> dict:
        """Run a local directory/file scan with explicit tool selection."""
        if not job.local_path:
            raise ValueError("No local path specified")

        job.status = ScanStatus.RUNNING
        job.started_at = datetime.now()
        job.progress = 0.1
        job.message = "Scanning local files..."

        path = Path(job.local_path)
        if not path.exists():
            raise FileNotFoundError(f"Path does not exist: {job.local_path}")

        # Find all .sol files
        sol_files = sorted(path.rglob("*.sol")) if path.is_dir() else ([path] if path.suffix == ".sol" else [])
        if not sol_files:
            raise ValueError(f"No .sol files found in {job.local_path}")

        job.progress = 0.25
        job.message = f"Found {len(sol_files)} Solidity file(s)..."

        # Compute content hash. A NUL separator between files keeps
        # ["ab","c"] from colliding with ["a","bc"] — a single file hashes
        # to exactly its own bytes, so existing single-file hashes hold.
        parts: list[bytes] = []
        for sf in sol_files:
            if sf.is_file():
                with open(sf, "rb") as f:
                    parts.append(f.read())
        combined = b"\x00".join(parts)

        if not combined:
            raise ValueError("No readable .sol file content")

        content_hash = hashlib.sha256(combined).hexdigest()

        # Record first: a mid-analysis crash must leave a history trace that
        # _mark_scan can move to a terminal status (started -> failed or
        # interrupted). Pre-analysis failures (bad path, no files) still
        # raise before any row exists.
        scan_id = self._record_started(path, "dashboard-local", content_hash)
        try:
            return self._run_local_scan_analyzed(job, path, sol_files, content_hash, scan_id)
        except JobCancelled:
            self._mark_scan(scan_id, "interrupted", "cancelled by user")
            raise
        except Exception as exc:
            self._mark_scan(scan_id, "failed", str(exc))
            raise

    def _run_local_scan_analyzed(
        self, job: ScanJob, path: Path, sol_files: list, content_hash: str, scan_id: str
    ) -> dict:
        """Run tool stages for an already-recorded local scan and finalize it.

        ``scan_id`` was inserted with status STARTED by the caller. On
        success this writes the execution record and marks the row
        completed; the caller marks failed/interrupted on exceptions.
        """
        from auditor.analysis.slither_runner import probe_solc, slither_tool_run
        from auditor.foundry import (
            not_requested_tool_run,
            run_forge_build,
            run_forge_test,
        )

        static_requested = bool(job.local_run_static)
        validate_requested = bool(job.local_validate)
        tests_requested = bool(job.local_run_tests)

        tools: list = []
        notes: list[str] = []
        findings: list = []
        validation: dict = {}

        solc_run = probe_solc()
        tools.append(solc_run)
        self._stage(job, "solc", solc_run.status, solc_run.message or solc_run.error or "")
        if job._cancel_event.is_set():
            raise JobCancelled()

        if static_requested:
            job.progress = 0.45
            job.message = "Running Slither static analysis..."
            findings, notes, slither_run = self._collect_static_findings(sol_files)
            if slither_run is not None:
                tools.append(slither_tool_run(slither_run, findings))
            else:
                tools.append(
                    not_requested_tool_run("slither", "Slither (static analysis)")
                )
                tools[-1].status = "skipped"
                tools[-1].requested = True
                tools[-1].message = (
                    "Slither execution was not observed (analysis modules ran "
                    "without the shared runner)"
                )
            stage = tools[-1]
            self._stage(job, "slither", stage.status, stage.message or stage.error or "")
        else:
            tools.append(
                not_requested_tool_run("slither", "Slither (static analysis)")
            )
            self._stage(
                job, "slither", "not_requested", "Static analysis not selected"
            )

        if job._cancel_event.is_set():
            raise JobCancelled()

        if validate_requested or tests_requested:
            from auditor.analysis.slither_runner import find_foundry_root

            project_root = find_foundry_root(path)
            base = project_root or (path if path.is_dir() else path.parent)
            if validate_requested:
                job.progress = 0.6
                job.message = "Running forge build (validation)..."
                build_run = run_forge_build(base)
                validation["forge_build"] = build_run.to_dict()
                tools.append(build_run)
                self._stage(
                    job, "forge build", build_run.status, build_run.error or build_run.message
                )
            else:
                tools.append(not_requested_tool_run("forge-build", "Foundry build (forge build)"))
            if tests_requested:
                job.progress = 0.8
                job.message = "Running forge test (validation)..."
                test_run = run_forge_test(base)
                validation["forge_test"] = test_run.to_dict()
                tools.append(test_run)
                self._stage(
                    job, "forge test", test_run.status, test_run.error or test_run.message
                )
            else:
                tools.append(not_requested_tool_run("forge-test", "Foundry tests (forge test)"))
        else:
            # Static-only mode: validation tools are visible as not selected
            # and NO build/test subprocess is started.
            tools.append(not_requested_tool_run("forge-build", "Foundry build (forge build)"))
            tools.append(not_requested_tool_run("forge-test", "Foundry tests (forge test)"))

        if job._cancel_event.is_set():
            raise JobCancelled()

        job.progress = 0.9
        job.message = "Recording scan..."

        validated = self._validated_for_history(findings)
        execution = self._build_execution(
            tools, validation, notes, static_requested, validate_requested, tests_requested
        )
        if not validated:
            if findings:
                # Tools surfaced findings but every one failed validation;
                # a plain "No findings detected" note would be untrue.
                execution["zero_findings_note"] = (
                    f"{len(findings)} finding(s) surfaced by the tools failed "
                    "validation and were not recorded (details in the server "
                    "log). This is not a clean result."
                )
            else:
                execution["zero_findings_note"] = _zero_findings_note(
                    static_requested,
                    any(t.status == "completed" and t.kind == "validation" for t in tools),
                    bool(execution["scan_complete"]),
                )

        # Finalize the STARTED history row: execution first, then completed,
        # so a persistence failure can never overwrite a completed status.
        history = ScanHistory(history_db_path())
        try:
            history.set_execution(scan_id, execution)
            history.mark_completed(scan_id, validated)
        finally:
            history.close()
        self._record_metadata(scan_id, job.metadata)

        # Build response
        return self._build_scan_detail(
            path, content_hash, findings, scan_id, execution=execution
        )

    def _run_address_scan(self, job: ScanJob) -> dict:
        """Run a contract address scan via Etherscan."""
        if not job.address:
            raise ValueError("No address specified")

        job.status = ScanStatus.RUNNING
        job.started_at = datetime.now()
        job.progress = 0.1
        job.message = "Validating address..."

        from auditor.target import validate_address

        va_result = validate_address(job.address)
        if not va_result.is_valid:
            raise ValueError(f"Invalid address: {job.address}: {va_result.reason}")

        job.progress = 0.2
        job.message = "Retrieving verified source from Etherscan..."

        return self._run_address_scan_direct(job)

    def _run_address_scan_direct(self, job: ScanJob) -> dict:
        """Run address scan logic directly without CLI."""
        import json as _json
        import os
        import tempfile
        import urllib.error
        import urllib.request

        api_key = os.environ.get("ETHERSCAN_API_KEY")
        if not api_key:
            raise ValueError("ETHERSCAN_API_KEY not set")

        base_url = "https://api.etherscan.io/v2/api"
        module = "contract"
        action = "getsourcecode"
        address_norm = job.address
        chainid = "1"

        url = f"{base_url}?module=contract&action=getsourcecode&address={address_norm}&apikey={api_key}&chainid={chainid}"

        def _redact(text: str) -> str:
            # The API key rides in the query string; remote error bodies can
            # echo the request URI. Never let it reach job records or logs.
            return text.replace(api_key, "***")

        job.progress = 0.3
        job.message = "Fetching source from Etherscan..."

        try:
            req = urllib.request.Request(url, headers={"User-Agent": "contract-auditor/1.0"})
            with urllib.request.urlopen(req, timeout=30) as resp:
                body = resp.read().decode("utf-8")
            data = _json.loads(body)
        except urllib.error.HTTPError as e:
            raise RuntimeError(f"Etherscan HTTP {e.code}: {_redact(e.read().decode('utf-8', errors='replace'))}")
        except urllib.error.URLError as e:
            raise RuntimeError(f"Etherscan connection error: {_redact(str(e))}")

        if data.get("status") != "1":
            msg = data.get("message", "unknown error")
            result_data = data.get("result", [])
            if isinstance(result_data, list) and len(result_data) == 0:
                raise RuntimeError(f"Contract not verified: {msg}")
            raise RuntimeError(f"Etherscan API error: {msg}")

        source_code_list = data.get("result", [])
        if not source_code_list or len(source_code_list) == 0:
            raise RuntimeError("No source code returned")

        primary_source = source_code_list[0].get("SourceCode", "")
        if not primary_source:
            raise RuntimeError(
                f"Contract not verified: no verified source returned for {job.address}"
            )

        job.progress = 0.5
        job.message = "Analyzing retrieved source..."

        content_hash = hashlib.sha256(primary_source.encode("utf-8")).hexdigest()

        # Write source to temp file
        with tempfile.NamedTemporaryFile(mode="w", suffix=".sol", delete=False, encoding="utf-8") as tmp:
            tmp.write(primary_source)
            tmp_path = tmp.name

        # The record goes INSIDE the try so the temp file is unlinked even
        # if recording itself raises; _mark_scan is guarded on scan_id.
        scan_id: Optional[str] = None

        try:
            # Record first: analysis failures below must leave a history trace.
            # Stable display path: the real source lives in an unlink-on-
            # completion temp file; recording that path in history would
            # surface a dead /var/folders/... path in every later view.
            # Plain string (not Path) so the // in the scheme survives.
            display_path = f"etherscan://{job.address}"
            scan_id = self._record_started(display_path, "dashboard-address", content_hash)

            from auditor.analysis.slither_runner import probe_solc, slither_tool_run
            from auditor.foundry import not_requested_tool_run

            findings, notes, slither_run = self._collect_static_findings([Path(tmp_path)])

            # Provenance: the retrieved source itself is a FACT.
            source_evidence = EvidenceItem(
                source="etherscan",
                artifact_type="verified_source",
                excerpt=primary_source[:200],
                epistemic=Epistemic.FACT,
                content_hash=content_hash,
            )
            for f in findings:
                f.add_evidence(source_evidence)

            solc_run = probe_solc()
            tools: list = [solc_run]
            if slither_run is not None:
                tools.append(slither_tool_run(slither_run, findings))
            else:
                placeholder = not_requested_tool_run("slither", "Slither (static analysis)")
                placeholder.status = "skipped"
                placeholder.requested = True
                placeholder.message = (
                    "Slither execution was not observed (analysis modules ran "
                    "without the shared runner)"
                )
                tools.append(placeholder)
            forge_build_row = not_requested_tool_run(
                "forge-build", "Foundry build (forge build)"
            )
            forge_build_row.message = "Not applicable to address scans (no local project)."
            forge_test_row = not_requested_tool_run(
                "forge-test", "Foundry tests (forge test)"
            )
            forge_test_row.message = "Not applicable to address scans (no local project)."
            tools.extend([forge_build_row, forge_test_row])

            validated = self._validated_for_history(findings)
            execution = self._build_execution(
                tools, {}, notes, True, False, False
            )
            if not validated:
                if findings:
                    execution["zero_findings_note"] = (
                        f"{len(findings)} finding(s) surfaced by the tools "
                        "failed validation and were not recorded (details in "
                        "the server log). This is not a clean result."
                    )
                else:
                    execution["zero_findings_note"] = _zero_findings_note(
                        True, False, bool(execution["scan_complete"])
                    )

            # Finalize the STARTED history row: execution first, then
            # completed, so a persistence failure can never overwrite a
            # completed status.
            history = ScanHistory(history_db_path())
            try:
                history.set_execution(scan_id, execution)
                history.mark_completed(scan_id, validated)
            finally:
                history.close()
            meta = dict(job.metadata or {})
            if job.network:
                meta.setdefault("chain", str(job.network))
            self._record_metadata(scan_id, meta)

            return self._build_scan_detail(
                display_path, content_hash, findings, scan_id, job.address,
                execution=execution,
            )
        except JobCancelled:
            if scan_id:
                self._mark_scan(scan_id, "interrupted", "cancelled by user")
            raise
        except Exception as exc:
            if scan_id:
                self._mark_scan(scan_id, "failed", str(exc))
            raise
        finally:
            try:
                os.unlink(tmp_path)
            except Exception:
                pass

    def _build_scan_detail(
        self,
        source_path: "Path | str",
        content_hash: str,
        findings: list,
        scan_id: str,
        address: Optional[str] = None,
        execution: Optional[dict] = None,
    ) -> dict:
        """Build a detailed scan response shaped like ScanDetail."""
        history = ScanHistory(history_db_path())
        try:
            record = history.get_scan(scan_id) or {}
        finally:
            history.close()

        # Findings that fail validation are dropped, never silently kept.
        findings_resp: list[dict] = []
        for f in findings:
            try:
                f.validate()
                findings_resp.append(f.to_dict())
            except Exception as e:  # noqa: BLE001 - one bad finding must not sink the scan
                log.warning("Finding dropped (validation failed): %s", e)

        findings_by_severity = {sev.value: 0 for sev in Severity}
        for fd in findings_resp:
            sev = fd.get("severity")
            if sev in findings_by_severity:
                findings_by_severity[sev] += 1

        return {
            "scan_id": scan_id,
            "timestamp": record.get("timestamp") or datetime.now().isoformat(),
            "source_path": str(source_path),
            "content_hash": content_hash,
            "config_fingerprint": record.get("config_fingerprint") or "dashboard",
            "status": record.get("status") or "completed",
            "finding_count": len(findings_resp),
            "findings_by_severity": findings_by_severity,
            "findings": findings_resp,
            "finding_fingerprints": record.get("finding_fingerprints") or [],
            "finding_details": findings_resp,
            "error_info": record.get("error_info"),
            "graph_snapshot": record.get("graph_snapshot"),
            **self._execution_fields(execution),
        }

    def get_job(self, job_id: str) -> Optional[ScanJobResponse]:
        """Get job status."""
        with self._lock:
            job = self._jobs.get(job_id)
            if not job:
                return None
            return self._job_to_response(job)

    def list_jobs(self, limit: int = 50) -> list[ScanJobResponse]:
        """List recent jobs."""
        with self._lock:
            jobs = sorted(self._jobs.values(), key=lambda j: j.created_at, reverse=True)[:limit]
            return [self._job_to_response(j) for j in jobs]

    def cancel_job(self, job_id: str) -> bool:
        """Cancel a pending/running job."""
        with self._lock:
            job = self._jobs.get(job_id)
            if not job:
                return False
            if job.status in (ScanStatus.PENDING, ScanStatus.RUNNING):
                job._cancel_event.set()
                job.status = ScanStatus.CANCELLED
                job.message = "Cancelled by user"
                self._persist_jobs()
                return True
            return False

    def _job_to_response(self, job: ScanJob) -> ScanJobResponse:
        elapsed: Optional[float] = None
        if job.started_at:
            end = job.completed_at or datetime.now()
            elapsed = round((end - job.started_at).total_seconds(), 3)
        return ScanJobResponse(
            job_id=job.job_id,
            scan_type=ScanType(job.scan_type),
            status=job.status,
            created_at=job.created_at,
            started_at=job.started_at,
            completed_at=job.completed_at,
            progress=job.progress,
            message=job.message,
            result=job.result,
            error=job.error,
            local_path=job.local_path,
            address=job.address,
            network=Network(job.network) if job.network else None,
            stages=list(job.stages),
            log=list(job.log_lines[-100:]),
            elapsed_seconds=elapsed,
            report=job.report,
        )


# Global job manager instance
job_manager = JobManager()