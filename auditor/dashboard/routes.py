"""API and web routes for the Contract Auditor Dashboard."""
from __future__ import annotations

import json
import logging
import os
import sqlite3
import subprocess
import threading
import time
from pathlib import Path
from typing import Optional, Any

from fastapi import APIRouter, HTTPException, Request, Response
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

from auditor import benchmark_store
from auditor.cli import _observe, _status_payload
from auditor.dashboard.jobs import job_manager
from auditor.dashboard.models import (
    AIAuditRequest,
    ApplyPatchRequest,
    BenchmarkRunDetail,
    BountyCheckRequest,
    FindingStateChangeRequest,
    OverviewStats,
    ProposePatchRequest,
    RetestRequest,
    ScanDetail,
    ScanHistoryResponse,
    ScanJobRequest,
    ScanJobResponse,
    ScanMetadataRequest,
    ScanSummary,
    StoredFinding,
    ToolchainResponse,
)
from auditor.dashboard.paths import history_db_path
from auditor.dashboard.rendering import templates
from auditor.scan_history import ScanHistory
from auditor.settings import load_settings
from auditor.target import validate_address

log = logging.getLogger("contract_auditor.dashboard.routes")

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_hunt_run_lock = threading.RLock()
_hunt_run: dict[str, Any] = {
    "status": "idle", "stage": "idle", "message": "No dashboard discovery run yet",
    "started_at": None, "finished_at": None, "returncode": None, "fuzz": None,
    "heartbeat_at": None, "last_event": None, "events": [],
}
_HUNT_RUN_KEY = "ethereum-discovery-once"


def _save_hunt_run(snapshot: dict[str, Any]) -> None:
    """Persist one-shot dashboard progress alongside continuous worker state."""
    try:
        from auditor.monitor import default_monitor_db_path
        path = default_monitor_db_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(path), timeout=3.0)
        conn.execute("PRAGMA busy_timeout=3000")
        conn.execute(
            "CREATE TABLE IF NOT EXISTS dashboard_worker_state ("
            "worker TEXT PRIMARY KEY, payload_json TEXT NOT NULL, updated_at REAL NOT NULL)"
        )
        conn.execute(
            "INSERT INTO dashboard_worker_state(worker,payload_json,updated_at) VALUES(?,?,?) "
            "ON CONFLICT(worker) DO UPDATE SET payload_json=excluded.payload_json,updated_at=excluded.updated_at",
            (_HUNT_RUN_KEY, json.dumps(snapshot, sort_keys=True, default=str), time.time()),
        )
        conn.commit()
        conn.close()
    except (OSError, sqlite3.Error) as exc:
        log.info("could not persist one-shot hunt status: %s", type(exc).__name__)


def _set_hunt_run(**changes: Any) -> None:
    with _hunt_run_lock:
        previous_stage = _hunt_run.get("stage")
        previous_status = _hunt_run.get("status")
        previous_message = _hunt_run.get("message")
        _hunt_run.update(changes)
        _hunt_run["heartbeat_at"] = time.time()
        event = changes.get("last_event")
        changed = (previous_stage != _hunt_run.get("stage")
                   or previous_status != _hunt_run.get("status")
                   or previous_message != _hunt_run.get("message"))
        if event or changed:
            events = list(_hunt_run.get("events") or [])
            events.append({"at": _hunt_run["heartbeat_at"],
                           "stage": _hunt_run.get("stage"),
                           "message": str(event or _hunt_run.get("message") or "")[:500]})
            _hunt_run["events"] = events[-100:]
            _hunt_run["last_event"] = str(event or _hunt_run.get("message") or "")[:500]
        snapshot = json.loads(json.dumps(_hunt_run, default=str))
    _save_hunt_run(snapshot)


def _hunt_run_payload() -> dict[str, Any]:
    with _hunt_run_lock:
        current = json.loads(json.dumps(_hunt_run, default=str))
    if current.get("status") == "idle":
        try:
            from auditor.monitor import default_monitor_db_path
            path = default_monitor_db_path()
            if path.exists():
                conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=1.0)
                row = conn.execute(
                    "SELECT payload_json FROM dashboard_worker_state WHERE worker=?",
                    (_HUNT_RUN_KEY,),
                ).fetchone()
                conn.close()
                if row:
                    saved = json.loads(row[0])
                    if isinstance(saved, dict):
                        current = saved
        except (OSError, sqlite3.Error, ValueError):
            pass
    # Keep the existing one-shot status/pipeline indicator aligned with the
    # continuous workers whenever they are actively processing the chain.
    try:
        from auditor.discovery_service import status as live_status
        live = live_status(include_metrics=False)
        if live.get("status") in {"starting", "running", "degraded"}:
            return {
                "status": "running", "stage": live.get("stage") or "discover",
                "message": live.get("message") or "Continuous Ethereum discovery is active",
                "started_at": live.get("started_at"), "finished_at": None,
                "returncode": None, "fuzz": None, "heartbeat_at": live.get("heartbeat_at"),
                "last_event": (live.get("events") or [{}])[-1].get("message"),
                "events": live.get("events") or [],
            }
    except Exception:  # noqa: BLE001 - status aggregation must not break the dashboard
        pass
    if current.get("status") in {"starting", "running"}:
        heartbeat = float(current.get("heartbeat_at") or 0)
        if time.time() - heartbeat > 90:
            current["status"] = "stale"
            current["message"] = "No progress heartbeat recently; check the dashboard server log."
    return {k: current.get(k) for k in
            ("status", "stage", "message", "started_at", "finished_at", "returncode",
             "fuzz", "heartbeat_at", "last_event", "events")}


def _recent_external_audit_activity() -> dict[str, bool]:
    """Best-effort DB signal to avoid overlapping the user's CLI auditors."""
    from auditor.monitor import default_monitor_db_path

    db = default_monitor_db_path()
    state = {"monitor": False, "hunt": False}
    if not db.exists():
        return state
    try:
        conn = sqlite3.connect(f"file:{db}?mode=ro", uri=True, timeout=1.0)
        tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        now = time.time()
        if "monitor_scans" in tables:
            cols = {r[1] for r in conn.execute("PRAGMA table_info(monitor_scans)")}
            if "origin" in cols:
                state["hunt"] = bool(conn.execute(
                    "SELECT 1 FROM monitor_scans WHERE status='running' AND origin='hunt' LIMIT 1"
                ).fetchone())
        if "hunt_runs" in tables:
            row = conn.execute("SELECT MAX(at) FROM hunt_runs WHERE network='ethereum'").fetchone()
            state["hunt"] = state["hunt"] or bool(row and row[0] and now - float(row[0]) < 180)
        if "monitor_polls" in tables:
            row = conn.execute("SELECT MAX(at) FROM monitor_polls WHERE network='ethereum'").fetchone()
            state["monitor"] = bool(row and row[0] and now - float(row[0]) < 90)
        conn.close()
    except sqlite3.Error:
        pass
    return state

web_router = APIRouter()
api_router = APIRouter()


# ---------------------------------------------------------------------------
# Web pages
# ---------------------------------------------------------------------------

@web_router.get("/", response_class=HTMLResponse)
async def dashboard_home(request: Request) -> HTMLResponse:
    return templates.TemplateResponse(
        request, "index.html", {"title": "Contract Auditor Dashboard"}
    )


@web_router.get("/scan", response_class=HTMLResponse)
async def scan_page(request: Request) -> HTMLResponse:
    return templates.TemplateResponse(request, "scan.html", {"title": "New Scan"})


@web_router.get("/history", response_class=HTMLResponse)
async def history_page(request: Request) -> HTMLResponse:
    return templates.TemplateResponse(request, "history.html", {"title": "Scan History"})


@web_router.get("/scan/{scan_id}", response_class=HTMLResponse)
async def scan_detail_page(request: Request, scan_id: str) -> HTMLResponse:
    return templates.TemplateResponse(
        request,
        "detail.html",
        {"title": f"Scan {scan_id[:8]}...", "scan_id": scan_id},
    )


@web_router.get("/jobs/{job_id}", response_class=HTMLResponse)
async def job_detail_page(request: Request, job_id: str) -> HTMLResponse:
    return templates.TemplateResponse(
        request,
        "job.html",
        {"title": f"Job {job_id[:8]}...", "job_id": job_id},
    )


@web_router.get("/tools", response_class=HTMLResponse)
async def tools_page(request: Request) -> HTMLResponse:
    return templates.TemplateResponse(request, "tools.html", {"title": "Tool Status"})


@web_router.get("/findings", response_class=HTMLResponse)
async def findings_page(request: Request) -> HTMLResponse:
    return templates.TemplateResponse(request, "findings.html", {"title": "Findings"})


@web_router.get("/benchmark", response_class=HTMLResponse)
async def benchmark_page(request: Request) -> HTMLResponse:
    return templates.TemplateResponse(request, "benchmark.html", {"title": "Benchmark"})


@web_router.get("/monitor", response_class=HTMLResponse)
async def monitor_page(request: Request) -> HTMLResponse:
    """Phase 18: live deployment-monitor page (polls read-only JSON)."""
    return templates.TemplateResponse(request, "monitor.html", {"title": "Live Monitor"})


@web_router.get("/hunt", response_class=HTMLResponse)
async def hunt_page(request: Request) -> HTMLResponse:
    """Phase 20: proactive high-value target hunt page (polls read-only JSON)."""
    return templates.TemplateResponse(request, "hunt.html", {"title": "Hunt"})


@web_router.get("/monitor/source/{row_id}", response_class=HTMLResponse)
async def monitor_source_page(request: Request, row_id: int, file: str = "") -> HTMLResponse:
    """Read-only, autoescaped view of cached verified source."""
    from auditor import monitor_view

    view = monitor_view.source_view(row_id, file or None)
    if view is None:
        raise HTTPException(status_code=404, detail="source not found")
    return templates.TemplateResponse(
        request, "monitor_source.html", {"title": "Contract Source", "view": view})


@web_router.get("/investigate/{scan_id}", response_class=HTMLResponse)
async def investigate_page(request: Request, scan_id: str, fp: str = "") -> HTMLResponse:
    return templates.TemplateResponse(
        request,
        "investigate.html",
        {
            "title": "Investigate finding",
            "scan_id": scan_id,
            "fingerprint": fp,
        },
    )


@web_router.get("/exploits", response_class=HTMLResponse)
async def exploits_page(request: Request) -> HTMLResponse:
    """Financial Exploits tab: second-stage finrisk reviews, per-verdict
    views, and the persisted-evidence exposure roll-up. Dedicated page —
    NOT the findings listing's financial-risk filter."""
    return templates.TemplateResponse(
        request, "exploits.html", {"title": "Financial Exploits"})


# ---------------------------------------------------------------------------
# API: overview / history
# ---------------------------------------------------------------------------

def _summary_of(history: ScanHistory, row: dict[str, Any]) -> ScanSummary:
    """Build a ScanSummary, enriching a bare history row from the full record."""
    record = history.get_scan(row["scan_id"]) or {}
    details = history.get_findings(row["scan_id"])
    by_severity: dict[str, int] = {}
    for d in details:
        sev = d.get("severity")
        if sev:
            by_severity[sev] = by_severity.get(sev, 0) + 1

    return ScanSummary(
        scan_id=row["scan_id"],
        timestamp=row.get("timestamp") or record.get("timestamp", ""),
        source_path=row.get("source_path") or record.get("source_path", ""),
        content_hash=row.get("content_hash") or record.get("content_hash", ""),
        config_fingerprint=record.get("config_fingerprint", ""),
        status=row.get("status") or record.get("status", ""),
        finding_count=len(details),
        findings_by_severity=by_severity,
        error_info=record.get("error_info"),
    )


@api_router.get("/overview", response_model=OverviewStats)
async def get_overview() -> OverviewStats:
    history = ScanHistory(history_db_path())
    try:
        # All records: a fixed cap (was 1000) made the totals silently wrong
        # once history grew past it.
        n = history.conn.execute("SELECT COUNT(*) FROM scan_records").fetchone()[0]
        rows = history.get_scan_history(limit=max(1, int(n)))
        summaries = [_summary_of(history, r) for r in rows]
    finally:
        history.close()

    completed = [s for s in summaries if s.status == "completed"]
    failed = [s for s in summaries if s.status == "failed"]

    total_findings = sum(s.finding_count for s in summaries)
    findings_by_severity: dict[str, int] = {}
    for s in summaries:
        for sev, n in s.findings_by_severity.items():
            findings_by_severity[sev] = findings_by_severity.get(sev, 0) + n

    return OverviewStats(
        total_scans=len(summaries),
        completed_scans=len(completed),
        failed_scans=len(failed),
        total_findings=total_findings,
        findings_by_severity=findings_by_severity,
        recent_scans=summaries[:5],
    )


@api_router.get("/disk-pressure")
async def get_disk_pressure() -> dict[str, Any]:
    """Disk pressure: heavy paused/resumed, last free GiB, check time, reason."""
    from auditor.disk_pressure import get_controller
    return get_controller().status()


@api_router.get("/monitor/status")
async def get_monitor_status(network: str = "ethereum", recent: int = 20) -> dict[str, Any]:
    """Phase 17: read-only monitor cursor/queue and recent alerts."""
    from auditor.monitor import NETWORKS, monitor_status

    if network not in NETWORKS:
        raise HTTPException(status_code=400, detail=f"unsupported network: {network}")
    return monitor_status(network, recent=max(1, min(int(recent), 200)))


@api_router.get("/monitor/live")
async def get_monitor_live(network: str = "ethereum", recent: int = 25, sort: str = "recent") -> dict[str, Any]:
    """Phase 18: counters, now-scanning (with ETA estimate), recent scans/alerts."""
    from auditor import monitor_view

    if not monitor_view.supported(network):
        raise HTTPException(status_code=400, detail=f"unsupported network: {network}")
    out = monitor_view.live(network, recent=max(1, min(int(recent), 200)),
                            sort=sort if sort in monitor_view.SORTS else "recent")
    try:
        from auditor.disk_pressure import get_controller
        out["disk_pressure"] = get_controller().status()
    except Exception as _dp_exc:  # noqa: BLE001
        out["disk_pressure"] = {"error": type(_dp_exc).__name__}
    return out


@api_router.get("/monitor/scans/{row_id}")
async def get_monitor_scan(row_id: int) -> dict[str, Any]:
    from auditor import monitor_view

    detail = monitor_view.scan_detail(row_id)
    if detail is None:
        raise HTTPException(status_code=404, detail="monitor scan not found")
    return detail


@api_router.get("/monitor/source/{row_id}")
async def get_monitor_source(row_id: int, file: str = "") -> dict[str, Any]:
    """Raw cached source as JSON text; the page renders it with textContent."""
    from auditor import monitor_view

    view = monitor_view.source_view(row_id, file or None)
    if view is None:
        raise HTTPException(status_code=404, detail="source not found")
    return view


@api_router.get("/hunt/live")
async def get_hunt_live(network: str = "ethereum", top: int = 50, sort: str = "priority") -> dict[str, Any]:
    """Phase 20: read-only hunt candidates + counters (Detroit 'today')."""
    import sqlite3
    import time
    from auditor.hunt import hunt_overview
    from auditor.monitor import NETWORKS, default_monitor_db_path

    if network not in NETWORKS:
        raise HTTPException(status_code=400, detail="unsupported network")
    sort = sort if sort in ("priority", "tvl", "recent", "loss") else "priority"
    db = default_monitor_db_path()
    if not db.exists():
        return {"network": network, "candidates": [], "counters": {}, "db": "absent",
                "generated_at": time.time(), "timezone": "America/Detroit"}
    # genuinely read-only (matches the documented contract); mode=ro keeps a
    # dashboard poller from ever becoming a writer on the contended store.
    # A lock window surfaces as a bounded-wait then an honest 503, not a 500.
    conn = sqlite3.connect(f"file:{db}?mode=ro", uri=True, timeout=10)
    conn.row_factory = sqlite3.Row
    try:
        from zoneinfo import ZoneInfo
        import datetime
        tz = ZoneInfo("America/Detroit")
        now = datetime.datetime.now(tz)
        start = now.replace(hour=0, minute=0, second=0, microsecond=0).timestamp()
        end = start + 86400
        overview = hunt_overview(conn, network, since=start, top=max(1, min(int(top), 200)), sort=sort)
    except sqlite3.OperationalError as exc:
        raise HTTPException(status_code=503,
                            detail=f"hunt store busy: {type(exc).__name__}: {exc}")
    finally:
        conn.close()
    overview["generated_at"] = time.time()
    overview["timezone"] = "America/Detroit"
    overview["today"] = {"start": start, "end": end, "date": now.strftime("%Y-%m-%d")}
    try:
        from auditor.disk_pressure import get_controller
        overview["disk_pressure"] = get_controller().status()
    except Exception as _dp_exc:  # noqa: BLE001
        overview["disk_pressure"] = {"error": type(_dp_exc).__name__}
    return overview


@api_router.get("/dashboard/pulse")
async def get_dashboard_pulse() -> dict[str, Any]:
    """Small read-only cross-tab telemetry snapshot; no source rows are loaded."""
    from auditor.monitor import default_monitor_db_path

    path = default_monitor_db_path()
    out: dict[str, Any] = {"generated_at": time.time(), "network": "ethereum",
                            "block": None, "queue_pending": 0, "scanned": 0,
                            "candidates": 0, "ready": 0, "hunt_scanned": 0}
    if not path.exists():
        return out
    conn: sqlite3.Connection | None = None
    try:
        conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=1.5)
        conn.row_factory = sqlite3.Row
        tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if "monitor_cursor" in tables:
            row = conn.execute("SELECT last_block FROM monitor_cursor WHERE network='ethereum'").fetchone()
            out["block"] = int(row[0]) if row else None
        if "monitor_queue" in tables:
            out["queue_pending"] = int(conn.execute(
                "SELECT COUNT(*) FROM monitor_queue WHERE network='ethereum' AND status='pending'"
            ).fetchone()[0])
        if "monitor_scans" in tables:
            out["scanned"] = int(conn.execute(
                "SELECT COUNT(*) FROM monitor_scans WHERE network='ethereum' AND status IN ('done','incomplete')"
            ).fetchone()[0])
            row = conn.execute(
                "SELECT stage,status,address FROM monitor_scans WHERE network='ethereum' AND status='running' "
                "ORDER BY started_at DESC LIMIT 1").fetchone()
            if row:
                out["monitor_stage"] = str(row["stage"] or "fetching")
        if "hunt_candidates" in tables:
            out["candidates"] = int(conn.execute(
                "SELECT COUNT(*) FROM hunt_candidates WHERE network='ethereum'"
            ).fetchone()[0])
            out["ready"] = int(conn.execute(
                "SELECT COUNT(*) FROM hunt_candidates WHERE network='ethereum' AND status IN ('new','measured','ready')"
            ).fetchone()[0])
            out["hunt_scanned"] = int(conn.execute(
                "SELECT COUNT(*) FROM hunt_candidates WHERE network='ethereum' AND status='scanned'"
            ).fetchone()[0])
        if "hunt_runs" in tables:
            row = conn.execute(
                "SELECT at,discovered,measured,scanned,error FROM hunt_runs WHERE network='ethereum' "
                "ORDER BY at DESC LIMIT 1").fetchone()
            if row:
                out["last_hunt"] = {"at": row["at"], "discovered": row["discovered"],
                                    "measured": row["measured"], "scanned": row["scanned"],
                                    "error": bool(row["error"])}
    except (sqlite3.Error, OSError) as exc:
        out["storage_state"] = type(exc).__name__
    finally:
        if conn is not None:
            conn.close()
    out["discovery_run"] = _hunt_run_payload()
    try:
        from auditor.discovery_service import status as live_status
        out["live_discovery"] = live_status(include_metrics=False)
    except Exception as exc:  # noqa: BLE001 - telemetry must not break the dashboard
        out["live_discovery"] = {"status": "unknown", "message": type(exc).__name__}
    return out


@api_router.get("/discovery/providers")
async def get_discovery_providers() -> dict[str, Any]:
    from auditor.discovery_sources import provider_status
    providers = provider_status()
    from auditor.monitor import default_monitor_db_path
    db = default_monitor_db_path()
    if db.exists():
        try:
            conn = sqlite3.connect(f"file:{db}?mode=ro", uri=True, timeout=1.5)
            row = conn.execute(
                "SELECT stats_json FROM hunt_runs WHERE network='ethereum' ORDER BY at DESC LIMIT 1"
            ).fetchone()
            conn.close()
            stats = json.loads(row[0] or "{}") if row else {}
            feed = ((stats.get("refresh") or {}).get("market_sources") or {})
            for provider in providers:
                recent = feed.get(provider["id"])
                if recent:
                    provider["last_run"] = recent
                    if recent.get("state") == "error":
                        provider["state"] = "error"
        except (sqlite3.Error, ValueError, TypeError):
            pass
    return {"providers": providers, "generated_at": time.time()}


def _hunt_run_worker() -> None:
    global _hunt_run
    heartbeat_stop = threading.Event()

    def keep_heartbeat() -> None:
        while not heartbeat_stop.wait(12.0):
            _set_hunt_run()

    threading.Thread(target=keep_heartbeat, name="dashboard-hunt-heartbeat", daemon=True).start()
    command = [str(_PROJECT_ROOT / "scripts" / "run_hunt.sh"), "--once", "--with-pools",
               "--pool-lookback", "200000", "--min-holder-usd", "10000", "--no-blue-chips",
               "--max-scan", "10", "--max-measure", "40", "--max-sim-per-cycle", "1"]
    stage_labels = {
        "discover": "Discovering Ethereum deployments, DeFi registries and pools",
        "retrieve_source": "Retrieving Etherscan and Sourcify source",
        "verify_deployment": "Checking deployed code, proxies and compiler metadata",
        "prioritize": "Ranking contracts by on-chain value and protocol role",
        "security_analysis": "Running Slither and contract security analyzers",
        "fork_validation": "Running bounded local fork invariants and exploitability checks",
    }
    try:
        _set_hunt_run(status="running", stage="discover",
                      message="Scanning recent Ethereum blocks for contract creations",
                      started_at=_hunt_run.get("started_at") or time.time(),
                      finished_at=None, returncode=None, last_event="One-shot discovery worker started")
        # Advance the persisted Ethereum creation cursor without running a
        # second set of scans. Hunt then adds protocol, market and pool feeds.
        activity = _recent_external_audit_activity()
        if activity["monitor"]:
            log.info("continuous monitor is active; using its Ethereum creation cursor")
        else:
            creation_command = [str(_PROJECT_ROOT / "scripts" / "run_monitor.sh"), "--once",
                                "--max-per-poll", "0", "--max-blocks-per-poll", "20"]
            creation_proc = subprocess.Popen(
                creation_command, cwd=str(_PROJECT_ROOT), stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT, text=True, encoding="utf-8", errors="replace",
                bufsize=1, env={**os.environ, "PYTHONUNBUFFERED": "1"})
            if creation_proc.stdout is not None:
                for _line in creation_proc.stdout:
                    line = _line.strip()
                    if line and ("indexed block" in line or "WebSocket" in line
                                 or "reorg" in line.lower() or "error" in line.lower()):
                        _set_hunt_run(stage="discover",
                                      message=line[:240], last_event=line[:500])
            creation_code = creation_proc.wait()
            if creation_code != 0:
                log.warning("Ethereum creation sweep did not complete; continuing with protocol and pool discovery")
                _set_hunt_run(stage="discover",
                              message="Creation sweep had an error; continuing with protocol and pool feeds",
                              last_event="Block creation sweep exited with code " + str(creation_code))

        proc = subprocess.Popen(command, cwd=str(_PROJECT_ROOT), stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, text=True, encoding="utf-8",
                                errors="replace", bufsize=1,
                                env={**os.environ, "PYTHONUNBUFFERED": "1"})
        _set_hunt_run(status="running", stage="discover",
                      message=stage_labels["discover"], last_event="Starting protocol and pool discovery")
        assert proc.stdout is not None
        for line in proc.stdout:
            line = line.strip()
            if line.startswith("pipeline:stage="):
                key = line.partition("=")[2].strip()
                _set_hunt_run(stage=key,
                              message=stage_labels.get(key, "Processing discovery run"),
                              last_event=stage_labels.get(key, "Processing discovery run"))
            elif line.startswith("cycle:"):
                _set_hunt_run(stage="complete", message=line[:240], last_event=line[:500])
        returncode = proc.wait()
        fuzz_result = None
        if returncode == 0:
            _set_hunt_run(stage="security_analysis",
                          message="Running bounded invariant fuzz on the top verified vault (local fork)",
                          last_event="Starting bounded local-fork invariant fuzz")
            try:
                from auditor.hunt_fuzz import run_top_verified_vault
                fuzz_result = run_top_verified_vault()
            except Exception as exc:  # noqa: BLE001
                log.exception("dashboard invariant fuzz failed")
                fuzz_result = {"status": "inconclusive", "reason": type(exc).__name__}
        if returncode != 0:
            final_message = "Hunt command exited with an error; check dashboard server log"
        elif not fuzz_result:
            final_message = "Discovery and scan cycle finished"
        elif fuzz_result.get("status") == "pass":
            final_message = "Discovery and scans finished · invariant fuzz found no counterexample in this run"
        elif fuzz_result.get("status") == "fail":
            final_message = "Discovery and scans finished · fuzz counterexample found; review it manually"
        else:
            final_message = "Discovery and scans finished · fuzz validation inconclusive"
        _set_hunt_run(status="completed" if returncode == 0 else "failed",
                      stage="complete" if returncode == 0 else "failed",
                      message=final_message, last_event=final_message,
                      finished_at=time.time(), returncode=returncode, fuzz=fuzz_result)
    except Exception as exc:  # noqa: BLE001
        log.exception("dashboard discovery run failed")
        _set_hunt_run(status="failed", stage="failed",
                      message=f"Could not start discovery: {type(exc).__name__}",
                      last_event=f"Could not start discovery: {type(exc).__name__}",
                      finished_at=time.time(), returncode=-1)
    finally:
        heartbeat_stop.set()


@api_router.post("/hunt/run", status_code=202)
async def start_hunt_run() -> dict[str, Any]:
    with _hunt_run_lock:
        if _hunt_run.get("status") in ("starting", "running"):
            return _hunt_run_payload()
        try:
            from auditor.discovery_service import status as live_status
            live = live_status(include_metrics=False)
            if live.get("status") in {"starting", "running", "degraded"}:
                return _hunt_run_payload()
        except Exception:  # noqa: BLE001 - proceed to existing duplicate-worker guard
            pass
        activity = _recent_external_audit_activity()
        if activity["hunt"]:
            now = time.time()
            _set_hunt_run(status="completed", stage="complete",
                          message="No duplicate cycle started: the background Hunt auditor is already active.",
                          last_event="Background Hunt auditor is already active",
                          started_at=now, finished_at=now, returncode=0, fuzz=None)
            return _hunt_run_payload()
        _set_hunt_run(status="starting", stage="discover",
                      message="Starting Ethereum discovery", last_event="Starting Ethereum discovery",
                      started_at=time.time(), finished_at=None, returncode=None, fuzz=None, events=[])
        threading.Thread(target=_hunt_run_worker, name="dashboard-hunt-run", daemon=True).start()
        return _hunt_run_payload()


@api_router.get("/hunt/run")
async def get_hunt_run() -> dict[str, Any]:
    return _hunt_run_payload()


@api_router.get("/discovery/live")
async def get_live_discovery() -> dict[str, Any]:
    """Persistent status and heartbeat for the continuous monitor + hunt workers."""
    from auditor.discovery_service import status
    return status()


@api_router.post("/discovery/live/start", status_code=202)
async def start_live_discovery() -> dict[str, Any]:
    """Start the live new-head monitor and periodic high-value hunt supervisor."""
    with _hunt_run_lock:
        if _hunt_run.get("status") in {"starting", "running"}:
            return {"status": "idle", "stage": "idle",
                    "message": "A one-cycle discovery audit is already running; start continuous discovery when it finishes."}
    activity = _recent_external_audit_activity()
    active = [name for name, is_active in activity.items() if is_active]
    if active:
        names = " and ".join(active)
        return {"status": "blocked", "stage": "discover",
                "message": f"Existing {names} worker activity detected. Stop those workers before starting another pair."}
    from auditor.discovery_service import start
    return start()


@api_router.post("/discovery/live/stop", status_code=202)
async def stop_live_discovery() -> dict[str, Any]:
    """Gracefully stop both read-only discovery workers."""
    from auditor.discovery_service import stop
    return stop()



@api_router.get("/exploitable")
async def get_exploitable(min_usd: float | None = None) -> dict[str, Any]:
    """Active EXPLOITABLE_REAL_MONEY banner payload (empty → banner hidden)."""
    from auditor.exploitable import banner_payload

    return banner_payload(min_usd=min_usd)


@api_router.get("/simulate/live")
async def get_simulate_live(network: str = "ethereum", limit: int = 20) -> dict[str, Any]:
    """Phase 22: read-only fork-simulation results (invariants / oracle / trust).

    Genuinely read-only: the connection is ``mode=ro`` and the schema-ensure
    write pass is skipped (``ensure_schema=False``). An older version of this
    route ran an unconditional ``executescript`` DDL batch on every browser
    poll — a masked writer against ``monitor_state.db`` that turned each
    dashboard refresh into a contended write transaction (documented hunt
    restart-loop trigger). A store without the simulation tables now answers
    with an honest empty payload instead of writing DDL."""
    import sqlite3
    import time
    from auditor.monitor import NETWORKS, default_monitor_db_path
    from auditor.simulate import simulation_overview

    if network not in NETWORKS:
        raise HTTPException(status_code=400, detail="unsupported network")
    db = default_monitor_db_path()
    if not db.exists():
        return {"network": network, "runs": [], "db": "absent", "generated_at": time.time()}
    conn = sqlite3.connect(f"file:{db}?mode=ro", uri=True, timeout=10)
    conn.row_factory = sqlite3.Row
    try:
        overview = simulation_overview(conn, network, limit=max(1, min(int(limit), 50)),
                                       ensure_schema=False)
    except sqlite3.OperationalError as exc:
        if "no such table" in str(exc):
            return {"network": network, "runs": [], "db": "present",
                    "generated_at": time.time(),
                    "note": "simulation tables not present in this store"}
        raise HTTPException(status_code=503,
                            detail=f"simulation store busy: {type(exc).__name__}: {exc}")
    finally:
        conn.close()
    overview["generated_at"] = time.time()
    return overview


@api_router.get("/monitor/playbook")
async def get_risk_playbook() -> dict[str, Any]:
    from auditor.risk_playbook import load_playbook

    return load_playbook()


@api_router.get("/scans", response_model=ScanHistoryResponse)
async def list_scans(limit: int = 50) -> ScanHistoryResponse:
    history = ScanHistory(history_db_path())
    try:
        rows = history.get_scan_history(limit=limit)
        summaries = [_summary_of(history, r) for r in rows]
    finally:
        history.close()
    return ScanHistoryResponse(scans=summaries, total=len(summaries))


@api_router.get("/scans/{scan_id}", response_model=ScanDetail)
async def get_scan(scan_id: str) -> ScanDetail:
    history = ScanHistory(history_db_path())
    try:
        record = history.get_scan(scan_id)
        if not record:
            raise HTTPException(status_code=404, detail="Scan not found")
        stored = history.get_findings(scan_id)
        by_severity: dict[str, int] = {}
        for d in stored:
            sev = d.get("severity")
            if sev:
                by_severity[sev] = by_severity.get(sev, 0) + 1
    finally:
        history.close()

    return ScanDetail(
        scan_id=record["scan_id"],
        timestamp=record.get("timestamp", ""),
        source_path=record.get("source_path", ""),
        content_hash=record.get("content_hash", ""),
        config_fingerprint=record.get("config_fingerprint", ""),
        status=record.get("status", ""),
        finding_count=len(stored),
        findings_by_severity=by_severity,
        error_info=record.get("error_info"),
        findings=[StoredFinding(**d) for d in stored],
        finding_fingerprints=record.get("finding_fingerprints") or [],
        finding_details=stored,
        graph_snapshot=record.get("graph_snapshot"),
        **_execution_fields(record.get("execution")),
    )


def _execution_fields(execution: Any) -> dict[str, Any]:
    """ScanDetail tool-execution fields; legacy scans report 'not recorded'."""
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


@api_router.get("/scans/{scan_id}/report")
async def export_report(scan_id: str, format: str = "json") -> Response:
    history = ScanHistory(history_db_path())
    try:
        record = history.get_scan(scan_id)
        if not record:
            raise HTTPException(status_code=404, detail="Scan not found")
        findings = history.get_findings(scan_id)
    finally:
        history.close()

    execution = record.get("execution")
    record = dict(record)
    record.pop("execution", None)

    if format in ("markdown", "md"):
        content = generate_markdown_report(record, findings, execution=execution)
        media = "text/markdown"
        ext = "md"
    else:
        content = json.dumps(
            {"scan": record, "findings": findings, "execution": execution},
            indent=2,
            default=str,
        )
        media = "application/json"
        ext = "json"

    return Response(
        content=content,
        media_type=media,
        headers={
            "Content-Disposition": f'attachment; filename="scan-{scan_id[:8]}.{ext}"'
        },
    )


# ---------------------------------------------------------------------------
# API: jobs
# ---------------------------------------------------------------------------

@api_router.post("/scan", response_model=ScanJobResponse, status_code=202)
async def start_scan(request: ScanJobRequest) -> ScanJobResponse:
    if request.scan_type.value == "local" and request.local is None:
        raise HTTPException(status_code=422, detail="local path required for local scan")
    if request.scan_type.value == "address" and request.address is None:
        raise HTTPException(status_code=422, detail="address required for address scan")
    if request.scan_type.value == "ai_audit" and request.ai_audit is None:
        raise HTTPException(status_code=422, detail="ai_audit payload required for ai_audit scan")
    if request.scan_type.value == "retest" and request.retest is None:
        raise HTTPException(status_code=422, detail="retest payload required for retest scan")
    try:
        return job_manager.submit_job(request)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@api_router.post("/ai-audit", response_model=ScanJobResponse, status_code=202)
async def start_ai_audit(body: AIAuditRequest) -> ScanJobResponse:
    """Convenience endpoint: submit a staged AI audit job.

    ``path`` may be a local path (confined to allowed roots) or the stored
    ``etherscan://<network>/<address>`` reference of a monitor/hunt scan, which
    is resolved to the exact cached verified source (imports included) for that
    scan's content hash. Nothing is fetched or substituted here.
    """
    from auditor.source_resolver import SourceResolutionError, recorded_compile_options, resolve_source

    content_hash = body.content_hash
    if body.scan_id and not content_hash:
        try:
            rec = ScanHistory(history_db_path()).get_scan(body.scan_id)
        except Exception:  # noqa: BLE001
            rec = None
        if rec:
            content_hash = rec.get("content_hash") or None
            if rec.get("source_path") and rec.get("source_path") != body.path:
                raise HTTPException(status_code=400, detail={
                    "code": "scan_mismatch",
                    "message": "path does not match the stored source of this scan"})
    try:
        resolved = resolve_source(body.path, content_hash)
    except SourceResolutionError as exc:
        status = 404 if exc.code in ("source_unavailable", "not_found", "missing") else 400
        raise HTTPException(status_code=status, detail={"code": exc.code, "message": str(exc),
                                                        "ref": body.path})
    if resolved.file_count == 0:
        raise HTTPException(status_code=422, detail={
            "code": "no_solidity", "message": f"no .sol files under {resolved.path}", "ref": body.path})
    if body.metadata is None and resolved.kind == "verified-cache":
        from auditor.dashboard.models import ScanMetadataRequest
        try:
            body.metadata = ScanMetadataRequest(chain=resolved.network, contract_address=resolved.address)
        except Exception:  # noqa: BLE001
            pass
    body.path = str(resolved.path)
    if resolved.kind == "verified-cache":
        body.compile_options = recorded_compile_options(Path(resolved.path))
    return await start_scan(ScanJobRequest(scan_type="ai_audit", ai_audit=body))




@api_router.get("/jobs", response_model=list[ScanJobResponse])
async def list_jobs(limit: int = 50) -> list[ScanJobResponse]:
    return job_manager.list_jobs(limit=limit)


@api_router.get("/jobs/{job_id}", response_model=ScanJobResponse)
async def get_job(job_id: str) -> ScanJobResponse:
    job = job_manager.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    return job


@api_router.delete("/jobs/{job_id}")
async def cancel_job(job_id: str) -> dict[str, str]:
    if job_manager.cancel_job(job_id):
        return {"message": "Job cancelled"}
    raise HTTPException(status_code=404, detail="Job not found or not cancellable")


# ---------------------------------------------------------------------------
# API: tools / validation
# ---------------------------------------------------------------------------

class _MockArgs:
    """Just enough of the CLI args namespace for status observation."""

    json = True
    model: str | None = None
    timeout: float | None = None
    no_probe_model = False
    verbose = False


@api_router.get("/tools", response_model=ToolchainResponse)
async def get_toolchain_status() -> ToolchainResponse:
    settings = load_settings()
    payload = _status_payload(_observe(settings, _MockArgs()), settings)
    return ToolchainResponse(
        toolchain=payload["toolchain"],
        ollama=payload["ollama"],
        storage=payload["storage"],
        analysis_modules=payload["analysis_modules"],
        configuration=payload["configuration"],
    )


class AddressValidationResponse(BaseModel):
    is_valid: bool
    normalized: str | None = None
    reason: str = ""
    checksum_status: str | None = None
    address: str | None = None
    chain: str | None = None

    model_config = {"extra": "allow"}


class AddressBody(BaseModel):
    address: str = Field(..., pattern=r"^0x[a-fA-F0-9]{40}$")


@api_router.post("/validate-address", response_model=AddressValidationResponse)
async def validate_address_api(body: AddressBody) -> AddressValidationResponse:
    result = validate_address(body.address)
    return AddressValidationResponse(**result.to_dict())


# ---------------------------------------------------------------------------
# API: findings, investigation, lifecycle, retest, bounty, patches, reports
# ---------------------------------------------------------------------------

def _load_finding_bundle(scan_id: str, fingerprint: str) -> dict[str, Any]:
    """Load one stored finding with review state, history, metadata, bounty."""
    from auditor.finding_store import get_metadata, get_review, history as review_history, open_store

    history = ScanHistory(history_db_path())
    try:
        record = history.get_scan(scan_id)
        if not record:
            raise HTTPException(status_code=404, detail="Scan not found")
        findings = history.get_findings(scan_id)
    finally:
        history.close()

    finding = next(
        (f for f in findings if str(f.get("fingerprint")) == fingerprint), None
    )
    if finding is None:
        raise HTTPException(status_code=404, detail="Finding not found in scan")

    store = open_store(history_db_path())
    try:
        review = get_review(store, scan_id, fingerprint)
        state_history = review_history(store, scan_id, fingerprint)
        metadata = get_metadata(store, scan_id)
    finally:
        store.close()

    bounty = None
    raw = metadata.get("bounty_check")
    if raw:
        try:
            bounty = json.loads(raw)
        except json.JSONDecodeError:
            bounty = None

    return {
        "record": record,
        "finding": finding,
        "review": review,
        "state_history": state_history,
        "metadata": metadata,
        "bounty": bounty,
    }


@api_router.get("/findings")
async def list_findings_api(
    q: str | None = None,
    severity: str | None = None,
    status: str | None = None,
    state: str | None = None,
    finrisk: str | None = None,
    sort: str = "severity",
    group: str = "none",
    hide_triaged: bool = False,
    limit: int = 200,
    offset: int = 0,
) -> dict[str, Any]:
    """Aggregated finding rows with search, filters, sort, and grouping.

    Paginated: ``limit`` (1..1000, default 200) rows from ``offset``; the
    response carries ``total`` (all matching rows), ``offset``, ``limit``,
    ``returned`` and ``has_more``. With grouping, the page is cut from the
    group-ordered row sequence and groups are rebuilt from that page.

    Rows from monitor/hunt scans carry ``monitor_triage`` (verdict + dismissal
    reason) when the monitor suppressed them, so they are not shown as open
    critical alerts; ``hide_triaged=true`` filters them out.

    ``finrisk`` filters by second-stage financial-risk review outcome
    (comma-separated): one of the five verdicts, ``pending`` (not yet
    completed), or ``high_impact`` (validated or potential)."""
    from auditor.finding_store import list_findings, open_store

    def _split(value: str | None) -> list[str] | None:
        if not value:
            return None
        parts = [p.strip() for p in value.split(",") if p.strip()]
        return parts or None

    store = open_store(history_db_path())
    try:
        result = list_findings(
            store,
            q=q,
            severity=_split(severity),
            status=_split(status),
            state=_split(state),
            sort=sort,
            group=group,
        )
    finally:
        store.close()
    return _paginate_findings(result, hide_triaged=hide_triaged, limit=limit, offset=offset,
                              finrisk=_split(finrisk))


def _paginate_findings(result: dict[str, Any], *, hide_triaged: bool, limit: int, offset: int,
                       finrisk: list[str] | None = None) -> dict[str, Any]:
    limit = max(1, min(int(limit), 1000))
    offset = max(0, int(offset))
    groups = result.get("groups")
    if isinstance(groups, dict):
        seq = [(k, f) for k, rows in groups.items() for f in (rows or []) if isinstance(f, dict)]
    else:
        seq = [(None, f) for f in (result.get("findings") or []) if isinstance(f, dict)]
    if hide_triaged:
        # triage needs the full set to filter before counting
        _annotate_monitor_triage({"findings": [f for _, f in seq]})
        seq = [(k, f) for k, f in seq if not f.get("monitor_triage")]
    if finrisk:
        # finrisk filtering needs the full set too (before pagination);
        # annotation is a read-only lookup in the isolated review store
        _annotate_finrisk({"findings": [f for _, f in seq]})
        seq = [(k, f) for k, f in seq if _finrisk_filter_match(f.get("finrisk"), finrisk)]
    total = len(seq)
    page = seq[offset:offset + limit]
    if not hide_triaged:
        _annotate_monitor_triage({"findings": [f for _, f in page]})
    _annotate_finrisk({"findings": [f for _, f in page]})
    out = dict(result)
    if isinstance(groups, dict):
        g: dict[str, list] = {}
        for k, f in page:
            g.setdefault(k, []).append(f)
        out["groups"] = g
        out["findings"] = [f for _, f in page] if "findings" in result else out.get("findings")
    else:
        out["findings"] = [f for _, f in page]
    out.update(total=total, offset=offset, limit=limit, returned=len(page),
               has_more=offset + len(page) < total)
    return out


def _annotate_finrisk(result: dict[str, Any] | list) -> None:
    """Attach the finrisk queue row (state + verdict) to finding rows.

    Completed rows are additionally annotated with the per-row financial
    basis (``basis_usd``) and the exposure class recorded in the persisted
    review payload, so the Financial Exploits tab can show confirmed /
    potential exposure without re-reading the review store per row.

    Read-only against the isolated review store. A missing store or a
    database error leaves rows unannotated (the UI shows them as not yet
    reviewed); this helper must never break the findings listing."""
    from auditor import finrisk

    if isinstance(result, dict):
        rows = [f for f in (result.get("findings") or []) if isinstance(f, dict)]
        for g in result.get("groups") or []:
            if isinstance(g, dict):
                rows += [f for f in g.get("findings") or [] if isinstance(f, dict)]
    elif isinstance(result, list):
        rows = [f for f in result if isinstance(f, dict)]
    else:
        return
    if not rows:
        return
    con = finrisk.open_finrisk_db_ro()
    if con is None:
        return
    try:
        # one full-table pass; the marker lookup is O(1) per finding row.
        # review_json is parsed ONLY for completed rows (small subset).
        markers: dict[tuple[str, str], dict] = {}
        for r in con.execute(
                "SELECT scan_id, fingerprint, state, verdict, attempts, last_error,"
                " updated_at, finished_at, review_json FROM finrisk_reviews"):
            marker = {
                "state": r["state"], "verdict": r["verdict"], "attempts": r["attempts"],
                "last_error": r["last_error"], "updated_at": r["updated_at"],
                "finished_at": r["finished_at"],
            }
            if r["state"] == finrisk.STATE_COMPLETED and r["review_json"]:
                try:
                    payload = json.loads(r["review_json"])
                except (ValueError, TypeError):
                    payload = None
                if isinstance(payload, dict):
                    basis = finrisk.row_financial_basis(payload)
                    if isinstance(basis, dict):
                        marker["basis_usd"] = basis.get("basis_usd")
                        marker["estimate_usd"] = basis.get("est_usd")
                        if basis.get("network"):
                            marker["network"] = basis.get("network")
                        if basis.get("address"):
                            marker["address"] = basis.get("address")
                    attacker = payload.get("attacker")
                    model = attacker.get("exposure_model") if isinstance(attacker, dict) else None
                    if isinstance(model, dict):
                        marker["exposure_class"] = model.get("vulnerability_class")
                    if isinstance(attacker, dict):
                        marker["privilege_gated"] = bool(attacker.get("privilege_gated"))
            markers[(str(r["scan_id"]), str(r["fingerprint"]))] = marker
    except sqlite3.Error:
        return
    finally:
        con.close()
    for f in rows:
        sid, fp = f.get("scan_id"), f.get("fingerprint")
        marker = markers.get((str(sid), str(fp))) if sid and fp else None
        f["finrisk"] = marker


def _finrisk_filter_match(fr: Any, wanted: list[str]) -> bool:
    """True when a finding row satisfies the requested finrisk tokens.

    ``pending`` also matches rows with no review yet (they are queued by
    the post-scan hook once the runner catches up); ``high_impact`` is the
    validated + potential union — the rows the engine risk-flagged.
    ``privileged_access`` matches privilege-gated findings.
    ``unverified_exposure`` matches inconclusive or pending reviews.
    ``disproved_false_positive`` matches disproved or benign/non-financial reviews."""
    from auditor import finrisk

    state = fr.get("state") if isinstance(fr, dict) else None
    verdict = fr.get("verdict") if isinstance(fr, dict) else None
    privilege_gated = bool(fr.get("privilege_gated")) if isinstance(fr, dict) else False

    for w in wanted:
        if w == "pending":
            if state != finrisk.STATE_COMPLETED:
                return True
        elif w == "high_impact":
            if verdict in (finrisk.VERDICT_VALIDATED, finrisk.VERDICT_POTENTIAL):
                return True
        elif w == "privileged_access":
            if privilege_gated or (verdict == finrisk.VERDICT_NOT_FINANCIAL and privilege_gated):
                return True
        elif w in ("unverified_exposure", "unverified"):
            if state != finrisk.STATE_COMPLETED or verdict == finrisk.VERDICT_INCONCLUSIVE:
                return True
        elif w in ("disproved_false_positive", "false_positives"):
            if verdict == finrisk.VERDICT_DISPROVED or (verdict == finrisk.VERDICT_NOT_FINANCIAL and not privilege_gated):
                return True
        elif verdict and w == verdict:
            return True
    return False


def _annotate_monitor_triage(result: dict[str, Any]) -> None:
    """Attach the monitor's triage verdict (suppressed + dismissal reason) to
    history findings from monitor/hunt scans. Read-only; history rows are not
    modified. A finding without a monitor verdict is left untouched."""
    import re as _re
    from auditor.monitor import default_monitor_db_path

    rows = [f for f in (result.get("findings") or []) if isinstance(f, dict)]
    for g in result.get("groups") or []:
        if isinstance(g, dict):
            rows += [f for f in g.get("findings") or [] if isinstance(f, dict)]
    if not rows:
        return
    db = default_monitor_db_path()
    if not Path(db).exists():
        return
    try:
        con = sqlite3.connect(f"file:{db}?mode=ro", uri=True, timeout=2)
    except sqlite3.Error:
        return
    try:
        cache: dict[tuple, Any] = {}
        for f in rows:
            m = _re.match(r"etherscan://(?:([a-z0-9-]+)/)?(0x[0-9a-fA-F]{40})$", str(f.get("source_path") or ""))
            if not m:
                continue
            net, addr = (m.group(1) or "ethereum"), m.group(2).lower()
            det = None
            dm = _re.search(r"'([a-z0-9-]+)',\s*'[^']*'\)$", str(f.get("fingerprint") or ""))
            if dm:
                det = dm.group(1)
            key = (net, addr, f.get("affected_contract"), f.get("affected_function"), det)
            if key not in cache:
                q = ("select triage_rule, triage_reason, triage_detail, verified_at from monitor_findings "
                     "where network=? and lower(address)=? and contract=? and function=? and suppressed=1")
                args: list[Any] = [net, addr, key[2], key[3]]
                if det:
                    q += " and detector=?"
                    args.append(det)
                q += " order by id desc limit 1"
                try:
                    cache[key] = con.execute(q, args).fetchone()
                except sqlite3.Error:
                    cache[key] = None
            hit = cache[key]
            if hit:
                disproved = hit[0] == "live-state-disproof"
                f["monitor_triage"] = {
                    "verdict": "Tested path disproved under current state" if disproved else "False positive",
                    "label": "disproved_current_state" if disproved else "false_positive",
                    "rule": hit[0],
                    "reason": " — ".join(x for x in (hit[1], hit[2]) if x) or "suppressed by triage rule (no reason recorded)",
                }
    finally:
        con.close()


def _monitor_context_for_scan(record: dict[str, Any], finding: dict[str, Any]) -> dict[str, Any]:
    """Load monitor holdings + triage + bytecode verify for an investigation card.

    Read-only against monitor_state.db. Missing DB/rows -> empty context (honest unknown).
    """
    import re as _re
    from auditor.monitor import default_monitor_db_path

    ctx: dict[str, Any] = {}
    src = str(record.get("source_path") or "")
    m = _re.match(r"etherscan://(?:([a-z0-9-]+)/)?(0x[0-9a-fA-F]{40})$", src)
    addr = None
    net = "ethereum"
    if m:
        net, addr = (m.group(1) or "ethereum"), m.group(2).lower()
    else:
        # filesystem path .../ethereum/<addr>/<hash>
        m2 = _re.search(r"/(0x[0-9a-fA-F]{40})/", src)
        if m2:
            addr = m2.group(1).lower()
    if not addr:
        return ctx
    try:
        from auditor.bytecode_verify import normalize_address, verify_deployed_source
        norm = normalize_address(addr)
        if norm:
            ctx["bytecode"] = verify_deployed_source(norm)
            addr = norm
    except Exception as exc:  # noqa: BLE001
        ctx["bytecode"] = {"value": "unknown", "basis": f"{type(exc).__name__}: {exc}"}

    db = default_monitor_db_path()
    if not Path(db).exists():
        return ctx
    try:
        con = sqlite3.connect(f"file:{db}?mode=ro", uri=True, timeout=2)
    except sqlite3.Error:
        return ctx
    try:
        row = con.execute(
            "SELECT value_json, tvl_usd, price_as_of FROM monitor_scans "
            "WHERE network=? AND lower(address)=? AND superseded_at IS NULL "
            "ORDER BY id DESC LIMIT 1",
            (net, addr),
        ).fetchone()
        if row and row[0]:
            try:
                vj = json.loads(row[0])
            except json.JSONDecodeError:
                vj = {}
            val = vj.get("value") if isinstance(vj.get("value"), dict) else vj
            if isinstance(val, dict):
                ctx["value"] = val
            elif row[1] is not None:
                ctx["value"] = {"tvl_usd": row[1], "price_as_of": row[2], "holdings": []}
        # triage for this finding
        det = None
        dm = _re.search(r"'([a-z0-9-]+)',\s*'[^']*'\)$", str(finding.get("fingerprint") or ""))
        if dm:
            det = dm.group(1)
        q = ("SELECT triage_rule, triage_reason, triage_detail, suppressed FROM monitor_findings "
             "WHERE network=? AND lower(address)=? AND contract=? AND function=? AND suppressed=1")
        args: list[Any] = [net, addr, finding.get("affected_contract"), finding.get("affected_function")]
        if det:
            q += " AND detector=?"
            args.append(det)
        q += " ORDER BY id DESC LIMIT 1"
        hit = con.execute(q, args).fetchone()
        if hit:
            disproved = hit[0] == "live-state-disproof"
            dyn = hit[0] == "dynamic-disproof" or (hit[1] or "").startswith("dynamic")
            ctx["triage"] = {
                "verdict": (
                    "Tested path disproved under current state" if disproved or dyn
                    else "False positive (detector-corrected)"
                ),
                "label": "disproved_current_state" if (disproved or dyn) else "false_positive",
                "rule": hit[0],
                "reason": hit[1],
                "detail": hit[2],
            }
    except sqlite3.Error:
        pass
    finally:
        con.close()
    return ctx


@api_router.get("/findings/{scan_id}/investigation")
async def get_investigation(scan_id: str, fp: str) -> dict[str, Any]:
    """Two-sided investigation payload for one finding."""
    from auditor.investigation import build_investigation

    bundle = _load_finding_bundle(scan_id, fp)
    record = bundle["record"]

    ai_analysis = None
    graph = record.get("graph_snapshot")
    if record.get("config_fingerprint") == "ai-audit" and isinstance(graph, dict):
        for entry in (graph.get("ai_analysis") or {}).get("findings", []):
            if str(entry.get("fingerprint")) == fp:
                ai_analysis = entry
    elif not ai_analysis:
        # Link recent AI audit analysis if an AI audit was conducted for this source / finding
        history = None
        try:
            history = ScanHistory(history_db_path())
            rows = history._conn.execute(
                "SELECT graph_snapshot FROM scan_records "
                "WHERE config_fingerprint = 'ai-audit' AND status = 'completed' "
                "AND (source_path = ? OR (content_hash IS NOT NULL AND content_hash = ?)) "
                "ORDER BY timestamp DESC LIMIT 5",
                (record.get("source_path"), record.get("content_hash"))
            ).fetchall()
            for r in rows:
                if r and r[0]:
                    try:
                        g = json.loads(r[0])
                        for entry in (g.get("ai_analysis") or {}).get("findings", []):
                            if str(entry.get("fingerprint")) == fp:
                                ai_analysis = entry
                                break
                    except Exception:
                        pass
                if ai_analysis:
                    break
        except Exception:
            pass
        finally:
            if history:
                try:
                    history.close()
                except Exception:
                    pass

    monitor_context = _monitor_context_for_scan(record, bundle["finding"])
    inv = build_investigation(
        bundle["finding"],
        record,
        review=bundle["review"],
        metadata=bundle["metadata"],
        source_root=record.get("source_path"),
        bounty=bundle["bounty"],
        state_history=bundle["state_history"],
        ai_analysis=ai_analysis,
        monitor_context=monitor_context,
    )
    try:
        inv["financial_risk_review"] = _finrisk_review_block(scan_id, fp)
    except Exception:  # noqa: BLE001 - the review panel outage must not hide the finding
        inv["financial_risk_review"] = None
    return inv


def _finrisk_review_block(scan_id: str, fp: str) -> dict[str, Any]:
    """Second-stage financial-risk review block for the investigation view.

    Read-only. Without a recorded review the block says so honestly
    (state ``not_queued``) instead of inventing fields."""
    from auditor import finrisk

    con = finrisk.open_finrisk_db_ro()
    if con is None:
        return {"state": "not_queued",
                "note": "No financial-risk review recorded yet; the store is not initialised."}
    try:
        payload = finrisk.review_payload(con, scan_id, fp)
    finally:
        con.close()
    if payload is None:
        return {"state": "not_queued",
                "note": ("Not reviewed yet; new completed scans are queued automatically "
                         "(scripts/run_finrisk.py) or review it now via the action button.")}
    return payload


@api_router.get("/finrisk/summary")
async def finrisk_summary_api() -> dict[str, Any]:
    """Queue counters + verdict breakdown + financial exposure roll-up.

    Computed from the persisted review rows only (no live calls). An
    empty store answers 200 with ``status: empty`` so the UI can show a
    calm 'no reviews yet' card."""
    from auditor import finrisk

    con = finrisk.open_finrisk_db_ro()
    if con is None:
        return {"status": "empty",
                "queue": {}, "verdicts": {}, "in_flight": [], "last_errors": [],
                "financial_rollup": None}
    try:
        out = finrisk.summary(con)
        out["financial_rollup"] = finrisk.financial_rollup(con)
    finally:
        con.close()
    out["status"] = "ok"
    return out


@api_router.get("/findings/{scan_id}/finrisk")
async def get_finrisk_review(scan_id: str, fp: str) -> dict[str, Any]:
    """Full review payload (state, verdict, evidence timeline) for one row.

    ``fp`` is a query parameter (compound fingerprints contain slashes,
    which cannot travel as a path segment)."""
    from auditor import finrisk

    if not fp.strip():
        raise HTTPException(status_code=422, detail="fingerprint is required")
    con = finrisk.open_finrisk_db_ro()
    if con is None:
        raise HTTPException(status_code=404, detail="no financial-risk review store")
    try:
        payload = finrisk.review_payload(con, scan_id, fp)
    finally:
        con.close()
    if payload is None:
        raise HTTPException(status_code=404, detail="finding not queued for financial-risk review")
    return payload


@api_router.post("/findings/{scan_id}/finrisk/run")
async def run_finrisk_review(scan_id: str, fp: str) -> dict[str, Any]:
    """Manual (re-)review of one finding, inline under the review lock.

    ``fp`` is a query parameter (compound fingerprints contain slashes).
    Runs the same engine the batch runner uses: enqueue-if-missing,
    reset attempts, claim, review, persist. 409 when the lock is busy
    (the batch runner or another request holds it) — never queues two
    writers on the same store."""
    from auditor import finrisk
    from auditor.dashboard.paths import history_db_path as _history_db

    if not fp.strip():
        raise HTTPException(status_code=422, detail="fingerprint is required")
    with finrisk.finrisk_lock() as lock:
        if not lock.acquired():
            raise HTTPException(status_code=409,
                                detail="financial-risk review already running; try again shortly")
        con = finrisk.open_finrisk_db()
        try:
            exists = con.execute(
                "SELECT 1 FROM finrisk_reviews WHERE scan_id=? AND fingerprint=?",
                (scan_id, fp)).fetchone()
            if exists is None:
                loader = finrisk.history_loader_for(_history_db())
                record = loader(scan_id)
                if record is None:
                    raise HTTPException(status_code=404, detail=f"scan {scan_id} not found")
                details = record.get("finding_details")
                if isinstance(details, str):
                    try:
                        details = json.loads(details or "[]")
                    except ValueError:
                        details = []
                detail = next((d for d in details or [] if isinstance(d, dict)
                               and str(d.get("fingerprint") or "") == fp), None)
                if detail is None:
                    raise HTTPException(status_code=404,
                                        detail="fingerprint not present in this scan record")
                finrisk.enqueue_findings(con, scan_id=scan_id,
                                         scan_timestamp=record.get("timestamp"),
                                         source_path=record.get("source_path") or "",
                                         findings=[detail])
            else:
                finrisk.reset_for_manual_run(con, scan_id, fp)
            claimed = finrisk.claim_one(con, scan_id, fp)
            if claimed is None:
                raise HTTPException(status_code=404, detail="finding not queued")
            result = finrisk.process_one(
                con, scan_id=scan_id, fingerprint=fp,
                history_loader=finrisk.history_loader_for(_history_db()),
                rpc_url=finrisk.rpc_url_for_review(),
                allow_network_verify=True,
                log=lambda m: logging.getLogger("finrisk").info("manual run: %s", m))
        finally:
            con.close()
        ro = finrisk.open_finrisk_db_ro()
        try:
            review = finrisk.review_payload(ro, scan_id, fp) if ro is not None else None
        finally:
            if ro is not None:
                ro.close()
    return {"status": "ok", "run": result, "review": review}


@api_router.post("/findings/{scan_id}/state")
async def change_finding_state(scan_id: str, body: FindingStateChangeRequest) -> dict[str, Any]:
    """Explicit analyst state transition (422 on illegal or unevidenced moves)."""
    from auditor.finding_store import get_review, history as review_history, open_store, set_state

    bundle = _load_finding_bundle(scan_id, body.fingerprint)
    store = open_store(history_db_path())
    try:
        ok, message = set_state(
            store,
            scan_id,
            body.fingerprint,
            body.state,
            finding=bundle["finding"],
            note=body.note,
            evidence_ref=body.evidence_ref,
        )
        if not ok:
            raise HTTPException(status_code=422, detail=message)
        review = get_review(store, scan_id, body.fingerprint)
        state_history = review_history(store, scan_id, body.fingerprint)
    finally:
        store.close()
    return {"message": message, "review": review, "history": state_history}


@api_router.post("/findings/{scan_id}/retest", response_model=ScanJobResponse, status_code=202)
async def retest_finding(scan_id: str, body: RetestRequest) -> ScanJobResponse:
    """Re-run analysis for one stored finding; reports whether it persists."""
    if body.scan_id is not None and body.scan_id != scan_id:
        raise HTTPException(status_code=422, detail="scan_id in body must match the path")
    # Ensures 404 before a job is scheduled.
    _load_finding_bundle(scan_id, body.fingerprint)
    retest = RetestRequest(scan_id=scan_id, fingerprint=body.fingerprint)
    request = ScanJobRequest(scan_type="retest", retest=retest)
    try:
        return job_manager.submit_job(request)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@api_router.post("/scans/{scan_id}/bounty")
async def run_bounty_check(scan_id: str, body: BountyCheckRequest) -> dict[str, Any]:
    """Read-only bounty check; evidence + timestamp only, never an assertion."""
    import urllib.error

    from auditor.bounty import check_eligibility
    from auditor.finding_store import open_store, set_metadata

    history = ScanHistory(history_db_path())
    try:
        record = history.get_scan(scan_id)
    finally:
        history.close()
    if not record:
        raise HTTPException(status_code=404, detail="Scan not found")

    from auditor.finding_store import get_metadata

    store = open_store(history_db_path())
    try:
        metadata = get_metadata(store, scan_id)
    finally:
        store.close()

    project_name = (body.project_name or "").strip() or metadata.get("project_name")
    category = (body.category or "").strip() or metadata.get("protocol_category")
    asset = (
        (body.asset or "").strip()
        or metadata.get("token_address")
        or metadata.get("token_symbol")
    )

    try:
        result = check_eligibility(
            project_name=project_name,
            asset=asset,
            category=category,
            official_url=(body.official_url or "").strip() or None,
        )
    except (urllib.error.URLError, OSError, ValueError) as exc:
        raise HTTPException(status_code=400, detail=f"bounty check failed: {exc}") from exc

    store = open_store(history_db_path())
    try:
        set_metadata(store, scan_id, {"bounty_check": json.dumps(result, default=str)})
    finally:
        store.close()
    return result


@api_router.post("/scans/{scan_id}/metadata")
async def record_scan_metadata(scan_id: str, body: ScanMetadataRequest) -> dict[str, Any]:
    """Record scope metadata (project/chain/token) for one scan."""
    from auditor.finding_store import get_metadata, open_store, set_metadata

    history = ScanHistory(history_db_path())
    try:
        record = history.get_scan(scan_id)
    finally:
        history.close()
    if not record:
        raise HTTPException(status_code=404, detail="Scan not found")

    payload = body.model_dump(exclude_none=True)
    store = open_store(history_db_path())
    try:
        if payload:
            set_metadata(store, scan_id, payload)
        metadata = get_metadata(store, scan_id)
    finally:
        store.close()
    return {"scan_id": scan_id, "metadata": metadata}


@api_router.get("/scans/{scan_id}/audit-report")
async def export_audit_report(scan_id: str, format: str = "json") -> Response:
    """Full structured report (12 sections + origin legend)."""
    from auditor.report_builder import build_report, render_markdown

    history = ScanHistory(history_db_path())
    try:
        record = history.get_scan(scan_id)
    finally:
        history.close()
    if not record:
        raise HTTPException(status_code=404, detail="Scan not found")

    report = build_report(scan_id, history_db=Path(history_db_path()))
    if format in ("markdown", "md"):
        content = render_markdown(report)
        media, ext = "text/markdown", "md"
    else:
        content = json.dumps(report, indent=2, default=str)
        media, ext = "application/json", "json"
    return Response(
        content=content,
        media_type=media,
        headers={
            "Content-Disposition": f'attachment; filename="audit-{scan_id[:8]}.{ext}"'
        },
    )


@api_router.get("/findings/{scan_id}/report")
async def export_finding_report(scan_id: str, fp: str, format: str = "json") -> Response:
    """Single-finding report (investigation view as JSON or Markdown)."""
    from auditor.report_builder import build_finding_report, render_investigation_markdown

    _load_finding_bundle(scan_id, fp)
    payload = build_finding_report(scan_id, fp, history_db=Path(history_db_path()))
    if format in ("markdown", "md"):
        content = render_investigation_markdown(payload)
        media, ext = "text/markdown", "md"
    else:
        content = json.dumps(payload, indent=2, default=str)
        media, ext = "application/json", "json"
    return Response(
        content=content,
        media_type=media,
        headers={
            "Content-Disposition": f'attachment; filename="finding-{scan_id[:8]}.{ext}"'
        },
    )


@api_router.get("/opencode")
async def opencode_status() -> dict[str, Any]:
    """Probe OpenCode availability (fixed-argv --version only)."""
    from auditor.opencode_review import probe

    return probe()


@api_router.get("/proposals")
async def list_proposals() -> list[dict[str, Any]]:
    from auditor.opencode_review import list_proposals as _list

    return _list()


@api_router.post("/findings/{scan_id}/propose")
async def propose_finding_patch(scan_id: str, body: ProposePatchRequest) -> dict[str, Any]:
    """Draft a patch proposal for a finding (read-only; never applied here)."""
    from auditor.investigation import _locate_file, _validate_root
    from auditor.opencode_review import propose_patch

    if body.scan_id is not None and body.scan_id != scan_id:
        raise HTTPException(status_code=422, detail="scan_id in body must match the path")
    bundle = _load_finding_bundle(scan_id, body.fingerprint)
    record = bundle["record"]
    root = _validate_root(record.get("source_path"), record.get("content_hash"))
    if root is None:
        raise HTTPException(
            status_code=400, detail="original source is no longer available for this scan"
        )
    target = _locate_file(root, bundle["finding"].get("affected_contract"))
    if target is None:
        raise HTTPException(
            status_code=400, detail="could not locate a source file for this finding"
        )
    try:
        return propose_patch(
            project_dir=root,
            target_file=target,
            finding=bundle["finding"],
            scan_id=scan_id,
            fingerprint=body.fingerprint,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@api_router.post("/patches/{proposal_id}/apply")
async def apply_proposed_patch(proposal_id: str, body: ApplyPatchRequest) -> dict[str, Any]:
    """Apply a stored proposal. Approval is explicit and per-request."""
    from auditor.opencode_review import apply_patch

    try:
        return apply_patch(
            proposal_id,
            approval=body.approval,
            expected_before_hash=body.expected_before_hash,
        )
    except ValueError as exc:
        status = 409 if "changed since" in str(exc) or "hash" in str(exc) else 400
        raise HTTPException(status_code=status, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# Report rendering
# ---------------------------------------------------------------------------

def generate_markdown_report(
    record: dict[str, Any], findings: list[dict], execution: dict[str, Any] | None = None
) -> str:
    """Generate a Markdown report for a scan."""
    lines = [
        f"# Scan Report: {str(record.get('scan_id', ''))[:8]}...",
        "",
        f"**Timestamp:** {record.get('timestamp', '')}",
        f"**Source:** {record.get('source_path', '')}",
        f"**Content Hash:** {record.get('content_hash', '')}",
        f"**Config:** {record.get('config_fingerprint', '')}",
        f"**Status:** {record.get('status', '')}",
        f"**Findings:** {len(findings)}",
        "",
    ]

    # Tool execution status — what actually ran, including failures.
    lines.append("## Tool execution")
    if execution:
        lines.append("")
        for tool in execution.get("tools") or []:
            row = f"- **{tool.get('label') or tool.get('key')}**: `{tool.get('status')}`"
            detail = tool.get("error") or tool.get("message") or ""
            if detail:
                row += f" — {detail}"
            if tool.get("finding_count") is not None and tool.get("kind") == "static-analysis":
                row += f" (findings surfaced: {tool.get('finding_count')})"
            lines.append(row)
        complete = execution.get("scan_complete")
        lines.append(
            f"- **Scan complete:** {'yes' if complete else 'no' if complete is False else 'not recorded'}"
        )
        for reason in execution.get("incomplete_reasons") or []:
            lines.append(f"  - incomplete: {reason}")
        if execution.get("zero_findings_note"):
            lines.append(f"- **Zero-findings note:** {execution['zero_findings_note']}")
        lines.append("")
        lines.append(
            "> Build/test results are compilation evidence only. A completed "
            "static-analysis run with zero findings means none were detected "
            "by the checks that completed — not that the code is free of "
            "vulnerabilities."
        )
        lines.append("")
    else:
        lines.append("")
        lines.append("Tool execution status was not recorded for this scan.")
        lines.append("")

    if not findings:
        note = (execution or {}).get("zero_findings_note") or "No findings recorded."
        lines.append(note)
        return "\n".join(lines)

    by_severity: dict[str, list[dict]] = {}
    for f in findings:
        by_severity.setdefault(str(f.get("severity", "UNKNOWN")), []).append(f)

    for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL", "UNKNOWN"]:
        for f in by_severity.get(severity, []):
            lines.append(f"## [{severity}] {f.get('title', 'Untitled')}")
            lines.append(
                f"- **ID:** {f.get('fingerprint') or f.get('finding_id', 'unknown')}"
            )
            lines.append(f"- **Category:** {f.get('category', 'unknown')}")
            lines.append(
                f"- **Status:** {f.get('status') or f.get('verification_status', 'UNVERIFIED')}"
            )
            lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# API: benchmark (Phase 14) — read-only over the dedicated benchmark store.
# Never reads or writes audit_scan_history.db.
# ---------------------------------------------------------------------------

def _benchmark_connection() -> sqlite3.Connection | None:
    """Open the benchmark store, or None when no run has ever been saved."""
    path = benchmark_store.default_benchmark_db_path()
    if not path.exists():
        return None
    return benchmark_store.open_store(path)


@api_router.get("/benchmark/latest")
async def benchmark_latest() -> dict[str, Any]:
    """The most recent stored benchmark run, or the empty state."""
    conn = _benchmark_connection()
    if conn is None:
        return {"status": "empty"}
    try:
        run = benchmark_store.get_latest(conn)
    finally:
        conn.close()
    if run is None:
        return {"status": "empty"}
    detail = BenchmarkRunDetail(**run)
    payload = detail.model_dump()
    payload["status"] = payload.get("status") or "completed"
    payload["store"] = str(benchmark_store.default_benchmark_db_path())
    return payload


@api_router.get("/benchmark/runs")
async def benchmark_runs(limit: int = 20) -> dict[str, Any]:
    """Run history (headers only)."""
    conn = _benchmark_connection()
    if conn is None:
        return {"status": "empty", "runs": []}
    try:
        runs = benchmark_store.list_runs(conn, limit=max(1, min(int(limit), 100)))
    finally:
        conn.close()
    if not runs:
        return {"status": "empty", "runs": []}
    return {"status": "ok", "runs": runs}


@api_router.get("/benchmark/runs/{run_id}")
async def benchmark_run_detail(run_id: str) -> dict[str, Any]:
    """One stored benchmark run with all fixture results."""
    conn = _benchmark_connection()
    if conn is None:
        raise HTTPException(status_code=404, detail="benchmark run not found")
    try:
        run = benchmark_store.get_run(conn, run_id)
    finally:
        conn.close()
    if run is None:
        raise HTTPException(status_code=404, detail="benchmark run not found")
    payload = BenchmarkRunDetail(**run).model_dump()
    payload["store"] = str(benchmark_store.default_benchmark_db_path())
    return payload


@api_router.get("/benchmark/baseline")
async def benchmark_baseline() -> dict[str, Any]:
    """The stored baseline run (PROTOCOL §9.6), or the empty state."""
    conn = _benchmark_connection()
    if conn is None:
        return {"status": "empty"}
    try:
        run = benchmark_store.get_baseline(conn)
    finally:
        conn.close()
    if run is None:
        return {"status": "no_baseline"}
    payload = BenchmarkRunDetail(**run).model_dump()
    payload["status"] = "ok"
    payload["store"] = str(benchmark_store.default_benchmark_db_path())
    return payload


@api_router.get("/benchmark/compare")
async def benchmark_compare(run_id: str | None = None) -> dict[str, Any]:
    """Compare a stored run (default: latest) against the stored baseline.

    Read-only consistency check per PROTOCOL §9.6: verdict/metric judgments
    are suppressed when the comparison is not like-for-like.
    """
    from auditor.benchmark import compare_runs

    conn = _benchmark_connection()
    if conn is None:
        return {"status": "empty"}
    try:
        baseline = benchmark_store.get_baseline(conn)
        if run_id:
            current = benchmark_store.get_run(conn, run_id)
            if current is None:
                raise HTTPException(status_code=404, detail="benchmark run not found")
        else:
            current = benchmark_store.get_latest(conn)
    finally:
        conn.close()
    if current is None:
        return {"status": "empty"}
    if baseline is None:
        return {"status": "no_baseline", "current_run_id": current.get("run_id")}
    comparison = compare_runs(current, baseline)
    return {
        "status": "ok",
        "current_run_id": current.get("run_id"),
        "comparison": comparison,
    }


def _recorded_compile_options(cache_dir: Path):  # back-compat alias
    from auditor.source_resolver import recorded_compile_options
    return recorded_compile_options(cache_dir)


def _review_con():
    from auditor import review_panel as P
    db = P.default_review_db()
    if not Path(db).exists():
        return None
    return P.connect(db)


@api_router.get("/review-panel/summary")
async def review_panel_summary() -> dict[str, Any]:
    """Panel summary from the isolated review DB. Empty (not zero) when never run."""
    from auditor import review_panel as P
    con = _review_con()
    if con is None:
        return {"available": False, "message": "review panel has not run yet"}
    try:
        return dict(P.panel_summary(con), available=True)
    finally:
        con.close()


@api_router.get("/review-panel/finding/{finding_id}")
async def review_panel_finding(finding_id: int) -> dict[str, Any]:
    from auditor import review_panel as P
    con = _review_con()
    p = P.panel_for(con, finding_id) if con is not None else None
    if con is not None:
        con.close()
    if p is None:
        return {"finding_id": finding_id, "reviewed": False}
    return dict(p, reviewed=True)


@api_router.get("/hunt/strategies")
async def hunt_strategies() -> dict[str, Any]:
    """Read-only status of the 7 hunting strategy stages. Unknown stays None."""
    import json as _json
    from auditor.monitor import default_monitor_db_path
    from auditor import disclosure

    out: dict[str, Any] = {"fork_diff": None, "known_exploit_findings": None,
                           "disclosures": len(list(disclosure.DISCLOSURE_DIR.glob("*.md")))
                           if disclosure.DISCLOSURE_DIR.exists() else 0,
                           "confirmed_exploitable": None}
    db = default_monitor_db_path()
    if Path(db).exists():
        con = sqlite3.connect(f"file:{db}?mode=ro", uri=True, timeout=2)
        try:
            try:
                rows = con.execute("SELECT address, family, changed_json, computed_at FROM fork_diffs "
                                   "ORDER BY computed_at DESC LIMIT 20").fetchall()
                out["fork_diff"] = []
                for a, f, j, t in rows:
                    ds = _json.loads(j)
                    same = sum(d.get("unchanged") or 0 for d in ds)
                    changed = [c["function"] for d in ds for c in d.get("changed") or []]
                    out["fork_diff"].append({
                        "address": a, "family": f, "computed_at": t, "changed": changed,
                        "unchanged": same, "no_reference": sum(d.get("no_reference") or 0 for d in ds),
                        # 0 changed with 0 unchanged means no reference, not "unmodified"
                        "conclusive": bool(changed or same)})
            except sqlite3.Error:
                out["fork_diff"] = []
            out["known_exploit_findings"] = {r[0]: r[1] for r in con.execute(
                "SELECT detector, COUNT(*) FROM monitor_findings WHERE finding_json LIKE '%known_exploits%' "
                "GROUP BY detector")}
            out["confirmed_exploitable"] = con.execute(
                "SELECT COUNT(*) FROM monitor_findings WHERE confirmed_exploitable=1").fetchone()[0]
            try:
                out["proxy_init"] = {
                    "by_status": {r[0]: r[1] for r in con.execute(
                        "SELECT status, COUNT(*) FROM proxy_init_sweeps GROUP BY status")},
                    "recent_flags": [{"address": r[0], "status": r[1], "kinds": r[2], "checked_at": r[3]}
                                     for r in con.execute(
                        "SELECT address, status, kinds, checked_at FROM proxy_init_sweeps WHERE kinds != '' "
                        "ORDER BY checked_at DESC LIMIT 20")]}
            except sqlite3.Error:
                out["proxy_init"] = None  # stage has not run yet: unknown, not zero
            # Seven hunting methods — real DB-backed statuses (never invent "pass")
            try:
                fuzz_n = con.execute("SELECT COUNT(*) FROM simulate_runs").fetchone()[0]
                fuzz_fail = con.execute(
                    "SELECT COUNT(*) FROM simulate_runs WHERE status='failed_invariants'").fetchone()[0]
            except sqlite3.Error:
                fuzz_n = None
                fuzz_fail = None
            try:
                kx = out.get("known_exploit_findings") or {}
                kx_n = sum(kx.values()) if isinstance(kx, dict) else 0
            except Exception:
                kx_n = 0
            fd = out.get("fork_diff")
            pi = out.get("proxy_init")
            out["methods"] = {
                "thin_defense": {
                    "status": "completed_with_findings" if kx_n else "completed_without_findings",
                    "evidence": f"known-exploit detector hits: {kx_n}",
                },
                "fork_diff": {
                    "status": ("completed_with_findings" if fd else "not_scheduled"),
                    "evidence": ({"count": len(fd), "sample": [x.get("address") for x in fd[:5]]} if isinstance(fd, list) else "no rows"),
                },
                "exploit_pattern": {
                    "status": "completed_with_findings" if kx_n else "completed_without_findings",
                    "evidence": kx if isinstance(kx, dict) else {},
                },
                "invariant_fuzz": {
                    "status": "completed_with_findings" if (fuzz_n or 0) > 0 else "not_scheduled",
                    "evidence": f"simulate_runs={fuzz_n}; failed_invariants={fuzz_fail}",
                },
                "oracle": {
                    "status": "n/a",
                    "evidence": "oracle stage present in simulate_oracles; per-candidate status TBD",
                },
                "proxy_init": {
                    "status": ("completed_with_findings" if (pi and (pi.get('by_status') or {}).get('flagged'))
                               else ("completed_without_findings" if pi else "not_scheduled")),
                    "evidence": pi.get("by_status") if isinstance(pi, dict) else None,
                },
                "verify_private_report": {
                    "status": "completed_with_findings" if (out.get("disclosures") or 0) > 0 else "not_scheduled",
                    "evidence": f"disclosure packages={out.get('disclosures')}",
                },
            }
        finally:
            con.close()
    if "methods" not in out:
        out["methods"] = {m: {"status": "unknown", "evidence": None} for m in
                          ("thin_defense", "fork_diff", "exploit_pattern", "invariant_fuzz",
                           "oracle", "proxy_init", "verify_private_report")}
    return out

@api_router.get("/tools/probe")
async def tools_probe() -> dict[str, Any]:
    """Installed analyzer tools and support status (no secrets, no network installs)."""
    from auditor.tool_adapters.base import probe_all
    return probe_all()

