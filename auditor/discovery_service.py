"""Local supervisor for continuous Ethereum discovery and periodic DeFi hunts.

The monitor and hunter remain separate, bounded command-line workers. This
module owns their lifecycle and stores a compact heartbeat in the existing
monitor database so the dashboard can distinguish active, degraded, stale,
and stopped runs across page reloads.
"""
from __future__ import annotations

import json
import os
import re
import signal
import sqlite3
import subprocess
import threading
import time
from pathlib import Path
from typing import Any, Dict, Optional

from auditor.monitor import default_monitor_db_path
from auditor.supervisor import EXIT_BUSY, WorkerLock, worker_lock_path

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
_STATE_KEY = "ethereum-discovery"
_lock = threading.RLock()
_stop_event: Optional[threading.Event] = None
_thread: Optional[threading.Thread] = None
_processes: Dict[str, subprocess.Popen] = {}
_state: Dict[str, Any] = {
    "status": "idle", "stage": "idle", "message": "Live Ethereum discovery is stopped",
    "started_at": None, "heartbeat_at": None, "finished_at": None,
    "children": {"monitor": {"status": "idle"}, "hunt": {"status": "idle"}}, "events": [],
}


def _connect() -> sqlite3.Connection:
    path = default_monitor_db_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path), timeout=5.0)
    conn.execute("PRAGMA busy_timeout=5000")
    conn.execute(
        "CREATE TABLE IF NOT EXISTS dashboard_worker_state ("
        "worker TEXT PRIMARY KEY, payload_json TEXT NOT NULL, updated_at REAL NOT NULL)"
    )
    return conn


def _persist(payload: Dict[str, Any]) -> None:
    try:
        conn = _connect()
        conn.execute(
            "INSERT INTO dashboard_worker_state(worker,payload_json,updated_at) VALUES(?,?,?) "
            "ON CONFLICT(worker) DO UPDATE SET payload_json=excluded.payload_json,updated_at=excluded.updated_at",
            (_STATE_KEY, json.dumps(payload, sort_keys=True, default=str), time.time()),
        )
        conn.commit()
        conn.close()
    except sqlite3.Error:
        # The supervisor keeps running if status persistence is temporarily busy.
        pass


def _saved_state() -> Dict[str, Any]:
    try:
        conn = sqlite3.connect(f"file:{default_monitor_db_path()}?mode=ro", uri=True, timeout=1.5)
        row = conn.execute(
            "SELECT payload_json FROM dashboard_worker_state WHERE worker=?", (_STATE_KEY,)
        ).fetchone()
        conn.close()
        value = json.loads(row[0]) if row else {}
        return value if isinstance(value, dict) else {}
    except (sqlite3.Error, OSError, ValueError):
        return {}


def _set_state(**changes: Any) -> None:
    global _state
    with _lock:
        changed = any(_state.get(key) != value for key, value in changes.items()
                      if key in {"status", "stage", "message"})
        _state.update(changes)
        _state["heartbeat_at"] = time.time()
        if changed:
            events = list(_state.get("events") or [])
            events.append({"at": time.time(), "component": "supervisor",
                           "stage": _state.get("stage"), "message": _state.get("message")})
            _state["events"] = events[-100:]
        snapshot = json.loads(json.dumps(_state, default=str))
    _persist(snapshot)


def _set_child(name: str, **changes: Any) -> None:
    with _lock:
        children = dict(_state.get("children") or {})
        child = dict(children.get(name) or {})
        event_message = changes.get("last_event")
        changed_stage = changes.get("stage") is not None and child.get("stage") != changes.get("stage")
        child.update(changes)
        child["heartbeat_at"] = time.time()
        children[name] = child
        _state["children"] = children
        _state["heartbeat_at"] = time.time()
        if name == "hunt" and changes.get("stage"):
            _state["stage"] = changes["stage"]
        elif name == "monitor" and changes.get("block") is not None:
            _state["stage"] = "discover"
        if event_message or changed_stage:
            events = list(_state.get("events") or [])
            events.append({"at": time.time(), "component": name,
                           "stage": child.get("stage"),
                           "message": str(event_message or child.get("message") or "")[:500]})
            _state["events"] = events[-100:]
        snapshot = json.loads(json.dumps(_state, default=str))
    _persist(snapshot)


def _reader(name: str, proc: subprocess.Popen) -> None:
    stream = proc.stdout
    if stream is None:
        return
    for raw in iter(stream.readline, ""):
        line = raw.strip()
        if not line:
            continue
        update: Dict[str, Any] = {"last_event": line[:500]}
        if line.startswith("pipeline:stage="):
            update["stage"] = line.partition("=")[2].strip()
        if name == "monitor":
            m = re.search(r"indexed block (\d+)/(\d+).*?(?:head (\d+))?", line)
            if m:
                update.update({"block": int(m.group(1)), "block_batch_end": int(m.group(2))})
                if m.group(3):
                    update["head"] = int(m.group(3))
            if "WebSocket unavailable" in line:
                update["stream"] = "http_poll_fallback"
            elif "newHeads notification" in line:
                update["stream"] = "websocket"
                try:
                    update["head"] = int(line.split("notification", 1)[1].split("(", 1)[0].strip(), 16)
                except (IndexError, ValueError):
                    pass
        elif line.startswith("pipeline:stage="):
            update["message"] = line.partition("=")[2].strip().replace("_", " ")
        elif line.startswith("hunt:"):
            update["message"] = line[:240]
        elif name == "hunt" and line.startswith("cycle:"):
            update.update({"stage": "waiting", "message": line[:240]})
        elif line.startswith(("warning:", "error:")):
            update["message"] = line[:240]
        _set_child(name, **update)
    code = proc.wait()
    current = dict((_state.get("children") or {}).get(name) or {})
    if code == 0:
        status, error = "completed", None
    elif code == EXIT_BUSY:
        # The worker refuses to start while another instance holds the
        # per-worker lock (e.g. a standalone watchdog is supervising it).
        status, error = "running_elsewhere", "already running outside the dashboard (worker lock held)"
    else:
        status, error = "failed", (current.get("last_event") or "worker exited")
    _set_child(name, status=status, returncode=code, error=error)


def _launch(name: str, command: list[str]) -> subprocess.Popen:
    proc = subprocess.Popen(
        command, cwd=str(_PROJECT_ROOT), stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, encoding="utf-8", errors="replace", bufsize=1,
        env={**os.environ, "PYTHONUNBUFFERED": "1"},
    )
    with _lock:
        _processes[name] = proc
    _set_child(name, status="running", pid=proc.pid, started_at=time.time(),
               stage="discover" if name == "monitor" else "queued", last_event="Worker started")
    threading.Thread(target=_reader, args=(name, proc), name=f"discovery-{name}-output", daemon=True).start()
    return proc


def _worker_lock_held(kind: str) -> Optional[Dict[str, Any]]:
    """Check the per-worker lock so the dashboard never spawns a second copy
    while a standalone watchdog (or a manually started worker) owns it."""
    try:
        lock = WorkerLock(worker_lock_path(default_monitor_db_path(), kind, "ethereum"))
        status, info = lock.probe()
    except OSError:  # lock path unwritable: fall back to old behavior
        return None
    return info if status == "held" else None


def _supervise(stop_event: threading.Event) -> None:
    global _processes
    monitor_cmd = [
        str(_PROJECT_ROOT / "scripts" / "run_monitor.sh"), "--interval", "15",
        "--max-blocks-per-poll", "100", "--max-per-poll", "2",
    ]
    hunt_cmd = [
        str(_PROJECT_ROOT / "scripts" / "run_hunt.sh"), "--interval", "300",
        "--with-pools", "--pool-lookback", "50000", "--min-holder-usd", "10000",
        "--no-blue-chips", "--max-scan", "10", "--max-measure", "40",
        "--max-sim-per-cycle", "1",
    ]
    try:
        _set_state(status="running", stage="discover",
                   message="Live monitor indexing new heads; periodic hunt is starting",
                   started_at=_state.get("started_at") or time.time(), finished_at=None)
        monitor = None
        hunt = None
        monitored = _worker_lock_held("monitor")
        if monitored is None:
            monitor = _launch("monitor", monitor_cmd)
        else:
            _set_child("monitor", status="running_elsewhere", pid=monitored.get("pid"),
                       message="already running outside the dashboard (worker lock held)")
        hunted = _worker_lock_held("hunt")
        if hunted is None:
            hunt = _launch("hunt", hunt_cmd)
        else:
            _set_child("hunt", status="running_elsewhere", pid=hunted.get("pid"),
                       message="already running outside the dashboard (worker lock held)")
        pairs = [("monitor", monitor), ("hunt", hunt)]
        while not stop_event.wait(2.0):
            children = dict(_state.get("children") or {})
            alive = [name for name, proc in pairs
                     if proc is not None and proc.poll() is None]
            elsewhere = any((children.get(name) or {}).get("status") == "running_elsewhere"
                            for name, _ in pairs)
            failed = any((children.get(name) or {}).get("status") == "failed" for name, _ in pairs)
            if not alive:
                _set_state(status="failed" if failed and not elsewhere
                           else ("running" if elsewhere else "completed"),
                           stage="complete",
                           message=("Workers are running outside the dashboard (worker lock held)"
                                    if elsewhere and not failed else
                                    ("One worker failed; inspect its last event" if failed else
                                     "Discovery workers exited; inspect each worker's last event.")),
                           finished_at=time.time() if not elsewhere else None)
                return
            status = "degraded" if failed else ("running" if not elsewhere else "degraded")
            _set_state(status=status,
                       message=("Workers are running outside the dashboard; this dashboard is not "
                                "supervising them" if elsewhere and not failed else
                                ("One worker failed; the other continues" if failed else
                                 "Monitoring chain heads and running periodic high-value hunts")))
        _set_state(status="stopping", message="Stopping live discovery workers")
        with _lock:
            procs = list(_processes.values())
        for proc in procs:
            if proc.poll() is None:
                try:
                    proc.send_signal(signal.SIGINT)
                except OSError:
                    pass
        deadline = time.monotonic() + 12
        for proc in procs:
            if proc.poll() is None:
                try:
                    proc.wait(timeout=max(0.1, deadline - time.monotonic()))
                except subprocess.TimeoutExpired:
                    proc.terminate()
                    try:
                        proc.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        proc.kill()
        _set_state(status="stopped", stage="idle", message="Live Ethereum discovery stopped",
                   finished_at=time.time())
    except Exception as exc:  # noqa: BLE001
        _set_state(status="failed", stage="failed",
                   message=f"Could not start live discovery ({type(exc).__name__})",
                   error=type(exc).__name__, finished_at=time.time())
    finally:
        with _lock:
            _processes = {}


def start() -> Dict[str, Any]:
    global _thread, _stop_event, _state
    with _lock:
        if _thread is not None and _thread.is_alive():
            return status()
        previous = _saved_state()
        if previous.get("status") == "running" and time.time() - float(previous.get("heartbeat_at") or 0) < 45:
            return previous
        _state = {
            "status": "starting", "stage": "discover",
            "message": "Starting continuous Ethereum discovery",
            "started_at": time.time(), "heartbeat_at": time.time(), "finished_at": None,
            "children": {"monitor": {"status": "starting"}, "hunt": {"status": "starting"}},
        }
        _persist(dict(_state))
        _stop_event = threading.Event()
        _thread = threading.Thread(target=_supervise, args=(_stop_event,),
                                   name="ethereum-live-discovery", daemon=True)
        _thread.start()
        return dict(_state)


def stop() -> Dict[str, Any]:
    with _lock:
        event = _stop_event
        if event is None or not (_thread and _thread.is_alive()):
            saved = _saved_state()
            saved.update({"status": "stopped", "stage": "idle",
                          "message": "Live Ethereum discovery is stopped", "finished_at": time.time()})
            _persist(saved)
            return saved
        event.set()
        procs = list(_processes.values())
    for proc in procs:
        if proc.poll() is None:
            try:
                proc.send_signal(signal.SIGINT)
            except OSError:
                pass
    _set_state(status="stopping", message="Stop requested; workers are finishing their current read-only stage")
    return dict(_state)


def shutdown(timeout: float = 15.0) -> None:
    """Ask children to exit and give the supervisor a short graceful window."""
    with _lock:
        if not (_thread and _thread.is_alive()):
            return
    stop()
    thread = _thread
    if thread is not None and thread.is_alive():
        thread.join(max(0.0, float(timeout)))


def _metrics() -> Dict[str, Any]:
    path = default_monitor_db_path()
    out: Dict[str, Any] = {}
    if not path.exists():
        return out
    conn: Optional[sqlite3.Connection] = None
    try:
        conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=1.5)
        conn.row_factory = sqlite3.Row
        tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if "monitor_cursor" in tables:
            row = conn.execute("SELECT last_block,updated_at FROM monitor_cursor WHERE network='ethereum'").fetchone()
            if row:
                out["last_block_indexed"] = int(row[0])
                out["cursor_updated_at"] = row[1]
        if "monitor_queue" in tables:
            out["queue"] = {str(r[0]): int(r[1]) for r in conn.execute(
                "SELECT status,COUNT(*) FROM monitor_queue WHERE network='ethereum' GROUP BY status")}
        if "monitor_scans" in tables:
            scan_cols = {r[1] for r in conn.execute("PRAGMA table_info(monitor_scans)")}
            if {"snapshot_block", "snapshot_finality"}.issubset(scan_cols):
                row = conn.execute(
                    "SELECT snapshot_block,snapshot_finality FROM monitor_scans "
                    "WHERE network='ethereum' AND snapshot_block IS NOT NULL "
                    "ORDER BY started_at DESC LIMIT 1"
                ).fetchone()
                if row:
                    out["read_snapshot"] = {"block": int(row[0]), "finality": row[1]}
        if "hunt_candidates" in tables:
            out["candidates"] = {str(r[0]): int(r[1]) for r in conn.execute(
                "SELECT status,COUNT(*) FROM hunt_candidates WHERE network='ethereum' GROUP BY status")}
            exact = 0
            for row in conn.execute("SELECT discovery_json FROM hunt_candidates WHERE network='ethereum'"):
                try:
                    data = json.loads(row[0] or "{}")
                    exact += int((data.get("source_verification") or {}).get("identity_status") == "exact_match")
                except (TypeError, ValueError):
                    continue
            out["exact_source_matches"] = exact
        if "hunt_runs" in tables:
            row = conn.execute(
                "SELECT at,discovered,measured,scanned,error,stats_json FROM hunt_runs "
                "WHERE network='ethereum' ORDER BY at DESC LIMIT 1"
            ).fetchone()
            if row:
                out["last_hunt"] = {"at": row["at"], "discovered": row["discovered"],
                                    "measured": row["measured"], "scanned": row["scanned"],
                                    "error": row["error"]}
                try:
                    details = json.loads(row["stats_json"] or "{}")
                except (ValueError, TypeError):
                    details = {}
                out["disk_pressure"] = details.get("disk_pressure")
                out["disk_deferred"] = details.get("disk_deferred") or []
    except sqlite3.Error as exc:
        out["metrics_error"] = type(exc).__name__
    finally:
        if conn is not None:
            conn.close()
    return out


def status(include_metrics: bool = True) -> Dict[str, Any]:
    with _lock:
        current = json.loads(json.dumps(_state, default=str))
        alive = bool(_thread and _thread.is_alive())
    if not alive:
        saved = _saved_state()
        if saved:
            current = saved
    heartbeat = float(current.get("heartbeat_at") or 0)
    if current.get("status") in {"running", "starting", "degraded"} and time.time() - heartbeat > 45:
        current["status"] = "stale"
        current["message"] = "No supervisor heartbeat recently; check worker logs and restart discovery"
    if include_metrics:
        current["metrics"] = _metrics()
        child_head = ((current.get("children") or {}).get("monitor") or {}).get("head")
        indexed = current["metrics"].get("last_block_indexed")
        if child_head is not None and indexed is not None:
            current["metrics"]["block_lag"] = max(0, int(child_head) - int(indexed))
    current["generated_at"] = time.time()
    return current
