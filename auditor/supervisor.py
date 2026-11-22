"""Standalone supervision of the monitor and hunt workers (P1 step 1).

The workers stay exactly what they were — bounded CLI processes
(``audit.py monitor`` / ``audit.py hunt``, normally launched through
``scripts/run_monitor.sh`` / ``scripts/run_hunt.sh``). This module adds three
additive pieces around them, without duplicating any worker logic:

1. **Per-worker cross-process locks** (``worker_lock_path``) so two copies of
   the same worker can never run at the same time. The lock is a POSIX
   ``flock`` held for the worker's whole run and released automatically by the
   kernel when the process exits or dies. Every spawn path benefits: manual
   ``run_monitor.sh``, the dashboard's discovery service, and this module's
   watchdog all launch the same workers, and the workers themselves enforce
   single instance. A worker that finds its lock held exits with
   :data:`EXIT_BUSY` so a supervisor can tell "already running elsewhere"
   apart from a crash.
2. **Worker self-heartbeats** written to the existing ``dashboard_worker_state``
   table of the monitor DB (the same table the dashboard's discovery service
   already uses). Rows are additive: the combined dashboard row
   (``ethereum-discovery``) is untouched. ``evaluate_workers`` resolves each
   worker to ``running`` / ``stale`` / ``stopped`` / ``never_started`` /
   ``db_unavailable`` so a stale heartbeat is never mistaken for "the database
   is broken" or "nothing ever started".
3. **A watchdog** (:class:`Supervisor`) that spawns the workers and restarts
   them after unexpected exits with bounded exponential backoff, gives up
   after a configurable number of consecutive failures, and stops children
   cleanly on SIGINT/SIGTERM (launchd/system-restart friendly). Under
   ``--once`` it runs a single supervision round, stops its children, and
   exits — useful for smoke tests; it never launches a scan cycle of its own.

Everything here is local-only: no chain calls, no model calls, no keys. DB
use is limited to heartbeat rows (best-effort writes) and ``mode=ro`` reads.
POSIX only (``fcntl``).
"""

from __future__ import annotations

import fcntl
import json
import logging
import os
import signal
import sqlite3
import subprocess
import sys
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Tuple

log = logging.getLogger("contract_auditor.supervisor")

_PROJECT_ROOT = Path(__file__).resolve().parent.parent

#: Worker exit code meaning "another instance holds the local worker lock".
#: A supervisor uses it to distinguish "already running elsewhere" from a crash.
EXIT_BUSY = 7
#: Watchdog-check exit code for an unusable monitor database (distinct from
#: stale, which is 1, and fresh, which is 0).
EXIT_DB_UNAVAILABLE = 2

WORKER_KINDS: Tuple[str, ...] = ("monitor", "hunt")

_HEARTBEAT_TABLE_SQL = (
    "CREATE TABLE IF NOT EXISTS dashboard_worker_state ("
    "worker TEXT PRIMARY KEY, payload_json TEXT NOT NULL, updated_at REAL NOT NULL)"
)


class LockError(Exception):
    """Base class for worker-lock failures."""


class LockHeld(LockError):
    """The worker lock is held by another holder (another process or thread)."""

    def __init__(self, message: str, *, pid: Optional[int] = None,
                 info: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(message)
        self.pid = pid
        self.info = info or {}


class LockUnavailable(LockError):
    """The lock file cannot be created/opened (missing directory, permissions)."""


# ---------------------------------------------------------------------------
# Cross-process worker lock
# ---------------------------------------------------------------------------

@dataclass
class _LockEntry:
    fd: int
    thread: int


_ENTRIES: Dict[str, _LockEntry] = {}
_ENTRIES_MUTEX = threading.Lock()


class LockHandle:
    """Released by :meth:`release`; release is idempotent, and works as a
    context manager."""

    def __init__(self, path: Path, entry: _LockEntry) -> None:
        self.path = path
        self._entry = entry
        self.released = False

    @property
    def pid(self) -> int:
        return os.getpid()

    def __enter__(self) -> "LockHandle":
        return self

    def __exit__(self, _exc_type, _exc, _tb) -> None:
        self.release()

    def release(self) -> None:
        if self.released:
            return
        self.released = True
        with _ENTRIES_MUTEX:
            entry = _ENTRIES.pop(str(self.path), None)
        if entry is not self._entry:
            # Registry already replaced (defensive); still release our fd.
            entry = self._entry
        try:
            Path(self.path).unlink()
        except OSError:
            pass
        try:
            fcntl.flock(entry.fd, fcntl.LOCK_UN)
        except OSError:
            pass
        try:
            os.close(entry.fd)
        except OSError:
            pass


class WorkerLock:
    """Exclusive lock file: kernel ``flock`` + PID content.

    One holder per path, period — a second ``acquire`` raises
    :class:`LockHeld` no matter whether the current holder is another
    process, another thread, or (nested) the same thread, so two copies of
    the same worker can never overlap. The lock is released automatically by
    the kernel when the owning process dies.
    """

    def __init__(self, path: Path | str) -> None:
        self.path = Path(path)

    def _content(self) -> Dict[str, Any]:
        return {
            "pid": os.getpid(),
            "argv": [str(a) for a in sys.argv[:6]],
            "started_at": time.time(),
        }

    def acquire(self) -> LockHandle:
        key = str(self.path)
        with _ENTRIES_MUTEX:
            entry = _ENTRIES.get(key)
            if entry is not None:
                holder = ("another thread of this process"
                          if entry.thread != threading.get_ident()
                          else "this process (nested acquire)")
                raise LockHeld(
                    f"worker lock already held ({self.path.name}) — {holder}",
                    pid=os.getpid(),
                    info={"pid": os.getpid(), "holder_thread": entry.thread})
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(self.path, os.O_RDWR | os.O_CREAT | os.O_CLOEXEC, 0o600)
        except OSError as exc:
            raise LockUnavailable(f"cannot open worker lock {self.path}: {exc}") from exc
        try:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError as exc:
                info = self.read() or {}
                pid = info.get("pid") if isinstance(info, dict) else None
                os.close(fd)
                raise LockHeld(
                    f"worker lock held by another process"
                    + (f" (pid {pid})" if isinstance(pid, int) else "")
                    + f": {self.path.name}", pid=pid if isinstance(pid, int) else None,
                    info=info) from exc
            content = self._content()
            try:
                os.lseek(fd, 0, os.SEEK_SET)
                os.ftruncate(fd, 0)
                os.write(fd, (json.dumps(content, sort_keys=True) + "\n").encode("utf-8"))
            except OSError:
                pass  # descriptive content is best-effort; the flock is the lock
            new_entry = _LockEntry(fd=fd, thread=threading.get_ident())
            with _ENTRIES_MUTEX:
                _ENTRIES[key] = new_entry
            return LockHandle(self.path, new_entry)
        except BaseException:
            try:
                os.close(fd)
            except OSError:
                pass
            raise

    @contextmanager
    def hold(self):
        handle = self.acquire()
        try:
            yield handle
        finally:
            handle.release()

    def read(self) -> Optional[Dict[str, Any]]:
        """Return the descriptive content of the lock file, or None."""
        try:
            raw = self.path.read_bytes()
        except OSError:
            return None
        try:
            value = json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return None
        return value if isinstance(value, dict) else None

    def probe(self) -> Tuple[str, Optional[Dict[str, Any]]]:
        """``("free", info_or_None)`` or ``("held", info)``.

        Never blocks, and never creates the lock file: a missing file cannot
        be held by anyone, so it is reported as free.
        """
        try:
            fd = os.open(self.path, os.O_RDWR | os.O_CLOEXEC)
        except OSError:
            return ("free", None)  # no file → nobody can hold it
        try:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError:
                return ("held", self.read())
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
            except OSError:
                pass
            return ("free", self.read())
        finally:
            try:
                os.close(fd)
            except OSError:
                pass


def worker_lock_path(db_path: Path | str, kind: str, network: str) -> Path:
    """Lock file colocated with the monitor database (so env overrides in
    tests/production move it together with the state it protects)."""
    return Path(db_path).expanduser().parent / f".worker-{kind}-{network}.lock"


def watchdog_lock_path(db_path: Path | str) -> Path:
    return Path(db_path).expanduser().parent / ".watchdog.lock"


# ---------------------------------------------------------------------------
# Worker self-heartbeats (dashboard_worker_state)
# ---------------------------------------------------------------------------

def record_worker_heartbeat(db_path: Path | str, worker: str, payload: Dict[str, Any],
                            *, at: Optional[float] = None) -> bool:
    """Best-effort upsert of one worker heartbeat row. Never raises."""
    stamp = time.time() if at is None else float(at)
    conn: Optional[sqlite3.Connection] = None
    try:
        conn = sqlite3.connect(str(db_path), timeout=5.0)
        conn.execute("PRAGMA busy_timeout=5000")
        conn.execute(_HEARTBEAT_TABLE_SQL)
        conn.execute(
            "INSERT INTO dashboard_worker_state(worker,payload_json,updated_at) VALUES(?,?,?) "
            "ON CONFLICT(worker) DO UPDATE SET payload_json=excluded.payload_json,"
            "updated_at=excluded.updated_at",
            (worker, json.dumps(payload, sort_keys=True, default=str), stamp),
        )
        conn.commit()
        return True
    except sqlite3.Error:
        log.debug("watchdog: heartbeat write for %s failed (continuing)", worker, exc_info=True)
        return False
    finally:
        if conn is not None:
            try:
                conn.close()
            except sqlite3.Error:
                pass


def read_worker_states(db_path: Path | str, workers: Optional[Iterable[str]] = None
                       ) -> Tuple[Dict[str, Dict[str, Any]], Optional[str]]:
    """Read-only read of worker heartbeat rows.

    Returns ``(states, error)``. ``states[key] = {"payload": dict,
    "updated_at": float}``. A missing database file or table is ``({}, None)``
    — nothing has ever written heartbeats, which is *not* a database error.
    Any other read failure (corruption, permissions, locks) is reported as a
    non-None error string so callers can distinguish ``db_unavailable`` from
    ``never_started``.Reads never create the database or table.
    """
    path = Path(db_path).expanduser()
    if not path.exists():
        return {}, None
    conn: Optional[sqlite3.Connection] = None
    try:
        conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=1.5)
    except sqlite3.Error as exc:
        return {}, exc.__class__.__name__
    try:
        try:
            rows = conn.execute(
                "SELECT worker,payload_json,updated_at FROM dashboard_worker_state").fetchall()
        except sqlite3.OperationalError as exc:
            if "no such table" in str(exc):
                return {}, None
            return {}, f"{exc.__class__.__name__}: {exc}"
        except sqlite3.DatabaseError as exc:
            return {}, f"{exc.__class__.__name__}: {exc}"
    finally:
        try:
            conn.close()
        except sqlite3.Error:
            pass
    wanted = set(workers) if workers is not None else None
    states: Dict[str, Dict[str, Any]] = {}
    for worker, payload_json, updated_at in rows:
        try:
            payload = json.loads(payload_json) if payload_json else {}
        except (TypeError, ValueError):
            payload = {}
        if not isinstance(payload, dict):
            payload = {}
        try:
            stamp = float(updated_at)
        except (TypeError, ValueError):
            stamp = 0.0
        if wanted is not None and worker not in wanted:
            continue
        states[worker] = {"payload": payload, "updated_at": stamp}
    return states, None


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return False
    return True


def evaluate_workers(db_path: Path | str, network: str = "ethereum",
                     kinds: Sequence[str] = WORKER_KINDS, *, stale_after: float = 600.0,
                     now: Optional[float] = None) -> Dict[str, Any]:
    """Resolve worker states, distinguishing the four request cases.

    States (per worker kind):
      * ``running``        — the worker lock is held (kernel truth: the hold
        survives only while the owning process is alive on this machine).
      * ``stale``          — lock released and the last heartbeat is older
        than ``stale_after`` seconds.
      * ``stopped``        — lock released, heartbeat fresh (a worker that
        exited within the threshold).
      * ``never_started``  — no heartbeat row at all and no lock held.
      * ``db_unavailable`` — the monitor database cannot be read
        (corruption/permissions); every worker gets this state and the
        report carries ``db_error``.
    """
    now = time.time() if now is None else float(now)
    states, db_error = read_worker_states(db_path)
    report: Dict[str, Any] = {
        "network": network,
        "stale_after": float(stale_after),
        "db_error": db_error,
        "workers": {},
        "generated_at": now,
    }
    for kind in kinds:
        name = f"{kind}-{network}"
        lock = WorkerLock(worker_lock_path(db_path, kind, network))
        lock_status, lock_info = lock.probe()
        beat = states.get(name)
        age = None if beat is None else max(0.0, now - float(beat["updated_at"]))
        worker: Dict[str, Any] = {
            "kind": kind,
            "worker": name,
            "heartbeat_age_s": round(age, 1) if age is not None else None,
        }
        if db_error:
            state = "db_unavailable"
        elif lock_status == "held":
            state = "running"
        elif beat is None:
            state = "never_started"
        elif age is None or age > float(stale_after):
            state = "stale"
        else:
            state = "stopped"
        worker["state"] = state
        if isinstance(lock_info, dict) and isinstance(lock_info.get("pid"), int):
            worker["pid"] = lock_info["pid"]
            worker["pid_alive"] = _pid_alive(lock_info["pid"])
        if beat is not None:
            worker["heartbeat"] = beat["payload"]
        if lock_info:
            worker["lock"] = lock_info
        report["workers"][kind] = worker
    watchdog = states.get("watchdog")
    if watchdog is not None:
        report["watchdog"] = {
            "heartbeat_age_s": round(max(0.0, now - watchdog["updated_at"]), 1),
            "heartbeat": watchdog["payload"],
        }
    wd_status, wd_info = WorkerLock(watchdog_lock_path(db_path)).probe()
    report["watchdog_lock"] = {"status": wd_status}
    if wd_info:
        report["watchdog_lock"]["info"] = wd_info
    return report


def worker_check_exit(report: Dict[str, Any], *, expect_running: bool = False) -> int:
    """Exit code for ``watchdog check``: 0 fresh, 1 stale, 2 db unavailable."""
    if report.get("db_error"):
        return EXIT_DB_UNAVAILABLE
    workers = report.get("workers") or {}
    states = {w.get("state") for w in workers.values() if isinstance(w, dict)}
    if "stale" in states:
        return 1
    if expect_running and ("stopped" in states or "never_started" in states):
        return 1
    return 0


# ---------------------------------------------------------------------------
# Watchdog supervisor
# ---------------------------------------------------------------------------

@dataclass
class WorkerSpec:
    """One supervised worker: exactly the existing CLI worker, no more."""

    name: str                       # "monitor" | "hunt"
    network: str = "ethereum"
    argv: List[str] = field(default_factory=list)
    enabled: bool = True


@dataclass
class SupervisorSettings:
    restart_backoff_base: float = 5.0      # seconds; doubles per consecutive failure
    restart_backoff_cap: float = 300.0     # upper bound for the backoff delay
    stable_reset_seconds: float = 600.0    # a worker alive this long resets the streak
    max_restarts: int = 20                 # consecutive crashes or rapid clean exits before giving up
    child_grace_seconds: float = 10.0      # SIGINT → wait → SIGTERM → wait → SIGKILL
    stop_settle_seconds: float = 0.5       # let already-exiting children finish first
    poll_interval: float = 2.0             # supervision round cadence
    persist_every: float = 5.0             # watchdog heartbeat write throttle
    # P1 step 2 — heartbeat-wedge recovery. A worker that keeps running but
    # stops updating its heartbeat is signalled (gracefully, escalating) and
    # restarted. 0 = per-kind auto threshold (see _STALE_AUTO_SECONDS).
    stale_recovery: bool = True
    stale_recovery_seconds: float = 0.0    # sustained stale-heartbeat age before recovery
    stale_min_observations: int = 3        # distinct stale rounds required (>= 2)


# Per-kind auto thresholds for heartbeat-wedge recovery. Chosen from measured
# worker behaviour: the monitor beats every poll (60 s interval; normal gap
# 60–100 s; the longest legal poll — ≤20 blocks + ≤5 contract scans at 15 s
# call timeouts — stays well under ~7 min) → 900 s ≈ 10× normal, ≈2× worst
# legal. Hunt writes milestone beats inside each cycle stage and every 60 s
# while waiting between cycles → the longest legal stage gap stays far under
# 1800 s, keeping this conservative for slow RPC calls and long scans.
_STALE_AUTO_SECONDS = {"monitor": 900.0, "hunt": 1800.0}


@dataclass
class _Runtime:
    spec: WorkerSpec
    proc: Any = None
    started_at: Optional[float] = None
    attempts: int = 0
    consecutive: int = 0
    state: str = "never_started"       # never_started|running|backoff|crashed|
    next_start_at: float = 0.0         # running_elsewhere|exited_clean|abandoned|stopped
    last_rc: Optional[int] = None
    held_info: Optional[Dict[str, Any]] = None
    # Heartbeat-wedge recovery state (P1 step 2)
    stale_observations: int = 0        # distinct rounds that saw an over-limit beat
    stale_since: Optional[float] = None
    wedge_started_at: Optional[float] = None   # when the sustained staleness began
    recovering: bool = False
    recovery_stage: int = 0            # 1 SIGINT → 2 SIGTERM → 3 SIGKILL
    recovery_signal_at: float = 0.0
    last_recovery_age: Optional[float] = None

    def reset_stale(self) -> None:
        self.stale_observations = 0
        self.stale_since = None

    def snapshot(self) -> Dict[str, Any]:
        return {
            "state": self.state,
            "pid": self.proc.pid if self.proc is not None else None,
            "attempts": self.attempts,
            "consecutive_failures": self.consecutive,
            "last_rc": self.last_rc,
            "next_start_at": self.next_start_at if self.next_start_at else None,
            "held_info": self.held_info,
        }


class Supervisor:
    """Spawn the workers, restart them with bounded backoff, stop them cleanly.

    ``clock`` / ``sleep`` / ``spawn`` are injectable so tests can drive the
    state machine deterministically. ``spawn(argv, env, cwd)`` defaults to
    ``subprocess.Popen`` with ``start_new_session=True`` so children leave the
    Ctrl-C process group and can be signalled as a group.
    """

    def __init__(self, db_path: Path | str, specs: Sequence[WorkerSpec], *,
                 settings: Optional[SupervisorSettings] = None,
                 clock: Callable[[], float] = time.time,
                 sleep: Callable[[float], None] = time.sleep,
                 emit: Callable[[str], None] = lambda _m: None,
                 spawn: Optional[Callable[..., Any]] = None) -> None:
        self.db_path = Path(db_path)
        self.settings = settings or SupervisorSettings()
        self._clock = clock
        self._sleep = sleep
        self._emit = emit
        self._spawn_fn = spawn or self._default_spawn
        self._runtimes: List[_Runtime] = [ _Runtime(spec=s) for s in specs if s.enabled ]
        self.stop_requested = False
        self.started_at: Optional[float] = None
        self._last_persist = 0.0
        self.events: List[Dict[str, Any]] = []

    # -- helpers ----------------------------------------------------------
    @staticmethod
    def _default_spawn(argv: Sequence[str], env: Dict[str, str], cwd: Path) -> Any:
        return subprocess.Popen(  # noqa: S603 - fixed argv, no shell
            list(argv), cwd=str(cwd), env=env, stdin=subprocess.DEVNULL,
            close_fds=True, start_new_session=True)

    def _spawn_env(self) -> Dict[str, str]:
        return {**os.environ, "PYTHONUNBUFFERED": "1"}

    def _project_root(self) -> Path:
        return _PROJECT_ROOT

    def _note(self, message: str) -> None:
        self._emit(message)
        self.events.append({"at": self._clock(), "message": message})
        self.events = self.events[-100:]

    def request_stop(self, *_args: Any) -> None:
        self.stop_requested = True

    def _lock(self, spec: WorkerSpec) -> WorkerLock:
        return WorkerLock(worker_lock_path(self.db_path, spec.name, spec.network))

    # -- lifecycle --------------------------------------------------------
    def run(self, once: bool = False, stop_event: Optional[Any] = None) -> int:
        wl = WorkerLock(watchdog_lock_path(self.db_path))
        try:
            handle = wl.acquire()
        except LockHeld as exc:
            self._emit(f"watchdog: already running (pid {exc.pid}); not starting a second supervisor")
            return EXIT_BUSY
        handlers: Dict[int, Any] = {}
        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                handlers[sig] = signal.signal(sig, self.request_stop)
            except ValueError:  # not the main thread (tests)
                handlers = {}
                break
        try:
            self.started_at = self._clock()
            self._persist_status("running")
            while not self.stop_requested and not (stop_event is not None and stop_event.is_set()):
                self._round(self._clock())
                self._persist_if_due()
                if once:
                    self.stop_requested = True
                    break
                self._sleep(self.settings.poll_interval)
            self._stop_children()
            self._persist_status("stopped")
        finally:
            handle.release()
            for sig, prev in handlers.items():
                try:
                    signal.signal(sig, prev)
                except Exception:  # noqa: BLE001 - restoring must not mask errors
                    pass
        return 0

    def summary(self) -> Dict[str, Any]:
        return {
            "stop_requested": bool(self.stop_requested),
            "started_at": self.started_at,
            "children": {rt.spec.name: rt.snapshot() for rt in self._runtimes},
            "events": list(self.events)[-50:],
        }

    # -- rounds -----------------------------------------------------------
    def _round(self, now: float) -> None:
        for rt in self._runtimes:
            self._advance(rt, now)

    def _advance(self, rt: _Runtime, now: float) -> None:
        if rt.state == "abandoned":
            return
        status, info = self._lock(rt.spec).probe()
        if rt.proc is not None:
            if rt.recovery_stage:
                self._escalate_recovery(rt, now)
            rc = rt.proc.poll()
            if rc is None:
                if not rt.recovery_stage:
                    self._check_stale(rt, now, status, info)
                return  # still running
            self._reap(rt, rc, now)
            return  # spawn decision happens on a later round
        if status == "held":
            if rt.state != "running_elsewhere":
                pid = info.get("pid") if isinstance(info, dict) else None
                self._note(f"watchdog: {rt.spec.name} is already running "
                           f"(pid {pid}); supervising without a second copy")
            rt.state = "running_elsewhere"
            rt.held_info = info if isinstance(info, dict) else None
            rt.next_start_at = 0.0  # take over as soon as the lock frees
            return
        if self.stop_requested:
            return
        if rt.state == "running_elsewhere":
            rt.state = "crashed"  # lock freed: eligible to start again immediately
        if now < rt.next_start_at:
            return
        argv = list(rt.spec.argv)
        if not argv:
            rt.state = "abandoned"
            self._note(f"watchdog: {rt.spec.name} has an empty command; not starting")
            return
        try:
            proc = self._spawn_fn(argv, self._spawn_env(), self._project_root())
        except OSError as exc:
            rt.consecutive += 1
            rt.state = "crashed"
            rt.next_start_at = now + self._backoff_delay(rt)
            self._note(f"watchdog: could not start {rt.spec.name} worker "
                       f"({exc.__class__.__name__}); retrying later")
            return
        rt.proc = proc
        rt.started_at = now
        rt.attempts += 1
        rt.state = "running"
        rt.held_info = None
        self._note(f"watchdog: started {rt.spec.name} worker (pid {proc.pid})")
        self._persist_status(self._overall_status())

    def _reap(self, rt: _Runtime, rc: int, now: float) -> None:
        alive_seconds = max(0.0, now - (rt.started_at if rt.started_at is not None else now))
        rt.proc = None
        rt.last_rc = rc
        recovering = rt.recovering
        if recovering:
            rt.recovering = False
            rt.recovery_stage = 0
        rt.reset_stale()
        # Streak-reset accounting: for ordinary reaps the child's full uptime
        # counts; for recovery reaps only the run time *before the wedge
        # began* counts, so a child that wedges again and again (each cycle
        # shorter than stable_reset_seconds of genuinely working time) still
        # accumulates the streak and eventually ends in abandoned/degraded.
        if recovering:
            healthy = (rt.wedge_started_at or (rt.started_at or now)) - (rt.started_at or now)
            if healthy >= self.settings.stable_reset_seconds:
                rt.consecutive = 0
            rt.wedge_started_at = None
        elif alive_seconds >= self.settings.stable_reset_seconds:
            rt.consecutive = 0
        if rc == EXIT_BUSY:
            rt.state = "running_elsewhere"
            rt.next_start_at = 0.0
            self._note(f"watchdog: {rt.spec.name} exited with 'already running' (code {EXIT_BUSY})")
        elif recovering:
            # Heartbeat-wedge recovery: the watchdog stopped this child because
            # it stayed alive too long without a heartbeat. It is restarted and
            # the episode counts toward the restart limit; the label stays
            # distinct from a crash, and watchdog/user-directed stop paths
            # (_stop_children) never reach this classification.
            rt.consecutive += 1
            if rt.consecutive > self.settings.max_restarts:
                rt.state = "abandoned"
                self._note(f"watchdog: {rt.spec.name} failed after heartbeat-wedge recovery "
                           f"{rt.consecutive} times in a row; giving up "
                           f"(max_restarts={self.settings.max_restarts})")
            else:
                rt.state = "recovered"
                rt.next_start_at = now + self._backoff_delay(rt)
                age_txt = (f", previous heartbeat {rt.last_recovery_age:.0f}s old"
                           if rt.last_recovery_age is not None else "")
                self._note(f"watchdog: {rt.spec.name} heartbeat-wedge recovery finished{age_txt}; "
                           f"restart in {rt.next_start_at - now:.0f}s")
            rt.last_recovery_age = None
        elif rc == 0:
            # A clean (rc 0) exit is still an unexpected stop for an always-on
            # worker: count rapid repeat clean exits toward the same restart
            # limit so a worker that instantly exits 0 over and over cannot
            # spin forever. The streak was already reset above for a worker
            # alive >= stable_reset_seconds, so long-lived workers restart at
            # the base delay and never accumulate a bogus failure count.
            # (--once and a watchdog-directed stop are unaffected: they end in
            # _stop_children, which records the final state without _reap.)
            rt.consecutive += 1
            if rt.consecutive > self.settings.max_restarts:
                rt.state = "abandoned"
                self._note(f"watchdog: {rt.spec.name} kept exiting cleanly (rc 0) "
                           f"{rt.consecutive} times in a row; giving up "
                           f"(max_restarts={self.settings.max_restarts})")
            else:
                rt.state = "exited_clean"
                rt.next_start_at = now + self._backoff_delay(rt)
                self._note(f"watchdog: {rt.spec.name} exited cleanly after "
                           f"{alive_seconds:.0f}s; restart in {rt.next_start_at - now:.0f}s")
        else:
            rt.consecutive += 1
            if rt.consecutive > self.settings.max_restarts:
                rt.state = "abandoned"
                self._note(f"watchdog: {rt.spec.name} failed {rt.consecutive} times in a row; "
                           f"giving up (max_restarts={self.settings.max_restarts})")
            else:
                rt.state = "crashed"
                rt.next_start_at = now + self._backoff_delay(rt)
                self._note(f"watchdog: {rt.spec.name} exited unexpectedly (code {rc}); "
                           f"restart in {rt.next_start_at - now:.0f}s")
        self._persist_status(self._overall_status())

    def _backoff_delay(self, rt: _Runtime) -> float:
        return min(self.settings.restart_backoff_cap,
                   max(self.settings.restart_backoff_base, 0.0) * (2 ** max(0, rt.consecutive - 1)))

    # -- heartbeat-wedge recovery (P1 step 2) ------------------------------
    def _stale_limit(self, kind: str) -> float:
        """Sustained stale-heartbeat age that qualifies a wedge suspicion."""
        if self.settings.stale_recovery_seconds > 0:
            return float(self.settings.stale_recovery_seconds)
        return _STALE_AUTO_SECONDS.get(kind, 1800.0)

    def _check_stale(self, rt: _Runtime, now: float, lock_status: str,
                     lock_info: Any) -> None:
        """Watch our own running child for a wedged heartbeat.

        Conservative by construction — recovery requires ALL of:
          * recovery enabled (and never fewer than 2 observations),
          * the worker's heartbeat row is older than the kind's limit,
          * the heartbeat row was written by exactly our child (payload pid),
          * the per-worker lock is STILL held by exactly our child's pid,
          * at least ``stale_min_observations`` distinct stale rounds AND a
            sustained stale wall time >= the limit.
        A fresh beat, a missing row, a read error, a released lock, or a lock
        held by a different pid resets the counters and can never trigger.
        """
        if not self.settings.stale_recovery:
            return
        if self.settings.stale_min_observations < 2:
            return  # defence in depth: never recover on a single observation
        limit = self._stale_limit(rt.spec.name)
        name = f"{rt.spec.name}-{rt.spec.network}"
        states, err = read_worker_states(self.db_path, workers=(name,))
        row = states.get(name)
        age: Optional[float] = None
        beat_pid = None
        if not err and row is not None:
            payload = row["payload"]
            if isinstance(payload, dict):
                beat_pid = payload.get("pid")
            age = now - float(row["updated_at"])
        if err or row is None or age is None or age <= limit:
            rt.reset_stale()
            return
        # Ownership proof — the beat itself must have been written by our
        # child (a beat row from a previous run, or another process, can
        # never be used to kill ours), and the worker lock must still be
        # held by exactly our child's pid.
        if beat_pid != rt.proc.pid \
                or lock_status != "held" or not isinstance(lock_info, dict) \
                or lock_info.get("pid") != rt.proc.pid:
            rt.reset_stale()
            return
        if rt.stale_since is None:
            rt.stale_since = now
        rt.stale_observations += 1
        if rt.stale_observations == 1:
            self._note(f"watchdog: {rt.spec.name} heartbeat is stale "
                       f"({age:.0f}s > {limit:.0f}s limit); watching")
        if rt.stale_observations >= max(2, self.settings.stale_min_observations) \
                and (now - rt.stale_since) >= limit:
            self._start_recovery(rt, now, age)

    def _start_recovery(self, rt: _Runtime, now: float, age: float) -> None:
        rt.recovering = True
        rt.recovery_stage = 1
        rt.recovery_signal_at = now
        rt.wedge_started_at = rt.stale_since
        rt.last_recovery_age = age
        self._note(f"watchdog: {rt.spec.name} appears wedged (heartbeat stale for "
                   f"{rt.stale_observations} observations, age {age:.0f}s); sending SIGINT")
        _signal_group(rt.proc, signal.SIGINT)

    def _escalate_recovery(self, rt: _Runtime, now: float) -> None:
        """Bounded, non-blocking stop ladder for a wedged child."""
        stage = rt.recovery_stage
        elapsed = now - rt.recovery_signal_at
        if stage == 1 and elapsed >= max(0.0, self.settings.child_grace_seconds):
            rt.recovery_stage = 2
            rt.recovery_signal_at = now
            self._note(f"watchdog: {rt.spec.name} still alive after SIGINT; escalating to SIGTERM")
            _signal_group(rt.proc, signal.SIGTERM)
        elif stage == 2 and elapsed >= 2.0:
            rt.recovery_stage = 3
            self._note(f"watchdog: {rt.spec.name} still alive after SIGTERM; escalating to SIGKILL")
            _signal_group(rt.proc, signal.SIGKILL)

    # -- stopping ---------------------------------------------------------
    def _stop_children(self) -> None:
        alive = [rt for rt in self._runtimes if rt.proc is not None]
        for rt in alive:
            # Children that raced ahead and already exited (e.g. an
            # "already running" exit in --once mode) get a short window to
            # finish so their true exit code can be recorded.
            if rt.proc.poll() is None and self.settings.stop_settle_seconds > 0:
                try:
                    rt.proc.wait(timeout=self.settings.stop_settle_seconds)
                except Exception:  # noqa: BLE001 - TimeoutExpired: still running
                    pass
        for rt in alive:
            if rt.proc.poll() is None:
                _signal_group(rt.proc, signal.SIGINT)
        deadline = time.monotonic() + max(0.0, self.settings.child_grace_seconds)
        pending = [rt for rt in alive if rt.proc.poll() is None]
        for rt in pending:
            remaining = deadline - time.monotonic()
            try:
                rt.proc.wait(timeout=max(0.05, remaining))
            except Exception:  # noqa: BLE001 - TimeoutExpired or sim-error: escalate
                if rt.proc.poll() is None:
                    _signal_group(rt.proc, signal.SIGTERM)
                    try:
                        rt.proc.wait(timeout=2.0)
                    except Exception:  # noqa: BLE001
                        if rt.proc.poll() is None:
                            try:
                                rt.proc.kill()
                            except OSError:
                                pass
                            try:
                                rt.proc.wait(timeout=2.0)
                            except Exception:  # noqa: BLE001
                                pass
        for rt in alive:
            rc = rt.proc.poll()
            if rc is not None:
                rt.last_rc = rc
            rt.proc = None
            # During shutdown only the "already running elsewhere" signal must
            # survive — everything else is a supervisor-initiated stop.
            rt.state = "running_elsewhere" if rc == EXIT_BUSY else "stopped"
        self._note("watchdog: requested stop; children signalled")

    # -- watchdog heartbeat row -------------------------------------------
    def _persist_if_due(self) -> None:
        now = self._clock()
        if now - self._last_persist < self.settings.persist_every:
            return
        self._persist_status(self._overall_status())

    def _overall_status(self) -> str:
        for rt in self._runtimes:
            if rt.state == "abandoned":
                return "degraded"
        return "running"

    def _persist_status(self, status: str) -> None:
        self._last_persist = self._clock()
        payload = {
            "status": status,
            "pid": os.getpid(),
            "started_at": self.started_at,
            "children": {rt.spec.name: rt.snapshot() for rt in self._runtimes},
        }
        record_worker_heartbeat(self.db_path, "watchdog", payload, at=self._clock())


def _signal_group(proc: Any, sig: int) -> None:
    try:
        os.killpg(os.getpgid(proc.pid), sig)
        return
    except OSError:
        pass
    try:
        proc.send_signal(sig)
    except OSError:
        pass


def check_command_report(db_path: Path | str, *, network: str = "ethereum",
                         kinds: Sequence[str] = WORKER_KINDS, stale_after: float = 600.0,
                         now: Optional[float] = None) -> Tuple[Dict[str, Any], int]:
    """One-shot ``watchdog check`` payload + exit code."""
    report = evaluate_workers(db_path, network=network, kinds=kinds,
                              stale_after=stale_after, now=now)
    return report, worker_check_exit(report)
