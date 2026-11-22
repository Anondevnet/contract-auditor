"""P1 step 1 — standalone worker watchdog: locks, heartbeats, supervision.

No live chain access and no real monitor/hunt work happens here: worker
processes are stubbed (either in-process fake Popen objects or short-lived
`python -c` sleep/exit children). Every DB and lock lives in a temp directory.

Covered per the phase requirements: duplicate-start protection (same process,
other thread, other process, second watchdog), crash restarts with bounded
exponential backoff and a restart limit, clean/SIGTERM shutdown, stale vs
never-started vs db-unavailable heartbeats, CLI wiring, and the
discovery-service guard against spawning a second copy.
"""

from __future__ import annotations

import io
import fcntl
import itertools
import json
import os
import signal as _signal
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import unittest.mock as mock
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from auditor import cli  # noqa: E402
from auditor import supervisor as sup  # noqa: E402

HELD_CHILD = (
    "import sys, time\n"
    f"sys.path.insert(0, {str(PROJECT_ROOT)!r})\n"
    "from auditor.supervisor import WorkerLock\n"
    "h = WorkerLock(sys.argv[1]).acquire()\n"
    "print('held:', h.pid, flush=True)\n"
    "time.sleep(60)\n"
)


class FakeProc:
    """Minimal Popen stand-in for Supervisor and discovery reader tests."""

    _ids = itertools.count(999000)

    def __init__(self, exit_rc: int | None = None) -> None:
        self.pid = next(FakeProc._ids)
        self.argv: list = []
        self.stdout: Any = io.StringIO("")
        self.signals: list[int] = []
        self.wait_calls: list = []
        self._rc: int | None = exit_rc

    def finish(self, rc: int) -> None:
        self._rc = rc

    def poll(self) -> int | None:
        return self._rc

    def wait(self, timeout=None) -> int:
        self.wait_calls.append(timeout)
        if self._rc is not None:
            return self._rc
        for sig, code in ((_signal.SIGTERM, 143), (_signal.SIGKILL, 137)):
            if sig in self.signals:
                self._rc = code
                return self._rc
        if _signal.SIGINT in self.signals:
            self._rc = 0  # monitor-style: clean exit on a Ctrl-C equivalent
            return self._rc
        raise subprocess.TimeoutExpired(self.argv, timeout)

    def send_signal(self, sig: int) -> None:
        self.signals.append(sig)

    def terminate(self) -> None:
        self.send_signal(_signal.SIGTERM)

    def kill(self) -> None:
        self.send_signal(_signal.SIGKILL)


class _TempDBTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.d = Path(self._tmp.name)
        self.db = self.d / "mon.db"
        self.addCleanup(self._tmp.cleanup)

    def acquire(self, kind: str) -> sup.LockHandle:
        return sup.WorkerLock(sup.worker_lock_path(self.db, kind, "ethereum")).acquire()


class WedgyProc(FakeProc):
    """A wedged worker: poll() reports a rc only once an un-ignored signal
    arrives (SIGKILL first), unless ``ignoring`` is narrowed — mirroring a
    worker whose handlers still respond (SIGINT → clean rc 0)."""

    def __init__(self, exit_rc: int | None = None,
                 ignoring: tuple[int, ...] = (_signal.SIGINT, _signal.SIGTERM)) -> None:
        super().__init__(exit_rc)
        self.ignoring = ignoring

    def poll(self) -> int | None:
        if self._rc is not None:
            return self._rc
        if _signal.SIGKILL in self.signals:
            self._rc = 137
            return self._rc
        for sig, code in ((_signal.SIGINT, 0), (_signal.SIGTERM, 143)):
            if sig in self.signals and sig not in self.ignoring:
                self._rc = code
                return self._rc
        return None


# Fake but consistent child identity for heartbeat-wedge tests: the proc pid,
# the worker-lock holder pid, and the beat payload pid must all match for
# recovery to qualify — and this pid's process group does not exist, so the
# supervisor's killpg() fails into proc.send_signal() (recorded signals) and
# can never signal the test runner itself.
_STALE_TEST_PID = 515015


class _FakeWorkerCase(_TempDBTestCase):
    """Deterministic Supervisor with injected clock/spawn — no real processes."""

    def setUp(self) -> None:
        super().setUp()
        self._held_lock_fds: dict[str, list[int]] = {}
        self.addCleanup(self._close_all_lock_fds)

    def _close_all_lock_fds(self) -> None:
        for fds in self._held_lock_fds.values():
            for fd in fds:
                try:
                    os.close(fd)
                except OSError:
                    pass

    def make(self, names=("monitor",), *, settings_overrides=None, queue=None,
             start_at=0.0, child_pids=None):
        overrides = dict(settings_overrides or {})
        settings = sup.SupervisorSettings(
            restart_backoff_base=2.0, restart_backoff_cap=8.0,
            stable_reset_seconds=100.0, max_restarts=2, child_grace_seconds=0.2,
            poll_interval=0.01, persist_every=1e9)
        for key, value in overrides.items():
            self.assertTrue(hasattr(settings, key), key)
            setattr(settings, key, value)
        spawned: list[FakeProc] = []
        if queue is None:
            queue = [FakeProc() for _ in names]
        clock = {"now": float(start_at)}
        self.now = clock
        child_pids = list(child_pids) if child_pids is not None else None

        def fake_spawn(argv, env, cwd):
            proc = queue.pop(0)
            if child_pids:
                proc.pid = child_pids.pop(0)
            proc.argv = list(argv)
            spawned.append(proc)
            return proc

        s = sup.Supervisor(
            self.db, [sup.WorkerSpec(name=n, network="ethereum", argv=[n]) for n in names],
            settings=settings, clock=lambda: clock["now"],
            sleep=lambda _s: None, emit=lambda _m: None, spawn=fake_spawn)
        return s, spawned, queue

    def stale_make(self, *, seconds=100.0, observations=3, queue=None,
                   child_pids=(_STALE_TEST_PID, _STALE_TEST_PID, _STALE_TEST_PID)):
        """Supervisor tuned for heartbeat-wedge tests: explicit threshold
        seconds (per-kind auto values are live-behaviour, not test values);
        child pids default to _STALE_TEST_PID so the in-test worker lock and
        the written beat payload share one ownership identity."""
        return self.make(names=("monitor",),
                         settings_overrides={"stale_recovery_seconds": seconds,
                                             "stale_min_observations": observations},
                         queue=queue, child_pids=child_pids)

    def hold_lock(self, kind: str = "monitor", pid: int = _STALE_TEST_PID) -> None:
        """Hold the worker's per-worker lock on behalf of ``pid`` — the same
        kernel flock + pid-content lock the real child would own, written by
        hand so the pid can be the fake test identity (WorkerLock.acquire
        hardcodes os.getpid()). Supervisor's killpg() then falls through to
        proc.send_signal() (recorded) and can never signal the test runner."""
        if not hasattr(self, "_held_lock_fds"):
            self._held_lock_fds = {}
        path = sup.worker_lock_path(self.db, kind, "ethereum")
        path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_CLOEXEC, 0o600)
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        content = {"pid": pid, "argv": ["stale-test"], "started_at": 0.0}
        os.lseek(fd, 0, os.SEEK_SET)
        os.ftruncate(fd, 0)
        os.write(fd, (json.dumps(content, sort_keys=True) + "\n").encode("utf-8"))
        self._held_lock_fds.setdefault(kind, []).append(fd)

    def release_lock(self, kind: str = "monitor") -> None:
        """Drop every flock this test currently holds for ``kind`` (the real
        child's lock dies with the process it owned); the fds are closed here
        once and removed so the setUp cleanup never closes them again."""
        for fd in self._held_lock_fds.pop(kind, None) or []:
            os.close(fd)

    def beat(self, at: float, name: str = "monitor-ethereum",
             pid: int = _STALE_TEST_PID, status: str = "running") -> None:
        """Write the worker's heartbeat row (payload carries the holder pid)."""
        sup.record_worker_heartbeat(self.db, name, {"pid": pid, "status": status}, at=at)


class WorkerLockTests(_TempDBTestCase):
    def test_acquire_writes_pid_content_and_release_removes_file(self):
        path = self.d / "lock1"
        handle = sup.WorkerLock(path).acquire()
        self.assertEqual(handle.pid, os.getpid())
        content = sup.WorkerLock(path).read()
        self.assertEqual(content["pid"], os.getpid())
        self.assertIn("started_at", content)
        handle.release()
        self.assertFalse(path.exists())
        # released: acquire works again
        with sup.WorkerLock(path).hold() as h2:
            self.assertEqual(h2.pid, os.getpid())
        self.assertFalse(path.exists())

    def test_nested_same_thread_acquire_is_contention(self):
        lock = sup.WorkerLock(self.d / "nested")
        with lock.hold():
            with self.assertRaises(sup.LockHeld) as ctx:
                sup.WorkerLock(self.d / "nested").acquire()
            self.assertIn("nested acquire", str(ctx.exception))
        # after release the lock is free again
        with lock.hold():
            pass

    def test_reentry_from_other_thread_is_contention(self):
        lock = sup.WorkerLock(self.d / "lt")
        with lock.hold():
            errors: list[Exception] = []

            def other():
                try:
                    sup.WorkerLock(self.d / "lt").acquire()
                except sup.LockHeld as exc:
                    errors.append(exc)

            t = threading.Thread(target=other)
            t.start()
            t.join(5)
            self.assertEqual(len(errors), 1)
            self.assertIn("another thread", str(errors[0]))

    def test_probe_reports_free_when_nothing_holds(self):
        self.assertEqual(sup.WorkerLock(self.d / "absent").probe(), ("free", None))
        self.assertFalse((self.d / "absent").exists())  # probing never creates files

    def test_probe_reports_held_with_info(self):
        with sup.WorkerLock(self.d / "ph").hold():
            status, info = sup.WorkerLock(self.d / "ph").probe()
        self.assertEqual(status, "held")
        self.assertEqual(info["pid"], os.getpid())

    def test_probe_reports_free_despite_leftover_content(self):
        path = self.d / "leftover"
        path.write_text(json.dumps({"pid": 4242, "argv": ["x"]}) + "\n")
        status, info = sup.WorkerLock(path).probe()
        self.assertEqual(status, "free")
        self.assertEqual(info["pid"], 4242)

    def test_cross_process_contention_and_auto_release(self):
        path = self.d / "cp.lock"
        child = subprocess.Popen(
            [sys.executable, "-c", HELD_CHILD, str(path)],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        try:
            self.addCleanup(child.kill)
            line = child.stdout.readline()  # emitted right after acquiring
            self.assertTrue(line.startswith("held:"))
            holder_pid = int(line.split()[1].rstrip(","))
            with self.assertRaises(sup.LockHeld) as ctx:
                sup.WorkerLock(path).acquire()
            self.assertEqual(ctx.exception.pid, holder_pid)
            child.kill()
            child.wait(timeout=10)
            deadline = time.time() + 5
            while time.time() < deadline:
                if sup.WorkerLock(path).probe()[0] == "free":
                    break
                time.sleep(0.05)
            self.assertEqual(sup.WorkerLock(path).probe()[0], "free")
        finally:
            if child.stdout:
                child.stdout.close()

    def test_unusable_location_is_a_distinct_error(self):
        blocker = self.d / "blocked"
        blocker.write_text("regular file in the way")
        with self.assertRaises(sup.LockUnavailable):
            sup.WorkerLock(blocker / "x.lock").acquire()


class HeartbeatTests(_TempDBTestCase):
    def test_record_then_read_roundtrip_and_upsert(self):
        self.assertTrue(sup.record_worker_heartbeat(
            self.db, "monitor-ethereum", {"status": "running"}, at=10.0))
        self.assertTrue(sup.record_worker_heartbeat(
            self.db, "monitor-ethereum", {"status": "stopped", "polls": 3}, at=20.0))
        states, err = sup.read_worker_states(self.db)
        self.assertIsNone(err)
        self.assertEqual(set(states), {"monitor-ethereum"})
        self.assertEqual(states["monitor-ethereum"]["payload"]["status"], "stopped")
        self.assertEqual(states["monitor-ethereum"]["updated_at"], 20.0)

    def test_missing_db_reads_empty_without_creating(self):
        states, err = sup.read_worker_states(self.d / "nope.db")
        self.assertEqual((states, err), ({}, None))
        self.assertFalse((self.d / "nope.db").exists())

    def test_corrupt_db_is_db_unavailable(self):
        self.db.write_bytes(b"this is not a database")
        states, err = sup.read_worker_states(self.db)
        self.assertEqual(states, {})
        self.assertIsNotNone(err)

    def test_missing_table_reads_empty(self):
        conn = sqlite3.connect(self.db)
        conn.execute("CREATE TABLE other(x)")
        conn.close()
        states, err = sup.read_worker_states(self.db)
        self.assertEqual((states, err), ({}, None))


class EvaluateTests(_TempDBTestCase):
    def test_each_state_is_distinguished(self):
        now = 1000.0
        report = sup.evaluate_workers(self.db, stale_after=600.0, now=now)
        self.assertEqual((report["workers"]["monitor"]["state"],
                          report["workers"]["hunt"]["state"]),
                         ("never_started", "never_started"))
        self.assertIsNone(report["db_error"])

        sup.record_worker_heartbeat(self.db, "monitor-ethereum", {"status": "stopped"},
                                    at=now - 30)
        report = sup.evaluate_workers(self.db, stale_after=600.0, now=now)
        self.assertEqual(report["workers"]["monitor"]["state"], "stopped")
        self.assertEqual(report["workers"]["hunt"]["state"], "never_started")

        sup.record_worker_heartbeat(self.db, "hunt-ethereum", {"status": "running"},
                                    at=now - 700)
        report = sup.evaluate_workers(self.db, stale_after=600.0, now=now)
        self.assertEqual(report["workers"]["monitor"]["state"], "stopped")
        self.assertEqual(report["workers"]["hunt"]["state"], "stale")
        self.assertEqual(sup.worker_check_exit(report), 1)

    def test_held_lock_wins_even_over_stale_heartbeat(self):
        now = 1000.0
        sup.record_worker_heartbeat(self.db, "monitor-ethereum", {"status": "running"},
                                    at=now - 5000)
        with self.acquire("monitor"):
            report = sup.evaluate_workers(self.db, stale_after=600.0, now=now)
        self.assertEqual(report["workers"]["monitor"]["state"], "running")
        self.assertEqual(report["workers"]["monitor"]["pid"], os.getpid())
        self.assertEqual(sup.worker_check_exit(report), 0)

    def test_db_unavailable_state_and_exit_code_2(self):
        self.db.write_bytes(b"garbage database")
        report = sup.evaluate_workers(self.db, now=1000.0)
        self.assertTrue(report["db_error"])
        self.assertEqual({w["state"] for w in report["workers"].values()},
                         {"db_unavailable"})
        self.assertEqual(sup.worker_check_exit(report), sup.EXIT_DB_UNAVAILABLE)

    def test_expect_running_option(self):
        now = 1000.0
        report = sup.evaluate_workers(self.db, now=now)
        self.assertEqual(sup.worker_check_exit(report, expect_running=True), 1)
        sup.record_worker_heartbeat(self.db, "monitor-ethereum", {}, at=now - 10)
        report = sup.evaluate_workers(self.db, stale_after=600.0, now=now)
        self.assertEqual(sup.worker_check_exit(report, expect_running=True), 1)
        with self.acquire("monitor"), self.acquire("hunt"):
            report = sup.evaluate_workers(self.db, stale_after=600.0, now=now)
            self.assertEqual(sup.worker_check_exit(report, expect_running=True), 0)


class SupervisorStateTests(_FakeWorkerCase):

    def _rows(self) -> dict:
        conn = sqlite3.connect(self.db)
        rows = dict(conn.execute("SELECT worker,payload_json FROM dashboard_worker_state"))
        conn.close()
        return {k: json.loads(v) for k, v in rows.items()}

    def test_crash_restart_backoff_then_abandonment(self):
        a, b, c = FakeProc(), FakeProc(), FakeProc()
        s, spawned, _queue = self.make(names=("monitor",), queue=[a, b, c])
        s._round(0.0)
        self.assertEqual(len(spawned), 1)
        self.assertEqual(s.summary()["children"]["monitor"]["state"], "running")
        a.finish(1)
        s._round(1.0)  # reap: crash → next start at 1 + base 2
        s._round(2.5)
        self.assertEqual(len(spawned), 1)  # backoff pending
        s._round(3.01)
        self.assertEqual(len(spawned), 2)  # second attempt
        b.finish(1)
        s._round(4.0)  # consecutive=2 → delay 4s
        s._round(7.9)
        self.assertEqual(len(spawned), 2)
        s._round(8.01)
        self.assertEqual(len(spawned), 3)  # third attempt
        c.finish(1)
        s._round(9.0)  # consecutive=3 > max_restarts=2 → abandoned
        snap = s.summary()["children"]["monitor"]
        self.assertEqual(snap["state"], "abandoned")
        self.assertTrue(any("giving up" in e["message"] for e in s.events))
        s._round(900.0)
        self.assertEqual(len(spawned), 3)  # no more spawns after abandonment

    def test_reset_after_stable_run(self):
        a, b = FakeProc(), FakeProc()
        s, spawned, _queue = self.make(names=("monitor",), queue=[a, b])
        s._round(0.0)
        a.finish(1)
        s._round(1.0)   # consecutive=1
        s._round(3.01)  # restart (b)
        b.finish(1)
        s._round(103.1)  # b alive 100.1s ≥ stable_reset → streak resets, then this
        # crash starts a fresh streak: reset 2 → 0, then increment → 1 (not 3)
        self.assertEqual(s.summary()["children"]["monitor"]["consecutive_failures"], 1)

    def test_busy_exit_marks_running_elsewhere_and_recovers(self):
        first, second = FakeProc(), FakeProc()
        s, spawned, _queue = self.make(names=("monitor",), queue=[first, second])
        s._round(0.0)
        first.finish(sup.EXIT_BUSY)
        s._round(1.0)
        self.assertEqual(s.summary()["children"]["monitor"]["state"], "running_elsewhere")
        # another process now holds the worker lock; the watchdog must not spawn
        outer = self.acquire("monitor")
        try:
            s._round(2.0)
            self.assertEqual(len(spawned), 1)
            snap = s.summary()["children"]["monitor"]
            self.assertEqual(snap["state"], "running_elsewhere")
            self.assertEqual(snap["held_info"]["pid"], os.getpid())
        finally:
            outer.release()
        s._round(3.0)  # lock free again → immediate takeover, no extra delay
        self.assertEqual(len(spawned), 2)
        self.assertEqual(s.summary()["children"]["monitor"]["state"], "running")

    def test_held_lock_prevents_first_spawn_and_takes_over(self):
        proc = FakeProc()
        s, spawned, _queue = self.make(names=("monitor",), queue=[proc])
        outer = self.acquire("monitor")
        try:
            s._round(0.0)
            s._round(1.0)
            self.assertEqual(len(spawned), 0)
            self.assertEqual(s.summary()["children"]["monitor"]["state"], "running_elsewhere")
        finally:
            outer.release()
        s._round(2.0)
        self.assertEqual(len(spawned), 1)
        self.assertEqual(s.summary()["children"]["monitor"]["state"], "running")

    def test_rapid_clean_exits_count_toward_restart_limit(self):
        # Regression: a worker that instantly exits 0 over and over must not
        # spin the supervisor forever. Repeat clean exits now follow the same
        # backoff/limit as crashes (P1 review fix #5).
        a, b, c = FakeProc(), FakeProc(), FakeProc()
        s, spawned, _queue = self.make(names=("monitor",), queue=[a, b, c])
        s._round(0.0)
        a.finish(0)
        s._round(1.0)  # first clean exit → streak 1, restart at base delay 2
        snap = s.summary()["children"]["monitor"]
        self.assertEqual(snap["state"], "exited_clean")
        self.assertEqual(snap["consecutive_failures"], 1)
        s._round(2.0)
        self.assertEqual(len(spawned), 1)          # pending: base delay not yet due
        s._round(3.01)
        self.assertEqual(len(spawned), 2)          # restart b at base delay
        b.finish(0)
        s._round(4.0)  # second rapid clean exit → streak 2 → doubled delay
        self.assertEqual(s.summary()["children"]["monitor"]["next_start_at"], 8.0)
        s._round(7.9)
        self.assertEqual(len(spawned), 2)
        s._round(8.01)
        self.assertEqual(len(spawned), 3)          # third attempt (cap 8s)
        c.finish(0)
        s._round(9.0)  # streak 3 > max_restarts 2 → abandoned, no more spins
        self.assertEqual(s.summary()["children"]["monitor"]["state"], "abandoned")
        self.assertTrue(any("exiting cleanly (rc 0)" in e["message"] for e in s.events))
        s._round(900.0)
        self.assertEqual(len(spawned), 3)

    def test_long_clean_exit_keeps_base_restart_delay(self):
        # A long-lived worker (alive >= stable_reset_seconds) that exits 0 has
        # its failure streak reset first: it restarts at the base delay and
        # never accumulates the limit, however often it is stopped cleanly.
        a, b = FakeProc(), FakeProc()
        s, spawned, _queue = self.make(names=("monitor",), queue=[a, b])
        s._round(0.0)
        a.finish(0)
        s._round(150.0)  # alive 150s >= stable_reset 100 → reset → streak 1
        snap = s.summary()["children"]["monitor"]
        self.assertEqual(snap["state"], "exited_clean")
        self.assertEqual(snap["consecutive_failures"], 1)
        s._round(152.01)  # base delay (2s) → restart
        self.assertEqual(len(spawned), 2)
        b.finish(0)
        s._round(300.0)  # b ran ~148s >= 100 → reset again, streak stays 1
        snap = s.summary()["children"]["monitor"]
        self.assertEqual(snap["consecutive_failures"], 1)
        self.assertEqual(snap["next_start_at"], 302.0)  # base delay, not backoff

    def test_stop_children_signal_ladder(self):
        s, spawned, _queue = self.make(names=("monitor", "hunt"))
        s._round(0.0)
        mon_child, hunt_child = spawned
        s.stop_requested = True
        with mock.patch("time.monotonic", lambda: 1.0):
            s._stop_children()
        for child in (mon_child, hunt_child):
            self.assertEqual(child.signals[0], _signal.SIGINT)
        for rt in s._runtimes:
            self.assertEqual(rt.state, "stopped")
        self.assertEqual(s.summary()["children"]["monitor"]["last_rc"], 0)

    def test_stop_children_escalates_for_stubborn_child(self):
        stubborn = FakeProc()

        def only_dies_on_kill(timeout=None):
            stubborn.wait_calls.append(timeout)
            if _signal.SIGKILL in stubborn.signals:
                stubborn._rc = 137
                return 137
            raise subprocess.TimeoutExpired(stubborn.argv, timeout)

        stubborn.wait = only_dies_on_kill
        s, _spawned, _queue = self.make(names=("monitor",), queue=[stubborn],
                                        settings_overrides={"child_grace_seconds": 0.1})
        s._round(0.0)
        s.stop_requested = True
        with mock.patch("time.monotonic", lambda: 1.0):
            s._stop_children()
        self.assertEqual(stubborn.signals, [_signal.SIGINT, _signal.SIGTERM, _signal.SIGKILL])

    def test_once_mode_persists_stopped_and_releases_instance_lock(self):
        s, _spawned, _queue = self.make(names=("monitor",))
        result: dict = {}
        thread = threading.Thread(target=lambda: result.setdefault("rc", s.run(once=True)))
        thread.start()
        thread.join(5)
        self.assertFalse(thread.is_alive())
        self.assertEqual(result.get("rc"), 0)
        rows = self._rows()
        self.assertEqual(rows["watchdog"]["status"], "stopped")
        self.assertEqual(
            sup.WorkerLock(sup.watchdog_lock_path(self.db)).probe()[0], "free")

    def test_run_loop_with_stop_event(self):
        s, spawned, _queue = self.make(names=("monitor",))
        stop = threading.Event()
        result: dict = {}

        def drive():
            result["rc"] = s.run(stop_event=stop)

        t = threading.Thread(target=drive)
        t.start()
        deadline = time.time() + 5
        while len(spawned) < 1 and time.time() < deadline:
            time.sleep(0.02)
        self.assertTrue(spawned, "supervisor should spawn the worker")
        stop.set()
        t.join(5)
        self.assertFalse(t.is_alive())
        self.assertEqual(result.get("rc"), 0)
        rows = self._rows()
        self.assertEqual(rows["watchdog"]["status"], "stopped")

    def test_duplicate_watchdog_refused_by_instance_lock(self):
        s, spawned, _queue = self.make(names=("monitor",), queue=[FakeProc()])
        result: dict = {}
        with sup.WorkerLock(sup.watchdog_lock_path(self.db)).hold():
            thread = threading.Thread(
                target=lambda: result.setdefault("rc", s.run(once=True)))
            thread.start()
            thread.join(5)
            self.assertEqual(result.get("rc"), sup.EXIT_BUSY)
            self.assertFalse(thread.is_alive())
        self.assertEqual(len(spawned), 0)

    def test_empty_command_abandons_without_spawning(self):
        s = sup.Supervisor(
            self.db, [sup.WorkerSpec(name="monitor", network="ethereum", argv=[])],
            settings=sup.SupervisorSettings(), clock=lambda: 0.0,
            sleep=lambda _s: None, emit=lambda _m: None, spawn=self.fail)
        s._round(0.0)
        self.assertEqual(s.summary()["children"]["monitor"]["state"], "abandoned")


class StaleRecoveryTests(_FakeWorkerCase):
    """Heartbeat-wedge recovery determinism (P1 step 2).

    No test relies on the auto thresholds (900 s / 1800 s are live-behaviour
    decisions, not test fixtures): every test pins ``stale_recovery_seconds``.
    The default child pid is this test process so the worker lock (held by
    this process) and the written beat payload share one ownership identity.
    """

    # -- trigger gates -----------------------------------------------------

    def test_unsustained_stale_window_never_recovers(self):
        s, spawned, _ = self.stale_make(seconds=100.0, observations=3)
        self.beat(-150.0)
        s._round(0.0)                     # spawn (lock still free)
        self.hold_lock("monitor")         # now held by our simulated child
        for t in (0.01, 0.02, 0.03, 1.0, 50.0, 99.5):
            s._round(t)
        rt = s._runtimes[0]
        # Six distinct stale rounds were counted, but the sustained window
        # (99.49 s) never reached the 100 s limit — no recovery, ever.
        self.assertEqual(spawned[0].signals, [])
        self.assertEqual(rt.recovery_stage, 0)
        self.assertFalse(rt.recovering)
        self.assertEqual(rt.stale_observations, 6)
        # A fresh beat then clears the counters:
        self.beat(99.6)
        s._round(99.7)
        self.assertEqual(rt.stale_observations, 0)
        self.assertIsNone(rt.stale_since)
        self.assertEqual(spawned[0].signals, [])

    def test_recovery_requires_repeated_stale_observations(self):
        # tiny seconds so the sustained gate cannot mask the observation gate
        s, spawned, _ = self.stale_make(seconds=0.02, observations=4)
        self.beat(-150.0)
        s._round(0.0)
        self.hold_lock("monitor")
        s._round(0.01)                    # obs 1
        s._round(0.02)                    # obs 2 (sustained 0.01)
        s._round(0.03)                    # obs 3 — sustained ok but < 4 obs
        self.assertEqual(spawned[0].signals, [])
        s._round(0.04)                    # obs 4 — both gates pass: SIGINT
        self.assertEqual(spawned[0].signals, [_signal.SIGINT])
        self.assertTrue(s._runtimes[0].recovering)
        self.assertEqual(s._runtimes[0].recovery_stage, 1)
        self.assertEqual(s._runtimes[0].last_recovery_age, 150.04)

    def test_fresh_beat_resets_stale_watch(self):
        s, spawned, _ = self.stale_make(seconds=100.0, observations=2)
        self.beat(-150.0)
        s._round(0.0)
        self.hold_lock("monitor")
        s._round(0.01)
        self.assertEqual(s._runtimes[0].stale_observations, 1)
        self.beat(0.02)                   # the "late" worker caught up
        s._round(0.03)
        self.assertEqual(s._runtimes[0].stale_observations, 0)
        self.assertIsNone(s._runtimes[0].stale_since)
        self.beat(0.06)
        s._round(2.0)
        self.assertEqual(spawned[0].signals, [])

    # -- ownership gates ---------------------------------------------------

    def test_beat_payload_pid_mismatch_never_recovers(self):
        # A heartbeat row from a previous run / another process can never
        # be used to kill our child.
        s, spawned, _ = self.stale_make(seconds=100.0, observations=2)
        self.beat(-150.0, pid=999999)     # written by someone else
        s._round(0.0)
        self.hold_lock("monitor")
        for t in (0.01, 0.03, 150.0):
            s._round(t)
        self.assertEqual(s._runtimes[0].stale_observations, 0)
        self.assertEqual(spawned[0].signals, [])

    def test_foreign_lock_holder_never_recovers(self):
        s, spawned, _ = self.make(
            settings_overrides={"stale_recovery_seconds": 100.0,
                                "stale_min_observations": 2},
            child_pids=(424242,))
        self.beat(-150.0, pid=424242)     # beat genuinely owned by the "child"
        s._round(0.0)                     # spawn while the lock is free
        self.hold_lock("monitor", pid=os.getpid())   # ...then a foreign process
        for t in (0.02, 0.05, 300.0):
            s._round(t)
        self.assertEqual(s._runtimes[0].stale_observations, 0)
        self.assertEqual(spawned[0].signals, [])
        self.assertEqual(s.summary()["children"]["monitor"]["state"], "running")

    def test_running_elsewhere_worker_is_never_recovered(self):
        s, spawned, _ = self.stale_make(seconds=100.0, observations=2)
        self.beat(-150.0)
        self.hold_lock("monitor")         # foreign holder from the very start
        for t in (0.0, 0.02, 500.0):
            s._round(t)
        self.assertEqual(spawned, [])
        self.assertEqual(s.summary()["children"]["monitor"]["state"],
                         "running_elsewhere")

    # -- fail-safes --------------------------------------------------------

    def test_disabled_recovery_never_signals(self):
        s, spawned, _ = self.make(
            settings_overrides={"stale_recovery": False,
                                "stale_recovery_seconds": 100.0,
                                "stale_min_observations": 2},
            child_pids=(_STALE_TEST_PID,))
        self.beat(-100000.0)
        s._round(0.0)
        self.hold_lock("monitor")
        for t in (0.01, 150.0, 400.0):
            s._round(t)
        self.assertEqual(spawned[0].signals, [])
        notes = " | ".join(str(ev.get("message", "")) for ev in s.summary()["events"])
        self.assertNotIn("heartbeat is stale", notes)
        self.assertNotIn("appears wedged", notes)

    def test_corrupt_db_read_fails_safe(self):
        s, spawned, _ = self.stale_make(seconds=100.0, observations=2)
        s._round(0.0)                     # spawn + watchdog persist on healthy db
        self.db.write_bytes(b"garbage database")     # beat reads now fail
        self.hold_lock("monitor")
        for t in (0.01, 0.03, 200.0):
            s._round(t)
        self.assertEqual(s._runtimes[0].stale_observations, 0)
        self.assertEqual(spawned[0].signals, [])
        notes = " | ".join(str(ev.get("message", "")) for ev in s.summary()["events"])
        self.assertNotIn("appears wedged", notes)

    # -- ladder + classification ------------------------------------------

    def test_wedged_child_ladder_and_recovered_restart(self):
        s, spawned, _ = self.stale_make(
            seconds=100.0, observations=3,
            queue=[WedgyProc(), WedgyProc()],
            child_pids=(_STALE_TEST_PID, _STALE_TEST_PID))
        self.beat(-150.0)
        s._round(0.0)                     # spawn #1
        self.hold_lock("monitor")
        s._round(0.01)
        s._round(0.02)
        s._round(0.03)                    # obs 1-3, sustained 0.02 s
        self.assertEqual(spawned[0].signals, [])
        s._round(100.05)                  # obs 4, sustained 100.04 → SIGINT
        self.assertEqual(spawned[0].signals, [_signal.SIGINT])
        s._round(100.15)                  # inside the SIGINT grace window
        self.assertEqual(spawned[0].signals, [_signal.SIGINT])
        s._round(100.31)                  # grace (0.2 s) elapsed → SIGTERM
        self.assertEqual(spawned[0].signals,
                         [_signal.SIGINT, _signal.SIGTERM])
        s._round(102.5)                   # +2 s → SIGKILL; poll reports 137 → reap
        self.assertEqual(spawned[0].signals,
                         [_signal.SIGINT, _signal.SIGTERM, _signal.SIGKILL])
        snap = s.summary()["children"]["monitor"]
        self.assertEqual(snap["state"], "recovered")     # NOT "crashed"
        self.assertEqual(snap["consecutive_failures"], 1)
        self.assertEqual(snap["next_start_at"], 104.5)   # base backoff 2 s
        notes = " | ".join(str(ev.get("message", "")) for ev in s.summary()["events"])
        self.assertIn("appears wedged", notes)
        self.assertIn("heartbeat-wedge recovery finished", notes)
        self.assertIn("previous heartbeat 250s old", notes)   # age frozen at trigger
        self.release_lock("monitor")      # the reaped child's lock died with it
        s._round(104.51)                  # overdue → spawn #2 (lock free)
        self.hold_lock("monitor")         # the new child acquires its lock
        self.assertEqual(len(spawned), 2)
        self.assertEqual(s.summary()["children"]["monitor"]["state"], "running")
        self.assertEqual(spawned[1].signals, [])
        rt = s._runtimes[0]
        self.assertEqual(rt.stale_observations, 0)
        self.assertIsNone(rt.stale_since)
        self.assertFalse(rt.recovering)

    def test_graceful_child_recovers_on_single_signal(self):
        s, spawned, _ = self.stale_make(
            seconds=100.0, observations=2,
            queue=[WedgyProc(ignoring=()), WedgyProc()],
            child_pids=(_STALE_TEST_PID, _STALE_TEST_PID))
        self.beat(-150.0)
        s._round(0.0)
        self.hold_lock("monitor")
        s._round(0.01)
        s._round(0.02)                    # obs 2, sustained 0.01 s < limit
        s._round(100.03)                  # sustained ≥ limit → SIGINT → rc 0
        self.assertEqual(spawned[0].signals, [_signal.SIGINT])  # ladder stopped
        s._round(100.06)                  # poll reports rc 0 → reap this round
        snap = s.summary()["children"]["monitor"]
        self.assertEqual(snap["state"], "recovered")
        self.assertEqual(snap["next_start_at"], 102.06)   # 100.06 + base backoff
        self.assertEqual(snap["last_rc"], 0)

    def test_repeated_recoveries_abandon_and_mark_degraded(self):
        s, spawned, _ = self.stale_make(
            seconds=100.0, observations=2,
            queue=[WedgyProc(), WedgyProc(), WedgyProc()],
            child_pids=(_STALE_TEST_PID, _STALE_TEST_PID, _STALE_TEST_PID))
        self.beat(-150.0)
        s._round(0.0)                     # spawn #1 (lock still free)
        self.hold_lock("monitor")         # ...and child #1 acquires its lock
        t = 0.0
        state = ""
        while t < 600.0:
            was_alive = s._runtimes[0].proc is not None
            before = len(spawned)
            s._round(t)
            now_alive = s._runtimes[0].proc is not None
            if was_alive and not now_alive and len(spawned) == before:
                self.release_lock("monitor")          # reaped: its lock is gone
            if now_alive and len(spawned) > before:
                self.hold_lock("monitor")             # new child acquires its lock
            state = s.summary()["children"]["monitor"]["state"]
            if state == "abandoned":
                break
            t += 0.25
        self.assertEqual(state, "abandoned")
        self.assertEqual(len(spawned), 3)          # no 4th spawn after giving up
        for proc in spawned:
            self.assertNotEqual(proc.signals, [])
            self.assertEqual(proc.signals[-1], _signal.SIGKILL)
        self.assertEqual(s.summary()["children"]["monitor"]["consecutive_failures"], 3)
        workers, _err = sup.read_worker_states(self.db)
        self.assertEqual(workers["watchdog"]["payload"]["status"], "degraded")

    def test_user_stop_during_recovery_is_stopped_not_recovered(self):
        s, spawned, _ = self.stale_make(
            seconds=100.0, observations=2,
            queue=[WedgyProc(), WedgyProc()],
            child_pids=(_STALE_TEST_PID, _STALE_TEST_PID))
        self.beat(-150.0)
        s._round(0.0)
        self.hold_lock("monitor")
        s._round(0.01)
        s._round(0.02)
        s._round(100.03)                  # recovery begins: SIGINT, stage 1
        self.assertTrue(s._runtimes[0].recovering)
        s.stop_requested = True
        s._stop_children()
        snap = s.summary()["children"]["monitor"]
        self.assertEqual(snap["state"], "stopped")   # not "recovered"/"crashed"
        self.assertEqual(snap["last_rc"], 0)         # graceful stop rc (fake)
        self.assertEqual(spawned[0].signals, [_signal.SIGINT])
        self.assertEqual(s._runtimes[0].consecutive, 0)   # never counted

    # -- settings + cli ----------------------------------------------------

    def test_stale_limit_auto_per_kind_and_override(self):
        s, _, _ = self.make(settings_overrides={"stale_recovery": False,
                                                "stale_recovery_seconds": 0.0})
        self.assertEqual(s._stale_limit("monitor"), 900.0)
        self.assertEqual(s._stale_limit("hunt"), 1800.0)
        self.assertEqual(s._stale_limit("other"), 1800.0)   # fallback
        s2, _, _ = self.make(settings_overrides={"stale_recovery_seconds": 55.0})
        self.assertEqual(s2._stale_limit("monitor"), 55.0)
        self.assertEqual(s2._stale_limit("hunt"), 55.0)

    def test_cli_stale_flags_defaults_and_validation(self):
        parser = cli.build_parser()
        ns = parser.parse_args(["watchdog", "run", "--no-hunt"])
        self.assertEqual(ns.stale_recovery, "on")
        self.assertEqual(ns.stale_recovery_seconds, 0.0)
        self.assertEqual(ns.stale_observations, 3)
        ns2 = parser.parse_args(["watchdog", "run", "--no-hunt",
                                 "--stale-recovery-seconds", "450"])
        self.assertEqual(ns2.stale_recovery_seconds, 450.0)
        ns3 = parser.parse_args(["watchdog", "run", "--no-hunt",
                                 "--stale-recovery", "off"])
        self.assertEqual(ns3.stale_recovery, "off")
        ns4 = parser.parse_args(["watchdog", "run", "--no-hunt",
                                 "--stale-observations", "1"])
        self.assertEqual(cli._cmd_watchdog(ns4, None), cli.EXIT_ERROR)


class MonitorLockIntegrationTests(_TempDBTestCase):
    """The monitor itself takes the lock and writes its own heartbeat row."""

    def setUp(self) -> None:
        super().setUp()
        from auditor import monitor as mod

        self.mod = mod

    def _monitor(self, emit):
        cfg = self.mod.MonitorConfig(
            db_path=self.db, alerts_path=self.d / "a.jsonl",
            cache_dir=self.d / "cache", interval=0.05)
        client = type("ClientStub", (), {"ws_url": None})()
        mon = self.mod.Monitor(cfg, client, emit=emit, clock=lambda: 5.0)

        def poll():
            mon.request_stop()
            return {"discovery": {"from": 1, "to": 2, "head": 3, "enqueued": 0},
                    "results": [], "alerts": 0}

        mon.poll = poll
        return mon

    def test_busy_lock_stops_second_copy_before_any_poll(self):
        with self.acquire("monitor"):
            mon = self._monitor(emit=lambda _s: None)
            mon.poll = self.fail  # a second copy must never reach any poll
            with self.assertRaises(sup.LockHeld):
                mon.run(once=True)

    def test_lock_released_between_runs_and_heartbeat_rows_written(self):
        mon = self._monitor(emit=lambda _s: None)
        mon.run(once=True)
        mon2 = self._monitor(emit=lambda _s: None)
        mon2.run(once=True)  # sequential runs both succeed: lock was released
        states, err = sup.read_worker_states(self.db)
        self.assertIsNone(err)
        row = states["monitor-ethereum"]
        self.assertEqual(row["payload"]["status"], "stopped")
        self.assertEqual(row["payload"]["pid"], os.getpid())
        self.assertEqual(row["payload"]["polls"], 1)
        self.assertFalse(sup.worker_lock_path(self.db, "monitor", "ethereum").exists())


class HuntLockIntegrationTests(_TempDBTestCase):
    def setUp(self) -> None:
        super().setUp()
        from auditor import hunt as hmod

        self.hmod = hmod

    def _hunter(self, emit):
        cfg = self.hmod.HuntConfig(db_path=self.db, interval=0.05,
                                   cache_dir=self.d / "hunt_cache")
        hunter = self.hmod.Hunter(cfg, client=None, emit=emit, clock=lambda: 5.0)

        def cycle(*_args, **_kwargs):
            hunter.request_stop()
            return {"refresh": {"discovered": 0}, "measured": [], "scanned": []}

        hunter.cycle = cycle
        return hunter

    def test_persistent_run_takes_and_releases_lock(self):
        hunter = self._hunter(emit=lambda _s: None)
        runs = hunter.run(once=True)
        self.assertEqual(len(runs), 1)
        states, err = sup.read_worker_states(self.db)
        self.assertIsNone(err)
        self.assertEqual(states["hunt-ethereum"]["payload"]["status"], "stopped")
        self.assertFalse(sup.worker_lock_path(self.db, "hunt", "ethereum").exists())

    def test_busy_lock_blocks_second_copy(self):
        with self.acquire("hunt"):
            hunter = self._hunter(emit=lambda _s: None)
            with self.assertRaises(sup.LockHeld):
                hunter.run(once=True)


class DiscoveryGuardTests(_TempDBTestCase):
    def setUp(self) -> None:
        super().setUp()
        from auditor import discovery_service as ds

        self.ds = ds
        self._original_state = ds._state
        ds._state = {"status": "idle", "stage": "idle", "message": "", "children": {"monitor": {}, "hunt": {}}, "events": []}
        env = dict(os.environ)
        env["AUDITOR_MONITOR_DB"] = str(self.db)
        patcher = mock.patch.dict(os.environ, env)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.addCleanup(setattr, self.ds, "_state", self._original_state)

    def test_probe_helper_sees_in_process_holder(self):
        self.assertIsNone(self.ds._worker_lock_held("monitor"))
        with self.acquire("monitor"):
            info = self.ds._worker_lock_held("monitor")
            self.assertEqual(info["pid"], os.getpid())
        self.assertIsNone(self.ds._worker_lock_held("monitor"))

    def test_reader_marks_busy_exit_as_running_elsewhere(self):
        self.ds._reader("monitor", FakeProc(exit_rc=sup.EXIT_BUSY))
        child = self.ds.status(include_metrics=False)["children"]["monitor"]
        self.assertEqual(child["status"], "running_elsewhere")
        self.assertIn("worker lock held", child["error"])

    def test_reader_still_marks_clean_and_failed(self):
        self.ds._reader("monitor", FakeProc(exit_rc=0))
        self.assertEqual(self.ds.status(include_metrics=False)["children"]["monitor"]["status"],
                         "completed")
        self.ds._reader("hunt", FakeProc(exit_rc=1))
        self.assertEqual(self.ds.status(include_metrics=False)["children"]["hunt"]["status"],
                         "failed")


class CLIWiringTests(unittest.TestCase):
    def setUp(self) -> None:
        self.parser = cli.build_parser()

    def test_run_flags_have_expected_defaults(self):
        ns = self.parser.parse_args(["watchdog", "run", "--no-hunt"])
        self.assertEqual(ns.watchdog_cmd, "run")
        self.assertFalse(ns.once)
        self.assertEqual(ns.network, "ethereum")
        self.assertEqual(ns.restart_backoff_base, 5.0)
        self.assertEqual(ns.restart_backoff_cap, 300.0)
        self.assertEqual(ns.max_restarts, 20)
        self.assertEqual(ns.stable_reset_seconds, 600.0)
        self.assertEqual(ns.child_grace, 10.0)
        self.assertTrue(ns.no_hunt)
        ns2 = self.parser.parse_args(["watchdog", "run"])
        self.assertFalse(ns2.no_hunt)
        self.assertEqual(ns2.monitor_cmd, "scripts/run_monitor.sh")
        self.assertEqual(ns2.hunt_cmd, "scripts/run_hunt.sh")

    def test_check_flags(self):
        ns = self.parser.parse_args(["watchdog", "check", "--expect-running"])
        self.assertTrue(ns.expect_running)
        self.assertEqual(ns.stale_threshold, 600.0)

    def test_exit_busy_is_the_shared_supervisor_constant(self):
        # Regression: EXIT_BUSY must stay defined exactly once (supervisor.py);
        # cli may not grow its own copy that can drift from the workers'.
        self.assertIs(cli.EXIT_BUSY, sup.EXIT_BUSY)

    def test_status_report_renderer(self):
        report = {"network": "ethereum", "stale_after": 600.0, "db_error": None,
                  "workers": {"monitor": {"state": "running", "heartbeat_age_s": 3.0,
                                          "pid": 4242, "pid_alive": True,
                                          "heartbeat": {"status": "running"}},
                              "hunt": {"state": "stale", "heartbeat_age_s": 900.0}},
                  "watchdog": {"heartbeat_age_s": 2.0, "heartbeat": {"status": "running"}},
                  "watchdog_lock": {"status": "held", "info": {"pid": 1}}}
        buf = io.StringIO()
        with mock.patch("sys.stdout", buf):
            cli._print_watchdog_report(report)
        text = buf.getvalue()
        self.assertIn("monitor: running (heartbeat 3s ago), pid 4242 (alive), last status running",
                      text)
        self.assertIn("hunt: stale (heartbeat 900s ago)", text)
        self.assertIn("watchdog instance lock: held", text)

    def test_worker_argv_resolves_relative_script(self):
        argv = cli._worker_argv("scripts/run_monitor.sh --interval 60", PROJECT_ROOT)
        self.assertEqual(argv[0], str(PROJECT_ROOT / "scripts" / "run_monitor.sh"))
        self.assertEqual(argv[-1], "60")


class RunEndToEndTests(_TempDBTestCase):
    """Real `audit.py watchdog` subprocesses with stub workers. Bounded."""

    def _env(self):
        env = dict(os.environ)
        env["AUDITOR_MONITOR_DB"] = str(self.db)
        env.setdefault("ETHERSCAN_API_KEY", "test-not-real")
        return env

    def _run_cli(self, argv, timeout, background=False):
        proc = subprocess.Popen(
            [sys.executable, str(PROJECT_ROOT / "audit.py")] + argv,
            cwd=str(PROJECT_ROOT), env=self._env(), stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True)
        if background:
            return proc
        out, err = proc.communicate(timeout=timeout)
        return proc.returncode, out, err

    def test_status_and_check_json_on_missing_db(self):
        code, out, err = self._run_cli(["watchdog", "status", "--json"], 60)
        self.assertEqual(code, 0, err)
        payload = json.loads(out)
        self.assertEqual(payload["workers"]["monitor"]["state"], "never_started")
        self.assertEqual(payload["db_error"], None)
        code, out, err = self._run_cli(["watchdog", "check", "--json"], 60)
        self.assertEqual(code, 0, err)
        code, out, err = self._run_cli(
            ["watchdog", "check", "--json", "--expect-running"], 60)
        self.assertEqual(code, 1)

    def test_stale_check_exit_code(self):
        sup.record_worker_heartbeat(self.db, "monitor-ethereum", {"status": "running"},
                                    at=time.time() - 5000)
        code, out, err = self._run_cli(["watchdog", "check", "--json"], 60)
        self.assertEqual(code, 1, err)
        payload = json.loads(out)
        self.assertEqual(payload["workers"]["monitor"]["state"], "stale")

    def test_once_runs_then_stops_children(self):
        stub = f'{sys.executable} -c "import sys; sys.exit(0)"'
        code, out, err = self._run_cli(
            ["watchdog", "run", "--once", "--no-hunt",
             "--monitor-cmd", stub,
             "--poll-interval", "0.05", "--child-grace", "2",
             "--restart-backoff-base", "0.01", "--stable-reset-seconds", "0"], 60)
        self.assertEqual(code, 0, err)
        self.assertIn("monitor: state=", out)

    def test_busy_exit_creates_running_elsewhere_state(self):
        stub_busy = f'{sys.executable} -c "import sys; sys.exit({sup.EXIT_BUSY})"'
        stub = f'{sys.executable} -c "import sys; sys.exit(0)"'
        code, out, err = self._run_cli(
            ["watchdog", "run", "--once", "--json",
             "--monitor-cmd", stub_busy, "--hunt-cmd", stub,
             "--poll-interval", "0.05", "--child-grace", "2",
             "--restart-backoff-base", "0.01", "--stable-reset-seconds", "0"], 60)
        self.assertEqual(code, 0, err)
        payload = json.loads(out)
        self.assertEqual(payload["summary"]["children"]["monitor"]["state"],
                         "running_elsewhere")
        self.assertEqual(payload["summary"]["children"]["hunt"]["state"], "stopped")

    def _wait_until(self, predicate, deadline=12.0, step=0.1):
        end = time.time() + deadline
        while time.time() < end:
            value = predicate()
            if value:
                return value
            time.sleep(step)
        raise AssertionError("condition not met in time")

    def test_second_watchdog_refused_and_first_shuts_down_cleanly(self):
        stub = f'{sys.executable} -c "import time; time.sleep(60)"'
        first = self._run_cli(
            ["watchdog", "run", "--no-hunt", "--json",
             "--monitor-cmd", stub,
             "--poll-interval", "0.2", "--child-grace", "3",
             "--restart-backoff-base", "0.05", "--stable-reset-seconds", "0",
             "--restart-backoff-cap", "0.1"], 30, background=True)
        try:
            def watchdog_row_with_child():
                states, err = sup.read_worker_states(self.db)
                row = states.get("watchdog")
                if row and (row["payload"].get("children") or {}).get("monitor", {}).get("pid"):
                    return row["payload"]
                return None

            payload = self._wait_until(watchdog_row_with_child)
            child_pid = payload["children"]["monitor"]["pid"]
            os.kill(child_pid, 0)  # worker child is alive before the stop

            code2, out2, err2 = self._run_cli(
                ["watchdog", "run", "--once", "--json",
                 "--monitor-cmd", stub,
                 "--poll-interval", "0.05", "--child-grace", "1",
                 "--restart-backoff-base", "0.01"], 60)
            self.assertEqual(code2, sup.EXIT_BUSY, err2)
            self.assertIn("pid", out2 + err2)

            first.terminate()
            out1, err1 = first.communicate(timeout=30)
            self.assertEqual(first.returncode, 0, err1)
            summary = json.loads(out1)["summary"]
            self.assertEqual(summary["children"]["monitor"]["state"], "stopped")
            self._wait_until(lambda: not _pid_alive(child_pid))
        finally:
            if first.poll() is None:
                first.kill()
                first.wait(timeout=10)


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except OSError:
        return True
    return True


if __name__ == "__main__":
    unittest.main()
