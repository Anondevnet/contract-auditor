"""Phase 42 — hunt restart-loop regressions (2026-10-24 diagnosis).

Root cause, as evidenced in `reports/watchdog.run.log`:

1. ``monitor_state.db`` runs in ``journal_mode=delete`` with several writers
   (monitor cycle, hunt cycle, watchdog heartbeats, dashboard pollers).
2. ``GET /api/simulate/live`` was a *masked writer*: a read-write connection
   plus an unconditional ``ensure_schema_v7`` DDL batch on every browser
   poll (190 requests in one dashboard log sweep) collided with the
   monitor's own write bursts, failing ``record_poll``/``record_block``
   repeatedly ``5s`` busy-timeouts apart.
3. ``Hunter.cycle()`` caught those mid-cycle lock failures and then —
   OUTSIDE its except clause — issued the ``hunt_runs`` outcome INSERT on
   the still-locked store. The uncaught ``OperationalError`` reached
   ``auditor/cli.py:main`` (``error: OperationalError: database is locked``
   → exit 1), killing the worker. The watchdog respawned it; each respawn
   collided the same way until one attempt landed in a quiet window.

Pinned fixes here: the route must be genuinely read-only (never DDL), the
outcome row must be best-effort, and ``Hunter.run()`` must survive an
unhandled cycle error like ``Monitor.run()`` already does (Phase 18.1).
"""
from __future__ import annotations

import sqlite3
import unittest.mock as mock

import pytest
from fastapi.testclient import TestClient

from auditor import hunt
from auditor.monitor import MonitorStore


# ---------------------------------------------------------------------------
# /api/simulate/live must NEVER write (regression: masked-writer DDL per poll)
# ---------------------------------------------------------------------------

def _bare_monitor_db(path):
    path.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(str(path))
    con.close()  # exists, but has zero tables (simulate ones NOT created)
    return path


@pytest.fixture()
def live_client(tmp_path, monkeypatch):
    """Dashboard app pointed at an ISOLATED monitor DB via AUDITOR_MONITOR_DB."""
    from auditor.dashboard.app import create_app

    monkeypatch.setenv("AUDITOR_MONITOR_DB", str(tmp_path / "monitor.db"))
    return TestClient(create_app())


def test_simulate_live_on_empty_store_is_honest_empty_and_writes_nothing(live_client, tmp_path):
    path = _bare_monitor_db(tmp_path / "monitor.db")
    r = live_client.get("/api/simulate/live")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["db"] == "present"
    assert body["runs"] == []
    # THE regression: the documented-read-only route must have written nothing.
    con = sqlite3.connect(str(path))
    tables = {row[0] for row in con.execute(
        "SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
    con.close()
    assert "simulate_runs" not in tables, (
        "the simulate/live endpoint executed DDL on a read path (old masked-writer bug)")


def test_simulate_live_returns_persisted_runs_from_readonly_store(live_client, tmp_path):
    from auditor.simulate import ensure_schema_v7

    path = tmp_path / "monitor.db"
    store = MonitorStore(path)  # full monitor schema first (ensure_v7 prerequisite)
    store.conn.execute("INSERT INTO simulate_runs(network,address,protocol,started_at,"
                       "finished_at,duration_s,status,fork_block) VALUES"
                       "('ethereum','0x" + "9" * 40 + "', 'Proto', 1.0, 2.0, 1.0, 'pass', 123)")
    store.conn.commit()
    store.conn.close()
    path.touch()  # ensure exists for the route probe
    _bare_monitor_db(path)  # no-op open/close under the same path
    from auditor.simulate import ensure_schema_v7 as _ensure  # noqa: F401 (kept for clarity)
    r = live_client.get("/api/simulate/live")
    assert r.status_code == 200, r.text
    body = r.json()
    assert len(body["runs"]) == 1 and body["runs"][0]["address"] == "0x" + "9" * 40


def test_simulation_overview_ensure_flag_is_respected(tmp_path):
    """Unit-level pin: ensure_schema=False genuinely skips the DDL batch."""
    from auditor.simulate import simulation_overview

    path = _bare_monitor_db(tmp_path / "unit.db")
    con = sqlite3.connect(str(path))
    with pytest.raises(sqlite3.OperationalError, match="no such table"):
        simulation_overview(con, network="ethereum", ensure_schema=False)
    con.close()
    # and the default (ensure_schema=True) still creates the schema for writers.
    # ensure_schema_v7 assumes the full monitor schema (it ALTERs hunt_candidates),
    # so create it via the normal writer path first.
    store = MonitorStore(path)
    store.conn.close()
    con = sqlite3.connect(str(path))
    overview = simulation_overview(con, network="ethereum")
    assert overview["runs"] == []
    tables = {row[0] for row in con.execute(
        "SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
    con.close()
    assert "simulate_runs" in tables


def test_hunt_live_reads_from_readonly_store(live_client, tmp_path):
    path = tmp_path / "monitor.db"
    store = MonitorStore(path)
    try:
        store.conn.close()
    except Exception:  # noqa: BLE001 - close is best-effort in the fixture
        pass
    r = live_client.get("/api/hunt/live")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["candidates"] == []


# ---------------------------------------------------------------------------
# hunt must SURVIVE store contention (regression: exit-1 cascade)
# ---------------------------------------------------------------------------

def _make_hunter(tmp_path):
    cfg = hunt.HuntConfig(db_path=tmp_path / "hunt.db", cache_dir=tmp_path / "cache")
    emits: list[str] = []
    hunter = hunt.Hunter(cfg, client=None, emit=lambda s: emits.append(s), clock=lambda: 10_000.0)
    return hunter, emits


def test_cycle_outcome_row_is_best_effort_on_locked_store(tmp_path, caplog, monkeypatch):
    """The post-cycle ``hunt_runs`` INSERT lock failure must not kill the
    process (it used to unwind out of cycle() and exit code 1).

    The lock is REAL here: a second connection holds an uncommitted
    ``BEGIN IMMEDIATE`` (RESERVED in delete journal mode) on the hunter's
    store, so hunt's own final write must wait out its busy timeout and
    fail — exactly like the production contention window."""
    import logging

    cfg = hunt.HuntConfig(db_path=tmp_path / "hunt.db", cache_dir=tmp_path / "cache",
                          measure_per_cycle=0, scan_per_cycle=0, simulate_per_cycle=0)
    emits: list[str] = []

    class _NoFetch:
        def get(self, key, url, ttl, as_json=True, force=False):
            if "protocols" in key:
                return []
            if "pools" in key:
                return {"data": []}
            raise hunt.TransientError("not in fixture")

    hunter = hunt.Hunter(cfg, client=None, cache=_NoFetch(),
                         emit=lambda s: emits.append(s), clock=lambda: 10_000.0)
    # keep the test fast: heartbeats are irrelevant here
    monkeypatch.setattr(hunt, "record_worker_heartbeat",
                        lambda *a, **k: None, raising=False)

    holder = sqlite3.connect(str(cfg.db_path), timeout=0.2)
    holder.execute("PRAGMA busy_timeout=200")
    holder.execute("BEGIN IMMEDIATE")  # hold RESERVED for the whole cycle body
    try:
        with caplog.at_level(logging.WARNING, logger="contract_auditor.hunt"):
            stats = hunter.cycle(refresh=True)
    finally:
        holder.rollback()
        holder.close()
    assert stats is not None  # cycle() returned — the worker is alive
    # the failure is honestly logged, never silently swallowed
    assert any("not recorded" in r.message for r in caplog.records), [r.message for r in caplog.records]
    assert any("not recorded" in e for e in emits)
    hunter.store.close()


def test_hunt_run_loop_survives_an_unhandled_cycle_error(tmp_path):
    """Parity with monitor.run(): one crashed cycle must not end the worker."""
    hunter, emits = _make_hunter(tmp_path)
    with mock.patch.object(hunt.Hunter, "cycle", side_effect=ValueError("boom")):
        runs = hunter.run(once=True)  # old code: ValueError propagated -> exit 1
    assert runs, "the loop appended a survivable error entry"
    assert "ValueError" in runs[0]["error"]
    assert any("aborted" in e for e in emits)
    hunter.store.close()
