"""Phase 43 — per-row commit discipline in ``Hunter._check_proxy_upgrades``.

Evidence (2026-10-24, ``reports/watchdog.run.log`` + fcntl lock-byte probes):
this stage executed per-row ``UPDATE hunt_candidates`` statements but kept the
only ``commit()`` at the very end of the ≤40-row loop. A candidate that
resolved successfully opened a write transaction (RESERVED+PENDING locks on
monitor_state.db) that stayed open across the NEXT rows' ``resolve_proxy()``
network calls and rate-limit sleeps — in the live wedge, ~50+ minutes — so
every other writer/reader (monitor poll, dashboard, watchdog heartbeat) was
blocked and the journal stayed frozen.

Pinned contract here:

1. Each successful row UPDATE is committed BEFORE the loop proceeds to the
   next candidate's ``resolve_proxy()`` RPC work (item ordering below).
2. No write transaction is open while any ``resolve_proxy()`` call runs
   (real ``sqlite3.Connection.in_transaction`` recorded inside the RPC double).
3. Both update branches are covered: the implementation-changed branch
   (``SET implementation=``) and the last_proxy_checked_at refresh branch
   (``SET last_proxy_checked_at=``).

No wall-clock assertions, no contention theater (nothing here merely asserts
that SQLite raises "database is locked"), and the live production
``monitor_state.db`` is never touched (isolated tmp MonitorStore only).

Test-double notes (see Phase 42 lesson): ``sqlite3.Connection`` is a builtin
and cannot be monkeypatched, so ``hunter.store.conn`` is replaced with a
duck-typed recording wrapper that forwards UPDATE/commit to the real
connection. ``resolve_proxy`` is imported inside the method on every call
(``from .vault_discovery import Reader, resolve_proxy``), so patching the
``auditor.vault_discovery`` module attribute reaches the method.
"""
from __future__ import annotations

import json
from typing import Any, Dict, List, Tuple

import pytest

from auditor import hunt
from auditor.monitor import MonitorStore


class _Info:
    """Minimal ``resolve_proxy`` result double (code_size/implementation/kind)."""

    def __init__(self, implementation: str, kind: str = "EIP1967", code_size: int = 1):
        self.implementation = implementation
        self.kind = kind
        self.code_size = code_size


class _RecordingConn:
    """Duck-typed connection wrapper recording execute/commit order.

    The candidate SELECT is served from canned rows; every write is recorded,
    classified by its SQL marker, and forwarded to the real connection so the
    real ``in_transaction`` state machine is exercised.
    """

    def __init__(self, real, plan_rows: List[Dict[str, Any]], events: List[Tuple[str, ...]]):
        self._real = real
        self._plan_rows = plan_rows
        self.events = events

    def execute(self, sql: str, params: Any = ()):
        head = " ".join(str(sql).split())
        if head.startswith("SELECT address"):
            self.events.append(("select",))
            return _CannedCursor(list(self._plan_rows))
        if "SET implementation=" in head:
            self.events.append(("update", "changed"))
        elif "SET last_proxy_checked_at=" in head:
            self.events.append(("update", "unchanged"))
        else:  # the pinned contract covers every write in this method
            raise AssertionError(f"unexpected SQL in _check_proxy_upgrades: {head}")
        return self._real.execute(sql, params)

    def commit(self) -> None:
        self.events.append(("commit",))
        self._real.commit()

    def close(self) -> None:
        # MonitorStore.close() calls self.conn.close(); forward it.
        self._real.close()

    def __getattr__(self, name: str) -> Any:  # surfacing the real conn in tests
        raise AttributeError(
            f"_RecordingConn has no attribute {name!r}; use `.real` for assertions"
        )

    @property
    def real(self):
        return self._real


class _CannedCursor:
    def __init__(self, rows: List[Dict[str, Any]]):
        self._rows = rows

    def fetchall(self) -> List[Dict[str, Any]]:
        return list(self._rows)

    def fetchone(self):
        return self._rows[0] if self._rows else None


def _addr(seed: str) -> str:
    return "0x" + (seed * 40)[:40]


def _canned_rows() -> List[Dict[str, Any]]:
    """Row 1 resolves to a NEW implementation (changed branch);
    row 2 resolves to the SAME implementation (unchanged branch)."""
    return [
        {
            "address": _addr("a"),
            "implementation": _addr("b"),
            "proxy_kind": "EIP1967",
            "discovery_json": json.dumps({"slot": "impl"}),
            "status": "scanned",
        },
        {
            "address": _addr("c"),
            "implementation": _addr("d"),
            "proxy_kind": "minimal",
            "discovery_json": None,
            "status": "scanned",
        },
    ]


@pytest.fixture()
def wired_hunter(tmp_path, monkeypatch):
    """Hunter on an isolated store + `hunter.store.conn` wrapped in the recorder.

    Returns (hunter, recorder, events, emitted, real_conn). The real store is
    closed at teardown, so no fixture leaks an open sqlite handle.
    """
    cfg = hunt.HuntConfig(db_path=tmp_path / "hunt43.db", cache_dir=tmp_path / "cache")
    emitted: List[str] = []
    hunter = hunt.Hunter(cfg, client=object(), emit=emitted.append, clock=lambda: 10_000.0)
    assert isinstance(hunter.store, MonitorStore)
    real_conn = hunter.store.conn  # genuine sqlite3.Connection from MonitorStore
    events: List[Tuple[str, ...]] = []
    hunter.store.conn = _RecordingConn(real_conn, _canned_rows(), events)
    yield hunter, hunter.store.conn, events, emitted, real_conn
    hunter.store.conn.close()


# ---------------------------------------------------------------------------
# 1) ordering: UPDATE → commit, BEFORE the next candidate's resolve_proxy()
# ---------------------------------------------------------------------------

def test_each_row_committed_before_next_rpc_both_branches(wired_hunter, monkeypatch):
    hunter, _recorder, events, _emitted, _real = wired_hunter

    def fake_resolve_proxy(reader, address):
        events.append(("rpc", address))
        if address == _addr("a"):
            return _Info(_addr("e"))  # differs from previous → changed branch
        return _Info(_addr("d"))  # same as previous → unchanged branch

    monkeypatch.setattr("auditor.vault_discovery.resolve_proxy", fake_resolve_proxy)

    stats = hunter._check_proxy_upgrades(limit=2)

    assert stats == {"checked": 2, "changed": 1, "unavailable": 0}
    # Update(r1) is committed BEFORE any rpc for r2; both branches hit; exactly
    # one commit per updated row and no trailing extra commit.
    assert events == [
        ("select",),
        ("rpc", _addr("a")),
        ("update", "changed"),
        ("commit",),
        ("rpc", _addr("c")),
        ("update", "unchanged"),
        ("commit",),
    ]


# ---------------------------------------------------------------------------
# 2) mechanism: no write transaction open while ANY resolve_proxy() runs
#    (real in_transaction state, recorded live inside the RPC double)
# ---------------------------------------------------------------------------

def test_no_write_txn_open_during_any_rpc(wired_hunter, monkeypatch):
    hunter, _recorder, events, _emitted, real = wired_hunter
    in_txn_during_rpc: List[bool] = []

    def fake_resolve_proxy(reader, address):
        events.append(("rpc", address))
        in_txn_during_rpc.append(bool(real.in_transaction))
        if address == _addr("a"):
            return _Info(_addr("e"))
        return _Info(_addr("d"))

    monkeypatch.setattr("auditor.vault_discovery.resolve_proxy", fake_resolve_proxy)

    hunter._check_proxy_upgrades(limit=2)

    # With the old loop-end commit, rpc #2 ran while r1's UPDATE transaction
    # was still open (in_transaction True). The contract: never true.
    assert in_txn_during_rpc == [False, False]
    # ... and the store is left with nothing pending at the end of the method.
    assert real.in_transaction is False


# ---------------------------------------------------------------------------
# 3) unchanged branch in isolation: exactly one rpc → one committed UPDATE
# ---------------------------------------------------------------------------

def test_unchanged_branch_commits_before_returning(wired_hunter, monkeypatch):
    hunter, _recorder, events, _emitted, real = wired_hunter
    only_row = _canned_rows()[1]  # unchanged-branch row alone
    hunter.store.conn = _RecordingConn(real, [only_row], events)

    def fake_resolve_proxy(reader, address):
        events.append(("rpc", address))
        return _Info(only_row["implementation"])  # same → untouched refresh branch

    monkeypatch.setattr("auditor.vault_discovery.resolve_proxy", fake_resolve_proxy)

    stats = hunter._check_proxy_upgrades(limit=2)

    assert stats == {"checked": 1, "changed": 0, "unavailable": 0}
    assert events == [("select",), ("rpc", _addr("c")), ("update", "unchanged"), ("commit",)]
    assert real.in_transaction is False
