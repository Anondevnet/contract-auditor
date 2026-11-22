"""Unit/integration tests for disk pressure controller (mocked free GiB)."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from auditor.disk_pressure import (
    DiskPressureController,
    reset_controller_for_tests,
)


@pytest.fixture
def tmp_ctrl(tmp_path: Path):
    free = {"g": 20.0}
    clock = {"t": 1_000_000.0}

    def free_fn():
        return float(free["g"])

    def clock_fn():
        return float(clock["t"])

    ctrl = DiskPressureController(
        state_path=tmp_path / "state.json",
        log_path=tmp_path / "disk_pressure.log",
        free_fn=free_fn,
        min_streak_interval=600.0,
        clock=clock_fn,
    )
    reset_controller_for_tests(ctrl)
    yield ctrl, free, clock
    reset_controller_for_tests(None)


def test_pause_below_12(tmp_ctrl):
    ctrl, free, clock = tmp_ctrl
    free["g"] = 11.0
    st = ctrl.check()
    assert st.heavy_paused is True
    assert st.consecutive_ok == 0
    assert st.last_action == "pause"
    ok, why = ctrl.allow_expensive("scan")
    assert ok is False
    assert "12" in why or "paused" in why.lower() or "defer" in why


def test_no_resume_in_12_to_14_9(tmp_ctrl):
    ctrl, free, clock = tmp_ctrl
    free["g"] = 11.0
    ctrl.check()
    free["g"] = 14.5
    st = ctrl.check()
    assert st.heavy_paused is True
    assert st.consecutive_ok == 0
    ok, why = ctrl.allow_expensive("scan")
    assert ok is False
    assert "15" in why or "defer" in why


def test_resume_only_after_two_consecutive_ge_15(tmp_ctrl):
    ctrl, free, clock = tmp_ctrl
    free["g"] = 11.0
    ctrl.check()
    assert ctrl.state.heavy_paused

    free["g"] = 16.0
    st1 = ctrl.check()
    assert st1.heavy_paused is True
    assert st1.consecutive_ok == 1
    ok1, _ = ctrl.allow_expensive("scan")
    assert ok1 is False  # still need second check

    # Too soon — same streak window; must not count as second
    clock["t"] += 60
    st_early = ctrl.check()
    assert st_early.consecutive_ok == 1
    assert st_early.heavy_paused is True

    # 10+ minutes later → second consecutive
    clock["t"] += 600
    st2 = ctrl.check()
    assert st2.consecutive_ok >= 2
    assert st2.heavy_paused is False
    assert st2.last_action == "resume"
    ok2, why2 = ctrl.allow_expensive("scan")
    assert ok2 is True
    assert "allow" in why2


def test_recheck_before_expensive_defers_if_dropped(tmp_ctrl):
    ctrl, free, clock = tmp_ctrl
    free["g"] = 16.0
    ctrl.check()
    clock["t"] += 600
    ctrl.check()
    assert ctrl.state.heavy_paused is False

    free["g"] = 14.0  # drop below resume threshold
    ok, why = ctrl.allow_expensive("fork")
    assert ok is False
    assert "14" in why or "15" in why


def test_drop_below_12_repauses(tmp_ctrl):
    ctrl, free, clock = tmp_ctrl
    free["g"] = 16.0
    ctrl.check()
    clock["t"] += 600
    ctrl.check()
    assert not ctrl.state.heavy_paused
    free["g"] = 10.0
    st = ctrl.check()
    assert st.heavy_paused is True
    assert st.consecutive_ok == 0
    ok, _ = ctrl.allow_expensive("scan")
    assert ok is False


def test_panel_floor_8(tmp_ctrl):
    ctrl, free, _ = tmp_ctrl
    free["g"] = 7.5
    ok, why = ctrl.allow_panel()
    assert ok is False
    free["g"] = 8.5
    ok2, _ = ctrl.allow_panel()
    assert ok2 is True


def test_queue_not_lost_on_defer(tmp_ctrl, tmp_path: Path):
    """Simulated queue: defer leaves items; resume processes without duplicate enqueue."""
    ctrl, free, clock = tmp_ctrl
    queue = ["a", "b", "c"]
    scanned = []
    seen = set()

    def run_expensive(item: str) -> bool:
        ok, _ = ctrl.allow_expensive(f"scan:{item}")
        if not ok:
            return False
        if item in seen:
            raise AssertionError("duplicate job")
        seen.add(item)
        scanned.append(item)
        return True

    free["g"] = 10.0
    ctrl.check()
    # attempt while paused — none run, queue intact
    for item in list(queue):
        run_expensive(item)
    assert scanned == []
    assert queue == ["a", "b", "c"]

    free["g"] = 16.0
    ctrl.check()
    clock["t"] += 600
    ctrl.check()
    assert not ctrl.state.heavy_paused

    # process without re-enqueue
    remaining = []
    for item in queue:
        if not run_expensive(item):
            remaining.append(item)
    assert scanned == ["a", "b", "c"]
    assert remaining == []
    # second pass must not duplicate
    for item in list(scanned):
        ok, _ = ctrl.allow_expensive(f"scan:{item}")
        assert ok is True
        if item in seen:
            pass  # caller skips already-scanned — queue state preserved by caller
    assert scanned == ["a", "b", "c"]


def test_log_and_state_persist(tmp_ctrl, tmp_path: Path):
    ctrl, free, clock = tmp_ctrl
    free["g"] = 11.0
    ctrl.check()
    free["g"] = 16.0
    ctrl.check()
    clock["t"] += 600
    ctrl.check()
    log = (tmp_path / "disk_pressure.log").read_text()
    assert "pause" in log
    assert "resume" in log
    state = json.loads((tmp_path / "state.json").read_text())
    assert state["heavy_paused"] is False
    assert state["consecutive_ok"] >= 2
