"""Disk pressure controller for heavy hunt/scan/fuzz work.

Policy (America/Detroit ops):
  * Pause NEW expensive jobs while free < PAUSE_BELOW_GIB (12).
  * Resume expensive work only after TWO consecutive checks with
    free >= RESUME_GIB (15).
  * Recheck free space immediately before each expensive job; if < 15,
    leave work queued (return False) without losing queue state.
  * Panel/light work: allowed when free >= PANEL_MIN_GIB (8).
  * Never deletes files, caches, or DBs.

State is durable under reports/research/disk_pressure_state.json.
Append-only log: reports/research/disk_pressure.log
"""
from __future__ import annotations

import json
import os
import shutil
import threading
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

PAUSE_BELOW_GIB = 12.0
RESUME_GIB = 15.0
PANEL_MIN_GIB = 8.0
REQUIRED_STREAK = 2
MIN_STREAK_INTERVAL_S = 600  # 10 min between streak-counting checks

_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_STATE_PATH = _ROOT / "reports" / "research" / "disk_pressure_state.json"
DEFAULT_LOG_PATH = _ROOT / "reports" / "research" / "disk_pressure.log"


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def free_gib(path: Optional[Path] = None) -> float:
    """Free space in GiB on the volume containing ``path`` (default project root)."""
    target = Path(path or _ROOT)
    usage = shutil.disk_usage(str(target))
    return usage.free / (1024 ** 3)


@dataclass
class DiskPressureState:
    heavy_paused: bool = True  # safe default: require dual >=15 before first expensive job
    consecutive_ok: int = 0
    last_free_gib: Optional[float] = None
    last_check_at: Optional[str] = None
    last_reason: str = "init: heavy paused until two consecutive checks >=15 GiB"
    last_action: str = "init"  # pause|resume|check|defer
    last_streak_check_mono: float = 0.0  # clock() of last streak-counting check
    checks: List[Dict[str, Any]] = field(default_factory=list)  # recent, capped

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "DiskPressureState":
        return cls(
            heavy_paused=bool(d.get("heavy_paused", True)),
            consecutive_ok=int(d.get("consecutive_ok") or 0),
            last_free_gib=(None if d.get("last_free_gib") is None else float(d["last_free_gib"])),
            last_check_at=d.get("last_check_at"),
            last_reason=str(d.get("last_reason") or ""),
            last_action=str(d.get("last_action") or "check"),
            last_streak_check_mono=float(d.get("last_streak_check_mono") or 0.0),
            checks=list(d.get("checks") or [])[-50:],
        )


class DiskPressureController:
    """Thread-safe controller with injectable free-space probe (for tests)."""

    def __init__(
        self,
        state_path: Optional[Path] = None,
        log_path: Optional[Path] = None,
        free_fn: Optional[Callable[[], float]] = None,
        pause_below: float = PAUSE_BELOW_GIB,
        resume_at: float = RESUME_GIB,
        panel_min: float = PANEL_MIN_GIB,
        required_streak: int = REQUIRED_STREAK,
        min_streak_interval: float = MIN_STREAK_INTERVAL_S,
        clock: Optional[Callable[[], float]] = None,
    ) -> None:
        self.state_path = Path(state_path or DEFAULT_STATE_PATH)
        self.log_path = Path(log_path or DEFAULT_LOG_PATH)
        self.free_fn = free_fn or free_gib
        self.pause_below = float(pause_below)
        self.resume_at = float(resume_at)
        self.panel_min = float(panel_min)
        self.required_streak = int(required_streak)
        self.min_streak_interval = float(min_streak_interval)
        self.clock = clock or time.time
        self._lock = threading.Lock()
        self.state = self._load()

    def _load(self) -> DiskPressureState:
        if self.state_path.exists():
            try:
                return DiskPressureState.from_dict(json.loads(self.state_path.read_text()))
            except (OSError, ValueError, TypeError):
                pass
        return DiskPressureState()

    def _save(self) -> None:
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.state_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self.state.to_dict(), indent=2, sort_keys=True))
        tmp.replace(self.state_path)

    def _log(self, action: str, free: float, reason: str) -> None:
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        line = f"{_utcnow()} action={action} free_gib={free:.2f} reason={reason}\n"
        with self.log_path.open("a", encoding="utf-8") as fh:
            fh.write(line)

    def check(self, free: Optional[float] = None) -> DiskPressureState:
        """Record one free-space observation and update pause/resume streak."""
        with self._lock:
            # Reload durable state so monitor/hunt/dashboard share one controller.
            self.state = self._load()
            g = float(self.free_fn() if free is None else free)
            prev_paused = self.state.heavy_paused
            action = "check"
            if g < self.pause_below:
                self.state.heavy_paused = True
                self.state.consecutive_ok = 0
                action = "pause"
                reason = f"heavy paused: free {g:.2f} GiB < {self.pause_below:g} GiB"
            elif g >= self.resume_at:
                now = float(self.clock())
                last = float(self.state.last_streak_check_mono or 0.0)
                # Count toward streak only if far enough from prior streak-counting check
                # (or first observation). Pause resets streak without waiting.
                if last <= 0.0 or (now - last) >= self.min_streak_interval:
                    self.state.consecutive_ok = int(self.state.consecutive_ok) + 1
                    self.state.last_streak_check_mono = now
                if self.state.heavy_paused and self.state.consecutive_ok >= self.required_streak:
                    self.state.heavy_paused = False
                    action = "resume"
                    reason = (
                        f"heavy resumed: {self.state.consecutive_ok} consecutive checks "
                        f">= {self.resume_at:g} GiB (free {g:.2f})"
                    )
                elif self.state.heavy_paused:
                    reason = (
                        f"heavy still paused: streak {self.state.consecutive_ok}/"
                        f"{self.required_streak} at free {g:.2f} GiB"
                    )
                else:
                    reason = f"heavy allowed: free {g:.2f} GiB (streak {self.state.consecutive_ok})"
            else:
                # 12 <= g < 15
                self.state.consecutive_ok = 0
                if self.state.heavy_paused:
                    reason = (
                        f"heavy paused: free {g:.2f} GiB in "
                        f"[{self.pause_below:g}, {self.resume_at:g}) — need >={self.resume_at:g}"
                    )
                else:
                    # Was running; do not auto-pause until <12, but expensive gate still needs >=15
                    reason = (
                        f"caution: free {g:.2f} GiB < {self.resume_at:g} — "
                        "expensive jobs deferred on next launch check"
                    )
            if action == "pause" and not prev_paused:
                pass  # already set
            elif action == "resume":
                pass
            elif g < self.pause_below:
                action = "pause"

            self.state.last_free_gib = g
            self.state.last_check_at = _utcnow()
            self.state.last_reason = reason
            self.state.last_action = action
            self.state.checks.append({
                "at": self.state.last_check_at,
                "free_gib": round(g, 3),
                "action": action,
                "consecutive_ok": self.state.consecutive_ok,
                "heavy_paused": self.state.heavy_paused,
                "reason": reason,
            })
            self.state.checks = self.state.checks[-50:]
            self._log(action, g, reason)
            self._save()
            return DiskPressureState.from_dict(self.state.to_dict())

    def allow_expensive(self, job: str = "expensive") -> Tuple[bool, str]:
        """Recheck free space before launching an expensive job (no streak advance).

        Streak / pause / resume transitions happen only via ``check()`` (once per
        hunt cycle or monitor tick). This method remasures free and:
          * if free < pause_below → force pause, defer
          * if free < resume_at → defer (queue preserved)
          * if heavy_paused → defer until dual >= resume_at via check()
          * else allow

        Returns (allowed, reason). Does not enqueue/dequeue.
        """
        g = float(self.free_fn())
        with self._lock:
            self.state = self._load()
            if g < self.pause_below:
                was = self.state.heavy_paused
                self.state.heavy_paused = True
                self.state.consecutive_ok = 0
                reason = (
                    f"defer {job}: free {g:.2f} GiB < {self.pause_below:g} GiB "
                    "(heavy paused; queued work preserved)"
                )
                self.state.last_free_gib = g
                self.state.last_check_at = _utcnow()
                self.state.last_action = "pause" if not was else "defer"
                self.state.last_reason = reason
                self._log(self.state.last_action, g, reason)
                self._save()
                return False, reason
            if g < self.resume_at:
                reason = (
                    f"defer {job}: free {g:.2f} GiB < {self.resume_at:g} GiB "
                    "(queued work preserved)"
                )
                self.state.last_free_gib = g
                self.state.last_check_at = _utcnow()
                self.state.last_action = "defer"
                self.state.last_reason = reason
                self._log("defer", g, reason)
                self._save()
                return False, reason
            if self.state.heavy_paused:
                reason = (
                    f"defer {job}: heavy still paused "
                    f"(streak {self.state.consecutive_ok}/{self.required_streak}; "
                    f"free {g:.2f} GiB)"
                )
                self.state.last_free_gib = g
                self.state.last_check_at = _utcnow()
                self.state.last_action = "defer"
                self.state.last_reason = reason
                self._log("defer", g, reason)
                self._save()
                return False, reason
            reason = f"allow {job}: free {g:.2f} GiB"
            self.state.last_free_gib = g
            self.state.last_check_at = _utcnow()
            self.state.last_action = "allow"
            self.state.last_reason = reason
            self._save()
            return True, reason

    def allow_panel(self, free: Optional[float] = None) -> Tuple[bool, str]:
        g = float(self.free_fn() if free is None else free)
        if g < self.panel_min:
            return False, f"panel stop: free {g:.2f} GiB < {self.panel_min:g} GiB"
        return True, f"panel ok: free {g:.2f} GiB"

    def status(self) -> Dict[str, Any]:
        with self._lock:
            self.state = self._load()
            st = self.state.to_dict()
        st.update({
            "pause_below_gib": self.pause_below,
            "resume_gib": self.resume_at,
            "panel_min_gib": self.panel_min,
            "required_streak": self.required_streak,
            "min_streak_interval_s": self.min_streak_interval,
            "state_path": str(self.state_path),
            "log_path": str(self.log_path),
        })
        return st


_controller: Optional[DiskPressureController] = None


def get_controller() -> DiskPressureController:
    global _controller
    if _controller is None:
        interval = float(os.environ.get("AUDITOR_DISK_STREAK_INTERVAL_S", MIN_STREAK_INTERVAL_S))
        state_path = os.environ.get("AUDITOR_DISK_STATE_PATH") or None
        log_path = os.environ.get("AUDITOR_DISK_LOG_PATH") or None
        _controller = DiskPressureController(
            state_path=Path(state_path) if state_path else None,
            log_path=Path(log_path) if log_path else None,
            min_streak_interval=interval,
        )
        # Tests and CI can opt out of the 10-minute dual-streak hysteresis when
        # the volume already has enough free space. Low-disk machines still gate.
        if os.environ.get("AUDITOR_DISK_PRESSURE_RELAX") == "1":
            g = _controller.free_fn()
            if g >= _controller.resume_at:
                _controller.state.heavy_paused = False
                _controller.state.consecutive_ok = _controller.required_streak
                _controller.state.last_reason = (
                    f"relaxed: free {g:.2f} GiB already >= {_controller.resume_at:g} GiB"
                )
                _controller.state.last_action = "resume"
                try:
                    _controller._save()
                except OSError:
                    pass
    return _controller


def reset_controller_for_tests(ctrl: Optional[DiskPressureController] = None) -> None:
    global _controller
    _controller = ctrl
