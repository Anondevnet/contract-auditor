"""Safe subprocess primitives.

Rules enforced here:

* ``shell=False`` always. Arguments are passed as a sequence, never interpolated
  into a command string, so target-controlled values cannot become shell syntax.
* Every call has a timeout. A hung tool cannot wedge the auditor.
* Failures are returned as data (``ProcResult``), not raised as bare
  ``OSError``, so callers are forced to decide what an error means.
* Captured output is truncated to bound memory use on hostile output.
"""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from typing import Sequence

DEFAULT_TIMEOUT_SECONDS: float = 15.0
MAX_CAPTURE_CHARS: int = 4096

__all__ = [
    "DEFAULT_TIMEOUT_SECONDS",
    "MAX_CAPTURE_CHARS",
    "ProcResult",
    "resolve_executable",
    "run",
]


@dataclass(frozen=True)
class ProcResult:
    """Outcome of one subprocess execution attempt."""

    argv: tuple[str, ...]
    returncode: int | None
    stdout: str
    stderr: str
    timed_out: bool = False
    error: str | None = None

    @property
    def ok(self) -> bool:
        """True only for a clean, non-timeout, zero-exit run."""
        return self.error is None and not self.timed_out and self.returncode == 0

    def combined(self) -> str:
        """stdout and stderr joined, for tools that print version to either."""
        parts = [part for part in (self.stdout, self.stderr) if part.strip()]
        return "\n".join(parts)

    def first_line(self) -> str:
        for line in self.combined().splitlines():
            if line.strip():
                return line.strip()
        return ""

    def to_dict(self) -> dict[str, object]:
        return {
            "argv": list(self.argv),
            "returncode": self.returncode,
            "timed_out": self.timed_out,
            "error": self.error,
        }


def _as_text(value: object) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)


def _truncate(text: str) -> str:
    if len(text) <= MAX_CAPTURE_CHARS:
        return text
    return text[:MAX_CAPTURE_CHARS] + f"\n...[truncated at {MAX_CAPTURE_CHARS} chars]"


def resolve_executable(names: Sequence[str]) -> str | None:
    """Return the first name found on PATH, or None.

    ``shutil.which`` is used rather than assuming fixed locations such as
    /usr/local/bin or /opt/homebrew/bin, because on this machine PATH order
    already decides which tool wins.
    """
    for name in names:
        if not name:
            continue
        found = shutil.which(name)
        if found:
            return found
    return None


def run(
    argv: Sequence[str],
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
    cwd: str | None = None,
) -> ProcResult:
    """Execute ``argv`` with no shell and a hard timeout."""
    args = tuple(str(part) for part in argv)
    if not args:
        return ProcResult(
            argv=(),
            returncode=None,
            stdout="",
            stderr="",
            error="refusing to execute empty argv",
        )

    try:
        completed = subprocess.run(  # noqa: S603 - shell=False, fixed argv
            args,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            check=False,
            shell=False,
            cwd=cwd,
        )
    except subprocess.TimeoutExpired as exc:
        return ProcResult(
            argv=args,
            returncode=None,
            stdout=_truncate(_as_text(exc.stdout)),
            stderr=_truncate(_as_text(exc.stderr)),
            timed_out=True,
            error=f"timeout after {timeout:g}s",
        )
    except (OSError, ValueError) as exc:
        return ProcResult(
            argv=args,
            returncode=None,
            stdout="",
            stderr="",
            error=f"{type(exc).__name__}: {exc}",
        )

    return ProcResult(
        argv=args,
        returncode=completed.returncode,
        stdout=_truncate(completed.stdout or ""),
        stderr=_truncate(completed.stderr or ""),
    )