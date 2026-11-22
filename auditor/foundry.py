"""Opt-in Foundry build/test validation.

Compilation and test results are **validation evidence, not security
results**: a green ``forge build`` or ``forge test`` never means the code is
free of vulnerabilities, and every message here says so. Only read-only,
offline-capable subcommands are ever executed — never ``forge create``,
``forge script --broadcast``, or any transaction-sending command.

Execution goes through :func:`auditor.procs.run` (argv arrays only,
``shell=False``, hard timeout, captured output) and every recorded string is
redacted for secret-shaped values.
"""
from __future__ import annotations

import time
from pathlib import Path
from typing import Optional

from .analysis.slither_runner import ToolRun, redact, truncate
from .procs import resolve_executable, run

FORGE_BUILD_TIMEOUT_SECONDS = 600.0
FORGE_TEST_TIMEOUT_SECONDS = 600.0

_BUILD_EVIDENCE_NOTE = (
    "Compilation result only — not evidence for or against vulnerabilities."
)
_TEST_EVIDENCE_NOTE = (
    "Test-run result only — passing tests do not establish the absence of "
    "vulnerabilities."
)


def not_requested_tool_run(key: str, label: str) -> ToolRun:
    return ToolRun(
        key=key,
        label=label,
        kind="validation",
        status="not_requested",
        requested=False,
        message="Not selected for this scan.",
    )


def _skipped(key: str, label: str, reason: str) -> ToolRun:
    return ToolRun(
        key=key,
        label=label,
        kind="validation",
        status="skipped",
        requested=True,
        message=truncate(reason),
    )


def _run_forge(
    key: str,
    label: str,
    subcommand: list[str],
    project_dir: Path,
    timeout: float,
    evidence_note: str,
) -> ToolRun:
    if not (Path(project_dir) / "foundry.toml").exists():
        return _skipped(key, label, f"no foundry.toml at {project_dir}")

    exe = resolve_executable(["forge"])
    if exe is None:
        return ToolRun(
            key=key,
            label=label,
            kind="validation",
            status="not_found",
            requested=True,
            error="forge not found on PATH (tried: forge)",
            message="Foundry is not installed or not on PATH",
        )

    argv = [exe] + list(subcommand)
    started = time.monotonic()
    result = run(argv, timeout=timeout, cwd=str(project_dir))
    duration = time.monotonic() - started

    if result.timed_out:
        return ToolRun(
            key=key,
            label=label,
            kind="validation",
            status="timeout",
            requested=True,
            duration_seconds=duration,
            error=f"forge {' '.join(subcommand)} timed out after {timeout:g}s",
            message=evidence_note,
            target=str(project_dir),
            argv=argv,
        )
    if result.error:
        return ToolRun(
            key=key,
            label=label,
            kind="validation",
            status="failed",
            requested=True,
            duration_seconds=duration,
            error=redact(truncate(result.error)),
            message=evidence_note,
            target=str(project_dir),
            argv=argv,
        )

    if result.returncode == 0:
        return ToolRun(
            key=key,
            label=label,
            kind="validation",
            status="completed",
            requested=True,
            returncode=0,
            duration_seconds=duration,
            message=f"forge {' '.join(subcommand)} exited 0. {evidence_note}",
            target=str(project_dir),
            argv=argv,
        )

    combined = (result.stderr or "") + "\n" + (result.stdout or "")
    first_error = next(
        (ln.strip() for ln in combined.splitlines() if ln.strip()),
        f"forge {' '.join(subcommand)} exited with code {result.returncode}",
    )
    return ToolRun(
        key=key,
        label=label,
        kind="validation",
        status="failed",
        requested=True,
        returncode=result.returncode,
        duration_seconds=duration,
        error=redact(truncate(first_error)),
        message=f"forge {' '.join(subcommand)} failed. {evidence_note}",
        target=str(project_dir),
        argv=argv,
    )


def run_forge_build(
    project_dir: Path, timeout: float = FORGE_BUILD_TIMEOUT_SECONDS
) -> ToolRun:
    """Compile the project (opt-in). Read-only build, never a deploy."""
    return _run_forge(
        "forge-build",
        "Foundry build (forge build)",
        ["build"],
        Path(project_dir),
        timeout,
        _BUILD_EVIDENCE_NOTE,
    )


def _has_tests(project_dir: Path) -> Optional[str]:
    """Return the test directory if one exists, else None."""
    for name in ("test", "tests"):
        candidate = Path(project_dir) / name
        if candidate.is_dir():
            return name
    return None


def run_forge_test(
    project_dir: Path, timeout: float = FORGE_TEST_TIMEOUT_SECONDS
) -> ToolRun:
    """Run the Foundry test suite (opt-in). Local EVM only; no RPC/network."""
    label = "Foundry tests (forge test)"
    if not (Path(project_dir) / "foundry.toml").exists():
        return _skipped("forge-test", label, f"no foundry.toml at {project_dir}")
    test_dir = _has_tests(Path(project_dir))
    if test_dir is None:
        return _skipped(
            "forge-test",
            label,
            "no test/ or tests/ directory found; forge test was not run",
        )
    return _run_forge(
        "forge-test",
        label,
        ["test"],
        Path(project_dir),
        timeout,
        _TEST_EVIDENCE_NOTE,
    )
