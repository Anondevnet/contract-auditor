"""Toolchain intelligence.

Executables are discovered via PATH resolution (``shutil.which``), never by
assuming a location. On this machine PATH order is itself a finding: ``solc``
resolves to a pyenv shim rather than a Foundry-managed compiler, so the resolved
path and whether it came from a shim are recorded explicitly.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from typing import Any, Sequence

from .procs import DEFAULT_TIMEOUT_SECONDS, ProcResult, resolve_executable, run

__all__ = [
    "ToolSpec",
    "ToolStatus",
    "ToolchainReport",
    "TOOL_SPECS",
    "detect_tool",
    "detect_toolchain",
    "extract_version",
]


@dataclass(frozen=True)
class ToolSpec:
    """How to find and interrogate one tool."""

    key: str
    display_name: str
    candidates: tuple[str, ...]
    version_arg: str = "--version"
    version_pattern: str = r"[0-9]+\.[0-9]+(?:\.[0-9]+)?(?:[-+][^\s]+)?"
    required: bool = False
    category: str = "general"
    notes: str = ""


TOOL_SPECS: tuple[ToolSpec, ...] = (
    ToolSpec(
        key="python",
        display_name="Python",
        candidates=("python3", "python"),
        version_pattern=r"Python\s+([0-9]+\.[0-9]+(?:\.[0-9]+)?)",
        required=True,
        category="runtime",
        notes="Slither is bound to the active pyenv interpreter.",
    ),
    ToolSpec(
        key="slither",
        display_name="Slither",
        candidates=("slither",),
        version_pattern=r"([0-9]+\.[0-9]+\.[0-9]+)",
        category="static-analysis",
        notes="Static analysis. Presence alone does not prove a clean build env.",
    ),
    ToolSpec(
        key="forge",
        display_name="Foundry / forge",
        candidates=("forge",),
        version_pattern=r"forge Version:\s*(\S+)",
        category="build-test",
        notes="Compilation, unit tests, fuzzing, invariant testing.",
    ),
    ToolSpec(
        key="cast",
        display_name="Foundry / cast",
        candidates=("cast",),
        version_pattern=r"cast Version:\s*(\S+)",
        category="chain-interface",
        notes="RPC reads and calldata encoding. Not used for transactions in Phase 1.",
    ),
    ToolSpec(
        key="anvil",
        display_name="Foundry / anvil",
        candidates=("anvil",),
        version_pattern=r"anvil Version:\s*(\S+)",
        category="chain-interface",
        notes="Local test chain for reproduction.",
    ),
    ToolSpec(
        key="solc",
        display_name="solc",
        candidates=("solc",),
        version_pattern=r"Version:\s*(\S+)",
        category="compiler",
        notes="Compiler availability is per-version; a global solc does not satisfy "
        "a pinned pragma.",
    ),
    ToolSpec(
        key="ollama",
        display_name="Ollama",
        candidates=("ollama",),
        version_pattern=r"ollama version is\s*(\S+)",
        category="ai-reasoning",
        notes="Local model runtime. Never treated as an authority.",
    ),
    ToolSpec(
        key="git",
        display_name="Git",
        candidates=("git",),
        version_pattern=r"git version\s*(\S+)",
        category="general",
    ),
)


_VERSION_PATTERNS: dict[str, re.Pattern[str]] = {
    spec.key: re.compile(spec.version_pattern) for spec in TOOL_SPECS
}


def extract_version(key: str, text: str) -> str | None:
    """Pull a version string out of tool output.

    Tries the tool's own pattern first, then a conservative fallback so an
    unexpected banner format still yields something reportable rather than a
    silent None. Returns None when genuinely nothing looks like a version.
    """
    if not text:
        return None

    pattern = _VERSION_PATTERNS.get(key)
    if pattern is not None:
        match = pattern.search(text)
        if match:
            return match.group(1).strip()

    fallback = re.search(r"[0-9]+\.[0-9]+(?:\.[0-9]+)?(?:[-+][A-Za-z0-9.]+)?", text)
    if fallback:
        return fallback.group(0)
    return None


@dataclass
class ToolStatus:
    """Observed state of one tool. Never assumed."""

    key: str
    display_name: str
    category: str
    required: bool
    available: bool
    path: str | None
    version: str | None
    version_line: str | None
    resolved_via_shim: bool
    returncode: int | None
    error: str | None
    argv: list[str] = field(default_factory=list)
    duration_ms: int = 0
    notes: str = ""
    redirected_by_pyenv: bool = False
    """True when the path sits in a pyenv version directory.

    Distinct from ``resolved_via_shim``: a pyenv shim rewrites PATH and execs
    the versioned binary, so a process launched through a shim sees the
    version directory instead. Which of the two is observed depends on the
    environment the auditor was started from, so both are recorded.
    """

    @property
    def resolution(self) -> str:
        if self.path is None:
            return "NOT_FOUND"
        if self.resolved_via_shim:
            return "SHIM"
        if self.redirected_by_pyenv:
            return "PYENV_VERSION_DIR"
        return "DIRECT"

    @property
    def status(self) -> str:
        if self.available:
            return "AVAILABLE"
        if self.path is None:
            return "NOT_ON_PATH"
        return "PRESENT_BUT_FAILED"

    def to_dict(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "display_name": self.display_name,
            "category": self.category,
            "required": self.required,
            "status": self.status,
            "available": self.available,
            "path": self.path,
            "version": self.version,
            "version_line": self.version_line,
            "resolved_via_shim": self.resolved_via_shim,
            "redirected_by_pyenv": self.redirected_by_pyenv,
            "resolution": self.resolution,
            "returncode": self.returncode,
            "error": self.error,
            "argv": list(self.argv),
            "duration_ms": self.duration_ms,
            "notes": self.notes,
        }


def detect_tool(spec: ToolSpec, timeout: float = DEFAULT_TIMEOUT_SECONDS) -> ToolStatus:
    """Resolve and interrogate a single tool."""
    path = resolve_executable(spec.candidates)

    if path is None:
        return ToolStatus(
            key=spec.key,
            display_name=spec.display_name,
            category=spec.category,
            required=spec.required,
            available=False,
            path=None,
            version=None,
            version_line=None,
            resolved_via_shim=False,
            returncode=None,
            error=f"executable not found on PATH (tried: {', '.join(spec.candidates)})",
            notes=spec.notes,
            redirected_by_pyenv=False,
        )

    argv = [path, spec.version_arg]
    started = time.monotonic()
    result: ProcResult = run(argv, timeout=timeout)
    duration_ms = int((time.monotonic() - started) * 1000)

    first_line = result.first_line() or None
    version = extract_version(spec.key, result.combined()) if result.ok else None

    error: str | None = None
    if result.error:
        error = result.error
    elif result.returncode not in (0, None):
        error = f"exit code {result.returncode}"
    elif version is None:
        error = "ran successfully but no version string could be parsed"

    return ToolStatus(
        key=spec.key,
        display_name=spec.display_name,
        category=spec.category,
        required=spec.required,
        available=result.ok and version is not None,
        path=path,
        version=version,
        version_line=first_line,
        resolved_via_shim=_looks_like_shim(path),
        returncode=result.returncode,
        error=error,
        argv=argv,
        duration_ms=duration_ms,
        notes=spec.notes,
        redirected_by_pyenv=_is_pyenv_version_dir(path),
    )


def _looks_like_shim(path: str) -> bool:
    """True for pyenv/asdf-style shim paths.

    Matters because a shim can point at a different interpreter or a
    globally-installed compiler than the one a given project will use.
    """
    normalized = path.replace("\\", "/").lower()
    return "/shims/" in normalized or normalized.endswith("/shim")


def _is_pyenv_version_dir(path: str) -> bool:
    """True for paths inside a concrete pyenv version directory.

    Indicates the tool was reached through a shim that rewrote PATH, so the
    reported path is the versioned binary rather than the shim the user's
    interactive shell would have resolved.
    """
    normalized = path.replace("\\", "/").lower()
    return "/.pyenv/versions/" in normalized


@dataclass
class ToolchainReport:
    tools: list[ToolStatus]
    timeout_seconds: float

    def get(self, key: str) -> ToolStatus | None:
        for tool in self.tools:
            if tool.key == key:
                return tool
        return None

    def version_of(self, key: str) -> str | None:
        tool = self.get(key)
        return tool.version if tool else None

    def available_keys(self) -> list[str]:
        return [tool.key for tool in self.tools if tool.available]

    def missing_required(self) -> list[str]:
        return [tool.key for tool in self.tools if tool.required and not tool.available]

    def observations(self) -> list[str]:
        """Facts worth surfacing rather than burying in JSON."""
        notes: list[str] = []
        pyenv_bound = [tool for tool in self.tools if tool.available and tool.redirected_by_pyenv]
        if pyenv_bound:
            notes.append(
                f"{', '.join(tool.key for tool in pyenv_bound)} bound to the active pyenv "
                "version via shim resolution; these paths depend on which shell the "
                "auditor was launched from, and selecting a different pyenv version "
                "would change these tools silently"
            )

        solc = self.get("solc")
        if solc is not None and solc.available and solc.resolution != "DIRECT":
            notes.append(
                "solc is a global pyenv-bound compiler, not a pinned per-project "
                "compiler; a project requiring a different pragma will not build "
                "reproducibly from this"
            )

        missing = [tool.key for tool in self.tools if not tool.available]
        if missing:
            notes.append(
                f"not detected: {', '.join(missing)}. This is an observation about this "
                "machine, not a pass/fail result."
            )
        return notes

    def to_dict(self) -> dict[str, Any]:
        return {
            "timeout_seconds": self.timeout_seconds,
            "available": self.available_keys(),
            "missing_required": self.missing_required(),
            "observations": self.observations(),
            "tools": [tool.to_dict() for tool in self.tools],
        }


def detect_toolchain(
    specs: Sequence[ToolSpec] = TOOL_SPECS,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
) -> ToolchainReport:
    return ToolchainReport(tools=[detect_tool(spec, timeout) for spec in specs], timeout_seconds=timeout)