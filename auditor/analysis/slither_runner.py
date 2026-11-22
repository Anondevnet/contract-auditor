"""Shared Slither execution and result normalization.

One subprocess per scan. Analyzers consume the run cached on the
``AnalysisContext`` so Slither is never invoked twice for the same inputs.

Facts enforced here:

* Slither accepts exactly ONE target. Passing many file paths makes the CLI
  exit with a usage error that contains neither ``InvalidCompilation`` nor a
  traceback — a failure mode that previously produced silent zero-finding
  scans for any multi-file project.
* A tool failure is never rendered as a clean result. ``ToolRun.status``
  carries ``failed`` / ``timeout`` / ``not_found`` with a redacted reason so
  the scan can be flagged incomplete.
* Results are parsed from Slither's JSON report (check, impact, confidence,
  element source mappings). The analyzers' existing text parsers remain as a
  fallback when no JSON report was produced.
* Captured tool output is redacted for secret-shaped values before it is
  stored, returned by the API, or exported.
* ``--solc`` / ``--solc-remaps`` are strictly opt-in and validated here
  before Slither is invoked: only an existing executable file is accepted as
  a compiler, never a bare version string, because crytic-compile resolves a
  non-path value through solc-select and would download it — breaking the
  offline guarantee. With neither flag given the argv is exactly what it was
  before they existed.
"""
from __future__ import annotations

import json
import os
import re
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from ..model import Confidence, Finding, Severity
from ..procs import ProcResult, resolve_executable, run

SLITHER_TIMEOUT_SECONDS = 120.0

FAIL_STATUSES = frozenset({"failed", "timeout", "not_found"})

IMPACT_TO_SEVERITY: Dict[str, Severity] = {
    "High": Severity.HIGH,
    "Medium": Severity.MEDIUM,
    "Low": Severity.LOW,
    "Informational": Severity.INFORMATIONAL,
    "Optimization": Severity.INFORMATIONAL,
    "N/A": Severity.INFORMATIONAL,
}

CONFIDENCE_MAP: Dict[str, Confidence] = {
    "High": Confidence.HIGH,
    "Medium": Confidence.MEDIUM,
    "Low": Confidence.LOW,
}

# Canonical set of Slither access-control detector checks. Defined here so
# the generic pass and the access-control analyzer agree without an import
# cycle; ``access_control.py`` aliases this as ACCESS_CONTROL_DETECTORS.
ACCESS_CONTROL_CHECKS = frozenset(
    {
        "tx-origin",
        "missing-zero-check",
        "missing-msg-sender-check",
        "controlled-delegatecall",
        "suicidal",
    }
)

_SECRET_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (
        re.compile(
            r"(?i)([A-Za-z0-9_]*(?:api[_-]?key|apikey|token|secret|password|"
            r"mnemonic|private[_-]?key)[A-Za-z0-9_]*)\s*[=:]\s*\"?[^\s\"';]+"
        ),
        r"\1=***",
    ),
    (re.compile(r"\bsk-[A-Za-z0-9_\-]{8,}"), "sk-***"),
    (re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._\-]+"), "Bearer ***"),
)


def redact(text: str) -> str:
    """Mask secret-shaped values in captured tool output.

    Applied to error/status text only — never to evidence excerpts taken
    from the scanned source itself. Also masks RPC provider path keys
    (``/v2/<key>``, long opaque URL path segments, apiKey query params).
    """
    out = text or ""
    for pattern, replacement in _SECRET_PATTERNS:
        out = pattern.sub(replacement, out)
    out = re.sub(r"(https?://\S+/v2/)([A-Za-z0-9_-]{8,})", r"\1***", out)
    out = re.sub(
        r"([?&](?:api[_-]?key|apikey|key)=)([^&\s]+)",
        r"\1***",
        out,
        flags=re.I,
    )
    out = re.sub(
        r"(https?://[^/\s]+)/(?:v3/)?([A-Za-z0-9_-]{32,})",
        r"\1/***",
        out,
    )
    return out

def truncate(text: str, limit: int = 300) -> str:
    text = (text or "").strip()
    if len(text) <= limit:
        return text
    return text[: limit - 1] + "…"


@dataclass
class ToolRun:
    """Observed execution record for one tool in one scan."""

    key: str
    label: str
    kind: str  # "static-analysis" | "validation" | "compiler"
    status: str  # completed | failed | timeout | not_found | skipped | not_requested
    requested: bool = True
    returncode: Optional[int] = None
    duration_seconds: float = 0.0
    message: str = ""
    error: Optional[str] = None
    finding_count: Optional[int] = None
    severity_counts: Dict[str, int] = field(default_factory=dict)
    detectors: Dict[str, int] = field(default_factory=dict)
    excluded_count: int = 0
    version: Optional[str] = None
    target: Optional[str] = None
    argv: Optional[List[str]] = None

    @property
    def failed(self) -> bool:
        return self.status in FAIL_STATUSES

    def to_dict(self) -> Dict[str, Any]:
        return {
            "key": self.key,
            "label": self.label,
            "kind": self.kind,
            "status": self.status,
            "requested": self.requested,
            "returncode": self.returncode,
            "duration_seconds": round(self.duration_seconds, 3),
            "message": redact(self.message),
            "error": redact(self.error) if self.error else None,
            "finding_count": self.finding_count,
            "severity_counts": dict(self.severity_counts),
            "detectors": dict(self.detectors),
            "excluded_count": self.excluded_count,
            "version": self.version,
            "target": self.target,
            "argv": list(self.argv) if self.argv else None,
        }


@dataclass
class SlitherRun:
    """Raw outcome of one Slither invocation."""

    status: str
    detectors: Optional[List[dict]] = None  # None = no JSON report parsed
    stdout: str = ""
    stderr: str = ""
    returncode: Optional[int] = None
    error: Optional[str] = None
    notes: List[str] = field(default_factory=list)
    target: Optional[str] = None
    cwd: Optional[str] = None
    duration_seconds: float = 0.0
    argv: List[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.status == "completed"

    def failure_note(self) -> Optional[str]:
        """Honest analyzer note when Slither did not complete."""
        if self.ok:
            return None
        reason = truncate(self.error or self.status)
        if self.status == "not_found":
            return f"slither is not available: {reason}"
        if self.status == "timeout":
            return (
                f"slither {reason}; zero findings here would be a tool "
                "failure, not a clean result"
            )
        return (
            f"slither failed ({reason}); zero findings here is a tool "
            "failure, not a clean result"
        )


#: Always-pruned non-first-party / build-output directory names.
_BASE_SKIP_DIRS = frozenset(
    {
        "node_modules",
        "out",
        "cache",
        "artifacts",
        "broadcasts",
        ".git",
        "vendor",
        "dependencies",
    }
)

#: Additional names pruned under the standard scan scope so test harnesses
#: and mock scaffolding never enter the evidence set. ``lib/`` is never
#: listed here — production implementations live there.
_STANDARD_EXTRA_SKIP_DIRS = frozenset({"test", "tests", "mocks", "script", "scripts"})

#: Recognized scan scopes. ``all`` is the Phase-12 legacy walk; ``standard``
#: is the Phase-15 default (dependency + test/mock filtering, ``lib/`` kept).
SCAN_SCOPES = frozenset({"standard", "all"})


def collect_sol_files(
    source_files: Sequence[Path], *, scope: str = "standard"
) -> List[Path]:
    """Expand files/directories into a sorted list of .sol files.

    Directory walks prune well-known non-first-party and build-output
    directories so a single-project scan never drags hundreds of vendored
    contracts into the analyzer's evidence set. If pruning would leave
    nothing (the user pointed directly into a pruned directory), the
    unpruned walk is used so an explicit path always works.

    ``scope`` selects the prune set:

    * ``standard`` (default) — dependency/build dirs plus ``test``/``tests``/
      ``mocks``/``script``/``scripts``. Legitimate production code under
      ``lib/`` is deliberately NOT pruned; users who want vendor-only code
      excluded can point at ``src/``.
    * ``all`` — the Phase-12 legacy set (dependencies/build only); test and
      mock trees are kept. An unknown value is treated as ``standard`` so a
      mistyped scope cannot silently widen the scan.
    """
    if str(scope or "standard") == "all":
        skip_dirs = set(_BASE_SKIP_DIRS)
    else:
        skip_dirs = set(_BASE_SKIP_DIRS) | set(_STANDARD_EXTRA_SKIP_DIRS)
    sol_files: List[Path] = []
    pruned_files: List[Path] = []
    for sf in source_files or []:
        sf = Path(sf)
        if sf.is_file() and sf.suffix.lower() == ".sol":
            sol_files.append(sf)
        elif sf.is_dir():
            for root, dirs, files in os.walk(sf):
                dirs[:] = [d for d in dirs if d not in skip_dirs]
                for name in files:
                    if name.lower().endswith(".sol"):
                        pruned_files.append(Path(root) / name)
            if pruned_files:
                sol_files.extend(pruned_files)
            else:
                # Explicit path into a skipped directory: honor it.
                for entry in sf.rglob("*.sol"):
                    if entry.is_file():
                        sol_files.append(entry)
            pruned_files = []
    return sorted(set(sol_files))


def strip_comments_and_strings(text: str) -> str:
    """Blank ``//``/``/* */`` comments and string literals with spaces.

    Newlines and character offsets are preserved so line numbers computed
    on the result are line numbers in the original source. Shared by the
    source-pattern analyzers (erc4626_inflation, oracle_staleness,
    pool_accounting) so a comment mentioning a mitigation hint cannot
    suppress a finding and commented-out code cannot raise one.
    """
    out = list(text)
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        nxt = text[i + 1] if i + 1 < n else ""
        if c == "/" and nxt == "/":
            while i < n and text[i] != "\n":
                out[i] = " "
                i += 1
        elif c == "/" and nxt == "*":
            end = text.find("*/", i + 2)
            end = n if end < 0 else end + 2
            for k in range(i, end):
                if text[k] != "\n":
                    out[k] = " "
            i = end
        elif c in "\"'":
            k = i + 1
            while k < n and text[k] != c and text[k] != "\n":
                k += 2 if text[k] == "\\" else 1
            end = min(k + 1, n)
            for m in range(i + 1, end - 1):
                out[m] = " "
            i = end
        else:
            i += 1
    return "".join(out)


def find_foundry_root(start: Path) -> Optional[Path]:
    """Nearest ancestor directory (from ``start``) containing foundry.toml."""
    current = start if start.is_dir() else start.parent
    for _ in range(24):
        if (current / "foundry.toml").exists():
            return current
        if current.parent == current:
            break
        current = current.parent
    return None


def choose_target(files: Sequence[Path]) -> tuple[str, Optional[str], Optional[str]]:
    """Pick the single Slither target plus cwd.

    * Foundry project on/above the sources → run at the project root so
      remappings and build config apply (project-aware compilation). A note
      records when the effective scope is wider than the selected path.
    * One file → the file itself.
    * Otherwise → the common ancestor directory.

    Returns ``(target, cwd, note)``.
    """
    if not files:
        raise ValueError("no source files to target")
    project = find_foundry_root(files[0])
    if project is not None:
        note = (
            f"project-aware target: Slither ran at Foundry project root "
            f"{project} (analysis may cover more than the selected path)"
        )
        return ".", str(project), note
    if len(files) == 1:
        solo = Path(os.path.abspath(str(files[0])))
        return str(solo), str(solo.parent), None
    common = Path(os.path.abspath(os.path.commonpath([str(f) for f in files])))
    # File or directory ancestor: absolute target, cwd = its parent.
    # Absolute paths are required — a relative target resolved against a
    # relative cwd double-prefixes (cwd=protocol/contracts +
    # target=protocol/contracts looked for
    # protocol/contracts/protocol/contracts and failed with
    # "not a file or directory"). abspath (not resolve) keeps symlinked
    # temp dirs (macOS /var -> /private/var) identical to caller paths.
    return str(common), str(common.parent), None


def _classify_slither_failure(text: str) -> Optional[str]:
    for line in text.splitlines():
        stripped = line.strip()
        if "InvalidCompilation" in stripped:
            for sub in text.splitlines():
                if "Error:" in sub:
                    return "slither could not compile the sources: " + sub.strip()
            return "slither could not compile the sources (InvalidCompilation)"
        if "unrecognized arguments" in stripped or stripped.startswith("usage: slither"):
            return "slither rejected the invocation (CLI usage error)"
    if "Traceback (most recent call last)" in text:
        lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
        for line in reversed(lines):
            if line and not line.startswith(("File ", "Traceback")):
                return "slither crashed: " + line[:200]
    for line in text.splitlines():
        if "Error" in line and line.strip():
            return truncate(line.strip())
    return None


def validate_solc_path(raw: Optional[str]) -> tuple[Optional[str], Optional[str]]:
    """Resolve ``--solc`` to an absolute executable path, or explain why not.

    Returns ``(path, None)`` on success and ``(None, reason)`` on rejection;
    ``None`` is not an error when no value was supplied at all.

    Only an existing, executable regular file is accepted. A bare compiler
    version such as ``0.8.20`` is rejected here rather than passed through:
    crytic-compile treats a non-path value as a solc-select version and calls
    ``install_artifacts()`` on it unless Foundry's ``offline`` flag is set, so
    forwarding it would let a scan reach for the network. The path is made
    absolute against the caller's working directory because Slither runs with
    a different ``cwd``.
    """
    if raw is None:
        return None, None
    text = str(raw).strip()
    if not text:
        return None, "--solc requires a path to a compiler executable"

    candidate = Path(os.path.expanduser(text))
    if not candidate.is_absolute():
        candidate = Path(os.path.abspath(str(candidate)))

    if not candidate.exists():
        return None, (
            f"--solc value is not an existing file: {raw!r}. Only a path to an "
            "installed compiler executable is accepted; bare compiler versions "
            "are rejected so a compiler is never downloaded"
        )
    if not candidate.is_file():
        return None, f"--solc value is not a regular file: {raw!r}"
    if not os.access(str(candidate), os.X_OK):
        return None, f"--solc value is not executable: {raw!r}"
    return str(candidate), None


def parse_solc_remappings(
    raw: Optional[str],
) -> tuple[Optional[List[str]], Optional[str]]:
    """Split ``--solc-remaps`` into individual ``PREFIX=PATH`` tokens.

    Returns ``(tokens, None)`` or ``(None, reason)``. crytic-compile splits
    the flag's value on spaces and appends each token to the solc argv, so the
    tokens are validated as space-free ``PREFIX=PATH`` pairs here — anything
    else would be silently re-split into a different remapping.
    """
    if raw is None:
        return None, None
    tokens = str(raw).split()
    if not tokens:
        return None, "--solc-remaps was given but contains no remappings"
    for token in tokens:
        if any(ch in token for ch in "\"'"):
            return None, f"remapping {token!r} must not contain quote characters"
        prefix, sep, target = token.partition("=")
        if not sep:
            return None, f"remapping {token!r} is not in PREFIX=PATH form"
        if not prefix or not target:
            return None, f"remapping {token!r} has an empty prefix or path"
    return tokens, None


_SOLC_ARG_FLAGS = frozenset({"--optimize", "--via-ir"})
_SOLC_ARG_VALUED = {
    "--optimize-runs": re.compile(r"^\d{1,10}$"),
    "--evm-version": re.compile(r"^[a-z][a-zA-Z]+$"),
    "--base-path": re.compile(r"^\.$"),
}


def parse_solc_args(raw: Optional[str]) -> tuple[Optional[str], Optional[str]]:
    """Phase 18.1: allow-listed solc settings forwarded via ``--solc-args``.

    Only optimizer / EVM-version / via-IR / ``--base-path .`` are accepted so
    the value can never smuggle another flag (or a download) into solc.
    """
    if raw is None or not str(raw).strip():
        return None, None
    toks = str(raw).split()
    i = 0
    while i < len(toks):
        t = toks[i]
        if t in _SOLC_ARG_FLAGS:
            i += 1
            continue
        if t in _SOLC_ARG_VALUED and i + 1 < len(toks) and _SOLC_ARG_VALUED[t].match(toks[i + 1]):
            i += 2
            continue
        return None, f"solc argument {t!r} is not allowed"
    return " ".join(toks), None


def run_slither(
    files: Sequence[Path],
    timeout: float = SLITHER_TIMEOUT_SECONDS,
    solc: Optional[str] = None,
    solc_remaps: Optional[str] = None,
    solc_args: Optional[str] = None,
    target_override: Optional[str] = None,
    cwd_override: Optional[str] = None,
) -> SlitherRun:
    """Execute Slither once with a single target and a JSON report.

    ``solc`` / ``solc_remaps`` are the already-validated forms of the opt-in
    ``--solc`` and ``--solc-remaps`` inputs. They are re-validated here so a
    caller that bypasses the CLI still cannot reach Slither with an argument
    that would trigger a download. Both are appended after ``--json`` so a
    default invocation keeps the exact argv it has always had.
    """
    solc_arg, solc_error = validate_solc_path(solc)
    remap_tokens, remap_error = parse_solc_remappings(solc_remaps)
    args_value, args_error = parse_solc_args(solc_args)
    target_error = None
    if (target_override is None) != (cwd_override is None):
        target_error = "slither target and cwd overrides must be given together"
    elif target_override is not None:
        _root = Path(cwd_override).resolve()
        _t = (_root / target_override).resolve()
        if Path(target_override).is_absolute() or _root not in _t.parents or not _t.is_file():
            target_error = f"slither target {target_override!r} is not a file under {cwd_override}"
    if solc_error or remap_error or args_error or target_error:
        reasons = [r for r in (solc_error, remap_error, args_error, target_error) if r]
        return SlitherRun(
            status="failed",
            error="; ".join(reasons),
            notes=["invalid --solc/--solc-remaps input; Slither was not invoked"],
        )

    exe = resolve_executable(["slither"])
    if exe is None:
        return SlitherRun(
            status="not_found",
            error="slither not found on PATH (tried: slither)",
            notes=["slither is not installed or not on PATH"],
        )

    if target_override is not None:
        target, cwd, note = target_override, cwd_override, None
    else:
        try:
            target, cwd, note = choose_target(files)
        except ValueError as exc:
            return SlitherRun(status="skipped", error=str(exc), notes=[str(exc)])

    notes = [note] if note else []
    with tempfile.TemporaryDirectory(prefix="ca-slither-") as tmp:
        json_path = Path(tmp) / "report.json"
        argv = [exe, str(target), "--json", str(json_path)]
        if solc_arg:
            argv += ["--solc", solc_arg]
        if remap_tokens:
            argv += ["--solc-remaps", " ".join(remap_tokens)]
        if args_value:
            argv += ["--solc-args", args_value]
        started = time.monotonic()
        result: ProcResult = run(argv, timeout=timeout, cwd=cwd)
        duration = time.monotonic() - started

        if result.timed_out:
            return SlitherRun(
                status="timeout",
                stdout=result.stdout,
                stderr=result.stderr,
                returncode=result.returncode,
                error=f"slither timed out after {timeout:g}s",
                notes=notes,
                target=str(target),
                cwd=cwd,
                duration_seconds=duration,
                argv=argv,
            )
        if result.error:
            return SlitherRun(
                status="failed",
                stdout=result.stdout,
                stderr=result.stderr,
                returncode=result.returncode,
                error=redact(result.error),
                notes=notes,
                target=str(target),
                cwd=cwd,
                duration_seconds=duration,
                argv=argv,
            )

        stdout, stderr = result.stdout or "", result.stderr or ""
        json_error: Optional[str] = None
        detectors: Optional[List[dict]] = None
        if json_path.exists():
            try:
                data = json.loads(json_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                json_error = f"could not read Slither JSON report: {exc}"
            else:
                if not isinstance(data, dict):
                    # A top-level array (or scalar) is not a Slither report;
                    # treat it as a parse failure instead of crashing on
                    # data.get(...) below.
                    json_error = "Slither JSON report is not a JSON object"
                elif data.get("success") is False:
                    json_error = truncate(str(data.get("error") or "Slither reported failure"))
                else:
                    results = data.get("results") or {}
                    raw = results.get("detectors")
                    detectors = [d for d in (raw or []) if isinstance(d, dict)]

        combined = stdout + "\n" + stderr
        if detectors is not None:
            # rc=255 is Slither's normal "findings present" exit; the JSON
            # report is authoritative.
            return SlitherRun(
                status="completed",
                detectors=detectors,
                stdout=stdout,
                stderr=stderr,
                returncode=result.returncode,
                notes=notes,
                target=str(target),
                cwd=cwd,
                duration_seconds=duration,
                argv=argv,
            )

        failure = json_error or _classify_slither_failure(combined) or (
            None
            if (result.returncode or 0) == 0
            else f"slither exited with code {result.returncode} without producing a JSON report"
        )
        if failure is None:
            # Exit 0 but no report: nothing to parse; treat as completed with
            # no detectors only if the tool itself says nothing went wrong.
            return SlitherRun(
                status="completed",
                detectors=[],
                stdout=stdout,
                stderr=stderr,
                returncode=result.returncode,
                notes=notes,
                target=str(target),
                cwd=cwd,
                duration_seconds=duration,
                argv=argv,
            )
        return SlitherRun(
            status="failed",
            detectors=None,
            stdout=stdout,
            stderr=stderr,
            returncode=result.returncode,
            error=redact(truncate(failure)),
            notes=notes,
            target=str(target),
            cwd=cwd,
            duration_seconds=duration,
            argv=argv,
        )


def get_slither_run(context: Any, timeout: float = SLITHER_TIMEOUT_SECONDS) -> SlitherRun:
    """Cached Slither run for this analysis context (executed at most once).

    Opt-in compiler selection travels on ``context.options`` (keys ``solc``
    and ``solc_remaps``), set by the CLI when the corresponding flags were
    supplied. A context without those options — every dashboard scan, every
    legacy caller — invokes Slither exactly as before.
    """
    cached = getattr(context, "_slither_run", None)
    if cached is not None:
        return cached
    options = getattr(context, "options", None) or {}
    if not isinstance(options, dict):
        options = {}
    scope = options.get("scope", "standard")
    files = collect_sol_files(
        getattr(context, "source_files", None) or [], scope=scope
    )
    if not files:
        run_result = SlitherRun(
            status="skipped",
            error="no .sol files to analyze",
            notes=["no .sol files found for Slither"],
        )
    else:
        run_result = run_slither(
            files,
            timeout=timeout,
            solc=options.get("solc"),
            solc_remaps=options.get("solc_remaps"),
            solc_args=options.get("solc_args"),
            target_override=options.get("slither_target"),
            cwd_override=options.get("slither_cwd"),
        )
    try:
        context._slither_run = run_result
    except Exception:  # noqa: BLE001 - context is a plain object; caching is best-effort
        pass
    return run_result


# ---------------------------------------------------------------------------
# Detector helpers
# ---------------------------------------------------------------------------

def detector_location(det: dict) -> tuple[Optional[str], Optional[str], List[int]]:
    """Extract (contract, function, lines) from a Slither JSON detector."""
    contract: Optional[str] = None
    function: Optional[str] = None
    lines: List[int] = []

    elements = [e for e in (det.get("elements") or []) if isinstance(e, dict)]
    for el in elements:
        mapping = el.get("source_mapping") or {}
        el_lines = [int(x) for x in (mapping.get("lines") or []) if isinstance(x, (int, float))]
        if el.get("type") == "function" and function is None:
            function = (el.get("name") or "").split("(")[0].strip() or None
            if el_lines:
                lines = el_lines
            parent = (el.get("type_specific_fields") or {}).get("parent") or {}
            if parent.get("type") == "contract" and parent.get("name"):
                contract = str(parent["name"])
        elif el.get("type") == "contract" and contract is None and el.get("name"):
            contract = str(el["name"])
            if not lines and el_lines:
                lines = el_lines

    if not lines:
        for el in elements:
            mapping = el.get("source_mapping") or {}
            el_lines = [int(x) for x in (mapping.get("lines") or []) if isinstance(x, (int, float))]
            if el_lines:
                lines = el_lines
                break

    if function is None or contract is None:
        header = re.search(r"\b([A-Za-z_]\w*)\.([A-Za-z_]\w*)\s*\(", str(det.get("description") or ""))
        if header:
            if contract is None:
                contract = header.group(1)
            if function is None:
                function = header.group(2)
    return contract, function, lines


def evidence_lines(det: dict, limit: int = 6) -> List[str]:
    """Bullet/summary lines from the detector description (verbatim)."""
    description = str(det.get("description") or "").strip()
    if not description:
        return []
    lines = [ln.strip() for ln in description.splitlines() if ln.strip()]
    bullets = [ln for ln in lines if ln.startswith("- ")]
    chosen = bullets[:limit] or lines[:limit]
    return [ln[:160] for ln in chosen]


def detector_filename(det: dict) -> Optional[str]:
    """Source file reported by the first Slither element that names one."""
    for el in det.get("elements") or []:
        if not isinstance(el, dict):
            continue
        mapping = el.get("source_mapping") or {}
        name = mapping.get("filename") or mapping.get("filename_short")
        if isinstance(name, str) and name:
            return name
    return None


def relative_source_name(
    filename: Optional[str], source_files: Sequence[Path]
) -> Optional[str]:
    """Project-relative name for a detector's file, or None if not multi-file.

    Single-file scans (including address scans, whose temp path is random)
    return None so fingerprints stay stable across runs. Multi-file scans
    relativize against the common root of the collected files; a path
    outside that root falls back to its basename (still deterministic for
    a fixed project layout).
    """
    if not filename:
        return None
    files = [str(f) for f in (source_files or [])]
    if len(files) < 2:
        return None
    try:
        if not os.path.isabs(filename):
            # Slither already emitted a cwd-relative path (Foundry root /
            # project-root runs): stable for the same project layout.
            return Path(filename).as_posix()
        root = os.path.commonpath(files)
        if root and (os.path.isfile(root) or root.lower().endswith(".sol")):
            root = os.path.dirname(root)
        rel = os.path.relpath(filename, root) if root else filename
        if rel.startswith(".."):
            return Path(filename).name
        return Path(rel).as_posix()
    except (ValueError, OSError):
        return Path(filename).name


def lines_to_str(lines: Sequence[int]) -> str:
    if not lines:
        return "unknown"
    ordered = sorted(int(x) for x in lines)
    if len(ordered) == 1:
        return str(ordered[0])
    return f"{ordered[0]}-{ordered[-1]}"


def surfaced_checks(detectors: Sequence[dict]) -> tuple[Dict[str, int], int]:
    """Split detectors into surfaced histogram + excluded count.

    Surfaced = reentrancy family (any impact) + access-control allowlist
    (any impact) + High/Medium/Low anything else. Everything else (mostly
    informational/optimization results) is excluded and counted so the tool
    status can say so instead of hiding it.
    """
    hist: Dict[str, int] = {}
    excluded = 0
    for det in detectors:
        check = str(det.get("check") or "unknown")
        impact = str(det.get("impact") or "")
        if check.startswith("reentrancy") or check in ACCESS_CONTROL_CHECKS:
            hist[check] = hist.get(check, 0) + 1
        elif impact in ("High", "Medium", "Low"):
            hist[check] = hist.get(check, 0) + 1
        else:
            excluded += 1
    return hist, excluded


def slither_tool_run(
    run_result: SlitherRun,
    findings: Sequence[Finding] = (),
    detector_findings_note: str = "",
) -> ToolRun:
    """Build the ToolRun record for one Slither run.

    Counts come from the findings the analyzers actually surfaced; the
    detector histogram and excluded count come from the JSON report.
    """
    severity_counts: Dict[str, int] = {}
    for f in findings:
        key = f.severity.value if isinstance(f.severity, Severity) else str(f.severity)
        severity_counts[key] = severity_counts.get(key, 0) + 1

    detectors: Dict[str, int] = {}
    excluded = 0
    if run_result.detectors is not None:
        detectors, excluded = surfaced_checks(run_result.detectors)

    if run_result.status == "completed":
        message = (
            f"Slither completed: {len(findings)} finding(s) surfaced from "
            f"{sum(detectors.values())} matching detector result(s)"
        )
        if excluded:
            message += f"; {excluded} informational/other result(s) not listed as findings"
        if detector_findings_note:
            message += f" ({detector_findings_note})"
        if run_result.notes:
            message += " — " + run_result.notes[0]
        error = None
    else:
        message = run_result.notes[0] if run_result.notes else "Slither did not complete"
        error = run_result.error or run_result.status

    return ToolRun(
        key="slither",
        label="Slither (static analysis)",
        kind="static-analysis",
        status=run_result.status,
        requested=True,
        returncode=run_result.returncode,
        duration_seconds=run_result.duration_seconds,
        message=message,
        error=error,
        finding_count=len(findings),
        severity_counts=severity_counts,
        detectors=detectors,
        excluded_count=excluded,
        target=run_result.target,
        argv=list(run_result.argv) if run_result.argv else None,
    )


def probe_solc(timeout: float = 10.0) -> ToolRun:
    """Record the global PATH solc as an informational tool status row."""
    from ..toolchain import TOOL_SPECS, detect_tool

    spec = next((s for s in TOOL_SPECS if s.key == "solc"), None)
    if spec is None:
        return ToolRun(
            key="solc",
            label="solc (compiler on PATH)",
            kind="compiler",
            status="skipped",
            requested=False,
            message="solc tool spec not defined",
        )
    status = detect_tool(spec, timeout=timeout)
    if status.available:
        message = (
            f"solc {status.version} resolved at {status.path} — global PATH "
            "compiler; which compiler an analysis tool actually used is "
            "determined by that tool, not by this probe"
        )
        return ToolRun(
            key="solc",
            label="solc (compiler on PATH)",
            kind="compiler",
            status="completed",
            requested=True,
            returncode=status.returncode,
            duration_seconds=status.duration_ms / 1000.0,
            message=message,
            version=status.version,
            argv=list(status.argv) or None,
        )
    reason = status.error or f"solc not usable (status {status.status})"
    return ToolRun(
        key="solc",
        label="solc (compiler on PATH)",
        kind="compiler",
        status="not_found" if status.path is None else "failed",
        requested=True,
        returncode=status.returncode,
        duration_seconds=status.duration_ms / 1000.0,
        message="solc probe did not succeed",
        error=truncate(reason),
    )


def required_analysis_verdict(run_result: Optional[SlitherRun]) -> tuple[Optional[bool], List[str]]:
    """Phase 18.1: was the REQUIRED analyzer (Slither) actually run to completion?

    ``(True, [])`` only when a Slither run was observed with status
    ``completed``; ``(False, [reason])`` for an observed run that did not
    complete (not found, compile failure, timeout, skipped). ``(None, [])``
    when no shared run was observed at all — an honest unknown, never a
    "complete". A scan without a True verdict must never be reported as a
    clean audit.
    """
    if run_result is None:
        return None, []
    if run_result.ok:
        err = str(getattr(run_result, "stderr", "") or "")
        if "No contract was analyzed" in err or re.search(r"analyzed \(0 contracts", err):
            # Exit 0 but nothing compiled (wrong solc/remappings/target): not a clean run.
            return False, ["Slither (static analysis): completed but analyzed 0 contracts "
                           "(compilation produced nothing; check solc version/remappings/target)"]
        return True, []
    reason = redact(truncate(run_result.error or run_result.status, 400))
    return False, [f"Slither (static analysis): {run_result.status}: {reason}"]
