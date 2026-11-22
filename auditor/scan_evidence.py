"""Scan evidence capture (Phase 15 DeFi-readiness, changes C1 + C2).

Persists reproducibility evidence alongside a scan record: which compiler and
which Slither were observable, which compiler the analysis *actually drove*,
and a fingerprint of the *effective* configuration.

Two fields must never be confused, because conflating them is exactly the
defect C2 corrects:

* ``compiler_version`` — the compiler Slither disclosed it invoked, parsed
  from the tool's own output. ``None`` whenever that could not be observed
  or the observations contradict each other. A PATH probe is never promoted
  into this field.
* ``path_compiler_version`` — the informational ``solc`` found on PATH. It
  says what is installed, not what ran. On this machine the two differ (a
  pyenv ``solc`` shim resolves 0.5.8 while scans are driven by 0.8.36), so
  reporting PATH as effective would misstate every result.

``selected_compiler`` records the same answer with provenance: ``source``
says *how* the compiler was determined and ``verification`` says whether it
is proof of runtime execution (``observed``), only project configuration
(``project-config`` — Foundry build-info, which says what a build *should*
have used, not what this run did), or nothing at all (``unverified``).

Evidence only. Nothing here feeds a finding: detector selection, severity,
deduplication, validation and scoring are untouched by design. Every probe
is a fixed-argv ``--version`` invocation with a hard timeout and is wrapped
so a probe failure degrades into a recorded reason instead of an exception —
a missing tool must never fail the scan that documents it.

Configuration fingerprint: computed over inputs this path actually honours
(analyser set, release gate, auditor/schema version, plus the opt-in
``--solc`` / ``--solc-remaps`` selection) so equal fingerprints mean equal
effective analysis. Inputs the CLI scan path does not use — model selection,
model probing, per-tool timeout — are deliberately excluded so the
fingerprint never changes for a reason that cannot change a result.
Absolute source paths and timestamps are excluded so the same configuration
in a different working directory fingerprints identically; a requested
compiler version and the requested remappings are *configuration*, not
source locations, so they are included.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

__all__ = [
    "SCAN_EVIDENCE_SCHEMA",
    "config_fingerprint",
    "collect_scan_evidence",
    "observe_compiler",
    "probe_binary_version",
    "probe_tool",
    "read_build_info_version",
    "selected_compiler",
]

#: Bump only when the persisted evidence shape changes incompatibly.
#: v2 adds compiler-*provenance* fields (``path_compiler_version``,
#: ``path_compiler_path``, ``selected_compiler.verification``) and stops
#: reporting PATH solc as the selected compiler. v1 records stay readable:
#: readers must treat every new key as optional.
SCAN_EVIDENCE_SCHEMA = "scan-evidence/v2"

#: Bump when the *inputs* that define an effective configuration change.
_CONFIG_FINGERPRINT_VERSION = "scan-config/1"

#: ``'solc --version' running`` / ``'solc file.sol --combined-json ...' running``
#: as crytic-compile logs them, echoed to Slither's stdout.
_RE_TOOL_COMMAND = re.compile(r"'(?P<cmd>[^'\n]+)' running")

#: solc's own diagnostic when the pragma and the invoked compiler disagree:
#: "Source file requires different compiler version (current compiler is
#: 0.5.8+commit.23d335f2.Darwin.appleclang - note that nightly builds ..."
_RE_SOLC_REPORTED_VERSION = re.compile(r"current compiler is ([^\s]+)")

#: Compiler version recorded in Foundry/Hardhat build-info JSON.
_RE_BUILD_INFO_SOLC_VERSION = re.compile(rb'"solcVersion"\s*:\s*"([^"]+)"')

#: Bounds on build-info reads so a hostile or enormous artifact cannot stall
#: evidence capture: at most this many files, this many bytes each.
_MAX_BUILD_INFO_FILES = 25
_MAX_BUILD_INFO_BYTES = 64 * 1024 * 1024


def probe_tool(key: str, timeout: float = 10.0) -> Dict[str, Any]:
    """Resolve one tool and its version. Never raises.

    Returns a JSON-safe record::

        {"key", "status", "version", "path", "error"}

    ``status`` is ``completed`` only when a version string was actually
    parsed — availability without a parseable version is reported as
    ``failed``, never as a version we did not observe.
    """
    from .toolchain import TOOL_SPECS, detect_tool

    def _result(status: str, version: Optional[str], path: Optional[str],
                error: Optional[str]) -> Dict[str, Any]:
        return {
            "key": key,
            "status": status,
            "version": version,
            "path": path,
            "error": error,
        }

    spec = next((s for s in TOOL_SPECS if s.key == key), None)
    if spec is None:
        return _result("skipped", None, None, f"no tool spec defined for {key}")

    try:
        status = detect_tool(spec, timeout=timeout)
    except Exception as exc:  # noqa: BLE001 - evidence capture must not fail a scan
        return _result("failed", None, None, f"{type(exc).__name__}: {exc}")

    if status.version:
        return _result("completed", status.version, status.path, None)
    if status.path is None:
        return _result("not_found", None, None,
                       status.error or "executable not found on PATH")
    return _result("failed", None, status.path,
                   status.error or "ran but no version string could be parsed")


def probe_binary_version(binary: str, timeout: float = 10.0) -> Dict[str, Any]:
    """Interrogate one specific executable with ``--version``. Never raises.

    Unlike :func:`probe_tool` this does not consult PATH at all — the caller
    supplies the exact binary, so the answer is about *that* binary rather
    than about whatever ``solc`` happens to resolve to here.

    Returns ``{"status", "version", "error"}``.
    """
    from .procs import run
    from .toolchain import extract_version

    if not binary:
        return {"status": "failed", "version": None,
                "error": "no binary supplied"}
    try:
        result = run([binary, "--version"], timeout=timeout)
    except Exception as exc:  # noqa: BLE001 - evidence capture must not fail a scan
        return {"status": "failed", "version": None,
                "error": f"{type(exc).__name__}: {exc}"}

    if result.error:
        return {"status": "failed", "version": None, "error": result.error}
    if result.returncode not in (0, None):
        return {"status": "failed", "version": None,
                "error": f"exit code {result.returncode}"}
    version = extract_version("solc", result.combined())
    if not version:
        return {"status": "failed", "version": None,
                "error": "ran but no version string could be parsed"}
    return {"status": "completed", "version": version, "error": None}


def observe_compiler(
    slither_run: Any,
    *,
    solc_requested: Optional[str] = None,
    timeout: float = 10.0,
) -> Dict[str, Any]:
    """Which compiler Slither actually drove, as disclosed by the tools.

    Two independent disclosures are used, in this order:

    1. the ``'<binary> --version' running`` / ``'<binary> <file>
       --combined-json ...' running`` lines crytic-compile logs while
       compiling, which Slither echoes to its stdout;
    2. solc's own ``current compiler is <version>`` diagnostic, emitted when
       the pragma and the invoked compiler disagree.

    The disclosed binary is then interrogated directly, so the version is
    about that binary and not about PATH.

    Returns ``{"binary", "version", "verification", "reason",
    "request_honored", "corroborating", "requested"}`` where
    ``verification`` is ``observed`` or ``unverified`` — never
    ``project-config``, because nothing here is configuration.
    """
    base = {
        "binary": None,
        "version": None,
        "verification": "unverified",
        "reason": None,
        "request_honored": None,
        "corroborating": None,
        "requested": solc_requested,
    }

    stdout = str(getattr(slither_run, "stdout", "") or "")
    stderr = str(getattr(slither_run, "stderr", "") or "")

    reported: Optional[str] = None
    match = _RE_SOLC_REPORTED_VERSION.search(stderr) or \
        _RE_SOLC_REPORTED_VERSION.search(stdout)
    if match:
        reported = match.group(1)

    commands = [m.group("cmd") for m in _RE_TOOL_COMMAND.finditer(stdout)]

    binary: Optional[str] = None
    for cmd in commands:
        if cmd.endswith(" --version"):
            binary = cmd[: -len(" --version")]
            break
    if binary is None:
        for cmd in commands:
            if " --combined-json " in cmd or " --standard-json" in cmd:
                binary = cmd.split(" ", 1)[0]
                break

    if binary is None:
        base["corroborating"] = reported
        base["reason"] = (
            "Slither did not disclose the compiler it invoked"
            if reported is None
            else "Slither did not disclose which binary it invoked; only "
                 f"the compiler diagnostic {reported!r} was observed"
        )
        return base

    base["binary"] = binary
    base["corroborating"] = reported
    probe = probe_binary_version(binary, timeout=timeout)
    probed_version = probe.get("version")

    if probed_version and reported and probed_version != reported:
        base["version"] = None
        base["verification"] = "unverified"
        base["reason"] = (
            f"observed compiler {binary!r} reports {probed_version} but the "
            f"analysis reported using {reported}; the two observations "
            "contradict each other"
        )
        return base

    version = probed_version or reported
    if version is None:
        base["reason"] = (
            f"observed compiler {binary!r} could not be interrogated: "
            f"{probe.get('error') or 'no version available'}"
        )
        return base

    base["version"] = version
    base["verification"] = "observed"
    if probed_version is None:
        base["reason"] = (
            f"version taken from the compiler's own diagnostic because "
            f"interrogating {binary!r} failed: {probe.get('error')}"
        )

    if solc_requested:
        honored = os.path.abspath(binary) == os.path.abspath(solc_requested)
        base["request_honored"] = honored
        if not honored:
            base["reason"] = (
                (base["reason"] + "; ") if base["reason"] else ""
            ) + (
                f"an explicit --solc {solc_requested!r} was supplied but "
                f"Slither reported using {binary!r}; the project build "
                "configuration likely overrode the request"
            )
    return base


def read_build_info_version(project_root: Path | str) -> Dict[str, Any]:
    """Compiler version declared by local Foundry build-info, if any.

    **Project-configuration evidence only.** Build-info says which compiler a
    *previous* ``forge build`` recorded for this project — it is not proof
    that this scan's Slither run executed that compiler, which is why
    :func:`selected_compiler` never marks it ``observed``.

    Reads only, bounded: at most ``_MAX_BUILD_INFO_FILES`` files of at most
    ``_MAX_BUILD_INFO_BYTES`` each, matched by a byte regex rather than a
    full JSON parse so a multi-megabyte AST cannot stall evidence capture.
    Returns ``{"version", "files", "reason"}``.
    """
    result: Dict[str, Any] = {"version": None, "files": 0, "reason": None}
    if not project_root:
        return result

    root = Path(project_root)
    candidates: List[Path] = []

    build_info_path: Optional[str] = None
    out_path: Optional[str] = None
    config = root / "foundry.toml"
    if config.is_file():
        try:
            import tomllib

            data = tomllib.loads(config.read_text(encoding="utf-8"))
            profile = (data.get("profile") or {}).get("default") or {}
            if isinstance(profile, dict):
                candidate = profile.get("build_info_path")
                if isinstance(candidate, str) and candidate:
                    build_info_path = candidate
                candidate = profile.get("out")
                if isinstance(candidate, str) and candidate:
                    out_path = candidate
        except Exception as exc:  # noqa: BLE001 - optional configuration read
            result["reason"] = f"could not read foundry.toml: {type(exc).__name__}"

    directory = root / build_info_path if build_info_path else root / (out_path or "out")
    directory = directory / "build-info" if build_info_path is None else directory
    if directory.is_dir():
        candidates = sorted(
            (p for p in directory.glob("*.json") if not p.name.endswith(".output.json")),
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        )[:_MAX_BUILD_INFO_FILES]

    if not candidates:
        result["reason"] = result["reason"] or "no local build-info found"
        return result

    versions: List[str] = []
    for path in candidates:
        try:
            if path.stat().st_size > _MAX_BUILD_INFO_BYTES:
                continue
            blob = path.read_bytes()
        except OSError:
            continue
        result["files"] += 1
        match = _RE_BUILD_INFO_SOLC_VERSION.search(blob)
        if match:
            try:
                versions.append(match.group(1).decode("utf-8", "replace"))
            except Exception:  # noqa: BLE001 - decode is already lossy-safe
                continue

    if not versions:
        result["reason"] = "build-info present but declares no solcVersion"
        return result
    distinct = sorted(set(versions))
    if len(distinct) > 1:
        result["reason"] = (
            "build-info declares multiple compiler versions: " + ", ".join(distinct)
        )
        return result
    result["version"] = distinct[0]
    result["reason"] = None
    return result


def selected_compiler(
    sol_files: Sequence[Path | str],
    solc_probe: Dict[str, Any],
    *,
    slither_run: Any = None,
    solc_requested: Optional[str] = None,
    probe_timeout: float = 10.0,
) -> Dict[str, Any]:
    """Which compiler governed this scan, with provenance for the claim.

    ``source`` is one of:

    * ``explicit-solc-arg`` — Slither disclosed the binary it invoked and it
      matches the ``--solc`` path the caller supplied. Proof of execution.
    * ``observed-from-tool-output`` — Slither disclosed the binary it invoked
      without an explicit request. Proof of execution.
    * ``project-build-config`` — a Foundry root governs and Slither disclosed
      nothing; the project's configuration (and any local build-info) is
      reported as configuration, never as proof of which binary this run
      executed. ``version`` is ``None`` unless build-info declares one.
    * ``unverified`` — no disclosure, no governing project. The PATH probe is
      reported in ``reason`` for context and in ``path_compiler_version`` at
      the top level, but is **not** promoted to a selected-compiler version:
      knowing which solc is installed is not knowing which one ran.
    * ``unavailable`` — nothing usable at all, including no PATH solc.

    ``verification`` is the load-bearing field: ``observed`` (proof of
    runtime execution), ``project-config`` (configuration evidence only), or
    ``unverified``.
    """
    project_root: Optional[str] = None

    def _shell(**overrides: Any) -> Dict[str, Any]:
        base: Dict[str, Any] = {
            "source": "unverified",
            "version": None,
            "path": None,
            "project_root": project_root,
            "verification": "unverified",
            "reason": None,
            "requested": solc_requested,
            "request_honored": None,
            "corroborating": None,
        }
        base.update(overrides)
        return base

    try:
        from .analysis.slither_runner import find_foundry_root

        root = find_foundry_root(Path(sol_files[0])) if sol_files else None
        project_root = str(root) if root is not None else None
    except Exception as exc:  # noqa: BLE001 - never fail evidence on root discovery
        # Without a trustworthy root answer we do not know whether a project
        # build configuration governs, and we still know nothing about what
        # ran, so nothing may be claimed.
        return _shell(
            source="unavailable",
            verification="unverified",
            reason=(
                f"could not determine project root: {type(exc).__name__}: {exc}"
            ),
        )

    observed: Optional[Dict[str, Any]] = None
    if slither_run is not None:
        observed = observe_compiler(
            slither_run, solc_requested=solc_requested, timeout=probe_timeout
        )

    if observed is not None and observed.get("verification") == "observed":
        source = (
            "explicit-solc-arg"
            if solc_requested
            and observed.get("binary")
            and os.path.abspath(str(observed["binary"])) == os.path.abspath(solc_requested)
            else "observed-from-tool-output"
        )
        return _shell(
            source=source,
            version=observed.get("version"),
            path=observed.get("binary"),
            verification="observed",
            reason=observed.get("reason"),
            request_honored=observed.get("request_honored"),
            corroborating=observed.get("corroborating"),
        )

    if project_root is not None:
        build_info = read_build_info_version(project_root)
        pieces = [
            "Foundry project root detected; the project's build configuration "
            "selects the compiler and was not probed as runtime execution"
        ]
        if build_info.get("version"):
            pieces.append(
                f"build-info declares solc {build_info['version']}, recorded as "
                "project-configuration evidence only — not proof of which "
                "compiler this run executed"
            )
        elif build_info.get("reason"):
            pieces.append(str(build_info["reason"]))
        if observed is not None and observed.get("reason"):
            pieces.append(str(observed["reason"]))
        elif observed is None:
            pieces.append("Slither disclosed no compiler for this run")
        if solc_requested and observed is None:
            pieces.append(
                f"an explicit --solc {solc_requested!r} was supplied but could "
                "not be confirmed to have taken effect"
            )
        return _shell(
            source="project-build-config",
            version=build_info.get("version"),
            verification="project-config",
            reason="; ".join(pieces) + ".",
            request_honored=(observed or {}).get("request_honored"),
            corroborating=(observed or {}).get("corroborating"),
        )

    # No governing project and no disclosure of what ran.
    path_version = solc_probe.get("version")
    if path_version:
        reason = (
            f"Slither disclosed no compiler for this run; the PATH solc is "
            f"{path_version}, but a PATH probe is not proof of which compiler "
            "was invoked"
        )
        if solc_requested:
            reason += (
                f"; an explicit --solc {solc_requested!r} was supplied but could "
                "not be confirmed to have taken effect"
            )
        if observed is not None and observed.get("reason"):
            reason += f"; {observed['reason']}"
        return _shell(reason=reason)

    return _shell(
        source="unavailable",
        reason=solc_probe.get("error") or "no usable solc observed",
    )


def config_fingerprint(
    *,
    analyzer_keys: Sequence[str],
    fail_on: Optional[str],
    auditor_version: str,
    schema_version: Any,
    solc: Optional[str] = None,
    solc_remaps: Optional[str] = None,
    scope: Optional[str] = None,
) -> str:
    """SHA-256 over the effective configuration of one scan.

    Deterministic (sorted keys, fixed separators) and independent of
    invocation order, absolute *source* paths and timestamps.

    ``solc`` is the identity of the opt-in compiler selection (its probed
    version, or its path when the version could not be probed) and
    ``solc_remaps`` the opt-in remappings. ``scope`` is a non-default
    file-collection scope (``standard`` is omitted, matching every scan
    before the flag existed). All three change what is analysed, so all
    three belong here; each is omitted entirely when unset/default, which
    keeps every fingerprint produced before they existed byte-identical.
    """
    payload = {
        "fingerprint_version": _CONFIG_FINGERPRINT_VERSION,
        "analyzers": sorted(str(k) for k in analyzer_keys),
        "fail_on": fail_on or None,
        "auditor_version": str(auditor_version),
        "schema_version": str(schema_version),
    }
    if solc:
        payload["solc"] = str(solc)
    if solc_remaps:
        payload["solc_remaps"] = str(solc_remaps)
    if scope and str(scope) != "standard":
        payload["scope"] = str(scope)
    blob = json.dumps(payload, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def collect_scan_evidence(
    *,
    sol_files: Sequence[Path | str],
    analyzer_keys: Sequence[str],
    fail_on: Optional[str],
    auditor_version: str,
    schema_version: Any,
    probe_timeout: float = 10.0,
    notes: Sequence[str] = (),
    slither_run: Any = None,
    solc_requested: Optional[str] = None,
    solc_version_requested: Optional[str] = None,
    solc_remaps_requested: Optional[str] = None,
    scope: Optional[str] = None,
) -> Dict[str, Any]:
    """Build the persisted tool-execution/evidence record for one scan.

    Shape is compatible with the dashboard's tool-execution reader (``tools``
    holds ``ToolRun``-shaped dicts) plus the C1/C2 evidence keys. Absent tools
    are recorded as absent; no key is ever populated with a version we did
    not observe.

    ``slither_run`` is the shared cached run (``context._slither_run``) when
    one happened; ``None`` means no Slither execution was observed at all,
    which is what makes ``compiler_version`` honestly ``None`` rather than a
    PATH guess.
    """
    solc = probe_tool("solc", timeout=probe_timeout)
    slither = probe_tool("slither", timeout=probe_timeout)
    compiler = selected_compiler(
        sol_files,
        solc,
        slither_run=slither_run,
        solc_requested=solc_requested,
        probe_timeout=probe_timeout,
    )

    fingerprint = config_fingerprint(
        analyzer_keys=analyzer_keys,
        fail_on=fail_on,
        auditor_version=auditor_version,
        schema_version=schema_version,
        solc=solc_version_requested,
        solc_remaps=solc_remaps_requested,
        scope=scope,
    )

    def _toolrun(probe: Dict[str, Any], label: str, kind: str) -> Dict[str, Any]:
        if probe["status"] == "completed":
            message = f"{probe['key']} {probe['version']} at {probe['path']}"
        elif probe["status"] == "not_found":
            message = f"{probe['key']} not found on PATH"
        else:
            message = probe.get("error") or f"{probe['key']} version not determined"
        return {
            "key": probe["key"],
            "label": label,
            "kind": kind,
            "status": probe["status"],
            "requested": True,
            "returncode": None,
            "duration_seconds": 0.0,
            "message": message,
            "error": probe.get("error"),
            "finding_count": None,
            "severity_counts": {},
            "detectors": {},
            "excluded_count": 0,
            "version": probe.get("version"),
            "target": None,
            "argv": None,
        }

    tools: List[Dict[str, Any]] = [
        _toolrun(solc, "solc (compiler on PATH)", "compiler"),
        _toolrun(slither, "Slither (static analysis)", "static-analysis"),
    ]

    clean_notes: List[str] = []
    for note in notes:
        text = str(note).strip()
        if text and text not in clean_notes:
            clean_notes.append(text)

    return {
        "schema": SCAN_EVIDENCE_SCHEMA,
        # CLI scans do not report a completion verdict here: deriving one
        # would need the shared Slither run result, and a fabricated
        # "complete" would be worse than the honest unknown the dashboard
        # already renders for a missing value.
        "tools": tools,
        "validation": None,
        "scan_complete": None,
        "incomplete_reasons": [],
        "zero_findings_note": None,
        "notes": clean_notes,
        "static_analysis_requested": True,
        "foundry_validation_requested": False,
        "foundry_tests_requested": False,
        # --- C1/C2 evidence ---
        # The compiler Slither disclosed it invoked — ``None`` unless that
        # disclosure was observed and self-consistent. Deliberately NOT the
        # PATH probe: see ``path_compiler_version`` below.
        "compiler_version": (
            compiler.get("version")
            if compiler.get("verification") == "observed"
            else None
        ),
        "slither_version": slither.get("version"),
        # Informational only: which solc this machine has on PATH. It answers
        # "what is installed", never "what ran".
        "path_compiler_version": solc.get("version"),
        "path_compiler_path": solc.get("path"),
        "selected_compiler": compiler,
        # Opt-in compiler selection as requested, recorded verbatim (already
        # validated to be an executable path and space-free PREFIX=PATH pairs).
        "solc_requested": solc_requested,
        "solc_version_requested": solc_version_requested,
        "solc_remaps_requested": solc_remaps_requested,
        # Toolchain inventory: the PATH probes, same source as
        # ``path_compiler_version``. Kept for the dashboard's tool table.
        "tool_versions": {
            "solc": solc.get("version"),
            "slither": slither.get("version"),
        },
        "config_fingerprint": fingerprint,
    }
