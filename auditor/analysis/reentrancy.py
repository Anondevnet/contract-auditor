"""Reentrancy vulnerability analyzer.

Wraps Slither's reentrancy detection and produces ``Finding`` objects with
full evidence trails.  The analyzer runs Slither as a subprocess with
``shell=False`` and a hard timeout; failures are isolated and reported as notes.

Typical usage::

    from auditor.analysis.reentrancy import analyze
    from auditor.analysis.base import AnalysisContext

    outcome = reentrancy_analyze.analyze(AnalysisContext(
        source_files=[Path("contracts/MyContract.sol")]
    ))
    for finding in outcome.findings:
        print(finding.title)
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any, List

from .base import AnalysisContext, AnalysisOutcome, BaseAnalyzer
from ..model import Severity, Confidence, VerificationStatus, Finding
from ..model import Epistemic, EvidenceItem


def analyze(context: AnalysisContext) -> AnalysisOutcome:
    """Run reentrancy analysis on the given source files.

    Consumes the shared, cached Slither run on ``context`` (executed at most
    once per scan, always with a single target). JSON detector results are
    authoritative; the text parser is a fallback when no JSON report exists.
    """
    from .slither_runner import (
        collect_sol_files,
        detector_filename,
        detector_location,
        evidence_lines,
        get_slither_run,
        lines_to_str,
        relative_source_name,
    )

    outcome = AnalysisOutcome()
    outcome.findings = []
    outcome.evidence = []
    outcome.notes = []

    source_files: list[Path] = context.source_files or []
    if not source_files:
        outcome.notes.append("no source files provided to reentrancy analyzer")
        return outcome

    _opts = getattr(context, "options", None)
    _scope = _opts.get("scope", "standard") if isinstance(_opts, dict) else "standard"
    sol_files = collect_sol_files(source_files, scope=_scope)
    if not sol_files:
        outcome.notes.append("no .sol files found")
        return outcome

    run_result = get_slither_run(context)
    outcome.notes.extend(n for n in run_result.notes if n)

    if run_result.detectors is not None:
        for det in run_result.detectors:
            check = str(det.get("check") or "")
            if not check.startswith("reentrancy"):
                continue
            contract, function, lines = detector_location(det)
            if not contract or not function:
                outcome.notes.append(
                    "slither reported a reentrancy result that could not be "
                    "located in the source; it was not recorded as a finding"
                )
                continue
            f = _make_finding(
                    contract,
                    function,
                    lines_to_str(lines),
                    evidence_lines(det),
                    detector=check,
                    impact=str(det.get("impact") or ""),
                    affected_file=relative_source_name(
                        detector_filename(det), sol_files
                    ),
                )
            _downgrade_lock_covered(f, sol_files)
            outcome.findings.append(f)
        return outcome

    # No JSON report: fall back to text parsing of whatever Slither printed.
    outcome.findings = _parse_slither_text(run_result.stdout, run_result.stderr)
    note = run_result.failure_note() or _slither_failure_note(run_result.stderr)
    if note:
        outcome.notes.append(note)
    return outcome


def _parse_slither_text(stdout: str, stderr: str) -> list[Any]:
    """Parse Slither's output and return a list of ``Finding`` objects.

    Slither prints reentrancy findings grouped under ``Detector: reentrancy-*``
    blocks. We capture the block header (contract, function, line range), the
    bullet lines with the external call and state write, and map the detector
    name to a severity (``reentrancy-eth`` -> HIGH, ``reentrancy-no-eth`` ->
    MEDIUM, ``reentrancy-benign`` -> LOW). Evidence items are built from the
    captured tool output lines (``Epistemic.FACT``).
    """
    findings: list[Any] = []

    text = stdout + stderr

    current_detector: str | None = None
    block_detector: str | None = None
    current_contract: str | None = None
    current_function: str | None = None
    current_lines: str = "unknown"
    current_evidence: list[str] = []

    def flush() -> None:
        nonlocal current_contract, current_function, current_lines, current_evidence, block_detector
        if current_contract and current_function:
            findings.append(_make_finding(
                current_contract,
                current_function,
                current_lines,
                list(current_evidence),
                detector=block_detector,
            ))
        current_contract = None
        current_function = None
        current_lines = "unknown"
        current_evidence = []
        block_detector = None

    for line in text.split("\n"):
        stripped = line.strip()

        if stripped.startswith("Detector:"):
            flush()
            current_detector = stripped.split(":", 1)[1].strip()
            continue
        if stripped.startswith("INFO:Detectors:"):
            flush()
            current_detector = None
            continue

        header_match = re.search(r"Reentrancy in (\w+)\.(\w+)\(", line)
        if header_match:
            flush()
            current_contract = header_match.group(1)
            current_function = header_match.group(2)
            block_detector = current_detector
            current_lines = "unknown"
            current_evidence = []
            range_match = re.search(r"#(\d+)-(\d+)", line)
            if range_match:
                current_lines = f"{range_match.group(1)}-{range_match.group(2)}"
            continue

        if current_contract is None:
            continue

        range_match = re.search(r"#(\d+)-(\d+)", line)
        if range_match:
            current_lines = f"{range_match.group(1)}-{range_match.group(2)}"
        else:
            single_match = re.search(r"#(\d+)", line)
            if single_match and current_lines == "unknown":
                current_lines = single_match.group(1)

        if stripped.startswith("Reference:"):
            flush()
        elif stripped == "" and current_lines != "unknown":
            flush()
        elif stripped.startswith("- ") and len(current_evidence) < 6:
            current_evidence.append(stripped[:160])

    flush()
    return findings


def _slither_failure_note(stderr: str) -> str | None:
    """Honest note when slither failed rather than finding nothing.

    A clean "0 findings" claim is wrong when the analyzer could not compile
    the sources at all; surface that as an analyzer note instead.
    """
    text = stderr or ""
    if "InvalidCompilation" not in text and "Traceback (most recent call last)" not in text:
        return None
    for line in text.splitlines():
        if "Error:" in line or "InvalidCompilation" in line:
            return "slither failed to analyze the sources: " + line.strip()[:200]
    return (
        "slither failed to analyze the sources; zero findings here is a "
        "tool failure, not a clean result"
    )


_DETECTOR_SEVERITY = {
    "reentrancy-eth": Severity.HIGH,
    "reentrancy-no-eth": Severity.MEDIUM,
    "reentrancy-benign": Severity.LOW,
}


def _make_finding(
    contract: str,
    function: str,
    lines: str,
    evidence: list[str],
    detector: str | None = None,
    impact: str = "",
    affected_file: str | None = None,
) -> Finding:
    """Create a Finding from parsed Slither reentrancy data."""
    from .slither_runner import IMPACT_TO_SEVERITY, redact

    raw = [redact(str(x).strip()) for x in evidence if str(x).strip()] or [
        f"slither reported reentrancy in {contract}.{function} (lines {lines})"
    ]
    severity = (
        _DETECTOR_SEVERITY.get(detector or "")
        or IMPACT_TO_SEVERITY.get(impact)
        or Severity.HIGH
    )
    detector_note = (
        f" Slither detector: {detector}." if detector else ""
    )
    return Finding(
        title=f"Reentrancy vulnerability in {contract}.{function}",
        description=(
            "Potential reentrancy vulnerability: external call before "
            "state variable write. The contract calls an external address "
            "and then modifies state, which can allow reentrant attacks."
            + detector_note
        ),
        category="security",
        severity=severity,
        confidence=Confidence.LOW if detector == "reentrancy-benign" else Confidence.MEDIUM,
        verification_status=VerificationStatus.UNVERIFIED,
        affected_contract=contract,
        affected_function=function,
        affected_lines=_parse_lines(lines),
        affected_file=affected_file,
        source="slither",
        tool="slither",
        evidence=[
            EvidenceItem(
                epistemic=Epistemic.FACT,
                source="slither",
                artifact_type="tool_output",
                excerpt=line,
                tool="slither",
            )
            for line in raw
        ],
        prerequisites=raw,
        likelihood="POSSIBLE",
        false_positive_risk="Requires manual review of the external call pattern",
        assumptions=["EVM environment", "slither detector output as produced"],
        contradicting_evidence=raw,
        benign_explanation="If the external call is to a trusted contract with no fallback/receive function, reentrancy risk is mitigated",
        remediation=(
            "Use the checks-effects-interactions pattern: "
            "write state variables before external calls. "
            "Consider using OpenZeppelin's ReentrancyGuard."
        ),
        references=[
            "https://github.com/crytic/slither/wiki/Detector-Documentation#reentrancy-vulnerabilities-1"
        ],
        )


def _parse_lines(lines_str: str) -> list[int]:
    """Parse a line range string like '16-21' (or a single line) into line numbers."""
    try:
        parts = lines_str.split("-")
        if len(parts) == 2:
            start, end = int(parts[0]), int(parts[1])
            return list(range(start, end + 1))
        if len(parts) == 1 and parts[0].strip().isdigit():
            return [int(parts[0])]
    except ValueError:
        pass
    return []

def _downgrade_lock_covered(finding, sol_files) -> None:
    """Same-contract reentry blocked by a mutex on every entry point -> INFORMATIONAL.

    Recorded as unresolved suspicion, not dismissed: cross-contract and
    read-only reentrancy (another market / integrator reading stale state
    mid-call) are not excluded by a per-contract lock.
    """
    from ..model import Severity
    from .sol_parse import admin_guarded, contracts_in, lock_covered
    universe = []
    for p in sol_files:
        try:
            universe.extend(contracts_in(Path(p).read_text(errors="replace")))
        except (OSError, ValueError, IndexError):
            continue
    lk = lock_covered(universe, finding.affected_function or "")
    if not lk:
        g = admin_guarded(universe, finding.affected_contract, finding.affected_function or "")
        if not g:
            return
        reason = (f"{finding.affected_function} is admin-only ({g}); an outsider cannot start this "
                  f"call sequence. Unresolved: a malicious/compromised admin or callee is not excluded")
        finding.severity = Severity.INFORMATIONAL
        finding.title = f"{finding.title} (admin-only path)"
        finding.benign_explanation = reason
        finding.false_positive_risk = "high: " + reason
        return
    reason = (f"every entry point into {finding.affected_function} holds reentrancy lock "
              f"'{lk}'; same-contract reentry blocked. Unresolved: cross-contract / "
              f"read-only reentrancy not excluded")
    finding.severity = Severity.INFORMATIONAL
    finding.title = f"{finding.title} (lock-covered: {lk})"
    finding.benign_explanation = reason
    finding.false_positive_risk = "high: " + reason
