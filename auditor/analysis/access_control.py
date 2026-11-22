"""Access control vulnerability analyzer.

Wraps Slither's access control detection and produces ``Finding`` objects with
full evidence trails.  The analyzer runs Slither as a subprocess with
``shell=False`` and a hard timeout; failures are isolated and reported as notes.

Typical usage::

    from auditor.analysis.access_control import analyze
    from auditor.analysis.base import AnalysisContext

    outcome = analyze(AnalysisContext(
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
from .slither_runner import ACCESS_CONTROL_CHECKS as ACCESS_CONTROL_DETECTORS
from ..model import Severity, Confidence, VerificationStatus, Finding
from ..model import Epistemic, EvidenceItem

#: Slither's own impact for each access-control detector slug (slither
#: 0.11.6, verified via ``slither --list-detectors``). Used when the JSON
#: report is absent (text fallback) so a ``missing-zero-check`` is not
#: inflated to HIGH. The JSON path always prefers the reported impact.
_DETECTOR_SEVERITY = {
    "suicidal": Severity.HIGH,
    "controlled-delegatecall": Severity.HIGH,
    "tx-origin": Severity.MEDIUM,
    "missing-zero-check": Severity.LOW,
    "missing-msg-sender-check": Severity.LOW,
}


def analyze(context: AnalysisContext) -> AnalysisOutcome:
    """Run access control analysis on the given source files.

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
        outcome.notes.append("no source files provided to access control analyzer")
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
            if check not in ACCESS_CONTROL_DETECTORS:
                continue
            contract, function, lines = detector_location(det)
            if not contract or not function:
                outcome.notes.append(
                    "slither reported an access-control result that could not "
                    "be located in the source; it was not recorded as a finding"
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
            if check == "controlled-delegatecall":
                _downgrade_fixed_target(f, sol_files)
            elif check == "missing-zero-check":
                _downgrade_admin_zero_check(f, sol_files)
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

    Only blocks belonging to an access-control detector (see
    ``ACCESS_CONTROL_DETECTORS``) are converted; other detectors' headers
    (reentrancy, low-level-calls, ...) must not be mislabeled as access
    control issues. Evidence is the block header plus its bullet lines
    (``Epistemic.FACT`` tool output).
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

        if current_contract is None:
            if current_detector in ACCESS_CONTROL_DETECTORS and not stripped.startswith("- "):
                header_match = re.search(r"(\w+)\.(\w+)\([^)]*\)", line)
                range_match = re.search(r"#(\d+)(?:-(\d+))?", line)
                if header_match and range_match:
                    current_contract = header_match.group(1)
                    current_function = header_match.group(2)
                    block_detector = current_detector
                    if range_match.group(2):
                        current_lines = f"{range_match.group(1)}-{range_match.group(2)}"
                    else:
                        current_lines = range_match.group(1)
                    current_evidence = [stripped[:160]]
            continue

        range_match = re.search(r"#(\d+)(?:-(\d+))?", line)
        if range_match:
            if range_match.group(2):
                current_lines = f"{range_match.group(1)}-{range_match.group(2)}"
            elif current_lines == "unknown":
                current_lines = range_match.group(1)

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


def _make_finding(
    contract: str,
    function: str,
    lines: str,
    evidence: list[str],
    detector: str | None = None,
    impact: str = "",
    affected_file: str | None = None,
) -> Finding:
    """Create a Finding from parsed Slither access control data."""
    from .slither_runner import IMPACT_TO_SEVERITY, redact

    remediation_lines = [
        "Add proper access control checks:",
        "use onlyOwner or require with appropriate conditions,",
        "or OpenZeppelin access control contracts such as AccessControl",
        "or Ownable.",
    ]
    remediation = "\n".join(remediation_lines)
    raw = [redact(str(x).strip()) for x in evidence if str(x).strip()] or [
        f"slither reported {contract}.{function} (lines {lines})"
    ]
    # JSON path: trust the impact Slither reported. Text fallback (no
    # impact): fall back to the verified slug map, then HIGH for any
    # unknown access-family detector rather than inventing a low rating.
    severity = (
        IMPACT_TO_SEVERITY.get(impact)
        or _DETECTOR_SEVERITY.get(detector or "")
        or Severity.HIGH
    )

    return Finding(
        title=f"Access control issue in {contract}.{function}",
        description=(
            "Potential access control vulnerability: function or modifier "
            "missing proper owner/require checks. External functions should "
            "be protected against unauthorized access."
            + (f" Slither detector: {detector}." if detector else "")
        ),
        category="security",
        severity=severity,
        confidence=Confidence.MEDIUM,
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
        false_positive_risk="Requires manual review of the access control pattern",
        assumptions=["EVM environment", "slither detector output as produced"],
        contradicting_evidence=raw,
        benign_explanation=(
            "If the function is intended to be callable by anyone, "
            "the missing access control may be by design"
        ),
        remediation=remediation,
        references=[
            "https://github.com/crytic/slither/wiki/Detector-Documentation#access-control"
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

def _downgrade_fixed_target(finding: Finding, sol_files: list[Path]) -> None:
    """controlled-delegatecall where the target is admin-fixed -> INFORMATIONAL.

    Slither flags user-controlled *data*; when the target address is an
    implementation only settable by constructor/msg.sender-guarded code
    (Compound CErc20Delegator.delegateTo / delegateAndReturn), an outsider
    cannot pick the code that runs. Recorded with the reason; not deleted.
    """
    from .sol_parse import all_modifiers, contracts_in, delegatecall_target_admin_fixed
    universe = []
    for p in sol_files:
        try:
            universe.extend(contracts_in(Path(p).read_text(errors="replace")))
        except (OSError, ValueError, IndexError):
            continue
    mods = all_modifiers(universe)
    if True:
        for c in universe:
            if c.name != finding.affected_contract:
                continue
            for fn in c.functions:
                if fn.name == finding.affected_function:
                    reason = delegatecall_target_admin_fixed(c, fn, mods, universe)
                    if reason:
                        finding.severity = Severity.INFORMATIONAL
                        finding.title = f"Delegatecall to admin-fixed target in {c.name}.{fn.name} (false positive: {reason.split(' (')[0]})"
                        finding.benign_explanation = reason
                        finding.false_positive_risk = "high: " + reason
                    return


def _downgrade_admin_zero_check(finding: Finding, sol_files: list[Path]) -> None:
    """missing-zero-check on a msg.sender-guarded function: admin input hygiene, no outsider path."""
    from .sol_parse import admin_guarded, contracts_in
    universe = []
    for p in sol_files:
        try:
            universe.extend(contracts_in(Path(p).read_text(errors="replace")))
        except (OSError, ValueError, IndexError):
            continue
    g = admin_guarded(universe, finding.affected_contract, finding.affected_function or "")
    if g:
        reason = f"missing zero-address check on admin-only function ({g}); input hygiene, no outsider path"
        finding.severity = Severity.INFORMATIONAL
        finding.title = f"Missing zero-check (admin-only) in {finding.affected_contract}.{finding.affected_function}"
        finding.benign_explanation = reason
        finding.false_positive_risk = "high: " + reason
