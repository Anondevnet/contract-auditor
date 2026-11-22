"""Generic Slither detector pass.

Surfaces High/Medium/Low-impact Slither detectors that the reentrancy and
access-control analyzers do not already cover, so a Slither run is not
silently narrowed to two detector families. Informational/optimization
results are excluded (and counted in the tool status) to keep findings
actionable rather than flooded.

Titles use Slither's own detector ``check`` slug — never a guessed
vulnerability class. Descriptions are the detector's verbatim output
(``Epistemic.FACT`` evidence from tool output).
"""
from __future__ import annotations

from pathlib import Path
from typing import List

from .base import AnalysisContext, AnalysisOutcome
from .slither_runner import (
    ACCESS_CONTROL_CHECKS,
    IMPACT_TO_SEVERITY,
    collect_sol_files,
    detector_filename,
    detector_location,
    evidence_lines,
    get_slither_run,
    relative_source_name,
)
from ..model import Confidence, Epistemic, EvidenceItem, Finding, Severity, VerificationStatus

_GENERIC_IMPACTS = ("High", "Medium", "Low")


def analyze(context: AnalysisContext) -> AnalysisOutcome:
    """Run the generic detector pass over the shared Slither run."""
    outcome = AnalysisOutcome()
    outcome.findings = []
    outcome.evidence = []
    outcome.notes = []

    source_files: List[Path] = context.source_files or []
    if not source_files:
        outcome.notes.append("no source files provided to generic detector analyzer")
        return outcome

    _opts = getattr(context, "options", None)
    _scope = _opts.get("scope", "standard") if isinstance(_opts, dict) else "standard"
    sol_files = collect_sol_files(source_files, scope=_scope)
    if not sol_files:
        outcome.notes.append("no .sol files found")
        return outcome

    run_result = get_slither_run(context)

    if run_result.detectors is None:
        # Text-only runs cannot identify arbitrary detector families without
        # inventing severity; say so instead of guessing.
        if run_result.ok:
            outcome.notes.append(
                "no Slither JSON report was produced; detector results outside "
                "the reentrancy/access-control families were not parsed"
            )
        return outcome

    for det in run_result.detectors:
        check = str(det.get("check") or "unknown")
        impact = str(det.get("impact") or "")
        if check.startswith("reentrancy") or check in ACCESS_CONTROL_CHECKS:
            continue
        if impact not in _GENERIC_IMPACTS:
            continue
        finding = _finding_from_detector(
            det,
            check,
            impact,
            affected_file=relative_source_name(detector_filename(det), sol_files),
        )
        if finding is not None:
            outcome.findings.append(finding)
    return outcome


def _finding_from_detector(
    det: dict, check: str, impact: str, affected_file: str | None = None
) -> Finding | None:
    contract, function, lines = detector_location(det)
    if not contract or not function:
        return None
    raw = evidence_lines(det) or [str(det.get("description") or check).strip()[:160]]
    severity = IMPACT_TO_SEVERITY.get(impact, Severity.INFORMATIONAL)
    confidence_text = str(det.get("confidence") or "")
    confidence = {
        "High": Confidence.HIGH,
        "Medium": Confidence.MEDIUM,
        "Low": Confidence.LOW,
    }.get(confidence_text, Confidence.MEDIUM)

    return Finding(
        title=f"{check} in {contract}.{function}",
        description=str(det.get("description") or "").strip()
        or f"Slither detector {check} reported a result in {contract}.{function}.",
        category="security",
        severity=severity,
        confidence=confidence,
        verification_status=VerificationStatus.UNVERIFIED,
        affected_contract=contract,
        affected_function=function,
        affected_lines=sorted(int(x) for x in lines if int(x) > 0),
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
        false_positive_risk=(
            "Static-analysis detector result; requires manual review "
            "(impact reported by Slither, not independently verified)"
        ),
        assumptions=["EVM environment", "slither detector output as produced"],
        contradicting_evidence=raw,
        benign_explanation=(
            "The detector flags a pattern that may be intentional; review the "
            "call site and project conventions before treating it as a bug"
        ),
        remediation="",
        references=[
            "https://github.com/crytic/slither/wiki/Detector-Documentation"
        ],
    )
