"""Oracle price staleness analysis (Phase 15 DeFi-readiness, change C4).

Hypothesis: a contract that reads a Chainlink-style ``latestRoundData()``
(or the deprecated ``latestAnswer()``) and then uses the price without any
freshness check on ``updatedAt``/``roundId``/``timestamp`` is exposed to
acting on a stale feed. This is a source-level pattern scan — Slither has
no dedicated stale-oracle detector — and every finding is a hypothesis that
requires manual review.

Explicit false-positive limitations (always recorded on the finding):

* The freshness check may live in a different contract, modifier, or
  inherited base that this single-file / selected-file walk cannot see.
* A protocol may intentionally consume the latest round for markets where
  latency is not security-critical (e.g. pure TWAP off-chain consumers).
* ``updatedAt`` may be validated against a median or sibling feed rather
  than ``block.timestamp`` directly; a textual miss of that pattern is
  still reported.
* Aggregator wrappers that re-check staleness inside `` getPrice()`` make
  the outer call site look unchecked even when the system is safe.

No finding is ever upgraded beyond ``UNVERIFIED``/``HYPOTHESIS``: the
analyzer never claims a confirmed stale-oracle vulnerability.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import List, Optional, Tuple

from .base import AnalysisContext, AnalysisOutcome
from .slither_runner import (
    collect_sol_files,
    relative_source_name,
    strip_comments_and_strings,
)
from ..model import Confidence, Epistemic, EvidenceItem, Finding, Severity, VerificationStatus

_NAME = "oracle_staleness"
_CATEGORY = "defi-oracle"

# Chainlink V3 round fields that, when compared, indicate a freshness check.
_FRESHNESS_HINTS = (
    "updatedat",
    "startedat",
    "roundid",
    "block.timestamp",
    "maxage",
    "stale",
    "heartbeat",
    "freshness",
    "answeredInRound",
)

_LATEST_ROUND_RE = re.compile(r"\blatestRoundData\s*\(")
_LATEST_ANSWER_RE = re.compile(r"\blatestAnswer\s*\(")

# Rough function boundaries: "function NAME" through a line with a lone "}".
_FUNC_START_RE = re.compile(
    r"^\s*function\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(", re.MULTILINE
)


def analyze(context: AnalysisContext) -> AnalysisOutcome:
    """Scan collected sources for unchecked latestRoundData/latestAnswer."""
    outcome = AnalysisOutcome()
    outcome.findings = []
    outcome.evidence = []
    outcome.notes = []

    source_files: List[Path] = context.source_files or []
    if not source_files:
        outcome.notes.append("no source files provided to oracle staleness analyzer")
        return outcome

    opts = getattr(context, "options", None)
    scope = opts.get("scope", "standard") if isinstance(opts, dict) else "standard"
    sol_files = collect_sol_files(source_files, scope=scope)
    if not sol_files:
        outcome.notes.append("no .sol files found")
        return outcome

    for sf in sol_files:
        try:
            text = sf.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            outcome.notes.append(f"could not read {sf.name}: {exc}")
            continue
        findings, notes = _scan_text(text, relative_source_name(sf, sol_files))
        outcome.findings.extend(findings)
        outcome.notes.extend(notes)
    return outcome


def _scan_text(
    text: str, affected_file: Optional[str]
) -> Tuple[List[Finding], List[str]]:
    # Match against comment/string-stripped code (offsets preserved) so a
    # comment mentioning updatedAt/stale cannot suppress a finding and a
    # commented-out latestRoundData call cannot raise one. Excerpts and
    # line numbers still come from the original text via the same offsets.
    code = strip_comments_and_strings(text)
    findings: List[Finding] = []
    notes: List[str] = []
    for match in list(_LATEST_ROUND_RE.finditer(code)) + list(
        _LATEST_ANSWER_RE.finditer(code)
    ):
        kind = (
            "latestRoundData"
            if match.group(0).startswith("latestRound")
            else "latestAnswer"
        )
        func_name, func_body, line_no = _enclosing_function(code, match.start())
        if func_body is None:
            notes.append(
                f"{affected_file or 'source'}: {kind} at line {line_no} could "
                "not be attributed to a function; not reported as a finding"
            )
            continue
        if _has_freshness_check(func_body):
            continue
        findings.append(
            _make_finding(kind, func_name, line_no, func_body, affected_file)
        )
    return findings, notes


def _enclosing_function(
    text: str, pos: int
) -> Tuple[str, Optional[str], int]:
    """Return (function_name, body_text, line_number) for the call at ``pos``."""
    line_no = text.count("\n", 0, pos) + 1
    start = None
    name = "<unknown>"
    for m in _FUNC_START_RE.finditer(text):
        if m.start() <= pos:
            start = m.start()
            name = m.group(1)
        else:
            break
    if start is None:
        return name, None, line_no
    # Body: from the first "{" after the signature to the matching close at
    # depth 0. A missing close means the snippet is the rest of the file.
    brace = text.find("{", start)
    if brace < 0 or brace > pos + 20000:
        return name, None, line_no
    depth = 0
    end = brace
    for i in range(brace, min(len(text), brace + 80000)):
        ch = text[i]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                end = i
                break
    else:
        end = min(len(text), brace + 80000)
    return name, text[brace : end + 1], line_no


def _has_freshness_check(body: str) -> bool:
    lowered = body.lower()
    return any(hint.lower() in lowered for hint in _FRESHNESS_HINTS)


def _make_finding(
    kind: str,
    func_name: str,
    line_no: int,
    body: str,
    affected_file: Optional[str],
) -> Finding:
    excerpt = body.strip().splitlines()[0][:200] if body.strip() else kind
    return Finding(
        title=f"stale-oracle-risk in {func_name}: unchecked {kind}",
        description=(
            f"{func_name} calls {kind}() but the enclosing function body has "
            "no obvious freshness check on updatedAt/roundId/timestamp. A "
            "stale price feed can be used for liquidations, minting, or "
            "arbitrage-sensitive accounting."
        ),
        category="security",
        severity=Severity.MEDIUM,
        confidence=Confidence.LOW,
        verification_status=VerificationStatus.UNVERIFIED,
        affected_contract=None,
        affected_function=func_name,
        affected_lines=[line_no] if line_no > 0 else [],
        affected_file=affected_file,
        source="source-analysis",
        tool=_NAME,
        evidence=[
            EvidenceItem(
                epistemic=Epistemic.FACT,
                source="source-analysis",
                artifact_type="source_excerpt",
                excerpt=excerpt,
                tool=_NAME,
            )
        ],
        prerequisites=[
            "an oracle aggregator (Chainlink-style) is consulted in-function",
            "no textual freshness guard is present in the same function body",
        ],
        likelihood="POSSIBLE",
        false_positive_risk=(
            "Source-pattern hypothesis only. A freshness check may live in a "
            "modifier, inherited base, or wrapper contract outside the "
            "collected files; some protocols intentionally consume the "
            "latest round. Manual review required; not a confirmed vuln."
        ),
        assumptions=[
            "the enclosing function body is complete in the collected sources",
            "latestRoundData/latestAnswer map to a Chainlink-style aggregator",
        ],
        contradicting_evidence=[
            "freshness may be enforced elsewhere in the system architecture"
        ],
        benign_explanation=(
            "Staleness may be checked in a shared helper, a price oracle "
            "wrapper, or off-chain monitoring; the pattern alone is not "
            "proof of exploitability."
        ),
        remediation=(
            "Require updatedAt >= block.timestamp - maxAge (and "
            "answeredInRound >= roundId where applicable) before using the "
            "price, or route reads through a staleness-checked helper."
        ),
        references=[
            "https://docs.chain.link/data-feeds/using-data-feeds",
            "https://blog.openzeppelin.com/price-feed-staleness",
        ],
    )
