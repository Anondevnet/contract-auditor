"""Pool accounting / constant-product invariant analysis (Phase 15, C6).

Hypothesis: a constant-product style pool that updates reserves from
``token.balanceOf(address(this))`` inside ``mint``/``swap``/``sync`` without
a k-invariant (or balance-vs-expected) check is exposed to donation-based
share-price manipulation and fee-on-transfer desynchronization. This is a
source-level pattern scan — Slither has no dedicated pool-invariant
detector — and every finding is a hypothesis that requires manual review.

Explicit false-positive limitations (always recorded on the finding):

* Uniswap V2/V3-style routers already verify amounts out and the pair's
  ``k`` check lives in a base contract that may not be in the collected
  files; a single-file view can look unchecked while the system is safe.
* ``balanceOf``-based accounting is intentional for fee-on-transfer tokens
  when paired with explicit expected-amount parameters elsewhere.
* A protocol may intentionally allow donations (skim/sync pattern) as the
  documented accounting model; that is not automatically a vulnerability.
* The k-invariant may be enforced in assembly or a library outside the
  selected files.

No finding is ever upgraded beyond ``UNVERIFIED``/``HYPOTHESIS``.
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

_NAME = "pool_accounting"
_CATEGORY = "defi-pool"

# Functions where reserve-from-balance is the classic donation surface.
_ENTRY_RE = re.compile(
    r"\bfunction\s+(mint|swap|sync|skim|burn)\s*\(", re.IGNORECASE
)

_BALANCE_RE = re.compile(
    r"\bbalanceOf\s*\(\s*address\s*\(\s*this\s*\)\s*\)"
    r"|\bbalanceOf\s*\(\s*address\s*\(\s*this\s*\)\s*\)",
    re.IGNORECASE,
)

# Signals that a k / product / expected-amount check exists. Deliberately
# excludes bare "credit"/"mint" helper names — those are what the finding
# is about, not evidence of a guard.
_K_HINTS = (
    "require",
    "revert",
    "klast",
    "invariant",
    "product",
    "getreserves",
    "reserve0",
    "reserve1",
    "amountout",
    "amount0out",
    "amount1out",
)


def analyze(context: AnalysisContext) -> AnalysisOutcome:
    """Scan collected sources for balanceOf-based pool accounting without k checks."""
    outcome = AnalysisOutcome()
    outcome.findings = []
    outcome.evidence = []
    outcome.notes = []

    source_files: List[Path] = context.source_files or []
    if not source_files:
        outcome.notes.append("no source files provided to pool accounting analyzer")
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
        findings = _scan_text(text, relative_source_name(sf, sol_files))
        outcome.findings.extend(findings)
    return outcome


def _scan_text(text: str, affected_file: Optional[str]) -> List[Finding]:
    # Match against comment/string-stripped code (offsets preserved) so a
    # comment mentioning require/k cannot suppress a finding and
    # commented-out balanceOf math cannot raise one. Line numbers still
    # come from the original text via the same offsets.
    code = strip_comments_and_strings(text)
    findings: List[Finding] = []
    for match in _ENTRY_RE.finditer(code):
        func_name = match.group(1)
        body, line_no = _function_body(code, match.start())
        if body is None:
            continue
        if not _BALANCE_RE.search(body):
            continue
        if _has_k_hint(body):
            continue
        findings.append(
            _make_finding(func_name, line_no, body, affected_file)
        )
    return findings


def _function_body(text: str, start: int) -> Tuple[Optional[str], int]:
    line_no = text.count("\n", 0, start) + 1
    brace = text.find("{", start)
    if brace < 0:
        return None, line_no
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
    return text[brace : end + 1], line_no


def _has_k_hint(body: str) -> bool:
    lowered = body.lower()
    return any(h in lowered for h in _K_HINTS)


def _make_finding(
    func_name: str,
    line_no: int,
    body: str,
    affected_file: Optional[str],
) -> Finding:
    excerpt = body.strip().splitlines()[0][:200] if body.strip() else func_name
    return Finding(
        title=f"pool-accounting risk in {func_name}: balanceOf(this) without k check",
        description=(
            f"{func_name} reads token.balanceOf(address(this)) to derive "
            "pool amounts but the function body has no obvious k-invariant "
            "or expected-amount require. Direct transfers (donations) or "
            "fee-on-transfer tokens can desynchronize reserves from the "
            "intended accounting."
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
            "pool function derives amounts from balanceOf(address(this))",
            "no textual k-invariant or expected-amount guard in the function",
        ],
        likelihood="POSSIBLE",
        false_positive_risk=(
            "Source-pattern hypothesis only. Routers and pair bases often "
            "enforce the k check outside the selected files; donation-based "
            "skim/sync can be the documented model; fee-on-transfer handling "
            "may live in a library. Manual review required; not a confirmed "
            "vulnerability."
        ),
        assumptions=[
            "balanceOf(this) is used as the authoritative amount",
            "the collected sources contain the full pool accounting logic",
        ],
        contradicting_evidence=[
            "k-invariant may be enforced in an inherited pair base or assembly"
        ],
        benign_explanation=(
            "Uniswap-style pairs intentionally track reserves separately and "
            "enforce k in a base contract; a local balanceOf read alone is "
            "not proof of an accounting bug."
        ),
        remediation=(
            "Verify amounts against explicit parameters and/or enforce the "
            "constant-product invariant (new_k >= old_k) before crediting "
            "LPs; use skim/sync deliberately with documented invariants."
        ),
        references=[
            "https://docs.uniswap.org/contracts/v2/reference/smart-contracts/pair",
            "https://blog.openzeppelin.com/erc4626-inflation-attack",
        ],
    )
