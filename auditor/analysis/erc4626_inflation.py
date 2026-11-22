"""ERC-4626 first-depositor / share-price inflation analysis (Phase 15 C5, hardened Phase 16).

Hypothesis: an ERC-4626-style vault whose ``convertToShares`` /
``previewDeposit`` math is a plain ``assets * totalSupply / totalAssets``
(with ``totalSupply == 0`` minting 1:1) and which has no virtual share /
``_decimalsOffset`` offset, minimum first deposit, or dead-shares burn is
exposed to the classic first-depositor share-price inflation attack
(donation inflates ``totalAssets`` so the next depositor's shares round
down to zero).

This is a source-level pattern scan — Slither has no ERC-4626 inflation
detector — and every finding is a hypothesis that requires manual review.

Explicit false-positive limitations (always recorded on the finding):

* OpenZeppelin's ERC4626 base already uses ``_decimalsOffset`` virtual
  shares; a vault that inherits it will not match the naive ratio pattern
  in this file and will not be flagged, but a vault that overrides
  ``convertToShares`` unsafely may still be vulnerable while the override
  lives in another file.
* Some vaults intentionally start with a large first deposit (bootstrapped
  liquidity) or burn dead shares in a constructor not visible here.
* A ``totalSupply == 0`` branch that mints ``assets`` shares is correct when
  combined with a virtual offset; the offset may be in an inherited
  constant not spelled ``VIRTUAL``/``decimalsOffset`` in this file.

No finding is ever upgraded beyond ``UNVERIFIED``/``HYPOTHESIS``.

Phase 16 hardening: comments and string literals are blanked (offsets
preserved) before matching, so a comment that mentions ``decimalsOffset``
no longer suppresses a finding and commented-out math no longer raises
one; mitigation hints, the ratio and the deposit/mint entrypoint are
evaluated per ``contract``/``abstract contract`` body (one finding per
contract, attributed to the enclosing contract + function); and the
OpenZeppelin ``mulDiv(totalSupply(), totalAssets())`` spelling is matched.
The description carries ``Source detector: erc4626-inflation.`` so the
benchmark matcher (PROTOCOL.md §10) can extract a channel slug.
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

_NAME = "erc4626_inflation"
_CATEGORY = "defi-vault"

_RATIO_RE = re.compile(
    r"totalSupply\s*\(\s*\)\s*/\s*totalAssets\s*\(\s*\)"
    r"|totalSupply\s*/\s*totalAssets\s*\(\s*\)"
    r"|assets\s*\*\s*totalSupply\s*\(\s*\)\s*/\s*totalAssets\s*\(\s*\)"
    r"|assets\s*\*\s*supply\s*/\s*totalAssets\s*\(\s*\)"
    r"|assets\s*\*\s*supply\s*/\s*totalAssets\b"
    r"|totalAssets\s*\(\s*\)\s*/\s*totalSupply\s*\(\s*\)"
    r"|mulDiv\s*\(\s*(?:assets\s*,\s*)?(?:totalSupply\s*\(\s*\)|supply)\s*,\s*totalAssets\s*\(\s*\)",
    re.IGNORECASE,
)

_ZERO_SUPPLY_MINT_RE = re.compile(
    r"totalSupply\s*\(\s*\)\s*==\s*0"
    r"|supply\s*==\s*0",
    re.IGNORECASE,
)

# Virtual-offset / dead-share markers that indicate a mitigated vault.
_VIRTUAL_HINTS = (
    "decimalsoffset",
    "virtualshares",
    "virtual_assets",
    "virtualassets",
    "virtual_share",
    "deadshares",
    "dead_shares",
    "minimumdeposit",
    "min_deposit",
    "minfirstdeposit",
    "first_deposit",
)

_ERC4626_HINT_RE = re.compile(
    r"\b(convertToShares|previewDeposit|deposit|mint|totalAssets)\b"
)


def analyze(context: AnalysisContext) -> AnalysisOutcome:
    """Scan collected sources for naive ERC-4626 share math."""
    outcome = AnalysisOutcome()
    outcome.findings = []
    outcome.evidence = []
    outcome.notes = []

    source_files: List[Path] = context.source_files or []
    if not source_files:
        outcome.notes.append("no source files provided to ERC-4626 analyzer")
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
        outcome.findings.extend(
            _scan_text(text, relative_source_name(sf, sol_files))
        )
    return outcome


SLUG = "erc4626-inflation"

_CONTRACT_RE = re.compile(r"\b(?:abstract\s+)?contract\s+([A-Za-z_]\w*)[^{;]*\{")
_FUNCTION_RE = re.compile(r"\bfunction\s+([A-Za-z_]\w*)\s*\([^{;]*\{")
_ENTRY_RE = re.compile(r"\bfunction\s+(deposit|mint)\s*\(")


def _block_end(text: str, open_idx: int) -> int:
    """Index just past the brace matching ``text[open_idx] == '{'``."""
    depth = 0
    for k in range(open_idx, len(text)):
        if text[k] == "{":
            depth += 1
        elif text[k] == "}":
            depth -= 1
            if depth == 0:
                return k + 1
    return len(text)


def _contract_blocks(code: str) -> List[Tuple[Optional[str], int, int]]:
    blocks: List[Tuple[Optional[str], int, int]] = []
    for m in _CONTRACT_RE.finditer(code):
        start = m.end() - 1
        blocks.append((m.group(1), start, _block_end(code, start)))
    # Interfaces/libraries/free code are not vault bodies; when no contract
    # is declared at all, fall back to the whole file (unattributed).
    return blocks or [(None, 0, len(code))]


def _enclosing_function(code: str, start: int, end: int, pos: int) -> Optional[str]:
    for m in _FUNCTION_RE.finditer(code, start, end):
        open_idx = m.end() - 1
        if open_idx <= pos < _block_end(code, open_idx):
            return m.group(1)
    return None


def _scan_text(text: str, affected_file: Optional[str]) -> List[Finding]:
    code = strip_comments_and_strings(text)
    if not _ERC4626_HINT_RE.search(code):
        return []
    findings: List[Finding] = []
    for contract, start, end in _contract_blocks(code):
        body = code[start:end]
        lowered = body.lower()
        if any(h in lowered for h in _VIRTUAL_HINTS):
            continue
        ratio = _RATIO_RE.search(code, start, end)
        if ratio is None:
            continue
        # Require either an explicit zero-supply 1:1 branch or a deposit/mint
        # entrypoint in the same contract so we do not flag unrelated math.
        if _ZERO_SUPPLY_MINT_RE.search(body) is None and _ENTRY_RE.search(body) is None:
            continue
        line_no = text.count("\n", 0, ratio.start()) + 1
        findings.append(_make_finding(
            line_no,
            text[ratio.start():ratio.end()],
            affected_file,
            contract=contract,
            function=_enclosing_function(code, start, end, ratio.start()),
        ))
    return findings


def _make_finding(
    line_no: int,
    ratio_snippet: str,
    affected_file: Optional[str],
    *,
    contract: Optional[str] = None,
    function: Optional[str] = None,
) -> Finding:
    return Finding(
        title="ERC-4626 share-price inflation risk (naive totalSupply/totalAssets ratio)",
        description=(
            "Vault share math uses a plain totalSupply/totalAssets ratio "
            "with no virtual-share offset, minimum first deposit, or "
            "dead-shares burn visible in this source. The first depositor "
            "can mint 1:1 shares, donate assets to inflate the share price, "
            "and cause later depositors' shares to round down to zero. "
            f"Source detector: {SLUG}."
        ),
        category="security",
        severity=Severity.MEDIUM,
        confidence=Confidence.LOW,
        verification_status=VerificationStatus.UNVERIFIED,
        affected_contract=contract,
        affected_function=function,
        affected_lines=[line_no] if line_no > 0 else [],
        affected_file=affected_file,
        source="source-analysis",
        tool=_NAME,
        evidence=[
            EvidenceItem(
                epistemic=Epistemic.FACT,
                source="source-analysis",
                artifact_type="source_excerpt",
                excerpt=ratio_snippet[:200],
                tool=_NAME,
            )
        ],
        prerequisites=[
            "vault mints shares proportional to totalSupply/totalAssets",
            "no virtual offset or minimum first deposit in the collected sources",
            "attacker can transfer assets directly into the vault",
        ],
        likelihood="POSSIBLE",
        false_positive_risk=(
            "Source-pattern hypothesis only. An inherited ERC4626 base may "
            "already apply a virtual offset (_decimalsOffset); dead shares "
            "may be burned in a constructor or another file; some vaults "
            "intentionally bootstrap liquidity. Manual review required; not "
            "a confirmed vuln."
        ),
        assumptions=[
            "totalAssets() is balance-based (donation can raise it)",
            "the collected sources contain the full share-conversion logic",
        ],
        contradicting_evidence=[
            "virtual shares/assets offset may exist in an inherited base"
        ],
        benign_explanation=(
            "OpenZeppelin-style ERC4626 implementations already mitigate "
            "this with virtual shares; the naive ratio alone is not proof "
            "the vault is exploitable."
        ),
        remediation=(
            "Apply a virtual-share offset (e.g. OZ _decimalsOffset), require "
            "a minimum first deposit, or burn dead shares on first mint."
        ),
        references=[
            "https://medium.com/coinmonks/erc4626-vault-inflation-attack",
            "https://docs.openzeppelin.com/contracts/4.x/api/token/erc20#ERC4626",
        ],
    )
