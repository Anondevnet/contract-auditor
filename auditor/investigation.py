"""Two-sided (attacker / white-hat) investigation view for one finding.

Pure and offline: this module only reads the stored finding record, the scan
record, analyst metadata, and the local source file. No network calls, no
model calls, no fabrication.

Hard rules encoded here:

* Unknown values render as ``Unknown — not verified`` or ``Not assessed``.
* Effort, time, difficulty, and exposure figures are labeled ``Approximate``
  or ``estimate`` — never presented as measured facts.
* Token amounts, USD values, balances, TVL, prices, and losses are never
  invented. They stay unknown unless a configured, attributed source exists.
* Attack content is a conceptual, defensive discussion of preconditions and
  trust assumptions — not an operational exploitation guide.
* Anything AI-authored arrives separately (``ai_analysis``) and is labeled
  ``generated_ai_analysis`` so it is never confused with scanner evidence.
* Chain, protocol, and deployment facts come only from recorded scan
  metadata — a missing chain stays ``Unknown — not verified`` (never a
  default chain), and every scan is classified (test fixture / local source /
  deployed-unverified) from observable local signals only.
* Example patches are grounded in the stored source excerpt, shown as a
  suggestion, and never applied automatically.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

UNKNOWN = "Unknown — not verified"
NOT_ASSESSED = "Not assessed"
APPROX = "Approximate"

_SOURCE_CONTEXT_LINES = 3
_MAX_SNIPPET_LINES = 40


def _as_list(value: Any) -> List[Any]:
    """Normalize a finding field that may be a scalar or a sequence.

    ``false_positive_risk`` is a ``str`` in the model but was iterated as
    if it were a list, exploding one sentence into single characters in
    every investigation/report payload. Strings must never be iterated
    char-by-char here.
    """
    if value is None:
        return []
    if isinstance(value, str):
        return [value] if value else []
    if isinstance(value, (list, tuple, set)):
        return list(value)
    return [value]


# ---------------------------------------------------------------------------
# label helpers
# ---------------------------------------------------------------------------

def _labeled(value: Any, origin: str) -> Dict[str, Any]:
    """Wrap a value with its provenance label."""
    return {"value": value, "origin": origin}


def _unknown(reason: str) -> Dict[str, Any]:
    return {
        "value": UNKNOWN,
        "origin": "unknown",
        "basis": reason,
        "confidence": "unknown",
    }


def _not_assessed(reason: str) -> Dict[str, Any]:
    return {
        "value": NOT_ASSESSED,
        "origin": "not_assessed",
        "basis": reason,
        "confidence": "not assessed",
    }


# ---------------------------------------------------------------------------
# source grounding
# ---------------------------------------------------------------------------

def _validate_root(root: Any, content_hash: Optional[str] = None) -> Optional[Path]:
    """Resolve an existing file/directory root, or return None.

    ``etherscan://[net/]addr`` refs resolve to the cached verified source via
    ``auditor.source_resolver`` (same rules as AI audit / retest)."""
    if not root:
        return None
    if str(root).startswith("etherscan://"):
        from auditor.source_resolver import SourceResolutionError, resolve_source
        try:
            return Path(resolve_source(str(root), content_hash).path)
        except SourceResolutionError:
            return None
    try:
        path = Path(str(root)).expanduser()
        resolved = path.resolve(strict=True)
    except (OSError, RuntimeError):
        return None
    if not (resolved.is_file() or resolved.is_dir()):
        return None
    return resolved


def _locate_file(root: Optional[Path], contract: Optional[str]) -> Optional[Path]:
    """Find the Solidity file that declares ``contract`` under ``root``."""
    if root is None:
        return None
    if root.is_file():
        return root
    contract = (contract or "").strip()
    pattern = re.compile(
        r"\b(?:contract|library|interface)\s+" + re.escape(contract) + r"\b"
    ) if contract else None
    try:
        candidates = sorted(root.rglob("*.sol"))
    except OSError:
        return None
    if pattern is None:
        return candidates[0] if candidates else None
    for candidate in candidates:
        try:
            text = candidate.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if pattern.search(text):
            return candidate
    return None


def _snippet(path: Optional[Path], lines: List[int]) -> Dict[str, Any]:
    """Read real source lines around the finding's affected lines."""
    out: Dict[str, Any] = {
        "file": str(path) if path else None,
        "line_range": None,
        "lines": [],
        "origin": "not available",
        "read_error": None,
    }
    if path is None:
        out["read_error"] = "source file not located"
        return out

    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        out["read_error"] = f"{type(exc).__name__}: {exc}"
        return out

    all_lines = text.splitlines()
    if lines:
        start = max(1, min(lines))
        end = max(start, max(lines))
    else:
        start, end = 1, min(len(all_lines), _MAX_SNIPPET_LINES)

    first = max(1, start - _SOURCE_CONTEXT_LINES)
    last = min(len(all_lines), end + _SOURCE_CONTEXT_LINES)
    if last < first:
        first, last = 1, min(len(all_lines), _MAX_SNIPPET_LINES)
    if last - first + 1 > _MAX_SNIPPET_LINES:
        last = first + _MAX_SNIPPET_LINES - 1

    out["file"] = str(path)
    out["line_range"] = [first, last]
    out["lines"] = [
        {"n": n, "text": all_lines[n - 1]} for n in range(first, last + 1)
    ]
    out["origin"] = "source file on disk (context lines included)"
    return out


def _reachability(root: Optional[Path], function: Optional[str], file_info: Dict[str, Any]) -> Dict[str, Any]:
    """Whether the affected function is reachable in the stored source."""
    function = (function or "").strip()
    if not function:
        return _not_assessed("no affected function recorded on the finding")
    if root is None:
        return _not_assessed("source root not available for this scan")

    try:
        paths = sorted(root.rglob("*.sol")) if root.is_dir() else [root]
    except OSError:
        return _not_assessed("source directory could not be read")

    pattern = re.compile(r"\bfunction\s+" + re.escape(function) + r"\s*\(")
    for path in paths:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        match = pattern.search(text)
        if not match:
            continue
        tail = text[match.end() : match.end() + 400]
        statement = tail.split("{", 1)[0]
        if re.search(r"\bprivate\b", statement):
            verdict = "Internal only — not externally callable (verified from source)"
        elif re.search(r"\b(external|public)\b", statement):
            verdict = "Reachable within source (verified from source)"
        else:
            verdict = "Declared in source; visibility not clearly parsed (verified location only)"
        line_no = text[: match.start()].count("\n") + 1
        return {
            "value": verdict,
            "origin": "verified",
            "basis": f"function {function} declared at {path.name}:{line_no}",
            "confidence": "verified from local source",
            "file": str(path),
            "line": line_no,
        }
    return _not_assessed(f"function {function} not located in the stored source")


# ---------------------------------------------------------------------------
# playbooks
# ---------------------------------------------------------------------------

_REENTRANCY = {
    "kind": "reentrancy",
    "plain_english": (
        "The contract makes an external call and then (or while) relying on its "
        "own bookkeeping. The address being called can run code that calls back "
        "into this contract before the original call's bookkeeping has finished. "
        "If state is only updated after the external call, the callback observes "
        "and acts on stale numbers."
    ),
    "attack_path": [
        "A function performs an external call to an address whose code the contract does not control.",
        "State that later reads depend on is still unchanged when that address's code runs.",
        "The called address uses the callback window to re-enter the same or a related function and act on the stale state.",
        "The contract commits state derived from values that were already superseded.",
    ],
    "preconditions": [
        "An external call (or equivalent callback surface) exists before the relevant state update.",
        "The call target can execute arbitrary code (a contract with a receive/fallback path, or an untrusted address).",
        "Re-entering changes an observable outcome (balances, accounting, shares, permissions).",
    ],
    "caia": {
        "confidentiality": "Usually unaffected — reentrancy is primarily a state-ordering issue.",
        "integrity": "Primary risk: state may be written based on values that were already out of date.",
        "availability": "Usually unaffected unless accounting corruption cascades into blocked operations.",
        "authenticity": "Relevant only when re-entry confuses identity or authorization checks.",
    },
    "misconceptions": [
        "A reentrancy pattern is not automatically exploitable: if state is written before the external call, or the callback target is trusted, the risk may not materialize (see the benign explanation).",
        "Not every external call is a reentrancy surface: view-only calls and calls to trusted, non-calling contracts reduce the practical risk.",
    ],
    "glossary": [
        {"term": "External call", "definition": "A call from this contract to another address, which can run that address's code."},
        {"term": "State variable", "definition": "Stored values the contract reads and writes between calls."},
        {"term": "Checks-effects-interactions", "definition": "Pattern of validating, then updating state, then making external calls."},
    ],
    "fix_hours": "2–8 hours (approximate)",
}

_ACCESS_CONTROL = {
    "kind": "access_control",
    "plain_english": (
        "A function that changes sensitive state can be reached, or was reached, "
        "by an address that should not be able to reach it — a permission check "
        "is missing, applied to the wrong subject, or bypassable."
    ),
    "attack_path": [
        "A sensitive function lacks (or mis-applies) a caller check.",
        "An address outside the intended authority set reaches that function.",
        "Sensitive state — ownership, parameters, withdrawals, upgrades — changes under unauthorized control.",
    ],
    "preconditions": [
        "The affected function (or a path to it) is reachable by an arbitrary caller.",
        "The state it touches has security consequences (ownership, funds, configuration, upgrade authority).",
        "No equivalent check is enforced elsewhere (another contract, a shared modifier, an upstream gate).",
    ],
    "caia": {
        "confidentiality": "Depends on the function: privileged reads or sealed data could leak.",
        "integrity": "Primary risk: unauthorized changes to privileged state.",
        "availability": "Possible if privileged state can be corrupted or frozen.",
        "authenticity": "Central: authorization of the caller is what fails.",
    },
    "misconceptions": [
        "A missing or unusual modifier is not automatically a vulnerability: the function may be intentionally permissionless or guarded elsewhere (see the benign explanation).",
        "A pattern match does not prove an address can actually reach the function — verify the call graph and deployment wiring.",
    ],
    "glossary": [
        {"term": "Modifier", "definition": "Solidity syntax that wraps a function with extra checks, commonly access checks."},
        {"term": "Privileged role", "definition": "An address (owner, admin, guardian, pauser) allowed to perform sensitive actions."},
        {"term": "Call graph", "definition": "Which functions can reach which, directly or through internal calls."},
    ],
    "fix_hours": "1–4 hours (approximate)",
}

_GENERIC = {
    "kind": "generic",
    "plain_english": "",
    "attack_path": [
        "Identify the trust assumption the code relies on (caller, external data, ordering, accounting).",
        "Check whether that assumption holds for every reachable caller and state transition.",
        "Where it does not, the divergent path is the exposure this finding points at.",
    ],
    "preconditions": [],
    "caia": {
        "confidentiality": NOT_ASSESSED,
        "integrity": NOT_ASSESSED,
        "availability": NOT_ASSESSED,
        "authenticity": NOT_ASSESSED,
    },
    "misconceptions": [
        "A scanner flag is a lead, not proof of exploitability — confirm against the source before concluding anything.",
    ],
    "glossary": [],
    "fix_hours": "1–8 hours (approximate)",
}


def _playbook_for(finding: Dict[str, Any]) -> Dict[str, Any]:
    category = str(finding.get("category") or "").lower()
    title = str(finding.get("title") or "").lower()
    if "reentrancy" in category or "reentrancy" in title:
        return _REENTRANCY
    if "access" in category or "access control" in title or "privilege" in title:
        return _ACCESS_CONTROL
    return _GENERIC


# ---------------------------------------------------------------------------
# effort estimates
# ---------------------------------------------------------------------------

def _estimates(playbook: Dict[str, Any], finding: Dict[str, Any]) -> Dict[str, Any]:
    """Planning ranges split into validation vs remediation, all approximate.

    Validation is what it costs to decide whether this finding is real; that
    is deliberately kept apart from the cost of changing the code.
    """
    note = (
        "All figures are approximate planning ranges for an experienced "
        "reviewer — not commitments. Actual effort depends on codebase size, "
        "test coverage, and reviewer familiarity. Validation effort "
        "(proving/disproving the finding) is listed separately from "
        "remediation effort (changing the code)."
    )
    validation = [
        {"stage": "Root-cause confirmation (this finding)", "range": "0.5–2 hours (approximate)", "label": APPROX, "group": "validation"},
        {"stage": "Adversarial review of the fix", "range": "1–4 hours (approximate)", "label": APPROX, "group": "validation"},
        {"stage": "Re-audit of the affected subsystem", "range": "2–8 hours (approximate)", "label": APPROX, "group": "validation"},
    ]
    remediation = [
        {"stage": "Fix implementation", "range": playbook["fix_hours"], "label": APPROX, "group": "remediation"},
        {"stage": "Regression / unit test additions", "range": "1–4 hours (approximate)", "label": APPROX, "group": "remediation"},
    ]
    return {"validation": validation, "remediation": remediation, "note": note}


# ---------------------------------------------------------------------------
# protocol / chain / asset
# ---------------------------------------------------------------------------

PROTOCOL_CATEGORIES = {
    "exchange": "Centralized exchange",
    "dex": "Decentralized exchange",
    "swap": "Swap / routing",
    "bridge": "Bridge",
    "lending": "Lending / borrowing",
    "staking": "Staking / yield",
    "wallet": "Wallet / custody",
    "oracle": "Oracle / price feed",
    "nft": "NFT / marketplace",
    "governance": "Governance",
    "other": "Other",
    "unknown": "Not assessed",
}

#: Chain identifiers are a fixed, documented mapping — verified, not guessed.
_CHAIN_IDS = {"ethereum": 1, "sepolia": 11155111, "holesky": 17000, "polygon": 137}


def _protocol_block(metadata: Dict[str, str], scan: Dict[str, Any]) -> Dict[str, Any]:
    meta = {k: str(v).strip() for k, v in (metadata or {}).items() if v is not None}
    raw_chain = (meta.get("chain") or meta.get("chain_name") or "").strip().lower()
    category_key = (meta.get("protocol_category") or "unknown").strip().lower()
    chain_id = _CHAIN_IDS.get(raw_chain) if raw_chain else None

    if raw_chain:
        chain_node = _labeled(raw_chain.title(), "verified (scan metadata)")
    else:
        chain_node = _unknown("No chain was recorded in scan metadata for this scan.")
    if chain_id is not None:
        chain_id_node = _labeled(chain_id, "verified (fixed chain registry)")
    elif raw_chain:
        chain_id_node = _unknown(f"Chain {raw_chain!r} is not in the local chain-id registry.")
    else:
        chain_id_node = _unknown("No chain recorded, so no chain id can be resolved.")

    fields = {
        "project_name": _labeled(meta.get("project_name") or UNKNOWN, "verified" if meta.get("project_name") else "unknown"),
        "protocol_category": _labeled(
            PROTOCOL_CATEGORIES.get(category_key, meta.get("protocol_category") or "Not assessed"),
            "verified" if meta.get("protocol_category") else "not_assessed",
        ),
        "chain": chain_node,
        "chain_id": chain_id_node,
        "contract_address": _labeled(
            meta.get("contract_address") or _first_address(scan) or UNKNOWN,
            "verified" if (meta.get("contract_address") or _first_address(scan)) else "unknown",
        ),
        "token_symbol": _labeled(meta.get("token_symbol") or UNKNOWN, "verified" if meta.get("token_symbol") else "unknown"),
        "token_address": _labeled(meta.get("token_address") or UNKNOWN, "verified" if meta.get("token_address") else "unknown"),
        "token_decimals": _labeled(meta.get("token_decimals") or UNKNOWN, "verified" if meta.get("token_decimals") else "unknown"),
        "role_in_scope": _labeled(meta.get("contract_role") or NOT_ASSESSED, "verified" if meta.get("contract_role") else "not_assessed"),
        "notes": _labeled(meta.get("notes") or NOT_ASSESSED, "verified" if meta.get("notes") else "not_assessed"),
    }

    balance = _not_assessed(
        "No RPC endpoint or balance source is configured for this assessment, "
        "so no contract balance was read."
    )
    usd = _unknown(
        "No price source is configured; USD conversion would be fabricated."
    )
    return {
        "fields": fields,
        "asset": {
            "token_balance_at_risk": balance,
            "usd_equivalent": usd,
            "tvl": _not_assessed("TVL was not read for this assessment."),
            "liquidity_depth": _not_assessed("Liquidity was not read for this assessment."),
            "warning": (
                "A contract balance is not the same as exploitable funds. "
                "Even a verified balance says nothing about what a given bug "
                "can actually move."
            ),
        },
    }


def _first_address(scan: Dict[str, Any]) -> Optional[str]:
    for key in ("address", "contract_address", "target_address"):
        value = scan.get(key)
        if value:
            return str(value)
    # etherscan://[network/]0x… and cache paths …/0x…/<hash>
    src = str(scan.get("source_path") or "")
    m = re.search(r"etherscan://(?:[a-z0-9-]+/)?(0x[0-9a-fA-F]{40})", src)
    if m:
        return m.group(1).lower()
    m = re.search(r"/(0x[0-9a-fA-F]{40})(?:/|$)", src)
    if m:
        return m.group(1).lower()
    return None


# ---------------------------------------------------------------------------
# source classification (fixture / local / deployed)
# ---------------------------------------------------------------------------

_FIXTURE_FILE_TOKENS = {"test", "tests", "fixture", "fixtures", "mock", "mocks", "spec"}
_FIXTURE_DIR_TOKENS = {
    # Do not include bare "tmp"/"temp": on Linux a TemporaryDirectory lives
    # under /tmp, which is also a normal place to drop a local file for review.
    "fixtures", "fixture", "testdata", "test-data",
    "test-fixtures", "__tests__", "tests", "test",
    "tmp_path", "tmpdir", "tempfile", "pytest-cache",
}


def _fixture_reason(path_str: str, config: str) -> Optional[str]:
    """Return why this scan looks like a test fixture, or None.

    Signals are purely local and observable: file name tokens (camelCase
    aware), path directory tokens, and the scan configuration fingerprint.
    Nothing about a real deployment is inferred either way.
    """
    reasons: List[str] = []
    try:
        path = Path(path_str) if path_str else None
    except (TypeError, ValueError, OSError):  # pragma: no cover - defensive
        path = None
    if path is not None and str(path) not in ("", "."):
        stem = path.stem
        tokens = set(
            re.split(r"[^a-z0-9]+", re.sub(r"(?<=[a-z0-9])(?=[A-Z])", " ", stem).lower())
        )
        if tokens & _FIXTURE_FILE_TOKENS:
            reasons.append(f"file name {path.name!r} marks a test/fixture file")
        if path.name.endswith(".t.sol"):
            reasons.append(f"file name {path.name!r} uses the .t.sol test suffix")
        lower_parts = [part.lower() for part in path.parts]
        hit_dirs = sorted({
            part for part in lower_parts
            if part in _FIXTURE_DIR_TOKENS
            or part.startswith("pytest-")
            or part.startswith("pytest_of")
        })
        if hit_dirs:
            reasons.append(
                "path runs through temporary/fixture directories: " + ", ".join(hit_dirs)
            )
    if config in ("fixture", "test-fixture", "test"):
        reasons.append(f"scan configuration fingerprint {config!r} marks a fixture run")
    if not reasons:
        return None
    return "; ".join(reasons) + ". This says nothing about a real deployment."


def _classification(scan: Dict[str, Any], metadata: Dict[str, str],
                    bytecode: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Classify what this scan's source is: fixture, local, or deployed."""
    meta = metadata or {}
    config = str(scan.get("config_fingerprint") or "")
    address = str(meta.get("contract_address") or "").strip()
    addr = address or _first_address(scan)

    if config == "dashboard-address" or address or _first_address(scan):
        basis: List[str] = []
        if config == "dashboard-address":
            basis.append("scan was run against a chain address (config 'dashboard-address')")
        if address:
            basis.append("a contract address is recorded in scan metadata")
        if not address and _first_address(scan):
            basis.append(f"an address is recorded on the scan record ({_first_address(scan)})")
        bc = bytecode
        if bc is None and addr:
            try:
                from auditor.bytecode_verify import verify_deployed_source
                bc = verify_deployed_source(str(addr))
            except Exception as exc:  # noqa: BLE001
                bc = {"value": "deployed_unverified", "label":
                      "Deployed target — source NOT verified against on-chain bytecode",
                      "basis": f"bytecode verify errored: {type(exc).__name__}: {exc}"}
        if isinstance(bc, dict) and bc.get("value") == "deployed_verified":
            return {
                "value": "deployed_verified",
                "label": bc.get("label") or "Deployed target — Etherscan-verified source; on-chain runtime code present",
                "basis": "; ".join(basis + [str(bc.get("basis") or "")]),
                "origin": "scan record + Etherscan + eth_getCode",
                "codehash": bc.get("codehash"),
                "address": bc.get("address") or addr,
            }
        basis.append(str((bc or {}).get("basis") or "deployed bytecode was not compared with this source"))
        return {
            "value": "deployed_unverified",
            "label": "Deployed target — source NOT verified against on-chain bytecode",
            "basis": "; ".join(x for x in basis if x),
            "origin": "scan record / scan metadata",
            "codehash": (bc or {}).get("codehash"),
            "address": (bc or {}).get("address") or addr,
        }

    fixture = _fixture_reason(str(scan.get("source_path") or ""), config)
    if fixture:
        return {
            "value": "test_fixture",
            "label": "TEST FIXTURE / NOT A VERIFIED DEPLOYED PROTOCOL",
            "basis": fixture,
            "origin": "local scan record",
        }

    return {
        "value": "local_source",
        "label": "Local source under review — not matched to any deployment",
        "basis": "No chain address or deployment metadata is recorded for this scan.",
        "origin": "local scan record",
    }


# ---------------------------------------------------------------------------
# financial impact (honest-unknown)
# ---------------------------------------------------------------------------

def _financial_block(
    scan: Dict[str, Any],
    classification: Dict[str, Any],
    exposure: Dict[str, Any],
    asset_block: Dict[str, Any],
    monitor_value: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Protocol-level financial block. Every figure stays unknown unless a
    configured, attributed source actually read it.

    When ``monitor_value`` carries a prior monitor/hunt ``value_json`` (holdings
    priced via the configured PriceSource), surface those as contract holdings —
    never as confirmed exploitable loss.
    """
    timestamp = scan.get("timestamp")
    mv = monitor_value or {}
    holdings = mv.get("holdings") if isinstance(mv.get("holdings"), list) else None
    tvl = mv.get("tvl_usd")
    price_as_of = mv.get("price_as_of")
    price_source = mv.get("price_source")
    price_stale = bool(mv.get("price_stale"))
    if holdings is not None and tvl is not None:
        hold_lines = [
            f"{h.get('symbol')}: {h.get('amount')} (~${float(h.get('usd') or 0):,.2f})"
            for h in holdings if isinstance(h, dict)
        ]
        tvl_f = float(tvl)
        summary = (
            f"Contract holdings priced at ~${tvl_f:,.2f} "
            f"(source: {price_source or 'monitor value_json'}"
            f"{'; stale' if price_stale else ''}). "
            "Holdings are not exploitable exposure."
        )
        bal_node = _labeled(
            f"~${tvl_f:,.2f} across {len(holdings)} asset(s)"
            + ((" — " + "; ".join(hold_lines[:6])) if hold_lines else ""),
            "monitor holdings (priced)",
        )
        tvl_node = _labeled(f"~${tvl_f:,.2f}", "monitor holdings (priced)")
        usd_node = _labeled(f"~${tvl_f:,.2f}", "monitor holdings (priced)")
        return {
            "status": "holdings_assessed",
            "summary": summary,
            "theoretical_max": exposure["theoretical_max"],
            "realistically_reachable": exposure["realistically_reachable"],
            "confirmed_loss": exposure["confirmed_loss"],
            "contract_balance": bal_node,
            "tvl": tvl_node,
            "usd_equivalent": usd_node,
            "holdings": holdings,
            "holdings_usd": tvl_f,
            "methodology": [
                "Holdings come from the monitor/hunt value assessment (RPC balances + price source).",
                "A contract balance or TVL is not the same as exploitable exposure.",
                "Confirmed outsider loss stays unknown unless a finding is dynamically reproduced.",
            ],
            "what_would_validate_these_numbers": [
                "Fresh RPC re-read of balances at a pinned block.",
                "Bytecode-vs-source verification for the deployed target.",
                "Pinned-fork reproduction for any confirmed-loss claim.",
            ],
            "source": _labeled(
                f"{price_source or 'monitor value_json'}"
                + (f" @ {price_as_of}" if price_as_of else ""),
                "monitor scan value_json",
            ),
            "as_of": (
                _labeled(price_as_of or timestamp, "price_as_of / scan record")
                if (price_as_of or timestamp)
                else _unknown("No timestamp recorded.")
            ),
            "confidence": "estimate" if not price_stale else "stale_estimate",
            "classification": classification["label"],
            "warning": (
                "Contract balance is not exploitable exposure. Even a verified "
                "balance says nothing about what a given bug can actually move."
            ),
        }
    return {
        "status": "not_assessed",
        "summary": (
            "No financial figure was read for this assessment: no balance, "
            "TVL, price, or incident source is configured."
        ),
        "theoretical_max": exposure["theoretical_max"],
        "realistically_reachable": exposure["realistically_reachable"],
        "confirmed_loss": exposure["confirmed_loss"],
        "contract_balance": asset_block.get("token_balance_at_risk"),
        "tvl": asset_block.get("tvl"),
        "usd_equivalent": asset_block.get("usd_equivalent"),
        "methodology": [
            "Figures stay 'Unknown — not verified' until a configured, attributed source reads them.",
            "A contract balance or TVL is not the same as exploitable exposure.",
            "No dollar amount, token amount, price, or loss figure is asserted in this block.",
        ],
        "what_would_validate_these_numbers": [
            "An RPC endpoint plus a verified contract address to read live balances.",
            "Bytecode-vs-source verification for the deployed target (if any).",
            "Liquidity / oracle reads from an attributed source, where relevant.",
            "Incident or exploit-transaction evidence for any confirmed-loss claim.",
        ],
        "source": _unknown("No balance, price, or incident source is configured for this scan."),
        "as_of": (
            _labeled(timestamp, "scan record")
            if timestamp
            else _unknown("Scan record has no timestamp.")
        ),
        "confidence": "unknown",
        "classification": classification["label"],
        "warning": (
            "Contract balance is not exploitable exposure. Even a verified "
            "balance says nothing about what a given bug can actually move."
        ),
    }


# ---------------------------------------------------------------------------
# severity / confidence provenance
# ---------------------------------------------------------------------------

def _severity_provenance(
    finding: Dict[str, Any],
    review: Dict[str, Any],
    ai_analysis: Optional[Dict[str, Any]],
) -> Dict[str, Any]:
    """Where the current severity/confidence/status came from, kept separate."""
    fact_count = int(finding.get("fact_evidence_count") or 0)
    if not fact_count:
        evidence = finding.get("evidence") or []
        fact_count = sum(
            1 for i in evidence
            if isinstance(i, dict) and str(i.get("epistemic")).upper() == "FACT"
        )
    status = str(
        finding.get("verification_status") or finding.get("status") or "UNVERIFIED"
    )
    history = review.get("history") or []
    evidence_backed = fact_count > 0
    return {
        "current": {
            "severity": finding.get("severity") or UNKNOWN,
            "confidence": finding.get("confidence") or UNKNOWN,
            "verification_status": status,
        },
        "scanner": {
            "severity": finding.get("severity") or UNKNOWN,
            "confidence": finding.get("confidence") or UNKNOWN,
            "tool": finding.get("tool") or UNKNOWN,
            "origin": "deterministic scanner record (as recorded at scan time)",
        },
        "ai": {
            "present": bool(ai_analysis),
            "severity": (ai_analysis or {}).get("severity") or NOT_ASSESSED,
            "origin": "generated_ai_analysis — opinion, never scanner evidence",
        },
        "triage": {
            "state": review.get("state") or "New",
            "recorded_events": len(history),
            "origin": "analyst triage record (finding_reviews / finding_review_history)",
        },
        "evidence_backed_verification": {
            "fact_evidence_count": fact_count,
            "verification_supported": evidence_backed,
            "note": (
                "At least one FACT evidence item supports this finding's status."
                if evidence_backed
                else "No FACT evidence is stored for this finding — its status is not "
                     "evidence-backed. Treat the severity as a lead, not proof."
            ),
        },
        "false_positive_review": {
            "recommended": (not evidence_backed) and status == "UNVERIFIED",
            "basis": (
                "Stored record has zero FACT evidence and status UNVERIFIED."
                if (not evidence_backed) and status == "UNVERIFIED"
                else "Evidence record is sufficient for the current status; review anyway before confirming."
            ),
            "action": "Compare against the benign explanation and false-positive considerations, then set the triage state.",
        },
        "note": (
            "Severity and confidence shown to users can be revised by triage; "
            "the scanner row above is what the tool recorded. A severity without "
            "FACT evidence is a lead, not proof of exploitability."
        ),
    }


# ---------------------------------------------------------------------------
# duplicates (same-scan groups)
# ---------------------------------------------------------------------------

def _normalized_title(title: Any) -> str:
    return re.sub(r"\s+", " ", str(title or "").strip().lower())


def _duplicates(finding: Dict[str, Any], scan: Dict[str, Any]) -> Dict[str, Any]:
    """Same-scan findings that share this finding's normalized title."""
    details = scan.get("finding_details")
    if isinstance(details, str):
        try:
            details = json.loads(details)
        except (json.JSONDecodeError, ValueError):
            details = None
    if isinstance(details, dict):
        details = list(details.values())
    if not isinstance(details, list):
        details = []

    fp = str(finding.get("fingerprint") or "")
    key = _normalized_title(finding.get("title"))
    members: List[Dict[str, Any]] = []
    if key:
        seen_self = False
        for other in details:
            if not isinstance(other, dict):
                continue
            other_fp = str(other.get("fingerprint") or "")
            if other_fp == fp and not seen_self:
                # First row with this fingerprint is the finding itself.
                seen_self = True
                continue
            if _normalized_title(other.get("title")) != key:
                continue
            loc = f"{other.get('affected_contract') or '?'}.{other.get('affected_function') or '?'}"
            members.append(
                {
                    "fingerprint": other.get("fingerprint"),
                    "title": other.get("title"),
                    "severity": other.get("severity") or UNKNOWN,
                    "location": loc,
                }
            )
    return {
        "group_key": "normalized_title",
        "value": key or UNKNOWN,
        "count": len(members),
        "members": members,
        "note": (
            f"{len(members)} other finding(s) in this scan share the same normalized "
            "title. Compare them in the findings list before confirming or "
            "closing any one of them — identical titles often mean duplicates "
            "or an over-broad pattern match."
            if members
            else "No other finding in this scan shares this title."
        ),
    }


# ---------------------------------------------------------------------------
# actionable fix + grounded example patch
# ---------------------------------------------------------------------------

def _actionable_fix(
    finding: Dict[str, Any],
    playbook: Dict[str, Any],
    snippet: Dict[str, Any],
    root_summary: str,
) -> Dict[str, Any]:
    """Concrete, ordered remediation steps grounded where possible."""
    grounded = bool(snippet.get("lines"))
    if playbook["kind"] == "reentrancy":
        steps = [
            "Commit every state write the function performs BEFORE the external call "
            "(checks-effects-interactions), or guard the function with a reentrancy guard.",
            "Keep all validation (require checks) ahead of both the state write and the call.",
            "Re-read the whole function: confirm no remaining external call happens before "
            "the state it depends on is finalized.",
        ]
    elif playbook["kind"] == "access_control":
        steps = [
            "Add or correct the authorization check on the affected function (modifier, "
            "owner/role check) so only the intended authority can reach it.",
            "Confirm the check binds to the right subject (msg.sender vs an argument) and "
            "cannot be bypassed through an alternate entrypoint or delegate path.",
            "Sweep sibling functions for the same missing or misapplied check.",
        ]
    else:
        steps = [
            "Re-read the affected lines against the project's security invariants and "
            "apply the project's standard mitigation for this pattern.",
            "Ask a second reviewer to confirm the mitigation does not break legitimate callers.",
        ]
    remediation = str(finding.get("remediation") or "").strip()
    if remediation and remediation != NOT_ASSESSED:
        steps.insert(0, f"Scanner-recommended remediation: {remediation}")
    return {
        "problem": root_summary,
        "steps": steps,
        "verify_with": [
            f"{t['step']}: {t['detail']}" for t in _test_plan(finding, playbook)
        ],
        "estimated_fix_range": {"range": playbook["fix_hours"], "label": APPROX},
        "grounded_in_source": grounded,
        "grounding_note": (
            "Steps reference the stored source excerpt (lines shown above)."
            if grounded
            else "Source excerpt unavailable — steps are playbook-level; locate the "
                 "affected lines in your editor before editing."
        ),
        "origin": "deterministic playbook + local source",
        "auto_applied": False,
    }


_CALL_PATTERNS = re.compile(
    r"\.call(?:\{[^}]*\})?(?:\s*\.\s*value\s*\([^)]*\))?(?:\s*\.\s*gas\s*\([^)]*\))?\s*\("
    r"|\.transfer\s*\(|\.send\s*\("
)


def _example_patch(playbook: Dict[str, Any], snippet: Dict[str, Any]) -> Dict[str, Any]:
    """A grounded, reorder-only example patch — suggested, never applied.

    Only produced when both the external call and a later state write can be
    located verbatim in the stored source excerpt. Anything else returns an
    explicit "unavailable" instead of inventing code.
    """
    unavailable = lambda reason: {  # noqa: E731 - small local helper
        "available": False,
        "reason": reason,
        "next_step": (
            "Use 'Propose patch (OpenCode)' to request a reviewed proposal — "
            "nothing is written without explicit approval and a hash check."
        ),
        "auto_applied": False,
    }
    if playbook["kind"] != "reentrancy":
        return unavailable(
            "No deterministic, source-grounded patch template applies to this "
            "finding category — the fix requires a project-specific design or "
            "authorization decision."
        )
    lines = [ln for ln in (snippet.get("lines") or []) if isinstance(ln, dict)]
    call_idx = None
    write_idx = None
    for i, line in enumerate(lines):
        text = str(line.get("text") or "")
        if call_idx is None:
            if _CALL_PATTERNS.search(text):
                call_idx = i
            continue
        if write_idx is not None:
            break
        if re.search(r"(?<![=!<>])=(?!=)", text) and "require" not in text and "event " not in text:
            write_idx = i
    if call_idx is None or write_idx is None or write_idx <= call_idx:
        return unavailable(
            "The external call and a later state write could not both be "
            "located verbatim in the stored source excerpt, so no grounded "
            "reorder can be shown."
        )
    call_line = lines[call_idx]
    write_line = lines[write_idx]
    file_name = Path(str(snippet.get("file") or "")).name or "source"
    return {
        "available": True,
        "rule": "checks-effects-interactions: commit state before the external call",
        "file": snippet.get("file"),
        "before": [
            {"n": call_line.get("n"), "text": call_line.get("text")},
            {"n": write_line.get("n"), "text": write_line.get("text")},
        ],
        "after": [
            {"n": write_line.get("n"), "text": write_line.get("text"), "note": "moved before the external call"},
            {"n": call_line.get("n"), "text": call_line.get("text")},
        ],
        "reference": f"{file_name}:{call_line.get('n')} (call), {file_name}:{write_line.get('n')} (state write)",
        "origin": "verbatim local source lines (order changed only)",
        "status": "suggested_not_applied",
        "apply_via": (
            "Manual edit, or 'Propose patch (OpenCode)' — never applied "
            "automatically; explicit approval plus a before-hash check required."
        ),
        "caveats": [
            "The two lines are shown in isolation — read the whole function first "
            "to confirm nothing between them depends on the original order.",
            "If values are computed between these lines, keep the computation and "
            "move only the state commit.",
        ],
        "auto_applied": False,
    }


def _vulnerable_operation(
    finding: Dict[str, Any],
    playbook: Dict[str, Any],
    snippet: Dict[str, Any],
    reachability: Dict[str, Any],
) -> Dict[str, Any]:
    """The specific operation at risk, grounded in the excerpt when possible."""
    file_name = Path(str(snippet.get("file") or "")).name or None
    lines = [ln for ln in (snippet.get("lines") or []) if isinstance(ln, dict)]
    if playbook["kind"] == "reentrancy":
        for line in lines:
            if _CALL_PATTERNS.search(str(line.get("text") or "")):
                return _labeled(
                    f"External call at {file_name or 'source'}:{line.get('n')}",
                    "verified from local source",
                ) | {"basis": "call line located verbatim in the stored excerpt"}
        return _labeled(
            "External call executed before state finalization (exact line not "
            "located in the stored excerpt)",
            "not fully located",
        )
    if playbook["kind"] == "access_control":
        base = "Sensitive function reachable without a correct caller-authorization check"
        if reachability.get("origin") == "verified" and reachability.get("line"):
            decl_file = Path(str(reachability.get("file") or "")).name or (file_name or "source")
            return _labeled(
                f"{base} — {decl_file}:{reachability.get('line')}",
                "verified from local source",
            ) | {"basis": str(reachability.get("basis") or "")}
        return _labeled(base, "playbook")
    return _labeled(
        f"Trust assumption in {finding.get('affected_contract') or 'the contract'}."
        f"{finding.get('affected_function') or ''} may not hold for every caller",
        "playbook",
    )


def _call_path(
    finding: Dict[str, Any],
    playbook: Dict[str, Any],
    snippet: Dict[str, Any],
    reachability: Dict[str, Any],
) -> List[str]:
    """Conceptual call path with file:line anchors where the excerpt allows."""
    target = finding.get("affected_contract") or "the contract"
    func = finding.get("affected_function") or "the affected function"
    file_name = Path(str(snippet.get("file") or "")).name
    anchor = ""
    if reachability.get("origin") == "verified" and reachability.get("line"):
        anchor = f" (declared at {file_name}:{reachability.get('line')})"
    lines = [ln for ln in (snippet.get("lines") or []) if isinstance(ln, dict)]
    call_line = next(
        (ln for ln in lines if _CALL_PATTERNS.search(str(ln.get("text") or ""))), None
    )
    write_line = None
    if call_line is not None:
        seen_call = False
        for line in lines:
            if line is call_line:
                seen_call = True
                continue
            if seen_call and re.search(r"(?<![=!<>])=(?!=)", str(line.get("text") or "")) \
                    and "require" not in str(line.get("text") or ""):
                write_line = line
                break

    if playbook["kind"] == "reentrancy":
        path = [
            f"A caller invokes {target}.{func}{anchor}.",
            "The function performs an external call to an address whose code it does not control"
            + (f" — {file_name}:{call_line.get('n')}" if call_line else " (line not located in the excerpt)") + ".",
            "That address's code runs and can call back into this contract while state is unchanged.",
            "State written after the call returns commits values that were already stale"
            + (f" — {file_name}:{write_line.get('n')}" if write_line else "") + ".",
        ]
        return path
    if playbook["kind"] == "access_control":
        return [
            f"An arbitrary caller reaches {target}.{func}{anchor}.",
            "The authorization check on that path is missing, wrong, or applied to the wrong subject.",
            "Sensitive state — ownership, parameters, withdrawals, upgrades — changes under unauthorized control.",
        ]
    return [
        f"A caller reaches {target}.{func}{anchor}.",
        "The trust assumption this finding points at does not hold on that path.",
        "The divergent path is the exposure.",
    ]


def _validation_time(playbook: Dict[str, Any]) -> Dict[str, Any]:
    """Time to decide whether this finding is real — kept apart from fixing it."""
    return {
        "range": "0.5–2 hours (approximate)",
        "label": APPROX,
        "explanation": (
            "Reading the affected code, reproducing the reasoning, and "
            "checking the benign explanation — validation only. Fixing the "
            "code is estimated separately in the remediation view."
        ),
        "separate_from": "remediation effort (fix implementation + tests)",
    }


def _evidence_needed(finding: Dict[str, Any], classification: Dict[str, Any]) -> List[str]:
    """Concrete evidence that would firm up today's honest unknowns."""
    items = [
        "Live contract balances (requires a configured RPC source — none configured).",
        "Verification that deployed bytecode matches this source (not performed for this scan).",
        "A parsed call graph beyond local text search (not computed).",
        "Incident or exploit-transaction evidence for any confirmed-loss claim (none collected).",
    ]
    if classification.get("value") == "deployed_unverified":
        items.insert(
            0,
            "Source-to-bytecode match for the recorded contract address "
            "(deployment is recorded; the match was not verified).",
        )
    if classification.get("value") == "test_fixture":
        items.insert(
            0,
            "Any statement about a real deployment — this scan targets a test "
            "fixture and cannot provide it.",
        )
    for extra in (finding.get("prerequisites") or []):
        if extra:
            items.append(f"Scanner prerequisite to confirm: {extra}")
    return items


# ---------------------------------------------------------------------------
# bounty placeholder
# ---------------------------------------------------------------------------

def _bounty_block(result: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    if not result:
        return {
            "status": "not_checked",
            "eligibility": NOT_ASSESSED,
            "reason": "No bounty check has been run for this scan.",
            "checked_at": None,
            "source_url": None,
            "evidence": [],
            "official_source_fetched": False,
            "reminder": (
                "Bounty eligibility and rewards are never asserted without an "
                "official program source. Read the program's official page and "
                "verify its scope, safe harbor, and authorization rules."
            ),
        }
    out = dict(result)
    out.setdefault(
        "official_source_fetched",
        out.get("status") == "checked" and bool(out.get("source_url")),
    )
    return out


# ---------------------------------------------------------------------------
# main builder
# ---------------------------------------------------------------------------

def build_investigation(
    finding: Dict[str, Any],
    scan: Dict[str, Any],
    review: Optional[Dict[str, Any]] = None,
    metadata: Optional[Dict[str, str]] = None,
    source_root: Any = None,
    bounty: Optional[Dict[str, Any]] = None,
    state_history: Optional[List[Dict[str, Any]]] = None,
    ai_analysis: Optional[Dict[str, Any]] = None,
    monitor_context: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Build the full two-sided investigation payload for one finding.

    ``monitor_context`` (optional) may carry ``value`` (holdings/TVL from
    monitor_scans.value_json), ``triage`` (suppressed + reason/detail), and
    ``bytecode`` (result of bytecode_verify.verify_deployed_source).
    """
    review = review or {}
    metadata = metadata or {}
    monitor_context = monitor_context or {}
    playbook = _playbook_for(finding)

    root = _validate_root(source_root)
    contract = finding.get("affected_contract")
    lines = finding.get("affected_lines") or []
    if not isinstance(lines, list):
        lines = []
    file_path = _locate_file(root, contract)
    snippet = _snippet(file_path, [int(x) for x in lines if isinstance(x, (int, float, str)) and str(x).isdigit()])
    reachability = _reachability(root, finding.get("affected_function"), snippet)

    plain = playbook["plain_english"] or str(finding.get("description") or "").strip() or NOT_ASSESSED
    root_summary = _root_cause_summary(finding, playbook, snippet)
    classification = _classification(scan, metadata, bytecode=monitor_context.get("bytecode"))

    difficulty_basis = []
    if finding.get("fact_evidence_count"):
        difficulty_basis.append("FACT evidence recorded by the scanner")
    if reachability.get("origin") == "verified":
        difficulty_basis.append("affected function located in local source")
    if difficulty_basis:
        difficulty = {
            "value": "Low-to-moderate for a caller who satisfies the preconditions (estimate)",
            "label": APPROX,
            "explanation": "Relative difficulty estimate based on: " + "; ".join(difficulty_basis) + ". Not measured against a live target.",
        }
    else:
        difficulty = {
            "value": NOT_ASSESSED,
            "label": "not_assessed",
            "explanation": "Insufficient verified context to estimate difficulty.",
        }

    exposure = {
        "theoretical_max": _unknown(
            "Would require token balances and, where relevant, liquidity or "
            "oracle reads from a configured RPC source. None were read."
        ),
        "realistically_reachable": _not_assessed(
            "Depends on the reachability verdict, privileges required, and "
            "real asset routing — none of which were measured against deployed state."
        ),
        "confirmed_loss": _not_assessed(
            "No incident, exploit transaction, or loss evidence was collected for this finding."
        ),
        "note": (
            "No maximum loss, loss range, or price is asserted here. Fabricated "
            "numbers are worse than honest unknowns."
        ),
    }

    protocol = _protocol_block(metadata, scan)
    financial = _financial_block(scan, classification, exposure, protocol.get("asset", {}), monitor_value=monitor_context.get("value"))
    remediation_primary = finding.get("remediation") or NOT_ASSESSED
    actionable = _actionable_fix(finding, playbook, snippet, root_summary)
    example_patch = _example_patch(playbook, snippet)
    provenance = _severity_provenance(finding, review, ai_analysis)
    duplicates = _duplicates(finding, scan)

    evidence_items = [
        item for item in (finding.get("evidence") or []) if isinstance(item, dict)
    ]

    assumptions = [str(a) for a in (finding.get("assumptions") or []) if a]
    unknowns = [
        "Actual asset balances and routing (no RPC configured).",
        "USD conversion of any exposure (no price source configured).",
        "Whether the deployed bytecode matches the reviewed source (not verified for this scan).",
        "Bounty eligibility (not checked — no official program source consulted).",
    ]
    if classification.get("value") == "test_fixture":
        unknowns.insert(
            0,
            "This scan targets a test fixture — no statement here applies to any "
            "real deployment (see source classification).",
        )
    elif classification.get("value") == "deployed_verified":
        unknowns.insert(
            0,
            "Etherscan-verified source with on-chain runtime code present; "
            "solc-artifact identity was not compared in this pass.",
        )
    elif classification.get("value") == "deployed_unverified":
        unknowns.insert(
            0,
            "A contract address is recorded, but deployed bytecode was not "
            "verified against this source (see source classification).",
        )
    for extra in (finding.get("prerequisites") or []):
        if extra and str(extra) not in unknowns:
            unknowns.append(f"Unverified prerequisite from the scanner: {extra}")

    triage = monitor_context.get("triage") if isinstance(monitor_context.get("triage"), dict) else None
    state = (review or {}).get("state") or "New"
    if triage and (not (review or {}).get("state") or state == "New"):
        # Prefer durable monitor triage over the default New review row.
        if triage.get("label") in ("false_positive", "disproved_current_state"):
            state = "False Positive"
    ver_status = finding.get("verification_status") or finding.get("status") or "UNVERIFIED"
    if triage and triage.get("label") == "disproved_current_state":
        ver_status = "DISPROVED (dynamically tested path)"
    elif triage and triage.get("label") == "false_positive":
        ver_status = "FALSE_POSITIVE (detector-corrected / triage)"
    target = finding.get("affected_contract") or "the contract"
    func = finding.get("affected_function") or "the affected function"
    if triage and triage.get("verdict"):
        headline = (
            f"{finding.get('severity') or UNKNOWN} finding in {target}.{func} — "
            f"triage: {triage.get('verdict')}"
            + (f" ({triage.get('reason')})" if triage.get("reason") else "")
            + (f"; {triage.get('detail')}" if triage.get("detail") else "")
        )
    else:
        headline = (
            f"{finding.get('severity') or UNKNOWN} finding in {target}.{func} — "
            f"triage state: {state}; status: {ver_status}."
        )
    if financial.get("status") == "holdings_assessed":
        fin_status = financial.get("summary") or "Holdings assessed (not exploitable exposure)."
    else:
        fin_status = (
            "Not assessed — no balance, price, TVL, or incident source is "
            "configured for this scan."
        )
    executive_summary = {
        "headline": headline,
        "what": root_summary,
        "recommended_action": remediation_primary,
        "fix_status": (
            "Not fixed — concrete steps below; nothing is applied to your code "
            "automatically."
            if not (triage and triage.get("label") in ("false_positive", "disproved_current_state"))
            else (
                "No code change required — finding triaged as "
                f"{triage.get('verdict')}: {triage.get('detail') or triage.get('reason') or ''}"
            )
        ),
        "financial_status": fin_status,
        "source_classification": classification["label"],
        "origin": "deterministic scan record + local source (no model output)",
        "monitor_triage": triage,
    }

    return {
        "scan_id": scan.get("scan_id"),
        "fingerprint": finding.get("fingerprint"),
        "title": finding.get("title") or UNKNOWN,
        "description": finding.get("description") or "",
        "category": finding.get("category") or UNKNOWN,
        "severity": finding.get("severity") or UNKNOWN,
        "confidence": finding.get("confidence") or UNKNOWN,
        "verification_status": ver_status,
        "executive_summary": executive_summary,
        "classification": classification,
        "financial_impact": financial,
        "severity_provenance": provenance,
        "duplicates": duplicates,
        "review": {
            "state": state,
            "updated_at": (review or {}).get("updated_at"),
            "note": (review or {}).get("note") or (triage or {}).get("detail"),
            "allowed_transitions": (review or {}).get("allowed_transitions") or [],
            "history": state_history or [],
            "monitor_triage": triage,
        },
        "scanner": {
            "tool": finding.get("tool") or UNKNOWN,
            "source": finding.get("source") or UNKNOWN,
            "config_fingerprint": scan.get("config_fingerprint"),
            "scan_timestamp": scan.get("timestamp"),
            "finding_id": finding.get("finding_id"),
            "label": "deterministic scanner evidence (unless a field below says otherwise)",
        },
        "protocol": protocol,
        "attacker": {
            "panel_label": "Attacker / risk view",
            "plain_english": plain,
            "attack_path": playbook["attack_path"],
            "attack_path_label": "Conceptual path (preconditions and trust assumptions), not an operational guide",
            "call_path": _call_path(finding, playbook, snippet, reachability),
            "vulnerable_operation": _vulnerable_operation(finding, playbook, snippet, reachability),
            "preconditions": list(dict.fromkeys(
                playbook["preconditions"] + [str(p) for p in (finding.get("prerequisites") or []) if p]
            )),
            "reachability": reachability,
            "privileges_required": _labeled(
                finding.get("exploitability") or NOT_ASSESSED,
                "verified" if finding.get("exploitability") else "not_assessed",
            ),
            "external_dependencies": [
                str(d) for d in (finding.get("prerequisites") or []) if d
            ] or [NOT_ASSESSED],
            "caia": playbook["caia"],
            "difficulty": difficulty,
            "validation_time": _validation_time(playbook),
            "evidence_needed": _evidence_needed(finding, classification),
            "exposure": exposure,
            "likelihood": _labeled(
                finding.get("likelihood") or UNKNOWN,
                "scanner heuristic" if finding.get("likelihood") else "unknown",
            ),
            "impact": _labeled(
                finding.get("impact") or NOT_ASSESSED,
                "scanner assessment" if finding.get("impact") else "not_assessed",
            ),
            "misconceptions": playbook["misconceptions"],
        },
        "defender": {
            "panel_label": "White-hat / remediation view",
            "root_cause": {
                "summary": root_summary,
                "source": snippet,
            },
            "actionable_fix": actionable,
            "example_patch": example_patch,
            "remediation": {
                "primary": remediation_primary,
                "references": [str(r) for r in (finding.get("references") or []) if r],
            },
            "benign_explanation": finding.get("benign_explanation") or NOT_ASSESSED,
            "false_positive_considerations": list(dict.fromkeys(
                [str(f) for f in _as_list(finding.get("false_positive_risk")) if f]
                + [str(c) for c in _as_list(finding.get("contradicting_evidence")) if c]
                + [playbook["misconceptions"][0]]
            )),
            "assumptions": assumptions or [NOT_ASSESSED],
            "estimates": _estimates(playbook, finding),
            "test_plan": _test_plan(finding, playbook),
        },
        "evidence": {
            "items": evidence_items,
            "fact_count": sum(1 for i in evidence_items if str(i.get("epistemic")) == "FACT"),
            "inference_count": sum(1 for i in evidence_items if str(i.get("epistemic")) == "INFERENCE"),
            "ai_opinion_count": sum(1 for i in evidence_items if str(i.get("epistemic")) == "AI_OPINION"),
            "label": "deterministic scanner evidence",
        },
        "bounty": _bounty_block(bounty),
        "ai_analysis": ai_analysis,
        "unknowns": unknowns,
        "glossary": playbook["glossary"],
    }


def _root_cause_summary(
    finding: Dict[str, Any],
    playbook: Dict[str, Any],
    snippet: Dict[str, Any],
) -> str:
    """Plain-language root cause grounded in the stored record + source."""
    target = finding.get("affected_contract") or "the contract"
    func = finding.get("affected_function") or "an affected function"
    aff: List[int] = []
    for raw in finding.get("affected_lines") or []:
        try:
            aff.append(int(raw))
        except (TypeError, ValueError):
            continue
    aff.sort()
    file = snippet.get("file")
    if aff and file:
        if len(aff) == 1:
            location = f" ({file}, line {aff[0]})"
        else:
            location = f" ({file}, lines {aff[0]}–{aff[-1]})"
    elif file:
        location = f" ({file})"
    else:
        location = ""
    base = f"In {target}.{func}{location}."
    if playbook["kind"] == "reentrancy":
        return (
            f"{base} An external call is made and state that later reads depend on "
            "is not yet finalized at that point, so a callback can observe stale values."
        )
    if playbook["kind"] == "access_control":
        return (
            f"{base} The caller-authorization check on this path is missing, wrong, "
            "or applied to the wrong subject, so a sensitive state change can be reached "
            "by an address outside the intended authority set."
        )
    desc = str(finding.get("description") or "").strip()
    return f"{base} {desc}".strip()


def _test_plan(finding: Dict[str, Any], playbook: Dict[str, Any]) -> List[Dict[str, str]]:
    func = finding.get("affected_function") or "the affected function"
    contract = finding.get("affected_contract") or "the contract"
    plan: List[Dict[str, str]] = [
        {
            "step": "Characterization test",
            "detail": f"Call {contract}.{func} under the finding's preconditions and assert the current (buggy) behavior, so the fix is provably behavior-changing.",
            "label": "deterministic",
        },
        {
            "step": "Fix regression test",
            "detail": "Repeat the same scenario after the fix and assert the unauthorized or stale outcome no longer occurs.",
            "label": "deterministic",
        },
    ]
    if playbook["kind"] == "reentrancy":
        plan.insert(0, {
            "step": "Callback simulation (in-test)",
            "detail": "In a test harness, have the callee re-enter during the external call and assert accounting cannot be double-counted.",
            "label": "deterministic",
        })
    elif playbook["kind"] == "access_control":
        plan.insert(0, {
            "step": "Unauthorized caller test",
            "detail": "Attempt the sensitive call from a non-privileged address and assert it reverts with the expected reason.",
            "label": "deterministic",
        })
    plan.append({
        "step": "Re-audit adjacent paths",
        "detail": "Check sibling functions for the same pattern before marking the finding Fixed.",
        "label": "deterministic",
    })
    return plan
