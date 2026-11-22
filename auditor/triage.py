"""Phase 19 — explicit, tested false-positive triage for analyzer findings.

Three rule families, applied after dedupe/validation and before history:

1. ``library-code`` (suppress): the finding's contract is recognised
   vendored library code (:mod:`auditor.library_code`, hash or heuristic
   level). Never the deployed main contract, never a scam/honeypot finding.
2. ``known-benign`` (suppress): a curated list of Slither patterns that are
   intentional in upstream libraries. Each rule checks the detector slug,
   the contract + function name AND the function body in the scanned source.
3. ``privileged-withdraw`` (downgrade to INFORMATIONAL): ``arbitrary-send-eth``
   where every ETH transfer in the function pays ``msg.sender`` and the
   function is gated by a visible msg.sender authorisation (owner/role/admin
   modifier whose definition checks msg.sender, or an inline check). It is
   an owner-rug / centralisation exposure, not an outsider-exploitable bug.

4. ``privileged-module-caller`` (Phase 20, downgrade to INFORMATIONAL):
   ``arbitrary-send-erc20`` / ``arbitrary-send-eth`` in a function whose
   modifier (or inline check) restricts ``msg.sender`` to an address held in
   a storage variable (``if (msg.sender != jobRegistry) revert`` /
   ``require(msg.sender == module)``), unless some public/external path lets
   ANY caller set that variable (then the finding is kept unchanged).

Findings in the project's own code are never suppressed except by rule 2,
and rules 3-4 only lower severity. Suppressed findings are returned with
their reason — they are kept (monitor DB, ``--show-suppressed``), not lost.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from .library_code import SourceIndex
from .model import Severity

SUPPRESS_LIBRARY = "library-code"
SUPPRESS_BENIGN = "known-benign"
DOWNGRADE_PRIVILEGED = "privileged-withdraw"
DOWNGRADE_MODULE = "privileged-module-caller"
DOWNGRADE_REASONS = (DOWNGRADE_PRIVILEGED, DOWNGRADE_MODULE)
SCAM_CATEGORY = "scam/honeypot"

_SLUG_RE = re.compile(r"(?:Slither|Source) detector: ([a-z0-9-]+)\.")
_TITLE_SLUG_RE = re.compile(r"^([a-z0-9]+(?:-[a-z0-9]+)+)\b")


def finding_slugs(f: Any) -> List[str]:
    desc = str(getattr(f, "description", "") or "")
    title = str(getattr(f, "title", "") or "")
    out = _SLUG_RE.findall(desc)
    m = _TITLE_SLUG_RE.match(title)
    if m and m.group(1) not in out:
        out.append(m.group(1))
    return out


@dataclass
class BenignRule:
    rule_id: str
    slug: str
    contracts: Tuple[str, ...]
    functions: Tuple[str, ...]
    body_patterns: Tuple[str, ...]   # every regex must match the function body
    rationale: str


KNOWN_BENIGN_RULES: Tuple[BenignRule, ...] = (
    BenignRule(
        "oz-erc1967-checknonpayable", "msg-value-in-nonpayable",
        ("ERC1967Utils",), ("_checkNonPayable",),
        (r"msg\.value\s*>\s*0", r"\brevert\b"),
        "OpenZeppelin ERC1967Utils._checkNonPayable reads msg.value precisely to REJECT stray ETH "
        "(reverts when msg.value > 0); the detector's concern (value silently ignored) cannot occur."),
    BenignRule(
        "oz-erc1967-upgrade-unused-return", "unused-return",
        ("ERC1967Utils",), ("upgradeToAndCall", "upgradeBeaconToAndCall"),
        (r"functionDelegateCall\s*\(",),
        "OpenZeppelin ERC1967Utils upgrade*AndCall ignore the bytes returned by "
        "Address.functionDelegateCall, which already reverts on failure; nothing is lost."),
    BenignRule(
        "oz-erc1967upgrade-unused-return", "unused-return",
        ("ERC1967Upgrade", "ERC1967UpgradeUpgradeable"),
        ("_upgradeToAndCall", "_upgradeBeaconToAndCall", "_upgradeToAndCallUUPS"),
        (r"functionDelegateCall\s*\(",),
        "OpenZeppelin 4.x ERC1967Upgrade upgrade helpers ignore the return of "
        "Address.functionDelegateCall, which reverts on failure."),
)


@dataclass
class TriageRecord:
    action: str                      # kept | suppressed | downgraded
    reason: Optional[str] = None     # library-code | known-benign | privileged-withdraw
    rule: Optional[str] = None
    detail: str = ""
    original_severity: Optional[str] = None
    library: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        return {"action": self.action, "reason": self.reason, "rule": self.rule, "detail": self.detail,
                "original_severity": self.original_severity, "library": self.library}


@dataclass
class TriageResult:
    kept: List[Any] = field(default_factory=list)
    suppressed: List[Tuple[Any, TriageRecord]] = field(default_factory=list)
    records: Dict[int, TriageRecord] = field(default_factory=dict)  # id(finding) -> record

    def record_for(self, f: Any) -> TriageRecord:
        return self.records.get(id(f)) or TriageRecord("kept")

    def summary(self) -> Dict[str, Any]:
        by: Dict[str, int] = {}
        for _, r in self.suppressed:
            by[r.reason or "?"] = by.get(r.reason or "?", 0) + 1
        down: Dict[str, int] = {}
        for r in self.records.values():
            if r.action == "downgraded":
                down[r.reason or "?"] = down.get(r.reason or "?", 0) + 1
        return {"suppressed": len(self.suppressed), "suppressed_by_reason": by,
                "downgraded": sum(down.values()), "downgraded_by_reason": down}

    def suppressed_dicts(self) -> List[Dict[str, Any]]:
        out = []
        for f, r in self.suppressed:
            d = _finding_brief(f)
            d["triage"] = r.to_dict()
            out.append(d)
        return out


def _finding_brief(f: Any) -> Dict[str, Any]:
    sev = getattr(f, "severity", "")
    return {"title": getattr(f, "title", ""), "severity": getattr(sev, "value", sev),
            "category": getattr(f, "category", ""),
            "affected_contract": getattr(f, "affected_contract", None),
            "affected_function": getattr(f, "affected_function", None),
            "affected_file": getattr(f, "affected_file", None),
            "affected_lines": list(getattr(f, "affected_lines", []) or []),
            "description": getattr(f, "description", ""),
            "finding_id": getattr(f, "finding_id", None),
            "evidence": [{"source": getattr(e, "source", None), "artifact_type": getattr(e, "artifact_type", None),
                          "epistemic": getattr(getattr(e, "epistemic", None), "value", getattr(e, "epistemic", None)),
                          "excerpt": str(getattr(e, "excerpt", "") or "")[:400]}
                         for e in (getattr(f, "evidence", None) or [])]}


def _function_body(index: SourceIndex, contract: str, function: str,
                   file: Optional[str]) -> Optional[Tuple[Any, Any, Dict[str, str]]]:
    from .analysis.sol_parse import all_modifiers, parse_contract

    hit = index.find_block(contract, file)
    if hit is None:
        return None
    rel, b = hit
    c = parse_contract(index.text[rel], b, index.code[rel])
    mods = getattr(index, "_all_modifiers", None)
    if mods is None:
        mods = {}
        for r2, bl in index.blocks.items():
            for b2 in bl:
                if b2.kind != "interface":
                    for k, v in parse_contract(index.text[r2], b2, index.code[r2]).modifiers.items():
                        mods.setdefault(k, v)
        index._all_modifiers = mods
    mods = dict(mods)
    mods.update(all_modifiers([c]))  # the finding's own contract wins on name clashes
    for fn in c.functions:
        if fn.name == function:
            return c, fn, mods
    return None


def _benign_rule(f: Any, index: SourceIndex) -> Optional[Tuple[BenignRule, str]]:
    slugs = finding_slugs(f)
    contract, function = getattr(f, "affected_contract", None), getattr(f, "affected_function", None)
    for rule in KNOWN_BENIGN_RULES:
        if rule.slug not in slugs or contract not in rule.contracts or function not in rule.functions:
            continue
        found = _function_body(index, contract, function, getattr(f, "affected_file", None))
        if found is None:
            continue
        body = found[1].body
        if all(re.search(p, body) for p in rule.body_patterns):
            return rule, rule.rationale
    return None


def privileged_withdraw(f: Any, index: SourceIndex) -> Optional[str]:
    """Detail string when *f* is an admin-gated withdraw to msg.sender, else None."""
    from .analysis.sol_parse import privileged_guard, value_sends

    if "arbitrary-send-eth" not in finding_slugs(f):
        return None
    contract, function = getattr(f, "affected_contract", None), getattr(f, "affected_function", None)
    if not contract or not function:
        return None
    found = _function_body(index, contract, function, getattr(f, "affected_file", None))
    if found is None:
        return None
    _c, fn, mods = found
    sends = value_sends(fn.body)
    if not sends or any(s["recipient"] != "msg.sender" for s in sends):
        return None
    guard = privileged_guard(fn, mods)
    if not guard:
        return None
    return (f"{contract}.{function} only pays msg.sender and is gated by {guard} (definition checks "
            "msg.sender). Outsiders cannot trigger it; the residual risk is the privileged account "
            "withdrawing the balance (owner-rug / centralisation exposure).")


# -- Phase 20: privileged module caller ------------------------------------

_MODULE_SLUGS = ("arbitrary-send-erc20", "arbitrary-send-erc20-permit", "arbitrary-send-eth")
_ADDR_EXPR = r"(?:address\s*\(\s*)?([A-Za-z_]\w*)(?:\s*\(\s*\))?(?:\s*\))?"
_SENDER_EQ_RES = (
    re.compile(r"require\s*\(\s*msg\.sender\s*==\s*" + _ADDR_EXPR + r"\s*[,)]"),
    re.compile(r"require\s*\(\s*" + _ADDR_EXPR + r"\s*==\s*msg\.sender\s*[,)]"),
    re.compile(r"if\s*\(\s*msg\.sender\s*!=\s*" + _ADDR_EXPR + r"\s*\)\s*(?:\{\s*)?(?:revert|throw)"),
    re.compile(r"if\s*\(\s*" + _ADDR_EXPR + r"\s*!=\s*msg\.sender\s*\)\s*(?:\{\s*)?(?:revert|throw)"),
)
_INIT_RE = re.compile(r"^(initialize\w*|init|__\w+_init\w*)$")


def sender_storage_guards(body: str) -> List[str]:
    """Identifiers that ``msg.sender`` must equal for *body* to proceed."""
    out: List[str] = []
    for rx in _SENDER_EQ_RES:
        for m in rx.finditer(body or ""):
            if m.group(1) not in out:
                out.append(m.group(1))
    return out


def _state_var_declared(index: SourceIndex, name: str) -> bool:
    """*name* (or ``_name`` for a ``name()`` getter) is a storage variable."""
    from .analysis.sol_parse import parse_contract

    cands = {name, "_" + name}
    decl = re.compile(r"(?:^|[;{}])\s*(?:address(?:\s+payable)?|I?[A-Z]\w*|\w+)\s+"
                      r"(?:(?:public|internal|private|immutable)\s+)*(" + "|".join(map(re.escape, cands)) +
                      r")\s*(?:=[^;]*)?;")
    for rel, bl in index.blocks.items():
        for b in bl:
            if b.kind == "interface":
                continue
            c = parse_contract(index.text[rel], b, index.code[rel])
            if re.search(r"\bconstant\b[^;]*\b(" + "|".join(map(re.escape, cands)) + r")\b", c.state_text):
                continue
            if decl.search(c.state_text):
                return True
    return False


def _all_functions(index: SourceIndex) -> List[Tuple[Any, Any]]:
    from .analysis.sol_parse import parse_contract

    cached = getattr(index, "_all_functions", None)
    if cached is None:
        cached = []
        for rel, bl in index.blocks.items():
            for b in bl:
                if b.kind != "interface":
                    c = parse_contract(index.text[rel], b, index.code[rel])
                    cached += [(c, fn) for fn in c.functions]
        index._all_functions = cached
    return cached


def _fn_guarded(fn: Any, mods: Dict[str, str]) -> bool:
    from .analysis.sol_parse import modifier_is_sender_guard, privileged_guard

    if privileged_guard(fn, mods):
        return True
    return any(modifier_is_sender_guard(mods.get(m)) for m in fn.modifiers)


def free_setters(index: SourceIndex, var: str, mods: Dict[str, str]) -> Tuple[List[str], List[str]]:
    """(freely callable setters, guarded/one-time setters) assigning storage *var*.

    A setter is "free" when it is public/external, not a constructor or
    initializer, and has no msg.sender guard; an internal setter is free when
    an unguarded public/external function calls it (one level deep).
    """
    names = {var, "_" + var}
    assign = re.compile(r"\b(" + "|".join(map(re.escape, names)) + r")\s*=(?!=)")
    free, guarded = [], []
    fns = _all_functions(index)
    for c, fn in fns:
        if fn.name in ("constructor",) or not assign.search(fn.body):
            continue
        label = f"{c.name}.{fn.name}"
        one_time = bool(_INIT_RE.match(fn.name)) or any(m in ("initializer", "reinitializer") for m in fn.modifiers)
        if one_time or _fn_guarded(fn, mods):
            guarded.append(label + (" (initializer)" if one_time else ""))
            continue
        if fn.visibility in ("public", "external"):
            free.append(label)
            continue
        call = re.compile(r"\b" + re.escape(fn.name) + r"\s*\(")
        callers = [(c2, f2) for c2, f2 in fns if f2 is not fn and call.search(f2.body)]
        open_callers = [f"{c2.name}.{f2.name}" for c2, f2 in callers
                        if f2.visibility in ("public", "external") and f2.name != "constructor"
                        and not _INIT_RE.match(f2.name) and not _fn_guarded(f2, mods)]
        (free if open_callers else guarded).append(label + (f" via {', '.join(open_callers)}" if open_callers else ""))
    return free, guarded


def privileged_module_caller(f: Any, index: SourceIndex) -> Optional[str]:
    """Detail when *f* is a value transfer only a storage-held address may trigger."""
    slugs = finding_slugs(f)
    if not any(s in slugs for s in _MODULE_SLUGS):
        return None
    contract, function = getattr(f, "affected_contract", None), getattr(f, "affected_function", None)
    if not contract or not function:
        return None
    found = _function_body(index, contract, function, getattr(f, "affected_file", None))
    if found is None:
        return None
    _c, fn, mods = found
    guards: List[Tuple[str, str]] = []
    for m in fn.modifiers:
        for v in sender_storage_guards(mods.get(m) or ""):
            guards.append((f"modifier {m}", v))
    for v in sender_storage_guards(fn.body[:400]):
        guards.append(("inline check", v))
    guards = [(where, v) for where, v in guards if v not in ("msg", "tx", "this") and _state_var_declared(index, v)]
    if not guards:
        return None
    where, var = guards[0]
    free, guarded = free_setters(index, var, mods)
    if free:
        return None  # any caller could make itself the privileged module: keep the finding
    setters = ("; set only by " + ", ".join(guarded)) if guarded else "; no setter found outside the constructor"
    return (f"{contract}.{function} can only be called by the address stored in `{var}` ({where} "
            f"restricts msg.sender){setters}. Outsiders cannot trigger the transfer; the residual risk is "
            "that address (or whoever can change it, e.g. governance) being compromised or malicious.")


def triage(findings: Sequence[Any], files: Sequence[Path], root: Optional[Path] = None,
           main_contract: Optional[str] = None, index: Optional[SourceIndex] = None) -> TriageResult:
    """Apply the three rule families. Mutates severity of downgraded findings only."""
    res = TriageResult()
    if not findings:
        return res
    index = index or SourceIndex(list(files), root)
    for f in findings:
        rec = TriageRecord("kept")
        is_scam = str(getattr(f, "category", "")) == SCAM_CATEGORY
        lib = None
        if not is_scam:
            lib = index.classify(getattr(f, "affected_contract", None), getattr(f, "affected_file", None),
                                 main_contract)
        benign = None if is_scam else _benign_rule(f, index)
        if benign is not None:
            rule, why = benign
            rec = TriageRecord("suppressed", SUPPRESS_BENIGN, rule.rule_id, why,
                               library=lib.to_dict() if lib else None)
        elif lib is not None and lib.is_library:
            rec = TriageRecord("suppressed", SUPPRESS_LIBRARY, f"library:{lib.level}",
                               f"{lib.detail} ({lib.package}{' ' + lib.version if lib.version else ''})",
                               library=lib.to_dict())
        else:
            reason, detail = DOWNGRADE_PRIVILEGED, privileged_withdraw(f, index)
            if not detail:
                reason, detail = DOWNGRADE_MODULE, privileged_module_caller(f, index)
            if detail:
                sev = getattr(f, "severity", None)
                orig = getattr(sev, "value", sev)
                if orig != Severity.INFORMATIONAL.value:
                    f.severity = Severity.INFORMATIONAL
                note = f"Triage ({reason}): severity {orig} -> INFORMATIONAL. {detail}"
                if note not in f.contradicting_evidence:
                    f.contradicting_evidence.append(note)
                rec = TriageRecord("downgraded", reason, reason, detail, orig)
        res.records[id(f)] = rec
        if rec.action == "suppressed":
            res.suppressed.append((f, rec))
        else:
            res.kept.append(f)
    return res


def apply_to_pipeline(findings: Sequence[Any], files: Sequence[Path], root: Optional[Path] = None,
                      main_contract: Optional[str] = None,
                      on_error: Optional[Callable[[str], None]] = None) -> TriageResult:
    """Fail-open wrapper: a triage bug must never drop findings."""
    try:
        return triage(findings, files, root, main_contract)
    except Exception as exc:  # noqa: BLE001
        if on_error:
            on_error(f"triage skipped: {type(exc).__name__}: {exc}")
        r = TriageResult(kept=list(findings))
        return r
