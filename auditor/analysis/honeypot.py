"""Phase 19 — scam / honeypot pattern analyzer (source-level).

These patterns describe a risk to **users who interact with the contract**
(they send funds and cannot get them back, or cannot sell), not an
exploitable bug the user could profit from. Every finding is a
HYPOTHESIS (status UNVERIFIED) with the matched source as FACT evidence,
category ``scam/honeypot`` and severity HIGH. Descriptions are defensive
only — they never describe how to run the scam or how to attack it.

Detectors (slug → idea):

* ``quiz-honeypot`` — a public payable "guess" function pays out the
  contract balance when ``keccak256(<user input>) == <stored hash>``, while
  a privileged function can replace the stored hash and/or withdraw the
  balance (so the privileged account can front-run or invalidate any
  correct answer). Classic "quiz"/"guess the answer" honeypot.
* ``payout-lure`` — a public payable function that appears to pay the
  caller the contract balance but first sends the balance to another
  (owner) address, or only pays when ``tx.origin`` equals a stored
  privileged address.
* ``hidden-owner-drain`` — a function that moves the contract balance and is
  authorised against a hard-coded address literal instead of a visible
  owner variable.
* ``transfer-blocking-token`` — an ERC-20 whose transfer path can be
  blocked per address (blacklist/bot mapping writable by a privileged
  account) or limited to privileged addresses (sell block against the
  pair / owner-only trading flag).
* ``unlimited-owner-mint`` — a privileged function mints an arbitrary
  amount with no cap check.
* ``external-log-gate`` — a bank/vault whose withdraw path (Collect /
  CashOut / Withdraw) calls an external ``Log`` / ``TransferLog`` helper's
  ``AddMessage`` (often set via constructor address or a setter). Classic
  PrivateBank / ETH_FUND family: deposits log "Put" fine, but the live
  helper can revert on "Collect" so outsiders cannot withdraw; verified
  Log source may not match the on-chain helper.

Library code that matches an upstream OpenZeppelin release by content hash
(``auditor.library_code``) is skipped. Heuristic (path/header) matches are
NOT skipped here: paths and header comments are attacker-controlled.
Limitations: regex/brace heuristics over one source set; inherited logic in
unscanned files, assembly and proxies are not followed. False positives are
possible (e.g. regulated stablecoins legitimately blacklist); review the
evidence before acting.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Dict, List, Optional, Sequence

from .base import AnalysisContext, AnalysisOutcome
from .slither_runner import collect_sol_files, relative_source_name
from .sol_parse import (FULL_BALANCE_RE, HEX_ADDR_RE, Contract, Function, all_modifiers, contracts_in,
                        privileged_guard, value_sends)
from ..model import Confidence, Epistemic, EvidenceItem, Finding, Severity, VerificationStatus

CATEGORY = "scam/honeypot"
SLUGS = ("quiz-honeypot", "payout-lure", "hidden-owner-drain", "transfer-blocking-token",
         "unlimited-owner-mint", "external-log-gate")

USER_RISK = ("RISK TO USERS WHO INTERACT: this is a scam/honeypot pattern, not an exploitable bug. "
             "Funds sent to this contract by users are likely to be lost or locked; do not interact. ")

_KECCAK_RE = re.compile(r"keccak256\s*\(")
_BLACKLIST_RE = re.compile(r"(black|bot|blocked|banned|ban\b|frozen|freeze|sniper|deny|isBad)", re.IGNORECASE)
_PAIR_RE = re.compile(r"\b(\w*[pP]air\w*|uniswapV2Pair|router)\b")
_TRADING_FLAG_RE = re.compile(r"\b(trading\w*|tradeEnabled|tradingOpen|canTrade|swapEnabled|launched|isOpen)\b",
                              re.IGNORECASE)
_CAP_RE = re.compile(r"\b(cap|maxSupply|MAX_SUPPLY|_cap|maxTotalSupply|supplyCap|MAX_TOTAL_SUPPLY)\b")
_TRANSFER_FNS = ("transfer", "transferFrom", "_transfer", "_update", "_beforeTokenTransfer", "_tokenTransfer")


def analyze(context: AnalysisContext) -> AnalysisOutcome:
    outcome = AnalysisOutcome()
    outcome.findings, outcome.evidence, outcome.notes = [], [], []
    files: List[Path] = context.source_files or []
    if not files:
        outcome.notes.append("no source files provided to honeypot analyzer")
        return outcome
    opts = getattr(context, "options", None)
    scope = opts.get("scope", "standard") if isinstance(opts, dict) else "standard"
    sol_files = collect_sol_files(files, scope=scope)
    if not sol_files:
        return outcome
    library = _library_blocks(sol_files, opts)
    parsed: Dict[Path, List[Contract]] = {}
    texts: Dict[Path, str] = {}
    for sf in sol_files:
        try:
            texts[sf] = sf.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            outcome.notes.append(f"could not read {sf.name}: {exc}")
            continue
        try:
            parsed[sf] = contracts_in(texts[sf])
        except Exception as exc:  # noqa: BLE001 - heuristics must never sink a scan
            outcome.notes.append(f"honeypot analyzer could not parse {sf.name}: {type(exc).__name__}")
    mods = all_modifiers([c for cs in parsed.values() for c in cs])
    for sf, cs in parsed.items():
        rel = relative_source_name(sf, sol_files)
        for c in cs:
            if c.name in library.get(sf, set()):
                continue
            outcome.findings.extend(scan_contract(c, texts[sf], mods, rel))
    return outcome


def _library_blocks(sol_files: Sequence[Path], opts) -> Dict[Path, set]:
    try:
        from ..library_code import SourceIndex

        main = opts.get("main_contract") if isinstance(opts, dict) else None
        root = opts.get("source_root") if isinstance(opts, dict) else None
        idx = SourceIndex(list(sol_files), Path(root) if root else None)
        # Only HASH-verified upstream code is skipped: vendored paths and OZ
        # header comments are attacker-controlled, so a heuristic match must
        # never hide a scam pattern.
        lib = {k: v for k, v in idx.library_block_names(main).items() if v.level == "hash"}
        out: Dict[Path, set] = {}
        for sf in sol_files:
            from ..library_code import _rel

            rel = _rel(sf, idx.root)
            out[sf] = {name for (r, name) in lib if r == rel}
        return out
    except Exception:  # noqa: BLE001 - fail open: scan everything
        return {}


# ---------------------------------------------------------------------------

def scan_contract(c: Contract, text: str, mods: Dict[str, str], rel: Optional[str]) -> List[Finding]:
    out: List[Finding] = []
    for fn in (_quiz(c, mods, text, rel), _payout_lure(c, mods, text, rel), _hidden_owner(c, text, rel),
               _transfer_block(c, mods, text, rel), _owner_mint(c, mods, text, rel),
               _external_log_gate(c, mods, text, rel)):
        out.extend(fn)
    return out


def _state_bytes32(c: Contract) -> List[str]:
    return re.findall(r"\bbytes32\s+(?:(?:public|private|internal|constant|immutable)\s+)*([A-Za-z_]\w*)\s*[;=]",
                      c.state_text)


def _param_names(fn: Function) -> List[str]:
    names = []
    for part in fn.params.split(","):
        toks = part.split()
        if len(toks) >= 2:
            names.append(toks[-1])
    return names


def _keccak_args(body: str) -> List[str]:
    out = []
    for m in _KECCAK_RE.finditer(body):
        depth, j = 0, m.end() - 1
        for k in range(j, len(body)):
            if body[k] == "(":
                depth += 1
            elif body[k] == ")":
                depth -= 1
                if depth == 0:
                    out.append(body[j + 1:k])
                    break
    return out


def _pays_full_balance_to_sender(fn: Function) -> bool:
    return any(s["recipient"] == "msg.sender" and FULL_BALANCE_RE.search(s["amount"] or "")
               for s in value_sends(fn.body))


def _quiz(c: Contract, mods, text, rel) -> List[Finding]:
    hashes = _state_bytes32(c)
    if not hashes:
        return []
    out = []
    for g in c.functions:
        if not g.payable or g.visibility not in ("public", "external") or privileged_guard(g, mods):
            continue
        params = _param_names(g)
        hv = [h for h in hashes if re.search(rf"\b{re.escape(h)}\b\s*==|==\s*\b{re.escape(h)}\b", g.body)]
        if not hv or not any(re.search(rf"\b{re.escape(p)}\b", a) for a in _keccak_args(g.body) for p in params):
            continue
        if not _pays_full_balance_to_sender(g):
            continue
        h = hv[0]
        changers, drainers = [], []
        for p in c.functions:
            if p is g:
                continue
            guard = privileged_guard(p, mods)
            if not guard:
                continue
            if re.search(rf"\b{re.escape(h)}\s*=(?!=)", p.body):
                changers.append(f"{p.name} ({guard})")
            if any(FULL_BALANCE_RE.search(s["amount"] or "") for s in value_sends(p.body)):
                drainers.append(f"{p.name} ({guard})")
        if not changers and not drainers:
            continue
        extras = []
        if re.search(r"msg\.sender\s*==\s*tx\.origin|tx\.origin\s*==\s*msg\.sender", g.body):
            extras.append("require(msg.sender == tx.origin) blocks contract callers (users cannot test the "
                          "payout from a contract first)")
        if re.search(r"msg\.value\s*(>|>=)", g.body):
            extras.append("a minimum msg.value is required to play")
        conf = Confidence.HIGH if changers and drainers else Confidence.MEDIUM
        desc = (USER_RISK + f"{c.name}.{g.name} looks like a quiz/guess game: it pays the whole contract balance "
                f"to the caller when keccak256(<your answer>) equals the stored hash `{h}`. But privileged "
                f"functions can " + ("replace that hash: " + ", ".join(changers) if changers else "") +
                ("; and " if changers and drainers else "") +
                ("withdraw the balance: " + ", ".join(drainers) if drainers else "") +
                ". The privileged account can therefore invalidate any correct answer or empty the pot before "
                "a winner is paid, so players' deposits are at risk. "
                + (" Additional signals: " + "; ".join(extras) + "." if extras else "")
                + " Source detector: quiz-honeypot.")
        out.append(_finding("quiz-honeypot", c, g, text, rel, desc, conf,
                            "Quiz honeypot: answer hash can be changed/drained by a privileged account"))
    return out


def _payout_lure(c: Contract, mods, text, rel) -> List[Finding]:
    out = []
    for g in c.functions:
        if not g.payable or g.visibility not in ("public", "external") or privileged_guard(g, mods):
            continue
        sends = value_sends(g.body)
        full = [s for s in sends if FULL_BALANCE_RE.search(s["amount"] or "")]
        to_sender = [i for i, s in enumerate(full) if s["recipient"] == "msg.sender"]
        to_other = [i for i, s in enumerate(full) if s["recipient"] != "msg.sender"]
        reason = None
        if to_sender and to_other and min(to_other) < max(to_sender):
            reason = (f"it first sends the whole balance to `{full[min(to_other)]['recipient']}` and only then "
                      "'pays' the caller the (now empty) balance")
        elif to_sender and re.search(r"tx\.origin\s*==\s*(?!msg\.sender)\w+|\w+\s*==\s*tx\.origin", g.body) \
                and not re.search(r"msg\.sender\s*==\s*tx\.origin|tx\.origin\s*==\s*msg\.sender", g.body):
            reason = "the payout only happens when tx.origin equals a stored privileged address"
        if not reason:
            continue
        desc = (USER_RISK + f"{c.name}.{g.name} is payable and appears to pay the caller the contract balance, "
                f"but {reason}. Callers' ETH stays with the privileged address. Source detector: payout-lure.")
        out.append(_finding("payout-lure", c, g, text, rel, desc, Confidence.MEDIUM,
                            "Payout lure: payable function pays a privileged address, not the caller"))
    return out


def _hidden_owner(c: Contract, text, rel) -> List[Finding]:
    out = []
    for g in c.functions:
        head = g.body[:400]
        m = re.search(r"(?:msg\.sender|tx\.origin)\s*==\s*(?:address\s*\(\s*)?(0x[0-9a-fA-F]{40})"
                      r"|(?:address\s*\(\s*)?(0x[0-9a-fA-F]{40})\s*\)?\s*==\s*(?:msg\.sender|tx\.origin)", head)
        if not m:
            continue
        moves = any(FULL_BALANCE_RE.search(s["amount"] or "") for s in value_sends(g.body)) or \
            re.search(r"\.transfer\s*\([^;]*balanceOf\s*\(\s*address\s*\(\s*this", g.body)
        if not moves:
            continue
        lit = m.group(1) or m.group(2)
        desc = (USER_RISK + f"{c.name}.{g.name} moves the contract's funds and is authorised against a hard-coded "
                f"address ({lit[:6]}…{lit[-4:]}) rather than a visible owner variable, so ownership "
                "renouncements or the displayed owner do not reflect who can drain it. "
                "Source detector: hidden-owner-drain.")
        out.append(_finding("hidden-owner-drain", c, g, text, rel, desc, Confidence.MEDIUM,
                            "Hidden owner: hard-coded address can drain the contract"))
    return out


def _is_token(c: Contract) -> bool:
    names = {f.name for f in c.functions}
    return bool({"transfer", "_transfer", "_update"} & names) and (
        "balanceOf" in names or re.search(r"\b_?balances\b", c.state_text) is not None)


def _transfer_block(c: Contract, mods, text, rel) -> List[Finding]:
    if not _is_token(c):
        return []
    priv_writes = []
    for p in c.functions:
        if privileged_guard(p, mods):
            priv_writes.append(p.body)
    priv_text = " ".join(priv_writes)
    for fn in c.functions:
        if fn.name not in _TRANSFER_FNS:
            continue
        checks = re.findall(r"(?:require\s*\(([^;]*)\)\s*;|if\s*\(([^)]*(?:\([^)]*\)[^)]*)*)\)\s*(?:\{\s*)?revert)",
                            fn.body)
        conds = [a or b for a, b in checks]
        signals = []
        for cond in conds:
            bl = re.search(r"!\s*(\w+)\s*\[\s*(?:from|to|sender|recipient|_from|_to|msg\.sender)\s*\]", cond)
            if bl and _BLACKLIST_RE.search(bl.group(1)) and re.search(rf"\b{re.escape(bl.group(1))}\s*\[", priv_text):
                signals.append(("blacklist", f"transfers revert for addresses in `{bl.group(1)}`, which a "
                                             "privileged account can set"))
            if _PAIR_RE.search(cond) and re.search(r"\b(owner|_owner|owner\s*\(\s*\)|isExcluded\w*|whitelist\w*|"
                                                   r"_isExcluded\w*|isWhitelisted)\b", cond):
                signals.append(("sell-block", "transfers to/from the trading pair are restricted to "
                                              "privileged/whitelisted addresses (users may be unable to sell)"))
            flag = _TRADING_FLAG_RE.search(cond)
            if flag and re.search(r"\b(owner|_owner|owner\s*\(\s*\)|isExcluded\w*|whitelist\w*|_isExcluded\w*)\b",
                                  cond) and re.search(rf"\b{re.escape(flag.group(1))}\s*=", priv_text):
                signals.append(("owner-only-flag", f"transfers require `{flag.group(1)}` (set by a privileged "
                                                   "account) unless the sender is privileged"))
        if not signals:
            continue
        kinds = sorted({k for k, _ in signals})
        conf = Confidence.MEDIUM if ("sell-block" in kinds or "owner-only-flag" in kinds) else Confidence.LOW
        desc = (USER_RISK + f"{c.name}.{fn.name}: " + "; ".join(sorted({t for _, t in signals})) +
                ". Holders may be unable to transfer or sell while privileged addresses can. Note: some "
                "regulated tokens blacklist legitimately; review who controls the list. "
                "Source detector: transfer-blocking-token.")
        return [_finding("transfer-blocking-token", c, fn, text, rel, desc, conf,
                         "Transfer-blocking token: privileged account can stop holders from selling")]
    return []


def _owner_mint(c: Contract, mods, text, rel) -> List[Finding]:
    if not _is_token(c) and "_mint" not in text:
        return []
    mint_override = next((f for f in c.functions if f.name in ("_mint", "_update")), None)
    capped_globally = bool(mint_override and _CAP_RE.search(mint_override.body))
    out = []
    for fn in c.functions:
        if fn.name in ("_mint", "constructor") or fn.visibility not in ("public", "external"):
            continue
        guard = privileged_guard(fn, mods)
        if not guard or not re.search(r"\b_mint\s*\(", fn.body):
            continue
        from .sol_parse import is_vault_claim_mint
        if is_vault_claim_mint(fn, c):
            continue  # ERC-4626/7540 claim of caller's own settled request
        params = _param_names(fn)
        m = re.search(r"\b_mint\s*\(\s*[^,]+,\s*([^)]+)\)", fn.body)
        if not m or not any(re.search(rf"\b{re.escape(p)}\b", m.group(1)) for p in params):
            continue
        if capped_globally or _CAP_RE.search(fn.body):
            continue
        desc = (USER_RISK + f"{c.name}.{fn.name} lets a privileged caller ({guard}) mint an arbitrary amount "
                "with no supply cap, so the supply can be inflated and buyers diluted or dumped on. "
                "Source detector: unlimited-owner-mint.")
        out.append(_finding("unlimited-owner-mint", c, fn, text, rel, desc, Confidence.MEDIUM,
                            "Unlimited owner mint: privileged account can mint without a cap"))
    return out



_WITHDRAW_FN_RE = re.compile(r"^(Collect|CashOut|Withdraw|withdraw|collect|cashOut|cashout)$")
_ADD_MESSAGE_RE = re.compile(r"(\w+)\s*\.\s*AddMessage\s*\(")
_LOG_STATE_RE = re.compile(
    r"\b((?:Transfer)?Log\w*)\s+(?:(?:public|private|internal|constant|immutable)\s+)*([A-Za-z_]\w*)\s*[;=]"
)
_COLLECT_STR_RE = re.compile(r"['\"]Collect['\"]|['\"]CashOut['\"]|['\"]Withdraw['\"]")


def _log_helper_vars(c: Contract) -> Dict[str, str]:
    """Map state-var name → declared type for Log / TransferLog helpers."""
    out: Dict[str, str] = {}
    for m in _LOG_STATE_RE.finditer(c.state_text):
        out[m.group(2)] = m.group(1)
    return out


def _log_assigned_from_address(c: Contract, var: str) -> bool:
    """True if constructor or a Set*Log* function assigns ``var`` from an address."""
    for fn in c.functions:
        name = fn.name or ""
        if name != "constructor" and not re.search(r"(?i)set.*log|change.*log", name):
            continue
        if not re.search(rf"\b{re.escape(var)}\s*=", fn.body):
            continue
        if "address" in (fn.params or "") or re.search(r"\bLog\w*\s*\(", fn.body):
            return True
    return False


def _external_log_gate(c: Contract, mods, text, rel) -> List[Finding]:
    """PrivateBank / ETH_FUND / Log family: withdraw path gated by external Log.AddMessage."""
    log_vars = _log_helper_vars(c)
    out: List[Finding] = []
    seen = set()
    for g in c.functions:
        if g.visibility not in ("public", "external"):
            continue
        if not _WITHDRAW_FN_RE.match(g.name or ""):
            continue
        m = _ADD_MESSAGE_RE.search(g.body)
        if not m:
            continue
        callee = m.group(1)
        if log_vars and callee not in log_vars:
            if not re.search(r"(?i)log", callee):
                continue
        key = (c.name, g.name, callee)
        if key in seen:
            continue
        seen.add(key)
        assigned = _log_assigned_from_address(c, callee)
        has_str = bool(_COLLECT_STR_RE.search(g.body))
        if assigned and (has_str or callee in log_vars):
            conf = Confidence.HIGH
        elif assigned or callee in log_vars:
            conf = Confidence.MEDIUM
        else:
            conf = Confidence.LOW
        typ = log_vars.get(callee, "Log")
        extras = []
        if assigned:
            extras.append(
                f"`{callee}` is assigned from a constructor/setter address "
                "(runtime helper can differ from verified source)"
            )
        if has_str:
            extras.append("the withdraw path passes a Collect/CashOut-style label into AddMessage")
        for d in c.functions:
            if re.match(r"(?i)deposit|put", d.name or "") and _ADD_MESSAGE_RE.search(d.body or ""):
                extras.append("deposit path also calls AddMessage (Put/Collect log pair)")
                break
        desc = (
            USER_RISK + f"{c.name}.{g.name} calls an external `{typ}` helper (`{callee}.AddMessage`) on the "
            "withdraw path. In the classic PrivateBank / ETH_FUND / Log honeypot family the helper accepts "
            "deposit (\"Put\") marks but reverts on withdraw (\"Collect\"/\"CashOut\"), trapping user deposits; "
            "the verified Log source may also not match the on-chain helper bytecode. "
            + ("Signals: " + "; ".join(extras) + ". " if extras else "")
            + "Verify the live helper address from storage and compare bytecode before treating the "
            "reentrancy/CEI shape as exploitable. Source detector: external-log-gate."
        )
        out.append(_finding(
            "external-log-gate", c, g, text, rel, desc, conf,
            "External Log gate on withdraw: helper can trap deposits (PrivateBank/Log family)",
        ))
    return out


def _finding(slug: str, c: Contract, fn: Function, text: str, rel: Optional[str], desc: str,
             conf: Confidence, headline: str) -> Finding:
    start = text.rfind("function", 0, fn.body_start)
    excerpt = text[start if start >= 0 else fn.body_start:fn.body_end + 1][:1200]
    end_line = text.count("\n", 0, fn.body_end) + 1
    return Finding(
        title=f"{slug} in {c.name}.{fn.name}: {headline}",
        description=desc,
        category=CATEGORY,
        severity=Severity.HIGH,
        confidence=conf,
        verification_status=VerificationStatus.UNVERIFIED,
        affected_contract=c.name,
        affected_function=fn.name,
        affected_lines=list(range(fn.line, min(end_line, fn.line + 40) + 1)),
        affected_file=rel,
        source="source-analysis",
        tool="honeypot",
        impact="Users who send funds or buy the token can lose them; the contract itself is not 'hacked'.",
        exploitability="Not an exploitable bug for outsiders: the risk is to users who interact.",
        likelihood="Pattern match (heuristic); review the evidence.",
        false_positive_risk="Heuristic source pattern; legitimate designs can share parts of it.",
        assumptions=["Static source pattern only; privileged account behaviour is inferred, not observed."],
        remediation=("Do not interact with or fund this contract. If this is your own contract, remove the "
                     "privileged ability to change the outcome or withdraw user deposits."),
        evidence=[EvidenceItem(source="source-analysis", artifact_type="source_excerpt", excerpt=excerpt,
                               epistemic=Epistemic.FACT, tool="honeypot")],
    )
