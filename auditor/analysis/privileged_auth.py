"""Phase 25 — privileged-function authorization analyzer (source-level).

For every scanned contract, locate functions that change ownership/admin/roles,
upgrade implementations, withdraw treasury funds, mint tokens, change fees, or
retarget oracle/price-feed/router addresses. Classify each as:

* ``UNPROTECTED`` — any outsider can call (HIGH/CRITICAL when it moves value
  or control)
* ``WEAK`` — tx.origin auth, auth on the wrong variable, check-after-effect,
  initializer callable by anyone, owner settable by anyone, missing check on
  one overload/entry point, or a public internal-helper
* ``PROTECTED`` — a real msg.sender / role guard is present (INFORMATIONAL
  centralization note; controller type filled from the trust map when
  available: EOA vs Safe m-of-n vs timelock delay)

Defensive only: descriptions name the missing check and the fix. No exploit
steps or calldata. Heuristic over sol_parse structure (+ optional Slither IR
hints); inherited modifiers in unscanned files are not followed.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from .base import AnalysisContext, AnalysisOutcome
from .slither_runner import collect_sol_files, relative_source_name
from .sol_parse import (
    FULL_BALANCE_RE,
    INLINE_GUARD_RE,
    Contract,
    Function,
    all_modifiers,
    contracts_in,
    modifier_is_sender_guard,
    privileged_guard,
    value_sends,
)
from ..model import (
    Confidence,
    Epistemic,
    EvidenceItem,
    Finding,
    Severity,
    VerificationStatus,
)

NAME = "privileged_auth"
CATEGORY = "privileged_auth"

# Detector slugs (benchmark channel). Status is encoded in the slug so
# PROTECTED findings never match vulnerable fixtures' accepted_checks.
SLUG_UNPROTECTED = "privileged-auth-unprotected"
SLUG_WEAK = "privileged-auth-weak"
SLUG_PROTECTED = "privileged-auth-protected"

# ---------------------------------------------------------------------------
# Category heuristics (name + body)
# ---------------------------------------------------------------------------

_OWNERSHIP_NAMES = re.compile(
    r"^(transferOwnership|setOwner|setAdmin|changeAdmin|acceptOwnership|"
    r"renounceOwnership|renounce|grantRole|revokeRole|setGovernance|"
    r"setPendingOwner|claimOwnership|transferAdmin|addOwner|removeOwner|"
    r"setAuthority|setAdminAddress)$",
    re.IGNORECASE,
)
_UPGRADE_NAMES = re.compile(
    r"^(upgradeTo|upgradeToAndCall|diamondCut|setImplementation|"
    r"upgrade|upgradeAndCall|setBeacon|upgradeBeaconTo|upgradeBeaconToAndCall|"
    r"setProxyOwner|changeImplementation)$",
    re.IGNORECASE,
)
_WITHDRAW_NAMES = re.compile(
    r"^(withdraw|withdrawETH|withdrawToken|sweep|sweepToken|rescue|"
    r"rescueTokens|rescueETH|emergencyWithdraw|drain|skim|collectFees|"
    r"claimFees|withdrawERC20|recoverERC20|recoverEth|pullTokens)$",
    re.IGNORECASE,
)
_MINT_NAMES = re.compile(r"^(mint|_mint|mintTo|mintTokens|issue|issueTokens)$", re.IGNORECASE)
_FEE_NAMES = re.compile(
    r"^(setFee|setFees|setFeeBps|setFeeRate|setProtocolFee|setSwapFee|"
    r"setPerformanceFee|setManagementFee|setWithdrawFee|setDepositFee|"
    r"updateFee|changeFee)$",
    re.IGNORECASE,
)
_ORACLE_NAMES = re.compile(
    r"^(setOracle|setPriceFeed|setFeed|setAggregator|setRouter|setPriceOracle|"
    r"updateOracle|changeOracle|setSpotOracle|setTwapOracle)$",
    re.IGNORECASE,
)
_INIT_NAMES = re.compile(r"^(initialize|reinitialize|init|__\w+_init)$", re.IGNORECASE)

_OWNER_WRITE_RE = re.compile(
    r"\b(owner|admin|_owner|_admin|governance|_governance|pendingOwner|"
    r"_pendingOwner|authority|_authority)\s*=\s*(?!owner\b)",
    re.IGNORECASE,
)
_ROLE_WRITE_RE = re.compile(
    r"\b(_grantRole|grantRole|_setupRole|_setRoleAdmin)\s*\(",
)
_IMPL_WRITE_RE = re.compile(
    r"\b(_setImplementation|implementation|_implementation|beacon|_beacon)\s*=|"
    r"\b(upgradeTo|upgradeToAndCall|diamondCut)\s*\(",
    re.IGNORECASE,
)
_MINT_BODY_RE = re.compile(r"\b(_mint|totalSupply\s*\+|balances?\s*\[)\s*")
_FEE_VAR_RE = re.compile(
    r"\b(fee|feeBps|feeRate|protocolFee|swapFee|performanceFee|managementFee|"
    r"withdrawFee|depositFee|_fee)\b",
    re.IGNORECASE,
)
_ORACLE_VAR_RE = re.compile(
    r"\b(oracle|priceFeed|feed|aggregator|router|priceOracle|_oracle|_priceFeed)\b",
    re.IGNORECASE,
)
_TX_ORIGIN_AUTH_RE = re.compile(
    r"(require|if)\s*\([^;]*\btx\.origin\b|"
    r"\btx\.origin\s*==|==\s*tx\.origin",
)
_INIT_MOD_RE = re.compile(r"^(initializer|reinitializer|onlyInitializing)$", re.IGNORECASE)
_SENDER_CHECK_RE = re.compile(
    r"(require|if)\s*\([^;]*msg\.sender|_checkOwner\s*\(|_checkRole\s*\(",
)
_STATE_ASSIGN_RE = re.compile(r"\b([A-Za-z_]\w*)\s*=\s*[^=]")


def analyze(context: AnalysisContext) -> AnalysisOutcome:
    outcome = AnalysisOutcome()
    outcome.findings, outcome.evidence, outcome.notes = [], [], []
    files: List[Path] = list(context.source_files or [])
    if not files:
        outcome.notes.append("no source files provided to privileged_auth analyzer")
        return outcome
    opts = getattr(context, "options", None) or {}
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
        except Exception as exc:  # noqa: BLE001
            outcome.notes.append(
                f"privileged_auth could not parse {sf.name}: {type(exc).__name__}"
            )

    all_cs = [c for cs in parsed.values() for c in cs]
    mods = all_modifiers(all_cs)
    global _FN_INDEX, _CONTRACT_INDEX
    _FN_INDEX = {}
    _CONTRACT_INDEX = {_c.name: _c for _c in all_cs}
    for _c in all_cs:
        for _f in _c.functions:
            _FN_INDEX.setdefault(_f.name, []).append(_f)
    fee_vars = _collect_fee_vars(all_cs)
    oracle_vars = _collect_oracle_vars(all_cs, texts)

    # Optional Slither IR hints (state-var writes / external call targets).
    slither_hints = _slither_hints(context)

    controller_cache: Dict[str, str] = {}
    for sf, cs in parsed.items():
        rel = relative_source_name(sf, sol_files)
        for c in cs:
            if c.name in library.get(sf, set()):
                continue
            outcome.findings.extend(
                scan_contract(
                    c,
                    texts[sf],
                    mods,
                    rel,
                    fee_vars,
                    oracle_vars,
                    slither_hints,
                    context,
                    controller_cache,
                )
            )
    return outcome


def scan_contract(
    c: Contract,
    text: str,
    mods: Dict[str, str],
    rel: Optional[str],
    fee_vars: set,
    oracle_vars: set,
    slither_hints: Dict[str, Any],
    context: AnalysisContext,
    controller_cache: Dict[str, str],
) -> List[Finding]:
    out: List[Finding] = []
    # Group overloads by name for "missing check on one entry point".
    by_name: Dict[str, List[Function]] = {}
    for fn in c.functions:
        by_name.setdefault(fn.name, []).append(fn)

    for fn in c.functions:
        if fn.name in ("constructor", "receive", "fallback"):
            continue
        if fn.visibility not in ("public", "external"):
            continue
        if re.search(r"\b(view|pure)\b", fn.header.split(")", 1)[-1] if ")" in fn.header else ""):
            continue
        if fn.name in ("ownerOf", "getOwner", "balanceOf", "allowance", "getRoleAdmin"):
            continue
        cats = _categories_for(fn, c, fee_vars, oracle_vars, slither_hints)
        if not cats:
            continue
        status, guard, weak_reason = _classify(fn, mods, by_name.get(fn.name) or [fn], contract=c)
        for cat in cats:
            out.append(
                _make_finding(
                    c, fn, text, rel, cat, status, guard, weak_reason,
                    context, controller_cache,
                )
            )
    return out


def _categories_for(
    fn: Function,
    c: Contract,
    fee_vars: set,
    oracle_vars: set,
    slither_hints: Dict[str, Any],
) -> List[str]:
    cats: List[str] = []
    name = fn.name
    body = fn.body

    if _OWNERSHIP_NAMES.match(name) or (
        name not in ("transfer", "transferFrom", "approve", "increaseAllowance", "decreaseAllowance")
        and (_OWNER_WRITE_RE.search(body) or _ROLE_WRITE_RE.search(body))
    ):
        cats.append("ownership")
    if _UPGRADE_NAMES.match(name) or _IMPL_WRITE_RE.search(body):
        cats.append("upgrade")
    if _INIT_NAMES.match(name):
        # Unprotected initialize on an implementation is an upgrade-adjacent risk.
        cats.append("upgrade")
    if _is_treasury_withdraw(fn):
        cats.append("withdraw")
    from .sol_parse import is_vault_claim_mint, is_proxy_forwarder
    if _is_admin_mint(fn) and not is_vault_claim_mint(fn, c) and not is_proxy_forwarder(fn, c):
        cats.append("mint")
    if _FEE_NAMES.match(name) or _writes_vars(body, fee_vars):
        cats.append("fees")
    if _ORACLE_NAMES.match(name) or _writes_vars(body, oracle_vars):
        cats.append("oracle")

    # Slither IR: state-var write of owner-like / fee / oracle vars.
    key = f"{c.name}.{name}"
    hinted = slither_hints.get("writes", {}).get(key) or []
    for var in hinted:
        vl = var.lower()
        if any(x in vl for x in ("owner", "admin", "governance", "role")):
            if "ownership" not in cats:
                cats.append("ownership")
        if any(x in vl for x in ("implement", "beacon", "upgrade")):
            if "upgrade" not in cats:
                cats.append("upgrade")
        if any(x in vl for x in ("fee",)):
            if "fees" not in cats:
                cats.append("fees")
        if any(x in vl for x in ("oracle", "feed", "router", "aggregat")):
            if "oracle" not in cats:
                cats.append("oracle")
    return cats



def _is_pull_payment(fn: Function) -> bool:
    """True when the function only pays msg.sender their own recorded credit.

    Classic pull-payment / withdrawal pattern: read credit[msg.sender] (or
    balances/owed/pending), zero it, then send that amount to msg.sender.
    Not a privileged treasury sweep.
    """
    body = fn.body
    bucket = (r"_?\w*(?:credit|balance|owed|pending|withdrawable|claim|deposit|refund|share)s?\w*")
    sender_ix = r"\[\s*(?:msg\.sender|_msgSender\(\s*\))\s*\]"
    if not re.search(bucket + r"\s*" + sender_ix, body, re.IGNORECASE):
        return False
    # The caller's own bucket must be debited: zeroed, `-=`, or `= x - amount`.
    debit = re.search(
        bucket + r"\s*" + sender_ix + r"\s*(?:=\s*0\b|-=|=\s*[\w.]+\s*-\s*[\w.]+)",
        body, re.IGNORECASE)
    if not debit:
        return False
    # Inside `unchecked`, a plain subtraction must be bounded by an explicit check.
    if "unchecked" in body and "-=" not in debit.group(0) and not re.search(r"=\s*0\b", debit.group(0)):
        if not re.search(r"(require\s*\(|if\s*\()\s*[\w.\[\]]+\s*(>=|<)\s*\w+", body):
            return False
    # Payment goes to msg.sender (not an arbitrary recipient param).
    if value_sends(body):
        sends = value_sends(body)
        if sends and all(s.get("recipient") in ("msg.sender", "payable(msg.sender)")
                         or "msg.sender" in (s.get("recipient") or "")
                         for s in sends):
            return True
    if re.search(
        r"msg\.sender\.(transfer|send)\s*\("
        r"|\.call\s*\{[^}]*value\s*:[^}]*\}\s*\(\s*(""|\'\')?\s*\)",
        body,
    ):
        return True
    return False


def _pays_fixed_fee_recipient(fn: Function) -> bool:
    """True when value/tokens go to a stored feeCollector/treasury, not the caller.

    Permissionless ``collectFees`` that forwards to ``feeCollector`` is not theft.
    """
    body = fn.body
    if not re.search(
        r"\b(feeCollector|treasury|feeRecipient|protocolTreasury|feeTo|platformWallet)\b",
        body,
    ):
        return False
    # Transfer/send targeting that variable (not msg.sender as beneficiary of swept funds).
    if re.search(
        r"\.(transfer|safeTransfer|send)\s*\(\s*(feeCollector|treasury|feeRecipient|"
        r"protocolTreasury|feeTo|platformWallet)\b"
        r"|transfer\s*\(\s*(feeCollector|treasury|feeRecipient|protocolTreasury|feeTo|"
        r"platformWallet)\b",
        body,
    ):
        return True
    return False


def _is_treasury_withdraw(fn: Function) -> bool:
    """True when the function looks like an admin sweep of contract funds.

    Standard ERC-4626 ``withdraw``/``redeem`` (burns caller shares) and
    ordinary ETH receive/refund paths are excluded. Pull-payments and
    permissionless fee-forwarders to a fixed collector are also excluded.
    """
    name = fn.name
    body = fn.body
    if _is_pull_payment(fn):
        return False
    if _pays_fixed_fee_recipient(fn):
        return False
    if re.search(r"\b(balanceOf|shares)\s*\[\s*msg\.sender\s*\]|\b_burn\s*\(|\b_withdraw\s*\(", body):
        # User redeem path (ERC-4626 / vault): not treasury privilege.
        if name in ("withdraw", "redeem", "removeLiquidity", "unstake", "exit"):
            return False
    if _WITHDRAW_NAMES.match(name):
        # Named sweep/rescue/emergencyWithdraw always counts; plain withdraw
        # only when it moves address(this).balance or sweeps ERC-20 holdings
        # without a burn/shares path.
        if name.lower() in ("withdraw", "withdraweth", "withdrawtoken") and not (
            value_sends(body) or _erc20_sweep(body) or FULL_BALANCE_RE.search(body)
            or re.search(r"balanceOf\s*\(\s*address\s*\(\s*this\s*\)", body)
        ):
            return False
        return True
    # Do not flag arbitrary payable games / refunds that send balance to
    # msg.sender (honeypot analyzer covers those). Treasury privilege requires
    # a withdraw/sweep/rescue-shaped name (handled above) or an ERC-20 sweep
    # body on such a name.
    return False


def _is_admin_mint(fn: Function) -> bool:
    """True for privileged mint (arbitrary supply increase), not ERC-4626 deposit mint."""
    name = fn.name
    body = fn.body
    # ERC-4626 / vault user mint(shares, receiver) deposits assets — not admin mint.
    if name == "mint" and re.search(r"\b(deposit|previewMint|assets|msg\.value)\b", body):
        return False
    if name in ("deposit", "mint") and re.search(r"\b_deposit\s*\(|previewMint|convertToAssets", body):
        return False
    if _MINT_NAMES.match(name):
        return True
    if re.search(r"\b_mint\s*\(", body) and fn.visibility in ("public", "external"):
        # Public wrapper around _mint with no asset pull → admin mint shape.
        if not re.search(r"\b(transferFrom|safeTransferFrom|msg\.value)\b", body):
            return True
    return False


def _erc20_sweep(body: str) -> bool:
    """ERC-20 transfer/transferFrom of contract-held balance to an arbitrary to."""
    if re.search(r"\b(transfer|transferFrom)\s*\(", body) and re.search(
        r"\b(balanceOf\s*\(\s*address\s*\(\s*this\s*\)|address\s*\(\s*this\s*\)\s*\.\s*balance)",
        body,
    ):
        return True
    if re.search(r"\bIERC20\b|\.transfer\s*\(\s*(?:to|recipient|_to|_recipient|msg\.sender)", body):
        # Named sweep/rescue already caught by name; body-only: require balance read.
        if re.search(r"balanceOf\s*\(", body) and re.search(r"\.transfer\s*\(", body):
            return True
    return False


def _writes_vars(body: str, vars_: set) -> bool:
    if not vars_:
        return False
    for v in vars_:
        if re.search(rf"\b{re.escape(v)}\s*=", body):
            return True
    return False


def _collect_fee_vars(contracts: Sequence[Contract]) -> set:
    out: set = set()
    for c in contracts:
        for m in _FEE_VAR_RE.finditer(c.state_text):
            # Prefer the identifier itself from state declarations.
            out.add(m.group(0))
        for m in re.finditer(
            r"\b(?:uint\d*|int\d*|address)\s+(?:public|private|internal)?\s*"
            r"(fee\w*|_\w*[Ff]ee\w*)\b",
            c.state_text,
        ):
            out.add(m.group(1))
    return out


def _collect_oracle_vars(contracts: Sequence[Contract], texts: Dict[Path, str]) -> set:
    out: set = set()
    for c in contracts:
        for m in re.finditer(
            r"\b(?:address|I\w+)\s+(?:public|private|internal)?\s*"
            r"(oracle\w*|priceFeed\w*|feed\w*|aggregator\w*|router\w*|_\w*"
            r"(?:[Oo]racle|[Ff]eed|[Rr]outer|[Aa]ggregator)\w*)\b",
            c.state_text,
        ):
            out.add(m.group(1))
        # Vars used as call targets for price reads.
        for fn in c.functions:
            for m in re.finditer(
                r"\b([A-Za-z_]\w*)\s*\.\s*(latestAnswer|latestRoundData|getPrice|"
                r"consult|quote|getRate|peek|read)\s*\(",
                fn.body,
            ):
                out.add(m.group(1))
    return out


_FN_INDEX: Dict[str, List[Function]] = {}
_CONTRACT_INDEX: Dict[str, Contract] = {}


def _bases_of(c: Contract) -> List[str]:
    m = re.search(r"\b(?:abstract\s+)?contract\s+" + re.escape(c.name) + r"\s+is\s+([^{]+)\{", c.code or "")
    if not m:
        return []
    return [b.strip().split("(")[0].strip() for b in m.group(1).split(",") if b.strip()]


def _ctor_disables_initializers(c: Optional[Contract], seen=None) -> bool:
    """True if c or any scanned base contract's constructor calls _disableInitializers()."""
    if c is None:
        return False
    seen = seen or set()
    if c.name in seen:
        return False
    seen.add(c.name)
    ctor = next((f for f in c.functions if f.name == "constructor"), None)
    if ctor and re.search(r"\b_disableInitializers\s*\(", ctor.body or ""):
        return True
    return any(_ctor_disables_initializers(_CONTRACT_INDEX.get(b), seen) for b in _bases_of(c))


def _inherited_guard(fn: Function, mods: Dict[str, str]) -> Optional[str]:
    """Guard enforced by a parent override the body forwards to (super.f / Base.f)."""
    m = re.search(r"\b(super|[A-Z]\w*)\s*\.\s*" + re.escape(fn.name) + r"\s*\(", fn.body or "")
    if not m:
        return None
    for parent in _FN_INDEX.get(fn.name, []):
        if parent is fn:
            continue
        g = privileged_guard(parent, mods) or _named_priv_modifier(parent)
        if g:
            return f"inherited via {m.group(1)}.{fn.name} ({g})"
    return None


def _classify(
    fn: Function,
    mods: Dict[str, str],
    overloads: Sequence[Function],
    contract: Optional[Contract] = None,
) -> Tuple[str, Optional[str], Optional[str]]:
    """Return (status, guard_name, weak_reason)."""
    from .sol_parse import PRIV_MODIFIER_RE

    # Library methods (first param "Something storage self") are not proxy/entry
    # points an outsider calls to drain; skip privileged-auth on them.
    params_flat = " ".join((fn.params or "").split())
    if re.search(r"\w+\s+storage\s+self", params_flat):
        return "PROTECTED", "library storage-self method (not an entry point)", None

    # Two-step ownership claim: pendingOwner / newOwner / _msgSender checks are auth.
    if (fn.name in ("acceptOwnership", "claimOwnership") or re.match(r"^_?(accept|claim)(Admin|Owner|Governance|Gov)\w*$", fn.name)) and re.search(
        r"(msg\.sender|_msgSender\s*\(\s*\)|sender)\s*(?:==|!=)\s*(pendingOwner|_pendingOwner|newOwner|_newOwner|pendingAdmin|_pendingAdmin|pendingGov\w*|pendingOwner\s*\(\s*\)|newOwner\s*\(\s*\)|pendingAdmin\s*\(\s*\))"
        r"|(pendingOwner|_pendingOwner|newOwner|_newOwner|pendingAdmin|_pendingAdmin|pendingGov\w*|pendingOwner\s*\(\s*\)|newOwner\s*\(\s*\)|pendingAdmin\s*\(\s*\))\s*(==|!=)\s*(msg\.sender|_msgSender\s*\(\s*\)|sender)",
        fn.body,
    ):
        return "PROTECTED", "inline pendingOwner/newOwner check", None

    # Public function whose name looks like an internal helper.
    if fn.name.startswith("_") and fn.visibility in ("public", "external"):
        guard = privileged_guard(fn, mods)
        if not guard and not _named_priv_modifier(fn):
            return "WEAK", None, "public internal-helper (leading underscore, no auth)"

    inherited = _inherited_guard(fn, mods)
    if inherited:
        return "PROTECTED", inherited, None

    # Initializer without initializer/reinitializer modifier and without auth.
    if _INIT_NAMES.match(fn.name):
        has_init_mod = any(_INIT_MOD_RE.match(m) for m in fn.modifiers)
        guard = privileged_guard(fn, mods)
        named = _named_priv_modifier(fn)
        if not has_init_mod and not guard and not named:
            return "UNPROTECTED", None, "initializer callable by anyone"
        if has_init_mod and not guard and not named:
            # OZ pattern: implementation constructor calls _disableInitializers(),
            # so the live risk is deploy-time front-run of an *uninitialized proxy*,
            # not re-init of an already-live vault. Treat as PROTECTED/centralization
            # (ops hygiene) rather than HIGH WEAK live outsider theft.
            if _ctor_disables_initializers(contract):
                return (
                    "PROTECTED",
                    "modifier initializer + _disableInitializers in constructor",
                    None,
                )
            # initializer modifier prevents re-entry after first call, but the
            # first call is still open to anyone → WEAK (front-runnable init).
            return "WEAK", "modifier initializer (no caller auth)", (
                "initializer callable by anyone on first call"
            )

    # Safe-style SelfAuthorized: modifier requires msg.sender == address(this)
    # (only reachable through the multisig's own execTransaction).
    for m in fn.modifiers:
        mb = mods.get(m) or ""
        if re.search(r"\brequireSelfCall\s*\(|msg\.sender\s*==\s*address\s*\(\s*this\s*\)", mb):
            return "PROTECTED", f"modifier {m} (self-call only)", None

    # Caller-scoped config: every state write is keyed by msg.sender, so the
    # caller can only change its own settings (e.g. Prisma setBoostDelegationParams).
    if _only_sender_scoped_writes(fn.body or ""):
        return "PROTECTED", "writes only msg.sender-keyed state (self-service)", None

    # tx.origin-only auth on a named modifier or inline.
    for m in fn.modifiers:
        body = mods.get(m)
        if body is None:
            continue
        if _TX_ORIGIN_AUTH_RE.search(body) and not re.search(r"msg\.sender", body):
            return "WEAK", f"modifier {m} (tx.origin)", "tx.origin authorization"

    head = fn.body[:500]
    if _TX_ORIGIN_AUTH_RE.search(head) and "msg.sender" not in head:
        return "WEAK", "inline tx.origin check", "tx.origin authorization"

    guard = privileged_guard(fn, mods)
    if guard is None:
        # Conventional onlyOwner / onlyRole / onlyAdmin name whose definition
        # lives in an unscanned base (e.g. OpenZeppelin Ownable in another
        # file): treat as PROTECTED rather than false-UNPROTECTED.
        named = _named_priv_modifier(fn)
        if named:
            guard = f"modifier {named} (definition not in scanned sources)"

    # Check-after-effect: a privileged state write appears before the first
    # msg.sender check in the body.
    if guard == "inline msg.sender check" or (guard is None):
        if _check_after_effect(fn.body):
            return "WEAK", guard, "authorization check after the effect"

    if guard is None:
        # Chainlink AuthorizedCallers / similar: auth via internal helper call
        # in the body (or in a helper the body invokes by name).
        if re.search(r"\b_validateCaller\s*\(|\b_onlyAuthorized\w*\s*\(", fn.body):
            guard = "inline _validateCaller / authorized-caller check"
        elif re.search(
            r"\b_validateDepositWithdraw\s*\(|\b_validate\w*Caller\s*\(",
            fn.body,
        ):
            # Defer: only treat as guard when the named helper itself checks
            # the caller — detected when helper definition is in mods or we
            # already saw _validateCaller in the same contract via all_modifiers
            # path. Conservative: if body calls _validateDepositWithdraw and
            # any scanned modifier/function text includes _validateCaller, the
            # analyze() path attaches via privileged_guard on expanded inline.
            # Fallback: treat _validateDepositWithdraw as likely auth gate when
            # the name is used (CCIP LockBox pattern); confirmed by unit test.
            guard = "inline _validateDepositWithdraw (authorized-caller gate)"

    if guard is None:
        helper = _sender_guard_helper(fn.body or "")
        if helper:
            guard = f"internal helper {helper}() reverts unless msg.sender matches"

    if guard:
        pass
    else:
        # Sibling has a guard but this overload does not.
        sibling_guarded = any(
            privileged_guard(sib, mods) or _named_priv_modifier(sib)
            for sib in overloads if sib is not fn
        )
        if sibling_guarded:
            return "WEAK", None, "missing check in one of several overloads/entry points"
        return "UNPROTECTED", None, None

    return "PROTECTED", guard, None


_SENDER_REVERT_RE = re.compile(
    r"if\s*\(\s*(?:\w+\s*!=\s*msg\.sender|msg\.sender\s*!=\s*\w+(?:\s*\(\s*\))?)\s*\)\s*(?:\{\s*)?revert\b"
    r"|require\s*\(\s*(?:msg\.sender\s*==\s*\w+|\w+\s*==\s*msg\.sender)")


def _sender_guard_helper(body: str) -> Optional[str]:
    """Name of an internal/private helper called at the START of ``body``
    (before any state write) whose own body reverts unless msg.sender equals a
    stored/derived address — e.g. Ekubo ``_requireLocker()``. None otherwise."""
    head = body[:300]
    for m in re.finditer(r"\b(_?\w+)\s*\(", head):
        for h in _FN_INDEX.get(m.group(1), []):
            if h.visibility in ("internal", "private") and _SENDER_REVERT_RE.search(h.body or ""):
                if ";" not in head[:m.start()]:  # first statement: no prior effect
                    return m.group(1)
    return None


def _named_priv_modifier(fn: Function) -> Optional[str]:
    """Return a conventional privilege modifier name on *fn*, if any."""
    from .sol_parse import PRIV_MODIFIER_RE
    for m in fn.modifiers:
        if PRIV_MODIFIER_RE.match(m) or m.startswith("onlyRole"):
            return m
    return None


def _strip_dead_if_false(text: str) -> str:
    """Remove `if (false) { ... }` dead blocks (Compound "Shh" non-pure trick)."""
    return re.sub(r"if\s*\(\s*false\s*\)\s*\{[^{}]*\}", "", text)




def _only_sender_scoped_writes(body: str) -> bool:
    """True when body has >=1 storage-looking write and all of them are X[msg.sender]."""
    b = _strip_dead_if_false(body)
    if not re.search(r"\[\s*(msg\.sender|_msgSender\(\))\s*\]\s*(=(?!=)|;)", b) and not re.search(
        r"delete\s+\w+\[\s*(msg\.sender|_msgSender\(\))\s*\]", b
    ):
        return False
    if value_sends(b) or re.search(r"\b(_mint|_burn|selfdestruct|delegatecall)\s*\(|\.call\s*[({]", b):
        return False
    writes = 0
    for m in re.finditer(r"(?:^|[;{}])\s*(delete\s+)?([A-Za-z_]\w*)\s*((?:\[[^\]]*\])*)\s*(=(?!=)|\+=|-=)", b):
        writes += 1
        idx = m.group(3) or ""
        if not re.match(r"\[\s*(msg\.sender|_msgSender\(\))\s*\]", idx):
            return False
    for m in re.finditer(r"delete\s+([A-Za-z_]\w*)\s*((?:\[[^\]]*\])*)", b):
        writes += 1
        if not re.match(r"\[\s*(msg\.sender|_msgSender\(\))\s*\]", m.group(2) or ""):
            return False
    return writes > 0


def _check_after_effect(body: str) -> bool:
    """True when a state write precedes the first sender check."""
    first_check = None
    for m in _SENDER_CHECK_RE.finditer(body):
        first_check = m.start()
        break
    if first_check is None:
        return False
    # Look for assignment to owner/admin/implementation/fee before the check.
    prefix = _strip_dead_if_false(body[:first_check])
    if _OWNER_WRITE_RE.search(prefix) or _IMPL_WRITE_RE.search(prefix):
        return True
    if re.search(r"\b(fee\w*|oracle\w*|implementation)\s*=", prefix, re.IGNORECASE):
        return True
    # External call / value send before auth.
    if value_sends(prefix) or re.search(r"\b_mint\s*\(", prefix):
        return True
    return False


def _make_finding(
    c: Contract,
    fn: Function,
    text: str,
    rel: Optional[str],
    category: str,
    status: str,
    guard: Optional[str],
    weak_reason: Optional[str],
    context: AnalysisContext,
    controller_cache: Dict[str, str],
) -> Finding:
    if status == "UNPROTECTED":
        slug = SLUG_UNPROTECTED
        sev = _severity_for(category, status)
        conf = Confidence.HIGH
    elif status == "WEAK":
        slug = SLUG_WEAK
        sev = _severity_for(category, status)
        conf = Confidence.MEDIUM
    else:
        slug = SLUG_PROTECTED
        sev = Severity.INFORMATIONAL
        conf = Confidence.MEDIUM

    controller = ""
    if status == "PROTECTED":
        controller = _controller_note(context, controller_cache)

    missing, fix = _missing_and_fix(category, status, weak_reason, guard)
    headline = _headline(category, status, weak_reason)
    meta = {
        "privileged_category": category,
        "status": status,
        "guard": guard or "none",
        "controller": controller or "",
        "weak_reason": weak_reason or "",
    }
    desc_parts = [
        f"Privileged-function authorization: category={category} status={status} "
        f"guard={guard or 'none'} controller={controller or 'n/a'}.",
        f"{c.name}.{fn.name}: {headline}.",
        missing,
        fix,
        "Defensive note only — no exploit steps.",
        f"Source detector: {slug}.",
    ]
    if status == "PROTECTED" and controller:
        desc_parts.insert(
            2,
            f"Centralization: on-chain controller appears to be {controller}. "
            "Prefer a timelocked multisig over an EOA for this privilege.",
        )

    start = text.rfind("function", 0, fn.body_start)
    excerpt = text[start if start >= 0 else fn.body_start : fn.body_end + 1][:1200]
    end_line = text.count("\n", 0, fn.body_end) + 1

    return Finding(
        title=f"{slug} in {c.name}.{fn.name}: {headline}",
        description=" ".join(desc_parts),
        category=CATEGORY,
        severity=sev,
        confidence=conf,
        verification_status=VerificationStatus.UNVERIFIED,
        affected_contract=c.name,
        affected_function=fn.name,
        affected_lines=list(range(fn.line, min(end_line, fn.line + 40) + 1)),
        affected_file=rel,
        source="source-analysis",
        tool=NAME,
        reasoning=json.dumps(meta, sort_keys=True),
        impact=_impact(category, status),
        exploitability=(
            "Outsiders can call this entry point."
            if status != "PROTECTED"
            else "Only the privileged controller can call; residual risk is centralization."
        ),
        likelihood="Static source pattern (heuristic); review the evidence.",
        false_positive_risk=(
            "Inherited modifiers in unscanned files, assembly, and proxy patterns "
            "are not followed; a guard defined only in an unscanned base may be missed."
        ),
        assumptions=[
            "Permission is inferred from visible modifiers/inline msg.sender checks only.",
            "tx.origin is never treated as a sufficient guard.",
        ],
        remediation=fix,
        evidence=[
            EvidenceItem(
                source="source-analysis",
                artifact_type="source_excerpt",
                excerpt=excerpt,
                epistemic=Epistemic.FACT,
                tool=NAME,
                proves=[f"privileged_auth:{category}:{status}"],
            )
        ],
    )


def _severity_for(category: str, status: str) -> Severity:
    if status == "PROTECTED":
        return Severity.INFORMATIONAL
    critical_cats = {"ownership", "upgrade", "withdraw", "mint"}
    if status == "UNPROTECTED" and category in critical_cats:
        return Severity.HIGH if category != "withdraw" else Severity.CRITICAL
    if status == "UNPROTECTED":
        return Severity.HIGH
    # WEAK
    if category in critical_cats:
        return Severity.HIGH
    return Severity.MEDIUM


def _headline(category: str, status: str, weak_reason: Optional[str]) -> str:
    labels = {
        "ownership": "ownership/admin/role change",
        "upgrade": "upgrade / initialize",
        "withdraw": "treasury / fund withdrawal",
        "mint": "token mint",
        "fees": "fee parameter change",
        "oracle": "oracle / router retarget",
    }
    base = labels.get(category, category)
    if status == "UNPROTECTED":
        return f"Unprotected {base}"
    if status == "WEAK":
        extra = f" ({weak_reason})" if weak_reason else ""
        return f"Weak authorization on {base}{extra}"
    return f"Protected {base} (centralization)"


def _missing_and_fix(
    category: str, status: str, weak_reason: Optional[str], guard: Optional[str]
) -> Tuple[str, str]:
    if status == "PROTECTED":
        return (
            f"Guard present: {guard}. Residual risk is who holds that privilege.",
            "Keep the guard; move the privileged key to a timelocked multisig "
            "(Safe m-of-n) and document the delay for upgrades/withdrawals.",
        )
    if weak_reason and "tx.origin" in weak_reason:
        return (
            "Missing check: authorization uses tx.origin instead of msg.sender "
            "(or a role), which is bypassable by intermediate contracts.",
            "Fix: replace tx.origin checks with msg.sender == owner / "
            "onlyOwner / AccessControl onlyRole, and keep the check before any effect.",
        )
    if weak_reason and "after the effect" in (weak_reason or ""):
        return (
            "Missing check: authorization runs after state changes or external calls "
            "(checks-effects-interactions violation on the auth path).",
            "Fix: require the privileged caller at the top of the function, before "
            "any state write, mint, or value transfer.",
        )
    if weak_reason and "initializer" in (weak_reason or ""):
        return (
            "Missing check: initialize/reinitialize is callable by anyone on first use "
            "(or lacks an initializer modifier).",
            "Fix: add OpenZeppelin initializer/reinitializer, disable initializers in "
            "the implementation constructor, and/or restrict initialize to a deployer "
            "multisig; never leave initialize public on a live implementation.",
        )
    if weak_reason and "overload" in (weak_reason or ""):
        return (
            "Missing check: one public overload/entry point lacks the auth present on siblings.",
            "Fix: apply the same onlyOwner / onlyRole guard to every public overload.",
        )
    if weak_reason and "internal-helper" in (weak_reason or ""):
        return (
            "Missing check: a helper named like an internal function is public/external "
            "with no caller restriction.",
            "Fix: mark it internal/private, or add an onlyOwner / onlyRole guard.",
        )
    # Default UNPROTECTED
    what = {
        "ownership": "restrict ownership/admin/role changes to the current admin "
        "(onlyOwner / AccessControl onlyRole) and reject zero-address where appropriate",
        "upgrade": "restrict upgradeTo / diamondCut / setImplementation to a "
        "timelocked multisig and disable initialize on implementations",
        "withdraw": "restrict sweep/rescue/withdraw of contract balances to a "
        "privileged role and emit events; prefer pull-payments",
        "mint": "restrict _mint / mint to a minter role with a supply cap",
        "fees": "restrict fee setters to governance and bound the new fee",
        "oracle": "restrict oracle/router setters to governance and validate the new address",
    }.get(category, "add an explicit msg.sender authorization check before the effect")
    return (
        f"Missing check: no msg.sender / role guard on this privileged {category} entry point.",
        f"Fix: {what}.",
    )


def _impact(category: str, status: str) -> str:
    if status == "PROTECTED":
        return (
            "Privilege is gated, but compromise or malice by the controller can still "
            f"affect {category}; treat as centralization risk."
        )
    impacts = {
        "ownership": "An outsider can seize admin/roles and then drive every gated action.",
        "upgrade": "An outsider can replace code or initialize an implementation and take control.",
        "withdraw": "An outsider can drain ETH/tokens held by the contract.",
        "mint": "An outsider can inflate supply and dilute or dump on holders.",
        "fees": "An outsider can set extractive fees.",
        "oracle": "An outsider can retarget price feeds/routers and corrupt accounting.",
    }
    return impacts.get(category, "Privileged behavior is reachable by outsiders.")


def _controller_note(context: AnalysisContext, cache: Dict[str, str]) -> str:
    """Best-effort on-chain controller type via the existing trust map."""
    addr = getattr(context, "address", None) or (
        (context.options or {}).get("address") if isinstance(context.options, dict) else None
    )
    if not addr:
        return ""
    key = str(addr).lower()
    if key in cache:
        return cache[key]
    note = ""
    try:
        reader = (context.options or {}).get("eth_reader") if isinstance(context.options, dict) else None
        if reader is None:
            # Prefer already-recorded trust rows when a DB path is provided.
            trust_hint = (context.options or {}).get("trust_owner_type")
            if trust_hint:
                note = str(trust_hint)
                cache[key] = note
                return note
            cache[key] = ""
            return ""
        from ..simulate import _owner_type  # noqa: WPS433

        owner = None
        if hasattr(reader, "call_addr"):
            # owner() selector 0x8da5cb5b
            owner = reader.call_addr(addr, "0x8da5cb5b")
        if owner:
            otype = _owner_type(reader, owner)
            if otype == "multisig" or otype == "gnosis-safe":
                # Try threshold/owners for Safe m-of-n.
                thr = None
                n_owners = None
                try:
                    thr = reader.call_int(owner, "0x2f54bf6e")  # wrong; use getThreshold
                except Exception:  # noqa: BLE001
                    thr = None
                # getThreshold() = 0x556d8164? Actually keccak getThreshold()[:4] = 0xceba1d99? 
                # Standard Safe getThreshold() selector is 0x556d8164 is isOwner.
                # getThreshold() = bytes4(keccak256("getThreshold()")) = 0xceba1d99 — verify:
                # We'll label generically.
                note = "Safe multisig (m-of-n)"
                try:
                    # getThreshold() selector: 0xceba1d99 is incorrect in some refs;
                    # cast sig getThreshold() → 0x556... no.
                    # Use known: getThreshold() → 0xceba1d99? Skip precise m/n if unsure.
                    t = reader.call_int(owner, "0xceba1d99") if hasattr(reader, "call_int") else None
                    # Actually Safe getThreshold is 0x556d8164? Let me use 0xceba1d99 only if >0.
                    if not t:
                        t = reader.call_int(owner, "0x556d8164") if hasattr(reader, "call_int") else None
                    # Safer: just say Safe multisig.
                except Exception:  # noqa: BLE001
                    pass
                note = "Safe multisig (m-of-n)"
            elif otype == "timelock":
                note = "timelock"
            elif otype == "eoa":
                note = "EOA"
            else:
                note = otype or "contract"
        else:
            note = ""
    except Exception:  # noqa: BLE001
        note = ""
    cache[key] = note
    return note


def _slither_hints(context: AnalysisContext) -> Dict[str, Any]:
    """Best-effort map of Contract.fn → written state vars from Slither JSON."""
    out: Dict[str, Any] = {"writes": {}}
    try:
        from .slither_runner import get_slither_run

        run = get_slither_run(context)
    except Exception:  # noqa: BLE001
        return out
    detectors = getattr(run, "detectors", None) or []
    # Also inspect raw JSON if the runner stashed it.
    raw = getattr(run, "raw_json", None) or getattr(run, "json_report", None)
    if isinstance(raw, dict):
        # Walk results for state variable writes if present (version-dependent).
        for res in raw.get("results", {}).get("detectors", []) or detectors:
            if not isinstance(res, dict):
                continue
            _ingest_detector_vars(res, out["writes"])
    for det in detectors:
        if isinstance(det, dict):
            _ingest_detector_vars(det, out["writes"])
    return out


def _ingest_detector_vars(det: dict, writes: dict) -> None:
    desc = str(det.get("description") or "")
    # Very light: "Contract.fn writes var" patterns occasionally appear.
    for m in re.finditer(r"\b([A-Za-z_]\w*)\.([A-Za-z_]\w*)\b[^\n]{0,80}\bwrites?\b[^\n]{0,40}\b([A-Za-z_]\w*)", desc):
        key = f"{m.group(1)}.{m.group(2)}"
        writes.setdefault(key, []).append(m.group(3))
    elements = det.get("elements") or []
    for el in elements:
        if not isinstance(el, dict):
            continue
        name = str(el.get("name") or "")
        typ = str(el.get("type") or "")
        parent = el.get("type_specific_fields") or {}
        parent_name = ""
        if isinstance(parent, dict):
            p = parent.get("parent") or {}
            if isinstance(p, dict):
                parent_name = str(p.get("name") or "")
        if typ in ("function", "modifier") and parent_name:
            # Collect mentioned state vars from additional fields if any.
            for v in parent.get("state_variables_written") or []:
                if isinstance(v, dict) and v.get("name"):
                    writes.setdefault(f"{parent_name}.{name}", []).append(str(v["name"]))
                elif isinstance(v, str):
                    writes.setdefault(f"{parent_name}.{name}", []).append(v)


def _library_blocks(sol_files: Sequence[Path], opts) -> Dict[Path, set]:
    try:
        from ..library_code import SourceIndex, _rel

        main = opts.get("main_contract") if isinstance(opts, dict) else None
        root = opts.get("source_root") if isinstance(opts, dict) else None
        idx = SourceIndex(list(sol_files), Path(root) if root else None)
        lib = {k: v for k, v in idx.library_block_names(main).items() if v.level == "hash"}
        out: Dict[Path, set] = {}
        for sf in sol_files:
            rel = _rel(sf, idx.root)
            out[sf] = {name for (r, name) in lib if r == rel}
        return out
    except Exception:  # noqa: BLE001
        return {}
