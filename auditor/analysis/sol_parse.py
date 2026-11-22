"""Phase 19 — light, offset-preserving Solidity structure helpers.

Regex + brace matching over comment/string-blanked text. This is NOT a
parser; callers treat every result as a heuristic and record it as such.
Shared by :mod:`auditor.triage` (privileged-withdraw rule) and
:mod:`auditor.analysis.honeypot`.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence

from ..library_code import Block, blocks, code_only, match_brace

_FUNC_RE = re.compile(r"\bfunction\s+([A-Za-z_]\w*)\s*\(")
_CTOR_RE = re.compile(r"\b(constructor)\s*\(")
_FALLBACK_RE = re.compile(r"\b(receive|fallback)\s*\(\s*\)")
_MOD_RE = re.compile(r"\bmodifier\s+([A-Za-z_]\w*)\s*(\([^)]*\))?\s*\{")

KEYWORDS = frozenset({
    "public", "external", "internal", "private", "view", "pure", "payable", "virtual",
    "override", "returns", "constant", "memory", "calldata", "storage",
})

#: Modifier names that conventionally mean "privileged caller only".
PRIV_MODIFIER_RE = re.compile(
    r"^(only\w*|is(?:Admin|Owner|Authorized|Operator|Governance)\w*|ifAdmin|ifOwner|"
    r"auth|requiresAuth|admin\w*|owner\w*|whenAdmin|restricted|ownerOnly|adminOnly|"
    r"onlyAuthorized\w*)$",
    re.IGNORECASE)

#: Inline msg.sender authorisation at the top of a function body.
INLINE_GUARD_RE = re.compile(
    r"(require\s*\(\s*(?:msg\.sender\s*==\s*[\w.()\[\]]+|[\w.()\[\]]+\s*==\s*msg\.sender|"
    r"\w+\s*\[\s*(?:keccak256\s*\(\s*abi\.encodePacked\s*\(\s*)?msg\.sender\s*\)?\s*\)?\s*\]\s*(?=\)|,|==\s*true)|"
    r"has\w*Role\s*\([^;]*msg\.sender|is\w*\s*\(\s*msg\.sender\s*\)|"
    r"[^;]*?\|\|\s*has\w*Role\s*\([^;]*?msg\.sender)"
    r"|if\s*\(\s*msg\.sender\s*!=\s*[\w.()\[\]]+\s*\)\s*(?:\{\s*)?(?:revert|throw|return)"
    r"|_checkOwner\s*\(\s*\)|_checkRole\s*\(|_onlyOwner\s*\(\s*\)"
    r"|_validateCaller\s*\(|_onlyAuthorized\w*\s*\()")

VALUE_SEND_RE = re.compile(
    r"([\w.()\[\]]+?)\s*\.\s*(transfer|send)\s*\(([^;]*?)\)\s*;"
    r"|([\w.()\[\]]+?)\s*\.\s*call\s*(?:\{\s*value\s*:\s*([^}]*)\}|\.value\s*\(([^)]*)\))")

FULL_BALANCE_RE = re.compile(r"(?:address\s*\(\s*this\s*\)|\bthis)\s*\.\s*balance\b")
HEX_ADDR_RE = re.compile(r"\b0x[0-9a-fA-F]{40}\b")


@dataclass
class Function:
    name: str
    header: str            # code-only header text: "function f(...) public payable onlyOwner"
    params: str
    body: str              # code-only body text (without outer braces)
    body_start: int        # absolute offsets in the file text
    body_end: int
    line: int              # 1-based line of the declaration
    modifiers: List[str] = field(default_factory=list)

    @property
    def payable(self) -> bool:
        return bool(re.search(r"\bpayable\b", self.header.split(")", 1)[-1] if ")" in self.header else ""))

    @property
    def visibility(self) -> str:
        tail = self.header.split(")", 1)[-1] if ")" in self.header else ""
        for v in ("external", "public", "internal", "private"):
            if re.search(rf"\b{v}\b", tail):
                return v
        return "public"


@dataclass
class Contract:
    block: Block
    code: str                                # code-only text of the whole file
    functions: List[Function] = field(default_factory=list)
    modifiers: Dict[str, str] = field(default_factory=dict)  # name -> code-only body
    state_text: str = ""                     # contract body with function bodies removed

    @property
    def name(self) -> str:
        return self.block.name


def _params_end(code: str, open_paren: int) -> int:
    depth = 0
    for j in range(open_paren, len(code)):
        if code[j] == "(":
            depth += 1
        elif code[j] == ")":
            depth -= 1
            if depth == 0:
                return j
    return len(code) - 1


def parse_contract(text: str, b: Block, code: Optional[str] = None) -> Contract:
    code = code if code is not None else code_only(text)
    c = Contract(b, code)
    lo, hi = b.body_open + 1, b.end
    state_parts: List[str] = []
    pos = lo
    regexes = (_FUNC_RE, _CTOR_RE, _FALLBACK_RE, _MOD_RE)
    while pos < hi:
        best = None
        for rx in regexes:
            m = rx.search(code, pos, hi)
            if m and (best is None or m.start() < best[0].start()):
                best = (m, rx)
        if best is None:
            state_parts.append(code[pos:hi])
            break
        m, rx = best
        state_parts.append(code[pos:m.start()])
        if rx is _MOD_RE:
            open_idx = m.end() - 1
            end = match_brace(code, open_idx)
            c.modifiers[m.group(1)] = code[open_idx + 1:end]
            pos = end + 1
            continue
        paren = code.index("(", m.start())
        pend = _params_end(code, paren)
        # header runs to '{' (implementation) or ';' (declaration only)
        j = pend + 1
        while j < hi and code[j] not in "{;":
            j += 1
        header = " ".join(code[m.start():j].split())
        if j >= hi or code[j] == ";":
            pos = j + 1
            continue
        end = match_brace(code, j)
        tail = code[pend + 1:j]
        mods = []
        for mm in re.finditer(r"\b([A-Za-z_]\w*)\s*(\([^)]*\))?", tail):
            w = mm.group(1)
            if w not in KEYWORDS and not w.startswith("returns"):
                mods.append(w)
        # strip return-type identifiers following 'returns'
        if "returns" in tail:
            before = tail.split("returns", 1)[0]
            mods = [w for w in mods if re.search(rf"\b{re.escape(w)}\b", before)]
        c.functions.append(Function(
            name=m.group(1), header=header, params=code[paren + 1:pend], body=code[j + 1:end],
            body_start=j + 1, body_end=end, line=text.count("\n", 0, m.start()) + 1, modifiers=mods))
        pos = end + 1
    c.state_text = " ".join(state_parts)
    return c


def contracts_in(text: str) -> List[Contract]:
    code = code_only(text)
    return [parse_contract(text, b, code) for b in blocks(text) if b.kind != "interface"]


def all_modifiers(contracts: Sequence[Contract]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for c in contracts:
        for k, v in c.modifiers.items():
            out.setdefault(k, v)
    return out


def modifier_is_sender_guard(body: Optional[str]) -> bool:
    """A modifier body that actually authorises msg.sender (not tx.origin)."""
    if not body:
        return False
    if re.search(r"tx\.origin", body) and not re.search(r"msg\.sender", body):
        return False
    return bool(INLINE_GUARD_RE.search(body)) or bool(
        re.search(r"(require|if)\s*\([^;]*msg\.sender", body)) or bool(
        re.search(r"_check\w*\s*\(|_validateCaller\s*\(|_onlyAuthorized\w*\s*\(", body))


def privileged_guard(fn: Function, modifiers: Dict[str, str]) -> Optional[str]:
    """Name/description of the privileged-caller guard on *fn*, or None.

    A conventional modifier name counts only when its definition is visible
    in the scanned sources and actually checks msg.sender; an inline
    ``require(msg.sender == X)`` / ``_checkOwner()`` at the top of the body
    also counts. ``tx.origin``-based checks never count.
    """
    for m in fn.modifiers:
        if PRIV_MODIFIER_RE.match(m) and modifier_is_sender_guard(modifiers.get(m)):
            return f"modifier {m}"
        if m.startswith("onlyRole") and "onlyRole" in modifiers and modifier_is_sender_guard(
                modifiers.get("onlyRole")):
            return "modifier onlyRole"
    head = fn.body[:400]
    g = INLINE_GUARD_RE.search(head)
    if g and "tx.origin" not in g.group(0):
        return "inline msg.sender check"

    # Recognize explicit boolean authorization checks.
    # Require an authorization-related expression and a reverting failure branch.
    for assignment in re.finditer(
        r"\bbool\s+([A-Za-z_]\w*)\s*=\s*([^;]+);", head
    ):
        variable, expression = assignment.groups()
        if not re.search(r"\bmsg\.sender\b", expression):
            continue
        if not re.search(
            r"\b(?:owner|canCall|isAuthorized|hasRole|hasPermission)\b",
            expression,
            re.IGNORECASE,
        ):
            continue
        tail = head[assignment.end():]
        failure = (
            rf"\bif\s*\(\s*!\s*{re.escape(variable)}\s*\)"
            rf"\s*(?:\{{\s*)?revert\b"
        )
        if re.search(failure, tail):
            return "inline boolean authorization check"

    return None


def value_sends(body: str) -> List[Dict[str, str]]:
    """ETH transfers in a body: [{recipient, amount}] (heuristic)."""
    out = []
    for m in VALUE_SEND_RE.finditer(body):
        if m.group(1):
            if m.group(2) in ("transfer", "send") and m.group(3) is not None:
                args = m.group(3).strip()
                if "," in args:  # token.transfer(to, amount): not an ETH send
                    continue
                out.append({"recipient": _norm_recipient(m.group(1)), "amount": args})
        else:
            out.append({"recipient": _norm_recipient(m.group(4)), "amount": (m.group(5) or m.group(6) or "").strip()})
    return out


def _norm_recipient(r: str) -> str:
    r = " ".join(r.split())
    m = re.fullmatch(r"(?:payable|address)\s*\(\s*(.+?)\s*\)", r)
    while m:
        r = m.group(1)
        m = re.fullmatch(r"(?:payable|address)\s*\(\s*(.+?)\s*\)", r)
    return r


def line_of(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


_CLAIM_HINT_RE = re.compile(
    r"\b(previewMint|convertToAssets|_convertToAssets|claimable\w*|\w*Settled\w*|pendingSilo|"
    r"lastDepositRequestId|depositRequest|requestId|epochs?)\b"
)


def is_vault_claim_mint(fn: "Function", contract: "Contract") -> bool:
    """ERC-4626 / ERC-7540 user mint(shares, receiver[, controller]).

    True when the public mint either prices assets (previewMint/convertToAssets),
    or forwards to an internal ``_mint`` overload with 3+ args whose body
    consumes the controller's own settled/claimable request. Such mints are
    user claims, not privileged supply inflation.
    """
    if fn.name != "mint":
        return False
    body = fn.body or ""
    if _CLAIM_HINT_RE.search(body):
        return True
    # Compound-style cToken supply: mint(amount) -> mintInternal(amount), which
    # pulls underlying from msg.sender (doTransferIn) and mints to msg.sender.
    if re.search(r"\bmintInternal\s*\(\s*\w+\s*\)", body):
        return True
    m = re.search(r"\b_mint\s*\(([^;]*)\)\s*;", body)
    if not m:
        return False
    nargs = len([a for a in m.group(1).split(",") if a.strip()])
    if nargs < 3:
        return False
    for f in getattr(contract, "functions", []) or []:
        if f.name == "_mint" and len([p for p in (f.params or "").split(",") if p.strip()]) == nargs:
            if _CLAIM_HINT_RE.search(f.body or ""):
                return True
    return False


# --- proxy-forwarder / admin-fixed delegatecall target (Compound CErc20Delegator shape) ---
_DELEGATECALL_RE = re.compile(r"\b([A-Za-z_]\w*)\s*\.\s*delegatecall\s*\(")


def _param_names(params: str) -> List[str]:
    out = []
    for p in params.strip("() ").split(","):
        toks = p.split()
        if toks:
            out.append(toks[-1])
    return out


def _is_state_var(cs: Sequence["Contract"], name: str) -> bool:
    return any(re.search(rf"\baddress\b[^;=(]*\b{re.escape(name)}\s*(;|=)", c.state_text) for c in cs)


def _state_var_admin_fixed(cs: Sequence["Contract"], name: str, modifiers: Dict[str, str]) -> bool:
    """State var written only in constructor or msg.sender-guarded functions (across *cs*)."""
    if not re.fullmatch(r"[A-Za-z_]\w*", name or "") or not _is_state_var(cs, name):
        return False
    for f in [f for c in cs for f in c.functions]:
        if re.search(rf"\b{re.escape(name)}\s*=(?!=)", f.body):
            if f.name in ("constructor", "") or f.header.startswith("constructor"):
                continue
            if privileged_guard(f, modifiers) is None:
                return False
    return True


def delegatecall_target_admin_fixed(c: "Contract", fn: Function, modifiers: Dict[str, str],
                                    universe: Optional[Sequence["Contract"]] = None) -> Optional[str]:
    """Reason string when every delegatecall in *fn* targets an admin-fixed address.

    Benign shape: target is a state var only written by constructor/guarded
    functions, or *fn* is internal/private and every in-contract caller passes
    such a state var (or is itself guarded / the constructor). None otherwise.
    """
    targets = _DELEGATECALL_RE.findall(fn.body)
    if not targets:
        return None
    cs = list(universe) if universe else [c]
    if c not in cs:
        cs.append(c)
    params = _param_names(fn.params)
    for t in targets:
        if _state_var_admin_fixed(cs, t, modifiers):
            continue
        if t in params and fn.visibility in ("internal", "private"):
            idx = params.index(t)
            callers = [f for f in c.functions if f is not fn and re.search(rf"\b{re.escape(fn.name)}\s*\(", f.body)]
            if not callers:
                return None
            for f in callers:
                guarded = privileged_guard(f, modifiers) is not None or f.header.startswith("constructor")
                for m in re.finditer(rf"\b{re.escape(fn.name)}\s*\(([^;]*)\)\s*;", f.body):
                    args = [a.strip() for a in m.group(1).split(",")]
                    a = args[idx] if idx < len(args) else ""
                    if not (guarded or _state_var_admin_fixed(cs, a, modifiers)):
                        return None
            continue
        return None
    return "delegatecall target is an admin-fixed implementation address (proxy forwarder); caller cannot choose the target"


def is_proxy_forwarder(fn: Function, c: "Contract") -> bool:
    """Body only forwards msg.data to the implementation via a private delegatecall helper."""
    for h in c.functions:
        if h is fn or h.visibility not in ("internal", "private"):
            continue
        if re.search(r"\.delegatecall\s*\(\s*msg\.data\s*\)", h.body) and re.search(rf"\b{re.escape(h.name)}\s*\(\s*\)", fn.body):
            stripped = re.sub(rf"\b{re.escape(h.name)}\s*\(\s*\)\s*;|\b\w+\s*;", "", fn.body).strip()
            return stripped == ""
    return False


# --- reentrancy-lock coverage (all entry points into a function hold a mutex) ---
def modifier_is_lock(body: Optional[str]) -> bool:
    """Modifier body that checks a flag, flips it before `_`, and restores it after."""
    if not body or "_" not in body:
        return False
    pre, _, post = body.partition("_;")
    m = re.search(r"require\s*\(\s*!?\s*(\w+)\s*(?:==|!=)?[^;]*\)\s*;", pre)
    if not m:
        return False
    flag = m.group(1)
    return bool(re.search(rf"\b{flag}\s*=", pre)) and bool(re.search(rf"\b{flag}\s*=", post))


def lock_covered(cs: Sequence["Contract"], fname: str, cname: Optional[str] = None,
                 depth: int = 4) -> Optional[str]:
    """Name of the lock modifier when every path into *fname* holds it, else None.

    A public/external function must carry the lock itself; an internal/private
    one is covered when it has callers and each caller is covered (bounded
    depth). Unknown structure stays None (unresolved).
    """
    mods = all_modifiers(cs)
    locks = {k for k, v in mods.items() if modifier_is_lock(v)}
    if not locks:
        return None
    fns = [f for c in cs for f in c.functions]

    def covered(name: str, d: int, seen: frozenset) -> Optional[str]:
        defs = [f for f in fns if f.name == name]
        if not defs or d < 0 or name in seen:
            return None
        hit = None
        for f in defs:
            lk = next((m for m in f.modifiers if m in locks), None)
            if lk:
                hit = lk
                continue
            if f.visibility in ("public", "external") or f.header.startswith(("constructor", "fallback", "receive")):
                return None
            callers = {g.name for g in fns if g is not f and re.search(rf"\b{re.escape(name)}\s*\(", g.body)}
            if not callers:
                return None
            for cn in callers:
                r = covered(cn, d - 1, seen | {name})
                if r is None:
                    return None
                hit = r
        return hit
    return covered(fname, depth, frozenset())


def admin_guarded(cs: Sequence["Contract"], cname: Optional[str], fname: str) -> Optional[str]:
    """Guard description when *fname* (in contract *cname*) is msg.sender-guarded, else None."""
    mods = all_modifiers(cs)
    hits = [f for c in cs if (cname is None or c.name == cname) for f in c.functions if f.name == fname]
    if not hits:
        return None
    gs = [privileged_guard(f, mods) for f in hits]
    return gs[0] if all(gs) else None
