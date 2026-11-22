"""Phase 21 — proxy resolution and fund-holder ("vault") discovery.

The Phase 20 hunter scanned the address DefiLlama lists for a protocol. That
is often a token, a governance contract or a proxy whose own balance is $0,
while the money sits in a vault, strategy or escrow contract next to it.
This module finds the contracts that actually hold the funds, read-only:

* :func:`resolve_proxy` — EIP-1967 implementation and beacon slots, EIP-1822
  (``PROXIABLE``), the OpenZeppelin legacy (zos) slot, Gnosis Safe
  ``masterCopy`` (slot 0), EIP-1167 minimal-proxy bytecode and EIP-897
  ``implementation()`` (only when the bytecode contains DELEGATECALL).
  Callers scan the *implementation's* verified source but measure value at
  the *proxy* address, because that is where the funds sit.
* :class:`VaultDiscovery` — breadth-first walk from a protocol's seed
  addresses (DefiLlama protocol address, adapter addresses, optional
  Etherscan contract-creator deployments) over zero-argument address getters
  (taken from the verified ABI when available, else a fixed list such as
  ``strategy()``, ``vault()``, ``cdo()``, ``escrow()``). ERC-20 neighbours
  that are not seeds are treated as *tokens* (measured, not walked); other
  contract neighbours are walked. Each contract's live holdings — ETH, the
  major tokens and every protocol token found (ERC-4626 ``asset()``, token
  getters, ERC-20 seeds) — are priced with DefiLlama's coins API (CoinGecko
  fallback) and ranked.

Only ``eth_getCode``, ``eth_getStorageAt`` and ``eth_call`` (view getters,
``balanceOf``) plus Etherscan/DefiLlama/CoinGecko GETs are used. Nothing
here signs or sends a transaction. All USD numbers are rough estimates.
"""

from __future__ import annotations

import json
import logging
import re
import time
import urllib.parse
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

log = logging.getLogger("contract_auditor.vault_discovery")

# --- storage slots (bytes32) ----------------------------------------------
SLOT_EIP1967_IMPL = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"
SLOT_EIP1967_BEACON = "0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50"
SLOT_EIP1967_ADMIN = "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103"
SLOT_EIP1822 = "0xc5f16f0fcc639fa48a6947836d9850f504798523bf8c9a3a87d5876cf622bcf7"
SLOT_OZ_LEGACY = "0x7050c9e0f4ca769c69bd3a8ef740bc37934f8e2c036e5a723fd8ee048ed3f8c3"

# --- function selectors ------------------------------------------------------
SEL = {
    "implementation()": "0x5c60da1b", "masterCopy()": "0xa619486e",
    "totalSupply()": "0x18160ddd", "decimals()": "0x313ce567", "symbol()": "0x95d89b41",
    "asset()": "0x38d52e0f", "totalAssets()": "0x01e1d114", "balanceOf(address)": "0x70a08231",
}
STRUCTURAL_GETTERS = {
    "strategy()": "0xa8c62e76", "cdo()": "0x387a7237", "vault()": "0xfbfa77cf",
    "pool()": "0x16f0115b", "escrow()": "0xe2fdcc17", "treasury()": "0x61d027b3",
    "silo()": "0xeb3beb29", "reserve()": "0xcd3293de", "custodian()": "0x375b74c3",
    "controller()": "0xf77c4791", "jrtVault()": "0x3e402006", "srtVault()": "0xa6ee7904",
    "bridge()": "0xe78cea92", "staking()": "0x4cf088d9", "lockbox()": "0x66cc5702",
}
TOKEN_GETTERS = {
    "asset()": "0x38d52e0f", "underlying()": "0x6f307dc3", "token()": "0xfc0c546a",
    "want()": "0x1f1fcd51", "collateral()": "0xd8dfeb45", "stakingToken()": "0x72f702f3",
    "sUSDe()": "0xe0d05d39", "USDe()": "0xd1609502", "token0()": "0x0dfe1681",
    "token1()": "0xd21220a7",
}
_SKIP_GETTER = re.compile(
    r"(owner|admin|governance|governor|guardian|acm|accesscontrol|accessmanager|authority|role|"
    r"oracle|feed|aggregator|pricer|configmanager|timelock|keeper|operator|signer|implementation|"
    r"beacon|factory|registry|deployer|minter|pauser|forwarder|trustedforwarder|permit2|weth9?$)",
    re.I)

_EIP1167 = re.compile(r"363d3d373d3d3d363d73([0-9a-f]{40})5af43d82803e903d91602b57fd5bf3")
_EIP7511 = re.compile(r"365f5f375f5f365f73([0-9a-f]{40})5af43d5f5f3e")
ZERO = "0x" + "0" * 40

COINS_LLAMA = "https://coins.llama.fi/prices/current/"
COINGECKO_TOKEN = "https://api.coingecko.com/api/v3/simple/token_price/ethereum"
VALUE_LABEL = "rough estimate (live balances x DefiLlama/CoinGecko prices)"


def _word_addr(word: Any) -> Optional[str]:
    if not isinstance(word, str) or not word.startswith("0x") or len(word) < 42:
        return None
    w = word[2:].rjust(64, "0")[-64:]
    if int(w[:24] or "0", 16) != 0:
        return None
    a = "0x" + w[-40:].lower()
    return None if a == ZERO else a


def _word_int(word: Any) -> Optional[int]:
    if not isinstance(word, str) or not word.startswith("0x") or len(word) <= 2:
        return None
    try:
        return int(word[2:66] or "0", 16)
    except ValueError:
        return None


def _decode_string(word: Any) -> Optional[str]:
    if not isinstance(word, str) or not word.startswith("0x") or len(word) < 66:
        return None
    h = word[2:]
    try:
        if len(h) >= 192 and int(h[:64], 16) == 32:
            n = int(h[64:128], 16)
            if n > 64:
                return None
            raw = bytes.fromhex(h[128:128 + 2 * n])
        else:
            raw = bytes.fromhex(h[:64]).rstrip(b"\0")
        s = raw.decode("utf-8", errors="ignore")
        s = re.sub(r"[^\w.\-+$ ]", "", s)[:24]
        return s or None
    except ValueError:
        return None


def has_delegatecall(code_hex: str) -> bool:
    try:
        code = bytes.fromhex((code_hex or "0x")[2:])
    except ValueError:
        return False
    i = 0
    while i < len(code):
        op = code[i]
        if op == 0xF4:
            return True
        i += (op - 0x5F + 1) if 0x60 <= op <= 0x7F else 1
    return False


class Reader:
    """Thin read-only facade over a monitor ChainClient (or a test fake)."""

    def __init__(self, client: Any, max_calls: int = 4000):
        self.client = client
        self.calls = 0
        self.errors = 0
        self.max_calls = int(max_calls)
        self._code: Dict[str, str] = {}

    def _budget(self) -> bool:
        if self.calls >= self.max_calls:
            return False
        self.calls += 1
        return True

    def code(self, address: str) -> str:
        a = address.lower()
        if a in self._code:
            return self._code[a]
        if not self._budget():
            return ""
        try:
            fn = getattr(self.client, "get_code", None)
            c = fn(a) if callable(fn) else None
            if c is None:
                n = int(self.client.code_size(a))
                c = "0x" + ("00" * n)
        except Exception as exc:  # noqa: BLE001
            self.errors += 1
            log.info("vault: code %s: %s", a, type(exc).__name__)
            return ""
        c = str(c or "0x").lower()
        self._code[a] = c
        return c

    def is_contract(self, address: str) -> bool:
        return len(self.code(address)) > 2

    def storage(self, address: str, slot: str) -> Optional[str]:
        fn = getattr(self.client, "storage_at", None)
        if not callable(fn) or not self._budget():
            return None
        try:
            return fn(address, slot)
        except Exception as exc:  # noqa: BLE001
            self.errors += 1
            log.info("vault: storage %s: %s", address, type(exc).__name__)
            return None

    def call(self, to: str, data: str) -> Optional[str]:
        fn = getattr(self.client, "call", None)
        if not callable(fn) or not self._budget():
            return None
        try:
            r = fn(to, data)
        except Exception:  # noqa: BLE001
            return None
        if not isinstance(r, str) or r in ("0x", "") or not r.startswith("0x"):
            return None
        return r.lower()

    def call_addr(self, to: str, sel: str) -> Optional[str]:
        return _word_addr(self.call(to, sel))

    def call_int(self, to: str, sel: str) -> Optional[int]:
        return _word_int(self.call(to, sel))

    def balance_of(self, token: str, holder: str) -> Optional[int]:
        r = self.call(token, SEL["balanceOf(address)"] + holder.lower()[2:].rjust(64, "0"))
        return _word_int(r)

    def native(self, holder: str) -> Optional[int]:
        if not self._budget():
            return None
        try:
            return int(self.client.native_balance(holder))
        except Exception:  # noqa: BLE001
            self.errors += 1
            return None


@dataclass
class ProxyInfo:
    address: str
    kind: Optional[str] = None
    implementation: Optional[str] = None
    beacon: Optional[str] = None
    admin: Optional[str] = None
    code_size: int = 0

    @property
    def is_proxy(self) -> bool:
        return bool(self.kind and self.implementation)

    def to_dict(self) -> Dict[str, Any]:
        return {"address": self.address, "kind": self.kind, "implementation": self.implementation,
                "beacon": self.beacon, "admin": self.admin, "code_size": self.code_size}


def resolve_proxy(reader: Reader, address: str) -> ProxyInfo:
    """Find the logic contract behind *address* (read-only; never raises)."""
    a = address.lower()
    code = reader.code(a)
    info = ProxyInfo(address=a, code_size=max((len(code) - 2) // 2, 0))
    if info.code_size == 0:
        return info
    # EIP-1167 / EIP-7511 minimal proxies (bytecode-only)
    for rx, kind in ((_EIP1167, "eip1167"), (_EIP7511, "eip1167-push0")):
        m = rx.search(code)
        if m:
            info.kind, info.implementation = kind, "0x" + m.group(1)
            return info
    # Storage-based proxies
    impl = _word_addr(reader.storage(a, SLOT_EIP1967_IMPL))
    if impl:
        info.kind, info.implementation = "eip1967", impl
        info.admin = _word_addr(reader.storage(a, SLOT_EIP1967_ADMIN))
        return info
    beacon = _word_addr(reader.storage(a, SLOT_EIP1967_BEACON))
    if beacon:
        info.beacon = beacon
        # EIP-1967 beacon: implementation() on the beacon
        be_impl = reader.call_addr(beacon, SEL["implementation()"])
        if be_impl:
            info.kind, info.implementation = "eip1967-beacon", be_impl
            return info
    uups = _word_addr(reader.storage(a, SLOT_EIP1822))
    if uups:
        info.kind, info.implementation = "eip1822", uups
        return info
    oz = _word_addr(reader.storage(a, SLOT_OZ_LEGACY))
    if oz:
        info.kind, info.implementation = "oz-legacy", oz
        return info
    # Gnosis Safe: masterCopy at slot 0 (or masterCopy())
    slot0 = _word_addr(reader.storage(a, "0x0"))
    if slot0 and has_delegatecall(code):
        # Prefer masterCopy() confirmation when present
        mc = reader.call_addr(a, SEL["masterCopy()"])
        if mc:
            info.kind, info.implementation = "gnosis-safe", mc
            return info
        # Heuristic: slot0 + DELEGATECALL + small/medium code looks like a Safe
        if info.code_size < 3000:
            info.kind, info.implementation = "gnosis-safe", slot0
            return info
    # EIP-897: implementation() only when the contract itself DELEGATECALLs
    if has_delegatecall(code):
        ei = reader.call_addr(a, SEL["implementation()"])
        if ei and ei != a:
            info.kind, info.implementation = "eip897", ei
            return info
    return info


# ---------------------------------------------------------------------------
# Token pricing (protocol-specific tokens beyond the Phase-19 major list)
# ---------------------------------------------------------------------------

HttpGet = Callable[[str, float], bytes]


def _http_get(url: str, timeout: float) -> bytes:
    import urllib.request
    host = urllib.parse.urlparse(url).hostname or ""
    if urllib.parse.urlparse(url).scheme != "https" or host not in (
            "coins.llama.fi", "api.coingecko.com"):
        raise ValueError(f"refusing host {host}")
    req = urllib.request.Request(url, method="GET",
                                 headers={"User-Agent": "contract-auditor/vault",
                                          "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
        return resp.read()


class TokenPricer:
    """Live USD prices for arbitrary ERC-20s (DefiLlama coins, CoinGecko fallback)."""

    def __init__(self, http_get: HttpGet = _http_get, clock: Callable[[], float] = time.time,
                 ttl: float = 300.0, major: Optional[Mapping[str, float]] = None):
        self.http_get, self.clock, self.ttl = http_get, clock, ttl
        self._cache: Dict[str, Tuple[float, Optional[float]]] = {}  # addr -> (as_of, usd)
        self.as_of: Optional[float] = None
        self.source: Optional[str] = None
        # Seed with Phase-19 major prices when the caller already has them.
        for a, p in (major or {}).items():
            self._cache[a.lower()] = (clock(), float(p) if p is not None else None)

    def seed_major(self, prices: Mapping[str, Any]) -> None:
        """Seed from a Phase-19 PriceSource.prices() result (coingecko ids)."""
        from .value_at_risk import TOKENS, NATIVE
        pmap = prices.get("prices") or {}
        now = self.clock()
        if "ethereum" in pmap and pmap["ethereum"] is not None:
            self._cache["native:eth"] = (now, float(pmap["ethereum"]))
        for sym, t in TOKENS.items():
            pid = t["price_id"]
            if pid in pmap and pmap[pid] is not None:
                self._cache[t["address"].lower()] = (now, float(pmap[pid]))
        self.as_of = prices.get("as_of") or now
        self.source = prices.get("source") or "coingecko"

    def price(self, address: Optional[str] = None, *, native: bool = False) -> Optional[float]:
        key = "native:eth" if native else (address or "").lower()
        if not key:
            return None
        now = self.clock()
        if key in self._cache and now - self._cache[key][0] < self.ttl:
            return self._cache[key][1]
        return None

    def fetch_many(self, addresses: Sequence[str]) -> Dict[str, Optional[float]]:
        need = []
        now = self.clock()
        for a in addresses:
            if not a:
                continue
            a = a.lower()
            cached = self._cache.get(a)
            if cached is None or now - cached[0] >= self.ttl:
                need.append(a)
        need = list(dict.fromkeys(need))
        out: Dict[str, Optional[float]] = {}
        if not need:
            for a in addresses:
                out[a.lower()] = self.price(a)
            return out
        # DefiLlama coins API (batch)
        try:
            keys = ",".join(f"ethereum:{a}" for a in need)
            raw = self.http_get(COINS_LLAMA + keys, 20.0)
            data = json.loads(raw.decode("utf-8") if isinstance(raw, bytes) else raw)
            coins = (data or {}).get("coins") or {}
            now = self.clock()
            for a in need:
                c = coins.get(f"ethereum:{a}") or {}
                usd = c.get("price")
                usd = float(usd) if isinstance(usd, (int, float)) else None
                self._cache[a] = (now, usd)
                if usd is not None:
                    self.as_of = now
                    self.source = "defillama coins"
            missing = [a for a in need if self._cache.get(a, (0, None))[1] is None]
        except Exception as exc:  # noqa: BLE001
            log.info("vault: llama prices: %s", type(exc).__name__)
            missing = list(need)
        # CoinGecko token_price fallback for anything still unknown
        if missing:
            try:
                q = urllib.parse.urlencode({"contract_addresses": ",".join(missing[:50]),
                                            "vs_currencies": "usd"})
                raw = self.http_get(f"{COINGECKO_TOKEN}?{q}", 20.0)
                data = json.loads(raw.decode("utf-8") if isinstance(raw, bytes) else raw)
                now = self.clock()
                for a in missing:
                    v = (data or {}).get(a) or (data or {}).get(a.lower()) or {}
                    usd = v.get("usd") if isinstance(v, dict) else None
                    usd = float(usd) if isinstance(usd, (int, float)) else None
                    self._cache[a] = (now, usd)
                    if usd is not None:
                        self.as_of = now
                        self.source = (self.source or "") + "+coingecko" if self.source else "coingecko"
            except Exception as exc:  # noqa: BLE001
                log.info("vault: coingecko prices: %s", type(exc).__name__)
                now = self.clock()
                for a in missing:
                    self._cache.setdefault(a, (now, None))
        for a in addresses:
            out[a.lower()] = self.price(a)
        return out


# ---------------------------------------------------------------------------
# Holder measurement
# ---------------------------------------------------------------------------

@dataclass
class Holding:
    symbol: str
    token: Optional[str]          # None for native ETH
    amount: float
    usd: Optional[float]
    decimals: int
    source: str                   # balance | totalAssets | totalSupply

    def to_dict(self) -> Dict[str, Any]:
        return {"symbol": self.symbol, "token": self.token, "amount": self.amount,
                "usd": round(self.usd, 2) if self.usd is not None else None,
                "decimals": self.decimals, "source": self.source}


@dataclass
class Holder:
    address: str
    role: str                     # seed | vault | strategy | escrow | token | related | proxy
    via: Optional[str] = None     # getter that discovered it
    parent: Optional[str] = None
    proxy: Optional[ProxyInfo] = None
    holdings: List[Holding] = field(default_factory=list)
    value_usd: Optional[float] = None
    total_assets_usd: Optional[float] = None  # ERC-4626 totalAssets priced
    is_erc20: bool = False
    is_erc4626: bool = False
    symbol: Optional[str] = None
    name: Optional[str] = None
    notes: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {"address": self.address, "role": self.role, "via": self.via, "parent": self.parent,
                "proxy": self.proxy.to_dict() if self.proxy else None,
                "holdings": [h.to_dict() for h in self.holdings],
                "value_usd": round(self.value_usd, 2) if self.value_usd is not None else None,
                "total_assets_usd": (round(self.total_assets_usd, 2)
                                    if self.total_assets_usd is not None else None),
                "is_erc20": self.is_erc20, "is_erc4626": self.is_erc4626,
                "symbol": self.symbol, "name": self.name, "notes": self.notes,
                "label": VALUE_LABEL}


from .value_at_risk import TOKENS, NATIVE  # noqa: E402  (late; keeps SEL/slots importable alone)


def _abi_view_address_getters(abi: Sequence[Mapping[str, Any]]) -> List[Tuple[str, str]]:
    """Zero-arg view functions returning address, minus access-control noise."""
    out: List[Tuple[str, str]] = []
    for f in abi or []:
        if not isinstance(f, Mapping) or f.get("type") != "function":
            continue
        if f.get("stateMutability") not in ("view", "pure"):
            continue
        if f.get("inputs"):
            continue
        outs = f.get("outputs") or []
        if len(outs) != 1 or outs[0].get("type") != "address":
            continue
        name = str(f.get("name") or "")
        if not name or _SKIP_GETTER.search(name):
            continue
        # keccak selector — reuse Crypto when available, else skip ABI path
        try:
            from Crypto.Hash import keccak
            h = keccak.new(digest_bits=256)
            h.update(f"{name}()".encode())
            sel = "0x" + h.hexdigest()[:8]
        except Exception:  # noqa: BLE001
            continue
        out.append((f"{name}()", sel))
    return out


def detect_token(reader: Reader, address: str) -> Dict[str, Any]:
    """Is *address* an ERC-20 / ERC-4626? Never raises."""
    info: Dict[str, Any] = {"is_erc20": False, "is_erc4626": False,
                            "symbol": None, "decimals": None, "asset": None,
                            "total_supply": None, "total_assets": None}
    ts = reader.call_int(address, SEL["totalSupply()"])
    if ts is None:
        return info
    info["is_erc20"] = True
    info["total_supply"] = ts
    info["decimals"] = reader.call_int(address, SEL["decimals()"])
    info["symbol"] = _decode_string(reader.call(address, SEL["symbol()"]))
    asset = reader.call_addr(address, SEL["asset()"])
    if asset:
        info["is_erc4626"] = True
        info["asset"] = asset
        info["total_assets"] = reader.call_int(address, SEL["totalAssets()"])
    return info


def measure_holder(reader: Reader, address: str, pricer: TokenPricer,
                   extra_tokens: Optional[Sequence[str]] = None,
                   role: str = "related", via: Optional[str] = None,
                   parent: Optional[str] = None,
                   proxy: Optional[ProxyInfo] = None) -> Holder:
    """Live holdings of *address* (ETH + majors + *extra_tokens*). Never raises."""
    h = Holder(address=address.lower(), role=role, via=via, parent=parent, proxy=proxy)
    # Native
    eth = reader.native(address)
    eth_price = pricer.price(native=True)
    if eth is not None and eth > 0:
        qty = eth / 1e18
        usd = qty * eth_price if eth_price is not None else None
        h.holdings.append(Holding("ETH", None, qty, usd, 18, "balance"))
    # Major tokens
    for sym, t in TOKENS.items():
        bal = reader.balance_of(t["address"], address)
        if bal is None or bal == 0:
            continue
        qty = bal / (10 ** int(t["decimals"]))
        px = pricer.price(t["address"])
        usd = qty * px if px is not None else None
        h.holdings.append(Holding(sym, t["address"], qty, usd, int(t["decimals"]), "balance"))
    # Protocol-specific tokens
    for tok in extra_tokens or ():
        tok = tok.lower()
        if any(t["address"] == tok for t in TOKENS.values()):
            continue
        bal = reader.balance_of(tok, address)
        if bal is None or bal == 0:
            continue
        meta = detect_token(reader, tok)
        dec = int(meta["decimals"] if meta["decimals"] is not None else 18)
        qty = bal / (10 ** dec)
        px = pricer.price(tok)
        usd = qty * px if px is not None else None
        sym = meta["symbol"] or (tok[:6] + ".." + tok[-4:])
        h.holdings.append(Holding(sym, tok, qty, usd, dec, "balance"))
    # ERC-4626 totalAssets (reported even when the vault itself holds $0 of majors)
    meta_self = detect_token(reader, address)
    h.is_erc20 = meta_self["is_erc20"]
    h.is_erc4626 = meta_self["is_erc4626"]
    h.symbol = meta_self["symbol"]
    if meta_self["is_erc4626"] and meta_self.get("total_assets") is not None:
        asset = meta_self["asset"]
        am = detect_token(reader, asset) if asset else {}
        adec = int(am.get("decimals") if am.get("decimals") is not None else 18)
        qty = meta_self["total_assets"] / (10 ** adec)
        # Prefer pricing the underlying; fall back to the vault share itself
        px = pricer.price(asset) if asset else None
        if px is None:
            px = pricer.price(address)
        usd = qty * px if px is not None else None
        h.total_assets_usd = usd
        asym = (am.get("symbol") if am else None) or "asset"
        h.holdings.append(Holding(f"totalAssets({asym})", asset, qty, usd, adec, "totalAssets"))
        h.notes.append("ERC-4626 totalAssets reported (may sit in a strategy, not this address)")
    total = sum(x.usd for x in h.holdings if x.usd is not None)
    # Prefer the larger of (direct balances) and totalAssets when both exist
    if h.total_assets_usd is not None:
        # Direct balances exclude the totalAssets synthetic row for the "value held" field
        direct = sum(x.usd for x in h.holdings if x.usd is not None and x.source == "balance")
        h.value_usd = max(direct, h.total_assets_usd) if direct else h.total_assets_usd
    else:
        h.value_usd = total if h.holdings else 0.0
    return h


# ---------------------------------------------------------------------------
# Vault discovery walk
# ---------------------------------------------------------------------------

@dataclass
class DiscoveryResult:
    seeds: List[str]
    holders: List[Holder]
    tokens: List[str]
    proxies: Dict[str, Dict[str, Any]]
    ranked: List[Holder]
    calls: int = 0
    errors: int = 0
    notes: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {"seeds": self.seeds, "holders": [h.to_dict() for h in self.holders],
                "tokens": self.tokens, "proxies": self.proxies,
                "ranked": [h.to_dict() for h in self.ranked],
                "calls": self.calls, "errors": self.errors, "notes": self.notes,
                "label": VALUE_LABEL}


class VaultDiscovery:
    """BFS over a protocol's related contracts; rank by live holdings."""

    def __init__(self, reader: Reader, pricer: TokenPricer,
                 abi_lookup: Optional[Callable[[str], Optional[Sequence[Mapping[str, Any]]]]] = None,
                 max_depth: int = 3, max_nodes: int = 40,
                 clock: Callable[[], float] = time.time):
        self.reader = reader
        self.pricer = pricer
        self.abi_lookup = abi_lookup
        self.max_depth = int(max_depth)
        self.max_nodes = int(max_nodes)
        self.clock = clock

    def _getters_for(self, address: str) -> List[Tuple[str, str]]:
        abi = None
        if self.abi_lookup:
            try:
                abi = self.abi_lookup(address)
            except Exception:  # noqa: BLE001
                abi = None
        if abi:
            got = _abi_view_address_getters(abi)
            if got:
                return got
        return list(STRUCTURAL_GETTERS.items()) + list(TOKEN_GETTERS.items())

    def discover(self, seeds: Sequence[str],
                 seed_roles: Optional[Mapping[str, str]] = None) -> DiscoveryResult:
        seeds_l = [s.lower() for s in seeds if s]
        seeds_l = list(dict.fromkeys(seeds_l))
        roles = {k.lower(): v for k, v in (seed_roles or {}).items()}
        visited: Dict[str, Holder] = {}
        tokens: Dict[str, str] = {}          # token addr -> how found
        proxies: Dict[str, Dict[str, Any]] = {}
        queue: List[Tuple[str, int, Optional[str], Optional[str], str]] = []
        # (addr, depth, via, parent, role)
        for s in seeds_l:
            queue.append((s, 0, None, None, roles.get(s, "seed")))
        notes: List[str] = []

        while queue and len(visited) < self.max_nodes:
            addr, depth, via, parent, role = queue.pop(0)
            if addr in visited or addr == ZERO:
                continue
            if not self.reader.is_contract(addr):
                continue
            proxy = resolve_proxy(self.reader, addr)
            if proxy.is_proxy:
                proxies[addr] = proxy.to_dict()
            # Resolve: walk/scan the implementation for getters; measure at the proxy.
            logic = proxy.implementation if proxy.is_proxy else addr
            # Detect whether this seed itself is an ERC-20 we should treat as a token
            meta = detect_token(self.reader, addr)
            if meta["is_erc20"] and role == "seed":
                tokens[addr] = "seed-erc20"
                if meta.get("asset"):
                    tokens[meta["asset"]] = "seed-asset"
            # Collect neighbours
            if depth < self.max_depth and role != "token":
                for gname, sel in self._getters_for(logic):
                    # eth_call against a proxy DELEGATECALLs into the impl — always call the proxy.
                    target = self.reader.call_addr(addr, sel)
                    if target is None or target == addr or target in visited:
                        continue
                    is_tok_getter = gname in TOKEN_GETTERS or gname.startswith("asset") or gname in (
                        "underlying()", "token()", "want()", "collateral()", "sUSDe()", "USDe()",
                        "token0()", "token1()", "stakingToken()")
                    if is_tok_getter:
                        tokens[target] = gname
                        # Measure the token itself only as a candidate if it holds other assets
                        # (rare); primarily it becomes an extra_token for holder pricing.
                        continue
                    # Structural neighbour
                    nrole = "strategy" if "strategy" in gname else (
                        "vault" if "vault" in gname or "cdo" in gname else (
                            "escrow" if any(k in gname for k in ("escrow", "silo", "custodian",
                                                                "lockbox", "treasury")) else "related"))
                    if self.reader.is_contract(target):
                        queue.append((target, depth + 1, gname, addr, nrole))
            # Also walk the implementation address as a related contract (for source)
            if proxy.is_proxy and proxy.implementation and proxy.implementation not in visited:
                # Implementations themselves rarely hold funds; skip measuring, just note.
                pass
            # Measure later (after we know the full token set) — stash a placeholder
            visited[addr] = Holder(address=addr, role=role, via=via, parent=parent, proxy=proxy,
                                   is_erc20=meta["is_erc20"], is_erc4626=meta["is_erc4626"],
                                   symbol=meta["symbol"])

        # Price every known token once, then measure each holder
        token_list = list(tokens)
        # Also include ERC-4626 assets from holders
        for h in list(visited.values()):
            meta = detect_token(self.reader, h.address)
            if meta.get("asset"):
                token_list.append(meta["asset"])
                tokens[meta["asset"]] = tokens.get(meta["asset"], "holder-asset")
        token_list = list(dict.fromkeys(token_list))
        # Seed major prices if the pricer has none yet
        if self.pricer.price(native=True) is None:
            try:
                from .value_at_risk import PriceSource
                ps = PriceSource(enabled=True)
                ids = [NATIVE["price_id"]] + [t["price_id"] for t in TOKENS.values()]
                self.pricer.seed_major(ps.prices(ids))
            except Exception as exc:  # noqa: BLE001
                notes.append(f"major prices unavailable: {type(exc).__name__}")
        self.pricer.fetch_many(token_list)

        measured: List[Holder] = []
        for addr, stub in visited.items():
            # Tokens that are seeds get measured (e.g. Noon USN totalSupply is the TVL signal);
            # other pure ERC-20s discovered via token getters are not ranked as holders.
            if stub.role == "token":
                continue
            holder = measure_holder(self.reader, addr, self.pricer, extra_tokens=token_list,
                                    role=stub.role, via=stub.via, parent=stub.parent,
                                    proxy=stub.proxy)
            # For seed ERC-20s whose own balance is $0, fall back to totalSupply × price
            # (Noon USN is the protocol TVL itself).
            if (holder.is_erc20 and (holder.value_usd or 0) < 1.0
                    and stub.role == "seed"):
                meta = detect_token(self.reader, addr)
                if meta.get("total_supply") is not None:
                    dec = int(meta["decimals"] if meta["decimals"] is not None else 18)
                    qty = meta["total_supply"] / (10 ** dec)
                    px = self.pricer.price(addr)
                    if px is not None:
                        usd = qty * px
                        holder.holdings.append(Holding(
                            meta["symbol"] or "token", addr, qty, usd, dec, "totalSupply"))
                        holder.value_usd = (holder.value_usd or 0) + usd
                        holder.notes.append(
                            "seed ERC-20: value = totalSupply x price (protocol liability / TVL signal)")
            measured.append(holder)

        ranked = sorted(measured, key=lambda h: (h.value_usd or 0.0), reverse=True)
        return DiscoveryResult(seeds=seeds_l, holders=measured, tokens=list(tokens),
                               proxies=proxies, ranked=ranked,
                               calls=self.reader.calls, errors=self.reader.errors, notes=notes)


def related_contracts_from_etherscan(client: Any, address: str, limit: int = 10) -> List[str]:
    """Best-effort: contracts created by the same deployer (Etherscan GET). Never raises."""
    try:
        # Etherscan V2: getcontractcreation → then txlist of the creator
        data = client._etherscan(module="contract", action="getcontractcreation",
                                 contractaddresses=address)  # noqa: SLF001
        result = (data or {}).get("result") if isinstance(data, dict) else None
        if not isinstance(result, list) or not result:
            return []
        creator = str(result[0].get("contractCreator") or "").lower()
        if not creator.startswith("0x"):
            return []
        data2 = client._etherscan(module="account", action="txlist", address=creator,
                                  startblock=0, endblock=99999999, page=1, offset=100,
                                  sort="desc")  # noqa: SLF001
        txs = (data2 or {}).get("result") if isinstance(data2, dict) else None
        if not isinstance(txs, list):
            return []
        out: List[str] = []
        for tx in txs:
            if not isinstance(tx, dict):
                continue
            # Contract creations have empty `to`
            if not tx.get("to") and tx.get("contractAddress"):
                a = str(tx["contractAddress"]).lower()
                if a != address.lower() and a not in out:
                    out.append(a)
            if len(out) >= limit:
                break
        return out
    except Exception as exc:  # noqa: BLE001
        log.info("vault: etherscan related: %s", type(exc).__name__)
        return []
