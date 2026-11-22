"""Phase 19 — rough value-at-risk / financial-loss estimates per finding and contract.

ALL NUMBERS HERE ARE ROUGH ESTIMATES. They combine:

* the contract's current holdings — native ETH plus a fixed list of major
  ERC-20s (WETH, USDC, USDT, DAI, WBTC, stETH) — read with read-only GET
  calls (Etherscan ``account`` module, or ``eth_getBalance`` / ``eth_call
  balanceOf`` on a configured read-only RPC). For a proxy the proxy
  address's own balance is used (that is where the funds sit);
* USD prices from CoinGecko's public ``simple/price`` endpoint (no key),
  cached locally with a "price as of" timestamp; when prices are unavailable
  USD values are ``None`` and token amounts are still reported;
* a per-vulnerability-class exposure factor and band from the risk playbook
  (``exposure`` block in ``auditor/data/risk_playbook.json``).

Estimated loss = value_at_risk × exposure factor (band low/high). It is not
a prediction, says nothing about exploitability, and ignores funds held by
other contracts that trust this one, future deposits, and price impact.
"""

from __future__ import annotations

import json
import os
import time
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence

ESTIMATE_LABEL = "rough estimate"
COINGECKO_URL = "https://api.coingecko.com/api/v3/simple/price"
PRICE_TTL_S = 300.0
PRICE_MAX_STALE_S = 24 * 3600.0

#: Ethereum mainnet token list (address, decimals, CoinGecko id).
TOKENS: Dict[str, Dict[str, Any]] = {
    "WETH": {"address": "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2", "decimals": 18, "price_id": "weth"},
    "USDC": {"address": "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48", "decimals": 6, "price_id": "usd-coin"},
    "USDT": {"address": "0xdac17f958d2ee523a2206206994597c13d831ec7", "decimals": 6, "price_id": "tether"},
    "DAI": {"address": "0x6b175474e89094c44da98b954eedeac495271d0f", "decimals": 18, "price_id": "dai"},
    "WBTC": {"address": "0x2260fac5e5542a773aa44fbcfedf7c193bc2c599", "decimals": 8, "price_id": "wrapped-bitcoin"},
    "stETH": {"address": "0xae7ab96520de3a18e5e111b5eaab095312d7fe84", "decimals": 18, "price_id": "staked-ether"},
}
NATIVE = {"symbol": "ETH", "decimals": 18, "price_id": "ethereum"}

SEVERITY_WEIGHT = {"CRITICAL": 1.0, "HIGH": 0.8, "MEDIUM": 0.4, "LOW": 0.1, "INFORMATIONAL": 0.02}

DEFAULT_EXPOSURE = {"model": "partial", "factor": 0.05, "low": 0.0, "high": 0.1,
                    "assumption": "Unclassified finding: small share of holdings assumed at risk."}

#: Slug-level overrides of the class exposure (applied before the class table).
SLUG_EXPOSURE = {
    "locked-ether": {"model": "locked", "factor": 1.0, "low": 1.0, "high": 1.0,
                     "assumption": "Locked ether: the native ETH balance cannot be withdrawn by anyone; "
                                   "estimate = ETH held (tokens excluded)."},
}

PRIVILEGED_EXPOSURE = {"model": "privileged", "factor": 0.0, "low": 0.0, "high": 0.0,
                       "assumption": "Privileged-only action: no loss expected from outsiders. The "
                                     "privileged account itself could withdraw everything (owner-rug "
                                     "exposure = full value at risk, shown separately)."}


# ---------------------------------------------------------------------------
# Prices
# ---------------------------------------------------------------------------

HttpGet = Callable[[str, float], bytes]


def _http_get(url: str, timeout: float) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "contract-auditor/value", "Accept": "application/json"},
                                 method="GET")
    with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310 - fixed https host
        return r.read()


def default_price_cache() -> Path:
    override = os.environ.get("AUDITOR_PRICE_CACHE", "").strip()
    if override:
        return Path(override)
    from .monitor import default_cache_dir

    return default_cache_dir() / "prices.json"


class PriceSource:
    """CoinGecko simple price, cached on disk. Never raises; unavailable → None prices."""

    def __init__(self, cache_path: Optional[Path] = None, http_get: HttpGet = _http_get,
                 clock: Callable[[], float] = time.time, ttl: float = PRICE_TTL_S,
                 max_stale: float = PRICE_MAX_STALE_S, enabled: bool = True):
        self.cache_path = Path(cache_path) if cache_path else default_price_cache()
        self.http_get = http_get
        self.clock = clock
        self.ttl = ttl
        self.max_stale = max_stale
        self.enabled = enabled
        self.last_error: Optional[str] = None

    def _load(self) -> Dict[str, Any]:
        try:
            return json.loads(self.cache_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}

    def _save(self, data: Dict[str, Any]) -> None:
        try:
            self.cache_path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.cache_path.with_suffix(".tmp")
            tmp.write_text(json.dumps(data, sort_keys=True), encoding="utf-8")
            tmp.replace(self.cache_path)
        except OSError:
            pass

    def prices(self, ids: Sequence[str]) -> Dict[str, Any]:
        """{"prices": {id: usd|None}, "as_of": epoch|None, "source": str, "stale": bool, "error": str|None}"""
        now = self.clock()
        cache = self._load()
        cached = cache.get("prices") or {}
        fetched_at = float(cache.get("fetched_at") or 0)
        have_all = all(i in cached for i in ids)
        if have_all and now - fetched_at < self.ttl:
            return self._result(cached, ids, cache, stale=False)
        if self.enabled:
            try:
                q = urllib.parse.urlencode({"ids": ",".join(sorted(set(ids) | set(cached))),
                                            "vs_currencies": "usd", "include_last_updated_at": "true"})
                body = self.http_get(f"{COINGECKO_URL}?{q}", 15.0)
                data = json.loads(body.decode("utf-8") if isinstance(body, bytes) else body)
                new = {}
                as_of = []
                for k, v in (data or {}).items():
                    if isinstance(v, dict) and isinstance(v.get("usd"), (int, float)):
                        new[k] = {"usd": float(v["usd"]), "last_updated_at": v.get("last_updated_at")}
                        if isinstance(v.get("last_updated_at"), (int, float)):
                            as_of.append(float(v["last_updated_at"]))
                if new:
                    cache = {"prices": {**cached, **new}, "fetched_at": now,
                             "as_of": min(as_of) if as_of else now, "source": "coingecko simple/price"}
                    self._save(cache)
                    return self._result(cache["prices"], ids, cache, stale=False)
                self.last_error = "price source returned no usable prices"
            except Exception as exc:  # noqa: BLE001 - graceful when unavailable
                self.last_error = f"price source unavailable: {type(exc).__name__}"
        if cached and now - fetched_at < self.max_stale:
            return self._result(cached, ids, cache, stale=True)
        return {"prices": {i: None for i in ids}, "as_of": None, "source": None, "stale": False,
                "error": self.last_error or "prices disabled"}

    def _result(self, cached, ids, cache, stale) -> Dict[str, Any]:
        return {"prices": {i: (cached.get(i) or {}).get("usd") for i in ids},
                "as_of": cache.get("as_of") or cache.get("fetched_at"),
                "source": cache.get("source", "coingecko simple/price") + (" (stale cache)" if stale else ""),
                "stale": stale, "error": self.last_error if stale else None}


# ---------------------------------------------------------------------------
# Holdings
# ---------------------------------------------------------------------------

def fetch_holdings(client: Any, address: str, tokens: Mapping[str, Mapping[str, Any]] = TOKENS
                   ) -> Dict[str, Any]:
    """Raw holdings via the monitor ChainClient's read-only methods. Never raises."""
    out: Dict[str, Any] = {"address": address.lower(), "native": None, "tokens": {}, "errors": []}
    try:
        out["native"] = int(client.native_balance(address))
    except Exception as exc:  # noqa: BLE001
        out["errors"].append(f"ETH balance unavailable: {type(exc).__name__}")
    for sym, t in tokens.items():
        try:
            out["tokens"][sym] = int(client.token_balance(t["address"], address))
        except Exception as exc:  # noqa: BLE001
            out["errors"].append(f"{sym} balance unavailable: {type(exc).__name__}")
    return out


@dataclass
class ValueAtRisk:
    address: str
    holdings: List[Dict[str, Any]] = field(default_factory=list)
    tvl_usd: Optional[float] = None
    native_usd: Optional[float] = None
    price_as_of: Optional[float] = None
    price_source: Optional[str] = None
    price_stale: bool = False
    complete: bool = True               # every balance + price known
    notes: List[str] = field(default_factory=list)
    is_proxy: bool = False
    implementation: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {"is_estimate": True, "label": ESTIMATE_LABEL, "address": self.address,
                "holdings": self.holdings, "tvl_usd": _r(self.tvl_usd), "native_usd": _r(self.native_usd),
                "price_as_of": self.price_as_of, "price_source": self.price_source,
                "price_stale": self.price_stale, "complete": self.complete, "notes": self.notes,
                "is_proxy": self.is_proxy, "implementation": self.implementation}


def _r(v: Optional[float]) -> Optional[float]:
    return None if v is None else round(float(v), 2)


def value_contract(raw: Mapping[str, Any], prices: Mapping[str, Any], record: Optional[Mapping[str, Any]] = None
                   ) -> ValueAtRisk:
    """Combine raw holdings and prices into a ValueAtRisk (pure function)."""
    v = ValueAtRisk(address=str(raw.get("address") or ""))
    v.notes += list(raw.get("errors") or [])
    p = prices.get("prices") or {}
    v.price_as_of, v.price_source, v.price_stale = prices.get("as_of"), prices.get("source"), bool(prices.get("stale"))
    if prices.get("error"):
        v.notes.append(str(prices["error"]))
    rows = [("ETH", raw.get("native"), NATIVE["decimals"], NATIVE["price_id"])]
    rows += [(s, (raw.get("tokens") or {}).get(s), TOKENS[s]["decimals"], TOKENS[s]["price_id"])
             for s in TOKENS]
    total, known = 0.0, True
    for sym, amount, dec, pid in rows:
        if amount is None:
            known = False
            v.holdings.append({"symbol": sym, "amount": None, "usd": None, "price_usd": p.get(pid)})
            continue
        qty = int(amount) / (10 ** dec)
        price = p.get(pid)
        usd = qty * price if price is not None else None
        if amount and price is None:
            known = False
        if usd is not None:
            total += usd
        if sym == "ETH":
            v.native_usd = usd if usd is not None else (0.0 if not amount else None)
        if amount:
            v.holdings.append({"symbol": sym, "amount": qty, "usd": _r(usd), "price_usd": price})
    any_value = any(h.get("usd") for h in v.holdings)
    v.tvl_usd = total if (known or any_value) else None
    v.complete = known
    if not known:
        v.notes.append("some balances or prices were unavailable: TVL is a lower bound or unknown")
    if record:
        if str(record.get("Proxy") or "0") == "1":
            v.is_proxy = True
            v.implementation = str(record.get("Implementation") or "") or None
            v.notes.append("proxy: balances are the proxy address's own (where user funds sit)")
    return v


# ---------------------------------------------------------------------------
# Per-finding loss
# ---------------------------------------------------------------------------

def exposure_for(finding: Mapping[str, Any], triage: Optional[Mapping[str, Any]] = None) -> Dict[str, Any]:
    from .risk_playbook import classify, load_playbook

    if triage and triage.get("reason") == "privileged-withdraw":
        return dict(PRIVILEGED_EXPOSURE, vulnerability_class="privileged_withdraw")
    if triage and triage.get("reason") == "privileged-module-caller":
        return dict(PRIVILEGED_EXPOSURE, vulnerability_class="privileged_module_caller",
                    assumption="Only a governance-set module address can trigger this transfer: 0% for "
                               "outsiders. If that module or governance were compromised, funds held or "
                               "approved to this contract would be exposed (shown as owner-rug exposure).")
    cls, slug = classify(finding)
    if slug in SLUG_EXPOSURE:
        return dict(SLUG_EXPOSURE[slug], vulnerability_class=cls)
    e = (load_playbook()["classes"].get(cls) or {}).get("exposure") or DEFAULT_EXPOSURE
    return dict(e, vulnerability_class=cls)


def estimate_finding(finding: Mapping[str, Any], var: Optional[ValueAtRisk],
                     triage: Optional[Mapping[str, Any]] = None) -> Dict[str, Any]:
    """Estimated loss for one finding (rough estimate; never raises)."""
    e = exposure_for(finding, triage)
    sev = str(finding.get("severity") or "INFORMATIONAL").upper()
    base = None
    if var is not None:
        base = var.native_usd if e["model"] == "locked" else var.tvl_usd
    out: Dict[str, Any] = {
        "is_estimate": True, "label": ESTIMATE_LABEL, "model": e["model"],
        "vulnerability_class": e.get("vulnerability_class"),
        "exposure_factor": e["factor"], "band_factors": [e["low"], e["high"]],
        "value_basis_usd": _r(base), "est_loss_usd": None, "est_loss_low_usd": None, "est_loss_high_usd": None,
        "owner_rug_exposure_usd": None, "user_funds_at_risk": False, "bait_balance_usd": None,
        "assumptions": [e["assumption"]], "severity": sev, "weighted_score": 0.0,
    }
    if e["model"] == "honeypot":
        out["user_funds_at_risk"] = True
        out["bait_balance_usd"] = _r(base)
        out["assumptions"].append("Honeypot: the contract is the scam, not the victim. The bait balance "
                                  "is shown to indicate scale; actual user losses depend on deposits.")
    if e["model"] == "privileged":
        out["owner_rug_exposure_usd"] = _r(base)
    if base is not None:
        out["est_loss_usd"] = _r(base * e["factor"])
        out["est_loss_low_usd"] = _r(base * e["low"])
        out["est_loss_high_usd"] = _r(base * e["high"])
    else:
        out["assumptions"].append("Value at risk unknown (balances or prices unavailable).")
    out["weighted_score"] = weighted_score(out["est_loss_usd"], sev)
    return out


def weighted_score(est_loss_usd: Optional[float], severity: str) -> float:
    """Severity-weighted ranking key: dollars dominate, severity breaks ties and scales.

    score = est_loss × weight(severity) + weight(severity) × 1e-3, so a $1M
    exposure always ranks above a $400 one, and with equal dollars a HIGH
    ranks above a LOW. Unknown value ranks by severity only.
    """
    w = SEVERITY_WEIGHT.get(str(severity).upper(), 0.02)
    return round((float(est_loss_usd or 0.0)) * w + w * 1e-3, 6)


def summarize(estimates: Sequence[Mapping[str, Any]], var: Optional[ValueAtRisk]) -> Dict[str, Any]:
    """Contract-level roll-up over KEPT (non-suppressed) findings.

    INFORMATIONAL findings (centralization notes, lock-covered / admin-fixed
    shapes) keep their per-finding estimate but never set the contract's
    exposure headline: they describe no outsider path.
    """
    estimates = [e for e in estimates if str(e.get("severity") or "").upper() != "INFORMATIONAL"]
    worst = max(estimates, key=lambda e: (e.get("est_loss_usd") or 0.0, e.get("weighted_score") or 0.0),
                default=None)
    return {"is_estimate": True, "label": ESTIMATE_LABEL,
            "tvl_usd": _r(var.tvl_usd) if var else None,
            "est_max_loss_usd": worst.get("est_loss_usd") if worst else None,
            "est_max_loss_low_usd": worst.get("est_loss_low_usd") if worst else None,
            "est_max_loss_high_usd": worst.get("est_loss_high_usd") if worst else None,
            "risk_score": max((e.get("weighted_score") or 0.0 for e in estimates), default=0.0),
            "user_funds_at_risk": any(e.get("user_funds_at_risk") for e in estimates),
            "price_as_of": var.price_as_of if var else None}


def assess(client: Any, address: str, record: Optional[Mapping[str, Any]] = None,
           price_source: Optional[PriceSource] = None) -> ValueAtRisk:
    raw = fetch_holdings(client, address)
    ps = price_source or PriceSource()
    ids = [NATIVE["price_id"]] + [t["price_id"] for t in TOKENS.values()]
    return value_contract(raw, ps.prices(ids), record)
