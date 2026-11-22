"""Phase 20/21 — proactive target discovery ("hunt") for live DeFi contracts.

Builds a candidate list of Ethereum contracts that hold real value from free,
public, read-only sources, ranks them with a clearly labelled *priority hint*
and feeds the top unscanned ones through the existing monitor pipeline
(compiler selection, Slither + analyzers, triage, honeypot, value at risk).

Sources (all GET, no key):

* DefiLlama ``https://api.llama.fi/protocols`` — protocol name, category,
  Ethereum TVL, listing date, audit flag, fork info, protocol address.
* DefiLlama ``https://yields.llama.fi/pools`` — per-project Ethereum pool
  count / pool TVL (pool-level context; the free API has no pool addresses).
* DefiLlama's public adapter source (``DefiLlama-Adapters`` on GitHub, the
  ``tvlCodePath`` each protocol publishes) — contract addresses the TVL
  adapter itself reads. Every address is checked on-chain (``eth_getCode`` +
  balances) before it becomes a candidate.
* Optional: recent large ERC-20 transfers (``eth_getLogs`` / Etherscan logs
  GET) whose counterparty is a contract.

Phase 21 adds read-only proxy resolution (EIP-1967 / 1822 / OZ legacy / EIP-897 / Gnosis Safe / EIP-1167) and vault discovery: from each DefiLlama seed the hunter walks related contracts (adapter addresses, ABI / structural getters like ``strategy()`` / ``cdo()`` / ``vault()``) and ranks them by live on-chain holdings (ETH + majors + protocol tokens / ERC-4626 ``totalAssets()``). The implementation's verified source is scanned; value is measured at the proxy / vault address where the funds sit.

The priority score is a HEURISTIC hint for ordering manual/automated review.
It is never a claim that a bug exists. Nothing here sends a transaction,
signs anything or produces exploit material.
"""

from __future__ import annotations

# pool_discovery imported lazily inside Hunter.refresh

import json
import logging
import sqlite3
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from .monitor import (NETWORKS, RPC_ENV, ChainClient, Monitor, MonitorConfig, MonitorError,
                      MonitorStore, TransientError, _redact, default_alerts_path,
                      default_cache_dir, default_monitor_db_path)
from .supervisor import LockHeld, WorkerLock, record_worker_heartbeat, worker_lock_path

log = logging.getLogger("contract_auditor.hunt")

LLAMA_PROTOCOLS = "https://api.llama.fi/protocols"
LLAMA_POOLS = "https://yields.llama.fi/pools"
ADAPTER_RAW = "https://raw.githubusercontent.com/DefiLlama/DefiLlama-Adapters/main/projects/"
SOURCIFY_V2 = "https://sourcify.dev/server/v2/contract/{chain}/{address}?fields=all"
ALLOWED_HOSTS = ("api.llama.fi", "yields.llama.fi", "raw.githubusercontent.com", "sourcify.dev",
                 "api.dexscreener.com")

SCORE_LABEL = ("Priority hint (heuristic): orders review, NOT evidence that a bug exists. "
               "Based on public metadata (DefiLlama) and source shape only.")

CATEGORY_GROUPS: Dict[str, Tuple[str, ...]] = {
    "swaps": ("Dexs", "Dexes", "DEX Aggregator"),
    "pools": ("Dexs", "Dexes", "Liquidity Manager"),
    "bridges": ("Bridge", "Cross Chain Bridge", "Canonical Bridge"),
    "lending": ("Lending", "CDP", "NFT Lending"),
    "vaults": ("Yield", "Yield Aggregator", "Liquidity Manager"),
}
DEFAULT_GROUPS = ("pools", "swaps", "bridges", "lending", "vaults")

BLUE_CHIP_PREFIXES = ("uniswap", "aave", "compound", "lido", "curve", "makerdao", "sky", "spark",
                      "balancer", "convex", "rocket-pool", "eigenlayer", "morpho", "yearn", "sushi",
                      "frax", "pendle", "ethena", "1inch", "lagoon", "safe", "gnosis-safe", "gnosis")
KNOWN_FORK_NAMES = re.compile(
    r"^(UniswapV2Pair|UniswapV3Pool|UniswapV2Router0\d|SwapRouter|CErc20Delegator|CEther|AToken\w*|"
    r"BalancerPool\w*|WeightedPool\w*|ComposableStablePool|PancakePair|SushiSwapPair|GnosisSafe\w*|Safe)$")

_ADDR_RE = re.compile(r"0x[0-9a-fA-F]{40}")
_TRANSFER_TOPIC = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
# Approval(address indexed owner, address indexed spender, uint256 value)
_APPROVAL_TOPIC = "0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925"
_IGNORED_ADDR = {"0x0000000000000000000000000000000000000000",
                 "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
                 "0x000000000000000000000000000000000000dead"}
# Major ERC-20s / WETH — adapters mention them constantly; not hunt targets.
KNOWN_TOKEN_ADDR = {
    "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2",  # WETH
    "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",  # USDC
    "0xdac17f958d2ee523a2206206994597c13d831ec7",  # USDT
    "0x6b175474e89094c44da98b954eedeac495271d0f",  # DAI
    "0x2260fac5e5542a773aa44fbcfedf7c193bc2c599",  # WBTC
    "0xae7ab96520de3a18e5e111b5eaab095312d7fe84",  # stETH
}

HttpGet = Callable[[str, float], bytes]


def _http_get(url: str, timeout: float) -> bytes:
    host = urllib.parse.urlparse(url).hostname or ""
    if urllib.parse.urlparse(url).scheme != "https" or host not in ALLOWED_HOSTS:
        raise MonitorError(f"refusing non-allow-listed URL host: {host}")
    req = urllib.request.Request(url, method="GET",
                                 headers={"User-Agent": "contract-auditor/hunt",
                                          "Accept": "application/json, text/plain"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
        return resp.read()


def default_hunt_cache() -> Path:
    return default_cache_dir() / "hunt"


class JsonCache:
    """Tiny on-disk GET cache: one file per key, with TTL (seconds)."""

    def __init__(self, root: Path, http_get: HttpGet = _http_get,
                 clock: Callable[[], float] = time.time,
                 sleep: Callable[[float], None] = time.sleep,
                 min_interval: float = 0.5, timeout: float = 60.0):
        self.root = Path(root)
        self.http_get, self.clock, self.sleep = http_get, clock, sleep
        self.min_interval, self.timeout, self._last = min_interval, timeout, 0.0

    def _path(self, key: str) -> Path:
        return self.root / re.sub(r"[^A-Za-z0-9_.-]+", "_", key)[:150]

    def get(self, key: str, url: str, ttl: float, as_json: bool = True, force: bool = False) -> Any:
        p = self._path(key)
        now = self.clock()
        if not force and p.exists():
            try:
                blob = json.loads(p.read_text(encoding="utf-8"))
                if now - float(blob.get("fetched_at", 0)) <= ttl:
                    return blob["body"]
            except (ValueError, OSError, KeyError):
                pass
        wait = self.min_interval - (time.monotonic() - self._last)
        if wait > 0:
            self.sleep(wait)
        self._last = time.monotonic()
        try:
            raw = self.http_get(url, self.timeout)
            text = raw.decode("utf-8", errors="replace") if isinstance(raw, bytes) else str(raw)
            body = json.loads(text) if as_json else text
        except Exception as exc:  # noqa: BLE001
            if p.exists():
                try:
                    return json.loads(p.read_text(encoding="utf-8"))["body"]
                except (ValueError, OSError, KeyError):
                    pass
            raise TransientError(
                f"GET {urllib.parse.urlparse(url).hostname} failed: {type(exc).__name__}") from None
        p.parent.mkdir(parents=True, exist_ok=True)
        tmp = p.with_suffix(".tmp")
        tmp.write_text(json.dumps({"fetched_at": now, "url": url, "body": body}), encoding="utf-8")
        tmp.replace(p)
        return body


def sourcify_to_record(d: Mapping[str, Any]) -> Optional[Dict[str, Any]]:
    """Convert a Sourcify v2 ``fields=all`` response into an Etherscan-shaped record."""
    if not isinstance(d, Mapping) or not d.get("match"):
        return None
    comp = d.get("compilation") or {}
    std = d.get("stdJsonInput") or {}
    if not std.get("sources"):
        return None
    settings = comp.get("compilerSettings") or std.get("settings") or {}
    opt = settings.get("optimizer") or {}
    lang = str(comp.get("language") or std.get("language") or "Solidity")
    version = str(comp.get("compilerVersion") or "")
    pr = d.get("proxyResolution") or {}
    impls = [i.get("address") for i in (pr.get("implementations") or []) if isinstance(i, Mapping)]
    dep = d.get("deployment") or {}
    if lang.lower() == "vyper":
        cv = ("vyper:" + version) if version else ""
    else:
        cv = ("v" + version) if version else ""
    return {
        "SourceCode": "{" + json.dumps(std, sort_keys=True) + "}",
        "ContractName": str(comp.get("name") or ""),
        "CompilerVersion": cv,
        "OptimizationUsed": "1" if opt.get("enabled") else "0",
        "Runs": str(opt.get("runs") or ""),
        "EVMVersion": str(settings.get("evmVersion") or "Default"),
        "Libraries": settings.get("libraries") or {},
        "ViaIR": settings.get("viaIR"),
        "Proxy": "1" if pr.get("isProxy") and impls else "0",
        "Implementation": str(impls[0]).lower() if impls and impls[0] else "",
        "Language": lang, "SourceProvider": "sourcify",
        "SourcifyMatch": str(d.get("match")),
        "DeployBlock": int(dep["blockNumber"]) if str(dep.get("blockNumber") or "").isdigit() else None,
    }


def record_language(rec: Mapping[str, Any]) -> str:
    if (str(rec.get("Language") or "").lower() == "vyper"
            or str(rec.get("CompilerVersion") or "").lower().startswith("vyper")):
        return "vyper"
    return "solidity"


class HuntClient(ChainClient):
    """Fetch Etherscan/Sourcify source, cross-check Sourcify matches, follow proxies."""

    def __init__(self, api_key: str, chain_id: int, rpc_url: Optional[str] = None,
                 sourcify: bool = True, **kw: Any):
        super().__init__(api_key, chain_id, rpc_url=rpc_url, **kw)
        self.sourcify = sourcify
        self._records: Dict[str, Optional[Dict[str, Any]]] = {}

    def _raw_source(self, address: str) -> Optional[Dict[str, Any]]:
        rec = None
        if self.api_key:
            rec = super().verified_source(address)
            if rec is not None:
                rec = dict(rec, SourceProvider="etherscan")

        # Query Sourcify even when Etherscan has source so deployment identity is
        # independently classified. Exact/partial match semantics are kept in
        # the returned record; Etherscan-only source remains explicitly weaker.
        sourcify_status = "not_checked"
        if self.sourcify:
            url = SOURCIFY_V2.format(chain=self.chain_id, address=self._check_addr(address))
            req = urllib.request.Request(url, method="GET",
                                         headers={"User-Agent": "contract-auditor/hunt"})
            try:
                data = self._request(req)
            except Exception as exc:  # noqa: BLE001 - optional cross-check must not block usable explorer source
                if "HTTP 404" in str(exc):
                    data = None
                    sourcify_status = "no_record"
                elif rec is None:
                    raise
                else:
                    # Keep usable explorer source when the independent check is
                    # temporarily unavailable; downstream metadata says so.
                    data = None
                    sourcify_status = "unavailable"
            sourcify_rec = sourcify_to_record(data) if data is not None else None
            if sourcify_rec:
                if rec:
                    sourcify_rec["EtherscanVerified"] = True
                    sourcify_rec["EtherscanContractName"] = rec.get("ContractName")
                    sourcify_rec["EtherscanCompilerVersion"] = rec.get("CompilerVersion")
                rec = sourcify_rec
                sourcify_status = (
                    "exact_match" if str(sourcify_rec.get("SourcifyMatch") or "").lower() == "exact_match"
                    else "partial_match"
                )
            elif data is not None:
                sourcify_status = "no_match"
            if rec is not None:
                rec["SourcifyCheckStatus"] = sourcify_status
        return rec

    def verified_source(self, address: str) -> Optional[Dict[str, Any]]:
        address = self._check_addr(address)
        if address in self._records:
            return self._records[address]
        rec = self._raw_source(address)
        impl = None
        if rec is not None and str(rec.get("Proxy") or "0") == "1":
            impl = str(rec.get("Implementation") or "").lower()
        # Phase 21: resolve via storage / bytecode when the explorer does not flag Proxy.
        if not (_ADDR_RE.fullmatch(impl or "") and impl != address):
            try:
                from .vault_discovery import Reader, resolve_proxy
                info = resolve_proxy(Reader(self, max_calls=32), address)
                if info.is_proxy and info.implementation:
                    impl = info.implementation
                    if rec is not None:
                        rec = dict(rec, Proxy="1", Implementation=impl,
                                   ProxyKind=info.kind, ProxyAddress=address)
            except Exception:  # noqa: BLE001 - resolution is best-effort
                pass
        if rec is not None and _ADDR_RE.fullmatch(impl or "") and impl != address:
            impl_rec = self._raw_source(impl)
            if impl_rec is not None:
                rec = dict(impl_rec, Proxy="1", Implementation=impl,
                           ProxyContractName=rec.get("ContractName") if rec else None,
                           ProxyAddress=address, ProxyKind=rec.get("ProxyKind") if rec else None)
            elif rec is not None:
                rec = dict(rec, Proxy="1", Implementation=impl, ProxyAddress=address)
        if len(self._records) > 512:
            self._records.clear()
        self._records[address] = rec
        return rec


def build_hunt_client(network: str = "ethereum", **kw: Any) -> HuntClient:
    if network not in NETWORKS:
        raise MonitorError(f"unsupported network: {network}")
    key = os.environ.get("ETHERSCAN_API_KEY", "").strip()
    rpc = os.environ.get(RPC_ENV, "").strip() or None
    if rpc and urllib.parse.urlparse(rpc).scheme not in ("http", "https"):
        raise MonitorError(f"{RPC_ENV} must be an http(s) URL")
    if not key and not rpc:
        raise MonitorError(
            "hunt needs ETHERSCAN_API_KEY, or AUDITOR_MONITOR_RPC_URL for balances "
            "(verified source then comes from Sourcify)")
    return HuntClient(key, NETWORKS[network], rpc_url=rpc, **kw)


def _groups_for(category: str, groups: Sequence[str]) -> List[str]:
    return [g for g in groups if category in CATEGORY_GROUPS.get(g, ())]


def is_blue_chip(slug: str, name: str = "", parent: str = "") -> bool:
    s = (slug or "").lower()
    p = (parent or "").lower().replace("parent#", "")
    n = (name or "").lower()
    if any(s.startswith(b) or p.startswith(b) for b in BLUE_CHIP_PREFIXES):
        return True
    # Explicit Safe / Gnosis Safe / Lagoon demotion (wallet / vault branding).
    if s in ("safe", "gnosis-safe", "lagoon") or p in ("safe", "gnosis-safe", "lagoon"):
        return True
    if n in ("safe", "gnosis safe") or n.startswith("gnosis safe") or "lagoon" in n:
        return True
    return False


def eth_address(value: Any) -> Optional[str]:
    if not isinstance(value, str):
        return None
    v = value.strip()
    if ":" in v:
        chain, _, v = v.partition(":")
        if chain.lower() not in ("ethereum", "eth"):
            return None
    return v.lower() if _ADDR_RE.fullmatch(v) else None


def protocol_entries(protocols: Iterable[Mapping[str, Any]],
                     pools: Optional[Mapping[str, Any]] = None,
                     groups: Sequence[str] = DEFAULT_GROUPS,
                     min_tvl: float = 100_000.0) -> List[Dict[str, Any]]:
    pool_stats: Dict[str, Dict[str, float]] = {}
    for p in ((pools or {}).get("data") or []):
        if not isinstance(p, Mapping) or p.get("chain") != "Ethereum":
            continue
        st = pool_stats.setdefault(str(p.get("project") or ""),
                                   {"pools": 0, "pool_tvl": 0.0, "max_pool": 0.0})
        tvl = float(p.get("tvlUsd") or 0)
        st["pools"] += 1
        st["pool_tvl"] += tvl
        st["max_pool"] = max(st["max_pool"], tvl)
    out = []
    for p in protocols:
        if not isinstance(p, Mapping):
            continue
        cat = str(p.get("category") or "")
        g = _groups_for(cat, groups)
        if not g or "Ethereum" not in (p.get("chains") or []):
            continue
        tvl = (p.get("chainTvls") or {}).get("Ethereum")
        try:
            tvl = float(tvl) if tvl is not None else None
        except (TypeError, ValueError):
            tvl = None
        if tvl is None or tvl < min_tvl:
            continue
        slug = str(p.get("slug") or "")
        forked = p.get("forkedFrom") or []
        st = pool_stats.get(slug) or {}
        out.append({
            "protocol": str(p.get("name") or slug), "slug": slug, "category": cat,
            "category_group": g[0], "llama_tvl_usd": tvl,
            "listed_at": float(p["listedAt"]) if p.get("listedAt") else None,
            "audits": None if p.get("audits") is None else str(p.get("audits")),
            "forked_from": (", ".join(map(str, forked)) if isinstance(forked, list)
                            else str(forked or "")),
            "blue_chip": is_blue_chip(slug, str(p.get("name") or ""),
                                      str(p.get("parentProtocol") or "")),
            "address": eth_address(p.get("address")),
            "module": str(p.get("module") or ""),
            "github": p.get("github"),
            "pools": int(st.get("pools") or 0),
            "max_pool_tvl_usd": st.get("max_pool"),
        })
    return out


def adapter_addresses(text: str, limit: int = 10) -> List[str]:
    if not text:
        return []
    seen: List[str] = []
    eth_sections = [m.start() for m in re.finditer(r"\b(ethereum|eth|mainnet)\s*[:=]", text)]
    ordered: List[Tuple[int, str]] = []
    for m in _ADDR_RE.finditer(text):
        near_eth = any(0 <= m.start() - s < 4000 for s in eth_sections)
        ordered.append((0 if near_eth else 1, m.group(0).lower()))
    for _rank, a in sorted(ordered, key=lambda x: x[0]):
        if a in _IGNORED_ADDR or a in KNOWN_TOKEN_ADDR or a in seen:
            continue
        seen.append(a)
        if len(seen) >= limit:
            break
    return seen


SOURCE_SIGNALS: Tuple[Tuple[str, re.Pattern, float, str], ...] = (
    ("proxy_upgrade", re.compile(
        r"\b(upgradeTo(AndCall)?|UUPSUpgradeable|ERC1967|_upgradeTo|"
        r"TransparentUpgradeableProxy|_setImplementation)\b"), 8.0,
     "proxy / upgradeable logic"),
    ("custom_amm_math", re.compile(
        r"\b(getAmountOut|getAmountsOut|sqrtPriceX96|get_dy|getD|invariant|"
        r"_computeInvariant|bondingCurve|calcOutGivenIn|TickMath|swapExactIn)\b"),
     8.0, "AMM / pricing math"),
    ("cross_chain", re.compile(
        r"\b(lzReceive|_nonblockingLzReceive|ccipReceive|_ccipReceive|"
        r"receiveWormholeMessages|xReceive|onMessageReceived|relayMessage|"
        r"IMessageTransmitter|handle\s*\(\s*uint32)\b"), 10.0, "cross-chain messaging"),
    ("flash_loan", re.compile(
        r"\b(onFlashLoan|executeOperation|flashLoan|uniswapV3FlashCallback|"
        r"uniswapV2Call|receiveFlashLoan|pancakeCall)\b"), 8.0, "flash-loan callbacks"),
    ("oracle", re.compile(r"\b(latestRoundData|getReserves|consult|observe)\s*\("), 4.0,
     "external price reads"),
)


def source_signals(rec: Optional[Mapping[str, Any]]) -> Dict[str, Any]:
    out: Dict[str, Any] = {"signals": [], "oz_fraction": None, "known_fork": False, "files": 0}
    if not rec:
        return out
    text = str(rec.get("SourceCode") or "")
    files: Dict[str, str] = {}
    t = text.strip()
    if t.startswith("{"):
        try:
            obj = json.loads(t[1:-1] if t.startswith("{{") else t)
            for path, e in (obj.get("sources", obj) or {}).items():
                if isinstance(e, Mapping) and isinstance(e.get("content"), str):
                    files[path] = e["content"]
        except (ValueError, AttributeError):
            files = {}
    if not files:
        files = {"main.sol": text}
    out["files"] = len(files)
    lib = [p for p in files if re.search(r"(@openzeppelin|openzeppelin-contracts|solmate|solady)", p)]
    out["oz_fraction"] = round(len(lib) / max(len(files), 1), 2)
    own = "\n".join(v for p, v in files.items() if p not in lib) or text
    for key, rx, _w, label in SOURCE_SIGNALS:
        if rx.search(own):
            out["signals"].append(key)
    if str(rec.get("Proxy") or "0") == "1" and "proxy_upgrade" not in out["signals"]:
        out["signals"].append("proxy_upgrade")
    name = str(rec.get("ContractName") or "")
    out["known_fork"] = bool(KNOWN_FORK_NAMES.match(name))
    out["contract_name"] = name
    return out


def priority_score(c: Mapping[str, Any], now: float,
                   signals: Optional[Mapping[str, Any]] = None) -> Tuple[float, List[str]]:
    """Heuristic 0-100 priority hint and human-readable reasons."""
    score, why = 20.0, ["base 20"]
    listed = c.get("listed_at")
    if listed:
        age_d = max(now - float(listed), 0) / 86400
        if age_d <= 180:
            score += 20; why.append(f"+20 listed {age_d:.0f}d ago (recent)")
        elif age_d <= 365:
            score += 12; why.append(f"+12 listed {age_d:.0f}d ago")
        elif age_d <= 730:
            score += 5; why.append(f"+5 listed {age_d:.0f}d ago")
        else:
            score -= 5; why.append(f"-5 listed {age_d:.0f}d ago (older)")
    else:
        why.append("listedAt unknown")
    tvl = c.get("onchain_tvl_usd")
    if tvl is None:
        tvl = c.get("llama_tvl_usd")
    try:
        tvl = float(tvl) if tvl is not None else None
    except (TypeError, ValueError):
        tvl = None
    if tvl is not None:
        if 1e5 <= tvl <= 5e7:
            score += 25; why.append(f"+25 TVL ${tvl:,.0f} in $100k-$50M sweet spot")
        elif 5e7 < tvl <= 2e8:
            score += 10; why.append(f"+10 TVL ${tvl:,.0f} (mid)")
        elif tvl > 2e8:
            score -= 15; why.append(f"-15 TVL ${tvl:,.0f} (blue-chip band)")
        else:
            score += 5; why.append(f"+5 TVL ${tvl:,.0f} (small)")
    market_liquidity = c.get("market_liquidity_usd")
    try:
        market_liquidity = float(market_liquidity) if market_liquidity is not None else None
    except (TypeError, ValueError):
        market_liquidity = None
    if market_liquidity is not None:
        if market_liquidity >= 250_000:
            score += 8; why.append(f"+8 DEX pool liquidity context ${market_liquidity:,.0f} (not holder exposure)")
        elif market_liquidity >= 50_000:
            score += 4; why.append(f"+4 DEX pool liquidity context ${market_liquidity:,.0f} (not holder exposure)")
    audits = c.get("audits")
    if audits in (None, "", "0"):
        score += 12; why.append("+12 no audit badge on DefiLlama")
    elif str(audits) in ("1",):
        score += 4; why.append("+4 partial audit badge")
    else:
        score -= 6; why.append(f"-6 audits={audits}")
    if c.get("forked_from"):
        score -= 8; why.append(f"-8 forkedFrom={c['forked_from'][:40]}")
    if c.get("blue_chip"):
        score -= 20; why.append("-20 blue-chip slug demotion")
    sig = signals or {}
    for key, rx, w, label in SOURCE_SIGNALS:
        if key in (sig.get("signals") or []):
            score += w; why.append(f"+{w:g} {label}")
    oz = sig.get("oz_fraction")
    if oz is not None and oz >= 0.5:
        score -= 10; why.append(f"-10 OpenZeppelin-heavy ({oz:.0%} of files)")
    if sig.get("known_fork"):
        score -= 15; why.append(f"-15 known fork name {sig.get('contract_name')}")
    if c.get("verified") is False:
        score -= 25; why.append("-25 unverified (skipped for scanning)")
    if c.get("has_code") is False:
        score -= 40; why.append("-40 no on-chain code")
    if c.get("has_user_approvals"):
        score += 10; why.append("+10 users have granted ERC-20 approvals to this contract")
        try:
            au = float(c["approval_usd"]) if c.get("approval_usd") is not None else None
        except (TypeError, ValueError):
            au = None
        if au is not None and au >= 250:
            score += 5; why.append(f"+5 approval_usd ${au:,.0f}")
    score = max(0.0, min(100.0, round(score, 1)))
    return score, why


# ---------------------------------------------------------------------------
# Persistence helpers
# ---------------------------------------------------------------------------

_HUNT_COLS = (
    "protocol", "slug", "category", "category_group", "source", "sources_json",
    "llama_tvl_usd", "onchain_tvl_usd", "tvl_measured_at", "value_json",
    "listed_at", "audits", "forked_from", "blue_chip",
    "has_code", "verified", "source_provider", "contract_name", "language",
    "is_proxy", "implementation",
    "proxy_kind", "holder_value_usd", "holder_role", "discovery_json", "scan_address",
    "has_user_approvals", "approval_usd",
    "priority_score", "score_reasons", "signals_json",
    "status", "last_error",
    "last_scan_row", "last_scan_id", "last_content_hash",
    "findings", "est_max_loss_usd",
    "discovered_at", "updated_at", "scanned_at",
    "last_attempt_at", "scan_attempt_at", "source_attempts", "source_retry_at",
    "sim_status", "sim_run_id", "sim_summary_json", "sim_at",
)


def upsert_candidate(store: MonitorStore, network: str, address: str, **fields: Any) -> None:
    now = fields.pop("now", None)
    row = store.conn.execute(
        "SELECT address FROM hunt_candidates WHERE network=? AND address=?",
        (network, address.lower())).fetchone()
    payload = {k: fields[k] for k in fields if k in _HUNT_COLS}
    if "blue_chip" in payload:
        payload["blue_chip"] = int(bool(payload["blue_chip"]))
    if "has_code" in payload and payload["has_code"] is not None:
        payload["has_code"] = int(bool(payload["has_code"]))
    if "verified" in payload and payload["verified"] is not None:
        payload["verified"] = int(bool(payload["verified"]))
    if "is_proxy" in payload and payload["is_proxy"] is not None:
        payload["is_proxy"] = int(bool(payload["is_proxy"]))
    if "has_user_approvals" in payload and payload["has_user_approvals"] is not None:
        payload["has_user_approvals"] = int(bool(payload["has_user_approvals"]))
    if now is not None:
        payload["updated_at"] = float(now)
        if row is None:
            payload.setdefault("discovered_at", float(now))
    if row is None:
        cols = ["network", "address"] + list(payload)
        store.conn.execute(
            f"INSERT INTO hunt_candidates({','.join(cols)}) VALUES({','.join('?'*len(cols))})",
            [network, address.lower()] + [payload[c] for c in payload])
    else:
        if not payload:
            return
        store.conn.execute(
            f"UPDATE hunt_candidates SET {', '.join(k+'=?' for k in payload)} "
            "WHERE network=? AND address=?",
            list(payload.values()) + [network, address.lower()])
    store.conn.commit()


@dataclass
class HuntConfig:
    network: str = "ethereum"
    min_tvl: float = 100_000.0
    max_tvl: Optional[float] = None
    categories: Tuple[str, ...] = DEFAULT_GROUPS
    include_blue_chips: bool = True          # demote when True; skip when False
    max_protocols: int = 80
    max_addresses_per_protocol: int = 6
    max_candidates: int = 500
    measure_per_cycle: int = 20
    scan_per_cycle: int = 10
    simulate_per_cycle: int = 1
    interval: float = 3600.0
    with_transfers: bool = False
    transfer_lookback_blocks: int = 3000
    transfer_tokens: Tuple[str, ...] = ("WETH", "USDC", "USDT", "DAI")
    prefer_verified: bool = True
    min_severity: str = "HIGH"
    min_value_usd: Optional[float] = None
    value_enabled: bool = True
    solc_auto_install: bool = True
    target_tvl_low: float = 500_000.0
    target_tvl_high: float = 3_000_000.0
    cache_dir: Path = field(default_factory=default_hunt_cache)
    db_path: Path = field(default_factory=default_monitor_db_path)
    alerts_path: Optional[Path] = None
    refresh_ttl: float = 6 * 3600.0
    adapter_ttl: float = 7 * 86400.0
    # Phase 21
    slugs: Tuple[str, ...] = ()              # when set, only these DefiLlama slugs
    vault_discovery: bool = True
    vault_max_depth: int = 3
    vault_max_nodes: int = 40
    related_from_etherscan: bool = True
    min_holder_usd: float = 10_000.0         # upsert discovered holders above this
    pool_discovery_enabled: bool = False   # Phase 24 / batch-3: factory PairCreated/PoolCreated
    pool_lookback_blocks: int = 50_000
    pool_max: int = 40


def _spender_topic(address: str) -> str:
    """Pad a 20-byte address into a 32-byte indexed Approval spender topic."""
    a = address.lower()
    if a.startswith("0x"):
        a = a[2:]
    return "0x" + ("0" * 24) + a


def probe_user_approvals(client: Any, address: str, *,
                         tokens: Sequence[str] = ("WETH", "USDC", "USDT", "DAI"),
                         lookback_blocks: int = 3000,
                         max_logs_per_token: int = 50) -> Dict[str, Any]:
    """Lightweight read-only check: any ERC-20 Approval where spender=address.

    Uses ``eth_getLogs`` (or the explorer logs fallback) on a small major-token
    set and a short lookback. Returns ``has_user_approvals`` plus a best-effort
    ``approval_usd`` (None when value cannot be priced cheaply). Never sends a
    transaction. Callers must gate this behind disk_pressure when used in-cycle.
    """
    from .value_at_risk import TOKENS

    out: Dict[str, Any] = {"has_user_approvals": False, "approval_usd": None,
                           "tokens_hit": [], "logs_seen": 0}
    if client is None or not address:
        return out
    try:
        head = client.block_number()
    except Exception as exc:  # noqa: BLE001
        log.info("hunt: approval probe head failed: %s", _redact(exc))
        return out
    start = max(int(head) - max(0, int(lookback_blocks)), 0)
    spender = _spender_topic(address)
    raw_total = 0.0
    priced = False
    for sym in tokens:
        tok = TOKENS.get(sym)
        if not tok:
            continue
        try:
            # Prefer topic-filtered getLogs (spender = candidate). Fall back to
            # topic0-only + local filter when the client rejects extra topics.
            try:
                logs = client.logs(tok["address"], _APPROVAL_TOPIC, start, head,
                                   topics=[_APPROVAL_TOPIC, None, spender])
            except TypeError:
                logs = client.logs(tok["address"], _APPROVAL_TOPIC, start, head)
                filtered = []
                for lg in logs or []:
                    topics = lg.get("topics") or []
                    if len(topics) >= 3 and str(topics[2]).lower().endswith(address.lower()[2:]):
                        filtered.append(lg)
                logs = filtered
        except Exception as exc:  # noqa: BLE001
            log.info("hunt: approval getLogs %s failed: %s", sym, _redact(exc))
            continue
        hits = list(logs or [])[:max_logs_per_token]
        if not hits:
            continue
        out["has_user_approvals"] = True
        out["tokens_hit"].append(sym)
        out["logs_seen"] += len(hits)
        decimals = int(tok.get("decimals") or 18)
        # Best-effort: sum Approval values when data field is present; leave
        # approval_usd None if we cannot price (price lookup is caller's job).
        for lg in hits:
            data = str(lg.get("data") or "0x")
            if data == "0x" or len(data) < 3:
                continue
            try:
                raw = int(data, 16)
            except ValueError:
                continue
            # Cap insane unlimited approvals so they don't dominate the sum.
            # 2**200 is still "effectively unlimited" for ERC-20 amounts.
            if raw >= (1 << 200):
                continue
            raw_total += raw / float(10 ** decimals)
            priced = True
    if out["has_user_approvals"] and priced and raw_total > 0:
        # Unitless token sum across majors is not USD; store as None and let
        # the boolean drive the priority boost. Callers may overwrite
        # approval_usd when they have prices.
        out["approval_usd"] = None
        out["approval_token_units"] = round(raw_total, 6)
    return out



class Hunter:
    """Discover → measure → rank → scan top candidates."""

    def __init__(self, config: HuntConfig, client: Optional[Any] = None,
                 cache: Optional[JsonCache] = None,
                 emit: Callable[[str], None] = print,
                 clock: Callable[[], float] = time.time,
                 sleep: Callable[[float], None] = time.sleep,
                 price_source: Any = None,
                 analyzer: Any = None, recorder: Any = None):
        self.cfg = config
        # Accept a plain ChainClient; wrap with Sourcify fallback when possible.
        if client is None:
            self.client = None  # refresh-only is allowed without a chain client
        elif isinstance(client, HuntClient):
            self.client = client
        elif hasattr(client, "_etherscan"):
            # Real ChainClient: wrap so verified_source follows proxies / Sourcify.
            # (A plain ChainClient returns the proxy's OZ boilerplate source.)
            self.client = HuntClient(
                getattr(client, "api_key", "") or "",
                getattr(client, "chain_id", 1),
                rpc_url=getattr(client, "rpc_url", None),
                http=getattr(client, "http", None) or _http_get_as_request,
                sleep=getattr(client, "sleep", sleep),
                min_interval=getattr(client, "min_interval", 0.25),
                timeout=getattr(client, "timeout", 30.0))
        else:
            # Test fake with its own verified_source / balances — keep as-is.
            self.client = client
        self.cache = cache or JsonCache(Path(config.cache_dir) / "http", clock=clock, sleep=sleep)
        self.emit = emit
        self.clock = clock
        self.sleep = sleep
        self.price_source = price_source
        self.store = MonitorStore(config.db_path)
        self._analyzer = analyzer
        self._recorder = recorder
        self.stop_requested = False

    def request_stop(self, *_a: Any) -> None:
        self.stop_requested = True

    def _beat(self, payload: Dict[str, Any]) -> None:
        """Best-effort worker heartbeat (dashboard_worker_state, additive row)."""
        try:
            record_worker_heartbeat(
                self.cfg.db_path, f"hunt-{self.cfg.network}",
                {"pid": os.getpid(), **payload}, at=self.clock())
        except Exception:  # noqa: BLE001 - heartbeats must never break the cycle loop
            pass

    def refresh(self, force: bool = False) -> Dict[str, Any]:
        """Fetch DefiLlama lists and extract candidate addresses. Never scans."""
        now = self.clock()
        protocols = self.cache.get("llama_protocols", LLAMA_PROTOCOLS, self.cfg.refresh_ttl,
                                   force=force)
        pools = self.cache.get("llama_pools", LLAMA_POOLS, self.cfg.refresh_ttl, force=force)
        entries = protocol_entries(protocols, pools, self.cfg.categories, self.cfg.min_tvl)
        if self.cfg.slugs:
            want = {s.lower() for s in self.cfg.slugs}
            entries = [e for e in entries if (e.get("slug") or "").lower() in want]
        if self.cfg.max_tvl is not None:
            entries = [e for e in entries if e["llama_tvl_usd"] <= self.cfg.max_tvl]
        if not self.cfg.include_blue_chips:
            entries = [e for e in entries if not e["blue_chip"]]

        def _sort_key(e: Mapping[str, Any]) -> Tuple:
            tvl = e["llama_tvl_usd"]
            sweet = 0 if self.cfg.min_tvl <= tvl <= 50_000_000 else 1
            return (int(bool(e["blue_chip"])), sweet, -(e.get("listed_at") or 0), -tvl)

        entries = sorted(entries, key=_sort_key)[: self.cfg.max_protocols]
        discovered = 0
        from .discovery_sources import (code4rena_context, dexscreener_pairs,
                                        dextools_pairs, github_repository_urls)
        for e in entries:
            if self.stop_requested:
                break
            addrs: List[str] = []
            if e.get("address"):
                addrs.append(e["address"])
            mod = (e.get("module") or "").rstrip("/")
            if mod and len(addrs) < self.cfg.max_addresses_per_protocol:
                text = None
                # DefiLlama `module` is sometimes "foo/index.js" and sometimes "foo".
                urls = []
                if mod.endswith((".js", ".ts")):
                    urls.append((mod, ADAPTER_RAW + mod))
                else:
                    for name in ("index.js", "index.ts", "ethereum.js", "api.js"):
                        urls.append((f"{mod}/{name}", ADAPTER_RAW + mod + "/" + name))
                for label, url in urls:
                    try:
                        text = self.cache.get(f"adapter:{label}", url,
                                              self.cfg.adapter_ttl, as_json=False)
                        break
                    except TransientError:
                        continue
                if text:
                    for a in adapter_addresses(text, self.cfg.max_addresses_per_protocol):
                        if a not in addrs:
                            addrs.append(a)
            for a in addrs[: self.cfg.max_addresses_per_protocol]:
                existing = self.store.conn.execute(
                    "SELECT status, sources_json, discovery_json FROM hunt_candidates "
                    "WHERE network=? AND address=?",
                    (self.cfg.network, a)).fetchone()
                sources = set()
                details: Dict[str, Any] = {}
                if existing and existing["sources_json"]:
                    try:
                        sources = set(json.loads(existing["sources_json"]))
                    except (ValueError, TypeError):
                        pass
                if existing and existing["discovery_json"]:
                    try:
                        details = json.loads(existing["discovery_json"])
                    except (ValueError, TypeError):
                        pass
                details.update({
                    "github_repositories": github_repository_urls(e.get("github")),
                    "code4rena": code4rena_context(e["protocol"]),
                })
                sources.add("defillama")
                sources.add("defillama-protocol-address" if e.get("address") == a
                            else "defillama-adapter")
                status = (existing["status"] if existing and existing["status"] not in
                          ("new", "measured", "queued", "ready") else "new")
                upsert_candidate(
                    self.store, self.cfg.network, a,
                    protocol=e["protocol"], slug=e["slug"], category=e["category"],
                    category_group=e["category_group"], source="defillama",
                    sources_json=json.dumps(sorted(sources)),
                    llama_tvl_usd=e["llama_tvl_usd"], listed_at=e["listed_at"],
                    audits=e["audits"], forked_from=e["forked_from"] or None,
                    blue_chip=e["blue_chip"], status=status,
                    discovery_json=json.dumps(details, sort_keys=True), now=now)
                discovered += 1
        market_signals: Dict[str, Any] = {}
        dex_pairs, market_signals["dexscreener"] = dexscreener_pairs(self.cache)
        tools_pairs, market_signals["dextools"] = dextools_pairs()
        for item in dex_pairs + tools_pairs:
            if self.stop_requested:
                break
            address = item["address"]
            existing = self.store.conn.execute(
                "SELECT status, sources_json, discovery_json, protocol, slug, category, category_group, source "
                "FROM hunt_candidates WHERE network=? AND address=?",
                (self.cfg.network, address)).fetchone()
            sources = set()
            details: Dict[str, Any] = {}
            if existing:
                try:
                    sources = set(json.loads(existing["sources_json"] or "[]"))
                except (ValueError, TypeError):
                    pass
                try:
                    details = json.loads(existing["discovery_json"] or "{}")
                except (ValueError, TypeError):
                    pass
            provider = "dextools" if str(item.get("slug", "")).startswith("dextools") else "dexscreener"
            sources.add(provider)
            details[provider] = {k: v for k, v in item.items() if k not in ("address",)}
            status = existing["status"] if existing and existing["status"] not in (
                "new", "measured", "queued", "ready") else "new"
            upsert_candidate(
                self.store, self.cfg.network, address,
                protocol=(existing["protocol"] if existing and existing["protocol"] else item.get("protocol")),
                slug=(existing["slug"] if existing and existing["slug"] else item.get("slug")),
                category=(existing["category"] if existing and existing["category"] else item.get("category")),
                category_group=(existing["category_group"] if existing and existing["category_group"] else item.get("category_group")),
                source=(existing["source"] if existing and existing["source"] else provider),
                sources_json=json.dumps(sorted(sources)),
                discovery_json=json.dumps(details, sort_keys=True),
                status=status, now=now)
            discovered += int(not existing)
        if self.cfg.with_transfers and self.client is not None:
            discovered += self._discover_transfers(now)
        if self.cfg.pool_discovery_enabled and self.client is not None:
            discovered += self._discover_pools(now)
        n = int(self.store.conn.execute(
            "SELECT COUNT(*) FROM hunt_candidates WHERE network=?",
            (self.cfg.network,)).fetchone()[0])
        trimmed = 0
        if n > self.cfg.max_candidates * 2:
            drop = self.store.conn.execute(
                "SELECT address FROM hunt_candidates WHERE network=? AND status IN "
                "('new','measured','skipped','unverified','ready') "
                "ORDER BY COALESCE(priority_score,0) ASC LIMIT ?",
                (self.cfg.network, n - self.cfg.max_candidates)).fetchall()
            for r in drop:
                self.store.conn.execute(
                    "DELETE FROM hunt_candidates WHERE network=? AND address=?",
                    (self.cfg.network, r["address"]))
                trimmed += 1
            self.store.conn.commit()
        return {"protocols": len(entries), "discovered": discovered, "trimmed": trimmed,
                "market_sources": market_signals}

    def _discover_transfers(self, now: float) -> int:
        from .value_at_risk import TOKENS
        found = 0
        try:
            head = self.client.block_number()
        except Exception as exc:  # noqa: BLE001
            log.info("hunt: transfer discovery skipped: %s", _redact(exc))
            return 0
        start = max(head - self.cfg.transfer_lookback_blocks, 0)
        for sym in self.cfg.transfer_tokens:
            tok = TOKENS.get(sym)
            if not tok:
                continue
            try:
                logs = self.client.logs(tok["address"], _TRANSFER_TOPIC, start, head)
            except Exception as exc:  # noqa: BLE001
                log.info("hunt: getLogs %s failed: %s", sym, _redact(exc))
                continue
            for lg in logs[:200]:
                topics = lg.get("topics") or []
                if len(topics) < 3:
                    continue
                for topic in topics[1:3]:
                    a = "0x" + str(topic)[-40:]
                    if a in _IGNORED_ADDR:
                        continue
                    try:
                        if self.client.code_size(a) == 0:
                            continue
                    except Exception:  # noqa: BLE001
                        continue
                    upsert_candidate(
                        self.store, self.cfg.network, a,
                        protocol=f"transfer:{sym}", slug=None, category="Transfer",
                        category_group="pools", source="transfer",
                        sources_json=json.dumps(["transfer"]),
                        llama_tvl_usd=None, blue_chip=False, status="new", now=now)
                    found += 1
                    if found >= 20:
                        return found
        return found

    def _discover_pools(self, now: float) -> int:
        """Phase 24: PairCreated/PoolCreated factory logs → pools holding >= min_holder_usd."""
        from .pool_discovery import PoolDiscovery
        found = 0
        prices: dict = {}
        try:
            # best-effort: reuse hunt price_source if it exposes a mapping
            src = getattr(self, "price_source", None)
            if isinstance(src, dict):
                prices = dict(src)
            elif src is not None and hasattr(src, "get_prices"):
                prices = dict(src.get_prices() or {})
        except Exception:  # noqa: BLE001
            prices = {}
        try:
            disc = PoolDiscovery(
                self.client,
                lookback_blocks=self.cfg.pool_lookback_blocks,
                min_holder_usd=self.cfg.min_holder_usd,
                max_pools=self.cfg.pool_max,
                prices_usd=prices,
                scan_any_emitter=True,
                sleep=self.sleep,
            )
            result = disc.discover()
        except Exception as exc:  # noqa: BLE001
            log.info("hunt: pool discovery skipped: %s", _redact(exc))
            return 0
        for p in result.pools:
            upsert_candidate(
                self.store, self.cfg.network, p.address,
                protocol=f"pool:{p.factory_label}", slug=p.factory_label,
                category="Dexs", category_group="pools", source="pool-discovery",
                sources_json=__import__("json").dumps(["pool-discovery", p.factory_label]),
                llama_tvl_usd=None, onchain_tvl_usd=p.value_usd,
                holder_value_usd=p.value_usd, holder_role="pool",
                discovery_json=__import__("json").dumps({
                    "factory": p.factory, "kind": p.kind,
                    "token0": p.token0, "token1": p.token1,
                    "breakdown": p.breakdown,
                }),
                blue_chip=False, has_code=True, status="new", now=now)
            found += 1
        if result.errors:
            log.info("hunt: pool discovery partial errors: %s", "; ".join(result.errors)[:300])
        return found


    def measure(self, limit: Optional[int] = None) -> List[Dict[str, Any]]:
        from .value_at_risk import PriceSource, assess
        from .vault_discovery import (Reader, TokenPricer, VaultDiscovery, resolve_proxy,
                                      related_contracts_from_etherscan)
        limit = int(limit if limit is not None else self.cfg.measure_per_cycle)
        if self.client is None:
            return []
        now = self.clock()
        # Prefer protocol-level addresses; then holders we have not valued yet.
        rows = self.store.conn.execute(
            "SELECT * FROM hunt_candidates WHERE network=? AND ("
            "status IN ('new','measured','ready') OR "
            "(status='unverified' AND (source_retry_at IS NULL OR source_retry_at<=?))) "
            "ORDER BY CASE WHEN status='unverified' THEN 1 ELSE 0 END, "
            "CASE WHEN onchain_tvl_usd IS NULL AND holder_value_usd IS NULL THEN 0 ELSE 1 END, "
            "CASE WHEN sources_json LIKE '%defillama-protocol-address%' THEN 0 ELSE 1 END, "
            "COALESCE(source_retry_at,0) ASC, COALESCE(priority_score,0) DESC, "
            "COALESCE(llama_tvl_usd,0) DESC LIMIT ?",
            (self.cfg.network, now, limit)).fetchall()
        if self.price_source is None:
            self.price_source = PriceSource(cache_path=Path(self.cfg.cache_dir) / "prices.json")
        out: List[Dict[str, Any]] = []
        from .discovery_sources import arkham_contract
        arkham_calls = 0
        # Group seeds by (slug) so vault discovery runs once per protocol per cycle.
        by_slug: Dict[str, List[Any]] = {}
        for row in rows:
            by_slug.setdefault(str(row["slug"] or row["protocol"] or row["address"]), []).append(row)

            # Arkham is optional and bounded: only enrich up to five candidates
            # per run, once per address. Its labels are contextual, not proof.
            if arkham_calls < 5 and os.environ.get("ARKHAM_API_KEY", "").strip():
                try:
                    info = json.loads(row["discovery_json"] or "{}")
                except (ValueError, TypeError):
                    info = {}
                if not info.get("arkham"):
                    arkham = arkham_contract(str(row["address"]))
                    arkham_calls += 1
                    if arkham:
                        info["arkham"] = arkham
                        self.store.conn.execute(
                            "UPDATE hunt_candidates SET discovery_json=? WHERE network=? AND address=?",
                            (json.dumps(info, sort_keys=True), self.cfg.network, row["address"]))
                        self.store.conn.commit()

        reader = Reader(self.client, max_calls=max(200, limit * 80))
        pricer = TokenPricer()
        try:
            ids = ["ethereum", "weth", "usd-coin", "tether", "dai", "wrapped-bitcoin", "staked-ether"]
            pricer.seed_major(self.price_source.prices(ids))
        except Exception:  # noqa: BLE001
            pass

        def _abi_lookup(addr: str):
            try:
                rec = self.client.verified_source(addr)
            except Exception:  # noqa: BLE001
                return None
            if not rec:
                return None
            # Sourcify / std-json may embed ABI; Etherscan returns ABI as a JSON string.
            for key in ("ABI", "abi"):
                raw = rec.get(key)
                if isinstance(raw, list):
                    return raw
                if isinstance(raw, str) and raw.strip().startswith("["):
                    try:
                        return json.loads(raw)
                    except ValueError:
                        pass
            return None

        disc = VaultDiscovery(reader, pricer, abi_lookup=_abi_lookup,
                              max_depth=self.cfg.vault_max_depth,
                              max_nodes=self.cfg.vault_max_nodes, clock=self.clock)

        processed: set = set()
        for slug, group in by_slug.items():
            if self.stop_requested:
                break
            seeds = [r["address"] for r in group]
            # Pull any other addresses already queued for this slug so discovery sees them.
            sibs = self.store.conn.execute(
                "SELECT address FROM hunt_candidates WHERE network=? AND slug=? LIMIT 30",
                (self.cfg.network, group[0]["slug"])).fetchall() if group[0]["slug"] else []
            for s in sibs:
                if s["address"] not in seeds:
                    seeds.append(s["address"])
            if self.cfg.related_from_etherscan and getattr(self.client, "api_key", ""):
                for s in list(seeds)[:3]:
                    for rel in related_contracts_from_etherscan(self.client, s, limit=5):
                        if rel not in seeds:
                            seeds.append(rel)

            discovery = None
            if self.cfg.vault_discovery:
                try:
                    discovery = disc.discover(seeds)
                except Exception as exc:  # noqa: BLE001
                    log.info("hunt: vault discovery for %s failed: %s", slug, _redact(exc))

            # Upsert every ranked holder above the floor as its own candidate.
            if discovery is not None:
                proto = group[0]
                for holder in discovery.ranked:
                    if holder.address in KNOWN_TOKEN_ADDR:
                        continue  # never treat USDC/WETH/… as a hunt target
                    if (holder.value_usd or 0) < self.cfg.min_holder_usd and holder.address not in {
                            r["address"] for r in group}:
                        continue
                    proxy = holder.proxy
                    is_proxy = bool(proxy and proxy.is_proxy)
                    impl = proxy.implementation if is_proxy else None
                    scan_addr = holder.address
                    existing = self.store.conn.execute(
                        "SELECT status, sources_json FROM hunt_candidates "
                        "WHERE network=? AND address=?",
                        (self.cfg.network, holder.address)).fetchone()
                    sources = set()
                    if existing and existing["sources_json"]:
                        try:
                            sources = set(json.loads(existing["sources_json"]))
                        except (ValueError, TypeError):
                            pass
                    sources.add("vault-discovery")
                    keep_status = (existing["status"] if existing and existing["status"] not in
                                   (None, "new", "measured") else "new")
                    fields = dict(
                        protocol=proto["protocol"], slug=proto["slug"],
                        category=proto["category"], category_group=proto["category_group"],
                        source="vault-discovery",
                        sources_json=json.dumps(sorted(sources)),
                        llama_tvl_usd=proto["llama_tvl_usd"], listed_at=proto["listed_at"],
                        audits=proto["audits"], forked_from=proto["forked_from"],
                        blue_chip=bool(proto["blue_chip"]),
                        has_code=True,
                        is_proxy=is_proxy, implementation=impl,
                        proxy_kind=(proxy.kind if is_proxy else None),
                        holder_value_usd=holder.value_usd,
                        holder_role=holder.role,
                        onchain_tvl_usd=holder.value_usd,
                        tvl_measured_at=now,
                        value_json=json.dumps(holder.to_dict()),
                        discovery_json=json.dumps({
                            "via": holder.via, "parent": holder.parent,
                            "tokens": discovery.tokens[:20],
                            "proxies": discovery.proxies.get(holder.address),
                        }),
                        scan_address=scan_addr, now=now)
                    if keep_status in ("new", "measured", "ready", "unverified"):
                        fields["status"] = keep_status if existing else "new"
                    upsert_candidate(self.store, self.cfg.network, holder.address, **fields)
                    self.emit(
                        f"hunt: holder {holder.address} ({holder.role}"
                        + (f" via {holder.via}" if holder.via else "")
                        + f") ~${holder.value_usd:,.0f}"
                        + (f" [{proxy.kind}→{impl[:10]}…]" if is_proxy and impl else ""))

            # Measure each requested row (and any newly upserted holders for this slug).
            targets = list(group)
            if discovery is not None:
                for holder in discovery.ranked[: self.cfg.max_addresses_per_protocol]:
                    if (holder.value_usd or 0) < self.cfg.min_holder_usd:
                        continue
                    if holder.address in processed:
                        continue
                    r = self.store.conn.execute(
                        "SELECT * FROM hunt_candidates WHERE network=? AND address=?",
                        (self.cfg.network, holder.address)).fetchone()
                    if r is not None:
                        targets.append(r)

            for row in targets:
                addr = row["address"]
                if addr in processed:
                    continue
                processed.add(addr)
                if self.stop_requested:
                    break
                upsert_candidate(self.store, self.cfg.network, addr, last_attempt_at=now, now=now)
                try:
                    has_code = self.client.code_size(addr) > 0
                except Exception as exc:  # noqa: BLE001
                    upsert_candidate(self.store, self.cfg.network, addr,
                                     last_error=f"code: {_redact(exc)[:200]}", now=now)
                    continue
                if not has_code:
                    upsert_candidate(self.store, self.cfg.network, addr, has_code=False,
                                     verified=False, status="skipped",
                                     last_error="no on-chain code", priority_score=0,
                                     score_reasons=json.dumps(["no code"]), now=now)
                    out.append({"address": addr, "status": "skipped"})
                    continue

                # Phase 21 proxy resolution (storage / bytecode), even without explorer flag.
                proxy_info = None
                try:
                    proxy_info = resolve_proxy(Reader(self.client, max_calls=16), addr)
                except Exception:  # noqa: BLE001
                    proxy_info = None

                var = None
                try:
                    var = assess(self.client, addr, None, self.price_source)
                except Exception as exc:  # noqa: BLE001
                    log.info("hunt: value for %s failed: %s", addr, _redact(exc))

                # Prefer vault-discovery holder value when it is richer than major-token TVL.
                holder_usd = None
                existing = self.store.conn.execute(
                    "SELECT holder_value_usd, value_json FROM hunt_candidates "
                    "WHERE network=? AND address=?",
                    (self.cfg.network, addr)).fetchone()
                if existing and existing["holder_value_usd"] is not None:
                    holder_usd = float(existing["holder_value_usd"])
                onchain = var.tvl_usd if var else None
                if holder_usd is not None and (onchain is None or holder_usd > (onchain or 0)):
                    onchain = holder_usd

                try:
                    rec = self.client.verified_source(addr)
                except TransientError as exc:
                    attempts = int(row["source_attempts"] or 0) + 1
                    retry_at = now + min(86400.0, 900.0 * (2 ** min(attempts - 1, 7)))
                    upsert_candidate(self.store, self.cfg.network, addr, has_code=True,
                                     verified=False, status="unverified", source_attempts=attempts,
                                     source_retry_at=retry_at,
                                     last_error=f"source: {_redact(exc)[:200]}", now=now)
                    continue
                except Exception as exc:  # providers can fail outside the typed RPC exception path
                    attempts = int(row["source_attempts"] or 0) + 1
                    retry_at = now + min(86400.0, 900.0 * (2 ** min(attempts - 1, 7)))
                    upsert_candidate(self.store, self.cfg.network, addr, has_code=True,
                                     verified=False, status="unverified", source_attempts=attempts,
                                     source_retry_at=retry_at,
                                     last_error=f"source: {_redact(exc)[:200]}", now=now)
                    continue
                verified = rec is not None
                lang = record_language(rec) if rec else None
                sig = source_signals(rec)
                try:
                    provenance = json.loads(row["discovery_json"] or "{}")
                except (ValueError, TypeError):
                    provenance = {}
                if rec:
                    provider = str(rec.get("SourceProvider") or "etherscan").lower()
                    match = str(rec.get("SourcifyMatch") or "").lower() or None
                    exact_match = match == "exact_match"
                    identity_status = ("exact_match" if exact_match else
                                       "partial_match" if match else "not_independently_matched")
                    sourcify_status = str(rec.get("SourcifyCheckStatus") or "")
                    if exact_match:
                        identity_note = "Sourcify reports an exact deployed-bytecode match"
                    elif match:
                        identity_note = (f"Sourcify reports a partial match ({match}); "
                                         "full deployed-bytecode identity is not established")
                    elif sourcify_status == "unavailable":
                        identity_note = ("Etherscan reports verified source and runtime code is present; "
                                         "the independent Sourcify check was unavailable, and no local "
                                         "compile comparison was run")
                    else:
                        identity_note = ("Etherscan reports verified source and runtime code is present; "
                                         "no Sourcify match or local compile comparison is available")
                    provenance["source_verification"] = {
                        "provider": provider,
                        "sourcify_match": match,
                        "identity_status": identity_status,
                        "bytecode_match": exact_match,
                        "runtime_code_present": True,
                        "compiler": str(rec.get("CompilerVersion") or "") or None,
                        "optimizer": str(rec.get("OptimizationUsed") or "") or None,
                        "optimizer_runs": str(rec.get("Runs") or "") or None,
                        "evm_version": str(rec.get("EVMVersion") or "") or None,
                        "via_ir": rec.get("ViaIR"),
                        "libraries": rec.get("Libraries") or rec.get("Library") or {},
                        "also_reported_by_etherscan": bool(rec.get("EtherscanVerified")),
                        "identity_note": identity_note,
                    }
                is_proxy = bool(
                    (proxy_info and proxy_info.is_proxy)
                    or (rec and str(rec.get("Proxy") or "0") == "1"))
                impl = None
                if proxy_info and proxy_info.is_proxy:
                    impl = proxy_info.implementation
                elif rec:
                    impl = str(rec.get("Implementation") or "") or None
                meta = dict(row)
                try:
                    discovery_meta = json.loads(row["discovery_json"] or "{}")
                except (ValueError, TypeError):
                    discovery_meta = {}
                market = max(
                    float((discovery_meta.get(provider) or {}).get("liquidity_usd") or 0)
                    for provider in ("dexscreener", "dextools")
                )
                meta["market_liquidity_usd"] = market or None
                # Token-approval signal (lightweight). Measure is already gated by
                # disk_pressure.allow_expensive("hunt.measure"); skip on failure.
                has_approvals = None
                approval_usd = None
                try:
                    existing_appr = self.store.conn.execute(
                        "SELECT has_user_approvals, approval_usd FROM hunt_candidates "
                        "WHERE network=? AND address=?",
                        (self.cfg.network, addr)).fetchone()
                except Exception:  # noqa: BLE001 — column may not exist yet on older DBs mid-migrate
                    existing_appr = None
                if existing_appr is not None and existing_appr["has_user_approvals"] is not None:
                    has_approvals = bool(existing_appr["has_user_approvals"])
                    approval_usd = existing_appr["approval_usd"]
                else:
                    try:
                        appr = probe_user_approvals(
                            self.client, addr,
                            tokens=self.cfg.transfer_tokens,
                            lookback_blocks=min(self.cfg.transfer_lookback_blocks, 3000))
                        has_approvals = bool(appr.get("has_user_approvals"))
                        approval_usd = appr.get("approval_usd")
                    except Exception as exc:  # noqa: BLE001
                        log.info("hunt: approval probe for %s failed: %s", addr, _redact(exc))
                meta.update({"onchain_tvl_usd": onchain, "has_code": True, "verified": verified,
                             "blue_chip": bool(row["blue_chip"]),
                             "has_user_approvals": has_approvals,
                             "approval_usd": approval_usd})
                score, why = priority_score(meta, now, sig)
                if verified and lang == "vyper":
                    status, err = "skipped", "vyper (not yet supported by local pipeline)"
                elif verified:
                    status, err = "ready", None
                else:
                    status, err = "unverified", "source not verified"
                attempts = int(row["source_attempts"] or 0)
                retry_at = None
                if not verified:
                    attempts += 1
                    retry_at = now + min(86400.0, 900.0 * (2 ** min(attempts - 1, 7)))
                upsert_candidate(
                    self.store, self.cfg.network, addr, has_code=True, verified=verified,
                    source_provider=(str(rec.get("SourceProvider") or "") if rec else None),
                    contract_name=(str(rec.get("ContractName") or "") or None) if rec else None,
                    language=lang, is_proxy=is_proxy, implementation=impl,
                    proxy_kind=(proxy_info.kind if proxy_info and proxy_info.is_proxy else
                                (str(rec.get("ProxyKind") or "") or None) if rec else None),
                    onchain_tvl_usd=onchain, tvl_measured_at=now,
                    holder_value_usd=holder_usd if holder_usd is not None else onchain,
                    value_json=(existing["value_json"] if existing and existing["value_json"]
                                else (json.dumps(var.to_dict()) if var else None)),
                    discovery_json=json.dumps(provenance, sort_keys=True),
                    has_user_approvals=has_approvals, approval_usd=approval_usd,
                    priority_score=score, score_reasons=json.dumps(why),
                    signals_json=json.dumps(sig), status=status, last_error=err,
                    source_attempts=attempts if not verified else 0,
                    source_retry_at=retry_at, now=now)
                out.append({"address": addr, "status": status, "priority_score": score,
                            "onchain_tvl_usd": onchain, "holder_value_usd": holder_usd,
                            "verified": verified, "is_proxy": is_proxy,
                            "implementation": impl})
        return out

    def _monitor(self) -> Monitor:
        cfg = MonitorConfig(
            network=self.cfg.network, min_severity=self.cfg.min_severity,
            max_per_poll=self.cfg.scan_per_cycle, interval=0,
            cache_dir=Path(self.cfg.cache_dir) / "sources",
            alerts_path=Path(self.cfg.alerts_path) if self.cfg.alerts_path
            else default_alerts_path(),
            db_path=self.cfg.db_path, solc_auto_install=self.cfg.solc_auto_install,
            value_enabled=self.cfg.value_enabled, min_value_usd=self.cfg.min_value_usd,
            origin="hunt")
        kw: Dict[str, Any] = {"emit": self.emit, "clock": self.clock, "sleep": self.sleep,
                              "price_source": self.price_source}
        if self._analyzer is not None:
            kw["analyzer"] = self._analyzer
        if self._recorder is not None:
            kw["recorder"] = self._recorder
        return Monitor(cfg, self.client, **kw)

    def scan_top(self, n: Optional[int] = None) -> List[Dict[str, Any]]:
        n = int(n if n is not None else self.cfg.scan_per_cycle)
        if n <= 0 or self.client is None:
            return []
        lo, hi = self.cfg.target_tvl_low, self.cfg.target_tvl_high
        # Prefer ready+verified in the target TVL band, then by priority.
        rows = self.store.conn.execute(
            "SELECT * FROM hunt_candidates WHERE network=? AND status='ready' "
            "AND verified=1 AND COALESCE(language,'solidity')='solidity' "
            "ORDER BY CASE WHEN COALESCE(holder_value_usd, onchain_tvl_usd) IS NOT NULL "
            "AND COALESCE(holder_value_usd, onchain_tvl_usd) BETWEEN ? AND ? "
            "THEN 0 ELSE 1 END, "
            "COALESCE(scan_attempt_at,0) ASC, "
            "COALESCE(holder_value_usd, onchain_tvl_usd, 0) DESC, "
            "priority_score DESC LIMIT ?",
            (self.cfg.network, lo, hi, n)).fetchall()
        if not rows:
            return []
        mon = self._monitor()
        results = []
        try:
            for row in rows:
                if self.stop_requested:
                    break
                addr = row["address"]
                self.store.enqueue(self.cfg.network, addr, "", 0)
                qrow = self.store.conn.execute(
                    "SELECT * FROM monitor_queue WHERE network=? AND address=?",
                    (self.cfg.network, addr)).fetchone()
                upsert_candidate(self.store, self.cfg.network, addr, status="scanning",
                                 scan_attempt_at=self.clock(), now=self.clock())
                try:
                    r = mon._process_safely(qrow)
                except Exception as exc:  # noqa: BLE001
                    r = {"address": addr, "status": "failed", "error": _redact(exc)}
                # Phase 21: major-token assess() often reports $0 on vaults that hold
                # protocol tokens (USN, sUSDe, …). Prefer the vault-discovery holder value.
                held = row["holder_value_usd"] if "holder_value_usd" in row.keys() else None
                if held is not None and (r.get("tvl_usd") is None or float(r.get("tvl_usd") or 0) < float(held)):
                    r = dict(r, tvl_usd=float(held), value_is_estimate=True)
                    if r.get("row"):
                        try:
                            self.store.conn.execute(
                                "UPDATE monitor_scans SET tvl_usd=? WHERE id=?",
                                (float(held), int(r["row"])))
                            self.store.conn.commit()
                        except Exception:  # noqa: BLE001
                            pass
                status = r.get("status") or "failed"
                hunt_status = {"scanned": "scanned", "incomplete": "incomplete",
                               "duplicate": "scanned", "deferred": "ready",
                               "unverified": "unverified", "failed": "failed"}.get(status, status)
                old_hash = row["last_content_hash"]
                new_hash = r.get("content_hash")
                fields = dict(
                    status=hunt_status,
                    last_scan_row=r.get("row"), last_scan_id=r.get("scan_id"),
                    last_content_hash=new_hash,
                    findings=r.get("findings"), est_max_loss_usd=r.get("est_max_loss_usd"),
                    last_error=r.get("error") or ("; ".join(r.get("reasons") or []) or None),
                    now=self.clock())
                if status in ("scanned", "duplicate", "incomplete"):
                    fields["scanned_at"] = self.clock()
                if old_hash and new_hash and old_hash != new_hash:
                    fields.update(sim_status=None, sim_run_id=None,
                                  sim_summary_json=None, sim_at=None)
                upsert_candidate(self.store, self.cfg.network, addr, **fields)
                from auditor.disk_pressure import get_controller as _dp
                _ok_fd, _why_fd = _dp().allow_expensive("hunt.fork_diff")
                if _ok_fd:
                    self._fork_diff_stage(addr, r)
                else:
                    log.info("hunt: fork_diff deferred for %s (%s)", addr[:12], _why_fd)
                    r["fork_diff"] = {"deferred": _why_fd}
                results.append(r)
                self.emit(
                    f"hunt: {addr} → {status}"
                    + (f" ({r.get('findings')} findings)" if "findings" in r else "")
                    + (f", TVL ~${r['tvl_usd']:,.0f}" if r.get("tvl_usd") is not None else "")
                    + (f", est. max loss ~${r['est_max_loss_usd']:,.0f}"
                       if r.get("est_max_loss_usd") is not None else ""))
        finally:
            mon.store.close()
        return results

    def _proxy_init_stage(self, limit: int = 10) -> Dict[str, Any]:
        """Strategy stage: read-only proxy/initializer sweep over proxied candidates
        (bounded per cycle, 24h re-check). Failure never breaks the cycle."""
        if self.client is None:
            return {"skipped": "no chain client"}
        try:
            from auditor import proxy_init_sweep
            return proxy_init_sweep.sweep(self.store.conn, self.client, self.cfg.network,
                                          limit=limit, emit=self.emit)
        except Exception as exc:  # noqa: BLE001
            self.emit(f"hunt: proxy/init sweep skipped: {type(exc).__name__}")
            return {"error": type(exc).__name__}

    def _queue_periodic_rescans(self, limit: int = 5) -> Dict[str, Any]:
        """Requeue a small slice of high-exposure targets on a bounded cadence."""
        try:
            interval = max(300.0, float(os.environ.get("AUDITOR_HUNT_RESCAN_SECONDS", "21600")))
        except ValueError:
            interval = 21600.0
        cutoff = self.clock() - interval
        min_value = max(0.0, self.cfg.min_holder_usd)
        rows = self.store.conn.execute(
            "SELECT address, holder_value_usd, onchain_tvl_usd, llama_tvl_usd "
            "FROM hunt_candidates WHERE network=? AND status='scanned' AND scanned_at IS NOT NULL "
            "AND scanned_at<=? AND COALESCE(holder_value_usd,onchain_tvl_usd,llama_tvl_usd,0)>=? "
            "ORDER BY COALESCE(holder_value_usd,onchain_tvl_usd,llama_tvl_usd,0) DESC, "
            "COALESCE(priority_score,0) DESC LIMIT ?",
            (self.cfg.network, cutoff, min_value, max(1, min(int(limit), 25))),
        ).fetchall()
        now = self.clock()
        for row in rows:
            self.store.conn.execute(
                "UPDATE hunt_candidates SET status='new', last_error=NULL, updated_at=? "
                "WHERE network=? AND address=? AND status='scanned'",
                (now, self.cfg.network, row["address"]),
            )
            self.emit(f"hunt: periodic re-audit queued for {row['address']} after {int(interval)}s")
        if rows:
            self.store.conn.commit()
        return {"queued": len(rows), "interval_seconds": int(interval)}

    def _recover_stale_scan_claims(self, stale_after_s: float = 1800.0) -> int:
        """Return abandoned scan claims to the eligible queue after worker restarts."""
        now = self.clock()
        cutoff = now - max(60.0, float(stale_after_s))
        cur = self.store.conn.execute(
            "UPDATE hunt_candidates SET status=CASE WHEN verified=1 THEN 'ready' ELSE 'unverified' END, "
            "last_error='recovered stale scan claim', updated_at=? "
            "WHERE network=? AND status='scanning' "
            "AND COALESCE(scan_attempt_at,last_attempt_at,updated_at,0)<=?",
            (now, self.cfg.network, cutoff))
        self.store.conn.commit()
        return max(0, int(cur.rowcount))

    def _check_proxy_upgrades(self, limit: int = 40, min_age: float = 300.0) -> Dict[str, Any]:
        """Re-read high-value proxies so implementation upgrades are re-audited.

        This is a bounded, read-only check. Only a positively resolved new
        implementation invalidates the old scan; an RPC/provider failure never
        erases the last known implementation.
        """
        if self.client is None:
            return {"checked": 0, "changed": 0, "unavailable": 0, "skipped": "no chain client"}
        from .vault_discovery import Reader, resolve_proxy

        now = self.clock()
        rows = self.store.conn.execute(
            "SELECT address, implementation, proxy_kind, discovery_json, status "
            "FROM hunt_candidates WHERE network=? AND is_proxy=1 "
            "AND (last_proxy_checked_at IS NULL OR last_proxy_checked_at<=?) "
            "ORDER BY COALESCE(holder_value_usd,onchain_tvl_usd,llama_tvl_usd,0) DESC, "
            "COALESCE(priority_score,0) DESC LIMIT ?",
            (self.cfg.network, now - max(0.0, float(min_age)), max(1, min(int(limit), 100))),
        ).fetchall()
        reader = Reader(self.client, max_calls=max(32, len(rows) * 16))
        checked = changed = unavailable = 0
        # Phase 43: each row's UPDATE below is committed immediately, BEFORE
        # the loop proceeds to the next row's resolve_proxy() RPC/rate-limit
        # sleep. Deferring the commit to the loop end held one write
        # transaction open across minutes of network waits (RESERVED+PENDING
        # verified live on the SQLite lock bytes on 2026-10-24), wedging every
        # other writer/reader. Rows are fully materialized via fetchall() and
        # resolve_proxy() does no DB access, so per-row commits cannot
        # invalidate iteration state.
        for row in rows:
            if self.stop_requested:
                break
            address = str(row["address"])
            previous = str(row["implementation"] or "").lower() or None
            try:
                info = resolve_proxy(reader, address)
            except Exception as exc:  # defensive: one malformed target must not stop the cycle
                unavailable += 1
                self.emit(f"hunt: proxy upgrade check unavailable for {address}: {type(exc).__name__}")
                continue
            # Empty code is ambiguous (unsupported RPC, rate limit, or unavailable
            # historical state), so do not record it as a successful check.
            if not info.code_size:
                unavailable += 1
                continue
            checked += 1
            current = str(info.implementation or "").lower() or None
            if current and current != previous:
                try:
                    discovery = json.loads(row["discovery_json"] or "{}")
                except (ValueError, TypeError):
                    discovery = {}
                discovery["proxy_upgrade"] = {
                    "previous_implementation": previous,
                    "implementation": current,
                    "detected_at": now,
                    "proxy_kind": info.kind,
                }
                self.store.conn.execute(
                    "UPDATE hunt_candidates SET implementation=?, proxy_kind=?, "
                    "last_proxy_checked_at=?, status='new', last_error=NULL, discovery_json=?, updated_at=? "
                    "WHERE network=? AND address=?",
                    (current, info.kind, now, json.dumps(discovery, sort_keys=True), now,
                     self.cfg.network, address),
                )
                self.store.conn.commit()  # per-row commit (Phase 43: see note above the loop)
                source_cache = getattr(self.client, "_records", None)
                if isinstance(source_cache, dict):
                    for cached_address in (address.lower(), previous, current):
                        if cached_address:
                            source_cache.pop(cached_address, None)
                changed += 1
                self.emit(
                    f"hunt: proxy implementation changed for {address}: {previous or 'unknown'} → {current}; "
                    "queued for source re-verification and rescan"
                )
            else:
                self.store.conn.execute(
                    "UPDATE hunt_candidates SET last_proxy_checked_at=?, "
                    "proxy_kind=COALESCE(?,proxy_kind), updated_at=? WHERE network=? AND address=?",
                    (now, info.kind, now, self.cfg.network, address),
                )
                self.store.conn.commit()  # per-row commit (Phase 43: see note above the loop)
        return {"checked": checked, "changed": changed, "unavailable": unavailable}

    def _fork_diff_stage(self, addr: str, r: Mapping[str, Any]) -> None:
        """Strategy 2 stage: after a scan, record which functions of a likely
        fork differ from the local verified-source corpus. Offline, read-only
        on sources; failure never affects the scan result."""
        if not r.get("row"):
            return
        try:
            from auditor import fork_diff
            row = self.store.conn.execute("SELECT cache_dir, content_hash FROM monitor_scans WHERE id=?",
                                          (int(r["row"]),)).fetchone()
            if not row or not row[0] or not Path(row[0]).is_dir():
                return
            idx = getattr(self, "_fork_index", None)
            if idx is None or self.clock() - getattr(self, "_fork_index_at", 0) > 3600:
                from auditor.monitor import default_cache_dir
                cache = default_cache_dir()
                roots = [p for p in cache.glob("*/*/*") if p.is_dir()]
                roots += [p for p in (cache / "hunt" / "sources").glob("*/*/*") if p.is_dir()]
                idx = fork_diff.build_index(roots)
                self._fork_index, self._fork_index_at = idx, self.clock()
                self._upstream_index = fork_diff.build_upstream_index()
            diffs = fork_diff.diff_candidate(Path(row[0]), idx, upstream=getattr(self, "_upstream_index", None))
            if diffs:
                fork_diff.record(self.store.conn, self.cfg.network, addr, row[1], diffs, idx["contracts"])
                n = sum(len(d["changed"]) for d in diffs)
                same = sum(d["unchanged"] for d in diffs)
                noref = sum(d["no_reference"] for d in diffs)
                added = sum(len((d.get("upstream") or {}).get("added") or []) for d in diffs)
                verdict = (f"{n} changed, {same} unchanged, {added} added vs pinned upstream, {noref} without corpus reference"
                           if (n or same or added) else f"inconclusive: no corpus reference for {noref} function(s)")
                self.emit(f"hunt: fork-diff {addr}: {','.join(sorted({d['family'] for d in diffs}))} {verdict}")
                ups = [d for d in diffs if "upstream" in d]
                if ups and all(d.get("unmodified_upstream") for d in ups):
                    # Byte-identical (normalized) to pinned audited upstream: lower review priority.
                    row2 = self.store.conn.execute(
                        "SELECT signals_json FROM hunt_candidates WHERE network=? AND address=?",
                        (self.cfg.network, addr)).fetchone()
                    if row2 is not None:
                        sj = json.loads(row2[0] or "{}")
                        sig = list(sj.get("signals") or [])
                        if "unmodified_upstream" not in sig:
                            sj["signals"] = sig + ["unmodified_upstream"]
                            self.store.conn.execute(
                                "UPDATE hunt_candidates SET signals_json=?, priority_score=COALESCE(priority_score,0)-10 "
                                "WHERE network=? AND address=?", (json.dumps(sj, sort_keys=True), self.cfg.network, addr))
                            self.store.conn.commit()
        except Exception as exc:  # noqa: BLE001
            self.emit(f"hunt: fork-diff skipped for {addr}: {type(exc).__name__}")

    def cycle(self, scan_limit: Optional[int] = None,
              measure_limit: Optional[int] = None, refresh: bool = True) -> Dict[str, Any]:
        """One refresh → measure → scan cycle (CLI ``--once`` / continuous tick).

        Expensive stages (measure / proxy_init / scan / fork-diff) are gated by
        ``auditor.disk_pressure``: paused while free < 12 GiB; resume only after
        two consecutive checks >= 15 GiB; free rechecked before each expensive
        stage (queued candidates preserved when deferred).
        """
        stats: Dict[str, Any] = {"network": self.cfg.network, "at": self.clock()}
        err = None
        try:
            from auditor.disk_pressure import get_controller
            dp = get_controller()
            stats["disk_pressure"] = dp.check().to_dict()
            snapshot_fn = getattr(self.client, "state_snapshot", None)
            if callable(snapshot_fn):
                try:
                    stats["snapshot"] = snapshot_fn()
                    snap = stats["snapshot"]
                    self.emit(f"hunt: pinned state reads to {snap.get('finality')} block {snap.get('block')}")
                except Exception as exc:  # noqa: BLE001 - use provider latest if block-tag RPC is unavailable
                    stats["snapshot"] = {"error": type(exc).__name__}
                    log.info("hunt: state snapshot unavailable: %s", type(exc).__name__)
            self._beat({"status": "running", "stage": "discover"})
            if refresh:
                self.emit("pipeline:stage=discover")
                stats["refresh"] = self.refresh()  # discovery metadata only — light
            self.emit("pipeline:stage=retrieve_source")
            self._beat({"status": "running", "stage": "retrieve_source"})
            stats["recovered_scans"] = self._recover_stale_scan_claims()
            stats["periodic_rescans"] = self._queue_periodic_rescans()
            allow_m, why_m = dp.allow_expensive("hunt.measure")
            if allow_m:
                stats["measured"] = self.measure(limit=measure_limit)
            else:
                stats["measured"] = []
                stats["disk_deferred"] = stats.get("disk_deferred") or []
                stats["disk_deferred"].append(why_m)
                self.emit(f"hunt: measure deferred ({why_m})")
            self.emit("pipeline:stage=verify_deployment")
            self._beat({"status": "running", "stage": "verify_deployment"})
            allow_u, why_u = dp.allow_expensive("hunt.proxy_upgrade_check")
            if allow_u:
                stats["proxy_upgrades"] = self._check_proxy_upgrades()
            else:
                stats["proxy_upgrades"] = {"deferred": why_u}
                stats.setdefault("disk_deferred", []).append(why_u)
            allow_p, why_p = dp.allow_expensive("hunt.proxy_init")
            if allow_p:
                stats["proxy_init"] = self._proxy_init_stage()
            else:
                stats["proxy_init"] = {"deferred": why_p}
                stats.setdefault("disk_deferred", []).append(why_p)
            self.emit("pipeline:stage=prioritize")
            self._beat({"status": "running", "stage": "prioritize"})
            allow_s, why_s = dp.allow_expensive("hunt.scan")
            if allow_s:
                self.emit("pipeline:stage=security_analysis")
                stats["scanned"] = self.scan_top(scan_limit)
            else:
                stats["scanned"] = []
                stats.setdefault("disk_deferred", []).append(why_s)
                self.emit(f"hunt: scan deferred ({why_s})")
            sim_limit = max(0, int(self.cfg.simulate_per_cycle))
            if sim_limit:
                self.emit("pipeline:stage=fork_validation")
                self._beat({"status": "running", "stage": "fork_validation"})
                allow_f, why_f = dp.allow_expensive("hunt.fork_simulation")
                if allow_f:
                    from .simulate import simulate_hunt_top
                    sim_results = simulate_hunt_top(
                        n=sim_limit, network=self.cfg.network, db_path=self.cfg.db_path,
                        client=self.client, emit=self.emit)
                    stats["simulated"] = [
                        {"address": r.get("address"), "run_id": r.get("run_id"),
                         "status": r.get("status"), "error": r.get("error")}
                        for r in sim_results]
                else:
                    stats["simulated"] = []
                    stats.setdefault("disk_deferred", []).append(why_f)
                    self.emit(f"hunt: fork simulation deferred ({why_f})")
            else:
                stats["simulated"] = []
            stats["disk_pressure"] = dp.status()
        except Exception as exc:  # noqa: BLE001
            err = f"{type(exc).__name__}: {_redact(exc)}"
            stats["error"] = err
            log.warning("hunt: cycle failed: %s", err)
            self.emit(f"warning: hunt failed: {err[:300]}")
        # Outcome recording is best-effort: this write sits directly on the
        # path where the store is under maximum contention (the cycle may
        # have just failed on the same lock). A raised OperationalError here
        # used to unwind cycle() -> run() -> cli main() and KILL the process
        # (watchdog restart loop amplification). The cycle outcome itself is
        # already carried in `stats` / the warning above either way.
        try:
            self.store.conn.execute(
                "INSERT INTO hunt_runs(network,at,refreshed,discovered,measured,scanned,error,stats_json) "
                "VALUES(?,?,?,?,?,?,?,?)",
                (self.cfg.network, self.clock(),
                 int((stats.get("refresh") or {}).get("protocols") or 0),
                 int((stats.get("refresh") or {}).get("discovered") or 0),
                 len(stats.get("measured") or []),
                 len(stats.get("scanned") or []),
                 err, json.dumps({k: v for k, v in stats.items() if k != "measured"},
                                 sort_keys=True, default=str)))
            self.store.conn.commit()
        except sqlite3.OperationalError as exc:
            log.warning("hunt: cycle outcome not recorded (%s: %s)",
                        type(exc).__name__, _redact(exc))
            self.emit(f"warning: hunt run row not recorded: {type(exc).__name__}: {exc}"[:160])
        return stats

    def run(self, once: bool = False, scan_limit: Optional[int] = None) -> List[Dict[str, Any]]:
        import signal
        prev: Dict[int, Any] = {}
        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                prev[sig] = signal.signal(sig, self.request_stop)
            except ValueError:
                prev = {}
                break
        runs: List[Dict[str, Any]] = []
        lock = WorkerLock(worker_lock_path(self.cfg.db_path, "hunt", self.cfg.network))
        lock_handle = None
        try:
            lock_handle = lock.acquire()
            self._beat({"status": "running", "once": bool(once), "interval": self.cfg.interval})
            while not self.stop_requested:
                try:
                    runs.append(self.cycle(scan_limit=scan_limit))
                except Exception as exc:  # noqa: BLE001 - the loop must survive
                    # Parity with monitor.run() (Phase 18.1): an unexpected
                    # cycle crash must not end the worker process — monitor/
                    # hunt restart loops under store contention are watchdog
                    # amplification, not repair. The error is logged with its
                    # stack (never silently swallowed) and surfaced via emit.
                    log.exception("hunt: cycle aborted (unhandled error); "
                                  "continuing after the interval wait")
                    self.emit("warning: hunt cycle aborted (unhandled error); will retry")
                    runs.append({"network": self.cfg.network,
                                 "error": f"{type(exc).__name__}: {_redact(exc)}"})
                self._beat({"status": "running", "cycles": len(runs), "interval": self.cfg.interval})
                if once:
                    break
                waited = 0.0
                last_wait_beat = waited
                while waited < self.cfg.interval and not self.stop_requested:
                    step = min(1.0, self.cfg.interval - waited)
                    self.sleep(step)
                    waited += step
                    if waited - last_wait_beat >= 60.0:
                        # (P1 step 2) keep the heartbeat fresh during the idle
                        # wait between cycles so heartbeat-based wedge
                        # detection never sees the normal inter-cycle sleep.
                        self._beat({"status": "waiting", "cycles": len(runs),
                                    "interval": self.cfg.interval})
                        last_wait_beat = waited
        except LockHeld as exc:
            self.emit(f"hunt: already running (pid {exc.pid}); exiting (busy)")
            self._beat({"status": "busy"})
            raise
        finally:
            if lock_handle is not None:  # busy workers leave no heartbeat row
                self._beat({"status": "stopped", "cycles": len(runs)})
            for sig, handler in prev.items():
                signal.signal(sig, handler)
            self.store.close()
            if lock_handle is not None:
                lock_handle.release()
        return runs


def _http_get_as_request(req: urllib.request.Request, timeout: float) -> bytes:
    """Adapter so HuntClient can reuse ChainClient's Request-based http hook."""
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
        return resp.read()


# ---------------------------------------------------------------------------
# Read-only status / dashboard helpers
# ---------------------------------------------------------------------------

_SORT_SQL = {
    "priority": "COALESCE(priority_score,0) DESC, COALESCE(holder_value_usd, onchain_tvl_usd, llama_tvl_usd, 0) DESC",
    "tvl": "COALESCE(holder_value_usd, onchain_tvl_usd, llama_tvl_usd, 0) DESC, COALESCE(priority_score,0) DESC",
    "recent": "COALESCE(updated_at, discovered_at, 0) DESC",
    "loss": "COALESCE(est_max_loss_usd, -1) DESC, COALESCE(priority_score,0) DESC",
}


def _ensure_hunt_v6(conn: sqlite3.Connection) -> None:
    """Idempotent Phase-21 columns so the dashboard works before MonitorStore opens."""
    if not conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='hunt_candidates'").fetchone():
        return
    cols = {r[1] for r in conn.execute("PRAGMA table_info(hunt_candidates)")}
    for col, decl in (("proxy_kind", "TEXT"), ("holder_value_usd", "REAL"),
                      ("holder_role", "TEXT"), ("discovery_json", "TEXT"),
                      ("last_proxy_checked_at", "REAL"),
                      ("scan_address", "TEXT"),
                      ("last_attempt_at", "REAL"), ("scan_attempt_at", "REAL"),
                      ("source_attempts", "INTEGER NOT NULL DEFAULT 0"),
                      ("source_retry_at", "REAL"),
                      ("sim_status", "TEXT"), ("sim_run_id", "INTEGER"),
                      ("sim_summary_json", "TEXT"), ("sim_at", "REAL"),
                      ("has_user_approvals", "INTEGER"), ("approval_usd", "REAL")):
        if col not in cols:
            conn.execute(f"ALTER TABLE hunt_candidates ADD COLUMN {col} {decl}")
    try:
        conn.commit()
    except Exception:  # noqa: BLE001
        pass



def _disk_pressure_status() -> Dict[str, Any]:
    try:
        from auditor.disk_pressure import get_controller
        return get_controller().status()
    except Exception as exc:  # noqa: BLE001
        return {"error": f"{type(exc).__name__}: {exc}"[:200]}


def hunt_overview(conn: sqlite3.Connection, network: str = "ethereum",
                  since: Optional[float] = None, until: Optional[float] = None,
                  top: int = 50, sort: str = "priority") -> Dict[str, Any]:
    """Aggregates for the /hunt dashboard and ``hunt-status`` CLI."""
    empty = {"candidates": [], "counters": {"total": 0, "scanned": 0, "ready": 0, "by_status": {},
                                            "hunted_value_scanned_today_usd": 0.0,
                                            "hunted_tvl_scanned_today_usd": 0.0,
                                            "source_unverified": 0, "source_retry_due": 0,
                                            "source_exact_matches": 0, "simulation_review": 0,
                                            "priority_label": SCORE_LABEL},
             "score_label": SCORE_LABEL, "network": network}
    exists = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='hunt_candidates'").fetchone()
    if not exists:
        return empty
    _ensure_hunt_v6(conn)
    by = {r[0]: int(r[1]) for r in conn.execute(
        "SELECT status, COUNT(*) FROM hunt_candidates WHERE network=? GROUP BY status",
        (network,)).fetchall()}
    order = _SORT_SQL.get(sort, _SORT_SQL["priority"])
    # Phase 21 columns are optional (pre-v6 DBs read via migration on open).
    top_rows = [dict(r) for r in conn.execute(
        "SELECT address, protocol, slug, category, category_group, "
        "llama_tvl_usd, onchain_tvl_usd, holder_value_usd, holder_role, "
        "priority_score, score_reasons, signals_json, "
        "status, verified, contract_name, language, blue_chip, findings, est_max_loss_usd, "
        "is_proxy, implementation, proxy_kind, scan_address, sim_status, sim_run_id, sim_summary_json, sim_at, "
        "last_attempt_at, source_attempts, source_retry_at, "
        "last_scan_row, last_scan_id, listed_at, audits, scanned_at, updated_at, source, "
        "sources_json, source_provider, discovery_json "
        "FROM hunt_candidates WHERE network=? "
        f"ORDER BY {order} LIMIT ?", (network, int(top))).fetchall()]
    for r in top_rows:
        for k in ("score_reasons", "signals_json"):
            if r.get(k):
                try:
                    r[k] = json.loads(r[k])
                except (ValueError, TypeError):
                    pass
        for k in ("sources_json", "discovery_json", "sim_summary_json"):
            if r.get(k):
                try:
                    r[k] = json.loads(r[k])
                except (ValueError, TypeError):
                    pass
        r["sources"] = r.pop("sources_json", []) or []
        r["discovery"] = r.pop("discovery_json", {}) or {}
        r["sim_summary"] = r.pop("sim_summary_json", {}) or {}
        r["potential_impact_estimate_usd"] = r.get("est_max_loss_usd")
        r["impact_estimate_kind"] = "heuristic_model" if r.get("est_max_loss_usd") is not None else None
        r["score_label"] = SCORE_LABEL
        r["explorer_url"] = f"https://etherscan.io/address/{r['address']}"

    def _sum_scanned(lo: Optional[float], hi: Optional[float]) -> Tuple[float, float, int]:
        # Phase 22: prefer holder_value_usd (vault-discovery) over major-token
        # onchain_tvl_usd / est_max_loss, which often under-count protocol tokens.
        q = ("SELECT COALESCE(SUM(COALESCE(holder_value_usd, onchain_tvl_usd, 0)),0), "
             "COALESCE(SUM(COALESCE(holder_value_usd, onchain_tvl_usd, 0)),0), "
             "COALESCE(SUM(COALESCE(findings,0)),0) "
             "FROM hunt_candidates WHERE network=? AND status='scanned'")
        args: List[Any] = [network]
        if lo is not None:
            q += " AND COALESCE(scanned_at, updated_at) >= ?"; args.append(lo)
        if hi is not None:
            q += " AND COALESCE(scanned_at, updated_at) < ?"; args.append(hi)
        row = conn.execute(q, args).fetchone()
        return float(row[0] or 0), float(row[1] or 0), int(row[2] or 0)

    held_t, tvl_t, find_t = _sum_scanned(since, until)
    held_a, tvl_a, find_a = _sum_scanned(None, None)
    ready = by.get("ready", 0) + by.get("new", 0) + by.get("measured", 0)
    candidate_cols = {r[1] for r in conn.execute("PRAGMA table_info(hunt_candidates)")}
    source_retry_due = 0
    simulation_review = 0
    source_exact_matches = 0
    if "source_retry_at" in candidate_cols:
        source_retry_due = int(conn.execute(
            "SELECT COUNT(*) FROM hunt_candidates WHERE network=? AND status='unverified' "
            "AND (source_retry_at IS NULL OR source_retry_at<=?)", (network, time.time())).fetchone()[0])
    if "sim_status" in candidate_cols:
        simulation_review = int(conn.execute(
            "SELECT COUNT(*) FROM hunt_candidates WHERE network=? AND sim_status IN ('fail','review')",
            (network,)).fetchone()[0])
    for item in conn.execute(
            "SELECT discovery_json FROM hunt_candidates WHERE network=? AND verified=1", (network,)):
        try:
            discovery = json.loads(item[0] or "{}")
            sv = discovery.get("source_verification") or {}
            source_exact_matches += int(sv.get("identity_status") == "exact_match")
        except (ValueError, TypeError, AttributeError):
            continue
    # Financial-loss buckets from monitor findings (confirmed vs unresolved vs disproved)
    fin = {"confirmed_outsider_usd": 0.0, "unresolved_suspicion_usd": 0.0,
           "disproved_excluded_usd": 0.0, "value_at_risk_found_usd": 0.0,
           "potential_impact_counts": {}, "potential_impact_estimates_usd": {},
           "potential_impact_estimate_note": (
               "Modeled potential impact only; per-mechanism estimates may overlap and are not confirmed loss.")}
    try:
        from auditor.monitor import value_overview
        # All-time buckets for confirmed / unresolved / disproved (today window can be empty
        # while holdings still show scanned-today). Holdings stay in hunted_* fields.
        vo = value_overview(conn, network)
        for k in fin:
            if k in vo:
                fin[k] = vo[k]
    except Exception:
        pass
    return {
        "network": network,
        "candidates": top_rows,
        "counters": {
            "total": sum(by.values()), "scanned": by.get("scanned", 0),
            "ready": ready, "by_status": by,
            "source_unverified": by.get("unverified", 0),
            "source_retry_due": source_retry_due,
            "source_exact_matches": source_exact_matches,
            "simulation_review": simulation_review,
            # "Hunted value" = live holder value of scanned candidates (rough estimate).
            "hunted_value_scanned_today_usd": held_t,
            "hunted_tvl_scanned_today_usd": tvl_t,
            "findings_today": find_t,
            "hunted_value_scanned_all_time_usd": held_a,
            "hunted_tvl_scanned_all_time_usd": tvl_a,
            "priority_label": SCORE_LABEL,
            **fin,
        },
        "score_label": SCORE_LABEL,
        "disk_pressure": _disk_pressure_status(),
        "recent_runs": [dict(r) for r in conn.execute(
            "SELECT id, at, refreshed, discovered, measured, scanned, error FROM hunt_runs "
            "WHERE network=? ORDER BY at DESC LIMIT 10", (network,)).fetchall()],
    }


def hunt_status(network: str = "ethereum", db_path: Optional[Path] = None,
                recent: int = 20, now: Optional[float] = None,
                sort: str = "priority") -> Dict[str, Any]:
    from .monitor_view import day_bounds, local_tz
    from datetime import datetime

    db = Path(db_path or default_monitor_db_path())
    out: Dict[str, Any] = {"network": network,
                           "monitor_db": "present" if db.exists() else "absent",
                           "score_label": SCORE_LABEL}
    if not db.exists():
        return out
    conn = sqlite3.connect(str(db))
    conn.row_factory = sqlite3.Row
    try:
        ts = now or time.time()
        tz = local_tz()
        start, end = day_bounds(ts, tz)
        overview = hunt_overview(conn, network, since=start, until=end, top=recent, sort=sort)
        out.update(overview)
        out["today_window"] = {"start": start, "end": end,
                               "date": datetime.fromtimestamp(ts, tz).date().isoformat(),
                               "timezone": str(tz)}
    finally:
        conn.close()
    return out
