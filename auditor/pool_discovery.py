"""Pool-level discovery from DEX factory creation events (read-only).

Scans ``PairCreated`` / ``PoolCreated`` logs on known Uniswap-style factories
(and optionally any emitter of those topics), measures live major-token
holdings, and returns pools above a USD threshold.

``eth_getLogs`` block-range limits (Alchemy free tier, public RPCs) are handled
by probing and auto-shrinking the chunk window, with sleep/backoff between
calls. Large lookbacks (200k+ blocks) are supported via chunking.

Defensive / discovery only — no exploit logic.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence, Tuple

log = logging.getLogger("auditor.pool_discovery")

PAIR_CREATED = "0x0d3648bd0f6ba80134a33ba9275ac585d9d315f0ad8355cddefde31afa28d0e9"
POOL_CREATED_V3 = "0x783cca1c0412dd0d695e784568c96da2e9c22ff989357a2e8b1d9b2b4e6b7118"

# (label, factory_or_empty, topic0, kind) — empty factory + scan_any_emitter uses topic-only
DEFAULT_FACTORIES: Tuple[Tuple[str, str, str, str], ...] = (
    ("uniswap-v2", "0x5c69bee701ef814a2b6a3edd4b1652cb9cc5aa6f", PAIR_CREATED, "v2"),
    ("sushiswap-v2", "0xc0aee478e3658e2610c5f7a4a2e1777ce9e4f2ac", PAIR_CREATED, "v2"),
    ("pancakeswap-v2", "0x1097053fd2ea711dad45caccc45eff7548fcb362", PAIR_CREATED, "v2"),
    ("shibaswap", "0x115934131916c8b277dd010ee02de365c4bd4f9a", PAIR_CREATED, "v2"),
    ("uniswap-v3", "0x1f98431c8ad98523631ae4a59f267346ea31f984", POOL_CREATED_V3, "v3"),
    ("sushiswap-v3", "0xbaceb8ec6b9355dfc0269c18bac9d6e2bdc29c4f", POOL_CREATED_V3, "v3"),
    ("pancakeswap-v3", "0x0bfbcf9fa4f9c56b0f40a671ad40e0805a091865", POOL_CREATED_V3, "v3"),
)

# Topic-only sweeps catch forks / unknown factories emitting the same events
TOPIC_SWEEPS: Tuple[Tuple[str, str, str], ...] = (
    ("any-pair-created", PAIR_CREATED, "v2"),
    ("any-pool-created-v3", POOL_CREATED_V3, "v3"),
)

MAJORS_SET = {
    "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2",
    "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
    "0xdac17f958d2ee523a2206206994597c13d831ec7",
    "0x6b175474e89094c44da98b954eedeac495271d0f",
    "0x2260fac5e5542a773aa44fbcfedf7c193bc2c599",
}

MAJOR_TOKENS: Dict[str, Tuple[str, int]] = {
    "WETH": ("0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2", 18),
    "USDC": ("0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48", 6),
    "USDT": ("0xdac17f958d2ee523a2206206994597c13d831ec7", 6),
    "DAI": ("0x6b175474e89094c44da98b954eedeac495271d0f", 18),
    "WBTC": ("0x2260fac5e5542a773aa44fbcfedf7c193bc2c599", 8),
}

DEFAULT_CHUNK = 2_000
MIN_CHUNK = 10
MAX_CHUNK = 10_000

_RANGE_MARKERS = (
    "block range",
    "range is too large",
    "query returned more than",
    "response size exceeded",
    "log response size exceeded",
    "eth_getlogs is limited",
    "exceeds the max",
    "free tier",
    "10 block range",  # some public nodes
    "block range is too wide",
)
_RATE_MARKERS = (
    "rate limit",
    "429",
    "too many requests",
    "compute units",
    "cu/s",
    "capacity",
    "timeout",
)


def _topic_addr(topic: str) -> str:
    t = topic.lower().replace("0x", "")
    return "0x" + t[-40:]


def _word_addr(data: str, word_index: int) -> Optional[str]:
    hexdata = (data or "").lower().replace("0x", "")
    start = word_index * 64
    if len(hexdata) < start + 64:
        return None
    return "0x" + hexdata[start + 24 : start + 64]


def parse_pool_from_log(kind: str, lg: Mapping[str, Any]) -> Optional[str]:
    """Extract the pool/pair address from a factory creation log."""
    data = lg.get("data") or "0x"
    if kind == "v2":
        return _word_addr(data, 0)
    if kind == "v3":
        return _word_addr(data, 1)
    return None


def is_range_error(exc: Any) -> bool:
    msg = str(exc).lower()
    return any(m in msg for m in _RANGE_MARKERS)


def is_rate_error(exc: Any) -> bool:
    msg = str(exc).lower()
    return any(m in msg for m in _RATE_MARKERS)


def next_chunk_size(current: int, *, shrink: bool = False, grow: bool = False) -> int:
    """Pure helper for adaptive eth_getLogs window sizing."""
    if shrink:
        return max(MIN_CHUNK, int(current) // 2)
    if grow:
        return min(MAX_CHUNK, max(int(current) * 2, int(current) + 1))
    return max(MIN_CHUNK, min(MAX_CHUNK, int(current)))


@dataclass
class DiscoveredPool:
    address: str
    factory_label: str
    factory: str
    kind: str
    token0: Optional[str] = None
    token1: Optional[str] = None
    value_usd: float = 0.0
    breakdown: Dict[str, float] = field(default_factory=dict)


@dataclass
class PoolDiscoveryResult:
    pools: List[DiscoveredPool] = field(default_factory=list)
    scanned_logs: int = 0
    factories_ok: int = 0
    errors: List[str] = field(default_factory=list)
    chunk_blocks_final: int = DEFAULT_CHUNK


def measure_major_holdings(
    address: str,
    *,
    eth_balance_wei: int,
    erc20_balances: Mapping[str, int],
    prices_usd: Mapping[str, float],
) -> Tuple[float, Dict[str, float]]:
    """Pure helper: ETH + major ERC-20 balances → USD total and per-symbol map."""
    breakdown: Dict[str, float] = {}
    total = 0.0
    eth_p = float(prices_usd.get("ETH") or prices_usd.get("WETH") or 0.0)
    eth_usd = (eth_balance_wei / 1e18) * eth_p
    if eth_usd:
        breakdown["ETH"] = eth_usd
        total += eth_usd
    for sym, (addr, dec) in MAJOR_TOKENS.items():
        raw = int(erc20_balances.get(addr.lower()) or erc20_balances.get(sym) or 0)
        px = float(prices_usd.get(sym) or 0.0)
        usd = (raw / (10 ** dec)) * px
        if usd:
            breakdown[sym] = usd
            total += usd
    return total, breakdown


class PoolDiscovery:
    """Read-only factory-log scanner + holdings filter with adaptive chunking."""

    def __init__(
        self,
        client: Any,
        *,
        factories: Sequence[Tuple[str, str, str, str]] = DEFAULT_FACTORIES,
        lookback_blocks: int = 50_000,
        chunk_blocks: int = DEFAULT_CHUNK,
        min_holder_usd: float = 10_000.0,
        max_pools: int = 40,
        prices_usd: Optional[Mapping[str, float]] = None,
        balance_of: Optional[Callable[[str, str], int]] = None,
        eth_balance: Optional[Callable[[str], int]] = None,
        scan_any_emitter: bool = False,
        request_sleep_s: float = 0.15,
        sleep: Optional[Callable[[float], None]] = None,
        max_retries_per_chunk: int = 6,
    ):
        self.client = client
        self.factories = list(factories)
        self.lookback_blocks = int(lookback_blocks)
        self.chunk_blocks = int(chunk_blocks)
        self.min_holder_usd = float(min_holder_usd)
        self.max_pools = int(max_pools)
        self.prices_usd = dict(prices_usd or {})
        self._balance_of = balance_of
        self._eth_balance = eth_balance
        self.scan_any_emitter = bool(scan_any_emitter)
        self.request_sleep_s = float(request_sleep_s)
        self.sleep = sleep or time.sleep
        self.max_retries_per_chunk = int(max_retries_per_chunk)
        self._probed_chunk: Optional[int] = None

    def discover(self) -> PoolDiscoveryResult:
        result = PoolDiscoveryResult()
        try:
            head = int(self.client.block_number())
        except Exception as exc:  # noqa: BLE001
            result.errors.append(f"block_number: {exc}")
            return result
        start = max(head - self.lookback_blocks, 0)
        seen: set[str] = set()

        # Probe once so subsequent factories reuse a safe window.
        if self._probed_chunk is None:
            self._probed_chunk = self._probe_chunk_size(start, head)
        result.chunk_blocks_final = int(self._probed_chunk)

        jobs: List[Tuple[str, Optional[str], str, str]] = []
        for label, factory, topic0, kind in self.factories:
            jobs.append((label, factory, topic0, kind))
        if self.scan_any_emitter:
            for label, topic0, kind in TOPIC_SWEEPS:
                jobs.append((label, None, topic0, kind))

        for label, factory, topic0, kind in jobs:
            try:
                logs = self._fetch_logs_adaptive(factory, topic0, start, head)
                result.factories_ok += 1
            except Exception as exc:  # noqa: BLE001
                result.errors.append(f"{label}: {exc}")
                continue
            result.scanned_logs += len(logs)
            for lg in logs:
                pool = parse_pool_from_log(kind, lg)
                if not pool or pool.lower() in seen or pool == "0x" + "0" * 40:
                    continue
                seen.add(pool.lower())
                topics = lg.get("topics") or []
                t0 = _topic_addr(topics[1]) if len(topics) > 1 else None
                t1 = _topic_addr(topics[2]) if len(topics) > 2 else None
                if t0 and t1 and t0.lower() not in MAJORS_SET and t1.lower() not in MAJORS_SET:
                    continue
                # Prefer known-factory label when topic-sweep rediscovers the same pool
                factory_addr = (factory or (lg.get("address") or "")).lower()
                value, br = self._measure(pool)
                if value < self.min_holder_usd:
                    continue
                result.pools.append(DiscoveredPool(
                    address=pool.lower(), factory_label=label, factory=factory_addr,
                    kind=kind, token0=t0, token1=t1, value_usd=value, breakdown=br,
                ))
                if len(result.pools) >= self.max_pools:
                    result.pools.sort(key=lambda p: p.value_usd, reverse=True)
                    return result
        # Dedupe by address: prefer named factory over any-*; else higher USD
        by_addr: Dict[str, DiscoveredPool] = {}
        for pool in result.pools:
            prev = by_addr.get(pool.address)
            if prev is None:
                by_addr[pool.address] = pool
            elif pool.factory_label.startswith("any-") and not prev.factory_label.startswith("any-"):
                continue
            elif (not pool.factory_label.startswith("any-") and prev.factory_label.startswith("any-"))                     or pool.value_usd > prev.value_usd:
                by_addr[pool.address] = pool
        result.pools = sorted(by_addr.values(), key=lambda p: p.value_usd, reverse=True)
        return result

    def _probe_chunk_size(self, start: int, head: int) -> int:
        """Find a working eth_getLogs window near *head* (shrink on range errors)."""
        chunk = max(MIN_CHUNK, min(self.chunk_blocks, MAX_CHUNK))
        # Use a known factory for the probe when available
        probe_factory = self.factories[0][1] if self.factories else None
        probe_topic = self.factories[0][2] if self.factories else PAIR_CREATED
        end = head
        begin = max(head - chunk + 1, start)
        for _ in range(12):
            try:
                self.client.logs(probe_factory, probe_topic, begin, end)
                if self.request_sleep_s > 0:
                    self.sleep(self.request_sleep_s)
                return chunk
            except Exception as exc:  # noqa: BLE001
                if is_rate_error(exc):
                    self.sleep(min(8.0, 1.0 + chunk / 500))
                    continue
                if is_range_error(exc) and chunk > MIN_CHUNK:
                    chunk = next_chunk_size(chunk, shrink=True)
                    begin = max(head - chunk + 1, start)
                    continue
                # Non-range failure: keep current guess (etherscan fallback may work)
                log.info("pool_discovery: probe non-range error; keeping chunk=%s", chunk)
                return chunk
        return max(MIN_CHUNK, chunk)

    def _fetch_logs_adaptive(
        self, factory: Optional[str], topic0: str, start: int, head: int,
    ) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        chunk = int(self._probed_chunk or self.chunk_blocks)
        cur = start
        consecutive_ok = 0
        while cur <= head:
            end = min(cur + chunk - 1, head)
            try:
                part = self.client.logs(factory, topic0, cur, end) or []
                out.extend(part)
                cur = end + 1
                consecutive_ok += 1
                # Slowly grow after sustained success (still capped)
                if consecutive_ok >= 4 and chunk < MAX_CHUNK:
                    chunk = next_chunk_size(chunk, grow=True)
                    consecutive_ok = 0
                    self._probed_chunk = chunk
                if self.request_sleep_s > 0:
                    self.sleep(self.request_sleep_s)
            except Exception as exc:  # noqa: BLE001
                consecutive_ok = 0
                if is_rate_error(exc):
                    self.sleep(min(15.0, 2.0))
                    continue
                if is_range_error(exc) and chunk > MIN_CHUNK:
                    chunk = next_chunk_size(chunk, shrink=True)
                    self._probed_chunk = chunk
                    continue
                # Fall back to Etherscan for this window slice then continue
                eth = getattr(self.client, "_etherscan", None)
                if callable(eth):
                    try:
                        data = eth(
                            module="logs", action="getLogs",
                            **({"address": factory} if factory else {}),
                            fromBlock=str(cur), toBlock=str(end), topic0=topic0,
                        )
                        result = data.get("result") if isinstance(data, dict) else None
                        if isinstance(result, list):
                            out.extend(x for x in result if isinstance(x, dict))
                            cur = end + 1
                            if self.request_sleep_s > 0:
                                self.sleep(self.request_sleep_s * 2)
                            continue
                    except Exception as exc2:  # noqa: BLE001
                        raise RuntimeError(f"getLogs failed: {exc2}") from exc2
                raise
        return out

    def _measure(self, pool: str) -> Tuple[float, Dict[str, float]]:
        eth_wei = 0
        bals: Dict[str, int] = {}
        try:
            if self._eth_balance:
                eth_wei = int(self._eth_balance(pool))
            elif hasattr(self.client, "balance"):
                eth_wei = int(self.client.balance(pool))
        except Exception:  # noqa: BLE001
            eth_wei = 0
        for sym, (token, _dec) in MAJOR_TOKENS.items():
            try:
                if self._balance_of:
                    raw = int(self._balance_of(token, pool))
                else:
                    raw = self._rpc_balance_of(token, pool)
                bals[token.lower()] = raw
                bals[sym] = raw
            except Exception:  # noqa: BLE001
                bals[token.lower()] = 0
        if not self.prices_usd:
            approx = {
                "USDC": bals.get(MAJOR_TOKENS["USDC"][0].lower(), 0) / 1e6,
                "USDT": bals.get(MAJOR_TOKENS["USDT"][0].lower(), 0) / 1e6,
                "DAI": bals.get(MAJOR_TOKENS["DAI"][0].lower(), 0) / 1e18,
            }
            total = sum(approx.values())
            return total, {k: v for k, v in approx.items() if v}
        return measure_major_holdings(
            pool, eth_balance_wei=eth_wei, erc20_balances=bals, prices_usd=self.prices_usd,
        )

    def _rpc_balance_of(self, token: str, holder: str) -> int:
        data = "0x70a08231000000000000000000000000" + holder.lower().replace("0x", "").zfill(40)[-40:]
        if hasattr(self.client, "call"):
            res = self.client.call(token, data)
        elif hasattr(self.client, "eth_call"):
            res = self.client.eth_call(token, data)
        else:
            raise AttributeError("client has no call")
        if isinstance(res, int):
            return res
        s = str(res)
        if s.startswith("0x"):
            return int(s, 16) if len(s) > 2 else 0
        return int(s)
