"""Phase 24 (small) — watch list for monitor-found / manual targets.

Re-measures holder value, ERC-20 totalSupply (as units only), and Uni V2/V3
pool presence on each monitor poll (and via ``audit.py watch check``). When
measured USD exposure meets ``min_value_usd``, appends a defensive alert to
``reports/monitor_alerts.jsonl``. Never broadcasts; read-only RPC.
"""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence

log = logging.getLogger("contract_auditor.watch")

LABEL = "rough estimate (watch re-measure — defensive)"
WETH = "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2"
USDC = "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"
USDT = "0xdac17f958d2ee523a2206206994597c13d831ec7"
UNI_V2_FACTORY = "0x5c69bee701ef814a2b6a3edd4b1652cb9cc5aa6f"
UNI_V3_FACTORY = "0x1f98431c8ad98523631ae4a59f267346ea31f984"
ZERO = "0x" + "0" * 40

SEL_TOTAL_SUPPLY = "0x18160ddd"
SEL_DECIMALS = "0x313ce567"
SEL_SYMBOL = "0x95d89b41"
SEL_GET_PAIR = "0xe6a43905"  # getPair(address,address)
SEL_GET_POOL = "0x1698ee82"  # getPool(address,address,uint24) — verify
SEL_GET_RESERVES = "0x0902f1ac"
SEL_TOKEN0 = "0x0dfe1681"
SEL_TOKEN1 = "0xd21220a7"


def ensure_watch_schema(conn: Any) -> None:
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS watch_targets (
            network TEXT NOT NULL,
            address TEXT NOT NULL,
            note TEXT,
            origin TEXT,
            related_address TEXT,
            min_value_usd REAL NOT NULL DEFAULT 1000,
            added_at REAL,
            updated_at REAL,
            last_checked_at REAL,
            last_holder_usd REAL,
            last_supply_raw TEXT,
            last_supply_decimals INTEGER,
            last_pool_usd REAL,
            last_measured_usd REAL,
            last_alert_at REAL,
            last_alert_level REAL,
            meta_json TEXT,
            PRIMARY KEY (network, address)
        );
        CREATE INDEX IF NOT EXISTS ix_watch_checked ON watch_targets(last_checked_at);
        """
    )
    try:
        conn.commit()
    except Exception:  # noqa: BLE001
        pass


def add_watch(
    store: Any, network: str, address: str, *, note: str = "",
    origin: str = "manual", related_address: Optional[str] = None,
    min_value_usd: float = 1000.0, now: Optional[float] = None,
) -> Dict[str, Any]:
    ensure_watch_schema(store.conn)
    # Also mirror into hunt_candidates so the hunt UI can surface it.
    try:
        from auditor.hunt import upsert_candidate
        upsert_candidate(
            store, network, address.lower(),
            protocol=None, status="watching", source="watch",
            sources_json=json.dumps(["watch"]),
            contract_name=None, discovered_at=now or time.time(),
            updated_at=now or time.time(),
            holder_role="watch",
            discovery_json=json.dumps({"note": note, "origin": origin,
                                       "related": related_address}),
        )
    except Exception as exc:  # noqa: BLE001
        log.info("watch: hunt mirror skipped: %s", type(exc).__name__)

    ts = float(now or time.time())
    store.conn.execute(
        "INSERT INTO watch_targets(network,address,note,origin,related_address,"
        "min_value_usd,added_at,updated_at) VALUES(?,?,?,?,?,?,?,?) "
        "ON CONFLICT(network,address) DO UPDATE SET "
        "note=excluded.note, origin=excluded.origin, "
        "related_address=excluded.related_address, "
        "min_value_usd=excluded.min_value_usd, updated_at=excluded.updated_at",
        (network, address.lower(), note or None, origin,
         related_address.lower() if related_address else None,
         float(min_value_usd), ts, ts),
    )
    store.conn.commit()
    return {"network": network, "address": address.lower(), "note": note,
            "min_value_usd": float(min_value_usd), "origin": origin}


def list_watches(store: Any, network: str = "ethereum") -> List[Dict[str, Any]]:
    ensure_watch_schema(store.conn)
    rows = store.conn.execute(
        "SELECT * FROM watch_targets WHERE network=? ORDER BY added_at DESC",
        (network,),
    ).fetchall()
    return [dict(r) for r in rows]


def remove_watch(store: Any, network: str, address: str) -> bool:
    ensure_watch_schema(store.conn)
    cur = store.conn.execute(
        "DELETE FROM watch_targets WHERE network=? AND address=?",
        (network, address.lower()),
    )
    store.conn.commit()
    return cur.rowcount > 0


def _pack_addr(a: str) -> str:
    return a.lower().replace("0x", "").rjust(64, "0")


def _pack_uint24(n: int) -> str:
    return format(int(n) & 0xFFFFFF, "064x")


def _call_int(client: Any, to: str, data: str) -> Optional[int]:
    try:
        raw = client.call(to, data)
    except Exception:  # noqa: BLE001
        return None
    if not isinstance(raw, str) or not raw.startswith("0x") or len(raw) < 3:
        return None
    try:
        return int(raw[2:66], 16)
    except ValueError:
        return None


def _call_addr(client: Any, to: str, data: str) -> Optional[str]:
    try:
        raw = client.call(to, data)
    except Exception:  # noqa: BLE001
        return None
    if not isinstance(raw, str) or not raw.startswith("0x") or len(raw) < 42:
        return None
    a = "0x" + raw[-40:].lower()
    return None if a == ZERO else a


def _pool_liquidity_usd(client: Any, token: str, price_usd: Optional[float]) -> Dict[str, Any]:
    """Rough Uni V2 reserve valuation + V3 pool presence (no tick math)."""
    out: Dict[str, Any] = {"pairs": [], "pools": [], "pool_usd": 0.0, "label": LABEL}
    token = token.lower()
    quotes = [("WETH", WETH), ("USDC", USDC), ("USDT", USDT)]
    for qname, quote in quotes:
        try:
            pair = _call_addr(
                client, UNI_V2_FACTORY,
                SEL_GET_PAIR + _pack_addr(token) + _pack_addr(quote),
            )
        except Exception:  # noqa: BLE001
            pair = None
        if not pair:
            # try reversed order (factory is commutative for getPair)
            continue
        r0 = _call_int(client, pair, SEL_GET_RESERVES)
        # getReserves returns (uint112,uint112,uint32) — need raw call
        try:
            raw = client.call(pair, SEL_GET_RESERVES)
            if isinstance(raw, str) and len(raw) >= 130:
                reserve0 = int(raw[2:66], 16) & ((1 << 112) - 1)
                reserve1 = int(raw[66:130], 16) & ((1 << 112) - 1)
            else:
                reserve0 = reserve1 = 0
        except Exception:  # noqa: BLE001
            reserve0 = reserve1 = 0
        t0 = _call_addr(client, pair, SEL_TOKEN0)
        entry = {"pair": pair, "quote": qname, "reserve0": reserve0, "reserve1": reserve1,
                 "token0": t0}
        out["pairs"].append(entry)
        # Value the quote-side reserve only (conservative lower bound).
        q_is_token0 = (t0 or "").lower() == quote
        q_reserve = reserve0 if q_is_token0 else reserve1
        # WETH 18dec, USDC/USDT 6dec
        q_dec = 18 if quote == WETH else 6
        q_amt = q_reserve / (10 ** q_dec)
        # Prefer stablecoin face value; WETH needs price — leave 0 if unknown.
        if quote in (USDC, USDT):
            out["pool_usd"] += q_amt
        elif quote == WETH and price_usd:
            # price_usd here is token price, not WETH — skip unless we have eth price in meta
            pass

    # Uni V3 presence only (liquidity sizing is tick-dependent).
    # getPool selector: keccak("getPool(address,address,uint24)")[:4]
    # 0x1698ee82 is correct for Uniswap V3 factory.
    for fee in (500, 3000, 10000):
        for quote, qaddr in ((WETH, WETH), (USDC, USDC)):
            try:
                pool = _call_addr(
                    client, UNI_V3_FACTORY,
                    "0x1698ee82" + _pack_addr(token) + _pack_addr(qaddr) + _pack_uint24(fee),
                )
            except Exception:  # noqa: BLE001
                pool = None
            if pool:
                out["pools"].append({"pool": pool, "quote": quote, "fee": fee})
    return out


def measure_target(client: Any, address: str, *, price_source: Any = None) -> Dict[str, Any]:
    """Read-only measurement of holdings / supply / pools for one address."""
    address = address.lower()
    measured: Dict[str, Any] = {
        "address": address, "holder_usd": 0.0, "supply_raw": None,
        "supply_decimals": None, "symbol": None, "pool_usd": 0.0,
        "pools": {}, "value": None, "measured_usd": 0.0, "label": LABEL,
    }
    # Holdings via Phase 19 assess (native + major tokens).
    try:
        from auditor.value_at_risk import assess, PriceSource
        ps = price_source or PriceSource()
        var = assess(client, address, None, ps)
        measured["value"] = var.to_dict() if var is not None else None
        if var is not None:
            measured["holder_usd"] = float(getattr(var, "tvl_usd", 0) or 0)
    except Exception as exc:  # noqa: BLE001
        measured["value_error"] = f"{type(exc).__name__}"

    supply = _call_int(client, address, SEL_TOTAL_SUPPLY)
    if supply is not None:
        measured["supply_raw"] = str(supply)
        dec = _call_int(client, address, SEL_DECIMALS)
        measured["supply_decimals"] = int(dec) if dec is not None else 18
    try:
        raw = client.call(address, SEL_SYMBOL)
        # ABI string decode is messy; leave None when not a clean string return
        if isinstance(raw, str) and len(raw) > 128:
            measured["symbol"] = None
    except Exception:  # noqa: BLE001
        pass

    pools = _pool_liquidity_usd(client, address, None)
    measured["pools"] = pools
    measured["pool_usd"] = float(pools.get("pool_usd") or 0)
    measured["measured_usd"] = max(measured["holder_usd"], measured["pool_usd"])
    return measured


def _append_alert(alerts_path: Path, payload: Dict[str, Any]) -> None:
    alerts_path.parent.mkdir(parents=True, exist_ok=True)
    with alerts_path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(payload, sort_keys=True) + "\n")


def check_watches(
    store: Any, client: Any, *, network: str = "ethereum",
    alerts_path: Optional[Path] = None, price_source: Any = None,
    emit: Callable[[str], None] = print, now: Optional[float] = None,
    default_min_value_usd: float = 1000.0,
) -> Dict[str, Any]:
    """Re-measure every watch target; alert when measured_usd >= threshold."""
    from auditor.monitor import default_alerts_path

    ensure_watch_schema(store.conn)
    ts = float(now or time.time())
    ap = Path(alerts_path or default_alerts_path())
    rows = list_watches(store, network)
    results = []
    alerts = 0
    for row in rows:
        addr = row["address"]
        threshold = float(row["min_value_usd"] if row["min_value_usd"] is not None else default_min_value_usd)
        try:
            m = measure_target(client, addr, price_source=price_source)
        except Exception as exc:  # noqa: BLE001
            emit(f"watch: {addr} measure failed: {type(exc).__name__}")
            store.conn.execute(
                "UPDATE watch_targets SET last_checked_at=?, updated_at=?, meta_json=? "
                "WHERE network=? AND address=?",
                (ts, ts, json.dumps({"error": type(exc).__name__}), network, addr),
            )
            store.conn.commit()
            results.append({"address": addr, "error": type(exc).__name__})
            continue

        store.conn.execute(
            "UPDATE watch_targets SET last_checked_at=?, updated_at=?, "
            "last_holder_usd=?, last_supply_raw=?, last_supply_decimals=?, "
            "last_pool_usd=?, last_measured_usd=?, meta_json=? "
            "WHERE network=? AND address=?",
            (ts, ts, m["holder_usd"], m.get("supply_raw"), m.get("supply_decimals"),
             m["pool_usd"], m["measured_usd"], json.dumps(m, default=str),
             network, addr),
        )
        # Mirror into hunt_candidates holder_value for dashboard visibility.
        try:
            from auditor.hunt import upsert_candidate
            upsert_candidate(
                store, network, addr,
                holder_value_usd=m["measured_usd"],
                onchain_tvl_usd=m["holder_usd"],
                value_json=json.dumps(m, default=str),
                tvl_measured_at=ts, updated_at=ts, status="watching",
            )
        except Exception:  # noqa: BLE001
            pass

        fired = False
        if m["measured_usd"] >= threshold:
            # Dedup: alert again only if value grew ≥10% since last alert level.
            last_level = row.get("last_alert_level")
            should = last_level is None or m["measured_usd"] >= float(last_level) * 1.10
            if should:
                alert = {
                    "ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
                    "kind": "watch_threshold",
                    "network": network,
                    "address": addr,
                    "related_address": row.get("related_address"),
                    "note": row.get("note"),
                    "severity": "HIGH",
                    "title": "watch: measured exposure crossed threshold",
                    "measured_usd": m["measured_usd"],
                    "holder_usd": m["holder_usd"],
                    "pool_usd": m["pool_usd"],
                    "min_value_usd": threshold,
                    "supply_raw": m.get("supply_raw"),
                    "value_is_estimate": True,
                    "label": LABEL,
                }
                _append_alert(ap, alert)
                store.conn.execute(
                    "UPDATE watch_targets SET last_alert_at=?, last_alert_level=? "
                    "WHERE network=? AND address=?",
                    (ts, m["measured_usd"], network, addr),
                )
                emit(f"ALERT [watch] {addr} measured ~${m['measured_usd']:,.0f} "
                     f"(threshold ${threshold:,.0f}) — rough estimate")
                alerts += 1
                fired = True
        store.conn.commit()
        results.append({"address": addr, "measured_usd": m["measured_usd"],
                        "holder_usd": m["holder_usd"], "pool_usd": m["pool_usd"],
                        "alerted": fired})
    return {"network": network, "checked": len(results), "alerts": alerts, "results": results}
