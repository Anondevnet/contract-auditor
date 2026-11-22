"""Scan-history balance_usd enrichment for Audit Grouper handoffs.

Problem: monitor_findings.balance_usd is populated at insert, but the
scan-history records that feed handoffs (audit_scan_history.db
scan_records / finding_details) historically lacked a first-class
balance_usd. Handoff batches therefore arrived at $0 even when monitor
or hunt already knew a value.

This module:
  * resolves the best available USD value for a (network, address[, scan_id])
    from monitor_findings.balance_usd, monitor_scans.tvl_usd / value_json,
    and hunt_candidates.holder_value_usd / onchain_tvl_usd;
  * enrichs a handoff batch in memory (and optionally persists into the
    additive scan_records.balance_usd column without clearing known values);
  * lists completed monitor_scans in a finished_at window using NOT INDEXED
    (defensive: indexes have been reported possibly corrupted; our own
    integrity_check was ok).

Never REINDEX / VACUUM / DROP / DELETE. Never starts measure/scan/fork.
"""

from __future__ import annotations

import json
import os
import re
import sqlite3
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
_SOURCE_REF_RE = re.compile(r"^etherscan://(?:([a-z0-9-]+)/)?(0x[0-9a-fA-F]{40})$", re.I)
DEFAULT_HANDOFF_CURSOR = _PROJECT_ROOT / "reports" / "research" / "scanner_handoff_cursor.json"
DEFAULT_MIN_BALANCE_USD = 250.0


def default_history_db() -> Path:
    override = os.environ.get("AUDITOR_HISTORY_DB", "").strip()
    if override:
        return Path(override)
    return _PROJECT_ROOT / "audit_scan_history.db"


def default_monitor_db() -> Path:
    override = os.environ.get("AUDITOR_MONITOR_DB", "").strip()
    if override:
        return Path(override)
    return _PROJECT_ROOT / "monitor_state.db"


def parse_source_ref(source_path: Any) -> Tuple[Optional[str], Optional[str]]:
    """Return (network, address) from an etherscan:// source_path, else (None, None)."""
    m = _SOURCE_REF_RE.match(str(source_path or ""))
    if not m:
        return None, None
    net = (m.group(1) or "ethereum").lower()
    return net, m.group(2).lower()


def _open_ro(path: Path) -> sqlite3.Connection:
    con = sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=5)
    con.row_factory = sqlite3.Row
    return con


def _as_float(v: Any) -> Optional[float]:
    if v is None or v == "":
        return None
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def _prefer(current: Optional[float], candidate: Optional[float]) -> Optional[float]:
    """Keep the larger known non-None value (more informative for handoff ranking)."""
    c = _as_float(candidate)
    if c is None:
        return current
    if current is None:
        return c
    return c if c > current else current


def _tvl_from_value_json(raw: Any) -> Optional[float]:
    if not raw:
        return None
    try:
        v = json.loads(raw) if isinstance(raw, str) else raw
    except (TypeError, ValueError, json.JSONDecodeError):
        return None
    if not isinstance(v, dict):
        return None
    if isinstance(v.get("value"), dict):
        v = v["value"]
    return _as_float(v.get("tvl_usd"))


def best_balance_usd(
    monitor_con: sqlite3.Connection,
    network: str,
    address: str,
    scan_id: Optional[str] = None,
) -> Optional[float]:
    """Best available USD balance for one contract from monitor/hunt tables.

    Preference order within each source is max(non-null); across sources we
    take the max so a later higher measurement wins. Returns None only when
    every source is unknown.
    """
    net = (network or "ethereum").lower()
    addr = (address or "").lower()
    if not addr:
        return None
    best: Optional[float] = None

    # 1) Exact scan_id match on monitor_scans (most precise when available).
    if scan_id:
        try:
            row = monitor_con.execute(
                "SELECT tvl_usd, value_json FROM monitor_scans "
                "WHERE scan_id = ? LIMIT 1",
                (scan_id,),
            ).fetchone()
        except sqlite3.Error:
            row = None
        if row is not None:
            best = _prefer(best, row["tvl_usd"])
            best = _prefer(best, _tvl_from_value_json(row["value_json"]))

    # 2) monitor_findings.balance_usd for this address.
    try:
        row = monitor_con.execute(
            "SELECT MAX(balance_usd) AS b FROM monitor_findings "
            "WHERE network = ? AND lower(address) = ? AND balance_usd IS NOT NULL",
            (net, addr),
        ).fetchone()
        if row is not None:
            best = _prefer(best, row["b"])
    except sqlite3.Error:
        pass

    # 3) monitor_scans.tvl_usd / value_json (latest finished preferred; no index).
    try:
        rows = monitor_con.execute(
            "SELECT tvl_usd, value_json FROM monitor_scans NOT INDEXED "
            "WHERE network = ? AND lower(address) = ? "
            "ORDER BY finished_at DESC, id DESC LIMIT 5",
            (net, addr),
        ).fetchall()
        for row in rows:
            best = _prefer(best, row["tvl_usd"])
            best = _prefer(best, _tvl_from_value_json(row["value_json"]))
    except sqlite3.Error:
        pass

    # 4) hunt_candidates holder / on-chain TVL.
    try:
        row = monitor_con.execute(
            "SELECT holder_value_usd, onchain_tvl_usd, llama_tvl_usd "
            "FROM hunt_candidates WHERE network = ? AND lower(address) = ? LIMIT 1",
            (net, addr),
        ).fetchone()
        if row is not None:
            for col in ("holder_value_usd", "onchain_tvl_usd", "llama_tvl_usd"):
                best = _prefer(best, row[col])
    except sqlite3.Error:
        pass

    return best


def enrich_rows(
    rows: Sequence[Mapping[str, Any]],
    *,
    monitor_db: Optional[Path] = None,
    history_db: Optional[Path] = None,
    persist: bool = False,
) -> List[Dict[str, Any]]:
    """Fill balance_usd on each row (in memory); optionally persist to history.

    Each input row should carry at least one of:
      - balance_usd (kept if already set)
      - network + address
      - source_path (etherscan://…)
      - scan_id (joined to monitor_scans / scan_records)

    When persist=True, only NULL scan_records.balance_usd values are filled
    (COALESCE); existing non-NULL values are never cleared or overwritten.
    """
    mon_path = Path(monitor_db) if monitor_db else default_monitor_db()
    hist_path = Path(history_db) if history_db else default_history_db()
    out: List[Dict[str, Any]] = [dict(r) for r in rows]
    if not out:
        return out

    mon = None
    if mon_path.exists():
        try:
            mon = _open_ro(mon_path)
        except sqlite3.Error:
            mon = None

    try:
        for row in out:
            if row.get("balance_usd") is not None:
                continue
            net = row.get("network")
            addr = row.get("address")
            if not net or not addr:
                net2, addr2 = parse_source_ref(row.get("source_path"))
                net = net or net2
                addr = addr or addr2
            if mon is not None and net and addr:
                resolved = best_balance_usd(
                    mon, str(net), str(addr), scan_id=row.get("scan_id")
                )
                if resolved is not None:
                    row["balance_usd"] = resolved
            # Also inject into finding_details entries when present as a list.
            details = row.get("finding_details")
            if row.get("balance_usd") is not None and isinstance(details, list):
                bal = float(row["balance_usd"])
                new_details = []
                for d in details:
                    if isinstance(d, dict):
                        dd = dict(d)
                        if dd.get("balance_usd") is None:
                            dd["balance_usd"] = bal
                        new_details.append(dd)
                    else:
                        new_details.append(d)
                row["finding_details"] = new_details
    finally:
        if mon is not None:
            mon.close()

    if persist and hist_path.exists():
        from auditor.scan_history import ScanHistory

        hist = ScanHistory(hist_path)  # ensures additive balance_usd column
        try:
            for row in out:
                sid = row.get("scan_id")
                bal = row.get("balance_usd")
                if sid and bal is not None:
                    hist.set_balance_usd(str(sid), float(bal))
        finally:
            hist.close()
    return out


def count_resolvable(
    *,
    history_db: Optional[Path] = None,
    monitor_db: Optional[Path] = None,
    only_null: bool = True,
) -> Dict[str, int]:
    """Read-only: how many completed scan_records resolve a non-null balance_usd."""
    hist_path = Path(history_db) if history_db else default_history_db()
    mon_path = Path(monitor_db) if monitor_db else default_monitor_db()
    out = {
        "completed": 0,
        "already_set": 0,
        "resolvable_nonnull": 0,
        "resolvable_ge_250": 0,
        "unresolvable": 0,
    }
    if not hist_path.exists() or not mon_path.exists():
        return out
    h = _open_ro(hist_path)
    m = _open_ro(mon_path)
    try:
        # Detect whether balance_usd column exists yet.
        cols = {r[1] for r in h.execute("PRAGMA table_info(scan_records)")}
        has_col = "balance_usd" in cols
        if has_col:
            sql = "SELECT scan_id, source_path, balance_usd FROM scan_records WHERE status='completed'"
        else:
            sql = "SELECT scan_id, source_path, NULL AS balance_usd FROM scan_records WHERE status='completed'"
        for row in h.execute(sql):
            out["completed"] += 1
            existing = _as_float(row["balance_usd"]) if has_col else None
            if existing is not None:
                out["already_set"] += 1
                if only_null:
                    continue
            net, addr = parse_source_ref(row["source_path"])
            if not addr:
                out["unresolvable"] += 1
                continue
            resolved = best_balance_usd(m, net or "ethereum", addr, scan_id=row["scan_id"])
            if resolved is None:
                out["unresolvable"] += 1
            else:
                out["resolvable_nonnull"] += 1
                if resolved >= DEFAULT_MIN_BALANCE_USD:
                    out["resolvable_ge_250"] += 1
    finally:
        h.close()
        m.close()
    return out


def handoff_scans_since(
    since_finished_at: float,
    *,
    monitor_db: Optional[Path] = None,
    history_db: Optional[Path] = None,
    until_finished_at: Optional[float] = None,
    min_balance_usd: float = DEFAULT_MIN_BALANCE_USD,
    prefer_value_holding: bool = True,
    persist: bool = False,
    limit: int = 500,
) -> List[Dict[str, Any]]:
    """Completed monitor_scans after *since_finished_at*, enriched with balance_usd.

    Uses ``monitor_scans NOT INDEXED`` for the finished_at window (defensive).
    When prefer_value_holding is True, rows with balance_usd >= min_balance_usd
    sort first; within each tier, finished_at ascending (stable handoff order).
    """
    mon_path = Path(monitor_db) if monitor_db else default_monitor_db()
    if not mon_path.exists():
        return []
    until = until_finished_at if until_finished_at is not None else time.time() + 1e9
    mon = _open_ro(mon_path)
    try:
        rows = mon.execute(
            """
            SELECT id, network, address, contract_name, scan_id, findings,
                   tvl_usd, value_json, finished_at, status, origin,
                   user_funds_at_risk, started_at
            FROM monitor_scans NOT INDEXED
            WHERE finished_at IS NOT NULL
              AND finished_at > ?
              AND finished_at <= ?
              AND status IN ('done', 'incomplete', 'completed')
            ORDER BY finished_at ASC, id ASC
            LIMIT ?
            """,
            (float(since_finished_at), float(until), int(limit)),
        ).fetchall()
        batch = []
        for r in rows:
            bal = _as_float(r["tvl_usd"])
            if bal is None:
                bal = _tvl_from_value_json(r["value_json"])
            if bal is None:
                bal = best_balance_usd(
                    mon, r["network"], r["address"], scan_id=r["scan_id"]
                )
            batch.append({
                "monitor_scan_id": r["id"],
                "network": r["network"],
                "address": r["address"],
                "contract_name": r["contract_name"],
                "scan_id": r["scan_id"],
                "findings": r["findings"],
                "tvl_usd": _as_float(r["tvl_usd"]),
                "balance_usd": bal,
                "finished_at": r["finished_at"],
                "status": r["status"],
                "origin": r["origin"],
                "user_funds_at_risk": r["user_funds_at_risk"],
                "source_path": f"etherscan://{r['network']}/{r['address']}",
            })
    finally:
        mon.close()

    # Re-enrich via shared path (also optional persist into scan_records).
    batch = enrich_rows(batch, monitor_db=mon_path, history_db=history_db, persist=persist)

    if prefer_value_holding:
        def _key(row: Mapping[str, Any]) -> Tuple[int, float, int]:
            bal = _as_float(row.get("balance_usd"))
            valued = 0 if (bal is not None and bal >= float(min_balance_usd)) else 1
            fin = float(row.get("finished_at") or 0.0)
            return (valued, fin, int(row.get("monitor_scan_id") or 0))

        batch.sort(key=_key)
    return batch


def load_handoff_cursor(path: Optional[Path] = None) -> Dict[str, Any]:
    p = Path(path) if path else DEFAULT_HANDOFF_CURSOR
    if not p.exists():
        return {"last_handoff_finished_at_epoch": 0.0, "scans_handed": 0}
    try:
        data = json.loads(p.read_text())
    except (OSError, ValueError, json.JSONDecodeError):
        return {"last_handoff_finished_at_epoch": 0.0, "scans_handed": 0}
    return data if isinstance(data, dict) else {"last_handoff_finished_at_epoch": 0.0}


def write_handoff_cursor(
    cursor: Mapping[str, Any],
    *,
    path: Optional[Path] = None,
    note: str = "",
) -> Path:
    """Write the handoff marker file (caller decides when a batch was sent)."""
    p = Path(path) if path else DEFAULT_HANDOFF_CURSOR
    p.parent.mkdir(parents=True, exist_ok=True)
    payload = dict(cursor)
    if note:
        payload["note"] = note
    if "last_handoff_at_utc" not in payload:
        payload["last_handoff_at_utc"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%MZ")
    p.write_text(json.dumps(payload, sort_keys=True))
    return p


def ensure_history_balance_column(history_db: Optional[Path] = None) -> bool:
    """Idempotent ADD COLUMN balance_usd on scan_records. Returns True if column exists after."""
    from auditor.scan_history import ScanHistory

    path = Path(history_db) if history_db else default_history_db()
    hist = ScanHistory(path)
    try:
        cols = {r[1] for r in hist.conn.execute("PRAGMA table_info(scan_records)")}
        return "balance_usd" in cols
    finally:
        hist.close()
