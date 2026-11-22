#!/usr/bin/env python3
"""Second-stage financial-risk review runner (finrisk-v1).

Mirrors ``scripts/run_review_panel.py`` conventions:

* Isolated DB: ``reports/finrisk.db`` (env override ``AUDITOR_FINRISK_DB``).
  Never the monitor or history DB — those are READ-ONLY from here.
* Idempotent enqueue: historical scans are folded in with INSERT OR IGNORE
  keyed by (scan_id, fingerprint); re-running never duplicates reviews.
* Single-instance: exclusive flock on finrisk.lock. Dashboard manual runs
  hold the same lock per request, so queue writes stay serialized.
* Disk-pressure gated: stops when free disk drops below the panel floor
  (auditor.disk_pressure owns hunt/panel pause and resume).
* Rate-limited: ``--min-interval`` between reviews; batch size bounded.

Retest / scan pipelines are never touched: the runner only claims rows that
finrisk itself enqueued.
"""
from __future__ import annotations

import argparse
import json
import sqlite3
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from auditor import finrisk as F  # noqa: E402
from auditor.disk_pressure import get_controller  # noqa: E402


def _history_loader(history_db: Path):
    def load(scan_id: str):
        if not history_db.exists():
            return None
        try:
            con = sqlite3.connect(f"file:{history_db}?mode=ro", uri=True, timeout=10)
            con.row_factory = sqlite3.Row
        except sqlite3.Error:
            return None
        try:
            r = con.execute(
                "SELECT scan_id, timestamp, source_path, content_hash, config_fingerprint,"
                " status, finding_fingerprints, finding_details FROM scan_records WHERE scan_id=?",
                (scan_id,)).fetchone()
            return dict(r) if r is not None else None
        except sqlite3.Error:
            return None
        finally:
            con.close()
    return load


def enqueue_history(con: sqlite3.Connection, history_db: Path, *, limit: int = 0,
                    pending_only: bool = False) -> int:
    """Fold completed history scans into the queue (idempotent)."""
    if not history_db.exists():
        print(f"history db missing: {history_db}", file=sys.stderr)
        return 0
    hc = sqlite3.connect(f"file:{history_db}?mode=ro", uri=True, timeout=10)
    hc.row_factory = sqlite3.Row
    n = 0
    try:
        sql = ("SELECT scan_id, timestamp, source_path, finding_details FROM scan_records "
               "WHERE status='completed' AND finding_details IS NOT NULL")
        if pending_only:
            sql += " AND scan_id NOT IN (SELECT DISTINCT scan_id FROM finrisk_reviews)"
        sql += " ORDER BY timestamp DESC"
        if limit:
            sql += f" LIMIT {int(limit)}"
        for row in hc.execute(sql):
            n += F.enqueue_history_row(con, scan_id=str(row["scan_id"]), row=dict(row))
    finally:
        hc.close()
    return n


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--history-db", default=str(ROOT / "audit_scan_history.db"))
    ap.add_argument("--monitor-db", default=str(ROOT / "monitor_state.db"))
    ap.add_argument("--finrisk-db", default=str(F.default_finrisk_db()))
    ap.add_argument("--enqueue-history-limit", type=int, default=0,
                    help="0 = all completed scans; folds findings into the queue (idempotent).")
    ap.add_argument("--enqueue-missing-only", action="store_true",
                    help="Skip scans that already appear in the queue.")
    ap.add_argument("--batch", type=int, default=5)
    ap.add_argument("--min-interval", type=float, default=2.0)
    ap.add_argument("--loop", action="store_true")
    ap.add_argument("--sleep", type=float, default=30.0)
    ap.add_argument("--enqueue-only", action="store_true")
    ap.add_argument("--network-verify", action="store_true",
                    help="Allow bytecode/source verification reads (cast + Etherscan) per finding.")
    ap.add_argument("--rpc", default=None,
                    help="RPC URL for runtime disproof reads; falls back to the monitor env var.")
    args = ap.parse_args()

    history_db = Path(args.history_db)
    monitor_db = Path(args.monitor_db)

    with F.finrisk_lock(Path(args.finrisk_db)) as lock:
        if not lock.acquired():
            print("finrisk: another runner holds finrisk.lock; exiting", file=sys.stderr)
            return 2
        con = F.open_finrisk_db(Path(args.finrisk_db))
        try:
            n = enqueue_history(con, history_db,
                                limit=args.enqueue_history_limit,
                                pending_only=args.enqueue_missing_only)
            s = F.summary(con)
            print(f"finrisk: enqueued {n} new row(s); queue={json.dumps(s['queue'])}", flush=True)
            if args.enqueue_only:
                return 0

            rpc = args.rpc or F.rpc_url_for_review()
            loader = _history_loader(history_db)
            while True:
                ok, why = get_controller().allow_panel()
                if not ok:
                    print(f"STOP finrisk: {why}")
                    return 3
                res = F.process_queue(
                    con, limit=args.batch, history_loader=loader,
                    monitor_db_path=monitor_db, rpc_url=rpc,
                    allow_network_verify=True if args.network_verify else None,
                    log=lambda m: print(f"  {m}", flush=True))
                if res:
                    verdicts = {r.get("verdict") or r.get("status") for r in res}
                    print(f"finrisk: batch={len(res)} verdicts={verdicts}", flush=True)
                if not args.loop:
                    break
                s = F.summary(con)
                pending = s["queue"].get(F.STATE_PENDING, 0) + s["queue"].get(F.STATE_RETRYABLE, 0)
                if pending <= 0:
                    print("finrisk: queue drained")
                    break
                time.sleep(args.sleep)
            s = F.summary(con)
            print(f"finrisk: summary={json.dumps(s['verdicts'])} queue={json.dumps(s['queue'])}")
            return 0
        finally:
            con.close()


if __name__ == "__main__":
    raise SystemExit(main())
