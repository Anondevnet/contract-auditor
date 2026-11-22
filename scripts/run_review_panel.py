#!/usr/bin/env python3
"""Background free local review-panel pass (panel-v5).

Isolated DB: reports/review_panel.db (never monitor/history).
Resumable: enqueue is INSERT OR IGNORE; queue statuses pending/retry/done.
Rate-limited: min_interval_s between findings; stops if free disk < 8 GiB (panel_min via disk_pressure).
"""
from __future__ import annotations

import argparse
import os
import shutil
import sqlite3
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from auditor import review_panel as P  # noqa: E402
from auditor.disk_pressure import get_controller  # noqa: E402


def free_gib(path: Path) -> float:
    u = shutil.disk_usage(str(path))
    return u.free / (1024 ** 3)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--monitor-db", default=str(ROOT / "monitor_state.db"))
    ap.add_argument("--review-db", default=str(P.default_review_db()))
    ap.add_argument("--batch", type=int, default=5)
    ap.add_argument("--min-interval", type=float, default=2.0)
    ap.add_argument("--loop", action="store_true")
    ap.add_argument("--sleep", type=float, default=30.0)
    ap.add_argument("--min-severity", default="HIGH")
    ap.add_argument("--model", default=os.environ.get("AUDITOR_PANEL_MODEL", "qwen3-8b-uncensored-16k:latest"))
    ap.add_argument("--enqueue-only", action="store_true")
    args = ap.parse_args()

    mon = Path(args.monitor_db)
    if not mon.exists():
        print("monitor db missing", mon, file=sys.stderr)
        return 2

    con = P.connect(Path(args.review_db))
    # enqueue unsuppressed high+ findings not already done
    sev_rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFORMATIONAL": 0}
    min_r = sev_rank.get(args.min_severity.upper(), 3)
    mcon = sqlite3.connect(f"file:{mon}?mode=ro", uri=True)
    mcon.row_factory = sqlite3.Row
    rows = mcon.execute(
        "SELECT id, title, detector, vuln_class, category, severity, suppressed "
        "FROM monitor_findings WHERE suppressed=0"
    ).fetchall()
    mcon.close()
    to_q = [dict(r) for r in rows if sev_rank.get(str(r["severity"] or "").upper(), 0) >= min_r]
    n = P.enqueue(con, to_q)
    print(f"enqueued {n} new (eligible {len(to_q)}); queue={P.panel_summary(con)['queue']}")
    if args.enqueue_only:
        return 0

    backend = P.ollama_backend()
    models = {r: args.model for r in P.ROLES}
    load = P.monitor_loader(mon)

    while True:
        ok, why = get_controller().allow_panel()
        if not ok:
            print(f"STOP panel: {why}")
            return 3
        res = P.run_queue(con, load, backend, models, limit=args.batch, min_interval_s=args.min_interval)
        s = P.panel_summary(con)
        print(f"batch={len(res)} summary={s}", flush=True)
        if not args.loop:
            break
        pending = int(s.get("queue", {}).get("pending", 0)) + int(s.get("queue", {}).get("retry", 0))
        if pending <= 0:
            print("queue drained")
            break
        time.sleep(args.sleep)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
