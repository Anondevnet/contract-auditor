"""Live-state disproof of source-shape hypotheses (read-only eth_call).

A source matcher can only say a *shape* exists. Some shapes are only
exploitable in a specific on-chain state (e.g. the Compound empty-market
attack needs totalSupply ~ 0). When the live state rules the tested path out,
the finding is suppressed with a recorded reason
``"tested path disproved under current state"`` plus the observed values and
block — it is NOT a fork test and NOT a proof of safety under other states.
Nothing here sends a transaction.
"""
from __future__ import annotations

import json
import sqlite3
from typing import Any, Dict, Optional

RULE = "live-state-disproof"
REASON = "tested path disproved under current state"
#: cToken base units (8 decimals => 10,000 cTokens). Empty-market attacks need ~wei-level supply.
MIN_SUPPLY = 10 ** 12

_TOTAL_SUPPLY = "0x18160ddd"


def _detector_of(f: Any) -> str:
    d = str(getattr(f, "description", "") or (f.get("description") if isinstance(f, dict) else "") or "")
    return d.split("Source detector: ")[-1].strip().rstrip(".") if "Source detector: " in d else ""


def check(finding: Any, address: str, client: Any) -> Optional[Dict[str, Any]]:
    """Return disproof evidence for *finding* at *address*, or None (not
    disproved / not applicable / RPC unavailable — unknown stays unknown)."""
    if _detector_of(finding) != "compound-empty-market" or client is None:
        return None
    try:
        raw = client.call(address, _TOTAL_SUPPLY)
        supply = int(raw, 16) if raw and raw != "0x" else None
        block = client.block_number() if callable(getattr(client, "block_number", None)) else None
    except Exception:  # noqa: BLE001 - unknown, not disproved
        return None
    if supply is None or supply < MIN_SUPPLY:
        return None
    return {"rule": RULE, "reason": REASON,
            "detail": (f"totalSupply={supply} (>= {MIN_SUPPLY}) at block {block}: market is not empty, so the "
                       "empty-market donation/rounding path is not available now. Read-only eth_call; not "
                       "fork-tested; re-check if supply falls."),
            "observed": {"totalSupply": supply, "block": block}}


def apply_to_row(conn: sqlite3.Connection, finding_row_id: int, ev: Dict[str, Any]) -> None:
    """Suppress one stored monitor finding with the disproof reason and re-roll
    the scan's exposure from the findings that remain unsuppressed."""
    r = conn.execute("SELECT scan_row FROM monitor_findings WHERE id=?", (finding_row_id,)).fetchone()
    if not r:
        return
    conn.execute("UPDATE monitor_findings SET suppressed=1, triage_rule=?, triage_reason=?, triage_detail=? "
                 "WHERE id=?", (ev["rule"], ev["reason"], ev["detail"], finding_row_id))
    reroll_scan(conn, int(r[0]))
    reroll_candidate(conn, int(r[0]))
    conn.commit()


def reroll_scan(conn: sqlite3.Connection, scan_row: int) -> None:
    """Scan exposure = worst UNSUPPRESSED finding estimate (same rule as
    value_at_risk.summarize); None when no unsuppressed estimate is known."""
    best = conn.execute("SELECT est_loss_usd, est_loss_low_usd, est_loss_high_usd FROM monitor_findings "
                        "WHERE scan_row=? AND suppressed=0 AND est_loss_usd IS NOT NULL "
                        "AND UPPER(COALESCE(severity,'')) != 'INFORMATIONAL' "
                        "ORDER BY est_loss_usd DESC LIMIT 1", (scan_row,)).fetchone()
    sup = conn.execute("SELECT COUNT(*) FROM monitor_findings WHERE scan_row=? AND suppressed=1",
                       (scan_row,)).fetchone()[0]
    row = conn.execute("SELECT est_max_loss_usd, risk_score, value_json FROM monitor_scans WHERE id=?",
                       (scan_row,)).fetchone()
    if not row:
        return
    old, risk, vj = row
    new = best[0] if best else None
    try:
        v = json.loads(vj) if vj else {}
    except ValueError:
        v = {}
    s = dict(v.get("summary") or {})
    s.update(est_max_loss_usd=new, est_max_loss_low_usd=best[1] if best else None,
             est_max_loss_high_usd=best[2] if best else None)
    if risk is not None and old:
        s["risk_score"] = None if new is None else round(float(risk) * float(new) / float(old), 4)
    v["summary"] = s
    conn.execute("UPDATE monitor_scans SET est_max_loss_usd=?, risk_score=?, value_json=?, suppressed_count=? "
                 "WHERE id=?", (new, s.get("risk_score", risk), json.dumps(v, sort_keys=True, default=str),
                                sup, scan_row))


def reroll_candidate(conn: sqlite3.Connection, scan_row: int) -> None:
    """Mirror the re-rolled scan exposure onto hunt_candidates rows that point at it."""
    try:
        new = conn.execute("SELECT est_max_loss_usd FROM monitor_scans WHERE id=?", (scan_row,)).fetchone()
        if new is None:
            return
        conn.execute("UPDATE hunt_candidates SET est_max_loss_usd=? WHERE last_scan_row=?", (new[0], scan_row))
    except sqlite3.OperationalError:
        pass  # DB without hunt tables (tests / older schema)


def apply_triage(conn: sqlite3.Connection, finding_row_id: int, *, rule: str, reason: str,
                 detail: str, suppress: bool, severity: Optional[str] = None) -> None:
    """Record a source-verified triage on a stored row; suppress (false positive) or
    downgrade (unresolved suspicion), then re-roll scan + candidate exposure."""
    r = conn.execute("SELECT scan_row FROM monitor_findings WHERE id=?", (finding_row_id,)).fetchone()
    if not r:
        return
    conn.execute("UPDATE monitor_findings SET suppressed=?, triage_rule=?, triage_reason=?, triage_detail=?, "
                 "severity=COALESCE(?, severity) WHERE id=?",
                 (1 if suppress else 0, rule, reason, detail, severity, finding_row_id))
    reroll_scan(conn, int(r[0]))
    reroll_candidate(conn, int(r[0]))
    conn.commit()
