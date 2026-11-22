"""Phase 18 — read-only views over monitor state for the live dashboard.

Every function opens ``monitor_state.db`` read-only (``mode=ro``) and never
creates it. Times are stored as UTC epoch seconds; "today" is the local day
in America/Detroit (override with ``AUDITOR_MONITOR_TZ``).
"""

from __future__ import annotations

import json
import os
import sqlite3
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional
from zoneinfo import ZoneInfo

from auditor.monitor import NETWORKS, default_alerts_path, default_cache_dir, default_monitor_db_path

DEFAULT_TZ = "America/Detroit"
ETA_WINDOW = 20
EXPLORERS = {"ethereum": "https://etherscan.io/address/"}
MAX_SOURCE_BYTES = 2_000_000


def local_tz() -> ZoneInfo:
    return ZoneInfo(os.environ.get("AUDITOR_MONITOR_TZ", "").strip() or DEFAULT_TZ)


def day_bounds(now: float, tz: Optional[ZoneInfo] = None) -> tuple[float, float]:
    """[start, end) of the local calendar day containing *now*, as epoch seconds."""
    tz = tz or local_tz()
    local = datetime.fromtimestamp(now, tz)
    start = local.replace(hour=0, minute=0, second=0, microsecond=0)
    end = start + timedelta(days=1)  # same-tz aware arithmetic is wall-clock: DST-safe
    return start.timestamp(), end.timestamp()


def estimate_eta(history: List[tuple[float, int]], line_count: Optional[int],
                 elapsed: float) -> Dict[str, Any]:
    """ESTIMATE of remaining scan time.

    Rolling mean of seconds-per-source-line over the last ``ETA_WINDOW``
    completed scans, scaled by the current contract's line count. Returns
    ``estimated_remaining_s=None`` when there is no history to base it on.
    """
    pts = [(float(d), max(int(l or 0), 1)) for d, l in history if d is not None and d >= 0][-ETA_WINDOW:]
    out: Dict[str, Any] = {"is_estimate": True, "basis_scans": len(pts),
                           "method": f"rolling mean of s/line over last {ETA_WINDOW} scans x lines",
                           "estimated_total_s": None, "estimated_remaining_s": None, "overrun": False}
    if not pts:
        return out
    rate = sum(d / l for d, l in pts) / len(pts)
    lines = max(int(line_count or 0), 1) if line_count else sum(l for _, l in pts) / len(pts)
    total = rate * lines
    out["estimated_total_s"] = round(total, 1)
    out["estimated_remaining_s"] = round(max(total - elapsed, 0.0), 1)
    out["overrun"] = elapsed > total
    return out


def _connect(db: Path) -> Optional[sqlite3.Connection]:
    if not db.exists():
        return None
    # The monitor/hunt writer can hold a write transaction (WAL) for a while.
    # A read-only connection with the DEFAULT zero busy timeout used to fail
    # instantly with "database is locked" (see logs/dashboard_disk.log); a
    # bounded busy-wait keeps dashboard reads honest under writer load
    # without ever writing.
    conn = sqlite3.connect(f"file:{db}?mode=ro", uri=True, timeout=10)
    conn.row_factory = sqlite3.Row
    return conn


def _has_table(conn: sqlite3.Connection, name: str) -> bool:
    return conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)).fetchone() is not None


def _row(r: sqlite3.Row, network: str) -> Dict[str, Any]:
    d = dict(r)
    d.pop("cache_dir", None)  # local path stays server-side
    d.pop("value_json", None)  # detail view only (Phase 19)
    try:
        d["severity_counts"] = json.loads(d.get("severity_counts") or "{}")
    except ValueError:
        d["severity_counts"] = {}
    d["potential_impact_estimate_usd"] = d.get("est_max_loss_usd")
    d["impact_estimate_kind"] = "heuristic_model" if d.get("est_max_loss_usd") is not None else None
    d["explorer_url"] = EXPLORERS.get(network, "") + d["address"] if network in EXPLORERS else None
    return d


def _alerts(path: Path, recent: int) -> tuple[int, List[Dict[str, Any]]]:
    if not path.exists():
        return 0, []
    lines = [l for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]
    out = []
    for l in lines[-recent:][::-1]:
        try:
            out.append(json.loads(l))
        except ValueError:
            continue
    return len(lines), out


def _annotate_alerts(conn: sqlite3.Connection, alerts: List[Dict[str, Any]]) -> None:
    """Attach the CURRENT triage of each alerted finding (alerts.jsonl is an
    append-only log): a later dismissal or live-state disproof is shown with
    its reason, and the alert no longer reads as active exposure."""
    for a in alerts:
        try:
            r = conn.execute(
                "SELECT f.suppressed, f.triage_rule, f.triage_reason, f.triage_detail FROM monitor_findings f "
                "JOIN monitor_scans s ON s.id=f.scan_row WHERE f.address=? AND f.title=? AND "
                "(s.scan_id=? OR ? IS NULL) ORDER BY f.id DESC LIMIT 1",
                (str(a.get("address") or "").lower(), a.get("title"), a.get("scan_id"), a.get("scan_id"))).fetchone()
        except sqlite3.Error:
            return
        if r and r[0]:
            a["triage"] = {"verdict": "disproved" if r[1] == "live-state-disproof" else "False positive",
                           "rule": r[1], "reason": r[2], "detail": r[3]}
            a["active_exposure"] = False


SORTS = {
    "recent": "finished_at DESC, id DESC",
    # Phase 19: rough-estimate value ordering (unknown value sorts last)
    "loss": "COALESCE(est_max_loss_usd, -1) DESC, COALESCE(risk_score, 0) DESC, finished_at DESC, id DESC",
    "risk": "COALESCE(risk_score, 0) DESC, COALESCE(est_max_loss_usd, -1) DESC, finished_at DESC, id DESC",
    "tvl": "COALESCE(tvl_usd, -1) DESC, finished_at DESC, id DESC",
}


def live(network: str = "ethereum", now: Optional[float] = None, db_path: Optional[Path] = None,
         alerts_path: Optional[Path] = None, recent: int = 25, sort: str = "recent") -> Dict[str, Any]:
    now = time.time() if now is None else now
    tz = local_tz()
    start, end = day_bounds(now, tz)
    total_alerts, alerts = _alerts(Path(alerts_path or default_alerts_path()), recent)
    data: Dict[str, Any] = {
        "network": network, "generated_at": now, "timezone": str(tz),
        "today": {"start": start, "end": end, "date": datetime.fromtimestamp(now, tz).date().isoformat()},
        "counters": {"audited_today": 0, "audited_all_time": 0, "findings_today": {},
                     "findings_today_total": 0, "findings_all_time": 0, "queue_pending": 0,
                     "unverified": 0, "last_block": None, "polls_last_hour": 0, "avg_scan_s": None,
                     # Phase 18.1: a scan whose required analyzer did not complete is
                     # NEVER "audited"; legacy rows have an unverified completion.
                     "could_not_analyze_today": 0, "could_not_analyze_all_time": 0,
                     "legacy_needs_rescan": 0,
                     # Phase 19: ROUGH ESTIMATES (value at risk found)
                     "value_at_risk_found_today_usd": 0.0, "value_at_risk_found_all_time_usd": 0.0,
                     "confirmed_outsider_today_usd": 0.0, "confirmed_outsider_all_time_usd": 0.0,
                     "unverified_exposure_today_usd": 0.0, "unverified_exposure_all_time_usd": 0.0,
                     "unresolved_suspicion_today_usd": 0.0, "unresolved_suspicion_all_time_usd": 0.0,
                     "disproved_excluded_today_usd": 0.0, "disproved_excluded_all_time_usd": 0.0,
                     "holdings_today_usd": 0.0, "holdings_all_time_usd": 0.0,
                     "holdings_unknown": True,
                     "tvl_with_findings_today_usd": 0.0, "suppressed_today": 0, "suppressed_all_time": 0,
                     "price_as_of": None, "value_is_estimate": True},
        "sort": sort if sort in SORTS else "recent", "top_risk": [],
        "current": [], "recent_scans": [], "alerts_total": total_alerts, "recent_alerts": alerts,
        "monitor_db": "present" if Path(db_path or default_monitor_db_path()).exists() else "absent",
    }
    conn = _connect(Path(db_path or default_monitor_db_path()))
    if conn is None:
        return data
    try:
        c = data["counters"]
        r = conn.execute("SELECT last_block FROM monitor_cursor WHERE network=?", (network,)).fetchone()
        c["last_block"] = int(r[0]) if r else None
        q = {k: int(v) for k, v in conn.execute(
            "SELECT status, COUNT(*) FROM monitor_queue WHERE network=? GROUP BY status", (network,))}
        c["queue_pending"], c["unverified"] = q.get("pending", 0), q.get("unverified", 0)
        if not _has_table(conn, "monitor_scans"):
            c["audited_all_time"] = int(conn.execute(
                "SELECT COUNT(*) FROM monitor_seen WHERE network=?", (network,)).fetchone()[0])
            return data
        from auditor.monitor import scan_outcome_counts

        _annotate_alerts(conn, alerts)
        has_v3 = "analysis_complete" in {x[1] for x in conn.execute("PRAGMA table_info(monitor_scans)")}
        oc_all = scan_outcome_counts(conn, network)
        oc_today = scan_outcome_counts(conn, network, start, end)
        c["audited_all_time"], c["audited_today"] = oc_all["audited"], 0
        c["could_not_analyze_all_time"] = oc_all["could_not_analyze"]
        c["could_not_analyze_today"] = oc_today["could_not_analyze"]
        c["legacy_needs_rescan"] = oc_all["legacy_needs_rescan"]
        counted = ("(status='done' AND analysis_complete=1) OR "
                   "(status IN ('incomplete','failed') AND superseded_at IS NULL)") if has_v3 else "0"
        done = conn.execute(
            "SELECT finished_at, findings, severity_counts, status FROM monitor_scans "
            f"WHERE network=? AND ({counted})", (network,)).fetchall()
        sev_today: Dict[str, int] = {}
        for fin, nf, sc, st in done:
            c["findings_all_time"] += int(nf or 0)
            if fin is not None and start <= float(fin) < end:
                c["audited_today"] += int(st == "done")
                c["findings_today_total"] += int(nf or 0)
                for k, v in json.loads(sc or "{}").items():
                    sev_today[k] = sev_today.get(k, 0) + int(v)
        c["findings_today"] = sev_today
        if _has_table(conn, "monitor_polls"):
            c["polls_last_hour"] = int(conn.execute(
                "SELECT COUNT(*) FROM monitor_polls WHERE network=? AND at>=?", (network, now - 3600)).fetchone()[0])
        hist = [(float(d), int(l or 0)) for d, l in conn.execute(
            "SELECT duration_s, line_count FROM monitor_scans WHERE network=? AND status='done' "
            + ("AND analysis_complete=1 " if has_v3 else "AND 0 ") +
            "AND duration_s IS NOT NULL ORDER BY finished_at DESC LIMIT ?", (network, ETA_WINDOW))][::-1]
        c["avg_scan_s"] = round(sum(d for d, _ in hist) / len(hist), 1) if hist else None
        for r in conn.execute("SELECT * FROM monitor_scans WHERE network=? AND status='running' "
                              "ORDER BY started_at", (network,)):
            d = _row(r, network)
            d["elapsed_s"] = round(max(now - float(r["started_at"]), 0.0), 1)
            d["stage_elapsed_s"] = round(max(now - float(r["stage_at"] or r["started_at"]), 0.0), 1)
            d["eta"] = estimate_eta(hist, r["line_count"], d["elapsed_s"])
            data["current"].append(d)
        has_v4 = "risk_score" in {x[1] for x in conn.execute("PRAGMA table_info(monitor_scans)")}
        order = SORTS.get(sort, SORTS["recent"]) if has_v4 else SORTS["recent"]
        data["recent_scans"] = [_row(r, network) for r in conn.execute(
            "SELECT * FROM monitor_scans WHERE network=? AND status!='running' "
            f"ORDER BY {order} LIMIT ?", (network, int(recent)))]
        if has_v4:
            from auditor.monitor import value_overview

            vt = value_overview(conn, network, start, end, top=5)
            va = value_overview(conn, network, top=5)
            c["value_at_risk_found_today_usd"] = vt["value_at_risk_found_usd"]
            c["value_at_risk_found_all_time_usd"] = va["value_at_risk_found_usd"]
            c["confirmed_outsider_today_usd"] = vt.get("confirmed_outsider_usd", vt["value_at_risk_found_usd"])
            c["confirmed_outsider_all_time_usd"] = va.get("confirmed_outsider_usd", va["value_at_risk_found_usd"])
            c["unverified_exposure_today_usd"] = vt.get("unverified_exposure_usd", 0.0)
            c["unverified_exposure_all_time_usd"] = va.get("unverified_exposure_usd", 0.0)
            c["unresolved_suspicion_today_usd"] = vt.get("unresolved_suspicion_usd", 0.0)
            c["unresolved_suspicion_all_time_usd"] = va.get("unresolved_suspicion_usd", 0.0)
            c["disproved_excluded_today_usd"] = vt.get("disproved_excluded_usd", 0.0)
            c["disproved_excluded_all_time_usd"] = va.get("disproved_excluded_usd", 0.0)
            c["holdings_today_usd"] = vt.get("holdings_usd", 0.0)
            c["holdings_all_time_usd"] = va.get("holdings_usd", 0.0)
            c["holdings_unknown"] = bool(va.get("holdings_unknown"))
            c["tvl_with_findings_today_usd"] = vt["tvl_with_findings_usd"]
            c["suppressed_today"] = vt["suppressed_findings"]
            c["suppressed_all_time"] = va["suppressed_findings"]
            c["price_as_of"] = va["price_as_of"]
            data["top_risk"] = va["top"]
    finally:
        conn.close()
    return data


def _scan_row(row_id: int, db_path: Optional[Path]) -> Optional[sqlite3.Row]:
    conn = _connect(Path(db_path or default_monitor_db_path()))
    if conn is None:
        return None
    try:
        if not _has_table(conn, "monitor_scans"):
            return None
        return conn.execute("SELECT * FROM monitor_scans WHERE id=?", (int(row_id),)).fetchone()
    finally:
        conn.close()


def stage_events(row_id: int, db_path: Optional[Path] = None) -> List[Dict[str, Any]]:
    conn = _connect(Path(db_path or default_monitor_db_path()))
    if conn is None:
        return []
    try:
        return [dict(r) for r in conn.execute(
            "SELECT stage, at FROM monitor_stage_events WHERE scan_row=? ORDER BY at, rowid", (int(row_id),))]
    finally:
        conn.close()


def scan_detail(row_id: int, db_path: Optional[Path] = None,
                history_findings: Optional[List[Dict[str, Any]]] = None) -> Optional[Dict[str, Any]]:
    """Scan row + stage timeline + findings enriched with the risk playbook."""
    from auditor.risk_playbook import risk_for

    r = _scan_row(row_id, db_path)
    if r is None:
        return None
    d = _row(r, r["network"])
    d["stages"] = stage_events(row_id, db_path)
    d["source_files"] = [str(p) for p in _list_cached(r)]
    d["value"] = None
    if "value_json" in r.keys() and r["value_json"]:
        try:
            d["value"] = json.loads(r["value_json"])
        except ValueError:
            d["value"] = None
    stored = _stored_findings(row_id, db_path) if history_findings is None else []
    if stored:
        d["findings_detail"] = [_detail_from_stored(x, risk_for) for x in stored]
        d["suppressed_detail_count"] = sum(1 for x in d["findings_detail"] if x["suppressed"])
        return d
    if history_findings is None:
        history_findings = []
        if r["scan_id"]:
            from auditor.scan_history import ScanHistory, default_history_db_path

            h = ScanHistory(default_history_db_path())
            try:
                history_findings = h.get_findings(r["scan_id"])
            finally:
                h.close()
    findings = []
    for f in history_findings:
        lines = f.get("affected_lines") or []
        findings.append({
            "title": f.get("title"), "severity": f.get("severity"), "confidence": f.get("confidence"),
            "status": f.get("verification_status") or f.get("status"),
            "location": {"file": f.get("affected_file"), "contract": f.get("affected_contract"),
                         "function": f.get("affected_function"), "lines": lines},
            "description": f.get("description"),
            "evidence": [{"source": e.get("source"), "artifact_type": e.get("artifact_type"),
                          "epistemic": e.get("epistemic"), "excerpt": e.get("excerpt")}
                         for e in (f.get("evidence") or []) if isinstance(e, dict)],
            "risk": risk_for(f),
            "suppressed": False, "triage": None, "estimate": None,
        })
    d["findings_detail"] = findings
    d["suppressed_detail_count"] = 0
    return d


def _stored_findings(row_id: int, db_path: Optional[Path]) -> List[Dict[str, Any]]:
    """Phase 19 per-finding rows (kept + suppressed) when the scan has them."""
    conn = _connect(Path(db_path or default_monitor_db_path()))
    if conn is None:
        return []
    try:
        if not _has_table(conn, "monitor_findings"):
            return []
        return [dict(x) for x in conn.execute(
            "SELECT * FROM monitor_findings WHERE scan_row=? ORDER BY suppressed, "
            "COALESCE(weighted_score,0) DESC, id", (int(row_id),))]
    finally:
        conn.close()


def _detail_from_stored(x: Dict[str, Any], risk_for: Any) -> Dict[str, Any]:
    try:
        f = json.loads(x.get("finding_json") or "{}")
    except ValueError:
        f = {}
    try:
        est = json.loads(x["estimate_json"]) if x.get("estimate_json") else None
    except ValueError:
        est = None
    lines = f.get("affected_lines") or []
    return {
        "id": x.get("id"),
        "title": x.get("title"), "severity": x.get("severity"), "confidence": x.get("confidence"),
        "status": "UNVERIFIED",
        "location": {"file": x.get("file"), "contract": x.get("contract"), "function": x.get("function"),
                     "lines": lines},
        "description": f.get("description"),
        "evidence": [e for e in (f.get("evidence") or []) if isinstance(e, dict)],
        "risk": risk_for({"title": x.get("title"), "description": f.get("description")}),
        "suppressed": bool(x.get("suppressed")),
        # Explicit label: every dismissed (suppressed) finding is a false positive.
        "verdict_label": ("Tested path disproved under current state" if x.get("triage_rule") == "live-state-disproof"
                          else "False positive") if x.get("suppressed") else None,
        "dismissal_reason": (" — ".join(str(v) for v in (x.get("triage_reason"), x.get("triage_detail")) if v)
                             or "suppressed by triage rule (no reason recorded)") if x.get("suppressed") else None,
        "triage": {"reason": x.get("triage_reason"), "rule": x.get("triage_rule"),
                   "detail": x.get("triage_detail"), "original_severity": x.get("original_severity")}
        if x.get("triage_reason") else None,
        "estimate": est,
        "potential_impact_estimate_usd": est.get("est_loss_usd") if est else None,
        "impact_estimate_kind": "heuristic_model" if est else None,
        "impact_class": x.get("impact_class") or "unknown",
        "impact_status": x.get("impact_status") or ("suppressed" if x.get("suppressed") else "unresolved"),
    }


def _cache_root() -> Path:
    return default_cache_dir().resolve()


def _list_cached(r: sqlite3.Row) -> List[Path]:
    cd = r["cache_dir"]
    if not cd:
        return []
    root = Path(cd).resolve()
    if not root.is_dir() or (_cache_root() not in root.parents and root != _cache_root()):
        return []
    return sorted(p.relative_to(root) for p in root.rglob("*") if p.is_file())


def source_view(row_id: int, file: Optional[str] = None,
                db_path: Optional[Path] = None) -> Optional[Dict[str, Any]]:
    """Raw cached source text (caller must escape when rendering). None = not found."""
    r = _scan_row(row_id, db_path)
    if r is None:
        return None
    files = _list_cached(r)
    names = [str(p) for p in files]
    if not names:
        return {"row": int(row_id), "address": r["address"], "contract_name": r["contract_name"],
                "files": [], "file": None, "content": None, "note": "source not cached for this scan"}
    chosen = file if file in names else names[0]
    if file and file not in names:
        return None  # only listed cache files may be read (no path traversal)
    p = Path(r["cache_dir"]).resolve() / chosen
    raw = p.read_bytes()[:MAX_SOURCE_BYTES]
    return {"row": int(row_id), "address": r["address"], "contract_name": r["contract_name"],
            "files": names, "file": chosen, "content": raw.decode("utf-8", errors="replace"),
            "truncated": p.stat().st_size > MAX_SOURCE_BYTES}


def supported(network: str) -> bool:
    return network in NETWORKS
