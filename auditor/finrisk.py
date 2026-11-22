"""Second-stage financial-risk review engine for recorded findings.

Stage 2 sits BEHIND the existing pipeline: it never creates, edits or
deduplicates findings. It takes findings exactly as the scanner recorded them
(``scan_id`` + ``fingerprint`` from the history store) and answers one
question, with stored evidence only:

    Does THIS finding represent a plausible, technically validated and
    financially meaningful risk to user funds or contract funds?

Design contracts (deliberate, matching existing conventions):

* **Isolated DB** (``reports/finrisk.db`` default; ``AUDITOR_FINRISK_DB``
  override). The history store already has many writers and the monitor
  store is the live monitor/hunt writer, so this stage keeps its OWN
  additively-migrated, WAL-journal database instead of writing to either.
  No existing database is reset, truncated or migrated destructively.
* **Idempotent queue**: identity is the existing finding identifier
  ``(scan_id, fingerprint)``. Re-enqueue uses ``INSERT OR IGNORE`` so a
  finding rediscovered by a later scan cannot create a duplicate review.
* **No-invention verdicts**: a verdict is only as strong as its stored
  evidence. ``confirmed_exploitable`` from the monitor pipeline (a
  dynamically reproduced, threshold outsider TP) is the ONLY thing that
  reaches ``validated_financial_risk``; this module adds no new
  confirmation path of its own.
* **Honest failures**: a timeout, unavailable source, RPC failure or an
  unknown answer NEVER becomes ``disproved``. Transient infrastructure
  failures land in ``retryable_error`` / ``inconclusive`` with the raw
  reason recorded and a bounded retry with backoff (mirroring
  ``auditor.review_panel``'s BACKOFF semantics).
* **Reuse, no duplicate subsystems**: exposure models come from
  ``auditor.value_at_risk`` / ``auditor.risk_playbook``, impact classes
  from ``auditor.monitor.classify_impact``, runtime disproof from
  ``auditor.live_disproof``, bytecode comparison from
  ``auditor.bytecode_verify``, and the AI review panel's majority labels
  are read-only supporting inputs (never a verdict by themselves).
* **Failures are side-effect free for the pipeline**: the enqueue hook in
  ``auditor.scan_history`` wraps everything; a review failure can never
  stop the monitor, hunt, dashboard scan, CLI scan, retest or AI audit.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence, Tuple

TOOL_VERSION = "finrisk-v1"

#: Queue states. ``inconclusive`` is a VERDICT (reported by a completed
#: review), not a queue state: the queue tracks whether the review itself
#: ran; the verdict records what it decided.
STATE_PENDING = "pending"
STATE_RUNNING = "running"
STATE_COMPLETED = "completed"
STATE_RETRYABLE = "retryable_error"
STATES = (STATE_PENDING, STATE_RUNNING, STATE_COMPLETED, STATE_RETRYABLE)

#: Machine-readable review verdicts (exact strings, never reworded).
VERDICT_VALIDATED = "validated_financial_risk"
VERDICT_POTENTIAL = "potential_financial_risk"
VERDICT_DISPROVED = "disproved"
VERDICT_INCONCLUSIVE = "inconclusive"
VERDICT_NOT_FINANCIAL = "not_financially_exploitable"
VERDICTS = (VERDICT_VALIDATED, VERDICT_POTENTIAL, VERDICT_DISPROVED,
            VERDICT_INCONCLUSIVE, VERDICT_NOT_FINANCIAL)

#: Severity -> queue priority class (higher runs first).
SEVERITY_PRIORITY = {"CRITICAL": 40, "HIGH": 30, "MEDIUM": 20, "LOW": 10,
                     "INFORMATIONAL": 0}

#: Bounded retries for transient infrastructure failure, with the same
#: backoff shape as auditor.review_panel.
MAX_ATTEMPTS = 3
BACKOFF_S = (60.0, 300.0, 1800.0)

_MAX_TITLE = 200

_ETH_ADDR_RE = re.compile(r"0x[0-9a-fA-F]{40}")
_SOURCE_REF_RE = re.compile(r"^etherscan://(?:([a-z0-9-]+)/)?(0x[0-9a-fA-F]{40})$")
#: Cache-path shape: .../0x<hex40>/<hash>  (same convention as routes.py)
_CACHE_ADDR_RE = re.compile(r"/(0x[0-9a-fA-F]{40})(?:/|$)")

#: triage rules (stored in monitor_findings) that carry POSITIVE disproof
#: evidence: a tested path recorded as NOT holding under current state.
_DISPROOF_RULES = ("live-state-disproof",)

#: triage reasons meaning the finding was suppressed as not-a-bug in the
#: recorded context; the existing pipeline already excludes these from
#: exposure totals.
_FP_SUPPRESSION_REASONS = ("library-code", "known-benign")

#: triage reasons that gate a privileged path (existing exposure models).
_PRIVILEGED_REASONS = ("privileged-withdraw", "privileged-module-caller")

#: env var giving a read-only RPC for optional runtime disproof checks.
RPC_ENV = "AUDITOR_MONITOR_RPC_URL"

_NETWORK_VERIFY_ENV = "AUDITOR_FINRISK_NETWORK_VERIFY"


def default_finrisk_db() -> Path:
    if os.environ.get("AUDITOR_FINRISK_DB"):
        return Path(os.environ["AUDITOR_FINRISK_DB"])
    reports = Path(__file__).resolve().parent.parent / "reports"
    return reports / "finrisk.db"


def _utcnow_iso() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).isoformat()


def _now() -> float:
    return time.time()


# ---------------------------------------------------------------------------
# schema (additive only; the DB is created empty when absent)
# ---------------------------------------------------------------------------

SCHEMA = """
CREATE TABLE IF NOT EXISTS finrisk_reviews (
  scan_id TEXT NOT NULL,
  fingerprint TEXT NOT NULL,
  content_key TEXT,
  scan_timestamp TEXT,
  source_path TEXT,
  network TEXT,
  address TEXT,
  title TEXT,
  severity TEXT,
  category TEXT,
  state TEXT NOT NULL,
  attempts INTEGER NOT NULL DEFAULT 0,
  priority INTEGER NOT NULL DEFAULT 0,
  next_attempt_at REAL NOT NULL DEFAULT 0,
  last_error TEXT,
  error_count INTEGER NOT NULL DEFAULT 0,
  heartbeat_at REAL,
  heartbeat_stage TEXT,
  enqueued_at REAL NOT NULL,
  started_at REAL,
  finished_at REAL,
  verdict TEXT,
  verdict_version TEXT,
  review_json TEXT,
  updated_at TEXT,
  PRIMARY KEY (scan_id, fingerprint)
);
CREATE INDEX IF NOT EXISTS ix_finrisk_state ON finrisk_reviews(state, next_attempt_at);
CREATE INDEX IF NOT EXISTS ix_finrisk_verdict ON finrisk_reviews(verdict);
CREATE INDEX IF NOT EXISTS ix_finrisk_content ON finrisk_reviews(content_key);

CREATE TABLE IF NOT EXISTS finrisk_review_history (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  scan_id TEXT NOT NULL,
  fingerprint TEXT NOT NULL,
  from_state TEXT,
  to_state TEXT NOT NULL,
  verdict TEXT,
  note TEXT,
  at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_finrisk_hist_row ON finrisk_review_history(scan_id, fingerprint);
"""


def open_finrisk_db(db_path: Optional[Path] = None) -> sqlite3.Connection:
    """Open (creating if needed) the review store. WAL + bounded busy-wait so
    dashboard readers never observe the instant-fail "database is locked"
    behaviour seen against monitor_state.db (mode=ro, zero timeout)."""
    p = Path(db_path) if db_path else default_finrisk_db()
    p.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(str(p), timeout=15)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("PRAGMA synchronous=NORMAL")
    con.executescript(SCHEMA)
    con.commit()
    return con


def open_finrisk_db_ro(db_path: Optional[Path] = None) -> Optional[sqlite3.Connection]:
    """Read-only connection for the dashboard; missing DB -> None."""
    p = Path(db_path) if db_path else default_finrisk_db()
    if not p.exists():
        return None
    con = sqlite3.connect(f"file:{p}?mode=ro", uri=True, timeout=10)
    con.row_factory = sqlite3.Row
    return con


# ---------------------------------------------------------------------------
# identity helpers (existing finding identifiers, stable content key)
# ---------------------------------------------------------------------------

def _detector_of(finding: Mapping[str, Any]) -> str:
    """Established convention: explicit 'Source detector: X' suffix in
    ``description``, else the recorded tool field."""
    desc = str((finding or {}).get("description") or "")
    if "Source detector: " in desc:
        return desc.split("Source detector: ")[-1].strip().rstrip(".")
    tool = str((finding or {}).get("tool") or "")
    return tool if tool.lower().startswith("local-") else tool


def content_key(finding: Mapping[str, Any]) -> str:
    """Stable identity of the code shape a finding describes.

    Used ONLY as a cross-scan review-reuse hint (a later screen of the same
    code shape inherits the earlier verdict with explicit provenance) —
    never as a database key: ``(scan_id, fingerprint)`` stays the queue key.
    """
    lines = ",".join(str(x) for x in (finding.get("affected_lines") or [])
                     if isinstance(x, (int, str)))
    parts = [_detector_of(finding), str(finding.get("category") or ""),
             str(finding.get("affected_contract") or ""),
             str(finding.get("affected_function") or ""), lines]
    raw = "|".join(parts)[:512]
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def resolve_chain_context(source_path: Any) -> Dict[str, Optional[str]]:
    """(network, address) from a stored source ref or cache path."""
    src = str(source_path or "")
    out: Dict[str, Optional[str]] = {"network": None, "address": None}
    m = _SOURCE_REF_RE.match(src)
    if m:
        out["network"] = m.group(1) or "ethereum"
        out["address"] = m.group(2).lower()
        return out
    m = _CACHE_ADDR_RE.search(src)
    if m:
        out["network"] = "ethereum"
        out["address"] = m.group(1).lower()
    return out


# ---------------------------------------------------------------------------
# queue operations (idempotent; auditor.review_panel conventions)
# ---------------------------------------------------------------------------

def enqueue_findings(con: sqlite3.Connection, *, scan_id: str, scan_timestamp: Any,
                     source_path: Any, findings: Sequence[Mapping[str, Any]]) -> int:
    """Queue every eligible finding once. INSERT OR IGNORE => re-running this
    for the same scan (or a re-scan producing identical fingerprints) adds
    nothing. Returns the number of NEW rows only."""
    n = 0
    stamp = str(scan_timestamp or "")
    src = str(source_path or "")
    chain = resolve_chain_context(src)
    for f in findings or []:
        if not isinstance(f, Mapping):
            continue
        fp = str(f.get("fingerprint") or "")
        if not fp:
            # A finding without its own fingerprint cannot be addressed
            # safely — skip rather than guess (the Findings tab assigns
            # uuid4 placeholders on READ; those are not stable identities).
            continue
        sev = str(f.get("severity") or "").upper()
        cur = con.execute(
            "INSERT OR IGNORE INTO finrisk_reviews"
            "(scan_id,fingerprint,content_key,scan_timestamp,source_path,network,address,"
            "title,severity,category,state,attempts,priority,next_attempt_at,"
            "enqueued_at,updated_at)"
            " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (scan_id, fp, content_key(f), stamp, src, chain["network"], chain["address"],
             str(f.get("title") or "")[:_MAX_TITLE], sev, str(f.get("category") or ""),
             STATE_PENDING, 0, SEVERITY_PRIORITY.get(sev, 0), 0, _now(), _utcnow_iso()))
        n += max(int(cur.rowcount or 0), 0)
    con.commit()
    return n


def enqueue_history_row(con: sqlite3.Connection, *, scan_id: str, row: Mapping[str, Any]) -> int:
    """Enqueue findings parsed from a history ``scan_records`` row dict."""
    details = row.get("finding_details")
    if isinstance(details, str):
        try:
            details = json.loads(details or "[]")
        except ValueError:
            details = []
    if isinstance(details, dict):
        details = list(details.values())
    if not isinstance(details, list):
        details = []
    return enqueue_findings(con, scan_id=str(row.get("scan_id") or ""),
                            scan_timestamp=row.get("timestamp"),
                            source_path=row.get("source_path"),
                            findings=[f for f in details if isinstance(f, Mapping)])


def set_state(con: sqlite3.Connection, scan_id: str, fingerprint: str, state: str, *,
              note: str = "", verdict: Optional[str] = None,
              extra_sql: str = "", extra_args: Sequence[Any] = ()) -> Dict[str, Any]:
    """One state transition + one append-only history row."""
    r = con.execute("SELECT state FROM finrisk_reviews WHERE scan_id=? AND fingerprint=?",
                    (scan_id, fingerprint)).fetchone()
    prev = r["state"] if r else None
    con.execute(
        f"UPDATE finrisk_reviews SET state=?, verdict=COALESCE(?, verdict), updated_at=?"
        f"{extra_sql} WHERE scan_id=? AND fingerprint=?",
        (state, verdict, _utcnow_iso(), *extra_args, scan_id, fingerprint))
    con.execute(
        "INSERT INTO finrisk_review_history"
        "(scan_id,fingerprint,from_state,to_state,verdict,note,at) VALUES(?,?,?,?,?,?,?)",
        (scan_id, fingerprint, prev, state, verdict, note or None, _now()))
    con.commit()
    return {"from_state": prev, "to_state": state, "verdict": verdict, "note": note}


def claim_due(con: sqlite3.Connection, *, limit: int = 1, now: Optional[float] = None) -> List[Dict[str, Any]]:
    """Claim up to ``limit`` due pending/retryable rows (priority first).

    Claimed rows move to ``running`` with a heartbeat. The caller must be
    the single finrisk writer for this DB (``scripts/run_finrisk.py`` holds
    the flock; a dashboard route holds it for the request).
    """
    now = _now() if now is None else now
    rows: List[Dict[str, Any]] = []
    # attempts<MAX_ATTEMPTS keeps a capped row (docstring of fail_retryable)
    # out of the automatic queue; manual runs reset attempts to re-queue it.
    due = con.execute(
        "SELECT scan_id,fingerprint FROM finrisk_reviews WHERE state IN (?,?) AND next_attempt_at<=? "
        "AND attempts<? "
        "ORDER BY priority DESC, enqueued_at LIMIT ?",
        (STATE_PENDING, STATE_RETRYABLE, now, MAX_ATTEMPTS, int(limit))).fetchall()
    for d in due:
        changed = set_state(con, d["scan_id"], d["fingerprint"], STATE_RUNNING,
                            note="claimed for review",
                            extra_sql=", started_at=COALESCE(started_at, ?), heartbeat_at=?, heartbeat_stage=?",
                            extra_args=(_now(), _now(), "claimed"))
        rows.append({"scan_id": d["scan_id"], "fingerprint": d["fingerprint"], **changed})
    return rows


def heartbeat(con: sqlite3.Connection, scan_id: str, fingerprint: str, stage: str) -> None:
    con.execute("UPDATE finrisk_reviews SET heartbeat_at=?, heartbeat_stage=?, updated_at=? "
                "WHERE scan_id=? AND fingerprint=?",
                (_now(), stage, _utcnow_iso(), scan_id, fingerprint))
    con.commit()


def save_review(con: sqlite3.Connection, scan_id: str, fingerprint: str, verdict: str,
                payload: Mapping[str, Any]) -> None:
    con.execute(
        "UPDATE finrisk_reviews SET verdict=?, verdict_version=?, review_json=?, "
        "finished_at=COALESCE(finished_at, ?), heartbeat_at=NULL, heartbeat_stage=NULL, "
        "last_error=NULL, updated_at=? WHERE scan_id=? AND fingerprint=?",
        (verdict, payload.get("tool_version") or TOOL_VERSION,
         json.dumps(payload, default=str), _now(), _utcnow_iso(), scan_id, fingerprint))
    con.commit()


def finish_completed(con: sqlite3.Connection, scan_id: str, fingerprint: str, verdict: str,
                     payload: Mapping[str, Any]) -> Dict[str, Any]:
    set_state(con, scan_id, fingerprint, STATE_COMPLETED,
              note=q(payload.get("verdict_rationale")), verdict=verdict)
    save_review(con, scan_id, fingerprint, verdict, payload)
    return {"scan_id": scan_id, "fingerprint": fingerprint, "verdict": verdict, "status": STATE_COMPLETED}


def fail_retryable(con: sqlite3.Connection, scan_id: str, fingerprint: str, error: str,
                   *, now: Optional[float] = None) -> bool:
    """Record a transient error; schedule a bounded retry (attempts cap).

    Returns True when a retry is scheduled. When the cap is reached the row
    stays in ``retryable_error`` with ``last_error`` so the dashboard shows
    it honestly and a manual run can still clear it (reset_for_manual_run).
    """
    now = _now() if now is None else now
    r = con.execute("SELECT attempts FROM finrisk_reviews WHERE scan_id=? AND fingerprint=?",
                    (scan_id, fingerprint)).fetchone()
    attempts = int((r or {"attempts": 0})["attempts"] or 0) + 1
    retry = attempts < MAX_ATTEMPTS
    # While retrying: next_attempt_at is the backoff deadline. At the cap:
    # the attempts guard in claim_due (attempts<MAX_ATTEMPTS) keeps the row
    # out of the automatic queue; only reset_for_manual_run (attempts=0)
    # re-queues it for a claim.
    nxt = now + BACKOFF_S[min(attempts - 1, len(BACKOFF_S) - 1)] if retry else now
    con.execute(
        "UPDATE finrisk_reviews SET state=?, attempts=?, next_attempt_at=?, last_error=?, "
        "error_count=error_count+1, finished_at=NULL, heartbeat_at=NULL, heartbeat_stage=NULL, "
        "updated_at=? WHERE scan_id=? AND fingerprint=?",
        (STATE_RETRYABLE, attempts, nxt, str(error)[:400], _utcnow_iso(), scan_id, fingerprint))
    con.execute(
        "INSERT INTO finrisk_review_history"
        "(scan_id,fingerprint,from_state,to_state,verdict,note,at) VALUES(?,?,?,?,?,?,?)",
        (scan_id, fingerprint, STATE_RUNNING, STATE_RETRYABLE, None,
         f"error: {str(error)[:200]}", _now()))
    con.commit()
    return retry


def reset_for_manual_run(con: sqlite3.Connection, scan_id: str, fingerprint: str) -> Dict[str, Any]:
    """Manual re-run: clear the attempt cap/backoff and re-queue.

    Never deletes prior evidence: the next review overwrites the payload
    with a new attempt and the history keeps every transition.
    """
    return set_state(con, scan_id, fingerprint, STATE_PENDING,
                     note="manual re-run requested",
                     extra_sql=", attempts=0, next_attempt_at=0, last_error=NULL")


def claim_one(con: sqlite3.Connection, scan_id: str, fingerprint: str,
              *, now: Optional[float] = None) -> Optional[Dict[str, Any]]:
    """Claim a SPECIFIC row (dashboard manual-run path, under the flock).

    Unlike :func:`claim_due` this takes a row, priority is honoured by the
    separate batch runner instead.
    """
    now = _now() if now is None else now
    r = con.execute("SELECT state FROM finrisk_reviews WHERE scan_id=? AND fingerprint=?",
                    (scan_id, fingerprint)).fetchone()
    if r is None:
        return None
    changed = set_state(con, scan_id, fingerprint, STATE_RUNNING,
                        note="claimed for manual review",
                        extra_sql=", started_at=COALESCE(started_at, ?), heartbeat_at=?, heartbeat_stage=?",
                        extra_args=(_now(), _now(), "claimed"))
    return {"scan_id": scan_id, "fingerprint": fingerprint, **changed}


def q(text: Any) -> str:
    return str(text or "")[:300]


# ---------------------------------------------------------------------------
# stored evidence readers (the monitor store stays READ-ONLY from here)
# ---------------------------------------------------------------------------

def monitor_context(db_path: Optional[Path], *, network: str,
                    address: str) -> Dict[str, Any]:
    """Read-only monitor-store slice for one (network, address): priced
    holdings from the latest ``value_json``, per-finding triage rows, and the
    latest recorded fork simulation. Missing DB -> {}."""
    db = Path(db_path) if db_path else None
    if db is None or not db.exists():
        return {}
    try:
        con = sqlite3.connect(f"file:{db}?mode=ro", uri=True, timeout=5)
        con.row_factory = sqlite3.Row
    except sqlite3.Error:
        return {}
    out: Dict[str, Any] = {"network": network, "address": address,
                           "holdings": None, "tvl_usd": None, "price_as_of": None,
                           "value_available": False, "findings": [], "sim": None}
    try:
        r = con.execute(
            "SELECT value_json, tvl_usd, price_as_of FROM monitor_scans WHERE network=? AND "
            "lower(address)=? ORDER BY finished_at DESC, id DESC LIMIT 1",
            (network, address)).fetchone()
        if r is not None:
            try:
                v = json.loads(r["value_json"]) if r["value_json"] else {}
            except ValueError:
                v = {}
            # value_json may nest the priced block under a "value" key
            # (same convention as routes._monitor_context_for_scan)
            if isinstance(v.get("value"), dict):
                v = v["value"]
            out.update({
                "holdings": v.get("holdings") if isinstance(v.get("holdings"), list) else None,
                "tvl_usd": v.get("tvl_usd") if v.get("tvl_usd") is not None else r["tvl_usd"],
                "price_as_of": v.get("price_as_of") if v.get("price_as_of") is not None else r["price_as_of"],
                "value_available": bool(v) or r["tvl_usd"] is not None,
            })
        for fr in con.execute(
                "SELECT id, title, detector, contract, function, severity, suppressed,"
                " confirmed_exploitable, triage_rule, triage_reason, triage_detail,"
                " est_loss_usd, est_loss_low_usd, est_loss_high_usd, estimate_json,"
                " impact_class, impact_status FROM monitor_findings WHERE network=? AND "
                "lower(address)=? ORDER BY id DESC LIMIT 80", (network, address)):
            row = dict(fr)
            if row.get("estimate_json"):
                try:
                    row["estimate"] = json.loads(row["estimate_json"])
                except ValueError:
                    row["estimate"] = {}
            out["findings"].append(row)
        try:
            sr = con.execute(
                "SELECT status, holder_value_usd, summary_json, fork_block, finished_at "
                "FROM simulate_runs WHERE lower(address)=? ORDER BY finished_at DESC LIMIT 1",
                (address,)).fetchone()
        except sqlite3.Error:
            sr = None
        if sr is not None:
            try:
                summary = json.loads(sr["summary_json"]) if sr["summary_json"] else None
            except ValueError:
                summary = None
            out["sim"] = {"status": sr["status"], "holder_value_usd": sr["holder_value_usd"],
                          "fork_block": sr["fork_block"], "finished_at": sr["finished_at"],
                          "summary": summary}
    except sqlite3.Error:
        pass
    finally:
        con.close()
    return out


def panel_for_monitor_finding(finding_id: Optional[int]) -> Optional[Dict[str, Any]]:
    """Majority label for one monitor finding id (read-only, isolated DB).

    Supporting signal ONLY: ``ai_majority_suspected`` never confirms a
    vulnerability and ``ai_majority_likely_fp`` never disproves one.
    """
    if not finding_id:
        return None
    try:
        from auditor import review_panel as P
    except Exception:  # noqa: BLE001
        return None
    if not P.default_review_db().exists():
        return None
    try:
        con = sqlite3.connect(f"file:{P.default_review_db()}?mode=ro", uri=True, timeout=5)
        con.row_factory = sqlite3.Row
        o = con.execute(
            "SELECT * FROM review_outcomes WHERE finding_id=? ORDER BY round DESC LIMIT 1",
            (int(finding_id),)).fetchone()
        if o is None:
            return None
        votes = [dict(v) for v in con.execute(
            "SELECT role, model, verdict, confidence, error, created_at FROM review_votes "
            "WHERE finding_id=? AND round=? ORDER BY id", (int(finding_id), o["round"]))]
        return {"finding_id": int(finding_id), "round": o["round"], "label": o["label"],
                "epistemic": o["epistemic"], "created_at": o["created_at"],
                "summary": (json.loads(o["summary_json"]) if o["summary_json"] else None),
                "roles": [v.get("role") for v in votes], "votes": votes}
    except (sqlite3.Error, ValueError, TypeError):
        return None
    finally:
        try:
            con.close()
        except Exception:  # noqa: BLE001
            pass


# ---------------------------------------------------------------------------
# runtime disproof (read-only eth_call; never sends a transaction)
# ---------------------------------------------------------------------------

class _EthCallClient:
    """Minimal read-only JSON-RPC client compatible with
    ``auditor.live_disproof.check`` (``call(to, data)`` + ``block_number``).

    The URL comes from the configured monitor RPC env var and is never
    logged or written. Short timeouts; failures surface as unknown, never
    as disproof.
    """

    def __init__(self, rpc_url: str, timeout: float = 8.0) -> None:
        self.rpc_url = rpc_url
        self.timeout = timeout

    def _rpc(self, method: str, params: list) -> Any:
        import urllib.request

        body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
        req = urllib.request.Request(self.rpc_url, data=body,
                                     headers={"Content-Type": "application/json",
                                              "User-Agent": "contract-auditor/finrisk"},
                                     method="POST")
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            data = json.loads(resp.read().decode())
        if isinstance(data, dict) and data.get("error"):
            raise RuntimeError(str(data["error"])[:200])
        return (data or {}).get("result")

    def call(self, to: str, data: str) -> Optional[str]:
        r = self._rpc("eth_call", [{"to": to, "data": data}, "latest"])
        return r if isinstance(r, str) else None

    def block_number(self):
        r = self._rpc("eth_blockNumber", [])
        try:
            return int(r, 16) if isinstance(r, str) else None
        except (TypeError, ValueError):
            return None


def rpc_url_for_review() -> Optional[str]:
    return os.environ.get(RPC_ENV) or None


def runtime_disproof(finding: Mapping[str, Any], address: str,
                     rpc_url: Optional[str]) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """Run the reused ``live_disproof`` check when an RPC is configured.

    Returns ``(evidence, error)``. ``evidence`` is set ONLY when the
    specific read succeeded and the tested path is DISPROVED; everything
    else (no RPC, module not applicable, read failure) is honest unknown.
    """
    if not rpc_url:
        return None, "no_rpc_configured"
    if not address:
        return None, "no_chain_address"
    try:
        from auditor.live_disproof import check

        ev = check(dict(finding), address, _EthCallClient(rpc_url))
        return ev or None, None
    except Exception as exc:  # noqa: BLE001 - unknown, not disproved
        return None, f"{type(exc).__name__}: {exc}"[:200]


# ---------------------------------------------------------------------------
# verdict mapping (pure, deterministic, evidence-derived)
# ---------------------------------------------------------------------------

def _sev_of(finding: Mapping[str, Any]) -> str:
    return str((finding or {}).get("severity") or "").upper()


def _is_protective_note(finding: Mapping[str, Any]) -> bool:
    """Protected-initializer / defensive centralization notes: the detector
    records a guard being PRESENT, never an exploitable fund path."""
    desc = str((finding or {}).get("description") or "")
    detector = _detector_of(finding)
    if detector == "privileged-auth-protected":
        return True
    return "status=PROTECTED" in desc and "no exploit steps" in desc.lower()


def _guarded_privileged(triage_rule: str, triage_reason: str, exposure_model: str) -> bool:
    if triage_rule in _PRIVILEGED_REASONS or triage_reason in _PRIVILEGED_REASONS:
        return True
    return exposure_model == "privileged"


def has_financial_basis(financial: Mapping[str, Any]) -> bool:
    if financial.get("holdings_usd") is not None and isinstance(financial.get("holdings_usd"), (int, float)):
        return True
    assets = financial.get("assets")
    if isinstance(assets, list) and any(
            isinstance(a, Mapping) and a.get("usd") is not None for a in assets):
        return True
    est = financial.get("stored_estimate")
    if isinstance(est, Mapping) and est.get("est_loss_usd") is not None:
        return True
    return False


def classify_verdict(*, evidence: Mapping[str, Any]) -> Tuple[str, str, bool]:
    """Deterministic verdict mapping. Every branch cites its evidence.

    Returns ``(verdict, rationale, retryable)``. ``retryable`` marks
    inconclusive outcomes whose inputs were unavailable for TRANSIENT
    reasons (missing RPC, timeouts) — a bounded retry may produce more
    evidence, whereas a missing source or a structural answer does not
    (and can never become ``disproved``).
    """
    validation = evidence.get("validation") or {}
    steps: List[Mapping[str, Any]] = list(validation.get("steps") or [])
    att = evidence.get("attacker") or {}
    fin = evidence.get("financial") or {}
    missing = list(evidence.get("missing_evidence") or [])
    infra_failures = list(evidence.get("infra_failures") or [])

    disproof = [s for s in steps if s.get("stage") == "runtime_disproof"
                and s.get("status") == "disproved"]
    stored_disproof = bool(evidence.get("triage_rule") in _DISPROOF_RULES)
    confirmed = bool(evidence.get("confirmed_exploitable"))
    suppressed = bool(evidence.get("suppressed"))
    triage_rule = str(evidence.get("triage_rule") or "")
    triage_reason = str(evidence.get("triage_reason") or "")
    # A privileged gate can be recorded either on the assembled attacker
    # block or directly in the stored triage fields; honour both.
    guarded = (bool(att.get("privilege_gated"))
               or triage_rule in _PRIVILEGED_REASONS
               or triage_reason in _PRIVILEGED_REASONS)
    protective = bool(evidence.get("protective_note"))
    user_funds = bool(fin.get("user_funds_at_risk"))
    exposure_model_block = att.get("exposure_model") or {}
    exposure_model = str(exposure_model_block.get("model") or "")
    try:
        factor = float(exposure_model_block.get("exposure_factor") or 0.0)
    except (TypeError, ValueError):
        factor = 0.0
    # Attacker-relevant exposure models from value_at_risk: 'locked' (funds
    # held live on the contract) and 'partial'/'honeypot' (user funds).
    # 'privileged' is the recorded owner-only model and is NOT dangerous
    # for outsiders (kept separately as owner-rug exposure).
    dangerous_class = exposure_model not in ("", "privileged") and (
        factor > 0 or user_funds)

    # 1. Positive disproof evidence — and ONLY that — yields 'disproved'.
    if disproof or stored_disproof:
        src_parts = []
        if stored_disproof:
            src_parts.append(f"stored pipeline triage rule {triage_rule!r}")
        for s in disproof:
            src_parts.append(str(s.get("detail") or "")[:220])
        return (VERDICT_DISPROVED,
                "Positive disproof evidence is stored ("
                + " | ".join(p for p in src_parts if p)
                + "). The suspected path does not hold under the TESTED conditions; "
                  "re-verify if state changes.", False)

    # 2. Suppression recorded as not-a-bug in context (trusted library etc.).
    if suppressed and triage_reason in _FP_SUPPRESSION_REASONS:
        return (VERDICT_NOT_FINANCIAL,
                f"Stored pipeline triage suppressed this finding ({triage_reason!r}): the tagged "
                "pattern was disqualifed in its recorded context. No outsider fund-loss path is "
                "established by the stored evidence.", False)

    # 3. Existing pipeline-confirmed dynamic reproduction.
    if confirmed:
        if has_financial_basis(fin):
            return (VERDICT_VALIDATED,
                    "Dynamic outsider reproduction is stored by the monitor pipeline "
                    "(confirmed_exploitable) and a priced asset basis exists for the affected "
                    "contract. Sharing this finding does not by itself prove THIS function is the "
                    "exploited path; verify the call path before acting.", False)
        return (VERDICT_VALIDATED,
                "Dynamic outsider reproduction is stored by the monitor pipeline "
                "(confirmed_exploitable). No reliable dollar figure is available for this "
                "address, so exposure is reported WITHOUT a number by this review.", False)

    # 4. Privilege-gated paths under the recorded context.
    if guarded:
        return (VERDICT_NOT_FINANCIAL,
                "Filtering by recorded guard context: the transfer path requires a privileged "
                "module/owner address (stored triage/exposure model). Outside the compromised-key "
                "scenario there is no demonstrated outsider fund-loss path; recorded owner-rug "
                "exposure is kept separately.", False)

    # 5. Defensive notes (guards present, no exploit steps).
    if protective:
        return (VERDICT_NOT_FINANCIAL,
                "The finding is a defensive/protective note (a guard is present); no unstated "
                "unprotected fund-loss path is established by the stored evidence.", False)

    # 6. Any OTHER stored suppression: not proven either way.
    if suppressed:
        return (VERDICT_INCONCLUSIVE,
                f"A stored suppression exists (rule={triage_rule!r}, reason={triage_reason!r}) but it "
                "is not a disproof of the financial-loss path; insufficient evidence to decide.", False)

    # 7. Dangerous exposure class with an attackable-priced asset basis.
    if dangerous_class and has_financial_basis(fin):
        return (VERDICT_POTENTIAL,
                "Plausible loss path: the recorded exposure model marks attacker-controllable risk "
                "and the affected contract carries a priced asset basis. Residual validation steps "
                "(dynamic reproduction, per-function simulation) are INCOMPLETE — potential, not "
                "validated.", False)

    # 8. No financial basis / no evidence at all -> inconclusive (never disproved).
    if infra_failures:
        return (VERDICT_INCONCLUSIVE,
                "Evidence could not be gathered: " + "; ".join(infra_failures[:4])
                + ". Insufficient evidence to decide (this is NOT a disproof; review can be retried).",
                True)
    if dangerous_class:
        return (VERDICT_POTENTIAL,
                "The recorded exposure model marks attacker-controllable risk for this vulnerability "
                "class, but no reliable financial basis was available for the affected address. "
                "Impact cannot be quantified; listed as potential.", False)
    return (VERDICT_INCONCLUSIVE,
            "Insufficient stored evidence: " + ("; ".join(missing[:4]) if missing else
                                                "no financial basis and no dangerous-path data") + ".",
            False)


# ---------------------------------------------------------------------------
# per-finding review
# ---------------------------------------------------------------------------

def review_finding(*, finding: Mapping[str, Any], scan: Mapping[str, Any],
                   monitor: Mapping[str, Any], matched: Optional[Mapping[str, Any]],
                   panel: Optional[Mapping[str, Any]], rpc_url: Optional[str],
                   allow_network_verify: Optional[bool] = None,
                   log: Optional[Callable[[str], None]] = None,
                   heartbeat_cb: Optional[Callable[[str], None]] = None) -> Dict[str, Any]:
    """One finding review: assemble evidence blocks, then map to a verdict.

    Every block carries provenance labels; nothing here invents numbers or
    asserts exploitability the stored evidence does not support.
    """
    emit = log or (lambda _m: None)
    if allow_network_verify is None:
        allow_network_verify = os.environ.get(_NETWORK_VERIFY_ENV, "").strip().lower() in ("1", "true", "yes")

    network = str((monitor.get("network") or scan.get("chain") or "ethereum"))
    chain_ctx = resolve_chain_context(scan.get("source_path"))
    address = monitor.get("address") or chain_ctx["address"]
    if not network and address:
        network = "ethereum"
    severity = _sev_of(finding)
    detector = _detector_of(finding)

    triage_rule = ""
    triage_reason = ""
    suppressed = False
    confirmed = False
    monitor_finding_id = None
    stored_estimate: Any = None
    if matched is not None:
        triage_rule = str(matched.get("triage_rule") or "")
        triage_reason = str(matched.get("triage_reason") or "")
        suppressed = bool(matched.get("suppressed"))
        confirmed = bool(matched.get("confirmed_exploitable"))
        monitor_finding_id = matched.get("id")
        stored_estimate = matched.get("estimate") if isinstance(matched.get("estimate"), Mapping) else None

    missing: List[str] = []
    infra_failures: List[str] = []

    blocks: Dict[str, Any] = {
        "title": finding.get("title"),
        "severity": severity,
        "category": finding.get("category"),
        "tool": finding.get("tool"),
        "detector": detector,
        "description": str(finding.get("description") or "")[:2000],
        "location": {"contract": finding.get("affected_contract"),
                     "function": finding.get("affected_function"),
                     "lines": finding.get("affected_lines"),
                     "file": finding.get("affected_file")},
        "chain": network,
        "address": address,
        "source_ref": scan.get("source_path"),
        "scan_id": scan.get("scan_id"),
        "scan_timestamp": scan.get("timestamp"),
        "config_fingerprint": scan.get("config_fingerprint"),
    }
    if monitor_finding_id is not None:
        blocks["monitor_finding_id"] = monitor_finding_id

    # -- stage: source/bytecode validity -------------------------------------
    if heartbeat_cb:
        heartbeat_cb("source_and_bytecode")
    has_source_ref = bool(str(scan.get("source_path") or ""))
    blocks["source_validity"] = {"available_for_review": has_source_ref,
                                 "ref": scan.get("source_path")}
    blocks["bytecode"] = {"outcome": "not_attempted", "basis": None}
    if not has_source_ref:
        missing.append("no source reference recorded for this scan")
    if not address:
        missing.append("no chain address recorded for this finding")
    if address and severity in ("CRITICAL", "HIGH", "MEDIUM") and allow_network_verify:
        try:
            from auditor.bytecode_verify import verify_deployed_source

            bc = verify_deployed_source(str(address))
            blocks["bytecode"] = {"outcome": bc.get("value") or "unknown",
                                  "codehash": bc.get("codehash"),
                                  "basis": bc.get("basis"),
                                  "label": bc.get("label")}
            if bc.get("value") == "deployed_unverified":
                missing.append("deployed bytecode not verified against this source")
            if str(bc.get("error") or "").startswith(("no_rpc", "no_etherscan_key")):
                infra_failures.append(f"bytecode_verify: {bc['error']}")
        except Exception as exc:  # noqa: BLE001
            blocks["bytecode"] = {"outcome": "error",
                                  "basis": f"{type(exc).__name__}: {exc}"[:200]}
            infra_failures.append("bytecode_verify errored")
    elif address and severity in ("CRITICAL", "HIGH", "MEDIUM") and not allow_network_verify:
        blocks["bytecode"] = {"outcome": "not_attempted",
                              "basis": "network verification not enabled for this run"}

    # -- stage: attacker feasibility ------------------------------------------
    if heartbeat_cb:
        heartbeat_cb("attacker_feasibility")
    exposure_model_block: Any = None
    try:
        from auditor.value_at_risk import exposure_for

        exposure = exposure_for(finding, {"reason": triage_rule} if triage_rule else None)
        if isinstance(exposure, Mapping):
            exposure_model_block = {
                "model": exposure.get("model"),
                "vulnerability_class": exposure.get("vulnerability_class"),
                "exposure_factor": exposure.get("factor"),
                "assumption": exposure.get("assumption"),
            }
    except Exception as exc:  # noqa: BLE001
        infra_failures.append(f"exposure model: {type(exc).__name__}")
    impact_class: Any = None
    try:
        from auditor.monitor import classify_impact

        impact_class = classify_impact(finding, detector, finding.get("category"))
    except Exception:  # noqa: BLE001
        pass
    protective = _is_protective_note(finding)
    exposure_model_name = str(exposure_model_block.get("model") or "") if exposure_model_block else ""
    att_flags = {
        "impact_class": impact_class,
        "exposure_model": exposure_model_block,
        "exposure_model_origin": "value_at_risk.exposure_for (existing pipeline)",
        "privilege_gated": _guarded_privileged(triage_rule, triage_reason, exposure_model_name),
        "protective_note": protective,
        "unprivileged_caller_assumption": ("An attacker is assumed to be an ordinary external "
                                           "account; stored triage does not show a bypass."),
        "assumptions": ([] if exposure_model_block is None
                        else [str(exposure_model_block.get("assumption") or "")]),
        "unavailable_evidence": [],
    }
    blocks["attacker"] = att_flags

    # -- stage: financial basis ----------------------------------------------
    if heartbeat_cb:
        heartbeat_cb("financial_basis")
    holdings = monitor.get("holdings") if isinstance(monitor.get("holdings"), list) else None
    blocks["financial"] = {
        "assets": holdings,
        "holdings_usd": monitor.get("tvl_usd"),
        "asset_basis_origin": ("monitor holdings value_json (priced by the pipeline's "
                               "PriceSource)" if monitor.get("value_available") else None),
        "price_as_of": monitor.get("price_as_of"),
        "methodology": ("Contract holdings priced by the monitor pipeline (RPC balances + configured "
                        "price source). Holdings are context — never claimed as confirmed convertible "
                        "loss by this review." if monitor.get("value_available") else None),
        "stored_estimate": None,
        "stored_estimate_origin": None,
        "user_funds_at_risk": False,
    }
    if stored_estimate is not None:
        blocks["financial"]["stored_estimate"] = {
            "est_loss_usd": stored_estimate.get("est_loss_usd"),
            "low": stored_estimate.get("est_loss_low_usd"),
            "high": stored_estimate.get("est_loss_high_usd"),
            "is_estimate": True,
            "label": "heuristic model recorded by the existing pipeline (never a prediction)",
            "assumptions": stored_estimate.get("assumptions"),
        }
        blocks["financial"]["stored_estimate_origin"] = "monitor_findings.estimate_json"
        blocks["financial"]["user_funds_at_risk"] = bool(stored_estimate.get("user_funds_at_risk"))
    if not monitor.get("value_available"):
        missing.append("no priced holdings/TVL recorded for the affected contract")

    # -- stage: validation ------------------------------------------------------
    if heartbeat_cb:
        heartbeat_cb("validation")
    steps: List[Dict[str, Any]] = []

    if stored_estimate is not None:
        steps.append({
            "stage": "stored_pipeline_estimate",
            "status": "completed",
            "epistemic": "HEURISTIC",
            "detail": "Existing pipeline estimate reused verbatim (inputs: value basis, exposure "
                      "factor and the assumptions stored beside it).",
        })
    if confirmed:
        steps.append({
            "stage": "dynamic_reproduction",
            "status": "completed",
            "epistemic": "FACT",
            "detail": "Monitor pipeline recorded a dynamically reproduced outsider TP above the "
                      "configured threshold (monitor_findings.confirmed_exploitable).",
        })
    if suppressed:
        steps.append({
            "stage": "pipeline_triage",
            "status": "completed",
            "epistemic": "FACT",
            "detail": f"Stored triage suppressed this finding (rule={triage_rule or ''!r}, "
                      f"reason={triage_reason or ''!r}, detail={str(matched.get('triage_detail') or '')[:200]!r}).",
        })
    sim = monitor.get("sim")
    if isinstance(sim, Mapping) and sim.get("status"):
        steps.append({
            "stage": "fork_simulation",
            "status": "recorded",
            "epistemic": "FACT",
            "detail": f"Stored fork simulation for this contract: status={sim.get('status')} "
                      f"(fork block {str(sim.get('fork_block'))[:40]}). Contract-scope evidence, "
                      "not a per-function proof.",
        })
    disproof_ev, rpc_err = runtime_disproof(finding, str(address or ""), rpc_url)
    if rpc_err == "no_rpc_configured":
        steps.append({
            "stage": "runtime_disproof",
            "status": "not_attempted",
            "epistemic": "UNKNOWN",
            "detail": "No RPC configured; read-only runtime disproof not attempted.",
        })
        # Optional step that cannot run in an offline context — recorded as
        # unknown, not as infra failure (it does not make the whole
        # review retryable, see ``classify_verdict``).
    else:
        steps.append({
            "stage": "runtime_disproof",
            "status": ("disproved" if disproof_ev else
                       ("error" if rpc_err else "not_applicable_or_unknown")),
            "epistemic": ("FACT" if disproof_ev else "UNKNOWN"),
            "detail": str(((disproof_ev or {}).get("detail")) or
                          (rpc_err or "read did not apply to this detector or could not decide"))[:400],
        })
        if rpc_err:
            infra_failures.append(f"runtime_disproof: {rpc_err}")
    if panel:
        steps.append({
            "stage": "ai_review_panel",
            "status": "recorded",
            "epistemic": "AI_OPINION",
            "detail": f"Majority panel label {panel.get('label')} (round {panel.get('round')}); "
                      "supporting signal only — never confirms or disproves.",
        })
    blocks["validation"] = {"steps": steps, "missing_steps": [], "test_refs": []}

    # assemble verdict inputs
    ev = {
        **blocks,
        "triage_rule": triage_rule,
        "triage_reason": triage_reason,
        "suppressed": suppressed,
        "confirmed_exploitable": confirmed,
        "missing_evidence": missing,
        "infra_failures": infra_failures,
    }
    verdict, rationale, retryable = classify_verdict(evidence=ev)

    assumptions = list(att_flags["assumptions"])
    unavailable = list(att_flags["unavailable_evidence"])
    unavail_map: Dict[str, str] = {}
    if missing:
        unavail_map.update({m.split()[0]: m for m in missing})
    if not allow_network_verify and (address or "").startswith("0x"):
        unavail_map.setdefault(
            "bytecode_verify", "On-chain bytecode/source correspondence was not verified in this "
                               "offline run (enable with AUDITOR_FINRISK_NETWORK_VERIFY=1).")
    if not rpc_url:
        unavail_map.setdefault(
            "runtime_disproof", "No read-only RPC configured; the runtime disproof check could not "
                                "be attempted (recorded as unknown, never as disproved).")
    unavailable.extend(unavail_map.values())

    payload: Dict[str, Any] = {
        "tool_version": TOOL_VERSION,
        "generated_at": _utcnow_iso(),
        "identity": blocks,
        "attacker": att_flags,
        "financial": blocks["financial"],
        "validation": blocks["validation"],
        "bytecode": blocks["bytecode"],
        "source_validity": blocks["source_validity"],
        "verdict": verdict,
        "verdict_rationale": rationale,
        "missing_evidence": missing,
        "assumptions": assumptions or
        ["Executed offline against stored records; on-chain reads beyond the stored pipeline "
         "data were not part of this attempt."],
        "unavailable_evidence": unavailable,
        "retryable": bool(retryable),
        "infra_failures": infra_failures,
        "panel": (None if not panel else {
            "label": panel.get("label"), "epistemic": panel.get("epistemic"),
            "round": panel.get("round"), "created_at": panel.get("created_at"),
        }),
        "ai_opinion_count": 1 if panel else 0,
        "epistemic_schema": ["FACT", "HEURISTIC", "AI_OPINION", "UNKNOWN"],
    }
    emit(f"finrisk: verdict={verdict} (missing={len(missing)}, infra={len(infra_failures)})")
    return payload


# ---------------------------------------------------------------------------
# cross-scan reuse + processing
# ---------------------------------------------------------------------------

def _find_reusable(con: sqlite3.Connection, content_key_value: Optional[str]) -> Optional[Dict[str, Any]]:
    if not content_key_value:
        return None
    r = con.execute(
        "SELECT scan_id, fingerprint, verdict, review_json, updated_at FROM finrisk_reviews "
        "WHERE content_key=? AND state=? AND verdict IS NOT NULL AND review_json IS NOT NULL "
        "ORDER BY finished_at DESC LIMIT 1", (content_key_value, STATE_COMPLETED)).fetchone()
    if r is None:
        return None
    try:
        payload = json.loads(r["review_json"]) if r["review_json"] else {}
    except ValueError:
        return None
    return {"scan_id": r["scan_id"], "fingerprint": r["fingerprint"],
            "verdict": r["verdict"], "payload": payload, "updated_at": r["updated_at"]}


def _reused_payload(base: Mapping[str, Any], reuse: Mapping[str, Any]) -> Dict[str, Any]:
    out = dict(base)
    out["verdict"] = reuse["verdict"]
    out["verdict_rationale"] = (
        f"Verdict inherited from a stored review of the SAME code shape "
        f"(content-key reuse, source scan {str(reuse['scan_id'])[:8]}… ). "
        + str(reuse['payload'].get('verdict_rationale') or ""))
    reusable = {"reused_from": {"scan_id": reuse["scan_id"], "fingerprint": reuse["fingerprint"],
                                "verdict": reuse["verdict"], "at": reuse["updated_at"]},
                "epistemic": "REVIEW_REUSE"}
    out["review_reuse"] = reusable
    out["missing_evidence"] = reuse["payload"].get("missing_evidence") or []
    out["assumptions"] = reuse["payload"].get("assumptions") or []
    return out


# ---------------------------------------------------------------------------
# context loading from the history store (read-only) + processing loop
# ---------------------------------------------------------------------------

def load_contexts(history_scan_row_loader: Callable[[str], Optional[Mapping[str, Any]]],
                  *, scan_ids: Sequence[str], monitor_db_path: Optional[Path] = None
                  ) -> Dict[str, Dict[str, Any]]:
    """Build engine inputs for one scan: (finding details, monitor rows).

    ``history_scan_row_loader`` returns the history row dict for a scan_id
    (the callers already have read helpers; keeping the loader injectable
    keeps this module switchable to a test store). Monitor reads stay
    read-only and missing-DB tolerant.
    """
    out: Dict[str, Dict[str, Any]] = {}
    by_scan: Dict[str, List[Mapping[str, Any]]] = {}
    for scan_id in scan_ids:
        row = history_scan_row_loader(scan_id)
        if row is None:
            continue
        details = row.get("finding_details")
        if isinstance(details, str):
            try:
                details = json.loads(details or "[]")
            except ValueError:
                details = []
        if not isinstance(details, list):
            details = []
        by_scan[scan_id] = [d for d in details if isinstance(d, Mapping)]
        src = str(row.get("source_path") or "")
        chain = resolve_chain_context(src)
        network = chain["network"] or "ethereum"
        address = chain["address"]
        row["_finrisk_chain"] = {"network": network, "address": address}
        if address:
            from auditor.monitor import default_monitor_db_path as _dmp

            ctx = monitor_context(Path(monitor_db_path) if monitor_db_path else _dmp(),
                                  network=network, address=address)
            if not ctx.get("findings"):
                ctx = {**ctx, "findings": []}
            out[scan_id] = {**row, "_monitor": ctx}
        else:
            out[scan_id] = {**row, "_monitor": {"network": network, "address": None,
                                                "findings": [], "holdings": None,
                                                "tvl_usd": None, "price_as_of": None,
                                                "value_available": False, "sim": None}}
    return out


def _match_monitor_row(monitor_ctx: Mapping[str, Any],
                       finding: Mapping[str, Any]) -> Optional[Mapping[str, Any]]:
    candidates = monitor_ctx.get("findings") or []
    if not candidates:
        return None
    det = _detector_of(finding)
    fn = str(finding.get("affected_function") or "")
    contract = str(finding.get("affected_contract") or "")
    scored: List[Dict[str, int]] = []
    for cand in candidates:
        score = 0
        if str(cand.get("detector") or "") == det:
            score += 4
        if fn and str(cand.get("function") or "") == fn:
            score += 2
        if contract and str(cand.get("contract") or "") == contract:
            score += 1
        if str(cand.get("title") or "") == str(finding.get("title") or ""):
            score += 1
        scored.append({"cand": cand, "score": score})
    if not scored:
        return None
    top_score = max(d["score"] for d in scored)
    if top_score < 4:
        return None  # no confident detector match; treat as unknown, not as confirmed polarity
    best = max(scored, key=lambda d: d["score"])["cand"]
    return best


def _history_loader_for(history_db: Optional[Path]):
    """Read-only loader for history scan rows; missing DB -> None loader."""
    def load(scan_id: str) -> Optional[Dict[str, Any]]:
        if not history_db or not Path(history_db).exists():
            return None
        con = sqlite3.connect(f"file:{history_db}?mode=ro", uri=True, timeout=10)
        con.row_factory = sqlite3.Row
        try:
            r = con.execute(
                "SELECT scan_id, timestamp, source_path, content_hash, config_fingerprint, status,"
                " finding_fingerprints, finding_details FROM scan_records WHERE scan_id=?",
                (scan_id,)).fetchone()
            if r is None:
                return None
            return dict(r)
        except sqlite3.Error:
            return None
        finally:
            con.close()
    return load


#: Public name for the dashboard (same function; read-only, never mutates
#: scan records).
history_loader_for = _history_loader_for


def process_one(con: sqlite3.Connection, *, scan_id: str, fingerprint: str,
                history_loader: Callable[[str], Optional[Mapping[str, Any]]],
                monitor_db_path: Optional[Path] = None,
                rpc_url: Optional[str] = None,
                allow_network_verify: Optional[bool] = None,
                log: Optional[Callable[[str], None]] = None) -> Dict[str, Any]:
    """Run ONE claimed review end-to-end, persisting the verdict.

    Returns a result dict; never raises into the caller except for the
    claim itself, which is already persisted.
    """
    emit = log or (lambda _m: None)

    row = con.execute(
        "SELECT * FROM finrisk_reviews WHERE scan_id=? AND fingerprint=?",
        (scan_id, fingerprint)).fetchone()
    if row is None:
        return {"scan_id": scan_id, "fingerprint": fingerprint, "status": "missing_row"}

    def beat(stage: str) -> None:
        try:
            heartbeat(con, scan_id, fingerprint, stage)
        except sqlite3.Error:
            pass

    try:
        hrow = history_loader(scan_id)
    except Exception as exc:  # noqa: BLE001
        return _record_failure(con, scan_id, fingerprint, f"history load: {type(exc).__name__}: {exc}")
    if hrow is None:
        # History row vanished? Honest: mark completed-inconclusive; never
        # claim a result we cannot support.
        payload = {**_empty_payload(), "verdict": VERDICT_INCONCLUSIVE,
                   "verdict_rationale": "The history scan record was not readable; nothing concluded.",
                   "missing_evidence": ["history scan record unavailable"]}
        set_state(con, scan_id, fingerprint, STATE_COMPLETED,
                  note=payload["verdict_rationale"], verdict=VERDICT_INCONCLUSIVE)
        save_review(con, scan_id, fingerprint, VERDICT_INCONCLUSIVE, payload)
        return {"scan_id": scan_id, "fingerprint": fingerprint, "verdict": VERDICT_INCONCLUSIVE,
                "status": STATE_COMPLETED}

    chain = hrow.get("_finrisk_chain") or resolve_chain_context(hrow.get("source_path"))
    monitor_ctx = hrow.get("_monitor") or {}

    # context row per finding is lazily built since monitor reads are cached per scan
    details = hrow.get("_details")
    if details is None:
        det_val = hrow.get("finding_details")
        if isinstance(det_val, str):
            try:
                det_val = json.loads(det_val or "[]")
            except ValueError:
                det_val = []
        details = [d for d in det_val or [] if isinstance(d, Mapping)] if isinstance(det_val, list) else []
        hrow["_details"] = details
    finding = next((d for d in details if str(d.get("fingerprint") or "") == fingerprint), None)
    if finding is None:
        payload = {**_empty_payload(), "verdict": VERDICT_INCONCLUSIVE,
                   "verdict_rationale": "The stored finding details for this fingerprint were not readable.",
                   "missing_evidence": ["finding details not found in scan record"]}
        set_state(con, scan_id, fingerprint, STATE_COMPLETED,
                  note=payload["verdict_rationale"], verdict=VERDICT_INCONCLUSIVE)
        save_review(con, scan_id, fingerprint, VERDICT_INCONCLUSIVE, payload)
        return {"scan_id": scan_id, "fingerprint": fingerprint, "verdict": VERDICT_INCONCLUSIVE,
                "status": STATE_COMPLETED}

    # cross-scan reuse fast path: same code shape already reviewed?
    # cross-scan reuse fast path: identical code shape already reviewed?
    reuse = _find_reusable(con, str(row["content_key"] or ""))
    if reuse is not None and (reuse["scan_id"], reuse["fingerprint"]) != (scan_id, fingerprint):
        beat("review_reuse")
        payload = _reused_payload(_empty_payload(), reuse)
        r = finish_completed(con, scan_id, fingerprint, reuse["verdict"], payload)
        r["reused"] = True
        return r

    matched = _match_monitor_row(monitor_ctx, finding)
    panel = panel_for_monitor_finding((matched or {}).get("id")) if matched else None

    beat("engine")
    try:
        payload = review_finding(
            finding=finding, scan={**hrow, "chain": chain["network"]},
            monitor=monitor_ctx, matched=matched, panel=panel,
            rpc_url=rpc_url, allow_network_verify=allow_network_verify,
            log=emit, heartbeat_cb=beat)
    except Exception as exc:  # noqa: BLE001 - never let a review kill the process
        return _record_failure(con, scan_id, fingerprint, f"engine: {type(exc).__name__}: {exc}")

    if payload.get("retryable") and (row["attempts"] or 0) + 1 < MAX_ATTEMPTS:
        # inconclusive-but-transient: keep the honest verdict in the row so
        # the dashboard shows it, and schedule a bounded retry.
        set_state(con, scan_id, fingerprint, STATE_RETRYABLE,
                  note=q(payload.get("verdict_rationale")), verdict=payload["verdict"])
        save_review(con, scan_id, fingerprint, payload["verdict"], payload)
        con.execute("UPDATE finrisk_reviews SET next_attempt_at=? WHERE scan_id=? AND fingerprint=?",
                    (_now() + BACKOFF_S[min(int(row["attempts"] or 0), len(BACKOFF_S) - 1)], scan_id, fingerprint))
        con.commit()
        return {"scan_id": scan_id, "fingerprint": fingerprint,
                "verdict": payload["verdict"], "status": STATE_RETRYABLE}
    return finish_completed(con, scan_id, fingerprint, payload["verdict"], payload)


def _record_failure(con: sqlite3.Connection, scan_id: str, fingerprint: str, message: str) -> Dict[str, Any]:
    fail_retryable(con, scan_id, fingerprint, message)
    return {"scan_id": scan_id, "fingerprint": fingerprint, "status": STATE_RETRYABLE,
            "error": message}


def _empty_payload() -> Dict[str, Any]:
    return {
        "tool_version": TOOL_VERSION, "generated_at": _utcnow_iso(),
        "identity": {}, "attacker": {}, "financial": {}, "validation": {"steps": []},
        "verdict": VERDICT_INCONCLUSIVE, "verdict_rationale": "",
        "missing_evidence": [], "assumptions": [], "unavailable_evidence": [],
        "retryable": False, "infra_failures": [], "panel": None, "ai_opinion_count": 0,
    }


def process_queue(con: sqlite3.Connection, *, limit: int = 5,
                  history_loader: Optional[Callable[[str], Optional[Mapping[str, Any]]]] = None,
                  monitor_db_path: Optional[Path] = None,
                  rpc_url: Optional[str] = None,
                  allow_network_verify: Optional[bool] = None,
                  log: Optional[Callable[[str], None]] = None) -> List[Dict[str, Any]]:
    """Process due reviews (priority order). Returns per-finding results."""
    if history_loader is None:
        history_loader = _history_loader_for(None)
    log = log or (lambda _m: None)
    results: List[Dict[str, Any]] = []
    claimed = claim_due(con, limit=limit)
    if not claimed:
        return results
    contexts = load_contexts(history_loader, scan_ids=[c["scan_id"] for c in claimed],
                             monitor_db_path=monitor_db_path)
    for c in claimed:
        scan_id, fingerprint = c["scan_id"], c["fingerprint"]
        hrow = contexts.get(scan_id)
        if hrow is None:
            r = _record_failure(con, scan_id, fingerprint, "history scan record unavailable")
        else:
            r = process_one(con, scan_id=scan_id, fingerprint=fingerprint,
                            history_loader=lambda _sid, _h=hrow: _h,
                            monitor_db_path=monitor_db_path,
                            rpc_url=rpc_url,
                            allow_network_verify=allow_network_verify,
                            log=log)
        results.append(r)
    return results


# ---------------------------------------------------------------------------
# observability
# ---------------------------------------------------------------------------

def summary(con: sqlite3.Connection, *, now: Optional[float] = None) -> Dict[str, Any]:
    """Queue counters, verdict counts, in-flight ages and retryable errors."""
    now = _now() if now is None else now
    q: Dict[str, int] = {}
    for r in con.execute("SELECT state, COUNT(*) FROM finrisk_reviews GROUP BY 1"):
        q[r[0]] = int(r[1])
    verdicts: Dict[str, int] = {v: 0 for v in VERDICTS}
    for r in con.execute("SELECT verdict, COUNT(*) FROM finrisk_reviews WHERE state=? GROUP BY 1",
                         (STATE_COMPLETED,)):
        if r[0] in verdicts:
            verdicts[r[0]] = int(r[1])
    inflight = []
    for r in con.execute("SELECT scan_id, fingerprint, started_at, heartbeat_at, heartbeat_stage "
                         "FROM finrisk_reviews WHERE state=?", (STATE_RUNNING,)):
        age = round(now - float(r["started_at"] or now), 1)
        inflight.append({"scan_id": r["scan_id"], "fingerprint": r["fingerprint"],
                         "age_s": age, "stage": r["heartbeat_stage"],
                         "heartbeat_age_s": round(now - float(r["heartbeat_at"] or now), 1)
                         if r["heartbeat_at"] else None})
    retryable = con.execute(
        "SELECT COUNT(*), MAX(error_count) FROM finrisk_reviews WHERE state=?",
        (STATE_RETRYABLE,)).fetchone() or (0, 0)
    last_errors = [dict(r) for r in con.execute(
        "SELECT scan_id, fingerprint, last_error, updated_at FROM finrisk_reviews "
        "WHERE last_error IS NOT NULL ORDER BY updated_at DESC LIMIT 5")]
    rates = con.execute("SELECT AVG(finished_at - started_at), COUNT(*) FROM finrisk_reviews "
                        "WHERE state=? AND started_at IS NOT NULL AND finished_at IS NOT NULL",
                        (STATE_COMPLETED,)).fetchone()
    return {
        "queue": q, "verdicts": verdicts, "in_flight": inflight,
        "retryable_count": int(retryable[0] or 0),
        "max_error_count": int(retryable[1] or 0),
        "last_errors": last_errors,
        "avg_seconds_per_review": (None if not rates[0] else round(float(rates[0]), 2)),
        "completed_count": int(rates[1] or 0),
        "tool_version": TOOL_VERSION,
    }


# ---------------------------------------------------------------------------
# §6 reporting rules: exposure roll-up from PERSISTED evidence only
# ---------------------------------------------------------------------------

_EXPOSURE_VERDICTS = (VERDICT_VALIDATED, VERDICT_POTENTIAL)


def _row_financial_basis(payload: Mapping[str, Any]) -> Dict[str, Any]:
    fin = payload.get("financial") if isinstance(payload.get("financial"), Mapping) else {}
    assets = fin.get("assets") if isinstance(fin.get("assets"), list) else []
    usd = 0.0
    priced_tokens = 0
    unpriced_tokens = 0
    for a in assets:
        if not isinstance(a, Mapping):
            continue
        v = a.get("usd")
        if isinstance(v, (int, float)):
            usd += float(v)
            priced_tokens += 1
        else:
            unpriced_tokens += 1
    est = fin.get("stored_estimate") if isinstance(fin.get("stored_estimate"), Mapping) else None
    est_value = None
    if est is not None:
        for key in ("high", "est_loss_usd", "low"):
            v = est.get(key)
            if isinstance(v, (int, float)):
                est_value = float(v)
                break
    ident = payload.get("identity") if isinstance(payload.get("identity"), Mapping) else {}
    return {"basis_usd": usd, "priced_tokens": priced_tokens, "unpriced_tokens": unpriced_tokens,
            "has_basis": bool(priced_tokens), "no_price_reason": fin.get("methodology"),
            "est_usd": est_value,
            "est_label": None if est is None else (
                (est.get("label") if isinstance(est, Mapping) else None)
                or "heuristic model recorded by the existing pipeline"),
            "est_assumptions": (est or {}).get("assumptions"),
            "as_of": fin.get("price_as_of"),
            "network": ident.get("chain"), "address": ident.get("address")}


def row_financial_basis(payload: Mapping[str, Any]) -> Dict[str, Any]:
    """Public wrapper for :func:`_row_financial_basis` (dashboard listing
    annotation reads the per-row financial basis from persisted payloads)."""
    return _row_financial_basis(payload)


def financial_rollup(con: sqlite3.Connection) -> Dict[str, Any]:
    """Reporting roll-up (requirement §6) computed from PERSISTED rows.

    * ``confirmed_outsider_exposure_usd``: validated rows, assets summed per
      UNIQUE (network, address) — the same address is never counted twice.
    * ``potential_or_unverified_exposure_usd``: potential rows on addresses
      NOT already counted as validated (a stronger verdict for the same
      address supersedes; no overlap across buckets).
    * ``modeled_impact_estimate_usd``: the pipeline's per-address heuristic
      estimate (monitor_findings.estimate_json, reused verbatim), labelled
      as a rough model — never added to confirmed exposure.
    * ``validated_without_dollar_estimate``: validated rows whose address
      has no priced basis.
    * ``disproved`` rows are EXCLUDED from every dollar total (only the
      count is reported).

    TVL / market cap / holder balances are never treated as stealable
    funds here: the basis is the REVIEWED contract's recorded holdings,
    and every bucket carries its evidence origin for the dashboard.
    """
    confirmed_bases: Dict[tuple, float] = {}
    potential_bases: Dict[tuple, float] = {}
    modeled: Dict[tuple, float] = {}
    validated_no_dollar = 0
    disproved_rows = 0
    rows = con.execute(
        "SELECT verdict, review_json FROM finrisk_reviews WHERE state=? AND verdict IS NOT NULL",
        (STATE_COMPLETED,))
    for r in rows:
        try:
            payload = json.loads(r["review_json"]) if r["review_json"] else {}
        except ValueError:
            continue
        if not isinstance(payload, Mapping):
            continue
        basis = _row_financial_basis(payload)
        key = (str(basis["network"] or ""), str(basis["address"] or "").lower())
        verdict = r["verdict"]
        if verdict == VERDICT_DISPROVED:
            disproved_rows += 1
            continue
        if verdict not in _EXPOSURE_VERDICTS:
            continue
        if verdict == VERDICT_VALIDATED and not basis["has_basis"]:
            validated_no_dollar += 1
        if not basis["address"]:
            continue
        # modeled estimate: capture for every priced-estimate row regardless
        # of bucket (own bucket, never mixed into exposure totals)
        if basis["est_usd"] is not None:
            modeled.setdefault(key, 0.0)
            modeled[key] = max(modeled[key], basis["est_usd"])
        if verdict == VERDICT_VALIDATED:
            if basis["has_basis"]:  # no priced basis -> reported via validated_without_dollar_estimate
                confirmed_bases.setdefault(key, 0.0)
                confirmed_bases[key] = max(confirmed_bases[key], basis["basis_usd"])
            potential_bases.pop(key, None)  # validated supersedes for this address either way
        else:
            if key in confirmed_bases or not basis["has_basis"]:
                continue  # validated supersedes / unpriced: no reliable dollar figure to add
            potential_bases[key] = max(potential_bases.get(key, 0.0), basis["basis_usd"])
    return {
        "confirmed_outsider_exposure_usd": round(sum(confirmed_bases.values()), 2),
        "confirmed_addresses": len(confirmed_bases),
        "potential_or_unverified_exposure_usd": round(sum(potential_bases.values()), 2),
        "potential_addresses": len(potential_bases),
        "modeled_impact_estimate_usd": round(sum(modeled.values()), 2),
        "modeled_addresses": len(modeled),
        "modeled_label": "heuristic rough estimate (pipeline model), NOT confirmed funds at risk",
        "validated_without_dollar_estimate": validated_no_dollar,
        "disproved_excluded_rows": disproved_rows,
        "methodology": ("Confirmed and potential buckets sum the REVIEWED contract's recorded priced "
                        "holdings once per (network,address); modeled figures reuse the existing "
                        "pipeline estimate with its stored assumptions; disproved rows are excluded."),
    }


# ---------------------------------------------------------------------------
# dashboard annotations
# ---------------------------------------------------------------------------

_ANNOTATE_COLS = ("state", "verdict", "verdict_version", "attempts", "last_error",
                  "heartbeat_stage", "heartbeat_at", "finished_at")


def annotate_findings(rows: List[Dict[str, Any]], con: Optional[sqlite3.Connection] = None,
                      db_path: Optional[Path] = None) -> List[Dict[str, Any]]:
    """Attach ``finrisk`` to each finding row (like _annotate_monitor_triage);
    read-only, no modification of history rows."""
    if con is None:
        con = open_finrisk_db_ro(db_path)
    if con is None:
        for f in rows:
            if isinstance(f, Mapping):
                f["finrisk"] = None
        return rows
    try:
        found: Dict[Tuple[str, str], Dict[str, Any]] = {}
        for f in rows:
            key = (str(f.get("scan_id") or ""), str(f.get("fingerprint") or ""))
            if key in found:
                continue
            r = con.execute(
                "SELECT state, verdict, verdict_version, attempts, last_error, "
                "heartbeat_stage, heartbeat_at, finished_at, review_json FROM finrisk_reviews "
                "WHERE scan_id=? AND fingerprint=?", key).fetchone()
            if r is None:
                d: Any = None
            else:
                d = {"state": r["state"], "verdict": r["verdict"],
                     "verdict_version": r["verdict_version"], "attempts": r["attempts"],
                     "last_error": r["last_error"],
                     "heartbeat_stage": r["heartbeat_stage"],
                     "in_flight": r["state"] == STATE_RUNNING,
                     "finished_at": r["finished_at"],
                     "has_review": bool(r["review_json"])}
            found[key] = d or None
        for f in rows:
            key = (str(f.get("scan_id") or ""), str(f.get("fingerprint") or ""))
            f["finrisk"] = found.get(key)
    except sqlite3.Error:
        for f in rows:
            f["finrisk"] = None
    finally:
        con.close()
    return rows


def review_payload(con: sqlite3.Connection, scan_id: str, fingerprint: str) -> Optional[Dict[str, Any]]:
    r = con.execute(
        "SELECT review_json, verdict, state, attempts, last_error, started_at, finished_at, "
        "heartbeat_stage, heartbeat_at, next_attempt_at, error_count, title, severity, "
        "category, source_path, network, address, content_key, enqueued_at "
        "FROM finrisk_reviews WHERE scan_id=? AND fingerprint=?",
        (scan_id, fingerprint)).fetchone()
    if r is None:
        return None
    try:
        payload = json.loads(r["review_json"]) if r["review_json"] else None
    except ValueError:
        payload = None
    row = dict(r)
    row.pop("review_json", None)
    row["review"] = payload
    try:
        h = [dict(x) for x in con.execute(
            "SELECT from_state, to_state, verdict, note, at FROM finrisk_review_history "
            "WHERE scan_id=? AND fingerprint=? ORDER BY id", (scan_id, fingerprint))]
    except sqlite3.Error:
        h = []
    row["history"] = h
    return row


# ---------------------------------------------------------------------------
# single-writer guard (POSIX flock; same rules as auditor.supervisor)
# ---------------------------------------------------------------------------

class finrisk_lock:
    """Exclusive flock over ``reports/finrisk.lock`` for the runner/routes.

    POSIX-only, matching auditor.supervisor's golden-thread behaviour. The
    dashboard route acquires it per-request; scripts/run_finrisk.py holds it
    for its whole run. Never blocks: busy -> False.
    """

    def __init__(self, db_path: Optional[Path] = None) -> None:
        db = Path(db_path) if db_path else default_finrisk_db()
        self.path = db.parent / "finrisk.lock"
        self.fd: Optional[int] = None

    def __enter__(self) -> "finrisk_lock":
        import fcntl
        os.makedirs(self.path.parent, exist_ok=True)
        self.fd = os.open(str(self.path), os.O_RDWR | os.O_CREAT)
        try:
            fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            os.write(self.fd, f"{os.getpid()}\n".encode())
        except OSError:
            os.close(self.fd)
            self.fd = None
        return self

    def __exit__(self, *exc: Any) -> None:
        if self.fd is not None:
            import fcntl
            try:
                fcntl.flock(self.fd, fcntl.LOCK_UN)
            except OSError:
                pass
            os.close(self.fd)
            self.fd = None

    def acquired(self) -> bool:
        return self.fd is not None
