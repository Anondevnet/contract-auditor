"""Phase 17 — live monitoring of newly deployed contracts.

Polls one EVM chain for contract-creation transactions since a persisted
block cursor, fetches verified source (read-only Etherscan V2 GET calls),
runs the existing local analysis pipeline, records each scan to scan
history and raises local alerts for findings at/above a severity threshold.

Ground rules (PLAN.md):
* Keys come from the environment only (``ETHERSCAN_API_KEY``; optional
  ``AUDITOR_MONITOR_RPC_URL``). They are never printed, logged or written:
  every error string passes through :func:`_redact`.
* Network is read-only. Etherscan is GET-only. A JSON-RPC endpoint needs
  HTTP POST by protocol, so only an allow-list of read-only ``eth_*``
  methods may be sent.
* Alerts go to a local JSONL file and the console. A webhook is used only
  when explicitly configured and must point at a loopback host.
* Findings still pass ``validated_findings`` — no FACT evidence, no finding.
* Discovery covers top-level creations (``tx.to is null``). Contracts
  deployed by factories inside another transaction are NOT discovered.
"""

from __future__ import annotations

import hashlib
import json
import os
import signal
import sqlite3
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence

import logging
import re

log = logging.getLogger("contract_auditor.monitor")

# Worker supervision (P1 step 1): per-worker lock + self-heartbeat. The
# supervisor module is stdlib-only and never imports monitor — no cycle.
from .supervisor import (LockHeld, WorkerLock, record_worker_heartbeat,  # noqa: E402
                         worker_lock_path)

_PROJECT_ROOT = Path(__file__).resolve().parent.parent

NETWORKS: Dict[str, int] = {"ethereum": 1}
ETHERSCAN_V2 = "https://api.etherscan.io/v2/api"
RPC_ENV = "AUDITOR_MONITOR_RPC_URL"
READ_ONLY_RPC = frozenset({"eth_blockNumber", "eth_getBlockByNumber", "eth_getTransactionReceipt",
                           # Phase 19: balances for value-at-risk (read-only)
                           "eth_getBalance", "eth_call",
                           # Phase 20: hunt (code presence, large-transfer discovery; read-only)
                           "eth_getCode", "eth_getLogs",
                           # Phase 21: proxy resolution (read-only)
                           "eth_getStorageAt",
                           # Optional local/provider trace for factory CREATE / CREATE2 calls.
                           "debug_traceBlockByNumber"})
_ERC20_BALANCE_OF = "0x70a08231"
SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL")
_LOOPBACK = ("127.0.0.1", "localhost", "::1")
# P0 diagnostics: non-secret provider families for refusal logs. Matches on the
# hostname suffix only; never exposes the host, scheme, path, or key material.
_PROVIDER_CATEGORIES = (("alchemy.com", "alchemy"), ("infura.io", "infura"),
                        ("quiknode.pro", "quiknode"), ("publicnode.com", "publicnode"),
                        ("ankr.com", "ankr"), ("drpc.org", "drpc"),
                        ("llamarpc.com", "llamarpc"))


class MonitorError(RuntimeError):
    """Configuration or upstream failure surfaced to the CLI."""


class TransientError(MonitorError):
    """Retryable: rate limit, 5xx, connection error."""


_SECRETS: List[str] = []

# Pattern-mask RPC provider URLs / path keys even when the full URL was not registered.
# Alchemy: https://eth-mainnet.g.alchemy.com/v2/<KEY> -> .../v2/***
_RPC_V2_KEY = re.compile(r"(https?://\S+/v2/)([A-Za-z0-9_-]{8,})")
_RPC_QUERY_KEY = re.compile(
    r"([?&](?:api[_-]?key|apikey|key)=)([^&\s]+)",
    re.I,
)
_RPC_LONG_PATH = re.compile(
    r"(https?://[^/\s]+)/(?:v3/)?([A-Za-z0-9_-]{32,})"
)
_V2_KEY_ONLY = re.compile(r"/v2/([A-Za-z0-9_-]{8,})")
_QUERY_KEY_ONLY = re.compile(
    r"[?&](?:api[_-]?key|apikey|key)=([^&\s]+)",
    re.I,
)


def redact_rpc_url(url: str) -> str:
    """Return a display-safe RPC URL (host kept; /v2/ keys and query secrets masked)."""
    return _redact(url)


def _register_secret(value: Optional[str]) -> None:
    if not value:
        return
    s = str(value)
    if s and s not in _SECRETS:
        _SECRETS.append(s)
    m = _V2_KEY_ONLY.search(s)
    if m and m.group(1) not in _SECRETS:
        _SECRETS.append(m.group(1))
    m2 = _QUERY_KEY_ONLY.search(s)
    if m2 and m2.group(1) not in _SECRETS:
        _SECRETS.append(m2.group(1))


def _redact(text: Any) -> str:
    """Strip registered secrets and provider URL path keys from any log/error string."""
    out = str(text)
    for s in list(_SECRETS):
        if s and len(s) >= 4:
            out = out.replace(s, "***")
    out = _RPC_V2_KEY.sub(r"\1***", out)
    out = _RPC_QUERY_KEY.sub(r"\1***", out)
    out = _RPC_LONG_PATH.sub(r"\1/***", out)
    return out


_HTTP_ERROR_BODY_MAX_BYTES = 4096


def _http_error_detail(exc: Any) -> str:
    """Bounded, sanitized reason for a provider 4xx (approved P2-diag fix).

    Reads the HTTPError response body once (single bounded read), prefers a
    parsed JSON-RPC error code+message, otherwise a sanitized body snippet,
    and returns ``no body`` when nothing is available. Never includes the
    request URL or headers; ``_redact`` masks registered secrets and provider
    key-shaped material. Read/parsing failures never raise, so the caller's
    original HTTP status is never masked.
    """
    raw = b""
    try:
        if getattr(exc, "fp", None) is not None:
            raw = exc.read(_HTTP_ERROR_BODY_MAX_BYTES) or b""
    except Exception:
        raw = b""
    try:
        exc.close()
    except Exception:
        pass
    text = " ".join(raw.decode("utf-8", "ignore").split())[:200]
    raw_detail = ""
    if text:
        try:
            obj = json.loads(text)
        except ValueError:
            obj = None
        if isinstance(obj, dict) and isinstance(obj.get("error"), dict):
            err = obj["error"]
            code = str(err.get("code", "")).strip()
            message = " ".join(str(err.get("message", "")).split())
            if code and message:
                raw_detail = f"code={code} {message}"
            elif code:
                raw_detail = f"code={code}"
            elif message:
                raw_detail = message
            else:
                raw_detail = text
        else:
            raw_detail = text
    return _redact(raw_detail)[:160] if raw_detail else "no body"


def _websocket_url(rpc_url: Optional[str], configured: Optional[str] = None) -> Optional[str]:
    """Choose a secure WebSocket endpoint, deriving it from HTTPS when possible.

    Plain ``ws://`` is accepted only for loopback RPCs. A public HTTP provider is
    never silently upgraded to an unencrypted WebSocket connection.
    """
    raw = (configured or os.environ.get("AUDITOR_MONITOR_WS_URL") or "").strip()
    if not raw and rpc_url:
        parsed = urllib.parse.urlparse(rpc_url)
        if parsed.scheme == "https":
            raw = urllib.parse.urlunparse(parsed._replace(scheme="wss"))
        elif parsed.scheme == "http" and (parsed.hostname or "").lower() in _LOOPBACK:
            raw = urllib.parse.urlunparse(parsed._replace(scheme="ws"))
    if not raw:
        return None
    parsed = urllib.parse.urlparse(raw)
    if parsed.scheme not in ("wss", "ws") or not parsed.hostname:
        raise MonitorError("AUDITOR_MONITOR_WS_URL must be a ws(s) endpoint")
    if parsed.scheme == "ws" and parsed.hostname.lower() not in _LOOPBACK:
        raise MonitorError("unencrypted ws:// is allowed only for a loopback endpoint")
    return raw

def _now() -> float:
    return time.time()


def _iso(ts: Optional[float] = None) -> str:
    return datetime.fromtimestamp(ts if ts is not None else _now(), tz=timezone.utc).isoformat()


def default_monitor_db_path() -> Path:
    override = os.environ.get("AUDITOR_MONITOR_DB", "").strip()
    return Path(override) if override else _PROJECT_ROOT / "monitor_state.db"


def default_cache_dir() -> Path:
    """Phase 18: local, git-ignored cache of fetched verified source."""
    override = os.environ.get("AUDITOR_MONITOR_CACHE", "").strip()
    return Path(override) if override else _PROJECT_ROOT / "monitor_cache"


def default_alerts_path() -> Path:
    override = os.environ.get("AUDITOR_MONITOR_ALERTS", "").strip()
    return Path(override) if override else _PROJECT_ROOT / "reports" / "monitor_alerts.jsonl"


def severity_at_least(value: str, threshold: str) -> bool:
    v = str(value).upper()
    t = str(threshold).upper()
    if v not in SEVERITIES or t not in SEVERITIES:
        return False
    return SEVERITIES.index(v) <= SEVERITIES.index(t)


# ---------------------------------------------------------------------------
# Persistent state
# ---------------------------------------------------------------------------

class MonitorStore:
    """Cursor, dedupe set and retry queue. Schema is idempotent."""

    def __init__(self, db_path: Path):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(self.db_path))
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS monitor_cursor (
                network TEXT PRIMARY KEY, last_block INTEGER NOT NULL, updated_at TEXT);
            CREATE TABLE IF NOT EXISTS monitor_seen (
                network TEXT NOT NULL, address TEXT NOT NULL, content_hash TEXT NOT NULL,
                scan_id TEXT, findings INTEGER, scanned_at TEXT,
                PRIMARY KEY (network, address, content_hash));
            CREATE TABLE IF NOT EXISTS monitor_queue (
                network TEXT NOT NULL, address TEXT NOT NULL, tx_hash TEXT, block INTEGER,
                attempts INTEGER NOT NULL DEFAULT 0, next_attempt_at REAL NOT NULL DEFAULT 0,
                status TEXT NOT NULL DEFAULT 'pending', last_error TEXT, updated_at TEXT,
                PRIMARY KEY (network, address));
            CREATE TABLE IF NOT EXISTS monitor_block_headers (
                network TEXT NOT NULL, block INTEGER NOT NULL, hash TEXT NOT NULL,
                parent_hash TEXT, checked_at REAL NOT NULL,
                PRIMARY KEY (network, block));
            CREATE TABLE IF NOT EXISTS monitor_reorgs (
                id INTEGER PRIMARY KEY AUTOINCREMENT, network TEXT NOT NULL,
                detected_at REAL NOT NULL, old_cursor INTEGER NOT NULL,
                common_ancestor INTEGER NOT NULL, old_hash TEXT, new_hash TEXT);
            """
        )
        self.conn.commit()
        self._migrate()

    SCHEMA_VERSION = 10

    def _migrate(self) -> None:
        """Phase 18 additive migration (idempotent; Phase 17 DBs upgrade in place)."""
        self.conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS monitor_scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                network TEXT NOT NULL, address TEXT NOT NULL, tx_hash TEXT, block INTEGER,
                content_hash TEXT, contract_name TEXT, compiler TEXT,
                file_count INTEGER, line_count INTEGER, source_bytes INTEGER, cache_dir TEXT,
                stage TEXT NOT NULL, status TEXT NOT NULL,
                started_at REAL NOT NULL, stage_at REAL, finished_at REAL, duration_s REAL,
                scan_id TEXT, findings INTEGER, severity_counts TEXT, error TEXT);
            CREATE INDEX IF NOT EXISTS ix_monitor_scans_finished ON monitor_scans(finished_at);
            CREATE INDEX IF NOT EXISTS ix_monitor_scans_status ON monitor_scans(status);
            CREATE TABLE IF NOT EXISTS monitor_stage_events (
                scan_row INTEGER NOT NULL, stage TEXT NOT NULL, at REAL NOT NULL);
            CREATE INDEX IF NOT EXISTS ix_monitor_stage_row ON monitor_stage_events(scan_row);
            CREATE TABLE IF NOT EXISTS monitor_polls (
                id INTEGER PRIMARY KEY AUTOINCREMENT, network TEXT NOT NULL, at REAL NOT NULL,
                blocks INTEGER, enqueued INTEGER, processed INTEGER, alerts INTEGER, error TEXT);
            CREATE INDEX IF NOT EXISTS ix_monitor_polls_at ON monitor_polls(at);
            """
        )
        cols = {r[1] for r in self.conn.execute("PRAGMA table_info(monitor_seen)")}
        if "contract_name" not in cols:
            self.conn.execute("ALTER TABLE monitor_seen ADD COLUMN contract_name TEXT")
        # Phase 18.1 (schema 3): honest completion verdict + legacy re-evaluation.
        scols = {r[1] for r in self.conn.execute("PRAGMA table_info(monitor_scans)")}
        for col, decl in (("analysis_complete", "INTEGER"), ("needs_rescan", "INTEGER NOT NULL DEFAULT 0"),
                          ("solc_version", "TEXT"), ("compile_settings", "TEXT"),
                          ("superseded_at", "REAL"), ("chain_canonical", "INTEGER NOT NULL DEFAULT 1"),
                          ("snapshot_block", "INTEGER"), ("snapshot_finality", "TEXT"),
                          ("source_verification", "TEXT")):
            if col not in scols:
                self.conn.execute(f"ALTER TABLE monitor_scans ADD COLUMN {col} {decl}")
        qcols = {r[1] for r in self.conn.execute("PRAGMA table_info(monitor_queue)")}
        for col, decl in (("block_hash", "TEXT"), ("discovery_method", "TEXT")):
            if col not in qcols:
                self.conn.execute(f"ALTER TABLE monitor_queue ADD COLUMN {col} {decl}")
        # Rows written before 18.1 never recorded whether Slither completed
        # (compile failures were stored as done/0 findings): flag them.
        self.conn.execute(
            "UPDATE monitor_scans SET needs_rescan=1 WHERE status='done' AND analysis_complete IS NULL "
            "AND superseded_at IS NULL")
        # Phase 19 (schema 4): value-at-risk (rough estimates) + per-finding triage/loss rows.
        scols = {r[1] for r in self.conn.execute("PRAGMA table_info(monitor_scans)")}
        for col, decl in (("tvl_usd", "REAL"), ("est_max_loss_usd", "REAL"), ("risk_score", "REAL"),
                          ("price_as_of", "REAL"), ("value_json", "TEXT"),
                          ("suppressed_count", "INTEGER NOT NULL DEFAULT 0"),
                          ("user_funds_at_risk", "INTEGER NOT NULL DEFAULT 0")):
            if col not in scols:
                self.conn.execute(f"ALTER TABLE monitor_scans ADD COLUMN {col} {decl}")
        self.conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS monitor_findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT, scan_row INTEGER NOT NULL,
                network TEXT NOT NULL, address TEXT NOT NULL, finding_id TEXT, title TEXT,
                detector TEXT, vuln_class TEXT, category TEXT, severity TEXT, original_severity TEXT,
                confidence TEXT, contract TEXT, function TEXT, file TEXT, lines TEXT,
                suppressed INTEGER NOT NULL DEFAULT 0, triage_reason TEXT, triage_rule TEXT,
                triage_detail TEXT, est_loss_usd REAL, est_loss_low_usd REAL, est_loss_high_usd REAL,
                exposure_factor REAL, weighted_score REAL, estimate_json TEXT, finding_json TEXT,
                impact_class TEXT NOT NULL DEFAULT 'unknown',
                impact_status TEXT NOT NULL DEFAULT 'unresolved');
            CREATE INDEX IF NOT EXISTS ix_monitor_findings_row ON monitor_findings(scan_row);
            CREATE INDEX IF NOT EXISTS ix_monitor_findings_score ON monitor_findings(weighted_score);
            """
        )
        fcols = {r[1] for r in self.conn.execute("PRAGMA table_info(monitor_findings)")}
        for col, decl in (("impact_class", "TEXT NOT NULL DEFAULT 'unknown'"),
                          ("impact_status", "TEXT NOT NULL DEFAULT 'unresolved'"),
                          ("balance_usd", "REAL")):
            if col not in fcols:
                self.conn.execute(f"ALTER TABLE monitor_findings ADD COLUMN {col} {decl}")
        self.conn.executescript(
            """
            DROP VIEW IF EXISTS monitor_finding_labels;  -- a view holds no data; redefined below
            CREATE VIEW monitor_finding_labels AS
                SELECT id, network, address, title, severity, suppressed,
                       CASE WHEN suppressed=1 AND triage_rule='live-state-disproof' THEN 'disproved_current_state'
                            WHEN suppressed=1 THEN 'false_positive'
                            WHEN confirmed_exploitable=1 THEN 'confirmed_exploitable'
                            ELSE 'unresolved' END AS verdict_label,
                       CASE WHEN suppressed=1 THEN COALESCE(NULLIF(TRIM(COALESCE(triage_reason,'') ||
                            CASE WHEN triage_detail IS NOT NULL THEN ' — ' || triage_detail ELSE '' END), ''),
                            'suppressed by triage rule (no reason recorded)') END AS dismissal_reason,
                       impact_class, impact_status
                FROM monitor_findings;
            """
        )
        # Phase 20 (schema 5): hunt candidates + scan origin (monitor | hunt).
        scols = {r[1] for r in self.conn.execute("PRAGMA table_info(monitor_scans)")}
        if "origin" not in scols:
            self.conn.execute("ALTER TABLE monitor_scans ADD COLUMN origin TEXT")
        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS hunt_candidates (
                network TEXT NOT NULL, address TEXT NOT NULL,
                protocol TEXT, slug TEXT, category TEXT, category_group TEXT,
                source TEXT, sources_json TEXT,
                llama_tvl_usd REAL, onchain_tvl_usd REAL, tvl_measured_at REAL, value_json TEXT,
                listed_at REAL, audits TEXT, forked_from TEXT, blue_chip INTEGER NOT NULL DEFAULT 0,
                has_code INTEGER, verified INTEGER, source_provider TEXT, contract_name TEXT, language TEXT,
                is_proxy INTEGER, implementation TEXT,
                priority_score REAL, score_reasons TEXT, signals_json TEXT,
                status TEXT NOT NULL DEFAULT 'new', last_error TEXT,
                last_scan_row INTEGER, last_scan_id TEXT, last_content_hash TEXT,
                findings INTEGER, est_max_loss_usd REAL,
                discovered_at REAL, updated_at REAL, scanned_at REAL,
                last_attempt_at REAL, scan_attempt_at REAL,
                source_attempts INTEGER NOT NULL DEFAULT 0, source_retry_at REAL,
                PRIMARY KEY (network, address))
            """)
        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS hunt_runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT, network TEXT NOT NULL, at REAL NOT NULL,
                refreshed INTEGER, discovered INTEGER, measured INTEGER, scanned INTEGER,
                error TEXT, stats_json TEXT)
            """)
        # Bring an older/partial hunt_candidates up to the Phase-20+21 column set.
        hcols = {r[1] for r in self.conn.execute("PRAGMA table_info(hunt_candidates)")}
        for col, decl in (
            ("protocol", "TEXT"), ("slug", "TEXT"), ("category", "TEXT"), ("category_group", "TEXT"),
            ("source", "TEXT"), ("sources_json", "TEXT"),
            ("llama_tvl_usd", "REAL"), ("onchain_tvl_usd", "REAL"), ("tvl_measured_at", "REAL"),
            ("value_json", "TEXT"), ("listed_at", "REAL"), ("audits", "TEXT"), ("forked_from", "TEXT"),
            ("blue_chip", "INTEGER NOT NULL DEFAULT 0"), ("has_code", "INTEGER"), ("verified", "INTEGER"),
            ("source_provider", "TEXT"), ("contract_name", "TEXT"), ("language", "TEXT"),
            ("is_proxy", "INTEGER"), ("implementation", "TEXT"),
            ("last_proxy_checked_at", "REAL"),
            ("priority_score", "REAL"), ("score_reasons", "TEXT"), ("signals_json", "TEXT"),
            ("status", "TEXT NOT NULL DEFAULT 'new'"), ("last_error", "TEXT"),
            ("last_scan_row", "INTEGER"), ("last_scan_id", "TEXT"), ("last_content_hash", "TEXT"),
            ("findings", "INTEGER"), ("est_max_loss_usd", "REAL"),
            ("discovered_at", "REAL"), ("updated_at", "REAL"), ("scanned_at", "REAL"),
            ("last_attempt_at", "REAL"), ("scan_attempt_at", "REAL"),
            ("source_attempts", "INTEGER NOT NULL DEFAULT 0"),
            ("source_retry_at", "REAL"),
            # Phase 21
            ("proxy_kind", "TEXT"), ("holder_value_usd", "REAL"), ("holder_role", "TEXT"),
            ("discovery_json", "TEXT"), ("scan_address", "TEXT"),
            # Discovery skew: ERC-20 Approval signal on the candidate (spender)
            ("has_user_approvals", "INTEGER"), ("approval_usd", "REAL"),
        ):
            if col not in hcols:
                self.conn.execute(f"ALTER TABLE hunt_candidates ADD COLUMN {col} {decl}")
        self.conn.execute(
            "CREATE INDEX IF NOT EXISTS ix_hunt_candidates_score ON hunt_candidates(priority_score)")
        self.conn.execute(
            "CREATE INDEX IF NOT EXISTS ix_hunt_candidates_status ON hunt_candidates(status)")
        self.conn.execute("CREATE INDEX IF NOT EXISTS ix_hunt_runs_at ON hunt_runs(at)")
        # Phase 22 (schema 7): fork simulation results.
        try:
            from auditor.simulate import ensure_schema_v7
            ensure_schema_v7(self.conn)
            try:
                from auditor.exploitable import ensure_schema as _ensure_exploitable
                _ensure_exploitable(Path(self.db_path))
            except Exception:  # noqa: BLE001
                pass
        except Exception:
            # Keep migration resilient if simulate is unavailable.
            pass
        try:
            from auditor.watch import ensure_watch_schema
            ensure_watch_schema(self.conn)
        except Exception:
            pass
        self.conn.execute(f"PRAGMA user_version = {self.SCHEMA_VERSION}")
        self.conn.commit()

    # -- Phase 18: scan lifecycle --------------------------------------------
    def start_scan(self, network: str, address: str, tx_hash: Optional[str], block: Optional[int],
                   now: float, origin: str = "monitor", snapshot_block: Optional[int] = None,
                   snapshot_finality: Optional[str] = None) -> int:
        cur = self.conn.execute(
            "INSERT INTO monitor_scans(network,address,tx_hash,block,stage,status,started_at,stage_at,origin,"
            "snapshot_block,snapshot_finality) VALUES(?,?,?,?, 'fetching','running',?,?,?,?,?)",
            (network, address.lower(), tx_hash, block, now, now, origin,
             snapshot_block, snapshot_finality))
        rid = int(cur.lastrowid)
        self.conn.execute("INSERT INTO monitor_stage_events VALUES(?,?,?)", (rid, "fetching", now))
        self.conn.commit()
        return rid

    def set_stage(self, rid: int, stage: str, now: float) -> None:
        self.conn.execute("UPDATE monitor_scans SET stage=?, stage_at=? WHERE id=?", (stage, now, rid))
        self.conn.execute("INSERT INTO monitor_stage_events VALUES(?,?,?)", (rid, stage, now))
        self.conn.commit()

    _META = ("content_hash", "contract_name", "compiler", "file_count", "line_count",
             "source_bytes", "cache_dir", "solc_version", "compile_settings", "source_verification")

    def set_meta(self, rid: int, **meta: Any) -> None:
        keys = [k for k in meta if k in self._META]
        if keys:
            self.conn.execute(
                f"UPDATE monitor_scans SET {', '.join(k + '=?' for k in keys)} WHERE id=?",
                [meta[k] for k in keys] + [rid])
            self.conn.commit()

    def finish_scan(self, rid: int, status: str, now: float, scan_id: Optional[str] = None,
                    findings: Optional[int] = None,
                    severity_counts: Optional[Dict[str, int]] = None,
                    error: Optional[str] = None, analysis_complete: Optional[bool] = None) -> None:
        row = self.conn.execute("SELECT started_at FROM monitor_scans WHERE id=?", (rid,)).fetchone()
        duration = (now - float(row[0])) if row else None
        self.conn.execute(
            "UPDATE monitor_scans SET stage='done', status=?, stage_at=?, finished_at=?, duration_s=?, "
            "scan_id=?, findings=?, severity_counts=?, error=?, analysis_complete=? WHERE id=?",
            (status, now, now, duration, scan_id, findings,
             json.dumps(severity_counts or {}, sort_keys=True),
             _redact(error)[:600] if error else None,
             None if analysis_complete is None else int(bool(analysis_complete)), rid))
        self.conn.execute("INSERT INTO monitor_stage_events VALUES(?,?,?)", (rid, "done", now))
        self.conn.commit()

    def set_value(self, rid: int, summary: Optional[Dict[str, Any]], value: Optional[Dict[str, Any]],
                  suppressed: int = 0) -> None:
        """Phase 19: contract-level value-at-risk roll-up (rough estimate)."""
        summary = summary or {}
        self.conn.execute(
            "UPDATE monitor_scans SET tvl_usd=?, est_max_loss_usd=?, risk_score=?, price_as_of=?, "
            "value_json=?, suppressed_count=?, user_funds_at_risk=? WHERE id=?",
            (summary.get("tvl_usd"), summary.get("est_max_loss_usd"), summary.get("risk_score"),
             summary.get("price_as_of"),
             json.dumps({"summary": summary, "value": value}, sort_keys=True, default=str) if (summary or value) else None,
             int(suppressed), int(bool(summary.get("user_funds_at_risk"))), rid))
        self.conn.commit()

    def add_findings(self, rid: int, network: str, address: str, rows: Sequence[Dict[str, Any]]) -> None:
        cols = ("finding_id", "title", "detector", "vuln_class", "category", "severity", "original_severity",
                "confidence", "contract", "function", "file", "lines", "suppressed", "triage_reason",
                "triage_rule", "triage_detail", "est_loss_usd", "est_loss_low_usd", "est_loss_high_usd",
                "exposure_factor", "weighted_score", "estimate_json", "finding_json",
                "impact_class", "impact_status", "balance_usd")
        self.conn.execute("DELETE FROM monitor_findings WHERE scan_row=?", (rid,))
        for r in rows:
            self.conn.execute(
                f"INSERT INTO monitor_findings(scan_row,network,address,{','.join(cols)}) "
                f"VALUES(?,?,?,{','.join('?' * len(cols))})",
                [rid, network, address.lower()] + [r.get(c) for c in cols])
        self.conn.commit()

    def interrupt_stale(self, now: float, origin: Optional[str] = None) -> int:
        """Mark rows left 'running' by a dead process. With *origin*, only that
        process kind's rows (a hunt run must not interrupt the live monitor)."""
        if origin is None:
            cur = self.conn.execute(
                "UPDATE monitor_scans SET status='interrupted', stage='done', finished_at=? "
                "WHERE status='running'", (now,))
        else:
            cur = self.conn.execute(
                "UPDATE monitor_scans SET status='interrupted', stage='done', finished_at=? "
                "WHERE status='running' AND COALESCE(origin,'monitor')=?", (now, origin))
        self.conn.commit()
        return cur.rowcount

    def record_poll(self, network: str, now: float, blocks: int, enqueued: int,
                    processed: int, alerts: int, error: Optional[str] = None) -> None:
        self.conn.execute(
            "INSERT INTO monitor_polls(network,at,blocks,enqueued,processed,alerts,error) VALUES(?,?,?,?,?,?,?)",
            (network, now, blocks, enqueued, processed, alerts, _redact(error)[:300] if error else None))
        self.conn.commit()

    def rescan_candidates(self, network: str, rows: Optional[Sequence[int]] = None) -> List[sqlite3.Row]:
        """Rows to re-evaluate: legacy unverified-completion rows, incomplete, failed."""
        if rows:
            marks = ",".join("?" * len(rows))
            return self.conn.execute(
                f"SELECT * FROM monitor_scans WHERE network=? AND id IN ({marks}) ORDER BY id",
                [network, *[int(r) for r in rows]]).fetchall()
        return self.conn.execute(
            "SELECT * FROM monitor_scans WHERE network=? AND superseded_at IS NULL AND "
            "(needs_rescan=1 OR status IN ('incomplete','failed')) ORDER BY id", (network,)).fetchall()

    def requeue_for_rescan(self, row: sqlite3.Row, now: float) -> None:
        net, addr = row["network"], row["address"]
        if row["content_hash"]:
            self.conn.execute("DELETE FROM monitor_seen WHERE network=? AND address=? AND content_hash=?",
                              (net, addr, row["content_hash"]))
        self.conn.execute(
            "INSERT INTO monitor_queue(network,address,tx_hash,block,updated_at) VALUES(?,?,?,?,?) "
            "ON CONFLICT(network,address) DO UPDATE SET status='pending', attempts=0, next_attempt_at=0, "
            "last_error='requeued for rescan', updated_at=excluded.updated_at",
            (net, addr, row["tx_hash"] or "", row["block"] or 0, _iso(now)))
        self.conn.execute("UPDATE monitor_scans SET needs_rescan=0, superseded_at=? WHERE id=?", (now, row["id"]))
        self.conn.commit()

    def get_cursor(self, network: str) -> Optional[int]:
        row = self.conn.execute(
            "SELECT last_block FROM monitor_cursor WHERE network=?", (network,)).fetchone()
        return int(row[0]) if row else None

    def set_cursor(self, network: str, block: int) -> None:
        """Persist a cursor when the provider cannot return canonical headers."""
        self.conn.execute(
            "INSERT INTO monitor_cursor(network,last_block,updated_at) VALUES(?,?,?) "
            "ON CONFLICT(network) DO UPDATE SET last_block=excluded.last_block,updated_at=excluded.updated_at",
            (network, int(block), _iso()),
        )
        self.conn.commit()

    def block_hash(self, network: str, block: int) -> Optional[str]:
        row = self.conn.execute(
            "SELECT hash FROM monitor_block_headers WHERE network=? AND block=?",
            (network, int(block))).fetchone()
        return str(row[0]) if row else None

    def record_block(self, network: str, block: int, block_hash: Optional[str],
                     parent_hash: Optional[str], *, retain: int = 128) -> None:
        """Atomically persist a canonical header and advance the durable cursor."""
        self.conn.execute(
            "INSERT INTO monitor_cursor(network,last_block,updated_at) VALUES(?,?,?) "
            "ON CONFLICT(network) DO UPDATE SET last_block=excluded.last_block, updated_at=excluded.updated_at",
            (network, int(block), _iso()))
        if block_hash:
            self.conn.execute(
                "INSERT OR REPLACE INTO monitor_block_headers(network,block,hash,parent_hash,checked_at) "
                "VALUES(?,?,?,?,?)",
                (network, int(block), str(block_hash).lower(),
                 str(parent_hash).lower() if parent_hash else None, _now()))
            self.conn.execute(
                "DELETE FROM monitor_block_headers WHERE network=? AND block<?",
                (network, max(0, int(block) - max(int(retain), 2))))
        self.conn.commit()

    def record_reorg(self, network: str, old_cursor: int, common_ancestor: int,
                     old_hash: Optional[str], new_hash: Optional[str], now: float) -> None:
        """Mark discoveries from the orphaned branch and rewind for backfill."""
        self.conn.execute(
            "INSERT INTO monitor_reorgs(network,detected_at,old_cursor,common_ancestor,old_hash,new_hash) "
            "VALUES(?,?,?,?,?,?)",
            (network, float(now), int(old_cursor), int(common_ancestor), old_hash, new_hash))
        self.conn.execute(
            "UPDATE monitor_queue SET status='orphaned', updated_at=?, last_error='block removed by reorg' "
            "WHERE network=? AND block>? AND discovery_method IS NOT NULL "
            "AND status IN ('pending','unverified','done','failed')",
            (_iso(now), network, int(common_ancestor)))
        self.conn.execute(
            "UPDATE monitor_scans SET status='orphaned', stage='done', finished_at=?, "
            "superseded_at=?, chain_canonical=0 WHERE network=? AND origin='monitor' "
            "AND block>? AND status!='running' AND chain_canonical=1",
            (float(now), float(now), network, int(common_ancestor)))
        self.conn.execute(
            "DELETE FROM monitor_block_headers WHERE network=? AND block>?",
            (network, int(common_ancestor)))
        self.conn.execute(
            "UPDATE monitor_cursor SET last_block=?, updated_at=? WHERE network=?",
            (int(common_ancestor), _iso(now), network))
        self.conn.commit()

    def enqueue(self, network: str, address: str, tx_hash: str, block: int,
                block_hash: Optional[str] = None, discovery_method: str = "block_creation") -> bool:
        existing = self.conn.execute(
            "SELECT status FROM monitor_queue WHERE network=? AND address=?",
            (network, address.lower())).fetchone()
        cur = self.conn.execute(
            "INSERT INTO monitor_queue(network,address,tx_hash,block,updated_at,block_hash,discovery_method) "
            "VALUES(?,?,?,?,?,?,?) ON CONFLICT(network,address) DO UPDATE SET "
            "tx_hash=CASE WHEN monitor_queue.status='orphaned' THEN excluded.tx_hash ELSE monitor_queue.tx_hash END, "
            "block=CASE WHEN monitor_queue.status='orphaned' THEN excluded.block ELSE monitor_queue.block END, "
            "block_hash=CASE WHEN monitor_queue.status='orphaned' THEN excluded.block_hash ELSE monitor_queue.block_hash END, "
            "discovery_method=COALESCE(monitor_queue.discovery_method,excluded.discovery_method), "
            "status=CASE WHEN monitor_queue.status='orphaned' THEN 'pending' ELSE monitor_queue.status END, "
            "attempts=CASE WHEN monitor_queue.status='orphaned' THEN 0 ELSE monitor_queue.attempts END, "
            "next_attempt_at=CASE WHEN monitor_queue.status='orphaned' THEN 0 ELSE monitor_queue.next_attempt_at END, "
            "last_error=CASE WHEN monitor_queue.status='orphaned' THEN NULL ELSE monitor_queue.last_error END, "
            "updated_at=excluded.updated_at",
            (network, address.lower(), tx_hash, int(block), _iso(), block_hash, discovery_method))
        self.conn.commit()
        return existing is None or str(existing[0]) == "orphaned"

    def due(self, network: str, limit: int, now: float) -> List[sqlite3.Row]:
        return self.conn.execute(
            "SELECT * FROM monitor_queue WHERE network=? AND status='pending' AND next_attempt_at<=? "
            "ORDER BY block, address LIMIT ?", (network, now, int(limit))).fetchall()

    def requeue_unverified(self, network: str, now: float, *, interval_s: float = 86400,
                           limit: int = 20) -> int:
        """Recheck a bounded number of parked addresses as explorer sources appear later."""
        cutoff = now - max(float(interval_s), 60.0)
        rows = self.conn.execute(
            "SELECT address FROM monitor_queue WHERE network=? AND status='unverified' "
            "AND (updated_at IS NULL OR CAST(strftime('%s',updated_at) AS REAL) <= ?) "
            "ORDER BY updated_at ASC, address ASC LIMIT ?",
            (network, cutoff, max(int(limit), 0))).fetchall()
        if not rows:
            return 0
        self.conn.executemany(
            "UPDATE monitor_queue SET status='pending',attempts=0,next_attempt_at=?,"
            "last_error='scheduled verified-source recheck',updated_at=? "
            "WHERE network=? AND address=? AND status='unverified'",
            [(now, _iso(now), network, str(r[0])) for r in rows])
        self.conn.commit()
        return len(rows)

    def defer(self, network: str, address: str, attempts: int, next_at: float,
              error: str, give_up: bool) -> None:
        self.conn.execute(
            "UPDATE monitor_queue SET attempts=?, next_attempt_at=?, last_error=?, status=?, updated_at=? "
            "WHERE network=? AND address=?",
            (attempts, next_at, _redact(error)[:300], "unverified" if give_up else "pending",
             _iso(), network, address))
        self.conn.commit()

    def finish(self, network: str, address: str, status: str = "done") -> None:
        self.conn.execute(
            "UPDATE monitor_queue SET status=?, updated_at=? WHERE network=? AND address=?",
            (status, _iso(), network, address))
        self.conn.commit()

    def is_seen(self, network: str, address: str, content_hash: str) -> bool:
        return self.conn.execute(
            "SELECT 1 FROM monitor_seen WHERE network=? AND address=? AND content_hash=?",
            (network, address.lower(), content_hash)).fetchone() is not None

    def mark_seen(self, network: str, address: str, content_hash: str,
                  scan_id: Optional[str], findings: int, contract_name: Optional[str] = None) -> None:
        self.conn.execute(
            "INSERT OR IGNORE INTO monitor_seen(network,address,content_hash,scan_id,findings,scanned_at,"
            "contract_name) VALUES(?,?,?,?,?,?,?)",
            (network, address.lower(), content_hash, scan_id, findings, _iso(), contract_name))
        self.conn.commit()

    def queue_counts(self, network: str) -> Dict[str, int]:
        rows = self.conn.execute(
            "SELECT status, COUNT(*) FROM monitor_queue WHERE network=? GROUP BY status",
            (network,)).fetchall()
        return {r[0]: int(r[1]) for r in rows}

    def seen_count(self, network: str) -> int:
        return int(self.conn.execute(
            "SELECT COUNT(*) FROM monitor_seen WHERE network=?", (network,)).fetchone()[0])

    def close(self) -> None:
        self.conn.close()


# ---------------------------------------------------------------------------
# Network client (read-only, rate limited, backoff)
# ---------------------------------------------------------------------------

HttpFn = Callable[[urllib.request.Request, float], bytes]


def _default_http(req: urllib.request.Request, timeout: float) -> bytes:
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - fixed https hosts
        return resp.read()


class ChainClient:
    def __init__(self, api_key: str, chain_id: int, rpc_url: Optional[str] = None,
                 ws_url: Optional[str] = None,
                 http: HttpFn = _default_http, sleep: Callable[[float], None] = time.sleep,
                 min_interval: float = 0.25, max_retries: int = 4, backoff_base: float = 1.0,
                 timeout: float = 30.0):
        self.api_key = api_key
        self.chain_id = int(chain_id)
        self.rpc_url = rpc_url or None
        self.ws_url = _websocket_url(self.rpc_url, ws_url)
        self.trace_internal_creations = (
            bool(self.rpc_url) and os.environ.get("AUDITOR_TRACE_INTERNAL_CREATIONS", "1").strip().lower()
            not in ("0", "false", "no", "off")
        )
        # "ready" is earned only by a successfully parsed trace response (in
        # trace_contract_creations); init must never advertise it in advance.
        self.trace_status = "unverified" if self.trace_internal_creations else "disabled"
        self.trace_error: Optional[str] = None
        self._state_block_tag = "latest"
        self._state_snapshot_block: Optional[int] = None
        self._state_snapshot_finality = "latest"
        self.http = http
        self.sleep = sleep
        self.min_interval = float(min_interval)
        self.max_retries = int(max_retries)
        self.backoff_base = float(backoff_base)
        self.timeout = timeout
        self._last = 0.0
        _register_secret(api_key)
        _register_secret(rpc_url)
        _register_secret(self.ws_url)

    # -- transport --------------------------------------------------------
    def _throttle(self) -> None:
        wait = self.min_interval - (time.monotonic() - self._last)
        if wait > 0:
            self.sleep(wait)
        self._last = time.monotonic()

    def _request(self, req: urllib.request.Request) -> Any:
        delay = self.backoff_base
        last_err: Exception = TransientError("no attempt made")
        for attempt in range(self.max_retries + 1):
            self._throttle()
            try:
                body = self.http(req, self.timeout)
                data = json.loads(body.decode("utf-8") if isinstance(body, bytes) else body)
                msg = str(data.get("result", "")) + str(data.get("message", "")) if isinstance(data, dict) else ""
                if isinstance(data, dict) and data.get("status") == "0" and "rate limit" in msg.lower():
                    raise TransientError("rate limited")
                return data
            except urllib.error.HTTPError as e:
                if e.code == 429 or e.code >= 500:
                    last_err = TransientError(f"HTTP {e.code}")
                else:
                    raise MonitorError(f"HTTP {e.code}: {_http_error_detail(e)}") from None
            except (urllib.error.URLError, TimeoutError, ConnectionError) as e:
                last_err = TransientError(f"connection error: {_redact(e)}")
            except TransientError as e:
                last_err = e
            except ValueError as e:
                raise MonitorError(f"invalid JSON from upstream: {_redact(e)}") from None
            if attempt < self.max_retries:
                self.sleep(delay)
                delay = min(delay * 2, 60.0)
        raise TransientError(_redact(last_err))

    def _etherscan(self, **params: Any) -> Any:
        q = {"chainid": str(self.chain_id), **{k: str(v) for k, v in params.items()}, "apikey": self.api_key}
        url = f"{ETHERSCAN_V2}?{urllib.parse.urlencode(q)}"
        req = urllib.request.Request(url, headers={"User-Agent": "contract-auditor/monitor"}, method="GET")
        return self._request(req)

    def _rpc(self, method: str, params: list) -> Any:
        if method not in READ_ONLY_RPC:
            raise MonitorError(f"refusing non-read-only RPC method {method}")
        if self.rpc_url:
            payload = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
            req = urllib.request.Request(self.rpc_url, data=payload, method="POST",
                                         headers={"Content-Type": "application/json",
                                                  "User-Agent": "contract-auditor/monitor"})
            data = self._request(req)
        else:
            extra: Dict[str, Any] = {}
            if method == "eth_getBlockByNumber":
                extra = {"tag": params[0], "boolean": "true" if params[1] else "false"}
            elif method == "eth_getTransactionReceipt":
                extra = {"txhash": params[0]}
            elif method == "eth_call":
                extra = {"to": params[0]["to"], "data": params[0]["data"], "tag": params[1]}
            elif method == "eth_getBalance":  # no proxy equivalent: use account/balance instead
                raise MonitorError("eth_getBalance needs an RPC URL")
            elif method == "eth_getCode":
                extra = {"address": params[0], "tag": params[1]}
            elif method == "eth_getStorageAt":
                extra = {"address": params[0], "position": params[1], "tag": params[2]}
            elif method == "eth_getLogs":  # Etherscan logs API (GET)
                flt = params[0]
                q = {"fromBlock": int(flt["fromBlock"], 16), "toBlock": int(flt["toBlock"], 16),
                     "page": 1, "offset": 1000}
                if flt.get("address"):
                    q["address"] = flt["address"]
                topics = flt.get("topics") or []
                if topics:
                    q["topic0"] = topics[0]
                    if len(topics) > 1 and topics[1] is not None:
                        q["topic1"] = topics[1]
                        q["topic0_1_opr"] = "and"
                    if len(topics) > 2 and topics[2] is not None:
                        q["topic2"] = topics[2]
                        q["topic0_2_opr"] = "and"
                data = self._etherscan(module="logs", action="getLogs", **q)
                if isinstance(data, dict) and str(data.get("status")) == "0":
                    msg = str(data.get("message") or "")
                    if "no records" in msg.lower():
                        return []
                    raise TransientError(f"getLogs: {_redact(data.get('result'))[:120]}")
                return (data or {}).get("result") or []
            data = self._etherscan(module="proxy", action=method, **extra)
        if isinstance(data, dict) and "error" in data and data["error"]:
            raise MonitorError(f"RPC error: {_redact(data['error'])}")
        if not isinstance(data, dict) or "result" not in data:
            raise MonitorError("malformed RPC response")
        return data["result"]

    # -- API --------------------------------------------------------------
    def block_number(self) -> int:
        result = self._rpc("eth_blockNumber", [])
        try:
            return int(result, 16)
        except (TypeError, ValueError):
            raise TransientError(f"bad block number: {_redact(result)[:80]}") from None

    def pin_state(self, block: int, finality: str = "numbered") -> Dict[str, Any]:
        """Pin subsequent state reads to one numbered block for a coherent scan."""
        number = max(0, int(block))
        self._state_block_tag = hex(number)
        self._state_snapshot_block = number
        self._state_snapshot_finality = str(finality)
        return {"block": number, "finality": self._state_snapshot_finality}

    def state_snapshot(self) -> Dict[str, Any]:
        """Prefer a safe/finalized RPC head, then pin to the observed head number."""
        if self.rpc_url:
            for tag in ("safe", "finalized"):
                try:
                    header = self._rpc("eth_getBlockByNumber", [tag, False])
                    if isinstance(header, dict) and header.get("number") is not None:
                        number = int(str(header["number"]), 16)
                        return self.pin_state(number, tag)
                except Exception:  # providers vary in support for safe/finalized tags
                    continue
        try:
            return self.pin_state(self.block_number(), "head")
        except Exception:
            self._state_block_tag = "latest"
            self._state_snapshot_block = None
            self._state_snapshot_finality = "latest"
            raise

    def block_header(self, block: int) -> Optional[Dict[str, Any]]:
        """Fetch a compact canonical header for cursor/reorg reconciliation."""
        result = self._rpc("eth_getBlockByNumber", [hex(int(block)), False])
        return result if isinstance(result, dict) else None

    def contract_creations(self, block: int) -> List[Dict[str, Any]]:
        blk = self._rpc("eth_getBlockByNumber", [hex(block), True])
        if not isinstance(blk, dict):
            raise TransientError(f"block {block} unavailable")
        out = []
        for tx in blk.get("transactions") or []:
            if isinstance(tx, dict) and not tx.get("to"):
                rcpt = self._rpc("eth_getTransactionReceipt", [tx.get("hash")])
                addr = (rcpt or {}).get("contractAddress") if isinstance(rcpt, dict) else None
                if addr and str((rcpt or {}).get("status", "0x1")) != "0x0":
                    out.append({"address": addr.lower(), "tx_hash": tx.get("hash"), "block": block,
                                "discovery_method": "top_level_create"})
        return out

    def provider_category(self) -> str:
        """P0 diagnostics: non-secret provider family for refusal log lines.

        Returns a category word only ("alchemy", "other", "local-loopback",
        "none"); never the host, scheme, path, or any credential material.
        Diagnostic-only: nothing in retry, disable, or discovery logic may
        branch on this value.
        """
        if not self.rpc_url:
            return "none"
        host = (urllib.parse.urlparse(self.rpc_url).hostname or "").lower()
        if host in _LOOPBACK:
            return "local-loopback"
        for suffix, name in _PROVIDER_CATEGORIES:
            if host.endswith(suffix):
                return name
        return "other"

    def trace_contract_creations(self, block: int) -> List[Dict[str, Any]]:
        """Discover factory-created CREATE/CREATE2 targets when RPC tracing is available."""
        if not self.trace_internal_creations or not self.rpc_url:
            return []
        try:
            traces = self._rpc("debug_traceBlockByNumber", [hex(int(block)), {"tracer": "callTracer"}])
        except TransientError:
            raise
        except MonitorError as exc:
            # Many public RPC providers intentionally disable debug namespaces.
            # Disable after the first definitive unsupported-method response.
            msg = str(exc).lower()
            if "method not found" in msg or "not available" in msg or "unsupported" in msg:
                self.trace_internal_creations = False
                self.trace_status = "unsupported"
                self.trace_error = type(exc).__name__
                return []
            raise
        if not isinstance(traces, list):
            self.trace_internal_creations = False
            self.trace_status = "unsupported"
            self.trace_error = "unexpected_trace_shape"
            return []
        found: List[Dict[str, Any]] = []

        def walk(call: Any, tx_hash: Optional[str]) -> None:
            if not isinstance(call, dict):
                return
            kind = str(call.get("type") or "").upper()
            if kind in {"CREATE", "CREATE2"} and not call.get("error"):
                created = call.get("to") or call.get("createdAddress")
                result = call.get("result")
                if not created and isinstance(result, dict):
                    created = result.get("address")
                if isinstance(created, str) and len(created) == 42 and created.startswith("0x"):
                    found.append({"address": created.lower(), "tx_hash": tx_hash, "block": int(block),
                                  "discovery_method": "trace_create2" if kind == "CREATE2"
                                  else "trace_create"})
            for child in call.get("calls") or []:
                walk(child, tx_hash)

        for tx in traces:
            if isinstance(tx, dict):
                walk(tx.get("result") or tx, tx.get("txHash") or tx.get("transactionHash"))
        self.trace_status = "ready"
        return found

    # -- Phase 19: balances (read-only) ------------------------------------
    @staticmethod
    def _check_addr(a: str) -> str:
        a = str(a).lower()
        if not (a.startswith("0x") and len(a) == 42 and all(c in "0123456789abcdef" for c in a[2:])):
            raise MonitorError("invalid address")
        return a

    def native_balance(self, address: str) -> int:
        """Wei held by *address* (Etherscan account/balance GET, or eth_getBalance on the RPC)."""
        address = self._check_addr(address)
        if self.rpc_url:
            return int(self._rpc("eth_getBalance", [address, self._state_block_tag]), 16)
        data = self._etherscan(module="account", action="balance", address=address, tag=self._state_block_tag)
        return self._int_result(data)

    def token_balance(self, token: str, address: str) -> int:
        """ERC-20 balanceOf (Etherscan account/tokenbalance GET, or eth_call on the RPC)."""
        token, address = self._check_addr(token), self._check_addr(address)
        if self.rpc_url:
            data = _ERC20_BALANCE_OF + address[2:].rjust(64, "0")
            res = self._rpc("eth_call", [{"to": token, "data": data}, self._state_block_tag])
            return int(res, 16) if res not in (None, "0x", "") else 0
        data = self._etherscan(module="account", action="tokenbalance", contractaddress=token,
                               address=address, tag=self._state_block_tag)
        return self._int_result(data)

    @staticmethod
    def _int_result(data: Any) -> int:
        if not isinstance(data, dict) or str(data.get("status")) != "1":
            raise TransientError(f"balance unavailable: {_redact(str((data or {}).get('result', '')))[:80]}")
        try:
            return int(str(data.get("result")))
        except ValueError:
            raise MonitorError("malformed balance") from None

    def code_size(self, address: str) -> int:
        """Phase 20: deployed bytecode size in bytes (0 = EOA / self-destructed)."""
        code = self.get_code(address)
        return (len(code) - 2) // 2

    def get_code(self, address: str) -> str:
        """Phase 21: raw runtime bytecode (``0x``-prefixed hex)."""
        code = self._rpc("eth_getCode", [self._check_addr(address), self._state_block_tag])
        if not isinstance(code, str) or not code.startswith("0x"):
            raise TransientError("eth_getCode: malformed result")
        return code.lower()

    def storage_at(self, address: str, slot: str) -> str:
        """Phase 21: ``eth_getStorageAt`` (read-only). *slot* is a hex word."""
        slot = str(slot)
        if not slot.startswith("0x"):
            slot = hex(int(slot))
        res = self._rpc("eth_getStorageAt", [self._check_addr(address), slot, self._state_block_tag])
        if not isinstance(res, str) or not res.startswith("0x"):
            raise TransientError("eth_getStorageAt: malformed result")
        return res.lower()

    def call(self, to: str, data: str) -> str:
        """Phase 21: ``eth_call`` (read-only). Returns the raw hex result."""
        data = str(data)
        if not data.startswith("0x"):
            raise MonitorError("call data must be 0x-hex")
        res = self._rpc("eth_call", [{"to": self._check_addr(to), "data": data}, self._state_block_tag])
        if not isinstance(res, str) or not res.startswith("0x"):
            raise TransientError("eth_call: malformed result")
        return res.lower()

    def logs(self, address: Optional[str], topic0: str, from_block: int, to_block: int,
             topics: Optional[Sequence[Optional[str]]] = None) -> List[Dict[str, Any]]:
        """Phase 20/24: event logs — optional *address* (None = any emitter for topic0).

        *topics* overrides the default ``[topic0]`` filter when provided (use
        ``None`` entries for wildcards, e.g. Approval spender = topic2).
        """
        topic_list: List[Any] = list(topics) if topics is not None else [topic0]
        flt: Dict[str, Any] = {"fromBlock": hex(int(from_block)),
                               "toBlock": hex(int(to_block)), "topics": topic_list}
        if address:
            flt["address"] = self._check_addr(address)
        res = self._rpc("eth_getLogs", [flt])
        return [x for x in (res or []) if isinstance(x, dict)]

    def verified_source(self, address: str) -> Optional[Dict[str, Any]]:
        """Return the getsourcecode record, or None when unverified / no API key."""
        if not self.api_key:
            return None  # Phase 20: caller may fall back to Sourcify
        data = self._etherscan(module="contract", action="getsourcecode", address=address)
        result = data.get("result") if isinstance(data, dict) else None
        if data.get("status") != "1" or not isinstance(result, list) or not result:
            if isinstance(result, str) and result and "not verified" not in result.lower():
                # Invalid API key etc.: treat as unavailable (not a retryable defer for hunt)
                if "api key" in result.lower():
                    return None
                raise TransientError(f"getsourcecode: {_redact(result)[:120]}")
            return None
        rec = result[0] if isinstance(result[0], dict) else {}
        return rec if rec.get("SourceCode") else None


class NewHeadSubscription:
    """Persistent JSON-RPC newHeads subscription with bounded reconnects."""

    def __init__(self, url: str, timeout: float = 8.0):
        self.url = url
        self.timeout = max(1.0, float(timeout))
        self.ws: Any = None
        self.subscription_id: Optional[str] = None

    def _close(self) -> None:
        ws, self.ws = self.ws, None
        self.subscription_id = None
        if ws is not None:
            try:
                ws.close()
            except Exception:  # noqa: BLE001
                pass

    def _connect(self) -> None:
        try:
            from websockets.sync.client import connect
            ws = connect(self.url, open_timeout=self.timeout, ping_interval=20,
                         ping_timeout=20, close_timeout=2, max_size=65536)
            ws.send(json.dumps({"jsonrpc": "2.0", "id": 1, "method": "eth_subscribe",
                                "params": ["newHeads"]}))
            deadline = time.monotonic() + self.timeout
            while time.monotonic() < deadline:
                raw = ws.recv(timeout=max(0.1, min(1.0, deadline - time.monotonic())))
                msg = json.loads(raw)
                if msg.get("id") == 1:
                    if msg.get("error") or not msg.get("result"):
                        ws.close()
                        raise TransientError("newHeads subscription was rejected by RPC provider")
                    self.ws = ws
                    self.subscription_id = str(msg["result"])
                    return
            ws.close()
            raise TransientError("newHeads subscription acknowledgement timed out")
        except TransientError:
            raise
        except Exception as exc:  # noqa: BLE001
            self._close()
            raise TransientError(f"newHeads WebSocket unavailable: {_redact(exc)}") from None

    def wait(self, timeout: float, stopped: Callable[[], bool]) -> Optional[Dict[str, Any]]:
        if self.ws is None:
            self._connect()
        deadline = time.monotonic() + max(0.0, float(timeout))
        try:
            while time.monotonic() < deadline and not stopped():
                try:
                    raw = self.ws.recv(timeout=max(0.1, min(1.0, deadline - time.monotonic())))
                except TimeoutError:
                    continue
                msg = json.loads(raw)
                params = msg.get("params") or {}
                if (msg.get("method") == "eth_subscription"
                        and str(params.get("subscription")) == self.subscription_id):
                    result = params.get("result")
                    return result if isinstance(result, dict) else None
            return None
        except Exception as exc:  # noqa: BLE001
            self._close()
            raise TransientError(f"newHeads stream disconnected: {_redact(exc)}") from None

    def close(self) -> None:
        self._close()


# ---------------------------------------------------------------------------
# Analysis (reuses the scan-address pipeline order)
# ---------------------------------------------------------------------------

def materialize_sources(source_code: str, dest: Path, name: str = "Contract") -> List[Path]:
    """Write Etherscan SourceCode (flat or standard-JSON) to *dest*."""
    text = source_code.strip()
    sources: Dict[str, str] = {}
    if text.startswith("{"):
        raw = text[1:-1] if text.startswith("{{") else text
        try:
            obj = json.loads(raw)
            srcs = obj.get("sources", obj)
            for path, entry in srcs.items():
                content = entry.get("content") if isinstance(entry, dict) else None
                if isinstance(content, str):
                    sources[path] = content
        except (ValueError, AttributeError):
            sources = {}
    if not sources:
        sources = {f"{name or 'Contract'}.sol": source_code}
    out = []
    root = dest.resolve()
    for rel, content in sources.items():
        p = (dest / rel.lstrip("/")).resolve()
        if root not in p.parents:  # path traversal guard
            continue
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
        if p.suffix == ".sol":
            out.append(p)
    return out


@dataclass
class AnalysisResult:
    """Phase 18.1: findings plus an honest completion verdict."""

    findings: list
    complete: bool = True
    reasons: List[str] = field(default_factory=list)
    execution: Optional[Dict[str, Any]] = None
    compile: Optional[Dict[str, Any]] = None
    # Phase 19: findings removed from the default report, with their reasons
    suppressed: List[Any] = field(default_factory=list)   # [(finding, TriageRecord)]
    triage: Any = None                                    # TriageResult or None


def _solc_auto_install_default() -> bool:
    return os.environ.get("AUDITOR_SOLC_AUTO_INSTALL", "1").strip().lower() not in ("0", "false", "no", "off")


def build_execution(slither_run: Any, findings: list, complete: bool, reasons: List[str],
                    compile_info: Optional[Dict[str, Any]], notes: Optional[List[str]] = None) -> Dict[str, Any]:
    """Execution record in the shape the dashboard already reads (Phase 12)."""
    tools = []
    if slither_run is not None:
        from auditor.analysis.slither_runner import slither_tool_run

        tools.append(slither_tool_run(slither_run, findings).to_dict())
    zero = None
    if not findings:
        zero = ("No findings, but the scan is INCOMPLETE; this is not a clean result."
                if not complete else "No findings from completed static analysis.")
    return {"tools": tools, "validation": None, "scan_complete": complete,
            "incomplete_reasons": list(reasons), "zero_findings_note": zero,
            "notes": [_redact(n) for n in (notes or [])], "compiler": compile_info,
            "static_analysis_requested": True, "foundry_validation_requested": False,
            "foundry_tests_requested": False}


def default_analyzer(files: List[Path], source_code: str, content_hash: str,
                     on_stage: Optional[Callable[[str], None]] = None,
                     record: Optional[Dict[str, Any]] = None, root: Optional[Path] = None,
                     allow_install: Optional[bool] = None) -> AnalysisResult:
    """Run the local pipeline with the contract's own compiler (Phase 18.1)."""
    from auditor.analysis.access_control import analyze as access_control_analyze
    from auditor.analysis.base import AnalysisContext
    from auditor.analysis.erc4626_inflation import analyze as erc4626_analyze
    from auditor.analysis.honeypot import analyze as honeypot_analyze
    from auditor.analysis.oracle_staleness import analyze as oracle_analyze
    from auditor.analysis.pool_accounting import analyze as pool_analyze
    from auditor.analysis.privileged_auth import analyze as privileged_auth_analyze
    from auditor.analysis.known_exploits import analyze as known_exploits_analyze
    from auditor.analysis.reentrancy import analyze as reentrancy_analyze
    from auditor.analysis.slither_generic import analyze as generic_analyze
    from auditor.analysis.slither_runner import get_slither_run, required_analysis_verdict
    from auditor.triage import apply_to_pipeline
    from auditor.compiler_select import CompilerSelectionError, plan_compile
    from auditor.model import Epistemic, EvidenceItem, deduplicate_findings, validated_findings

    if on_stage:
        on_stage("compiling")
    context = AnalysisContext()
    context.source_files = list(files)
    main_contract = str((record or {}).get("ContractName") or "") or None
    context.options = {"scope": "standard", "main_contract": main_contract,
                       "source_root": str(root) if root else None}
    compile_info: Optional[Dict[str, Any]] = None
    if record is not None:
        try:
            plan = plan_compile(record, files, Path(root or (files[0].parent if files else ".")),
                                allow_install=_solc_auto_install_default() if allow_install is None else allow_install)
        except CompilerSelectionError as e:
            reasons = [f"compiler selection failed: {_redact(e)}"]
            return AnalysisResult([], False, reasons, build_execution(None, [], False, reasons, None))
        context.options.update(plan.options())
        compile_info = plan.to_dict()
    run = get_slither_run(context)  # cached on the context; the analyzers reuse it
    if on_stage:
        on_stage("analyzing")
    findings: list = []
    notes: List[str] = []
    for fn in (reentrancy_analyze, access_control_analyze, generic_analyze,
               oracle_analyze, erc4626_analyze, pool_analyze, honeypot_analyze,
               privileged_auth_analyze, known_exploits_analyze):
        out = fn(context)
        findings += list(out.findings or [])
        notes += [n for n in (out.notes or []) if n and n not in notes]
    findings, _ = deduplicate_findings(findings)
    evidence = EvidenceItem(source=str((record or {}).get("SourceProvider") or "etherscan"),
                            artifact_type="verified_source",
                            excerpt=source_code[:200], epistemic=Epistemic.FACT,
                            content_hash=content_hash)
    for f in findings:
        f.add_evidence(evidence)
    findings = validated_findings(findings)
    # Phase 19: library-code / known-benign suppression + privileged-withdraw downgrade.
    tri = apply_to_pipeline(findings, files, Path(root) if root else None, main_contract, notes.append)
    complete, reasons = required_analysis_verdict(run)
    if complete is not True:  # the monitor always runs Slither: unknown == incomplete
        complete = False
        reasons = reasons or ["Slither (static analysis): execution was not observed"]
    execution = build_execution(run, tri.kept, complete, reasons, compile_info, notes)
    execution["triage"] = dict(tri.summary(), suppressed_findings=tri.suppressed_dicts())
    return AnalysisResult(tri.kept, complete, reasons, execution, compile_info,
                          suppressed=list(tri.suppressed), triage=tri)


def record_to_history(address: str, network: str, findings: list, content_hash: str,
                      execution: Optional[Dict[str, Any]] = None,
                      balance_usd: Optional[float] = None) -> str:
    from auditor.scan_history import ScanHistory, default_history_db_path

    history = ScanHistory(default_history_db_path())
    try:
        scan_id = history.record_scan(
            source_path=f"etherscan://{network}/{address}",
            config_fingerprint=f"monitor-{network}",
            findings=findings, content_hash=content_hash)
        if execution is not None:
            history.set_execution(scan_id, execution)  # before completed (Phase 12 order)
        history.mark_completed(scan_id, findings, balance_usd=balance_usd)
        return scan_id
    finally:
        history.close()


def _call(fn: Callable, *args: Any, **kwargs: Any) -> Any:
    """Call *fn* passing only the keyword arguments its signature accepts."""
    import inspect

    try:
        params = inspect.signature(fn).parameters
    except (TypeError, ValueError):
        return fn(*args)
    if any(p.kind is inspect.Parameter.VAR_KEYWORD for p in params.values()):
        return fn(*args, **kwargs)
    return fn(*args, **{k: v for k, v in kwargs.items() if k in params})


def _as_result(out: Any) -> AnalysisResult:
    if isinstance(out, AnalysisResult):
        return out
    return AnalysisResult(list(out or []), True, [])  # legacy analyzers: list of findings


# ---------------------------------------------------------------------------
# Monitor
# ---------------------------------------------------------------------------

@dataclass
class MonitorConfig:
    network: str = "ethereum"
    min_severity: str = "HIGH"
    max_per_poll: int = 5
    max_blocks_per_poll: int = 20
    interval: float = 60.0
    start_lookback: int = 5
    max_attempts: int = 6
    retry_base: float = 60.0
    retry_cap: float = 3600.0
    cache_dir: Path = field(default_factory=default_cache_dir)
    alerts_path: Path = field(default_factory=default_alerts_path)
    db_path: Path = field(default_factory=default_monitor_db_path)
    webhook_url: Optional[str] = None
    solc_auto_install: bool = field(default_factory=_solc_auto_install_default)
    error_backoff_cap: float = 600.0
    # Phase 20: which process wrote the scan row ("monitor" deployments | "hunt" targets)
    origin: str = "monitor"
    # Phase 19: value-at-risk (rough estimate) and alert threshold
    value_enabled: bool = field(default_factory=lambda: os.environ.get(
        "AUDITOR_VALUE_AT_RISK", "1").strip().lower() not in ("0", "false", "no", "off"))
    min_value_usd: Optional[float] = None


def validate_webhook(url: Optional[str]) -> Optional[str]:
    if not url:
        return None
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ("http", "https") or (parsed.hostname or "") not in _LOOPBACK:
        raise MonitorError("webhook must be an http(s) URL on a loopback host (127.0.0.1/localhost/::1)")
    return url


def build_client_from_env(network: str, **kw: Any) -> ChainClient:
    if network not in NETWORKS:
        raise MonitorError(f"unsupported network: {network}")
    key = os.environ.get("ETHERSCAN_API_KEY", "").strip()
    if not key:
        raise MonitorError("ETHERSCAN_API_KEY not set; the monitor needs it to fetch verified source")
    rpc = os.environ.get(RPC_ENV, "").strip() or None
    if rpc and urllib.parse.urlparse(rpc).scheme not in ("http", "https"):
        raise MonitorError(f"{RPC_ENV} must be an http(s) URL")
    ws = os.environ.get("AUDITOR_MONITOR_WS_URL", "").strip() or None
    return ChainClient(key, NETWORKS[network], rpc_url=rpc, ws_url=ws, **kw)


class Monitor:
    def __init__(self, config: MonitorConfig, client: ChainClient,
                 analyzer: Callable[[List[Path], str, str], list] = default_analyzer,
                 recorder: Callable[[str, str, list, str], str] = record_to_history,
                 emit: Callable[[str], None] = print, clock: Callable[[], float] = _now,
                 sleep: Callable[[float], None] = time.sleep, webhook_post: Optional[Callable] = None,
                 price_source: Any = None):
        self.cfg = config
        self.price_source = price_source
        self.client = client
        self.analyzer = analyzer
        self.recorder = recorder
        self.emit = emit
        self.clock = clock
        self.sleep = sleep
        self.webhook_url = validate_webhook(config.webhook_url)
        self.webhook_post = webhook_post or self._post_webhook
        self.store = MonitorStore(config.db_path)
        self.store.interrupt_stale(self.clock(), config.origin or "monitor")
        self.stop_requested = False

    def request_stop(self, *_a: Any) -> None:
        self.stop_requested = True

    # -- discovery --------------------------------------------------------
    def _reconcile_cursor(self, cursor: int) -> int:
        """Detect a changed canonical tail and rewind to a shared stored header."""
        header_fn = getattr(self.client, "block_header", None)
        if cursor <= 0 or not callable(header_fn):
            return cursor
        old_hash = self.store.block_hash(self.cfg.network, cursor)
        if not old_hash:
            return cursor  # legacy cursor: establish hashes as new blocks are indexed
        current = header_fn(cursor) or {}
        current_hash = str(current.get("hash") or "").lower()
        if not current_hash or current_hash == old_hash.lower():
            return cursor
        floor = max(0, cursor - 64)
        common = floor
        common_hash = None
        for candidate in range(cursor - 1, floor - 1, -1):
            known = self.store.block_hash(self.cfg.network, candidate)
            if not known:
                continue
            canonical = header_fn(candidate) or {}
            canonical_hash = str(canonical.get("hash") or "").lower()
            if canonical_hash and canonical_hash == known.lower():
                common, common_hash = candidate, canonical_hash
                break
        if common_hash is None and floor > 0:
            floor_header = header_fn(floor) or {}
            common_hash = str(floor_header.get("hash") or "").lower() or None
        self.store.record_reorg(self.cfg.network, cursor, common, old_hash,
                                current_hash, self.clock())
        self.emit(f"monitor: canonical chain changed at block {cursor}; rewound to {common} and will backfill")
        return common

    def discover(self) -> Dict[str, Any]:
        net = self.cfg.network
        head = self.client.block_number()
        cursor = self.store.get_cursor(net)
        if cursor is None:
            cursor = max(head - max(self.cfg.start_lookback, 0), 0)
            self.store.set_cursor(net, cursor)
        else:
            cursor = self._reconcile_cursor(cursor)
        end = min(head, cursor + max(self.cfg.max_blocks_per_poll, 1))
        found = 0
        direct_found = 0
        traced_found = 0
        trace_fn = getattr(self.client, "trace_contract_creations", None)
        block = cursor
        for block in range(cursor + 1, end + 1):
            if self.stop_requested:
                block -= 1
                break
            header_fn = getattr(self.client, "block_header", None)
            header = header_fn(block) if callable(header_fn) else None
            block_hash = str((header or {}).get("hash") or "").lower() or None
            parent_hash = str((header or {}).get("parentHash") or "").lower() or None
            creations = list(self.client.contract_creations(block))
            if callable(trace_fn):
                try:
                    traced = trace_fn(block) or []
                except TransientError:
                    raise
                except Exception as exc:  # noqa: BLE001 - trace support is optional
                    traced = []
                    # Bounded, sanitized detail: _redact strips registered secrets
                    # and RPC URL keys so provider refusals become diagnosable
                    # (and the phrase-based auto-disable in
                    # trace_contract_creations stays verifiable) without ever
                    # logging credentials, headers, or fetch endpoints.
                    detail = " ".join(_redact(str(exc)).split())[:160]
                    category = getattr(self.client, "provider_category", None)
                    provider = category() if callable(category) else "unknown"
                    self.emit(f"monitor: internal creation tracing unavailable "
                              f"({type(exc).__name__}: {detail}); top-level discovery "
                              f"continues (method=debug_traceBlockByNumber "
                              f"provider={provider})")
                seen = {str(c.get("address") or "").lower() for c in creations}
                for c in traced:
                    if str(c.get("address") or "").lower() not in seen:
                        creations.append(c)
                        seen.add(str(c.get("address") or "").lower())
            for c in creations:
                method = str(c.get("discovery_method") or "top_level_create")
                inserted = self.store.enqueue(net, c["address"], c.get("tx_hash") or "", block,
                                              block_hash=block_hash, discovery_method=method)
                found += int(inserted)
                if inserted and method == "top_level_create":
                    direct_found += 1
                elif inserted:
                    traced_found += 1
            if block_hash:
                self.store.record_block(net, block, block_hash, parent_hash)
            else:
                self.store.set_cursor(net, block)  # advance only after a block is fully enumerated
            if block % 10 == 0 or block == end:
                self.emit(f"monitor: indexed block {block}/{end} (head {head}); {found} new creations queued")
        trace_status = getattr(self.client, "trace_status", "unavailable")
        return {"head": head, "from": cursor + 1, "to": self.store.get_cursor(net),
                "enqueued": found, "top_level": direct_found, "internal": traced_found,
                "trace_status": trace_status}

    # -- processing -------------------------------------------------------
    def _defer(self, row: sqlite3.Row, error: str) -> str:
        attempts = int(row["attempts"]) + 1
        give_up = attempts >= self.cfg.max_attempts
        delay = min(self.cfg.retry_base * (2 ** (attempts - 1)), self.cfg.retry_cap)
        self.store.defer(self.cfg.network, row["address"], attempts, self.clock() + delay, error, give_up)
        return "unverified" if give_up else "deferred"

    def process_one(self, row: sqlite3.Row) -> Dict[str, Any]:
        net, addr = self.cfg.network, row["address"]
        store = self.store
        snapshot_fn = getattr(self.client, "state_snapshot", None)
        if callable(snapshot_fn) and getattr(self.client, "_state_snapshot_block", None) is None:
            try:
                snapshot_fn()
            except Exception as exc:  # noqa: BLE001 - keep source scan available on providers lacking head tags
                log.info("monitor: state snapshot unavailable for %s: %s", addr, type(exc).__name__)
        snapshot_block = getattr(self.client, "_state_snapshot_block", None)
        snapshot_finality = getattr(self.client, "_state_snapshot_finality", None)
        rid = store.start_scan(net, addr, row["tx_hash"], row["block"], self.clock(), origin=self.cfg.origin,
                               snapshot_block=snapshot_block, snapshot_finality=snapshot_finality)
        if snapshot_block is not None:
            self.emit(f"monitor: pinned {addr} state reads to {snapshot_finality} block {snapshot_block}")
        rec = None
        fetch_err = None
        try:
            rec = self.client.verified_source(addr)
        except TransientError as e:
            fetch_err = str(e)
        except MonitorError as e:
            fetch_err = str(e)
        if rec is None:
            # Sourcify is an independent fallback for every discovery path,
            # including newly created contracts that Etherscan has not indexed.
            try:
                from auditor.hunt import CachedFetcher, sourcify_record
                fetch = CachedFetcher(Path(self.cfg.cache_dir) / "http")
                rec = sourcify_record(addr, fetch)
            except Exception as e:  # noqa: BLE001
                log.info("monitor: sourcify fallback for %s: %s", addr, _redact(e))
                rec = None
        if rec is None:
            reason = "source not verified" + (f"; provider error: {_redact(fetch_err)[:160]}" if fetch_err else "")
            status = self._defer(row, reason)
            store.finish_scan(rid, status, self.clock(), error=reason)
            return {"address": addr, "status": status, "row": rid, "source_verification": {
                "provider": None, "identity_status": "unavailable", "exact_source_match": False,
                "reason": reason}}
        source = rec["SourceCode"]
        content_hash = hashlib.sha256(source.encode("utf-8")).hexdigest()
        name = str(rec.get("ContractName") or "") or None
        provider = str(rec.get("SourceProvider") or
                       ("sourcify" if rec.get("SourcifyMatch") else "etherscan")).lower()
        match = str(rec.get("SourcifyMatch") or "").lower() or None
        exact_match = match == "exact_match"
        identity_status = ("exact_match" if exact_match else
                           "partial_match" if match else "provider_verified_not_bytecode_matched")
        source_verification = {
            "provider": provider,
            "sourcify_match": match,
            "identity_status": identity_status,
            "exact_source_match": exact_match,
            "runtime_code_present": True,
            "compile_output_compared": False,
            "note": ("Sourcify reports exact deployed-bytecode identity." if exact_match else
                     "Source is available for analysis, but exact deployed-bytecode identity "
                     "has not been established."),
        }
        store.set_meta(rid, content_hash=content_hash, contract_name=name,
                       compiler=str(rec.get("CompilerVersion") or "") or None,
                       source_bytes=len(source.encode("utf-8")),
                       source_verification=json.dumps(source_verification, sort_keys=True))
        if store.is_seen(net, addr, content_hash):
            store.finish(net, addr, "duplicate")
            store.finish_scan(rid, "duplicate", self.clock())
            return {"address": addr, "status": "duplicate", "content_hash": content_hash, "row": rid}
        try:
            cache = Path(self.cfg.cache_dir) / net / addr / content_hash[:16]
            files = materialize_sources(source, cache, name or "Contract")
            lines = sum(len(f.read_text(encoding="utf-8").splitlines()) for f in files)
            store.set_meta(rid, file_count=len(files), line_count=lines, cache_dir=str(cache))
            store.set_stage(rid, "compiling", self.clock())
            on_stage = (lambda st: store.set_stage(rid, st, self.clock()))
            if not _accepts_on_stage(self.analyzer):
                store.set_stage(rid, "analyzing", self.clock())
            result = _as_result(_call(self.analyzer, files, source, content_hash, on_stage=on_stage,
                                      record=rec, root=cache, allow_install=self.cfg.solc_auto_install))
            findings = result.findings
            if result.compile:
                store.set_meta(rid, solc_version=result.compile.get("solc_version"),
                               compile_settings=json.dumps(result.compile, sort_keys=True, default=str))
            # Phase 19: value at risk (rough estimate) before history, so it is recorded with the scan.
            var = self._value(addr, rec)
            rows, est_by_id, vsum = finding_value_rows(findings, result.suppressed, result.triage, var)
            execution = result.execution
            if execution is not None:
                execution = dict(execution)
                execution["value_at_risk"] = {"summary": vsum, "contract": var.to_dict() if var else None,
                                              "finding_estimates": [
                                                  {"finding_id": r["finding_id"], "title": r["title"],
                                                   **json.loads(r["estimate_json"] or "{}")}
                                                  for r in rows if not r["suppressed"]]}
            # Best available USD value for scan-history / handoff (NULL if unknown).
            bal = None
            if var is not None:
                bal = getattr(var, "tvl_usd", None)
                if bal is None:
                    bal = getattr(var, "holder_value_usd", None)
            if bal is None and isinstance(vsum, dict):
                bal = vsum.get("tvl_usd")
            scan_id = _call(self.recorder, addr, net, findings, content_hash,
                            execution=execution, balance_usd=bal)
            # Live-state disproof (read-only eth_call): suppress shape findings whose
            # required state is absent now, with the recorded reason; never alert on them.
            disproved = self._live_disproofs(findings, addr)
            for r in rows:
                ev = disproved.get(r.get("finding_id"))
                if ev:
                    r.update(suppressed=1, triage_rule=ev["rule"], triage_reason=ev["reason"],
                             triage_detail=ev["detail"])
            store.add_findings(rid, net, addr, rows)
            store.set_value(rid, vsum if var is not None or rows else None, var.to_dict() if var else None,
                            len(result.suppressed) + len(disproved))
            if disproved:
                from auditor.live_disproof import reroll_scan
                reroll_scan(store.conn, rid)
                store.conn.commit()
                findings = [f for f in findings if getattr(f, "finding_id", None) not in disproved]
        except Exception as e:
            store.finish_scan(rid, "failed", self.clock(), error=f"{type(e).__name__}: {e}",
                              analysis_complete=False)
            raise
        sev_counts: Dict[str, int] = {}
        for f in findings:
            sev_counts[_sev(f)] = sev_counts.get(_sev(f), 0) + 1
        if result.complete:
            store.mark_seen(net, addr, content_hash, scan_id, len(findings), name)
            store.finish(net, addr, "done")
            status, error = "done", None
        else:
            # Never a clean audit: not marked seen, so a rescan / re-discovery retries it.
            store.finish(net, addr, "incomplete")
            status, error = "incomplete", "; ".join(result.reasons) or "required analyzer did not complete"
            self.emit(f"warning: {addr} could not be fully analyzed: {_redact(error)[:300]}")
        store.finish_scan(rid, status, self.clock(), scan_id=scan_id, findings=len(findings),
                          severity_counts=sev_counts, error=error, analysis_complete=result.complete)
        alerts = []
        for f in findings:
            if not severity_at_least(_sev(f), self.cfg.min_severity):
                continue
            est = est_by_id.get(id(f)) or {}
            if self.cfg.min_value_usd is not None and est.get("est_loss_usd") is not None \
                    and not est.get("user_funds_at_risk") \
                    and float(est["est_loss_usd"]) < float(self.cfg.min_value_usd):
                continue  # below the value threshold (unknown value still alerts: fail-open)
            alerts.append(self._alert(addr, row, scan_id, content_hash, f, incomplete=not result.complete,
                                      estimate=est, summary=vsum))
        return {"address": addr, "status": "scanned" if result.complete else "incomplete",
                "scan_id": scan_id, "row": rid, "contract_name": name, "content_hash": content_hash,
                "source_verification": source_verification,
                "findings": len(findings), "alerts": alerts, "reasons": list(result.reasons),
                "suppressed": len(result.suppressed), "tvl_usd": vsum.get("tvl_usd"),
                "est_max_loss_usd": vsum.get("est_max_loss_usd"), "value_is_estimate": True}

    def _alert(self, addr: str, row: sqlite3.Row, scan_id: str, chash: str, f: Any,
               incomplete: bool = False, estimate: Optional[Dict[str, Any]] = None,
               summary: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        estimate, summary = estimate or {}, summary or {}
        alert = {"scan_incomplete": bool(incomplete), "ts": _iso(self.clock()), "network": self.cfg.network, "address": addr,
                 "block": row["block"], "tx_hash": row["tx_hash"], "scan_id": scan_id,
                 "content_hash": chash, "severity": _sev(f),
                 "confidence": str(getattr(getattr(f, "confidence", ""), "value", getattr(f, "confidence", ""))),
                 "title": str(getattr(f, "title", "")),
                 # Phase 19: rough value estimates (never a prediction)
                 "category": str(getattr(f, "category", "") or ""),
                 "value_is_estimate": True,
                 "tvl_usd": summary.get("tvl_usd"),
                 "est_loss_usd": estimate.get("est_loss_usd"),
                 "est_loss_low_usd": estimate.get("est_loss_low_usd"),
                 "est_loss_high_usd": estimate.get("est_loss_high_usd"),
                 "user_funds_at_risk": bool(estimate.get("user_funds_at_risk")),
                 "price_as_of": summary.get("price_as_of")}
        path = Path(self.cfg.alerts_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(alert, sort_keys=True) + "\n")
        money = ""
        if alert["est_loss_usd"] is not None:
            money = f" est. loss ~${alert['est_loss_usd']:,.0f} (rough estimate)"
        elif alert["tvl_usd"] is not None:
            money = f" TVL ~${alert['tvl_usd']:,.0f}"
        self.emit(f"ALERT [{alert['severity']}] {addr} block {alert['block']}: {alert['title']}{money} (scan {scan_id})")
        # Top-tier confirmed outsider-theft alert (never from unconfirmed UNPROTECTED alone).
        try:
            from auditor.exploitable import emit_if_qualifies, qualifies
            if qualifies(f, min_usd=self.cfg.min_value_usd):
                emit_if_qualifies(
                    f,
                    address=addr,
                    contract_name=str(getattr(f, "affected_contract", None) or ""),
                    network=self.cfg.network,
                    scan_id=scan_id,
                    min_usd=self.cfg.min_value_usd,
                    emit=self.emit,
                    notify=True,
                )
        except Exception as _ex_exc:  # noqa: BLE001
            self.emit(f"warning: exploitable alert path failed: {_redact(_ex_exc)}")
        if self.webhook_url:
            try:
                self.webhook_post(self.webhook_url, alert)
            except Exception as e:  # noqa: BLE001 - webhook is best-effort
                self.emit(f"warning: webhook failed: {_redact(e)}")
        return alert

    def _live_disproofs(self, findings: Sequence[Any], addr: str) -> Dict[Any, Dict[str, Any]]:
        out: Dict[Any, Dict[str, Any]] = {}
        try:
            from auditor.live_disproof import check
            for f in findings:
                ev = check(f, addr, self.client if callable(getattr(self.client, "call", None)) else None)
                if ev and getattr(f, "finding_id", None) is not None:
                    out[f.finding_id] = ev
                    self.emit(f"monitor: {addr} {getattr(f, 'title', '')[:60]} — {ev['reason']}")
        except Exception as e:  # noqa: BLE001 - never breaks a scan
            log.warning("monitor: live disproof skipped for %s: %s", addr, _redact(e))
        return out

    def _value(self, addr: str, rec: Optional[Dict[str, Any]]) -> Any:
        """Holdings + prices (rough estimate). Never raises; None when disabled/unsupported."""
        if not self.cfg.value_enabled or not callable(getattr(self.client, "native_balance", None)):
            return None
        try:
            from auditor.value_at_risk import PriceSource, assess

            if self.price_source is None:
                self.price_source = PriceSource(cache_path=Path(self.cfg.cache_dir) / "prices.json")
            return assess(self.client, addr, rec, self.price_source)
        except Exception as e:  # noqa: BLE001
            log.warning("monitor: value-at-risk unavailable for %s: %s", addr, _redact(e))
            return None

    @staticmethod
    def _post_webhook(url: str, alert: Dict[str, Any]) -> None:
        req = urllib.request.Request(url, data=json.dumps(alert).encode(), method="POST",
                                     headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=5):  # noqa: S310 - loopback only (validated)
            pass

    def poll(self) -> Dict[str, Any]:
        # Disk pressure: record observation each poll; defer NEW heavy scans when gated.
        disk_meta = None
        try:
            from auditor.disk_pressure import get_controller
            dp = get_controller()
            disk_meta = dp.check().to_dict()
        except Exception as _dp_exc:  # noqa: BLE001
            log.warning("monitor: disk_pressure check failed: %s", _dp_exc)
            dp = None
        source_rechecks = 0
        try:
            source_rechecks = self.store.requeue_unverified(
                self.cfg.network, self.clock(),
                interval_s=float(os.environ.get("AUDITOR_SOURCE_RECHECK_SECONDS", "86400")),
                limit=max(1, self.cfg.max_per_poll))
        except (TypeError, ValueError):
            source_rechecks = self.store.requeue_unverified(
                self.cfg.network, self.clock(), limit=max(1, self.cfg.max_per_poll))
        disc = self.discover()  # light: enqueue only
        results = []
        due_rows = self.store.due(self.cfg.network, max(self.cfg.max_per_poll, 0), self.clock())
        snapshot_fn = getattr(self.client, "state_snapshot", None)
        if due_rows and callable(snapshot_fn):
            try:
                snapshot = snapshot_fn()
                self.emit(f"monitor: pinned scan batch to {snapshot.get('finality')} block {snapshot.get('block')}")
            except Exception as exc:  # noqa: BLE001 - scan can fall back to latest when block tags fail
                log.info("monitor: scan batch state snapshot unavailable: %s", type(exc).__name__)
        elif not due_rows and callable(snapshot_fn):
            try:
                snapshot_fn()  # refresh the view used by read-only watch checks below
            except Exception as exc:  # noqa: BLE001 - watch checks can still use latest state
                log.info("monitor: watch state snapshot unavailable: %s", type(exc).__name__)
        for row in due_rows:
            if self.stop_requested:
                break
            if dp is not None:
                ok, why = dp.allow_expensive("monitor.scan")
                if not ok:
                    self.emit(f"monitor: heavy scan deferred ({why})")
                    disk_meta = dp.status()
                    break  # leave remaining due() rows pending — queue preserved
            results.append(self._process_safely(row))
        n_alerts = sum(len(r.get("alerts", [])) for r in results)
        watch_summary = None
        if not self.stop_requested:
            # Graceful stop skips the watch sweep: in the soak2 stop this
            # flag-unresponsive HTTP tail consumed the supervisor's 10 s child
            # grace. The cursor and the pending queue are untouched here and
            # record_poll below still runs, so the round stays accounted for.
            try:
                watch_summary = self._check_watches()
                n_alerts += int((watch_summary or {}).get("alerts") or 0)
            except Exception as exc:  # noqa: BLE001 — watch must not stop the monitor
                log.warning("monitor: watch check failed: %s", _redact(exc))
                self.emit(f"warning: watch check failed: {type(exc).__name__}")
        self.store.record_poll(self.cfg.network, self.clock(), max(disc["to"] - disc["from"] + 1, 0),
                               disc["enqueued"], len(results), n_alerts)
        out = {"discovery": disc, "results": results, "alerts": n_alerts,
               "source_rechecks": source_rechecks}
        if watch_summary is not None:
            out["watch"] = watch_summary
        if disk_meta is not None:
            out["disk_pressure"] = disk_meta
        return out

    def _check_watches(self) -> Dict[str, Any]:
        from auditor.watch import check_watches
        return check_watches(
            self.store, self.client, network=self.cfg.network,
            alerts_path=Path(self.cfg.alerts_path),
            price_source=getattr(self, "price_source", None),
            emit=self.emit, now=self.clock(),
            default_min_value_usd=float(self.cfg.min_value_usd or 1000),
        )

    def _process_safely(self, row: sqlite3.Row) -> Dict[str, Any]:
        """One bad contract must not stop the monitor: record, back off, continue."""
        try:
            return self.process_one(row)
        except Exception as e:  # noqa: BLE001
            msg = f"{type(e).__name__}: {_redact(e)}"
            log.warning("monitor: processing %s failed: %s", row["address"], msg)
            self.emit(f"warning: processing {row['address']} failed (will retry): {msg[:300]}")
            return {"address": row["address"], "status": "failed", "queue": self._defer(row, msg),
                    "error": msg}

    def process_addresses(self, addresses: Sequence[str]) -> List[Dict[str, Any]]:
        """Process specific queued addresses now (used by monitor-rescan)."""
        out = []
        for addr in addresses:
            if self.stop_requested:
                break
            row = self.store.conn.execute(
                "SELECT * FROM monitor_queue WHERE network=? AND address=? AND status='pending'",
                (self.cfg.network, addr.lower())).fetchone()
            if row is not None:
                out.append(self._process_safely(row))
        return out

    def _beat(self, payload: Dict[str, Any]) -> None:
        """Best-effort worker heartbeat (dashboard_worker_state, additive row)."""
        try:
            record_worker_heartbeat(
                self.cfg.db_path, f"monitor-{self.cfg.network}",
                {"pid": os.getpid(), **payload}, at=self.clock())
        except Exception:  # noqa: BLE001 - heartbeats must never break the loop
            pass

    def run(self, once: bool = False) -> List[Dict[str, Any]]:
        prev: Dict[int, Any] = {}
        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                prev[sig] = signal.signal(sig, self.request_stop)
            except ValueError:  # not main thread
                prev = {}
                break
        polls = []
        consecutive_errors = 0
        head_stream = (NewHeadSubscription(self.client.ws_url)
                       if getattr(self.client, "ws_url", None) else None)
        lock = WorkerLock(worker_lock_path(self.cfg.db_path, "monitor", self.cfg.network))
        lock_handle = None
        try:
            lock_handle = lock.acquire()
            self._beat({"status": "running", "once": bool(once), "interval": self.cfg.interval})
            while not self.stop_requested:
                try:
                    summary = self.poll()
                    consecutive_errors = 0
                except Exception as e:  # noqa: BLE001 - the loop must survive (Phase 18.1)
                    if once and not isinstance(e, TransientError):
                        raise
                    consecutive_errors += 1
                    msg = f"{type(e).__name__}: {_redact(e)}"
                    summary = {"error": msg}
                    log.warning("monitor: poll failed (%d in a row): %s", consecutive_errors, msg)
                    try:
                        self.store.record_poll(self.cfg.network, self.clock(), 0, 0, 0, 0, error=msg)
                    except Exception:  # noqa: BLE001 - DB trouble must not kill the loop either
                        log.exception("monitor: could not record poll error")
                    self.emit(f"warning: poll failed (will retry): {msg[:300]}")
                polls.append(summary)
                beat_payload = {"status": "running", "polls": len(polls),
                                "consecutive_errors": consecutive_errors,
                                "interval": self.cfg.interval}
                discovery = summary.get("discovery") if isinstance(summary, dict) else None
                if isinstance(discovery, dict):
                    beat_payload["last_poll"] = {k: discovery.get(k) for k in
                                                 ("from", "to", "head", "enqueued") if k in discovery}
                elif isinstance(summary, dict) and summary.get("error"):
                    beat_payload["last_poll"] = {"error": str(summary["error"])[:200]}
                self._beat(beat_payload)
                if once:
                    break
                pause = self.cfg.interval
                if consecutive_errors:
                    pause = min(max(self.cfg.interval, 1.0) * (2 ** (consecutive_errors - 1)),
                                max(self.cfg.error_backoff_cap, self.cfg.interval))
                if head_stream is not None:
                    try:
                        new_head = head_stream.wait(pause, lambda: self.stop_requested)
                        if new_head:
                            self.emit(f"monitor: newHeads notification {new_head.get('number', '?')} "
                                      f"({str(new_head.get('hash') or '')[:12]})")
                    except TransientError as exc:
                        head_stream.close()
                        log.warning("monitor: newHeads stream unavailable; HTTP cursor backfill remains active: %s",
                                    _redact(exc))
                        self.emit("monitor: WebSocket unavailable; falling back to HTTP polling until reconnect")
                        waited = 0.0
                        while waited < pause and not self.stop_requested:
                            step = min(1.0, pause - waited)
                            self.sleep(step)
                            waited += step
                else:
                    waited = 0.0
                    while waited < pause and not self.stop_requested:
                        step = min(1.0, pause - waited)
                        self.sleep(step)
                        waited += step
        except LockHeld as exc:
            self.emit(f"monitor: already running (pid {exc.pid}); exiting (busy)")
            raise
        finally:
            if lock_handle is not None:  # busy workers leave no heartbeat row
                self._beat({"status": "stopped", "polls": len(polls)})
            if head_stream is not None:
                head_stream.close()
            if lock_handle is not None:
                lock_handle.release()
            for sig, handler in prev.items():
                signal.signal(sig, handler)
            self.store.close()
        return polls


def _accepts_on_stage(fn: Callable) -> bool:
    import inspect

    try:
        return "on_stage" in inspect.signature(fn).parameters
    except (TypeError, ValueError):
        return False


def _sev(f: Any) -> str:
    s = getattr(f, "severity", "")
    return str(getattr(s, "value", s)).upper()


def finding_value_rows(kept: Sequence[Any], suppressed: Sequence[Any], tri: Any, var: Any
                       ) -> tuple:
    """(monitor_findings rows, {id(finding): estimate}, contract summary) — Phase 19."""
    from auditor.risk_playbook import classify
    from auditor.triage import _finding_brief
    from auditor.value_at_risk import estimate_finding, summarize

    rows: List[Dict[str, Any]] = []
    est_by_id: Dict[int, Dict[str, Any]] = {}

    def _row(f: Any, rec: Any, sup: bool) -> Dict[str, Any]:
        brief = _finding_brief(f)
        trd = rec.to_dict() if rec is not None else {}
        cls, slug = classify(brief)
        est = None if sup else estimate_finding(brief, var, trd)
        impact_class = classify_impact(brief, slug, cls)
        explicitly_confirmed = bool(getattr(f, "confirmed_exploitable", False))
        impact_status = ("suppressed" if sup else
                         "confirmed_exploitable" if explicitly_confirmed else "unresolved")
        if est is not None:
            est_by_id[id(f)] = est
        balance_usd = None
        if var is not None:
            balance_usd = getattr(var, "tvl_usd", None)
            if balance_usd is None:
                balance_usd = getattr(var, "holder_value_usd", None)
        return {"finding_id": getattr(f, "finding_id", None), "title": brief["title"], "detector": slug,
                "vuln_class": cls, "category": brief["category"], "severity": _sev(f),
                "original_severity": trd.get("original_severity"),
                "confidence": str(getattr(getattr(f, "confidence", ""), "value", getattr(f, "confidence", ""))),
                "contract": brief["affected_contract"], "function": brief["affected_function"],
                "file": brief["affected_file"], "lines": json.dumps(brief["affected_lines"]),
                "suppressed": int(sup), "triage_reason": trd.get("reason"), "triage_rule": trd.get("rule"),
                "triage_detail": trd.get("detail"),
                "est_loss_usd": est and est["est_loss_usd"], "est_loss_low_usd": est and est["est_loss_low_usd"],
                "est_loss_high_usd": est and est["est_loss_high_usd"],
                "potential_impact_estimate_usd": est and est["est_loss_usd"],
                "impact_estimate_kind": "heuristic_model" if est else None,
                "exposure_factor": est and est["exposure_factor"],
                "weighted_score": est["weighted_score"] if est else 0.0,
                "impact_class": impact_class, "impact_status": impact_status,
                "balance_usd": balance_usd,
                "estimate_json": json.dumps(est, sort_keys=True) if est else None,
                "finding_json": json.dumps(brief, sort_keys=True, default=str)}

    for f in kept:
        rows.append(_row(f, tri.record_for(f) if tri is not None else None, False))
    for f, rec in suppressed or []:
        rows.append(_row(f, rec, True))
    summary = summarize([e for e in est_by_id.values()], var)
    return rows, est_by_id, summary


def classify_impact(brief: Mapping[str, Any], detector: str = "", vuln_class: str = "") -> str:
    """Bucket potential financial-harm mechanisms; this does not confirm exploitability."""
    text = " ".join(str(brief.get(k) or "") for k in
                    ("title", "description", "category", "affected_function", "impact"))
    text = f"{text} {detector} {vuln_class}".lower()
    if any(k in text for k in ("bad debt", "insolven", "undercollateral", "liquidat")):
        return "bad_debt_or_solvency"
    if any(k in text for k in ("oracle", "price manipulation", "spot price", "twap")):
        return "oracle_or_market_loss"
    if any(k in text for k in ("withdraw", "redeem", "cooldown", "locked", "liquidity", "freeze")):
        return "withdrawal_or_liquidity"
    if any(k in text for k in ("accounting", "rounding", "share price", "inflation", "exchange rate")):
        return "accounting_or_share_value"
    if any(k in text for k in ("owner", "admin", "privileged", "upgrade", "access control", "authorization")):
        return "privileged_control_risk"
    if any(k in text for k in ("drain", "steal", "arbitrary transfer", "reentrancy", "asset loss", "fund loss")):
        return "direct_asset_loss"
    return "other_or_unclassified"


def scan_outcome_counts(conn: sqlite3.Connection, network: str,
                        since: Optional[float] = None, until: Optional[float] = None) -> Dict[str, int]:
    """audited (Slither completed) vs could_not_analyze vs legacy rows awaiting re-evaluation."""
    out = {"audited": 0, "could_not_analyze": 0, "legacy_needs_rescan": 0}
    cols = {r[1] for r in conn.execute("PRAGMA table_info(monitor_scans)")}
    if not cols:
        return out
    where, args = "network=?", [network]
    if since is not None:
        where += " AND finished_at>=? AND finished_at<?"
        args += [since, until]
    if "analysis_complete" not in cols:  # Phase 18 DB not yet migrated: completion unknown
        out["legacy_needs_rescan"] = int(conn.execute(
            f"SELECT COUNT(*) FROM monitor_scans WHERE {where} AND status='done'", args).fetchone()[0])
        return out
    q = ("SELECT "
         "SUM(CASE WHEN status='done' AND analysis_complete=1 THEN 1 ELSE 0 END), "
         "SUM(CASE WHEN status IN ('incomplete','failed') AND superseded_at IS NULL THEN 1 ELSE 0 END), "
         "SUM(CASE WHEN status='done' AND analysis_complete IS NULL AND superseded_at IS NULL THEN 1 ELSE 0 END) "
         f"FROM monitor_scans WHERE {where}")
    a, b, c = conn.execute(q, args).fetchone()
    out.update(audited=int(a or 0), could_not_analyze=int(b or 0), legacy_needs_rescan=int(c or 0))
    return out


def rescan(store: "MonitorStore", network: str, rows: Optional[Sequence[int]] = None,
           now: Optional[float] = None, dry_run: bool = False) -> List[Dict[str, Any]]:
    """Requeue incomplete / failed / legacy rows; mark their history records unverified."""
    now = _now() if now is None else now
    out = []
    for r in store.rescan_candidates(network, rows):
        item = {"row": int(r["id"]), "address": r["address"], "status": r["status"],
                "legacy": r["status"] == "done" and r["analysis_complete"] is None,
                "scan_id": r["scan_id"]}
        out.append(item)
        if dry_run:
            continue
        if item["legacy"] and r["scan_id"]:
            _mark_history_unverified(r["scan_id"])
        store.requeue_for_rescan(r, now)
    return out


def _mark_history_unverified(scan_id: str) -> None:
    """Legacy (Phase 18) monitor scans have no execution record; say so honestly."""
    from auditor.scan_history import ScanHistory, default_history_db_path

    h = ScanHistory(default_history_db_path())
    try:
        rec = h.get_scan(scan_id)
        if rec and not rec.get("execution"):
            reason = ("legacy monitor scan (Phase 18): Slither completion was not recorded and "
                      "compile failures were stored as clean; re-scan requested (Phase 18.1)")
            h.set_execution(scan_id, {"tools": [], "validation": None, "scan_complete": False,
                                      "incomplete_reasons": [reason],
                                      "zero_findings_note": "Not a clean result: analysis completion unverified.",
                                      "notes": []})
    finally:
        h.close()



def value_overview(conn: sqlite3.Connection, network: str, since: Optional[float] = None,
                   until: Optional[float] = None, top: int = 10,
                   show_suppressed: bool = False) -> Dict[str, Any]:
    """Phase 19 roll-up (ROUGH ESTIMATES): value at risk found, top contracts by risk score.

    Headline ``value_at_risk_found_usd`` counts only **confirmed outsider-
    exploitable** exposure (non-suppressed findings with
    ``confirmed_exploitable=1``). Unconfirmed privileged-auth UNPROTECTED/WEAK
    hits are excluded from the headline and reported separately as
    ``unverified_exposure_usd``. Scam/honeypot findings are user-risk, not
    outsider theft, and are not included in the headline.
    """
    out: Dict[str, Any] = {"is_estimate": True, "label": "rough estimate", "value_at_risk_found_usd": 0.0,
                           "confirmed_outsider_usd": 0.0,
                           "unverified_exposure_usd": 0.0,
                           "unresolved_suspicion_usd": 0.0,
                           "disproved_excluded_usd": 0.0,
                           "potential_impact_estimates_usd": {},
                           "potential_impact_estimate_note": (
                               "Per mechanism: modeled estimate using the maximum finding estimate per scan; "
                               "mechanisms can overlap and are not confirmed loss."),
                           "holdings_usd": 0.0,
                           "holdings_unknown": False,
                           "tvl_with_findings_usd": 0.0, "contracts_with_value": 0, "suppressed_findings": 0,
                           "potential_impact_counts": {}, "top": [], "price_as_of": None}
    cols = {r[1] for r in conn.execute("PRAGMA table_info(monitor_scans)")}
    if "risk_score" not in cols:
        return out
    where, args = "network=? AND superseded_at IS NULL AND status IN ('done','incomplete')", [network]
    if since is not None:
        where += " AND finished_at>=? AND finished_at<?"
        args += [since, until]

    scan_headline: Dict[int, float] = {}
    scan_unverified: Dict[int, float] = {}
    if _table_exists(conn, "monitor_findings"):
        fcols = {r[1] for r in conn.execute("PRAGMA table_info(monitor_findings)")}
        if "impact_class" in fcols:
            impact_rows = conn.execute(
                "SELECT COALESCE(impact_class,'other_or_unclassified'), COUNT(*) "
                "FROM monitor_findings f JOIN monitor_scans s ON s.id=f.scan_row "
                "WHERE s.network=? AND s.superseded_at IS NULL AND s.status IN ('done','incomplete') "
                "AND f.suppressed=0 GROUP BY impact_class", [network]).fetchall()
            out["potential_impact_counts"] = {str(k): int(v) for k, v in impact_rows}
            if "est_loss_usd" in fcols:
                iw = ("s.network=? AND s.superseded_at IS NULL AND "
                      "s.status IN ('done','incomplete') AND f.suppressed=0")
                iargs: list = [network]
                if since is not None:
                    iw += " AND s.finished_at>=? AND s.finished_at<?"
                    iargs += [since, until]
                estimates: Dict[str, float] = {}
                for impact_class, amount in conn.execute(
                        "SELECT impact_class, SUM(scan_class_max) FROM ("
                        "SELECT f.scan_row, COALESCE(f.impact_class,'other_or_unclassified') AS impact_class, "
                        "MAX(f.est_loss_usd) AS scan_class_max "
                        "FROM monitor_findings f JOIN monitor_scans s ON s.id=f.scan_row "
                        f"WHERE {iw} AND f.est_loss_usd IS NOT NULL "
                        "GROUP BY f.scan_row, impact_class) GROUP BY impact_class", iargs):
                    estimates[str(impact_class)] = round(float(amount or 0.0), 2)
                out["potential_impact_estimates_usd"] = estimates
        if "est_loss_usd" in fcols:
            conf_expr = ("COALESCE(f.confirmed_exploitable, 0)"
                         if "confirmed_exploitable" in fcols else "0")
            sw = ("s.network=? AND s.superseded_at IS NULL AND "
                  "s.status IN ('done','incomplete')")
            sargs: list = [network]
            if since is not None:
                sw += " AND s.finished_at>=? AND s.finished_at<?"
                sargs += [since, until]
            q = (
                "SELECT f.scan_row, f.est_loss_usd, f.category, f.detector, "
                f"f.suppressed, {conf_expr} AS confirmed "
                "FROM monitor_findings f JOIN monitor_scans s ON s.id=f.scan_row "
                f"WHERE {sw} AND f.est_loss_usd IS NOT NULL"
            )
            scan_unresolved: Dict[int, float] = {}
            scan_disproved: Dict[int, float] = {}
            for scan_row, loss, cat, det, sup, confirmed in conn.execute(q, sargs):
                loss_f = float(loss or 0.0)
                if loss_f <= 0:
                    continue
                sid = int(scan_row)
                if int(sup or 0):
                    if loss_f > scan_disproved.get(sid, 0.0):
                        scan_disproved[sid] = loss_f
                    continue
                cat_s = (cat or "").lower()
                det_s = (det or "").lower()
                is_pa = (cat_s == "privileged_auth"
                         or det_s.startswith("privileged-auth-"))
                is_pa_unconfirmed_risk = (
                    det_s in ("privileged-auth-unprotected", "privileged-auth-weak")
                    or (is_pa and ("unprotected" in det_s or "weak" in det_s))
                )
                if int(confirmed or 0):
                    if loss_f > scan_headline.get(sid, 0.0):
                        scan_headline[sid] = loss_f
                    continue
                if is_pa and not is_pa_unconfirmed_risk:
                    # Protected / informational privileged-auth: exclude from headline
                    continue
                # unresolved suspicion (includes unconfirmed PA-unprotected/weak + other open findings)
                if loss_f > scan_unresolved.get(sid, 0.0):
                    scan_unresolved[sid] = loss_f
                if is_pa_unconfirmed_risk:
                    if loss_f > scan_unverified.get(sid, 0.0):
                        scan_unverified[sid] = loss_f
            out["value_at_risk_found_usd"] = round(sum(scan_headline.values()), 2)
            out["confirmed_outsider_usd"] = out["value_at_risk_found_usd"]
            out["unverified_exposure_usd"] = round(sum(scan_unverified.values()), 2)
            out["unresolved_suspicion_usd"] = round(sum(scan_unresolved.values()), 2)
            out["disproved_excluded_usd"] = round(sum(scan_disproved.values()), 2)

    holdings_sum = 0.0
    holdings_any = False
    holdings_missing = False
    for tvl, loss, nf, sup, pa in conn.execute(
            f"SELECT tvl_usd, est_max_loss_usd, findings, suppressed_count, price_as_of "
            f"FROM monitor_scans WHERE {where}",
            args):
        out["suppressed_findings"] += int(sup or 0)
        if tvl is not None:
            out["contracts_with_value"] += 1
            holdings_sum += float(tvl)
            holdings_any = True
        else:
            holdings_missing = True
        if nf and tvl is not None:
            out["tvl_with_findings_usd"] += float(tvl)
        if pa is not None:
            out["price_as_of"] = max(out["price_as_of"] or 0, float(pa))
    out["tvl_with_findings_usd"] = round(out["tvl_with_findings_usd"], 2)
    out["holdings_usd"] = round(holdings_sum, 2)
    out["holdings_unknown"] = (not holdings_any) or (holdings_missing and not holdings_any)
    for r in conn.execute(
            f"SELECT id, address, contract_name, tvl_usd, est_max_loss_usd, risk_score, findings, "
            f"severity_counts, user_funds_at_risk FROM monitor_scans WHERE {where} AND findings>0 "
            "ORDER BY COALESCE(risk_score,0) DESC, COALESCE(est_max_loss_usd,0) DESC, id DESC LIMIT ?",
            args + [int(top)]):
        out["top"].append({"row": r[0], "address": r[1], "contract_name": r[2], "tvl_usd": r[3],
                           "est_max_loss_usd": r[4], "risk_score": r[5], "findings": r[6],
                           "severity_counts": json.loads(r[7] or "{}"), "user_funds_at_risk": bool(r[8])})
    if show_suppressed and _table_exists(conn, "monitor_findings"):
        out["suppressed"] = [
            {"row": r[0], "address": r[1], "title": r[2], "severity": r[3], "reason": r[4], "rule": r[5],
             "detail": r[6]}
            for r in conn.execute(
                "SELECT f.scan_row, f.address, f.title, f.severity, f.triage_reason, f.triage_rule, f.triage_detail "
                "FROM monitor_findings f JOIN monitor_scans s ON s.id=f.scan_row "
                f"WHERE f.suppressed=1 AND s.{where.replace(' AND ', ' AND s.')} ORDER BY f.scan_row DESC LIMIT 200",
                args)]
    return out


def _table_exists(conn: sqlite3.Connection, name: str) -> bool:
    return conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)).fetchone() is not None


def monitor_status(network: str = "ethereum", db_path: Optional[Path] = None,
                   alerts_path: Optional[Path] = None, recent: int = 10,
                   show_suppressed: bool = False, now: Optional[float] = None) -> Dict[str, Any]:
    """Read-only status. Does not create the DB if absent."""
    db = Path(db_path or default_monitor_db_path())
    ap = Path(alerts_path or default_alerts_path())
    status: Dict[str, Any] = {"network": network, "db_path": str(db), "alerts_path": str(ap),
                              "cursor": None, "queue": {}, "seen": 0, "recent_alerts": [], "alerts_total": 0}
    if db.exists():
        conn = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
        try:
            row = conn.execute("SELECT last_block, updated_at FROM monitor_cursor WHERE network=?",
                               (network,)).fetchone()
            if row:
                status["cursor"], status["cursor_updated_at"] = int(row[0]), row[1]
            status["queue"] = {r[0]: int(r[1]) for r in conn.execute(
                "SELECT status, COUNT(*) FROM monitor_queue WHERE network=? GROUP BY status", (network,))}
            status["seen"] = int(conn.execute(
                "SELECT COUNT(*) FROM monitor_seen WHERE network=?", (network,)).fetchone()[0])
            status["scans"] = scan_outcome_counts(conn, network)
            from auditor.monitor_view import day_bounds

            start, end = day_bounds(_now() if now is None else now)
            status["value"] = {"all_time": value_overview(conn, network, show_suppressed=show_suppressed),
                               "today": value_overview(conn, network, start, end, top=5)}
        except sqlite3.OperationalError:
            pass
        finally:
            conn.close()
    if ap.exists():
        lines = [l for l in ap.read_text(encoding="utf-8").splitlines() if l.strip()]
        status["alerts_total"] = len(lines)
        for l in lines[-recent:][::-1]:
            try:
                status["recent_alerts"].append(json.loads(l))
            except ValueError:
                continue
    return status
