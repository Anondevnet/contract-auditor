"""Persistent scan history and incremental scanning support.

Local-first, SQLite-backed storage of scan records. No network, no Docker,
no external services. All data stored alongside the project, versioned, and
transaction-safe.

Typical usage:
    from auditor.scan_history import ScanHistory
    history = ScanHistory(PROJECT_ROOT / "audit_scan_history.db")
    scan_id = history.record_scan(
        source_path, config_fingerprint, findings=..., content_hash=...
    )
    history.mark_completed(scan_id, findings)
    history.mark_failed(scan_id, error_info)
    record = history.get_last_scan(source_path)
    previous_findings = history.get_findings(scan_id)
    is_unchanged = history.is_source_unchanged(source_path, content_hash)

Callers that already computed a content hash (dashboards and the CLI do)
must pass ``content_hash=...``: directories hash to the empty-string
digest when recomputed from disk alone.
"""

import sqlite3
import json
import os
import hashlib
import uuid
from datetime import datetime, timezone
from pathlib import Path
from enum import Enum
from dataclasses import dataclass
from typing import Any, Optional, Dict, List, Tuple
from auditor.model import finding_fingerprint

_PROJECT_ROOT = Path(__file__).resolve().parent.parent


def default_history_db_path() -> Path:
    """Resolve the scan-history database path.

    ``AUDITOR_HISTORY_DB`` overrides the location so test suites can point
    every read and write at a throwaway database instead of the production
    one. Empty or unset means the project database.
    """
    override = os.environ.get("AUDITOR_HISTORY_DB", "").strip()
    if override:
        return Path(override)
    return _PROJECT_ROOT / "audit_scan_history.db"


def _safe_json_loads(raw: Any, default: Any) -> Any:
    """Parse a stored JSON column; corrupt/partial rows must not crash reads.

    A disk-full or interrupted write can leave truncated JSON. Every
    row-deserialization path uses this helper so one bad record degrades
    to a default instead of taking down the whole history view.
    """
    if raw is None or raw == "":
        return default
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, TypeError, ValueError, UnicodeDecodeError):
        return default


def _finrisk_enqueue_after(conn: sqlite3.Connection, scan_id: str, details: Any) -> None:
    """Queue completed findings for the second-stage financial-risk review.

    Idempotent (INSERT OR IGNORE on scan_id+fingerprint) and isolated: the
    queue lives in ``reports/finrisk.db`` (mirrors the review-panel DB), NOT
    in this history store or the monitor store, so no new writer ever
    contends for the databases the monitor/hunt/dashboard actively use.

    Kept strictly best-effort at the call site; this function itself raises
    only real programming errors and SQLite problems are caught by the
    caller's guard (a review-queue outage must never stop a scan).
    """
    import auditor.finrisk as finrisk

    if not isinstance(details, list):
        return
    # Test isolation: when the history store is test-overridden but the
    # finrisk store is NOT, skip enqueueing so the SHARED queue never
    # receives rows whose scan lives only in a throwaway database.
    # Production runs set neither variable and always enqueue.
    if os.environ.get("AUDITOR_HISTORY_DB") and not os.environ.get("AUDITOR_FINRISK_DB"):
        return
    src = conn.execute("SELECT source_path, timestamp FROM scan_records WHERE scan_id=?",
                       (scan_id,)).fetchone()
    source_path = (src[0] if src else "") or ""
    scan_ts = (src[1] if src else None) or None
    store = finrisk.open_finrisk_db()
    try:
        finrisk.enqueue_findings(store, scan_id=scan_id, scan_timestamp=scan_ts,
                                 source_path=source_path,
                                 findings=[d for d in details if isinstance(d, dict)])
    finally:
        store.close()


def _finding_detail(finding: Any) -> Dict[str, Any]:
    """Serialize one finding for storage, full record when possible.

    The full ``Finding.to_dict()`` powers the investigation view. If a finding
    fails its own validation (e.g. a CONFIRMED status without FACT evidence)
    we keep the minimal summary instead so the scan is never lost.
    """
    fp = str(finding_fingerprint(finding))
    severity = getattr(finding, "severity", None)
    status = getattr(finding, "verification_status", None)
    minimal: Dict[str, Any] = {
        "fingerprint": fp,
        "title": getattr(finding, "title", None),
        "severity": severity.value if hasattr(severity, "value") else None,
        "category": getattr(finding, "category", None),
        "status": status.value if hasattr(status, "value") else None,
    }
    to_dict = getattr(finding, "to_dict", None)
    if callable(to_dict):
        try:
            full = to_dict()
        except Exception:  # noqa: BLE001 - one bad finding must not sink a scan
            return minimal
        if isinstance(full, dict):
            full["fingerprint"] = fp
            return full
    return minimal


class ScanStatus(Enum):
    """Status of a scan run."""
    STARTED = "started"
    COMPLETED = "completed"
    FAILED = "failed"
    INTERRUPTED = "interrupted"


class FindingState(Enum):
    """Lifecycle state of a finding across scans."""
    NEW = "new"
    PERSISTING = "persisting"
    CHANGED = "changed"
    RESOLVED = "resolved"
    REOPENED = "reopened"


@dataclass
class ScanRecord:
    """A single scan run record."""
    scan_id: str
    timestamp: str
    source_path: str
    content_hash: str
    config_fingerprint: str
    status: ScanStatus
    finding_fingerprints: List[str]
    finding_details: str  # JSON: {fingerprint: finding_summary_dict}
    error_info: Optional[str] = None
    graph_snapshot: Optional[str] = None  # JSON: graph reference


@dataclass
class FindingLifecycle:
    """A finding state transition record."""
    finding_id: str
    title: str
    previous_state: FindingState
    new_state: FindingState
    changed_reasons: List[str] = None


class ScanHistory:
    """SQLite-backed persistent scan history for incremental scanning.

    Supports:
    - First scan when no history exists
    - Skipping analysis when source and config are unchanged
    - Rescanning when source or config changes
    - Detecting added, removed, and changed files
    - Finding lifecycle tracking (NEW -> PERSISTING -> CHANGED -> RESOLVED/REOPENED)
    - Failed scan preservation (last good result not destroyed)
    - Idempotent reruns
    """

    def __init__(self, db_path: Path):
        self.db_path = db_path
        self.conn = sqlite3.connect(str(db_path))
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA synchronous=NORMAL")
        self._init_schema()

    def _init_schema(self):
        """Initialize the database schema."""
        self.conn.executescript("""
            CREATE TABLE IF NOT EXISTS scan_records (
                scan_id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                source_path TEXT NOT NULL,
                content_hash TEXT NOT NULL,
                config_fingerprint TEXT NOT NULL,
                status TEXT NOT NULL,
                finding_fingerprints TEXT NOT NULL DEFAULT '[]',
                finding_details TEXT NOT NULL DEFAULT '{}',
                error_info TEXT,
                graph_snapshot TEXT,
                execution TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );

            CREATE INDEX IF NOT EXISTS idx_scan_source
                ON scan_records(source_path, content_hash);
            CREATE INDEX IF NOT EXISTS idx_scan_status
                ON scan_records(status);
            CREATE INDEX IF NOT EXISTS idx_scan_timestamp
                ON scan_records(timestamp);
        """)
        # Additive migration for databases created before tool-execution
        # tracking existed. Existing rows keep execution = NULL (recorded
        # "not recorded"), never a fabricated status.
        columns = {row[1] for row in self.conn.execute("PRAGMA table_info(scan_records)")}
        if "execution" not in columns:
            self.conn.execute("ALTER TABLE scan_records ADD COLUMN execution TEXT")
        # Additive: contract/holder value known at scan time (USD). NULL = unknown.
        # Handoff enrichment can fill NULLs later from monitor/hunt without rewriting history.
        if "balance_usd" not in columns:
            self.conn.execute("ALTER TABLE scan_records ADD COLUMN balance_usd REAL")
        self.conn.commit()

    def _content_hash(self, source_path: Path) -> str:
        """Compute SHA-256 hash of file contents."""
        if source_path.is_file():
            with open(source_path, "rb") as f:
                return hashlib.sha256(f.read()).hexdigest()
        return hashlib.sha256(b"").hexdigest()

    def record_scan(
        self,
        source_path: "Path | str",
        config_fingerprint: str,
        findings: List[Any] = None,
        graph_snapshot: Any = None,
        status: ScanStatus = ScanStatus.STARTED,
        content_hash: Optional[str] = None,
    ) -> str:
        """Record a new scan and return its scan_id.

        Args:
            source_path: The Solidity file or directory that was scanned.
            config_fingerprint: Fingerprint of the analysis configuration.
            findings: List of Finding objects from this scan.
            graph_snapshot: Optional serialized graph snapshot.
            status: Initial scan status.
            content_hash: Optional precomputed content hash. Directories hash
                to a constant when computed from disk alone, so callers that
                already hashed the real content should pass it. ``None``
                keeps the on-disk computation.

        Returns:
            The scan_id for this record.
        """
        scan_id = str(uuid.uuid4())
        if content_hash is None:
            content_hash = self._content_hash(source_path)

        finding_fps: List[str] = []
        finding_dtls: str = "{}"
        if findings:
            fps = [finding_fingerprint(f) for f in findings]
            finding_fps = fps
            # Full finding record for the investigation view; falls back to a
            # minimal summary per finding if validation fails.
            dtls_list: List[Dict[str, Any]] = [_finding_detail(f) for f in findings]
            finding_dtls = json.dumps(dtls_list, default=str)

        self.conn.execute(
            """
            INSERT INTO scan_records
            (scan_id, timestamp, source_path, content_hash, config_fingerprint,
             status, finding_fingerprints, finding_details, error_info, graph_snapshot)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                scan_id,
                datetime.now(timezone.utc).isoformat(),
                str(source_path),
                content_hash,
                config_fingerprint,
                status.value,
                json.dumps(finding_fps),
                finding_dtls,
                None,
                json.dumps(graph_snapshot) if graph_snapshot else None,
            ),
        )
        self.conn.commit()
        return scan_id

    def mark_completed(
        self,
        scan_id: str,
        findings: List[Any],
        error_info: str = None,
        graph_snapshot: Any = None,
        balance_usd: Optional[float] = None,
    ):
        """Mark a scan as completed with findings.

        Args:
            scan_id: The scan record to update.
            findings: List of Finding objects from this scan.
            error_info: Optional error string if scan had issues.
            graph_snapshot: Optional serialized graph snapshot.
            balance_usd: Optional contract/holder USD value known at scan time.
                Written to ``scan_records.balance_usd`` and injected into each
                finding_details entry when that entry has no balance_usd yet.
                Leave None when truly unknown (enrichment may fill later).
        """
        finding_fps: List[str] = []
        finding_dtls: str = "{}"
        if findings:
            fps = [finding_fingerprint(f) for f in findings]
            finding_fps = fps
            # Full finding record for the investigation view; falls back to a
            # minimal summary per finding if validation fails.
            dtls_list: List[Dict[str, Any]] = [_finding_detail(f) for f in findings]
            if balance_usd is not None:
                for d in dtls_list:
                    if isinstance(d, dict) and d.get("balance_usd") is None:
                        d["balance_usd"] = float(balance_usd)
            finding_dtls = json.dumps(dtls_list, default=str)

        self.conn.execute(
            """
            UPDATE scan_records
            SET status = ?,
                finding_fingerprints = ?,
                finding_details = ?,
                error_info = ?,
                graph_snapshot = ?,
                balance_usd = COALESCE(?, balance_usd)
            WHERE scan_id = ?
            """,
            (
                ScanStatus.COMPLETED.value,
                json.dumps(finding_fps),
                finding_dtls,
                error_info,
                json.dumps(graph_snapshot) if graph_snapshot else None,
                float(balance_usd) if balance_usd is not None else None,
                scan_id,
            ),
        )
        self.conn.commit()
        # Second-stage financial-risk review queue (additive, best-effort).
        # Every finding-producing path (CLI scan, monitor/hunt pipeline,
        # dashboard scan/retest/AI-audit) records through mark_completed, so
        # one hook here queues every eligible finding exactly once. The hook
        # is fully swallowed: a queue failure can never break recording.
        try:
            _finrisk_enqueue_after(self.conn, scan_id, _safe_json_loads(finding_dtls, []))
        except Exception:  # noqa: BLE001 - enrichment must never break the scan
            pass

    def set_execution(self, scan_id: str, execution: Dict[str, Any]) -> None:
        """Persist tool-execution status for one scan (additive, optional).

        Legacy scans never had this recorded and stay NULL — the API reports
        that as "not recorded" rather than inventing a status.
        """
        self.conn.execute(
            "UPDATE scan_records SET execution = ? WHERE scan_id = ?",
            (json.dumps(execution, default=str), scan_id),
        )
        self.conn.commit()

    def set_balance_usd(self, scan_id: str, balance_usd: Optional[float]) -> None:
        """Set ``balance_usd`` on one scan (additive; never clears a known value).

        Passing None is a no-op. A non-None value only overwrites when the
        existing column is NULL (COALESCE), so enrichment never clobber a
        more specific write from mark_completed.
        """
        if balance_usd is None:
            return
        self.conn.execute(
            "UPDATE scan_records SET balance_usd = COALESCE(balance_usd, ?) WHERE scan_id = ?",
            (float(balance_usd), scan_id),
        )
        self.conn.commit()

    def mark_failed(
        self, scan_id: str, error_info: str, only_if_started: bool = False
    ):
        """Mark a scan as failed.

        Does NOT destroy the last successful result; only marks status.
        With ``only_if_started=True`` the update only applies to rows still
        in ``started`` (or ``running``), so a completed scan can never be
        overwritten by a late failure.
        """
        sql = """
            UPDATE scan_records
            SET status = ?, error_info = ?
            WHERE scan_id = ?
        """
        params: list = [ScanStatus.FAILED.value, error_info, scan_id]
        if only_if_started:
            sql += " AND status = ?"
            params.append(ScanStatus.STARTED.value)
        self.conn.execute(sql, params)
        self.conn.commit()

    def mark_interrupted(
        self, scan_id: str, error_info: str, only_if_started: bool = False
    ):
        """Mark a scan as interrupted (e.g. cancelled by the user).

        The recorded rows and execution state are preserved; only the
        status changes. Distinct from ``failed`` so cancelled scans are
        not reported as failures. With ``only_if_started=True`` a completed
        scan is never overwritten.
        """
        sql = """
            UPDATE scan_records
            SET status = ?, error_info = ?
            WHERE scan_id = ?
        """
        params: list = [ScanStatus.INTERRUPTED.value, error_info, scan_id]
        if only_if_started:
            sql += " AND status = ?"
            params.append(ScanStatus.STARTED.value)
        self.conn.execute(sql, params)
        self.conn.commit()

    def get_last_scan(self, source_path: Path) -> Optional[Dict]:
        """Get the most recent scan record for a source path.

        Returns None if no scan exists for this source.
        If the source content hash changed, the record is still returned
        but the caller should check content_hash compatibility.
        """
        content_hash = self._content_hash(source_path) if source_path.is_file() else ""
        cursor = self.conn.execute(
            """
            SELECT scan_id, timestamp, source_path, content_hash, config_fingerprint,
                   status, finding_fingerprints, finding_details, error_info, graph_snapshot,
                   balance_usd
            FROM scan_records
            WHERE source_path = ?
            ORDER BY timestamp DESC
            LIMIT 1
            """,
            (str(source_path),),
        )
        row = cursor.fetchone()
        if row:
            return {
                "scan_id": row[0],
                "timestamp": row[1],
                "source_path": row[2],
                "content_hash": row[3],
                "config_fingerprint": row[4],
                "status": row[5],
                "finding_fingerprints": _safe_json_loads(row[6], []),
                "finding_details": _safe_json_loads(row[7], {}),
                "error_info": row[8],
                "graph_snapshot": _safe_json_loads(row[9], None),
                "balance_usd": row[10],
            }
        return None

    def is_source_unchanged(self, source_path: Path, new_content_hash: str) -> bool:
        """Return True if the source has not changed since the last scan.

        Returns False if there is no previous scan for this source.
        """
        record = self.get_last_scan(source_path)
        if not record:
            return False
        return record["content_hash"] == new_content_hash

    def get_scan(self, scan_id: str) -> Optional[Dict]:
        """Get a specific scan record by scan_id."""
        cursor = self.conn.execute(
            """
            SELECT scan_id, timestamp, source_path, content_hash, config_fingerprint,
                   status, finding_fingerprints, finding_details, error_info, graph_snapshot,
                   balance_usd,
                   execution
            FROM scan_records WHERE scan_id = ?
            """,
            (scan_id,),
        )
        row = cursor.fetchone()
        if row:
            return {
                "scan_id": row[0],
                "timestamp": row[1],
                "source_path": row[2],
                "content_hash": row[3],
                "config_fingerprint": row[4],
                "status": row[5],
                "finding_fingerprints": _safe_json_loads(row[6], []),
                "finding_details": _safe_json_loads(row[7], {}),
                "error_info": row[8],
                "graph_snapshot": _safe_json_loads(row[9], None),
                "balance_usd": row[10],
                "execution": _safe_json_loads(row[11], None),
            }
        return None

    def get_findings(self, scan_id: str) -> List[Dict]:
        """Get all findings from a completed scan record.

        Returns an empty list if the scan is not completed or not found.
        """
        record = self.get_scan(scan_id)
        if record and record["status"] == ScanStatus.COMPLETED.value:
            details = record.get("finding_details", "")
            # details could be a JSON list or dict
            if isinstance(details, str):
                try:
                    details = json.loads(details)
                except json.JSONDecodeError:
                    details = []
            if isinstance(details, list):
                return details
            return list(details.values()) if isinstance(details, dict) else []
        return []

    def get_failed_scans(self) -> List[Dict]:
        """Get all failed scan records as dicts."""
        cursor = self.conn.execute(
            """
            SELECT scan_id, timestamp, source_path, content_hash, config_fingerprint,
                   status, finding_fingerprints, finding_details, error_info, graph_snapshot,
                   balance_usd
            FROM scan_records WHERE status = ?
        """,
            (ScanStatus.FAILED.value,),
        )
        records = []
        for row in cursor.fetchall():
            records.append(
                {
                    "scan_id": row[0],
                    "timestamp": row[1],
                    "source_path": row[2],
                    "content_hash": row[3],
                    "config_fingerprint": row[4],
                    "status": row[5],
                    "finding_fingerprints": _safe_json_loads(row[6], []),
                    "finding_details": _safe_json_loads(row[7], {}),
                    "error_info": row[8],
                    "graph_snapshot": _safe_json_loads(row[9], None),
                    "balance_usd": row[10],
                }
            )
        return records

    def get_scan_history(self, limit: int = 50) -> List[Dict]:
        """Get a summary list of recent scan records.

        Each dict contains: scan_id, timestamp, source_path, content_hash, status,
        balance_usd.
        """
        cursor = self.conn.execute(
            """
            SELECT scan_id, timestamp, source_path, content_hash, status, balance_usd
            FROM scan_records
            ORDER BY timestamp DESC
            LIMIT ?
            """,
            (limit,),
        )
        records = []
        for row in cursor.fetchall():
            records.append(
                {
                    "scan_id": row[0],
                    "timestamp": row[1],
                    "source_path": row[2],
                    "content_hash": row[3],
                    "status": row[4],
                    "balance_usd": row[5],
                }
            )
        return records

    def record_finding_transition(
        self,
        finding_id: str,
        title: str,
        previous_state: FindingState,
        new_state: FindingState,
        changed_reasons: List[str] = None,
    ) -> FindingLifecycle:
        """Record a finding state transition in the history.

        Args:
            finding_id: The stable fingerprint or ID of the finding.
            title: The finding title.
            previous_state: The FindingState before the transition.
            new_state: The FindingState after the transition.
            changed_reasons: Optional list of strings explaining the change.

        Returns:
            A FindingLifecycle dataclass describing the transition.
        """
        # Ensure the transitions table exists
        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS finding_transitions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                finding_id TEXT NOT NULL,
                title TEXT NOT NULL,
                previous_state TEXT NOT NULL,
                new_state TEXT NOT NULL,
                changed_reasons TEXT,
                timestamp TEXT DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        self.conn.execute(
            """
            INSERT INTO finding_transitions
            (finding_id, title, previous_state, new_state, changed_reasons)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                finding_id,
                title,
                previous_state.value,
                new_state.value,
                json.dumps(changed_reasons) if changed_reasons else None,
            ),
        )
        self.conn.commit()
        return FindingLifecycle(
            finding_id=finding_id,
            title=title,
            previous_state=previous_state,
            new_state=new_state,
            changed_reasons=changed_reasons,
        )

    def close(self):
        """Close the SQLite connection."""
        self.conn.close()