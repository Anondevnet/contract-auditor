"""Finding review lifecycle, scan metadata, and cross-scan finding queries.

Three idempotent ``CREATE TABLE IF NOT EXISTS`` tables live in the same
SQLite database as the scan history. The existing ``scan_records`` table is
never ALTERed, so old rows and existing tooling keep working untouched.

States are analyst-owned: a finding starts at New and only moves when a
human (or an explicitly confirmed retest) says so. Nothing here ever
auto-confirms a vulnerability.
"""

from __future__ import annotations

import json
import sqlite3
import uuid
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


class TriageState(str, Enum):
    """Analyst-facing triage states for one finding (distinct from the cross-scan
persistence lifecycle in ``scan_history.FindingState``)."""

    NEW = "New"
    NEEDS_REVIEW = "Needs Review"
    POTENTIAL_VULNERABILITY = "Potential Vulnerability"
    CONFIRMED_BY_EVIDENCE = "Confirmed by Evidence"
    FALSE_POSITIVE = "False Positive"
    FIXED = "Fixed"
    RETESTED = "Retested"


DEFAULT_STATE = TriageState.NEW

#: Allowed transitions. Anything not listed is rejected with a 422.
ALLOWED_TRANSITIONS: Dict[TriageState, Tuple[TriageState, ...]] = {
    TriageState.NEW: (
        TriageState.NEEDS_REVIEW,
        TriageState.POTENTIAL_VULNERABILITY,
        TriageState.FALSE_POSITIVE,
    ),
    TriageState.NEEDS_REVIEW: (
        TriageState.POTENTIAL_VULNERABILITY,
        TriageState.FALSE_POSITIVE,
        TriageState.NEW,
    ),
    TriageState.POTENTIAL_VULNERABILITY: (
        TriageState.CONFIRMED_BY_EVIDENCE,
        TriageState.FALSE_POSITIVE,
        TriageState.NEEDS_REVIEW,
    ),
    TriageState.CONFIRMED_BY_EVIDENCE: (
        TriageState.FIXED,
        TriageState.NEEDS_REVIEW,
    ),
    TriageState.FIXED: (
        TriageState.RETESTED,
        TriageState.NEEDS_REVIEW,
    ),
    TriageState.RETESTED: (
        TriageState.POTENTIAL_VULNERABILITY,
        TriageState.NEEDS_REVIEW,
    ),
    TriageState.FALSE_POSITIVE: (
        TriageState.NEEDS_REVIEW,
    ),
}

_SEVERITY_ORDER = {
    "CRITICAL": 0,
    "HIGH": 1,
    "MEDIUM": 2,
    "LOW": 3,
    "INFORMATIONAL": 4,
}

_SORT_KEYS = ("severity", "title", "timestamp", "state", "category")


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def open_store(db_path: Path | str) -> sqlite3.Connection:
    """Open the shared database with review/metadata tables ensured."""
    conn = sqlite3.connect(str(db_path), timeout=15)
    conn.row_factory = sqlite3.Row
    init_schema(conn)
    return conn


def init_schema(conn: sqlite3.Connection) -> None:
    """Create the review and metadata tables if they do not exist yet."""
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS finding_reviews (
            scan_id TEXT NOT NULL,
            fingerprint TEXT NOT NULL,
            state TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            note TEXT,
            evidence_ref TEXT,
            PRIMARY KEY (scan_id, fingerprint)
        );

        CREATE TABLE IF NOT EXISTS finding_review_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id TEXT NOT NULL,
            fingerprint TEXT NOT NULL,
            from_state TEXT,
            to_state TEXT NOT NULL,
            changed_at TEXT NOT NULL,
            note TEXT
        );

        CREATE TABLE IF NOT EXISTS scan_metadata (
            scan_id TEXT NOT NULL,
            key TEXT NOT NULL,
            value TEXT,
            PRIMARY KEY (scan_id, key)
        );
        """
    )
    conn.commit()


def has_fact_evidence(finding: Dict[str, Any]) -> bool:
    """True when the stored finding record carries at least one FACT evidence."""
    for item in finding.get("evidence") or []:
        if not isinstance(item, dict):
            continue
        if str(item.get("epistemic", "")).upper() == "FACT":
            excerpt = str(item.get("excerpt") or "").strip()
            if excerpt:
                return True
    return False


def get_review(conn: sqlite3.Connection, scan_id: str, fingerprint: str) -> Dict[str, Any]:
    """Review row for one finding; defaults to the New state."""
    row = conn.execute(
        "SELECT state, updated_at, note, evidence_ref FROM finding_reviews"
        " WHERE scan_id = ? AND fingerprint = ?",
        (scan_id, fingerprint),
    ).fetchone()
    if row is None:
        return {
            "state": DEFAULT_STATE.value,
            "updated_at": None,
            "note": None,
            "evidence_ref": None,
            "allowed_transitions": [s.value for s in ALLOWED_TRANSITIONS[DEFAULT_STATE]],
        }
    state = TriageState(row["state"]) if row["state"] in TriageState._value2member_map_ else DEFAULT_STATE
    return {
        "state": state.value,
        "updated_at": row["updated_at"],
        "note": row["note"],
        "evidence_ref": row["evidence_ref"],
        "allowed_transitions": [s.value for s in ALLOWED_TRANSITIONS[state]],
    }


def get_all_reviews(conn: sqlite3.Connection, scan_id: str | None = None) -> Dict[str, Dict[str, Any]]:
    """All review rows keyed by ``fingerprint`` (optionally one scan)."""
    sql = "SELECT scan_id, fingerprint, state, updated_at, note, evidence_ref FROM finding_reviews"
    params: Tuple[Any, ...] = ()
    if scan_id is not None:
        sql += " WHERE scan_id = ?"
        params = (scan_id,)
    out: Dict[str, Dict[str, Any]] = {}
    for row in conn.execute(sql, params).fetchall():
        key = row["fingerprint"]
        out[key] = {
            "scan_id": row["scan_id"],
            "state": row["state"],
            "updated_at": row["updated_at"],
            "note": row["note"],
            "evidence_ref": row["evidence_ref"],
        }
    return out


def set_state(
    conn: sqlite3.Connection,
    scan_id: str,
    fingerprint: str,
    new_state: str,
    finding: Dict[str, Any] | None = None,
    note: str | None = None,
    evidence_ref: str | None = None,
) -> Tuple[bool, str]:
    """Move one finding to ``new_state``.

    Returns ``(ok, message)``. ``Confirmed by Evidence`` is rejected unless
    the stored finding actually carries FACT evidence — state can never
    outrun the data behind it.
    """
    try:
        target = TriageState(new_state)
    except ValueError:
        return False, f"unknown state: {new_state!r}"

    current = get_review(conn, scan_id, fingerprint)
    current_state = TriageState(current["state"])

    if target == current_state:
        return True, f"already in state {target.value}"

    if target not in ALLOWED_TRANSITIONS[current_state]:
        allowed = ", ".join(s.value for s in ALLOWED_TRANSITIONS[current_state])
        return False, f"transition {current_state.value} -> {target.value} is not allowed (allowed: {allowed})"

    if target == TriageState.CONFIRMED_BY_EVIDENCE:
        if finding is None:
            return False, "confirmation requires the stored finding record (FACT evidence check)"
        if not has_fact_evidence(finding):
            return False, (
                "Confirmed by Evidence requires at least one FACT evidence item; "
                "the stored finding has none"
            )

    now = _utcnow()
    conn.execute(
        """
        INSERT INTO finding_reviews (scan_id, fingerprint, state, updated_at, note, evidence_ref)
        VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT(scan_id, fingerprint) DO UPDATE SET
            state = excluded.state,
            updated_at = excluded.updated_at,
            note = excluded.note,
            evidence_ref = excluded.evidence_ref
        """,
        (scan_id, fingerprint, target.value, now, note, evidence_ref),
    )
    conn.execute(
        """
        INSERT INTO finding_review_history
            (scan_id, fingerprint, from_state, to_state, changed_at, note)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (scan_id, fingerprint, current_state.value, target.value, now, note),
    )
    conn.commit()
    return True, f"{current_state.value} -> {target.value}"


def history(conn: sqlite3.Connection, scan_id: str, fingerprint: str) -> List[Dict[str, Any]]:
    """Chronological state changes for one finding."""
    rows = conn.execute(
        """
        SELECT from_state, to_state, changed_at, note
        FROM finding_review_history
        WHERE scan_id = ? AND fingerprint = ?
        ORDER BY id ASC
        """,
        (scan_id, fingerprint),
    ).fetchall()
    return [dict(r) for r in rows]


def set_metadata(conn: sqlite3.Connection, scan_id: str, metadata: Dict[str, Any]) -> None:
    """Record scan-level metadata (project, chain, token, protocol class)."""
    for key, value in (metadata or {}).items():
        if value is None:
            continue
        clean = str(key).strip()
        if not clean:
            continue
        conn.execute(
            """
            INSERT INTO scan_metadata (scan_id, key, value)
            VALUES (?, ?, ?)
            ON CONFLICT(scan_id, key) DO UPDATE SET value = excluded.value
            """,
            (scan_id, clean, str(value)),
        )
    conn.commit()


def get_metadata(conn: sqlite3.Connection, scan_id: str) -> Dict[str, str]:
    """Metadata map for one scan (empty dict when none was recorded)."""
    rows = conn.execute(
        "SELECT key, value FROM scan_metadata WHERE scan_id = ? ORDER BY key",
        (scan_id,),
    ).fetchall()
    return {r["key"]: r["value"] for r in rows}


def _severity_rank(value: Any) -> int:
    return _SEVERITY_ORDER.get(str(value or "").upper(), 99)


def _parse_details(raw: Any) -> List[Dict[str, Any]]:
    if isinstance(raw, (bytes, str)):
        try:
            raw = json.loads(raw)
        except (json.JSONDecodeError, UnicodeDecodeError):
            return []
    if isinstance(raw, dict):
        raw = list(raw.values())
    if not isinstance(raw, list):
        return []
    return [f for f in raw if isinstance(f, dict)]


def list_findings(
    conn: sqlite3.Connection,
    q: str | None = None,
    severity: List[str] | None = None,
    status: List[str] | None = None,
    state: List[str] | None = None,
    sort: str = "severity",
    group: str = "none",
) -> Dict[str, Any]:
    """Aggregated, filterable finding rows across completed scans."""
    try:
        rows = conn.execute(
            """
            SELECT scan_id, timestamp, source_path, config_fingerprint,
                   finding_fingerprints, finding_details
            FROM scan_records
            WHERE status = 'completed'
            ORDER BY timestamp DESC
            """
        ).fetchall()
    except sqlite3.OperationalError:
        # Pristine database: scan_records is created by the first scan.
        rows = []

    # Reviews are per (scan_id, fingerprint). Keying the lookup by
    # fingerprint alone let one scan's review leak onto another scan's
    # finding (and, with duplicate fingerprints across scans, the oldest
    # row silently won). One query fetches every review row with its
    # scan_id so the composite key is built without an N+1 loop.
    reviews: Dict[Tuple[str, str], Dict[str, Any]] = {}
    try:
        review_rows = conn.execute(
            "SELECT scan_id, fingerprint, state, updated_at, note, evidence_ref "
            "FROM finding_reviews"
        ).fetchall()
    except sqlite3.OperationalError:
        review_rows = []
    for review in review_rows:
        reviews[(review["scan_id"], review["fingerprint"])] = {
            "scan_id": review["scan_id"],
            "state": review["state"],
            "updated_at": review["updated_at"],
            "note": review["note"],
            "evidence_ref": review["evidence_ref"],
        }

    findings: List[Dict[str, Any]] = []
    for row in rows:
        details = _parse_details(row["finding_details"])
        fps: List[str] = []
        try:
            parsed = json.loads(row["finding_fingerprints"] or "[]")
            if isinstance(parsed, list):
                fps = [str(f) for f in parsed]
        except (json.JSONDecodeError, TypeError):
            fps = []

        for idx, finding in enumerate(details):
            fp = str(finding.get("fingerprint") or (fps[idx] if idx < len(fps) else ""))
            if not fp:
                fp = str(uuid.uuid4())
            review = reviews.get((row["scan_id"], fp), {})
            state_value = str(review.get("state") or DEFAULT_STATE.value)
            findings.append(
                {
                    "scan_id": row["scan_id"],
                    "scan_timestamp": row["timestamp"],
                    "source_path": row["source_path"],
                    "config_fingerprint": row["config_fingerprint"],
                    "fingerprint": fp,
                    "title": finding.get("title"),
                    "description": finding.get("description"),
                    "severity": finding.get("severity"),
                    "category": finding.get("category"),
                    "confidence": finding.get("confidence"),
                    "verification_status": finding.get("status")
                    or finding.get("verification_status"),
                    "state": state_value,
                    "state_updated_at": review.get("updated_at"),
                    "affected_contract": finding.get("affected_contract"),
                    "affected_function": finding.get("affected_function"),
                    "affected_lines": finding.get("affected_lines"),
                    "tool": finding.get("tool"),
                    "source": finding.get("source"),
                    "fact_evidence_count": finding.get("fact_evidence_count"),
                }
            )

    # --- filters ---
    if q:
        needle = q.strip().lower()
        if needle:
            findings = [
                f
                for f in findings
                if any(
                    needle in str(f.get(k) or "").lower()
                    for k in (
                        "title",
                        "description",
                        "category",
                        "affected_contract",
                        "affected_function",
                        "tool",
                        "scan_id",
                    )
                )
            ]

    if severity:
        wanted = {s.strip().upper() for s in severity if s and s.strip()}
        if wanted:
            findings = [f for f in findings if str(f.get("severity") or "").upper() in wanted]

    if status:
        wanted = {s.strip().upper() for s in status if s and s.strip()}
        if wanted:
            findings = [
                f for f in findings if str(f.get("verification_status") or "").upper() in wanted
            ]

    if state:
        wanted = {s.strip() for s in state if s and s.strip()}
        if wanted:
            findings = [f for f in findings if str(f.get("state") or "") in wanted]

    # --- sort ---
    sort_key = sort if sort in _SORT_KEYS else "severity"
    if sort_key == "severity":
        findings.sort(key=lambda f: (_severity_rank(f.get("severity")), str(f.get("title") or "")))
    elif sort_key == "title":
        findings.sort(key=lambda f: str(f.get("title") or "").lower())
    elif sort_key == "timestamp":
        findings.sort(key=lambda f: str(f.get("scan_timestamp") or ""), reverse=True)
    elif sort_key == "state":
        findings.sort(key=lambda f: str(f.get("state") or ""))
    elif sort_key == "category":
        findings.sort(key=lambda f: str(f.get("category") or "").lower())

    # --- group ---
    groups: Optional[Dict[str, List[Dict[str, Any]]]] = None
    if group in ("severity", "category", "state"):
        groups = {}
        for f in findings:
            key = str(f.get(group) or "Unknown")
            groups.setdefault(key, []).append(f)
        if group == "severity":
            groups = dict(
                sorted(groups.items(), key=lambda kv: _severity_rank(kv[0]))
            )

    return {
        "findings": findings,
        "total": len(findings),
        "groups": groups,
    }
