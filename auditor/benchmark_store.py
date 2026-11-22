"""Dedicated benchmark store — a separate SQLite database.

Pattern follows ``auditor.finding_store`` / ``auditor.scan_history``
(open_store + init_schema), with one hard difference: benchmark results
NEVER go into ``audit_scan_history.db``. The database location resolves as
``$AUDITOR_BENCHMARK_DB`` (tests point it at a throwaway file) or
``<project>/benchmark_store.db``.
"""
from __future__ import annotations

import json
import os
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

__all__ = [
    "default_benchmark_db_path",
    "open_store",
    "init_schema",
    "save_run",
    "get_latest",
    "list_runs",
    "get_run",
    "get_baseline",
    "mark_baseline",
    "BaselineError",
]

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_BENCHMARK_DB = PROJECT_ROOT / "benchmark_store.db"

#: The production scan-history database. Never opened here.
PRODUCTION_HISTORY_DB_NAME = "audit_scan_history.db"


class BaselineError(ValueError):
    """Rejected baseline request (incomplete run, missing run, or existing baseline)."""


def default_benchmark_db_path() -> Path:
    """Resolve the benchmark database path (env-overridable)."""
    override = os.environ.get("AUDITOR_BENCHMARK_DB", "").strip()
    if override:
        return Path(override)
    return DEFAULT_BENCHMARK_DB


def open_store(db_path: Path | str | None = None) -> sqlite3.Connection:
    """Open (and create, if needed) the benchmark database."""
    path = Path(db_path) if db_path is not None else default_benchmark_db_path()
    if path.name == PRODUCTION_HISTORY_DB_NAME:
        raise ValueError(
            "benchmark store must never use the production scan-history database"
        )
    conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row
    init_schema(conn)
    return conn


def init_schema(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS benchmark_runs (
            run_id      TEXT PRIMARY KEY,
            started_at  TEXT NOT NULL,
            finished_at TEXT NOT NULL,
            status      TEXT NOT NULL,
            toolchain   TEXT NOT NULL,
            totals      TEXT NOT NULL,
            metrics     TEXT NOT NULL,
            notes       TEXT NOT NULL DEFAULT '[]',
            is_baseline INTEGER NOT NULL DEFAULT 0,
            toolchain_fingerprint TEXT,
            corpus_fingerprint    TEXT,
            reconciliation TEXT NOT NULL DEFAULT '{}'
        )
        """
    )
    # PRAGMA-guarded additive migration: pre-protocol-v2 databases gain the
    # baseline/fingerprint/reconciliation columns without rewriting rows.
    existing = {row[1] for row in conn.execute("PRAGMA table_info(benchmark_runs)")}
    migrations = (
        ("is_baseline", "ALTER TABLE benchmark_runs ADD COLUMN is_baseline INTEGER NOT NULL DEFAULT 0"),
        ("toolchain_fingerprint", "ALTER TABLE benchmark_runs ADD COLUMN toolchain_fingerprint TEXT"),
        ("corpus_fingerprint", "ALTER TABLE benchmark_runs ADD COLUMN corpus_fingerprint TEXT"),
        ("reconciliation", "ALTER TABLE benchmark_runs ADD COLUMN reconciliation TEXT NOT NULL DEFAULT '{}'"),
    )
    for column, statement in migrations:
        if column not in existing:
            conn.execute(statement)
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS benchmark_results (
            run_id            TEXT NOT NULL,
            fixture_id        TEXT NOT NULL,
            category          TEXT NOT NULL,
            expected_label    TEXT NOT NULL,
            status            TEXT NOT NULL,
            verdict           TEXT,
            matched_check     TEXT,
            matched_title     TEXT,
            expected_contract TEXT,
            expected_function TEXT,
            actual_contract   TEXT,
            actual_function   TEXT,
            other_findings    TEXT NOT NULL DEFAULT '[]',
            evidence          TEXT,
            na_reason         TEXT,
            reason            TEXT,
            reconciliation    TEXT,
            PRIMARY KEY (run_id, fixture_id)
        )
        """
    )
    existing_results = {
        row[1] for row in conn.execute("PRAGMA table_info(benchmark_results)")
    }
    if "reconciliation" not in existing_results:
        conn.execute("ALTER TABLE benchmark_results ADD COLUMN reconciliation TEXT")
    conn.commit()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def save_run(conn: sqlite3.Connection, run: dict[str, Any]) -> None:
    """Persist one benchmark run and its per-fixture results (transactional)."""
    results = run.get("results") or []
    try:
        conn.execute(
            "INSERT INTO benchmark_runs (run_id, started_at, finished_at, status,"
            " toolchain, totals, metrics, notes, is_baseline, toolchain_fingerprint,"
            " corpus_fingerprint, reconciliation)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                run["run_id"],
                run.get("started_at") or _now(),
                run.get("finished_at") or _now(),
                run.get("status") or "unknown",
                json.dumps(run.get("toolchain") or {}),
                json.dumps(run.get("totals") or {}),
                json.dumps(run.get("metrics") or {}),
                json.dumps(run.get("notes") or []),
                1 if run.get("is_baseline") else 0,
                run.get("toolchain_fingerprint"),
                run.get("corpus_fingerprint"),
                json.dumps(run.get("reconciliation") or {}),
            ),
        )
        for row in results:
            conn.execute(
                "INSERT INTO benchmark_results (run_id, fixture_id, category,"
                " expected_label, status, verdict, matched_check, matched_title,"
                " expected_contract, expected_function, actual_contract,"
                " actual_function, other_findings, evidence, na_reason, reason,"
                " reconciliation)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    run["run_id"],
                    row.get("fixture_id"),
                    row.get("category"),
                    row.get("expected_label"),
                    row.get("status"),
                    row.get("verdict"),
                    row.get("matched_check"),
                    row.get("matched_title"),
                    row.get("expected_contract"),
                    row.get("expected_function"),
                    row.get("actual_contract"),
                    row.get("actual_function"),
                    json.dumps(row.get("other_findings") or []),
                    json.dumps(row.get("evidence")) if row.get("evidence") is not None else None,
                    row.get("na_reason"),
                    row.get("reason"),
                    json.dumps(row.get("reconciliation"))
                    if row.get("reconciliation") is not None else None,
                ),
            )
        conn.commit()
    except Exception:
        conn.rollback()
        raise


def _run_from_row(row: sqlite3.Row, include_results: bool, conn: sqlite3.Connection) -> dict[str, Any]:
    run = {
        "run_id": row["run_id"],
        "started_at": row["started_at"],
        "finished_at": row["finished_at"],
        "status": row["status"],
        "toolchain": json.loads(row["toolchain"]),
        "totals": json.loads(row["totals"]),
        "metrics": json.loads(row["metrics"]),
        "notes": json.loads(row["notes"]),
        "is_baseline": bool(row["is_baseline"]) if row["is_baseline"] is not None else False,
        "toolchain_fingerprint": row["toolchain_fingerprint"],
        "corpus_fingerprint": row["corpus_fingerprint"],
        "reconciliation": json.loads(row["reconciliation"] or "{}"),
        "results": [],
    }
    if include_results:
        for r in conn.execute(
            "SELECT * FROM benchmark_results WHERE run_id=? ORDER BY fixture_id",
            (row["run_id"],),
        ):
            run["results"].append(
                {
                    "fixture_id": r["fixture_id"],
                    "category": r["category"],
                    "expected_label": r["expected_label"],
                    "status": r["status"],
                    "verdict": r["verdict"],
                    "matched_check": r["matched_check"],
                    "matched_title": r["matched_title"],
                    "expected_contract": r["expected_contract"],
                    "expected_function": r["expected_function"],
                    "actual_contract": r["actual_contract"],
                    "actual_function": r["actual_function"],
                    "other_findings": json.loads(r["other_findings"] or "[]"),
                    "evidence": json.loads(r["evidence"]) if r["evidence"] else None,
                    "na_reason": r["na_reason"],
                    "reason": r["reason"],
                    "reconciliation": (
                        json.loads(r["reconciliation"])
                        if r["reconciliation"] else None
                    ),
                }
            )
    return run


def get_latest(conn: sqlite3.Connection) -> Optional[dict[str, Any]]:
    row = conn.execute(
        "SELECT * FROM benchmark_runs ORDER BY started_at DESC, run_id DESC LIMIT 1"
    ).fetchone()
    if row is None:
        return None
    return _run_from_row(row, True, conn)


def list_runs(conn: sqlite3.Connection, limit: int = 20) -> list[dict[str, Any]]:
    rows = conn.execute(
        "SELECT * FROM benchmark_runs ORDER BY started_at DESC, run_id DESC LIMIT ?",
        (int(limit),),
    ).fetchall()
    return [_run_from_row(r, False, conn) for r in rows]


def get_run(conn: sqlite3.Connection, run_id: str) -> Optional[dict[str, Any]]:
    row = conn.execute(
        "SELECT * FROM benchmark_runs WHERE run_id=?", (run_id,)
    ).fetchone()
    if row is None:
        return None
    return _run_from_row(row, True, conn)


def new_run_id() -> str:
    return f"B-{uuid.uuid4().hex[:12]}"


# ---------------------------------------------------------------------------
# Baselines (PROTOCOL §9.6 — single-baseline invariant, explicit override)
# ---------------------------------------------------------------------------

def get_baseline(conn: sqlite3.Connection) -> Optional[dict[str, Any]]:
    row = conn.execute(
        "SELECT * FROM benchmark_runs WHERE is_baseline=1"
        " ORDER BY started_at DESC LIMIT 1"
    ).fetchone()
    if row is None:
        return None
    return _run_from_row(row, True, conn)


def mark_baseline(
    conn: sqlite3.Connection,
    run_id: str,
    replace: bool = False,
) -> str:
    """Mark ``run_id`` as the single baseline run.

    Rejected: unknown run, run whose status is not ``completed``, runs with
    skipped/harness-error fixtures (totals), and replacing an existing
    baseline without ``replace=True`` — never an implicit overwrite.
    Returns the marked run id (committed).
    """
    row = conn.execute(
        "SELECT run_id, status, totals FROM benchmark_runs WHERE run_id=?",
        (run_id,),
    ).fetchone()
    if row is None:
        raise BaselineError(f"unknown run: {run_id}")
    if str(row["status"]) != "completed":
        raise BaselineError(
            f"run {run_id} is not a completed run (status={row['status']});"
            " only completed runs can be baselines"
        )
    totals = json.loads(row["totals"] or "{}")
    for key in ("skipped", "harness_error"):
        if int(totals.get(key) or 0) > 0:
            raise BaselineError(
                f"run {run_id} contains {key} fixtures;"
                " incomplete runs cannot be baselines"
            )
    existing = conn.execute(
        "SELECT run_id FROM benchmark_runs WHERE is_baseline=1 AND run_id!=?",
        (run_id,),
    ).fetchone()
    if existing is not None and not replace:
        raise BaselineError(
            f"baseline already set to {existing['run_id']};"
            " pass replace/force to switch baselines explicitly"
        )
    try:
        conn.execute("UPDATE benchmark_runs SET is_baseline=0")
        conn.execute(
            "UPDATE benchmark_runs SET is_baseline=1 WHERE run_id=?", (run_id,)
        )
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    return run_id
