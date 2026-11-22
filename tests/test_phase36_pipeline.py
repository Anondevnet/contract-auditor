"""Pipeline recovery, impact labeling, and review telemetry regressions."""
from __future__ import annotations

import json

from auditor import hunt, simulate
from auditor.monitor import MonitorStore, classify_impact, value_overview


def test_impact_categories_cover_non_theft_harm_without_confirming_it() -> None:
    assert classify_impact({"title": "Withdrawals frozen by cooldown"}) == "withdrawal_or_liquidity"
    assert classify_impact({"title": "Oracle price manipulation creates bad debt"}) == "bad_debt_or_solvency"
    assert classify_impact({"title": "Share inflation from rounding"}) == "accounting_or_share_value"


def test_hunt_overview_reports_source_retry_and_fork_review(tmp_path) -> None:
    store = MonitorStore(tmp_path / "monitor.db")
    hunt.upsert_candidate(
        store, "ethereum", "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        protocol="Unverified", status="unverified", verified=False,
        source_attempts=3, source_retry_at=0, now=1,
    )
    hunt.upsert_candidate(
        store, "ethereum", "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        protocol="Review", status="scanned", verified=True, sim_status="review",
        sim_summary_json=json.dumps({"fork_block": 19_000_000}),
        discovery_json=json.dumps({"source_verification": {"identity_status": "exact_match"}}),
        now=2,
    )
    overview = hunt.hunt_overview(store.conn, "ethereum", top=10)
    counters = overview["counters"]
    assert counters["source_unverified"] == 1
    assert counters["source_retry_due"] == 1
    assert counters["source_exact_matches"] == 1
    assert counters["simulation_review"] == 1
    row = next(x for x in overview["candidates"] if x["protocol"] == "Review")
    assert row["sim_summary"]["fork_block"] == 19_000_000
    assert row["potential_impact_estimate_usd"] is None
    store.close()


def test_potential_impact_rollup_stays_separate_and_avoids_same_scan_double_count(tmp_path) -> None:
    store = MonitorStore(tmp_path / "value.db")
    now = 2_000_000_000.0
    cur = store.conn.execute(
        "INSERT INTO monitor_scans(network,address,stage,status,started_at,finished_at,"
        "risk_score,findings,suppressed_count) VALUES(?,?,?,?,?,?,?,?,?)",
        ("ethereum", "0x" + "c" * 40, "done", "done", now, now, 1.0, 3, 0),
    )
    scan_id = cur.lastrowid
    for amount, impact in ((40.0, "withdrawal_or_liquidity"),
                           (60.0, "withdrawal_or_liquidity"),
                           (20.0, "bad_debt_or_solvency")):
        store.conn.execute(
            "INSERT INTO monitor_findings(scan_row,network,address,suppressed,est_loss_usd,"
            "impact_class,impact_status) VALUES(?,?,?,0,?,?, 'unresolved')",
            (scan_id, "ethereum", "0x" + "c" * 40, amount, impact),
        )
    store.conn.commit()
    overview = value_overview(store.conn, "ethereum")
    assert overview["value_at_risk_found_usd"] == 0.0
    assert overview["potential_impact_estimates_usd"] == {
        "withdrawal_or_liquidity": 60.0,
        "bad_debt_or_solvency": 20.0,
    }
    store.close()


def test_simulation_schema_helper_preserves_monitor_schema_version(tmp_path) -> None:
    store = MonitorStore(tmp_path / "schema.db")
    before = store.conn.execute("PRAGMA user_version").fetchone()[0]
    simulate.ensure_schema_v7(store.conn)
    after = store.conn.execute("PRAGMA user_version").fetchone()[0]
    assert before == after == MonitorStore.SCHEMA_VERSION
    store.close()


def test_abandoned_scan_claim_is_released_after_restart(tmp_path) -> None:
    cfg = hunt.HuntConfig(db_path=tmp_path / "hunt.db", cache_dir=tmp_path / "cache")
    hunter = hunt.Hunter(cfg, client=None, clock=lambda: 10_000.0)
    hunt.upsert_candidate(
        hunter.store, "ethereum", "0xdddddddddddddddddddddddddddddddddddddddd",
        status="scanning", verified=True, scan_attempt_at=1, now=1,
    )
    recovered = hunter._recover_stale_scan_claims(stale_after_s=60)
    row = hunter.store.conn.execute(
        "SELECT status,last_error FROM hunt_candidates WHERE address=?",
        ("0xdddddddddddddddddddddddddddddddddddddddd",),
    ).fetchone()
    assert recovered == 1
    assert row[0] == "ready"
    assert row[1] == "recovered stale scan claim"
    hunter.store.close()
