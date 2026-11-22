"""API vs DB: financial roll-up buckets stay separated and honest."""
from __future__ import annotations

import sqlite3
import time
from pathlib import Path

from auditor.monitor import value_overview


def _seed(db: Path) -> None:
    con = sqlite3.connect(str(db))
    con.executescript(
        """
        CREATE TABLE monitor_scans (
          id INTEGER PRIMARY KEY, network TEXT, address TEXT, status TEXT,
          superseded_at REAL, finished_at REAL, tvl_usd REAL, est_max_loss_usd REAL,
          findings INTEGER, suppressed_count INTEGER, price_as_of REAL, risk_score REAL,
          severity_counts TEXT, user_funds_at_risk INTEGER, contract_name TEXT
        );
        CREATE TABLE monitor_findings (
          id INTEGER PRIMARY KEY, scan_row INTEGER, network TEXT, address TEXT,
          category TEXT, detector TEXT, suppressed INTEGER, confirmed_exploitable INTEGER,
          est_loss_usd REAL
        );
        """
    )
    now = time.time()
    cols = ("id,network,address,status,superseded_at,finished_at,tvl_usd,est_max_loss_usd,"
            "findings,suppressed_count,price_as_of,risk_score,severity_counts,"
            "user_funds_at_risk,contract_name")
    con.execute(
        f"INSERT INTO monitor_scans ({cols}) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (1, "ethereum", "0xabc", "done", None, now, 1000.0, 500.0, 2, 0, now, 10.0, "{}", 0, "T"),
    )
    con.execute(
        "INSERT INTO monitor_findings VALUES (1,1,'ethereum','0xabc','reentrancy','reentrancy',0,1,400)"
    )
    con.execute(
        "INSERT INTO monitor_findings VALUES (2,1,'ethereum','0xabc','other','foo',0,0,200)"
    )
    con.execute(
        "INSERT INTO monitor_findings VALUES (3,1,'ethereum','0xabc','privileged_auth',"
        "'privileged-auth-unprotected',1,0,900)"
    )
    con.commit()
    con.close()


def test_value_overview_buckets(tmp_path: Path) -> None:
    db = tmp_path / "m.db"
    _seed(db)
    con = sqlite3.connect(str(db))
    out = value_overview(con, "ethernet") if False else value_overview(con, "ethereum")
    con.close()
    assert out["confirmed_outsider_usd"] == 400.0
    assert out["value_at_risk_found_usd"] == 400.0
    assert out["unresolved_suspicion_usd"] == 200.0
    assert out["disproved_excluded_usd"] == 900.0
    assert out["holdings_usd"] == 1000.0
    assert out["holdings_unknown"] is False


def test_normalize_address_length_and_ekubo() -> None:
    from auditor.bytecode_verify import normalize_address
    real = "0xe0e0e08a6a4b9dc7bd67bcb7aade5cf48157d444"
    assert normalize_address(real) == real
    assert normalize_address(real[:-1]) is None
    assert normalize_address(real + "4") is None
    typo = "0xe0e0e08a6a49dc7bd67bcb7aade5cf48157d4444"
    assert normalize_address(typo) == typo  # valid length, different address
    assert typo != real
    # path extraction
    assert normalize_address(f"etherscan://ethereum/{real}") == real
