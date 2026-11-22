import sqlite3
from auditor.value_at_risk import summarize
from auditor import live_disproof as L


def test_informational_never_sets_headline():
    s = summarize([{"est_loss_usd": 8e6, "severity": "INFORMATIONAL"},
                   {"est_loss_usd": 1e3, "severity": "LOW"}], None)
    assert s["est_max_loss_usd"] == 1e3
    assert summarize([{"est_loss_usd": 8e6, "severity": "INFORMATIONAL"}], None)["est_max_loss_usd"] is None


def _db():
    c = sqlite3.connect(":memory:")
    c.execute("CREATE TABLE monitor_findings(id INTEGER PRIMARY KEY, scan_row INT, suppressed INT, severity TEXT,"
              " est_loss_usd REAL, est_loss_low_usd REAL, est_loss_high_usd REAL, triage_rule TEXT,"
              " triage_reason TEXT, triage_detail TEXT)")
    c.execute("CREATE TABLE monitor_scans(id INTEGER PRIMARY KEY, est_max_loss_usd REAL, risk_score REAL,"
              " value_json TEXT, suppressed_count INT)")
    c.execute("CREATE TABLE hunt_candidates(address TEXT, last_scan_row INT, est_max_loss_usd REAL)")
    c.execute("INSERT INTO monitor_scans VALUES(1, 16e6, 1.0, '{}', 0)")
    c.execute("INSERT INTO hunt_candidates VALUES('0xa', 1, 16e6)")
    for i, (sev, est) in enumerate([("HIGH", 16e6), ("MEDIUM", 8e6), ("INFORMATIONAL", 8e6), ("LOW", 8e5)], 1):
        c.execute("INSERT INTO monitor_findings(id,scan_row,suppressed,severity,est_loss_usd) VALUES(?,?,?,?,?)",
                  (i, 1, 0, sev, est))
    return c


def test_apply_triage_rerolls_scan_and_candidate():
    c = _db()
    L.apply_triage(c, 1, rule="r", reason="false positive", detail="d", suppress=True)
    assert c.execute("select est_max_loss_usd from monitor_scans").fetchone()[0] == 8e6
    L.apply_triage(c, 2, rule="r2", reason="unresolved", detail="d", suppress=False, severity="INFORMATIONAL")
    assert c.execute("select est_max_loss_usd from monitor_scans").fetchone()[0] == 8e5
    assert c.execute("select est_max_loss_usd from hunt_candidates").fetchone()[0] == 8e5
    assert c.execute("select suppressed,severity from monitor_findings where id=2").fetchone() == (0, "INFORMATIONAL")
