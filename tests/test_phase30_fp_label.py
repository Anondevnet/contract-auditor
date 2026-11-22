import sqlite3
from auditor.monitor import MonitorStore
from auditor.monitor_view import _detail_from_stored


def test_view_labels_dismissed_as_false_positive(tmp_path):
    db = tmp_path / "m.db"
    MonitorStore(db)
    con = sqlite3.connect(db)
    con.execute("insert into monitor_findings(scan_row,network,address,title,suppressed,triage_reason,triage_detail)"
                " values(1,'ethereum','0x1','a',1,'own-balance-withdraw','debits msg.sender bucket')")
    con.execute("insert into monitor_findings(scan_row,network,address,title,suppressed) values(1,'ethereum','0x1','b',0)")
    con.execute("insert into monitor_findings(scan_row,network,address,title,suppressed) values(1,'ethereum','0x1','c',1)")
    con.commit()
    rows = con.execute("select title,verdict_label,dismissal_reason from monitor_finding_labels order by title").fetchall()
    assert rows[0] == ("a", "false_positive", "own-balance-withdraw — debits msg.sender bucket")
    assert rows[1] == ("b", "unresolved", None)
    assert rows[2][1] == "false_positive" and "no reason recorded" in rows[2][2]


def test_api_detail_carries_label():
    d = _detail_from_stored({"suppressed": 1, "triage_reason": "r", "triage_detail": "d"}, lambda _x: None)
    assert d["verdict_label"] == "False positive" and d["dismissal_reason"] == "r — d"
    d = _detail_from_stored({"suppressed": 0}, lambda _x: None)
    assert d["verdict_label"] is None and d["dismissal_reason"] is None


def test_ui_shows_false_positive_text():
    import auditor.dashboard as D, pathlib
    js = pathlib.Path(D.__file__).parent / "static" / "js"
    assert '"False positive: "' in (js / "monitor.js").read_text()
    assert 'text: "False positive"' in (js / "findings.js").read_text()
