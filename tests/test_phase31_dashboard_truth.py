"""Phase 31: dashboard API totals must match the database (isolated DBs only)."""
import sqlite3


def test_overview_counts_every_record(tmp_path, monkeypatch):
    db = tmp_path / "h.db"
    monkeypatch.setenv("AUDITOR_HISTORY_DB", str(db))
    monkeypatch.setenv("AUDITOR_MONITOR_DB", str(tmp_path / "m.db"))
    from auditor.scan_history import ScanHistory
    h = ScanHistory(db)
    for i in range(7):
        sid = h.record_scan(source_path=f"/tmp/x{i}", config_fingerprint="t", findings=[], content_hash=str(i))
        h.mark_completed(sid, [])
    h.close()
    import auditor.scan_history as S
    orig = S.ScanHistory.get_scan_history
    monkeypatch.setattr(S.ScanHistory, "get_scan_history",
                        lambda self, limit=50: orig(self, limit=limit))
    from fastapi.testclient import TestClient
    from auditor.dashboard.app import create_app
    ov = TestClient(create_app()).get("/api/overview").json()
    n = sqlite3.connect(db).execute("select count(*) from scan_records").fetchone()[0]
    assert ov["total_scans"] == n == 7 and ov["completed_scans"] == 7


def test_overview_has_no_fixed_cap():
    import inspect
    from auditor.dashboard import routes
    assert "limit=1000" not in inspect.getsource(routes.get_overview)


def test_times_render_in_detroit():
    import pathlib, auditor.dashboard as D
    js = pathlib.Path(D.__file__).parent / "static" / "js"
    for name in ("dashboard.js", "hunt.js", "monitor.js"):
        assert 'America/Detroit' in (js / name).read_text(), name


def test_api_timestamps_carry_offset(tmp_path, monkeypatch):
    db = tmp_path / "h.db"
    monkeypatch.setenv("AUDITOR_HISTORY_DB", str(db))
    monkeypatch.setenv("AUDITOR_MONITOR_DB", str(tmp_path / "m.db"))
    from auditor.scan_history import ScanHistory
    h = ScanHistory(db); sid = h.record_scan(source_path="/tmp/x", config_fingerprint="t", findings=[], content_hash="1")
    h.mark_completed(sid, []); h.close()
    from fastapi.testclient import TestClient
    from auditor.dashboard.app import create_app
    s = TestClient(create_app()).get("/api/scans").json()
    s = s if isinstance(s, list) else s["scans"]
    assert s[0]["timestamp"].endswith("+00:00")
