import json, sqlite3
from types import SimpleNamespace
from auditor import live_disproof as L
from auditor.monitor import MonitorStore

F = SimpleNamespace(description="x Source detector: compound-empty-market.", finding_id="f1", title="Empty-market")


class C:
    def __init__(self, supply, fail=False): self.supply, self.fail = supply, fail
    def call(self, to, data):
        if self.fail: raise RuntimeError("rpc down")
        return hex(self.supply)
    def block_number(self): return 123


def test_large_supply_disproves():
    ev = L.check(F, "0x1", C(6 * 10 ** 16))
    assert ev["reason"] == "tested path disproved under current state" and ev["observed"]["block"] == 123


def test_small_supply_or_unknown_is_not_disproved():
    assert L.check(F, "0x1", C(5)) is None
    assert L.check(F, "0x1", C(0, fail=True)) is None  # unknown stays unknown
    assert L.check(SimpleNamespace(description="Source detector: other."), "0x1", C(10 ** 20)) is None


def _db(tmp_path):
    db = tmp_path / "m.db"; MonitorStore(db); con = sqlite3.connect(db)
    con.execute("insert into monitor_scans(id,network,address,stage,status,started_at,est_max_loss_usd,risk_score,value_json) "
                "values(1,'ethereum','0x1','done','done',0,4000000,100,?)", (json.dumps({"summary": {"est_max_loss_usd": 4e6}}),))
    con.execute("insert into monitor_findings(id,scan_row,network,address,title,suppressed,est_loss_usd) values(10,1,'ethereum','0x1','Empty-market',0,4000000)")
    con.execute("insert into monitor_findings(id,scan_row,network,address,title,suppressed,est_loss_usd) values(11,1,'ethereum','0x1','other',0,1000)")
    con.commit(); return con


def test_apply_suppresses_and_rerolls_exposure(tmp_path):
    con = _db(tmp_path)
    L.apply_to_row(con, 10, L.check(F, "0x1", C(10 ** 16)))
    sup, rule, reason = con.execute("select suppressed,triage_rule,triage_reason from monitor_findings where id=10").fetchone()
    assert (sup, rule, reason) == (1, "live-state-disproof", "tested path disproved under current state")
    est, risk = con.execute("select est_max_loss_usd, risk_score from monitor_scans where id=1").fetchone()
    assert est == 1000 and abs(risk - 100 * 1000 / 4e6) < 1e-6
    lab = con.execute("select verdict_label from monitor_finding_labels where id=10").fetchone()[0]
    assert lab == "disproved_current_state"


def test_all_disproved_exposure_is_unknown_not_zero(tmp_path):
    con = _db(tmp_path)
    con.execute("update monitor_findings set suppressed=1 where id=11"); con.commit()
    L.apply_to_row(con, 10, L.check(F, "0x1", C(10 ** 16)))
    assert con.execute("select est_max_loss_usd from monitor_scans where id=1").fetchone()[0] is None


def test_alert_annotated(tmp_path):
    from auditor.monitor_view import _annotate_alerts
    con = _db(tmp_path)
    L.apply_to_row(con, 10, L.check(F, "0x1", C(10 ** 16)))
    alerts = [{"address": "0x1", "title": "Empty-market", "scan_id": None}, {"address": "0x1", "title": "other"}]
    _annotate_alerts(con, alerts)
    assert alerts[0]["triage"]["verdict"] == "disproved" and alerts[0]["active_exposure"] is False
    assert "triage" not in alerts[1]
