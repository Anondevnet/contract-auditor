"""scan_records.balance_usd + handoff enrichment (no pipeline start)."""

from __future__ import annotations

import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from auditor.scan_history import ScanHistory
from auditor import scan_balance as sb


class _F:
    def __init__(self, title="t", severity="HIGH"):
        self.title = title
        self.category = "security"
        self.severity = type("S", (), {"value": severity})()
        self.verification_status = type("V", (), {"value": "UNVERIFIED"})()
        self.affected_contract = "C"
        self.affected_function = "f"
        self.affected_file = "C.sol"
        self.affected_lines = [1]

    def to_dict(self):
        return {"title": self.title, "severity": self.severity.value,
                "category": self.category, "verification_status": "UNVERIFIED",
                "affected_contract": self.affected_contract,
                "affected_function": self.affected_function,
                "affected_file": self.affected_file,
                "affected_lines": self.affected_lines}


class ScanHistoryBalanceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = Path(self.tmp.name) / "hist.db"

    def tearDown(self):
        self.tmp.cleanup()

    def test_schema_adds_balance_usd_idempotent(self):
        h = ScanHistory(self.db)
        cols = {r[1] for r in h.conn.execute("PRAGMA table_info(scan_records)")}
        self.assertIn("balance_usd", cols)
        h.close()
        h2 = ScanHistory(self.db)
        cols2 = {r[1] for r in h2.conn.execute("PRAGMA table_info(scan_records)")}
        self.assertIn("balance_usd", cols2)
        h2.close()

    def test_mark_completed_writes_column_and_finding_details(self):
        h = ScanHistory(self.db)
        sid = h.record_scan("etherscan://ethereum/0x" + "ab" * 20,
                            "cfg", content_hash="deadbeef")
        h.mark_completed(sid, [_F()], balance_usd=189_208.5)
        row = h.conn.execute(
            "SELECT balance_usd, finding_details FROM scan_records WHERE scan_id=?",
            (sid,),
        ).fetchone()
        self.assertEqual(row[0], 189_208.5)
        details = json.loads(row[1])
        self.assertEqual(details[0]["balance_usd"], 189_208.5)
        got = h.get_scan(sid)
        self.assertEqual(got["balance_usd"], 189_208.5)
        self.assertEqual(h.get_findings(sid)[0]["balance_usd"], 189_208.5)
        h.close()

    def test_set_balance_usd_coalesce_does_not_clobber(self):
        h = ScanHistory(self.db)
        sid = h.record_scan("/tmp/x.sol", "cfg", content_hash="aa")
        h.mark_completed(sid, [], balance_usd=100.0)
        h.set_balance_usd(sid, 999.0)
        self.assertEqual(h.get_scan(sid)["balance_usd"], 100.0)
        sid2 = h.record_scan("/tmp/y.sol", "cfg", content_hash="bb")
        h.mark_completed(sid2, [])
        self.assertIsNone(h.get_scan(sid2)["balance_usd"])
        h.set_balance_usd(sid2, 250.0)
        self.assertEqual(h.get_scan(sid2)["balance_usd"], 250.0)
        h.close()


class EnrichmentTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.hist = self.root / "hist.db"
        self.mon = self.root / "mon.db"
        self._build_monitor()

    def tearDown(self):
        self.tmp.cleanup()

    def _build_monitor(self):
        con = sqlite3.connect(self.mon)
        con.executescript(
            """
            CREATE TABLE monitor_scans (
              id INTEGER PRIMARY KEY, network TEXT, address TEXT, scan_id TEXT,
              tvl_usd REAL, value_json TEXT, finished_at REAL, status TEXT,
              contract_name TEXT, findings INTEGER, origin TEXT,
              user_funds_at_risk INTEGER, started_at REAL
            );
            CREATE TABLE monitor_findings (
              id INTEGER PRIMARY KEY, network TEXT, address TEXT, balance_usd REAL,
              scan_row INTEGER
            );
            CREATE TABLE hunt_candidates (
              network TEXT, address TEXT, holder_value_usd REAL,
              onchain_tvl_usd REAL, llama_tvl_usd REAL
            );
            """
        )
        con.execute(
            "INSERT INTO monitor_scans "
            "(id,network,address,scan_id,tvl_usd,value_json,finished_at,status,"
            " contract_name,findings,origin,user_funds_at_risk,started_at) VALUES "
            "(1,'ethereum','0xaaaabbbbccccddddeeeeffffaaaabbbbccccdddd',"
            " 'sid-1', NULL, NULL, 1000.0, 'done', 'Pool', 2, 'monitor', 0, 900.0)"
        )
        con.execute(
            "INSERT INTO monitor_findings (network,address,balance_usd,scan_row) "
            "VALUES ('ethereum','0xaaaabbbbccccddddeeeeffffaaaabbbbccccdddd',189208.5,1)"
        )
        con.execute(
            "INSERT INTO monitor_scans "
            "(id,network,address,scan_id,tvl_usd,value_json,finished_at,status,"
            " contract_name,findings,origin,user_funds_at_risk,started_at) VALUES "
            "(2,'ethereum','0x1111222233334444555566667777888899990000',"
            " 'sid-2', 50.0, NULL, 1100.0, 'done', 'Dust', 1, 'monitor', 0, 1000.0)"
        )
        con.execute(
            "INSERT INTO hunt_candidates "
            "(network,address,holder_value_usd,onchain_tvl_usd,llama_tvl_usd) VALUES "
            "('ethereum','0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef',3200.0,NULL,NULL)"
        )
        con.commit()
        con.close()

    def test_best_balance_from_monitor_findings(self):
        con = sqlite3.connect(self.mon)
        con.row_factory = sqlite3.Row
        v = sb.best_balance_usd(
            con, "ethereum", "0xaaaabbbbccccddddeeeeffffaaaabbbbccccdddd", scan_id="sid-1"
        )
        self.assertEqual(v, 189208.5)
        con.close()

    def test_enrich_rows_and_persist(self):
        h = ScanHistory(self.hist)
        addr = "0xaaaabbbbccccddddeeeeffffaaaabbbbccccdddd"
        sid = h.record_scan(f"etherscan://ethereum/{addr}", "cfg", content_hash="x")
        h.mark_completed(sid, [_F()])
        self.assertIsNone(h.get_scan(sid)["balance_usd"])
        h.close()
        rows = sb.enrich_rows(
            [{"scan_id": sid, "source_path": f"etherscan://ethereum/{addr}"}],
            monitor_db=self.mon,
            history_db=self.hist,
            persist=True,
        )
        self.assertEqual(rows[0]["balance_usd"], 189208.5)
        h = ScanHistory(self.hist)
        self.assertEqual(h.get_scan(sid)["balance_usd"], 189208.5)
        h.close()

    def test_handoff_prefers_value_holding_and_not_indexed(self):
        batch = sb.handoff_scans_since(
            500.0,
            monitor_db=self.mon,
            history_db=self.hist,
            min_balance_usd=250.0,
            prefer_value_holding=True,
            persist=False,
        )
        self.assertEqual(len(batch), 2)
        # Pool ($189k) before Dust ($50)
        self.assertEqual(batch[0]["address"].lower(),
                         "0xaaaabbbbccccddddeeeeffffaaaabbbbccccdddd")
        self.assertGreaterEqual(batch[0]["balance_usd"], 250.0)
        self.assertLess(batch[1]["balance_usd"], 250.0)

    def test_handoff_cursor_roundtrip(self):
        path = self.root / "cursor.json"
        sb.write_handoff_cursor(
            {"last_handoff_finished_at_epoch": 42.5, "scans_handed": 3},
            path=path,
            note="test",
        )
        cur = sb.load_handoff_cursor(path)
        self.assertEqual(cur["last_handoff_finished_at_epoch"], 42.5)
        self.assertEqual(cur["scans_handed"], 3)
        self.assertEqual(cur["note"], "test")


class RecordToHistoryBalanceTests(unittest.TestCase):
    def test_record_to_history_passes_balance(self):
        from auditor.monitor import record_to_history

        tmp = tempfile.TemporaryDirectory()
        db = Path(tmp.name) / "hist.db"
        with mock.patch.dict("os.environ", {"AUDITOR_HISTORY_DB": str(db)}):
            # Avoid finrisk enqueue into shared DB.
            sid = record_to_history(
                "0xaaaabbbbccccddddeeeeffffaaaabbbbccccdddd",
                "ethereum",
                [_F()],
                "hash1",
                balance_usd=1234.0,
            )
            h = ScanHistory(db)
            self.assertEqual(h.get_scan(sid)["balance_usd"], 1234.0)
            self.assertEqual(h.get_findings(sid)[0]["balance_usd"], 1234.0)
            h.close()
        tmp.cleanup()


if __name__ == "__main__":
    unittest.main()
