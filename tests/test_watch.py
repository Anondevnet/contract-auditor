"""Watch list — add/list/check/alert threshold."""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from auditor import monitor as m
from auditor import watch as w


class Env(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.d = Path(self.tmp.name)
        self.env = mock.patch.dict(os.environ, {
            "AUDITOR_MONITOR_DB": str(self.d / "mon.db"),
            "AUDITOR_MONITOR_CACHE": str(self.d / "cache"),
            "AUDITOR_MONITOR_ALERTS": str(self.d / "alerts.jsonl"),
            "AUDITOR_HISTORY_DB": str(self.d / "hist.db"),
            "AUDITOR_PRICE_CACHE": str(self.d / "prices.json"),
            "AUDITOR_SOLC_AUTO_INSTALL": "0",
        })
        self.env.start()

    def tearDown(self):
        self.env.stop()
        self.tmp.cleanup()


class WatchCrud(Env):
    def test_add_list_remove(self):
        store = m.MonitorStore(self.d / "mon.db")
        w.add_watch(store, "ethereum", "0x" + "ab" * 20, note="EMAUSD",
                    min_value_usd=1000, related_address="0x" + "cd" * 20)
        rows = w.list_watches(store, "ethereum")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["address"], "0x" + "ab" * 20)
        self.assertEqual(rows[0]["note"], "EMAUSD")
        # hunt mirror
        hc = store.conn.execute(
            "SELECT status, source FROM hunt_candidates WHERE address=?",
            ("0x" + "ab" * 20,)).fetchone()
        self.assertIsNotNone(hc)
        self.assertEqual(hc["status"], "watching")
        self.assertTrue(w.remove_watch(store, "ethereum", "0x" + "ab" * 20))
        self.assertEqual(w.list_watches(store, "ethereum"), [])
        store.close()

    def test_schema_current(self):
        store = m.MonitorStore(self.d / "mon.db")
        ver = store.conn.execute("PRAGMA user_version").fetchone()[0]
        tables = {r[0] for r in store.conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
        self.assertEqual(ver, m.MonitorStore.SCHEMA_VERSION)
        self.assertIn("watch_targets", tables)
        store.close()


class WatchCheck(Env):
    def test_alert_when_threshold_crossed(self):
        store = m.MonitorStore(self.d / "mon.db")
        addr = "0x" + "11" * 20
        w.add_watch(store, "ethereum", addr, min_value_usd=1000, note="t")
        alerts = self.d / "alerts.jsonl"

        class FakeClient:
            def call(self, to, data):
                return "0x" + "0" * 64

            def native_balance(self, a):
                return 0

            def get_code(self, a):
                return "0x00"

        measured = {
            "address": addr, "holder_usd": 5000.0, "supply_raw": "0",
            "supply_decimals": 18, "symbol": None, "pool_usd": 0.0,
            "pools": {}, "value": None, "measured_usd": 5000.0, "label": w.LABEL,
        }
        with mock.patch.object(w, "measure_target", return_value=measured):
            summary = w.check_watches(
                store, FakeClient(), network="ethereum",
                alerts_path=alerts, default_min_value_usd=1000,
                emit=lambda s: None,
            )
        self.assertEqual(summary["alerts"], 1)
        lines = [json.loads(l) for l in alerts.read_text().splitlines() if l.strip()]
        self.assertEqual(lines[-1]["kind"], "watch_threshold")
        self.assertEqual(lines[-1]["address"], addr)
        self.assertGreaterEqual(lines[-1]["measured_usd"], 1000)
        # Second check without growth should not re-alert
        with mock.patch.object(w, "measure_target", return_value=measured):
            summary2 = w.check_watches(
                store, FakeClient(), network="ethereum",
                alerts_path=alerts, emit=lambda s: None,
            )
        self.assertEqual(summary2["alerts"], 0)
        store.close()


if __name__ == "__main__":
    unittest.main()
