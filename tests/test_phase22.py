"""Phase 22 — hunt counter uses holder_value; simulate invariants/oracle/trust; schema v7."""

from __future__ import annotations

import json
import os
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from auditor import hunt, monitor as m, simulate as sim


class Env(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.d = Path(self.tmp.name)
        self.env = mock.patch.dict(os.environ, {
            "AUDITOR_MONITOR_DB": str(self.d / "mon.db"),
            "AUDITOR_MONITOR_CACHE": str(self.d / "cache"),
            "AUDITOR_HISTORY_DB": str(self.d / "hist.db"),
            "AUDITOR_MONITOR_ALERTS": str(self.d / "a.jsonl"),
            "AUDITOR_PRICE_CACHE": str(self.d / "prices.json"),
            "AUDITOR_SOLC_AUTO_INSTALL": "0",
        })
        self.env.start()

    def tearDown(self):
        self.env.stop()
        self.tmp.cleanup()


class CounterTests(Env):
    def test_hunted_value_uses_holder_value_usd(self):
        store = m.MonitorStore(self.d / "mon.db")
        hunt.upsert_candidate(
            store, "ethereum", "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            protocol="Noon", status="scanned", holder_value_usd=46_000_000,
            onchain_tvl_usd=12.0, est_max_loss_usd=0.0, scanned_at=1_700_000_000,
            now=1_700_000_000)
        hunt.upsert_candidate(
            store, "ethereum", "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            protocol="Strata", status="scanned", holder_value_usd=23_000_000,
            onchain_tvl_usd=0.0, est_max_loss_usd=5.0, scanned_at=1_700_000_000,
            now=1_700_000_000)
        ov = hunt.hunt_overview(store.conn, "ethereum", since=0)
        # Prefer holder_value (46M+23M), not the tiny onchain/est_max_loss figures.
        self.assertAlmostEqual(ov["counters"]["hunted_value_scanned_today_usd"], 69_000_000)
        self.assertAlmostEqual(ov["counters"]["hunted_tvl_scanned_today_usd"], 69_000_000)
        store.close()


class OracleTrustTests(unittest.TestCase):
    def test_classify_chainlink_and_spot(self):
        src = "function price() { return AggregatorV3Interface(feed).latestRoundData(); }"
        r = sim.classify_oracles(src)
        self.assertIn("chainlink", r["kinds"])
        self.assertIn("missing-staleness-check", r["flags"])

        src2 = "pair.getReserves(); getAmountOut(amount, r0, r1);"
        r2 = sim.classify_oracles(src2)
        self.assertTrue(any(k.startswith("uniswap") or k == "spot-unknown" for k in r2["kinds"]))
        self.assertIn("spot-price-dependence", r2["flags"])

    def test_trust_map_extracts_addresses(self):
        src = "address constant FEED = 0x1111111111111111111111111111111111111111;"
        t = sim.build_trust_map(src)
        self.assertEqual(t["count"], 1)
        self.assertEqual(t["nodes"][0]["address"], "0x1111111111111111111111111111111111111111")


class InvariantPureTests(unittest.TestCase):
    def test_round_trip_fail_when_user_favoured(self):
        """Fake fork: convertToAssets/Shares favour the user → fail."""

        class FakeFork:
            def call_int(self, to, data):
                sel = data[:10]
                if sel == sim.SEL["asset()"]:
                    return None  # handled by call_addr
                if sel == sim.SEL["totalAssets()"]:
                    return 1_000_000 * 10**18
                if sel == sim.SEL["totalSupply()"]:
                    return 1_000_000 * 10**18
                if sel == sim.SEL["decimals()"]:
                    return 18
                if sel == sim.SEL["convertToAssets(uint256)"]:
                    return 10**18 + 100  # slightly high
                if sel == sim.SEL["convertToShares(uint256)"]:
                    # Returning more shares than deposited → user-favoured
                    arg = int(data[10:74], 16)
                    return arg + 50
                if sel == sim.SEL["balanceOf(address)"]:
                    return 0
                return 0

            def call_addr(self, to, data):
                if data.startswith(sim.SEL["asset()"]):
                    return "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2"
                return None

            def call(self, to, data):
                return "0x" + "0" * 64

        # Monkeypatch helpers used inside check
        results = sim.check_erc4626_invariants(FakeFork(), "0x" + "ab" * 20, holder_value_usd=1e6)
        names = {r.name: r for r in results}
        self.assertIn("round-trip-share", names)
        self.assertEqual(names["round-trip-share"].status, "fail")
        self.assertTrue(names["round-trip-share"].guidance)


class MigrationTests(Env):
    def test_v6_to_current(self):
        db = self.d / "old.db"
        conn = sqlite3.connect(db)
        conn.executescript("""
            CREATE TABLE hunt_candidates (
                network TEXT NOT NULL, address TEXT NOT NULL, status TEXT DEFAULT 'new',
                PRIMARY KEY (network, address));
            PRAGMA user_version = 6;
        """)
        conn.close()
        store = m.MonitorStore(db)
        ver = store.conn.execute("PRAGMA user_version").fetchone()[0]
        tables = {r[0] for r in store.conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        self.assertEqual(ver, m.MonitorStore.SCHEMA_VERSION)
        self.assertTrue({"simulate_runs", "simulate_invariants", "simulate_oracles", "simulate_trust"} <= tables)
        store.close()


class OverviewSimTests(Env):
    def test_simulation_overview_empty(self):
        store = m.MonitorStore(self.d / "mon.db")
        ov = sim.simulation_overview(store.conn)
        self.assertEqual(ov["runs"], [])
        store.close()

    def test_dashboard_simulate_route(self):
        store = m.MonitorStore(self.d / "mon.db")
        store.close()
        from fastapi.testclient import TestClient
        from auditor.dashboard.app import create_app
        client = TestClient(create_app())
        r = client.get("/api/simulate/live")
        self.assertEqual(r.status_code, 200)
        self.assertIn("runs", r.json())
        r = client.get("/hunt")
        self.assertEqual(r.status_code, 200)
        self.assertIn(b"Fork simulation", r.content)


if __name__ == "__main__":
    unittest.main()
