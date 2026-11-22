"""Phase 20 — hunt discovery, priority scoring, privileged-module-caller triage."""

from __future__ import annotations

import json
import os
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from auditor import hunt, triage as tr, monitor as m, value_at_risk as var
from auditor.model import Severity

PROJECT_ROOT = Path(__file__).resolve().parent.parent

STAKE = (
    "// SPDX-License-Identifier: MIT\n"
    "pragma solidity ^0.8.25;\n"
    "interface IERC20 { function transferFrom(address,address,uint256) external returns (bool); }\n"
    "abstract contract Governable {\n"
    "    address public governance;\n"
    "    error NotGovernance();\n"
    "    modifier onlyGovernance() { if (msg.sender != governance) revert NotGovernance(); _; }\n"
    "    function setGovernance(address g) external onlyGovernance { governance = g; }\n"
    "}\n"
    "abstract contract StakeManagerBase is Governable {\n"
    "    IERC20 public token;\n"
    "    address public jobRegistry;\n"
    "    address public disputeModule;\n"
    "    error NotJobRegistry();\n"
    "    error NotDisputeModule();\n"
    "    modifier onlyJobRegistry() { if (msg.sender != jobRegistry) revert NotJobRegistry(); _; }\n"
    "    modifier onlyDisputeModule() { if (msg.sender != disputeModule) revert NotDisputeModule(); _; }\n"
    "    function setModules(address registry, address dispute) external onlyGovernance {\n"
    "        jobRegistry = registry; disputeModule = dispute;\n"
    "    }\n"
    "    function _entry_lock(address from, uint256 amount) external onlyJobRegistry {\n"
    "        token.transferFrom(from, address(this), amount);\n"
    "    }\n"
    "    function _entry_lockReward(address from, uint256 amount) external onlyJobRegistry {\n"
    "        token.transferFrom(from, address(this), amount);\n"
    "    }\n"
    "    function _entry_lockDisputeFee(address payer, uint256 amount) external onlyDisputeModule {\n"
    "        token.transferFrom(payer, address(this), amount);\n"
    "    }\n"
    "}\n"
    "contract StakeManager is StakeManagerBase {\n"
    "    constructor(IERC20 t, address g) { token = t; governance = g; }\n"
    "}\n"
)

FREE_SETTER = (
    "pragma solidity ^0.8.0;\n"
    "contract OpenModule {\n"
    "    address public module;\n"
    "    IERC20 public token;\n"
    "    function setModule(address m) external { module = m; }\n"
    "    function pull(address from, uint256 amt) external {\n"
    "        require(msg.sender == module);\n"
    "        token.transferFrom(from, address(this), amt);\n"
    "    }\n"
    "}\n"
    "interface IERC20 { function transferFrom(address,address,uint256) external returns (bool); }\n"
)

PROTOCOLS = [
    {"name": "NewDex", "slug": "newdex", "category": "Dexs", "chains": ["Ethereum"],
     "chainTvls": {"Ethereum": 1_200_000}, "address": "0x1111111111111111111111111111111111111111",
     "listedAt": 1_750_000_000, "audits": "0", "module": "newdex", "parentProtocol": None,
     "forkedFrom": None},
    {"name": "Uniswap V3", "slug": "uniswap-v3", "category": "Dexs", "chains": ["Ethereum"],
     "chainTvls": {"Ethereum": 2_000_000_000}, "address": "0x1f9840a85d5af5bf1d1762f925bdaddc4201f984",
     "listedAt": 1_620_000_000, "audits": "2", "module": "uniswap",
     "parentProtocol": "parent#uniswap", "forkedFrom": None},
    {"name": "TinyBridge", "slug": "tinybridge", "category": "Bridge", "chains": ["Ethereum"],
     "chainTvls": {"Ethereum": 50_000}, "address": "0x2222222222222222222222222222222222222222",
     "listedAt": 1_760_000_000, "audits": "0", "module": "tinybridge",
     "parentProtocol": None, "forkedFrom": None},
    {"name": "BscOnly", "slug": "bsconly", "category": "Lending", "chains": ["Binance"],
     "chainTvls": {"Binance": 5_000_000}, "address": "bsc:0x3333333333333333333333333333333333333333",
     "listedAt": 1_760_000_000, "audits": "0", "module": "bsconly",
     "parentProtocol": None, "forkedFrom": None},
]
POOLS = {"data": [{"chain": "Ethereum", "project": "newdex", "tvlUsd": 800_000, "pool": "x"}]}
ADAPTER_SRC = (
    'module.exports = { ethereum: { vault: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",\n'
    '  pool: "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" },\n'
    '  bsc: { x: "0xcccccccccccccccccccccccccccccccccccccccc" } };\n'
)


def _finding(title, contract, function, file="contracts/X.sol", sev=Severity.HIGH, desc=""):
    from auditor.model import Finding, Confidence
    return Finding(title=title, description=desc or f"Slither detector: {title.split()[0]}.",
                   severity=sev, confidence=Confidence.MEDIUM, category="security",
                   affected_contract=contract, affected_function=function, affected_file=file)


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
            "AUDITOR_SOLC_ARTIFACTS": str(self.d / "art"),
        })
        self.env.start()
        self.t = [1_760_000_000.0]

    def tearDown(self):
        self.env.stop()
        self.tmp.cleanup()

    def clock(self):
        self.t[0] += 1
        return self.t[0]


class ModuleCallerTests(Env):
    def test_stake_manager_base_downgraded(self):
        root = self.d / "sm"
        f = root / "contracts" / "StakeManager.sol"
        f.parent.mkdir(parents=True)
        f.write_text(STAKE)
        fs = [_finding(f"arbitrary-send-erc20 in StakeManagerBase.{fn}", "StakeManagerBase", fn,
                       "contracts/StakeManager.sol",
                       desc="Slither detector: arbitrary-send-erc20.")
              for fn in ("_entry_lock", "_entry_lockReward", "_entry_lockDisputeFee")]
        r = tr.triage(fs, [f], root, "StakeManager")
        self.assertEqual(len(r.kept), 3)
        for x in fs:
            rec = r.records[id(x)]
            self.assertEqual(rec.action, "downgraded")
            self.assertEqual(rec.reason, "privileged-module-caller")
            self.assertEqual(x.severity, Severity.INFORMATIONAL)

    def test_free_setter_keeps_finding(self):
        root = self.d / "open"
        f = root / "contracts" / "OpenModule.sol"
        f.parent.mkdir(parents=True)
        f.write_text(FREE_SETTER)
        finding = _finding("arbitrary-send-erc20 in OpenModule.pull", "OpenModule", "pull",
                           "contracts/OpenModule.sol", desc="Slither detector: arbitrary-send-erc20.")
        r = tr.triage([finding], [f], root, "OpenModule")
        self.assertEqual(r.records[id(finding)].action, "kept")
        self.assertEqual(finding.severity, Severity.HIGH)

    def test_exposure_maps_to_privileged(self):
        e = var.exposure_for({"severity": "INFORMATIONAL", "title": "x"},
                             {"reason": "privileged-module-caller"})
        self.assertEqual(e["model"], "privileged")
        self.assertEqual(e["factor"], 0.0)


class DiscoveryTests(Env):
    def test_protocol_entries_filters(self):
        entries = hunt.protocol_entries(PROTOCOLS, POOLS, min_tvl=100_000)
        slugs = {e["slug"] for e in entries}
        self.assertEqual(slugs, {"newdex", "uniswap-v3"})
        new = next(e for e in entries if e["slug"] == "newdex")
        self.assertFalse(new["blue_chip"])
        self.assertIn(new["category_group"], ("swaps", "pools"))
        uni = next(e for e in entries if e["slug"] == "uniswap-v3")
        self.assertTrue(uni["blue_chip"])

    def test_adapter_address_extraction(self):
        addrs = hunt.adapter_addresses(ADAPTER_SRC)
        self.assertEqual(addrs[0], "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        self.assertIn("0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", addrs)

    def test_priority_score_prefers_mid_tvl_recent_unaudited(self):
        now = self.clock()
        sg, rg = hunt.priority_score(
            {"onchain_tvl_usd": 1_200_000, "listed_at": now - 30 * 86400,
             "audits": "0", "blue_chip": False, "verified": True, "has_code": True},
            now, {"signals": ["custom_amm_math"], "oz_fraction": 0.1, "known_fork": False})
        sb, rb = hunt.priority_score(
            {"onchain_tvl_usd": 2_000_000_000, "listed_at": now - 2000 * 86400,
             "audits": "2", "blue_chip": True, "verified": True, "has_code": True,
             "forked_from": "x"},
            now, {"signals": [], "oz_fraction": 0.8, "known_fork": True,
                  "contract_name": "UniswapV3Pool"})
        self.assertGreater(sg, sb)
        self.assertTrue(any("sweet spot" in x for x in rg))
        self.assertTrue(any("blue-chip" in x for x in rb))
        self.assertIn("NOT", hunt.SCORE_LABEL)

    def test_discover_persists_deduped(self):
        class Cache:
            def get(self, key, url, ttl, as_json=True, force=False):
                if "protocols" in key:
                    return PROTOCOLS
                if "pools" in key:
                    return POOLS
                if "newdex" in key:
                    return ADAPTER_SRC
                if "uniswap" in key:
                    return "module.exports={}"
                raise hunt.TransientError("miss")

        cfg = hunt.HuntConfig(db_path=self.d / "mon.db", cache_dir=self.d / "c",
                              min_tvl=100_000, max_protocols=10)
        hunter = hunt.Hunter(cfg, client=None, cache=Cache(), emit=lambda s: None, clock=self.clock)
        stats = hunter.refresh()
        self.assertGreaterEqual(stats["discovered"], 2)
        addrs = {r["address"] for r in hunter.store.conn.execute(
            "SELECT address FROM hunt_candidates").fetchall()}
        self.assertIn("0x1111111111111111111111111111111111111111", addrs)
        self.assertIn("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", addrs)
        stats2 = hunter.refresh()
        n = hunter.store.conn.execute("SELECT COUNT(*) FROM hunt_candidates").fetchone()[0]
        self.assertEqual(n, len(addrs))
        hunter.store.close()


class FakeChain:
    def __init__(self, code=None, sources=None, native=None):
        self.code, self.sources = code or {}, sources or {}
        self.native = native or {}
        self.chain_id, self.api_key, self.rpc_url = 1, "t", "http://x"

    def code_size(self, a):
        return self.code.get(a.lower(), 0)

    def verified_source(self, a):
        return self.sources.get(a.lower())

    def native_balance(self, a):
        return self.native.get(a.lower(), 0)

    def token_balance(self, t, a):
        return 0

    def block_number(self):
        return 1


class FakePrices:
    def prices(self, ids):
        return {"prices": {i: 3000.0 if "eth" in i or i == "weth" else 1.0 for i in ids},
                "as_of": 1_760_000_000.0, "source": "test", "stale": False, "error": None}


class MeasureScanTests(Env):
    def test_measure_and_scan_pipeline_mocked(self):
        addr = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        src = ("pragma solidity ^0.8.0; contract Pool { "
               "function withdraw() external { "
               "(bool ok,) = msg.sender.call{value: address(this).balance}(\"\"); require(ok); } }")
        rec = {"SourceCode": json.dumps({"language": "Solidity",
                                         "sources": {"contracts/Pool.sol": {"content": src}},
                                         "settings": {"optimizer": {"enabled": False}}}),
               "ContractName": "Pool", "CompilerVersion": "v0.8.20+commit.a1b79de6",
               "OptimizationUsed": "0", "Runs": "200", "EVMVersion": "Default",
               "SourceProvider": "test"}
        chain = FakeChain(code={addr: 100}, sources={addr: rec}, native={addr: 100 * 10**18})
        cfg = hunt.HuntConfig(db_path=self.d / "mon.db", cache_dir=self.d / "hunt",
                              alerts_path=self.d / "a.jsonl", scan_per_cycle=1,
                              measure_per_cycle=5, solc_auto_install=False,
                              target_tvl_low=100_000, target_tvl_high=5_000_000,
                              min_tvl=100_000, max_protocols=1)
        # seed candidate
        store = m.MonitorStore(cfg.db_path)
        hunt.upsert_candidate(store, "ethereum", addr, protocol="NewDex", slug="newdex",
                              category="Dexs", category_group="swaps", source="defillama",
                              llama_tvl_usd=1_200_000, listed_at=self.clock() - 40 * 86400,
                              audits="0", blue_chip=False, status="new", now=self.clock())
        store.close()

        from auditor.monitor import AnalysisResult, build_execution
        from auditor.model import Finding
        from auditor.triage import apply_to_pipeline

        def fake_analyzer(files, source, chash, **kw):
            f = Finding(title="arbitrary-send-eth in Pool.withdraw", severity=Severity.HIGH,
                        confidence="HIGH", category="security",
                        description="Slither detector: arbitrary-send-eth.",
                        affected_contract="Pool", affected_function="withdraw",
                        affected_file="contracts/Pool.sol")
            tri = apply_to_pipeline([f], files, Path(kw.get("root") or files[0].parent), "Pool")
            return AnalysisResult(tri.kept, True, [],
                                  build_execution(None, tri.kept, True, [], None),
                                  None, suppressed=list(tri.suppressed), triage=tri)

        class Cache:
            def get(self, *a, **k):
                raise hunt.TransientError("unused")

        hunter = hunt.Hunter(cfg, chain, cache=Cache(), emit=lambda s: None, clock=self.clock,
                             sleep=lambda s: None, price_source=FakePrices(),
                             analyzer=fake_analyzer, recorder=lambda *a, **k: "scan-1")
        measured = hunter.measure()
        self.assertEqual(len(measured), 1)
        self.assertEqual(measured[0]["status"], "ready")
        self.assertAlmostEqual(measured[0]["onchain_tvl_usd"], 300_000.0)
        scanned = hunter.scan_top(1)
        self.assertEqual(len(scanned), 1)
        self.assertEqual(scanned[0]["status"], "scanned")
        origin = hunter.store.conn.execute(
            "SELECT origin FROM monitor_scans ORDER BY id DESC LIMIT 1").fetchone()
        self.assertEqual(origin[0], "hunt")
        hunter.store.close()


class OverviewTests(Env):
    def test_overview_and_dashboard_route(self):
        store = m.MonitorStore(self.d / "mon.db")
        hunt.upsert_candidate(store, "ethereum", "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                              protocol="NewDex", slug="newdex", category="Dexs",
                              category_group="swaps", source="defillama", llama_tvl_usd=1_200_000,
                              onchain_tvl_usd=1_100_000, priority_score=42.5,
                              score_reasons=json.dumps(["sweet spot"]), status="scanned",
                              findings=1, est_max_loss_usd=200_000, scanned_at=self.clock(),
                              now=self.clock())
        ov = hunt.hunt_overview(store.conn, "ethereum", since=0, sort="priority")
        self.assertEqual(ov["counters"]["total"], 1)
        self.assertEqual(ov["counters"]["hunted_value_scanned_today_usd"], 1_100_000)  # Phase 22: holder/onchain TVL, not est_max_loss
        self.assertIn("NOT evidence", ov["counters"]["priority_label"])
        store.close()

        from fastapi.testclient import TestClient
        from auditor.dashboard.app import create_app
        client = TestClient(create_app())
        r = client.get("/hunt")
        self.assertEqual(r.status_code, 200)
        self.assertIn(b"High-value Target Hunt", r.content)
        r = client.get("/api/hunt/live?sort=priority")
        self.assertEqual(r.status_code, 200)
        body = r.json()
        self.assertEqual(body["counters"]["total"], 1)
        self.assertEqual(body["candidates"][0]["protocol"], "NewDex")

    def test_cli_hunt_status(self):
        store = m.MonitorStore(self.d / "mon.db")
        hunt.upsert_candidate(store, "ethereum", "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                              protocol="NewDex", status="ready", priority_score=10,
                              llama_tvl_usd=1e6, now=self.clock())
        store.close()
        from auditor.cli import main
        import io, contextlib
        buf = io.StringIO()
        with mock.patch("sys.argv", ["audit.py", "hunt-status", "--json"]):
            with contextlib.redirect_stdout(buf):
                code = main()
        self.assertEqual(code, 0)
        payload = json.loads(buf.getvalue())
        self.assertEqual(payload["counters"]["total"], 1)


class MigrationTests(Env):
    def test_v4_to_v5(self):
        db = self.d / "old.db"
        conn = sqlite3.connect(db)
        conn.executescript("""
            CREATE TABLE monitor_scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT, network TEXT NOT NULL, address TEXT NOT NULL,
                stage TEXT NOT NULL, status TEXT NOT NULL, started_at REAL NOT NULL,
                finished_at REAL, tvl_usd REAL, est_max_loss_usd REAL);
            PRAGMA user_version = 4;
        """)
        conn.close()
        store = m.MonitorStore(db)
        ver = store.conn.execute("PRAGMA user_version").fetchone()[0]
        tables = {r[0] for r in store.conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        cols = {r[1] for r in store.conn.execute("PRAGMA table_info(monitor_scans)")}
        self.assertEqual(ver, m.MonitorStore.SCHEMA_VERSION)
        self.assertTrue({"hunt_candidates", "hunt_runs"} <= tables)
        self.assertIn("origin", cols)
        store.close()


if __name__ == "__main__":
    unittest.main()
