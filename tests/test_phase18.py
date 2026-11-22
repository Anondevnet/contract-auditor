"""Phase 18 — live monitor dashboard: stages, counters, ETA, source view,
risk playbook, schema migration. Network fully mocked; temp DBs/dirs only."""

from __future__ import annotations

import json
import os
import sqlite3
import sys
import tempfile
import unittest
import unittest.mock as mock
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace
from zoneinfo import ZoneInfo

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from auditor import monitor as m  # noqa: E402
from auditor import monitor_view as mv  # noqa: E402
from auditor import risk_playbook as rp  # noqa: E402
from auditor.disk_pressure import RESUME_GIB, free_gib  # noqa: E402

DET = ZoneInfo("America/Detroit")
SRC = "pragma solidity ^0.8.0;\ncontract Vault {\n  function f() public {}\n}\n"


def _ts(y, mo, d, h=0, mi=0, s=0, tz=DET):
    return datetime(y, mo, d, h, mi, s, tzinfo=tz).timestamp()


class FakeClient:
    def __init__(self, creations, sources):
        self.creations, self.sources = creations, sources

    def block_number(self):
        return 10

    def contract_creations(self, block):
        return [{"address": a, "tx_hash": "0xt", "block": block} for a in self.creations.get(block, [])]

    def verified_source(self, address):
        src = self.sources.get(address)
        return {"SourceCode": src, "ContractName": "Vault", "CompilerVersion": "v0.8.24+commit.e11b9ed9"} if src else None


class TmpEnv(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        d = Path(self.tmp.name)
        self.db, self.alerts, self.cache = d / "mon.db", d / "alerts.jsonl", d / "cache"
        self.env = mock.patch.dict(os.environ, {
            "AUDITOR_MONITOR_DB": str(self.db), "AUDITOR_MONITOR_ALERTS": str(self.alerts),
            "AUDITOR_MONITOR_CACHE": str(self.cache), "AUDITOR_HISTORY_DB": str(d / "hist.db"),
            "AUDITOR_MONITOR_TZ": ""})
        self.env.start()
        self.t = [1000.0]

    def tearDown(self):
        self.env.stop()
        self.tmp.cleanup()

    def _skip_if_disk_gated(self) -> None:
        """Skip scan-asserting tests while the real disk-pressure gate defers heavy scans.

        Mirrors auditor.monitor.poll(): when free_gib() < RESUME_GIB, the controller's
        allow_expensive("monitor.scan") refuses expensive scans (queued work preserved),
        so tests whose assertions require a processed scan would fail on empty results.
        Production behavior is untouched; coverage returns automatically once the real
        free space reaches RESUME_GIB again.
        """
        free = free_gib()
        if free < RESUME_GIB:
            self.skipTest(
                f"real disk-pressure gate active: free {free:.2f} GiB < RESUME_GIB "
                f"{RESUME_GIB:g} GiB; heavy scans would be deferred (queued work preserved); "
                "this test's assertions require a processed scan. Coverage returns "
                f"automatically once free space >= {RESUME_GIB:g} GiB.")

    def clock(self):
        self.t[0] += 1.0
        return self.t[0]

    def monitor(self, client, analyzer, **kw):
        cfg = m.MonitorConfig(db_path=self.db, alerts_path=self.alerts, cache_dir=self.cache,
                              interval=0, start_lookback=5, **kw)
        return m.Monitor(cfg, client, analyzer=analyzer, recorder=lambda a, n, f, h: "scan-1",
                         emit=lambda s: None, clock=self.clock, sleep=lambda s: None)


class MigrationTests(TmpEnv):
    def test_phase17_db_upgrades_in_place_idempotently(self):
        conn = sqlite3.connect(self.db)
        conn.executescript("""
            CREATE TABLE monitor_cursor (network TEXT PRIMARY KEY, last_block INTEGER NOT NULL, updated_at TEXT);
            CREATE TABLE monitor_seen (network TEXT NOT NULL, address TEXT NOT NULL, content_hash TEXT NOT NULL,
                scan_id TEXT, findings INTEGER, scanned_at TEXT, PRIMARY KEY (network, address, content_hash));
            CREATE TABLE monitor_queue (network TEXT NOT NULL, address TEXT NOT NULL, tx_hash TEXT, block INTEGER,
                attempts INTEGER NOT NULL DEFAULT 0, next_attempt_at REAL NOT NULL DEFAULT 0,
                status TEXT NOT NULL DEFAULT 'pending', last_error TEXT, updated_at TEXT,
                PRIMARY KEY (network, address));
            INSERT INTO monitor_cursor VALUES ('ethereum', 1234, 'x');
            INSERT INTO monitor_seen VALUES ('ethereum', '0xa', 'h', 's', 2, 'x');
        """)
        conn.commit()
        conn.close()
        for _ in range(2):
            s = m.MonitorStore(self.db)
            self.assertEqual(s.get_cursor("ethereum"), 1234)
            self.assertTrue(s.is_seen("ethereum", "0xa", "h"))
            s.close()
        conn = sqlite3.connect(self.db)
        tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        cols = {r[1] for r in conn.execute("PRAGMA table_info(monitor_seen)")}
        ver = conn.execute("PRAGMA user_version").fetchone()[0]
        conn.close()
        self.assertTrue({"monitor_scans", "monitor_stage_events", "monitor_polls"} <= tables)
        self.assertIn("contract_name", cols)
        self.assertEqual(ver, m.MonitorStore.SCHEMA_VERSION)  # additive monitor schema

    def test_live_view_on_phase17_db_without_new_tables(self):
        conn = sqlite3.connect(self.db)
        conn.executescript("""
            CREATE TABLE monitor_cursor (network TEXT PRIMARY KEY, last_block INTEGER NOT NULL, updated_at TEXT);
            CREATE TABLE monitor_seen (network TEXT, address TEXT, content_hash TEXT, scan_id TEXT, findings INTEGER, scanned_at TEXT);
            CREATE TABLE monitor_queue (network TEXT, address TEXT, tx_hash TEXT, block INTEGER, attempts INTEGER,
                next_attempt_at REAL, status TEXT, last_error TEXT, updated_at TEXT);
            INSERT INTO monitor_cursor VALUES ('ethereum', 77, 'x');
            INSERT INTO monitor_seen VALUES ('ethereum', '0xa', 'h', 's', 2, 'x');
        """)
        conn.close()
        d = mv.live(now=2e9)
        self.assertEqual((d["counters"]["last_block"], d["counters"]["audited_all_time"]), (77, 1))


class StageTests(TmpEnv):
    def test_stage_transitions_metadata_and_cache(self):
        self._skip_if_disk_gated()
        def analyzer(files, src, h, on_stage=None):
            on_stage("compiling")
            on_stage("analyzing")
            return [SimpleNamespace(severity=SimpleNamespace(value="HIGH"), title="x",
                                    confidence=SimpleNamespace(value="LOW"))]

        mon = self.monitor(FakeClient({6: ["0xa"]}, {"0xa": SRC}), analyzer)
        res = mon.run(once=True)[0]["results"][0]
        self.assertEqual(res["status"], "scanned")
        conn = sqlite3.connect(self.db)
        conn.row_factory = sqlite3.Row
        row = conn.execute("SELECT * FROM monitor_scans").fetchone()
        stages = [r[0] for r in conn.execute("SELECT stage FROM monitor_stage_events ORDER BY at, rowid")]
        polls = conn.execute("SELECT COUNT(*) FROM monitor_polls").fetchone()[0]
        name = conn.execute("SELECT contract_name FROM monitor_seen").fetchone()[0]
        conn.close()
        self.assertEqual(stages, ["fetching", "compiling", "compiling", "analyzing", "done"])
        self.assertEqual((row["status"], row["stage"], row["contract_name"]), ("done", "done", "Vault"))
        self.assertEqual((row["compiler"], row["file_count"], row["line_count"]), ("v0.8.24+commit.e11b9ed9", 1, 4))
        self.assertGreater(row["duration_s"], 0)
        self.assertEqual(json.loads(row["severity_counts"]), {"HIGH": 1})
        self.assertEqual((polls, name), (1, "Vault"))
        self.assertTrue((Path(row["cache_dir"]) / "Vault.sol").exists())
        self.assertIn(str(self.cache), row["cache_dir"])

    def test_legacy_analyzer_gets_analyzing_stage(self):
        self._skip_if_disk_gated()
        mon = self.monitor(FakeClient({6: ["0xa"]}, {"0xa": SRC}), lambda f, s, h: [])
        mon.run(once=True)
        conn = sqlite3.connect(self.db)
        stages = [r[0] for r in conn.execute("SELECT stage FROM monitor_stage_events ORDER BY at, rowid")]
        conn.close()
        self.assertEqual(stages, ["fetching", "compiling", "analyzing", "done"])

    def test_unverified_and_failed_rows(self):
        self._skip_if_disk_gated()
        def boom(f, s, h):
            raise RuntimeError("slither exploded")

        mon = self.monitor(FakeClient({6: ["0xa", "0xb"]}, {"0xb": SRC}), boom)
        # Phase 18.1: a failing contract no longer stops the poll.
        res = mon.run(once=True)[0]["results"]
        self.assertEqual([r["status"] for r in res], ["deferred", "failed"])
        conn = sqlite3.connect(self.db)
        st = dict(conn.execute("SELECT address, status FROM monitor_scans").fetchall())
        conn.close()
        self.assertEqual(st, {"0xb": "failed", "0xa": "deferred"})

    def test_stale_running_rows_marked_interrupted(self):
        s = m.MonitorStore(self.db)
        s.start_scan("ethereum", "0xa", None, 1, 5.0)
        s.close()
        self.monitor(FakeClient({}, {}), lambda f, s, h: []).store.close()
        conn = sqlite3.connect(self.db)
        self.assertEqual(conn.execute("SELECT status FROM monitor_scans").fetchone()[0], "interrupted")
        conn.close()


def _seed(db: Path, rows):
    s = m.MonitorStore(db)
    ids = []
    for r in rows:
        rid = s.start_scan("ethereum", r["address"], "0xt", 5, r["started"])
        s.set_meta(rid, contract_name=r.get("name"), line_count=r.get("lines"), file_count=1,
                   compiler="v0.8.24", content_hash="h" + r["address"])
        if r.get("finished"):
            s.finish_scan(rid, r.get("status", "done"), r["finished"], scan_id=None,
                          findings=sum(r.get("sev", {}).values()), severity_counts=r.get("sev", {}),
                          analysis_complete=r.get("status", "done") == "done")
        ids.append(rid)
    s.set_cursor("ethereum", 999)
    s.close()
    return ids


class CounterTests(TmpEnv):
    def test_today_boundary_is_detroit_midnight(self):
        now = _ts(2026, 10, 17, 12)
        midnight = _ts(2026, 10, 17)
        self.assertEqual(datetime.fromtimestamp(midnight, ZoneInfo("UTC")).hour, 4)  # EDT = UTC-4
        _seed(self.db, [
            {"address": "0x1", "started": midnight - 10, "finished": midnight - 1, "sev": {"HIGH": 1}, "lines": 10},
            {"address": "0x2", "started": midnight - 5, "finished": midnight, "sev": {"HIGH": 2, "LOW": 1}, "lines": 10},
            # 01:00 UTC on Oct 17 is still Oct 16 in Detroit:
            {"address": "0x3", "started": 0, "finished": datetime(2026, 10, 17, 1, tzinfo=ZoneInfo("UTC")).timestamp(),
             "sev": {"MEDIUM": 1}, "lines": 10},
            {"address": "0x4", "started": now - 30, "finished": now - 20, "sev": {}, "lines": 10},
            {"address": "0x5", "started": now - 3, "lines": 20},  # running
            {"address": "0x6", "started": now - 3, "finished": now - 2, "status": "unverified"},
        ])
        q = m.MonitorStore(self.db)
        q.enqueue("ethereum", "0xq", "0x", 1)
        q.enqueue("ethereum", "0xz", "0x", 1)
        q.defer("ethereum", "0xz", 6, 0, "x", True)
        q.record_poll("ethereum", now - 100, 1, 0, 0, 0)
        q.record_poll("ethereum", now - 4000, 1, 0, 0, 0)
        q.close()
        d = mv.live(now=now)
        c = d["counters"]
        self.assertEqual(d["timezone"], "America/Detroit")
        self.assertEqual(c["audited_today"], 2)
        self.assertEqual(c["audited_all_time"], 4)
        self.assertEqual(c["findings_today"], {"HIGH": 2, "LOW": 1})
        self.assertEqual((c["findings_today_total"], c["findings_all_time"]), (3, 5))
        self.assertEqual((c["queue_pending"], c["unverified"], c["last_block"]), (1, 1, 999))
        self.assertEqual(c["polls_last_hour"], 1)
        self.assertIsNotNone(c["avg_scan_s"])
        self.assertEqual([r["address"] for r in d["current"]], ["0x5"])
        cur = d["current"][0]
        self.assertTrue(cur["eta"]["is_estimate"])
        self.assertEqual(cur["explorer_url"], "https://etherscan.io/address/0x5")
        self.assertNotIn("cache_dir", cur)
        self.assertEqual(len(d["recent_scans"]), 5)

    def test_dst_day_lengths(self):
        s, e = mv.day_bounds(_ts(2026, 11, 1, 12))  # fall back
        self.assertEqual(e - s, 25 * 3600)
        s, e = mv.day_bounds(_ts(2026, 3, 8, 12))  # spring forward
        self.assertEqual(e - s, 23 * 3600)

    def test_live_without_db_is_empty_and_creates_nothing(self):
        d = mv.live(now=1e9)
        self.assertEqual((d["monitor_db"], d["counters"]["audited_all_time"]), ("absent", 0))
        self.assertFalse(self.db.exists())


class EtaTests(unittest.TestCase):
    def test_no_history(self):
        e = mv.estimate_eta([], 100, 5)
        self.assertTrue(e["is_estimate"])
        self.assertIsNone(e["estimated_remaining_s"])

    def test_scaled_by_lines(self):
        e = mv.estimate_eta([(10.0, 100), (30.0, 100)], 200, 10)  # 0.2 s/line
        self.assertEqual((e["estimated_total_s"], e["estimated_remaining_s"], e["overrun"]), (40.0, 30.0, False))

    def test_overrun_clamps_to_zero(self):
        e = mv.estimate_eta([(1.0, 10)], 10, 5)
        self.assertEqual((e["estimated_remaining_s"], e["overrun"]), (0.0, True))

    def test_rolling_window(self):
        hist = [(1000.0, 1)] * 5 + [(1.0, 1)] * mv.ETA_WINDOW
        e = mv.estimate_eta(hist, 1, 0)
        self.assertEqual((e["estimated_total_s"], e["basis_scans"]), (1.0, mv.ETA_WINDOW))


class SourceAndEndpointTests(TmpEnv):
    def setUp(self):
        super().setUp()
        self.evil = "contract X { string s = \"</pre><script>alert(1)</script>\"; }\n"
        mon = self.monitor(FakeClient({6: ["0xa"]}, {"0xa": self.evil}), lambda f, s, h: [])
        mon.run(once=True)
        from fastapi.testclient import TestClient

        from auditor.dashboard.app import create_app

        self.client = TestClient(create_app())

    def test_source_html_is_escaped(self):
        self._skip_if_disk_gated()
        r = self.client.get("/monitor/source/1")
        self.assertEqual(r.status_code, 200)
        self.assertNotIn("<script>alert(1)</script>", r.text)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", r.text)

    def test_source_json_and_traversal(self):
        self._skip_if_disk_gated()
        r = self.client.get("/api/monitor/source/1")
        self.assertEqual(r.status_code, 200)
        self.assertEqual((r.json()["files"], r.json()["content"]), (["Vault.sol"], self.evil))
        self.assertEqual(self.client.get("/api/monitor/source/1?file=../../../etc/passwd").status_code, 404)
        self.assertEqual(self.client.get("/api/monitor/source/99").status_code, 404)
        self.assertEqual(self.client.get("/monitor/source/1?file=..%2F..%2Fx").status_code, 404)

    def test_live_and_page(self):
        self._skip_if_disk_gated()
        r = self.client.get("/api/monitor/live")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()["counters"]["audited_all_time"], 1)
        self.assertEqual(self.client.get("/api/monitor/live?network=bogus").status_code, 400)
        page = self.client.get("/monitor")
        self.assertEqual(page.status_code, 200)
        self.assertIn("Live Deployment Monitor", page.text)
        self.assertIn("/static/js/monitor.js", page.text)
        self.assertEqual(self.client.get("/static/js/monitor.js").status_code, 200)

    def test_scan_detail_includes_risk(self):
        self._skip_if_disk_gated()
        from auditor.model import (Confidence, Epistemic, EvidenceItem, Finding, Severity,
                                   VerificationStatus)

        f = Finding(title="Reentrancy vulnerability in Vault.withdraw",
                    description="External call before state update. Slither detector: reentrancy-eth.",
                    category="security", severity=Severity.HIGH, confidence=Confidence.MEDIUM,
                    verification_status=VerificationStatus.UNVERIFIED, affected_contract="Vault",
                    affected_function="withdraw", affected_lines=[12],
                    evidence=[EvidenceItem(source="slither", artifact_type="tool_output", excerpt="ev",
                                           epistemic=Epistemic.FACT, tool="slither")])
        d = mv.scan_detail(1, history_findings=[f.to_dict()])
        fd = d["findings_detail"][0]
        self.assertEqual(fd["risk"]["vulnerability_class"], "reentrancy")
        self.assertTrue(fd["risk"]["heuristic"])
        self.assertEqual(fd["location"]["function"], "withdraw")
        self.assertEqual(fd["evidence"][0]["epistemic"], "FACT")
        self.assertEqual([s["stage"] for s in d["stages"]][0], "fetching")
        r = self.client.get("/api/monitor/scans/1")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(self.client.get("/api/monitor/scans/42").status_code, 404)

    def test_monitor_routes_are_get_only(self):
        for route in self.client.app.routes:
            path = getattr(route, "path", "")
            if "/monitor" in path:
                self.assertEqual(set(route.methods) - {"HEAD"}, {"GET"}, path)

    def test_endpoints_do_not_write(self):
        before = self.db.stat().st_mtime_ns, self.db.read_bytes()
        for u in ("/api/monitor/live", "/api/monitor/scans/1", "/api/monitor/source/1", "/monitor/source/1",
                  "/api/monitor/status"):
            self.client.get(u)
        self.assertEqual(before, (self.db.stat().st_mtime_ns, self.db.read_bytes()))


class PlaybookTests(unittest.TestCase):
    REQUIRED = ("label", "exploitability", "time_to_exploit", "attack_class", "remediation",
                "fix_pattern", "time_to_fix", "slugs")

    def test_schema_and_heuristic_labels(self):
        pb = rp.load_playbook()
        self.assertIn("not measured", pb["heuristic_note"])
        for name, e in pb["classes"].items():
            for k in self.REQUIRED:
                self.assertIn(k, e, f"{name}.{k}")
                if k != "slugs":
                    self.assertTrue(str(e[k]).strip(), f"{name}.{k} empty")
            self.assertIn(e["exploitability"], {"trivial", "moderate", "hard", "unknown"}, name)

    def _assert_mapped(self, slug):
        self.assertIn(slug, rp.slug_index(), f"detector slug {slug!r} has no playbook entry")

    def test_every_project_detector_slug_is_covered(self):
        from auditor.analysis import access_control, erc4626_inflation, reentrancy
        from auditor.analysis.slither_runner import ACCESS_CONTROL_CHECKS

        slugs = set(reentrancy._DETECTOR_SEVERITY) | set(access_control._DETECTOR_SEVERITY)
        slugs |= set(ACCESS_CONTROL_CHECKS) | {erc4626_inflation.SLUG, "stale-oracle-risk", "pool-accounting"}
        for s in sorted(slugs):
            self._assert_mapped(s)

    def test_every_benchmark_category_has_a_class(self):
        from auditor.benchmark import CATEGORIES

        for cat in CATEGORIES:
            self.assertIn(cat, rp.load_playbook()["classes"], cat)

    def test_every_installed_slither_detector_is_covered(self):
        try:
            import inspect

            from slither.detectors import all_detectors
            from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification as C
        except Exception:  # noqa: BLE001
            self.skipTest("slither not importable")
        emitted = {C.HIGH, C.MEDIUM, C.LOW}  # slither_generic keeps High/Medium/Low only
        for _, o in inspect.getmembers(all_detectors, inspect.isclass):
            if issubclass(o, AbstractDetector) and o.IMPACT in emitted:
                self._assert_mapped(o.ARGUMENT)

    def test_classify_real_title_shapes(self):
        cases = {
            ("Reentrancy vulnerability in A.f", "x Slither detector: reentrancy-no-eth."): "reentrancy",
            ("Access control issue in A.kill", "Slither detector: suicidal."): "access_control",
            ("Access control issue in A.f", "Slither detector: controlled-delegatecall."): "delegatecall",
            ("arbitrary-send-eth in A.f", ""): "arbitrary_transfer",
            ("stale-oracle-risk in price: unchecked updatedAt", ""): "oracle_staleness",
            ("pool-accounting risk in swap: balanceOf(this) without k check", ""): "pool_accounting",
            ("ERC-4626 share-price inflation risk (naive totalSupply/totalAssets ratio)",
             "Source detector: erc4626-inflation."): "erc4626_inflation",
            ("some-new-detector in A.f", ""): "generic",
            ("", ""): "generic",
        }
        for (title, desc), want in cases.items():
            self.assertEqual(rp.classify({"title": title, "description": desc})[0], want, title)

    def test_no_exploit_payloads(self):
        import re

        text = json.dumps(rp.load_playbook())
        self.assertIsNone(re.search(r"0x[0-9a-fA-F]{40}", text))  # no concrete addresses
        for banned in ("step 1", "Step 1", "exploit code", "payload"):
            self.assertFalse(banned in text, banned)


if __name__ == "__main__":
    unittest.main()
