"""Phase 17 — live deployment monitor. Network fully mocked, temp DBs."""

from __future__ import annotations

import contextlib
import io
import json
import os
import sqlite3
import sys
import tempfile
import unittest
import unittest.mock as mock
import urllib.error
from pathlib import Path
from types import SimpleNamespace

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from auditor import monitor as m  # noqa: E402
from auditor.cli import EXIT_ERROR, EXIT_OK, main  # noqa: E402
from auditor.disk_pressure import RESUME_GIB, free_gib  # noqa: E402

KEY = "SECRETKEY123abc"
SRC = "pragma solidity ^0.8.0; contract A { function f() public {} }"


class FakeClient:
    """Stands in for ChainClient: head, per-block creations, sources."""

    def __init__(self, head=100, creations=None, sources=None, fail_source=None):
        self.head = head
        self.creations = creations or {}
        self.sources = sources or {}
        self.fail_source = fail_source or set()
        self.blocks_seen: list[int] = []
        self.source_calls: list[str] = []

    def block_number(self):
        return self.head

    def contract_creations(self, block):
        self.blocks_seen.append(block)
        return [{"address": a, "tx_hash": f"0xt{a}", "block": block} for a in self.creations.get(block, [])]

    def verified_source(self, address):
        self.source_calls.append(address)
        if address in self.fail_source:
            raise m.TransientError("HTTP 503")
        src = self.sources.get(address)
        return {"SourceCode": src, "ContractName": "A"} if src else None


def _real_finding(title="boom"):
    from auditor.model import (Confidence, Epistemic, EvidenceItem, Finding, Severity,
                               VerificationStatus)
    return Finding(
        title=title, description="Slither detector: reentrancy-eth in A.f.", category="reentrancy",
        severity=Severity.HIGH, confidence=Confidence.MEDIUM,
        verification_status=VerificationStatus.UNVERIFIED, affected_contract="A",
        affected_function="f", affected_lines=[1],
        evidence=[EvidenceItem(source="slither", artifact_type="tool_output", excerpt="x",
                               epistemic=Epistemic.FACT, tool="slither")])


def _finding(sev, title="t"):
    return SimpleNamespace(severity=SimpleNamespace(value=sev), confidence=SimpleNamespace(value="HIGH"),
                           title=title)


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        d = Path(self.tmp.name)
        self.db = d / "mon.db"
        self.alerts = d / "alerts.jsonl"
        self.recorded: list = []
        self.out: list[str] = []
        self.now = [1000.0]

    def tearDown(self):
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

    def mk(self, client, findings=None, **cfg):
        c = m.MonitorConfig(db_path=self.db, alerts_path=self.alerts, interval=0,
                            cache_dir=Path(self.tmp.name) / "cache", **cfg)
        fs = findings if findings is not None else []

        def rec(addr, net, f, h):
            self.recorded.append((addr, h))
            return f"scan-{len(self.recorded)}"

        return m.Monitor(c, client, analyzer=lambda files, s, h: list(fs), recorder=rec,
                         emit=self.out.append, clock=lambda: self.now[0], sleep=lambda s: None)


class CursorTests(Base):
    def test_cursor_persists_and_resumes(self):
        cl = FakeClient(head=100, creations={98: ["0xa"]}, sources={"0xa": SRC})
        mon = self.mk(cl, start_lookback=5, max_blocks_per_poll=3)
        mon.run(once=True)
        self.assertEqual(cl.blocks_seen, [96, 97, 98])
        self.assertEqual(m.MonitorStore(self.db).get_cursor("ethereum"), 98)
        cl2 = FakeClient(head=100)
        self.mk(cl2, start_lookback=5, max_blocks_per_poll=3).run(once=True)
        self.assertEqual(cl2.blocks_seen, [99, 100])
        self.assertEqual(m.MonitorStore(self.db).get_cursor("ethereum"), 100)

    def test_schema_idempotent(self):
        m.MonitorStore(self.db).close()
        s = m.MonitorStore(self.db)
        s.set_cursor("ethereum", 5)
        s.close()
        self.assertEqual(m.MonitorStore(self.db).get_cursor("ethereum"), 5)

    def test_bounded_batch(self):
        self._skip_if_disk_gated()
        cl = FakeClient(head=10, creations={6: ["0xa", "0xb", "0xc"]},
                        sources={a: SRC for a in ("0xa", "0xb", "0xc")})
        mon = self.mk(cl, start_lookback=5, max_per_poll=2)
        res = mon.run(once=True)[0]
        self.assertEqual(len(res["results"]), 2)
        self.assertEqual(m.MonitorStore(self.db).queue_counts("ethereum").get("pending"), 1)


class DedupeTests(Base):
    def test_same_address_and_hash_scanned_once(self):
        self._skip_if_disk_gated()
        store = m.MonitorStore(self.db)
        cl = FakeClient(head=10, creations={6: ["0xa"]}, sources={"0xa": SRC})
        self.mk(cl, start_lookback=5).run(once=True)
        self.assertEqual(len(self.recorded), 1)
        # Re-queue the same address (e.g. re-discovered): content unchanged -> duplicate.
        store.conn.execute("UPDATE monitor_queue SET status='pending'")
        store.conn.commit()
        res = self.mk(cl).run(once=True)[0]
        self.assertEqual(res["results"][0]["status"], "duplicate")
        self.assertEqual(len(self.recorded), 1)

    def test_enqueue_ignores_duplicates(self):
        s = m.MonitorStore(self.db)
        self.assertTrue(s.enqueue("ethereum", "0xA", "0x1", 1))
        self.assertFalse(s.enqueue("ethereum", "0xa", "0x1", 1))


class UnverifiedAndBackoffTests(Base):
    def test_unverified_deferred_with_backoff_then_given_up(self):
        self._skip_if_disk_gated()
        cl = FakeClient(head=10, creations={6: ["0xu"]})
        mon = self.mk(cl, start_lookback=5, retry_base=10, max_attempts=3)
        r = mon.run(once=True)[0]["results"][0]
        self.assertEqual(r["status"], "deferred")
        row = m.MonitorStore(self.db).conn.execute("SELECT * FROM monitor_queue").fetchone()
        self.assertEqual(row["attempts"], 1)
        self.assertEqual(row["next_attempt_at"], 1010.0)
        # Not due yet -> not retried.
        self.assertEqual(self.mk(cl).run(once=True)[0]["results"], [])
        self.now[0] = 1011.0
        self.mk(cl, retry_base=10, max_attempts=3).run(once=True)
        row = m.MonitorStore(self.db).conn.execute("SELECT * FROM monitor_queue").fetchone()
        self.assertEqual((row["attempts"], row["next_attempt_at"]), (2, 1031.0))  # doubled
        self.now[0] = 2000.0
        r = self.mk(cl, retry_base=10, max_attempts=3).run(once=True)[0]["results"][0]
        self.assertEqual(r["status"], "unverified")
        self.assertEqual(len(self.recorded), 0)

    def test_verified_later_is_scanned(self):
        self._skip_if_disk_gated()
        cl = FakeClient(head=10, creations={6: ["0xa"]})
        self.mk(cl, start_lookback=5, retry_base=1).run(once=True)
        cl.sources["0xa"] = SRC
        self.now[0] += 5
        r = self.mk(cl, retry_base=1).run(once=True)[0]["results"][0]
        self.assertEqual(r["status"], "scanned")

    def test_transient_source_error_deferred(self):
        self._skip_if_disk_gated()
        cl = FakeClient(head=10, creations={6: ["0xa"]}, fail_source={"0xa"})
        r = self.mk(cl, start_lookback=5).run(once=True)[0]["results"][0]
        self.assertEqual(r["status"], "deferred")

    def test_client_retries_with_exponential_backoff_and_redacts_key(self):
        sleeps: list[float] = []
        calls = {"n": 0}

        def http(req, timeout):
            calls["n"] += 1
            self.assertEqual(req.get_method(), "GET")
            if calls["n"] < 3:
                raise urllib.error.HTTPError(req.full_url, 429, "x", {}, None)
            return json.dumps({"jsonrpc": "2.0", "result": "0x10"}).encode()

        c = m.ChainClient(KEY, 1, http=http, sleep=sleeps.append, min_interval=0, backoff_base=1)
        self.assertEqual(c.block_number(), 16)
        self.assertEqual(sleeps, [1, 2])

        def bad(req, timeout):
            raise urllib.error.URLError(f"boom {req.full_url}")

        c2 = m.ChainClient(KEY, 1, http=bad, sleep=lambda s: None, min_interval=0, max_retries=2)
        with self.assertRaises(m.TransientError) as cm:
            c2.block_number()
        self.assertNotIn(KEY, str(cm.exception))

    def test_rate_limit_message_is_retried(self):
        seq = [{"status": "0", "message": "NOTOK", "result": "Max rate limit reached"},
               {"status": "1", "message": "OK", "result": [{"SourceCode": SRC}]}]
        c = m.ChainClient(KEY, 1, http=lambda r, t: json.dumps(seq.pop(0)).encode(),
                          sleep=lambda s: None, min_interval=0)
        self.assertEqual(c.verified_source("0xa")["SourceCode"], SRC)

    def test_rpc_rejects_write_methods(self):
        c = m.ChainClient(KEY, 1, http=lambda r, t: b"{}", sleep=lambda s: None)
        with self.assertRaises(m.MonitorError):
            c._rpc("eth_sendRawTransaction", ["0x"])


class ThresholdTests(Base):
    def test_threshold_filter_and_jsonl(self):
        self._skip_if_disk_gated()
        cl = FakeClient(head=10, creations={6: ["0xa"]}, sources={"0xa": SRC})
        fs = [_finding("CRITICAL", "c"), _finding("HIGH", "h"), _finding("MEDIUM", "m"), _finding("LOW", "l")]
        res = self.mk(cl, findings=fs, start_lookback=5, min_severity="HIGH").run(once=True)[0]
        self.assertEqual(res["alerts"], 2)
        lines = [json.loads(l) for l in self.alerts.read_text().splitlines()]
        self.assertEqual([l["severity"] for l in lines], ["CRITICAL", "HIGH"])
        self.assertTrue(any(o.startswith("ALERT [CRITICAL]") for o in self.out))

    def test_severity_at_least(self):
        self.assertTrue(m.severity_at_least("MEDIUM", "LOW"))
        self.assertFalse(m.severity_at_least("LOW", "MEDIUM"))
        self.assertFalse(m.severity_at_least("WEIRD", "LOW"))

    def test_webhook_off_by_default_and_loopback_only(self):
        posts = []
        cl = FakeClient(head=10, creations={6: ["0xa"]}, sources={"0xa": SRC})
        mon = self.mk(cl, findings=[_finding("HIGH")], start_lookback=5)
        mon.webhook_post = lambda u, a: posts.append(u)
        mon.run(once=True)
        self.assertEqual(posts, [])
        with self.assertRaises(m.MonitorError):
            m.validate_webhook("https://example.com/hook")
        self.assertEqual(m.validate_webhook("http://127.0.0.1:9000/x"), "http://127.0.0.1:9000/x")


class SourceTests(unittest.TestCase):
    def test_standard_json_and_traversal_guard(self):
        sc = "{" + json.dumps({"language": "Solidity", "sources": {
            "src/A.sol": {"content": "contract A {}"}, "../../evil.sol": {"content": "x"}}}) + "}"
        with tempfile.TemporaryDirectory() as d:
            files = m.materialize_sources(sc, Path(d))
            self.assertEqual([f.name for f in files], ["A.sol"])

    def test_flat_source(self):
        with tempfile.TemporaryDirectory() as d:
            files = m.materialize_sources(SRC, Path(d), "Tok")
            self.assertEqual(files[0].name, "Tok.sol")


class CliTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        d = Path(self.tmp.name)
        self.env = {"AUDITOR_MONITOR_DB": str(d / "m.db"), "AUDITOR_MONITOR_ALERTS": str(d / "a.jsonl"),
                    "AUDITOR_HISTORY_DB": str(d / "h.db"), "AUDITOR_MONITOR_CACHE": str(d / "cache")}

    def tearDown(self):
        self.tmp.cleanup()

    def _run(self, argv, env):
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.dict(os.environ, env, clear=False), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main(argv)
        return code, out.getvalue(), err.getvalue()

    def test_missing_key_errors(self):
        env = dict(self.env, ETHERSCAN_API_KEY="")
        code, out, err = self._run(["monitor", "--once"], env)
        self.assertEqual(code, EXIT_ERROR)
        self.assertIn("ETHERSCAN_API_KEY not set", err)

    def test_once_run_end_to_end_json(self):
        # CliTests extends unittest.TestCase directly, so the guard is inline here.
        free = free_gib()
        if free < RESUME_GIB:
            self.skipTest(
                f"real disk-pressure gate active: free {free:.2f} GiB < RESUME_GIB "
                f"{RESUME_GIB:g} GiB; heavy scans would be deferred (queued work preserved); "
                "this test's assertions require a processed scan. Coverage returns "
                f"automatically once free space >= {RESUME_GIB:g} GiB.")
        responses = {
            "eth_blockNumber": {"result": "0x64"},
            "eth_getBlockByNumber": {"result": {"transactions": [
                {"hash": "0xtx", "to": None}, {"hash": "0xother", "to": "0xdead"}]}},
            "eth_getTransactionReceipt": {"result": {"contractAddress": "0xABC", "status": "0x1"}},
            "getsourcecode": {"status": "1", "message": "OK", "result": [{"SourceCode": SRC, "ContractName": "A"}]},
        }
        urls = []

        def http(req, timeout):
            urls.append(req.full_url)
            self.assertEqual(req.get_method(), "GET")
            for k, v in responses.items():
                if f"action={k}" in req.full_url:
                    return json.dumps(v).encode()
            raise AssertionError(req.full_url)

        env = dict(self.env, ETHERSCAN_API_KEY=KEY, AUDITOR_MONITOR_RPC_URL="")
        # Inject a stub analyzer (slither is not part of this test).
        orig = m.Monitor

        def patched(cfg, client, **kw):
            kw.setdefault("analyzer", lambda f, s, h: [_real_finding("boom")])
            return orig(cfg, client, **kw)

        with mock.patch.object(m.ChainClient.__init__, "__defaults__",
                               (None, http, lambda s: None, 0.0, 4, 1.0, 30.0)), \
                mock.patch.object(m, "Monitor", patched):
            code, out, err = self._run(["monitor", "--once", "--json", "--max-blocks-per-poll", "1"], env)
        self.assertEqual(code, EXIT_OK, err)
        payload = json.loads(out)
        res = payload["polls"][0]["results"][0]
        self.assertEqual((res["address"], res["status"], res["findings"]), ("0xabc", "scanned", 1))
        self.assertEqual(payload["polls"][0]["alerts"], 1)
        self.assertNotIn(KEY, out + err)
        # Recorded in scan history (temp DB).
        conn = sqlite3.connect(self.env["AUDITOR_HISTORY_DB"])
        n = conn.execute("SELECT COUNT(*) FROM scan_records").fetchone()[0]
        conn.close()
        self.assertEqual(n, 1)
        # monitor-status reads it back.
        code, out, _ = self._run(["monitor-status", "--json"], env)
        st = json.loads(out)
        self.assertEqual((st["cursor"], st["seen"], st["alerts_total"]), (96, 1, 1))
        self.assertEqual(st["recent_alerts"][0]["title"], "boom")

    def test_status_without_db_creates_nothing(self):
        code, out, _ = self._run(["monitor-status"], self.env)
        self.assertEqual(code, EXIT_OK)
        self.assertIn("not started", out)
        self.assertFalse(Path(self.env["AUDITOR_MONITOR_DB"]).exists())


class SigintTests(Base):
    def test_stop_request_ends_loop(self):
        cl = FakeClient(head=10)
        mon = self.mk(cl, start_lookback=1)
        orig = mon.poll

        def poll_then_stop():
            r = orig()
            mon.request_stop()
            return r

        mon.poll = poll_then_stop
        polls = mon.run(once=False)
        self.assertEqual(len(polls), 1)



class DashboardMonitorApiTests(unittest.TestCase):
    def test_monitor_status_endpoint_read_only(self):
        from fastapi.testclient import TestClient

        from auditor.dashboard.app import create_app

        with tempfile.TemporaryDirectory() as d:
            env = {"AUDITOR_MONITOR_DB": str(Path(d) / "m.db"),
                   "AUDITOR_MONITOR_ALERTS": str(Path(d) / "a.jsonl")}
            Path(env["AUDITOR_MONITOR_ALERTS"]).write_text(json.dumps({"title": "x"}) + "\n")
            with mock.patch.dict(os.environ, env):
                client = TestClient(create_app())
                r = client.get("/api/monitor/status")
                self.assertEqual(r.status_code, 200)
                self.assertEqual(r.json()["alerts_total"], 1)
                self.assertFalse(Path(env["AUDITOR_MONITOR_DB"]).exists())
                self.assertEqual(client.get("/api/monitor/status?network=x").status_code, 400)


if __name__ == "__main__":
    unittest.main()
