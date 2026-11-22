"""Reliability regressions for the soak2 follow-up fixes (graceful stop + trace
refusal diagnostics), the Investigation C honest trace-status state (P1), and
the adjacent pause/cursor/orphan/reorg recovery paths.

Every test is deterministic: chain behaviour is a fake client, persistence is a
fresh sqlite file in a temp dir, and no process/WS/network is ever started.
"""
import io
import json
import os
import sqlite3
import tempfile
import types
import unittest
import urllib.error
from pathlib import Path
from unittest import mock

from auditor import monitor as m


# ---------------------------------------------------------------------------
# deterministic doubles
# ---------------------------------------------------------------------------

class FakeClient:
    """Chain double: head/creations/verified-source are per-test configured."""

    def __init__(self, creations=None, head=10):
        self.creations = dict(creations or {})
        self.head = head
        self.verified_calls = []
        self.trace_blocks = []
        self.trace_raise = None  # Optional[Exception]: raised on every trace call

    def block_number(self):
        return self.head

    def contract_creations(self, block):
        return [{"address": a, "tx_hash": "0xt", "block": block}
                for a in self.creations.get(block, [])]

    def verified_source(self, address):
        self.verified_calls.append(address)
        return None

    def trace_contract_creations(self, block):
        self.trace_blocks.append(block)
        if self.trace_raise is not None:
            raise self.trace_raise
        return []


class MonitorReliabilityBase(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.d = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)
        self.emitted = []
        self.sleeps = []
        self._t = 1792620000.0

    def addCleanup_source_secret(self, secret: str) -> None:
        def _unregister():
            try:
                m._SECRETS.remove(secret)
            except ValueError:
                pass
        self.addCleanup(_unregister)

    def clock(self) -> float:
        self._t += 0.5
        return self._t

    def _monitor(self, client, **kw):
        kw.setdefault("db_path", self.d / "mon.db")
        opts = dict(alerts_path=self.d / "a.jsonl", cache_dir=self.d / "cache",
                    interval=0, start_lookback=5, max_per_poll=0,
                    solc_auto_install=False)
        opts.update(kw)
        cfg = m.MonitorConfig(**opts)
        mon = m.Monitor(cfg, client, emit=self.emitted.append, clock=self.clock,
                        sleep=self.sleeps.append)
        mon.emitted = self.emitted
        return mon

    def _poll(self, mon):
        """Run one poll with the watch sweep stubbed; returns (out, watch_mock)."""
        with mock.patch.object(m.Monitor, "_check_watches", return_value={"alerts": 0}) as cw:
            out = mon.poll()
        cw.assert_called_once()
        return out, cw

    def _heartbeat(self):
        conn = sqlite3.connect(self.d / "mon.db")
        try:
            row = conn.execute(
                "SELECT payload_json FROM dashboard_worker_state WHERE worker='monitor-ethereum'"
            ).fetchone()
        finally:
            conn.close()
        return json.loads(row[0]) if row else None

    def _poll_rows(self):
        conn = sqlite3.connect(self.d / "mon.db")
        try:
            return conn.execute(
                "SELECT blocks, enqueued, processed, alerts FROM monitor_polls ORDER BY id"
            ).fetchall()
        finally:
            conn.close()


# ---------------------------------------------------------------------------
# Change A: the watch sweep is skipped once a stop has been requested
# ---------------------------------------------------------------------------

class GracefulStopTests(MonitorReliabilityBase):
    def test_poll_skips_watch_sweep_when_stopping(self):
        client = FakeClient(creations={6: ["0xa6"]}, head=10)
        mon = self._monitor(client)
        mon.stop_requested = True  # mirrors the soak2 soak: SIGINT landed mid-round
        with mock.patch.object(m.Monitor, "_check_watches",
                               return_value={"alerts": 9}) as watch:
            out = mon.poll()
        watch.assert_not_called()  # the ~10 s HTTP tail is gone on stop
        self.assertEqual(out["alerts"], 0)
        self.assertEqual(out["discovery"]["to"], 5)  # loop broke before any block
        self.assertEqual(self._poll_rows(), [(0, 0, 0, 0)])  # round still recorded

    def test_poll_runs_watches_and_records_when_not_stopping(self):
        client = FakeClient(head=10)
        mon = self._monitor(client)
        with mock.patch.object(m.Monitor, "_check_watches",
                               return_value={"alerts": 1}) as watch:
            out = mon.poll()
        watch.assert_called_once()  # control: the skip is bound to the stop flag
        self.assertEqual(out["watch"], {"alerts": 1})
        self.assertEqual(out["alerts"], 1)

    def test_midround_stop_finishes_round_without_watch_tail(self):
        client = FakeClient(creations={6: ["0xa6"], 7: ["0xa7"], 8: ["0xa8"]}, head=10)
        mon = self._monitor(client)
        orig = client.contract_creations

        def stop_midround(block):  # stop lands during a block (soak shape)
            mon.request_stop()
            return orig(block)

        client.contract_creations = stop_midround
        with mock.patch.object(m.Monitor, "_check_watches",
                               return_value={"alerts": 9}) as watch:
            out = mon.poll()
        watch.assert_not_called()
        self.assertEqual(mon.store.get_cursor("ethereum"), 6)  # 6 fully recorded, broke at 7
        self.assertEqual(out["discovery"]["from"], 6)
        self.assertEqual(out["discovery"]["enqueued"], 1)
        self.assertEqual(client.verified_calls, [])
        conn = sqlite3.connect(self.d / "mon.db")
        try:
            queued = conn.execute("SELECT address FROM monitor_queue").fetchall()
        finally:
            conn.close()
        self.assertEqual(queued, [("0xa6",)])
        self.assertEqual(self._poll_rows(), [(1, 1, 0, 0)])  # record_poll stays consistent

    def test_pending_rows_survive_and_recover_after_stopped_round(self):
        client = FakeClient(head=10)
        mon = self._monitor(client)
        self.assertTrue(mon.store.enqueue("ethereum", "0xaA1", "0xt", 6))
        mon.stop_requested = True
        mon.poll()
        row = mon.store.conn.execute(
            "SELECT status, attempts FROM monitor_queue").fetchone()
        self.assertEqual(tuple(row), ("pending", 0))  # nothing dropped or started
        self.assertEqual(client.verified_calls, [])
        mon.stop_requested = False
        due = mon.store.due("ethereum", 5, self.clock())
        self.assertEqual([r["address"] for r in due], ["0xaa1"])  # recoverable next round

    def test_run_exits_cleanly_when_stop_already_requested(self):
        client = FakeClient()
        mon = self._monitor(client)
        mon.stop_requested = True
        polls = mon.run(once=False)
        self.assertEqual(polls, [])
        self.assertEqual(client.verified_calls, [])
        self.assertEqual(client.trace_blocks, [])
        states = self._heartbeat()
        self.assertEqual(states["status"], "stopped")
        self.assertEqual(states["polls"], 0)
        lock = m.WorkerLock(m.worker_lock_path(self.d / "mon.db", "monitor", "ethereum"))
        handle = lock.acquire()  # the worker lock was released, nothing hung
        handle.release()


# ---------------------------------------------------------------------------
# Change B: trace refusals are diagnosed without touching discovery state
# ---------------------------------------------------------------------------

class TraceRefusalTests(MonitorReliabilityBase):
    def test_trace_refusal_detail_is_sanitized_and_bounded(self):
        secret = "v2_deadbeefdeadbeefdead"
        m._register_secret(secret)
        self.addCleanup_source_secret(secret)
        client = FakeClient(creations={6: ["0xa6"]}, head=10)
        client.trace_raise = m.MonitorError(
            "upstream refused debug: token " + secret + " end\nsecond line " + "z" * 300)
        mon = self._monitor(client)
        out = self._poll(mon)[0]
        refusals = [ln for ln in mon.emitted
                    if "internal creation tracing unavailable" in ln]
        self.assertEqual(len(refusals), 5)  # one diagnostic per discovery block
        for line in refusals:
            detail = line.split("(MonitorError: ", 1)[1].rsplit(
                "); top-level discovery continues", 1)[0]
            self.assertLessEqual(len(detail), 160)
            self.assertEqual(len(detail), 160)  # message truncated at the bound
            self.assertNotIn(secret, line)
            self.assertIn("***", line)  # runtime-registered secret redacted
            self.assertNotIn("\n", line)  # stays a single log line
        disc = out["discovery"]
        self.assertEqual(disc["to"], 10)  # cursor advanced: top-level kept working
        self.assertEqual(disc["top_level"], 1)
        self.assertEqual(disc["internal"], 0)

    def test_trace_failure_keeps_cursor_queue_and_stats_consistent(self):
        client = FakeClient(creations={6: ["0xa6"]}, head=10)
        client.trace_raise = m.MonitorError("provider refused politely")
        mon = self._monitor(client)
        out = self._poll(mon)[0]
        disc = out["discovery"]
        self.assertEqual(disc["to"], 10)  # block fully enumerated despite tracing off
        self.assertEqual(disc["top_level"], 1)
        self.assertEqual(disc["internal"], 0)
        self.assertEqual(len(client.trace_blocks), 5)  # no permanent disable: retried per block
        conn = sqlite3.connect(self.d / "mon.db")
        try:
            queued = conn.execute(
                "SELECT address, discovery_method FROM monitor_queue").fetchall()
        finally:
            conn.close()
        self.assertEqual(queued, [("0xa6", "top_level_create")])
        self.assertEqual(self._poll_rows(), [(5, 1, 0, 0)])

    def test_transient_trace_failure_stops_round_at_block_boundary_then_recovers(self):
        client = FakeClient(creations={6: ["0xa6"], 7: ["0xa7"]}, head=10)
        hiccup = {"n": 0}

        def trace(block):
            client.trace_blocks.append(block)
            if block == 7 and hiccup["n"] == 0:
                hiccup["n"] += 1
                raise m.TransientError("stream hiccup")
            return []

        client.trace_contract_creations = trace
        mon = self._monitor(client)
        with self.assertRaises(m.TransientError):
            mon.poll()
        self.assertEqual(mon.store.get_cursor("ethereum"), 6)  # block 7 stays unrecorded
        self.assertEqual(self._poll_rows(), [])  # aborted round records nothing
        out = self._poll(mon)[0]  # healed: resumes from the cursor
        disc = out["discovery"]
        self.assertEqual(disc["from"], 7)  # no gap: continues after block 6
        self.assertEqual(disc["to"], 10)
        self.assertEqual(disc["enqueued"], 1)  # 0xa7 only; 0xa6 not duplicated
        conn = sqlite3.connect(self.d / "mon.db")
        try:
            queued = conn.execute(
                "SELECT address, status, attempts FROM monitor_queue ORDER BY address"
            ).fetchall()
        finally:
            conn.close()
        self.assertEqual(queued, [("0xa6", "pending", 0), ("0xa7", "pending", 0)])
        self.assertEqual(self._poll_rows(), [(4, 1, 0, 0)])

    def test_unsupported_phrases_disable_repeated_trace_attempts(self):
        real_trace = m.ChainClient.__dict__["trace_contract_creations"]
        for phrase in ("method not found", "not available", "unsupported"):
            with self.subTest(phrase=phrase):
                fake = types.SimpleNamespace(trace_internal_creations=True,
                                             rpc_url="https://rpc.example/v2/***",
                                             trace_status="ready", trace_error=None)
                fake._rpc = lambda method, payload, _p=phrase: (_ for _ in ()).throw(
                    m.MonitorError(f"the method is {_p}"))
                self.assertEqual(real_trace(fake, 42), [])
                self.assertFalse(fake.trace_internal_creations)
                self.assertEqual(fake.trace_status, "unsupported")
                self.assertEqual(fake.trace_error, "MonitorError")
                fake._rpc = lambda method, payload: (_ for _ in ()).throw(
                    AssertionError("RPC called after permanent disable"))
                self.assertEqual(real_trace(fake, 43), [])  # no repeated attempts

    def test_non_matching_refusal_keeps_retrying_and_does_not_disable(self):
        real_trace = m.ChainClient.__dict__["trace_contract_creations"]
        fake = types.SimpleNamespace(trace_internal_creations=True,
                                     rpc_url="https://rpc.example/v2/***",
                                     trace_status="ready", trace_error=None)
        fake._rpc = lambda method, payload: (_ for _ in ()).throw(
            m.MonitorError("the host says the route is not allowed"))
        with self.assertRaises(m.MonitorError):
            real_trace(fake, 42)
        self.assertTrue(fake.trace_internal_creations)  # pinned: no speculative phrases
        self.assertEqual(fake.trace_status, "ready")


# ---------------------------------------------------------------------------
# P1 (Investigation C): trace_status must be honest — 'unverified' until a
# trace response is parsed; 'ready' is only ever earned, never assumed
# ---------------------------------------------------------------------------

class TraceStatusHonestyTests(MonitorReliabilityBase):
    """Real ChainClient lifecycle tests (no network: stubbed http, no workers).

    Refusal texts used here are shape-canonical, taken from the soak evidence:
    a JSON-RPC error body without any auto-disable phrase, and an HTTP-level
    4xx rejection. No new error phrases or disable rules are introduced.
    """
    KEY = "v2_demo_key_removed"  # clients only use it for Etherscan GETs

    def _client(self, http, **kw):
        kw.setdefault("rpc_url", "https://rpc.example/v2/***")
        with mock.patch.dict(os.environ, {"AUDITOR_TRACE_INTERNAL_CREATIONS": "1"}):
            return m.ChainClient(self.KEY, 1, http=http, sleep=lambda s: None,
                                 min_interval=0, **kw)

    @staticmethod
    def _rpc_reply(**data):
        return json.dumps({"jsonrpc": "2.0", "id": 1, **data}).encode()

    def test_enabled_tracing_starts_unverified_and_disabled_stays_disabled(self):
        c = self._client(lambda req, t: b"{}")
        self.assertTrue(c.trace_internal_creations)
        self.assertEqual(c.trace_status, "unverified")  # not 'ready' before any parse
        self.assertIsNone(c.trace_error)
        # disabled states are unchanged: no RPC url, or the opt-out flag
        d = self._client(lambda req, t: b"{}", rpc_url=None)
        self.assertFalse(d.trace_internal_creations)
        self.assertEqual(d.trace_status, "disabled")
        with mock.patch.dict(os.environ, {"AUDITOR_TRACE_INTERNAL_CREATIONS": "0"}):
            e = m.ChainClient(self.KEY, 1, rpc_url="https://rpc.example/v2/***",
                              http=lambda req, t: b"{}", sleep=lambda s: None,
                              min_interval=0)
        self.assertFalse(e.trace_internal_creations)
        self.assertEqual(e.trace_status, "disabled")

    def test_non_canonical_refusal_cannot_leave_status_ready(self):
        def http(req, timeout):
            body = json.loads(req.data.decode())
            self.assertEqual(body["method"], "debug_traceBlockByNumber")
            return self._rpc_reply(
                error={"code": -32603, "message": "debug api access denied for this key"})

        c = self._client(http)
        self.assertEqual(c.trace_status, "unverified")
        with self.assertRaises(m.MonitorError):  # refusal propagates: nothing hidden
            c.trace_contract_creations(123)
        self.assertEqual(c.trace_status, "unverified")  # soak-consistent honesty
        self.assertNotEqual(c.trace_status, "ready")
        self.assertTrue(c.trace_internal_creations)  # pinned: no speculative disable
        self.assertIsNone(c.trace_error)  # only recognized disables set trace_error

    def test_http_level_refusal_also_stays_unverified_without_disabling(self):
        def http(req, timeout):
            raise urllib.error.HTTPError("https://rpc.example/v2/***", 403,
                                         "Forbidden", {}, io.BytesIO(b""))

        c = self._client(http)  # the soak2 refusal shape: HTTP status, no phrases
        with self.assertRaises(m.MonitorError) as ctx:
            c.trace_contract_creations(123)
        self.assertIn("HTTP 403", str(ctx.exception))
        self.assertEqual(c.trace_status, "unverified")
        self.assertNotEqual(c.trace_status, "ready")
        self.assertTrue(c.trace_internal_creations)

    def test_successful_trace_earns_ready_and_extracts_creations(self):
        # SYNTHETIC callTracer-shaped payload: this tests parse semantics only.
        # Provider response shapes were checked against official docs in
        # Investigation C; a captured real fixture is deferred to later phases.
        payload = [{"txHash": "0x" + "ab" * 32,
                    "result": {"type": "CALL",
                               "calls": [
                                   {"type": "CREATE", "to": "0x" + "9a" * 20},
                                   {"type": "CREATE2", "createdAddress": "0x" + "c2" * 20},
                                   {"type": "CALL", "to": "0x" + "11" * 20},
                                   {"type": "CREATE", "to": "0x" + "cc" * 20,
                                    "error": "revert"},
                               ]}}]

        def http(req, timeout):
            body = json.loads(req.data.decode())
            self.assertEqual(body["method"], "debug_traceBlockByNumber")
            return self._rpc_reply(result=payload)

        c = self._client(http)
        found = c.trace_contract_creations(123)
        self.assertEqual([f["address"] for f in found],
                         ["0x" + "9a" * 20, "0x" + "c2" * 20])
        self.assertEqual([f["discovery_method"] for f in found],
                         ["trace_create", "trace_create2"])
        self.assertEqual(found[0]["tx_hash"], "0x" + "ab" * 32)
        self.assertEqual(c.trace_status, "ready")  # earned only here
        self.assertIsNone(c.trace_error)
        # capability semantics: a later refusal per call downgrades nothing
        with mock.patch.object(c, "_rpc", side_effect=[
                m.MonitorError("debug api access denied for this key")]):
            with self.assertRaises(m.MonitorError):
                c.trace_contract_creations(456)
        self.assertEqual(c.trace_status, "ready")

    def test_top_level_discovery_works_despite_trace_refusal(self):
        def http(req, timeout):
            body = json.loads(req.data.decode())
            if body.get("method") == "debug_traceBlockByNumber":
                return self._rpc_reply(
                    error={"code": -32603,
                           "message": "debug api access denied for this key"})
            if body.get("method") == "eth_getBlockByNumber":
                return self._rpc_reply(result={
                    "number": "0x6", "hash": "0x" + "06" * 32,
                    "parentHash": "0x" + "05" * 32,
                    "transactions": [{"hash": "0x" + "ab" * 32}]})
            if body.get("method") == "eth_getTransactionReceipt":
                return self._rpc_reply(result={
                    "status": "0x1", "contractAddress": "0x" + "a6" * 20})
            raise AssertionError("unexpected RPC method: %r" % body.get("method"))

        c = self._client(http)
        with self.assertRaises(m.MonitorError):
            c.trace_contract_creations(6)
        # receipts-only discovery continues on the same client, undamaged
        direct = c.contract_creations(6)
        self.assertEqual(direct, [{"address": "0x" + "a6" * 20,
                                   "tx_hash": "0x" + "ab" * 32,
                                   "block": 6,
                                   "discovery_method": "top_level_create"}])
        self.assertEqual(c.trace_status, "unverified")


# ---------------------------------------------------------------------------
# P0: refusal diagnostics name the traced RPC method and a non-secret provider
# category; the endpoint URL/host never appears anywhere in the log line
# ---------------------------------------------------------------------------

class TraceDiagnosticTagTests(MonitorReliabilityBase):
    KEY = "v2_demo_key_removed"

    def _client(self, http, rpc_url):
        with mock.patch.dict(os.environ, {"AUDITOR_TRACE_INTERNAL_CREATIONS": "1"}):
            return m.ChainClient(self.KEY, 1, rpc_url=rpc_url, http=http,
                                 sleep=lambda s: None, min_interval=0)

    def test_provider_category_never_leaks_the_endpoint(self):
        # synthetic endpoints + DEMO-REDACTED keys: fixtures only
        cases = (
            ("https://eth-mainnet.g.alchemy.com/v2/DEMO-REDACTED", "alchemy"),
            ("https://eth-mainnet.alchemy.com/v2/DEMO-REDACTED", "alchemy"),
            ("https://abc.infura.io/v3/DEMO-REDACTED", "infura"),
            ("https://node.quiknode.pro/DEMO-REDACTED/", "quiknode"),
            ("https://ethereum.publicnode.com/", "publicnode"),
            ("https://node.ankr.com/", "ankr"),
            ("https://127.0.0.1:8545/", "local-loopback"),
            ("https://localhost:8545/", "local-loopback"),
            ("https://some-unknown.example.host/", "other"),
        )
        for url, want in cases:
            with self.subTest(category=want):
                c = self._client(lambda req, t: b"{}", url)
                got = c.provider_category()
                self.assertEqual(got, want)
                self.assertNotIn(url, got)   # never the full URL
                self.assertNotIn("/", got)   # never any path/fragment of it
        # without an RPC url there is no provider to name
        self.assertEqual(
            self._client(lambda req, t: b"{}", None).provider_category(), "none")

    def test_refusal_diagnostic_line_carries_method_and_provider_tags(self):
        class TaggedClient(FakeClient):
            def provider_category(self):
                return "alchemy"

        client = TaggedClient(creations={6: ["0xa6"]}, head=10)
        client.trace_raise = m.MonitorError("debug api access denied for this key")
        mon = self._monitor(client)
        out = self._poll(mon)[0]   # top-level discovery unaffected by the tags
        self.assertEqual(out["discovery"]["top_level"], 1)
        lines = [ln for ln in mon.emitted
                 if "internal creation tracing unavailable" in ln]
        self.assertEqual(len(lines), 5)
        for line in lines:
            self.assertIn("(method=debug_traceBlockByNumber provider=alchemy)", line)
            self.assertNotIn("://", line)          # never an endpoint URL
            self.assertNotIn("DEMO-REDACTED", line)

    def test_doubles_without_provider_category_report_unknown(self):
        client = FakeClient(head=10)
        client.trace_raise = m.MonitorError("provider refused politely")
        mon = self._monitor(client)
        self._poll(mon)
        tagged = [ln for ln in mon.emitted
                  if "provider=unknown" in ln
                  and "internal creation tracing unavailable" in ln]
        self.assertEqual(len(tagged), 5)


# ---------------------------------------------------------------------------
# Approved HTTP-4xx diagnostic fix: the discarded provider error body is now
# surfaced sanitized/bounded on the permanent-4xx path only; the 429/5xx
# transient ladder and every P0/P1 behavior stay byte-identical
# ---------------------------------------------------------------------------

class HttpErrorDetailTests(MonitorReliabilityBase):
    KEY = "H0AXFAKEY_syntheticDemo"  # fake on purpose; never a real credential
    RPC = "https://rpc.example/v2/DEMONOTREALKEY"
    URL = "https://rpc.example/v2/DEMONOTREALKEY"

    def _client(self, http, **kw):
        kw.setdefault("rpc_url", self.RPC)
        secrets_before = list(m._SECRETS)  # restore: __init__ also registers
        with mock.patch.dict(os.environ, {"AUDITOR_TRACE_INTERNAL_CREATIONS": "1"}):  # /v2/ key components
            client = m.ChainClient(self.KEY, 1, http=http, sleep=self.sleeps.append,
                                   min_interval=0, **kw)

        def _restore_secrets():
            m._SECRETS[:] = secrets_before
        self.addCleanup(_restore_secrets)
        return client

    def _http_error(self, code: int, body: bytes = b"") -> urllib.error.HTTPError:
        labels = {400: "Bad Request", 403: "Forbidden", 429: "Too Many Requests",
                  503: "Service Unavailable"}
        return urllib.error.HTTPError(self.URL, code, labels[code], {},
                                      io.BytesIO(body))

    def _thrown_client(self, code: int, body: bytes = b"", **kw):
        def http(req, timeout):
            raise self._http_error(code, body)
        return self._client(http, **kw)

    def test_400_jsonrpc_body_yields_code_and_message(self):
        body = json.dumps({"jsonrpc": "2.0", "id": 1,
                           "error": {"code": -32000, "message": "block not found"}}).encode()
        c = self._thrown_client(400, body)
        with self.assertRaises(m.MonitorError) as ctx:
            c.trace_contract_creations(123)
        self.assertEqual(str(ctx.exception), "HTTP 400: code=-32000 block not found")
        self.assertEqual(self.sleeps, [])  # permanent 4xx: zero retry/backoff
        self.assertEqual(c.trace_status, "unverified")  # P1 status machine intact
        self.assertTrue(c.trace_internal_creations)  # no new disable rules

    def test_400_body_secrets_and_key_shaped_material_are_redacted(self):
        body = json.dumps({"error": {"code": -32602, "message":
            "bad tracer for " + self.RPC + " plus https://eth-mainnet.g.alchemy.com/v2/ALSOFAKEKEY99"
            " and ?apikey=DEMONOTREALKEY"}}).encode()
        c = self._thrown_client(400, body)
        with self.assertRaises(m.MonitorError) as ctx:
            c.trace_contract_creations(123)
        self.assertEqual(
            str(ctx.exception),
            "HTTP 400: code=-32602 bad tracer for *** plus "
            "https://eth-mainnet.g.alchemy.com/v2/*** and ?apikey=***")
        self.assertNotIn("DEMONOTREALKEY", str(ctx.exception))
        self.assertNotIn("ALSOFAKEKEY99", str(ctx.exception))

    def test_400_html_body_becomes_bounded_snippet(self):
        raw = b"<html><body><h1>400 Bad Request</h1>" + b"opaque" * 40 + b"</body></html>"
        c = self._thrown_client(400, raw)
        with self.assertRaises(m.MonitorError) as ctx:
            c.trace_contract_creations(123)
        detail = str(ctx.exception)
        self.assertTrue(detail.startswith("HTTP 400: <html><body><h1>400"))
        self.assertLessEqual(len(detail), len("HTTP 400: ") + 160)
        self.assertNotIn("\n", detail)  # stays a single line
        self.assertEqual(len(detail.split(": ", 1)[1]), 160)  # bound reached

    def test_400_empty_body_and_read_failure_yield_no_body(self):
        empty = urllib.error.HTTPError("https://rpc.example/v2/k", 400, "Bad Request",
                                       {}, io.BytesIO(b""))
        self.assertEqual(m._http_error_detail(empty), "no body")
        self.assertEqual(m._http_error_detail(urllib.error.HTTPError(
            "https://rpc.example/v2/k", 400, "Bad Request", {}, None)), "no body")

        class BombFP:
            def read(self, _n=None):
                raise OSError("fixture read failure")

            def close(self):
                self.closed = True

        bomb = BombFP()
        e = urllib.error.HTTPError("https://rpc.example/v2/k", 400, "Bad Request", {}, bomb)
        self.assertEqual(m._http_error_detail(e), "no body")
        self.assertTrue(bomb.closed)  # response still closed safely

    def test_403_with_body_keeps_status_and_disable_contract(self):
        body = json.dumps({"error": {"code": -32000,
                                     "message": "debug api access denied for this key"}}).encode()
        c = self._thrown_client(403, body)
        with self.assertRaises(m.MonitorError) as ctx:
            c.trace_contract_creations(123)
        self.assertEqual(str(ctx.exception), "HTTP 403: code=-32000 debug api access denied for this key")
        self.assertEqual(c.trace_status, "unverified")
        self.assertTrue(c.trace_internal_creations)  # still not a recognized disable
        self.assertEqual(self.sleeps, [])

    def test_429_and_5xx_ladder_unchanged(self):
        for code in (429, 503):
            with self.subTest(code=code):
                self.sleeps = []  # subTests share one instance; isolate each ladder
                body = json.dumps({"error": {"code": -32000,
                                             "message": "body marker must not surface"}}).encode()
                c = self._thrown_client(code, body, max_retries=2)  # bounded ladder
                with self.assertRaises(m.TransientError) as ctx:
                    c.trace_contract_creations(123)
                self.assertEqual(str(ctx.exception), f"HTTP {code}")  # unchanged shape
                self.assertNotIn("body marker", str(ctx.exception))  # no body detail added
                self.assertEqual(len(self.sleeps), 2)  # even ladder: 1.0 then 2.0
                self.assertEqual(self.sleeps, [1.0, 2.0])
                self.assertEqual(c.trace_status, "unverified")

    def test_400_refusal_keeps_top_level_discovery_and_unverified_status(self):
        def http(req, timeout):
            method = json.loads(req.data.decode()).get("method")
            if method == "debug_traceBlockByNumber":
                raise self._http_error(400, json.dumps(
                    {"error": {"code": -32000, "message": "block not found"}}).encode())
            if method == "eth_getBlockByNumber":
                return json.dumps({"jsonrpc": "2.0", "id": 1, "result": {
                    "number": "0x6", "hash": "0x" + "06" * 32,
                    "parentHash": "0x" + "05" * 32,
                    "transactions": [{"hash": "0x" + "ab" * 32}]}}).encode()
            if method == "eth_getTransactionReceipt":
                return json.dumps({"jsonrpc": "2.0", "id": 1, "result": {
                    "status": "0x1", "contractAddress": "0x" + "a6" * 20}}).encode()
            raise AssertionError("unexpected RPC method: %r" % method)

        c = self._client(http)
        with self.assertRaises(m.MonitorError) as ctx:
            c.trace_contract_creations(6)
        self.assertIn("HTTP 400: code=-32000 block not found", str(ctx.exception))
        # receipts-only discovery continues on the same client, undamaged
        self.assertEqual(c.contract_creations(6), [{
            "address": "0x" + "a6" * 20, "tx_hash": "0x" + "ab" * 32,
            "block": 6, "discovery_method": "top_level_create"}])
        self.assertEqual(c.trace_status, "unverified")


# ---------------------------------------------------------------------------
# WebSocket drop → TransientError → HTTP fallback (flag-aware)
# ---------------------------------------------------------------------------

class WebSocketDropTests(MonitorReliabilityBase):
    def test_stream_disconnect_maps_to_transient_and_closes(self):
        sub = m.NewHeadSubscription("wss://rpc.example.invalid")
        recv_n = {"n": 0}

        class FakeWS:
            def send(self, raw):
                pass

            def recv(self, timeout=None):
                recv_n["n"] += 1
                if recv_n["n"] == 1:
                    return json.dumps({"id": 1, "result": "0xsub"})
                raise ConnectionResetError("connection closed during keepalive ping")

            def close(self):
                self.closed = True

        ws = FakeWS()
        with mock.patch("websockets.sync.client.connect", return_value=ws):
            sub._connect()
            self.assertEqual(sub.subscription_id, "0xsub")
            with self.assertRaises(m.TransientError) as ctx:
                sub.wait(1.0, lambda: False)
        self.assertIn("disconnected", str(ctx.exception))
        self.assertIsNone(sub.ws)  # closed → reconnect attempted next round

    def test_subscription_rejection_maps_to_transient(self):
        class RejectingWS:
            def send(self, raw):
                pass

            def recv(self, timeout=None):
                return json.dumps({"id": 1, "error": {"code": -32601,
                                                      "message": "subscription rejected"}})

            def close(self):
                self.closed = True

        sub = m.NewHeadSubscription("wss://rpc.example.invalid")
        with mock.patch("websockets.sync.client.connect", return_value=RejectingWS()):
            with self.assertRaises(m.TransientError) as ctx:
                sub._connect()
        self.assertIn("rejected", str(ctx.exception))
        self.assertIsNone(sub.ws)

    def test_run_falls_back_to_http_when_ws_drops_and_honors_stop_immediately(self):
        holder = {"mon": None}
        client = FakeClient(head=10)
        client.ws_url = "wss://rpc.example.invalid"

        class DroppingStream:
            def __init__(self, url):
                holder["url"] = url

            def wait(self, timeout, stopped):
                holder["mon"].request_stop()  # stop arrives on/near the drop
                raise m.TransientError("newHeads stream disconnected: closed")

            def close(self):
                holder["closed"] = True

        mon = self._monitor(client, interval=1.0)
        holder["mon"] = mon
        with mock.patch.object(m.Monitor, "_check_watches", return_value={"alerts": 0}):
            with mock.patch.object(m, "NewHeadSubscription", DroppingStream):
                polls = mon.run(once=False)
        self.assertEqual(len(polls), 1)  # the drop does not lose the round
        self.assertTrue(holder["closed"])
        fallback_lines = [ln for ln in mon.emitted
                          if "WebSocket unavailable; falling back" in ln]
        self.assertEqual(len(fallback_lines), 1)
        self.assertEqual(len(self.sleeps), 0)  # stop flag honored: zero fallback step-sleeps
        states = self._heartbeat()
        self.assertEqual(states["status"], "stopped")


# ---------------------------------------------------------------------------
# Orphaned-run recovery at boot (scoped to origin)
# ---------------------------------------------------------------------------

class OrphanRunTests(MonitorReliabilityBase):
    def test_boot_interrupts_running_rows_only_for_equal_origin(self):
        store = m.MonitorStore(self.d / "mon.db")
        store.start_scan("ethereum", "0xaaa", "0xt", 5, 100.0, origin="monitor")
        store.start_scan("ethereum", "0xbbb", "0xt", 5, 100.0, origin="hunt")
        mon = self._monitor(FakeClient())  # a fresh Monitor boots on the same DB
        conn = sqlite3.connect(self.d / "mon.db")
        try:
            rows = conn.execute(
                "SELECT address, status, finished_at IS NULL FROM monitor_scans ORDER BY id"
            ).fetchall()
        finally:
            conn.close()
        self.assertEqual(rows, [("0xaaa", "interrupted", 0),
                                ("0xbbb", "running", 1)])  # hunt rows are never touched


# ---------------------------------------------------------------------------
# Reorg rewind: orphan the branch, rewind, then backfill without duplicates
# ---------------------------------------------------------------------------

class ReorgTests(MonitorReliabilityBase):
    def test_record_reorg_rewinds_cursor_orphans_queue_and_resumes_backfill(self):
        store = m.MonitorStore(self.d / "mon.db")
        for b in range(6, 11):
            store.record_block("ethereum", b, f"0x{b:048x}", f"0x{b - 1:048x}")
        store.enqueue("ethereum", "0xq7", "0xt", 7, discovery_method="top_level_create")
        store.enqueue("ethereum", "0xq10", "0xt", 10, discovery_method="top_level_create")
        store.record_reorg("ethereum", 12, 9, "0x0c", "0x09", 5000.0)
        self.assertEqual(store.get_cursor("ethereum"), 9)  # rewound to the ancestor
        self.assertIsNone(store.block_hash("ethereum", 10))  # orphaned tail purged
        self.assertEqual(store.block_hash("ethereum", 9), f"0x{9:048x}")
        reorg = store.conn.execute(
            "SELECT old_cursor, common_ancestor FROM monitor_reorgs").fetchone()
        self.assertEqual(tuple(reorg), (12, 9))
        st = {addr: (status, err) for addr, status, err in store.conn.execute(
            "SELECT address, status, last_error FROM monitor_queue")}
        self.assertEqual(st["0xq7"], ("pending", None))  # below ancestor: untouched
        self.assertEqual(st["0xq10"], ("orphaned", "block removed by reorg"))
        self.assertTrue(store.enqueue("ethereum", "0xq10", "0txn", 10,
                                      discovery_method="top_level_create"))
        row = store.conn.execute(
            "SELECT status, attempts, last_error, tx_hash, block FROM monitor_queue "
            "WHERE address='0xq10'").fetchone()
        self.assertEqual(tuple(row), ("pending", 0, None, "0txn", 10))  # reset for backfill
        self.assertIn("0xq10", [r["address"] for r in store.due("ethereum", 5, self.clock())])

    def test_canonical_rewind_backfills_from_common_ancestor(self):
        store = m.MonitorStore(self.d / "mon.db")
        for b in range(6, 11):
            store.record_block("ethereum", b, f"0x{b:048x}", None)
        store.enqueue("ethereum", "0xq10", "0xt", 10, discovery_method="top_level_create")

        client = FakeClient(creations={10: ["0xq10"]}, head=12)
        client.block_header = lambda b: {"hash": "0xnewchain" if b >= 10 else f"0x{b:048x}"}
        mon = self._monitor(client)
        out = self._poll(mon)[0]
        self.assertTrue(any("canonical chain changed at block 10; rewound to 9" in ln
                            for ln in mon.emitted))
        discovered = out["discovery"]
        self.assertEqual(discovered["from"], 10)  # backfill resumes after the ancestor
        self.assertEqual(discovered["to"], 12)
        self.assertEqual(store.get_cursor("ethereum"), 12)  # reindexed on the new chain
        self.assertEqual(store.block_hash("ethereum", 10), "0xnewchain")
        reorg = store.conn.execute(
            "SELECT old_cursor, common_ancestor FROM monitor_reorgs").fetchone()
        self.assertEqual(tuple(reorg), (10, 9))
        row = store.conn.execute(
            "SELECT status, block, attempts FROM monitor_queue WHERE address='0xq10'"
        ).fetchone()
        self.assertEqual(tuple(row), ("pending", 10, 0))  # re-queued exactly once
        conn = sqlite3.connect(self.d / "mon.db")
        try:
            queued = conn.execute("SELECT COUNT(*) FROM monitor_queue").fetchone()[0]
        finally:
            conn.close()
        self.assertEqual(queued, 1)  # no duplicates on re-walk


if __name__ == "__main__":
    unittest.main()
