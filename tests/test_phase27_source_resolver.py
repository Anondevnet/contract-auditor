"""Phase 27: AI-audit source resolution (etherscan:// refs, local confinement)."""
from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from auditor.source_resolver import SourceResolutionError, resolve_source  # noqa: E402

ADDR = "0xe0e0e08a6a4b9dc7bd67bcb7aade5cf48157d444"
HASH = "dca2a31f5bd531b7bfa99fb1f03158425749cb461de5d3169a86f8549763156d"


class ResolverTests(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.cache = Path(self.td.name) / "cache"
        d = self.cache / "hunt" / "sources" / "ethereum" / ADDR / HASH[:16] / "src"
        d.mkdir(parents=True)
        (d / "Core.sol").write_text("pragma solidity ^0.8.0; import './Lib.sol'; contract Core {}")
        (d / "Lib.sol").write_text("pragma solidity ^0.8.0; library Lib {}")
        self.env = mock.patch.dict(os.environ, {"AUDITOR_MONITOR_CACHE": str(self.cache)})
        self.env.start()

    def tearDown(self):
        self.env.stop(); self.td.cleanup()

    def test_collectfees_etherscan_ref_resolves_exact_version_with_imports(self):
        r = resolve_source(f"etherscan://ethereum/{ADDR}", HASH)
        self.assertEqual(r.kind, "verified-cache")
        self.assertEqual(r.file_count, 2)
        self.assertTrue(str(r.path).endswith(HASH[:16]))

    def test_legacy_ref_without_network(self):
        self.assertEqual(resolve_source(f"etherscan://{ADDR}", HASH).address, ADDR)

    def test_unavailable_version_is_actionable_not_substituted(self):
        with self.assertRaises(SourceResolutionError) as cm:
            resolve_source(f"etherscan://ethereum/{ADDR}", "ab" * 32)
        self.assertEqual(cm.exception.code, "source_unavailable")
        self.assertIn("scan-address", str(cm.exception))

    def test_malformed_ref(self):
        for bad in ("etherscan://ethereum/0x123", "etherscan://../../etc/0x" + "a" * 40,
                    "etherscan://a/b/c"):
            with self.assertRaises(SourceResolutionError):
                resolve_source(bad)

    def test_valid_local(self):
        r = resolve_source(str(self.cache))
        self.assertEqual(r.kind, "local")

    def test_unsafe_paths_rejected(self):
        for bad in ("/etc", "/etc/../etc/passwd", str(Path.home() / ".ssh"), "/usr/bin"):
            with self.assertRaises(SourceResolutionError) as cm:
                resolve_source(bad)
            self.assertEqual(cm.exception.code, "unsafe_path", bad)

    def test_missing_local(self):
        with self.assertRaises(SourceResolutionError) as cm:
            resolve_source(str(Path(self.td.name) / "nope"))
        self.assertEqual(cm.exception.code, "not_found")


class AIAuditEndpointTests(unittest.TestCase):
    """Endpoint-level: etherscan ref accepted, failures reported precisely."""

    def setUp(self):
        from fastapi.testclient import TestClient
        from auditor.dashboard.app import create_app
        self.td = tempfile.TemporaryDirectory()
        self.cache = Path(self.td.name) / "cache"
        d = self.cache / "ethereum" / ADDR / HASH[:16]
        d.mkdir(parents=True)
        (d / "Core.sol").write_text("pragma solidity ^0.8.0;\ncontract Core { uint x; function f() external { x = 1; } }\n")
        self.env = mock.patch.dict(os.environ, {
            "AUDITOR_MONITOR_CACHE": str(self.cache),
            "AUDITOR_HISTORY_DB": str(Path(self.td.name) / "h.db")})
        self.env.start()
        self.client = TestClient(create_app())
        self.client.__enter__()

    def tearDown(self):
        self.client.__exit__(None, None, None)
        self.env.stop(); self.td.cleanup()

    def test_unavailable_ref_404_with_code(self):
        res = self.client.post("/api/ai-audit", json={"path": f"etherscan://ethereum/{'0x' + '1' * 40}", "use_ai": False})
        self.assertEqual(res.status_code, 404, res.text)
        self.assertEqual(res.json()["detail"]["code"], "source_unavailable")

    def test_unsafe_path_400(self):
        res = self.client.post("/api/ai-audit", json={"path": "/etc", "use_ai": False})
        self.assertEqual(res.status_code, 400)
        self.assertEqual(res.json()["detail"]["code"], "unsafe_path")

    def test_etherscan_ref_job_reaches_terminal_state(self):
        import time
        res = self.client.post("/api/ai-audit", json={
            "path": f"etherscan://ethereum/{ADDR}", "content_hash": HASH, "use_ai": False, "timeout_seconds": 120})
        self.assertEqual(res.status_code, 202, res.text)
        jid = res.json()["job_id"]
        job = {}
        for _ in range(240):
            job = self.client.get(f"/api/jobs/{jid}").json()
            if job["status"] in ("completed", "failed", "cancelled"):
                break
            time.sleep(0.5)
        self.assertIn(job["status"], ("completed", "failed"), job)
        if job["status"] == "failed":
            self.assertTrue(job.get("error"), "failed job must carry a real error")
        else:
            self.assertEqual((job.get("report") or {}).get("kind"), "ai_audit")


if __name__ == "__main__":
    unittest.main()


class FindingsTriageAnnotationTests(unittest.TestCase):
    def test_suppressed_monitor_finding_carries_verdict_and_reason(self):
        import sqlite3 as sq
        from auditor.monitor import MonitorStore
        from auditor.dashboard.routes import _annotate_monitor_triage
        with tempfile.TemporaryDirectory() as td:
            db = Path(td) / "m.db"
            MonitorStore(db).conn.close()  # create schema
            con = sq.connect(db)
            con.execute("insert into monitor_findings(scan_row,network,address,finding_id,title,detector,severity,"
                        "contract,function,suppressed,triage_rule,triage_reason,triage_detail) values "
                        "(1,'ethereum',?, 'F-1','t','privileged-auth-unprotected','CRITICAL','BlurPool','withdraw',1,"
                        "'pull-payment-or-locker','privileged-auth-fp','pays msg.sender own balance')", (ADDR,))
            con.commit(); con.close()
            fp = "('BlurPool', 'withdraw', (84,), 'privileged-auth-unprotected', 'contracts/pool/BlurPool.sol')"
            res = {"findings": [
                {"source_path": f"etherscan://ethereum/{ADDR}", "fingerprint": fp,
                 "affected_contract": "BlurPool", "affected_function": "withdraw"},
                {"source_path": f"etherscan://ethereum/{ADDR}", "fingerprint": fp.replace("withdraw", "sweep"),
                 "affected_contract": "BlurPool", "affected_function": "sweep"},
                {"source_path": "/tmp/x", "fingerprint": fp, "affected_contract": "BlurPool", "affected_function": "withdraw"}]}
            with mock.patch.dict(os.environ, {"AUDITOR_MONITOR_DB": str(db)}):
                _annotate_monitor_triage(res)
            a, b, c = res["findings"]
            self.assertEqual(a["monitor_triage"]["rule"], "pull-payment-or-locker")
            self.assertIn("own balance", a["monitor_triage"]["reason"])
            self.assertNotIn("monitor_triage", b)   # untriaged stays open
            self.assertNotIn("monitor_triage", c)   # local scans untouched

    def test_missing_monitor_db_is_noop(self):
        from auditor.dashboard.routes import _annotate_monitor_triage
        res = {"findings": [{"source_path": f"etherscan://{ADDR}"}]}
        with mock.patch.dict(os.environ, {"AUDITOR_MONITOR_DB": "/nonexistent/m.db"}):
            _annotate_monitor_triage(res)
        self.assertNotIn("monitor_triage", res["findings"][0])


class ValidateRootEtherscanTests(ResolverTests):
    """Phase 34: propose/investigation use the same resolver (was: 'source no longer available')."""

    def test_validate_root_resolves_etherscan_ref(self):
        from auditor.investigation import _validate_root
        p = _validate_root(f"etherscan://ethereum/{ADDR}", HASH)
        self.assertIsNotNone(p)
        self.assertTrue(str(p).endswith(HASH[:16]))
        self.assertIsNone(_validate_root(f"etherscan://ethereum/{ADDR}", "ab" * 32))
