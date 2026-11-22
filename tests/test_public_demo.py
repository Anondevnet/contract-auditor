"""Public demo: paste/upload routes, limits, and disabled surfaces."""

from __future__ import annotations

import io
import os
import unittest
from pathlib import Path
from unittest import mock

from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[1]
SAMPLE = (ROOT / "samples" / "reentrancy.sol").read_text(encoding="utf-8")


class PublicDemoTests(unittest.TestCase):
    def setUp(self) -> None:
        self._mode = os.environ.get("AUDITOR_MODE")
        os.environ["AUDITOR_MODE"] = "public"
        # Isolate rate-limit / spend state.
        self._data = os.environ.get("AUDITOR_PUBLIC_DATA_DIR")
        self._tmpdir = __import__("tempfile").TemporaryDirectory()
        os.environ["AUDITOR_PUBLIC_DATA_DIR"] = self._tmpdir.name
        os.environ["AUDITOR_RATE_LIMIT_PER_HOUR"] = "10"
        from auditor.public_demo.app import create_public_app
        self.client = TestClient(create_public_app())
        self.client.__enter__()

    def tearDown(self) -> None:
        self.client.__exit__(None, None, None)
        if self._mode is None:
            os.environ.pop("AUDITOR_MODE", None)
        else:
            os.environ["AUDITOR_MODE"] = self._mode
        if self._data is None:
            os.environ.pop("AUDITOR_PUBLIC_DATA_DIR", None)
        else:
            os.environ["AUDITOR_PUBLIC_DATA_DIR"] = self._data
        os.environ.pop("AUDITOR_RATE_LIMIT_PER_HOUR", None)
        self._tmpdir.cleanup()

    def test_health_and_home(self) -> None:
        res = self.client.get("/health")
        self.assertEqual(res.status_code, 200)
        body = res.json()
        self.assertEqual(body["status"], "healthy")
        self.assertEqual(body["mode"], "public")
        self.assertEqual(body["provider"], "none")
        home = self.client.get("/")
        self.assertEqual(home.status_code, 200)
        self.assertIn("Paste or upload", home.text)
        self.assertTrue(res.headers.get("X-Request-ID") or res.headers.get("x-request-id"))

    def test_samples_list_and_fetch(self) -> None:
        res = self.client.get("/api/samples")
        self.assertEqual(res.status_code, 200)
        names = {s["id"] for s in res.json()["samples"]}
        self.assertIn("reentrancy.sol", names)
        one = self.client.get("/api/samples/reentrancy.sol")
        self.assertEqual(one.status_code, 200)
        self.assertIn("pragma solidity", one.json()["source"])
        bad = self.client.get("/api/samples/../audit.py")
        self.assertIn(bad.status_code, (404, 422))

    def test_rejects_path_and_address_payloads(self) -> None:
        res = self.client.post("/api/scan", json={"path": "/etc/passwd"})
        self.assertEqual(res.status_code, 400)
        res = self.client.post("/api/scan", json={"address": "0x" + "11" * 20})
        self.assertEqual(res.status_code, 400)

    def test_rejects_non_sol_and_oversize(self) -> None:
        res = self.client.post(
            "/api/scan",
            files={"file": ("notes.txt", io.BytesIO(b"pragma solidity ^0.8.0;"), "text/plain")},
        )
        self.assertEqual(res.status_code, 400)
        with mock.patch.dict(os.environ, {"AUDITOR_MAX_UPLOAD_BYTES": "32"}):
            # Recreate app so limits are re-read.
            from auditor.public_demo.app import create_public_app
            client = TestClient(create_public_app())
            with client:
                huge = "pragma solidity ^0.8.0;" + ("// x" * 100)
                res = client.post("/api/scan", json={"source": huge})
                self.assertEqual(res.status_code, 400)
                self.assertIn("size cap", res.json()["error"])

    def test_disabled_routes_are_404(self) -> None:
        for path in (
            "/monitor", "/hunt", "/api/monitor/status", "/api/hunt/run",
            "/api/discovery/live", "/api/finrisk/summary",
            "/api/validate-address", "/api/exploitable",
            "/api/simulate/live", "/benchmark",
            "/api/ai-audit", "/history", "/findings",
        ):
            res = self.client.get(path)
            self.assertEqual(res.status_code, 404, path)
            # POST too
            res = self.client.post(path)
            self.assertEqual(res.status_code, 404, path)

    def test_json_scan_returns_findings_or_status(self) -> None:
        res = self.client.post("/api/scan", json={"source": SAMPLE, "filename": "reentrancy.sol"})
        self.assertEqual(res.status_code, 200, res.text)
        body = res.json()
        self.assertIn(body["status"], {"completed", "compile_failed", "slither_failed", "timeout"})
        self.assertIn("findings_by_severity", body)
        self.assertIn("content_sha256", body)
        # Must not echo a filesystem path from the host.
        self.assertNotIn("/Users/", res.text)
        if body["status"] == "completed":
            # Reentrancy sample should usually produce at least one finding
            # when Slither is available; if the toolchain is missing, status
            # will say so instead of silently returning an empty success.
            self.assertIsInstance(body["findings"], list)

    def test_rate_limit_returns_429(self) -> None:
        os.environ["AUDITOR_RATE_LIMIT_PER_HOUR"] = "2"
        from auditor.public_demo.app import create_public_app
        from auditor.public_demo.scan import scan_source
        fake = {
            "status": "completed", "findings": [], "findings_by_severity": {},
            "solc_version": "0.8.0", "error": None, "duration_s": 0.01,
            "n_findings": 0, "content_sha256": "abc", "filename": "paste.sol",
        }
        with mock.patch("auditor.public_demo.app.scan_source", return_value=fake):
            client = TestClient(create_public_app())
            with client:
                self.assertEqual(client.post("/api/scan", json={"source": "pragma solidity ^0.8.0; contract A {}"}).status_code, 200)
                self.assertEqual(client.post("/api/scan", json={"source": "pragma solidity ^0.8.0; contract B {}"}).status_code, 200)
                third = client.post("/api/scan", json={"source": "pragma solidity ^0.8.0; contract C {}"})
                self.assertEqual(third.status_code, 429)
                self.assertIn("rate limit", third.json()["error"])
                self.assertIn("Retry-After", third.headers)

    def test_create_app_dispatches_in_public_mode(self) -> None:
        from auditor.dashboard.app import create_app
        with TestClient(create_app()) as client:
            self.assertEqual(client.get("/health").json()["mode"], "public")
            self.assertEqual(client.get("/monitor").status_code, 404)
