"""Dashboard test suite (Phase 9).

Run with:

    python3 -m unittest discover -s tests -v

Every test runs against a throwaway history database pointed to by
``AUDITOR_HISTORY_DB`` so the production ``audit_scan_history.db`` is never
written to, and every network-dependent path is mocked: no test performs
live HTTP requests, and no test prints an API key.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import time
import unittest
import unittest.mock as mock
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from auditor.dashboard.paths import history_db_path  # noqa: E402
from auditor.model import Confidence, Finding, Severity, VerificationStatus  # noqa: E402
from auditor.scan_history import ScanHistory  # noqa: E402

FAKE_API_KEY = "SUPER-SECRET-ETHERSCAN-KEY-DO-NOT-LEAK"
VALID_ADDRESS = "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"


def _fake_outcome(titles):
    """Minimal AnalysisOutcome stand-in with canned findings."""
    from auditor.analysis.base import AnalysisOutcome

    outcome = AnalysisOutcome()
    outcome.findings = [
        Finding(
            title=title,
            description="External call precedes state update (fixture finding).",
            category="reentrancy",
            severity=Severity.HIGH,
            confidence=Confidence.MEDIUM,
            verification_status=VerificationStatus.UNVERIFIED,
            affected_lines=[12, 18],
        )
        for title in titles
    ]
    outcome.evidence = []
    outcome.notes = ["fixture analyzer"]
    return outcome


def _mock_urlopen(payload: bytes):
    """Build a urllib mock whose read() gives bytes inside a context manager."""
    response = mock.MagicMock()
    response.read.return_value = payload
    response.__enter__ = mock.Mock(return_value=response)
    response.__exit__ = mock.Mock(return_value=False)
    return mock.patch("urllib.request.urlopen", return_value=response)


class DashboardTestCase(unittest.TestCase):
    """Shared client + isolated history database."""

    client = None
    _tmpdir = None

    @classmethod
    def setUpClass(cls) -> None:
        from fastapi.testclient import TestClient

        from auditor.dashboard.app import create_app

        cls._tmpdir = tempfile.TemporaryDirectory(prefix="audit-dash-test-")
        cls._db_path = Path(cls._tmpdir.name) / "history.db"
        os.environ["AUDITOR_HISTORY_DB"] = str(cls._db_path)
        cls.client = TestClient(create_app())
        cls.client.__enter__()

    @classmethod
    def tearDownClass(cls) -> None:
        if cls.client is not None:
            cls.client.__exit__(None, None, None)
        os.environ.pop("AUDITOR_HISTORY_DB", None)
        if cls._tmpdir is not None:
            cls._tmpdir.cleanup()

    # -- helpers -----------------------------------------------------------

    def _wait_for_job(self, job_id: str, timeout: float = 30.0) -> dict:
        deadline = time.time() + timeout
        while time.time() < deadline:
            res = self.client.get(f"/api/jobs/{job_id}")
            self.assertEqual(res.status_code, 200)
            job = res.json()
            if job["status"] in ("completed", "failed", "cancelled"):
                return job
            time.sleep(0.1)
        self.fail(f"job {job_id} did not finish within {timeout}s")

    def _submit_local_scan(self, path: str) -> str:
        res = self.client.post(
            "/api/scan",
            json={"scan_type": "local", "local": {"path": path, "validate_project": False}},
        )
        self.assertEqual(res.status_code, 202, res.text)
        return res.json()["job_id"]

    def _submit_address_scan(self, address: str) -> str:
        res = self.client.post(
            "/api/scan",
            json={"scan_type": "address", "address": {"network": "ethereum", "address": address}},
        )
        self.assertEqual(res.status_code, 202, res.text)
        return res.json()["job_id"]


class TestHealthAndPages(DashboardTestCase):
    def test_health(self) -> None:
        res = self.client.get("/health")
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json(), {"status": "healthy"})

    def test_index_renders(self) -> None:
        res = self.client.get("/")
        self.assertEqual(res.status_code, 200)
        self.assertIn("Contract Auditor", res.text)
        self.assertIn("overview", res.text.lower())

    def test_scan_page_renders(self) -> None:
        res = self.client.get("/scan")
        self.assertEqual(res.status_code, 200)
        self.assertIn("New Scan", res.text)

    def test_history_page_renders(self) -> None:
        res = self.client.get("/history")
        self.assertEqual(res.status_code, 200)
        self.assertIn("Scan History", res.text)

    def test_tools_page_renders(self) -> None:
        res = self.client.get("/tools")
        self.assertEqual(res.status_code, 200)
        self.assertIn("Tool Status", res.text)

    def test_static_css_served(self) -> None:
        res = self.client.get("/static/css/dashboard.css")
        self.assertEqual(res.status_code, 200)
        self.assertIn("text/css", res.headers["content-type"])

    def test_static_js_served(self) -> None:
        res = self.client.get("/static/js/dashboard.js")
        self.assertEqual(res.status_code, 200)


class TestApiShape(DashboardTestCase):
    def test_overview_shape(self) -> None:
        res = self.client.get("/api/overview")
        self.assertEqual(res.status_code, 200)
        body = res.json()
        for key in (
            "total_scans",
            "completed_scans",
            "failed_scans",
            "total_findings",
            "findings_by_severity",
            "recent_scans",
        ):
            self.assertIn(key, body)
        self.assertIsInstance(body["recent_scans"], list)

    def test_list_scans_shape(self) -> None:
        res = self.client.get("/api/scans?limit=10")
        self.assertEqual(res.status_code, 200)
        body = res.json()
        self.assertIsInstance(body["scans"], list)
        self.assertEqual(body["total"], len(body["scans"]))

    def test_scan_detail_404(self) -> None:
        res = self.client.get("/api/scans/does-not-exist")
        self.assertEqual(res.status_code, 404)

    def test_job_404(self) -> None:
        res = self.client.get("/api/jobs/does-not-exist")
        self.assertEqual(res.status_code, 404)

    def test_cancel_unknown_job_404(self) -> None:
        res = self.client.delete("/api/jobs/does-not-exist")
        self.assertEqual(res.status_code, 404)

    def test_jobs_list_is_list(self) -> None:
        res = self.client.get("/api/jobs")
        self.assertEqual(res.status_code, 200)
        self.assertIsInstance(res.json(), list)

    def test_local_scan_requires_path(self) -> None:
        res = self.client.post("/api/scan", json={"scan_type": "local"})
        self.assertEqual(res.status_code, 422)

    def test_address_scan_requires_address(self) -> None:
        res = self.client.post("/api/scan", json={"scan_type": "address"})
        self.assertEqual(res.status_code, 422)

    def test_malformed_address_rejected(self) -> None:
        res = self.client.post(
            "/api/scan",
            json={"scan_type": "address", "address": {"network": "ethereum", "address": "0xnope"}},
        )
        self.assertEqual(res.status_code, 422)

    def test_validate_address_ok(self) -> None:
        res = self.client.post("/api/validate-address", json={"address": VALID_ADDRESS})
        self.assertEqual(res.status_code, 200)
        self.assertTrue(res.json()["is_valid"])

    def test_validate_address_malformed_422(self) -> None:
        res = self.client.post("/api/validate-address", json={"address": "0x123"})
        self.assertEqual(res.status_code, 422)

    def test_tools_endpoint_shape(self) -> None:
        res = self.client.get("/api/tools")
        self.assertEqual(res.status_code, 200)
        body = res.json()
        for key in ("toolchain", "ollama", "storage", "analysis_modules", "configuration"):
            self.assertIn(key, body)
        self.assertIn("tools", body["toolchain"])


class TestScanJobs(DashboardTestCase):
    def test_local_scan_job_completes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp) / "proj"
            project.mkdir()
            (project / "Vulnerable.sol").write_text(
                "// SPDX-License-Identifier: MIT\n"
                "pragma solidity ^0.8.0;\n"
                "contract Vulnerable { uint256 public balance; }\n",
                encoding="utf-8",
            )
            with mock.patch(
                "auditor.analysis.reentrancy.analyze",
                side_effect=lambda ctx: _fake_outcome(["Fixture reentrancy"]),
            ), mock.patch(
                "auditor.analysis.access_control.analyze",
                side_effect=lambda ctx: _fake_outcome([]),
            ), mock.patch(
                "auditor.analysis.slither_generic.analyze",
                side_effect=lambda ctx: _fake_outcome([]),
            ):
                job_id = self._submit_local_scan(str(project))
                job = self._wait_for_job(job_id)

        self.assertEqual(job["status"], "completed", job.get("error"))
        self.assertIsNotNone(job["result"])
        self.assertEqual(job["result"]["finding_count"], 1)
        scan_id = job["result"]["scan_id"]

        # Recorded in the isolated history database, retrievable via the API.
        self.assertTrue(self._db_path.exists())
        detail = self.client.get(f"/api/scans/{scan_id}")
        self.assertEqual(detail.status_code, 200)
        body = detail.json()
        self.assertEqual(body["finding_count"], 1)
        self.assertEqual(body["findings"][0]["title"], "Fixture reentrancy")
        self.assertEqual(body["findings"][0]["severity"], "HIGH")

    def test_local_scan_missing_path_fails_job(self) -> None:
        job_id = self._submit_local_scan("/definitely/not/a/real/path")
        job = self._wait_for_job(job_id)
        self.assertEqual(job["status"], "failed")
        self.assertIn("not", (job["error"] or "").lower())

    def test_address_scan_missing_api_key_fails_cleanly(self) -> None:
        with mock.patch.dict(os.environ, {"ETHERSCAN_API_KEY": ""}):
            job_id = self._submit_address_scan(VALID_ADDRESS)
            job = self._wait_for_job(job_id)

        self.assertEqual(job["status"], "failed")
        self.assertIn("ETHERSCAN_API_KEY", job["error"])
        # The key must never surface in any API representation of the job.
        raw = json.dumps(job, default=str)
        self.assertNotIn(FAKE_API_KEY, raw)

    @mock.patch.dict(os.environ, {"ETHERSCAN_API_KEY": FAKE_API_KEY})
    def test_address_scan_mocked_success(self) -> None:
        payload = {
            "status": "1",
            "message": "OK",
            "result": [
                {
                    "SourceCode": "// SPDX-License-Identifier: MIT\n"
                    "pragma solidity ^0.8.0;\n"
                    "contract Retrieved { uint256 public balance; }\n",
                    "ContractName": "Retrieved",
                }
            ],
        }
        captured = {}

        def _capture(req, timeout=None, *a, **kw):
            captured["url"] = req.full_url
            response = mock.MagicMock()
            response.read.return_value = json.dumps(payload).encode("utf-8")
            response.__enter__ = mock.Mock(return_value=response)
            response.__exit__ = mock.Mock(return_value=False)
            return response

        with mock.patch("urllib.request.urlopen", side_effect=_capture), mock.patch(
            "auditor.analysis.reentrancy.analyze",
            side_effect=lambda ctx: _fake_outcome(["Fixture address finding"]),
        ), mock.patch(
            "auditor.analysis.access_control.analyze",
            side_effect=lambda ctx: _fake_outcome([]),
        ), mock.patch(
            "auditor.analysis.slither_generic.analyze",
            side_effect=lambda ctx: _fake_outcome([]),
        ):
            job_id = self._submit_address_scan(VALID_ADDRESS)
            job = self._wait_for_job(job_id)

        self.assertEqual(job["status"], "completed", job.get("error"))
        self.assertEqual(job["result"]["finding_count"], 1)

        # Etherscan V2 endpoint with chainid=1 was used.
        self.assertIn("/v2/api", captured["url"])
        self.assertIn("chainid=1", captured["url"])

        # The key was sent (as a query param) but never echoed back.
        raw = json.dumps(job, default=str)
        self.assertNotIn(FAKE_API_KEY, raw)

    @mock.patch.dict(os.environ, {"ETHERSCAN_API_KEY": FAKE_API_KEY})
    def test_address_scan_unverified_contract_fails(self) -> None:
        payload = {
            "status": "1",
            "message": "OK",
            "result": [{"SourceCode": "", "ContractName": ""}],
        }
        with _mock_urlopen(json.dumps(payload).encode("utf-8")):
            job_id = self._submit_address_scan(VALID_ADDRESS)
            job = self._wait_for_job(job_id)

        self.assertEqual(job["status"], "failed")
        self.assertIn("not verified", (job["error"] or "").lower())


class TestHistoryAndReports(DashboardTestCase):
    def _record_scan(self) -> str:
        fixture = Path(self._db_path.parent) / "Fixture.sol"
        fixture.write_text("// fixture\n", encoding="utf-8")
        history = ScanHistory(history_db_path())
        try:
            finding = Finding(
                title="Stored finding",
                description="d",
                category="reentrancy",
                severity=Severity.MEDIUM,
                confidence=Confidence.LOW,
                verification_status=VerificationStatus.UNVERIFIED,
            )
            scan_id = history.record_scan(
                source_path=fixture,
                config_fingerprint="test-fixture",
                findings=[finding],
            )
            history.mark_completed(scan_id, [finding])
            return scan_id
        finally:
            history.close()

    def test_report_export_json(self) -> None:
        scan_id = self._record_scan()
        res = self.client.get(f"/api/scans/{scan_id}/report?format=json")
        self.assertEqual(res.status_code, 200)
        self.assertIn("application/json", res.headers["content-type"])
        self.assertIn("attachment", res.headers["content-disposition"])
        body = json.loads(res.text)
        self.assertEqual(body["scan"]["scan_id"], scan_id)
        self.assertEqual(len(body["findings"]), 1)

    def test_report_export_markdown(self) -> None:
        scan_id = self._record_scan()
        res = self.client.get(f"/api/scans/{scan_id}/report?format=markdown")
        self.assertEqual(res.status_code, 200)
        self.assertIn("text/markdown", res.headers["content-type"])
        self.assertIn("# Scan Report", res.text)
        self.assertIn("Stored finding", res.text)

    def test_history_lists_recorded_scans(self) -> None:
        scan_id = self._record_scan()
        res = self.client.get("/api/scans?limit=100")
        self.assertEqual(res.status_code, 200)
        ids = [s["scan_id"] for s in res.json()["scans"]]
        self.assertIn(scan_id, ids)

    def test_overview_counts_recorded_scans(self) -> None:
        scan_id = self._record_scan()
        res = self.client.get("/api/overview")
        body = res.json()
        ids = [s["scan_id"] for s in body["recent_scans"]]
        self.assertIn(scan_id, ids)


class TestIsolationAndCli(unittest.TestCase):
    def test_db_path_honors_override(self) -> None:
        with mock.patch.dict(os.environ, {"AUDITOR_HISTORY_DB": "/tmp/override.db"}):
            self.assertEqual(history_db_path(), Path("/tmp/override.db"))

    def test_db_path_defaults_to_project_db(self) -> None:
        env = {k: v for k, v in os.environ.items() if k != "AUDITOR_HISTORY_DB"}
        with mock.patch.dict(os.environ, env, clear=True):
            self.assertEqual(
                history_db_path(), PROJECT_ROOT / "audit_scan_history.db"
            )

    def test_cli_dashboard_rejects_non_loopback(self) -> None:
        from auditor.cli import main

        with mock.patch("sys.stderr", new_callable=lambda: __import__("io").StringIO()) as err:
            code = main(["dashboard", "--host", "0.0.0.0"])
        self.assertEqual(code, 1)
        self.assertIn("loopback-only", err.getvalue())

    def test_cli_dashboard_rejects_bad_port(self) -> None:
        from auditor.cli import main

        with mock.patch("sys.stderr", new_callable=lambda: __import__("io").StringIO()):
            code = main(["dashboard", "--port", "99999"])
        self.assertEqual(code, 1)


if __name__ == "__main__":
    unittest.main()
