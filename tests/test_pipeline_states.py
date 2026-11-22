"""Mission Phase 3: pipeline state machine and failure-propagation tests.

Covers the record-first history contract introduced for scan orchestration:

* a successful scan leaves a COMPLETED row whose content hash is the real
  combined hash (directories previously hashed to the empty-string digest),
* a mid-analysis crash leaves a FAILED row whose error_info carries the
  cause (previously such failures left no history trace at all),
* a cancelled scan leaves an INTERRUPTED row that is not reported as a
  failure,
* failures raised before any analysis runs leave NO history row,
* terminal status writes are sticky: a COMPLETED row can never be
  overwritten by a late failure when ``only_if_started=True``,
* metadata persistence is best-effort and never fails a valid scan.

Run with:

    python3 -m unittest discover -s tests -v
    python3 -m pytest -q

Every test runs against a throwaway history database pointed to by
``AUDITOR_HISTORY_DB``; the production ``audit_scan_history.db`` is never
written to. All network-dependent paths are mocked.
"""

from __future__ import annotations

import contextlib

import hashlib
import json
import os
import sys
import tempfile
import unittest
import unittest.mock as mock
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from test_dashboard import FAKE_API_KEY, VALID_ADDRESS, _fake_outcome, _mock_urlopen  # noqa: E402

from auditor.dashboard.paths import history_db_path  # noqa: E402
from auditor.scan_history import ScanHistory  # noqa: E402

SOLIDITY_SOURCE = (
    "// SPDX-License-Identifier: MIT\n"
    "pragma solidity ^0.8.0;\n"
    "contract PipelineState { uint256 public balance; }\n"
)


class PipelineStateTestCase(unittest.TestCase):
    """Shared test client + isolated history database."""

    client = None
    _tmpdir = None
    _saved_env = None

    @classmethod
    def setUpClass(cls) -> None:
        from fastapi.testclient import TestClient

        from auditor.dashboard.app import create_app

        cls._saved_env = os.environ.get("AUDITOR_HISTORY_DB")
        cls._tmpdir = tempfile.TemporaryDirectory()
        cls._db_path = Path(cls._tmpdir.name) / "history.db"
        os.environ["AUDITOR_HISTORY_DB"] = str(cls._db_path)
        cls.client = TestClient(create_app())
        cls.client.__enter__()

    @classmethod
    def tearDownClass(cls) -> None:
        if cls.client is not None:
            cls.client.__exit__(None, None, None)
            cls.client = None
        if cls._saved_env is None:
            os.environ.pop("AUDITOR_HISTORY_DB", None)
        else:
            os.environ["AUDITOR_HISTORY_DB"] = cls._saved_env
        if cls._tmpdir is not None:
            cls._tmpdir.cleanup()

    # -- helpers -----------------------------------------------------------

    def _wait_for_job(self, job_id: str, timeout: float = 30.0) -> dict:
        import time

        deadline = time.time() + timeout
        while time.time() < deadline:
            res = self.client.get(f"/api/jobs/{job_id}")
            self.assertEqual(res.status_code, 200)
            job = res.json()
            if job["status"] in ("completed", "failed", "cancelled"):
                return job
            time.sleep(0.1)
        self.fail(f"job {job_id} did not finish within {timeout}s")

    def _submit_local_scan(self, path: str, metadata: dict | None = None) -> str:
        local: dict = {"path": path, "validate_project": False}
        if metadata is not None:
            local["metadata"] = metadata
        res = self.client.post(
            "/api/scan", json={"scan_type": "local", "local": local}
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

    def _history(self) -> ScanHistory:
        return ScanHistory(history_db_path())

    def _row_count(self) -> int:
        history = self._history()
        try:
            return history.conn.execute(
                "SELECT COUNT(*) FROM scan_records"
            ).fetchone()[0]
        finally:
            history.close()

    def _get_record(self, scan_id: str) -> dict | None:
        history = self._history()
        try:
            return history.get_scan(scan_id)
        finally:
            history.close()

    @staticmethod
    def _mock_analyzers(titles=("Fixture finding",)):
        empty = lambda ctx: _fake_outcome([])
        return (
            mock.patch(
                "auditor.analysis.reentrancy.analyze",
                side_effect=lambda ctx: _fake_outcome(list(titles)),
            ),
            mock.patch(
                "auditor.analysis.access_control.analyze",
                side_effect=empty,
            ),
            mock.patch(
                "auditor.analysis.slither_generic.analyze",
                side_effect=empty,
            ),
            mock.patch("auditor.analysis.oracle_staleness.analyze", side_effect=empty),
            mock.patch("auditor.analysis.erc4626_inflation.analyze", side_effect=empty),
            mock.patch("auditor.analysis.pool_accounting.analyze", side_effect=empty),
            mock.patch("auditor.analysis.honeypot.analyze", side_effect=empty),
            mock.patch("auditor.analysis.privileged_auth.analyze", side_effect=empty),
        )


class TestLocalScanHistoryStates(PipelineStateTestCase):
    def test_completed_row_uses_real_directory_content_hash(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp) / "proj"
            project.mkdir()
            (project / "Contract.sol").write_text(SOLIDITY_SOURCE, encoding="utf-8")

            patches = self._mock_analyzers(["Fixture reentrancy"])
            with contextlib.ExitStack() as stack:
                for p in patches:
                    stack.enter_context(p)
                job_id = self._submit_local_scan(str(project))
                job = self._wait_for_job(job_id)

        self.assertEqual(job["status"], "completed", job.get("error"))
        scan_id = job["result"]["scan_id"]
        record = self._get_record(scan_id)
        self.assertIsNotNone(record)

        expected = hashlib.sha256(SOLIDITY_SOURCE.encode("utf-8")).hexdigest()
        self.assertEqual(record["status"], "completed")
        self.assertEqual(record["content_hash"], expected)
        # The old on-disk computation for directories was sha256(b""), the
        # empty digest. A real project must never collide with that.
        self.assertNotEqual(record["content_hash"], hashlib.sha256(b"").hexdigest())
        self.assertEqual(record["config_fingerprint"], "dashboard-local")
        self.assertIsNotNone(record["execution"])
        self.assertTrue(record["execution"]["scan_complete"])
        self.assertEqual(len(record["finding_fingerprints"]), 1)
        # The job response carries the same hash as the stored row.
        self.assertEqual(job["result"]["content_hash"], expected)

        detail = self.client.get(f"/api/scans/{scan_id}")
        self.assertEqual(detail.status_code, 200)
        self.assertEqual(detail.json()["finding_count"], 1)

    def test_invalid_finding_dropped_consistently(self) -> None:
        from auditor.analysis.base import AnalysisOutcome
        from auditor.model import Confidence, Finding, Severity, VerificationStatus

        # CONFIRMED requires FACT evidence; this finding passes
        # fingerprinting but fails its own validate() on serialization.
        bad = Finding(
            title="Reentrancy pattern without evidence",
            description="CONFIRMED without FACT evidence fails validation.",
            category="reentrancy",
            severity=Severity.HIGH,
            confidence=Confidence.MEDIUM,
            verification_status=VerificationStatus.CONFIRMED,
            affected_lines=[1],
        )
        outcome = AnalysisOutcome()
        outcome.findings = [bad]
        outcome.evidence = []
        outcome.notes = ["bad-finding fixture"]

        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp) / "proj"
            project.mkdir()
            (project / "Contract.sol").write_text(SOLIDITY_SOURCE, encoding="utf-8")

            with mock.patch(
                "auditor.analysis.reentrancy.analyze", return_value=outcome
            ), mock.patch(
                "auditor.analysis.access_control.analyze",
                side_effect=lambda ctx: _fake_outcome([]),
            ), mock.patch(
                "auditor.analysis.slither_generic.analyze",
                side_effect=lambda ctx: _fake_outcome([]),
            ):
                job_id = self._submit_local_scan(str(project))
                job = self._wait_for_job(job_id)

        # The invalid finding is dropped from the job response...
        self.assertEqual(job["status"], "completed", job.get("error"))
        self.assertEqual(job["result"]["finding_count"], 0)

        # ...and equally from history, so both sources agree exactly.
        record = self._get_record(job["result"]["scan_id"])
        self.assertEqual(record["status"], "completed")
        self.assertEqual(record["finding_fingerprints"], [])

        detail = self.client.get(f"/api/scans/{job['result']['scan_id']}")
        self.assertEqual(detail.status_code, 200)
        self.assertEqual(detail.json()["finding_count"], 0)

    def test_mid_scan_crash_marks_history_failed_with_cause(self) -> None:
        before = self._row_count()
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp) / "proj"
            project.mkdir()
            (project / "Contract.sol").write_text(SOLIDITY_SOURCE, encoding="utf-8")

            with mock.patch(
                "auditor.analysis.reentrancy.analyze",
                side_effect=RuntimeError("boom analyzer crash"),
            ), mock.patch(
                "auditor.analysis.access_control.analyze",
                side_effect=lambda ctx: _fake_outcome([]),
            ), mock.patch(
                "auditor.analysis.slither_generic.analyze",
                side_effect=lambda ctx: _fake_outcome([]),
            ):
                job_id = self._submit_local_scan(str(project))
                job = self._wait_for_job(job_id)

        self.assertEqual(job["status"], "failed")
        self.assertIn("boom analyzer crash", job.get("error") or "")

        # Exactly one NEW row exists, it is FAILED, and it carries the
        # cause — this trace did not exist before record-first
        # orchestration.
        self.assertEqual(self._row_count(), before + 1)
        history = self._history()
        try:
            failed = history.get_failed_scans()
        finally:
            history.close()
        crash_rows = [
            r for r in failed if "boom analyzer crash" in (r["error_info"] or "")
        ]
        self.assertEqual(len(crash_rows), 1)
        scan_id = crash_rows[0]["scan_id"]

        record = self._get_record(scan_id)
        self.assertEqual(record["status"], "failed")
        # A failed scan must not expose findings as if they were verified.
        detail = self.client.get(f"/api/scans/{scan_id}")
        self.assertEqual(detail.status_code, 200)
        self.assertEqual(detail.json()["finding_count"], 0)

    def test_cancel_dispatch_marks_history_interrupted(self) -> None:
        from auditor.dashboard.jobs import JobCancelled, JobManager, ScanJob

        before = self._row_count()
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp) / "proj"
            project.mkdir()
            (project / "Contract.sol").write_text(SOLIDITY_SOURCE, encoding="utf-8")

            job = ScanJob(job_id="cancel-test", scan_type="local", local_path=str(project))
            job._cancel_event.set()
            manager = JobManager()
            with self.assertRaises(JobCancelled):
                manager._dispatch(job)

        self.assertEqual(self._row_count(), before + 1)
        history = self._history()
        try:
            rows = history.conn.execute(
                "SELECT scan_id, status, error_info FROM scan_records "
                "WHERE error_info = ?",
                ("cancelled by user",),
            ).fetchall()
            failed_ids = {r["scan_id"] for r in history.get_failed_scans()}
        finally:
            history.close()
        self.assertEqual(len(rows), 1)
        scan_id, status, _ = rows[0]
        self.assertEqual(status, "interrupted")
        # Interrupted scans are not failures.
        self.assertNotIn(scan_id, failed_ids)

    def test_missing_path_records_no_history_row(self) -> None:
        before = self._row_count()
        job_id = self._submit_local_scan("/definitely/not/a/real/path")
        job = self._wait_for_job(job_id)
        self.assertEqual(job["status"], "failed")
        # Failures raised before analysis must not leave orphan rows.
        self.assertEqual(self._row_count(), before)

    def test_metadata_persisted_on_success(self) -> None:
        from auditor.finding_store import get_metadata, open_store

        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp) / "proj"
            project.mkdir()
            (project / "Contract.sol").write_text(SOLIDITY_SOURCE, encoding="utf-8")

            patches = self._mock_analyzers()
            with contextlib.ExitStack() as stack:
                for p in patches:
                    stack.enter_context(p)
                job_id = self._submit_local_scan(
                    str(project), metadata={"project_name": "pipeline-meta"}
                )
                job = self._wait_for_job(job_id)

        self.assertEqual(job["status"], "completed", job.get("error"))
        store = open_store(history_db_path())
        try:
            metadata = get_metadata(store, job["result"]["scan_id"])
        finally:
            store.close()
        self.assertEqual(metadata.get("project_name"), "pipeline-meta")

    def test_metadata_failure_does_not_fail_scan(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp) / "proj"
            project.mkdir()
            (project / "Contract.sol").write_text(SOLIDITY_SOURCE, encoding="utf-8")

            patches = self._mock_analyzers()
            with contextlib.ExitStack() as stack:
                for p in patches:
                    stack.enter_context(p)
                stack.enter_context(mock.patch(
                    "auditor.finding_store.open_store",
                    side_effect=RuntimeError("store down"),
                ))
                job_id = self._submit_local_scan(
                    str(project), metadata={"project_name": "doomed-meta"}
                )
                job = self._wait_for_job(job_id)

        # Metadata is enrichment: its persistence failure must never fail
        # an otherwise valid scan.
        self.assertEqual(job["status"], "completed", job.get("error"))
        self.assertIsNotNone(job["result"])
        record = self._get_record(job["result"]["scan_id"])
        self.assertEqual(record["status"], "completed")


class TestAddressScanHistoryStates(PipelineStateTestCase):
    @mock.patch.dict(os.environ, {"ETHERSCAN_API_KEY": FAKE_API_KEY})
    def test_address_success_records_completed_row(self) -> None:
        source = (
            "// SPDX-License-Identifier: MIT\n"
            "pragma solidity ^0.8.0;\n"
            "contract Retrieved { uint256 public balance; }\n"
        )
        payload = {
            "status": "1",
            "message": "OK",
            "result": [{"SourceCode": source, "ContractName": "Retrieved"}],
        }

        patches = self._mock_analyzers(["Fixture address finding"])
        with contextlib.ExitStack() as stack:
            stack.enter_context(_mock_urlopen(json.dumps(payload).encode("utf-8")))
            for p in patches:
                stack.enter_context(p)
            job_id = self._submit_address_scan(VALID_ADDRESS)
            job = self._wait_for_job(job_id)

        self.assertEqual(job["status"], "completed", job.get("error"))
        record = self._get_record(job["result"]["scan_id"])
        self.assertEqual(record["status"], "completed")
        self.assertEqual(record["config_fingerprint"], "dashboard-address")
        self.assertEqual(
            record["content_hash"], hashlib.sha256(source.encode("utf-8")).hexdigest()
        )
        # Stable display path — never the unlinked temp file the scan
        # actually read from.
        self.assertEqual(record["source_path"], f"etherscan://{VALID_ADDRESS}")
        self.assertEqual(
            job["result"]["source_path"], f"etherscan://{VALID_ADDRESS}"
        )

    @mock.patch.dict(os.environ, {"ETHERSCAN_API_KEY": FAKE_API_KEY})
    def test_address_failure_before_analysis_records_no_row(self) -> None:
        before = self._row_count()
        payload = {"status": "1", "message": "OK", "result": [{"SourceCode": "", "ContractName": ""}]}
        with _mock_urlopen(json.dumps(payload).encode("utf-8")):
            job_id = self._submit_address_scan(VALID_ADDRESS)
            job = self._wait_for_job(job_id)

        self.assertEqual(job["status"], "failed")
        self.assertIn("not verified", (job.get("error") or "").lower())
        # Unverified source fails before any row is recorded.
        self.assertEqual(self._row_count(), before)


class TestTerminalStatusGuards(unittest.TestCase):
    """Unit tests for the sticky-terminal-status guard on scan_history."""

    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        db_path = Path(self._tmpdir.name) / "history.db"
        self._saved = os.environ.get("AUDITOR_HISTORY_DB")
        os.environ["AUDITOR_HISTORY_DB"] = str(db_path)
        self.history = ScanHistory(db_path)

    def tearDown(self) -> None:
        self.history.close()
        if self._saved is None:
            os.environ.pop("AUDITOR_HISTORY_DB", None)
        else:
            os.environ["AUDITOR_HISTORY_DB"] = self._saved
        self._tmpdir.cleanup()

    def test_only_if_started_cannot_overwrite_completed(self) -> None:
        scan_id = self.history.record_scan(
            source_path=Path("/tmp/x.sol"), config_fingerprint="unit"
        )
        self.history.mark_completed(scan_id, [])
        self.assertEqual(self.history.get_scan(scan_id)["status"], "completed")

        self.history.mark_failed(
            scan_id, "late failure", only_if_started=True
        )
        self.assertEqual(
            self.history.get_scan(scan_id)["status"],
            "completed",
            "a guarded mark_failed must not overwrite a completed scan",
        )

        self.history.mark_interrupted(
            scan_id, "late cancel", only_if_started=True
        )
        self.assertEqual(
            self.history.get_scan(scan_id)["status"],
            "completed",
            "a guarded mark_interrupted must not overwrite a completed scan",
        )

    def test_unguarded_mark_still_transitions_started(self) -> None:
        scan_id = self.history.record_scan(
            source_path=Path("/tmp/x.sol"), config_fingerprint="unit"
        )
        self.history.mark_failed(scan_id, "first failure")
        self.assertEqual(self.history.get_scan(scan_id)["status"], "failed")

        # Guarded marking applies while the row is still started.
        scan_id2 = self.history.record_scan(
            source_path=Path("/tmp/y.sol"), config_fingerprint="unit"
        )
        self.history.mark_interrupted(scan_id2, "cancelled", only_if_started=True)
        self.assertEqual(
            self.history.get_scan(scan_id2)["status"], "interrupted"
        )

    def test_record_scan_uses_explicit_content_hash(self) -> None:
        scan_id = self.history.record_scan(
            source_path=Path("/tmp/dir"),
            config_fingerprint="unit",
            content_hash="explicit-hash-value",
        )
        self.assertEqual(
            self.history.get_scan(scan_id)["content_hash"], "explicit-hash-value"
        )


if __name__ == "__main__":
    unittest.main()
