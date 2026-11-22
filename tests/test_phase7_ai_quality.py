"""Phase 7: AI investigation quality regressions.

Guards for the AI-audit pass:

* record-first: a crash or cancel mid-pipeline leaves an honest
  terminal row (`failed` / `interrupted`), never a silent gap;
* invalid findings are dropped by the shared ``validated_findings``
  contract instead of crashing the pipeline at ``to_dict()``;
* AI output stays in the separate ``ai_analysis`` opinion block — it
  never becomes FACT evidence and never upgrades a verification status.
"""
from __future__ import annotations

import os
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

from auditor.model import (
    Confidence,
    Epistemic,
    EvidenceItem,
    Finding,
    Severity,
    VerificationStatus,
)

VAULT_SOL = """\
pragma solidity ^0.5.8;

contract Vault {
    mapping(address => uint) public balances;

    function withdraw(uint amount) public {
        (bool ok, ) = msg.sender.call.value(amount)("");
        require(ok, "transfer failed");
        balances[msg.sender] -= amount;
    }
}
"""


def _fact_finding() -> Finding:
    return Finding(
        title="Reentrancy vulnerability in Vault.withdraw",
        description="fixture finding",
        category="security",
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        verification_status=VerificationStatus.UNVERIFIED,
        affected_contract="Vault",
        affected_function="withdraw",
        affected_lines=[10, 11, 12],
        evidence=[
            EvidenceItem(
                epistemic=Epistemic.FACT,
                source="slither",
                artifact_type="tool_output",
                excerpt="- call before write",
                tool="slither",
            )
        ],
    )


def _invalid_finding() -> Finding:
    # CONFIRMED without FACT evidence violates the evidence-before-
    # conclusion rule; validated_findings must drop it.
    return Finding(
        title="Confirmed without evidence",
        description="should be dropped",
        category="security",
        severity=Severity.HIGH,
        verification_status=VerificationStatus.CONFIRMED,
        evidence=[],
    )


class _AIAuditCase(unittest.TestCase):
    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory(prefix="p7-ai-")
        self._saved = os.environ.get("AUDITOR_HISTORY_DB")
        self._db = Path(self._tmpdir.name) / "history.db"
        os.environ["AUDITOR_HISTORY_DB"] = str(self._db)
        self._root = Path(self._tmpdir.name) / "src"
        self._root.mkdir()
        (self._root / "Vault.sol").write_text(VAULT_SOL, encoding="utf-8")

    def tearDown(self) -> None:
        if self._saved is None:
            os.environ.pop("AUDITOR_HISTORY_DB", None)
        else:
            os.environ["AUDITOR_HISTORY_DB"] = self._saved
        self._tmpdir.cleanup()

    def _run(self, **kwargs):
        from auditor.ai_agent import run_ai_audit

        defaults = dict(
            use_ai=False,
            history_db=self._db,
            timeout_seconds=60.0,
        )
        defaults.update(kwargs)
        return run_ai_audit(self._root, **defaults)

    def _records(self) -> list[dict]:
        import sqlite3

        conn = sqlite3.connect(str(self._db))
        try:
            rows = conn.execute(
                "SELECT scan_id, status, error_info FROM scan_records"
            ).fetchall()
        finally:
            conn.close()
        return [
            {"scan_id": r[0], "status": r[1], "error_info": r[2] or ""} for r in rows
        ]


class TestAIRecordFirst(_AIAuditCase):
    def test_completed_audit_marks_row_completed(self) -> None:
        with mock.patch(
            "auditor.ai_agent._run_analyzers",
            return_value=([_fact_finding()], ["fixture"]),
        ):
            report = self._run()
        records = self._records()
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["status"], "completed")
        self.assertEqual(records[0]["scan_id"], report["scan_id"])

    def test_crash_mid_pipeline_leaves_failed_row(self) -> None:
        with mock.patch(
            "auditor.ai_agent._run_analyzers",
            side_effect=RuntimeError("analyzer exploded"),
        ):
            with self.assertRaises(RuntimeError):
                self._run()
        records = self._records()
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["status"], "failed")
        self.assertIn("RuntimeError", records[0]["error_info"])
        self.assertIn("analyzer exploded", records[0]["error_info"])

    def test_cancel_mid_pipeline_leaves_interrupted_row(self) -> None:
        cancel = threading.Event()
        cancel.set()
        with mock.patch(
            "auditor.ai_agent._run_analyzers",
            return_value=([_fact_finding()], ["fixture"]),
        ):
            from auditor.ai_agent import PipelineAbort

            with self.assertRaises(PipelineAbort):
                self._run(cancel_event=cancel)
        records = self._records()
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["status"], "interrupted")
        self.assertIn("cancelled", records[0]["error_info"])


class TestAIQualityGuards(_AIAuditCase):
    def test_invalid_findings_dropped_not_crash(self) -> None:
        with mock.patch(
            "auditor.ai_agent._run_analyzers",
            return_value=([_invalid_finding(), _fact_finding()], ["fixture"]),
        ):
            report = self._run()
        self.assertEqual(report["dropped_invalid_findings"], 1)
        self.assertEqual(len(report["prioritized"]), 1)
        self.assertEqual(
            report["prioritized"][0]["title"],
            "Reentrancy vulnerability in Vault.withdraw",
        )
        records = self._records()
        self.assertEqual(records[0]["status"], "completed")

    def test_ai_block_never_mixes_into_finding_evidence(self) -> None:
        with mock.patch(
            "auditor.ai_agent._run_analyzers",
            return_value=([_fact_finding()], ["fixture"]),
        ):
            report = self._run(use_ai=False)
        ai = report["ai_analysis"]
        self.assertEqual(ai["status"], "skipped")
        self.assertEqual(ai["origin"], "generated_ai_analysis")
        self.assertIn("not scanner evidence", ai["label"])
        # Scanner findings keep FACT-only evidence and UNVERIFIED status.
        from auditor.scan_history import ScanHistory

        history = ScanHistory(self._db)
        try:
            stored = history.get_findings(report["scan_id"])
        finally:
            history.close()
        self.assertEqual(len(stored), 1)
        finding = stored[0]
        self.assertEqual(finding["verification_status"], "UNVERIFIED")
        for ev in finding["evidence"]:
            self.assertEqual(ev["epistemic"], "FACT")


if __name__ == "__main__":
    unittest.main()
