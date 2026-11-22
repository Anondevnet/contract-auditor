"""Phase 10: report quality regressions.

A bounty check is program/scan-level. Every finding's investigation in
a multi-finding scan must show it — previously the check was attached
only when the scan happened to have exactly one finding, so the
per-finding view contradicted the top-level bounty_status block.
"""
from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

from auditor.model import (
    Confidence,
    Epistemic,
    EvidenceItem,
    Finding,
    Severity,
    VerificationStatus,
)
from auditor.scan_history import ScanHistory


def _finding(title: str) -> Finding:
    return Finding(
        title=title,
        description="fixture",
        category="security",
        severity=Severity.MEDIUM,
        confidence=Confidence.MEDIUM,
        verification_status=VerificationStatus.UNVERIFIED,
        affected_contract="Vault",
        affected_function="withdraw",
        affected_lines=[1],
        evidence=[
            EvidenceItem(
                epistemic=Epistemic.FACT,
                source="slither",
                artifact_type="tool_output",
                excerpt="- fixture",
                tool="slither",
            )
        ],
    )


class TestMultiFindingBountyPropagation(unittest.TestCase):
    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory(prefix="p10-report-")
        self._saved = os.environ.get("AUDITOR_HISTORY_DB")
        self._db = Path(self._tmpdir.name) / "history.db"
        os.environ["AUDITOR_HISTORY_DB"] = str(self._db)
        self._source = Path(self._tmpdir.name) / "Vault.sol"
        self._source.write_text("contract Vault {}", encoding="utf-8")

    def tearDown(self) -> None:
        if self._saved is None:
            os.environ.pop("AUDITOR_HISTORY_DB", None)
        else:
            os.environ["AUDITOR_HISTORY_DB"] = self._saved
        self._tmpdir.cleanup()

    def test_bounty_reaches_every_investigation_in_multi_finding_scan(self) -> None:
        from auditor.finding_store import open_store, set_metadata
        from auditor.report_builder import build_report

        findings = [_finding("Alpha issue"), _finding("Beta issue")]
        history = ScanHistory(self._db)
        try:
            scan_id = history.record_scan(
                self._source, "fp", findings=[], content_hash="h10"
            )
            history.mark_completed(scan_id, findings)
        finally:
            history.close()

        stored = {
            "status": "checked",
            "eligibility": "not_verified_automatically",
            "source_url": "https://example.org/bug-bounty",
            "checked_at": "2026-10-14T00:00:00+00:00",
            "evidence": [],
        }
        store = open_store(self._db)
        try:
            set_metadata(store, scan_id, {"bounty_check": json.dumps(stored)})
        finally:
            store.close()

        report = build_report(scan_id, history_db=self._db)
        self.assertEqual(len(report["prioritized_findings"]), 2)
        # Scan-level bounty check is visible at the report level regardless
        # of how many findings the scan produced.
        self.assertEqual(report["bounty_status"]["status"], "checked")
        self.assertEqual(
            report["bounty_status"]["source_url"], "https://example.org/bug-bounty"
        )
        # Markdown rendering includes the check in section 8.
        from auditor.report_builder import render_markdown

        md = render_markdown(report)
        self.assertIn("https://example.org/bug-bounty", md)
        self.assertIn("## 8. Bounty status", md)

    def test_no_bounty_check_still_reports_not_checked(self) -> None:
        from auditor.report_builder import build_report

        findings = [_finding("Only issue")]
        history = ScanHistory(self._db)
        try:
            scan_id = history.record_scan(
                self._source, "fp", findings=[], content_hash="h10b"
            )
            history.mark_completed(scan_id, findings)
        finally:
            history.close()
        report = build_report(scan_id, history_db=self._db)
        self.assertEqual(report["bounty_status"]["status"], "not_checked")
        self.assertIn("this scan", report["bounty_status"]["reason"])

    def test_finding_report_from_multi_finding_scan_shows_bounty(self) -> None:
        from auditor.finding_store import open_store, set_metadata
        from auditor.report_builder import build_finding_report

        findings = [_finding("Alpha issue"), _finding("Beta issue")]
        history = ScanHistory(self._db)
        try:
            scan_id = history.record_scan(
                self._source, "fp", findings=[], content_hash="h10c"
            )
            history.mark_completed(scan_id, findings)
            stored_fps = [
                str(f["fingerprint"]) for f in history.get_findings(scan_id)
            ]
        finally:
            history.close()

        store = open_store(self._db)
        try:
            set_metadata(
                store,
                scan_id,
                {
                    "bounty_check": json.dumps(
                        {
                            "status": "checked",
                            "source_url": "https://example.org/bug-bounty",
                            "checked_at": "2026-10-14T00:00:00+00:00",
                        }
                    )
                },
            )
        finally:
            store.close()

        for fp in stored_fps:
            payload = build_finding_report(scan_id, fp, history_db=self._db)
            self.assertEqual(payload["investigation"]["bounty"]["status"], "checked")


if __name__ == "__main__":
    unittest.main()
