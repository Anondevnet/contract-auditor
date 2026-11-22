"""Phase 4: finding normalization / dedup regression tests.

The canonical merge contract for the whole pipeline:

* the same vulnerability reported by several detectors collapses to one
  finding, preserving every detector's evidence and the worst severity;
* distinct vulnerabilities at the same location are never merged;
* multi-file projects are distinguished by ``affected_file``;
* missing evidence and conflicting analyzer results cannot crash or
  silently upgrade a finding;
* dedupe is deterministic and idempotent;
* the CLI path dedupes exactly like the dashboard path, and the AI-audit
  retest runs the same three analyzers and still matches fingerprints
  stored before the file dimension was added.
"""
from __future__ import annotations

import argparse
import json
import os
import sqlite3
import sys
import tempfile
import unittest
from io import StringIO
from pathlib import Path
from unittest import mock

from test_dashboard import FAKE_API_KEY, VALID_ADDRESS, _mock_urlopen  # noqa: E402

from auditor.model import (  # noqa: E402
    Confidence,
    Epistemic,
    EvidenceItem,
    Finding,
    Severity,
    VerificationStatus,
    deduplicate_findings,
    finding_fingerprint,
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


def _ev(excerpt: str) -> EvidenceItem:
    return EvidenceItem(
        epistemic=Epistemic.FACT,
        source="slither",
        artifact_type="tool_output",
        excerpt=excerpt,
        tool="slither",
    )


def _finding(
    title: str = "Reentrancy vulnerability in Vault.withdraw",
    *,
    description: str = "fixture description",
    severity: Severity = Severity.MEDIUM,
    confidence: Confidence = Confidence.MEDIUM,
    contract: str = "Vault",
    function: str = "withdraw",
    lines: tuple[int, ...] = (10, 11, 12),
    affected_file: str | None = None,
    evidence: list[EvidenceItem] | None = None,
    tool: str = "slither",
) -> Finding:
    return Finding(
        title=title,
        description=description,
        category="security",
        severity=severity,
        confidence=confidence,
        verification_status=VerificationStatus.UNVERIFIED,
        affected_contract=contract,
        affected_function=function,
        affected_lines=list(lines),
        affected_file=affected_file,
        evidence=list(evidence) if evidence is not None else [_ev("- call before write")],
        source="slither",
        tool=tool,
    )


def _stable(f: Finding) -> dict:
    """Deterministic projection: no random ids or timestamps."""
    return {
        "title": f.title,
        "severity": f.severity.value,
        "confidence": f.confidence.value,
        "description": f.description,
        "affected_file": f.affected_file,
        "tool": f.tool,
        "evidence_hashes": sorted(
            ev.content_hash for ev in f.evidence if ev.content_hash
        ),
        "evidence_tools": sorted({ev.tool or "" for ev in f.evidence}),
        "fingerprint": str(finding_fingerprint(f)),
    }


class TestCanonicalDedupe(unittest.TestCase):
    def test_same_vuln_duplicates_merge_preserving_metadata(self) -> None:
        eth = _finding(
            description="Reentrancy in Vault.withdraw. Slither detector: reentrancy-eth.",
            severity=Severity.HIGH,
            evidence=[_ev("- (ok,None) = msg.sender.call.value(amount)()")],
        )
        no_eth = _finding(
            description="Reentrancy in Vault.withdraw. Slither detector: reentrancy-no-eth.",
            severity=Severity.MEDIUM,
            evidence=[_ev("- balances[msg.sender] -= amount")],
        )
        unique, count = deduplicate_findings([eth, no_eth])

        self.assertEqual(count, 1)
        self.assertEqual(len(unique), 1)
        merged = unique[0]
        self.assertEqual(merged.severity, Severity.HIGH)
        self.assertEqual(merged.confidence, Confidence.MEDIUM)
        self.assertEqual(merged.tool, "slither")
        excerpts = {ev.excerpt for ev in merged.evidence}
        self.assertIn("- (ok,None) = msg.sender.call.value(amount)()", excerpts)
        self.assertIn("- balances[msg.sender] -= amount", excerpts)
        self.assertIn("reentrancy-eth", merged.description)
        self.assertIn("reentrancy-no-eth", merged.description)
        # First finding's identity is stable (first-seen order).
        self.assertIs(merged, eth)

    def test_distinct_vulns_same_location_not_merged(self) -> None:
        reent = _finding()
        access = _finding(title="Access control issue in Vault.withdraw")
        unique, count = deduplicate_findings([reent, access])
        self.assertEqual(count, 0)
        self.assertEqual(len(unique), 2)

    def test_same_prefix_different_lines_not_merged(self) -> None:
        a = _finding(lines=(10, 11, 12))
        b = _finding(lines=(40, 41))
        unique, count = deduplicate_findings([a, b])
        self.assertEqual(count, 0)
        self.assertEqual(len(unique), 2)

    def test_multi_file_same_contract_distinguished_by_file(self) -> None:
        src = _finding(affected_file="src/Vault.sol")
        test = _finding(affected_file="test/Vault.sol")
        self.assertNotEqual(finding_fingerprint(src), finding_fingerprint(test))
        unique, count = deduplicate_findings([src, test])
        self.assertEqual(count, 0)
        self.assertEqual(len(unique), 2)

    def test_same_file_duplicates_merge(self) -> None:
        a = _finding(affected_file="src/Vault.sol", severity=Severity.MEDIUM)
        b = _finding(affected_file="src/Vault.sol", severity=Severity.CRITICAL)
        unique, count = deduplicate_findings([a, b])
        self.assertEqual(count, 1)
        self.assertEqual(len(unique), 1)
        self.assertEqual(unique[0].severity, Severity.CRITICAL)

    def test_missing_evidence_merges_cleanly(self) -> None:
        bare = _finding(evidence=[])
        with_ev = _finding(evidence=[_ev("- external call observed")])
        unique, count = deduplicate_findings([bare, with_ev])
        self.assertEqual(count, 1)
        self.assertEqual(len(unique[0].evidence), 1)

    def test_evidence_union_dedups_identical_content(self) -> None:
        a = _finding(evidence=[_ev("- same excerpt")])
        b = _finding(evidence=[_ev("- same excerpt")])  # equal hash, unique id
        unique, _count = deduplicate_findings([a, b])
        self.assertEqual(len(unique[0].evidence), 1)

    def test_conflicting_severity_keeps_worst_confidence_first_wins(self) -> None:
        first = _finding(severity=Severity.LOW, confidence=Confidence.LOW)
        second = _finding(severity=Severity.HIGH, confidence=Confidence.HIGH)
        unique, _count = deduplicate_findings([first, second])
        self.assertEqual(unique[0].severity, Severity.HIGH)
        self.assertEqual(unique[0].confidence, Confidence.LOW)

    def test_unknown_severity_never_upgrades_known(self) -> None:
        good = _finding(severity=Severity.MEDIUM)
        bogus = _finding(severity="NOT_A_SEVERITY")  # type: ignore[arg-type]
        unique, _count = deduplicate_findings([good, bogus])
        self.assertEqual(unique[0].severity, Severity.MEDIUM)

    def test_deterministic_and_idempotent(self) -> None:
        def batch() -> list[Finding]:
            return [
                _finding(
                    description="Slither detector: reentrancy-eth.",
                    severity=Severity.HIGH,
                    evidence=[_ev("- call")],
                ),
                _finding(
                    description="Slither detector: reentrancy-no-eth.",
                    severity=Severity.MEDIUM,
                    evidence=[_ev("- write")],
                ),
                _finding(
                    title="Access control issue in Vault.withdraw",
                    evidence=[_ev("- missing zero check")],
                ),
            ]

        first, count1 = deduplicate_findings(batch())
        second, count2 = deduplicate_findings(batch())
        self.assertEqual(count1, count2)
        self.assertEqual(
            [_stable(f) for f in first], [_stable(f) for f in second]
        )
        again, extra = deduplicate_findings(list(first))
        self.assertEqual(extra, 0)
        self.assertEqual([_stable(f) for f in first], [_stable(f) for f in again])

    def test_jobs_delegate_matches_model(self) -> None:
        from auditor.dashboard.jobs import _dedupe_findings

        batch = [
            _finding(severity=Severity.HIGH, evidence=[_ev("- a")]),
            _finding(severity=Severity.MEDIUM, evidence=[_ev("- b")]),
        ]
        via_model, count = deduplicate_findings(batch)
        self.assertEqual(count, 1)
        via_jobs = _dedupe_findings(batch)
        self.assertEqual(len(via_jobs), len(via_model))
        self.assertEqual(
            [_stable(f) for f in via_jobs], [_stable(f) for f in via_model]
        )


class TestFingerprintFormat(unittest.TestCase):
    def test_fingerprint_is_five_tuple_with_stable_string(self) -> None:
        f = _finding(affected_file="src/Vault.sol")
        fp = finding_fingerprint(f)
        self.assertEqual(len(fp), 5)
        self.assertEqual(fp[4], "src/Vault.sol")
        self.assertEqual(str(fp), str(finding_fingerprint(f)))

    def test_legacy_four_tuple_projection(self) -> None:
        f = _finding(affected_file="src/Vault.sol")
        legacy = str(tuple(finding_fingerprint(f))[:4])
        self.assertEqual(
            legacy,
            str(("Vault", "withdraw", (10, 11, 12), "Reentrancy")),
        )
        # Without a file the fifth element is empty, so the 4-tuple
        # projection is identical — the legacy retest fallback key.
        no_file = _finding()
        self.assertEqual(str(tuple(finding_fingerprint(no_file))[:4]), legacy)
        self.assertEqual(
            str(finding_fingerprint(no_file)),
            str(("Vault", "withdraw", (10, 11, 12), "Reentrancy", "")),
        )

    def test_to_dict_carries_affected_file(self) -> None:
        d = _finding(affected_file="src/Vault.sol").to_dict()
        self.assertEqual(d["affected_file"], "src/Vault.sol")


class _HistoryEnv(unittest.TestCase):
    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory(prefix="p4-dedup-")
        self._saved = os.environ.get("AUDITOR_HISTORY_DB")
        os.environ["AUDITOR_HISTORY_DB"] = str(Path(self._tmpdir.name) / "history.db")
        self._proj = Path(self._tmpdir.name) / "proj"
        self._proj.mkdir()
        (self._proj / "Vault.sol").write_text(VAULT_SOL, encoding="utf-8")

    def tearDown(self) -> None:
        if self._saved is None:
            os.environ.pop("AUDITOR_HISTORY_DB", None)
        else:
            os.environ["AUDITOR_HISTORY_DB"] = self._saved
        self._tmpdir.cleanup()

    @staticmethod
    def _make_outcome(findings: list):
        from auditor.analysis.base import AnalysisOutcome

        o = AnalysisOutcome()
        o.findings = list(findings)
        o.evidence = []
        o.notes = []
        return o

    def _stored_findings(self) -> list[dict]:
        from auditor.scan_history import ScanHistory

        history = ScanHistory(Path(os.environ["AUDITOR_HISTORY_DB"]))
        try:
            cursor = history.conn.execute(
                "SELECT scan_id FROM scan_records ORDER BY timestamp DESC, scan_id DESC LIMIT 1"
            )
            row = cursor.fetchone()
            self.assertIsNotNone(row, "no scan was recorded")
            findings = history.get_findings(row[0])
        finally:
            history.close()
        return findings


class TestCLIPathParity(_HistoryEnv):
    def _run_cmd_scan(self, reent: list, access: list, generic: list) -> int:
        from auditor.cli import _cmd_scan
        from auditor.settings import load_settings

        args = argparse.Namespace(
            path=str(self._proj),
            json=True,
            fail_on=None,
            verbose=False,
            model=None,
            timeout=None,
            no_probe_model=False,
        )
        settings = load_settings()
        with mock.patch(
            "auditor.analysis.reentrancy.analyze",
            return_value=self._make_outcome(reent),
        ), mock.patch(
            "auditor.analysis.access_control.analyze",
            return_value=self._make_outcome(access),
        ), mock.patch(
            "auditor.analysis.slither_generic.analyze",
            return_value=self._make_outcome(generic),
        ), mock.patch(
            "auditor.analysis.privileged_auth.analyze",
            return_value=self._make_outcome([]),
        ):
            old_stdout = sys.stdout
            sys.stdout = StringIO()
            try:
                code = _cmd_scan(args, settings)
            finally:
                sys.stdout = old_stdout
        return code

    def test_cli_local_scan_merges_detector_duplicates(self) -> None:
        eth = _finding(severity=Severity.HIGH, evidence=[_ev("- call")])
        no_eth = _finding(severity=Severity.MEDIUM, evidence=[_ev("- write")])
        access = _finding(title="Access control issue in Vault.withdraw")
        code = self._run_cmd_scan([eth, no_eth], [access], [])
        self.assertEqual(code, 0)
        stored = self._stored_findings()
        self.assertEqual(len(stored), 2)
        titles = sorted(f["title"] for f in stored)
        self.assertEqual(
            titles,
            [
                "Access control issue in Vault.withdraw",
                "Reentrancy vulnerability in Vault.withdraw",
            ],
        )
        reent_row = next(f for f in stored if "Reentrancy" in f["title"])
        self.assertEqual(reent_row["severity"], "HIGH")

    def test_cli_address_scan_runs_generic_and_merges(self) -> None:
        from auditor.cli import _cmd_scan_address
        from auditor.settings import load_settings

        source = VAULT_SOL
        payload = {
            "status": "1",
            "message": "OK",
            "result": [{"SourceCode": source, "ContractName": "Vault"}],
        }
        dup_a = _finding(severity=Severity.MEDIUM, evidence=[_ev("- call")])
        dup_b = _finding(severity=Severity.HIGH, evidence=[_ev("- generic")])
        generic_finding = _finding(
            title="arbitrary-send in Vault.withdraw",
            severity=Severity.MEDIUM,
            evidence=[_ev("- arbitrary send")],
        )
        args = argparse.Namespace(address=VALID_ADDRESS, network="ethereum")
        settings = load_settings()
        with mock.patch.dict(os.environ, {"ETHERSCAN_API_KEY": FAKE_API_KEY}), \
                _mock_urlopen(json.dumps(payload).encode("utf-8")), \
                mock.patch(
                    "auditor.analysis.reentrancy.analyze",
                    return_value=self._make_outcome([dup_a]),
                ), mock.patch(
                    "auditor.analysis.access_control.analyze",
                    return_value=self._make_outcome([]),
                ), mock.patch(
                    "auditor.analysis.slither_generic.analyze",
                    return_value=self._make_outcome([dup_b, generic_finding]),
                ) as generic_mock, mock.patch(
                    "auditor.analysis.privileged_auth.analyze",
                    return_value=self._make_outcome([]),
                ):
            old_stdout = sys.stdout
            sys.stdout = StringIO()
            try:
                code = _cmd_scan_address(args, settings)
            finally:
                sys.stdout = old_stdout
        self.assertEqual(code, 0)
        generic_mock.assert_called_once()
        stored = self._stored_findings()
        # dup_a + dup_b merge; generic_finding is distinct.
        self.assertEqual(len(stored), 2)
        titles = sorted(f["title"] for f in stored)
        self.assertEqual(
            titles,
            [
                "Reentrancy vulnerability in Vault.withdraw",
                "arbitrary-send in Vault.withdraw",
            ],
        )


class TestAIAgentParity(unittest.TestCase):
    def test_run_analyzers_includes_generic(self) -> None:
        from auditor.ai_agent import _run_analyzers

        generic_finding = _finding(title="suicidal in Vault.withdraw")
        with mock.patch(
            "auditor.ai_agent.reentrancy_analyze",
            return_value=TestCLIPathParity._make_outcome([_finding()]),
        ), mock.patch(
            "auditor.ai_agent.access_control_analyze",
            return_value=TestCLIPathParity._make_outcome([]),
        ), mock.patch(
            "auditor.ai_agent.generic_analyze",
            return_value=TestCLIPathParity._make_outcome([generic_finding]),
        ) as generic_mock:
            findings, _notes = _run_analyzers([Path("Vault.sol")])
        generic_mock.assert_called_once()
        self.assertEqual(len(findings), 2)
        self.assertIn("suicidal in Vault.withdraw", {f.title for f in findings})


class TestLegacyRetestFingerprint(unittest.TestCase):
    """Pre-upgrade scans stored 4-tuple fingerprints; retest must still match."""

    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory(prefix="p4-retest-")
        self._saved = os.environ.get("AUDITOR_HISTORY_DB")
        os.environ["AUDITOR_HISTORY_DB"] = str(Path(self._tmpdir.name) / "history.db")
        self._root = Path(self._tmpdir.name) / "src"
        self._root.mkdir()
        (self._root / "Vault.sol").write_text(VAULT_SOL, encoding="utf-8")

    def tearDown(self) -> None:
        if self._saved is None:
            os.environ.pop("AUDITOR_HISTORY_DB", None)
        else:
            os.environ["AUDITOR_HISTORY_DB"] = self._saved
        self._tmpdir.cleanup()

    def test_retest_matches_legacy_four_tuple_fingerprint(self) -> None:
        from auditor.ai_agent import run_retest
        from auditor.scan_history import ScanHistory

        finding = _finding(lines=(10, 11, 12))
        db_path = Path(os.environ["AUDITOR_HISTORY_DB"])
        history = ScanHistory(db_path)
        try:
            scan_id = history.record_scan(
                source_path=self._root,
                config_fingerprint="legacy-fixture",
                findings=[finding],
            )
            history.mark_completed(scan_id, [finding])
        finally:
            history.close()

        # Simulate a pre-upgrade row: rewrite the stored fingerprint from
        # the 5-tuple form to the legacy 4-tuple string.
        legacy_fp = str(tuple(finding_fingerprint(finding))[:4])
        conn = sqlite3.connect(str(db_path))
        try:
            row = conn.execute(
                "SELECT finding_details FROM scan_records WHERE scan_id = ?",
                (scan_id,),
            ).fetchone()
            details = json.loads(row[0])
            for detail in details:
                detail["fingerprint"] = legacy_fp
            conn.execute(
                "UPDATE scan_records SET finding_details = ? WHERE scan_id = ?",
                (json.dumps(details, default=str), scan_id),
            )
            conn.commit()
        finally:
            conn.close()

        reproduced = _finding(lines=(10, 11, 12))
        with mock.patch(
            "auditor.ai_agent.reentrancy_analyze",
            return_value=TestCLIPathParity._make_outcome([reproduced]),
        ), mock.patch(
            "auditor.ai_agent.access_control_analyze",
            return_value=TestCLIPathParity._make_outcome([]),
        ), mock.patch(
            "auditor.ai_agent.generic_analyze",
            return_value=TestCLIPathParity._make_outcome([]),
        ):
            result = run_retest(
                scan_id, legacy_fp, history_db=db_path, timeout_seconds=60
            )
        self.assertTrue(result["persisted"], result)
        self.assertIn(reproduced.title, result["matches"])

    def test_retest_new_format_fingerprint_still_matches(self) -> None:
        from auditor.ai_agent import run_retest
        from auditor.scan_history import ScanHistory

        finding = _finding(lines=(10, 11, 12))
        db_path = Path(os.environ["AUDITOR_HISTORY_DB"])
        history = ScanHistory(db_path)
        try:
            scan_id = history.record_scan(
                source_path=self._root,
                config_fingerprint="current-fixture",
                findings=[finding],
            )
            history.mark_completed(scan_id, [finding])
        finally:
            history.close()

        new_fp = str(finding_fingerprint(finding))
        reproduced = _finding(lines=(10, 11, 12))
        with mock.patch(
            "auditor.ai_agent.reentrancy_analyze",
            return_value=TestCLIPathParity._make_outcome([reproduced]),
        ), mock.patch(
            "auditor.ai_agent.access_control_analyze",
            return_value=TestCLIPathParity._make_outcome([]),
        ), mock.patch(
            "auditor.ai_agent.generic_analyze",
            return_value=TestCLIPathParity._make_outcome([]),
        ):
            result = run_retest(
                scan_id, new_fp, history_db=db_path, timeout_seconds=60
            )
        self.assertTrue(result["persisted"], result)


class TestRelativeSourceName(unittest.TestCase):
    def test_single_file_returns_none(self) -> None:
        from auditor.analysis.slither_runner import relative_source_name

        single = [Path("/tmp/abc123/contract.sol")]
        self.assertIsNone(relative_source_name("/tmp/abc123/contract.sol", single))
        self.assertIsNone(relative_source_name(None, single))

    def test_multi_file_relativizes_absolute_path(self) -> None:
        from auditor.analysis.slither_runner import relative_source_name

        files = [
            Path("/proj/src/Vault.sol"),
            Path("/proj/test/Vault.t.sol"),
        ]
        self.assertEqual(
            relative_source_name("/proj/src/Vault.sol", files), "src/Vault.sol"
        )

    def test_multi_file_keeps_relative_path(self) -> None:
        from auditor.analysis.slither_runner import relative_source_name

        files = [Path("/proj/src/Vault.sol"), Path("/proj/test/Vault.t.sol")]
        self.assertEqual(
            relative_source_name("src/Vault.sol", files), "src/Vault.sol"
        )

    def test_multi_file_outside_root_falls_back_to_basename(self) -> None:
        from auditor.analysis.slither_runner import relative_source_name

        files = [Path("/proj/src/A.sol"), Path("/proj/src/B.sol")]
        self.assertEqual(
            relative_source_name("/elsewhere/C.sol", files), "C.sol"
        )


class TestDetectorFilename(unittest.TestCase):
    def test_extracts_filename_from_elements(self) -> None:
        from auditor.analysis.slither_runner import detector_filename

        det = {
            "elements": [
                {
                    "type": "function",
                    "name": "withdraw(uint256)",
                    "source_mapping": {
                        "filename": "src/Vault.sol",
                        "lines": [10, 11],
                    },
                }
            ]
        }
        self.assertEqual(detector_filename(det), "src/Vault.sol")

    def test_missing_filename_returns_none(self) -> None:
        from auditor.analysis.slither_runner import detector_filename

        self.assertIsNone(detector_filename({"elements": []}))
        self.assertIsNone(detector_filename({}))


class TestAnalyzerAffectedFile(unittest.TestCase):
    """Analyzers set affected_file only when the scan has multiple files."""

    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory(prefix="p4-analyzers-")
        self._proj = Path(self._tmpdir.name) / "proj"
        (self._proj / "src").mkdir(parents=True)
        (self._proj / "test").mkdir()
        self._vault = self._proj / "src" / "Vault.sol"
        self._other = self._proj / "test" / "Other.sol"
        self._vault.write_text(VAULT_SOL, encoding="utf-8")
        self._other.write_text(VAULT_SOL.replace("Vault", "Other"), encoding="utf-8")

    def tearDown(self) -> None:
        self._tmpdir.cleanup()

    @staticmethod
    def _slither_run(detectors: list):
        run = mock.MagicMock()
        run.ok = True
        run.detectors = detectors
        run.notes = []
        run.failure_note.return_value = ""
        run.stdout = ""
        run.stderr = ""
        return run

    @staticmethod
    def _det(check: str, impact: str, filename: str, *, confidence: str = "Medium") -> dict:
        return {
            "check": check,
            "impact": impact,
            "confidence": confidence,
            "description": f"{check} in Vault.withdraw(uint256)",
            "elements": [
                {
                    "type": "function",
                    "name": "withdraw(uint256)",
                    "source_mapping": {"filename": filename, "lines": [10, 11, 12]},
                    "type_specific_fields": {"parent": {"type": "contract", "name": "Vault"}},
                }
            ],
        }

    def test_reentrancy_multi_file_sets_relative_file(self) -> None:
        from auditor.analysis.base import AnalysisContext
        from auditor.analysis.reentrancy import analyze

        det = self._det("reentrancy-eth", "High", str(self._vault))
        context = AnalysisContext()
        context.source_files = [self._vault, self._other]
        with mock.patch(
            "auditor.analysis.slither_runner.run_slither",
            return_value=self._slither_run([det]),
        ):
            outcome = analyze(context)
        self.assertEqual(len(outcome.findings), 1)
        self.assertEqual(outcome.findings[0].affected_file, "src/Vault.sol")

    def test_single_file_scan_leaves_file_none(self) -> None:
        from auditor.analysis.base import AnalysisContext
        from auditor.analysis.reentrancy import analyze

        det = self._det("reentrancy-eth", "High", str(self._vault))
        context = AnalysisContext()
        context.source_files = [self._vault]
        with mock.patch(
            "auditor.analysis.slither_runner.run_slither",
            return_value=self._slither_run([det]),
        ):
            outcome = analyze(context)
        self.assertEqual(len(outcome.findings), 1)
        self.assertIsNone(outcome.findings[0].affected_file)

    def test_generic_multi_file_sets_relative_file(self) -> None:
        from auditor.analysis.base import AnalysisContext
        from auditor.analysis.slither_generic import analyze

        det = self._det("arbitrary-send", "High", str(self._vault))
        context = AnalysisContext()
        context.source_files = [self._vault, self._other]
        with mock.patch(
            "auditor.analysis.slither_runner.run_slither",
            return_value=self._slither_run([det]),
        ):
            outcome = analyze(context)
        self.assertEqual(len(outcome.findings), 1)
        self.assertEqual(outcome.findings[0].affected_file, "src/Vault.sol")

    def test_access_control_multi_file_sets_relative_file(self) -> None:
        from auditor.analysis.access_control import analyze
        from auditor.analysis.base import AnalysisContext

        det = self._det("missing-zero-check", "High", str(self._vault))
        context = AnalysisContext()
        context.source_files = [self._vault, self._other]
        with mock.patch(
            "auditor.analysis.slither_runner.run_slither",
            return_value=self._slither_run([det]),
        ):
            outcome = analyze(context)
        self.assertEqual(len(outcome.findings), 1)
        self.assertEqual(outcome.findings[0].affected_file, "src/Vault.sol")


if __name__ == "__main__":
    unittest.main()
