"""Phase 13 — severity-based release gates (``--fail-on``).

Covers: default behavior identical to Phase 12, every supported threshold,
no-qualifying-findings exits 0 on a complete scan, incomplete scans fail closed, invalid thresholds rejected by argparse,
JSON stdout stays parseable with the gate decision on stderr, existing
error handling unchanged, unknown/missing severities never crash the gate,
and the same gate on ``scan-address``.

All analyzers are mocked (no subprocesses) and scan-history writes go to an
isolated ``AUDITOR_HISTORY_DB`` — the production database is never touched.
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import sys
import tempfile
import unittest
import unittest.mock as mock
from pathlib import Path
from types import SimpleNamespace

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from auditor.cli import (  # noqa: E402
    EXIT_ERROR,
    EXIT_OK,
    FAIL_ON_CHOICES,
    _fail_on_gate,
    _severity_rank,
    build_parser,
    main,
)
from auditor.model import (  # noqa: E402
    Confidence,
    Finding,
    Severity,
    VerificationStatus,
)

VALID_ADDRESS = "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"


def _finding(severity: Severity) -> Finding:
    return Finding(
        title=f"Fixture {severity.value} finding",
        description="Fixture finding for release-gate testing.",
        category="security",
        severity=severity,
        confidence=Confidence.MEDIUM,
        verification_status=VerificationStatus.UNVERIFIED,
        affected_lines=[10, 11],
    )


def _outcome(findings):
    from auditor.analysis.base import AnalysisOutcome

    outcome = AnalysisOutcome()
    outcome.findings = list(findings)
    outcome.evidence = []
    outcome.notes = []
    return outcome


class _AnalyzerPatch:
    """Context manager patching all three analyzers with fixture findings."""

    def __init__(self, findings):
        self.findings = list(findings)
        self._stack = contextlib.ExitStack()

    def __enter__(self):
        from unittest import mock as _mock

        self._stack.enter_context(
            _mock.patch(
                "auditor.analysis.reentrancy.analyze",
                side_effect=lambda ctx: _outcome(self.findings),
            )
        )
        self._stack.enter_context(
            _mock.patch(
                "auditor.analysis.access_control.analyze",
                side_effect=lambda ctx: _outcome([]),
            )
        )
        self._stack.enter_context(
            _mock.patch(
                "auditor.analysis.slither_generic.analyze",
                side_effect=lambda ctx: _outcome([]),
            )
        )
        # Later analyzers (oracle, erc4626, honeypot, ...) also run on this
        # path and would otherwise leave the scan incomplete, which trips the
        # intentional fail-closed --fail-on gate. These tests measure the
        # severity gate, so completeness is forced to True here.
        self._stack.enter_context(
            _mock.patch(
                "auditor.analysis.slither_runner.required_analysis_verdict",
                return_value=(True, []),
            )
        )
        return self

    def __exit__(self, *exc):
        return self._stack.__exit__(*exc)


class GateTestCase(unittest.TestCase):
    """Isolated history DB + CLI runner helpers."""

    _tmpdir = None

    @classmethod
    def setUpClass(cls) -> None:
        cls._tmpdir = tempfile.TemporaryDirectory(prefix="audit-phase13-")
        os.environ["AUDITOR_HISTORY_DB"] = str(
            Path(cls._tmpdir.name) / "history.db"
        )

    @classmethod
    def tearDownClass(cls) -> None:
        os.environ.pop("AUDITOR_HISTORY_DB", None)
        if cls._tmpdir is not None:
            cls._tmpdir.cleanup()

    def _project(self, n_files: int = 2) -> Path:
        root = Path(tempfile.mkdtemp(prefix="p13-proj-", dir=self._tmpdir.name))
        for i in range(n_files):
            (root / f"Fixture{i}.sol").write_text(
                f"pragma solidity ^0.5.8;\ncontract Fixture{i} {{ }}\n",
                encoding="utf-8",
            )
        return root

    def _run(self, argv):
        """Run main(argv); return (exit_code, stdout, stderr)."""
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main(argv)
        return code, out.getvalue(), err.getvalue()


# ---------------------------------------------------------------------------
# Gate helper unit tests
# ---------------------------------------------------------------------------


class TestGateHelper(GateTestCase):
    def test_gate_omitted_is_silent_ok(self) -> None:
        self.assertEqual(_fail_on_gate(None, [_finding(Severity.CRITICAL)]), EXIT_OK)
        self.assertEqual(_fail_on_gate("", []), EXIT_OK)

    def test_unknown_and_missing_severities_never_crash(self) -> None:
        weird = [
            SimpleNamespace(severity=None),
            SimpleNamespace(severity="MAJOR"),  # unknown string
            SimpleNamespace(),  # severity attribute absent
            SimpleNamespace(severity=42),  # wrong type
        ]
        self.assertEqual(_fail_on_gate("HIGH", weird), EXIT_OK)
        self.assertIsNone(_severity_rank(None))
        self.assertIsNone(_severity_rank("bogus"))
        self.assertIsNone(_severity_rank(object()))
        self.assertEqual(_severity_rank(Severity.LOW), 3)
        self.assertEqual(_severity_rank("high"), 1)

    def test_unknown_severity_mixed_with_real_finding(self) -> None:
        mixed = [SimpleNamespace(severity=None), _finding(Severity.CRITICAL)]
        self.assertEqual(_fail_on_gate("HIGH", mixed), EXIT_ERROR)


# ---------------------------------------------------------------------------
# Parser surface
# ---------------------------------------------------------------------------


class TestParser(GateTestCase):
    def test_fail_on_defaults_to_none(self) -> None:
        args = build_parser().parse_args(["scan", "x.sol"])
        self.assertIsNone(args.fail_on)

    def test_fail_on_choices_and_case_normalization(self) -> None:
        self.assertEqual(
            FAIL_ON_CHOICES,
            ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"),
        )
        args = build_parser().parse_args(["scan", "--fail-on", "high", "x.sol"])
        self.assertEqual(args.fail_on, "HIGH")
        args = build_parser().parse_args(
            ["scan-address", "--network", "ethereum", "--address", VALID_ADDRESS,
             "--fail-on", "low"]
        )
        self.assertEqual(args.fail_on, "LOW")

    def test_invalid_threshold_exits_2(self) -> None:
        with self.assertRaises(SystemExit) as cm:
            with contextlib.redirect_stderr(io.StringIO()) as err:
                build_parser().parse_args(["scan", "--fail-on", "SEVERE", "x.sol"])
        self.assertEqual(cm.exception.code, 2)
        self.assertIn("invalid choice", err.getvalue())


# ---------------------------------------------------------------------------
# End-to-end exit codes via main()
# ---------------------------------------------------------------------------


class TestScanGateExitCodes(GateTestCase):
    def test_default_behavior_unchanged(self) -> None:
        """No --fail-on → exit 0 with findings, no gate output anywhere."""
        project = self._project()
        with _AnalyzerPatch([_finding(Severity.CRITICAL)]):
            code, out, err = self._run(["scan", "--json", str(project)])
        self.assertEqual(code, EXIT_OK)
        self.assertEqual(json.loads(out)["findings"][0]["severity"], "CRITICAL")
        self.assertNotIn("gate:", err)
        self.assertNotIn("gate:", out)

    def test_each_threshold_matrix(self) -> None:
        """MEDIUM finding: gated by MEDIUM/LOW/INFORMATIONAL, not by
        CRITICAL/HIGH. HIGH finding: gated by HIGH and below, not CRITICAL."""
        cases = [
            (Severity.MEDIUM, "CRITICAL", EXIT_OK),
            (Severity.MEDIUM, "HIGH", EXIT_OK),
            (Severity.MEDIUM, "MEDIUM", EXIT_ERROR),
            (Severity.MEDIUM, "LOW", EXIT_ERROR),
            (Severity.MEDIUM, "INFORMATIONAL", EXIT_ERROR),
            (Severity.HIGH, "CRITICAL", EXIT_OK),
            (Severity.HIGH, "HIGH", EXIT_ERROR),
            (Severity.CRITICAL, "CRITICAL", EXIT_ERROR),
            (Severity.LOW, "LOW", EXIT_ERROR),
            (Severity.INFORMATIONAL, "INFORMATIONAL", EXIT_ERROR),
            (Severity.INFORMATIONAL, "LOW", EXIT_OK),
        ]
        for severity, threshold, expected in cases:
            with self.subTest(severity=severity.value, threshold=threshold):
                project = self._project()
                with _AnalyzerPatch([_finding(severity)]):
                    code, out, err = self._run(
                        ["scan", "--json", "--fail-on", threshold, str(project)]
                    )
                self.assertEqual(code, expected)
                self.assertEqual(json.loads(out)["findings"][0]["severity"],
                                 severity.value)
                if expected == EXIT_ERROR:
                    self.assertIn("triggered", err)
                else:
                    self.assertIn("not triggered", err)

    def test_no_qualifying_findings_exit_0(self) -> None:
        project = self._project()
        with _AnalyzerPatch([_finding(Severity.LOW)]):
            code, out, err = self._run(
                ["scan", "--json", "--fail-on", "CRITICAL", str(project)]
            )
        self.assertEqual(code, EXIT_OK)
        self.assertIn("0 of 1 finding(s)", err)
        self.assertEqual(len(json.loads(out)["findings"]), 1)

    def test_zero_findings_exit_0(self) -> None:
        project = self._project()
        with _AnalyzerPatch([]):
            code, out, err = self._run(
                ["scan", "--json", "--fail-on", "HIGH", str(project)]
            )
        self.assertEqual(code, EXIT_OK)
        self.assertIn("not triggered", err)

    def test_incomplete_scan_fail_on_cannot_pass(self) -> None:
        """Fail-closed: --fail-on cannot certify a clean result on an incomplete scan."""
        project = self._project()
        with _AnalyzerPatch([]), mock.patch(
            "auditor.analysis.slither_runner.required_analysis_verdict",
            return_value=(False, ["slither did not finish"]),
        ):
            code, out, err = self._run(
                ["scan", "--json", "--fail-on", "HIGH", str(project)]
            )
        self.assertEqual(code, EXIT_ERROR)
        self.assertIn("incomplete", err)

    def test_json_stdout_stays_valid_gate_on_stderr(self) -> None:
        project = self._project()
        with _AnalyzerPatch([_finding(Severity.HIGH)]):
            code, out, err = self._run(
                ["scan", "--json", "--fail-on", "HIGH", str(project)]
            )
        self.assertEqual(code, EXIT_ERROR)
        payload = json.loads(out)  # stdout is pure JSON
        self.assertEqual(payload["findings"][0]["severity"], "HIGH")
        self.assertIn("scan_id", payload)
        self.assertNotIn("gate:", out)
        self.assertIn("gate: fail-on HIGH triggered by 1 finding(s)", err)

    def test_text_mode_output_structure_preserved_with_gate(self) -> None:
        project = self._project()
        with _AnalyzerPatch([_finding(Severity.HIGH)]):
            code, out, err = self._run(
                ["scan", str(project), "--fail-on", "HIGH"]
            )
        self.assertEqual(code, EXIT_ERROR)
        self.assertIn("findings: 1", out)
        self.assertIn("- Fixture HIGH finding (HIGH/MEDIUM)", out)
        self.assertNotIn("gate:", out)
        self.assertIn("gate: fail-on HIGH triggered", err)

    def test_existing_error_handling_preserved(self) -> None:
        """Pre-gate errors still exit 1 with the original message only."""
        code, out, err = self._run(
            ["scan", "--fail-on", "HIGH", "/definitely/not/a/real/path"]
        )
        self.assertEqual(code, EXIT_ERROR)
        self.assertIn("path does not exist", err)
        self.assertNotIn("gate:", err)
        self.assertEqual(out, "")

        # Directory with no .sol files: same pre-gate failure, no gate output.
        empty = Path(tempfile.mkdtemp(prefix="p13-empty-", dir=self._tmpdir.name))
        code, out, err = self._run(
            ["scan", "--fail-on", "HIGH", str(empty)]
        )
        self.assertEqual(code, EXIT_ERROR)
        self.assertIn("no .sol files", err)
        self.assertNotIn("gate:", err)


# ---------------------------------------------------------------------------
# scan-address gate
# ---------------------------------------------------------------------------


class TestScanAddressGate(GateTestCase):
    def _run_address(self, extra):
        source = "pragma solidity ^0.8.0;\ncontract Retrieved { }\n"
        payload = json.dumps(
            {
                "status": "1",
                "message": "OK",
                "result": [{"SourceCode": source, "ContractName": "Retrieved"}],
            }
        ).encode("utf-8")

        response = mock.MagicMock()
        response.read.return_value = payload
        response.__enter__ = mock.Mock(return_value=response)
        response.__exit__ = mock.Mock(return_value=False)

        from unittest import mock as _mock

        with _mock.patch.dict(
            os.environ, {"ETHERSCAN_API_KEY": "test-key-not-a-real-secret"}
        ), _mock.patch(
            "urllib.request.urlopen", return_value=response
        ), _AnalyzerPatch([_finding(Severity.HIGH)]):
            return self._run(
                [
                    "scan-address",
                    "--network", "ethereum",
                    "--address", VALID_ADDRESS,
                    "--json",
                    *extra,
                ]
            )

    def test_address_gate_triggers(self) -> None:
        code, out, err = self._run_address(["--fail-on", "HIGH"])
        self.assertEqual(code, EXIT_ERROR)
        payload = json.loads(out)
        self.assertEqual(payload["findings"][0]["severity"], "HIGH")
        self.assertIn("gate: fail-on HIGH triggered", err)
        self.assertNotIn("gate:", out)

    def test_address_default_unchanged(self) -> None:
        code, out, err = self._run_address([])
        self.assertEqual(code, EXIT_OK)
        self.assertNotIn("gate:", err)
        self.assertEqual(len(json.loads(out)["findings"]), 1)

    def test_address_gate_not_triggered(self) -> None:
        code, out, err = self._run_address(["--fail-on", "CRITICAL"])
        self.assertEqual(code, EXIT_OK)
        self.assertIn("not triggered", err)


if __name__ == "__main__":
    unittest.main()
