"""Phase 5: detector validation regressions.

Guards for the detector-validation pass:

* the access-control text fallback maps detector slugs to slither's real
  impacts (no more inflating ``missing-zero-check`` to HIGH);
* the JSON path still trusts the reported impact over the slug map;
* the dead, false-positive-prone class-based analyzers stay removed.
"""
from __future__ import annotations

import os
import unittest
from pathlib import Path

from auditor.model import Severity

ACCESS_TEXT_OUTPUT = """\
INFO:Detectors:
Detector: missing-zero-check
Vault.setOwner(address).newOwner (Vault.sol#20) lacks a zero-check on :
\t\t- owner = newOwner (Vault.sol#21)
Reference: https://github.com/crytic/slither/wiki/Detector-Documentation#missing-zero-address-validation
"""

TX_ORIGIN_OUTPUT = """\
INFO:Detectors:
Detector: tx-origin
Vault.forward(address) (Vault.sol#30) uses tx.origin for auth: require(tx.origin == owner)
Reference: https://github.com/crytic/slither/wiki/Detector-Documentation#dangerous-tx-origin
"""

SUICIDAL_OUTPUT = """\
INFO:Detectors:
Detector: suicidal
Vault.kill() (Vault.sol#40) allows anyone to destruct the contract
Reference: https://github.com/crytic/slither/wiki/Detector-Documentation#suicidal
"""


class TestAccessTextSeverityMap(unittest.TestCase):
    def test_missing_zero_check_maps_to_low(self) -> None:
        from auditor.analysis.access_control import _parse_slither_text

        findings = _parse_slither_text(ACCESS_TEXT_OUTPUT, "")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, Severity.LOW)

    def test_tx_origin_maps_to_medium(self) -> None:
        from auditor.analysis.access_control import _parse_slither_text

        findings = _parse_slither_text(TX_ORIGIN_OUTPUT, "")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, Severity.MEDIUM)

    def test_suicidal_maps_to_high(self) -> None:
        from auditor.analysis.access_control import _parse_slither_text

        findings = _parse_slither_text(SUICIDAL_OUTPUT, "")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, Severity.HIGH)

    def test_json_impact_wins_over_slug_map(self) -> None:
        from auditor.analysis.access_control import _make_finding

        f = _make_finding(
            "Vault",
            "setOwner",
            "20",
            ["- owner = newOwner"],
            detector="missing-zero-check",
            impact="High",
        )
        self.assertEqual(f.severity, Severity.HIGH)

    def test_text_fallback_without_impact_uses_slug(self) -> None:
        from auditor.analysis.access_control import _make_finding

        f = _make_finding(
            "Vault",
            "setOwner",
            "20",
            ["- owner = newOwner"],
            detector="missing-zero-check",
        )
        self.assertEqual(f.severity, Severity.LOW)

    def test_unknown_access_slug_defaults_conservative_high(self) -> None:
        from auditor.analysis.access_control import _make_finding

        f = _make_finding(
            "Vault",
            "adminOp",
            "30",
            ["- unrestricted"],
            detector="some-new-access-check",
        )
        self.assertEqual(f.severity, Severity.HIGH)


class TestDeadAnalyzerClassesStayRemoved(unittest.TestCase):
    def test_class_based_analyzers_are_gone(self) -> None:
        import auditor.analysis.base as base

        self.assertFalse(hasattr(base, "ReentrancyAnalyzer"))
        self.assertFalse(hasattr(base, "AccessControlAnalyzer"))

    def test_shared_types_and_abc_remain(self) -> None:
        from auditor.analysis.base import (
            AnalysisContext,
            AnalysisOutcome,
            BaseAnalyzer,
        )

        self.assertTrue(callable(BaseAnalyzer))
        self.assertIsInstance(AnalysisContext(), AnalysisContext)
        self.assertIsInstance(AnalysisOutcome(), AnalysisOutcome)


class TestGenericImpactPolicy(unittest.TestCase):
    def test_informational_and_optimization_are_not_generic_impacts(self) -> None:
        from auditor.analysis.slither_generic import _GENERIC_IMPACTS

        self.assertNotIn("Informational", _GENERIC_IMPACTS)
        self.assertNotIn("Optimization", _GENERIC_IMPACTS)
        self.assertEqual(_GENERIC_IMPACTS, ("High", "Medium", "Low"))


if __name__ == "__main__":
    unittest.main()


class TestChooseTargetRealWorld(unittest.TestCase):
    """Regression: multi-file directory scans must resolve on disk.

    Found by the Phase 6 real-world corpus scan (protocol/contracts):
    cwd == target made Slither look for protocol/contracts/protocol/contracts.
    """

    def setUp(self) -> None:
        import tempfile
        from pathlib import Path

        self._tmpdir = tempfile.TemporaryDirectory(prefix="p5-target-")
        self._root = Path(self._tmpdir.name) / "proj"
        (self._root / "src").mkdir(parents=True)
        (self._root / "src" / "A.sol").write_text("// A\n", encoding="utf-8")
        (self._root / "src" / "B.sol").write_text("// B\n", encoding="utf-8")

    def tearDown(self) -> None:
        self._tmpdir.cleanup()

    def test_multi_file_directory_target_is_absolute_with_parent_cwd(self) -> None:
        from auditor.analysis.slither_runner import collect_sol_files, choose_target

        files = collect_sol_files([self._root])
        self.assertEqual(len(files), 2)
        target, cwd, _note = choose_target(files)
        self.assertTrue(os.path.isabs(target), target)
        self.assertEqual(os.path.realpath(target), os.path.realpath(str(self._root / "src")))
        self.assertEqual(
            os.path.realpath(cwd), os.path.realpath(str(self._root))
        )
        self.assertTrue(os.path.isdir(target))

    def test_relative_input_paths_still_resolve(self) -> None:
        from auditor.analysis.slither_runner import choose_target

        # Simulate CLI-style relative paths.
        old = os.getcwd()
        try:
            os.chdir(self._root)
            target, cwd, _note = choose_target([Path("src/A.sol"), Path("src/B.sol")])
            self.assertTrue(os.path.isabs(target))
            self.assertTrue(os.path.isdir(target))
            self.assertTrue(os.path.isdir(cwd))
            self.assertEqual(os.path.realpath(cwd), os.path.realpath(str(self._root)))
        finally:
            os.chdir(old)

    def test_single_file_target_is_absolute(self) -> None:
        from auditor.analysis.slither_runner import choose_target

        solo = self._root / "src" / "A.sol"
        target, cwd, _note = choose_target([solo])
        self.assertTrue(os.path.isabs(target))
        self.assertEqual(os.path.realpath(target), os.path.realpath(str(solo)))
        self.assertEqual(os.path.realpath(cwd), os.path.realpath(str(solo.parent)))
