"""Phase 16 — ERC-4626 inflation detector hardening + benchmark channel.

Covers: comment/string blanking, per-contract scoping and attribution,
mulDiv spelling, the ``Source detector:`` slug channel (PROTOCOL.md §10),
reconciliation exclusion of source-analysis findings, and the VAULT-001/002
manifest entries. No test invokes the real Slither or the network; every
file lives under a temporary directory.
"""
from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from auditor.analysis.base import AnalysisContext  # noqa: E402
from auditor.analysis.erc4626_inflation import (  # noqa: E402
    SLUG,
    analyze,
    strip_comments_and_strings,
)
from auditor.benchmark import (  # noqa: E402
    CATEGORIES,
    classify_finding,
    extract_slugs,
    load_manifest,
    reconcile_raw,
    validate_manifest,
)

FIXTURES = PROJECT_ROOT / "benchmarks" / "fixtures"

_NAIVE = """
pragma solidity ^0.8.0;
contract Vault {
    function totalSupply() public view returns (uint256) { return 0; }
    function totalAssets() public view returns (uint256) { return address(this).balance; }
    function convertToShares(uint256 assets) public view returns (uint256) {
        uint256 supply = totalSupply();
        return supply == 0 ? assets : assets * supply / totalAssets();
    }
    function deposit(uint256 assets) external { convertToShares(assets); }
}
"""


def _run(source: str, name: str = "V.sol"):
    with tempfile.TemporaryDirectory(prefix="p16-vault-") as tmp:
        p = Path(tmp) / name
        p.write_text(source, encoding="utf-8")
        ctx = AnalysisContext()
        ctx.source_files = [p]
        return analyze(ctx)


class StripTests(unittest.TestCase):
    def test_offsets_and_newlines_preserved(self):
        src = 'a // x\n/* y\n z */ b "c//d" \'e\'\n'
        out = strip_comments_and_strings(src)
        self.assertEqual(len(out), len(src))
        self.assertEqual(out.count("\n"), src.count("\n"))
        self.assertNotIn("x", out)
        self.assertNotIn("y", out)
        self.assertNotIn("c//d", out)
        self.assertIn("b", out)

    def test_unterminated_block_comment_is_blanked(self):
        out = strip_comments_and_strings("a /* never closed\nfoo")
        self.assertNotIn("foo", out)


class DetectorTests(unittest.TestCase):
    def test_attribution_contract_function_and_line(self):
        out = _run(_NAIVE)
        self.assertEqual(len(out.findings), 1)
        f = out.findings[0]
        self.assertEqual(f.affected_contract, "Vault")
        self.assertEqual(f.affected_function, "convertToShares")
        self.assertEqual(f.affected_lines, [8])  # _NAIVE starts with a newline
        self.assertEqual(f.verification_status.value, "UNVERIFIED")
        self.assertIn(f"Source detector: {SLUG}.", f.description)

    def test_comment_mentioning_offset_no_longer_suppresses(self):
        out = _run("// TODO: add _decimalsOffset like OZ\n" + _NAIVE)
        self.assertEqual(len(out.findings), 1)

    def test_commented_out_ratio_is_not_flagged(self):
        src = _NAIVE.replace(
            "return supply == 0 ? assets : assets * supply / totalAssets();",
            "// return assets * supply / totalAssets();\n        return assets;",
        )
        self.assertEqual(_run(src).findings, [])

    def test_mitigation_in_other_contract_does_not_suppress(self):
        other = "contract Helper { uint256 constant decimalsOffset = 3; }\n"
        out = _run(_NAIVE + other)
        self.assertEqual([f.affected_contract for f in out.findings], ["Vault"])

    def test_one_finding_per_vulnerable_contract(self):
        second = _NAIVE.replace("contract Vault", "contract VaultTwo").replace(
            "pragma solidity ^0.8.0;", "")
        out = _run(_NAIVE + second)
        self.assertEqual(
            sorted(f.affected_contract for f in out.findings), ["Vault", "VaultTwo"]
        )

    def test_muldiv_spelling_is_flagged(self):
        src = _NAIVE.replace(
            "assets * supply / totalAssets()",
            "assets.mulDiv(totalSupply(), totalAssets())",
        )
        out = _run(src)
        self.assertEqual(len(out.findings), 1)
        self.assertIn("mulDiv", out.findings[0].evidence[0].excerpt)

    def test_ratio_without_entry_or_zero_branch_is_ignored(self):
        src = """
contract Price {
    function totalSupply() public view returns (uint256) { return 1; }
    function totalAssets() public view returns (uint256) { return 1; }
    function pps(uint256 assets) public view returns (uint256) {
        return assets * totalSupply() / totalAssets();
    }
}
"""
        self.assertEqual(_run(src).findings, [])


class BenchmarkChannelTests(unittest.TestCase):
    def test_slug_extracted_from_source_detector_note(self):
        f = _run(_NAIVE).findings[0]
        self.assertEqual(extract_slugs(f), [SLUG])

    def test_classify_matches_vault_fixture(self):
        f = _run(_NAIVE).findings[0]
        fixture = {
            "accepted_checks": [SLUG], "analyzer_family": "generic",
            "expected_contract": "Vault", "expected_function": "convertToShares",
        }
        cls = classify_finding(f, fixture)
        self.assertTrue(cls["matched"], cls)

    def test_source_findings_excluded_from_reconciliation(self):
        f = _run(_NAIVE).findings[0]
        rec = reconcile_raw({}, None, [f])
        self.assertNotIn(SLUG, rec.get("surfaced_without_raw", []))

    def test_manifest_v3_vault_fixtures(self):
        manifest = load_manifest()
        fixtures = {f["fixture_id"]: f for f in validate_manifest(manifest)}
        self.assertGreaterEqual(manifest["schema_version"], 3)  # v4 since Phase 19
        self.assertIn("erc4626_inflation", CATEGORIES)
        for fid, label in (("VAULT-001", "vulnerable"), ("VAULT-002", "safe")):
            fx = fixtures[fid]
            self.assertEqual(fx["expected_label"], label)
            self.assertEqual(fx["accepted_checks"], [SLUG])
            self.assertTrue((FIXTURES / fx["file"]).is_file())

    def test_detector_on_real_fixtures(self):
        def run(name):
            ctx = AnalysisContext()
            ctx.source_files = [FIXTURES / name]
            return analyze(ctx).findings
        vuln = run("VAULT-001-vulnerable.sol")
        self.assertEqual(
            [(f.affected_contract, f.affected_function) for f in vuln],
            [("NaiveVault", "convertToShares")],
        )
        self.assertEqual(run("VAULT-002-safe.sol"), [])


if __name__ == "__main__":
    unittest.main()
