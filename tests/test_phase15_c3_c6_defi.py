"""Phase 15 DeFi-readiness — C3–C6.

C3: standard scan scope prunes dependency/test/mock trees while keeping
    ``lib/`` production implementations; ``--scope all`` is the legacy walk.
C4: oracle staleness — unchecked ``latestRoundData``/``latestAnswer`` is a
    source-pattern hypothesis with explicit false-positive limitations.
C5: ERC-4626 first-depositor / share-price inflation — naive
    totalSupply/totalAssets ratio without a virtual offset is flagged as a
    hypothesis.
C6: pool accounting — ``balanceOf(address(this))`` in mint/swap/sync without
    a k-invariant hint is flagged as a hypothesis.

Isolation: every database is created under a temporary directory. No test
invokes the real Slither or the network.
"""
from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from auditor.analysis.slither_runner import collect_sol_files  # noqa: E402
from auditor.analysis.oracle_staleness import analyze as oracle_analyze  # noqa: E402
from auditor.analysis.erc4626_inflation import analyze as erc4626_analyze  # noqa: E402
from auditor.analysis.pool_accounting import analyze as pool_analyze  # noqa: E402
from auditor.analysis.base import AnalysisContext  # noqa: E402
from auditor.scan_evidence import config_fingerprint  # noqa: E402
from auditor.model import Finding  # noqa: E402


class ScopePruningTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="c3-scope-")
        self.root = Path(self._tmp.name)
        (self.root / "src").mkdir()
        (self.root / "src" / "Vault.sol").write_text("// first-party", encoding="utf-8")
        for junk in (
            "node_modules",
            "out",
            "cache",
            "artifacts",
            "broadcasts",
            "vendor",
            "dependencies",
            "test",
            "tests",
            "mocks",
            "script",
            "scripts",
        ):
            d = self.root / junk / "sub"
            d.mkdir(parents=True)
            (d / "Junk.sol").write_text("// junk", encoding="utf-8")
        (self.root / "lib" / "oz").mkdir(parents=True)
        (self.root / "lib" / "oz" / "Token.sol").write_text("// lib", encoding="utf-8")

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_standard_prunes_test_and_mocks_but_keeps_lib(self) -> None:
        files = collect_sol_files([self.root], scope="standard")
        names = {f.name for f in files}
        self.assertIn("Vault.sol", names)
        self.assertIn("Token.sol", names, "lib/ production code must be kept")
        self.assertNotIn("Junk.sol", names)

    def test_all_is_the_legacy_walk_and_keeps_test_trees(self) -> None:
        files = collect_sol_files([self.root], scope="all")
        names = {f.name for f in files}
        self.assertIn("Vault.sol", names)
        self.assertIn("Token.sol", names)
        self.assertIn("Junk.sol", names, "scope=all must keep test/mock trees")

    def test_explicit_path_into_pruned_dir_still_works(self) -> None:
        files = collect_sol_files([self.root / "test" / "sub"], scope="standard")
        self.assertEqual([f.name for f in files], ["Junk.sol"])

    def test_unknown_scope_treated_as_standard(self) -> None:
        files = collect_sol_files([self.root], scope="bogus")
        names = {f.name for f in files}
        self.assertIn("Vault.sol", names)
        self.assertNotIn("Junk.sol", names)

    def test_single_file_unchanged(self) -> None:
        files = collect_sol_files([self.root / "src" / "Vault.sol"], scope="standard")
        self.assertEqual([f.name for f in files], ["Vault.sol"])

    def test_scope_all_changes_the_fingerprint(self) -> None:
        base = config_fingerprint(
            analyzer_keys=("a",), fail_on=None,
            auditor_version="0.0.0-test", schema_version=1,
        )
        all_fp = config_fingerprint(
            analyzer_keys=("a",), fail_on=None,
            auditor_version="0.0.0-test", schema_version=1, scope="all",
        )
        self.assertNotEqual(base, all_fp)
        # standard/None are omitted — byte-identical to pre-C3.
        std_fp = config_fingerprint(
            analyzer_keys=("a",), fail_on=None,
            auditor_version="0.0.0-test", schema_version=1, scope="standard",
        )
        none_fp = config_fingerprint(
            analyzer_keys=("a",), fail_on=None,
            auditor_version="0.0.0-test", schema_version=1, scope=None,
        )
        self.assertEqual(base, std_fp)
        self.assertEqual(base, none_fp)


# ---------------------------------------------------------------------------
# C4 oracle staleness
# ---------------------------------------------------------------------------

_VULN_ORACLE = """
pragma solidity ^0.8.0;
interface Aggregator {
    function latestRoundData()
        external
        view
        returns (uint80, int256, uint256, uint256, uint80);
}
contract Stale {
    Aggregator public feed;
    function price() external view returns (int256) {
        (, int256 p,,,) = feed.latestRoundData();
        return p;
    }
}
"""

_SAFE_ORACLE = """
pragma solidity ^0.8.0;
interface Aggregator {
    function latestRoundData()
        external
        view
        returns (uint80, int256, uint256, uint256, uint80);
}
contract Fresh {
    Aggregator public feed;
    function price() external view returns (int256) {
        (, int256 p,, uint256 updatedAt,) = feed.latestRoundData();
        require(updatedAt >= block.timestamp - 1 hours, "stale");
        return p;
    }
}
"""


class OracleStalenessTests(unittest.TestCase):
    def _run(self, source: str):
        with tempfile.TemporaryDirectory(prefix="c4-oracle-") as tmp:
            p = Path(tmp) / "O.sol"
            p.write_text(source, encoding="utf-8")
            ctx = AnalysisContext()
            ctx.source_files = [p]
            return oracle_analyze(ctx)

    def test_unchecked_latest_round_data_is_flagged(self) -> None:
        outcome = self._run(_VULN_ORACLE)
        self.assertTrue(outcome.findings)
        f = outcome.findings[0]
        self.assertIn("stale-oracle", f.title)
        self.assertEqual(f.verification_status.value, "UNVERIFIED")
        self.assertIn("false_positive_risk", dir(f) or [])
        self.assertTrue(f.false_positive_risk)
        self.assertIn("modifier", f.false_positive_risk.lower())
        self.assertTrue(f.fact_evidence)

    def test_freshness_check_suppresses_the_finding(self) -> None:
        outcome = self._run(_SAFE_ORACLE)
        self.assertEqual(outcome.findings, [])

    def test_unattributed_call_is_not_a_finding(self) -> None:
        source = "pragma solidity ^0.8.0;\ncontract X {}\n"
        outcome = self._run(source)
        self.assertEqual(outcome.findings, [])

    def test_comment_mentioning_freshness_does_not_suppress(self) -> None:
        # A comment that merely says "stale"/"heartbeat" must not act as a
        # freshness check (same blanking class Phase 16 fixed for C5).
        source = _VULN_ORACLE.replace(
            "        return p;",
            "        // guard against stale heartbeat here\n        return p;",
        )
        outcome = self._run(source)
        self.assertTrue(outcome.findings)

    def test_commented_out_freshness_check_does_not_suppress(self) -> None:
        # require(...) only inside a comment is not a check.
        source = _VULN_ORACLE.replace(
            "        return p;",
            '        // require(updatedAt >= block.timestamp - 1 hours, "stale");\n        return p;',
        )
        outcome = self._run(source)
        self.assertTrue(outcome.findings)


# ---------------------------------------------------------------------------
# C5 ERC-4626 inflation
# ---------------------------------------------------------------------------

_VULN_VAULT = """
pragma solidity ^0.8.0;
contract Vault {
    uint256 public totalSupply;
    function totalAssets() public view returns (uint256) {
        return address(this).balance;
    }
    function convertToShares(uint256 assets) public view returns (uint256) {
        uint256 supply = totalSupply();
        return supply == 0 ? assets : assets * supply / totalAssets();
    }
    function deposit(uint256 assets) external {
        uint256 shares = convertToShares(assets);
        totalSupply += shares;
    }
}
"""

_SAFE_VAULT = """
pragma solidity ^0.8.0;
contract Vault {
    uint256 public totalSupply;
    uint256 internal constant _DECIMALS_OFFSET = 3;
    function totalAssets() public view returns (uint256) {
        return address(this).balance;
    }
    function convertToShares(uint256 assets) public view returns (uint256) {
        uint256 supply = totalSupply();
        return assets * (supply + 10 ** _DECIMALS_OFFSET) / (totalAssets() + 1);
    }
    function deposit(uint256 assets) external {
        uint256 shares = convertToShares(assets);
        totalSupply += shares;
    }
}
"""


class Erc4626InflationTests(unittest.TestCase):
    def _run(self, source: str):
        with tempfile.TemporaryDirectory(prefix="c5-vault-") as tmp:
            p = Path(tmp) / "V.sol"
            p.write_text(source, encoding="utf-8")
            ctx = AnalysisContext()
            ctx.source_files = [p]
            return erc4626_analyze(ctx)

    def test_naive_ratio_is_flagged(self) -> None:
        outcome = self._run(_VULN_VAULT)
        self.assertTrue(outcome.findings)
        f = outcome.findings[0]
        self.assertIn("ERC-4626", f.title)
        self.assertEqual(f.verification_status.value, "UNVERIFIED")
        self.assertTrue(f.false_positive_risk)
        self.assertIn("virtual", f.false_positive_risk.lower())
        self.assertTrue(f.fact_evidence)

    def test_virtual_offset_suppresses_the_finding(self) -> None:
        outcome = self._run(_SAFE_VAULT)
        self.assertEqual(outcome.findings, [])

    def test_non_vault_source_is_ignored(self) -> None:
        outcome = self._run("pragma solidity ^0.8.0;\ncontract A {}\n")
        self.assertEqual(outcome.findings, [])


# ---------------------------------------------------------------------------
# C6 pool accounting
# ---------------------------------------------------------------------------

_VULN_POOL = """
pragma solidity ^0.8.0;
contract Pool {
    function mint(address to) external {
        uint256 amount = token.balanceOf(address(this));
        _credit(to, amount);
    }
    function _credit(address to, uint256 a) internal {}
    IERC20 public token;
}
interface IERC20 {
    function balanceOf(address) external view returns (uint256);
}
"""

_SAFE_POOL = """
pragma solidity ^0.8.0;
contract Pool {
    IERC20 public token;
    function mint(uint256 amount, address to) external {
        require(amount > 0, "zero");
        uint256 bal = token.balanceOf(address(this));
        require(bal >= amount, "short");
        _credit(to, amount);
    }
    function _credit(address to, uint256 a) internal {}
}
interface IERC20 {
    function balanceOf(address) external view returns (uint256);
}
"""


class PoolAccountingTests(unittest.TestCase):
    def _run(self, source: str):
        with tempfile.TemporaryDirectory(prefix="c6-pool-") as tmp:
            p = Path(tmp) / "P.sol"
            p.write_text(source, encoding="utf-8")
            ctx = AnalysisContext()
            ctx.source_files = [p]
            return pool_analyze(ctx)

    def test_balance_of_this_without_k_hint_is_flagged(self) -> None:
        outcome = self._run(_VULN_POOL)
        self.assertTrue(outcome.findings)
        f = outcome.findings[0]
        self.assertIn("pool-accounting", f.title)
        self.assertIn("mint", f.affected_function or "")
        self.assertEqual(f.verification_status.value, "UNVERIFIED")
        self.assertTrue(f.false_positive_risk)
        self.assertIn("router", f.false_positive_risk.lower())
        self.assertTrue(f.fact_evidence)

    def test_expected_amount_require_suppresses_the_finding(self) -> None:
        # The safe pool reads balanceOf(this) but pairs it with require
        # guards and an explicit amount parameter — a k-hint suppresses.
        outcome = self._run(_SAFE_POOL)
        self.assertEqual(outcome.findings, [])

    def test_non_pool_source_is_ignored(self) -> None:
        outcome = self._run("pragma solidity ^0.8.0;\ncontract A {}\n")
        self.assertEqual(outcome.findings, [])

    def test_comment_mentioning_require_does_not_suppress(self) -> None:
        # Demonstrated gap: a fixture comment containing "require" once
        # suppressed a finding; blanking (Phase 16 class) fixes it for C6.
        source = _VULN_POOL.replace(
            "        _credit(to, amount);",
            "        // require(bal >= amount);\n        _credit(to, amount);",
        )
        outcome = self._run(source)
        self.assertTrue(outcome.findings)


# ---------------------------------------------------------------------------
# Finding guardrails shared by C4–C6
# ---------------------------------------------------------------------------


class FindingGuardrailTests(unittest.TestCase):
    def test_new_findings_validate_without_fact_requirement(self) -> None:
        # UNVERIFIED does not require FACT, but our analyzers still attach one.
        for source, analyze in (
            (_VULN_ORACLE, oracle_analyze),
            (_VULN_VAULT, erc4626_analyze),
            (_VULN_POOL, pool_analyze),
        ):
            with self.subTest(tool=analyze.__module__):
                with tempfile.TemporaryDirectory(prefix="c-guard-") as tmp:
                    p = Path(tmp) / "G.sol"
                    p.write_text(source, encoding="utf-8")
                    ctx = AnalysisContext()
                    ctx.source_files = [p]
                    outcome = analyze(ctx)
                self.assertTrue(outcome.findings)
                for f in outcome.findings:
                    self.assertIsInstance(f, Finding)
                    f.validate()
                    self.assertFalse(f.affected_lines and any(
                        ln < 1 for ln in f.affected_lines
                    ))


if __name__ == "__main__":
    unittest.main()
