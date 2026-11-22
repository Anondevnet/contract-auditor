"""Phase 12: performance regressions.

* ``collect_sol_files`` prunes vendor/build-output directories so a
  project scan never drags hundreds of vendored contracts into the
  analyzer's evidence set — but an explicit path into a pruned
  directory still works.
* ``list_findings`` builds the (scan_id, fingerprint) review map in a
  single query instead of one query per completed scan (N+1).
"""
from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from auditor.analysis.slither_runner import collect_sol_files


class TestCollectSolFilesPruning(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="p12-walk-")
        self.root = Path(self._tmp.name)
        (self.root / "src").mkdir()
        (self.root / "src" / "Vault.sol").write_text("// first-party", encoding="utf-8")
        for junk in ("node_modules", "out", "cache", "artifacts", "broadcasts", "vendor", "dependencies"):
            d = self.root / junk / "dep"
            d.mkdir(parents=True)
            (d / "Dep.sol").write_text("// vendored", encoding="utf-8")
        # lib/ is deliberately NOT pruned.
        (self.root / "lib" / "oz").mkdir(parents=True)
        (self.root / "lib" / "oz" / "Token.sol").write_text("// lib", encoding="utf-8")

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_prunes_vendor_and_build_dirs(self) -> None:
        files = collect_sol_files([self.root])
        names = {f.name for f in files}
        self.assertIn("Vault.sol", names)
        self.assertIn("Token.sol", names)  # lib kept
        self.assertNotIn("Dep.sol", names)

    def test_explicit_path_into_pruned_dir_still_works(self) -> None:
        files = collect_sol_files([self.root / "node_modules" / "dep"])
        self.assertEqual([f.name for f in files], ["Dep.sol"])

    def test_single_file_unchanged(self) -> None:
        files = collect_sol_files([self.root / "src" / "Vault.sol"])
        self.assertEqual([f.name for f in files], ["Vault.sol"])


class TestListFindingsSingleQuery(unittest.TestCase):
    def test_cross_scan_fingerprint_does_not_leak(self) -> None:
        """Same fingerprint in two scans keeps reviews separate (N+1 fix
        must not resurrect the old fingerprint-only keying bug)."""
        import json
        import os as _os

        from auditor.finding_store import list_findings, open_store, set_state
        from auditor.scan_history import ScanHistory

        with tempfile.TemporaryDirectory(prefix="p12-rev-") as tmp:
            db = Path(tmp) / "history.db"
            # ScanHistory creates the scan_records table.
            ScanHistory(db).close()
            conn = open_store(db)
            try:
                for scan_id in ("scan-a", "scan-b"):
                    conn.execute(
                        """
                        INSERT INTO scan_records (
                            scan_id, timestamp, source_path, content_hash,
                            config_fingerprint, status, finding_fingerprints,
                            finding_details, error_info, graph_snapshot
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            scan_id,
                            "2026-01-01T00:00:00+00:00",
                            f"/tmp/{scan_id}.sol",
                            "h",
                            "fp",
                            "completed",
                            json.dumps(["fp-shared"]),
                            json.dumps([{"fingerprint": "fp-shared", "title": "T", "severity": "LOW"}]),
                            None,
                            None,
                        ),
                    )
                ok, msg = set_state(conn, "scan-a", "fp-shared", "Needs Review", note="a only")
                self.assertTrue(ok, msg)
                conn.commit()
                out = list_findings(conn)
                rows = {(r["scan_id"], r["state"]) for r in out["findings"]}
                self.assertIn(("scan-a", "Needs Review"), rows)
                self.assertIn(("scan-b", "New"), rows)
            finally:
                conn.close()


if __name__ == "__main__":
    unittest.main()
