"""Phase 9: DB reliability regressions.

A truncated or corrupt JSON column (disk-full, interrupted write,
manual edit) must degrade to a default — never crash history reads
that feed the dashboard and CLI.
"""
from __future__ import annotations

import os
import sqlite3
import tempfile
import unittest
from pathlib import Path

from auditor.scan_history import ScanHistory


class TestCorruptRowResilience(unittest.TestCase):
    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory(prefix="p9-db-")
        self._saved = os.environ.get("AUDITOR_HISTORY_DB")
        self._db = Path(self._tmpdir.name) / "history.db"
        os.environ["AUDITOR_HISTORY_DB"] = str(self._db)
        self.history = ScanHistory(self._db)

    def tearDown(self) -> None:
        self.history.close()
        if self._saved is None:
            os.environ.pop("AUDITOR_HISTORY_DB", None)
        else:
            os.environ["AUDITOR_HISTORY_DB"] = self._saved
        self._tmpdir.cleanup()

    def _record_one(self, scan_id: str, path: str, status: str) -> None:
        self.history.conn.execute(
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
                path,
                "hash-" + scan_id,
                "fp",
                status,
                '["corrupt',  # truncated JSON
                '{"broken": ',
                None,
                "{not json",
            ),
        )
        self.history.conn.commit()

    def test_get_scan_survives_corrupt_json(self) -> None:
        self._record_one("s-corrupt", "/tmp/a.sol", "completed")
        record = self.history.get_scan("s-corrupt")
        self.assertIsNotNone(record)
        self.assertEqual(record["scan_id"], "s-corrupt")
        self.assertEqual(record["finding_fingerprints"], [])
        self.assertEqual(record["finding_details"], {})
        self.assertIsNone(record["graph_snapshot"])
        self.assertIsNone(record["execution"])

    def test_get_last_scan_survives_corrupt_json(self) -> None:
        self._record_one("s-last", "/tmp/b.sol", "completed")
        record = self.history.get_last_scan(Path("/tmp/b.sol"))
        self.assertIsNotNone(record)
        self.assertEqual(record["scan_id"], "s-last")
        self.assertEqual(record["finding_fingerprints"], [])
        self.assertEqual(record["finding_details"], {})

    def test_get_failed_scans_survives_corrupt_json(self) -> None:
        self._record_one("s-fail", "/tmp/c.sol", "failed")
        records = self.history.get_failed_scans()
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["scan_id"], "s-fail")
        self.assertEqual(records[0]["finding_fingerprints"], [])

    def test_get_findings_on_corrupt_details_returns_empty(self) -> None:
        self._record_one("s-find", "/tmp/d.sol", "completed")
        self.assertEqual(self.history.get_findings("s-find"), [])

    def test_empty_string_json_columns_default_cleanly(self) -> None:
        # Empty strings can appear via legacy rows or manual edits; the
        # schema forbids NULL, so "" is the realistic degraded state.
        self.history.conn.execute(
            """
            INSERT INTO scan_records (
                scan_id, timestamp, source_path, content_hash,
                config_fingerprint, status, finding_fingerprints,
                finding_details, error_info, graph_snapshot
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            ("s-null", "2026-01-01T00:00:00+00:00", "/tmp/e.sol", "h", "fp", "completed", "", "", None, ""),
        )
        self.history.conn.commit()
        record = self.history.get_scan("s-null")
        self.assertIsNotNone(record)
        self.assertEqual(record["finding_fingerprints"], [])
        self.assertEqual(record["finding_details"], {})
        self.assertIsNone(record["graph_snapshot"])


if __name__ == "__main__":
    unittest.main()
