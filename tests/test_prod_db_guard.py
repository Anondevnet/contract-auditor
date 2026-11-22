import sqlite3, sys, tempfile, unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
from _prod_db_guard import ProdDBWriteGuard  # noqa: E402


class ProdGuardTests(unittest.TestCase):
    def test_detects_in_process_write_open_and_ignores_others(self):
        with tempfile.TemporaryDirectory() as td:
            prod = Path(td) / "prod.db"; sqlite3.connect(prod).close()
            other = Path(td) / "other.db"
            g = ProdDBWriteGuard(prod).start()
            sqlite3.connect(other).close()
            sqlite3.connect(f"file:{prod}?mode=ro", uri=True).close()
            self.assertEqual(g.hits, [])
            sqlite3.connect(str(prod)).close()
            self.assertEqual(len(g.stop()), 1)

    def test_external_writer_does_not_trip_guard(self):
        # Simulates the live monitor writing the prod DB mid-test.
        with tempfile.TemporaryDirectory() as td:
            prod = Path(td) / "prod.db"
            g = ProdDBWriteGuard(prod).start()
            g._real(str(prod)).execute("create table t(x)")  # out-of-band writer
            self.assertEqual(g.stop(), [])
