"""Scanner-brain overview visualization: wiring + offline/honesty guards."""

import re
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_dashboard import DashboardTestCase  # noqa: E402

STATIC = Path(__file__).resolve().parents[1] / "auditor" / "dashboard" / "static"


class TestScanViz(DashboardTestCase):
    def test_overview_has_hook(self) -> None:
        res = self.client.get("/")
        self.assertEqual(res.status_code, 200)
        self.assertIn('id="scanviz"', res.text)
        self.assertIn("/static/js/scanviz.js", res.text)
        self.assertIn("/static/css/scanviz.css", res.text)

    def test_assets_served(self) -> None:
        for path, kind in (("/static/js/scanviz.js", "javascript"), ("/static/css/scanviz.css", "css")):
            res = self.client.get(path)
            self.assertEqual(res.status_code, 200, path)
            self.assertIn(kind, res.headers.get("content-type", ""))

    def test_no_external_network(self) -> None:
        for name in ("js/scanviz.js", "css/scanviz.css"):
            text = (STATIC / name).read_text(encoding="utf-8")
            self.assertIsNone(re.search(r"https?://", text), f"{name} must not load remote resources")

    def test_reads_only_existing_live_apis(self) -> None:
        js = (STATIC / "js" / "scanviz.js").read_text(encoding="utf-8")
        used = set(re.findall(r"getJSON\('(/api/[a-z/]+)", js))
        self.assertTrue(used)
        routes = {getattr(r, "path", "") for r in self.client.app.routes}
        for p in used:
            self.assertTrue(any(r.startswith(p.rstrip("/")) for r in routes), f"unknown API {p}")
        self.assertNotIn("method: 'POST'", js)

    def test_live_stage_names_match_monitor(self) -> None:
        js = (STATIC / "js" / "scanviz.js").read_text(encoding="utf-8")
        mon = (Path(__file__).resolve().parents[1] / "auditor" / "monitor.py").read_text(encoding="utf-8")
        for stage in ("fetching", "compiling", "analyzing"):
            self.assertIn(f"'{stage}'", js)
            self.assertIn(f'"{stage}"', mon)


if __name__ == "__main__":
    unittest.main()
