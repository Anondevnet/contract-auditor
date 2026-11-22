"""Phase 8: auditor security regressions.

Guards for the API-key handling fix: Etherscan error bodies can echo
the request URI (which carries ``apikey=``); neither the dashboard job
path nor the CLI path may ever place the raw key into job records,
stderr, or logs.
"""
from __future__ import annotations

import io
import os
import unittest
import urllib.error
from unittest import mock


class TestApiKeyRedaction(unittest.TestCase):
    KEY = "SECRETKEY123DO_NOT_LEAK"

    def setUp(self) -> None:
        self._saved = os.environ.get("ETHERSCAN_API_KEY")
        os.environ["ETHERSCAN_API_KEY"] = self.KEY

    def tearDown(self) -> None:
        if self._saved is None:
            os.environ.pop("ETHERSCAN_API_KEY", None)
        else:
            os.environ["ETHERSCAN_API_KEY"] = self._saved

    def _http_error_echoing_key(self) -> urllib.error.HTTPError:
        body = f"Internal error while serving /v2/api?apikey={self.KEY}&chainid=1".encode()
        return urllib.error.HTTPError(
            "https://api.etherscan.io/v2/api",
            500,
            "Internal Server Error",
            {},
            io.BytesIO(body),
        )

    def test_dashboard_address_scan_redacts_key_from_http_error(self) -> None:
        from auditor.dashboard.jobs import JobManager, ScanJob

        manager = JobManager()
        job = ScanJob(
            job_id="p8-redact",
            scan_type="address",
            address="0x" + "1" * 40,
            network="ethereum",
        )
        with mock.patch(
            "urllib.request.urlopen",
            side_effect=self._http_error_echoing_key(),
        ):
            with self.assertRaises(RuntimeError) as ctx:
                manager._run_address_scan_direct(job)
        message = str(ctx.exception)
        self.assertNotIn(self.KEY, message)
        self.assertIn("***", message)

    def test_dashboard_address_scan_redacts_key_from_url_error(self) -> None:
        from auditor.dashboard.jobs import JobManager, ScanJob

        manager = JobManager()
        job = ScanJob(
            job_id="p8-redact-url",
            scan_type="address",
            address="0x" + "2" * 40,
            network="ethereum",
        )
        with mock.patch(
            "urllib.request.urlopen",
            side_effect=urllib.error.URLError(
                f"timed out while fetching ?apikey={self.KEY}"
            ),
        ):
            with self.assertRaises(RuntimeError) as ctx:
                manager._run_address_scan_direct(job)
        message = str(ctx.exception)
        self.assertNotIn(self.KEY, message)
        self.assertIn("***", message)

    def test_cli_scan_address_redacts_key_from_http_error(self) -> None:
        import contextlib
        import io as _io

        from auditor import cli

        stderr = _io.StringIO()
        with mock.patch.object(
            cli,
            "validate_address",
            return_value=type("V", (), {"normalized": "0x" + "3" * 40})(),
        ):
            with mock.patch(
                "urllib.request.urlopen",
                side_effect=self._http_error_echoing_key(),
            ):
                with contextlib.redirect_stderr(stderr):
                    rc = cli._cmd_scan_address(
                        mock.Mock(address="0x" + "3" * 40, network="ethereum", fail_on=None),
                        mock.Mock(),
                    )
        self.assertNotEqual(rc, 0)
        output = stderr.getvalue()
        self.assertNotIn(self.KEY, output)
        self.assertIn("***", output)


if __name__ == "__main__":
    unittest.main()
