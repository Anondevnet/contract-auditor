"""Public mode refuses live/local-path CLI commands."""

from __future__ import annotations

import os
import unittest
from unittest import mock

from auditor.cli import EXIT_ERROR, main, resolve_dashboard_port
from auditor.mode import PUBLIC_BLOCKED_COMMANDS


class PublicCliTests(unittest.TestCase):
    def test_blocked_commands_refuse(self) -> None:
        with mock.patch.dict(os.environ, {"AUDITOR_MODE": "public"}):
            calls = {
                "scan": ["scan", "ignored.sol"],
                "scan-address": [
                    "scan-address",
                    "--network", "ethereum",
                    "--address", "0x" + "11" * 20,
                ],
                "hunt": ["hunt", "--once"],
                "monitor": ["monitor", "--once"],
            }
            for cmd, argv in calls.items():
                self.assertIn(cmd, PUBLIC_BLOCKED_COMMANDS)
                code = main(argv)
                self.assertEqual(code, EXIT_ERROR, argv)


class DashboardPortTests(unittest.TestCase):
    def test_explicit_cli_port_wins(self) -> None:
        self.assertEqual(resolve_dashboard_port(9090, {"PORT": "1234"}), 9090)

    def test_env_port_when_cli_absent(self) -> None:
        self.assertEqual(resolve_dashboard_port(None, {"PORT": "3000"}), 3000)

    def test_default_8080(self) -> None:
        self.assertEqual(resolve_dashboard_port(None, {}), 8080)

    def test_invalid_rejected(self) -> None:
        self.assertIsNone(resolve_dashboard_port(None, {"PORT": "not-a-port"}))
        self.assertIsNone(resolve_dashboard_port(0, {}))
        self.assertIsNone(resolve_dashboard_port(70000, {}))
