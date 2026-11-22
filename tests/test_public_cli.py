"""Public mode refuses live/local-path CLI commands."""

from __future__ import annotations

import os
import unittest
from unittest import mock

from auditor.cli import EXIT_ERROR, main
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
