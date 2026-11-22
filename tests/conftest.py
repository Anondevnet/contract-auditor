"""Session fixtures for the auditor test suite.

Relaxes the disk-pressure hysteresis when the volume already has enough
free space, and keeps the suite in local mode unless a test opts into
public mode. Unittest suites picked up by pytest also see this module.
"""

from __future__ import annotations

import os
from pathlib import Path

# Must be set before auditor.disk_pressure.get_controller() is first called.
os.environ.setdefault("AUDITOR_DISK_PRESSURE_RELAX", "1")
os.environ.setdefault("AUDITOR_MODE", "local")

import pytest

from auditor.disk_pressure import reset_controller_for_tests


@pytest.fixture(scope="session", autouse=True)
def _isolate_disk_pressure_state(tmp_path_factory):
    root = tmp_path_factory.mktemp("disk-pressure")
    os.environ["AUDITOR_DISK_STATE_PATH"] = str(root / "state.json")
    os.environ["AUDITOR_DISK_LOG_PATH"] = str(root / "disk.log")
    os.environ["AUDITOR_DISK_PRESSURE_RELAX"] = "1"
    reset_controller_for_tests(None)
    yield
    reset_controller_for_tests(None)
