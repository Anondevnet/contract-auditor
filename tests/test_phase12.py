"""Phase 12 — real tool integration tests.

Covers: single-target Slither execution over multi-file projects, normalized
findings with detector attribution, conservative dedupe, honest handling of
every Slither failure mode (compile failure, CLI usage error — the silent
zero-finding root cause, timeout, not-found), forge build/test validation
gating, tool-selection flags (including back-compat defaults), persisted
tool-execution status surfaced through the API and both exports, secret
redaction, legacy scans without execution records, CLI directory scans over
ALL files, and the tool-status UI elements.

Every subprocess is mocked; the production history database is never written.
"""

from __future__ import annotations

import argparse
import contextlib
import io
import json
import os
import sys
import tempfile
import time
import unittest
import unittest.mock as mock
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from auditor.analysis.slither_runner import ToolRun  # noqa: E402
from auditor.procs import ProcResult  # noqa: E402

SOL_BODY_VAULT = """\
pragma solidity ^0.5.8;

contract Vault {
    mapping(address => uint256) public balances;

    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount);
        (bool ok, ) = msg.sender.call.value(amount)("");
        require(ok);
        balances[msg.sender] -= amount;
    }
}
"""

SOL_BODY_OTHER = """\
pragma solidity ^0.5.8;

contract Other {
    function noop() public {}
}
"""


# ---------------------------------------------------------------------------
# Detector fixtures (shape verified against real Slither --json output)
# ---------------------------------------------------------------------------


def _detector(
    check: str,
    impact: str = "High",
    confidence: str = "Medium",
    contract: str = "Vault",
    fn: str = "withdraw",
    lines: tuple = (6, 9),
    bullets: tuple = (),
) -> dict:
    bullet_lines = ["\t- " + b for b in bullets] or ["\t- example tool output line"]
    description = f"{check} in {contract}.{fn}:\n" + "\n".join(bullet_lines)
    return {
        "check": check,
        "impact": impact,
        "confidence": confidence,
        "description": description,
        "id": check,
        "elements": [
            {
                "type": "function",
                "name": f"{fn}(uint256)",
                "source_mapping": {"lines": list(lines)},
                "type_specific_fields": {
                    "parent": {"type": "contract", "name": contract}
                },
            }
        ],
    }


# ---------------------------------------------------------------------------
# Fake tool environment — records every call, returns configured results
# ---------------------------------------------------------------------------


class FakeTools:
    """Deterministic stand-in for slither/forge subprocess execution."""

    def __init__(
        self,
        *,
        detectors: Optional[List[dict]] = None,
        slither_rc: int = 255,
        slither_stderr: str = "",
        slither_error: Optional[str] = None,
        slither_timed_out: bool = False,
        forge_results: Optional[Dict[str, Any]] = None,
    ) -> None:
        self.detectors = detectors
        self.slither_rc = slither_rc
        self.slither_stderr = slither_stderr
        self.slither_error = slither_error
        self.slither_timed_out = slither_timed_out
        self.forge_results = forge_results or {}
        self.calls: List[dict] = []

    def resolve(self, _names) -> str:
        return "/fake/bin/slither"

    def resolve_forge(self, _names) -> str:
        return "/fake/bin/forge"

    def run(self, argv, timeout: Optional[float] = None, cwd: Optional[str] = None) -> ProcResult:
        argv = [str(a) for a in argv]
        self.calls.append({"argv": list(argv), "cwd": cwd, "timeout": timeout})
        exe = Path(argv[0]).name

        if exe == "slither":
            if self.slither_timed_out:
                return ProcResult(tuple(argv), None, "", "", timed_out=True)
            if self.slither_error is not None:
                return ProcResult(tuple(argv), None, "", "", error=self.slither_error)
            if self.detectors is not None and "--json" in argv:
                report = Path(argv[argv.index("--json") + 1])
                report.write_text(
                    json.dumps(
                        {"success": True, "results": {"detectors": self.detectors}}
                    ),
                    encoding="utf-8",
                )
            return ProcResult(tuple(argv), self.slither_rc, "", self.slither_stderr)

        if exe == "forge":
            sub = argv[1] if len(argv) > 1 else ""
            configured = self.forge_results.get(sub)
            if configured is None:
                return ProcResult(tuple(argv), 0, "forge ok", "")
            if isinstance(configured, ProcResult):
                return configured
            rc, out, err = configured
            return ProcResult(tuple(argv), rc, out, err)

        return ProcResult(tuple(argv), 0, "", "")

    def slither_calls(self) -> List[dict]:
        return [c for c in self.calls if Path(c["argv"][0]).name == "slither"]

    def forge_calls(self) -> List[dict]:
        return [c for c in self.calls if Path(c["argv"][0]).name == "forge"]


def _solc_probe(*_a, **_k) -> ToolRun:
    return ToolRun(
        key="solc",
        label="solc (compiler on PATH)",
        kind="compiler",
        status="completed",
        requested=True,
        returncode=0,
        message="solc 0.5.8 resolved (test probe)",
        version="0.5.8",
    )


@contextlib.contextmanager
def tool_patches(tools: FakeTools, slither_exe: str = "/fake/bin/slither"):
    """Patch every subprocess boundary used by the scan pipeline."""
    with contextlib.ExitStack() as stack:
        stack.enter_context(
            mock.patch(
                "auditor.analysis.slither_runner.resolve_executable",
                return_value=slither_exe,
            )
        )
        stack.enter_context(
            mock.patch(
                "auditor.analysis.slither_runner.run", side_effect=tools.run
            )
        )
        stack.enter_context(
            mock.patch(
                "auditor.analysis.slither_runner.probe_solc",
                side_effect=_solc_probe,
            )
        )
        stack.enter_context(
            mock.patch("auditor.foundry.resolve_executable", return_value="/fake/bin/forge")
        )
        stack.enter_context(mock.patch("auditor.foundry.run", side_effect=tools.run))
        yield tools


# ---------------------------------------------------------------------------
# Shared dashboard test case
# ---------------------------------------------------------------------------


class Phase12DashboardTestCase(unittest.TestCase):
    """Isolated history DB + TestClient, mirroring the dashboard suite."""

    client = None
    _tmpdir = None

    @classmethod
    def setUpClass(cls) -> None:
        from fastapi.testclient import TestClient

        from auditor.dashboard.app import create_app

        cls._tmpdir = tempfile.TemporaryDirectory(prefix="audit-phase12-test-")
        cls._db_path = Path(cls._tmpdir.name) / "history.db"
        os.environ["AUDITOR_HISTORY_DB"] = str(cls._db_path)
        cls.client = TestClient(create_app())
        cls.client.__enter__()

    @classmethod
    def tearDownClass(cls) -> None:
        if cls.client is not None:
            cls.client.__exit__(None, None, None)
        os.environ.pop("AUDITOR_HISTORY_DB", None)
        if cls._tmpdir is not None:
            cls._tmpdir.cleanup()

    def _project(self, extra_files: Optional[Dict[str, str]] = None) -> Path:
        """Two-file Solidity project in a private temp directory."""
        base = Path(tempfile.mkdtemp(prefix="p12-proj-", dir=self._tmpdir.name))
        (base / "Vault.sol").write_text(SOL_BODY_VAULT, encoding="utf-8")
        (base / "Other.sol").write_text(SOL_BODY_OTHER, encoding="utf-8")
        for rel, content in (extra_files or {}).items():
            target = base / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content, encoding="utf-8")
        return base

    def _submit_local(self, path: Path, **flags: Any) -> str:
        local: Dict[str, Any] = {"path": str(path)}
        local.update(flags)
        res = self.client.post("/api/scan", json={"scan_type": "local", "local": local})
        self.assertEqual(res.status_code, 202, res.text)
        return res.json()["job_id"]

    def _wait_for_job(self, job_id: str, timeout: float = 30.0) -> dict:
        deadline = time.time() + timeout
        while time.time() < deadline:
            res = self.client.get(f"/api/jobs/{job_id}")
            self.assertEqual(res.status_code, 200)
            job = res.json()
            if job["status"] in ("completed", "failed", "cancelled"):
                return job
            time.sleep(0.05)
        self.fail(f"job {job_id} did not finish within {timeout}s")

    def _scan_detail(self, scan_id: str) -> dict:
        res = self.client.get(f"/api/scans/{scan_id}")
        self.assertEqual(res.status_code, 200, res.text)
        return res.json()

    @staticmethod
    def _tool(detail: dict, key: str) -> dict:
        for tool in detail.get("tool_runs") or []:
            if tool.get("key") == key:
                return tool
        raise AssertionError(f"tool row {key!r} missing from {detail.get('tool_runs')}")


# ---------------------------------------------------------------------------
# Success path
# ---------------------------------------------------------------------------


class TestSingleInvocationAndFindings(Phase12DashboardTestCase):

    @classmethod
    def setUpClass(cls):
        from auditor.analysis.base import AnalysisOutcome
        super().setUpClass()
        empty = AnalysisOutcome()
        empty.findings, empty.evidence, empty.notes = [], [], []
        cls._pa_patch = mock.patch(
            "auditor.analysis.privileged_auth.analyze",
            return_value=empty,
        )
        cls._pa_patch.start()

    @classmethod
    def tearDownClass(cls):
        cls._pa_patch.stop()
        super().tearDownClass()

    def test_multifile_scan_single_slither_single_target(self) -> None:
        project = self._project()
        detectors = [
            _detector(
                "reentrancy-eth",
                bullets=["call.value(amount)(\"\") before state write"],
            ),
            _detector("tx-origin", lines=(3, 4), bullets=["tx.origin used for auth"]),
            _detector(
                "incorrect-equality",
                impact="Medium",
                fn="checkReady",
                lines=(2, 3),
                bullets=["balance == amount comparison"],
            ),
            _detector(
                "solc-version", impact="Informational", fn="noop", lines=(1, 1)
            ),
        ]
        tools = FakeTools(detectors=detectors)

        with tool_patches(tools):
            job_id = self._submit_local(project)  # back-compat defaults
            job = self._wait_for_job(job_id)

        self.assertEqual(job["status"], "completed", job.get("error"))
        result = job["result"]
        scan_id = result["scan_id"]

        # The original root cause: multiple file paths passed as targets made
        # Slither exit with a usage error that was silently reported as an
        # empty scan. Exactly one invocation, exactly ONE target argument.
        slither_calls = tools.slither_calls()
        self.assertEqual(len(slither_calls), 1, tools.calls)
        argv = slither_calls[0]["argv"]
        self.assertEqual(len(argv), 4, argv)
        self.assertEqual(argv[1], str(project))
        self.assertEqual(argv[2], "--json")
        # cwd is the target's PARENT: running Slither with cwd == the
        # directory target made it resolve the target relative to itself
        # (protocol/contracts/protocol/contracts → "not a file or
        # directory"); found by the Phase 6 real-world corpus scan.
        self.assertEqual(slither_calls[0]["cwd"], str(project.parent))
        # Static-only scan never starts forge.
        self.assertEqual(tools.forge_calls(), [])

        detail = self._scan_detail(scan_id)
        self.assertTrue(detail["scan_complete"])
        self.assertEqual(detail["incomplete_reasons"], [])
        self.assertIsNone(detail["validation"])

        slither_row = self._tool(detail, "slither")
        self.assertEqual(slither_row["status"], "completed")
        self.assertEqual(slither_row["finding_count"], 3)
        self.assertEqual(slither_row["severity_counts"], {"HIGH": 2, "MEDIUM": 1})
        self.assertEqual(
            slither_row["detectors"],
            {"reentrancy-eth": 1, "tx-origin": 1, "incorrect-equality": 1},
        )
        # Informational results are counted, not hidden.
        self.assertEqual(slither_row["excluded_count"], 1)

        self.assertEqual(detail["finding_count"], 3)
        self.assertEqual(
            detail["findings_by_severity"]["HIGH"], 2
        )
        self.assertEqual(detail["findings_by_severity"]["MEDIUM"], 1)
        self.assertIsNone(detail["zero_findings_note"])

        forge_build = self._tool(detail, "forge-build")
        forge_test = self._tool(detail, "forge-test")
        self.assertEqual(forge_build["status"], "not_requested")
        self.assertEqual(forge_test["status"], "not_requested")

        # Per-tool progress stages are exposed while the job runs.
        stage_names = [s["name"] for s in job.get("stages") or []]
        self.assertIn("solc", stage_names)
        self.assertIn("slither", stage_names)

    def test_dedupe_merges_same_location_detectors(self) -> None:
        project = self._project()
        detectors = [
            _detector(
                "reentrancy-eth",
                bullets=["external call then state write"],
            ),
            _detector(
                "reentrancy-no-eth",
                bullets=["transfer-style call then state write"],
            ),
        ]
        tools = FakeTools(detectors=detectors)

        with tool_patches(tools):
            job = self._wait_for_job(self._submit_local(project))

        self.assertEqual(job["status"], "completed", job.get("error"))
        detail = self._scan_detail(job["result"]["scan_id"])

        # Conservative dedupe: one record per location, both detectors kept.
        self.assertEqual(detail["finding_count"], 1)
        slither_row = self._tool(detail, "slither")
        self.assertEqual(slither_row["finding_count"], 1)
        self.assertEqual(
            slither_row["detectors"], {"reentrancy-eth": 1, "reentrancy-no-eth": 1}
        )
        description = detail["findings"][0]["description"]
        self.assertIn("reentrancy-eth", description)
        self.assertIn("reentrancy-no-eth", description)


# ---------------------------------------------------------------------------
# Failure paths — every failure is visible, never a silent zero
# ---------------------------------------------------------------------------


class TestSlitherFailureModes(Phase12DashboardTestCase):

    @classmethod
    def setUpClass(cls):
        from auditor.analysis.base import AnalysisOutcome
        super().setUpClass()
        empty = AnalysisOutcome()
        empty.findings, empty.evidence, empty.notes = [], [], []
        cls._pa_patch = mock.patch(
            "auditor.analysis.privileged_auth.analyze",
            return_value=empty,
        )
        cls._pa_patch.start()

    @classmethod
    def tearDownClass(cls):
        cls._pa_patch.stop()
        super().tearDownClass()

    def test_compile_failure_flags_incomplete_with_honest_zero_note(self) -> None:
        project = self._project()
        tools = FakeTools(
            detectors=None,
            slither_rc=1,
            slither_stderr=(
                "Traceback (most recent call last):\n"
                "Error: InvalidCompilation: out/build-info is not a directory\n"
            ),
        )

        with tool_patches(tools):
            job = self._wait_for_job(self._submit_local(project))

        self.assertEqual(job["status"], "completed", job.get("error"))
        detail = self._scan_detail(job["result"]["scan_id"])

        self.assertEqual(detail["finding_count"], 0)
        self.assertFalse(detail["scan_complete"])
        self.assertTrue(detail["incomplete_reasons"])
        self.assertIn("could not compile", detail["incomplete_reasons"][0])

        slither_row = self._tool(detail, "slither")
        self.assertEqual(slither_row["status"], "failed")
        self.assertIn("could not compile", slither_row["error"])

        note = detail["zero_findings_note"] or ""
        self.assertIn("No findings detected by the checks that completed.", note)
        self.assertIn("not a clean result", note)
        self.assertNotIn("is safe", note.lower())

        # Export shows the failure instead of a silent empty result.
        md = self.client.get(
            f"/api/scans/{detail['scan_id']}/report?format=markdown"
        )
        self.assertEqual(md.status_code, 200)
        self.assertIn("## Tool execution", md.text)
        self.assertIn("**Scan complete:** no", md.text)
        self.assertIn("incomplete:", md.text)

    def test_usage_error_regression_umia_silent_zero(self) -> None:
        """Multi-target CLI usage error must surface as a failed tool."""
        project = self._project()
        tools = FakeTools(
            detectors=None,
            slither_rc=2,
            slither_stderr=(
                "slither: error: unrecognized arguments: A.sol B.sol C.sol\n"
                "usage: slither [OPTIONS] [TARGET]\n"
            ),
        )

        with tool_patches(tools):
            job = self._wait_for_job(self._submit_local(project))

        detail = self._scan_detail(job["result"]["scan_id"])

        # No InvalidCompilation, no traceback — the class that used to be
        # silently swallowed — is now a visible failed tool status.
        slither_row = self._tool(detail, "slither")
        self.assertEqual(slither_row["status"], "failed")
        self.assertIn("usage error", slither_row["error"])
        self.assertFalse(detail["scan_complete"])
        self.assertEqual(detail["finding_count"], 0)
        note = detail["zero_findings_note"] or ""
        self.assertIn("not a clean result", note)

        # And our own invocation still passes a single target.
        argv = tools.slither_calls()[0]["argv"]
        self.assertEqual(len(argv), 4, argv)
        self.assertEqual(argv[1], str(project))

    def test_timeout_flags_incomplete(self) -> None:
        project = self._project()
        tools = FakeTools(detectors=None, slither_timed_out=True)

        with tool_patches(tools):
            job = self._wait_for_job(self._submit_local(project))

        detail = self._scan_detail(job["result"]["scan_id"])
        slither_row = self._tool(detail, "slither")
        self.assertEqual(slither_row["status"], "timeout")
        self.assertFalse(detail["scan_complete"])
        self.assertTrue(
            any("timed out" in reason for reason in detail["incomplete_reasons"])
        )
        self.assertIn("not a clean result", detail["zero_findings_note"] or "")

    def test_slither_missing_flags_incomplete(self) -> None:
        project = self._project()
        tools = FakeTools(detectors=None)

        with tool_patches(tools, slither_exe=None):
            job = self._wait_for_job(self._submit_local(project))

        detail = self._scan_detail(job["result"]["scan_id"])
        slither_row = self._tool(detail, "slither")
        self.assertEqual(slither_row["status"], "not_found")
        self.assertFalse(detail["scan_complete"])
        self.assertTrue(
            any("not found" in reason for reason in detail["incomplete_reasons"])
        )
        self.assertEqual(tools.slither_calls(), [])
        self.assertIn("not a clean result", detail["zero_findings_note"] or "")


# ---------------------------------------------------------------------------
# Foundry validation
# ---------------------------------------------------------------------------


class TestFoundryValidation(Phase12DashboardTestCase):

    @classmethod
    def setUpClass(cls):
        from auditor.analysis.base import AnalysisOutcome
        super().setUpClass()
        empty = AnalysisOutcome()
        empty.findings, empty.evidence, empty.notes = [], [], []
        cls._pa_patch = mock.patch(
            "auditor.analysis.privileged_auth.analyze",
            return_value=empty,
        )
        cls._pa_patch.start()

    @classmethod
    def tearDownClass(cls):
        cls._pa_patch.stop()
        super().tearDownClass()

    def test_static_only_mode_never_starts_forge(self) -> None:
        project = self._project()
        tools = FakeTools(detectors=[])

        with tool_patches(tools):
            # Back-compat payload: no new tool flags at all.
            job = self._wait_for_job(
                self._submit_local(project, validate_project=False)
            )

        detail = self._scan_detail(job["result"]["scan_id"])
        self.assertEqual(tools.forge_calls(), [])
        self.assertIsNone(detail["validation"])
        self.assertTrue(detail["scan_complete"])
        self.assertEqual(detail["finding_count"], 0)
        note = detail["zero_findings_note"] or ""
        self.assertEqual(
            note, "No findings detected by the checks that completed."
        )

    def test_forge_build_failure_marks_scan_incomplete(self) -> None:
        project = self._project({"foundry.toml": "[profile.default]\n"})
        tools = FakeTools(
            detectors=[],
            forge_results={"build": (1, "", "Error: failed to compile: unexpected token")},
        )

        with tool_patches(tools):
            job = self._wait_for_job(
                self._submit_local(project, validate_project=True)
            )

        self.assertEqual(job["status"], "completed", job.get("error"))
        detail = self._scan_detail(job["result"]["scan_id"])

        self.assertEqual(len(tools.forge_calls()), 1)
        self.assertEqual(tools.forge_calls()[0]["argv"][1], "build")

        build = self._tool(detail, "forge-build")
        self.assertEqual(build["status"], "failed")
        self.assertIn("failed to compile", build["error"])
        self.assertIn(
            "not evidence for or against vulnerabilities", build["message"]
        )

        self.assertFalse(detail["scan_complete"])
        self.assertTrue(any("forge" in r.lower() for r in detail["incomplete_reasons"]))
        self.assertIn("not a clean result", detail["zero_findings_note"] or "")
        self.assertEqual(detail["validation"]["forge_build"]["status"], "failed")

    def test_forge_test_success_is_never_security_evidence(self) -> None:
        project = self._project(
            {
                "foundry.toml": "[profile.default]\n",
                "test/Vault.t.sol": "// tests\n",
            }
        )
        tools = FakeTools(detectors=[], forge_results={"test": (0, "2 passing", "")})

        with tool_patches(tools):
            job = self._wait_for_job(
                self._submit_local(
                    project,
                    run_static_analysis=False,
                    run_tests=True,
                )
            )

        self.assertEqual(job["status"], "completed", job.get("error"))
        detail = self._scan_detail(job["result"]["scan_id"])

        # Static analysis deselected → Slither never ran.
        self.assertEqual(tools.slither_calls(), [])
        self.assertEqual(self._tool(detail, "slither")["status"], "not_requested")

        forge_calls = tools.forge_calls()
        self.assertEqual(len(forge_calls), 1)
        self.assertEqual(forge_calls[0]["argv"][1], "test")

        test_row = self._tool(detail, "forge-test")
        self.assertEqual(test_row["status"], "completed")
        self.assertIn(
            "passing tests do not establish the absence", test_row["message"]
        )

        self.assertTrue(detail["scan_complete"])
        self.assertEqual(detail["validation"]["forge_test"]["status"], "completed")
        note = detail["zero_findings_note"] or ""
        self.assertIn("Static analysis was not requested", note)
        self.assertIn("compilation evidence, not security evidence", note)

    def test_validate_without_foundry_toml_skips_honestly(self) -> None:
        project = self._project()  # no foundry.toml
        tools = FakeTools(detectors=[])

        with tool_patches(tools):
            job = self._wait_for_job(
                self._submit_local(project, validate_project=True)
            )

        detail = self._scan_detail(job["result"]["scan_id"])
        self.assertEqual(tools.forge_calls(), [])
        self.assertEqual(self._tool(detail, "forge-build")["status"], "skipped")
        # A visible skip is not a tool failure.
        self.assertTrue(detail["scan_complete"])


# ---------------------------------------------------------------------------
# Tool selection + redaction
# ---------------------------------------------------------------------------


class TestToolSelectionAndRedaction(Phase12DashboardTestCase):
    def test_all_tools_deselected_runs_nothing_honestly(self) -> None:
        project = self._project()
        tools = FakeTools(detectors=[])

        with tool_patches(tools):
            job = self._wait_for_job(
                self._submit_local(
                    project,
                    run_static_analysis=False,
                    validate_project=False,
                    run_tests=False,
                )
            )

        detail = self._scan_detail(job["result"]["scan_id"])
        self.assertEqual(tools.calls, [])  # no subprocess at all
        self.assertEqual(detail["finding_count"], 0)
        self.assertTrue(detail["scan_complete"])
        note = detail["zero_findings_note"] or ""
        self.assertIn("No finding-producing checks were selected", note)
        self.assertEqual(self._tool(detail, "slither")["status"], "not_requested")

    def test_secrets_redacted_from_api_and_exports(self) -> None:
        project = self._project({"foundry.toml": "[profile.default]\n"})
        tools = FakeTools(
            detectors=None,
            slither_rc=1,
            slither_stderr=(
                "Error: ANTHROPIC_API_KEY=sk-AAAABBBBCCCCDDDD "
                "ETHERSCAN_API_KEY=abc123def456\n"
            ),
            forge_results={
                "build": (1, "", "Error: RPC_SECRET=supersecretvalue123\n")
            },
        )

        with tool_patches(tools):
            job = self._wait_for_job(
                self._submit_local(project, validate_project=True)
            )

        self.assertEqual(job["status"], "completed", job.get("error"))
        scan_id = job["result"]["scan_id"]

        detail = self._scan_detail(scan_id)
        # Both requested tools failed and both reasons are redacted.
        self.assertFalse(detail["scan_complete"])
        self.assertEqual(len(detail["incomplete_reasons"]), 2)
        detail_text = json.dumps(detail, default=str)
        self.assertNotIn("sk-AAAABBBBCCCCDDDD", detail_text)
        self.assertNotIn("abc123def456", detail_text)
        self.assertNotIn("supersecretvalue123", detail_text)
        self.assertIn("ANTHROPIC_API_KEY=***", detail_text)
        self.assertIn("ETHERSCAN_API_KEY=***", detail_text)
        self.assertIn("RPC_SECRET=***", detail_text)

        json_export = self.client.get(f"/api/scans/{scan_id}/report?format=json")
        self.assertEqual(json_export.status_code, 200)
        body = json_export.text
        self.assertNotIn("sk-AAAABBBBCCCCDDDD", body)
        self.assertNotIn("abc123def456", body)
        self.assertNotIn("supersecretvalue123", body)
        payload = json_export.json()
        self.assertIn("execution", payload)
        self.assertIsNotNone(payload["execution"])

        md_export = self.client.get(f"/api/scans/{scan_id}/report?format=markdown")
        self.assertEqual(md_export.status_code, 200)
        self.assertNotIn("sk-AAAABBBBCCCCDDDD", md_export.text)
        self.assertNotIn("abc123def456", md_export.text)
        self.assertNotIn("supersecretvalue123", md_export.text)
        self.assertIn("## Tool execution", md_export.text)

    def test_markdown_and_json_exports_include_tool_execution(self) -> None:
        project = self._project()
        detectors = [
            _detector("reentrancy-eth", bullets=["call before write"]),
        ]
        tools = FakeTools(detectors=detectors)

        with tool_patches(tools):
            job = self._wait_for_job(self._submit_local(project))
        scan_id = job["result"]["scan_id"]

        json_export = self.client.get(f"/api/scans/{scan_id}/report?format=json")
        execution = json_export.json()["execution"]
        self.assertIsNotNone(execution)
        keys = [t["key"] for t in execution["tools"]]
        self.assertIn("slither", keys)
        self.assertIn("solc", keys)
        self.assertIn("forge-build", keys)
        self.assertTrue(execution["scan_complete"])

        md = self.client.get(f"/api/scans/{scan_id}/report?format=markdown")
        self.assertIn("## Tool execution", md.text)
        self.assertIn("Slither (static analysis)", md.text)
        self.assertIn("**Scan complete:** yes", md.text)


# ---------------------------------------------------------------------------
# Legacy scans + UI
# ---------------------------------------------------------------------------


class TestLegacyAndUI(Phase12DashboardTestCase):
    def _legacy_scan(self) -> str:
        from auditor.scan_history import ScanHistory
        from auditor.dashboard.paths import history_db_path

        fixture = Path(self._tmpdir.name) / "Legacy.sol"
        fixture.write_text("// legacy fixture\n", encoding="utf-8")
        history = ScanHistory(history_db_path())
        try:
            scan_id = history.record_scan(
                source_path=fixture,
                config_fingerprint="legacy",
                findings=[],
            )
            history.mark_completed(scan_id, [])
            # No set_execution — recorded before tool-status tracking.
        finally:
            history.close()
        return scan_id

    def test_legacy_scan_reports_not_recorded(self) -> None:
        scan_id = self._legacy_scan()

        detail = self._scan_detail(scan_id)
        self.assertEqual(detail["tool_runs"], [])
        self.assertIsNone(detail["scan_complete"])
        self.assertIsNone(detail["validation"])
        self.assertIsNone(detail["zero_findings_note"])

        md = self.client.get(f"/api/scans/{scan_id}/report?format=markdown")
        self.assertEqual(md.status_code, 200)
        self.assertIn(
            "Tool execution status was not recorded for this scan.", md.text
        )

        page = self.client.get(f"/scan/{scan_id}")
        self.assertEqual(page.status_code, 200)
        self.assertIn("id=\"tool-status-body\"", page.text)

    def test_scan_pages_render_tool_controls(self) -> None:
        new_scan = self.client.get("/scan")
        self.assertEqual(new_scan.status_code, 200)
        self.assertIn("id=\"run-static-analysis\"", new_scan.text)
        self.assertIn("id=\"validate-project\"", new_scan.text)
        self.assertIn("id=\"run-tests\"", new_scan.text)

        scan_js = self.client.get("/static/js/scan.js")
        self.assertEqual(scan_js.status_code, 200)
        self.assertIn("run_static_analysis", scan_js.text)
        self.assertIn("run_tests", scan_js.text)

        detail_js = self.client.get("/static/js/detail.js")
        self.assertEqual(detail_js.status_code, 200)
        self.assertIn("renderToolStatus", detail_js.text)
        self.assertIn("not selected for this scan", detail_js.text)

        project = self._project()
        tools = FakeTools(detectors=[])
        with tool_patches(tools):
            job = self._wait_for_job(self._submit_local(project))
        page = self.client.get(f"/scan/{job['result']['scan_id']}")
        self.assertEqual(page.status_code, 200)
        self.assertIn("id=\"tool-status-card\"", page.text)
        self.assertIn("id=\"detail-scan-warning\"", page.text)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


class TestCliDirectoryScan(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        from auditor.analysis.base import AnalysisOutcome
        super().setUpClass()
        empty = AnalysisOutcome()
        empty.findings, empty.evidence, empty.notes = [], [], []
        cls._pa_patch = mock.patch(
            "auditor.analysis.privileged_auth.analyze",
            return_value=empty,
        )
        cls._pa_patch.start()

    @classmethod
    def tearDownClass(cls):
        cls._pa_patch.stop()
        super().tearDownClass()

    def test_cli_scan_directory_analyzes_all_files(self) -> None:
        from auditor.cli import EXIT_OK, _cmd_scan

        captured: dict = {}

        def recording_analyzer(ctx):
            captured.setdefault("files", []).append(
                [str(p) for p in ctx.source_files]
            )
            from auditor.analysis.base import AnalysisOutcome

            outcome = AnalysisOutcome()
            outcome.findings = []
            outcome.evidence = []
            outcome.notes = []
            return outcome

        with tempfile.TemporaryDirectory(prefix="p12-cli-") as tmp:
            root = Path(tmp)
            (root / "A.sol").write_text(SOL_BODY_VAULT, encoding="utf-8")
            (root / "B.sol").write_text(SOL_BODY_OTHER, encoding="utf-8")

            ns = argparse.Namespace(path=str(root), json=True)
            buf = io.StringIO()
            with mock.patch.dict(
                os.environ,
                {"AUDITOR_HISTORY_DB": str(Path(tmp) / "cli-history.db")},
            ), mock.patch(
                "auditor.analysis.reentrancy.analyze",
                side_effect=recording_analyzer,
            ), mock.patch(
                "auditor.analysis.access_control.analyze",
                side_effect=recording_analyzer,
            ), mock.patch(
                "auditor.analysis.slither_generic.analyze",
                side_effect=recording_analyzer,
            ), contextlib.redirect_stdout(buf):
                from auditor.scan_history import default_history_db_path

                # The CLI must record into the isolated DB, never production.
                self.assertEqual(
                    default_history_db_path(), Path(tmp) / "cli-history.db"
                )
                rc = _cmd_scan(ns, None)

        self.assertEqual(rc, EXIT_OK)
        # The directory scan previously analyzed only the first .sol file.
        self.assertEqual(len(captured["files"]), 3)
        seen = captured["files"][-1]
        self.assertEqual(len(seen), 2)
        self.assertTrue(any(p.endswith("A.sol") for p in seen))
        self.assertTrue(any(p.endswith("B.sol") for p in seen))

        payload = json.loads(buf.getvalue())
        self.assertIn("scan_id", payload)
        self.assertEqual(payload["findings"], [])
        self.assertEqual(payload["notes"], [])


# ---------------------------------------------------------------------------
# Scan-history migration
# ---------------------------------------------------------------------------


class TestExecutionColumnMigration(unittest.TestCase):
    def test_legacy_db_gains_execution_column_on_open(self) -> None:
        """Additive migration: pre-Phase-12 databases upgrade in place."""
        import sqlite3

        from auditor.scan_history import ScanHistory

        with tempfile.TemporaryDirectory(prefix="p12-mig-") as tmp:
            db = Path(tmp) / "legacy.db"

            history = ScanHistory(db)
            scan_id = history.record_scan(
                source_path=Path(tmp) / "Legacy.sol",
                config_fingerprint="legacy",
                findings=[],
            )
            history.mark_completed(scan_id, [])
            history.close()

            # Simulate a database created before tool-execution tracking.
            conn = sqlite3.connect(db)
            conn.execute("ALTER TABLE scan_records DROP COLUMN execution")
            conn.commit()
            conn.close()

            history = ScanHistory(db)
            try:
                columns = {
                    row[1]
                    for row in history.conn.execute("PRAGMA table_info(scan_records)")
                }
                self.assertIn("execution", columns)

                record = history.get_scan(scan_id)
                self.assertIsNone(record.get("execution"))

                history.set_execution(
                    scan_id, {"scan_complete": False, "tools": []}
                )
                record = history.get_scan(scan_id)
                self.assertEqual(
                    record["execution"], {"scan_complete": False, "tools": []}
                )
            finally:
                history.close()


if __name__ == "__main__":
    unittest.main()
