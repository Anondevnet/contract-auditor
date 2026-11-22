"""Phase 15 DeFi-readiness, change C1 — scan evidence capture.

Covers the four requirements of C1 and their failure modes:

* compiler version and Slither version are captured when observable;
* selected-compiler information is recorded only when determinable — a
  project build configuration governs the compiler and is reported without
  guessing a version, and a missing tool stays missing rather than becoming
  a version we never observed;
* the effective-configuration fingerprint is stable (same effective config
  in any directory, in any analyzer order) and moves only when an input this
  path actually honours moves;
* records written before C1 still read back exactly as before — legacy rows
  keep ``execution IS NULL`` and their original ``config_fingerprint``, and
  the schema migration that adds ``execution`` is still idempotent.

Probe failures degrade into recorded reasons: no test may let a missing or
broken ``--version`` probe raise into the scan.

Isolation: every database is created under a temporary directory with
``AUDITOR_HISTORY_DB`` redirected. The production ``audit_scan_history.db``
is asserted unchanged (absent before and after, or byte-identical) and no
test runs Slither — analyzers are patched, probes are mocked.
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import sys
import tempfile
import unittest
import unittest.mock as mock
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from auditor.scan_evidence import (  # noqa: E402
    SCAN_EVIDENCE_SCHEMA,
    collect_scan_evidence,
    config_fingerprint,
    probe_tool,
    selected_compiler,
)
from auditor.scan_history import ScanHistory  # noqa: E402
from auditor.toolchain import TOOL_SPECS, ToolStatus  # noqa: E402

PRODUCTION_DB = PROJECT_ROOT / "audit_scan_history.db"

_ANALYZERS = ("access_control", "reentrancy", "slither_generic")


def _md5(path: Path) -> str:
    return hashlib.md5(path.read_bytes()).hexdigest()


def _rmtree_quiet(path: Path) -> None:
    import shutil

    try:
        shutil.rmtree(path, ignore_errors=True)
    except OSError:
        pass


def _spec(key: str):
    return next(s for s in TOOL_SPECS if s.key == key)


def _status(key: str, *, path, version, error, returncode=0):
    spec = _spec(key)
    return ToolStatus(
        key=spec.key,
        display_name=spec.display_name,
        category=spec.category,
        required=spec.required,
        available=path is not None and version is not None,
        path=path,
        version=version,
        version_line=None,
        resolved_via_shim=False,
        returncode=returncode,
        error=error,
        argv=[path, spec.version_arg] if path else [],
        duration_ms=1,
        notes=spec.notes,
    )


def _fingerprint(**overrides):
    kwargs = dict(
        analyzer_keys=_ANALYZERS,
        fail_on=None,
        auditor_version="0.0.0-test",
        schema_version=7,
    )
    kwargs.update(overrides)
    return config_fingerprint(**kwargs)


class _EvidenceIsolation(unittest.TestCase):
    """Temporary history DB + production-DB guard for every test here."""

    _saved: str | None = None
    _tmp: tempfile.TemporaryDirectory | None = None

    @classmethod
    def setUpClass(cls) -> None:
        cls._saved = os.environ.get("AUDITOR_HISTORY_DB")
        cls._tmp = tempfile.TemporaryDirectory(prefix="audit-c1-")
        os.environ["AUDITOR_HISTORY_DB"] = str(Path(cls._tmp.name) / "history.db")

    @classmethod
    def tearDownClass(cls) -> None:
        if cls._saved is None:
            os.environ.pop("AUDITOR_HISTORY_DB", None)
        else:
            os.environ["AUDITOR_HISTORY_DB"] = cls._saved
        if cls._tmp is not None:
            cls._tmp.cleanup()

    def setUp(self) -> None:
        # In-process write guard (md5 compare raced with the live monitor).
        sys.path.insert(0, str(Path(__file__).resolve().parent))
        from _prod_db_guard import ProdDBWriteGuard
        self._prod_guard = ProdDBWriteGuard(PRODUCTION_DB).start()

    def tearDown(self) -> None:
        hits = self._prod_guard.stop()
        self.assertEqual(hits, [], "test opened the production scan-history database for writing")


# ---------------------------------------------------------------------------
# 1. Missing tools
# ---------------------------------------------------------------------------


class MissingToolTests(_EvidenceIsolation):
    def test_absent_executable_is_recorded_not_raised(self) -> None:
        with mock.patch(
            "auditor.toolchain.detect_tool",
            return_value=_status("solc", path=None, version=None,
                                 error="executable not found on PATH (tried: solc)",
                                 returncode=None),
        ):
            probe = probe_tool("solc")
        self.assertEqual(probe["status"], "not_found")
        self.assertIsNone(probe["version"])
        self.assertIn("not found", probe["error"])

    def test_unknown_tool_key_is_skipped_without_probing(self) -> None:
        with mock.patch("auditor.toolchain.detect_tool") as detect:
            probe = probe_tool("definitely-not-a-tool")
        detect.assert_not_called()
        self.assertEqual(probe["status"], "skipped")
        self.assertIsNone(probe["version"])

    def test_evidence_still_built_when_both_tools_are_missing(self) -> None:
        def _missing(spec, *_args, **_kwargs):
            return _status(spec.key, path=None, version=None,
                           error="executable not found on PATH", returncode=None)

        with mock.patch("auditor.toolchain.detect_tool", side_effect=_missing):
            evidence = collect_scan_evidence(
                sol_files=[],
                analyzer_keys=_ANALYZERS,
                fail_on=None,
                auditor_version="0.0.0-test",
                schema_version=7,
            )
        self.assertEqual(evidence["schema"], SCAN_EVIDENCE_SCHEMA)
        self.assertIsNone(evidence["compiler_version"])
        self.assertIsNone(evidence["slither_version"])
        self.assertEqual(evidence["tool_versions"],
                         {"solc": None, "slither": None})
        statuses = {t["key"]: t["status"] for t in evidence["tools"]}
        self.assertEqual(statuses, {"solc": "not_found", "slither": "not_found"})
        # Nothing fabricated: no tool row claims a version.
        self.assertTrue(all(t["version"] is None for t in evidence["tools"]))
        self.assertEqual(len(evidence["config_fingerprint"]), 64)


# ---------------------------------------------------------------------------
# 2. Version-detection failures
# ---------------------------------------------------------------------------


class VersionDetectionFailureTests(_EvidenceIsolation):
    def test_unparseable_version_is_a_failure_not_a_version(self) -> None:
        with mock.patch(
            "auditor.toolchain.detect_tool",
            return_value=_status("slither", path="/usr/bin/slither",
                                 version=None,
                                 error="ran successfully but no version string "
                                       "could be parsed"),
        ):
            probe = probe_tool("slither")
        self.assertEqual(probe["status"], "failed")
        self.assertIsNone(probe["version"])
        self.assertEqual(probe["path"], "/usr/bin/slither")
        self.assertIn("no version string", probe["error"])

    def test_probe_exception_is_recorded_and_never_raised(self) -> None:
        with mock.patch(
            "auditor.toolchain.detect_tool",
            side_effect=RuntimeError("probe exploded"),
        ):
            probe = probe_tool("solc")
        self.assertEqual(probe["status"], "failed")
        self.assertIsNone(probe["version"])
        self.assertIn("RuntimeError", probe["error"])
        self.assertIn("probe exploded", probe["error"])

    def test_evidence_survives_a_probe_that_keeps_raising(self) -> None:
        with mock.patch(
            "auditor.toolchain.detect_tool", side_effect=ValueError("always"),
        ):
            evidence = collect_scan_evidence(
                sol_files=[],
                analyzer_keys=_ANALYZERS,
                fail_on="HIGH",
                auditor_version="0.0.0-test",
                schema_version=7,
            )
        self.assertEqual(evidence["compiler_version"], None)
        self.assertEqual(evidence["slither_version"], None)
        self.assertEqual(evidence["selected_compiler"]["source"], "unavailable")
        self.assertIn("ValueError", evidence["selected_compiler"]["reason"])
        self.assertEqual(evidence["config_fingerprint"], _fingerprint(fail_on="HIGH"))


# ---------------------------------------------------------------------------
# 3. Stable fingerprints
# ---------------------------------------------------------------------------


class ConfigFingerprintTests(_EvidenceIsolation):
    def test_same_inputs_same_fingerprint_and_shape(self) -> None:
        first, second = _fingerprint(), _fingerprint()
        self.assertEqual(first, second)
        self.assertEqual(len(first), 64)
        self.assertEqual(set(first), set("0123456789abcdef"))

    def test_analyzer_order_does_not_change_the_fingerprint(self) -> None:
        self.assertEqual(
            _fingerprint(analyzer_keys=("reentrancy", "access_control",
                                        "slither_generic")),
            _fingerprint(analyzer_keys=("slither_generic", "reentrancy",
                                        "access_control")),
        )

    def test_effective_inputs_move_the_fingerprint(self) -> None:
        base = _fingerprint()
        self.assertNotEqual(base, _fingerprint(fail_on="HIGH"))
        self.assertNotEqual(base, _fingerprint(fail_on="MEDIUM"))
        self.assertNotEqual(base, _fingerprint(auditor_version="9.9.9"))
        self.assertNotEqual(base, _fingerprint(schema_version=8))
        self.assertNotEqual(base, _fingerprint(analyzer_keys=("reentrancy",)))

    def test_fail_on_none_and_empty_are_the_same_configuration(self) -> None:
        self.assertEqual(_fingerprint(fail_on=None), _fingerprint(fail_on=""))

    def test_fingerprint_is_independent_of_source_location(self) -> None:
        """Same config, different working directory, same fingerprint."""

        def _make_tree(base: Path) -> list[Path]:
            directory = Path(tempfile.mkdtemp(prefix="c1-fp-", dir=base))
            self.addCleanup(_rmtree_quiet, directory)
            files = []
            for name in ("A.sol", "B.sol"):
                path = directory / name
                path.write_text(f"contract {name[:-4]} {{}}\n", encoding="utf-8")
                files.append(path)
            return files

        def _collect(files):
            with mock.patch(
                "auditor.toolchain.detect_tool",
                return_value=_status("solc", path="/usr/bin/solc",
                                     version="0.8.36", error=None),
            ):
                return collect_scan_evidence(
                    sol_files=files,
                    analyzer_keys=_ANALYZERS,
                    fail_on=None,
                    auditor_version="0.0.0-test",
                    schema_version=7,
                )

        in_temp = _make_tree(Path(self._tmp.name))
        elsewhere = _make_tree(Path(tempfile.gettempdir()))
        self.assertNotEqual(in_temp[0].parent, elsewhere[0].parent)
        self.assertEqual(_collect(in_temp)["config_fingerprint"],
                         _collect(elsewhere)["config_fingerprint"])

    def test_evidence_fingerprint_matches_the_pure_function(self) -> None:
        with mock.patch(
            "auditor.toolchain.detect_tool",
            return_value=_status("solc", path="/usr/bin/solc",
                                 version="0.8.36", error=None),
        ):
            evidence = collect_scan_evidence(
                sol_files=[],
                analyzer_keys=_ANALYZERS,
                fail_on="LOW",
                auditor_version="0.0.0-test",
                schema_version=7,
            )
        self.assertEqual(
            evidence["config_fingerprint"],
            _fingerprint(fail_on="LOW"),
        )


# ---------------------------------------------------------------------------
# 3b. Selected-compiler information (only when determinable)
# ---------------------------------------------------------------------------


class SelectedCompilerTests(_EvidenceIsolation):
    def _solc_probe(self, status="completed", version="0.8.36", error=None):
        return {"key": "solc", "status": status, "version": version,
                "path": "/usr/bin/solc", "error": error}

    def test_path_probe_alone_is_never_proof_of_the_compiler_used(self) -> None:
        """C2 correction: knowing which solc is on PATH does not say what ran.

        Before C2 this reported ``source="path-solc"`` with the PATH version as
        the selected compiler — the exact promotion of a PATH probe into proof
        that the C2 evidence rules forbid. With no Slither run to disclose its
        compiler, the answer is ``unverified`` and the PATH value is preserved
        only as context and in ``path_compiler_version``.
        """
        with tempfile.TemporaryDirectory(dir=self._tmp.name) as tmp:
            src = Path(tmp) / "A.sol"
            src.write_text("pragma solidity ^0.8.0;\ncontract A {}\n",
                           encoding="utf-8")
            chosen = selected_compiler([src], self._solc_probe())
        self.assertEqual(chosen["source"], "unverified")
        self.assertEqual(chosen["verification"], "unverified")
        self.assertIsNone(chosen["version"],
                          "a PATH probe must not become the selected compiler")
        self.assertIsNone(chosen["project_root"])
        self.assertIn("not proof of which compiler was invoked", chosen["reason"])
        self.assertIn("0.8.36", chosen["reason"], "PATH value kept as context")

    def test_foundry_root_yields_project_build_config_without_guessing(self) -> None:
        with tempfile.TemporaryDirectory(dir=self._tmp.name) as tmp:
            root = Path(tmp)
            (root / "foundry.toml").write_text("[profile.default]\n", encoding="utf-8")
            src = root / "src" / "A.sol"
            src.parent.mkdir()
            src.write_text("pragma solidity ^0.8.0;\ncontract A {}\n",
                           encoding="utf-8")
            chosen = selected_compiler([src], self._solc_probe())
        self.assertEqual(chosen["source"], "project-build-config")
        self.assertIsNone(chosen["version"], "must not invent a compiler version")
        self.assertEqual(chosen["project_root"], str(root))
        self.assertIn("not probed", chosen["reason"])

    def test_unavailable_compiler_states_the_reason(self) -> None:
        probe = self._solc_probe(status="not_found", version=None,
                                 error="executable not found on PATH")
        chosen = selected_compiler([], probe)
        self.assertEqual(chosen["source"], "unavailable")
        self.assertIsNone(chosen["version"])
        self.assertIn("not found", chosen["reason"])

    def test_root_discovery_failure_degrades_to_unavailable(self) -> None:
        with mock.patch(
            "auditor.analysis.slither_runner.find_foundry_root",
            side_effect=OSError("unreadable"),
        ):
            chosen = selected_compiler(["/tmp/a.sol"], self._solc_probe())
        self.assertEqual(chosen["source"], "unavailable")
        self.assertIsNone(chosen["version"])
        self.assertIn("OSError", chosen["reason"])


# ---------------------------------------------------------------------------
# 4. Backward compatibility with existing scan records
# ---------------------------------------------------------------------------


class LegacyRecordCompatibilityTests(_EvidenceIsolation):
    """Rows written before C1 must read back byte-for-byte unchanged."""

    _LEGACY_COLS = (
        "scan_id", "timestamp", "source_path", "content_hash",
        "config_fingerprint", "status", "finding_fingerprints",
        "finding_details", "error_info", "graph_snapshot",
    )

    def _legacy_row(self, conn, scan_id: str, fingerprint: str) -> None:
        conn.execute(
            """
            INSERT INTO scan_records (
                scan_id, timestamp, source_path, content_hash,
                config_fingerprint, status, finding_fingerprints,
                finding_details, error_info, graph_snapshot
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (scan_id, "2026-01-01T00:00:00+00:00", "/legacy/A.sol",
             "hash-" + scan_id, fingerprint, "completed",
             "[]", "{}", None, None),
        )
        conn.commit()

    def test_pre_c1_row_still_reads_with_execution_none(self) -> None:
        path = Path(self._tmp.name) / "legacy.db"
        history = ScanHistory(path)
        try:
            self._legacy_row(history.conn, "s-legacy", "scan-cli")
            record = history.get_scan("s-legacy")
        finally:
            history.close()

        self.assertIsNotNone(record)
        self.assertEqual(record["config_fingerprint"], "scan-cli")
        self.assertIsNone(record["execution"])
        self.assertEqual(record["content_hash"], "hash-s-legacy")

    def test_pre_c1_row_can_gain_evidence_without_a_rewrite(self) -> None:
        path = Path(self._tmp.name) / "legacy-attach.db"
        history = ScanHistory(path)
        try:
            self._legacy_row(history.conn, "s-attach", "scan-cli")
            history.set_execution("s-attach", {"schema": SCAN_EVIDENCE_SCHEMA})
            record = history.get_scan("s-attach")
        finally:
            history.close()

        self.assertEqual(record["config_fingerprint"], "scan-cli")
        self.assertEqual(record["execution"]["schema"], SCAN_EVIDENCE_SCHEMA)

    def test_db_without_execution_column_is_migrated_idempotently(self) -> None:
        path = Path(self._tmp.name) / "pre-execution.db"
        conn = sqlite3.connect(str(path))
        conn.executescript(
            """
            CREATE TABLE scan_records (
                scan_id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                source_path TEXT NOT NULL,
                content_hash TEXT NOT NULL,
                config_fingerprint TEXT NOT NULL,
                status TEXT NOT NULL,
                finding_fingerprints TEXT NOT NULL DEFAULT '[]',
                finding_details TEXT NOT NULL DEFAULT '{}',
                error_info TEXT,
                graph_snapshot TEXT
            );
            """
        )
        self._legacy_row(conn, "s-old", "scan-cli")
        conn.close()

        for _ in range(2):  # migration must be repeatable
            history = ScanHistory(path)
            try:
                columns = [r[1] for r in history.conn.execute(
                    "PRAGMA table_info(scan_records)")]
                record = history.get_scan("s-old")
            finally:
                history.close()
            self.assertIn("execution", columns)
            self.assertIsNone(record["execution"])
            self.assertEqual(record["config_fingerprint"], "scan-cli")

    def test_c1_adds_no_columns(self) -> None:
        """C1 records evidence inside existing columns; it does not add C1-specific columns."""
        path = Path(self._tmp.name) / "schema.db"
        history = ScanHistory(path)
        try:
            columns = {r[1] for r in history.conn.execute(
                "PRAGMA table_info(scan_records)")}
        finally:
            history.close()
        # Later work added balance_usd on purpose; C1 still does not add its
        # own columns (evidence stays inside existing fields).
        self.assertEqual(columns, set(self._LEGACY_COLS) | {"execution",
                                                             "created_at",
                                                             "balance_usd"})

    def test_dashboard_reader_handles_both_legacy_and_c1_rows(self) -> None:
        from auditor.dashboard.jobs import JobManager

        legacy = JobManager._execution_fields(None)
        self.assertEqual(legacy["tool_runs"], [])
        self.assertIsNone(legacy["scan_complete"])

        with mock.patch(
            "auditor.toolchain.detect_tool",
            return_value=_status("solc", path="/usr/bin/solc",
                                 version="0.8.36", error=None),
        ):
            evidence = collect_scan_evidence(
                sol_files=[],
                analyzer_keys=_ANALYZERS,
                fail_on=None,
                auditor_version="0.0.0-test",
                schema_version=7,
            )
        fields = JobManager._execution_fields(evidence)
        self.assertEqual(len(fields["tool_runs"]), 2)
        # Honest unknown, not a fabricated completion verdict.
        self.assertIsNone(fields["scan_complete"])


# ---------------------------------------------------------------------------
# End-to-end: CLI scan persists the evidence
# ---------------------------------------------------------------------------


class _EmptyAnalyzers:
    """Patch all CLI analyzers so no test here ever runs Slither."""

    def __enter__(self):
        import contextlib

        from auditor.analysis.base import AnalysisOutcome

        def _empty(_ctx):
            outcome = AnalysisOutcome()
            outcome.findings = []
            outcome.evidence = []
            outcome.notes = []
            return outcome

        self._stack = contextlib.ExitStack()
        for target in (
            "auditor.analysis.reentrancy.analyze",
            "auditor.analysis.access_control.analyze",
            "auditor.analysis.slither_generic.analyze",
            "auditor.analysis.oracle_staleness.analyze",
            "auditor.analysis.erc4626_inflation.analyze",
            "auditor.analysis.pool_accounting.analyze",
            "auditor.analysis.honeypot.analyze",
            "auditor.analysis.privileged_auth.analyze",
        ):
            self._stack.enter_context(mock.patch(target, side_effect=_empty))
        return self

    def __exit__(self, *exc):
        return self._stack.__exit__(*exc)


class CliScanEvidenceTests(_EvidenceIsolation):
    def _project(self) -> Path:
        root = Path(tempfile.mkdtemp(prefix="c1-proj-", dir=self._tmp.name))
        for i in range(2):
            (root / f"Fixture{i}.sol").write_text(
                f"pragma solidity ^0.5.8;\ncontract Fixture{i} {{ }}\n",
                encoding="utf-8",
            )
        return root

    def _run_cli(self, argv):
        import contextlib
        import io

        from auditor.cli import main

        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main(argv)
        return code, out.getvalue(), err.getvalue()

    def test_scan_persists_execution_and_hashed_fingerprint(self) -> None:
        from auditor.cli import EXIT_OK
        from auditor.scan_history import default_history_db_path

        project = self._project()
        probe_calls = []

        def _probe(spec, *args, **kwargs):
            probe_calls.append(spec.key)
            if spec.key == "solc":
                return _status("solc", path="/usr/bin/solc",
                               version="0.8.36", error=None)
            return _status("slither", path="/usr/local/bin/slither",
                           version="0.11.6", error=None)

        with mock.patch("auditor.toolchain.detect_tool",
                         side_effect=_probe), _EmptyAnalyzers():
            code, out, err = self._run_cli(["scan", "--json", str(project)])
        self.assertEqual(code, EXIT_OK)

        payload = json.loads(out)
        scan_id = payload["scan_id"]

        history = ScanHistory(default_history_db_path())
        try:
            record = history.get_scan(scan_id)
        finally:
            history.close()

        self.assertEqual(record["status"], "completed")
        # Fingerprint: 64 hex chars, and no longer the old constant.
        fp = record["config_fingerprint"]
        self.assertEqual(len(fp), 64)
        self.assertNotEqual(fp, "scan-cli")
        self.assertTrue(all(c in "0123456789abcdef" for c in fp), fp)

        execution = record["execution"]
        self.assertIsNotNone(execution, "C1 evidence was not persisted")
        self.assertEqual(execution["schema"], SCAN_EVIDENCE_SCHEMA)
        self.assertEqual(execution["config_fingerprint"], fp)
        # C2 correction: the analyzers here are patched to empty outcomes, so
        # no Slither run exists to disclose its compiler. compiler_version
        # must therefore be None — it is NOT the PATH probe.
        self.assertIsNone(execution["compiler_version"])
        # The PATH probe survives under its own name, and stays in the tool
        # inventory, so nothing informational is lost by the correction.
        self.assertEqual(execution["path_compiler_version"], "0.8.36")
        self.assertEqual(execution["slither_version"], "0.11.6")
        self.assertEqual(execution["tool_versions"],
                         {"solc": "0.8.36", "slither": "0.11.6"})
        self.assertEqual(execution["selected_compiler"]["source"], "unverified")
        self.assertEqual(execution["selected_compiler"]["verification"],
                         "unverified")
        self.assertIsNone(execution["selected_compiler"]["version"])
        # Opt-in selection is recorded even when unused (absent, not empty).
        self.assertIsNone(execution["solc_requested"])
        self.assertIsNone(execution["solc_remaps_requested"])
        self.assertEqual(
            execution["config_fingerprint"],
            config_fingerprint(
                analyzer_keys=(
                    "access_control",
                    "reentrancy",
                    "slither_generic",
                    "oracle_staleness",
                    "erc4626_inflation",
                    "pool_accounting",
                    "honeypot",  # Phase 19
                    "privileged_auth",  # Phase 25
                ),
                fail_on=None,
                auditor_version=__import__("auditor").__version__,
                schema_version=__import__("auditor").SCHEMA_VERSION,
            ),
        )
        # Probes are bounded: exactly one version probe per captured tool.
        self.assertEqual(sorted(set(probe_calls)), ["slither", "solc"])

    def test_fail_on_is_part_of_the_recorded_configuration(self) -> None:
        from auditor.scan_history import default_history_db_path

        def _probe(spec, *args, **kwargs):
            version = "0.8.36" if spec.key == "solc" else "0.11.6"
            return _status(spec.key, path=f"/usr/bin/{spec.key}",
                           version=version, error=None)

        fps = {}
        for gate in (None, "HIGH"):
            project = self._project()
            argv = ["scan", "--json", str(project)]
            if gate:
                argv += ["--fail-on", gate]
            with mock.patch("auditor.toolchain.detect_tool",
                             side_effect=_probe), _EmptyAnalyzers():
                _, out, _ = self._run_cli(argv)
            scan_id = json.loads(out)["scan_id"]
            history = ScanHistory(default_history_db_path())
            try:
                record = history.get_scan(scan_id)
            finally:
                history.close()
            fps[gate] = record["config_fingerprint"]

        self.assertNotEqual(fps[None], fps["HIGH"],
                            "the release gate is part of the effective config")

    def test_scan_without_settings_still_records_evidence(self) -> None:
        """``_cmd_scan(ns, None)`` is a supported call site (Phase 12 test)."""
        import argparse
        import contextlib
        import io

        from auditor.cli import EXIT_OK, _cmd_scan
        from auditor.scan_history import default_history_db_path

        project = self._project()
        ns = argparse.Namespace(path=str(project), json=True, fail_on=None)
        buf = io.StringIO()
        with _EmptyAnalyzers(), contextlib.redirect_stdout(buf):
            rc = _cmd_scan(ns, None)

        self.assertEqual(rc, EXIT_OK)
        payload = json.loads(buf.getvalue())
        history = ScanHistory(default_history_db_path())
        try:
            last = history.get_last_scan(Path(str(project)))
            record = history.get_scan(payload["scan_id"])
        finally:
            history.close()

        self.assertIsNotNone(last)
        self.assertEqual(last["scan_id"], payload["scan_id"])
        self.assertIsNotNone(record["execution"])
        self.assertEqual(len(record["config_fingerprint"]), 64)
        self.assertNotEqual(record["config_fingerprint"], "scan-cli")

    def test_scan_output_contract_is_unchanged(self) -> None:
        """C1 adds evidence to history only — stdout keeps its old shape."""
        from auditor.scan_history import default_history_db_path

        project = self._project()
        with mock.patch("auditor.toolchain.detect_tool") as detect, \
                _EmptyAnalyzers():
            detect.return_value = _status("solc", path="/usr/bin/solc",
                                          version="0.8.36", error=None)
            code, out, err = self._run_cli(["scan", "--json", str(project)])

        payload = json.loads(out)
        self.assertEqual(
            set(payload),
            {"scan_id", "source_path", "content_hash", "findings", "notes"},
        )
        history = ScanHistory(default_history_db_path())
        try:
            record = history.get_scan(payload["scan_id"])
        finally:
            history.close()
        self.assertIsNotNone(record["execution"])


if __name__ == "__main__":
    unittest.main()
