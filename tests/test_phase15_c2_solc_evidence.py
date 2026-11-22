"""Phase 15 DeFi-readiness — change C2: opt-in compiler selection + honest
compiler evidence.

Two independent deliverables, both evidence-only:

**1. ``--solc PATH`` / ``--solc-remaps "PREFIX=PATH ..."``**

* validated *before* Slither can be invoked — an invalid value is a usage
  error that leaves no scan row, never a silent failed (zero-finding) run;
* bare compiler versions such as ``0.8.20`` are rejected, because
  crytic-compile resolves a non-path value through solc-select and would
  ``install_artifacts()`` it, breaking the offline guarantee;
* default invocations keep their exact historical argv
  (``[exe, target, "--json", path]``), so nothing that did not opt in
  changes behaviour or fingerprint.

**2. Compiler evidence that distinguishes what ran from what is installed**

* ``compiler_version`` is the compiler Slither disclosed it invoked, and is
  ``None`` when no such disclosure exists — never the PATH probe;
* ``path_compiler_version`` / ``path_compiler_path`` preserve the PATH probe
  under its own name;
* ``selected_compiler.verification`` separates ``observed`` (proof of
  runtime execution) from ``project-config`` (Foundry build-info, which only
  says what a build should have used) from ``unverified``.

Isolation: every database is created under a temporary directory with
``AUDITOR_HISTORY_DB`` redirected. The production ``audit_scan_history.db``
is asserted unchanged (absent before and after, or byte-identical). No test
invokes the real Slither or the network: subprocesses are mocked, and the
only executables created here are local ``#!/bin/sh`` version printers in
temporary directories.
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

from auditor.analysis.slither_runner import (  # noqa: E402
    SlitherRun,
    parse_solc_remappings,
    run_slither,
    validate_solc_path,
)
from auditor.scan_evidence import (  # noqa: E402
    SCAN_EVIDENCE_SCHEMA,
    collect_scan_evidence,
    config_fingerprint,
    observe_compiler,
    probe_binary_version,
    read_build_info_version,
    selected_compiler,
)
from auditor.scan_history import ScanHistory  # noqa: E402
from auditor.toolchain import TOOL_SPECS, ToolStatus  # noqa: E402

PRODUCTION_DB = PROJECT_ROOT / "audit_scan_history.db"

_ANALYZERS = ("access_control", "reentrancy", "slither_generic")

#: What the CLI actually runs after C3–C6. Pure-function golden tests above
#: still use the historical 3-key set so the frozen digest remains valid.
_CLI_ANALYZERS = (
    "access_control",
    "reentrancy",
    "slither_generic",
    "oracle_staleness",
    "erc4626_inflation",
    "pool_accounting",
    "honeypot",  # Phase 19
    "privileged_auth",  # Phase 25
)

#: Digest of the C1-era fingerprint payload for the fixed inputs below.
#: Frozen so that adding an always-present key to ``config_fingerprint``
#: cannot silently re-key every scan recorded before C2.
_C1_GOLDEN_FINGERPRINT = (
    "9d5119e7e2ffd17a7e105739e4d26c08aa6910cb59b04296dbfb6eff45290cc6"
)


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


def _probe_patch(solc_version="0.5.8", slither_version="0.11.6",
                 solc_path="/usr/bin/solc"):
    """Deterministic PATH inventory: deliberately NOT the compiler that runs."""

    def _probe(spec, *args, **kwargs):
        if spec.key == "solc":
            return _status("solc", path=solc_path, version=solc_version,
                           error=None)
        return _status("slither", path="/usr/local/bin/slither",
                       version=slither_version, error=None)

    return mock.patch("auditor.toolchain.detect_tool", side_effect=_probe)


def _fingerprint(**overrides):
    kwargs = dict(
        analyzer_keys=_ANALYZERS,
        fail_on=None,
        auditor_version="0.0.0-test",
        schema_version=7,
    )
    kwargs.update(overrides)
    return config_fingerprint(**kwargs)


def _slither_run(stdout="", stderr="", status="completed") -> SlitherRun:
    return SlitherRun(
        status=status,
        detectors=[] if status == "completed" else None,
        stdout=stdout,
        stderr=stderr,
        returncode=0,
    )


class _EvidenceIsolation(unittest.TestCase):
    """Temporary history DB + production-DB guard for every test here."""

    _saved: str | None = None
    _tmp: tempfile.TemporaryDirectory | None = None

    @classmethod
    def setUpClass(cls) -> None:
        cls._saved = os.environ.get("AUDITOR_HISTORY_DB")
        cls._tmp = tempfile.TemporaryDirectory(prefix="audit-c2-")
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

    # -- shared fixtures --------------------------------------------------
    def make_source(self, name: str = "A.sol",
                    root: Path | None = None) -> Path:
        directory = Path(root) if root else Path(
            tempfile.mkdtemp(prefix="c2-src-", dir=self._tmp.name))
        directory.mkdir(parents=True, exist_ok=True)
        path = directory / name
        path.write_text("pragma solidity ^0.8.0;\ncontract A {}\n",
                        encoding="utf-8")
        return path

    def make_fake_solc(self, directory: Path,
                       version: str = "0.8.99+commit.abcdef00.Darwin.appleclang",
                       name: str = "solc-fake") -> str:
        """Local executable that prints a solc-style version banner."""
        script = Path(directory) / name
        script.write_text(
            "#!/bin/sh\n"
            'echo "solc, the solidity compiler commandline interface"\n'
            f'echo "Version: {version}"\n',
            encoding="utf-8",
        )
        script.chmod(0o755)
        return str(script)


# ---------------------------------------------------------------------------
# 1. Argument validation (before Slither can be reached)
# ---------------------------------------------------------------------------


class SolcPathValidationTests(_EvidenceIsolation):
    def test_absent_value_is_not_an_error(self) -> None:
        self.assertEqual(validate_solc_path(None), (None, None))

    def test_existing_executable_is_accepted_and_made_absolute(self) -> None:
        with tempfile.TemporaryDirectory(dir=self._tmp.name) as tmp:
            script = self.make_fake_solc(Path(tmp))
            old = os.getcwd()
            try:
                os.chdir(tmp)
                resolved, error = validate_solc_path("solc-fake")
            finally:
                os.chdir(old)
        self.assertIsNone(error)
        self.assertTrue(Path(resolved).is_absolute(), resolved)
        self.assertEqual(Path(resolved).resolve(), Path(script).resolve())

    def test_bare_compiler_version_is_rejected(self) -> None:
        """The offline guarantee: a version string must never reach crytic."""
        for value in ("0.8.20", "0.8", "v0.8.20"):
            with self.subTest(value=value):
                resolved, error = validate_solc_path(value)
                self.assertIsNone(resolved)
                self.assertIsNotNone(error)
                self.assertIn("bare compiler versions", error)
                self.assertIn("downloaded", error)

    def test_missing_file_is_rejected(self) -> None:
        resolved, error = validate_solc_path("/nonexistent/solc-xyz")
        self.assertIsNone(resolved)
        self.assertIn("not an existing file", error)

    def test_directory_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory(dir=self._tmp.name) as tmp:
            resolved, error = validate_solc_path(tmp)
        self.assertIsNone(resolved)
        self.assertIn("not a regular file", error)

    def test_non_executable_file_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory(dir=self._tmp.name) as tmp:
            plain = Path(tmp) / "solc.txt"
            plain.write_text("not a compiler", encoding="utf-8")
            plain.chmod(0o644)
            resolved, error = validate_solc_path(str(plain))
        self.assertIsNone(resolved)
        self.assertIn("not executable", error)

    def test_blank_value_is_rejected(self) -> None:
        resolved, error = validate_solc_path("   ")
        self.assertIsNone(resolved)
        self.assertIn("requires a path", error)


class SolcRemappingValidationTests(_EvidenceIsolation):
    def test_absent_value_is_not_an_error(self) -> None:
        self.assertEqual(parse_solc_remappings(None), (None, None))

    def test_single_and_multiple_remappings_parse(self) -> None:
        one, error = parse_solc_remappings("@oz/=lib/openzeppelin/")
        self.assertIsNone(error)
        self.assertEqual(one, ["@oz/=lib/openzeppelin/"])

        many, error = parse_solc_remappings(
            "@oz/=lib/oz/   @chainlink/=lib/chainlink/")
        self.assertIsNone(error)
        self.assertEqual(many, ["@oz/=lib/oz/", "@chainlink/=lib/chainlink/"])

    def test_context_prefix_form_is_accepted(self) -> None:
        tokens, error = parse_solc_remappings("a:b/=lib/b/")
        self.assertIsNone(error)
        self.assertEqual(tokens, ["a:b/=lib/b/"])

    def test_token_without_equals_is_rejected(self) -> None:
        tokens, error = parse_solc_remappings("@oz/=lib/oz/ not-a-remap")
        self.assertIsNone(tokens)
        self.assertIn("PREFIX=PATH", error)
        self.assertIn("not-a-remap", error)

    def test_empty_prefix_or_path_is_rejected(self) -> None:
        for value in ("=lib/oz/", "@oz/="):
            with self.subTest(value=value):
                tokens, error = parse_solc_remappings(value)
                self.assertIsNone(tokens)
                self.assertIn("empty prefix or path", error)

    def test_quotes_are_rejected(self) -> None:
        tokens, error = parse_solc_remappings('@oz/="lib/oz/"')
        self.assertIsNone(tokens)
        self.assertIn("quote", error)

    def test_empty_string_is_rejected(self) -> None:
        tokens, error = parse_solc_remappings("   ")
        self.assertIsNone(tokens)
        self.assertIn("contains no remappings", error)

    def test_tokens_cannot_carry_whitespace_by_construction(self) -> None:
        """Spacing is the split delimiter, so a token can never smuggle one."""
        tokens, _ = parse_solc_remappings("@a/=x @b/=y")
        self.assertTrue(all(not t.split("=", 1)[0].isspace() for t in tokens))


# ---------------------------------------------------------------------------
# 2. Argument compatibility with Slither
# ---------------------------------------------------------------------------


class SlitherArgvCompatibilityTests(_EvidenceIsolation):
    def _run(self, **kwargs):
        files = [self.make_source()]
        captured: list[list[str]] = []

        def _fake_run(argv, timeout=None, cwd=None):
            from auditor.procs import ProcResult

            captured.append([str(a) for a in argv])
            return ProcResult(tuple(str(a) for a in argv), 0, "", "")

        with mock.patch(
            "auditor.analysis.slither_runner.resolve_executable",
            return_value="/usr/bin/slither",
        ), mock.patch(
            "auditor.analysis.slither_runner.run", side_effect=_fake_run
        ):
            result = run_slither(files, **kwargs)
        return result, captured

    def test_default_argv_is_exactly_the_historical_one(self) -> None:
        result, captured = self._run()
        self.assertEqual(result.status, "completed")
        self.assertEqual(len(captured), 1)
        argv = captured[0]
        self.assertEqual(len(argv), 4, argv)
        self.assertEqual(argv[0], "/usr/bin/slither")
        self.assertTrue(os.path.isabs(argv[1]) or Path(argv[1]).exists(), argv)
        self.assertEqual(argv[2], "--json")
        self.assertTrue(argv[3].endswith("report.json"), argv)
        self.assertNotIn("--solc", argv)
        self.assertNotIn("--solc-remaps", argv)

    def test_optin_flags_are_appended_after_json(self) -> None:
        with tempfile.TemporaryDirectory(dir=self._tmp.name) as tmp:
            solc = self.make_fake_solc(Path(tmp))
            result, captured = self._run(
                solc=solc, solc_remaps="@oz/=lib/oz/ @b/=lib/b/"
            )
        self.assertEqual(result.status, "completed")
        argv = captured[0]
        self.assertEqual(argv[2], "--json", "target/JSON positions must not move")
        self.assertEqual(argv[-4:], [
            "--solc", solc, "--solc-remaps", "@oz/=lib/oz/ @b/=lib/b/",
        ])
        self.assertEqual(len(argv), 8)

    def test_only_solc_is_supplied_without_remappings(self) -> None:
        with tempfile.TemporaryDirectory(dir=self._tmp.name) as tmp:
            solc = self.make_fake_solc(Path(tmp))
            result, captured = self._run(solc=solc)
        argv = captured[0]
        self.assertNotIn("--solc-remaps", argv)
        self.assertEqual(argv[-2:], ["--solc", solc])

    def test_invalid_solc_never_reaches_slither(self) -> None:
        files = [self.make_source()]
        with mock.patch(
            "auditor.analysis.slither_runner.resolve_executable"
        ) as resolve, mock.patch("auditor.analysis.slither_runner.run") as runner:
            result = run_slither(files, solc="0.8.20")
        resolve.assert_not_called()
        runner.assert_not_called()
        self.assertEqual(result.status, "failed")
        self.assertIn("bare compiler versions", result.error)
        self.assertIn("Slither was not invoked", result.notes[0])

    def test_invalid_remappings_never_reach_slither(self) -> None:
        files = [self.make_source()]
        with mock.patch(
            "auditor.analysis.slither_runner.resolve_executable"
        ) as resolve, mock.patch("auditor.analysis.slither_runner.run") as runner:
            result = run_slither(files, solc_remaps="nonsense")
        resolve.assert_not_called()
        runner.assert_not_called()
        self.assertEqual(result.status, "failed")
        self.assertIn("PREFIX=PATH", result.error)


# ---------------------------------------------------------------------------
# 3. Observed-compiler disclosure
# ---------------------------------------------------------------------------


class ObservedCompilerTests(_EvidenceIsolation):
    def _run_with(self, stdout="", stderr="", solc_requested=None):
        return observe_compiler(
            _slither_run(stdout=stdout, stderr=stderr),
            solc_requested=solc_requested,
            timeout=5.0,
        )

    def test_version_probe_line_discloses_the_binary(self) -> None:
        with tempfile.TemporaryDirectory(dir=self._tmp.name) as tmp:
            solc = self.make_fake_solc(Path(tmp))
            observed = self._run_with(
                stdout=f"'{solc} --version' running\n"
                       f"'{solc} A.sol --combined-json abi,ast' running\n"
            )
        self.assertEqual(observed["verification"], "observed")
        self.assertEqual(observed["binary"], solc)
        self.assertEqual(observed["version"],
                         "0.8.99+commit.abcdef00.Darwin.appleclang")
        self.assertIsNone(observed["request_honored"])

    def test_compile_line_alone_is_enough_when_no_version_probe(self) -> None:
        with tempfile.TemporaryDirectory(dir=self._tmp.name) as tmp:
            solc = self.make_fake_solc(Path(tmp))
            observed = self._run_with(
                stdout=f"'{solc} A.sol --combined-json abi,ast --allow-paths .' running\n"
            )
        self.assertEqual(observed["verification"], "observed")
        self.assertEqual(observed["binary"], solc)

    def test_no_disclosure_is_unverified_not_a_path_guess(self) -> None:
        observed = self._run_with(stdout="", stderr="")
        self.assertEqual(observed["verification"], "unverified")
        self.assertIsNone(observed["binary"])
        self.assertIsNone(observed["version"])
        self.assertIn("did not disclose", observed["reason"])

    def test_failed_probe_falls_back_to_solcs_own_diagnostic(self) -> None:
        """A disclosed binary that prints no solc banner: the diagnostic is used.

        An earlier fixture used ``/bin/echo``. GNU coreutils ``echo --version``
        prints a version banner, which broke the fallback on Linux.
        """
        with tempfile.TemporaryDirectory(dir=self._tmp.name) as tmp:
            silent = Path(tmp) / "silent-solc"
            silent.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            silent.chmod(0o755)
            observed = self._run_with(
                stdout=f"'{silent} A.sol --combined-json abi' running\n",
                stderr=(
                    "Error: Source file requires different compiler version "
                    "(current compiler is 0.8.19+commit.7dd6d404.Darwin.appleclang "
                    "- note that nightly builds are considered to be strictly "
                    "less than the released version\n"
                ),
            )
        self.assertEqual(observed["verification"], "observed")
        self.assertEqual(observed["version"],
                         "0.8.19+commit.7dd6d404.Darwin.appleclang")
        self.assertIn("diagnostic", observed["reason"])
        self.assertEqual(observed["corroborating"],
                         "0.8.19+commit.7dd6d404.Darwin.appleclang")

    def test_probe_and_diagnostic_disagreeing_is_unverified(self) -> None:
        with tempfile.TemporaryDirectory(dir=self._tmp.name) as tmp:
            solc = self.make_fake_solc(Path(tmp), version="0.8.99+commit.aaaa")
            observed = self._run_with(
                stdout=f"'{solc} --version' running\n",
                stderr="current compiler is 0.5.8+commit.23d335f2.Darwin.appleclang "
                       " - note that nightly\n",
            )
        self.assertEqual(observed["verification"], "unverified")
        self.assertIsNone(observed["version"],
                          "contradictory observations yield no version")
        self.assertIn("contradict", observed["reason"])
        self.assertIn("0.8.99+commit.aaaa", observed["reason"])
        self.assertIn("0.5.8+commit.23d335f2.Darwin.appleclang",
                      observed["reason"])
        self.assertEqual(observed["corroborating"],
                         "0.5.8+commit.23d335f2.Darwin.appleclang")

    def test_matching_explicit_solc_is_recorded_as_honored(self) -> None:
        with tempfile.TemporaryDirectory(dir=self._tmp.name) as tmp:
            solc = self.make_fake_solc(Path(tmp))
            observed = self._run_with(
                stdout=f"'{solc} --version' running\n", solc_requested=solc
            )
        self.assertTrue(observed["request_honored"])
        self.assertEqual(observed["requested"], solc)
        self.assertIsNone(observed["reason"])

    def test_explicit_solc_overridden_by_project_is_recorded(self) -> None:
        with tempfile.TemporaryDirectory(dir=self._tmp.name) as tmp:
            requested = self.make_fake_solc(Path(tmp), name="requested")
            actual = self.make_fake_solc(Path(tmp), name="actual")
            observed = self._run_with(
                stdout=f"'{actual} --version' running\n",
                solc_requested=requested,
            )
        self.assertFalse(observed["request_honored"])
        self.assertEqual(observed["binary"], actual)
        self.assertEqual(observed["verification"], "observed",
                         "what actually ran is still observed, just not requested")
        self.assertIn("likely overrode the request", observed["reason"])

    def test_non_solidity_tool_output_never_becomes_a_binary(self) -> None:
        observed = self._run_with(
            stdout="No contract was analyzed\n0 result(s) found\n"
        )
        self.assertIsNone(observed["binary"])
        self.assertEqual(observed["verification"], "unverified")

    def test_probe_binary_version_never_raises(self) -> None:
        result = probe_binary_version("/nonexistent/compiler", timeout=5.0)
        self.assertEqual(result["status"], "failed")
        self.assertIsNone(result["version"])
        self.assertTrue(result["error"])

    def test_probe_binary_version_reads_a_real_binary(self) -> None:
        with tempfile.TemporaryDirectory(dir=self._tmp.name) as tmp:
            solc = self.make_fake_solc(Path(tmp))
            result = probe_binary_version(solc, timeout=5.0)
        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["version"],
                         "0.8.99+commit.abcdef00.Darwin.appleclang")

    def test_probe_binary_version_rejects_empty_input(self) -> None:
        result = probe_binary_version("", timeout=5.0)
        self.assertEqual(result["status"], "failed")
        self.assertIn("no binary", result["error"])


# ---------------------------------------------------------------------------
# 4. Selected-compiler provenance
# ---------------------------------------------------------------------------


class SelectedCompilerProvenanceTests(_EvidenceIsolation):
    def _solc_probe(self, status="completed", version="0.5.8", error=None):
        return {"key": "solc", "status": status, "version": version,
                "path": "/usr/bin/solc", "error": error}

    def test_observed_run_beats_the_path_probe(self) -> None:
        with tempfile.TemporaryDirectory(dir=self._tmp.name) as tmp:
            src = self.make_source(root=Path(tmp))
            solc = self.make_fake_solc(Path(tmp))
            chosen = selected_compiler(
                [src], self._solc_probe(),
                slither_run=_slither_run(stdout=f"'{solc} --version' running\n"),
            )
        self.assertEqual(chosen["source"], "observed-from-tool-output")
        self.assertEqual(chosen["verification"], "observed")
        self.assertEqual(chosen["version"], "0.8.99+commit.abcdef00.Darwin.appleclang")
        self.assertEqual(chosen["path"], solc)
        self.assertNotEqual(chosen["version"], "0.5.8",
                            "PATH version must not leak into the selection")

    def test_requested_and_observed_binary_is_explicit_solc_arg(self) -> None:
        with tempfile.TemporaryDirectory(dir=self._tmp.name) as tmp:
            src = self.make_source(root=Path(tmp))
            solc = self.make_fake_solc(Path(tmp))
            chosen = selected_compiler(
                [src], self._solc_probe(),
                slither_run=_slither_run(stdout=f"'{solc} --version' running\n"),
                solc_requested=solc,
            )
        self.assertEqual(chosen["source"], "explicit-solc-arg")
        self.assertEqual(chosen["verification"], "observed")
        self.assertTrue(chosen["request_honored"])
        self.assertEqual(chosen["requested"], solc)

    def test_path_probe_alone_is_unverified_and_versionless(self) -> None:
        with tempfile.TemporaryDirectory(dir=self._tmp.name) as tmp:
            src = self.make_source(root=Path(tmp))
            chosen = selected_compiler([src], self._solc_probe())
        self.assertEqual(chosen["source"], "unverified")
        self.assertEqual(chosen["verification"], "unverified")
        self.assertIsNone(chosen["version"])
        self.assertIsNone(chosen["path"])
        self.assertIn("not proof of which compiler was invoked", chosen["reason"])
        self.assertIn("0.5.8", chosen["reason"])

    def test_requested_but_undisclosed_says_so(self) -> None:
        with tempfile.TemporaryDirectory(dir=self._tmp.name) as tmp:
            src = self.make_source(root=Path(tmp))
            chosen = selected_compiler(
                [src], self._solc_probe(), solc_requested="/opt/solc-0.8.36",
            )
        self.assertEqual(chosen["source"], "unverified")
        self.assertIsNone(chosen["version"])
        self.assertIsNone(chosen["request_honored"],
                          "an unconfirmed request is neither honored nor refused")
        self.assertIn("could not be confirmed to have taken effect",
                      chosen["reason"])

    def test_no_observation_no_project_no_path_is_unavailable(self) -> None:
        with tempfile.TemporaryDirectory(dir=self._tmp.name) as tmp:
            src = self.make_source(root=Path(tmp))
            chosen = selected_compiler(
                [src],
                {"key": "solc", "status": "not_found", "version": None,
                 "path": None, "error": "executable not found on PATH"},
            )
        self.assertEqual(chosen["source"], "unavailable")
        self.assertEqual(chosen["verification"], "unverified")
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

    def test_observed_run_wins_even_under_a_foundry_root(self) -> None:
        """Proof of execution outranks project configuration."""
        with tempfile.TemporaryDirectory(dir=self._tmp.name) as tmp:
            root = Path(tmp)
            (root / "foundry.toml").write_text("[profile.default]\n",
                                               encoding="utf-8")
            src = root / "src" / "A.sol"
            src.parent.mkdir()
            src.write_text("pragma solidity ^0.8.0;\ncontract A {}\n",
                           encoding="utf-8")
            solc = self.make_fake_solc(root)
            chosen = selected_compiler(
                [src], self._solc_probe(),
                slither_run=_slither_run(stdout=f"'{solc} --version' running\n"),
            )
        self.assertEqual(chosen["verification"], "observed")
        self.assertEqual(chosen["version"], "0.8.99+commit.abcdef00.Darwin.appleclang")


# ---------------------------------------------------------------------------
# 5. Foundry build-info = configuration evidence, never proof
# ---------------------------------------------------------------------------


class BuildInfoTests(_EvidenceIsolation):
    def _project(self, build_info: dict | None = None,
                 toml: str = "[profile.default]\n",
                 build_dir: str = "out") -> Path:
        root = Path(tempfile.mkdtemp(prefix="c2-fnd-", dir=self._tmp.name))
        (root / "foundry.toml").write_text(toml, encoding="utf-8")
        src = root / "src" / "A.sol"
        src.parent.mkdir()
        src.write_text("pragma solidity ^0.8.0;\ncontract A {}\n",
                       encoding="utf-8")
        if build_info is not None:
            directory = root / build_dir / "build-info"
            directory.mkdir(parents=True, exist_ok=True)
            (directory / "c1.json").write_text(json.dumps(build_info),
                                               encoding="utf-8")
        return root

    def test_build_info_version_is_read_but_not_marked_observed(self) -> None:
        root = self._project({"solcVersion": "0.8.20", "input": {}})
        info = read_build_info_version(root)
        self.assertEqual(info["version"], "0.8.20")
        self.assertEqual(info["files"], 1)

        with mock.patch(
            "auditor.toolchain.detect_tool",
            return_value=_status("solc", path="/usr/bin/solc",
                                 version="0.5.8", error=None),
        ):
            chosen = selected_compiler([root / "src" / "A.sol"],
                                       {"key": "solc", "status": "completed",
                                        "version": "0.5.8", "path": "/usr/bin/solc",
                                        "error": None})
        self.assertEqual(chosen["source"], "project-build-config")
        self.assertEqual(chosen["verification"], "project-config",
                         "build-info is configuration, not execution")
        self.assertEqual(chosen["version"], "0.8.20")
        self.assertIn("not proof of which compiler this run executed",
                      chosen["reason"])
        self.assertIn("was not probed", chosen["reason"])

    def test_build_info_without_version_declares_none(self) -> None:
        root = self._project({"input": {}})
        info = read_build_info_version(root)
        self.assertIsNone(info["version"])
        self.assertIn("declares no solcVersion", info["reason"])

    def test_multiple_build_info_versions_yield_none(self) -> None:
        root = self._project()
        directory = root / "out" / "build-info"
        directory.mkdir(parents=True, exist_ok=True)
        (directory / "a.json").write_text('{"solcVersion": "0.8.20"}',
                                          encoding="utf-8")
        (directory / "b.json").write_text('{"solcVersion": "0.8.24"}',
                                          encoding="utf-8")
        info = read_build_info_version(root)
        self.assertIsNone(info["version"])
        self.assertIn("multiple compiler versions", info["reason"])
        self.assertIn("0.8.20", info["reason"])
        self.assertIn("0.8.24", info["reason"])

    def test_no_build_info_is_reported_as_absent(self) -> None:
        root = self._project()
        info = read_build_info_version(root)
        self.assertIsNone(info["version"])
        self.assertEqual(info["files"], 0)
        self.assertIn("no local build-info", info["reason"])

    def test_custom_out_directory_from_foundry_config_is_honored(self) -> None:
        root = self._project({"solcVersion": "0.8.19"},
                             toml='[profile.default]\nout = "artifacts"\n',
                             build_dir="artifacts")
        info = read_build_info_version(root)
        self.assertEqual(info["version"], "0.8.19")

    def test_explicit_build_info_path_is_used_directly(self) -> None:
        root = Path(tempfile.mkdtemp(prefix="c2-bip-", dir=self._tmp.name))
        (root / "foundry.toml").write_text(
            '[profile.default]\nbuild_info_path = "custom-bi"\n',
            encoding="utf-8")
        directory = root / "custom-bi"
        directory.mkdir()
        (directory / "x.json").write_text('{"solcVersion": "0.8.21"}',
                                          encoding="utf-8")
        info = read_build_info_version(root)
        self.assertEqual(info["version"], "0.8.21")

    def test_output_json_artifacts_are_ignored(self) -> None:
        root = self._project()
        directory = root / "out" / "build-info"
        directory.mkdir(parents=True, exist_ok=True)
        (directory / "c1.output.json").write_text(
            '{"solcVersion": "0.8.24"}', encoding="utf-8")
        info = read_build_info_version(root)
        self.assertEqual(info["files"], 0)

    def test_malformed_foundry_toml_degrades_without_raising(self) -> None:
        root = Path(tempfile.mkdtemp(prefix="c2-badtoml-", dir=self._tmp.name))
        (root / "foundry.toml").write_text("[profile.default\n",
                                           encoding="utf-8")
        info = read_build_info_version(root)
        self.assertIsNone(info["version"])
        self.assertIn("could not read foundry.toml", info["reason"])

    def test_no_project_root_is_a_noop(self) -> None:
        info = read_build_info_version("")
        self.assertIsNone(info["version"])
        self.assertEqual(info["files"], 0)

    def test_foundry_root_without_disclosure_keeps_compiler_version_none(self) -> None:
        """The load-bearing rule: config evidence never populates compiler_version."""
        root = self._project({"solcVersion": "0.8.20"})
        with mock.patch(
            "auditor.toolchain.detect_tool",
            return_value=_status("solc", path="/usr/bin/solc",
                                 version="0.5.8", error=None),
        ):
            evidence = collect_scan_evidence(
                sol_files=[root / "src" / "A.sol"],
                analyzer_keys=_ANALYZERS,
                fail_on=None,
                auditor_version="0.0.0-test",
                schema_version=7,
            )
        self.assertEqual(evidence["schema"], "scan-evidence/v2")
        self.assertIsNone(evidence["compiler_version"],
                          "build-info must not be promoted to proof")
        self.assertEqual(evidence["selected_compiler"]["version"], "0.8.20")
        self.assertEqual(evidence["selected_compiler"]["verification"],
                         "project-config")
        self.assertEqual(evidence["path_compiler_version"], "0.5.8")


# ---------------------------------------------------------------------------
# 6. Evidence record: observed vs PATH separation
# ---------------------------------------------------------------------------


class EvidenceSeparationTests(_EvidenceIsolation):
    def test_path_probe_and_observed_compiler_are_reported_separately(self) -> None:
        """The C1 defect: PATH said 0.5.8, Slither ran 0.8.36 — both recorded."""
        with tempfile.TemporaryDirectory(dir=self._tmp.name) as tmp:
            src = self.make_source(root=Path(tmp))
            solc = self.make_fake_solc(Path(tmp))
            with _probe_patch(solc_version="0.5.8"):
                evidence = collect_scan_evidence(
                    sol_files=[src],
                    analyzer_keys=_ANALYZERS,
                    fail_on=None,
                    auditor_version="0.0.0-test",
                    schema_version=7,
                    slither_run=_slither_run(stdout=f"'{solc} --version' running\n"),
                )
        self.assertEqual(evidence["path_compiler_version"], "0.5.8")
        self.assertEqual(evidence["compiler_version"],
                         "0.8.99+commit.abcdef00.Darwin.appleclang")
        self.assertNotEqual(evidence["compiler_version"],
                            evidence["path_compiler_version"])
        self.assertEqual(evidence["selected_compiler"]["verification"], "observed")
        self.assertEqual(evidence["tool_versions"],
                         {"solc": "0.5.8", "slither": "0.11.6"},
                         "the tool inventory stays the PATH inventory")

    def test_no_slither_run_means_no_claimed_compiler(self) -> None:
        with tempfile.TemporaryDirectory(dir=self._tmp.name) as tmp:
            src = self.make_source(root=Path(tmp))
            with _probe_patch(solc_version="0.5.8"):
                evidence = collect_scan_evidence(
                    sol_files=[src],
                    analyzer_keys=_ANALYZERS,
                    fail_on=None,
                    auditor_version="0.0.0-test",
                    schema_version=7,
                    slither_run=None,
                )
        self.assertIsNone(evidence["compiler_version"])
        self.assertEqual(evidence["path_compiler_version"], "0.5.8")
        self.assertEqual(evidence["selected_compiler"]["source"], "unverified")

    def test_failed_slither_run_never_yields_a_compiler(self) -> None:
        with tempfile.TemporaryDirectory(dir=self._tmp.name) as tmp:
            src = self.make_source(root=Path(tmp))
            solc = self.make_fake_solc(Path(tmp))
            with _probe_patch(solc_version="0.5.8"):
                evidence = collect_scan_evidence(
                    sol_files=[src],
                    analyzer_keys=_ANALYZERS,
                    fail_on=None,
                    auditor_version="0.0.0-test",
                    schema_version=7,
                    slither_run=SlitherRun(
                        status="failed", detectors=None,
                        stdout=f"'{solc} --version' running\n",
                        stderr="InvalidCompilation",
                        returncode=1, error="slither could not compile",
                    ),
                )
        # The disclosure still identifies what ran; that is observed fact.
        self.assertEqual(evidence["compiler_version"],
                         "0.8.99+commit.abcdef00.Darwin.appleclang")
        self.assertEqual(evidence["selected_compiler"]["verification"], "observed")
        self.assertIsNone(evidence["scan_complete"],
                          "completion verdict stays an honest unknown")

    def test_requested_compiler_is_persisted_verbatim(self) -> None:
        with tempfile.TemporaryDirectory(dir=self._tmp.name) as tmp:
            src = self.make_source(root=Path(tmp))
            solc = self.make_fake_solc(Path(tmp))
            with _probe_patch():
                evidence = collect_scan_evidence(
                    sol_files=[src],
                    analyzer_keys=_ANALYZERS,
                    fail_on=None,
                    auditor_version="0.0.0-test",
                    schema_version=7,
                    slither_run=_slither_run(stdout=f"'{solc} --version' running\n"),
                    solc_requested=solc,
                    solc_version_requested="0.8.99+commit.abcdef00.Darwin.appleclang",
                    solc_remaps_requested="@oz/=lib/oz/",
                )
        self.assertEqual(evidence["solc_requested"], solc)
        self.assertEqual(evidence["solc_version_requested"],
                         "0.8.99+commit.abcdef00.Darwin.appleclang")
        self.assertEqual(evidence["solc_remaps_requested"], "@oz/=lib/oz/")
        self.assertEqual(evidence["selected_compiler"]["source"],
                         "explicit-solc-arg")

    def test_schema_version_was_bumped(self) -> None:
        self.assertEqual(SCAN_EVIDENCE_SCHEMA, "scan-evidence/v2")


# ---------------------------------------------------------------------------
# 7. Fingerprint stability
# ---------------------------------------------------------------------------


class FingerprintStabilityTests(_EvidenceIsolation):
    def test_default_fingerprint_is_the_c1_golden_value(self) -> None:
        """No --solc/--solc-remaps ⇒ byte-identical to every C1 scan."""
        self.assertEqual(_fingerprint(), _C1_GOLDEN_FINGERPRINT)
        self.assertEqual(_fingerprint(solc=None, solc_remaps=None),
                         _C1_GOLDEN_FINGERPRINT)

    def test_default_fingerprint_is_independent_of_directory(self) -> None:
        def _make_tree(base: Path) -> list[Path]:
            directory = Path(tempfile.mkdtemp(prefix="c2-fp-", dir=base))
            self.addCleanup(_rmtree_quiet, directory)
            files = []
            for name in ("A.sol", "B.sol"):
                path = directory / name
                path.write_text(f"contract {name[:-4]} {{}}\n", encoding="utf-8")
                files.append(path)
            return files

        in_temp = _make_tree(Path(self._tmp.name))
        elsewhere = _make_tree(Path(tempfile.gettempdir()))
        with mock.patch("auditor.toolchain.detect_tool",
                        return_value=_status("solc", path="/usr/bin/solc",
                                             version="0.8.36", error=None)):
            def _collect(files):
                return collect_scan_evidence(
                    sol_files=files, analyzer_keys=_ANALYZERS, fail_on=None,
                    auditor_version="0.0.0-test", schema_version=7,
                )["config_fingerprint"]

            self.assertEqual(_collect(in_temp), _collect(elsewhere))

    def test_requested_compiler_version_moves_the_fingerprint(self) -> None:
        base = _fingerprint()
        self.assertNotEqual(base, _fingerprint(solc="0.8.36"))
        self.assertNotEqual(_fingerprint(solc="0.8.36"),
                            _fingerprint(solc="0.8.37"))

    def test_requested_remappings_move_the_fingerprint(self) -> None:
        base = _fingerprint()
        self.assertNotEqual(base, _fingerprint(solc_remaps="@oz/=lib/oz/"))
        self.assertNotEqual(_fingerprint(solc_remaps="@oz/=lib/oz/"),
                            _fingerprint(solc_remaps="@oz/=lib/oz2/"))

    def test_empty_selection_equals_no_selection(self) -> None:
        """Falsy selections are omitted, so '' never becomes a real input."""
        self.assertEqual(_fingerprint(solc="", solc_remaps=""),
                         _fingerprint())

    def test_selection_is_independent_of_source_location(self) -> None:
        """A version identity (not a path) keeps cwd out of the fingerprint."""
        with tempfile.TemporaryDirectory(dir=self._tmp.name) as a, \
                tempfile.TemporaryDirectory(dir=self._tmp.name) as b:
            src_a = self.make_source(root=Path(a))
            src_b = self.make_source(root=Path(b))
            with _probe_patch():
                def _collect(files, requested, version):
                    return collect_scan_evidence(
                        sol_files=files, analyzer_keys=_ANALYZERS, fail_on=None,
                        auditor_version="0.0.0-test", schema_version=7,
                        solc_requested=requested,
                        solc_version_requested=version,
                    )["config_fingerprint"]

                first = _collect([src_a], "/opt/a/solc", "0.8.36")
                second = _collect([src_b], "/opt/b/solc", "0.8.36")
                third = _collect([src_b], "/opt/b/solc", "0.8.37")
        self.assertEqual(first, second,
                         "same version identity ⇒ same fingerprint")
        self.assertNotEqual(second, third)

    def test_analyzer_order_and_fail_on_still_behave_as_before(self) -> None:
        self.assertEqual(
            _fingerprint(analyzer_keys=("reentrancy", "access_control",
                                        "slither_generic")),
            _fingerprint(analyzer_keys=("slither_generic", "reentrancy",
                                        "access_control")),
        )
        self.assertNotEqual(_fingerprint(), _fingerprint(fail_on="HIGH"))


# ---------------------------------------------------------------------------
# 8. Backward compatibility
# ---------------------------------------------------------------------------


class BackwardCompatibilityTests(_EvidenceIsolation):
    _LEGACY_COLS = {
        "scan_id", "timestamp", "source_path", "content_hash",
        "config_fingerprint", "status", "finding_fingerprints",
        "finding_details", "error_info", "graph_snapshot",
        "execution", "created_at", "balance_usd",
    }

    def test_c2_adds_no_database_columns(self) -> None:
        path = Path(self._tmp.name) / "schema-c2.db"
        history = ScanHistory(path)
        try:
            columns = {r[1] for r in history.conn.execute(
                "PRAGMA table_info(scan_records)")}
        finally:
            history.close()
        self.assertEqual(columns, self._LEGACY_COLS)

    def test_migration_is_still_idempotent(self) -> None:
        path = Path(self._tmp.name) / "pre-execution-c2.db"
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
        conn.execute(
            "INSERT INTO scan_records (scan_id, timestamp, source_path, "
            "content_hash, config_fingerprint, status) VALUES "
            "('s-old','2026-01-01T00:00:00+00:00','/l/A.sol','h','scan-cli',"
            "'completed')"
        )
        conn.commit()
        conn.close()

        for _ in range(2):
            history = ScanHistory(path)
            try:
                record = history.get_scan("s-old")
            finally:
                history.close()
            self.assertEqual(record["config_fingerprint"], "scan-cli")
            self.assertIsNone(record["execution"])

    def test_v1_evidence_blob_still_reads_through_the_dashboard(self) -> None:
        from auditor.dashboard.jobs import JobManager

        v1 = {
            "schema": "scan-evidence/v1",
            "tools": [{"key": "solc", "status": "completed"}],
            "scan_complete": None,
            "incomplete_reasons": [],
            "zero_findings_note": None,
            "validation": None,
            "compiler_version": "0.8.36",
            "selected_compiler": {"source": "path-solc", "version": "0.8.36"},
            "config_fingerprint": "abc",
            # no path_compiler_version, no verification — pre-C2 blob
        }
        fields = JobManager._execution_fields(v1)
        self.assertEqual(len(fields["tool_runs"]), 1)
        self.assertIsNone(fields["scan_complete"])
        self.assertNotIn("path_compiler_version", v1,
                         "v1 blobs stay exactly as written")

    def test_v2_evidence_reaches_the_dashboard_reader(self) -> None:
        from auditor.dashboard.jobs import JobManager

        with _probe_patch():
            evidence = collect_scan_evidence(
                sol_files=[], analyzer_keys=_ANALYZERS, fail_on=None,
                auditor_version="0.0.0-test", schema_version=7,
            )
        fields = JobManager._execution_fields(evidence)
        self.assertEqual(len(fields["tool_runs"]), 2)
        self.assertIsNone(fields["scan_complete"])
        self.assertEqual(evidence["schema"], SCAN_EVIDENCE_SCHEMA)


# ---------------------------------------------------------------------------
# 9. End-to-end CLI: validation, selection and persistence
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


class CliSelectionTests(_EvidenceIsolation):
    def setUp(self) -> None:
        super().setUp()
        from auditor.scan_history import default_history_db_path

        self._history_path = default_history_db_path()
        self._rows_before = self._row_count()

    def _row_count(self) -> int:
        if not Path(self._history_path).exists():
            return 0
        conn = sqlite3.connect(str(self._history_path))
        try:
            return int(conn.execute("SELECT COUNT(*) FROM scan_records")
                       .fetchone()[0])
        finally:
            conn.close()

    def _run_cli(self, argv):
        import contextlib
        import io

        from auditor.cli import main

        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main(argv)
        return code, out.getvalue(), err.getvalue()

    def _project(self) -> Path:
        root = Path(tempfile.mkdtemp(prefix="c2-proj-", dir=self._tmp.name))
        (root / "Fixture.sol").write_text(
            "pragma solidity ^0.8.0;\ncontract Fixture { }\n", encoding="utf-8")
        return root

    def _execution(self, scan_id: str) -> dict:
        history = ScanHistory(self._history_path)
        try:
            record = history.get_scan(scan_id)
        finally:
            history.close()
        return record["execution"]

    def test_bare_version_is_a_usage_error_with_no_scan_row(self) -> None:
        from auditor.cli import EXIT_ERROR

        project = self._project()
        with _EmptyAnalyzers():
            code, out, err = self._run_cli(
                ["scan", "--json", str(project), "--solc", "0.8.20"])

        self.assertEqual(code, EXIT_ERROR)
        self.assertEqual(out.strip(), "", "no partial JSON on stdout")
        self.assertIn("--solc value is not an existing file", err)
        self.assertIn("never downloaded", err)
        self.assertEqual(self._row_count(), self._rows_before,
                         "a rejected scan must not leave a row behind")

    def test_invalid_remapping_is_a_usage_error_with_no_scan_row(self) -> None:
        from auditor.cli import EXIT_ERROR

        project = self._project()
        with _EmptyAnalyzers():
            code, out, err = self._run_cli(
                ["scan", "--json", str(project), "--solc-remaps", "oops"])

        self.assertEqual(code, EXIT_ERROR)
        self.assertEqual(out.strip(), "")
        self.assertIn("PREFIX=PATH", err)
        self.assertEqual(self._row_count(), self._rows_before)

    def test_missing_path_still_fails_before_any_solidity_work(self) -> None:
        from auditor.cli import EXIT_ERROR

        with _EmptyAnalyzers():
            code, _, err = self._run_cli(
                ["scan", "/nonexistent/path/xyz.sol", "--solc", "0.8.20"])
        self.assertEqual(code, EXIT_ERROR)
        self.assertIn("path does not exist", err)

    def test_accepted_solc_is_persisted_and_moves_the_fingerprint(self) -> None:
        from auditor.cli import EXIT_OK
        from auditor import __version__, SCHEMA_VERSION

        def _cli_fingerprint(**overrides):
            kwargs = dict(
                analyzer_keys=_CLI_ANALYZERS,
                fail_on=None,
                auditor_version=__version__,
                schema_version=SCHEMA_VERSION,
            )
            kwargs.update(overrides)
            return config_fingerprint(**kwargs)

        default_fp = None
        for label, extra in (("default", []), ("solc", [])):
            project = self._project()
            argv = ["scan", "--json", str(project)]
            if label == "solc":
                with tempfile.TemporaryDirectory(dir=self._tmp.name) as tmp:
                    solc = self.make_fake_solc(Path(tmp))
                    argv += ["--solc", solc,
                             "--solc-remaps", "@oz/=lib/oz/"]
                    with _probe_patch(), _EmptyAnalyzers():
                        code, out, err = self._run_cli(argv)
                    self.assertEqual(code, EXIT_OK, err)
                    execution = self._execution(json.loads(out)["scan_id"])
                    self.assertEqual(execution["solc_requested"], solc)
                    self.assertEqual(execution["solc_version_requested"],
                                     "0.8.99+commit.abcdef00.Darwin.appleclang")
                    self.assertEqual(execution["solc_remaps_requested"],
                                     "@oz/=lib/oz/")
                    # No Slither ran (analyzers patched) ⇒ still unverified.
                    self.assertIsNone(execution["compiler_version"])
                    self.assertEqual(execution["path_compiler_version"], "0.5.8")
                    self.assertEqual(
                        execution["config_fingerprint"],
                        _cli_fingerprint(
                            solc="0.8.99+commit.abcdef00.Darwin.appleclang",
                            solc_remaps="@oz/=lib/oz/",
                        ),
                    )
                    optin_fp = execution["config_fingerprint"]
            else:
                with _probe_patch(), _EmptyAnalyzers():
                    code, out, err = self._run_cli(argv)
                self.assertEqual(code, EXIT_OK, err)
                execution = self._execution(json.loads(out)["scan_id"])
                self.assertIsNone(execution["solc_requested"])
                self.assertIsNone(execution["solc_remaps_requested"])
                self.assertEqual(execution["config_fingerprint"],
                                 _cli_fingerprint())
                default_fp = execution["config_fingerprint"]

        self.assertEqual(default_fp, _cli_fingerprint())
        self.assertNotEqual(optin_fp, default_fp,
                            "an opted-in compiler selection is a different "
                            "effective configuration")

    def test_stdout_contract_is_unchanged_with_and_without_flags(self) -> None:
        from auditor.cli import EXIT_OK

        for extra in ([], ["--solc-remaps", "@oz/=lib/oz/"]):
            with self.subTest(extra=extra):
                project = self._project()
                argv = ["scan", "--json", str(project)] + extra
                with _probe_patch(), _EmptyAnalyzers():
                    code, out, _ = self._run_cli(argv)
                self.assertEqual(code, EXIT_OK)
                payload = json.loads(out)
                self.assertEqual(
                    set(payload),
                    {"scan_id", "source_path", "content_hash", "findings",
                     "notes"},
                )

    def test_scan_without_settings_still_honours_the_new_flags(self) -> None:
        """``_cmd_scan(ns, None)`` is a supported call site (Phase 12 test)."""
        import argparse
        import contextlib
        import io

        from auditor.cli import EXIT_ERROR, _cmd_scan

        project = self._project()
        ns = argparse.Namespace(path=str(project), json=True, fail_on=None,
                                solc="0.8.20", solc_remaps=None)
        buf = io.StringIO()
        with _EmptyAnalyzers(), contextlib.redirect_stdout(buf):
            rc = _cmd_scan(ns, None)
        self.assertEqual(rc, EXIT_ERROR)
        self.assertEqual(buf.getvalue(), "")
        self.assertEqual(self._row_count(), self._rows_before)


if __name__ == "__main__":
    unittest.main()
