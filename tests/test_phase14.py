"""Phase 14 — vulnerability detection benchmark and evidence validation.

Covers: manifest validation (fatal schema defects vs per-fixture skips),
the three-rule matcher (channel + location + FACT evidence), outcome
taxonomy (blocked / not-evaluable / skipped / pipeline-failure /
harness-error / metadata-gaps kept distinct and never counted as TN or FN),
zero-denominator metrics returning null, FACT vs AI evidence separation,
the dedicated benchmark store (never the production scan history), CLI
dispatch and exit codes, and dashboard benchmark endpoints (empty and
populated states).

No test runs Slither: the harness is exercised with stub runs and stub
runners, and benchmark persistence always writes to a temporary database
under ``AUDITOR_BENCHMARK_DB``. The production ``audit_scan_history.db`` is
never opened for writing, and its content hash is asserted unchanged.
"""

from __future__ import annotations

import contextlib
import hashlib
import io
import json
import os
import sys
import tempfile
import unittest
import unittest.mock as mock
from pathlib import Path
from types import SimpleNamespace

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from auditor import benchmark_store  # noqa: E402
from auditor.benchmark import (  # noqa: E402
    ManifestError,
    classify_finding,
    compute_metrics,
    evaluate_fixture,
    extract_slugs,
    load_manifest,
    run_benchmark,
    validate_manifest,
)
from auditor.cli import EXIT_ERROR, EXIT_OK, build_parser, main  # noqa: E402
from auditor.model import (  # noqa: E402
    Confidence,
    Epistemic,
    EvidenceItem,
    Finding,
    Severity,
    VerificationStatus,
)

PRODUCTION_DB = PROJECT_ROOT / "audit_scan_history.db"


# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------

def _fixture(fixture_id="F-001", label="vulnerable", category="reentrancy",
             family="reentrancy", accepted=None, evaluable=True,
             contract="Vault", function="withdraw"):
    return {
        "fixture_id": fixture_id,
        "file": f"{fixture_id}.sol",
        "category": category,
        "expected_label": label,
        "expected_contract": contract,
        "expected_function": function,
        "expected_behavior": "synthetic ground truth",
        "accepted_checks": accepted if accepted is not None else ["reentrancy-eth"],
        "analyzer_family": family,
        "compiler": "solc-0.5.8",
        "requires_tools": ["slither", "solc"],
        "evaluable": evaluable,
        "na_reason": None if evaluable else "toolchain detector inoperable",
        "provenance": "synthetic test fixture",
    }


def _fact(source="slither", tool="slither", excerpt="detector output"):
    return EvidenceItem(
        source=source,
        artifact_type="tool_output",
        excerpt=excerpt,
        epistemic=Epistemic.FACT,
        tool=tool,
    )


def _ai_opinion(excerpt="model interpretation"):
    return EvidenceItem(
        source="ollama",
        artifact_type="model_output",
        excerpt=excerpt,
        epistemic=Epistemic.AI_OPINION,
        tool="ollama",
    )


def _finding(slug="reentrancy-eth", contract="Vault", function="withdraw",
             evidence=None, title=None, description=None, facts=True,
             lines=(10, 11)):
    desc = description
    if desc is None:
        desc = (
            f"Slither detector: {slug}. Reentrancy via external call before "
            "state update in Vault.withdraw."
        )
    return Finding(
        title=title or f"Reentrancy vulnerability in {contract}.{function}",
        description=desc,
        category="reentrancy",
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        verification_status=VerificationStatus.UNVERIFIED,
        affected_contract=contract,
        affected_function=function,
        affected_lines=list(lines),
        evidence=([_fact()] if facts and evidence is None else (evidence or [])),
        remediation="Move the state update before the external call.",
    )


def _run_result(status="completed", detectors=None, error=None):
    return SimpleNamespace(
        status=status,
        detectors=detectors,
        error=error,
        failure_note=lambda: (f"slither {error or status}" if status != "completed" else None),
    )


def _synthetic_run(run_id="B-test0000001"):
    row = evaluate_fixture(
        _fixture(),
        [_finding()],
        _run_result(detectors=[{"check": "reentrancy-eth", "description": "x"}]),
    )
    metrics = compute_metrics([row])
    return {
        "run_id": run_id,
        "started_at": "2026-10-13T00:00:00+00:00",
        "finished_at": "2026-10-13T00:00:05+00:00",
        "status": "completed",
        "toolchain": {"slither": {"available": True, "version": "0.11.6"}},
        "totals": {
            "fixtures": 1, "passed": 1, "failed": 0, "blocked": 0,
            "not_evaluable": 0, "skipped": 0, "pipeline_failure": 0,
            "harness_error": 0, "tp": 1, "fp": 0, "fn": 0, "tn": 0,
            "duration_seconds": 1.5,
        },
        "metrics": metrics,
        "notes": [],
        "manifest": str(PROJECT_ROOT / "benchmarks" / "manifest.json"),
        "fixtures_dir": str(PROJECT_ROOT / "benchmarks" / "fixtures"),
        "results": [row],
    }


def _md5(path: Path) -> str:
    return hashlib.md5(path.read_bytes()).hexdigest()


# ---------------------------------------------------------------------------
# Manifest validation
# ---------------------------------------------------------------------------

class ManifestTests(unittest.TestCase):
    def test_real_manifest_is_valid(self):
        manifest = load_manifest()
        fixtures = validate_manifest(manifest)
        # Phase 16 (PROTOCOL.md §10) bumped the manifest to schema v3 / 20;
        # Phase 19 (§11) to schema v4 / 24 (scam_honeypot pairs);
        # Phase 25 added PAUTH-001..008; HONEY-003/004; Phase 26 HONEY-005/006, PAUTH-009/010; Phase 27 PAUTH-011/012; Phase 28 PAUTH-013/014; Phase 32 KX-001..007 → 49.
        self.assertEqual(manifest.get("schema_version"), 4)
        self.assertEqual(len(fixtures), 49)
        ids = [f["fixture_id"] for f in fixtures]
        self.assertEqual(len(set(ids)), len(ids))

    def _base_manifest(self, **overrides):
        entry = _fixture()
        entry.update(overrides)
        return {"schema_version": 1, "fixtures": [entry]}

    def test_missing_required_field_rejected(self):
        with self.assertRaises(ManifestError) as ctx:
            validate_manifest(self._base_manifest(accepted_checks=None))
        self.assertIn("accepted_checks", str(ctx.exception))

    def test_duplicate_fixture_id_rejected(self):
        manifest = self._base_manifest()
        manifest["fixtures"].append(dict(manifest["fixtures"][0]))
        with self.assertRaises(ManifestError) as ctx:
            validate_manifest(manifest)
        self.assertIn("duplicate", str(ctx.exception))

    def test_unknown_category_rejected(self):
        with self.assertRaises(ManifestError):
            validate_manifest(self._base_manifest(category="mint_reentrancy"))

    def test_wrong_label_rejected(self):
        with self.assertRaises(ManifestError):
            validate_manifest(self._base_manifest(expected_label="buggy"))

    def test_not_evaluable_requires_na_reason(self):
        entry = _fixture(evaluable=False)
        entry.pop("na_reason")
        with self.assertRaises(ManifestError) as ctx:
            validate_manifest({"schema_version": 1, "fixtures": [entry]})
        self.assertIn("na_reason", str(ctx.exception))

    def test_missing_manifest_file_rejected(self):
        with self.assertRaises(ManifestError):
            load_manifest(PROJECT_ROOT / "benchmarks" / "does-not-exist.json")

    def test_invalid_json_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            bad = Path(tmp) / "manifest.json"
            bad.write_text("{not json", encoding="utf-8")
            with self.assertRaises(ManifestError):
                load_manifest(bad)

    def test_empty_fixtures_rejected(self):
        with self.assertRaises(ManifestError):
            validate_manifest({"fixtures": []})


# ---------------------------------------------------------------------------
# Matcher (channel + location + FACT evidence)
# ---------------------------------------------------------------------------

class MatcherTests(unittest.TestCase):
    def test_extract_slugs_from_description(self):
        self.assertEqual(
            extract_slugs(_finding(slug="tx-origin")), ["tx-origin"]
        )

    def test_extract_slugs_title_fallback(self):
        f = _finding(
            slug=None,
            description="No detector note here.",
            title="unchecked-lowlevel in Vault.withdraw",
        )
        self.assertEqual(extract_slugs(f), ["unchecked-lowlevel"])

    def test_extract_slugs_multi_note_description(self):
        f = _finding(
            description=(
                "Slither detector: reentrancy-eth. Also "
                "Slither detector: reentrancy-no-eth. State updated late."
            )
        )
        self.assertEqual(extract_slugs(f), ["reentrancy-eth", "reentrancy-no-eth"])

    def test_channel_location_fact_match_is_tp(self):
        row = evaluate_fixture(
            _fixture(), [_finding()],
            _run_result(detectors=[{"check": "reentrancy-eth"}]),
        )
        self.assertEqual(row["status"], "passed")
        self.assertEqual(row["verdict"], "TP")
        self.assertEqual(row["matched_check"], "reentrancy-eth")
        self.assertIsNotNone(row["evidence"])
        self.assertEqual(row["evidence"]["facts"], 1)
        self.assertIn("static-analysis", row["evidence"]["provenance"])

    def test_safe_with_matching_finding_is_fp(self):
        row = evaluate_fixture(
            _fixture(label="safe"), [_finding()],
            _run_result(detectors=[{"check": "reentrancy-eth"}]),
        )
        self.assertEqual(row["status"], "failed")
        self.assertEqual(row["verdict"], "FP")

    def test_vulnerable_without_finding_is_fn(self):
        row = evaluate_fixture(
            _fixture(), [], _run_result(detectors=[]),
        )
        self.assertEqual(row["status"], "failed")
        self.assertEqual(row["verdict"], "FN")

    def test_safe_without_finding_is_tn(self):
        row = evaluate_fixture(
            _fixture(label="safe"), [], _run_result(detectors=[]),
        )
        self.assertEqual(row["status"], "passed")
        self.assertEqual(row["verdict"], "TN")

    def test_channel_mismatch_is_not_matched(self):
        row = evaluate_fixture(
            _fixture(), [_finding(slug="tx-origin")],
            _run_result(detectors=[{"check": "tx-origin"}]),
        )
        self.assertIsNone(row["matched_check"])
        self.assertEqual(len(row["other_findings"]), 1)
        self.assertEqual(
            row["other_findings"][0]["not_matched_because"], "channel_mismatch"
        )
        # vulnerable fixture with no match → FN, not an invented match
        self.assertEqual(row["verdict"], "FN")

    def test_wrong_location_is_not_matched(self):
        row = evaluate_fixture(
            _fixture(),
            [_finding(contract="Other", function="withdraw")],
            _run_result(detectors=[{"check": "reentrancy-eth"}]),
        )
        self.assertIsNone(row["matched_check"])
        self.assertEqual(
            row["other_findings"][0]["not_matched_because"], "wrong_location"
        )
        self.assertEqual(row["verdict"], "FN")

    def test_fact_evidence_required(self):
        ai_only = _finding(evidence=[_ai_opinion()])
        cls = classify_finding(ai_only, _fixture())
        self.assertTrue(cls["in_channel"])
        self.assertTrue(cls["location_ok"])
        self.assertFalse(cls["evidence_ok"])
        self.assertFalse(cls["matched"])
        row = evaluate_fixture(_fixture(), [ai_only], _run_result(detectors=[]))
        self.assertIsNone(row["matched_check"])
        self.assertEqual(row["evidence_insufficient"], 1)
        self.assertEqual(
            row["other_findings"][0]["not_matched_because"], "no_fact_evidence"
        )
        self.assertEqual(row["verdict"], "FN")

    def test_fact_plus_ai_evidence_matches(self):
        both = _finding(evidence=[_fact(), _ai_opinion()])
        row = evaluate_fixture(_fixture(), [both], _run_result(detectors=[]))
        self.assertEqual(row["verdict"], "TP")
        self.assertEqual(row["evidence"]["facts"], 1)
        self.assertEqual(row["evidence"]["ai_opinions"], 1)

    def test_family_fallback_when_slug_missing_counts_gap(self):
        no_note = _finding(
            description="External call before state update.",
            title="Reentrancy vulnerability in Vault.withdraw",
        )
        self.assertEqual(extract_slugs(no_note), [])
        row = evaluate_fixture(_fixture(), [no_note], _run_result(detectors=[]))
        self.assertEqual(row["verdict"], "TP")
        self.assertEqual(row["metadata_gaps"], 1)

    def test_any_accepted_slug_matches(self):
        desc = (
            "Slither detector: reentrancy-no-eth. Also "
            "Slither detector: reentrancy-eth. State updated late."
        )
        f = _finding(description=desc)
        row = evaluate_fixture(
            _fixture(accepted=["reentrancy-eth"]), [f],
            _run_result(detectors=[]),
        )
        self.assertEqual(row["matched_check"], "reentrancy-eth")

    def test_additional_match_recorded_not_silently_dropped(self):
        row = evaluate_fixture(
            _fixture(accepted=["reentrancy-eth", "reentrancy-no-eth"]),
            [_finding(), _finding(slug="reentrancy-no-eth")],
            _run_result(detectors=[]),
        )
        self.assertEqual(row["verdict"], "TP")
        self.assertEqual(len(row["other_findings"]), 1)
        self.assertEqual(
            row["other_findings"][0]["not_matched_because"], "additional_match"
        )


# ---------------------------------------------------------------------------
# Outcome taxonomy (PROTOCOL §4)
# ---------------------------------------------------------------------------

class OutcomeTaxonomyTests(unittest.TestCase):
    def test_tool_missing_is_blocked_not_tn(self):
        row = evaluate_fixture(
            _fixture(label="safe"), [],
            _run_result(status="not_found", error="slither is not available"),
        )
        self.assertEqual(row["status"], "blocked")
        self.assertIsNone(row["verdict"])
        self.assertIn("tool/compiler failure", row["reason"])
        metrics = compute_metrics([row])
        self.assertEqual(metrics["overall"]["blocked"], 1)
        self.assertEqual(metrics["overall"]["tn"], 0)
        self.assertEqual(metrics["overall"]["fn"], 0)

    def test_completed_without_json_is_blocked(self):
        row = evaluate_fixture(_fixture(), [], _run_result(detectors=None))
        self.assertEqual(row["status"], "blocked")
        self.assertIsNone(row["verdict"])
        self.assertIn("JSON report", row["reason"])

    def test_not_evaluable_is_never_scored(self):
        fixture = _fixture(label="vulnerable", evaluable=False)
        row = evaluate_fixture(fixture, [], _run_result(detectors=[]))
        self.assertEqual(row["status"], "not_evaluable")
        self.assertIsNone(row["verdict"])
        metrics = compute_metrics([row])
        self.assertEqual(metrics["overall"]["not_evaluable"], 1)
        self.assertEqual(metrics["overall"]["fn"], 0)
        self.assertEqual(metrics["overall"]["tp"], 0)

    def test_skipped_fixture_when_file_missing(self):
        row = evaluate_fixture(_fixture(), [], None, file_exists=False)
        self.assertEqual(row["status"], "skipped")
        self.assertIsNone(row["verdict"])

    def test_harness_error_captured(self):
        row = evaluate_fixture(
            _fixture(), [], None, error="RuntimeError: boom",
        )
        self.assertEqual(row["status"], "harness_error")
        self.assertIsNone(row["verdict"])
        self.assertIn("boom", row["reason"])

    def test_pipeline_failure_is_not_fn(self):
        raw = [{"check": "reentrancy-eth",
                "description": "Reentrancy in Vault.withdraw (lines 10-11)."}]
        row = evaluate_fixture(_fixture(), [], _run_result(detectors=raw))
        self.assertEqual(row["status"], "pipeline_failure")
        self.assertIsNone(row["verdict"])
        self.assertEqual(row["raw_unsurfaced_hits"], 1)
        metrics = compute_metrics([row])
        self.assertEqual(metrics["overall"]["pipeline_failure"], 1)
        self.assertEqual(metrics["overall"]["fn"], 0)

    def test_safe_fixture_with_unsurfaced_raw_hit_stays_tn_with_note(self):
        raw = [{"check": "reentrancy-eth",
                "description": "Reentrancy in Vault.withdraw (lines 10-11)."}]
        row = evaluate_fixture(
            _fixture(label="safe"), [], _run_result(detectors=raw)
        )
        self.assertEqual(row["status"], "passed")
        self.assertEqual(row["verdict"], "TN")
        self.assertEqual(row["raw_unsurfaced_hits"], 1)
        self.assertIn("not surfaced", row["reason"])


# ---------------------------------------------------------------------------
# Metrics (PROTOCOL §6)
# ---------------------------------------------------------------------------

class MetricsTests(unittest.TestCase):
    def _rows(self, verdicts):
        out = []
        for v in verdicts:
            out.append({"category": "reentrancy", "status":
                        "passed" if v in ("TP", "TN") else "failed",
                        "verdict": v, "other_findings": []})
        return out

    def test_zero_denominators_return_null(self):
        metrics = compute_metrics([])
        overall = metrics["overall"]
        self.assertIsNone(overall["precision"])
        self.assertIsNone(overall["recall"])
        self.assertIsNone(overall["f1"])
        self.assertEqual(overall["tp"], 0)

    def test_precision_null_when_no_predicted_positives(self):
        overall = compute_metrics(self._rows(["FN", "TN"]))["overall"]
        self.assertIsNone(overall["precision"])
        self.assertEqual(overall["recall"], 0.0)

    def test_recall_null_when_no_actual_positives(self):
        overall = compute_metrics(self._rows(["FP", "TN"]))["overall"]
        self.assertIsNone(overall["recall"])
        self.assertEqual(overall["precision"], 0.0)

    def test_f1_null_when_no_tp_and_no_predictions(self):
        overall = compute_metrics(self._rows(["TN"]))["overall"]
        self.assertIsNone(overall["f1"])

    def test_full_scores(self):
        overall = compute_metrics(self._rows(["TP", "TP", "FP", "FN"]))["overall"]
        self.assertAlmostEqual(overall["precision"], 2 / 3)
        self.assertAlmostEqual(overall["recall"], 2 / 3)
        # F1 = 2TP / (2TP + FP + FN) = 4 / (4 + 1 + 1)
        self.assertAlmostEqual(overall["f1"], 2 / 3)

    def test_per_category_nulls_for_na_category(self):
        rows = [
            {"category": "privileged_change", "status": "not_evaluable",
             "verdict": None, "other_findings": []},
            {"category": "reentrancy", "status": "passed",
             "verdict": "TP", "other_findings": []},
        ]
        metrics = compute_metrics(rows)
        priv = metrics["categories"]["privileged_change"]
        self.assertEqual(priv["evaluable"], 0)
        self.assertIsNone(priv["precision"])
        self.assertIsNone(priv["recall"])
        self.assertIsNone(priv["f1"])
        self.assertEqual(metrics["categories"]["reentrancy"]["tp"], 1)


# ---------------------------------------------------------------------------
# Dedicated benchmark store
# ---------------------------------------------------------------------------

class StoreTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="bench-store-test-")
        self._db = Path(self._tmp.name) / "benchmark_store.db"
        self._env = mock.patch.dict(
            os.environ, {"AUDITOR_BENCHMARK_DB": str(self._db)}
        )
        self._env.start()

    def tearDown(self):
        self._env.stop()
        self._tmp.cleanup()

    def test_env_override_resolves(self):
        self.assertEqual(benchmark_store.default_benchmark_db_path(), self._db)
        self.assertNotEqual(self._db.name, "audit_scan_history.db")

    def test_open_store_rejects_production_name(self):
        with self.assertRaises(ValueError):
            benchmark_store.open_store(Path("/tmp/audit_scan_history.db"))

    def test_roundtrip_latest_list_get(self):
        run_a = _synthetic_run("B-run-aaaa")
        run_b = _synthetic_run("B-run-bbbb")
        run_b["started_at"] = "2026-10-13T01:00:00+00:00"
        run_b["finished_at"] = "2026-10-13T01:00:05+00:00"
        conn = benchmark_store.open_store()
        try:
            benchmark_store.save_run(conn, run_a)
            benchmark_store.save_run(conn, run_b)
            latest = benchmark_store.get_latest(conn)
            self.assertEqual(latest["run_id"], "B-run-bbbb")
            self.assertEqual(len(latest["results"]), 1)
            self.assertEqual(latest["results"][0]["verdict"], "TP")
            listing = benchmark_store.list_runs(conn)
            self.assertEqual([r["run_id"] for r in listing],
                             ["B-run-bbbb", "B-run-aaaa"])
            detail = benchmark_store.get_run(conn, "B-run-aaaa")
            self.assertEqual(detail["run_id"], "B-run-aaaa")
            self.assertIsNone(benchmark_store.get_run(conn, "B-nope"))
        finally:
            conn.close()

    def test_store_path_is_never_production_history(self):
        resolved = benchmark_store.default_benchmark_db_path().resolve()
        self.assertNotEqual(resolved, PRODUCTION_DB.resolve())
        self.assertEqual(resolved.name, "benchmark_store.db")


# ---------------------------------------------------------------------------
# run_benchmark orchestration (stub runner — no Slither in tests)
# ---------------------------------------------------------------------------

class RunBenchmarkTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="bench-run-test-")
        self._root = Path(self._tmp.name)
        self._fixtures = self._root / "fixtures"
        self._fixtures.mkdir()
        (self._fixtures / "F-001.sol").write_text(
            "// fixture\ncontract Vault { function withdraw() external {} }\n",
            encoding="utf-8",
        )
        self._manifest = self._root / "manifest.json"
        self._manifest.write_text(
            json.dumps({"schema_version": 1, "fixtures": [_fixture()]}),
            encoding="utf-8",
        )
        self._db = self._root / "benchmark_store.db"
        self._env = mock.patch.dict(
            os.environ, {"AUDITOR_BENCHMARK_DB": str(self._db)}
        )
        self._env.start()

    def tearDown(self):
        self._env.stop()
        self._tmp.cleanup()

    def test_run_benchmark_saves_to_benchmark_db_only(self):
        def runner(fixture, fixtures_dir):
            return evaluate_fixture(fixture, [_finding()], _run_result(detectors=[]))

        run = run_benchmark(
            manifest_path=self._manifest,
            fixtures_dir=self._fixtures,
            save=True,
            runner=runner,
        )
        self.assertEqual(run["status"], "completed")
        self.assertEqual(run["totals"]["tp"], 1)
        self.assertTrue(self._db.exists())
        self.assertEqual(
            benchmark_store.default_benchmark_db_path(), self._db
        )
        conn = benchmark_store.open_store()
        try:
            stored = benchmark_store.get_latest(conn)
            self.assertEqual(stored["run_id"], run["run_id"])
            self.assertEqual(stored["results"][0]["verdict"], "TP")
        finally:
            conn.close()

    def test_missing_fixture_file_becomes_skipped(self):
        manifest = json.loads(self._manifest.read_text(encoding="utf-8"))
        manifest["fixtures"][0]["file"] = "GONE.sol"
        self._manifest.write_text(json.dumps(manifest), encoding="utf-8")

        # runner defaults to the real run_fixture, which detects the missing
        # file before any tool is invoked (no Slither needed).
        run = run_benchmark(
            manifest_path=self._manifest,
            fixtures_dir=self._fixtures,
            save=False,
        )
        self.assertEqual(run["results"][0]["status"], "skipped")
        self.assertIsNone(run["results"][0]["verdict"])
        self.assertEqual(run["status"], "completed_with_errors")

    def test_manifest_error_propagates(self):
        bad = self._root / "bad.json"
        bad.write_text(json.dumps({"fixtures": []}), encoding="utf-8")
        with self.assertRaises(ManifestError):
            run_benchmark(manifest_path=bad, save=False)

    def test_limit_slices_fixtures(self):
        manifest = json.loads(self._manifest.read_text(encoding="utf-8"))
        second = dict(manifest["fixtures"][0])
        second["fixture_id"] = "F-002"
        manifest["fixtures"].append(second)
        self._manifest.write_text(json.dumps(manifest), encoding="utf-8")
        run = run_benchmark(
            manifest_path=self._manifest,
            fixtures_dir=self._fixtures,
            save=False,
            limit=1,
            runner=lambda f, d: evaluate_fixture(f, [], _run_result(detectors=[])),
        )
        self.assertEqual(len(run["results"]), 1)


# ---------------------------------------------------------------------------
# CLI dispatch
# ---------------------------------------------------------------------------

class CliTests(unittest.TestCase):
    def test_benchmark_subparser_registered_without_fail_on(self):
        parser = build_parser()
        args = parser.parse_args(["benchmark", "--no-save", "--limit", "1"])
        self.assertEqual(args.command, "benchmark")
        self.assertTrue(args.no_save)
        self.assertEqual(args.limit, 1)
        self.assertFalse(hasattr(args, "fail_on"))
        # --fail-on belongs to scan commands only; argparse must reject it
        # on benchmark with its standard usage error (exit 2).
        with self.assertRaises(SystemExit) as ctx:
            parser.parse_args(["benchmark", "--fail-on", "HIGH"])
        self.assertEqual(ctx.exception.code, 2)

    def test_benchmark_json_success_exit_0(self):
        run = _synthetic_run()
        buf = io.StringIO()
        with mock.patch("auditor.benchmark.run_benchmark", return_value=run):
            with contextlib.redirect_stdout(buf):
                code = main(["benchmark", "--json"])
        self.assertEqual(code, EXIT_OK)
        payload = json.loads(buf.getvalue())
        self.assertEqual(payload["run_id"], "B-test0000001")
        self.assertEqual(payload["results"][0]["verdict"], "TP")

    def test_benchmark_text_success_exit_0(self):
        run = _synthetic_run()
        buf = io.StringIO()
        with mock.patch("auditor.benchmark.run_benchmark", return_value=run):
            with contextlib.redirect_stdout(buf):
                code = main(["benchmark", "--no-save"])
        self.assertEqual(code, EXIT_OK)
        out = buf.getvalue()
        self.assertIn("verdicts: TP=1 FP=0 FN=0 TN=0", out)
        self.assertIn("precision=1.000", out)
        self.assertIn("store: not saved", out)

    def test_benchmark_manifest_error_exit_1(self):
        buf = io.StringIO()
        with mock.patch(
            "auditor.benchmark.run_benchmark",
            side_effect=ManifestError("manifest validation failed: boom"),
        ):
            with contextlib.redirect_stdout(buf):
                with contextlib.redirect_stderr(io.StringIO()) as err:
                    code = main(["benchmark"])
        self.assertEqual(code, EXIT_ERROR)
        self.assertIn("manifest validation failed", err.getvalue())

    def test_metric_formatting_null_renders_na(self):
        from auditor.cli import _fmt_metric
        self.assertEqual(_fmt_metric(None), "n/a")
        self.assertEqual(_fmt_metric(0.5), "0.500")


# ---------------------------------------------------------------------------
# Dashboard endpoints (empty + populated)
# ---------------------------------------------------------------------------

class _DashboardBenchCase(unittest.TestCase):
    client = None
    _tmp = None

    @classmethod
    def setUpClass(cls):
        from fastapi.testclient import TestClient
        from auditor.dashboard.app import create_app

        cls._tmp = tempfile.TemporaryDirectory(prefix="bench-dash-test-")
        root = Path(cls._tmp.name)
        os.environ["AUDITOR_HISTORY_DB"] = str(root / "history.db")
        os.environ["AUDITOR_BENCHMARK_DB"] = str(root / "benchmark_store.db")
        cls.bench_db = root / "benchmark_store.db"
        cls.client = TestClient(create_app())
        cls.client.__enter__()

    @classmethod
    def tearDownClass(cls):
        if cls.client is not None:
            cls.client.__exit__(None, None, None)
        os.environ.pop("AUDITOR_HISTORY_DB", None)
        os.environ.pop("AUDITOR_BENCHMARK_DB", None)
        if cls._tmp is not None:
            cls._tmp.cleanup()


class DashboardBenchmarkEmptyTests(_DashboardBenchCase):
    def test_page_renders(self):
        res = self.client.get("/benchmark")
        self.assertEqual(res.status_code, 200)
        self.assertIn("bench-content", res.text)
        self.assertIn("Vulnerability Detection Benchmark", res.text)

    def test_latest_empty_state(self):
        res = self.client.get("/api/benchmark/latest")
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json(), {"status": "empty"})

    def test_runs_empty_state(self):
        res = self.client.get("/api/benchmark/runs")
        self.assertEqual(res.status_code, 200)
        body = res.json()
        self.assertEqual(body["status"], "empty")
        self.assertEqual(body["runs"], [])

    def test_unknown_run_is_404(self):
        res = self.client.get("/api/benchmark/runs/B-does-not-exist")
        self.assertEqual(res.status_code, 404)

    def test_empty_state_does_not_create_db_file(self):
        self.assertFalse(self.bench_db.exists())


class DashboardBenchmarkPopulatedTests(_DashboardBenchCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        run = _synthetic_run("B-dash0000001")
        conn = benchmark_store.open_store(cls.bench_db)
        try:
            benchmark_store.save_run(conn, run)
        finally:
            conn.close()

    def test_latest_returns_full_run(self):
        res = self.client.get("/api/benchmark/latest")
        self.assertEqual(res.status_code, 200)
        body = res.json()
        self.assertEqual(body["run_id"], "B-dash0000001")
        self.assertEqual(body["status"], "completed")
        self.assertEqual(body["metrics"]["overall"]["precision"], 1.0)
        self.assertEqual(len(body["results"]), 1)
        self.assertEqual(body["results"][0]["verdict"], "TP")
        self.assertTrue(body["store"].endswith("benchmark_store.db"))
        self.assertNotIn("audit_scan_history.db", body["store"])

    def test_runs_listing(self):
        res = self.client.get("/api/benchmark/runs")
        self.assertEqual(res.status_code, 200)
        body = res.json()
        self.assertEqual(body["status"], "ok")
        self.assertEqual([r["run_id"] for r in body["runs"]], ["B-dash0000001"])

    def test_run_detail(self):
        res = self.client.get("/api/benchmark/runs/B-dash0000001")
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()["run_id"], "B-dash0000001")

    def test_run_detail_unknown_404(self):
        res = self.client.get("/api/benchmark/runs/B-nope")
        self.assertEqual(res.status_code, 404)


# ---------------------------------------------------------------------------
# Production database preservation
# ---------------------------------------------------------------------------

class ProductionDbPreservationTests(unittest.TestCase):
    def test_benchmark_write_leaves_production_untouched(self):
        import sys as _sys
        _sys.path.insert(0, str(Path(__file__).resolve().parent))
        from _prod_db_guard import ProdDBWriteGuard
        guard = ProdDBWriteGuard(PRODUCTION_DB).start()
        # Expected stub-run counts derived from the real manifest so fixture
        # additions never require touching this test again.
        manifest = load_manifest()
        expected_fn = sum(
            1 for f in manifest["fixtures"]
            if f.get("evaluable") and f.get("expected_label") == "vulnerable"
        )
        expected_tn = sum(
            1 for f in manifest["fixtures"]
            if f.get("evaluable") and f.get("expected_label") == "safe"
        )
        expected_na = sum(
            1 for f in manifest["fixtures"] if not f.get("evaluable")
        )
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "benchmark_store.db"
            with mock.patch.dict(os.environ, {"AUDITOR_BENCHMARK_DB": str(db)}):
                run = run_benchmark(
                    save=True,
                    runner=lambda f, d: evaluate_fixture(
                        f, [], _run_result(detectors=[])
                    ),
                )
                # Stub runner: vulnerable fixtures score FN, safe score TN,
                # non-evaluable fixtures stay not_evaluable.
                self.assertEqual(run["totals"]["tp"], 0)
                self.assertEqual(run["totals"]["tn"], expected_tn)
                self.assertEqual(run["totals"]["fn"], expected_fn)
                self.assertEqual(run["totals"]["not_evaluable"], expected_na)
                self.assertTrue(db.exists())
                # The benchmark store path must resolve to the override,
                # never to production scan history.
                self.assertEqual(
                    benchmark_store.default_benchmark_db_path(), db
                )
        # In-process write guard; md5 compare raced with the live monitor.
        self.assertEqual(guard.stop(), [], "production scan history opened for writing")

    def test_benchmark_db_name_not_in_history_env_default(self):
        with mock.patch.dict(os.environ, {"AUDITOR_BENCHMARK_DB": ""}):
            path = benchmark_store.default_benchmark_db_path()
            self.assertEqual(path.name, "benchmark_store.db")
            self.assertNotEqual(path.resolve(), PRODUCTION_DB.resolve())


if __name__ == "__main__":
    unittest.main()
