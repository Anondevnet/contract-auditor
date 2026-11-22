"""Phase 15 — benchmark hardening (PROTOCOL.md §9).

Covers: manifest schema_version + source-label consistency (fatal config
defects vs per-fixture skips), independent raw↔surfaced reconciliation
(observation only — never a verdict path), toolchain/corpus fingerprints,
baseline comparison with like-for-like suppression and regression
definitions, the single-baseline store invariant with PRAGMA-guarded
migration, CLI gates (`--baseline`, `--set-baseline`, `--force`) with
fail-closed exit codes and parseable JSON stdout, dashboard
baseline/compare endpoints, normalized determinism fingerprints, and
production scan-history preservation.

No test runs Slither: the harness is exercised with stub runs and stub
runners, benchmark persistence always writes to a temporary database under
``AUDITOR_BENCHMARK_DB``, and the production ``audit_scan_history.db`` hash
is asserted unchanged.
"""

from __future__ import annotations

import contextlib
import hashlib
import io
import json
import os
import sqlite3
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
    CATEGORIES,
    ManifestError,
    aggregate_reconciliation,
    compare_runs,
    corpus_fingerprint,
    evaluate_fixture,
    load_manifest,
    normalized_run_fingerprint,
    reconcile_raw,
    run_benchmark,
    toolchain_fingerprint,
    validate_manifest,
)
from auditor.cli import EXIT_ERROR, EXIT_OK, main  # noqa: E402
from auditor.model import (  # noqa: E402
    Confidence,
    Epistemic,
    EvidenceItem,
    Finding,
    Severity,
    VerificationStatus,
)

def _find_production_db():
    """Locate the production DB; in a git worktree it lives in the main checkout."""
    local = PROJECT_ROOT / "audit_scan_history.db"
    import subprocess
    try:
        common = subprocess.run(
            ["git", "rev-parse", "--path-format=absolute", "--git-common-dir"],
            cwd=PROJECT_ROOT, capture_output=True, text=True, check=True,
        ).stdout.strip()
        # Prefer the main checkout's DB: a worktree can hold its own
        # scratch history DB from local scans, which is not production.
        main = Path(common).parent / "audit_scan_history.db"
        if main.exists():
            return main
    except Exception:
        pass
    return local


PRODUCTION_DB = _find_production_db()


# ---------------------------------------------------------------------------
# Local helpers (kept independent of other test modules)
# ---------------------------------------------------------------------------

def _fact(source="slither", tool="slither", excerpt="detector output"):
    return EvidenceItem(
        source=source,
        artifact_type="tool_output",
        excerpt=excerpt,
        epistemic=Epistemic.FACT,
        tool=tool,
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
        "provenance": "synthetic fixture for tests",
    }


def _row(fixture_id="F-001", status="passed", verdict="TP", category="reentrancy",
         expected_label="vulnerable", matched_check="reentrancy-eth",
         other=None, reason=None, reconciliation=None):
    row = {
        "fixture_id": fixture_id,
        "category": category,
        "expected_label": expected_label,
        "status": status,
        "verdict": verdict,
        "matched_check": matched_check,
        "other_findings": other if other is not None else [],
        "reason": reason,
    }
    if reconciliation is not None:
        row["reconciliation"] = reconciliation
    return row


def _run(run_id="B-current", rows=None, overall=None, corpus="corpus-fp-a",
         slither="0.11.6", status="completed",
         started="2026-10-13T00:00:00+00:00",
         finished="2026-10-13T00:00:05+00:00",
         duration=1.5, toolchain_fp="tc-fp", reconciliation=None):
    rows = rows if rows is not None else [_row()]
    overall = overall if overall is not None else {
        "precision": 1.0, "recall": 1.0, "f1": 1.0,
        "tp": 1, "fp": 0, "fn": 0, "tn": 0,
        "fixtures": len(rows),
    }
    return {
        "run_id": run_id,
        "started_at": started,
        "finished_at": finished,
        "status": status,
        "toolchain": {"slither": {"available": True, "version": slither}},
        "toolchain_fingerprint": toolchain_fp,
        "corpus_fingerprint": corpus,
        "totals": {
            "fixtures": len(rows), "skipped": 0, "harness_error": 0,
            "duration_seconds": duration,
        },
        "metrics": {"overall": overall, "categories": {}},
        "reconciliation": reconciliation or {"fixtures": 0, "discrepancies": 0},
        "notes": [],
        "results": rows,
    }


def _md5(path: Path) -> str:
    return hashlib.md5(path.read_bytes()).hexdigest()


# ---------------------------------------------------------------------------
# Manifest schema_version + categories (PROTOCOL §9.1/§9.2)
# ---------------------------------------------------------------------------

class ManifestSchemaTests(unittest.TestCase):
    def test_schema_version_required(self):
        with self.assertRaises(ManifestError) as ctx:
            validate_manifest({"fixtures": [_fixture()]})
        self.assertIn("schema_version", str(ctx.exception))

    def test_schema_version_must_be_supported(self):
        with self.assertRaises(ManifestError) as ctx:
            validate_manifest({"schema_version": 99, "fixtures": [_fixture()]})
        self.assertIn("schema_version", str(ctx.exception))

    def test_schema_version_one_and_two_accepted(self):
        for version in (1, 2, 3):
            fixtures = validate_manifest(
                {"schema_version": version, "fixtures": [_fixture()]}
            )
            self.assertEqual(len(fixtures), 1)

    def test_real_manifest_is_schema_v2_with_new_categories(self):
        manifest = load_manifest()
        fixtures = validate_manifest(manifest)
        self.assertGreaterEqual(manifest["schema_version"], 2)
        self.assertGreaterEqual(len(fixtures), 18)
        self.assertIn("delegatecall", CATEGORIES)
        self.assertIn("arbitrary_transfer", CATEGORIES)
        categories = {f["category"] for f in fixtures}
        self.assertLessEqual({"delegatecall", "arbitrary_transfer"}, categories)


class SourceConsistencyTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="p15-source-")
        self._root = Path(self._tmp.name)
        self._fixtures = self._root / "fixtures"
        self._fixtures.mkdir()
        (self._fixtures / "F-001.sol").write_text(
            "// fixture\ncontract Vault { function withdraw() external {} }\n",
            encoding="utf-8",
        )
        self._manifest_path = self._root / "manifest.json"

    def tearDown(self):
        self._tmp.cleanup()

    def _write(self, entry_overrides=None, evaluable=True, write_file=True):
        if not write_file and (self._fixtures / "F-001.sol").exists():
            (self._fixtures / "F-001.sol").unlink()
        entry = _fixture(evaluable=evaluable)
        entry.update(entry_overrides or {})
        manifest = {"schema_version": 2, "fixtures": [entry]}
        self._manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        manifest["_manifest_path"] = str(self._manifest_path)
        return manifest

    def test_contract_typo_is_fatal(self):
        manifest = self._write({"expected_contract": "NoSuchContract"})
        with self.assertRaises(ManifestError) as ctx:
            validate_manifest(manifest)
        self.assertIn("source-label inconsistency", str(ctx.exception))
        self.assertIn("NoSuchContract", str(ctx.exception))

    def test_function_typo_is_fatal(self):
        manifest = self._write({"expected_function": "noSuchFunction"})
        with self.assertRaises(ManifestError) as ctx:
            validate_manifest(manifest)
        self.assertIn("source-label inconsistency", str(ctx.exception))

    def test_matching_labels_validate(self):
        manifest = self._write()
        self.assertEqual(len(validate_manifest(manifest)), 1)

    def test_missing_fixture_file_is_not_fatal(self):
        # Missing file stays a per-fixture 'skipped' at run time (§4).
        manifest = self._write(write_file=False)
        self.assertEqual(len(validate_manifest(manifest)), 1)

    def test_not_evaluable_fixture_is_not_source_checked(self):
        manifest = self._write(
            {"expected_contract": "DoesNotExist"}, evaluable=False
        )
        self.assertEqual(len(validate_manifest(manifest)), 1)


# ---------------------------------------------------------------------------
# Raw ↔ surfaced reconciliation (PROTOCOL §9.3) — observation, not verdict
# ---------------------------------------------------------------------------

class ReconcileRawTests(unittest.TestCase):
    def test_surfaced_detector(self):
        fixture = _fixture()
        finding = _finding(slug="reentrancy-eth")
        run = _run_result(detectors=[{"check": "reentrancy-eth", "impact": "High"}])
        rec = reconcile_raw(fixture, run, [finding])
        self.assertEqual(rec["surfaced"], 1)
        self.assertEqual(rec["missing"], [])
        self.assertEqual(rec["discrepancies"], 0)

    def test_informational_detector_is_policy_excluded(self):
        fixture = _fixture()
        run = _run_result(detectors=[
            {"check": "solc-version", "impact": "Informational"},
            {"check": "low-level-calls", "impact": "Informational"},
        ])
        rec = reconcile_raw(fixture, run, [])
        self.assertEqual(rec["excluded_informational"], 2)
        self.assertEqual(rec["missing"], [])
        self.assertEqual(rec["discrepancies"], 0)

    def test_missing_non_informational_detector(self):
        fixture = _fixture()
        run = _run_result(detectors=[{"check": "tx-origin", "impact": "Medium"}])
        rec = reconcile_raw(fixture, run, [])
        self.assertEqual(rec["missing"], ["tx-origin"])
        self.assertEqual(rec["discrepancies"], 1)

    def test_surfaced_without_raw(self):
        fixture = _fixture()
        finding = _finding(slug="tx-origin")
        run = _run_result(detectors=[])
        rec = reconcile_raw(fixture, run, [finding])
        self.assertEqual(rec["surfaced_without_raw"], ["tx-origin"])
        self.assertEqual(rec["discrepancies"], 1)

    def test_no_run_recorded(self):
        rec = reconcile_raw(_fixture(), None, [])
        self.assertEqual(rec["raw_status"], "not_run")
        self.assertEqual(rec["raw_detectors"], 0)

    def test_reconciliation_never_changes_the_verdict(self):
        # A surfaced finding still scores TP even when the raw report shows
        # nothing at all (raw emission alone is never proof either way).
        fixture = _fixture()
        finding = _finding(slug="reentrancy-eth")
        row = evaluate_fixture(fixture, [finding], _run_result(detectors=[]))
        rec = reconcile_raw(fixture, _run_result(detectors=[]), [finding])
        self.assertEqual(row["verdict"], "TP")
        self.assertEqual(rec["surfaced_without_raw"], ["reentrancy-eth"])
        self.assertGreater(rec["discrepancies"], 0)
        self.assertEqual(row["verdict"], "TP")

    def test_aggregate_sums_and_skips_rows_without_reconciliation(self):
        rows = [
            {"fixture_id": "A", "reconciliation": {
                "fixture_id": "A", "raw_status": "completed", "surfaced": 1,
                "excluded_informational": 1, "missing": ["tx-origin"],
                "surfaced_without_raw": [], "discrepancies": 1,
            }},
            {"fixture_id": "B"},  # stub runner row — no reconciliation block
            {"fixture_id": "C", "reconciliation": {
                "fixture_id": "C", "raw_status": "blocked", "surfaced": 0,
                "excluded_informational": 0, "missing": [],
                "surfaced_without_raw": ["suicidal"], "discrepancies": 1,
            }},
        ]
        agg = aggregate_reconciliation(rows)
        self.assertEqual(agg["fixtures"], 2)
        self.assertEqual(agg["surfaced"], 1)
        self.assertEqual(agg["excluded_informational"], 1)
        self.assertEqual(agg["missing"], ["A:tx-origin"])
        self.assertEqual(agg["surfaced_without_raw"], ["C:suicidal"])
        self.assertEqual(agg["discrepancies"], 2)
        self.assertEqual(agg["raw_status_counts"],
                         {"blocked": 1, "completed": 1})
        self.assertEqual(set(agg["details"]), {"A", "C"})


# ---------------------------------------------------------------------------
# Fingerprints (PROTOCOL §9.6)
# ---------------------------------------------------------------------------

class FingerprintTests(unittest.TestCase):
    def test_toolchain_fingerprint_stable_and_version_sensitive(self):
        a = toolchain_fingerprint({"slither": {"available": True, "version": "0.11.6"}})
        b = toolchain_fingerprint({"slither": {"available": True, "version": "0.11.6"}})
        c = toolchain_fingerprint({"slither": {"available": True, "version": "0.10.0"}})
        self.assertEqual(a, b)
        self.assertNotEqual(a, c)

    def test_toolchain_fingerprint_unavailable_when_no_tools(self):
        self.assertEqual(
            toolchain_fingerprint({}), toolchain_fingerprint({"slither": {"available": False}})
        )
        self.assertNotEqual(toolchain_fingerprint({}),
                            toolchain_fingerprint({"slither": {"available": True, "version": "1"}}))

    def test_corpus_fingerprint_detects_label_and_channel_changes(self):
        base = [_fixture(), _fixture(fixture_id="F-002", label="safe")]
        same = [_fixture(fixture_id="F-002", label="safe"), _fixture()]  # order-insensitive
        self.assertEqual(corpus_fingerprint(base), corpus_fingerprint(same))

        relabeled = [_fixture(), _fixture(fixture_id="F-002", label="vulnerable")]
        self.assertNotEqual(corpus_fingerprint(base), corpus_fingerprint(relabeled))

        rechannelled = [_fixture(accepted=["tx-origin"]),
                        _fixture(fixture_id="F-002", label="safe")]
        self.assertNotEqual(corpus_fingerprint(base), corpus_fingerprint(rechannelled))


# ---------------------------------------------------------------------------
# Baseline comparison (PROTOCOL §9.6)
# ---------------------------------------------------------------------------

class CompareRunsTests(unittest.TestCase):
    def test_identical_runs_are_comparable_without_regressions(self):
        cmp = compare_runs(_run(), _run(run_id="B-base"))
        self.assertTrue(cmp["comparable"])
        self.assertTrue(cmp["toolchain_match"])
        self.assertTrue(cmp["corpus_match"])
        self.assertEqual(cmp["verdict_changes"], [])
        self.assertEqual(cmp["regressions"], [])

    def test_verdict_downgrade_is_a_regression(self):
        current = _run(rows=[_row(status="failed", verdict="FN", matched_check=None)])
        baseline = _run(run_id="B-base", rows=[_row(verdict="TP")])
        cmp = compare_runs(current, baseline)
        self.assertTrue(cmp["comparable"])
        self.assertEqual(cmp["verdict_changes"],
                         [{"fixture_id": "F-001", "from": "TP", "to": "FN",
                           "regression": True}])
        self.assertTrue(any("F-001" in r for r in cmp["regressions"]))

    def test_safe_to_false_positive_is_a_regression(self):
        current = _run(rows=[_row(fixture_id="F-001", status="failed",
                                 verdict="FP", expected_label="safe")])
        baseline = _run(run_id="B-base", rows=[
            _row(fixture_id="F-001", verdict="TN", expected_label="safe")
        ])
        cmp = compare_runs(current, baseline)
        self.assertEqual(cmp["verdict_changes"][0]["from"], "TN")
        self.assertEqual(cmp["verdict_changes"][0]["to"], "FP")
        self.assertEqual(len(cmp["regressions"]), 1)

    def test_fn_to_tn_improvement_is_reported_but_not_a_regression(self):
        current = _run(rows=[_row(status="passed", verdict="TN", expected_label="safe")])
        baseline = _run(run_id="B-base", rows=[
            _row(fixture_id="F-001", status="failed", verdict="FN",
                 expected_label="vulnerable", matched_check=None)
        ])
        cmp = compare_runs(current, baseline)
        self.assertTrue(cmp["comparable"])
        self.assertEqual(len(cmp["verdict_changes"]), 1)
        self.assertEqual(cmp["regressions"], [])

    def test_verdict_to_pipeline_failure_is_a_regression(self):
        current = _run(rows=[_row(status="pipeline_failure", verdict=None,
                                 matched_check=None)])
        baseline = _run(run_id="B-base", rows=[_row(verdict="TP")])
        cmp = compare_runs(current, baseline)
        self.assertTrue(any("pipeline_failure" in r for r in cmp["regressions"]))

    def test_metric_decrease_is_a_regression_on_matching_corpus(self):
        current = _run(overall={"precision": 0.75, "recall": 0.5, "f1": 0.6,
                                "tp": 3, "fp": 1, "fn": 3, "tn": 0, "fixtures": 7})
        baseline = _run(run_id="B-base",
                        overall={"precision": 1.0, "recall": 1.0, "f1": 1.0,
                                 "tp": 4, "fp": 0, "fn": 0, "tn": 3, "fixtures": 7})
        cmp = compare_runs(current, baseline)
        self.assertTrue(cmp["comparable"])
        self.assertEqual(cmp["metric_deltas"]["precision"], -0.25)
        self.assertTrue(any(r.startswith("precision:") for r in cmp["regressions"]))
        self.assertTrue(any(r.startswith("recall:") for r in cmp["regressions"]))
        self.assertTrue(any(r.startswith("f1:") for r in cmp["regressions"]))

    def test_toolchain_mismatch_is_not_comparable(self):
        current = _run(slither="0.11.6")
        baseline = _run(run_id="B-base", slither="0.10.0")
        cmp = compare_runs(current, baseline)
        self.assertFalse(cmp["comparable"])
        self.assertIn("toolchain mismatch", cmp["not_comparable_reason"])
        # Judgments suppressed even though the current run is worse.
        current["results"] = [_row(status="failed", verdict="FN", matched_check=None)]
        cmp = compare_runs(current, baseline)
        self.assertEqual(cmp["verdict_changes"], [])
        self.assertEqual(cmp["regressions"], [])

    def test_corpus_mismatch_is_not_comparable(self):
        current = _run(corpus="corpus-fp-a")
        baseline = _run(run_id="B-base", corpus="corpus-fp-b")
        cmp = compare_runs(current, baseline)
        self.assertFalse(cmp["comparable"])
        self.assertTrue(cmp["corpus_changed"])
        self.assertIn("corpus mismatch", cmp["not_comparable_reason"])

    def test_missing_fingerprint_is_not_comparable(self):
        current = _run()
        current["corpus_fingerprint"] = None
        baseline = _run(run_id="B-base")
        cmp = compare_runs(current, baseline)
        self.assertFalse(cmp["comparable"])
        self.assertIn("corpus fingerprint", cmp["not_comparable_reason"])

    def test_added_and_removed_fixtures_listed(self):
        current = _run(rows=[_row(), _row(fixture_id="F-NEW")])
        baseline = _run(run_id="B-base",
                        rows=[_row(), _row(fixture_id="F-GONE")])
        cmp = compare_runs(current, baseline)
        self.assertTrue(cmp["comparable"])
        self.assertEqual(cmp["added_fixtures"], ["F-NEW"])
        self.assertEqual(cmp["removed_fixtures"], ["F-GONE"])


# ---------------------------------------------------------------------------
# Determinism fingerprints (PROTOCOL §9.5)
# ---------------------------------------------------------------------------

class NormalizedFingerprintTests(unittest.TestCase):
    def test_unstable_fields_are_ignored(self):
        a = _run(run_id="B-one", started="2026-10-13T00:00:00+00:00",
                 finished="2026-10-13T00:00:05+00:00", duration=1.5)
        b = _run(run_id="B-two", started="2026-10-14T09:00:00+00:00",
                 finished="2026-10-14T09:00:55+00:00", duration=55.0)
        self.assertEqual(normalized_run_fingerprint(a),
                         normalized_run_fingerprint(b))

    def test_verdict_change_changes_fingerprint(self):
        a = _run(rows=[_row(verdict="TP")])
        b = _run(rows=[_row(status="failed", verdict="FN", matched_check=None)])
        self.assertNotEqual(normalized_run_fingerprint(a),
                            normalized_run_fingerprint(b))

    def test_evidence_payloads_are_excluded(self):
        a = _run()
        b = _run()
        b["results"][0] = dict(b["results"][0])
        b["results"][0]["evidence"] = {"finding_id": "random-uuid-1"}
        a["results"][0] = dict(a["results"][0])
        a["results"][0]["evidence"] = {"finding_id": "random-uuid-2"}
        self.assertEqual(normalized_run_fingerprint(a),
                         normalized_run_fingerprint(b))

    def test_reconciliation_change_changes_fingerprint(self):
        a = _run(reconciliation={"discrepancies": 0})
        b = _run(reconciliation={"discrepancies": 2})
        self.assertNotEqual(normalized_run_fingerprint(a),
                            normalized_run_fingerprint(b))


# ---------------------------------------------------------------------------
# Store: baselines + migration (PROTOCOL §9.6)
# ---------------------------------------------------------------------------

class StoreBaselineTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="p15-store-")
        self._db = Path(self._tmp.name) / "benchmark_store.db"
        self._conn = benchmark_store.open_store(self._db)

    def tearDown(self):
        self._conn.close()
        self._tmp.cleanup()

    def _seed(self, run_id="B-seed", status="completed", skipped=0,
              harness_error=0, corpus="corpus-fp-a"):
        run = _run(run_id=run_id, status=status, corpus=corpus)
        run["totals"]["skipped"] = skipped
        run["totals"]["harness_error"] = harness_error
        benchmark_store.save_run(self._conn, run)
        return run

    def test_save_persists_fingerprints_reconciliation_and_baseline_flag(self):
        self._seed()
        stored = benchmark_store.get_run(self._conn, "B-seed")
        self.assertEqual(stored["toolchain_fingerprint"], "tc-fp")
        self.assertEqual(stored["corpus_fingerprint"], "corpus-fp-a")
        self.assertEqual(stored["reconciliation"], {"fixtures": 0, "discrepancies": 0})
        self.assertFalse(stored["is_baseline"])

    def test_row_level_reconciliation_roundtrips(self):
        # Store round-trip must be lossless for the normalized fingerprint
        # (PROTOCOL §9.5): live run and reloaded run must digest alike.
        rec = {"fixture_id": "F-001", "raw_status": "completed",
               "surfaced": 1, "excluded_informational": 2, "missing": [],
               "surfaced_without_raw": [], "discrepancies": 0,
               "per_check": {"reentrancy-eth": 1}}
        run = _run(run_id="B-rec", rows=[_row(reconciliation=rec)])
        benchmark_store.save_run(self._conn, run)
        stored = benchmark_store.get_run(self._conn, "B-rec")
        self.assertEqual(stored["results"][0]["reconciliation"], rec)
        self.assertEqual(normalized_run_fingerprint(run),
                         normalized_run_fingerprint(stored))
        # Legacy rows (pre-column) reload as None without breaking digests.
        self._conn.execute(
            "UPDATE benchmark_results SET reconciliation=NULL WHERE run_id='B-rec'"
        )
        self._conn.commit()
        legacy = benchmark_store.get_run(self._conn, "B-rec")
        self.assertIsNone(legacy["results"][0]["reconciliation"])

    def test_mark_and_get_baseline_roundtrip(self):
        self._seed()
        benchmark_store.mark_baseline(self._conn, "B-seed")
        baseline = benchmark_store.get_baseline(self._conn)
        self.assertIsNotNone(baseline)
        self.assertEqual(baseline["run_id"], "B-seed")
        self.assertTrue(baseline["is_baseline"])

    def test_single_baseline_invariant_needs_explicit_replace(self):
        self._seed("B-one")
        self._seed("B-two")
        benchmark_store.mark_baseline(self._conn, "B-one")
        with self.assertRaises(benchmark_store.BaselineError) as ctx:
            benchmark_store.mark_baseline(self._conn, "B-two")
        self.assertIn("B-one", str(ctx.exception))
        # Explicit replace switches the single baseline.
        benchmark_store.mark_baseline(self._conn, "B-two", replace=True)
        baseline = benchmark_store.get_baseline(self._conn)
        self.assertEqual(baseline["run_id"], "B-two")
        rows = self._conn.execute(
            "SELECT COUNT(*) FROM benchmark_runs WHERE is_baseline=1"
        ).fetchone()[0]
        self.assertEqual(rows, 1)

    def test_unknown_run_rejected(self):
        with self.assertRaises(benchmark_store.BaselineError):
            benchmark_store.mark_baseline(self._conn, "B-nope")

    def test_incomplete_status_rejected(self):
        self._seed(run_id="B-broken", status="completed_with_errors")
        with self.assertRaises(benchmark_store.BaselineError) as ctx:
            benchmark_store.mark_baseline(self._conn, "B-broken")
        self.assertIn("not a completed run", str(ctx.exception))

    def test_skipped_or_harness_error_totals_rejected(self):
        self._seed(run_id="B-skips", skipped=2)
        with self.assertRaises(benchmark_store.BaselineError):
            benchmark_store.mark_baseline(self._conn, "B-skips")
        self._seed(run_id="B-harness", harness_error=1)
        with self.assertRaises(benchmark_store.BaselineError):
            benchmark_store.mark_baseline(self._conn, "B-harness")

    def test_migration_is_idempotent_on_legacy_schema(self):
        legacy = Path(self._tmp.name) / "legacy.db"
        raw = sqlite3.connect(legacy)
        raw.execute(
            "CREATE TABLE benchmark_runs ("
            " run_id TEXT PRIMARY KEY, started_at TEXT NOT NULL,"
            " finished_at TEXT NOT NULL, status TEXT NOT NULL,"
            " toolchain TEXT NOT NULL, totals TEXT NOT NULL,"
            " metrics TEXT NOT NULL, notes TEXT NOT NULL DEFAULT '[]')"
        )
        raw.execute(
            "INSERT INTO benchmark_runs VALUES ('B-old','t','t','completed',"
            "'{}','{}','{}','[]')"
        )
        raw.commit()
        raw.close()
        conn = benchmark_store.open_store(legacy)
        try:
            cols = {r[1] for r in conn.execute("PRAGMA table_info(benchmark_runs)")}
            for expected in ("is_baseline", "toolchain_fingerprint",
                             "corpus_fingerprint", "reconciliation"):
                self.assertIn(expected, cols)
            stored = benchmark_store.get_run(conn, "B-old")
            self.assertFalse(stored["is_baseline"])
            self.assertIsNone(stored["toolchain_fingerprint"])
        finally:
            conn.close()
        # Second open (re-running init_schema) must not fail.
        conn2 = benchmark_store.open_store(legacy)
        conn2.close()

    def test_production_database_name_is_refused(self):
        with self.assertRaises(ValueError):
            benchmark_store.open_store("audit_scan_history.db")


# ---------------------------------------------------------------------------
# CLI gates (PROTOCOL §9.6 exit semantics)
# ---------------------------------------------------------------------------

class CliBaselineTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="p15-cli-")
        self._db = Path(self._tmp.name) / "benchmark_store.db"
        self._env = mock.patch.dict(
            os.environ, {"AUDITOR_BENCHMARK_DB": str(self._db)}
        )
        self._env.start()

    def tearDown(self):
        self._env.stop()
        self._tmp.cleanup()

    def _main(self, run, *argv):
        # The real run_benchmark persists before returning; keep that contract
        # while stubbing out Slither entirely.
        def fake_run_benchmark(**kwargs):
            if kwargs.get("save", True):
                conn = benchmark_store.open_store(kwargs.get("db_path"))
                try:
                    conn.execute(
                        "DELETE FROM benchmark_results WHERE run_id=?",
                        (run["run_id"],),
                    )
                    conn.execute(
                        "DELETE FROM benchmark_runs WHERE run_id=?",
                        (run["run_id"],),
                    )
                    conn.commit()
                    benchmark_store.save_run(conn, run)
                finally:
                    conn.close()
            return run

        out, err = io.StringIO(), io.StringIO()
        with mock.patch(
            "auditor.benchmark.run_benchmark", side_effect=fake_run_benchmark
        ):
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                code = main(["benchmark", *argv])
        return code, out.getvalue(), err.getvalue()

    def test_set_baseline_without_save_is_rejected(self):
        code, out, err = self._main(_run(), "--no-save", "--set-baseline")
        self.assertEqual(code, EXIT_ERROR)
        self.assertIn("--set-baseline requires", err)

    def test_set_baseline_then_second_set_requires_force(self):
        code, out, err = self._main(_run(), "--set-baseline")
        self.assertEqual(code, EXIT_OK)
        self.assertIn("stored as baseline", out)

        code, out, err = self._main(_run(run_id="B-second"), "--set-baseline")
        self.assertEqual(code, EXIT_ERROR)
        self.assertIn("baseline already set", err)

        code, out, err = self._main(
            _run(run_id="B-second"), "--set-baseline", "--force"
        )
        self.assertEqual(code, EXIT_OK)
        conn = benchmark_store.open_store(self._db)
        try:
            self.assertEqual(benchmark_store.get_baseline(conn)["run_id"], "B-second")
        finally:
            conn.close()

    def test_set_baseline_rejects_incomplete_run(self):
        run = _run(status="completed_with_errors")
        run["totals"]["skipped"] = 1
        code, out, err = self._main(run, "--set-baseline")
        self.assertEqual(code, EXIT_ERROR)
        self.assertIn("error:", err)

    def test_baseline_gate_clean_run_exits_zero_with_parseable_json(self):
        self._main(_run(run_id="B-base"), "--set-baseline")
        code, out, err = self._main(_run(run_id="B-current"), "--baseline", "--json")
        self.assertEqual(code, EXIT_OK)
        payload = json.loads(out)  # stdout must stay parseable
        self.assertIn("comparison", payload)
        self.assertTrue(payload["comparison"]["comparable"])
        self.assertEqual(payload["comparison"]["regressions"], [])

    def test_baseline_gate_regression_exits_one_with_stderr_lines(self):
        base = _run(run_id="B-base")
        self._main(base, "--set-baseline")
        regressed = _run(
            run_id="B-regressed",
            rows=[_row(status="failed", verdict="FN", matched_check=None)],
            overall={"precision": 0.0, "recall": 0.0, "f1": 0.0,
                     "tp": 0, "fp": 0, "fn": 1, "tn": 0, "fixtures": 1},
        )
        code, out, err = self._main(regressed, "--baseline", "--json")
        self.assertEqual(code, EXIT_ERROR)
        payload = json.loads(out)
        self.assertTrue(payload["comparison"]["regressions"])
        self.assertIn("regression: F-001", err)

    def test_baseline_gate_without_baseline_errors(self):
        code, out, err = self._main(_run(), "--baseline")
        self.assertEqual(code, EXIT_ERROR)
        self.assertIn("no baseline stored", err)

    def test_baseline_gate_toolchain_mismatch_fails_closed(self):
        self._main(_run(slither="0.11.6"), "--set-baseline")
        code, out, err = self._main(
            _run(run_id="B-newtc", slither="0.10.0"), "--baseline"
        )
        self.assertEqual(code, EXIT_ERROR)
        self.assertIn("not like-for-like", err)


# ---------------------------------------------------------------------------
# Dashboard baseline endpoints (empty + populated)
# ---------------------------------------------------------------------------

class _DashboardBaselineCase(unittest.TestCase):
    client = None
    _tmp = None

    @classmethod
    def setUpClass(cls):
        from fastapi.testclient import TestClient
        from auditor.dashboard.app import create_app

        cls._tmp = tempfile.TemporaryDirectory(prefix="p15-dash-")
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

    @classmethod
    def _seed_store(cls, baseline_id=None, with_run=True):
        conn = benchmark_store.open_store(cls.bench_db)
        try:
            if with_run:
                benchmark_store.save_run(conn, _run(run_id="B-dash0000001"))
            if baseline_id:
                benchmark_store.mark_baseline(conn, baseline_id)
        finally:
            conn.close()


class DashboardBaselineEmptyTests(_DashboardBaselineCase):
    def test_baseline_empty_state(self):
        res = self.client.get("/api/benchmark/baseline")
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json(), {"status": "empty"})

    def test_compare_empty_state(self):
        res = self.client.get("/api/benchmark/compare")
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json(), {"status": "empty"})

    def test_no_db_file_created(self):
        self.assertFalse(self.bench_db.exists())


class DashboardCompareNoBaselineTests(_DashboardBaselineCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls._seed_store(baseline_id=None, with_run=True)

    def test_baseline_reports_no_baseline(self):
        res = self.client.get("/api/benchmark/baseline")
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()["status"], "no_baseline")

    def test_compare_reports_no_baseline(self):
        res = self.client.get("/api/benchmark/compare")
        self.assertEqual(res.status_code, 200)
        body = res.json()
        self.assertEqual(body["status"], "no_baseline")
        self.assertEqual(body["current_run_id"], "B-dash0000001")


class DashboardComparePopulatedTests(_DashboardBaselineCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls._seed_store(baseline_id="B-dash0000001", with_run=True)
        conn = benchmark_store.open_store(cls.bench_db)
        try:
            benchmark_store.save_run(conn, _run(run_id="B-dash0000002"))
        finally:
            conn.close()

    def test_baseline_returns_stored_run(self):
        res = self.client.get("/api/benchmark/baseline")
        self.assertEqual(res.status_code, 200)
        body = res.json()
        self.assertEqual(body["status"], "ok")
        self.assertEqual(body["run_id"], "B-dash0000001")
        self.assertTrue(body["is_baseline"])
        self.assertEqual(body["corpus_fingerprint"], "corpus-fp-a")

    def test_compare_latest_against_baseline(self):
        res = self.client.get("/api/benchmark/compare")
        self.assertEqual(res.status_code, 200)
        body = res.json()
        self.assertEqual(body["status"], "ok")
        self.assertEqual(body["current_run_id"], "B-dash0000002")
        comparison = body["comparison"]
        self.assertTrue(comparison["comparable"])
        self.assertEqual(comparison["regressions"], [])
        self.assertEqual(comparison["baseline_run_id"], "B-dash0000001")

    def test_compare_specific_run(self):
        res = self.client.get("/api/benchmark/compare", params={"run_id": "B-dash0000001"})
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()["current_run_id"], "B-dash0000001")

    def test_compare_unknown_run_404(self):
        res = self.client.get("/api/benchmark/compare", params={"run_id": "B-nope"})
        self.assertEqual(res.status_code, 404)

    def test_page_still_renders(self):
        res = self.client.get("/benchmark")
        self.assertEqual(res.status_code, 200)
        self.assertIn("bench-compare-card", res.text)


# ---------------------------------------------------------------------------
# Production scan-history preservation
# ---------------------------------------------------------------------------

class ProductionDbPreservationTests(unittest.TestCase):
    def test_production_db_untouched_by_phase15(self):
        if not PRODUCTION_DB.exists():
            self.skipTest(
                "production audit_scan_history.db is a local artifact, gitignored, "
                "and is not present in this checkout"
            )
        sys.path.insert(0, str(Path(__file__).resolve().parent))
        from _prod_db_guard import ProdDBWriteGuard
        guard = ProdDBWriteGuard(PRODUCTION_DB).start()
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "benchmark_store.db"
            with mock.patch.dict(os.environ, {"AUDITOR_BENCHMARK_DB": str(db)}):
                conn = benchmark_store.open_store(db)
                try:
                    benchmark_store.save_run(conn, _run(run_id="B-preserve"))
                    benchmark_store.mark_baseline(conn, "B-preserve")
                finally:
                    conn.close()
        # md5/size compare raced with the live monitor writing this DB.
        self.assertEqual(guard.stop(), [])


if __name__ == "__main__":
    unittest.main()
