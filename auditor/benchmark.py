"""Phase 14 vulnerability-detection benchmark harness.

Reads the fixture corpus and ground truth (``benchmarks/manifest.json``),
runs the **existing** three-analyzer pipeline over each fixture (one shared
Slither run per fixture — the exact call sequence the scan job uses), scores
the surfaced findings against ground truth per ``benchmarks/PROTOCOL.md``,
and persists runs to the dedicated ``benchmark_store``.

Design rules (PROTOCOL.md):

* Ground truth comes from the manifest/code semantics only — never from
  the tool output and never from an AI opinion.
* A finding counts as correct only when the detector-slug channel, the
  contract/function location, and ≥1 FACT evidence item all match.
* Blocked / not-evaluable / skipped / harness-error / pipeline-failure /
  metadata-gap outcomes are kept distinct and are never counted as TN or FN.
* Precision/recall/F1 return ``None`` (rendered "n/a") on zero denominators.
"""
from __future__ import annotations

import json
import re
import time
import traceback
from pathlib import Path
from typing import Any, Callable, Iterable, Optional

from .model import Finding
from . import benchmark_store

__all__ = [
    "ManifestError",
    "CATEGORIES",
    "LABELS",
    "load_manifest",
    "validate_manifest",
    "extract_slug",
    "classify_finding",
    "evaluate_fixture",
    "compute_metrics",
    "reconcile_raw",
    "toolchain_fingerprint",
    "corpus_fingerprint",
    "compare_runs",
    "normalized_run_fingerprint",
    "run_fixture",
    "run_benchmark",
]

CATEGORIES = frozenset(
    {
        "reentrancy", "access_control", "unchecked_call", "arithmetic",
        "privileged_change", "delegatecall", "arbitrary_transfer",
        # Protocol v3 (PROTOCOL.md §10): source-analysis channel.
        "erc4626_inflation",
        # Protocol v4 (PROTOCOL.md §11): scam / honeypot source analyzer.
        "scam_honeypot",
        # Protocol v5 (Phase 25): privileged-function authorization.
        "privileged_auth",
        # Phase 32: known-exploit shape matchers (hunting strategy 3).
        "known_exploit",
    }
)
LABELS = frozenset({"vulnerable", "safe"})
FAMILIES = frozenset({"reentrancy", "access_control", "generic"})

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_MANIFEST = PROJECT_ROOT / "benchmarks" / "manifest.json"
DEFAULT_FIXTURES_DIR = PROJECT_ROOT / "benchmarks" / "fixtures"

#: Slugs from the analyzer's own detector notes (reentrancy / access control),
#: plus source-analysis detector notes (PROTOCOL.md §10, e.g. erc4626-inflation).
_DESC_SLUGS_RE = re.compile(r"(?:Slither|Source) detector: ([a-z0-9-]+)\.")
#: Slug as the generic analyzer's title prefix: "{check} in {contract}.{function}".
_TITLE_SLUG_RE = re.compile(r"^([a-z0-9-]+) in \S+\.\S+")

_SLUG_LIKE = re.compile(r"^[a-z0-9-]+$")


class ManifestError(ValueError):
    """Fatal problem in the benchmark manifest (schema/ground-truth defects)."""


# ---------------------------------------------------------------------------
# Manifest loading / validation
# ---------------------------------------------------------------------------

def load_manifest(manifest_path: Path | str | None = None) -> dict[str, Any]:
    path = Path(manifest_path) if manifest_path else DEFAULT_MANIFEST
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ManifestError(f"manifest not found: {path}") from exc
    except json.JSONDecodeError as exc:
        raise ManifestError(f"manifest is not valid JSON: {exc}") from exc
    if not isinstance(data, dict) or not isinstance(data.get("fixtures"), list):
        raise ManifestError("manifest must be an object with a 'fixtures' list")
    data["_manifest_path"] = str(path)
    return data


def validate_manifest(manifest: dict[str, Any]) -> list[dict[str, Any]]:
    """Validate schema; return the fixtures list. Raises ManifestError on defects.

    Beyond §1 schema checks this enforces PROTOCOL §9.2: a supported
    ``schema_version`` and source-label consistency (ground-truth contract /
    function tokens must actually occur in the fixture source), so a manifest
    typo can never be silently scored as a false negative.
    """
    schema_version = manifest.get("schema_version")
    if schema_version not in (1, 2, 3, 4):
        raise ManifestError(
            f"manifest 'schema_version' must be 1, 2, 3 or 4 (got {schema_version!r})"
        )
    fixtures = manifest.get("fixtures")
    if not isinstance(fixtures, list) or not fixtures:
        raise ManifestError("manifest 'fixtures' must be a non-empty list")

    problems: list[str] = []
    seen_ids: set[str] = set()
    # PROTOCOL §9.2 source-label consistency: read each fixture's source when
    # available (a missing file stays a per-fixture 'skipped', not fatal).
    manifest_path = manifest.get("_manifest_path")
    fixtures_dir = (
        Path(manifest_path).parent / "fixtures" if manifest_path else DEFAULT_FIXTURES_DIR
    )
    required = (
        "fixture_id", "file", "category", "expected_label", "expected_contract",
        "expected_function", "expected_behavior", "accepted_checks",
        "analyzer_family", "compiler", "requires_tools", "evaluable", "provenance",
    )
    for i, fx in enumerate(fixtures):
        if not isinstance(fx, dict):
            problems.append(f"fixture #{i}: not an object")
            continue
        fid = fx.get("fixture_id") or f"#{i}"
        for key in required:
            if key not in fx:
                problems.append(f"{fid}: missing field '{key}'")
        fid_s = str(fid)
        if fid_s in seen_ids:
            problems.append(f"{fid_s}: duplicate fixture_id")
        seen_ids.add(fid_s)
        if fx.get("category") not in CATEGORIES:
            problems.append(f"{fid_s}: unknown category {fx.get('category')!r}")
        if fx.get("expected_label") not in LABELS:
            problems.append(f"{fid_s}: expected_label must be vulnerable|safe")
        if fx.get("analyzer_family") not in FAMILIES:
            problems.append(f"{fid_s}: analyzer_family must be reentrancy|access_control|generic")
        checks = fx.get("accepted_checks")
        if not isinstance(checks, list) or not checks or not all(
            isinstance(c, str) and c for c in checks
        ):
            problems.append(f"{fid_s}: accepted_checks must be a non-empty list of strings")
        if not str(fx.get("expected_contract") or "").strip():
            problems.append(f"{fid_s}: expected_contract must be non-empty")
        if not str(fx.get("expected_function") or "").strip():
            problems.append(f"{fid_s}: expected_function must be non-empty")
        if not str(fx.get("provenance") or "").strip():
            problems.append(f"{fid_s}: provenance must document fixture origin")
        if not str(fx.get("expected_behavior") or "").strip():
            problems.append(f"{fid_s}: expected_behavior must document the ground truth")
        if fx.get("evaluable") is False and not str(fx.get("na_reason") or "").strip():
            problems.append(f"{fid_s}: evaluable=false requires na_reason")
        if not str(fx.get("file") or "").strip():
            problems.append(f"{fid_s}: file must be non-empty")
            continue
        if fx.get("evaluable") is False:
            continue
        source_path = fixtures_dir / str(fx.get("file"))
        if not source_path.is_file():
            continue  # missing file → per-fixture skipped at run time (§4)
        try:
            source_text = source_path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            problems.append(f"{fid_s}: cannot read fixture source: {exc}")
            continue
        for token_field in ("expected_contract", "expected_function"):
            token = str(fx.get(token_field) or "").strip()
            if token and token not in source_text:
                problems.append(
                    f"{fid_s}: {token_field} {token!r} does not occur in "
                    f"{source_path.name} (source-label inconsistency, PROTOCOL §9.2)"
                )

    if problems:
        raise ManifestError("manifest validation failed: " + "; ".join(problems))
    return fixtures


# ---------------------------------------------------------------------------
# Finding classification (matcher inputs — PROTOCOL §2/§3)
# ---------------------------------------------------------------------------

def extract_slugs(finding: Any) -> list[str]:
    """All detector slugs on the finding (a deduped finding can carry several
    detector notes), or [] when unavailable (limitation L3)."""
    desc = str(getattr(finding, "description", "") or "")
    slugs = _DESC_SLUGS_RE.findall(desc)
    if not slugs:
        title = str(getattr(finding, "title", "") or "")
        m2 = _TITLE_SLUG_RE.match(title)
        if m2:
            slugs = [m2.group(1)]
    return slugs


def extract_slug(finding: Any) -> Optional[str]:
    """First detector slug on the finding, or None when unavailable (L3)."""
    slugs = extract_slugs(finding)
    return slugs[0] if slugs else None


def title_family(finding: Any) -> str:
    """Analyzer family from the title shape (fallback when no slug exists)."""
    title = str(getattr(finding, "title", "") or "")
    if title.startswith("Reentrancy vulnerability"):
        return "reentrancy"
    if title.startswith("Access control issue"):
        return "access_control"
    return "generic"


def classify_finding(finding: Any, fixture: dict[str, Any]) -> dict[str, Any]:
    """Apply the three match rules; returns the classification of ONE finding."""
    accepted = list(fixture.get("accepted_checks") or [])
    slugs = extract_slugs(finding)
    if slugs:
        accepted_hit = next((s for s in slugs if s in accepted), None)
        in_channel = accepted_hit is not None
        slug = accepted_hit or slugs[0]
        slug_gap = False
    else:
        # L3 fallback: family-by-title. Generic titles are always slug-shaped,
        # so a missing slug only happens for reentrancy/access-control titles
        # produced without a detector note (text-parser fallback).
        in_channel = title_family(finding) == fixture.get("analyzer_family")
        slug = None
        slug_gap = True

    contract = str(getattr(finding, "affected_contract", "") or "")
    function = str(getattr(finding, "affected_function", "") or "")
    location_ok = (
        contract == str(fixture.get("expected_contract"))
        and function == str(fixture.get("expected_function"))
    )
    facts = list(getattr(finding, "fact_evidence", []) or [])
    evidence_ok = len(facts) >= 1

    if in_channel and location_ok and evidence_ok:
        reason = None
    elif not in_channel:
        reason = "channel_mismatch"
    elif not location_ok:
        reason = "wrong_location"
    else:
        reason = "no_fact_evidence"

    return {
        "slug": slug,
        "in_channel": in_channel,
        "location_ok": location_ok,
        "evidence_ok": evidence_ok,
        "facts": len(facts),
        "slug_gap": slug_gap,
        "matched": reason is None,
        "not_matched_because": reason,
    }


def _brief(finding: Any, cls: dict[str, Any]) -> dict[str, Any]:
    return {
        "title": str(getattr(finding, "title", "")),
        "check": cls["slug"],
        "severity": str(getattr(getattr(finding, "severity", None), "value", None) or ""),
        "contract": str(getattr(finding, "affected_contract", "") or ""),
        "function": str(getattr(finding, "affected_function", "") or ""),
        "not_matched_because": cls["not_matched_because"],
    }


def evidence_summary(finding: Any) -> dict[str, Any]:
    """Reproducible evidence record for a matched detection (PROTOCOL §7)."""
    evidence = list(getattr(finding, "evidence", []) or [])
    facts = [e for e in evidence if getattr(e, "epistemic", None) is not None
             and e.epistemic.value == "FACT"]
    ai = [e for e in evidence if getattr(e, "epistemic", None) is not None
          and e.epistemic.value == "AI_OPINION"]
    other = [e for e in evidence if e not in facts and e not in ai]
    lines = list(getattr(finding, "affected_lines", []) or [])
    return {
        "finding_id": str(getattr(finding, "finding_id", "")),
        "title": str(getattr(finding, "title", "")),
        "severity": str(getattr(getattr(finding, "severity", None), "value", None) or ""),
        "confidence": str(getattr(getattr(finding, "confidence", None), "value", None) or ""),
        "verification_status": str(
            getattr(getattr(finding, "verification_status", None), "value", None) or ""
        ),
        "contract": str(getattr(finding, "affected_contract", "") or ""),
        "function": str(getattr(finding, "affected_function", "") or ""),
        "lines": sorted(int(x) for x in lines if isinstance(x, (int, float)) and x >= 1),
        "facts": len(facts),
        "ai_opinions": len(ai),
        "other_epistemic": len(other),
        "sources": sorted({str(e.source) for e in evidence if getattr(e, "source", None)}),
        "tools": sorted({str(e.tool) for e in evidence if getattr(e, "tool", None)}),
        "epistemic": sorted({str(e.epistemic.value) for e in evidence if getattr(e, "epistemic", None)}),
        "description_present": bool(str(getattr(finding, "description", "")).strip()),
        "remediation_present": bool(str(getattr(finding, "remediation", "")).strip()),
        "prerequisites": [str(p) for p in (getattr(finding, "prerequisites", []) or [])],
        "assumptions": [str(a) for a in (getattr(finding, "assumptions", []) or [])],
        "excerpt": (facts[0].excerpt[:240] if facts else None),
        "provenance": (
            "static-analysis tool evidence (Epistemic.FACT); finding "
            "verification_status is not upgraded by the benchmark"
        ),
    }


# ---------------------------------------------------------------------------
# Raw-detector check (pipeline-failure detection, PROTOCOL §4)
# ---------------------------------------------------------------------------

def _raw_channel_hit(run_result: Any, fixture: dict[str, Any]) -> bool:
    """True when the RAW Slither report claims the expected channel+location.

    Used only to separate 'detector fired but surfacing lost it'
    (pipeline_failure) from a genuine miss (FN).
    """
    detectors = getattr(run_result, "detectors", None)
    if not detectors:
        return False
    accepted = set(fixture.get("accepted_checks") or [])
    needle = (
        f"{fixture.get('expected_contract')}.{fixture.get('expected_function')}"
    )
    for det in detectors:
        if not isinstance(det, dict):
            continue
        if str(det.get("check") or "") not in accepted:
            continue
        if needle in str(det.get("description") or ""):
            return True
    return False


# ---------------------------------------------------------------------------
# Independent raw ↔ surfaced reconciliation (PROTOCOL §9.3)
# ---------------------------------------------------------------------------

def reconcile_raw(
    fixture: dict[str, Any],
    run_result: Any,
    findings: Iterable[Finding],
) -> dict[str, Any]:
    """Compare the raw Slither detector list against the surfaced findings.

    Consistency check ONLY — never a verdict path: a raw emission alone is not
    a TP and a ``missing`` entry alone is not an FN (§3 matcher decides).
    """
    findings = list(findings or [])
    surfaced_slugs: set[str] = set()
    for f in findings:
        # Source-analysis findings (PROTOCOL.md §10) have no raw Slither
        # counterpart by construction; they are not reconciliation input.
        if str(getattr(f, "source", "") or "") == "source-analysis":
            continue
        surfaced_slugs.update(extract_slugs(f))

    raw_status = str(getattr(run_result, "status", "") or "") if run_result is not None else "not_run"
    detectors = list(getattr(run_result, "detectors", None) or []) if run_result is not None else []

    surfaced = 0
    excluded_informational = 0
    missing: list[str] = []
    per_check: dict[str, int] = {}
    for det in detectors:
        if not isinstance(det, dict):
            continue
        slug = str(det.get("check") or "")
        if not slug:
            continue
        is_surfaced = slug in surfaced_slugs
        if is_surfaced:
            surfaced += 1
            status = "surfaced"
        elif str(det.get("impact") or "") == "Informational":
            excluded_informational += 1
            status = "excluded_informational"
        else:
            missing.append(slug)
            status = "missing"
        per_check[slug] = per_check.get(slug, 0) + 1
        _ = status  # status is per-instance; only aggregates are returned

    raw_slugs = {str(d.get("check")) for d in detectors if isinstance(d, dict)}
    surfaced_without_raw = sorted(surfaced_slugs - raw_slugs)

    return {
        "fixture_id": fixture.get("fixture_id"),
        "raw_status": raw_status,
        "raw_detectors": len(detectors),
        "surfaced": surfaced,
        "excluded_informational": excluded_informational,
        "missing": sorted(missing),
        "surfaced_without_raw": surfaced_without_raw,
        "discrepancies": len(missing) + len(surfaced_without_raw),
        "per_check": dict(sorted(per_check.items())),
    }


def aggregate_reconciliation(rows: Iterable[dict[str, Any]]) -> dict[str, Any]:
    """Aggregate per-fixture reconciliation blocks of a completed run."""
    fixtures = 0
    surfaced = 0
    excluded = 0
    missing: list[str] = []
    without_raw: list[str] = []
    raw_status_counts: dict[str, int] = {}
    details: dict[str, Any] = {}
    for row in rows:
        rec = row.get("reconciliation")
        if not isinstance(rec, dict):
            continue
        fixtures += 1
        fid = str(rec.get("fixture_id") or row.get("fixture_id") or "?")
        details[fid] = rec
        surfaced += int(rec.get("surfaced") or 0)
        excluded += int(rec.get("excluded_informational") or 0)
        missing.extend(f"{fid}:{s}" for s in rec.get("missing") or [])
        without_raw.extend(f"{fid}:{s}" for s in rec.get("surfaced_without_raw") or [])
        st = str(rec.get("raw_status") or "unknown")
        raw_status_counts[st] = raw_status_counts.get(st, 0) + 1
    return {
        "fixtures": fixtures,
        "surfaced": surfaced,
        "excluded_informational": excluded,
        "missing": missing,
        "surfaced_without_raw": without_raw,
        "discrepancies": len(missing) + len(without_raw),
        "raw_status_counts": dict(sorted(raw_status_counts.items())),
        "details": details,
    }


# ---------------------------------------------------------------------------
# Fingerprints & baseline comparison (PROTOCOL §9.6)
# ---------------------------------------------------------------------------

def toolchain_fingerprint(toolchain: Any) -> str:
    """Stable slug of slither/solc/forge versions (available tools only)."""
    import hashlib

    tc = toolchain if isinstance(toolchain, dict) else {}
    parts = []
    for key in ("slither", "solc", "forge"):
        entry = tc.get(key) if isinstance(tc, dict) else None
        if isinstance(entry, dict) and entry.get("available") and entry.get("version"):
            parts.append(f"{key}={entry['version']}")
    raw = "|".join(parts) if parts else "unavailable"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def corpus_fingerprint(fixtures: Iterable[dict[str, Any]]) -> str:
    """Stable slug over fixture ids, labels, categories, locations, channels."""
    import hashlib

    parts = []
    for fx in fixtures:
        if not isinstance(fx, dict):
            continue
        checks = ",".join(sorted(str(c) for c in fx.get("accepted_checks") or []))
        parts.append(
            "|".join(
                (
                    str(fx.get("fixture_id")),
                    str(fx.get("expected_label")),
                    str(fx.get("category")),
                    str(fx.get("expected_contract")),
                    str(fx.get("expected_function")),
                    checks,
                )
            )
        )
    raw = "\n".join(sorted(parts))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def _row_verdict(row: dict[str, Any]) -> str:
    """Verdict key for comparison: TP/FP/FN/TN, or the status bucket itself."""
    verdict = str(row.get("verdict") or "")
    if verdict in ("TP", "FP", "FN", "TN"):
        return verdict
    return str(row.get("status") or "unknown")


def _metric_value(run: dict[str, Any], key: str) -> Optional[float]:
    overall = (run.get("metrics") or {}).get("overall") or {}
    value = overall.get(key)
    return float(value) if isinstance(value, (int, float)) else None


_DOWNGRADE_PAIRS = {("TP", "FN"), ("TP", "FP"), ("TN", "FP")}


def compare_runs(current: dict[str, Any], baseline: dict[str, Any]) -> dict[str, Any]:
    """Compare a current run against a baseline run (PROTOCOL §9.6).

    Toolchain or corpus mismatch ⇒ ``comparable: false``: verdict and metric
    judgments are suppressed and reported as not-comparable, never presented
    as like-for-like results.
    """
    cur_tc = toolchain_fingerprint(current.get("toolchain"))
    base_tc = toolchain_fingerprint(baseline.get("toolchain"))
    cur_corpus = current.get("corpus_fingerprint")
    base_corpus = baseline.get("corpus_fingerprint")

    toolchain_match = cur_tc == base_tc
    corpus_match = bool(cur_corpus) and cur_corpus == base_corpus
    result: dict[str, Any] = {
        "baseline_run_id": str(baseline.get("run_id") or ""),
        "current_run_id": str(current.get("run_id") or ""),
        "toolchain_match": toolchain_match,
        "toolchain_fingerprint": {"current": cur_tc, "baseline": base_tc},
        "corpus_match": corpus_match,
        "corpus_fingerprint": {"current": cur_corpus, "baseline": base_corpus},
        "corpus_changed": bool(cur_corpus and base_corpus and cur_corpus != base_corpus),
        "comparable": False,
        "not_comparable_reason": None,
        "added_fixtures": [],
        "removed_fixtures": [],
        "verdict_changes": [],
        "metric_deltas": {"precision": None, "recall": None, "f1": None},
        "regressions": [],
        "notes": [],
    }

    cur_rows = {str(r.get("fixture_id")): r for r in (current.get("results") or [])}
    base_rows = {str(r.get("fixture_id")): r for r in (baseline.get("results") or [])}
    result["added_fixtures"] = sorted(set(cur_rows) - set(base_rows))
    result["removed_fixtures"] = sorted(set(base_rows) - set(cur_rows))

    if not cur_corpus or not base_corpus:
        result["not_comparable_reason"] = (
            "run lacks a corpus fingerprint (produced before protocol v2; re-run to compare)"
        )
    elif not toolchain_match:
        result["not_comparable_reason"] = "toolchain mismatch (slither/solc/forge versions differ)"
    elif not corpus_match:
        result["not_comparable_reason"] = "corpus mismatch (fixture set or labels changed)"
    else:
        result["comparable"] = True

    if not result["comparable"]:
        result["notes"].append(
            "verdict/metric judgments suppressed: comparison is not like-for-like"
        )
        return result

    regressions: list[str] = []
    for fid in sorted(set(cur_rows) & set(base_rows)):
        before = _row_verdict(base_rows[fid])
        after = _row_verdict(cur_rows[fid])
        if before == after:
            continue
        is_regression = (before, after) in _DOWNGRADE_PAIRS or (
            before in ("TP", "FP", "FN", "TN") and after in ("blocked", "pipeline_failure")
        )
        result["verdict_changes"].append(
            {"fixture_id": fid, "from": before, "to": after, "regression": is_regression}
        )
        if is_regression:
            regressions.append(f"{fid}: verdict {before} -> {after}")

    for key in ("precision", "recall", "f1"):
        cur_v = _metric_value(current, key)
        base_v = _metric_value(baseline, key)
        if cur_v is not None and base_v is not None:
            delta = round(cur_v - base_v, 6)
            result["metric_deltas"][key] = delta
            if delta < 0:
                regressions.append(f"{key}: {base_v:.4f} -> {cur_v:.4f} (delta {delta:+.4f})")

    result["regressions"] = regressions
    return result


def normalized_run_fingerprint(run: dict[str, Any]) -> str:
    """Deterministic digest over the normalized run (PROTOCOL §9.5).

    Includes fixture rows (identifiers, statuses, verdicts, matches,
    other-findings, reason, reconciliation), metrics, totals excluding
    ``duration_seconds``, and run status. Excludes ``run_id``, timestamps,
    and evidence payloads (whose finding ids need not be stable across
    runs) — a diff of two normalized fingerprints is nondeterminism.
    """
    import hashlib

    results = []
    for r in run.get("results") or []:
        if not isinstance(r, dict):
            continue
        results.append(
            {
                "fixture_id": r.get("fixture_id"),
                "category": r.get("category"),
                "expected_label": r.get("expected_label"),
                "status": r.get("status"),
                "verdict": r.get("verdict"),
                "matched_check": r.get("matched_check"),
                "actual_contract": r.get("actual_contract"),
                "actual_function": r.get("actual_function"),
                "other_findings": r.get("other_findings") or [],
                "reason": r.get("reason"),
                "reconciliation": r.get("reconciliation"),
            }
        )
    results.sort(key=lambda x: str(x["fixture_id"]))
    totals = {
        k: v
        for k, v in (run.get("totals") or {}).items()
        if k != "duration_seconds"
    }
    payload = json.dumps(
        {
            "status": run.get("status"),
            "results": results,
            "metrics": run.get("metrics") or {},
            "totals": totals,
            "reconciliation": run.get("reconciliation") or {},
        },
        sort_keys=True,
        default=str,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Fixture evaluation
# ---------------------------------------------------------------------------

def evaluate_fixture(
    fixture: dict[str, Any],
    findings: Iterable[Finding],
    run_result: Any,
    error: Optional[str] = None,
    file_exists: bool = True,
) -> dict[str, Any]:
    """Score one fixture per PROTOCOL §3/§4. Pure function (easily testable)."""
    row: dict[str, Any] = {
        "fixture_id": fixture.get("fixture_id"),
        "category": fixture.get("category"),
        "expected_label": fixture.get("expected_label"),
        "expected_contract": fixture.get("expected_contract"),
        "expected_function": fixture.get("expected_function"),
        "status": None,
        "verdict": None,
        "matched_check": None,
        "matched_title": None,
        "actual_contract": None,
        "actual_function": None,
        "other_findings": [],
        "evidence": None,
        "na_reason": fixture.get("na_reason"),
        "reason": None,
        "metadata_gaps": 0,
        "evidence_insufficient": 0,
        "raw_unsurfaced_hits": 0,
    }
    findings = list(findings or [])

    if not file_exists:
        row["status"] = "skipped"
        row["reason"] = f"fixture file not found: {fixture.get('file')}"
        return row

    if fixture.get("evaluable") is False:
        # Not evaluable: never scored (PROTOCOL §5). Record observations only.
        row["status"] = "not_evaluable"
        row["reason"] = fixture.get("na_reason")
        cls_all = [classify_finding(f, fixture) for f in findings]
        row["other_findings"] = [_brief(f, c) for f, c in zip(findings, cls_all)]
        return row

    if error:
        row["status"] = "harness_error"
        row["reason"] = error
        return row

    if run_result is None:
        row["status"] = "harness_error"
        row["reason"] = "no analyzer run was recorded for this fixture"
        return row

    status = str(getattr(run_result, "status", "") or "")
    if status != "completed":
        detail = (
            getattr(run_result, "error", None)
            or getattr(run_result, "failure_note", lambda: None)()
            or status
        )
        row["status"] = "blocked"
        row["reason"] = f"tool/compiler failure: {detail}"
        cls_all = [classify_finding(f, fixture) for f in findings]
        row["other_findings"] = [_brief(f, c) for f, c in zip(findings, cls_all)]
        return row

    if getattr(run_result, "detectors", None) is None:
        row["status"] = "blocked"
        row["reason"] = "slither completed without a parseable JSON report"
        return row

    # --- matcher (PROTOCOL §3) -------------------------------------------
    matched: Optional[Finding] = None
    matched_cls: Optional[dict[str, Any]] = None
    others: list[dict[str, Any]] = []
    gaps = 0
    insufficient = 0
    for f in findings:
        cls = classify_finding(f, fixture)
        if cls["slug_gap"]:
            gaps += 1
        if cls["matched"] and matched is None:
            matched, matched_cls = f, cls
            continue
        entry = _brief(f, cls)
        if cls["matched"]:
            # Additional channel+location match on the same fixture: scoring
            # is fixture-level (one verdict per fixture), so record it here.
            entry["not_matched_because"] = "additional_match"
        elif cls["not_matched_because"] == "no_fact_evidence":
            insufficient += 1
        others.append(entry)

    row["metadata_gaps"] = gaps
    row["evidence_insufficient"] = insufficient
    row["other_findings"] = others

    raw_hit = _raw_channel_hit(run_result, fixture)
    label = fixture.get("expected_label")

    if matched is not None:
        cls = matched_cls or {}
        row["matched_check"] = cls.get("slug")
        row["matched_title"] = str(getattr(matched, "title", ""))
        row["actual_contract"] = str(getattr(matched, "affected_contract", "") or "")
        row["actual_function"] = str(getattr(matched, "affected_function", "") or "")
        row["evidence"] = evidence_summary(matched)
        if label == "vulnerable":
            row["status"] = "passed"
            row["verdict"] = "TP"
        else:
            row["status"] = "failed"
            row["verdict"] = "FP"
        return row

    if label == "vulnerable":
        if raw_hit:
            # Detector fired on the expected channel+location but no finding
            # was surfaced: surfacing/pipeline failure — NOT a genuine miss.
            row["status"] = "pipeline_failure"
            row["reason"] = (
                "raw Slither report contains the expected detector at the "
                "expected location, but the analyzer pipeline surfaced no "
                "matching finding"
            )
            row["raw_unsurfaced_hits"] = 1
        else:
            row["status"] = "failed"
            row["verdict"] = "FN"
            row["reason"] = "no matching finding surfaced for a vulnerable fixture"
        return row

    # safe label, no matching finding → correct rejection
    row["status"] = "passed"
    row["verdict"] = "TN"
    if raw_hit:
        row["raw_unsurfaced_hits"] = 1
        row["reason"] = (
            "raw detector hit at the expected location was not surfaced by "
            "the pipeline (would have been a false positive); recorded for "
            "transparency"
        )
    return row


# ---------------------------------------------------------------------------
# Running one fixture through the EXISTING pipeline
# ---------------------------------------------------------------------------

def _collect_findings(source_file: Path) -> tuple[list[Finding], Any, Optional[str]]:
    """Run the three existing analyzers over ONE shared Slither run.

    Identical call sequence to ``JobManager._collect_static_findings``
    (including its dedupe) — no competing detector implementation.
    """
    from .analysis.access_control import analyze as access_control_analyze
    from .analysis.base import AnalysisContext
    from .analysis.reentrancy import analyze as reentrancy_analyze
    from .analysis.slither_generic import analyze as generic_analyze
    from .analysis.oracle_staleness import analyze as oracle_analyze
    from .analysis.erc4626_inflation import analyze as erc4626_analyze
    from .analysis.pool_accounting import analyze as pool_analyze
    from .analysis.honeypot import analyze as honeypot_analyze
    from .analysis.privileged_auth import analyze as privileged_auth_analyze
    from .analysis.known_exploits import analyze as known_exploits_analyze
    from .dashboard.jobs import _dedupe_findings
    from .triage import apply_to_pipeline

    context = AnalysisContext()
    context.source_files = [source_file]
    findings: list[Finding] = []
    for analyzer in (
        reentrancy_analyze,
        access_control_analyze,
        generic_analyze,
        oracle_analyze,
        erc4626_analyze,
        pool_analyze,
        honeypot_analyze,
        privileged_auth_analyze,
        known_exploits_analyze,
    ):
        outcome = analyzer(context)
        findings.extend(outcome.findings or [])
    findings = _dedupe_findings(findings)
    # Phase 19 (PROTOCOL §11): same triage as the scan paths (suppression never
    # touches non-library fixtures; the privileged-withdraw downgrade only
    # changes severity, which the matcher never uses).
    findings = apply_to_pipeline(findings, [source_file]).kept
    run_result = getattr(context, "_slither_run", None)
    return findings, run_result, None


def run_fixture(fixture: dict[str, Any], fixtures_dir: Path) -> dict[str, Any]:
    """Evaluate one fixture end-to-end; never raises (harness_error captured)."""
    path = fixtures_dir / str(fixture.get("file") or "")
    if not path.is_file():
        return evaluate_fixture(fixture, [], None, file_exists=False)
    try:
        findings, run_result, err = _collect_findings(path)
        row = evaluate_fixture(fixture, findings, run_result, error=err, file_exists=True)
        if row.get("status") != "skipped":
            row["reconciliation"] = reconcile_raw(fixture, run_result, findings)
        return row
    except Exception as exc:  # noqa: BLE001 - harness isolation per PROTOCOL §4
        return evaluate_fixture(
            fixture,
            [],
            None,
            error=f"{type(exc).__name__}: {str(exc)[:300]}",
            file_exists=True,
        )


# ---------------------------------------------------------------------------
# Metrics (PROTOCOL §6)
# ---------------------------------------------------------------------------

def _ratio(num: int, den: int) -> Optional[float]:
    return (num / den) if den else None


def _f1(tp: int, fp: int, fn: int) -> Optional[float]:
    den = 2 * tp + fp + fn
    return (2 * tp / den) if den else None


def compute_metrics(results: Iterable[dict[str, Any]]) -> dict[str, Any]:
    """Confusion matrix + P/R/F1 (None on zero denominators), overall and per category."""
    results = list(results)
    counts = {
        "tp": 0, "fp": 0, "fn": 0, "tn": 0,
        "blocked": 0, "not_evaluable": 0, "skipped": 0,
        "pipeline_failure": 0, "harness_error": 0,
        "metadata_gaps": 0, "evidence_insufficient": 0,
        "raw_unsurfaced_hits": 0, "other_findings": 0,
    }
    per_cat_rows: dict[str, list[dict[str, Any]]] = {}

    for row in results:
        cat = str(row.get("category") or "unknown")
        per_cat_rows.setdefault(cat, []).append(row)
        status = row.get("status")
        verdict = row.get("verdict")
        if status in ("passed", "failed") and verdict in ("TP", "FP", "FN", "TN"):
            counts[verdict.lower()] += 1
        elif status in counts:
            counts[status] += 1
        else:
            counts["harness_error"] += 1
        counts["metadata_gaps"] += int(row.get("metadata_gaps") or 0)
        counts["evidence_insufficient"] += int(row.get("evidence_insufficient") or 0)
        counts["raw_unsurfaced_hits"] += int(row.get("raw_unsurfaced_hits") or 0)
        counts["other_findings"] += len(row.get("other_findings") or [])

    def block(rows: list[dict[str, Any]]) -> dict[str, Any]:
        tp = sum(1 for r in rows if r.get("verdict") == "TP")
        fp = sum(1 for r in rows if r.get("verdict") == "FP")
        fn = sum(1 for r in rows if r.get("verdict") == "FN")
        tn = sum(1 for r in rows if r.get("verdict") == "TN")
        return {
            "tp": tp, "fp": fp, "fn": fn, "tn": tn,
            "precision": _ratio(tp, tp + fp),
            "recall": _ratio(tp, tp + fn),
            "f1": _f1(tp, fp, fn),
        }

    categories = {}
    for cat in sorted(per_cat_rows):
        rows = per_cat_rows[cat]
        b = block(rows)
        b["fixtures"] = len(rows)
        b["evaluable"] = sum(
            1 for r in rows if r.get("status") in ("passed", "failed")
        )
        categories[cat] = b

    overall = block(results)
    overall.update(counts)
    overall["fixtures"] = len(results)
    return {"overall": overall, "categories": categories}


# ---------------------------------------------------------------------------
# Full run
# ---------------------------------------------------------------------------

def _toolchain_snapshot(timeout: float = 10.0) -> dict[str, Any]:
    try:
        from .toolchain import TOOL_SPECS, detect_tool
    except Exception as exc:  # noqa: BLE001 - snapshot must never kill a run
        return {"error": f"{type(exc).__name__}: {exc}"}
    snap: dict[str, Any] = {}
    for key in ("slither", "solc", "forge"):
        spec = next((s for s in TOOL_SPECS if s.key == key), None)
        if spec is None:
            continue
        try:
            st = detect_tool(spec, timeout=timeout)
            snap[key] = {
                "available": bool(getattr(st, "available", False)),
                "version": getattr(st, "version", None),
                "path": getattr(st, "path", None),
                "status": getattr(st, "status", None),
            }
        except Exception as exc:  # noqa: BLE001
            snap[key] = {"available": False, "error": f"{type(exc).__name__}: {exc}"}
    return snap


def run_benchmark(
    manifest_path: Path | str | None = None,
    fixtures_dir: Path | str | None = None,
    db_path: Path | str | None = None,
    save: bool = True,
    limit: int | None = None,
    runner: Optional[Callable[[dict[str, Any], Path], dict[str, Any]]] = None,
) -> dict[str, Any]:
    """Run the whole benchmark, optionally persisting to the benchmark store."""
    from .benchmark_store import new_run_id, open_store, save_run

    manifest = load_manifest(manifest_path)
    fixtures = validate_manifest(manifest)
    if limit is not None:
        fixtures = fixtures[: max(0, int(limit))]

    if fixtures_dir is None:
        fixtures_dir = Path(manifest["_manifest_path"]).parent / "fixtures"
    fixtures_dir = Path(fixtures_dir)

    run: dict[str, Any] = {
        "run_id": new_run_id(),
        "started_at": _iso_now(),
        "finished_at": None,
        "status": "running",
        "toolchain": _toolchain_snapshot(),
        "manifest": str(manifest.get("_manifest_path")),
        "fixtures_dir": str(fixtures_dir),
        "totals": {},
        "metrics": {},
        "notes": [],
        "results": [],
    }
    run["toolchain_fingerprint"] = toolchain_fingerprint(run["toolchain"])
    run["corpus_fingerprint"] = corpus_fingerprint(fixtures)

    runner = runner or run_fixture
    started = time.monotonic()
    for fixture in fixtures:
        run["results"].append(runner(fixture, fixtures_dir))
    duration = time.monotonic() - started

    run["metrics"] = compute_metrics(run["results"])
    run["reconciliation"] = aggregate_reconciliation(run["results"])
    overall = run["metrics"]["overall"]
    status_counts: dict[str, int] = {}
    for r in run["results"]:
        st = str(r.get("status") or "unknown")
        status_counts[st] = status_counts.get(st, 0) + 1
    run["totals"] = {
        "fixtures": overall["fixtures"],
        "passed": status_counts.get("passed", 0),
        "failed": status_counts.get("failed", 0),
        "blocked": status_counts.get("blocked", 0),
        "not_evaluable": status_counts.get("not_evaluable", 0),
        "skipped": status_counts.get("skipped", 0),
        "pipeline_failure": status_counts.get("pipeline_failure", 0),
        "harness_error": status_counts.get("harness_error", 0),
        "tp": overall["tp"], "fp": overall["fp"],
        "fn": overall["fn"], "tn": overall["tn"],
        "reconciliation_fixtures": run["reconciliation"]["fixtures"],
        "reconciliation_discrepancies": run["reconciliation"]["discrepancies"],
        "duration_seconds": round(duration, 3),
    }
    run["finished_at"] = _iso_now()
    run["status"] = (
        "completed_with_errors"
        if status_counts.get("harness_error") or status_counts.get("skipped")
        else "completed"
    )

    if save:
        conn = open_store(db_path)
        try:
            save_run(conn, run)
        finally:
            conn.close()
    return run


def _iso_now() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat(timespec="seconds")
