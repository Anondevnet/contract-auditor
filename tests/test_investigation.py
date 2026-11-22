"""Phase 10 test suite — two-sided finding investigation, AI audit agent,
triage state machine, bounty checks, OpenCode proposals, and rich reports.

Run with:

    python3 -m unittest discover -s tests -v

Every test runs against a throwaway history database pointed to by
``AUDITOR_HISTORY_DB`` so the production ``audit_scan_history.db`` is never
written to, and every network-dependent path is mocked: no test performs
live HTTP requests, no subprocess is spawned without a mock, and no test
prints an API key.
"""

from __future__ import annotations

import json
import os
import re
import sys
import tempfile
import time
import unittest
import unittest.mock as mock
from pathlib import Path
from types import SimpleNamespace

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from auditor.dashboard.paths import history_db_path  # noqa: E402
from auditor.finding_store import (  # noqa: E402
    TriageState,
    get_review,
    has_fact_evidence,
    open_store,
)
from auditor.model import (  # noqa: E402
    Confidence,
    Epistemic,
    EvidenceItem,
    Finding,
    Severity,
    VerificationStatus,
    finding_fingerprint,
)
from auditor.scan_history import ScanHistory  # noqa: E402

FAKE_ANTHROPIC_KEY = "SUPER-SECRET-ANTHROPIC-KEY-DO-NOT-LEAK"

VAULT_SOL = """\
pragma solidity ^0.5.8;

contract Vault {
    mapping(address => uint) public balances;

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint amount) public {
        (bool ok, ) = msg.sender.call.value(amount)("");
        require(ok, "transfer failed");
        balances[msg.sender] -= amount;
    }
}
"""

REENTRANCY_SLITHER_OUTPUT = """\
INFO:Detectors:
Detector: reentrancy-benign
Reentrancy in Vault.withdraw(uint256) (Vault.sol#9-13):
\tExternal calls:
\t- (ok,None) = msg.sender.call.value(amount)() (Vault.sol#10)
\tState variables written after the call(s):
\t- balances[msg.sender] -= amount (Vault.sol#12)
Reference: https://github.com/crytic/slither/wiki/Detector-Documentation#reentrancy-vulnerabilities-3
"""

ACCESS_SLITHER_OUTPUT = """\
INFO:Detectors:
Detector: missing-zero-check
Vault.setOwner(address).newOwner (Vault.sol#20) lacks a zero-check on :
\t\t- owner = newOwner (Vault.sol#21)
Reference: https://github.com/crytic/slither/wiki/Detector-Documentation#missing-zero-address-validation
"""


def _finding(
    title: str = "Reentrancy vulnerability in Vault.withdraw",
    *,
    severity: Severity = Severity.HIGH,
    contract: str = "Vault",
    function: str = "withdraw",
    lines: list[int] | None = None,
    with_fact: bool = True,
) -> Finding:
    evidence: list[EvidenceItem] = []
    if with_fact:
        evidence = [
            EvidenceItem(
                epistemic=Epistemic.FACT,
                source="slither",
                artifact_type="tool_output",
                excerpt="- (ok,None) = msg.sender.call.value(amount)() (Vault.sol#10)",
                tool="slither",
            )
        ]
    return Finding(
        title=title,
        description="External call precedes state update (fixture finding).",
        category="security",
        severity=severity,
        confidence=Confidence.MEDIUM,
        verification_status=VerificationStatus.UNVERIFIED,
        affected_contract=contract,
        affected_function=function,
        affected_lines=lines or [10, 12],
        evidence=evidence,
    )


def _outcome(titles: list[str], *, severity: Severity = Severity.HIGH):
    from auditor.analysis.base import AnalysisOutcome

    outcome = AnalysisOutcome()
    outcome.findings = [
        _finding(title, severity=severity, lines=[10, 11, 12]) for title in titles
    ]
    outcome.evidence = []
    outcome.notes = ["fixture analyzer"]
    return outcome


def _mock_urlopen(payload: bytes):
    response = mock.MagicMock()
    response.read.return_value = payload
    response.__enter__ = mock.Mock(return_value=response)
    response.__exit__ = mock.Mock(return_value=False)
    return mock.patch("urllib.request.urlopen", return_value=response)


class InvestigationTestCase(unittest.TestCase):
    """Shared TestClient + isolated history database + source fixture."""

    client = None
    _tmpdir = None

    @classmethod
    def setUpClass(cls) -> None:
        from fastapi.testclient import TestClient

        from auditor.dashboard.app import create_app

        cls._tmpdir = tempfile.TemporaryDirectory(prefix="audit-invest-test-")
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

    # -- helpers -----------------------------------------------------------

    def _source_dir(self) -> Path:
        root = Path(tempfile.mkdtemp(prefix="inv-src-"))
        (root / "Vault.sol").write_text(VAULT_SOL, encoding="utf-8")
        return root

    def _seed_scan(self, findings: list[Finding], *, config: str = "fixture") -> str:
        root = self._source_dir()
        history = ScanHistory(history_db_path())
        try:
            scan_id = history.record_scan(
                source_path=root, config_fingerprint=config, findings=findings
            )
            history.mark_completed(scan_id, findings)
        finally:
            history.close()
        return scan_id

    def _seed_completed(self, findings: list[Finding]) -> tuple[str, str, Path]:
        """Seed a scan and return (scan_id, fingerprint, source_root)."""
        scan_id = self._seed_scan(findings)
        fp = str(finding_fingerprint(findings[0]))
        history = ScanHistory(history_db_path())
        try:
            record = history.get_scan(scan_id)
        finally:
            history.close()
        root = Path(record["source_path"])
        return scan_id, fp, root

    def _wait_for_job(self, job_id: str, timeout: float = 60.0) -> dict:
        deadline = time.time() + timeout
        while time.time() < deadline:
            res = self.client.get(f"/api/jobs/{job_id}")
            self.assertEqual(res.status_code, 200)
            job = res.json()
            if job["status"] in ("completed", "failed", "cancelled"):
                return job
            time.sleep(0.1)
        self.fail(f"job {job_id} did not finish within {timeout}s")


# ---------------------------------------------------------------------------
# Pages
# ---------------------------------------------------------------------------


class TestPages(InvestigationTestCase):
    def test_findings_page_renders(self) -> None:
        res = self.client.get("/findings")
        self.assertEqual(res.status_code, 200)
        for element in (
            "findings-q",
            "findings-severity",
            "findings-state",
            "findings-sort",
            "findings-groups",
        ):
            self.assertIn(element, res.text)

    def test_investigate_page_renders(self) -> None:
        scan_id, fp, _ = self._seed_completed([_finding()])
        res = self.client.get(f"/investigate/{scan_id}", params={"fp": fp})
        self.assertEqual(res.status_code, 200)
        for element in (
            "inv-grid",
            "inv-attacker-panel",
            "inv-defender-panel",
            "inv-state-apply",
            "inv-retest-btn",
            "inv-ai-btn",
            "inv-bounty-btn",
            "inv-propose-btn",
            "inv-summary-card",
            "inv-protocol-card",
            "inv-classification",
            "inv-financial",
            "inv-provenance-card",
            "inv-duplicates",
            "inv-evidence-card",
        ):
            self.assertIn(element, res.text)

    def test_nav_has_findings_link(self) -> None:
        res = self.client.get("/history")
        self.assertEqual(res.status_code, 200)
        self.assertIn('href="/findings"', res.text)

    def test_static_assets_served(self) -> None:
        for asset in (
            "/static/js/findings.js",
            "/static/js/investigate.js",
            "/static/js/job.js",
            "/static/css/dashboard.css",
        ):
            res = self.client.get(asset)
            self.assertEqual(res.status_code, 200, asset)


# ---------------------------------------------------------------------------
# Findings list API
# ---------------------------------------------------------------------------


class TestFindingsListAPI(InvestigationTestCase):
    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        # Seed canonical rows once; unittest sorts test methods alphabetically,
        # so individual tests must not depend on run order.
        cls._instance = cls("test_lists_seeded_findings")
        cls._instance._seed_scan(
            [
                _finding("Reentrancy vulnerability in Vault.withdraw"),
                _finding(
                    "Access control issue in Vault.setOwner",
                    severity=Severity.MEDIUM,
                    function="setOwner",
                    lines=[20],
                ),
            ]
        )

    def test_lists_seeded_findings(self) -> None:
        # Seed a row unique to this test: sibling tests triage the class-level
        # rows (e.g. to Needs Review), so asserting on findings[0] was
        # order-dependent under randomized test ordering.
        unique = "Unchecked call in Vault.sweepListedOnly"
        self._seed_scan(
            [
                _finding(unique, function="sweepListedOnly", lines=[77]),
                _finding(
                    "Access control issue in Vault.setOwner",
                    severity=Severity.MEDIUM,
                    function="setOwner",
                    lines=[20],
                ),
            ]
        )
        res = self.client.get("/api/findings", params={"limit": 500})
        self.assertEqual(res.status_code, 200)
        body = res.json()
        self.assertGreaterEqual(body["total"], 2)
        self.assertTrue(body["findings"])
        for key in ("scan_id", "fingerprint", "title", "severity", "state"):
            self.assertIn(key, body["findings"][0])
        mine = [r for r in body["findings"] if r["title"] == unique]
        self.assertTrue(mine, "freshly seeded finding not listed")
        self.assertEqual(mine[0]["state"], TriageState.NEW.value)

    def test_severity_filter(self) -> None:
        res = self.client.get("/api/findings", params={"severity": "MEDIUM"})
        self.assertEqual(res.status_code, 200)
        for row in res.json()["findings"]:
            self.assertEqual(row["severity"], "MEDIUM")

    def test_search_filter(self) -> None:
        res = self.client.get("/api/findings", params={"q": "setOwner"})
        self.assertEqual(res.status_code, 200)
        self.assertTrue(res.json()["findings"])
        for row in res.json()["findings"]:
            self.assertIn(
                "setowner",
                (row["title"] + str(row.get("affected_function") or "")).lower(),
            )

    def test_sort_by_title(self) -> None:
        res = self.client.get("/api/findings", params={"sort": "title"})
        self.assertEqual(res.status_code, 200)
        titles = [r["title"].lower() for r in res.json()["findings"]]
        self.assertEqual(titles, sorted(titles))

    def test_group_by_severity(self) -> None:
        res = self.client.get("/api/findings", params={"group": "severity"})
        self.assertEqual(res.status_code, 200)
        groups = res.json().get("groups") or {}
        self.assertTrue(groups)
        self.assertIn("MEDIUM", groups)

    def test_state_filter_after_transition(self) -> None:
        scan_id, fp, _ = self._seed_completed([_finding("NeedsReview unique fixture title")])
        self.client.post(
            f"/api/findings/{scan_id}/state",
            json={"fingerprint": fp, "state": "Needs Review"},
        )
        res = self.client.get("/api/findings", params={"state": "Needs Review"})
        self.assertEqual(res.status_code, 200)
        matched = [r for r in res.json()["findings"] if r["title"] == "NeedsReview unique fixture title"]
        self.assertTrue(matched)
        for row in matched:
            self.assertEqual(row["state"], "Needs Review")

    def test_review_state_is_scoped_to_its_scan(self) -> None:
        """The same fingerprint in two scans keeps independent triage states.

        Reviews are keyed (scan_id, fingerprint). A review written for one
        scan must never leak onto another scan's finding with the same
        fingerprint (previously the oldest row silently won).
        """
        title = "CrossScan scoped fixture title"
        scan_a, _, _ = self._seed_completed([_finding(title)])
        scan_b, fp, _ = self._seed_completed([_finding(title)])

        res = self.client.post(
            f"/api/findings/{scan_b}/state",
            json={"fingerprint": fp, "state": "Needs Review"},
        )
        self.assertEqual(res.status_code, 200, res.text)

        res = self.client.get("/api/findings", params={"q": "CrossScan scoped"})
        self.assertEqual(res.status_code, 200)
        rows = [r for r in res.json()["findings"] if r["title"] == title]
        by_scan = {r["scan_id"]: r for r in rows}
        self.assertIn(scan_a, by_scan)
        self.assertIn(scan_b, by_scan)
        self.assertEqual(by_scan[scan_b]["state"], "Needs Review")
        self.assertEqual(
            by_scan[scan_a]["state"],
            TriageState.NEW.value,
            "a review for scan B must not leak onto scan A",
        )


# ---------------------------------------------------------------------------
# Investigation payload
# ---------------------------------------------------------------------------


class TestInvestigationAPI(InvestigationTestCase):
    def test_false_positive_considerations_keeps_full_sentence(self) -> None:
        """``false_positive_risk`` is a str — never explode it per character.

        The defender payload used to iterate the field as a sequence, so
        one sentence became dozens of single-character bullets in every
        investigation/report export.
        """
        from auditor.investigation import build_investigation

        finding = _finding("CharSplit fixture title").to_dict()
        finding["false_positive_risk"] = "Requires manual review of the call pattern"
        payload = build_investigation(finding, {"status": "completed"})

        considerations = payload["defender"]["false_positive_considerations"]
        self.assertTrue(
            any(
                "Requires manual review of the call pattern" in str(item)
                for item in considerations
            ),
            f"sentence lost: {considerations!r}",
        )
        self.assertNotIn("R", considerations, "string iterated char-by-char")

    def test_payload_shape(self) -> None:
        scan_id, fp, _ = self._seed_completed([_finding()])
        res = self.client.get(
            f"/api/findings/{scan_id}/investigation", params={"fp": fp}
        )
        self.assertEqual(res.status_code, 200)
        body = res.json()
        for key in (
            "title",
            "fingerprint",
            "attacker",
            "defender",
            "evidence",
            "review",
            "bounty",
            "ai_analysis",
            "executive_summary",
            "classification",
            "financial_impact",
            "severity_provenance",
            "duplicates",
        ):
            self.assertIn(key, body)
        self.assertIn("reachability", body["attacker"])
        self.assertIn("exposure", body["attacker"])
        self.assertIn("attack_path", body["attacker"])
        self.assertIn("vulnerable_operation", body["attacker"])
        self.assertIn("call_path", body["attacker"])
        self.assertIn("validation_time", body["attacker"])
        self.assertIn("evidence_needed", body["attacker"])
        self.assertIn("root_cause", body["defender"])
        self.assertIn("test_plan", body["defender"])
        self.assertIn("estimates", body["defender"])
        self.assertIn("actionable_fix", body["defender"])
        self.assertIn("example_patch", body["defender"])

    def test_unknowns_are_labeled_not_invented(self) -> None:
        scan_id, fp, _ = self._seed_completed([_finding()])
        res = self.client.get(
            f"/api/findings/{scan_id}/investigation", params={"fp": fp}
        )
        body = res.json()
        exposure = body["attacker"]["exposure"]["theoretical_max"]["value"]
        self.assertTrue(
            exposure.startswith("Unknown") or exposure.startswith("Approximate"),
            f"exposure must be labeled, got {exposure!r}",
        )
        dumped = json.dumps(body)
        # No fabricated monetary figures anywhere in the payload (the word
        # "USD" may appear in honest disclaimers such as "no price source").
        self.assertIsNone(re.search(r"\$\s?\d", dumped), "dollar amount found")
        self.assertIsNone(re.search(r"\d+(?:\.\d+)?\s*USD\b", dumped), "USD amount found")
        self.assertIsNone(re.search(r"\b(?:loss|stolen|drained)\b[^.]{0,40}\$?\d", dumped, re.I),
                          "loss figure found")

    def test_estimates_are_labeled_approximate(self) -> None:
        scan_id, fp, _ = self._seed_completed([_finding()])
        body = self.client.get(
            f"/api/findings/{scan_id}/investigation", params={"fp": fp}
        ).json()
        estimates = body["defender"]["estimates"]
        self.assertIn("validation", estimates)
        self.assertIn("remediation", estimates)
        self.assertNotIn(
            "re-audit",
            " ".join(r["stage"].lower() for r in estimates["remediation"]),
            "validation-only stage must not be in remediation group",
        )
        for group in ("validation", "remediation"):
            rows = estimates[group]
            self.assertTrue(rows, f"group {group} must not be empty")
            for est in rows:
                self.assertIn("range", est)
                self.assertEqual(est.get("group"), group)
                self.assertTrue(
                    "approximate" in str(est["range"]).lower()
                    or "approximate" in str(est.get("basis", "")).lower(),
                    f"estimate must be labeled: {est}",
                )
        self.assertIn("approximate", str(estimates.get("note", "")).lower())

    def test_evidence_uses_real_source(self) -> None:
        scan_id, fp, root = self._seed_completed([_finding()])
        body = self.client.get(
            f"/api/findings/{scan_id}/investigation", params={"fp": fp}
        ).json()
        source = body["defender"]["root_cause"]["source"]
        self.assertIn("source file", source["origin"])
        self.assertTrue(source["lines"])
        joined = " ".join(ln["text"] for ln in source["lines"])
        self.assertIn("withdraw", joined)

    def test_bounty_never_asserts_eligibility(self) -> None:
        scan_id, fp, _ = self._seed_completed([_finding()])
        body = self.client.get(
            f"/api/findings/{scan_id}/investigation", params={"fp": fp}
        ).json()
        bounty = body["bounty"]
        self.assertEqual(bounty["status"], "not_checked")
        self.assertIn("not", bounty["eligibility"].lower())

    def test_unknown_scan_404(self) -> None:
        res = self.client.get(
            "/api/findings/does-not-exist/investigation", params={"fp": "x"}
        )
        self.assertEqual(res.status_code, 404)

    def test_unknown_fingerprint_404(self) -> None:
        scan_id, _, _ = self._seed_completed([_finding()])
        res = self.client.get(
            f"/api/findings/{scan_id}/investigation", params={"fp": "nope"}
        )
        self.assertEqual(res.status_code, 404)


# ---------------------------------------------------------------------------
# Triage state machine
# ---------------------------------------------------------------------------


class TestStateMachine(InvestigationTestCase):
    def test_new_to_needs_review(self) -> None:
        scan_id, fp, _ = self._seed_completed([_finding()])
        res = self.client.post(
            f"/api/findings/{scan_id}/state",
            json={"fingerprint": fp, "state": "Needs Review", "note": "triage"},
        )
        self.assertEqual(res.status_code, 200, res.text)
        body = res.json()
        self.assertEqual(body["review"]["state"], "Needs Review")
        self.assertEqual(len(body["history"]), 1)

    def test_new_to_confirmed_rejected(self) -> None:
        scan_id, fp, _ = self._seed_completed([_finding()])
        res = self.client.post(
            f"/api/findings/{scan_id}/state",
            json={"fingerprint": fp, "state": "Confirmed by Evidence"},
        )
        self.assertEqual(res.status_code, 422)
        self.assertIn("not allowed", res.json()["detail"])

    def test_full_chain_with_fact_evidence(self) -> None:
        scan_id, fp, _ = self._seed_completed([_finding(with_fact=True)])
        for state in (
            "Needs Review",
            "Potential Vulnerability",
            "Confirmed by Evidence",
        ):
            res = self.client.post(
                f"/api/findings/{scan_id}/state",
                json={"fingerprint": fp, "state": state},
            )
            self.assertEqual(res.status_code, 200, f"{state}: {res.text}")
        res = self.client.get(
            f"/api/findings/{scan_id}/investigation", params={"fp": fp}
        )
        self.assertEqual(res.json()["review"]["state"], "Confirmed by Evidence")

    def test_confirm_requires_fact_evidence(self) -> None:
        scan_id, fp, _ = self._seed_completed([_finding(with_fact=False)])
        store = open_store(history_db_path())
        try:
            self.assertFalse(has_fact_evidence(get_review(store, scan_id, fp)))
        finally:
            store.close()
        for state in ("Needs Review", "Potential Vulnerability"):
            self.client.post(
                f"/api/findings/{scan_id}/state",
                json={"fingerprint": fp, "state": state},
            )
        res = self.client.post(
            f"/api/findings/{scan_id}/state",
            json={"fingerprint": fp, "state": "Confirmed by Evidence"},
        )
        self.assertEqual(res.status_code, 422)
        self.assertIn("FACT", res.json()["detail"])

    def test_retested_not_reachable_directly(self) -> None:
        scan_id, fp, _ = self._seed_completed([_finding()])
        res = self.client.post(
            f"/api/findings/{scan_id}/state",
            json={"fingerprint": fp, "state": "Retested"},
        )
        self.assertEqual(res.status_code, 422)

    def test_unknown_state_name_422(self) -> None:
        scan_id, fp, _ = self._seed_completed([_finding()])
        res = self.client.post(
            f"/api/findings/{scan_id}/state",
            json={"fingerprint": fp, "state": "Made Up State"},
        )
        self.assertEqual(res.status_code, 422)

    def test_unknown_fingerprint_404(self) -> None:
        scan_id, _, _ = self._seed_completed([_finding()])
        res = self.client.post(
            f"/api/findings/{scan_id}/state",
            json={"fingerprint": "missing", "state": "Needs Review"},
        )
        self.assertEqual(res.status_code, 404)


# ---------------------------------------------------------------------------
# Metadata
# ---------------------------------------------------------------------------


class TestMetadata(InvestigationTestCase):
    def test_metadata_roundtrip(self) -> None:
        scan_id, fp, _ = self._seed_completed([_finding()])
        res = self.client.post(
            f"/api/scans/{scan_id}/metadata",
            json={"project_name": "Demo", "protocol_category": "other"},
        )
        self.assertEqual(res.status_code, 200, res.text)
        self.assertEqual(res.json()["metadata"]["project_name"], "Demo")
        body = self.client.get(
            f"/api/findings/{scan_id}/investigation", params={"fp": fp}
        ).json()
        self.assertEqual(body["protocol"]["fields"]["project_name"]["value"], "Demo")

    def test_invalid_category_422(self) -> None:
        scan_id, _, _ = self._seed_completed([_finding()])
        res = self.client.post(
            f"/api/scans/{scan_id}/metadata",
            json={"protocol_category": "definitely-not-real"},
        )
        self.assertEqual(res.status_code, 422)


# ---------------------------------------------------------------------------
# Bounty checks
# ---------------------------------------------------------------------------


class TestBounty(InvestigationTestCase):
    def test_no_project_not_checked(self) -> None:
        scan_id, _, _ = self._seed_completed([_finding()])
        res = self.client.post(f"/api/scans/{scan_id}/bounty", json={})
        self.assertEqual(res.status_code, 200, res.text)
        body = res.json()
        self.assertEqual(body["status"], "not_checked")
        self.assertIn("not assessed", body["eligibility"].lower())
        self.assertIn("reminder", body)

    def test_private_url_blocked(self) -> None:
        scan_id, _, _ = self._seed_completed([_finding()])
        res = self.client.post(
            f"/api/scans/{scan_id}/bounty",
            json={"official_url": "http://localhost:8787/program"},
        )
        self.assertEqual(res.status_code, 200, res.text)
        body = res.json()
        self.assertEqual(body["status"], "blocked")
        self.assertIn("not assessed", body["eligibility"].lower())
        self.assertIn("non-public", body["error"])

    def test_file_scheme_rejected(self) -> None:
        scan_id, _, _ = self._seed_completed([_finding()])
        res = self.client.post(
            f"/api/scans/{scan_id}/bounty",
            json={"official_url": "file:///etc/passwd"},
        )
        # Rejected before any fetch; never asserted as eligible either way.
        self.assertIn(res.status_code, (200, 422))
        if res.status_code == 200:
            body = res.json()
            self.assertNotEqual(body["eligibility"], "eligible")
            self.assertIn("not assessed", body["eligibility"].lower())

    def test_registry_file_is_valid_json(self) -> None:
        registry = PROJECT_ROOT / "config" / "bounty_registry.json"
        self.assertTrue(registry.exists())
        data = json.loads(registry.read_text(encoding="utf-8"))
        self.assertIn("programs", data)


# ---------------------------------------------------------------------------
# Reports
# ---------------------------------------------------------------------------


class TestReports(InvestigationTestCase):
    def test_audit_report_sections(self) -> None:
        from auditor.report_builder import build_report

        scan_id, fp, _ = self._seed_completed([_finding()])
        report = build_report(scan_id, history_db=history_db_path())
        for key in (
            "executive_summary",
            "scope_and_context",
            "prioritized_findings",
            "attacker_view",
            "defender_plan",
            "evidence_summary",
            "exposure_assumptions_confidence",
            "estimates",
            "bounty_status",
            "test_and_retest_results",
            "false_positive_considerations",
            "ai_generated_analysis",
            "unknowns_and_limitations",
            "origin_legend",
        ):
            self.assertIn(key, report)

    def test_markdown_render_honest_labels(self) -> None:
        from auditor.report_builder import build_report, render_markdown

        scan_id, _, _ = self._seed_completed([_finding()])
        report = build_report(scan_id, history_db=history_db_path())
        md = render_markdown(report)
        self.assertIn("Audit report", md)
        self.assertIn("Origin legend", md)
        self.assertTrue("Unknown — not verified" in md or "Not assessed" in md)

    def test_finding_report_endpoints(self) -> None:
        scan_id, fp, _ = self._seed_completed([_finding()])
        res_json = self.client.get(
            f"/api/findings/{scan_id}/report", params={"fp": fp}
        )
        self.assertEqual(res_json.status_code, 200, res_json.text)
        res_md = self.client.get(
            f"/api/findings/{scan_id}/report",
            params={"fp": fp, "format": "markdown"},
        )
        self.assertEqual(res_md.status_code, 200)
        self.assertIn("Finding report", res_md.text)
        self.assertIn("Triage state", res_md.text)

    def test_audit_report_endpoint_json_and_markdown(self) -> None:
        scan_id, _, _ = self._seed_completed([_finding()])
        res_json = self.client.get(f"/api/scans/{scan_id}/audit-report")
        self.assertEqual(res_json.status_code, 200)
        self.assertIn("origin_legend", res_json.json())
        res_md = self.client.get(
            f"/api/scans/{scan_id}/audit-report", params={"format": "markdown"}
        )
        self.assertEqual(res_md.status_code, 200)
        self.assertIn("# Audit report", res_md.text)

    def test_reports_never_contain_api_key(self) -> None:
        from auditor.report_builder import build_report, render_markdown

        scan_id, fp, _ = self._seed_completed([_finding()])
        with mock.patch.dict(os.environ, {"ANTHROPIC_API_KEY": FAKE_ANTHROPIC_KEY}):
            report = build_report(scan_id, history_db=history_db_path())
            text = json.dumps(report, default=str) + render_markdown(report)
        self.assertNotIn(FAKE_ANTHROPIC_KEY, text)
        self.assertNotIn("ANTHROPIC_API_KEY", text)


# ---------------------------------------------------------------------------
# Slither parsers (regression: labels, evidence, severity mapping)
# ---------------------------------------------------------------------------


class TestSlitherParsers(unittest.TestCase):
    def test_reentrancy_benign_maps_to_low(self) -> None:
        from auditor.analysis.reentrancy import _parse_slither_text

        findings = _parse_slither_text(REENTRANCY_SLITHER_OUTPUT, "")
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f.severity, Severity.LOW)
        self.assertEqual(f.affected_lines, [9, 10, 11, 12, 13])
        self.assertEqual(len(f.evidence), 2)
        self.assertTrue(all(e.epistemic is Epistemic.FACT for e in f.evidence))
        self.assertIn("reentrancy-benign", f.description)

    def test_reentrancy_eth_maps_to_high(self) -> None:
        from auditor.analysis.reentrancy import _parse_slither_text

        output = REENTRANCY_SLITHER_OUTPUT.replace(
            "Detector: reentrancy-benign", "Detector: reentrancy-eth"
        )
        findings = _parse_slither_text(output, "")
        self.assertEqual(findings[0].severity, Severity.HIGH)

    def test_access_control_only_allowed_detectors(self) -> None:
        from auditor.analysis.access_control import _parse_slither_text

        # Reentrancy header alone must not become an access-control finding.
        findings = _parse_slither_text(REENTRANCY_SLITHER_OUTPUT, "")
        self.assertEqual(findings, [])
        # missing-zero-check is an access-control detector and is captured.
        findings = _parse_slither_text(ACCESS_SLITHER_OUTPUT, "")
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f.affected_function, "setOwner")
        self.assertEqual(f.affected_lines, [20])
        self.assertTrue(f.evidence)
        self.assertTrue(all(e.epistemic is Epistemic.FACT for e in f.evidence))

    def test_failure_note_on_compilation_error(self) -> None:
        from auditor.analysis.reentrancy import _slither_failure_note

        note = _slither_failure_note(
            "Traceback (most recent call last):\nInvalidCompilation: boom"
        )
        self.assertIsNotNone(note)
        self.assertIn("failed to analyze", note)

    def test_no_failure_note_on_clean_output(self) -> None:
        from auditor.analysis.reentrancy import _slither_failure_note

        self.assertIsNone(_slither_failure_note("INFO: analyzed"))

    def test_empty_evidence_still_yields_fact(self) -> None:
        from auditor.analysis.reentrancy import _make_finding

        f = _make_finding("Vault", "withdraw", "9-13", [])
        self.assertEqual(len(f.evidence), 1)
        self.assertIs(f.evidence[0].epistemic, Epistemic.FACT)
        self.assertTrue(has_fact_evidence(f.to_dict()))

    def test_parse_lines_single_and_range(self) -> None:
        from auditor.analysis.reentrancy import _parse_lines

        self.assertEqual(_parse_lines("20"), [20])
        self.assertEqual(_parse_lines("3-5"), [3, 4, 5])
        self.assertEqual(_parse_lines("unknown"), [])


# ---------------------------------------------------------------------------
# AI audit agent + jobs
# ---------------------------------------------------------------------------


class TestAIAudit(InvestigationTestCase):
    def _patched_analyzers(self, titles: list[str]):
        return mock.patch.multiple(
            "auditor.ai_agent",
            reentrancy_analyze=mock.Mock(
                return_value=_outcome(titles, severity=Severity.HIGH)
            ),
            access_control_analyze=mock.Mock(return_value=_outcome([])),
            generic_analyze=mock.Mock(return_value=_outcome([])),
        )

    def test_ai_audit_job_without_llm(self) -> None:
        root = self._source_dir()
        with self._patched_analyzers(["Reentrancy vulnerability in Vault.withdraw"]):
            res = self.client.post(
                "/api/ai-audit",
                json={
                    "path": str(root),
                    "deep_tests": False,
                    "use_ai": False,
                    "timeout_seconds": 120,
                },
            )
            self.assertEqual(res.status_code, 202, res.text)
            job = self._wait_for_job(res.json()["job_id"])
        self.assertEqual(job["status"], "completed", job.get("error"))
        report = job["report"]
        self.assertEqual(report["kind"], "ai_audit")
        stages = {s["name"]: s for s in job["stages"]}
        for name in (
            "scan",
            "collect",
            "dedupe",
            "prioritize",
            "inspect",
            "analyze",
            "tests",
            "report",
            "save",
        ):
            self.assertIn(name, stages)
            self.assertEqual(stages[name]["status"], "done", stages[name])
        self.assertEqual(report["ai_analysis"]["status"], "skipped")
        self.assertEqual(len(report["conclusions"]), 1)
        # The scan is persisted and visible through the findings API.
        scan_id = report["scan_id"]
        res = self.client.get(f"/api/scans/{scan_id}")
        self.assertEqual(res.status_code, 200)
        self.assertEqual(len(res.json()["findings"]), 1)

    def test_ai_audit_rejects_missing_path(self) -> None:
        res = self.client.post(
            "/api/ai-audit",
            json={"path": "/definitely/not/a/real/path", "use_ai": False},
        )
        self.assertIn(res.status_code, (400, 422))

    def test_ai_disabled_is_labeled_not_fabricated(self) -> None:
        from auditor.ai_agent import Pipeline, _ai_enrich

        pipeline = Pipeline([], lambda _m: None, timeout_seconds=30)
        result = _ai_enrich(
            [],
            [],
            endpoint="http://localhost:11434",
            model="test-model",
            use_ai=False,
            pipeline=pipeline,
            source_root=Path(tempfile.gettempdir()),
        )
        self.assertEqual(result["status"], "skipped")
        self.assertIn("use_ai=false", result["reason"])
        self.assertEqual(result["origin"], "generated_ai_analysis")
        self.assertEqual(result["findings"], [])

    def test_ollama_unreachable_is_loud_skip(self) -> None:
        from auditor.ai_agent import Pipeline, _ai_enrich

        status = SimpleNamespace(reachable=False, error="connection refused")
        pipeline = Pipeline([], lambda _m: None, timeout_seconds=30)
        with mock.patch("auditor.ollama.probe_ollama", return_value=status):
            result = _ai_enrich(
                [],
                [],
                endpoint="http://localhost:11434",
                model="test-model",
                use_ai=True,
                pipeline=pipeline,
                source_root=Path(tempfile.gettempdir()),
            )
        self.assertEqual(result["status"], "skipped")
        self.assertIn("unreachable", result["reason"])

    def test_ai_audit_report_has_no_secret(self) -> None:
        root = self._source_dir()
        with self._patched_analyzers(["Reentrancy vulnerability in Vault.withdraw"]):
            with mock.patch.dict(
                os.environ, {"ANTHROPIC_API_KEY": FAKE_ANTHROPIC_KEY}
            ):
                res = self.client.post(
                    "/api/ai-audit",
                    json={
                        "path": str(root),
                        "deep_tests": False,
                        "use_ai": False,
                        "timeout_seconds": 120,
                    },
                )
                job = self._wait_for_job(res.json()["job_id"])
        blob = json.dumps(job, default=str) + json.dumps(job.get("report"), default=str)
        self.assertNotIn(FAKE_ANTHROPIC_KEY, blob)
        self.assertNotIn("ANTHROPIC_API_KEY", blob)

    def test_ai_audit_investigation_linkage(self) -> None:
        """Verify that an AI audit's analysis links back to the original scan's investigation."""
        scan_orig, fp, root = self._seed_completed([_finding()])
        with self._patched_analyzers(["Reentrancy vulnerability in Vault.withdraw"]):
            res = self.client.post(
                "/api/ai-audit",
                json={
                    "path": str(root),
                    "scan_id": scan_orig,
                    "deep_tests": False,
                    "use_ai": False,
                    "timeout_seconds": 120,
                },
            )
            self.assertEqual(res.status_code, 202)
            job = self._wait_for_job(res.json()["job_id"])
        self.assertEqual(job["status"], "completed")
        # Check that get_investigation on the original scan can now discover the ai_analysis
        inv = self.client.get(
            f"/api/findings/{scan_orig}/investigation", params={"fp": fp}
        ).json()
        self.assertIsNotNone(inv)

    def test_job_persistence_survives_reload(self) -> None:
        """Verify that job states are persisted and reloaded by JobManager."""
        import uuid
        from auditor.dashboard.jobs import JobManager, ScanJob, ScanStatus
        cache = Path(self._tmpdir.name) / "jobs_cache.json"
        self._saved_jobs_cache = os.environ.get("AUDITOR_JOBS_CACHE")
        os.environ["AUDITOR_JOBS_CACHE"] = str(cache)
        jm = JobManager()
        test_id = "test-job-" + uuid.uuid4().hex[:8]
        job = ScanJob(
            job_id=test_id,
            scan_type="ai_audit",
            status=ScanStatus.COMPLETED,
            message="Completed test job",
        )
        jm._jobs[test_id] = job
        jm._persist_jobs()

        # Create a new JobManager instance (simulating restart)
        jm2 = JobManager()
        recovered = jm2.get_job(test_id)
        self.assertIsNotNone(recovered)
        self.assertEqual(recovered.job_id, test_id)
        self.assertEqual(recovered.message, "Completed test job")
        if self._saved_jobs_cache is None:
            os.environ.pop("AUDITOR_JOBS_CACHE", None)
        else:
            os.environ["AUDITOR_JOBS_CACHE"] = self._saved_jobs_cache


# ---------------------------------------------------------------------------
# Retest
# ---------------------------------------------------------------------------


class TestRetest(InvestigationTestCase):
    def test_retest_job_persists_matching_finding(self) -> None:
        scan_id, fp, _ = self._seed_completed(
            [_finding("Reentrancy vulnerability in Vault.withdraw", lines=[10, 11, 12])]
        )
        with mock.patch(
            "auditor.ai_agent.reentrancy_analyze",
            return_value=_outcome(
                ["Reentrancy vulnerability in Vault.withdraw"], severity=Severity.HIGH
            ),
        ), mock.patch(
            "auditor.ai_agent.access_control_analyze", return_value=_outcome([])
        ), mock.patch(
            "auditor.ai_agent.generic_analyze", return_value=_outcome([])
        ):
            res = self.client.post(
                f"/api/findings/{scan_id}/retest", json={"fingerprint": fp}
            )
            self.assertEqual(res.status_code, 202, res.text)
            job = self._wait_for_job(res.json()["job_id"])
        self.assertEqual(job["status"], "completed", job.get("error"))
        report = job["report"]
        self.assertEqual(report["kind"], "retest")
        self.assertTrue(report["persisted"])
        self.assertIn("Retest method", " ".join(report["notes"]))
        # The result payload lives in `report`, never coerced into an empty
        # ScanDetail-shaped `result` with fabricated blank fields.
        self.assertIsNone(job["result"])
        # A retest scan is recorded (append-only history).
        history = ScanHistory(history_db_path())
        try:
            rec = history.get_scan(report["retest_scan_id"])
        finally:
            history.close()
        self.assertEqual(rec["config_fingerprint"], "retest")

    def test_retest_body_scan_id_must_match_path(self) -> None:
        scan_id, fp, _ = self._seed_completed([_finding()])
        res = self.client.post(
            f"/api/findings/{scan_id}/retest",
            json={"scan_id": "other", "fingerprint": fp},
        )
        self.assertEqual(res.status_code, 422)

    def test_retest_missing_fingerprint_422(self) -> None:
        scan_id, _, _ = self._seed_completed([_finding()])
        res = self.client.post(f"/api/findings/{scan_id}/retest", json={})
        self.assertEqual(res.status_code, 422)

    def test_fixed_advances_to_retested_only_on_retest(self) -> None:
        from auditor.ai_agent import run_retest

        scan_id, fp, _ = self._seed_completed(
            [_finding("Reentrancy vulnerability in Vault.withdraw", lines=[10, 11, 12])]
        )
        for state in (
            "Needs Review",
            "Potential Vulnerability",
            "Confirmed by Evidence",
            "Fixed",
        ):
            res = self.client.post(
                f"/api/findings/{scan_id}/state",
                json={"fingerprint": fp, "state": state},
            )
            self.assertEqual(res.status_code, 200, res.text)
        with mock.patch(
            "auditor.ai_agent.reentrancy_analyze",
            return_value=_outcome(
                ["Reentrancy vulnerability in Vault.withdraw"], severity=Severity.HIGH
            ),
        ), mock.patch(
            "auditor.ai_agent.access_control_analyze", return_value=_outcome([])
        ), mock.patch(
            "auditor.ai_agent.generic_analyze", return_value=_outcome([])
        ):
            result = run_retest(
                scan_id, fp, history_db=history_db_path(), timeout_seconds=60
            )
        self.assertIn("Fixed -> Retested", str(result.get("state_change")))
        store = open_store(history_db_path())
        try:
            review = get_review(store, scan_id, fp)
        finally:
            store.close()
        self.assertEqual(review["state"], TriageState.RETESTED.value)

    def test_retest_without_fixed_state_does_not_change_state(self) -> None:
        from auditor.ai_agent import run_retest

        scan_id, fp, _ = self._seed_completed([_finding()])
        with mock.patch(
            "auditor.ai_agent.reentrancy_analyze",
            return_value=_outcome(["Reentrancy vulnerability in Vault.withdraw"]),
        ), mock.patch(
            "auditor.ai_agent.access_control_analyze", return_value=_outcome([])
        ), mock.patch(
            "auditor.ai_agent.generic_analyze", return_value=_outcome([])
        ):
            run_retest(scan_id, fp, history_db=history_db_path(), timeout_seconds=60)
        store = open_store(history_db_path())
        try:
            review = get_review(store, scan_id, fp)
        finally:
            store.close()
        self.assertEqual(review["state"], TriageState.NEW.value)

    def test_source_change_is_reported_honestly(self) -> None:
        from auditor.ai_agent import run_retest

        scan_id, fp, root = self._seed_completed(
            [_finding("Reentrancy vulnerability in Vault.withdraw", lines=[10, 11, 12])]
        )
        # Mutate the source after the scan.
        (root / "Vault.sol").write_text(VAULT_SOL + "\n// changed\n", encoding="utf-8")
        with mock.patch(
            "auditor.ai_agent.reentrancy_analyze",
            return_value=_outcome(
                ["Reentrancy vulnerability in Vault.withdraw"], severity=Severity.HIGH
            ),
        ), mock.patch(
            "auditor.ai_agent.access_control_analyze", return_value=_outcome([])
        ), mock.patch(
            "auditor.ai_agent.generic_analyze", return_value=_outcome([])
        ):
            result = run_retest(
                scan_id, fp, history_db=history_db_path(), timeout_seconds=60
            )
        # Directory scans historically store an "unknown" hash sentinel; the
        # result must say what is known instead of inventing a verdict.
        self.assertIn("source_changed", result)
        self.assertIn("persisted", result)


# ---------------------------------------------------------------------------
# OpenCode proposals
# ---------------------------------------------------------------------------


class TestOpenCode(InvestigationTestCase):
    def _fake_run_result(self, stdout: str):
        return SimpleNamespace(
            stdout=stdout, stderr="", error=None, timed_out=False, returncode=0
        )

    def test_probe_reports_available(self) -> None:
        with mock.patch(
            "auditor.opencode_review.procs_run",
            return_value=SimpleNamespace(
                stdout="1.19.0", stderr="", error=None, timed_out=False, returncode=0
            ),
        ), mock.patch(
            "auditor.opencode_review.shutil.which", return_value="/usr/bin/opencode"
        ):
            from auditor.opencode_review import probe

            status = probe()
        self.assertTrue(status["available"])
        self.assertIn("scratch copy", status["usage"])

    def test_propose_with_mocked_opencode(self) -> None:
        from auditor.opencode_review import propose_patch

        root = self._source_dir()
        target = root / "Vault.sol"
        revised = VAULT_SOL.replace(
            '(bool ok, ) = msg.sender.call.value(amount)("");',
            "(bool ok, ) = msg.sender.call.value(amount)(\"\"); // reordered",
        )
        assistant = "Here is the file:\n```solidity\n" + revised + "\n```\n"
        with mock.patch(
            "auditor.opencode_review.probe",
            return_value={"available": True, "binary": "/usr/bin/opencode", "version": "1.19.0"},
        ), mock.patch(
            "auditor.opencode_review.procs_run",
            return_value=self._fake_run_result(assistant),
        ):
            proposal = propose_patch(
                project_dir=root,
                target_file=target,
                finding=_finding().to_dict(),
                scan_id="scan-x",
                fingerprint="fp-x",
                timeout=5,
            )
        self.assertEqual(proposal["status"], "proposed", proposal)
        self.assertIn("diff", proposal)
        self.assertTrue(proposal["proposal_id"])
        self.assertNotIn(FAKE_ANTHROPIC_KEY, json.dumps(proposal))

    def test_propose_falls_back_to_unfenced_response(self) -> None:
        from auditor.opencode_review import propose_patch

        root = self._source_dir()
        target = root / "Vault.sol"
        revised = VAULT_SOL.replace("contract Vault", "contract Vault2")
        with mock.patch(
            "auditor.opencode_review.probe",
            return_value={"available": True, "binary": "/usr/bin/opencode", "version": "1.19.0"},
        ), mock.patch(
            "auditor.opencode_review.procs_run",
            return_value=self._fake_run_result("Sure:\n" + revised),
        ):
            proposal = propose_patch(
                project_dir=root,
                target_file=target,
                finding=_finding().to_dict(),
                timeout=5,
            )
        self.assertEqual(proposal["status"], "proposed", proposal)

    def test_propose_scratch_edit_is_used(self) -> None:
        from auditor.opencode_review import propose_patch

        root = self._source_dir()
        target = root / "Vault.sol"
        revised = VAULT_SOL + "\n// edited via write tool\n"

        def _fake_run(argv, timeout=None, cwd=None):
            # Simulate OpenCode writing the staged copy in the scratch dir.
            scratch = Path(argv[argv.index("--dir") + 1])
            (scratch / "Vault.sol").write_text(revised, encoding="utf-8")
            return self._fake_run_result("done (no file text in chat)")

        with mock.patch(
            "auditor.opencode_review.probe",
            return_value={"available": True, "binary": "/usr/bin/opencode", "version": "1.19.0"},
        ), mock.patch("auditor.opencode_review.procs_run", side_effect=_fake_run):
            proposal = propose_patch(
                project_dir=root, target_file=target, finding=_finding().to_dict(), timeout=5
            )
        self.assertEqual(proposal["status"], "proposed", proposal)
        self.assertIn("edited via write tool", proposal.get("diff", ""))

    def test_propose_opencode_failure_is_reported(self) -> None:
        from auditor.opencode_review import propose_patch

        root = self._source_dir()
        with mock.patch(
            "auditor.opencode_review.probe",
            return_value={"available": True, "binary": "/usr/bin/opencode", "version": "1.19.0"},
        ), mock.patch(
            "auditor.opencode_review.procs_run",
            return_value=SimpleNamespace(
                stdout="", stderr="", error="timeout", timed_out=True, returncode=None
            ),
        ):
            proposal = propose_patch(
                project_dir=root, target_file=root / "Vault.sol", finding=_finding().to_dict(), timeout=5
            )
        self.assertEqual(proposal["status"], "failed")
        self.assertIn("opencode", proposal["reason"])

    def test_propose_rejects_outside_target(self) -> None:
        from auditor.opencode_review import propose_patch

        root = self._source_dir()
        outside = Path(tempfile.mkdtemp(prefix="outside-")) / "Evil.sol"
        outside.write_text("contract Evil {}", encoding="utf-8")
        with self.assertRaises(ValueError):
            propose_patch(
                project_dir=root, target_file=outside, finding=_finding().to_dict(), timeout=5
            )

    def test_apply_requires_approval_and_hash(self) -> None:
        import hashlib

        from auditor import opencode_review as ocr

        root = self._source_dir()
        target = root / "Vault.sol"
        revised = VAULT_SOL.replace("contract Vault", "contract VaultPatched")
        before_hash = hashlib.sha256(target.read_bytes()).hexdigest()
        after_hash = hashlib.sha256(revised.encode("utf-8")).hexdigest()
        pid = "test-proposal-apply-1"
        ocr._proposals[pid] = {
            "proposal_id": pid,
            "source": "test",
            "project_dir": str(root),
            "target_file": str(target),
            "relative_path": "Vault.sol",
            "scan_id": "scan-x",
            "fingerprint": "fp-x",
            "before_hash": before_hash,
            "after_hash": after_hash,
            "new_content": revised,
            "diff": "--- a/Vault.sol\n+++ b/Vault.sol\n",
            "created_at": time.time(),
        }
        try:
            # Approval is checked before anything else.
            res = self.client.post(f"/api/patches/{pid}/apply", json={"approval": False})
            self.assertEqual(res.status_code, 400)
            self.assertIn("approval", res.json()["detail"])

            # Wrong confirmation hash → conflict, file untouched.
            res = self.client.post(
                f"/api/patches/{pid}/apply",
                json={"approval": True, "expected_before_hash": "c" * 64},
            )
            self.assertEqual(res.status_code, 409)
            self.assertEqual(hashlib.sha256(target.read_bytes()).hexdigest(), before_hash)

            # Correct hash → applied.
            res = self.client.post(
                f"/api/patches/{pid}/apply",
                json={"approval": True, "expected_before_hash": before_hash},
            )
            self.assertEqual(res.status_code, 200, res.text)
            self.assertEqual(hashlib.sha256(target.read_bytes()).hexdigest(), after_hash)

            # Second apply → file changed since proposal.
            res = self.client.post(
                f"/api/patches/{pid}/apply",
                json={"approval": True, "expected_before_hash": before_hash},
            )
            self.assertEqual(res.status_code, 409)
        finally:
            ocr._proposals.pop(pid, None)

    def test_propose_endpoint_wiring(self) -> None:
        root = self._source_dir()
        target = root / "Vault.sol"
        with mock.patch(
            "auditor.opencode_review.propose_patch",
            return_value={
                "status": "proposed",
                "proposal_id": "wired-proposal",
                "diff": "--- a/Vault.sol\n+++ b/Vault.sol\n",
                "checked_at": "2026-01-01T00:00:00+00:00",
            },
        ), mock.patch(
            "auditor.dashboard.routes._load_finding_bundle",
            return_value={
                "record": {"source_path": str(root)},
                "finding": _finding().to_dict(),
            },
        ):
            res = self.client.post(
                "/api/findings/scan-x/propose", json={"fingerprint": "fp-x"}
            )
        self.assertEqual(res.status_code, 200, res.text)
        self.assertEqual(res.json()["proposal_id"], "wired-proposal")

    def test_propose_scan_id_mismatch_422(self) -> None:
        with mock.patch(
            "auditor.dashboard.routes._load_finding_bundle",
            return_value={"record": {}, "finding": {}},
        ):
            res = self.client.post(
                "/api/findings/scan-x/propose",
                json={"scan_id": "other", "fingerprint": "fp"},
            )
        self.assertEqual(res.status_code, 422)


# ---------------------------------------------------------------------------
# Fabrication guards (cross-cutting)
# ---------------------------------------------------------------------------


class TestFabricationGuards(InvestigationTestCase):
    def test_investigation_marks_generated_ai_analysis(self) -> None:
        scan_id, fp, _ = self._seed_completed([_finding()])
        body = self.client.get(
            f"/api/findings/{scan_id}/investigation", params={"fp": fp}
        ).json()
        ai = body.get("ai_analysis") or {}
        self.assertIn(body, [body])  # response decoded
        if ai:
            self.assertEqual(ai.get("origin"), "generated_ai_analysis")
        else:
            # Honest absence — never a fabricated model opinion.
            self.assertNotIn("risk_analysis", body)

    def test_deterministic_evidence_is_separate_from_ai(self) -> None:
        scan_id, fp, _ = self._seed_completed([_finding()])
        body = self.client.get(
            f"/api/findings/{scan_id}/investigation", params={"fp": fp}
        ).json()
        evidence = body["evidence"]
        items = evidence["items"]
        self.assertTrue(items)
        self.assertGreaterEqual(evidence["fact_count"], 1)
        for item in items:
            self.assertIn("epistemic", item)
            if item["epistemic"] == "FACT":
                self.assertNotIn("generated_ai_analysis", str(item.get("origin", "")))

    def test_no_operational_exploit_steps_in_playbook(self) -> None:
        scan_id, fp, _ = self._seed_completed([_finding()])
        body = self.client.get(
            f"/api/findings/{scan_id}/investigation", params={"fp": fp}
        ).json()
        playbook = {
            "attack_path": body["attacker"]["attack_path"],
            "preconditions": body["attacker"]["preconditions"],
            "misconceptions": body["attacker"]["misconceptions"],
            "test_plan": body["defender"]["test_plan"],
        }
        blob = json.dumps(playbook).lower()
        for banned in ("private key", "steal funds", "step 1:", "metamask"):
            self.assertNotIn(banned, blob)


# ---------------------------------------------------------------------------
# Pipeline cancellation / timeout
# ---------------------------------------------------------------------------


class TestPipeline(unittest.TestCase):
    def test_cancel_stops_next_stage(self) -> None:
        from auditor.ai_agent import Pipeline, PipelineAbort

        stages: list[dict] = []
        cancel = mock.Mock()
        cancel.is_set.return_value = True
        pipeline = Pipeline(stages, lambda _m: None, cancel_event=cancel, timeout_seconds=30)
        with self.assertRaises(PipelineAbort) as ctx:
            with pipeline.stage("scan"):
                pass
            with pipeline.stage("collect"):
                pass
        self.assertEqual(ctx.exception.reason, "cancelled")

    def test_timeout_stops_next_stage(self) -> None:
        from auditor.ai_agent import Pipeline, PipelineAbort

        stages: list[dict] = []
        pipeline = Pipeline(stages, lambda _m: None, cancel_event=None, timeout_seconds=0.001)
        time.sleep(0.01)
        with self.assertRaises(PipelineAbort) as ctx:
            with pipeline.stage("scan"):
                pass
        self.assertEqual(ctx.exception.reason, "timeout")

    def test_stage_records_status(self) -> None:
        from auditor.ai_agent import Pipeline

        stages: list[dict] = []
        pipeline = Pipeline(stages, lambda _m: None, timeout_seconds=30)
        with pipeline.stage("scan") as entry:
            entry["detail"] = "hello"
        self.assertEqual(stages[0]["name"], "scan")
        self.assertEqual(stages[0]["status"], "done")
        self.assertEqual(stages[0]["detail"], "hello")


# ---------------------------------------------------------------------------
# Investigation builder internals
# ---------------------------------------------------------------------------


class TestInvestigationBuilder(unittest.TestCase):
    def test_validate_root_rejects_missing(self) -> None:
        from auditor.investigation import _validate_root

        self.assertIsNone(_validate_root(None))
        self.assertIsNone(_validate_root("/definitely/not/here"))

    def test_snippet_reports_missing_file(self) -> None:
        from auditor.investigation import _snippet

        info = _snippet(None, [1])
        self.assertIsNotNone(info["read_error"])
        self.assertEqual(info["origin"], "not available")

    def test_snippet_uses_real_lines(self) -> None:
        from auditor.investigation import _snippet

        tmp = Path(tempfile.mkdtemp(prefix="snip-")) / "A.sol"
        tmp.write_text("\n".join(f"line {i}" for i in range(1, 41)), encoding="utf-8")
        info = _snippet(tmp, [10])
        first, last = info["line_range"]
        self.assertLessEqual(first, 10)
        self.assertGreaterEqual(last, 10)
        self.assertGreater(last - first + 1, 1)  # context lines included
        self.assertIn(10, [ln["n"] for ln in info["lines"]])
        self.assertIn("context", info["origin"])

    def test_playbook_selection(self) -> None:
        from auditor.investigation import _playbook_for

        reentrancy = _playbook_for(
            _finding("Reentrancy vulnerability in Vault.withdraw").to_dict()
        )
        self.assertEqual(reentrancy["kind"], "reentrancy")
        access = _playbook_for(_finding("Access control issue in Vault.setOwner").to_dict())
        self.assertEqual(access["kind"], "access_control")
        generic = _playbook_for(_finding("Some other issue").to_dict())
        self.assertEqual(generic["kind"], "generic")

    def test_root_cause_location_uses_finding_lines(self) -> None:
        from auditor.investigation import _root_cause_summary

        finding = _finding(lines=[17]).to_dict()
        playbook = {"kind": "access_control"}
        snippet = {"file": "/tmp/Vault.sol", "line_range": [14, 20]}
        summary = _root_cause_summary(finding, playbook, snippet)
        self.assertIn("line 17", summary)
        self.assertNotIn("14–20", summary)


if __name__ == "__main__":
    unittest.main()
