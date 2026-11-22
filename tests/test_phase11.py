"""Phase 11 test suite — evidence, financial impact, and fix clarity.

Covers:

* Source classification (test fixture / local source / deployed-unverified)
  and the no-fabrication rule for chain fields (a missing chain stays
  Unknown — never silently "ethereum").
* The Protocol & Financial Impact block: honest labels, methodology, and the
  promise that no dollar/token/loss figure is invented.
* Executive summary, actionable remediation steps, and the grounded example
  patch (suggestion only, never auto-applied).
* Severity/confidence provenance with evidence-backed verification and
  false-positive review signals, plus same-scan duplicate grouping.
* Bounty display gating on a fetched official source.
* Report/markdown rendering for every new section.

Run with:

    python3 -m unittest discover -s tests -v

Every test runs against a throwaway history database pointed to by
``AUDITOR_HISTORY_DB`` so the production ``audit_scan_history.db`` is never
written to, and no test performs a live network request.
"""

from __future__ import annotations

import json
import re
import sys
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
TESTS_DIR = Path(__file__).resolve().parent
for entry in (str(PROJECT_ROOT), str(TESTS_DIR)):
    if entry not in sys.path:
        sys.path.insert(0, entry)

from test_investigation import (  # noqa: E402
    VAULT_SOL,
    InvestigationTestCase,
    _finding,
)

from auditor.dashboard.paths import history_db_path  # noqa: E402
from auditor.model import finding_fingerprint  # noqa: E402


class Phase11Case(InvestigationTestCase):
    """Shared client + isolated history DB (inherited from Phase 10 base)."""


# ---------------------------------------------------------------------------
# Protocol, chain, classification
# ---------------------------------------------------------------------------


class TestProtocolAndChain(Phase11Case):
    def _investigation(self, scan_id: str, fp: str) -> dict:
        res = self.client.get(
            f"/api/findings/{scan_id}/investigation", params={"fp": fp}
        )
        self.assertEqual(res.status_code, 200, res.text)
        return res.json()

    def test_chain_unknown_when_not_recorded(self) -> None:
        scan_id, fp, _ = self._seed_completed([_finding()])
        body = self._investigation(scan_id, fp)
        chain = body["protocol"]["fields"]["chain"]
        self.assertTrue(
            chain["value"].startswith("Unknown"),
            f"missing chain must stay Unknown, got {chain['value']!r}",
        )
        self.assertEqual(chain["origin"], "unknown")
        chain_id = body["protocol"]["fields"]["chain_id"]
        self.assertTrue(chain_id["value"].startswith("Unknown"))
        self.assertEqual(chain_id["origin"], "unknown")

    def test_chain_verified_when_recorded(self) -> None:
        scan_id, fp, _ = self._seed_completed([_finding()])
        res = self.client.post(
            f"/api/scans/{scan_id}/metadata", json={"chain": "polygon"}
        )
        self.assertEqual(res.status_code, 200, res.text)
        body = self._investigation(scan_id, fp)
        chain = body["protocol"]["fields"]["chain"]
        self.assertEqual(chain["value"], "Polygon")
        self.assertIn("verified", chain["origin"])
        self.assertEqual(body["protocol"]["fields"]["chain_id"]["value"], 137)

    def test_metadata_without_chain_does_not_default_to_ethereum(self) -> None:
        scan_id, fp, _ = self._seed_completed([_finding()])
        res = self.client.post(
            f"/api/scans/{scan_id}/metadata", json={"project_name": "Demo"}
        )
        self.assertEqual(res.status_code, 200, res.text)
        stored = res.json()["metadata"]
        self.assertNotIn("chain", stored)
        body = self._investigation(scan_id, fp)
        chain = body["protocol"]["fields"]["chain"]
        self.assertTrue(chain["value"].startswith("Unknown"))
        self.assertEqual(
            body["protocol"]["fields"]["project_name"]["value"], "Demo"
        )

    def test_classification_test_fixture(self) -> None:
        scan_id, fp, _ = self._seed_completed([_finding()])
        body = self._investigation(scan_id, fp)
        cls = body["classification"]
        self.assertEqual(cls["value"], "test_fixture")
        self.assertIn("TEST FIXTURE", cls["label"])
        self.assertTrue(cls["basis"])
        self.assertTrue(
            any("test fixture" in u.lower() for u in body["unknowns"]),
            "fixture classification must be called out in unknowns",
        )

    def test_classification_local_source(self) -> None:
        finding = _finding()
        scan_id = self._seed_scan([finding], config="dashboard")
        fp = str(finding_fingerprint(finding))
        body = self._investigation(scan_id, fp)
        self.assertEqual(body["classification"]["value"], "local_source")
        self.assertIn("not matched", body["classification"]["label"])

    def test_classification_deployed_via_metadata_address(self) -> None:
        import shutil
        if shutil.which("cast") is None:
            self.skipTest(
                "needs Foundry `cast` to fetch on-chain bytecode; "
                "it is not installed in this environment and is not part of the public demo image"
            )
        scan_id, fp, _ = self._seed_completed([_finding()])
        res = self.client.post(
            f"/api/scans/{scan_id}/metadata",
            json={"contract_address": "0x" + "ab" * 20},
        )
        self.assertEqual(res.status_code, 200, res.text)
        body = self._investigation(scan_id, fp)
        cls = body["classification"]
        self.assertEqual(cls["value"], "deployed_unverified")
        self.assertIn("NOT verified", cls["label"])
        self.assertIn("bytecode", cls["basis"])


# ---------------------------------------------------------------------------
# Financial impact + executive summary
# ---------------------------------------------------------------------------


class TestFinancialImpact(Phase11Case):
    def _investigation(self) -> dict:
        scan_id, fp, _ = self._seed_completed([_finding()])
        res = self.client.get(
            f"/api/findings/{scan_id}/investigation", params={"fp": fp}
        )
        self.assertEqual(res.status_code, 200, res.text)
        return res.json()

    def test_financial_block_shape_and_honesty(self) -> None:
        body = self._investigation()
        fin = body["financial_impact"]
        self.assertEqual(fin["status"], "not_assessed")
        self.assertTrue(fin["summary"])
        for key in ("theoretical_max", "realistically_reachable", "confirmed_loss"):
            value = fin[key]["value"]
            self.assertTrue(
                value.startswith("Unknown") or value.startswith("Not assessed"),
                f"{key} must be labeled, got {value!r}",
            )
        self.assertEqual(fin["confidence"], "unknown")
        self.assertTrue(fin["methodology"])
        self.assertTrue(fin["what_would_validate_these_numbers"])
        self.assertTrue(fin["warning"])
        self.assertIn("TEST FIXTURE", fin["classification"])

    def test_no_fabricated_figures_anywhere(self) -> None:
        body = self._investigation()
        dumped = json.dumps(body, default=str)
        self.assertIsNone(re.search(r"\$\s?\d", dumped), "dollar amount found")
        self.assertIsNone(re.search(r"\d+(?:\.\d+)?\s*USD\b", dumped), "USD amount found")
        self.assertIsNone(
            re.search(r"\b(?:loss|stolen|drained)\b[^.]{0,40}\$?\d", dumped, re.I),
            "loss figure found",
        )

    def test_executive_summary_honest(self) -> None:
        body = self._investigation()
        s = body["executive_summary"]
        self.assertIn("HIGH finding in Vault.withdraw", s["headline"])
        self.assertTrue(s["what"])
        self.assertNotEqual(s["recommended_action"], "")
        self.assertIn("nothing is applied", s["fix_status"])
        self.assertTrue(s["financial_status"].startswith("Not assessed"))
        self.assertIn("TEST FIXTURE", s["source_classification"])
        self.assertIn("no model output", s["origin"])


# ---------------------------------------------------------------------------
# Actionable fix + grounded example patch
# ---------------------------------------------------------------------------


class TestActionableFixAndPatch(Phase11Case):
    def _defender(self) -> dict:
        scan_id, fp, _ = self._seed_completed([_finding()])
        res = self.client.get(
            f"/api/findings/{scan_id}/investigation", params={"fp": fp}
        )
        self.assertEqual(res.status_code, 200, res.text)
        return res.json()["defender"]

    def test_actionable_fix_reentrancy_steps(self) -> None:
        fix = self._defender()["actionable_fix"]
        self.assertTrue(fix["steps"])
        joined = " ".join(fix["steps"]).lower()
        self.assertIn("before the external call", joined)
        self.assertTrue(fix["grounded_in_source"])
        self.assertFalse(fix["auto_applied"])
        self.assertEqual(fix["estimated_fix_range"]["label"], "Approximate")
        self.assertTrue(fix["verify_with"])

    def test_example_patch_grounded_in_verbatim_source(self) -> None:
        patch = self._defender()["example_patch"]
        self.assertTrue(patch["available"])
        self.assertFalse(patch["auto_applied"])
        self.assertEqual(patch["status"], "suggested_not_applied")
        self.assertIn("approval", patch["apply_via"])
        self.assertIn("checks-effects-interactions", patch["rule"])
        before = patch["before"]
        after = patch["after"]
        self.assertEqual(len(before), 2)
        self.assertEqual(len(after), 2)
        # Both sides must be verbatim lines from the fixture source.
        source_lines = set(VAULT_SOL.splitlines())
        for row in before + after:
            self.assertIn(row["text"], source_lines)
        # Suggested order swaps the call and the state write.
        self.assertEqual(
            [r["text"] for r in after], [before[1]["text"], before[0]["text"]]
        )
        self.assertIn("call.value", before[0]["text"])
        self.assertIn("-=", before[1]["text"])
        self.assertTrue(patch["caveats"])

    def test_example_patch_unavailable_for_access_control(self) -> None:
        finding = _finding(
            "Access control issue in Vault.setOwner",
            function="setOwner",
            lines=[20],
        )
        scan_id = self._seed_scan([finding])
        fp = str(finding_fingerprint(finding))
        res = self.client.get(
            f"/api/findings/{scan_id}/investigation", params={"fp": fp}
        )
        self.assertEqual(res.status_code, 200, res.text)
        patch = res.json()["defender"]["example_patch"]
        self.assertFalse(patch["available"])
        self.assertIn("project-specific", patch["reason"])
        self.assertIn("OpenCode", patch["next_step"])
        self.assertFalse(patch["auto_applied"])


# ---------------------------------------------------------------------------
# Severity provenance + duplicates
# ---------------------------------------------------------------------------


class TestProvenanceAndDuplicates(Phase11Case):
    def test_provenance_evidence_backed_with_fact(self) -> None:
        scan_id, fp, _ = self._seed_completed([_finding()])
        body = self.client.get(
            f"/api/findings/{scan_id}/investigation", params={"fp": fp}
        ).json()
        prov = body["severity_provenance"]
        self.assertEqual(prov["scanner"]["severity"], "HIGH")
        self.assertIn("deterministic scanner record", prov["scanner"]["origin"])
        self.assertEqual(prov["triage"]["state"], "New")
        self.assertFalse(prov["ai"]["present"])
        self.assertIn("generated_ai_analysis", prov["ai"]["origin"])
        ev = prov["evidence_backed_verification"]
        self.assertTrue(ev["verification_supported"])
        self.assertGreaterEqual(ev["fact_evidence_count"], 1)
        self.assertFalse(prov["false_positive_review"]["recommended"])

    def test_provenance_without_fact_flags_unverified(self) -> None:
        finding = _finding(with_fact=False)
        scan_id = self._seed_scan([finding])
        fp = str(finding_fingerprint(finding))
        body = self.client.get(
            f"/api/findings/{scan_id}/investigation", params={"fp": fp}
        ).json()
        prov = body["severity_provenance"]
        ev = prov["evidence_backed_verification"]
        self.assertFalse(ev["verification_supported"])
        self.assertIn("not evidence-backed", ev["note"])
        self.assertTrue(prov["false_positive_review"]["recommended"])
        self.assertIn("UNVERIFIED", prov["false_positive_review"]["basis"])

    def test_duplicates_same_title_grouped(self) -> None:
        first = _finding("Reentrancy vulnerability in Vault.withdraw")
        second = _finding("Reentrancy vulnerability in Vault.withdraw")
        scan_id = self._seed_scan([first, second])
        fp = str(finding_fingerprint(first))
        body = self.client.get(
            f"/api/findings/{scan_id}/investigation", params={"fp": fp}
        ).json()
        dupes = body["duplicates"]
        self.assertEqual(dupes["count"], 1)
        self.assertEqual(dupes["group_key"], "normalized_title")
        self.assertEqual(dupes["members"][0]["fingerprint"], str(finding_fingerprint(second)))
        self.assertIn("duplicates", dupes["note"].lower())

    def test_duplicates_zero_for_unique_titles(self) -> None:
        first = _finding("Reentrancy vulnerability in Vault.withdraw")
        second = _finding(
            "Access control issue in Vault.setOwner",
            function="setOwner",
            lines=[20],
        )
        scan_id = self._seed_scan([first, second])
        fp = str(finding_fingerprint(first))
        body = self.client.get(
            f"/api/findings/{scan_id}/investigation", params={"fp": fp}
        ).json()
        self.assertEqual(body["duplicates"]["count"], 0)
        self.assertEqual(body["duplicates"]["members"], [])


# ---------------------------------------------------------------------------
# Attacker panel additions
# ---------------------------------------------------------------------------


class TestAttackerPanelAdditions(Phase11Case):
    def _attacker(self) -> dict:
        scan_id, fp, _ = self._seed_completed([_finding()])
        body = self.client.get(
            f"/api/findings/{scan_id}/investigation", params={"fp": fp}
        ).json()
        return body["attacker"]

    def test_vulnerable_operation_grounded(self) -> None:
        vuln = self._attacker()["vulnerable_operation"]
        self.assertIn("External call at Vault.sol:", vuln["value"])
        self.assertEqual(vuln["origin"], "verified from local source")

    def test_call_path_anchors_to_source_lines(self) -> None:
        path = self._attacker()["call_path"]
        self.assertTrue(path)
        joined = " ".join(path)
        self.assertIn("Vault.withdraw", joined)
        self.assertRegex(joined, r"Vault\.sol:\d+")

    def test_validation_time_separate_from_remediation(self) -> None:
        vt = self._attacker()["validation_time"]
        self.assertIn("approximate", vt["range"].lower())
        self.assertEqual(vt["label"], "Approximate")
        self.assertIn("remediation", vt["separate_from"])
        self.assertIn("separately", vt["explanation"].lower())

    def test_evidence_needed_list(self) -> None:
        needed = self._attacker()["evidence_needed"]
        self.assertTrue(needed)
        joined = " ".join(needed).lower()
        self.assertIn("rpc", joined)
        self.assertIn("bytecode", joined)
        self.assertIn("fixture", joined)


# ---------------------------------------------------------------------------
# Bounty display gating
# ---------------------------------------------------------------------------


class TestBountyDisplay(Phase11Case):
    def test_bounty_flag_false_when_not_checked(self) -> None:
        scan_id, fp, _ = self._seed_completed([_finding()])
        body = self.client.get(
            f"/api/findings/{scan_id}/investigation", params={"fp": fp}
        ).json()
        self.assertEqual(body["bounty"]["status"], "not_checked")
        self.assertFalse(body["bounty"]["official_source_fetched"])

    def test_bounty_flag_true_when_official_source_fetched(self) -> None:
        from auditor.dashboard.paths import history_db_path
        from auditor.finding_store import open_store, set_metadata

        scan_id, fp, _ = self._seed_completed([_finding()])
        stored = {
            "status": "checked",
            "eligibility": "not_verified_automatically",
            "source_url": "https://example.org/bug-bounty",
            "checked_at": "2026-10-13T00:00:00+00:00",
            "http_status": 200,
            "evidence": [{"keyword": "bounty", "snippet": "…bug bounty…"}],
            "reminder": "verify scope yourself",
        }
        store = open_store(history_db_path())
        try:
            set_metadata(store, scan_id, {"bounty_check": json.dumps(stored)})
        finally:
            store.close()
        body = self.client.get(
            f"/api/findings/{scan_id}/investigation", params={"fp": fp}
        ).json()
        bounty = body["bounty"]
        self.assertTrue(bounty["official_source_fetched"])
        self.assertEqual(bounty["source_url"], "https://example.org/bug-bounty")


# ---------------------------------------------------------------------------
# Reports / markdown rendering
# ---------------------------------------------------------------------------


class TestPhase11Reports(Phase11Case):
    def test_finding_markdown_has_new_sections(self) -> None:
        scan_id, fp, _ = self._seed_completed([_finding()])
        res = self.client.get(
            f"/api/findings/{scan_id}/report",
            params={"fp": fp, "format": "markdown"},
        )
        self.assertEqual(res.status_code, 200)
        md = res.text
        for heading in (
            "## Executive summary",
            "## Source classification",
            "## Financial impact",
            "## Severity provenance",
            "## Duplicates",
            "**Actionable fix**",
            "**Example patch**",
            "**Validation**",
            "**Remediation**",
            "Evidence still needed",
        ):
            self.assertIn(heading, md, f"missing {heading!r}")
        self.assertIn("TEST FIXTURE", md)
        self.assertIn("suggested_not_applied", md)

    def test_scan_report_scope_has_classification(self) -> None:
        from auditor.report_builder import build_report

        scan_id, _, _ = self._seed_completed([_finding()])
        report = build_report(scan_id, history_db=history_db_path())
        scope = report["scope_and_context"]
        self.assertIn("source_classification", scope)
        self.assertEqual(scope["source_classification"]["value"], "test_fixture")

    def test_scan_report_markdown_renders_grouped_estimates(self) -> None:
        from auditor.report_builder import build_report, render_markdown

        scan_id, _, _ = self._seed_completed([_finding()])
        report = build_report(scan_id, history_db=history_db_path())
        md = render_markdown(report)
        self.assertIn("**Validation**", md)
        self.assertIn("**Remediation**", md)
        self.assertIn("approximate", md.lower())


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
