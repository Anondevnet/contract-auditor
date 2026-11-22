"""Structured audit report generation (JSON + Markdown).

Sections follow the reporting contract: executive summary, scope with
sources, prioritized findings, attacker view, defender plan, evidence,
exposure with assumptions/confidence, labeled estimates, bounty status,
test/retest results, false-positive considerations, and an explicit
unknowns/limitations section.

Origin labels travel with every block (``deterministic_scanner_evidence``,
``generated_ai_analysis``, ``estimate``, ``unknown``) so no AI-generated text
can be mistaken for scanner evidence — and nothing here invents prices,
balances, losses, or rewards.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from auditor.finding_store import get_all_reviews, get_metadata, open_store
from auditor.investigation import build_investigation
from auditor.scan_history import ScanHistory, default_history_db_path

_SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFORMATIONAL": 4}


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def _db_path(history_db: Optional[Path]) -> Path:
    return Path(history_db) if history_db else default_history_db_path()


def _load_scan(scan_id: str, db: Path) -> Dict[str, Any]:
    history = ScanHistory(db)
    try:
        record = history.get_scan(scan_id)
        findings = history.get_findings(scan_id)
    finally:
        history.close()
    if not record:
        raise ValueError(f"scan not found: {scan_id}")
    return {"record": record, "findings": findings}


def _load_reviews(scan_id: str, db: Path) -> Dict[str, Dict[str, Any]]:
    store = open_store(db)
    try:
        return get_all_reviews(store, scan_id)
    finally:
        store.close()


def _load_metadata(scan_id: str, db: Path) -> Dict[str, str]:
    store = open_store(db)
    try:
        return get_metadata(store, scan_id)
    finally:
        store.close()


def _find_retests(scan_id: str, db: Path) -> List[Dict[str, Any]]:
    """Retest results recorded against this scan (stored as retest scans)."""
    store = open_store(db)
    try:
        rows = store.execute(
            """
            SELECT graph_snapshot FROM scan_records
            WHERE config_fingerprint = 'retest'
            ORDER BY timestamp DESC
            LIMIT 100
            """
        ).fetchall()
    finally:
        store.close()
    out: List[Dict[str, Any]] = []
    for row in rows:
        snapshot = row["graph_snapshot"]
        if isinstance(snapshot, str):
            try:
                snapshot = json.loads(snapshot)
            except json.JSONDecodeError:
                continue
        if isinstance(snapshot, dict) and snapshot.get("scan_id") == scan_id:
            out.append(snapshot)
    return out


def _sorted_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return sorted(
        findings,
        key=lambda f: (
            _SEVERITY_ORDER.get(str(f.get("severity") or "").upper(), 99),
            str(f.get("title") or ""),
        ),
    )


def build_report(
    scan_id: str,
    *,
    history_db: Optional[Path] = None,
    bounty: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Full structured report for one scan."""
    db = _db_path(history_db)
    loaded = _load_scan(scan_id, db)
    record = loaded["record"]
    findings = _sorted_findings(loaded["findings"])
    reviews = _load_reviews(scan_id, db)
    metadata = _load_metadata(scan_id, db)
    retests = _find_retests(scan_id, db)

    graph = record.get("graph_snapshot")
    if isinstance(graph, str):
        try:
            graph = json.loads(graph)
        except json.JSONDecodeError:
            graph = None
    graph = graph if isinstance(graph, dict) else None

    if bounty is None:
        raw = metadata.get("bounty_check")
        if raw:
            try:
                bounty = json.loads(raw)
            except json.JSONDecodeError:
                bounty = None

    investigations: List[Dict[str, Any]] = []
    for finding in findings:
        fp = str(finding.get("fingerprint") or "")
        inv = build_investigation(
            finding,
            record,
            review=reviews.get(fp, {}),
            metadata=metadata,
            source_root=record.get("source_path"),
            # A bounty check is program/scan-level; every finding shares
            # the same scope, so all investigations show it (not only
            # when the scan happens to have exactly one finding).
            bounty=bounty,
        )
        investigations.append(inv)

    by_severity: Dict[str, int] = {}
    by_state: Dict[str, int] = {}
    for finding in findings:
        sev = str(finding.get("severity") or "UNKNOWN").upper()
        by_severity[sev] = by_severity.get(sev, 0) + 1
        fp = str(finding.get("fingerprint") or "")
        state = str(reviews.get(fp, {}).get("state") or "New")
        by_state[state] = by_state.get(state, 0) + 1

    is_ai_audit = record.get("config_fingerprint") == "ai-audit"
    ai_block = graph.get("ai_analysis") if is_ai_audit and graph else None

    return {
        "report_kind": "scan_report",
        "generated_at": _utcnow(),
        "scan": {
            "scan_id": scan_id,
            "timestamp": record.get("timestamp"),
            "source_path": record.get("source_path"),
            "config_fingerprint": record.get("config_fingerprint"),
            "status": record.get("status"),
            "origin": "deterministic_scan_record",
        },
        "executive_summary": {
            "finding_count": len(findings),
            "by_severity": by_severity,
            "by_state": by_state,
            "headline": (
                f"{len(findings)} finding(s) recorded; {by_severity.get('CRITICAL', 0)} critical, "
                f"{by_severity.get('HIGH', 0)} high. No finding is treated as confirmed "
                "unless an analyst sets that state with FACT evidence."
            ),
            "origin": "deterministic_scan_record",
        },
        "scope_and_context": {
            "metadata": metadata or {},
            "protocol": investigations[0]["protocol"] if investigations else None,
            "source_classification": investigations[0]["classification"] if investigations else None,
            "sources": [
                "Scan metadata recorded at scan time (fields marked verified).",
                "Chain identifiers come from a fixed chain registry mapping; a missing chain stays Unknown.",
                "No balance, TVL, price, or USD source is configured — those stay unknown.",
            ],
            "origin": "mixed (see per-field labels)",
        },
        "prioritized_findings": [
            {
                "fingerprint": f.get("fingerprint"),
                "title": f.get("title"),
                "severity": f.get("severity"),
                "confidence": f.get("confidence"),
                "category": f.get("category"),
                "verification_status": f.get("status") or f.get("verification_status"),
                "state": reviews.get(str(f.get("fingerprint") or ""), {}).get("state", "New"),
                "location": {
                    "contract": f.get("affected_contract"),
                    "function": f.get("affected_function"),
                    "lines": f.get("affected_lines"),
                },
                "origin": "deterministic_scanner_evidence",
            }
            for f in findings
        ],
        "attacker_view": [
            {
                "fingerprint": inv.get("fingerprint"),
                "title": inv.get("title"),
                "plain_english": inv["attacker"]["plain_english"],
                "attack_path_label": inv["attacker"]["attack_path_label"],
                "attack_path": inv["attacker"]["attack_path"],
                "preconditions": inv["attacker"]["preconditions"],
                "reachability": inv["attacker"]["reachability"],
                "difficulty": inv["attacker"]["difficulty"],
                "origin": "deterministic_scanner_evidence (conceptual, defensive framing)",
            }
            for inv in investigations
        ],
        "defender_plan": [
            {
                "fingerprint": inv.get("fingerprint"),
                "root_cause": inv["defender"]["root_cause"]["summary"],
                "remediation": inv["defender"]["remediation"],
                "test_plan": inv["defender"]["test_plan"],
                "false_positive_considerations": inv["defender"]["false_positive_considerations"],
                "estimates": inv["defender"]["estimates"],
                "origin": "deterministic_scanner_evidence",
            }
            for inv in investigations
        ],
        "evidence_summary": [
            {
                "fingerprint": inv.get("fingerprint"),
                "fact_count": inv["evidence"]["fact_count"],
                "inference_count": inv["evidence"]["inference_count"],
                "ai_opinion_count": inv["evidence"]["ai_opinion_count"],
                "label": inv["evidence"]["label"],
                "origin": "deterministic_scanner_evidence",
            }
            for inv in investigations
        ],
        "exposure_assumptions_confidence": [
            {
                "fingerprint": inv.get("fingerprint"),
                "exposure": inv["attacker"]["exposure"],
                "assumptions": inv["defender"]["assumptions"],
                "confidence": inv.get("confidence"),
                "origin": "unknown / not_assessed unless a field says otherwise",
            }
            for inv in investigations
        ],
        "estimates": [
            {
                "fingerprint": inv.get("fingerprint"),
                "stages": inv["defender"]["estimates"],
                "origin": "estimate",
            }
            for inv in investigations
        ],
        "bounty_status": bounty or {
            "status": "not_checked",
            "eligibility": "Not assessed",
            "reason": "No bounty check has been run for this scan.",
            "origin": "unknown",
        },
        "test_and_retest_results": {
            "retests": retests,
            "ai_audit_tests": graph.get("tests") if is_ai_audit and graph else None,
            "origin": "deterministic_reanalysis",
        },
        "false_positive_considerations": [
            {
                "fingerprint": inv.get("fingerprint"),
                "benign_explanation": inv["defender"]["benign_explanation"],
                "considerations": inv["defender"]["false_positive_considerations"],
                "origin": "deterministic_scanner_evidence",
            }
            for inv in investigations
        ],
        "ai_generated_analysis": {
            "present": bool(ai_block),
            "origin": "generated_ai_analysis",
            "block": ai_block,
            "note": (
                "AI output is model opinion, separated from scanner evidence."
                if ai_block
                else "No AI-generated analysis is attached to this scan."
            ),
        },
        "unknowns_and_limitations": sorted(
            {u for inv in investigations for u in inv.get("unknowns", [])}
            | {
                "Verification that deployed bytecode matches this source was not performed.",
                "Bounty scope was not automatically verified (see bounty_status).",
                "All effort/time figures are labeled approximate planning ranges.",
            }
        ),
        "origin_legend": {
            "deterministic_scanner_evidence": "Produced by local analyzers from source text.",
            "generated_ai_analysis": "Produced by a local LLM — opinion, not evidence.",
            "estimate": "Approximate planning figure, not a measurement.",
            "unknown": "Not verified — deliberately left unknown.",
            "not_assessed": "Not measured in this assessment.",
        },
    }


def build_finding_report(
    scan_id: str,
    fingerprint: str,
    *,
    history_db: Optional[Path] = None,
    bounty: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Structured report for a single finding (investigation view as data)."""
    db = _db_path(history_db)
    loaded = _load_scan(scan_id, db)
    reviews = _load_reviews(scan_id, db)
    metadata = _load_metadata(scan_id, db)
    finding = next(
        (f for f in loaded["findings"] if str(f.get("fingerprint")) == fingerprint),
        None,
    )
    if finding is None:
        raise ValueError(f"finding {fingerprint} not found in scan {scan_id}")
    if bounty is None:
        raw = metadata.get("bounty_check")
        if raw:
            try:
                bounty = json.loads(raw)
            except json.JSONDecodeError:
                bounty = None
    from auditor.finding_store import history as review_history

    store = open_store(db)
    try:
        state_history = review_history(store, scan_id, fingerprint)
    finally:
        store.close()

    inv = build_investigation(
        finding,
        loaded["record"],
        review=reviews.get(fingerprint, {}),
        metadata=metadata,
        source_root=loaded["record"].get("source_path"),
        bounty=bounty,
        state_history=state_history,
    )
    return {
        "report_kind": "finding_report",
        "generated_at": _utcnow(),
        "investigation": inv,
        "origin_legend": {
            "deterministic_scanner_evidence": "Local analyzer output.",
            "generated_ai_analysis": "Local LLM opinion (if present).",
            "estimate": "Approximate planning figure.",
            "unknown": "Not verified.",
            "not_assessed": "Not measured.",
        },
    }


# ---------------------------------------------------------------------------
# markdown rendering
# ---------------------------------------------------------------------------

def _md_escape(value: Any) -> str:
    return str(value if value is not None else "").replace("|", "\\|").replace("\n", " ")


def _labeled_line(label: str, node: Any) -> str:
    if isinstance(node, dict):
        origin = node.get("origin", "")
        basis = node.get("basis")
        line = f"- **{label}:** {node.get('value', '')}"
        if origin:
            line += f" _(origin: {origin})_"
        if basis:
            line += f" — {basis}"
        return line
    return f"- **{label}:** {node}"


def render_markdown(report: Dict[str, Any]) -> str:
    """Render a structured report as Markdown."""
    scan = report.get("scan", {})
    summary = report.get("executive_summary", {})
    lines: List[str] = []
    lines.append(f"# Audit report — {scan.get('scan_id', '')}")
    lines.append("")
    lines.append(f"- Generated: {report.get('generated_at')}")
    lines.append(f"- Scan time: {scan.get('timestamp')}")
    lines.append(f"- Source: `{scan.get('source_path')}`")
    lines.append(f"- Scan type: {scan.get('config_fingerprint')}")
    lines.append("")

    lines.append("## 1. Executive summary")
    lines.append("")
    lines.append(summary.get("headline", ""))
    lines.append("")
    by_sev = summary.get("by_severity", {})
    if by_sev:
        lines.append("| Severity | Count |")
        lines.append("|---|---|")
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"):
            if sev in by_sev:
                lines.append(f"| {sev} | {by_sev[sev]} |")
        lines.append("")

    lines.append("## 2. Scope and context")
    lines.append("")
    scope = report.get("scope_and_context", {})
    metadata = scope.get("metadata") or {}
    if metadata:
        for key, value in sorted(metadata.items()):
            lines.append(f"- **{_md_escape(key)}:** {_md_escape(value)} _(recorded metadata)_")
    else:
        lines.append("- No project/chain/token metadata was recorded for this scan.")
    lines.append("- Balances, TVL, liquidity, and USD values: **Not assessed / Unknown — not verified** (no configured source).")
    lines.append("")

    lines.append("## 3. Prioritized findings")
    lines.append("")
    rows = report.get("prioritized_findings", [])
    if not rows:
        lines.append("_No findings recorded._")
        lines.append("")
    else:
        lines.append("| # | Severity | Title | Category | State | Location | Origin |")
        lines.append("|---|---|---|---|---|---|---|")
        for idx, row in enumerate(rows, 1):
            loc = row.get("location") or {}
            location = f"{loc.get('contract') or '?'}.{loc.get('function') or '?'}"
            if loc.get("lines"):
                location += f":{loc['lines'][0]}"
            lines.append(
                f"| {idx} | {_md_escape(row.get('severity'))} | {_md_escape(row.get('title'))} | "
                f"{_md_escape(row.get('category'))} | {_md_escape(row.get('state'))} | "
                f"`{_md_escape(location)}` | {_md_escape(row.get('origin'))} |"
            )
        lines.append("")

    lines.append("## 4. Attacker view (conceptual, defensive)")
    lines.append("")
    for block in report.get("attacker_view", []):
        lines.append(f"### {_md_escape(block.get('title'))}")
        lines.append("")
        lines.append(f"{block.get('plain_english')}")
        lines.append("")
        lines.append(f"_{block.get('attack_path_label')}_")
        for step in block.get("attack_path", []):
            lines.append(f"- {step}")
        lines.append("")
        lines.append("**Preconditions**")
        for pre in block.get("preconditions", []):
            lines.append(f"- {pre}")
        lines.append("")
        reach = block.get("reachability") or {}
        lines.append(_labeled_line("Reachability", reach))
        diff = block.get("difficulty") or {}
        if isinstance(diff, dict):
            lines.append(f"- **Difficulty:** {diff.get('value')} _(estimate unless stated otherwise)_")
        lines.append("")

    lines.append("## 5. White-hat plan and estimates")
    lines.append("")
    for block in report.get("defender_plan", []):
        lines.append(f"### {_md_escape(block.get('root_cause'))}")
        lines.append("")
        lines.append(f"**Remediation:** {block.get('remediation', {}).get('primary')}")
        for ref in block.get("remediation", {}).get("references", []):
            lines.append(f"- Reference: {ref}")
        lines.append("")
        lines.append("**Test plan**")
        for step in block.get("test_plan", []):
            lines.append(f"- {step.get('step')}: {step.get('detail')}")
        lines.append("")
        lines.append("**Effort estimates** _(approximate planning ranges)_")
        lines.append("")
        est = block.get("estimates", {})
        if isinstance(est, dict):
            for group in ("validation", "remediation"):
                rows = [r for r in (est.get(group) or []) if isinstance(r, dict) and "stage" in r]
                if not rows:
                    continue
                lines.append(f"**{group.title()}**")
                lines.append("")
                lines.append("| Stage | Range | Label |")
                lines.append("|---|---|---|")
                for row in rows:
                    lines.append(
                        f"| {_md_escape(row.get('stage'))} | {_md_escape(row.get('range'))} | {row.get('label')} |"
                    )
                lines.append("")
            if est.get("note"):
                lines.append(f"_{est['note']}_")
                lines.append("")
        else:
            for row in est if isinstance(est, list) else []:
                if isinstance(row, dict) and "stage" in row:
                    lines.append(
                        f"| {_md_escape(row.get('stage'))} | {_md_escape(row.get('range'))} | {row.get('label')} |"
                    )
            lines.append("")

    lines.append("## 6. Evidence")
    lines.append("")
    for block in report.get("evidence_summary", []):
        lines.append(
            f"- {block.get('fingerprint')}: FACT={block.get('fact_count')}, "
            f"INFERENCE={block.get('inference_count')}, AI_OPINION={block.get('ai_opinion_count')} "
            f"_(label: {block.get('label')})_"
        )
    lines.append("")

    lines.append("## 7. Exposure, assumptions, confidence")
    lines.append("")
    for block in report.get("exposure_assumptions_confidence", []):
        exposure = block.get("exposure", {})
        lines.append(f"### {_md_escape(block.get('fingerprint'))}")
        for key, label in (
            ("theoretical_max", "Theoretical maximum"),
            ("realistically_reachable", "Realistically reachable"),
            ("confirmed_loss", "Confirmed loss"),
        ):
            lines.append(_labeled_line(label, exposure.get(key)))
        lines.append(f"- **Confidence:** {block.get('confidence')}")
        lines.append("")

    lines.append("## 8. Bounty status")
    lines.append("")
    bounty = report.get("bounty_status", {})
    lines.append(f"- Status: {bounty.get('status')}")
    lines.append(f"- Eligibility: {bounty.get('eligibility')}")
    if bounty.get("source_url"):
        lines.append(f"- Source: {bounty.get('source_url')} (checked {bounty.get('checked_at')})")
    if bounty.get("reason"):
        lines.append(f"- Reason: {bounty.get('reason')}")
    if bounty.get("reminder"):
        lines.append(f"- Reminder: {bounty.get('reminder')}")
    lines.append("")

    lines.append("## 9. Test and retest results")
    lines.append("")
    tests = report.get("test_and_retest_results", {})
    retests = tests.get("retests") or []
    if not retests:
        lines.append("- No retest has been recorded for this scan.")
    for retest in retests:
        lines.append(
            f"- Retest at {retest.get('tested_at')}: "
            f"{'persisted' if retest.get('persisted') else 'not reproduced'} "
            f"(retest scan `{retest.get('retest_scan_id')}`)"
        )
        for note in retest.get("notes", []):
            lines.append(f"  - {note}")
    if tests.get("ai_audit_tests"):
        lines.append("- AI audit test stage recorded (see scan job report).")
    lines.append("")

    lines.append("## 10. False-positive considerations")
    lines.append("")
    for block in report.get("false_positive_considerations", []):
        lines.append(f"- **Benign explanation:** {block.get('benign_explanation')}")
        for item in block.get("considerations", []):
            lines.append(f"- {item}")
    lines.append("")

    lines.append("## 11. AI-generated analysis")
    lines.append("")
    ai = report.get("ai_generated_analysis", {})
    lines.append(f"- Present: {ai.get('present')} _(origin: generated_ai_analysis)_")
    if ai.get("block"):
        block = ai["block"]
        lines.append(f"- Status: {block.get('status')} (model: {block.get('model')})")
        if block.get("reason"):
            lines.append(f"- Reason: {block.get('reason')}")
        for entry in block.get("findings", []):
            lines.append(f"- [{entry.get('fingerprint')}] risk_analysis: {entry.get('risk_analysis')}")
            if entry.get("uncertainty"):
                lines.append(f"  - uncertainty: {entry.get('uncertainty')}")
    else:
        lines.append("- None recorded for this scan.")
    lines.append("")

    lines.append("## 12. Unknowns and limitations")
    lines.append("")
    for item in report.get("unknowns_and_limitations", []):
        lines.append(f"- {item}")
    lines.append("")

    lines.append("## Origin legend")
    lines.append("")
    for key, value in (report.get("origin_legend") or {}).items():
        lines.append(f"- **{key}** — {value}")
    lines.append("")
    return "\n".join(lines)


def render_investigation_markdown(payload: Dict[str, Any]) -> str:
    """Render a single-finding report payload as Markdown."""
    inv = payload.get("investigation") or payload
    lines: List[str] = []
    lines.append(f"# Finding report — {inv.get('title', '')}")
    lines.append("")
    lines.append(f"- Generated: {payload.get('generated_at', _utcnow())}")
    lines.append(f"- Scan: {inv.get('scan_id')}")
    lines.append(f"- Fingerprint: {inv.get('fingerprint')}")
    lines.append(f"- Severity / confidence: {inv.get('severity')} / {inv.get('confidence')}")
    review = inv.get("review") or {}
    lines.append(f"- Triage state: {review.get('state')}")
    lines.append("")

    exec_summary = inv.get("executive_summary") or {}
    if exec_summary:
        lines.append("## Executive summary")
        lines.append("")
        lines.append(f"**{exec_summary.get('headline', '')}**")
        lines.append("")
        lines.append(f"- What: {exec_summary.get('what')}")
        lines.append(f"- Recommended action: {exec_summary.get('recommended_action')}")
        lines.append(f"- Fix status: {exec_summary.get('fix_status')}")
        lines.append(f"- Financial status: {exec_summary.get('financial_status')}")
        lines.append(f"- Source classification: {exec_summary.get('source_classification')}")
        lines.append(f"- _{exec_summary.get('origin')}_")
        lines.append("")

    lines.append("## Scope")
    lines.append("")
    protocol = (inv.get("protocol") or {}).get("fields") or {}
    for key, node in protocol.items():
        if isinstance(node, dict):
            lines.append(_labeled_line(key.replace("_", " ").title(), node))
    lines.append("")

    classification = inv.get("classification") or {}
    if classification:
        lines.append("## Source classification")
        lines.append("")
        lines.append(f"- **{classification.get('label')}** _(origin: {classification.get('origin')})_")
        if classification.get("basis"):
            lines.append(f"- Basis: {classification['basis']}")
        lines.append("")

    financial = inv.get("financial_impact") or {}
    if financial:
        lines.append("## Financial impact")
        lines.append("")
        lines.append(f"- Status: {financial.get('status')} — {financial.get('summary')}")
        for key, label in (
            ("theoretical_max", "Theoretical maximum"),
            ("realistically_reachable", "Realistically reachable"),
            ("confirmed_loss", "Confirmed loss"),
            ("contract_balance", "Contract balance"),
            ("usd_equivalent", "USD equivalent"),
        ):
            lines.append(_labeled_line(label, financial.get(key)))
        for item in financial.get("methodology", []):
            lines.append(f"- Methodology: {item}")
        lines.append(f"- Confidence: {financial.get('confidence')}")
        lines.append("")

    attacker = inv.get("attacker") or {}
    lines.append("## Attacker view (conceptual, defensive)")
    lines.append("")
    lines.append(str(attacker.get("plain_english", "")))
    lines.append("")
    vuln = attacker.get("vulnerable_operation")
    if isinstance(vuln, dict):
        lines.append(_labeled_line("Vulnerable operation", vuln))
    if attacker.get("call_path"):
        lines.append("")
        lines.append("**Call path (conceptual)**")
        for step in attacker.get("call_path", []):
            lines.append(f"- {step}")
    lines.append("")
    lines.append(f"_{attacker.get('attack_path_label')}_")
    for step in attacker.get("attack_path", []):
        lines.append(f"- {step}")
    lines.append("")
    lines.append(_labeled_line("Reachability", attacker.get("reachability")))
    vt = attacker.get("validation_time") or {}
    if vt:
        lines.append(
            f"- **Validation time:** {vt.get('range')} — {vt.get('explanation')} "
            f"_(separate from {vt.get('separate_from')})_"
        )
    if attacker.get("evidence_needed"):
        lines.append("")
        lines.append("**Evidence still needed**")
        for item in attacker.get("evidence_needed", []):
            lines.append(f"- {item}")
    exposure = attacker.get("exposure") or {}
    lines.append("")
    lines.append("### Exposure")
    for key, label in (
        ("theoretical_max", "Theoretical maximum"),
        ("realistically_reachable", "Realistically reachable"),
        ("confirmed_loss", "Confirmed loss"),
    ):
        lines.append(_labeled_line(label, exposure.get(key)))
    if exposure.get("note"):
        lines.append(f"- {exposure['note']}")
    lines.append("")

    defender = inv.get("defender") or {}
    lines.append("## White-hat / remediation view")
    lines.append("")
    root = defender.get("root_cause") or {}
    lines.append(f"**Root cause:** {root.get('summary')}")
    lines.append("")
    lines.append(f"**Remediation:** {(defender.get('remediation') or {}).get('primary')}")
    lines.append("")
    actionable = defender.get("actionable_fix") or {}
    if actionable:
        lines.append("**Actionable fix**")
        for step in actionable.get("steps", []):
            lines.append(f"- {step}")
        fix_est = actionable.get("estimated_fix_range") or {}
        if fix_est:
            lines.append(
                f"- Estimated fix range: {fix_est.get('range')} ({fix_est.get('label')})"
            )
        lines.append(f"- _{actionable.get('grounding_note')}_")
        lines.append("")
    patch = defender.get("example_patch") or {}
    lines.append("**Example patch**")
    if patch.get("available"):
        lines.append(f"- Rule: {patch.get('rule')}")
        lines.append(f"- Reference: {patch.get('reference')} _(origin: {patch.get('origin')})_")
        lines.append("- Before:")
        for row in patch.get("before", []):
            lines.append(f"  - `{row.get('n')}` {row.get('text')}")
        lines.append("- After (suggested order):")
        for row in patch.get("after", []):
            lines.append(f"  - `{row.get('n')}` {row.get('text')}")
        lines.append(f"- Status: {patch.get('status')} — {patch.get('apply_via')}")
        for caveat in patch.get("caveats", []):
            lines.append(f"- Caveat: {caveat}")
    else:
        lines.append(f"- Unavailable: {patch.get('reason')}")
        if patch.get("next_step"):
            lines.append(f"- Next step: {patch['next_step']}")
    lines.append("")
    lines.append("**Test plan**")
    for step in defender.get("test_plan", []):
        lines.append(f"- {step.get('step')}: {step.get('detail')}")
    lines.append("")
    lines.append("**Effort estimates** _(approximate; validation separated from remediation)_")
    lines.append("")
    estimates = defender.get("estimates", {})
    if isinstance(estimates, dict):
        for group in ("validation", "remediation"):
            rows = [r for r in (estimates.get(group) or []) if isinstance(r, dict) and "stage" in r]
            if not rows:
                continue
            lines.append(f"**{group.title()}**")
            for est in rows:
                lines.append(f"- {est.get('stage')}: {est.get('range')} ({est.get('label')})")
            lines.append("")
        if estimates.get("note"):
            lines.append(f"_{estimates['note']}_")
            lines.append("")
    elif isinstance(estimates, list):
        for est in estimates:
            if isinstance(est, dict) and "stage" in est:
                lines.append(f"- {est.get('stage')}: {est.get('range')} ({est.get('label')})")
        lines.append("")

    lines.append("## Evidence")
    lines.append("")
    evidence = inv.get("evidence") or {}
    lines.append(
        f"- FACT={evidence.get('fact_count')}, INFERENCE={evidence.get('inference_count')}, "
        f"AI_OPINION={evidence.get('ai_opinion_count')} _(label: {evidence.get('label')})_"
    )
    for item in evidence.get("items", []):
        lines.append(f"- [{item.get('epistemic')}] {item.get('source')}: {_md_escape(item.get('excerpt'))}")
    lines.append("")

    provenance = inv.get("severity_provenance") or {}
    if provenance:
        lines.append("## Severity provenance")
        lines.append("")
        scanner = provenance.get("scanner") or {}
        lines.append(
            f"- Scanner: severity={scanner.get('severity')}, confidence={scanner.get('confidence')}, "
            f"tool={scanner.get('tool')} _({scanner.get('origin')})_"
        )
        triage = provenance.get("triage") or {}
        lines.append(
            f"- Triage: state={triage.get('state')}, recorded_events={triage.get('recorded_events')} "
            f"_({triage.get('origin')})_"
        )
        ai = provenance.get("ai") or {}
        lines.append(f"- AI: present={ai.get('present')}, severity={ai.get('severity')} _({ai.get('origin')})_")
        ev = provenance.get("evidence_backed_verification") or {}
        lines.append(
            f"- Evidence-backed verification: {ev.get('verification_supported')} — {ev.get('note')}"
        )
        fp = provenance.get("false_positive_review") or {}
        lines.append(
            f"- False-positive review recommended: {fp.get('recommended')} — {fp.get('basis')}"
        )
        if provenance.get("note"):
            lines.append(f"- _{provenance['note']}_")
        lines.append("")

    dupes = inv.get("duplicates") or {}
    if dupes:
        lines.append("## Duplicates")
        lines.append("")
        lines.append(f"- Count: {dupes.get('count')} (group key: {dupes.get('group_key')})")
        for member in dupes.get("members", []):
            lines.append(
                f"  - {member.get('fingerprint')}: {member.get('title')} "
                f"[{member.get('severity')}] {member.get('location')}"
            )
        if dupes.get("note"):
            lines.append(f"- {dupes['note']}")
        lines.append("")

    bounty = inv.get("bounty") or {}
    lines.append("## Bounty status")
    lines.append("")
    lines.append(f"- Status: {bounty.get('status')}")
    lines.append(f"- Eligibility: {bounty.get('eligibility')}")
    lines.append(f"- Official source fetched: {bounty.get('official_source_fetched')}")
    if bounty.get("source_url"):
        lines.append(f"- Source: {bounty.get('source_url')} (checked {bounty.get('checked_at')})")
    if bounty.get("reminder"):
        lines.append(f"- {bounty.get('reminder')}")
    lines.append("")

    ai = inv.get("ai_analysis")
    lines.append("## AI analysis")
    lines.append("")
    if ai:
        lines.append(f"- Status: {ai.get('status')} _(origin: generated_ai_analysis)_")
        for entry in ai.get("findings", []):
            lines.append(f"- risk_analysis: {entry.get('risk_analysis')}")
            lines.append(f"- remediation: {entry.get('remediation')}")
            lines.append(f"- uncertainty: {entry.get('uncertainty')}")
    else:
        lines.append("- None recorded for this finding.")
    lines.append("")

    lines.append("## Unknowns")
    lines.append("")
    for item in inv.get("unknowns", []):
        lines.append(f"- {item}")
    lines.append("")
    return "\n".join(lines)
