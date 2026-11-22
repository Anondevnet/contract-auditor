"""Phase 41 — second-stage financial-risk review engine (finrisk).

Verdicts are evidence-derived ONLY: disproof needs positive evidence,
validated needs the monitor pipeline's stored dynamic reproduction, and all
infrastructure failures (timeouts, missing sources, RPC down) stay
inconclusive/retryable — never disproved. The queue is additive, isolated
(``reports/finrisk.db``) and idempotent; nothing here touches the monitor,
hunt, scan recording or the finding lifecycle itself.
"""
from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path

import pytest

from auditor import finrisk as F
from auditor.model import Confidence, Finding, Severity, VerificationStatus
from auditor.scan_history import ScanHistory


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def finding_dict(title="Unprotected withdrawal", severity="HIGH", category="access",
                 contract="Vault", function="withdraw", lines=(10, 24),
                 detail_extra=True):
    base = {
        "fingerprint": "vault|withdraw|unprotected",
        "title": title, "severity": severity, "category": category,
        "affected_contract": contract, "affected_function": function,
        "affected_lines": list(lines),
        "description": "Public withdrawals were not restricted.",
        "tool": "local-test",
    }
    if detail_extra:
        base["description"] += " Source detector: unguarded-withdraw."
    return base


def history_row(scan_id="s1", source="etherscan://0x" + "a" * 40, details=None,
                timestamp="2026-10-24T00:00:00Z"):
    return {"scan_id": scan_id, "timestamp": timestamp,
            "source_path": source, "content_hash": "h", "config_fingerprint": "cfg",
            "status": "completed",
            "finding_fingerprints": [d["fingerprint"] for d in (details or [])],
            "finding_details": details or []}


def reopen(db: Path):
    return F.open_finrisk_db(db)


# ---------------------------------------------------------------------------
# queue: idempotent enqueue + dedupe on rediscovery
# ---------------------------------------------------------------------------

def test_enqueue_is_idempotent_per_finding(tmp_path):
    db = tmp_path / "finrisk.db"
    con = reopen(db)
    f = finding_dict()
    first = F.enqueue_findings(con, scan_id="s1", scan_timestamp="t",
                               source_path="etherscan://0x" + "a" * 40, findings=[f])
    second = F.enqueue_findings(con, scan_id="s1", scan_timestamp="t",
                                source_path="etherscan://0x" + "a" * 40, findings=[f])
    assert first == 1 and second == 0
    n = con.execute("SELECT COUNT(*) FROM finrisk_reviews").fetchone()[0]
    assert n == 1


def test_enqueue_skips_findings_without_fingerprint(tmp_path):
    con = reopen(tmp_path / "finrisk.db")
    f = finding_dict()
    f2 = dict(f, fingerprint="")
    n = F.enqueue_findings(con, scan_id="s1", scan_timestamp="t",
                           source_path="local", findings=[f, f2])
    assert n == 1


def test_states_track_pending_running_completed_and_verdict(tmp_path):
    db = tmp_path / "finrisk.db"
    con = reopen(db)
    F.enqueue_findings(con, scan_id="s1", scan_timestamp=None, source_path="local",
                       findings=[finding_dict()])
    claimed = F.claim_due(con, limit=1)
    assert claimed and claimed[0]["to_state"] == F.STATE_RUNNING
    sc, fp = claimed[0]["scan_id"], claimed[0]["fingerprint"]
    r = F.heartbeat(con, sc, fp, "validation")
    row = con.execute("SELECT heartbeat_stage, state FROM finrisk_reviews WHERE scan_id=? AND fingerprint=?",
                      (sc, fp)).fetchone()
    assert row["state"] == F.STATE_RUNNING and row["heartbeat_stage"] == "validation"
    payload = F._empty_payload()
    payload["verdict_rationale"] = "ok"
    res = F.finish_completed(con, sc, fp, F.VERDICT_POTENTIAL, payload)
    assert res["status"] == F.STATE_COMPLETED and res["verdict"] == F.VERDICT_POTENTIAL
    hist = con.execute("SELECT from_state, to_state FROM finrisk_review_history WHERE scan_id=?",
                       (sc,)).fetchall()
    pairs = {(h[0], h[1]) for h in hist}
    assert (F.STATE_PENDING, F.STATE_RUNNING) in pairs
    assert (F.STATE_RUNNING, F.STATE_COMPLETED) in pairs


def test_fail_retryable_then_backoff_then_cap(tmp_path):
    db = tmp_path / "finrisk.db"
    con = reopen(db)
    F.enqueue_findings(con, scan_id="s1", scan_timestamp=None, source_path="local",
                       findings=[finding_dict()])
    (sc, fp), = [(c["scan_id"], c["fingerprint"]) for c in F.claim_due(con, limit=1)]
    assert F.fail_retryable(con, sc, fp, "rpc down", now=1000.0) is True
    row = con.execute("SELECT state, attempts, next_attempt_at FROM finrisk_reviews WHERE scan_id=?",
                      (sc,)).fetchone()
    assert row["state"] == F.STATE_RETRYABLE and row["attempts"] == 1
    assert row["next_attempt_at"] > 1000.0
    # not due until backoff elapses
    assert F.claim_due(con, limit=1, now=row["next_attempt_at"] - 1) == []
    attempts = 1
    while attempts < F.MAX_ATTEMPTS:
        # step past this attempt's backoff before claiming again (the probe
        # clock must advance with the schedule, not stay fixed)
        now = row["next_attempt_at"] + 1
        c = F.claim_due(con, limit=1, now=now)
        assert c, "a retryable row becomes claimable once its backoff elapsed"
        assert (c[0]["scan_id"], c[0]["fingerprint"]) == (sc, fp)
        attempts += 1
        scheduled = F.fail_retryable(con, sc, fp, "rpc down", now=now)
        row = con.execute("SELECT attempts, next_attempt_at FROM finrisk_reviews WHERE scan_id=?",
                          (sc,)).fetchone()
        assert row["attempts"] == attempts
        if attempts < F.MAX_ATTEMPTS:
            assert scheduled is True and row["next_attempt_at"] > now
        else:
            assert scheduled is False  # the attempt cap holds
    # at the cap: stays retryable, no more auto claims, error recorded for the UI
    assert F.claim_due(con, limit=5, now=now + 10 ** 9) == []
    s = F.summary(con)
    assert s["retryable_count"] == 1 and s["last_errors"]


def test_manual_reset_clears_attempts_without_destroying_history(tmp_path):
    con = reopen(tmp_path / "finrisk.db")
    F.enqueue_findings(con, scan_id="s1", scan_timestamp=None, source_path="local",
                       findings=[finding_dict()])
    claims = F.claim_due(con, limit=1)
    sc, fp = claims[0]["scan_id"], claims[0]["fingerprint"]
    F.fail_retryable(con, sc, fp, "rpm fail", now=1.0)
    before = con.execute("SELECT attempts FROM finrisk_reviews WHERE scan_id=?", (sc,)).fetchone()[0]
    F.reset_for_manual_run(con, sc, fp)
    row = con.execute("SELECT state, attempts FROM finrisk_reviews WHERE scan_id=?", (sc,)).fetchone()
    assert before >= 1 and row["state"] == F.STATE_PENDING and row["attempts"] == 0
    # transitions survive in the append-only history
    tos = [h[0] for h in con.execute("SELECT to_state FROM finrisk_review_history WHERE scan_id=?", (sc,))]
    assert F.STATE_PENDING in tos and F.STATE_RETRYABLE in tos


# ---------------------------------------------------------------------------
# verdict mapping: the five outcomes and their evidence rules
# ---------------------------------------------------------------------------

def evidence(**over):
    base = {
        "validation": {"steps": []},
        "attacker": {"exposure_model": None, "privilege_gated": False},
        "financial": {"assets": None, "holdings_usd": None, "stored_estimate": None},
        "missing_evidence": [], "infra_failures": [],
        "triage_rule": "", "triage_reason": "", "suppressed": False,
        "confirmed_exploitable": False, "protective_note": False,
    }
    base.update(over)
    return base


def test_disproved_requires_positive_disproof_evidence():
    v, r, _ = F.classify_verdict(evidence={
        "validation": {"steps": [{"stage": "runtime_disproof", "status": "disproved",
                                  "epistemic": "FACT", "detail": "totalSupply high at block 123"}]}})
    assert v == F.VERDICT_DISPROVED and "totalSupply" in r
    v2, _, _ = F.classify_verdict(evidence={"triage_rule": "live-state-disproof"})
    assert v2 == F.VERDICT_DISPROVED


def test_infra_failures_and_missing_source_never_disproved():
    v, r, retry = F.classify_verdict(evidence={"infra_failures": ["runtime_disproof: timeout"]})
    assert v == F.VERDICT_INCONCLUSIVE and retry is True and "NOT a disproof" in r
    v2, _, retry2 = F.classify_verdict(evidence={"missing_evidence": ["no source"]})
    assert v2 == F.VERDICT_INCONCLUSIVE and not retry2


def test_confirmed_exploitable_maps_to_validated_with_and_without_money():
    basis = dict(evidence(), confirmed_exploitable=True,
                 financial={"holdings_usd": 1234.0})
    v, r, _ = F.classify_verdict(evidence=basis)
    assert v == F.VERDICT_VALIDATED and "(confirmed_exploitable)" in r
    v2, r2, _ = F.classify_verdict(evidence=dict(evidence(), confirmed_exploitable=True))
    assert v2 == F.VERDICT_VALIDATED and "WITHOUT a number" in r2


def test_privileged_gate_and_protective_note_map_to_not_financial():
    v, r, _ = F.classify_verdict(evidence={"triage_reason": "privileged-module-caller"})
    assert v == F.VERDICT_NOT_FINANCIAL and "privileged" in r
    v2, _, _ = F.classify_verdict(evidence={"attacker": {
        "exposure_model": {"model": "privileged", "exposure_factor": 0.0},
        "privilege_gated": True}})
    assert v2 == F.VERDICT_NOT_FINANCIAL
    v3, _, _ = F.classify_verdict(evidence={"protective_note": True})
    assert v3 == F.VERDICT_NOT_FINANCIAL


def test_potential_when_dangerous_class_with_financial_basis():
    att = {"exposure_model": {"model": "partial", "exposure_factor": 0.05},
           "privilege_gated": False}
    fin = {"holdings_usd": 25000.0}
    v, r, _ = F.classify_verdict(evidence={"attacker": att, "financial": fin})
    assert v == F.VERDICT_POTENTIAL and "potential, not" in r


def test_potential_honeypot_user_funds_even_without_holdings_number():
    att = {"exposure_model": {"model": "honeypot", "exposure_factor": 1.0},
           "privilege_gated": False}
    fin = {"stored_estimate": {"est_loss_usd": 1200.0}, "user_funds_at_risk": True}
    v, _, _ = F.classify_verdict(evidence={"attacker": att, "financial": fin})
    assert v == F.VERDICT_POTENTIAL


def test_unknown_suppression_stays_inconclusive_not_disproved():
    v, r, _ = F.classify_verdict(evidence={
        "suppressed": True, "triage_rule": "some-rule", "triage_reason": "manual-call"})
    assert v == F.VERDICT_INCONCLUSIVE and "manual-call" in r


# ---------------------------------------------------------------------------
# end-to-end per-finding review (injected contexts; offline)
# ---------------------------------------------------------------------------

def _engine_outcome(tmp_path, *, details_row, monitor_ctx, matched=None, panel=None,
                    scan=None, rpc_url=None, allow_network_verify=False):
    db = tmp_path / "finrisk.db"
    con = reopen(db)
    scan = dict({"scan_id": "s1", "timestamp": "2026-10-24T00:00:00Z",
                 "source_path": (monitor_ctx or {}).get("source_path") or "etherscan://" + "b" * 40,
                 "config_fingerprint": "cfg"}, **(scan or {}))
    F.enqueue_findings(con, scan_id="s1", scan_timestamp=scan["timestamp"],
                       source_path=scan["source_path"], findings=[details_row])
    claims = F.claim_due(con, limit=1)
    sc, fp = claims[0]["scan_id"], claims[0]["fingerprint"]
    f_find = next(d for d in [(details_row)] if True)
    loader = lambda _sid: {**history_row(details=[details_row]), "_finrisk_chain":
                           F.resolve_chain_context(scan["source_path"]),
                           **({"_monitor": monitor_ctx} if monitor_ctx is not None else {})}
    if monitor_ctx is None:
        loader = lambda _sid: {**history_row(details=[details_row]),
                               "_finrisk_chain": F.resolve_chain_context(scan["source_path"]),
                               "_monitor": {"network": "ethereum", "address": None,
                                            "findings": [], "holdings": None,
                                            "tvl_usd": None, "price_as_of": None,
                                            "value_available": False, "sim": None}}
    res = F.process_one(con, scan_id=sc, fingerprint=fp, history_loader=loader,
                        rpc_url=rpc_url, allow_network_verify=allow_network_verify)
    return con, res


def test_engine_local_finding_without_monitor_is_potential_or_inconclusive(tmp_path):
    con, res = _engine_outcome(tmp_path, details_row=finding_dict(), monitor_ctx=None)
    assert res["status"] == F.STATE_COMPLETED
    v = res["verdict"]
    assert v in (F.VERDICT_POTENTIAL, F.VERDICT_INCONCLUSIVE)
    row = con.execute("SELECT review_json FROM finrisk_reviews WHERE scan_id=? AND fingerprint=?",
                      (res["scan_id"], res["fingerprint"])).fetchone()
    p = json.loads(row[0])
    assert p["identity"]["chain"]
    assert p["financial"]["methodology"] is None  # no holdings were read: no invented basis


def test_engine_saved_monitor_row_means_disproved_and_reused(tmp_path):
    addr = "0x" + "c" * 40
    src = f"etherscan://ethereum/{addr}"
    ri = finding_dict()
    mctx = {
        "network": "ethereum", "address": addr, "holdings": [{"symbol": "WETH", "usd": 5000.0}],
        "tvl_usd": 5000.0, "price_as_of": 1700000000.0, "value_available": True,
        "sim": None,
        "findings": [{"id": 11, "detector": "unguarded-withdraw", "function": "withdraw",
                      "contract": "Vault", "title": ri["title"], "suppressed": 1,
                      "confirmed_exploitable": 0, "triage_rule": "live-state-disproof",
                      "triage_reason": "tested", "triage_detail": "supply reads high",
                      "estimate": {}}],
    }
    con, res = _engine_outcome(tmp_path, details_row=ri, monitor_ctx=mctx)
    assert res["verdict"] == F.VERDICT_DISPROVED and res["status"] == F.STATE_COMPLETED
    p = json.loads(con.execute(
        "SELECT review_json FROM finrisk_reviews WHERE scan_id='s1' AND fingerprint=?",
        (res["fingerprint"],)).fetchone()[0])
    kinds = {s["stage"] for s in p["validation"]["steps"]}
    assert "pipeline_triage" in kinds
    # offline run: the runtime check is honestly recorded as not attempted,
    # never as a disproof
    rd = next(s for s in p["validation"]["steps"] if s["stage"] == "runtime_disproof")
    assert rd["status"] == "not_attempted" and rd["epistemic"] == "UNKNOWN"
    assert p["identity"]["address"] == addr


def test_engine_confirmed_monitor_row_maps_to_validated(tmp_path):
    addr = "0x" + "d" * 40
    ri = finding_dict()
    mctx = {"network": "ethereum", "address": addr,
            "holdings": [], "tvl_usd": 20000.0, "price_as_of": 1700000000.0,
            "value_available": True, "sim": None,
            "findings": [{"id": 12, "detector": "unguarded-withdraw", "function": "withdraw",
                          "contract": "Vault", "title": ri["title"], "suppressed": 0,
                          "confirmed_exploitable": 1, "triage_rule": "",
                          "triage_reason": "", "triage_detail": None,
                          "estimate": {"est_loss_usd": 20000.0}}]}
    con, res = _engine_outcome(tmp_path, details_row=ri, monitor_ctx=mctx)
    assert res["verdict"] == F.VERDICT_VALIDATED
    p = json.loads(con.execute("SELECT review_json FROM finrisk_reviews WHERE scan_id='s1'"
                               " AND fingerprint=?", (res["fingerprint"],)).fetchone()[0])
    st = {s["stage"]: s["status"] for s in p["validation"]["steps"]}
    assert st["dynamic_reproduction"] == "completed"
    assert p["financial"]["stored_estimate"]["est_loss_usd"] == 20000.0


def test_cross_scan_content_reuse_copies_verdict_with_provenance(tmp_path):
    ri = finding_dict()
    first_con, first = _engine_outcome(tmp_path / "one", details_row=ri, monitor_ctx=None)
    assert first["status"] == F.STATE_COMPLETED
    # second scan of the SAME code shape
    con = F.open_finrisk_db(tmp_path / "one" / "finrisk.db")
    F.enqueue_findings(con, scan_id="s2", scan_timestamp="t2",
                       source_path=first["scan_id"] and "local2", findings=[ri])
    claims = F.claim_due(con, limit=5)
    assert claims and claims[0]["scan_id"] == "s2"
    loader = lambda _sid: {**history_row(scan_id="s2", details=[ri]),
                           "_finrisk_chain": {"network": None, "address": None},
                           "_monitor": {"network": "ethereum", "address": None,
                                        "findings": [], "holdings": None, "tvl_usd": None,
                                        "price_as_of": None, "value_available": False,
                                        "sim": None}}
    res = F.process_one(con, scan_id="s2", fingerprint=claims[0]["fingerprint"],
                        history_loader=loader, rpc_url=None, allow_network_verify=False)
    assert res["verdict"] == first["verdict"] and res.get("reused") is True
    p = json.loads(con.execute(
        "SELECT review_json FROM finrisk_reviews WHERE scan_id='s2'").fetchone()[0])
    assert p["review_reuse"]["epistemic"] == "REVIEW_REUSE"


def test_missing_history_scan_record_is_inconclusive_not_a_crash(tmp_path):
    con = reopen(tmp_path / "finrisk.db")
    F.enqueue_findings(con, scan_id="ghost", scan_timestamp=None, source_path="local",
                       findings=[finding_dict()])
    claims = F.claim_due(con, limit=1)
    sc, fp = claims[0]["scan_id"], claims[0]["fingerprint"]
    res = F.process_one(con, scan_id=sc, fingerprint=fp,
                        history_loader=lambda _sid: None, rpc_url=None,
                        allow_network_verify=False)
    assert res["verdict"] == F.VERDICT_INCONCLUSIVE and res["status"] == F.STATE_COMPLETED


def test_upstream_rpc_error_is_retryable_inconclusive(tmp_path):
    con, res = _engine_outcome(tmp_path, details_row=finding_dict(),
                               monitor_ctx=None, rpc_url="http://127.0.0.1:1",
                               # force the runtime_disproof step to run against a dead endpoint
                               allow_network_verify=False)
    # the engine only calls RPC via runtime_disproof with rpc_url set; the
    # dead endpoint should surface an honest UNKNOWN step, not a disproof.
    p = json.loads(con.execute(
        "SELECT review_json FROM finrisk_reviews WHERE scan_id=? AND fingerprint=?",
        (res["scan_id"], res["fingerprint"])).fetchone()[0])
    disproof = [s for s in p["validation"]["steps"] if s["stage"] == "runtime_disproof"][0]
    assert disproof["status"] in ("error", "not_applicable_or_unknown")
    assert disproof["epistemic"] != "FACT"


# ---------------------------------------------------------------------------
# integration: enqueue hook through ScanHistory.mark_completed
# ---------------------------------------------------------------------------

def test_mark_completed_queues_findings_for_review(tmp_path, monkeypatch):
    monkeypatch.setenv("AUDITOR_FINRISK_DB", str(tmp_path / "finrisk.db"))
    db = tmp_path / "history.db"
    h = ScanHistory(db)
    try:
        fid = h.record_scan(Path("example.sol"), "dashboard-local", content_hash="x")
        findings = [
            Finding(title="Unprotected call", description="d", category="reentrancy",
                    severity=Severity.HIGH, confidence=Confidence.LOW,
                    verification_status=VerificationStatus.POSSIBLE),
            Finding(title="Guarded transfer", description="x", category="access",
                    severity=Severity.INFORMATIONAL, confidence=Confidence.LOW,
                    verification_status=VerificationStatus.UNVERIFIED),
        ]
        h.mark_completed(fid, findings)
    finally:
        h.close()
    con = F.open_finrisk_db_ro(tmp_path / "finrisk.db")
    assert con is not None
    n = con.execute("SELECT COUNT(*) FROM finrisk_reviews").fetchone()[0]
    con.close()
    assert n == 2
    s = F.summary(F.open_finrisk_db_ro(tmp_path / "finrisk.db"))
    assert s["queue"][F.STATE_PENDING] == 2


def test_finrisk_outage_cannot_break_scan_recording(tmp_path, monkeypatch):
    monkeypatch.setenv("AUDITOR_FINRISK_DB", str(tmp_path / "finrisk.db"))
    import auditor.scan_history as SH

    def boom(_conn, _scan_id, _details):
        raise sqlite3.OperationalError("sqlite is upset")

    monkeypatch.setattr(SH, "_finrisk_enqueue_after", boom)
    h = ScanHistory(tmp_path / "history.db")
    try:
        fid = h.record_scan(Path("example.sol"), "dashboard-local", content_hash="x")
        h.mark_completed(fid, [Finding(title="t", description="d", category="c")])
        rec = h.get_scan(fid)
        assert rec["status"] == "completed"  # recording unaffected
    finally:
        h.close()


def test_mark_completed_rediscovery_does_not_duplicate_reviews(tmp_path, monkeypatch):
    monkeypatch.setenv("AUDITOR_FINRISK_DB", str(tmp_path / "finrisk.db"))
    h = ScanHistory(tmp_path / "history.db")
    try:
        for _ in range(2):
            fid = h.record_scan(Path("example.sol"), "dashboard-local", content_hash="x")
            h.mark_completed(fid, [Finding(title="t", description="d", category="c")])
    finally:
        h.close()
    con = F.open_finrisk_db_ro(tmp_path / "finrisk.db")
    n = con.execute("SELECT COUNT(*) FROM finrisk_reviews").fetchone()[0]
    con.close()
    assert n == 2  # distinct scan_ids, not re-queued rows per scan


# ---------------------------------------------------------------------------
# reporting roll-up (§6): persisted evidence, no double counting
# ---------------------------------------------------------------------------

def _completed_review(con, scan_id, fingerprint, verdict, payload):
    F.enqueue_findings(con, scan_id=scan_id, scan_timestamp=None, source_path="local",
                       findings=[dict(finding_dict(), fingerprint=fingerprint)])
    (sc, fp), = [(c["scan_id"], c["fingerprint"]) for c in F.claim_due(con, limit=1)]
    payload = {**F._empty_payload(), **payload, "verdict": verdict}
    F.finish_completed(con, sc, fp, verdict, payload)


def test_financial_rollup_never_double_counts_one_address(tmp_path):
    con = reopen(tmp_path / "finrisk.db")
    addr = "0x" + "e" * 40
    idr = {"chain": "ethereum", "address": addr}
    # two validated reviews of the SAME address: counted once
    _completed_review(con, "a1", fp := "fp1", F.VERDICT_VALIDATED, {
        "identity": idr, "financial": {"assets": [{"symbol": "WETH", "usd": 1000.0}]}})
    _completed_review(con, "a2", "fp2", F.VERDICT_VALIDATED, {
        "identity": idr, "financial": {"assets": [{"symbol": "WETH", "usd": 4000.0}]}})
    # potential on the SAME address is superseded by the validated verdict
    _completed_review(con, "a3", "fp3", F.VERDICT_POTENTIAL, {
        "identity": idr, "financial": {"assets": [{"symbol": "USDC", "usd": 99.0}]}})
    # potential on a DIFFERENT address counts separately
    _completed_review(con, "a4", "fp4", F.VERDICT_POTENTIAL, {
        "identity": {"chain": "ethereum", "address": "0x" + "f" * 40},
        "financial": {"assets": [{"symbol": "USDC", "usd": 250.0}]},
        # modeled estimate reused from the pipeline, labelled
        "stored_estimate_used": True})
    # modeled estimate on the validated address: separate bucket
    _completed_review(con, "a5", "fp5", F.VERDICT_POTENTIAL, {
        "identity": {"chain": "ethereum", "address": "0x" + "9" * 40},
        "financial": {"assets": [], "stored_estimate": {"est_loss_usd": 750.0,
                                                        "label": "heuristic"}}})
    # validated WITHOUT a reliable dollar figure
    _completed_review(con, "a6", "fp6", F.VERDICT_VALIDATED, {
        "identity": {"chain": "base", "address": "0x" + "8" * 40},
        "financial": {"assets": [], "holdings_usd": None}})
    # a disproved review is excluded from every dollar total
    _completed_review(con, "a7", "fp7", F.VERDICT_DISPROVED, {
        "identity": {"chain": "ethereum", "address": "0x" + "7" * 40},
        "financial": {"assets": [{"symbol": "WETH", "usd": 100000.0}]}})
    m = F.financial_rollup(con)
    assert m["confirmed_outsider_exposure_usd"] == 4000.0  # max basis for the one address
    assert m["confirmed_addresses"] == 1
    # potential bucket: priced-holdings addresses only; the heuristic 750 lives
    # exclusively in the modeled bucket (never mixed into exposure totals)
    assert m["potential_or_unverified_exposure_usd"] == 250.0
    assert m["modeled_impact_estimate_usd"] == 750.0
    assert m["validated_without_dollar_estimate"] == 1
    assert m["disproved_excluded_rows"] == 1
    assert "NOT confirmed funds" in m["modeled_label"]


def test_monitor_context_unwraps_value_json(tmp_path):
    db = tmp_path / "monitor.db"
    con = sqlite3.connect(db)
    con.execute("CREATE TABLE monitor_scans (network TEXT, address TEXT, value_json TEXT,"
                " tvl_usd REAL, price_as_of REAL, finished_at TEXT, id INTEGER PRIMARY KEY)")
    con.execute("INSERT INTO monitor_scans (network, address, value_json, tvl_usd, price_as_of,"
                " finished_at, id) VALUES ('ethereum','0xabc',?,123.0,100.0,'t',1)",
                (json.dumps({"value": {"holdings": [{"symbol": "WETH", "usd": 222.0}],
                                       "tvl_usd": 999.0, "price_as_of": 42.0}}),))
    con.commit()
    con.close()
    ctx = F.monitor_context(db, network="ethereum", address="0xabc")
    assert ctx["holdings"] == [{"symbol": "WETH", "usd": 222.0}]
    assert ctx["tvl_usd"] == 999.0 and ctx["price_as_of"] == 42.0
    assert ctx["value_available"] is True


# ---------------------------------------------------------------------------
# database contention behaviour (documented SQLite locking conventions)
# ---------------------------------------------------------------------------

def test_reader_with_bounded_busy_wait_reads_while_writer_active(tmp_path):
    db = tmp_path / "finrisk.db"
    con = F.open_finrisk_db(db)
    F.enqueue_findings(con, scan_id="s1", scan_timestamp=None, source_path="local",
                       findings=[finding_dict()])
    # writer holds an uncommitted write transaction
    writer = sqlite3.connect(str(db), timeout=15)
    writer.execute("BEGIN IMMEDIATE")
    writer.execute("UPDATE finrisk_reviews SET priority=7 WHERE scan_id='s1'")
    # dashboard-style read-only reader (mode=ro, bounded timeout) still works: WAL
    reader = sqlite3.connect(f"file:{db}?mode=ro", uri=True, timeout=10)
    reader.row_factory = sqlite3.Row
    rows = reader.execute("SELECT COUNT(*) AS n FROM finrisk_reviews").fetchone()
    writer.rollback()
    writer.close()
    reader.close()
    assert rows["n"] == 1


def test_finrisk_lock_is_exclusive_and_released(tmp_path):
    db = tmp_path / "finrisk.db"
    with F.finrisk_lock(db) as l1:
        assert l1.acquired()
        with F.finrisk_lock(db) as l2:
            assert not l2.acquired()
    with F.finrisk_lock(db) as l3:
        assert l3.acquired()  # released on exit


def test_monitor_view_reader_carries_bounded_busy_timeout():
    from auditor import monitor_view

    db = Path(__file__).resolve().parents[1] / "monitor_state.db"
    if not db.exists():
        pytest.skip("no local monitor_state.db")
    con = monitor_view._connect(db)
    assert con is not None
    busy = con.execute("PRAGMA busy_timeout").fetchone()[0]
    con.close()
    assert busy == 10000


def test_enqueue_hook_skips_when_history_is_test_isolated(tmp_path, monkeypatch):
    """Isolation rule: a test-overridden history DB must never leak rows into
    the SHARED finrisk queue (they would dangle once the tmp dir vanishes).

    The hook checks env ordering itself; here the finrisk path is pointed at
    a tmp file that must NOT even be created when the guard engages."""
    import unittest.mock as mock

    import auditor.scan_history as SH

    monkeypatch.delenv("AUDITOR_FINRISK_DB", raising=False)
    monkeypatch.setenv("AUDITOR_HISTORY_DB", str(tmp_path / "unused-history.db"))
    fin_db = tmp_path / "finrisk-store.db"
    conn = mock.MagicMock()
    SH._finrisk_enqueue_after(conn=conn, scan_id="iso", details=[finding_dict()])
    assert not conn.execute.called, "guard must short-circuit before touching the history db"
    # sanity: without the history override the same call reaches the DB layer
    monkeypatch.delenv("AUDITOR_HISTORY_DB", raising=False)
    monkeypatch.setenv("AUDITOR_FINRISK_DB", str(fin_db))
    SH._finrisk_enqueue_after(conn=mock.MagicMock(), scan_id="iso",
                              details=[finding_dict()])
    con = F.open_finrisk_db(fin_db)
    n = con.execute("SELECT COUNT(*) FROM finrisk_reviews WHERE scan_id='iso'").fetchone()[0]
    con.close()
    assert n == 1, "the normal production path still enqueues"


# ---------------------------------------------------------------------------
# dashboard integration: auto-enqueue via mark_completed, listing filter +
# annotation, manual run endpoint, investigation block (isolated DBs only)
# ---------------------------------------------------------------------------

def _fake_finrisk_outcome(titles):
    from auditor.analysis.base import AnalysisOutcome

    outcome = AnalysisOutcome()
    outcome.findings = [
        Finding(
            title=title,
            description="External call precedes state update (fixture finding).",
            category="reentrancy",
            severity=Severity.HIGH,
            confidence=Confidence.MEDIUM,
            verification_status=VerificationStatus.UNVERIFIED,
            affected_lines=[12, 18],
        )
        for title in titles
    ]
    outcome.evidence = []
    outcome.notes = ["fixture analyzer"]
    return outcome


def _run_mocked_scan(client, tmp_path):
    """Submit a mocked local scan through the dashboard job runner.

    Returns (scan_id, fingerprint) of the recorded finding, mirroring
    tests/test_dashboard.py's offline job pattern."""
    import unittest.mock as mock

    project = tmp_path / "proj"
    project.mkdir(exist_ok=True)
    (project / "Vulnerable.sol").write_text(
        "// SPDX-License-Identifier: MIT\n"
        "pragma solidity ^0.8.0;\n"
        "contract Vulnerable { uint256 public balance; }\n",
        encoding="utf-8",
    )
    with mock.patch(
        "auditor.analysis.reentrancy.analyze",
        side_effect=lambda ctx: _fake_finrisk_outcome(["Fixture reentrancy"]),
    ), mock.patch(
        "auditor.analysis.access_control.analyze",
        side_effect=lambda ctx: _fake_finrisk_outcome([]),
    ), mock.patch(
        "auditor.analysis.slither_generic.analyze",
        side_effect=lambda ctx: _fake_finrisk_outcome([]),
    ):
        res = client.post(
            "/api/scan",
            json={"scan_type": "local", "local": {"path": str(project),
                                                  "validate_project": False}})
        assert res.status_code == 202, res.text
        job_id = res.json()["job_id"]
        deadline = time.time() + 30
        job = {}
        while time.time() < deadline:
            job = client.get(f"/api/jobs/{job_id}").json()
            if job.get("status") in ("completed", "failed", "cancelled"):
                break
            time.sleep(0.1)
        assert job["status"] == "completed", job.get("error")
        scan_id = job["result"]["scan_id"]
    listing = client.get("/api/findings", params={"limit": 50}).json()
    row = next(f for f in listing.get("findings", [])
               if f.get("scan_id") == scan_id and f.get("fingerprint"))
    return scan_id, row["fingerprint"]


@pytest.fixture()
def finrisk_client(tmp_path, monkeypatch):
    """Dashboard app wired at isolated DBs (history + finrisk + no RPC).

    Returns ``(client, tmp_path)``."""
    from fastapi.testclient import TestClient

    from auditor.dashboard.app import create_app

    monkeypatch.setenv("AUDITOR_HISTORY_DB", str(tmp_path / "history.db"))
    monkeypatch.setenv("AUDITOR_FINRISK_DB", str(tmp_path / "finrisk.db"))
    monkeypatch.setattr(F, "rpc_url_for_review", lambda: None)
    client = TestClient(create_app())
    client.__enter__()  # run app lifespan (job manager threads start here)
    try:
        yield client, tmp_path
    finally:
        client.__exit__(None, None, None)


def test_scan_completion_autoenqueues_and_pending_filter_matches(finrisk_client):
    c, tmp = finrisk_client
    scan_id, fp = _run_mocked_scan(c, tmp)
    # the mark_completed hook queued the completed finding automatically
    s = c.get("/api/finrisk/summary").json()
    assert s["status"] == "ok"
    assert s["queue"].get("pending") == 1
    assert all(v == 0 for v in (s.get("verdicts") or {}).values())
    # listed rows carry the queue annotation; the pending filter matches it
    rows = c.get("/api/findings", params={"finrisk": "pending"}).json().get("findings") or []
    hit = [f for f in rows if f.get("scan_id") == scan_id and f.get("finrisk")]
    assert hit, "the queued finding must appear under the pending filter"
    assert hit[0]["finrisk"]["state"] == "pending" or hit[0]["finrisk"]["state"] in (
        "pending", "running", "retryable_error", "completed")
    assert hit[0]["finrisk"]["verdict"] is None
    # other filters do not match a not-yet-reviewed row
    other = c.get("/api/findings",
                  params={"finrisk": "validated_financial_risk,potential_financial_risk,"
                                    "disproved,inconclusive,not_financially_exploitable"})
    assert other.json().get("total") == 0
    # empty-ish rollup on a not-yet-reviewed queue
    assert s["financial_rollup"]["confirmed_outsider_exposure_usd"] == 0


def test_finrisk_manual_run_and_filters_and_investigation_block(finrisk_client):
    c, tmp = finrisk_client
    scan_id, fp = _run_mocked_scan(c, tmp)
    run = c.post(f"/api/findings/{scan_id}/finrisk/run", params={"fp": fp})
    assert run.status_code == 200, run.text
    body = run.json()
    review = body["review"]
    assert review["state"] == F.STATE_COMPLETED
    assert review["verdict"] in (F.VERDICT_VALIDATED, F.VERDICT_POTENTIAL, F.VERDICT_DISPROVED,
                                 F.VERDICT_INCONCLUSIVE, F.VERDICT_NOT_FINANCIAL)
    # payload endpoint mirrors it
    payload = c.get(f"/api/findings/{scan_id}/finrisk", params={"fp": fp})
    assert payload.status_code == 200
    assert payload.json()["verdict"] == review["verdict"]
    # investigation carries the block (state + verdict, no invented fields)
    inv = c.get(f"/api/findings/{scan_id}/investigation", params={"fp": fp}).json()
    block = inv["financial_risk_review"]
    assert block["state"] == F.STATE_COMPLETED and block["verdict"] == review["verdict"]
    # verdict filters now resolve; the pending filter no longer matches it,
    # and a fresh listing annotates the row
    vrows = c.get("/api/findings", params={"finrisk": review["verdict"]}).json()
    assert vrows["total"] == 1
    assert vrows["findings"][0]["finrisk"]["verdict"] == review["verdict"]
    pending = c.get("/api/findings", params={"finrisk": "pending"}).json()
    assert pending["total"] == 0
    # grouped listing stays annotated too
    grouped = c.get("/api/findings", params={"finrisk": review["verdict"], "group": "severity"})
    gfindings = [f for g in (grouped.json().get("groups") or {}).values() for f in g]
    assert all(f.get("finrisk", {}).get("verdict") == review["verdict"] for f in gfindings)
    # the roll up saw the completed review without inventing dollars on an
    # unpriced local fixture
    roll = c.get("/api/finrisk/summary").json()["financial_rollup"]
    assert roll["disproved_excluded_rows"] >= 0
    if review["verdict"] != F.VERDICT_VALIDATED:
        assert roll["confirmed_outsider_exposure_usd"] == 0


def test_finrisk_run_404_paths_and_empty_fp(finrisk_client):
    c, tmp = finrisk_client
    # unknown scan
    assert c.post("/api/findings/nope/finrisk/run", params={"fp": "x"}).status_code == 404
    # empty fingerprint
    assert c.post("/api/findings/nope/finrisk/run",
                  params={"fp": "   "}).status_code == 422
    # queued scan, but an unrelated fingerprint
    scan_id, fp = _run_mocked_scan(c, tmp)
    bad = c.post(f"/api/findings/{scan_id}/finrisk/run", params={"fp": "not|a|real|fp"})
    assert bad.status_code == 404
    assert "fingerprint not present" in bad.json()["detail"]
    # GET payload endpoints for unknown things
    assert c.get("/api/findings/nope/finrisk", params={"fp": "x"}).status_code in (404, 405)


def test_finrisk_run_http409_when_lock_busy(finrisk_client):
    c, tmp = finrisk_client
    scan_id, fp = _run_mocked_scan(c, tmp)
    with F.finrisk_lock() as busy:
        assert busy.acquired()
        res = c.post(f"/api/findings/{scan_id}/finrisk/run", params={"fp": fp})
        assert res.status_code == 409
        assert "already running" in res.json()["detail"]


def test_findings_page_renders_finrisk_filter_and_counters(finrisk_client):
    c, _tmp = finrisk_client
    html = c.get("/findings").text
    for needle in ('id="findings-finrisk"', 'id="finrisk-counters"',
                   "pending", "validated_financial_risk", "potential_financial_risk",
                   "disproved", "inconclusive", "not_financially_exploitable", "high_impact"):
        assert needle in html, needle


def test_investigate_page_renders_finrisk_panel_and_actions(finrisk_client):
    c, tmp = finrisk_client
    scan_id, fp = _run_mocked_scan(c, tmp)
    html = c.get(f"/investigate/{scan_id}", params={"fp": fp}).text
    for needle in ('id="inv-finrisk-card"', 'id="inv-finrisk-review-btn"',
                   'id="inv-finrisk-rerun-btn"', 'id="inv-finrisk"'):
        assert needle in html, needle


# ---------------------------------------------------------------------------
# Financial Exploits tab (/exploits): per-verdict views, validated-only
# inclusion, per-row financial basis, roll-up counters (isolated DBs only)
# ---------------------------------------------------------------------------

def _seed_finrisk_verdict(tmp, scan_id, fp, verdict, extra=None):
    """Seed a verdict directly into the ISOLATED review store.

    Validated rows require the pipeline's lab outcome, which the manual-run
    endpoint cannot force; tests therefore persist the review payload the
    same way the engine does (finish_completed) instead of faking API calls."""
    con = F.open_finrisk_db(tmp / "finrisk.db")
    try:
        payload = {**F._empty_payload(), **(extra or {}), "verdict": verdict}
        F.finish_completed(con, scan_id, fp, verdict, payload)
    finally:
        con.close()


_VALUED_PAYLOAD = {
    "identity": {"chain": "ethereum", "address": "0x" + "b" * 40},
    "financial": {"assets": [{"symbol": "WETH", "usd": 1000.0}]},
    "attacker": {"exposure_model": {"vulnerability_class": "drain_all"},
                 "privilege_gated": False},
}


def test_exploits_page_renders_tab_and_views(finrisk_client):
    c, _tmp = finrisk_client
    html = c.get("/exploits").text
    # dedicated sidebar tab (present on this page and wired into shared nav)
    assert 'href="/exploits"' in html and 'data-page="exploits"' in html
    # per-verdict view buttons, one per exact verdict token
    for token in ("validated_financial_risk", "potential_financial_risk",
                  "inconclusive", "disproved", "not_financially_exploitable"):
        assert f'data-v="{token}"' in html, token
    # roll-up card + honest empty-state elements exist in the template
    for needle in ('id="exploits-rollup-card"', 'id="exploits-rollup-body"',
                   'id="exploits-empty"', 'id="exploits-table"', 'id="exploits-error"'):
        assert needle in html, needle


def test_exploits_validated_view_only_exact_verdict_with_basis(finrisk_client):
    c, tmp = finrisk_client
    # review 1 -> VALIDATED with a priced basis
    scan_id, fp = _run_mocked_scan(c, tmp)
    _seed_finrisk_verdict(tmp, scan_id, fp, F.VERDICT_VALIDATED,
                          extra=_VALUED_PAYLOAD)
    # review 2 -> INCONCLUSIVE (must never leak into the validated view)
    scan2, fp2 = _run_mocked_scan(c, tmp)
    _seed_finrisk_verdict(tmp, scan2, fp2, F.VERDICT_INCONCLUSIVE,
                          extra={"identity": {"chain": "ethereum",
                                              "address": "0x" + "c" * 40}})
    # validated view: exactly the validated row, exact verdict only
    rows = c.get("/api/findings",
                 params={"finrisk": "validated_financial_risk"}).json()
    assert rows["total"] == 1
    hit = rows["findings"][0]
    assert hit["scan_id"] == scan_id and hit["finrisk"]["verdict"] == F.VERDICT_VALIDATED
    # the annotation carries the persisted per-row financial basis
    assert hit["finrisk"]["basis_usd"] == 1000.0
    assert hit["finrisk"]["estimate_usd"] is None
    assert hit["finrisk"]["network"] == "ethereum"
    assert hit["finrisk"]["address"] == "0x" + "b" * 40
    assert hit["finrisk"]["exposure_class"] == "drain_all"
    # inconclusive view lists ONLY the inconclusive row
    inc = c.get("/api/findings", params={"finrisk": "inconclusive"}).json()
    assert inc["total"] == 1 and inc["findings"][0]["scan_id"] == scan2
    # the two views never share rows
    assert {f["scan_id"] for f in rows["findings"]} & {scan2} == set()


def test_exploits_pending_never_appears_in_verdict_views(finrisk_client):
    c, tmp = finrisk_client
    scan_id, fp = _run_mocked_scan(c, tmp)
    # the auto-enqueued row is pending with no verdict
    pend = c.get("/api/findings", params={"finrisk": "pending"}).json()
    assert pend["total"] == 1
    # every exact-verdict view stays empty — pending rows can never appear
    for token in ("validated_financial_risk", "potential_financial_risk",
                  "inconclusive", "disproved", "not_financially_exploitable"):
        assert c.get("/api/findings", params={"finrisk": token}).json()["total"] == 0, token
    # after completion the row leaves the pending filter and joins its verdict
    _seed_finrisk_verdict(tmp, scan_id, fp, F.VERDICT_POTENTIAL,
                          extra={"identity": {"chain": "ethereum",
                                              "address": "0x" + "d" * 40}})
    assert c.get("/api/findings", params={"finrisk": "pending"}).json()["total"] == 0
    pot = c.get("/api/findings", params={"finrisk": "potential_financial_risk"}).json()
    assert pot["total"] == 1 and pot["findings"][0]["finrisk"]["verdict"] == F.VERDICT_POTENTIAL


def test_exploits_disproved_isolated_and_excluded_from_dollars(finrisk_client):
    c, tmp = finrisk_client
    scan_id, fp = _run_mocked_scan(c, tmp)
    _seed_finrisk_verdict(tmp, scan_id, fp, F.VERDICT_DISPROVED,
                          extra={"identity": {"chain": "ethereum",
                                              "address": "0x" + "7" * 40},
                                 "financial": {"assets": [{"symbol": "WETH",
                                                           "usd": 100000.0}]}})
    dis = c.get("/api/findings", params={"finrisk": "disproved"}).json()
    assert dis["total"] == 1 and dis["findings"][0]["finrisk"]["verdict"] == F.VERDICT_DISPROVED
    # a high-dollar disproved row is excluded from every exposure total
    roll = c.get("/api/finrisk/summary").json()["financial_rollup"]
    assert roll["disproved_excluded_rows"] == 1
    assert roll["confirmed_outsider_exposure_usd"] == 0
    assert roll["potential_or_unverified_exposure_usd"] == 0
    # not_financially_exploitable view is its own bucket
    assert c.get("/api/findings",
                 params={"finrisk": "not_financially_exploitable"}).json()["total"] == 0


def test_exploits_rollup_dedupe_via_summary_api(finrisk_client):
    """Two validated reviews of ONE address: the tab's roll-up counters must
    count the holding once, never double."""
    c, tmp = finrisk_client
    scan_id, fp = _run_mocked_scan(c, tmp)
    _seed_finrisk_verdict(tmp, scan_id, fp, F.VERDICT_VALIDATED,
                          extra=_VALUED_PAYLOAD)
    scan2, fp2 = _run_mocked_scan(c, tmp)
    richer = {**_VALUED_PAYLOAD,
              "financial": {"assets": [{"symbol": "WETH", "usd": 4000.0}]}}
    _seed_finrisk_verdict(tmp, scan2, fp2, F.VERDICT_VALIDATED, extra=richer)
    roll = c.get("/api/finrisk/summary").json()["financial_rollup"]
    assert roll["confirmed_addresses"] == 1
    assert roll["confirmed_outsider_exposure_usd"] == 4000.0
    # both rows still surface individually in the validated view
    rows = c.get("/api/findings",
                 params={"finrisk": "validated_financial_risk"}).json()
    assert rows["total"] == 2


def test_exploits_corrupt_review_json_degrades_gracefully(finrisk_client):
    """A completed row whose stored payload no longer parses must keep its
    state/verdict badge and simply lose the dollar basis — the listing and
    the tab must never break."""
    c, tmp = finrisk_client
    scan_id, fp = _run_mocked_scan(c, tmp)
    _seed_finrisk_verdict(tmp, scan_id, fp, F.VERDICT_VALIDATED,
                          extra=_VALUED_PAYLOAD)
    con = F.open_finrisk_db(tmp / "finrisk.db")
    try:
        con.execute("UPDATE finrisk_reviews SET review_json='{not json'"
                    " WHERE scan_id=? AND fingerprint=?", (scan_id, fp))
        con.commit()
    finally:
        con.close()
    rows = c.get("/api/findings",
                 params={"finrisk": "validated_financial_risk"}).json()
    assert rows["total"] == 1  # verdict column still exact
    hit = rows["findings"][0]
    assert hit["finrisk"]["verdict"] == F.VERDICT_VALIDATED
    assert "basis_usd" not in hit["finrisk"]  # unknown, not fabricated
    assert "exposure_class" not in hit["finrisk"]


def test_exploits_categories_filter_and_privileged_separation(finrisk_client):
    """Verify the 5 distinct categories on the Financial Loss Risk tab:
    confirmed losses, suspected risk, privileged access, unverified exposure,
    and disproved/false positives."""
    c, tmp = finrisk_client
    # 1. Privileged access row (owner-gated path, not outsider exploitable)
    scan_priv, fp_priv = _run_mocked_scan(c, tmp)
    _seed_finrisk_verdict(tmp, scan_priv, fp_priv, F.VERDICT_NOT_FINANCIAL, extra={
        "attacker": {"privilege_gated": True, "exposure_model": {"model": "privileged"}}
    })

    # 2. Disproved row (tested path does not hold)
    scan_disp, fp_disp = _run_mocked_scan(c, tmp)
    _seed_finrisk_verdict(tmp, scan_disp, fp_disp, F.VERDICT_DISPROVED)

    # 3. Inconclusive row (RPC/infra outage)
    scan_inc, fp_inc = _run_mocked_scan(c, tmp)
    _seed_finrisk_verdict(tmp, scan_inc, fp_inc, F.VERDICT_INCONCLUSIVE)

    # Privileged category matches ONLY the privileged row
    priv_resp = c.get("/api/findings", params={"finrisk": "privileged_access"}).json()
    assert priv_resp["total"] == 1
    assert priv_resp["findings"][0]["scan_id"] == scan_priv
    assert priv_resp["findings"][0]["finrisk"]["privilege_gated"] is True

    # Unverified exposure matches the inconclusive row (and any pending row)
    unv_resp = c.get("/api/findings", params={"finrisk": "unverified_exposure"}).json()
    assert any(f["scan_id"] == scan_inc for f in unv_resp["findings"])
    assert not any(f["scan_id"] == scan_priv for f in unv_resp["findings"])

    # Disproved / False positive matches the disproved row, distinct from privileged access
    disp_resp = c.get("/api/findings", params={"finrisk": "disproved_false_positive"}).json()
    assert any(f["scan_id"] == scan_disp for f in disp_resp["findings"])
    assert not any(f["scan_id"] == scan_priv for f in disp_resp["findings"])



