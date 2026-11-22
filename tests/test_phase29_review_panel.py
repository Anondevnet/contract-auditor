import json
import auditor.review_panel as P


def V(verdict, err=None, ev=None):
    return P.Vote("attacker", "m", verdict, error=err, evidence_lines=ev or [])


def test_3_0_yes():
    a = P.aggregate([V("yes", ev=["A.sol:1"]), V("yes"), V("yes")])
    assert a["label"] == "ai_majority_suspected" and a["epistemic"] == "statically supported"
    assert a["confirmed_exploitable"] == 0


def test_2_1_yes_no_evidence_is_unresolved():
    a = P.aggregate([V("yes"), V("yes"), V("no")])
    assert a["label"] == "ai_majority_suspected" and a["epistemic"] == "unresolved suspicion"


def test_1_2_no():
    assert P.aggregate([V("yes"), V("no"), V("no")])["label"] == "ai_majority_likely_fp"


def test_no_majority():
    assert P.aggregate([V("yes"), V("no"), V("inconclusive")])["label"] == "inconclusive"


def test_failure_is_not_a_vote():
    a = P.aggregate([V("yes"), V("yes"), V(None, err="timeout")])
    assert a["label"] == "inconclusive" and a["valid_votes"] == 2 and a["failed"] == 1


def test_parse_vote_variants():
    v = P.parse_vote("defender", "m", '<think>x</think>{"vulnerable": "No", "confidence": 80,'
                     ' "evidence_lines": "C.sol:38"}', None)
    assert v.verdict == "no" and v.confidence == 0.8 and v.evidence_lines == ["C.sol:38"]
    assert not P.parse_vote("d", "m", "garbage", None).valid
    assert not P.parse_vote("d", "m", None, "refused").valid


def test_prompts_independent():
    seen = []
    def backend(model, system, prompt):
        seen.append(prompt)
        return json.dumps({"vulnerable": "yes"}), None
    P.review_finding({"title": "t"}, "src", backend, {r: "m" for r in P.ROLES})
    assert len(seen) == 3 and len(set(seen)) == 1  # same inputs, no peer answers leaked


def test_persistence_queue_and_retry(tmp_path):
    con = P.connect(tmp_path / "r.db")
    assert P.enqueue(con, [{"id": 1, "title": "drain", "severity": "LOW"},
                           {"id": 2, "title": "naming", "severity": "HIGH"}]) == 2
    assert P.enqueue(con, [{"id": 1}]) == 0  # durable, idempotent
    calls = {"n": 0}
    def backend(model, system, prompt):
        calls["n"] += 1
        return (None, "boom") if calls["n"] == 1 else (json.dumps({"vulnerable": "yes", "evidence_lines": ["x"]}), None)
    load = lambda fid: ({"id": fid, "title": "t"}, "src")
    res = P.run_queue(con, load, backend, {r: "m" for r in P.ROLES}, limit=1, now=lambda: 0)
    assert res[0]["finding_id"] == 1 and res[0]["status"] == "retry"  # priority: drain first
    assert P.run_queue(con, load, backend, {r: "m" for r in P.ROLES}, limit=5, now=lambda: 0)[0]["finding_id"] == 2
    res = P.run_queue(con, load, backend, {r: "m" for r in P.ROLES}, limit=5, now=lambda: 10**9)
    assert res[0]["label"] == "ai_majority_suspected"
    p = P.panel_for(con, 1)
    assert p["round"] == 2 and len(p["votes"]) == 4 and all(v["model"] in ("m", "deterministic") for v in p["votes"])
    assert all(v["prompt_version"] == P.PROMPT_VERSION and v["created_at"] for v in p["votes"])
    s = P.panel_summary(con)
    assert s["labels"]["ai_majority_suspected"] == 2 and s["votes"] == 12


def test_majority_yes_never_touches_confirmed(tmp_path):
    import inspect
    assert "confirmed_exploitable=1" not in inspect.getsource(P).replace(" ", "")


def test_api_panel_endpoints(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient
    from auditor.dashboard.app import create_app
    monkeypatch.setenv("AUDITOR_REVIEW_DB", str(tmp_path / "none.db"))
    c = TestClient(create_app())
    assert c.get("/api/review-panel/summary").json() == {"available": False, "message": "review panel has not run yet"}
    assert c.get("/api/review-panel/finding/5").json() == {"finding_id": 5, "reviewed": False}
    con = P.connect(tmp_path / "r.db")
    P.save_round(con, 5, [P.Vote("attacker", "qwen", "yes"), P.Vote("defender", "qwen", "no"),
                          P.Vote("invariant", "qwen", None, error="timeout")])
    monkeypatch.setenv("AUDITOR_REVIEW_DB", str(tmp_path / "r.db"))
    d = c.get("/api/review-panel/finding/5").json()
    assert d["reviewed"] and d["label"] == "inconclusive" and len(d["votes"]) == 3
    assert d["summary"]["confirmed_exploitable"] == 0
    s = c.get("/api/review-panel/summary").json()
    assert s["available"] and s["votes"] == 3
    assert c.get("/monitor").status_code == 200


def test_tie_on_four_votes_is_inconclusive():
    assert P.aggregate([V("yes"), V("yes"), V("no"), V("no")])["label"] == "inconclusive"
    assert P.aggregate([V("yes"), V("yes"), V("yes"), V("no")])["label"] == "ai_majority_suspected"


def test_deterministic_guard_reviewer():
    src = "2129:     function _entry_lock(address from, uint256 amount) internal onlyJobRegistry whenNotPaused {"
    v = P.deterministic_guard_vote({"function": "_entry_lock", "file": "S.sol"}, src)
    assert v.verdict == "no" and v.model == "deterministic" and v.evidence_lines == ["S.sol:2129"]
    v = P.deterministic_guard_vote({"function": "sweep"}, "10: function sweep(address t) external onlyOwner {")
    assert v.verdict == "no"
    v = P.deterministic_guard_vote({"function": "drain"}, "5: function drain() external {")
    assert v.verdict == "inconclusive"
    assert P.deterministic_guard_vote({"function": "zz"}, "nothing").verdict == "inconclusive"


def test_guard_check_veto():
    g = P.Vote("guard_check", "deterministic", "no", evidence_lines=["S.sol:1"])
    a = P.aggregate([V("yes"), V("yes"), V("yes"), g])
    assert a["label"] == "inconclusive" and "vetoed" in a["reason"] and a["confirmed_exploitable"] == 0
