from pathlib import Path
from auditor import fork_diff as F

UP = """pragma solidity ^0.8.0;
contract Vault {
  function totalAssets() public view returns (uint) { return 1; }
  function convertToShares(uint a) public view returns (uint) { return a * 2; }
  function convertToAssets(uint s) public view returns (uint) { return s / 2; }
  function previewDeposit(uint a) public view returns (uint) { return convertToShares(a); }
  function deposit(uint a, address r) public returns (uint) { return a; }
  function redeem(uint s, address r, address o) public returns (uint) { return s; }
  function withdraw(uint a, address r, address o) public returns (uint) { return a; }
}"""


def _mk(root: Path, name: str, text: str) -> Path:
    d = root / name; d.mkdir(parents=True); (d / "V.sol").write_text(text); return d


def test_family_detection():
    assert F.family_of(["getReserves", "swap", "skim", "sync", "mint", "burn"]) == "uniswap_v2"
    assert F.family_of(["foo", "bar"]) is None


def test_only_modified_function_is_flagged(tmp_path):
    roots = [_mk(tmp_path, f"u{i}", UP) for i in range(3)]
    cand = _mk(tmp_path, "cand", UP.replace("return a * 2;", "return a * 2 + 1;"))
    idx = F.build_index(roots + [cand])
    d = F.diff_candidate(cand, idx)
    assert d[0]["family"] == "erc4626"
    assert [c["function"] for c in d[0]["changed"]] == ["convertToShares"]
    same = F.diff_candidate(roots[0], idx)
    assert same[0]["changed"] == []


def test_comment_and_whitespace_changes_are_not_changes(tmp_path):
    roots = [_mk(tmp_path, f"u{i}", UP) for i in range(3)]
    cand = _mk(tmp_path, "cand", UP.replace("return 1;", "return   1; /* note */"))
    d = F.diff_candidate(cand, F.build_index(roots + [cand]))
    assert d[0]["changed"] == []


def test_record_and_count(tmp_path):
    import sqlite3
    con = sqlite3.connect(tmp_path / "m.db")
    F.record(con, "ethereum", "0xAB", "h", [{"family": "erc4626", "changed": [{"function": "f"}]}], 3)
    assert F.changed_count(con, "ethereum", "0xab") == 1
    assert F.changed_count(con, "ethereum", "0xcd") is None


def test_wired_into_hunt():
    import inspect
    from auditor.hunt import Hunter
    assert "_fork_diff_stage" in inspect.getsource(Hunter.scan_ready if hasattr(Hunter, "scan_ready") else Hunter)


def test_strategies_endpoint(tmp_path, monkeypatch):
    monkeypatch.setenv("AUDITOR_MONITOR_DB", str(tmp_path / "m.db"))
    monkeypatch.setenv("AUDITOR_HISTORY_DB", str(tmp_path / "h.db"))
    from auditor.monitor import MonitorStore
    MonitorStore(tmp_path / "m.db")
    from fastapi.testclient import TestClient
    from auditor.dashboard.app import create_app
    c = TestClient(create_app())
    d = c.get("/api/hunt/strategies").json()
    assert d["fork_diff"] == [] and d["known_exploit_findings"] == {} and d["confirmed_exploitable"] == 0
    assert c.get("/hunt").status_code == 200
