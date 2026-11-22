from pathlib import Path
from auditor import fork_diff as F

UP = """pragma solidity ^0.8.0;
contract Pair {
  function getReserves() public view returns (uint a) { a = 1; }
  function swap(uint x) external { require(x > 0); }
  function skim(address t) external { t; }
  function sync() external { }
  function mint(address t) external returns (uint) { t; return 1; }
  function burn(address t) external returns (uint) { t; return 2; }
}"""


def _mk(tmp, name, src, pin=None):
    d = tmp / name; d.mkdir(parents=True)
    (d / "P.sol").write_text(src)
    if pin:
        (d / ".pinned_commit").write_text(pin)
    return d


def test_missing_corpus_is_none(tmp_path):
    assert F.build_upstream_index(tmp_path / "nope") is None


def test_match_changed_added(tmp_path):
    _mk(tmp_path / "up", "univ2", UP, pin="abcdef1234567890")
    up = F.build_upstream_index(tmp_path / "up")
    assert up["refs"] == ["univ2@abcdef1234"]
    cand = UP.replace("require(x > 0);", "require(x > 1);").replace(
        "function sync() external { }", "function sync() external { }\n  function rescue() external { selfdestruct(payable(msg.sender)); }")
    c = _mk(tmp_path, "cand", cand)
    [d] = F.diff_candidate(c, {"families": {}}, upstream=up)
    assert [x["function"] for x in d["changed"]] == ["swap"] and d["changed"][0]["basis"] == "upstream"
    assert d["upstream"]["added"] == ["rescue"]
    assert d["unchanged"] == 4 and d["unmodified_upstream"] is False


def test_unmodified_upstream(tmp_path):
    _mk(tmp_path / "up", "univ2", UP)
    up = F.build_upstream_index(tmp_path / "up")
    [d] = F.diff_candidate(_mk(tmp_path, "cand", UP.replace("{ }", "{  }")), {"families": {}}, upstream=up)
    assert d["unmodified_upstream"] is True


def test_corpus_fallback_without_family_reference(tmp_path):
    up = F.build_upstream_index(_mk(tmp_path / "upx", "emptyup", "contract X { function f() public { } }").parent)
    [d] = F.diff_candidate(_mk(tmp_path, "cand", UP), {"families": {}}, upstream=up)
    assert "upstream" not in d and d["no_reference"] + d["unchanged"] == 5
