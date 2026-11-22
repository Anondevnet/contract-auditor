import sqlite3
from pathlib import Path
from auditor import proxy_init_sweep as P

INIT_SRC = """pragma solidity ^0.8.20;
contract V is Initializable, UUPSUpgradeable { address public owner;
  function initialize(address o) external initializer { owner = o; }
  function _authorizeUpgrade(address) internal override {}
}"""
SAFE_SRC = INIT_SRC.replace("address public owner;", "address public owner; constructor() { _disableInitializers(); }")
Z = "0x" + "0" * 64
IMPL = "0x" + "0" * 24 + "11" * 20


class FakeClient:
    def __init__(self, init=Z, owner=Z, impl_init=Z, fail=False):
        self.init, self.owner, self.impl_init, self.fail = init, owner, impl_init, fail
    def block_number(self):
        if self.fail: raise OSError("rpc down")
        return 100
    def storage_at(self, a, slot):
        if self.fail: raise OSError("rpc down")
        if slot == P.EIP1967_IMPL: return IMPL
        return self.impl_init if a.endswith("11" * 20) else self.init
    def call(self, a, data):
        if self.fail: raise OSError("rpc down")
        return self.owner if data == P.SEL_OWNER else "0x"


def _facts(tmp_path, src):
    (tmp_path / "V.sol").write_text(src)
    return P.source_facts(tmp_path)


def test_uninitialized_proxy_is_lead(tmp_path):
    r = P.assess(FakeClient(), "0xabc", None, _facts(tmp_path, INIT_SRC))
    assert r["status"] == "lead" and "proxy-uninitialized" in r["kinds"]
    assert "impl-uninitialized-uups" in r["kinds"]


def test_initialized_proxy_with_disabled_impl_is_clear(tmp_path):
    r = P.assess(FakeClient(init="0x" + "0" * 63 + "1", owner="0x" + "0" * 24 + "22" * 20),
                 "0xabc", None, _facts(tmp_path, SAFE_SRC))
    assert r["status"] == "clear" and r["kinds"] == []


def test_rpc_failure_is_unknown_not_clear(tmp_path):
    r = P.assess(FakeClient(fail=True), "0xabc", None, _facts(tmp_path, INIT_SRC))
    assert r["status"] == "unknown"


def test_no_source_is_unknown():
    assert P.assess(FakeClient(), "0xabc", None, P.source_facts(None))["status"] == "unknown"


def test_sweep_records_and_bumps_priority(tmp_path):
    src = tmp_path / "src"; src.mkdir(); (src / "V.sol").write_text(INIT_SRC)
    c = sqlite3.connect(":memory:")
    c.execute("CREATE TABLE hunt_candidates(network TEXT, address TEXT, implementation TEXT, is_proxy INT,"
              " priority_score REAL, signals_json TEXT, last_scan_row INT)")
    c.execute("CREATE TABLE monitor_scans(id INTEGER PRIMARY KEY, cache_dir TEXT)")
    c.execute("INSERT INTO monitor_scans VALUES(1, ?)", (str(src),))
    c.execute("INSERT INTO hunt_candidates VALUES('ethereum','0xabc',NULL,1,10,'{}',1)")
    c.execute("INSERT INTO hunt_candidates VALUES('ethereum','0xdef',NULL,0,99,'{}',1)")
    out = P.sweep(c, FakeClient(), "ethereum", now=1000.0)
    assert out["checked"] == 1 and out["lead"] == 1
    assert c.execute("select priority_score from hunt_candidates where address='0xabc'").fetchone()[0] == 25
    # re-check suppressed within 24h
    assert P.sweep(c, FakeClient(), "ethereum", now=2000.0)["checked"] == 0
