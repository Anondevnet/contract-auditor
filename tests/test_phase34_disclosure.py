from auditor import disclosure as D

GOOD = {"kind": "dynamically_reproduced", "fork_block": 26228161, "attacker_is_outsider": True,
        "outsider_take_usd": 5000.0, "poc_path": str(D.POC_ROOT / "x" / "Poc.t.sol")}


def test_gate_requires_dynamic_and_1k():
    assert D.confirmation_gate(GOOD)[0]
    assert not D.confirmation_gate(dict(GOOD, kind="statically_supported"))[0]
    assert not D.confirmation_gate(dict(GOOD, kind="ai_majority_suspected"))[0]
    assert not D.confirmation_gate(dict(GOOD, outsider_take_usd=999))[0]
    assert not D.confirmation_gate(dict(GOOD, outsider_take_usd=None))[0]
    assert not D.confirmation_gate(dict(GOOD, attacker_is_outsider=False))[0]
    assert not D.confirmation_gate(dict(GOOD, fork_block=None))[0]
    assert not D.confirmation_gate(dict(GOOD, poc_path="/tmp/Poc.t.sol"))[0]


def test_package_written_privately_and_contacts_found(tmp_path):
    src = "/// @custom:security-contact security@example.org\ncontract X {}"
    m = D.build_package({"address": "0xAbC", "title": "t"}, GOOD, src, out_dir=tmp_path)
    assert m["created"] and not m["contacted"] and m["contacts"][0]["value"] == "security@example.org"
    text = open(m["path"]).read()
    assert "PRIVATE" in text and "NOT contacted" in text and "0x" in text


def test_package_refused_without_gate(tmp_path):
    m = D.build_package({"address": "0x1"}, dict(GOOD, outsider_take_usd=10), out_dir=tmp_path)
    assert m == {"created": False, "reason": m["reason"], "confirmed_exploitable": 0}
    assert list(tmp_path.iterdir()) == []
