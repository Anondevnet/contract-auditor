"""Regression: Compound CErc20Delegator proxy-forwarder shapes are not access-control exposure."""
from auditor.analysis.sol_parse import (contracts_in, all_modifiers,
                                        delegatecall_target_admin_fixed, is_proxy_forwarder)

SAFE = """
pragma solidity ^0.5.8;
contract Store { address public implementation; address public admin; }
contract Delegator is Store {
    constructor(address i) public { admin = msg.sender; implementation = i; }
    function _setImplementation(address i) public {
        require(msg.sender == admin, "only admin");
        implementation = i;
        delegateTo(implementation, abi.encodeWithSignature("_become()"));
    }
    function mint(uint a) external returns (uint) { a; delegateAndReturn(); }
    function delegateTo(address callee, bytes memory data) internal returns (bytes memory) {
        (bool ok, bytes memory r) = callee.delegatecall(data); require(ok); return r;
    }
    function delegateToImplementation(bytes memory data) public returns (bytes memory) {
        return delegateTo(implementation, data);
    }
    function delegateAndReturn() private returns (bytes memory) {
        (bool ok, ) = implementation.delegatecall(msg.data); ok;
    }
}
"""

UNSAFE_PUBLIC = SAFE.replace(
    "function delegateTo(address callee, bytes memory data) internal",
    "function delegateTo(address callee, bytes memory data) public")
UNSAFE_SETTER = SAFE.replace('require(msg.sender == admin, "only admin");', "")
UNSAFE_CALLER = SAFE + """
contract Bad is Store {
    function run(address t, bytes memory d) public { go(t, d); }
    function go(address t, bytes memory d) internal { (bool ok,) = t.delegatecall(d); ok; }
}
"""
REAL_MINT = SAFE.replace("function mint(uint a) external returns (uint) { a; delegateAndReturn(); }",
                         "mapping(address=>uint) bal; function mint(uint a) external returns (uint) { bal[msg.sender] += a; delegateAndReturn(); }")


def _get(src, cname, fname):
    cs = contracts_in(src)
    c = [x for x in cs if x.name == cname][0]
    return c, [f for f in c.functions if f.name == fname][0], all_modifiers(cs), cs


def test_fixed_target_private_and_internal_are_benign():
    for fname in ("delegateAndReturn", "delegateTo"):
        c, fn, m, u = _get(SAFE, "Delegator", fname)
        assert delegatecall_target_admin_fixed(c, fn, m, u)


def test_public_param_target_stays_flagged():
    c, fn, m, u = _get(UNSAFE_PUBLIC, "Delegator", "delegateTo")
    assert delegatecall_target_admin_fixed(c, fn, m, u) is None


def test_unguarded_implementation_setter_stays_flagged():
    c, fn, m, u = _get(UNSAFE_SETTER, "Delegator", "delegateAndReturn")
    assert delegatecall_target_admin_fixed(c, fn, m, u) is None


def test_user_controlled_caller_arg_stays_flagged():
    c, fn, m, u = _get(UNSAFE_CALLER, "Bad", "go")
    assert delegatecall_target_admin_fixed(c, fn, m, u) is None


def test_mint_forwarder_not_admin_mint_but_real_mint_is():
    c, fn, _, _ = _get(SAFE, "Delegator", "mint")
    assert is_proxy_forwarder(fn, c)
    c, fn, _, _ = _get(REAL_MINT, "Delegator", "mint")
    assert not is_proxy_forwarder(fn, c)


LOCKED = """
pragma solidity ^0.5.8;
contract T {
    bool _notEntered = true; mapping(address=>uint) bal;
    modifier nonReentrant() { require(_notEntered, "re"); _notEntered = false; _; _notEntered = true; }
    function redeem(uint a) external nonReentrant { redeemFresh(msg.sender, a); }
    function redeemFresh(address payable r, uint a) internal { bal[r] -= a; r.transfer(a); }
}
"""
LEAKY = LOCKED.replace("}\n}", "}\n    function redeemNoLock(uint a) external { redeemFresh(msg.sender, a); }\n}")
FAKE_LOCK = LOCKED.replace('_notEntered = false; _; _notEntered = true;', '_;')


def test_lock_covered_internal():
    from auditor.analysis.sol_parse import lock_covered
    assert lock_covered(contracts_in(LOCKED), "redeemFresh") == "nonReentrant"


def test_unlocked_entry_point_not_covered():
    from auditor.analysis.sol_parse import lock_covered
    assert lock_covered(contracts_in(LEAKY), "redeemFresh") is None


def test_modifier_named_nonreentrant_without_mutex_not_covered():
    from auditor.analysis.sol_parse import lock_covered
    assert lock_covered(contracts_in(FAKE_LOCK), "redeemFresh") is None


def test_admin_guarded_helper():
    from auditor.analysis.sol_parse import admin_guarded
    cs = contracts_in(SAFE)
    assert admin_guarded(cs, "Delegator", "_setImplementation")
    assert admin_guarded(contracts_in(UNSAFE_SETTER), "Delegator", "_setImplementation") is None
    assert admin_guarded(cs, "Delegator", "mint") is None


def test_balance_require_is_not_an_admin_guard():
    from auditor.analysis.sol_parse import INLINE_GUARD_RE as R
    assert R.search("require(balances[msg.sender] >= amount);") is None
    assert R.search("require(whitelist[msg.sender]);")
    assert R.search('require(isAdmin[msg.sender], "no");')
