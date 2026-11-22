"""Phase 25 — privileged-function authorization analyzer."""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from auditor.analysis.base import AnalysisContext  # noqa: E402
from auditor.analysis import privileged_auth as pa  # noqa: E402
from auditor.benchmark import validate_manifest, load_manifest  # noqa: E402


FIXTURES = PROJECT_ROOT / "benchmarks" / "fixtures"


def _analyze_file(path: Path):
    ctx = AnalysisContext()
    ctx.source_files = [path]
    return pa.analyze(ctx)


def _by_fn(outcome):
    return {(f.affected_contract, f.affected_function, json.loads(f.reasoning).get("status")): f
            for f in outcome.findings}


class PrivilegedAuthFixtures(unittest.TestCase):
    def test_unprotected_set_owner(self):
        out = _analyze_file(FIXTURES / "PAUTH-001-unprotected-setOwner.sol")
        hits = [f for f in out.findings if f.affected_function == "setOwner"]
        self.assertTrue(hits, out.notes)
        meta = json.loads(hits[0].reasoning)
        self.assertEqual(meta["status"], "UNPROTECTED")
        self.assertEqual(meta["privileged_category"], "ownership")
        self.assertIn("privileged-auth-unprotected", hits[0].title)
        self.assertIn("Missing check", hits[0].description)
        self.assertIn("Fix:", hits[0].description)

    def test_unprotected_upgrade_to(self):
        out = _analyze_file(FIXTURES / "PAUTH-002-unprotected-upgradeTo.sol")
        hits = [f for f in out.findings if f.affected_function == "upgradeTo"]
        self.assertTrue(hits)
        self.assertEqual(json.loads(hits[0].reasoning)["status"], "UNPROTECTED")
        self.assertEqual(json.loads(hits[0].reasoning)["privileged_category"], "upgrade")

    def test_unprotected_withdraw(self):
        out = _analyze_file(FIXTURES / "PAUTH-003-unprotected-withdraw.sol")
        hits = [f for f in out.findings if f.affected_function == "withdraw"]
        self.assertTrue(hits)
        meta = json.loads(hits[0].reasoning)
        self.assertEqual(meta["status"], "UNPROTECTED")
        self.assertEqual(meta["privileged_category"], "withdraw")
        self.assertEqual(hits[0].severity.value, "CRITICAL")

    def test_tx_origin_weak(self):
        out = _analyze_file(FIXTURES / "PAUTH-004-tx-origin-auth.sol")
        hits = [f for f in out.findings if f.affected_function == "setOwner"]
        self.assertTrue(hits)
        meta = json.loads(hits[0].reasoning)
        self.assertEqual(meta["status"], "WEAK")
        self.assertIn("tx.origin", meta.get("weak_reason") or "")
        self.assertIn("privileged-auth-weak", hits[0].title)

    def test_unprotected_initialize(self):
        out = _analyze_file(FIXTURES / "PAUTH-005-unprotected-initialize.sol")
        hits = [f for f in out.findings if f.affected_function == "initialize"]
        self.assertTrue(hits)
        self.assertEqual(json.loads(hits[0].reasoning)["status"], "UNPROTECTED")


    def test_oz_initializer_with_disable_is_protected(self):
        """UUPS/OZ pattern: initialize+initializer+_disableInitializers → not HIGH WEAK."""
        import tempfile
        from auditor.model import Severity
        sol = """
        pragma solidity ^0.8.0;
        contract V {
            address public owner;
            constructor() { _disableInitializers(); }
            function _disableInitializers() internal {}
            modifier initializer() { _; }
            function initialize(address o) external initializer { owner = o; }
            function withdraw() external { require(msg.sender == owner); payable(msg.sender).transfer(address(this).balance); }
        }
        """
        td = tempfile.mkdtemp()
        f = Path(td) / "V.sol"
        f.write_text(sol)
        out = _analyze_file(f)
        weak = [x for x in out.findings if x.affected_function == "initialize" and "weak" in x.title]
        prot = [x for x in out.findings if x.affected_function == "initialize" and "protected" in x.title]
        self.assertEqual(weak, [])
        self.assertTrue(prot)
        self.assertEqual(prot[0].severity, Severity.INFORMATIONAL)


    def test_ownable_protected_no_unprotected(self):
        out = _analyze_file(FIXTURES / "PAUTH-006-ownable-protected.sol")
        bad = [
            f for f in out.findings
            if f.affected_function == "setOwner"
            and json.loads(f.reasoning)["status"] in ("UNPROTECTED", "WEAK")
        ]
        self.assertEqual(bad, [])
        prot = [
            f for f in out.findings
            if f.affected_function == "setOwner"
            and json.loads(f.reasoning)["status"] == "PROTECTED"
        ]
        self.assertTrue(prot)
        self.assertEqual(prot[0].severity.value, "INFORMATIONAL")

    def test_accesscontrol_protected_mint(self):
        out = _analyze_file(FIXTURES / "PAUTH-007-accesscontrol-protected.sol")
        bad = [
            f for f in out.findings
            if f.affected_function == "mint"
            and json.loads(f.reasoning)["status"] in ("UNPROTECTED", "WEAK")
        ]
        self.assertEqual(bad, [])
        prot = [
            f for f in out.findings
            if f.affected_function == "mint"
            and json.loads(f.reasoning)["status"] == "PROTECTED"
        ]
        self.assertTrue(prot)

    def test_safe_controlled_tn_channel(self):
        out = _analyze_file(FIXTURES / "PAUTH-008-safe-controlled.sol")
        bad = [
            f for f in out.findings
            if f.affected_function == "withdraw"
            and json.loads(f.reasoning)["status"] in ("UNPROTECTED", "WEAK")
        ]
        self.assertEqual(bad, [])

    def test_controller_enrichment_from_options(self):
        path = FIXTURES / "PAUTH-008-safe-controlled.sol"
        ctx = AnalysisContext()
        ctx.source_files = [path]
        ctx.address = "0x" + "ab" * 20
        ctx.options = {"trust_owner_type": "Safe multisig (m-of-n)"}
        out = pa.analyze(ctx)
        prot = [
            f for f in out.findings
            if json.loads(f.reasoning)["status"] == "PROTECTED"
        ]
        self.assertTrue(prot)
        meta = json.loads(prot[0].reasoning)
        self.assertIn("Safe", meta.get("controller") or "")

    def test_manifest_accepts_pauth(self):
        m = load_manifest(PROJECT_ROOT / "benchmarks" / "manifest.json")
        fixtures = validate_manifest(m)
        ids = {f["fixture_id"] for f in fixtures}
        for i in range(1, 9):
            self.assertIn(f"PAUTH-00{i}", ids)


class PrivilegedAuthHelpers(unittest.TestCase):
    def test_check_after_effect(self):
        body = "owner = newOwner;\nrequire(msg.sender == owner);"
        self.assertTrue(pa._check_after_effect(body))
        body2 = "require(msg.sender == owner);\nowner = newOwner;"
        self.assertFalse(pa._check_after_effect(body2))


if __name__ == "__main__":
    unittest.main()


class PrivilegedAuthFpTriage(unittest.TestCase):
    """General FP patterns found in the Phase 25 rescan verification."""


    def test_boolean_owner_or_authority_guard_is_recognized(self):
        from auditor.analysis.sol_parse import Function, privileged_guard

        fn = Function(
            name="setAuthority",
            header="function setAuthority(address a) public",
            params="address a",
            body="""
                bool ok = msg.sender == $.owner ||
                    (address(auth) != address(0) &&
                     auth.canCall(msg.sender, address(this), msg.sig));
                if (!ok) {
                    revert Unauthorized();
                }
                $.authority = a;
            """,
            body_start=0,
            body_end=0,
            line=1,
        )
        self.assertEqual(
            privileged_guard(fn, {}),
            "inline boolean authorization check",
        )

    def test_arbitrary_bool_and_low_level_call_are_not_auth_guards(self):
        from auditor.analysis.sol_parse import Function, privileged_guard

        cases = [
            """
                bool ok = msg.sender == attacker;
                if (!ok) { revert Unauthorized(); }
            """,
            """
                (bool ok,) = target.call(data);
                if (!ok) { revert Unauthorized(); }
            """,
        ]
        for body in cases:
            fn = Function(
                name="setAuthority",
                header="function setAuthority(address a) public",
                params="address a",
                body=body,
                body_start=0,
                body_end=0,
                line=1,
            )
            with self.subTest(body=body):
                self.assertIsNone(privileged_guard(fn, {}))

    def test_boolean_owner_or_authority_guard_is_recognized(self):
        from auditor.analysis.sol_parse import Function, privileged_guard

        fn = Function(
            name="setAuthority",
            header="function setAuthority(address a) public",
            params="address a",
            body="""
                bool ok = msg.sender == $.owner ||
                    (address(auth) != address(0) &&
                     auth.canCall(msg.sender, address(this), msg.sig));
                if (!ok) {
                    revert Unauthorized();
                }
                $.authority = a;
            """,
            body_start=0,
            body_end=0,
            line=1,
        )
        self.assertEqual(
            privileged_guard(fn, {}),
            "inline boolean authorization check",
        )

    def test_arbitrary_bool_and_low_level_call_are_not_auth_guards(self):
        from auditor.analysis.sol_parse import Function, privileged_guard

        cases = [
            """
                bool ok = msg.sender == attacker;
                if (!ok) { revert Unauthorized(); }
            """,
            """
                (bool ok,) = target.call(data);
                if (!ok) { revert Unauthorized(); }
            """,
        ]
        for body in cases:
            fn = Function(
                name="setAuthority",
                header="function setAuthority(address a) public",
                params="address a",
                body=body,
                body_start=0,
                body_end=0,
                line=1,
            )
            with self.subTest(body=body):
                self.assertIsNone(privileged_guard(fn, {}))

    def test_boolean_owner_or_authority_guard_is_recognized(self):
        from auditor.analysis.sol_parse import Function, privileged_guard

        fn = Function(
            name="setAuthority",
            header="function setAuthority(address a) public",
            params="address a",
            body="""
                bool ok = msg.sender == $.owner ||
                    (address(auth) != address(0) &&
                     auth.canCall(msg.sender, address(this), msg.sig));
                if (!ok) {
                    revert Unauthorized();
                }
                $.authority = a;
            """,
            body_start=0,
            body_end=0,
            line=1,
        )
        self.assertEqual(
            privileged_guard(fn, {}),
            "inline boolean authorization check",
        )

    def test_arbitrary_bool_and_low_level_call_are_not_auth_guards(self):
        from auditor.analysis.sol_parse import Function, privileged_guard

        cases = [
            """
                bool ok = msg.sender == attacker;
                if (!ok) { revert Unauthorized(); }
            """,
            """
                (bool ok,) = target.call(data);
                if (!ok) { revert Unauthorized(); }
            """,
        ]
        for body in cases:
            fn = Function(
                name="setAuthority",
                header="function setAuthority(address a) public",
                params="address a",
                body=body,
                body_start=0,
                body_end=0,
                line=1,
            )
            with self.subTest(body=body):
                self.assertIsNone(privileged_guard(fn, {}))

    def test_boolean_owner_or_authority_guard_is_recognized(self):
        from auditor.analysis.sol_parse import Function, privileged_guard

        fn = Function(
            name="setAuthority",
            header="function setAuthority(address a) public",
            params="address a",
            body="""
                bool ok = msg.sender == $.owner ||
                    (address(auth) != address(0) &&
                     auth.canCall(msg.sender, address(this), msg.sig));
                if (!ok) {
                    revert Unauthorized();
                }
                $.authority = a;
            """,
            body_start=0,
            body_end=0,
            line=1,
        )
        self.assertEqual(
            privileged_guard(fn, {}),
            "inline boolean authorization check",
        )

    def test_arbitrary_bool_and_low_level_call_are_not_auth_guards(self):
        from auditor.analysis.sol_parse import Function, privileged_guard

        cases = [
            """
                bool ok = msg.sender == attacker;
                if (!ok) { revert Unauthorized(); }
            """,
            """
                (bool ok,) = target.call(data);
                if (!ok) { revert Unauthorized(); }
            """,
        ]
        for body in cases:
            fn = Function(
                name="setAuthority",
                header="function setAuthority(address a) public",
                params="address a",
                body=body,
                body_start=0,
                body_end=0,
                line=1,
            )
            with self.subTest(body=body):
                self.assertIsNone(privileged_guard(fn, {}))

    def test_boolean_owner_or_authority_guard_is_recognized(self):
        from auditor.analysis.sol_parse import Function, privileged_guard

        fn = Function(
            name="setAuthority",
            header="function setAuthority(address a) public",
            params="address a",
            body="""
                bool ok = msg.sender == $.owner ||
                    (address(auth) != address(0) &&
                     auth.canCall(msg.sender, address(this), msg.sig));
                if (!ok) {
                    revert Unauthorized();
                }
                $.authority = a;
            """,
            body_start=0,
            body_end=0,
            line=1,
        )
        self.assertEqual(
            privileged_guard(fn, {}),
            "inline boolean authorization check",
        )

    def test_arbitrary_bool_and_low_level_call_are_not_auth_guards(self):
        from auditor.analysis.sol_parse import Function, privileged_guard

        cases = [
            """
                bool ok = msg.sender == attacker;
                if (!ok) { revert Unauthorized(); }
            """,
            """
                (bool ok,) = target.call(data);
                if (!ok) { revert Unauthorized(); }
            """,
        ]
        for body in cases:
            fn = Function(
                name="setAuthority",
                header="function setAuthority(address a) public",
                params="address a",
                body=body,
                body_start=0,
                body_end=0,
                line=1,
            )
            with self.subTest(body=body):
                self.assertIsNone(privileged_guard(fn, {}))

    def test_accept_ownership_newowner_is_protected(self):
        import tempfile
        sol = """
        pragma solidity ^0.5.8;
        contract Owned {
            address public owner;
            address public newOwner;
            constructor() public { owner = msg.sender; }
            function transferOwner(address n) public { require(msg.sender==owner); owner=n; }
            function changeOwner(address n) public { require(msg.sender==owner); newOwner=n; }
            function acceptOwnership() public { if (msg.sender == newOwner) { owner = newOwner; } }
            function withdraw() public { require(msg.sender==owner); msg.sender.transfer(address(this).balance); }
            function() external payable {}
        }
        """
        td = tempfile.mkdtemp()
        f = Path(td) / "O.sol"
        f.write_text(sol)
        out = _analyze_file(f)
        hits = [x for x in out.findings if x.affected_function == "acceptOwnership"]
        self.assertTrue(hits)
        self.assertTrue(all("unprotected" not in x.title for x in hits))
        self.assertTrue(any("protected" in x.title for x in hits))

    def _tmp(self, sol, name="T.sol"):
        import tempfile
        td = tempfile.mkdtemp(); f = Path(td) / name; f.write_text(sol); return _analyze_file(f)

    def test_safe_self_authorized_removeOwner_protected(self):
        out = self._tmp("""
        pragma solidity ^0.8.0;
        contract SelfAuthorized {
            function requireSelfCall() private view { require(msg.sender == address(this), "GS031"); }
            modifier authorized() { requireSelfCall(); _; }
        }
        contract OwnerManager is SelfAuthorized {
            mapping(address => address) internal owners; uint256 ownerCount; address public owner;
            function removeOwner(address prevOwner, address o, uint256 t) public authorized {
                owners[prevOwner] = owners[o]; owners[o] = address(0); ownerCount--;
            }
        }""")
        bad = [x for x in out.findings if x.affected_function == "removeOwner" and ("unprotected" in x.title or "weak" in x.title)]
        self.assertEqual(bad, [])

    def test_sender_scoped_setter_not_unprotected(self):
        out = self._tmp("""
        pragma solidity ^0.8.0;
        contract V {
            struct D { bool on; uint16 fee; address cb; }
            mapping(address => D) public boostDelegation; address public owner;
            function setBoostDelegationParams(bool on, uint256 feePct, address callback) external returns (bool) {
                if (on) { require(feePct <= 10000); boostDelegation[msg.sender] = D(true, uint16(feePct), callback); }
                else { delete boostDelegation[msg.sender]; }
                return true;
            }
            function setFeeReceiver(address r) external { owner = r; }
        }""")
        bad = [x for x in out.findings if x.affected_function == "setBoostDelegationParams" and ("unprotected" in x.title or "weak" in x.title)]
        self.assertEqual(bad, [])
        # control: a genuinely open global setter is still caught
        ctl = [x for x in out.findings if x.affected_function == "setFeeReceiver" and "unprotected" in x.title]
        self.assertTrue(ctl)

    def test_compound_dead_if_false_not_check_after_effect(self):
        out = self._tmp("""
        pragma solidity ^0.8.0;
        contract D {
            address public admin; address public implementation;
            function _becomeImplementation(bytes memory data) public {
                data;
                if (false) { implementation = address(0); }
                require(msg.sender == admin, "only the admin may call _becomeImplementation");
            }
        }""")
        bad = [x for x in out.findings if x.affected_function == "_becomeImplementation" and "weak" in x.title.lower()]
        self.assertEqual(bad, [])

    def test_library_storage_self_not_unprotected_entry(self):
        import tempfile
        sol = """
        pragma solidity ^0.5.8;
        library Lib {
            struct Data { mapping(bytes32 => uint) m; }
            function addUserTx(Data storage self, uint fee) public {
                self.m[bytes32(0)] = fee;
            }
        }
        contract C {
            using Lib for Lib.Data;
            Lib.Data d;
            address public owner;
            constructor() public { owner = msg.sender; }
            function withdraw() public { require(msg.sender==owner); msg.sender.transfer(address(this).balance); }
            function() external payable {}
        }
        """
        td = tempfile.mkdtemp()
        f = Path(td) / "L.sol"
        f.write_text(sol)
        out = _analyze_file(f)
        unp = [x for x in out.findings if "unprotected" in x.title and x.affected_function == "addUserTx"]
        self.assertEqual(unp, [])


    def _run(self, source: str):
        d = Path(tempfile.mkdtemp())
        f = d / "T.sol"
        f.write_text(source)
        ctx = AnalysisContext()
        ctx.source_files = [f]
        return pa.analyze(ctx)

    def test_validate_caller_lockbox_protected(self):
        src = """pragma solidity ^0.5.8;
contract Auth {
  mapping(address => bool) s_authorizedCallers;
  function _validateCaller() internal view {
    require(s_authorizedCallers[msg.sender], "no");
  }
  function _validateDepositWithdraw(address token, uint256 amount) internal view {
    require(amount > 0);
    _validateCaller();
  }
}
contract ERC20LockBox is Auth {
  function withdraw(address token, uint256 amount, address recipient) external {
    _validateDepositWithdraw(token, amount);
    uint256 balance = IERC20(token).balanceOf(address(this));
    require(amount <= balance);
  }
}
interface IERC20 { function balanceOf(address) external view returns (uint256); }
"""
        out = self._run(src)
        hits = [f for f in out.findings if f.affected_function == "withdraw"]
        self.assertTrue(hits)
        for f in hits:
            meta = json.loads(f.reasoning)
            self.assertEqual(meta["status"], "PROTECTED", meta)

    def test_pull_payment_withdraw_not_flagged_unprotected(self):
        src = """pragma solidity ^0.5.8;
contract Chronos {
  mapping(address => uint256) public credit;
  modifier guard() { _; }
  function withdraw() external guard {
    uint256 amt = credit[msg.sender];
    require(amt > 0);
    credit[msg.sender] = 0;
    msg.sender.transfer(amt);
  }
}
"""
        out = self._run(src)
        bad = [
            f for f in out.findings
            if f.affected_function == "withdraw"
            and json.loads(f.reasoning)["status"] in ("UNPROTECTED", "WEAK")
            and json.loads(f.reasoning)["privileged_category"] == "withdraw"
        ]
        self.assertEqual(bad, [])

    def test_collect_fees_to_fee_collector_not_theft(self):
        src = """pragma solidity ^0.5.8;
interface IERC20 { function transfer(address to, uint256 amt) external returns (bool); }
contract AbstractARM {
  address public feeCollector;
  IERC20 public liquidityAsset;
  function collectFees() public returns (uint256 fees) {
    fees = 1;
    if (fees == 0) return 0;
    liquidityAsset.transfer(feeCollector, fees);
  }
}
"""
        out = self._run(src)
        bad = [
            f for f in out.findings
            if f.affected_function == "collectFees"
            and json.loads(f.reasoning)["status"] in ("UNPROTECTED", "WEAK")
            and json.loads(f.reasoning)["privileged_category"] == "withdraw"
        ]
        self.assertEqual(bad, [])
