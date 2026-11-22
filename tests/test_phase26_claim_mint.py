"""Phase 26: ERC-4626/7540 claim mint is not an unlimited owner mint."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from auditor.analysis.base import AnalysisContext  # noqa: E402
from auditor.analysis import honeypot, privileged_auth as pa  # noqa: E402

FIX = ROOT / "benchmarks" / "fixtures"
VAULT_SRC = ROOT / "monitor_cache/hunt/sources/ethereum/0x1b2cb79a4564206f53ba80b4d780f251b4ae6765"


def _run(mod, path: Path):
    ctx = AnalysisContext()
    ctx.source_files = sorted(path.rglob("*.sol")) if path.is_dir() else [path]
    return mod.analyze(ctx)


def _mint_hits(outcome):
    return [f for f in outcome.findings if f.affected_function == "mint"
            and ("unlimited-owner-mint" in (f.title or "").lower() or "unlimited owner mint" in (f.title or "").lower()
                 or "privileged-auth-weak" in (f.title or "") or "privileged-auth-unprotected" in (f.title or ""))]


class ClaimMintTests(unittest.TestCase):
    def test_open_owner_mint_still_flagged(self):
        hits = [f for f in _run(honeypot, FIX / "HONEY-005-vulnerable.sol").findings
                if f.affected_function == "mint" and "owner mint" in f.title.lower()]
        self.assertTrue(hits, "uncapped onlyOwner mint must still flag")

    def test_erc7540_claim_mint_fixture_not_flagged(self):
        self.assertEqual(_mint_hits(_run(honeypot, FIX / "HONEY-006-safe.sol")), [])
        self.assertEqual(_mint_hits(_run(pa, FIX / "HONEY-006-safe.sol")), [])

    @unittest.skipUnless(VAULT_SRC.exists(), "cached live source not present")
    def test_live_erc7540_vault_mint_not_flagged(self):
        self.assertEqual(_mint_hits(_run(honeypot, VAULT_SRC)), [])
        self.assertEqual(_mint_hits(_run(pa, VAULT_SRC)), [])


if __name__ == "__main__":
    unittest.main()


class CompoundPatternTests(unittest.TestCase):
    SRC = """
    pragma solidity ^0.8.0;
    contract CToken {
        address public admin; address payable public pendingAdmin; uint public accrualBlockNumber;
        function initialize(uint rate) public {
            require(msg.sender == admin, "only admin may initialize the market");
            require(accrualBlockNumber == 0, "once"); accrualBlockNumber = rate;
        }
        function _acceptAdmin() external returns (uint) {
            if (msg.sender != pendingAdmin || msg.sender == address(0)) { revert(); }
            admin = pendingAdmin; pendingAdmin = payable(address(0)); return 0;
        }
        function mintInternal(uint amount) internal { amount; }
    }
    contract CErc20 is CToken {
        address public underlying;
        function initialize(address u, uint rate) public {
            super.initialize(rate);
            underlying = u;
        }
        function mint(uint mintAmount) external returns (uint) { mintInternal(mintAmount); return 0; }
    }
    contract Open {
        address public admin;
        function initialize(address a) public { admin = a; }
    }
    """

    def test_compound_super_init_accept_admin_and_supply_mint(self):
        import tempfile
        td = Path(tempfile.mkdtemp()); f = td / "C.sol"; f.write_text(self.SRC)
        out = _run(pa, f)
        bad = [(x.affected_contract, x.affected_function) for x in out.findings
               if ("unprotected" in x.title or "weak" in x.title)
               and x.affected_contract in ("CToken", "CErc20")]
        self.assertEqual(bad, [])
        # control: a genuinely open initializer is still flagged
        self.assertTrue([x for x in out.findings if x.affected_contract == "Open"
                         and x.affected_function == "initialize" and "unprotected" in x.title])


class OrHasRoleGuardTests(unittest.TestCase):
    def test_require_count_or_hasrole_is_guard_and_open_still_flags(self):
        import tempfile
        src = """
        pragma solidity ^0.8.0;
        contract M {
            bytes32 public constant OPERATOR = keccak256("OPERATOR");
            mapping(bytes32 => uint) public fee; address public feeRecipient; uint public defaultFee;
            function getRoleMemberCount(bytes32) public view returns (uint) { return 1; }
            function hasRole(bytes32, address) public view returns (bool) { return false; }
            function setFeeRecipient(address r) external {
                require(getRoleMemberCount(OPERATOR) == 0 || hasRole(OPERATOR, msg.sender), "unauthorized");
                feeRecipient = r;
            }
            function setFeeRecipientOpen(address r) external { feeRecipient = r; }
        }"""
        f = Path(tempfile.mkdtemp()) / "M.sol"; f.write_text(src)
        out = _run(pa, f)
        bad = [x for x in out.findings if x.affected_function == "setFeeRecipient" and "unprotected" in x.title]
        self.assertEqual(bad, [])
        self.assertTrue([x for x in out.findings if x.affected_function == "setFeeRecipientOpen" and "unprotected" in x.title])


class InheritedDisableInitializersTests(unittest.TestCase):
    def test_base_constructor_disable_initializers_counts(self):
        import tempfile
        src = """
        pragma solidity ^0.8.0;
        abstract contract Initializable { modifier initializer() { _; } function _disableInitializers() internal {} }
        abstract contract AccessControlled is Initializable { constructor() { _disableInitializers(); } }
        contract Tranche is AccessControlled {
            address public owner;
            function initialize(address o) external initializer { owner = o; }
        }
        contract NoDisable is Initializable {
            address public owner;
            function initialize(address o) external initializer { owner = o; }
        }"""
        f = Path(tempfile.mkdtemp()) / "T.sol"; f.write_text(src)
        out = _run(pa, f)
        weak = lambda c: [x for x in out.findings if x.affected_contract == c and x.affected_function == "initialize"
                          and ("weak" in x.title or "unprotected" in x.title)]
        self.assertEqual(weak("Tranche"), [])
        self.assertTrue(weak("NoDisable"), "front-runnable initializer without disable must still flag")


class OwnBalanceWithdrawTests(unittest.TestCase):
    def test_own_balance_debit_is_pull_payment_but_drain_flags(self):
        safe = _run(pa, FIX / "PAUTH-011-own-balance-withdraw-safe.sol")
        vuln = _run(pa, FIX / "PAUTH-012-unprotected-pool-drain.sol")
        self.assertEqual([x for x in safe.findings if x.affected_function == "withdraw" and "unprotected" in x.title], [])
        self.assertTrue([x for x in vuln.findings if x.affected_function == "withdraw" and "unprotected" in x.title])

    def test_unchecked_unbounded_debit_still_flags(self):
        import tempfile
        src = """pragma solidity ^0.8.0;
        contract U { mapping(address=>uint) _balances;
          function withdraw(uint amount) external {
            unchecked { _balances[msg.sender] = _balances[msg.sender] - amount; }
            payable(msg.sender).transfer(amount);
          } }"""
        f = Path(tempfile.mkdtemp()) / "U.sol"; f.write_text(src)
        self.assertTrue([x for x in _run(pa, f).findings if x.affected_function == "withdraw" and "unprotected" in x.title])
