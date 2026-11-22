"""Phase 23 — any-token fork funding via storage slots / whale impersonation."""

from __future__ import annotations

import unittest
from unittest import mock

from auditor import simulate as sim


class DealHelpers(unittest.TestCase):
    def test_erc7201_base_matches_known_pattern(self):
        """OZ ERC20 ERC-7201 base ends with 0x00 (256-byte aligned)."""
        class FakeFork:
            def cast(self, args):
                # Mirror cast keccak for the two calls used by _erc7201_base
                if args[0] == "keccak" and args[1] == "openzeppelin.storage.ERC20":
                    return "0xb750591399365444a618527b69a54ce09476c8bde1ecff60f5aa1fe2b52605ff"
                if args[0] == "keccak" and args[1].startswith("0x"):
                    # Deterministic fake: return a value that after mask ends with 00
                    # Use the real precomputed result for this ns.
                    return "0x52c63247e1f47db19d5ce0460030c497f067ca4cebf71ba98eeadabe20baceff"
                raise AssertionError(args)

        base = sim._erc7201_base(FakeFork(), "openzeppelin.storage.ERC20")
        self.assertTrue(base.startswith("0x"))
        self.assertEqual(int(base, 16) & 0xff, 0)

    def test_find_balance_slot_hits_solidity_mapping(self):
        acct = sim.ANVIL_ACCT0
        token = "0x4c9edd5852cd905f086c759e8383e09bff1e68b3"
        probe = 10**24

        class FakeFork:
            def __init__(self):
                self.store = {}

            def cast(self, args):
                if args[0] == "index" and args[1] == "address":
                    # slot 2 → distinct idx
                    base = args[3]
                    if base == "2":
                        return "0x" + "ab" * 32
                    return "0x" + "00" * 31 + "01"
                if args[0] == "keccak":
                    return "0x" + "cd" * 32
                raise AssertionError(args)

            def rpc(self, method, params):
                if method == "eth_getStorageAt":
                    return self.store.get((params[0].lower(), params[1].lower()), "0x" + "0" * 64)
                if method == "anvil_setStorageAt":
                    self.store[(params[0].lower(), params[1].lower())] = params[2]
                    return True
                raise AssertionError(method)

            def set_storage(self, address, slot, value):
                self.rpc("anvil_setStorageAt", [address, slot, value])

            def call_int(self, to, data):
                # balanceOf reads storage at slot for acct when set to probe
                key = (to.lower(), ("0x" + "ab" * 32).lower())
                val = self.store.get(key)
                if val and int(val, 16) == probe:
                    return probe
                return 0

        hit = sim.find_balance_slot(FakeFork(), token, acct, probe_amount=probe, max_plain_slots=5)
        self.assertIsNotNone(hit)
        self.assertEqual(hit["kind"], "solidity-mapping")
        self.assertEqual(hit["base"], "2")

    def test_deal_erc20_weth_wrap_path(self):
        calls = []

        class FakeFork:
            def set_balance(self, a, w):
                calls.append(("bal", a, w))

            def impersonate(self, a):
                calls.append(("imp", a))

            def stop_impersonate(self, a):
                calls.append(("stop", a))

            def send(self, *a, **k):
                calls.append(("send", a, k))
                return "0x"

            def call_int(self, to, data):
                return 10**18

            def cast(self, args):
                return "0x0"

            def rpc(self, *a, **k):
                return "0x0"

            def set_storage(self, *a, **k):
                pass

        r = sim.deal_erc20(FakeFork(), sim.WETH, sim.ANVIL_ACCT0, 10**18)
        self.assertTrue(r["ok"])
        self.assertEqual(r["method"], "weth-wrap")


class WhaleDepositMonotonic(unittest.TestCase):
    def _run_case(self, result: str, max_redeem: int = 10**18):
        state = {"phase": "before"}

        class FakeFork:
            def set_balance(self, *a, **k):
                pass

            def impersonate(self, *a):
                pass

            def stop_impersonate(self, *a):
                pass

            def set_storage(self, *a, **k):
                pass

            def send(self, *a, **k):
                # advance phase on vault deposit/redeem
                data = a[2] if len(a) > 2 else ""
                if data.startswith(sim.SEL["deposit(uint256,address)"]):
                    state["phase"] = "mid"
                if data.startswith(sim.SEL["redeem(uint256,address,address)"]):
                    state["phase"] = "after"
                return "0x"

            def call_int(self, to, data):
                sel = data[:10]
                if sel == sim.SEL["balanceOf(address)"]:
                    if to.lower() == "0x4c9edd5852cd905f086c759e8383e09bff1e68b3":
                        end_balance = (10**20 + 10**18 if result == "gain"
                                       else 10**20 - 10**18)
                        return {"before": 10**20, "mid": 10**20 - 10**18,
                                "after": end_balance}[state["phase"]]
                    # vault shares
                    return {"before": 0, "mid": 10**18, "after": 0}[state["phase"]]
                if sel == sim.SEL["maxRedeem(address)"]:
                    return max_redeem
                if sel == sim.SEL["maxWithdraw(address)"]:
                    return 10**18
                if sel == sim.SEL["previewRedeem(uint256)"]:
                    return 10**18
                if sel == sim.SEL["totalSupply()"]:
                    initial = 10**24
                    if state["phase"] == "mid":
                        return initial + 10**18
                    if state["phase"] == "after" and result != "burn":
                        return initial + 10**18
                    return initial
                if sel == sim.SEL["convertToAssets(uint256)"]:
                    return 10**18
                return 0

            def cast(self, args):
                if args[0] == "index":
                    return "0x" + "ab" * 32
                if args[0] == "keccak":
                    return "0x52c63247e1f47db19d5ce0460030c497f067ca4cebf71ba98eeadabe20baceff"
                return "0x0"

            def rpc(self, method, params):
                if method == "eth_getStorageAt":
                    return "0x" + "0" * 64
                if method == "anvil_setStorageAt":
                    return True
                if method == "eth_getLogs":
                    return []
                return "0x0"

        # Patch find_balance_slot to succeed immediately
        with mock.patch.object(sim, "find_balance_slot",
                               return_value={"kind": "solidity-mapping", "base": "2",
                                             "slot": "0x" + "ab" * 32, "verified_balance": 10**24}):
            with mock.patch.object(sim, "deal_erc20",
                                   return_value={"ok": True, "method": "setStorageAt",
                                                 "detail": "mock", "slot_info": {}}):
                out = sim._whale_deposit_withdraw(
                    FakeFork(),
                    vault="0xe24a3dc889621612422a64e6388927901608b91d",
                    asset="0x4c9edd5852cd905f086c759e8383e09bff1e68b3",
                    info={"asset_decimals": 18, "decimals": 18, "total_assets": 10**24},
                    holder_value_usd=1_000_000,
                )
        return out

    def test_conservation_fail_when_user_gains(self):
        """deposit/redeem that returns extra assets → fail."""
        statuses = {r.name: r.status for r in self._run_case("gain")}
        self.assertEqual(statuses.get("deposit-withdraw-conservation"), "fail")
        self.assertEqual(statuses.get("deposit-redeem-round-trip"), "fail")

    def test_cooldown_share_transfer_is_review_not_loss(self):
        results = self._run_case("cooldown")
        by_name = {r.name: r for r in results}
        self.assertEqual(by_name["deposit-withdraw-conservation"].status, "review")
        self.assertEqual(by_name["deposit-redeem-round-trip"].status, "review")
        self.assertEqual(by_name["deposit-withdraw-conservation"].evidence["withdrawal_state"],
                         "shares_moved_pending_or_locked")

    def test_burned_shares_without_payout_remains_a_failure_lead(self):
        results = self._run_case("burn")
        by_name = {r.name: r for r in results}
        self.assertEqual(by_name["deposit-withdraw-conservation"].status, "fail")
        self.assertEqual(by_name["deposit-withdraw-conservation"].evidence["withdrawal_state"],
                         "shares_burned_without_payout")

    def test_zero_max_redeem_is_review_not_loss(self):
        results = self._run_case("cooldown", max_redeem=0)
        self.assertEqual(results[-1].status, "review")
        self.assertEqual(results[-1].evidence["withdrawal_state"], "not_immediately_redeemable")


if __name__ == "__main__":
    unittest.main()
