"""Batch-2 AMM / reward invariant helpers (pure / fake-fork)."""
from __future__ import annotations
import unittest
from unittest import mock

from auditor import simulate as sim


class AmmDetect(unittest.TestCase):
    def test_skip_when_not_pair(self):
        class F:
            def call_addr(self, to, data):
                return None
            def call_int(self, *a, **k):
                return None
            def call(self, *a, **k):
                return "0x"
        r = sim.check_amm_invariants(F(), "0x" + "ab" * 20)
        self.assertEqual(r[0].name, "amm-detect")
        self.assertEqual(r[0].status, "skip")

    def test_reserves_fail_when_bal_low(self):
        class F:
            def call_addr(self, to, data):
                if data.startswith(sim.SEL["token0()"]):
                    return "0x" + "11" * 20
                if data.startswith(sim.SEL["token1()"]):
                    return "0x" + "22" * 20
                return None
            def call(self, to, data):
                if data.startswith(sim.SEL["getReserves()"]):
                    return "0x" + format(1000, "064x") + format(2000, "064x") + format(0, "064x")
                return "0x" + "0" * 64
            def call_int(self, to, data):
                return 10
        with mock.patch.object(sim, "deal_erc20",
                               return_value={"ok": False, "detail": "x", "method": None}):
            r = sim.check_amm_invariants(F(), "0x" + "ab" * 20, holder_value_usd=1e6)
        names = {x.name: x for x in r}
        self.assertEqual(names["amm-reserves-vs-balance"].status, "fail")


class RewardDetect(unittest.TestCase):
    def test_skip_without_earned(self):
        class F:
            def call_int(self, to, data):
                return None
        r = sim.check_reward_invariants(F(), "0x" + "cd" * 20)
        self.assertEqual(r[0].status, "skip")


if __name__ == "__main__":
    unittest.main()
