"""Phase 24 — pool discovery (adaptive logs) + RPC URL redaction."""

from __future__ import annotations

import unittest
from unittest import mock

from auditor.monitor import _redact, _register_secret, redact_rpc_url
from auditor.analysis.slither_runner import redact as slither_redact
from auditor.pool_discovery import (
    PoolDiscovery,
    measure_major_holdings,
    parse_pool_from_log,
    next_chunk_size,
    is_range_error,
    is_rate_error,
    PAIR_CREATED,
    POOL_CREATED_V3,
    MIN_CHUNK,
)


class RedactRpcTests(unittest.TestCase):
    def test_alchemy_v2_path_masked(self):
        url = "https://eth-mainnet.g.alchemy.com/v2/AbCdEfGhIjKlMnOpQrStUvWx"
        out = _redact(url)
        self.assertIn("/v2/***", out)
        self.assertNotIn("AbCdEfGhIjKlMnOpQrStUvWx", out)

    def test_register_secret_masks_full_url_and_key(self):
        key = "SuperSecretAlchemyKey999"
        url = f"https://eth-mainnet.g.alchemy.com/v2/{key}"
        _register_secret(url)
        blob = f"fork failed contacting {url} key={key}"
        out = _redact(blob)
        self.assertNotIn(key, out)
        self.assertIn("***", out)

    def test_slither_redact_also_masks_v2(self):
        url = "https://eth-mainnet.g.alchemy.com/v2/ZzYyXxWwVvUuTtSsRrQqPpOo"
        out = slither_redact(f"error from {url}")
        self.assertNotIn("ZzYyXxWwVvUuTtSsRrQqPpOo", out)
        self.assertIn("/v2/***", out)

    def test_query_apikey_masked(self):
        out = _redact("https://example.com/rpc?apikey=deadbeefcafebabe0123456789abcdef")
        self.assertNotIn("deadbeefcafebabe0123456789abcdef", out)

    def test_redact_rpc_url_helper(self):
        self.assertEqual(
            redact_rpc_url("https://eth-mainnet.g.alchemy.com/v2/abc12345secret"),
            "https://eth-mainnet.g.alchemy.com/v2/***",
        )


class ParseLogTests(unittest.TestCase):
    def test_v2_pair_from_data(self):
        pair = "0x1111111111111111111111111111111111111111"
        data = "0x" + "0" * 24 + pair[2:] + "0" * 64
        lg = {
            "topics": [PAIR_CREATED, "0x" + "0" * 24 + "a" * 40, "0x" + "0" * 24 + "b" * 40],
            "data": data,
        }
        self.assertEqual(parse_pool_from_log("v2", lg), pair.lower())

    def test_v3_pool_from_data_word1(self):
        pool = "0x2222222222222222222222222222222222222222"
        data = "0x" + "0" * 64 + "0" * 24 + pool[2:]
        lg = {"topics": [POOL_CREATED_V3], "data": data}
        self.assertEqual(parse_pool_from_log("v3", lg), pool.lower())


class ChunkAdaptiveTests(unittest.TestCase):
    def test_next_chunk_shrink_grow(self):
        self.assertEqual(next_chunk_size(2000, shrink=True), 1000)
        self.assertEqual(next_chunk_size(MIN_CHUNK, shrink=True), MIN_CHUNK)
        self.assertEqual(next_chunk_size(1000, grow=True), 2000)

    def test_range_and_rate_detectors(self):
        self.assertTrue(is_range_error(RuntimeError("block range is too large")))
        self.assertTrue(is_rate_error(RuntimeError("429 Too Many Requests")))
        self.assertFalse(is_range_error(RuntimeError("connection reset")))

    def test_auto_shrink_on_range_error(self):
        pair = "0x3333333333333333333333333333333333333333"
        data = "0x" + "0" * 24 + pair[2:] + "0" * 64
        usdc = "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"
        other = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        lg = {
            "topics": [
                PAIR_CREATED,
                "0x" + "0" * 24 + usdc[2:],
                "0x" + "0" * 24 + other[2:],
            ],
            "data": data,
            "address": "0x5c69bee701ef814a2b6a3edd4b1652cb9cc5aa6f",
        }
        calls = {"n": 0, "sizes": []}

        class FakeClient:
            def block_number(self):
                return 100_000

            def logs(self, address, topic0, start, end):
                calls["n"] += 1
                span = end - start + 1
                calls["sizes"].append(span)
                # Fail until window <= 500
                if span > 500:
                    raise RuntimeError("eth_getLogs block range is too large")
                return [lg]

            def balance(self, address):
                return 0

            def call(self, to, data):
                if to.lower().startswith("0xa0b8"):
                    return hex(20_000 * 10**6)
                return "0x0"

        disc = PoolDiscovery(
            FakeClient(),
            factories=(("uniswap-v2", "0x5c69bee701ef814a2b6a3edd4b1652cb9cc5aa6f", PAIR_CREATED, "v2"),),
            lookback_blocks=1000,
            chunk_blocks=2000,
            min_holder_usd=10_000.0,
            scan_any_emitter=False,
            request_sleep_s=0.0,
            sleep=lambda _s: None,
            prices_usd={"USDC": 1.0, "USDT": 1.0, "DAI": 1.0, "WETH": 1.0, "ETH": 1.0, "WBTC": 1.0},
        )
        result = disc.discover()
        self.assertGreaterEqual(calls["n"], 2)
        self.assertLessEqual(result.chunk_blocks_final, 500)
        self.assertEqual(len(result.pools), 1)
        self.assertEqual(result.pools[0].address, pair.lower())


class MeasureTests(unittest.TestCase):
    def test_stables_and_eth(self):
        prices = {"ETH": 2000.0, "WETH": 2000.0, "USDC": 1.0, "USDT": 1.0, "DAI": 1.0, "WBTC": 50000.0}
        usdc = "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"
        total, br = measure_major_holdings(
            "0xabc",
            eth_balance_wei=10**18,
            erc20_balances={usdc: 5_000_000_000},
            prices_usd=prices,
        )
        self.assertAlmostEqual(total, 7000.0)
        self.assertIn("ETH", br)
        self.assertIn("USDC", br)


class DiscoveryIntegration(unittest.TestCase):
    def test_filters_by_min_usd(self):
        pair = "0x3333333333333333333333333333333333333333"
        data = "0x" + "0" * 24 + pair[2:] + "0" * 64
        usdc = "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"
        other = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        lg = {
            "topics": [
                PAIR_CREATED,
                "0x" + "0" * 24 + usdc[2:],
                "0x" + "0" * 24 + other[2:],
            ],
            "data": data,
        }

        class FakeClient:
            def block_number(self):
                return 100_000

            def logs(self, address, topic0, start, end):
                return [lg]

            def balance(self, address):
                return 0

            def call(self, to, data):
                if to.lower().startswith("0xa0b8"):
                    return hex(20_000 * 10**6)
                return "0x0"

        disc = PoolDiscovery(
            FakeClient(),
            factories=(("uniswap-v2", "0x5c69bee701ef814a2b6a3edd4b1652cb9cc5aa6f", PAIR_CREATED, "v2"),),
            lookback_blocks=500,
            chunk_blocks=1000,
            min_holder_usd=10_000.0,
            scan_any_emitter=False,
            request_sleep_s=0.0,
            sleep=lambda _s: None,
            prices_usd={"USDC": 1.0, "USDT": 1.0, "DAI": 1.0, "WETH": 1.0, "ETH": 1.0, "WBTC": 1.0},
        )
        result = disc.discover()
        self.assertGreaterEqual(result.scanned_logs, 1)
        self.assertEqual(len(result.pools), 1)
        self.assertEqual(result.pools[0].address, pair.lower())
        self.assertGreaterEqual(result.pools[0].value_usd, 10_000.0)

    def test_below_threshold_dropped(self):
        pair = "0x4444444444444444444444444444444444444444"
        data = "0x" + "0" * 24 + pair[2:] + "0" * 64
        usdc = "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"
        other = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        lg = {
            "topics": [
                PAIR_CREATED,
                "0x" + "0" * 24 + usdc[2:],
                "0x" + "0" * 24 + other[2:],
            ],
            "data": data,
        }

        class FakeClient:
            def block_number(self):
                return 50_000

            def logs(self, address, topic0, start, end):
                return [lg]

            def balance(self, address):
                return 0

            def call(self, to, data):
                return hex(100 * 10**6)

        disc = PoolDiscovery(
            FakeClient(),
            factories=(("uniswap-v2", "0x5c69bee701ef814a2b6a3edd4b1652cb9cc5aa6f", PAIR_CREATED, "v2"),),
            lookback_blocks=500,
            min_holder_usd=10_000.0,
            scan_any_emitter=False,
            request_sleep_s=0.0,
            sleep=lambda _s: None,
            prices_usd={"USDC": 1.0},
        )
        self.assertEqual(disc.discover().pools, [])


if __name__ == "__main__":
    unittest.main()
