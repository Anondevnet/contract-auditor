"""Phase 21 — proxy resolution, vault discovery, schema v6, hunt holder ranking."""

from __future__ import annotations

import json
import os
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from auditor import hunt, monitor as m, vault_discovery as vd

# Minimal EIP-1967 TransparentUpgradeableProxy-shaped bytecode: contains DELEGATECALL (0xf4)
# and is long enough not to look like a Safe. Real proxies are larger; tests inject storage.
PROXY_CODE = "0x" + ("00" * 100) + "f4" + ("00" * 50)
IMPL_CODE = "0x" + ("00" * 200)
# EIP-1167 minimal proxy pointing at 0x1111…1111
MIN_PROXY = (
    "0x363d3d373d3d3d363d73" + ("11" * 20) + "5af43d82803e903d91602b57fd5bf3"
)
SLOT_IMPL = vd.SLOT_EIP1967_IMPL
SLOT_1822 = vd.SLOT_EIP1822
SLOT_OZ = vd.SLOT_OZ_LEGACY


def _pad_addr(a: str) -> str:
    return "0x" + a.lower().replace("0x", "").rjust(64, "0")


class FakeReaderClient:
    """In-memory chain: code, storage, eth_call, balances."""

    def __init__(self):
        self.code: dict[str, str] = {}
        self.storage: dict[tuple[str, str], str] = {}
        self.calls: dict[tuple[str, str], str] = {}  # (to, data_prefix_or_full) -> result
        self.native: dict[str, int] = {}
        self.token_bal: dict[tuple[str, str], int] = {}  # (token, holder) -> amount
        self.api_key = "t"
        self.chain_id = 1
        self.rpc_url = "http://x"

    def get_code(self, a):
        return self.code.get(a.lower(), "0x")

    def code_size(self, a):
        c = self.get_code(a)
        return max((len(c) - 2) // 2, 0)

    def storage_at(self, a, slot):
        return self.storage.get((a.lower(), slot.lower()), "0x" + "0" * 64)

    def call(self, to, data):
        to, data = to.lower(), data.lower()
        if (to, data) in self.calls:
            return self.calls[(to, data)]
        if data.startswith(vd.SEL["balanceOf(address)"]):
            holder = "0x" + data[-40:]
            n = self.token_bal.get((to, holder), 0)
            return "0x" + format(n, "064x")
        for (t0, d), r in self.calls.items():
            if t0 == to and (data == d or data.startswith(d)):
                return r
        raise RuntimeError("revert")

    def native_balance(self, a):
        return self.native.get(a.lower(), 0)

    def verified_source(self, a):
        return None


class ResolveProxyTests(unittest.TestCase):
    def test_eip1967(self):
        c = FakeReaderClient()
        proxy, impl = "0x" + "aa" * 20, "0x" + "bb" * 20
        c.code[proxy] = PROXY_CODE
        c.code[impl] = IMPL_CODE
        c.storage[(proxy, SLOT_IMPL.lower())] = _pad_addr(impl)
        info = vd.resolve_proxy(vd.Reader(c), proxy)
        self.assertTrue(info.is_proxy)
        self.assertEqual(info.kind, "eip1967")
        self.assertEqual(info.implementation, impl)

    def test_eip1822(self):
        c = FakeReaderClient()
        proxy, impl = "0x" + "aa" * 20, "0x" + "cc" * 20
        c.code[proxy] = PROXY_CODE
        c.storage[(proxy, SLOT_1822.lower())] = _pad_addr(impl)
        info = vd.resolve_proxy(vd.Reader(c), proxy)
        self.assertEqual(info.kind, "eip1822")
        self.assertEqual(info.implementation, impl)

    def test_oz_legacy(self):
        c = FakeReaderClient()
        proxy, impl = "0x" + "aa" * 20, "0x" + "dd" * 20
        c.code[proxy] = PROXY_CODE
        c.storage[(proxy, SLOT_OZ.lower())] = _pad_addr(impl)
        info = vd.resolve_proxy(vd.Reader(c), proxy)
        self.assertEqual(info.kind, "oz-legacy")
        self.assertEqual(info.implementation, impl)

    def test_eip1167(self):
        c = FakeReaderClient()
        proxy = "0x" + "ee" * 20
        c.code[proxy] = MIN_PROXY
        info = vd.resolve_proxy(vd.Reader(c), proxy)
        self.assertEqual(info.kind, "eip1167")
        self.assertEqual(info.implementation, "0x" + "11" * 20)

    def test_eip897_requires_delegatecall(self):
        c = FakeReaderClient()
        addr, impl = "0x" + "aa" * 20, "0x" + "bb" * 20
        # No DELEGATECALL in code → implementation() must be ignored (plain registry).
        c.code[addr] = "0x" + ("00" * 80)  # no f4
        c.calls[(addr, vd.SEL["implementation()"])] = _pad_addr(impl)
        info = vd.resolve_proxy(vd.Reader(c), addr)
        self.assertFalse(info.is_proxy)
        # With DELEGATECALL → accepted
        c.code[addr] = PROXY_CODE
        c._code_cache_clear = True
        r = vd.Reader(c)
        info = vd.resolve_proxy(r, addr)
        self.assertEqual(info.kind, "eip897")
        self.assertEqual(info.implementation, impl)

    def test_gnosis_safe_mastercopy(self):
        c = FakeReaderClient()
        safe, master = "0x" + "aa" * 20, "0x" + "ff" * 20
        c.code[safe] = "0x" + ("00" * 50) + "f4" + ("00" * 20)  # small + DELEGATECALL
        c.storage[(safe, "0x0")] = _pad_addr(master)
        c.calls[(safe, vd.SEL["masterCopy()"])] = _pad_addr(master)
        info = vd.resolve_proxy(vd.Reader(c), safe)
        self.assertEqual(info.kind, "gnosis-safe")
        self.assertEqual(info.implementation, master)


class VaultDiscoveryTests(unittest.TestCase):
    def test_walks_strategy_and_ranks_by_holdings(self):
        c = FakeReaderClient()
        vault = "0x" + "a1" * 20
        strategy = "0x" + "a2" * 20
        susde = "0x" + "a3" * 20
        for a, code in ((vault, PROXY_CODE), (strategy, PROXY_CODE), (susde, IMPL_CODE)):
            c.code[a] = code
        # vault is EIP-1967 → impl (irrelevant for call; we call the proxy)
        c.storage[(vault, SLOT_IMPL.lower())] = _pad_addr("0x" + "b1" * 20)
        c.code["0x" + "b1" * 20] = IMPL_CODE
        # vault.cdo / strategy path: use structural getters on vault → strategy
        c.calls[(vault, vd.STRUCTURAL_GETTERS["strategy()"])] = _pad_addr(strategy)
        # strategy.sUSDe() token getter
        c.calls[(strategy, vd.TOKEN_GETTERS["sUSDe()"])] = _pad_addr(susde)
        # strategy holds 1000 sUSDe (18 decimals)
        c.token_bal[(susde, strategy)] = 1000 * 10**18
        # sUSDe looks like ERC-20
        c.calls[(susde, vd.SEL["totalSupply()"])] = "0x" + format(10**24, "064x")
        c.calls[(susde, vd.SEL["decimals()"])] = "0x" + format(18, "064x")
        c.calls[(susde, vd.SEL["symbol()"])] = (
            "0x" + "20".rjust(64, "0") + format(5, "064x")
            + "7355534465".ljust(64, "0")  # "sUSDe"
        )
        # vault is ERC-4626 with totalAssets
        c.calls[(vault, vd.SEL["totalSupply()"])] = "0x" + format(500 * 10**18, "064x")
        c.calls[(vault, vd.SEL["decimals()"])] = "0x" + format(18, "064x")
        c.calls[(vault, vd.SEL["asset()"])] = _pad_addr(susde)
        c.calls[(vault, vd.SEL["totalAssets()"])] = "0x" + format(900 * 10**18, "064x")

        class P(vd.TokenPricer):
            def fetch_many(self, addresses):
                for a in addresses:
                    self._cache[a.lower()] = (self.clock(), 1.25)
                return {a.lower(): 1.25 for a in addresses}

            def price(self, address=None, *, native=False):
                if native:
                    return 3000.0
                return 1.25

        reader = vd.Reader(c, max_calls=500)
        disc = vd.VaultDiscovery(reader, P(), max_depth=2, max_nodes=10)
        result = disc.discover([vault])
        addrs = {h.address: h for h in result.ranked}
        self.assertIn(strategy, addrs)
        self.assertGreaterEqual(addrs[strategy].value_usd or 0, 1000 * 1.25 - 1)
        self.assertIn(vault, addrs)
        # vault reports totalAssets
        self.assertTrue(addrs[vault].is_erc4626)
        self.assertGreaterEqual(addrs[vault].value_usd or 0, 900 * 1.25 - 1)
        self.assertIn(vault, result.proxies)


class MigrationTests(unittest.TestCase):
    def test_v5_to_v6(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        db = Path(tmp.name) / "old.db"
        conn = sqlite3.connect(db)
        conn.executescript("""
            CREATE TABLE hunt_candidates (
                network TEXT NOT NULL, address TEXT NOT NULL,
                protocol TEXT, status TEXT NOT NULL DEFAULT 'new',
                PRIMARY KEY (network, address));
            CREATE TABLE hunt_runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT, network TEXT NOT NULL, at REAL NOT NULL);
            PRAGMA user_version = 5;
        """)
        conn.close()
        store = m.MonitorStore(db)
        ver = store.conn.execute("PRAGMA user_version").fetchone()[0]
        cols = {r[1] for r in store.conn.execute("PRAGMA table_info(hunt_candidates)")}
        self.assertEqual(ver, m.MonitorStore.SCHEMA_VERSION)
        self.assertTrue({"proxy_kind", "holder_value_usd", "holder_role",
                         "discovery_json", "scan_address"} <= cols)
        store.close()


class Env(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.d = Path(self.tmp.name)
        self.env = mock.patch.dict(os.environ, {
            "AUDITOR_MONITOR_DB": str(self.d / "mon.db"),
            "AUDITOR_MONITOR_CACHE": str(self.d / "cache"),
            "AUDITOR_HISTORY_DB": str(self.d / "hist.db"),
            "AUDITOR_MONITOR_ALERTS": str(self.d / "a.jsonl"),
            "AUDITOR_PRICE_CACHE": str(self.d / "prices.json"),
            "AUDITOR_SOLC_AUTO_INSTALL": "0",
            "AUDITOR_SOLC_ARTIFACTS": str(self.d / "art"),
        })
        self.env.start()
        self.t = [1_760_000_000.0]

    def tearDown(self):
        self.env.stop()
        self.tmp.cleanup()

    def clock(self):
        self.t[0] += 1
        return self.t[0]


class OverviewPhase21(Env):
    def test_overview_shows_proxy_and_holder_value(self):
        store = m.MonitorStore(self.d / "mon.db")
        hunt.upsert_candidate(
            store, "ethereum", "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            protocol="Noon", slug="noon", category="Yield", category_group="vaults",
            source="vault-discovery", llama_tvl_usd=36e6, onchain_tvl_usd=33e6,
            holder_value_usd=33e6, holder_role="seed",
            is_proxy=1, implementation="0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            proxy_kind="eip1967", priority_score=55, status="ready", now=self.clock())
        ov = hunt.hunt_overview(store.conn, "ethereum", since=0, sort="tvl")
        row = ov["candidates"][0]
        self.assertEqual(row["holder_value_usd"], 33e6)
        self.assertEqual(row["proxy_kind"], "eip1967")
        self.assertEqual(row["implementation"], "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
        store.close()

        from fastapi.testclient import TestClient
        from auditor.dashboard.app import create_app
        client = TestClient(create_app())
        r = client.get("/hunt")
        self.assertEqual(r.status_code, 200)
        self.assertIn(b"Value held", r.content)
        self.assertIn(b"Proxy", r.content)
        r = client.get("/api/hunt/live?sort=tvl")
        self.assertEqual(r.status_code, 200)
        body = r.json()
        self.assertEqual(body["candidates"][0]["holder_value_usd"], 33e6)


class SlugFilterTests(Env):
    def test_refresh_respects_slugs(self):
        class Cache:
            def get(self, key, url, ttl, as_json=True, force=False):
                if "protocols" in key:
                    return [
                        {"name": "Noon", "slug": "noon", "category": "Yield",
                         "chains": ["Ethereum"], "chainTvls": {"Ethereum": 36e6},
                         "address": None, "listedAt": 1_750_000_000, "audits": "2",
                         "module": "noon/index.js", "forkedFrom": None, "parentProtocol": None},
                        {"name": "Other", "slug": "other", "category": "Yield",
                         "chains": ["Ethereum"], "chainTvls": {"Ethereum": 10e6},
                         "address": "0x1111111111111111111111111111111111111111",
                         "listedAt": 1_750_000_000, "audits": "0",
                         "module": "other", "forkedFrom": None, "parentProtocol": None},
                    ]
                if "pools" in key:
                    return {"data": []}
                if "adapter" in key or "noon" in key:
                    return (
                        "ethereum: { usn: '0xdA67B4284609d2d48e5d10cfAc411572727dc1eD',\n"
                        "  susn: '0xE24a3DC889621612422A64E6388927901608B91D' }"
                    )
                raise hunt.TransientError("nope")

        cfg = hunt.HuntConfig(db_path=self.d / "mon.db", cache_dir=self.d / "hunt",
                              slugs=("noon",), max_protocols=10, min_tvl=1e6,
                              vault_discovery=False)
        hunter = hunt.Hunter(cfg, client=None, cache=Cache(), emit=lambda s: None,
                             clock=self.clock, sleep=lambda s: None)
        stats = hunter.refresh()
        rows = hunter.store.conn.execute(
            "SELECT slug, address FROM hunt_candidates").fetchall()
        self.assertTrue(rows)
        self.assertTrue(all(r["slug"] == "noon" for r in rows))
        self.assertGreaterEqual(stats["discovered"], 1)
        hunter.store.close()


if __name__ == "__main__":
    unittest.main()
