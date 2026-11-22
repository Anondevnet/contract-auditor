"""Discovery skew: blue-chip Lagoon/Safe demotion, balance_usd, approval probe."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from auditor import hunt, monitor as m


class BlueChipSkewTests(unittest.TestCase):
    def test_lagoon_and_safe_are_blue_chips(self):
        self.assertIn("lagoon", hunt.BLUE_CHIP_PREFIXES)
        self.assertIn("safe", hunt.BLUE_CHIP_PREFIXES)
        self.assertTrue(hunt.is_blue_chip("lagoon", "Lagoon Finance", ""))
        self.assertTrue(hunt.is_blue_chip("lagoon-vaults", "Lagoon", "parent#lagoon"))
        self.assertTrue(hunt.is_blue_chip("safe", "Safe", "parent#safe"))
        self.assertTrue(hunt.is_blue_chip("gnosis-safe", "Gnosis Safe", ""))
        self.assertTrue(hunt.is_blue_chip("something", "Gnosis Safe Multisig", ""))
        self.assertFalse(hunt.is_blue_chip("newdex", "NewDex", ""))

    def test_safe_contract_name_known_fork_demotes(self):
        sig = hunt.source_signals({
            "SourceCode": "pragma solidity ^0.8.0; contract Safe {}",
            "ContractName": "Safe", "Proxy": "0",
        })
        self.assertTrue(sig["known_fork"])
        score, why = hunt.priority_score(
            {"listed_at": None, "audits": "0", "blue_chip": True, "verified": True,
             "has_code": True, "onchain_tvl_usd": 1_000_000},
            1_800_000_000, sig)
        self.assertTrue(any("blue-chip" in w for w in why))
        self.assertTrue(any("known fork" in w for w in why))
        self.assertLess(score, 40)

    def test_proxy_upgrade_signal_still_active(self):
        keys = [k for k, *_ in hunt.SOURCE_SIGNALS]
        self.assertIn("proxy_upgrade", keys)
        sig = hunt.source_signals({
            "SourceCode": "function upgradeTo(address a) external {}",
            "ContractName": "Vault", "Proxy": "1",
        })
        self.assertIn("proxy_upgrade", sig["signals"])
        score, why = hunt.priority_score(
            {"listed_at": 1_750_000_000, "audits": "0", "blue_chip": False,
             "verified": True, "has_code": True, "onchain_tvl_usd": 1_200_000},
            1_800_000_000, sig)
        self.assertTrue(any("proxy" in w.lower() for w in why))
        self.assertGreater(score, 50)


class ApprovalSkewTests(unittest.TestCase):
    def test_priority_boost_for_approvals(self):
        base, _ = hunt.priority_score(
            {"listed_at": None, "audits": "0", "blue_chip": False, "verified": True,
             "has_code": True, "onchain_tvl_usd": 1_000_000},
            1_800_000_000)
        boosted, why = hunt.priority_score(
            {"listed_at": None, "audits": "0", "blue_chip": False, "verified": True,
             "has_code": True, "onchain_tvl_usd": 1_000_000,
             "has_user_approvals": True, "approval_usd": 5_000},
            1_800_000_000)
        self.assertGreaterEqual(boosted - base, 15)
        self.assertTrue(any("approvals" in w.lower() for w in why))
        self.assertTrue(any("approval_usd" in w for w in why))

    def test_probe_user_approvals_detects_spender(self):
        spender = "0x1111111111111111111111111111111111111111"
        topic2 = hunt._spender_topic(spender)

        class FakeClient:
            def block_number(self):
                return 20_000_000

            def logs(self, address, topic0, from_block, to_block, topics=None):
                if topics and len(topics) >= 3 and topics[2] == topic2:
                    return [{"topics": [hunt._APPROVAL_TOPIC, "0x" + "0" * 64, topic2],
                             "data": "0x" + hex(10**18)[2:].zfill(64)}]
                return []

        out = hunt.probe_user_approvals(FakeClient(), spender, tokens=("WETH",), lookback_blocks=100)
        self.assertTrue(out["has_user_approvals"])
        self.assertIn("WETH", out["tokens_hit"])
        self.assertGreaterEqual(out["logs_seen"], 1)

    def test_probe_noop_without_client(self):
        out = hunt.probe_user_approvals(None, "0x1111111111111111111111111111111111111111")
        self.assertFalse(out["has_user_approvals"])


class BalanceUsdTests(unittest.TestCase):
    def test_schema_adds_balance_usd_idempotent(self):
        with tempfile.TemporaryDirectory() as td:
            db = Path(td) / "m.db"
            store = m.MonitorStore(db)
            fcols = {r[1] for r in store.conn.execute("PRAGMA table_info(monitor_findings)")}
            self.assertIn("balance_usd", fcols)
            hcols = {r[1] for r in store.conn.execute("PRAGMA table_info(hunt_candidates)")}
            self.assertIn("has_user_approvals", hcols)
            self.assertIn("approval_usd", hcols)
            # second open is idempotent
            store.close()
            store2 = m.MonitorStore(db)
            fcols2 = {r[1] for r in store2.conn.execute("PRAGMA table_info(monitor_findings)")}
            self.assertIn("balance_usd", fcols2)
            store2.close()

    def test_finding_value_rows_sets_balance_usd(self):
        class F:
            finding_id = "f1"
            severity = "HIGH"
            confidence = "HIGH"
            confirmed_exploitable = False
            title = "t"
            category = "reentrancy"
            description = ""
            affected_contract = "C"
            affected_function = "f"
            affected_file = "C.sol"
            affected_lines = [1]
            impact = ""

        class Var:
            tvl_usd = 12_345.0
            holder_value_usd = None
            native_usd = None
            holdings = []

            def to_dict(self):
                return {"tvl_usd": self.tvl_usd}

        class Tri:
            def record_for(self, f):
                return None

        # estimate_finding may return None for unknown shapes; balance_usd must still set
        with mock.patch("auditor.risk_playbook.classify", return_value=("other", "x")):
            with mock.patch("auditor.triage._finding_brief", return_value={
                "title": "t", "category": "reentrancy", "description": "",
                "affected_contract": "C", "affected_function": "f",
                "affected_file": "C.sol", "affected_lines": [1], "impact": "",
            }):
                with mock.patch("auditor.value_at_risk.estimate_finding", return_value=None):
                    with mock.patch("auditor.value_at_risk.summarize",
                                    return_value={"tvl_usd": 12_345.0}):
                        rows, _, _ = m.finding_value_rows([F()], [], Tri(), Var())
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["balance_usd"], 12_345.0)

    def test_add_findings_persists_balance_usd(self):
        with tempfile.TemporaryDirectory() as td:
            db = Path(td) / "m.db"
            store = m.MonitorStore(db)
            rid = store.conn.execute(
                "INSERT INTO monitor_scans(network,address,status,stage,started_at) VALUES(?,?,?,?,?)",
                ("ethereum", "0x" + "ab" * 20, "done", "done", 1.0)).lastrowid
            store.conn.commit()
            store.add_findings(rid, "ethereum", "0x" + "ab" * 20, [{
                "finding_id": "f1", "title": "t", "detector": "x", "vuln_class": "y",
                "category": "c", "severity": "HIGH", "original_severity": "HIGH",
                "confidence": "HIGH", "contract": "C", "function": "f", "file": "C.sol",
                "lines": "[1]", "suppressed": 0, "triage_reason": None, "triage_rule": None,
                "triage_detail": None, "est_loss_usd": None, "est_loss_low_usd": None,
                "est_loss_high_usd": None, "exposure_factor": None, "weighted_score": 0.0,
                "estimate_json": None, "finding_json": "{}",
                "impact_class": "unknown", "impact_status": "unresolved",
                "balance_usd": 999.5,
            }])
            got = store.conn.execute(
                "SELECT balance_usd FROM monitor_findings WHERE scan_row=?", (rid,)).fetchone()
            self.assertEqual(got[0], 999.5)
            store.close()


if __name__ == "__main__":
    unittest.main()
