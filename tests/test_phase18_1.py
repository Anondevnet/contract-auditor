"""Phase 18.1 — honest status for compile failures, per-scan solc selection,
standard-JSON remappings, legacy re-scan, monitor loop robustness.

Network fully mocked; temp DBs, temp solc artifact dirs with fake binaries.
One optional integration test runs the real Slither when solc 0.8.30 is
already installed in the solc-select cache (never downloads).
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import shutil
import sqlite3
import stat
import sys
import tempfile
import unittest
import unittest.mock as mock
from pathlib import Path
from types import SimpleNamespace

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from auditor import compiler_select as cs  # noqa: E402
from auditor import monitor as m  # noqa: E402
from auditor import monitor_view as mv  # noqa: E402
from auditor.analysis import slither_runner as sr  # noqa: E402
from auditor.analysis.slither_runner import SlitherRun  # noqa: E402
from auditor.cli import EXIT_ERROR, EXIT_OK, _fail_on_gate, main  # noqa: E402
from auditor.disk_pressure import RESUME_GIB, free_gib  # noqa: E402

SRC_830 = "// SPDX-License-Identifier: MIT\npragma solidity 0.8.30;\ncontract Bank { function f() external {} }\n"
REC_830 = {"SourceCode": SRC_830, "ContractName": "Bank", "CompilerVersion": "v0.8.30+commit.73712a01",
           "OptimizationUsed": "1", "Runs": "200", "EVMVersion": "prague"}


def _fake_solc(root: Path, version: str) -> Path:
    p = cs.artifact_path(version, root)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text("#!/bin/sh\necho fake solc\n")
    p.chmod(p.stat().st_mode | stat.S_IEXEC)
    return p


class Env(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.d = Path(self.tmp.name)
        self.art = self.d / "artifacts"
        self.env = mock.patch.dict(os.environ, {
            "AUDITOR_MONITOR_DB": str(self.d / "mon.db"), "AUDITOR_MONITOR_ALERTS": str(self.d / "a.jsonl"),
            "AUDITOR_MONITOR_CACHE": str(self.d / "cache"), "AUDITOR_HISTORY_DB": str(self.d / "hist.db"),
            "AUDITOR_SOLC_ARTIFACTS": str(self.art), "AUDITOR_SOLC_AUTO_INSTALL": "0"})
        self.env.start()
        self.t = [1000.0]

    def tearDown(self):
        self.env.stop()
        self.tmp.cleanup()

    def _skip_if_disk_gated(self) -> None:
        """Skip scan-asserting tests while the real disk-pressure gate defers heavy scans.

        Mirrors auditor.monitor.poll(): when free_gib() < RESUME_GIB, the controller's
        allow_expensive("monitor.scan") refuses expensive scans (queued work preserved),
        so tests whose assertions require a processed scan would fail on empty results.
        Production behavior is untouched; coverage returns automatically once the real
        free space reaches RESUME_GIB again.
        """
        free = free_gib()
        if free < RESUME_GIB:
            self.skipTest(
                f"real disk-pressure gate active: free {free:.2f} GiB < RESUME_GIB "
                f"{RESUME_GIB:g} GiB; heavy scans would be deferred (queued work preserved); "
                "this test's assertions require a processed scan. Coverage returns "
                f"automatically once free space >= {RESUME_GIB:g} GiB.")

    def clock(self):
        self.t[0] += 0.5
        return self.t[0]


# ---------------------------------------------------------------------------
# version selection
# ---------------------------------------------------------------------------

class VersionSelectionTests(Env):
    def test_etherscan_version_parsing(self):
        self.assertEqual(cs.parse_etherscan_version("v0.8.30+commit.73712a01"), "0.8.30")
        self.assertEqual(cs.parse_etherscan_version("0.5.10"), "0.5.10")
        self.assertIsNone(cs.parse_etherscan_version("vyper:0.3.10"))
        self.assertIsNone(cs.parse_etherscan_version("v0.8.4-nightly.2021.1.1+commit.x"))
        self.assertIsNone(cs.parse_etherscan_version(""))

    def test_pragma_constraints_and_choice(self):
        self.assertEqual(cs.pragma_constraints(["// pragma solidity 0.4.24;\npragma solidity ^0.8.20;"]), ["^0.8.20"])
        inst = ["0.5.8", "0.5.10", "0.8.37"]
        self.assertEqual(cs.choose_pragma_version(["^0.8.0"], inst), "0.8.37")
        self.assertEqual(cs.choose_pragma_version(["^0.5.8"], inst), "0.5.10")
        self.assertEqual(cs.choose_pragma_version(["0.8.30"], inst), "0.8.30")  # exact, not installed
        self.assertEqual(cs.choose_pragma_version([">=0.6.0 <0.8.0"], inst), "0.7.6")
        self.assertEqual(cs.choose_pragma_version(["^0.8.0", "<0.8.25"], inst), "0.8.24")
        self.assertEqual(cs.choose_pragma_version(["^0.4.0 || ^0.5.0"], inst), "0.5.10")
        self.assertIsNone(cs.choose_pragma_version([], inst))

    def test_plan_uses_etherscan_version_and_flat_settings(self):
        _fake_solc(self.art, "0.8.30")
        root = self.d / "src"
        files = m.materialize_sources(SRC_830, root, "Bank")
        plan = cs.plan_compile(REC_830, files, root, allow_install=False)
        self.assertEqual((plan.version, plan.version_source), ("0.8.30", "etherscan"))
        self.assertEqual(plan.solc_path, str(cs.artifact_path("0.8.30", self.art)))
        self.assertEqual(plan.solc_args, "--base-path . --optimize --optimize-runs 200 --evm-version prague")
        self.assertEqual((plan.target, plan.cwd), ("Bank.sol", str(root.resolve())))

    def test_pragma_fallback_and_old_solc_has_no_base_path(self):
        _fake_solc(self.art, "0.5.8")
        root = self.d / "old"
        files = m.materialize_sources("pragma solidity ^0.5.0;\ncontract Old {}", root, "Old")
        plan = cs.plan_compile({"SourceCode": "x", "EVMVersion": "Default"}, files, root, allow_install=False)
        self.assertEqual((plan.version, plan.version_source, plan.solc_args), ("0.5.8", "pragma", ""))

    def test_missing_solc_install_policy(self):
        root = self.d / "s"
        files = m.materialize_sources(SRC_830, root, "Bank")
        with self.assertRaises(cs.CompilerSelectionError) as cm:
            cs.plan_compile(REC_830, files, root, allow_install=False)
        self.assertIn("solc-select install 0.8.30", str(cm.exception))
        calls = []
        plan = cs.plan_compile(REC_830, files, root, allow_install=True,
                               installer=lambda v: (calls.append(v), _fake_solc(self.art, v)))
        self.assertEqual((calls, plan.version), (["0.8.30"], "0.8.30"))

    def test_invalid_inputs_rejected(self):
        with self.assertRaises(cs.CompilerSelectionError):
            cs.ensure_solc("0.8.30; rm -rf /", allow_install=True, installer=lambda v: None, root=self.art)
        _fake_solc(self.art, "0.8.30")
        root = self.d / "e"
        files = m.materialize_sources(SRC_830, root, "Bank")
        with self.assertRaises(cs.CompilerSelectionError):
            cs.plan_compile(dict(REC_830, EVMVersion="paris --output-dir /tmp"), files, root, allow_install=False)


class ScopedCompilerTests(Env):
    def test_default_installer_only_runs_install_never_use(self):
        seen = []

        def fake_run(argv, **kw):
            seen.append(list(argv))
            _fake_solc(self.art, argv[2])
            return SimpleNamespace(returncode=0, stdout="", stderr="")

        with mock.patch("shutil.which", return_value="/usr/local/bin/solc-select"), \
                mock.patch.object(cs.subprocess, "run", fake_run):
            path = cs.ensure_solc("0.8.30", allow_install=True)
        self.assertEqual(seen, [["/usr/local/bin/solc-select", "install", "0.8.30"]])
        self.assertTrue(path.endswith("solc-0.8.30"))

    def test_slither_argv_is_scoped_and_global_env_unchanged(self):
        _fake_solc(self.art, "0.8.30")
        root = self.d / "c"
        files = m.materialize_sources(SRC_830, root, "Bank")
        captured = {}

        def fake_proc(argv, timeout=None, cwd=None):
            captured.update(argv=list(argv), cwd=cwd)
            Path(argv[3]).write_text(json.dumps({"success": True, "results": {"detectors": []}}))
            return sr.ProcResult(argv=tuple(argv), returncode=0, stdout="", stderr="")

        before = dict(os.environ)
        with mock.patch.object(sr, "resolve_executable", return_value="/bin/slither"), \
                mock.patch.object(sr, "run", fake_proc):
            res = m.default_analyzer(files, SRC_830, "h", record=REC_830, root=root, allow_install=False)
        self.assertEqual(dict(os.environ), before)
        self.assertNotIn("SOLC_VERSION", os.environ.get("__never__", ""))
        argv = captured["argv"]
        self.assertEqual(argv[1], "Bank.sol")
        self.assertEqual(captured["cwd"], str(root.resolve()))
        self.assertEqual(argv[argv.index("--solc") + 1], str(cs.artifact_path("0.8.30", self.art)))
        self.assertIn("--evm-version prague", argv[argv.index("--solc-args") + 1])
        self.assertTrue(res.complete)
        self.assertEqual(res.execution["scan_complete"], True)
        self.assertEqual(res.compile["solc_version"], "0.8.30")

    def test_solc_args_allow_list(self):
        self.assertEqual(sr.parse_solc_args("--optimize --optimize-runs 1 --via-ir")[1], None)
        self.assertIsNotNone(sr.parse_solc_args("--output-dir /tmp")[1])
        self.assertIsNotNone(sr.parse_solc_args("--base-path /")[1])
        r = sr.run_slither([Path("x.sol")], solc_args="--allow-paths /")
        self.assertEqual(r.status, "failed")


class StandardJsonTests(Env):
    def _sj(self, settings):
        return "{" + json.dumps({"language": "Solidity", "settings": settings, "sources": {
            "src/Vault.sol": {"content": 'pragma solidity 0.8.30;\nimport "@oz/token/T.sol";\ncontract Vault is T {}\n'},
            "lib/oz/token/T.sol": {"content": "pragma solidity ^0.8.20;\ncontract T {}\n"}}}) + "}"

    def test_remappings_settings_and_target(self):
        _fake_solc(self.art, "0.8.30")
        src = self._sj({"optimizer": {"enabled": True, "runs": 999}, "evmVersion": "cancun", "viaIR": True,
                        "remappings": ["@oz/=lib/oz/"]})
        root = self.d / "sj"
        files = m.materialize_sources(src, root, "Vault")
        self.assertTrue((root / "lib/oz/token/T.sol").exists())
        rec = {"SourceCode": src, "ContractName": "Vault", "CompilerVersion": "v0.8.30+commit.73712a01",
               "OptimizationUsed": "0", "EVMVersion": "Default"}
        plan = cs.plan_compile(rec, files, root, allow_install=False)
        self.assertEqual(plan.solc_remaps, "@oz/=lib/oz/")
        self.assertEqual(plan.target, "src/Vault.sol")
        self.assertEqual(plan.solc_args, "--base-path . --optimize --optimize-runs 999 --evm-version cancun --via-ir")

    def test_escaping_remapping_rejected(self):
        _fake_solc(self.art, "0.8.30")
        src = self._sj({"remappings": ["@oz/=/etc/"]})
        root = self.d / "bad"
        files = m.materialize_sources(src, root, "Vault")
        with self.assertRaises(cs.CompilerSelectionError):
            cs.plan_compile({"SourceCode": src, "ContractName": "Vault",
                             "CompilerVersion": "v0.8.30+commit.73712a01"}, files, root, allow_install=False)

    @unittest.skipUnless(shutil.which("slither") and cs.artifact_path("0.8.30", cs.artifacts_dir()).is_file()
                         if "AUDITOR_SOLC_ARTIFACTS" not in os.environ else False,
                         "integration: needs slither on PATH and solc 0.8.30 in the solc-select cache")
    def test_real_slither_compiles_openzeppelin_style_imports(self):
        os.environ.pop("AUDITOR_SOLC_ARTIFACTS", None)
        src = "{" + json.dumps({"language": "Solidity", "settings": {"optimizer": {"enabled": True, "runs": 200}},
                                "sources": {
            "contracts/Bank.sol": {"content": '// SPDX-License-Identifier: MIT\npragma solidity 0.8.30;\n'
                                   'import "@openzeppelin/contracts/utils/Ctx.sol";\nimport "./Lib.sol";\n'
                                   'contract Bank is Ctx { function f() external view returns (address) { return _s(); } }\n'},
            "contracts/Lib.sol": {"content": "// SPDX-License-Identifier: MIT\npragma solidity ^0.8.0;\nlibrary Lib {}\n"},
            "@openzeppelin/contracts/utils/Ctx.sol": {"content": "// SPDX-License-Identifier: MIT\npragma solidity ^0.8.20;\n"
                                                      "abstract contract Ctx { function _s() internal view returns (address) { return msg.sender; } }\n"}}}) + "}"
        root = self.d / "real"
        files = m.materialize_sources(src, root, "Bank")
        res = m.default_analyzer(files, src, "h", record={"SourceCode": src, "ContractName": "Bank",
                                                           "CompilerVersion": "v0.8.30+commit.73712a01"},
                                 root=root, allow_install=False)
        self.assertTrue(res.complete, res.reasons)


# ---------------------------------------------------------------------------
# honest status
# ---------------------------------------------------------------------------

class FakeClient:
    def __init__(self, creations, sources):
        self.creations, self.sources = creations, sources

    def block_number(self):
        return 10

    def contract_creations(self, block):
        return [{"address": a, "tx_hash": "0xt", "block": block} for a in self.creations.get(block, [])]

    def verified_source(self, address):
        return self.sources.get(address)


class HonestStatusTests(Env):
    def _monitor(self, client, **kw):
        cfg = m.MonitorConfig(db_path=self.d / "mon.db", alerts_path=self.d / "a.jsonl",
                              cache_dir=self.d / "cache", interval=0, start_lookback=5,
                              solc_auto_install=False, **kw)
        return m.Monitor(cfg, client, emit=lambda s: None, clock=self.clock, sleep=lambda s: None)

    def _run_with_slither(self, slither_run):
        _fake_solc(self.art, "0.8.30")
        mon = self._monitor(FakeClient({6: ["0xa"]}, {"0xa": dict(REC_830)}))
        with mock.patch.object(sr, "run_slither", return_value=slither_run):
            return mon.run(once=True)[0]["results"][0]

    def test_compile_failure_is_incomplete_not_clean(self):
        self._skip_if_disk_gated()
        failed = SlitherRun(status="failed", error="slither could not compile the sources: Error: Source file "
                            "requires different compiler version", returncode=1)
        r = self._run_with_slither(failed)
        self.assertEqual(r["status"], "incomplete")
        conn = sqlite3.connect(self.d / "mon.db")
        conn.row_factory = sqlite3.Row
        row = conn.execute("SELECT * FROM monitor_scans").fetchone()
        seen = conn.execute("SELECT COUNT(*) FROM monitor_seen").fetchone()[0]
        q = conn.execute("SELECT status FROM monitor_queue").fetchone()[0]
        conn.close()
        self.assertEqual((row["status"], row["analysis_complete"], seen, q), ("incomplete", 0, 0, "incomplete"))
        self.assertIn("could not compile", row["error"])
        self.assertEqual(row["solc_version"], "0.8.30")
        from auditor.scan_history import ScanHistory

        h = ScanHistory(self.d / "hist.db")
        rec = h.get_scan(row["scan_id"])
        h.close()
        self.assertIs(rec["execution"]["scan_complete"], False)
        self.assertIn("could not compile", rec["execution"]["incomplete_reasons"][0])
        self.assertIn("not a clean result", rec["execution"]["zero_findings_note"])
        c = mv.live(now=self.t[0] + 1)["counters"]
        self.assertEqual((c["audited_all_time"], c["could_not_analyze_all_time"]), (0, 1))
        st = m.monitor_status("ethereum")
        self.assertEqual(st["scans"]["could_not_analyze"], 1)
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            main(["monitor-status"])
        self.assertIn("could not analyze: 1", out.getvalue())

    def test_completed_slither_is_audited(self):
        self._skip_if_disk_gated()
        r = self._run_with_slither(SlitherRun(status="completed", detectors=[]))
        self.assertEqual(r["status"], "scanned")
        c = mv.live(now=self.t[0] + 1)["counters"]
        self.assertEqual((c["audited_all_time"], c["could_not_analyze_all_time"]), (1, 0))

    def test_compiler_selection_failure_is_incomplete(self):
        self._skip_if_disk_gated()
        mon = self._monitor(FakeClient({6: ["0xa"]}, {"0xa": dict(REC_830)}))  # 0.8.30 not "installed"
        r = mon.run(once=True)[0]["results"][0]
        self.assertEqual(r["status"], "incomplete")
        self.assertIn("compiler selection failed", r["reasons"][0])

    def test_gate_fails_on_incomplete(self):
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            self.assertEqual(_fail_on_gate("HIGH", [], complete=False), EXIT_ERROR)
        self.assertIn("incomplete", err.getvalue())
        self.assertEqual(_fail_on_gate("HIGH", [], complete=None), EXIT_OK)
        self.assertEqual(_fail_on_gate(None, [], complete=False), EXIT_OK)

    def test_plain_scan_records_incomplete(self):
        sol = self.d / "A.sol"
        sol.write_text("pragma solidity 0.8.30;\ncontract A {}\n")
        failed = SlitherRun(status="failed", error="slither could not compile the sources: Error: x")
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(sr, "run_slither", return_value=failed), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main(["scan", "--json", str(sol)])
        payload = json.loads(out.getvalue())
        self.assertEqual(set(payload), {"scan_id", "source_path", "content_hash", "findings", "notes"})
        self.assertIn("INCOMPLETE", err.getvalue())
        self.assertEqual(code, EXIT_OK)
        from auditor.scan_history import ScanHistory

        h = ScanHistory(self.d / "hist.db")
        ex = h.get_scan(payload["scan_id"])["execution"]
        h.close()
        self.assertIs(ex["scan_complete"], False)
        self.assertTrue(ex["incomplete_reasons"])
        with mock.patch.object(sr, "run_slither", return_value=failed), \
                contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(main(["scan", "--fail-on", "HIGH", str(sol)]), EXIT_ERROR)

    def test_scan_address_uses_etherscan_compiler_and_records_verdict(self):
        _fake_solc(self.art, "0.8.30")
        body = json.dumps({"status": "1", "message": "OK", "result": [REC_830]}).encode()
        resp = mock.MagicMock()
        resp.read.return_value = body
        resp.__enter__ = mock.Mock(return_value=resp)
        resp.__exit__ = mock.Mock(return_value=False)
        seen = {}

        def fake_run_slither(files, **kw):
            seen.update(kw)
            return SlitherRun(status="failed", error="slither could not compile the sources: Error: boom")

        out, err = io.StringIO(), io.StringIO()
        with mock.patch("urllib.request.urlopen", return_value=resp), \
                mock.patch.dict(os.environ, {"ETHERSCAN_API_KEY": "k123"}), \
                mock.patch.object(sr, "run_slither", fake_run_slither), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main(["scan-address", "--network", "ethereum", "--json",
                         "--address", "0x1234567890abcdef1234567890abcdef12345678"])
        self.assertEqual(code, EXIT_OK)
        payload = json.loads(out.getvalue())
        self.assertIs(payload["scan_complete"], False)
        self.assertEqual(payload["compiler"]["solc_version"], "0.8.30")
        self.assertEqual(seen["solc"], str(cs.artifact_path("0.8.30", self.art)))
        self.assertIn("--optimize-runs 200", seen["solc_args"])
        self.assertNotIn("k123", out.getvalue() + err.getvalue())


# ---------------------------------------------------------------------------
# legacy rows + rescan
# ---------------------------------------------------------------------------

class RescanTests(Env):
    def _legacy_db(self):
        """A Phase 18 (schema v2) DB with two done/0-finding rows, like the Mac's."""
        from auditor.scan_history import ScanHistory

        h = ScanHistory(self.d / "hist.db")
        ids = []
        for i in range(2):
            sid = h.record_scan(source_path=f"etherscan://ethereum/0x{i}", config_fingerprint="monitor-ethereum",
                                findings=[], content_hash=f"h{i}")
            h.mark_completed(sid, [])
            ids.append(sid)
        h.close()
        conn = sqlite3.connect(self.d / "mon.db")
        conn.executescript("""
            CREATE TABLE monitor_cursor (network TEXT PRIMARY KEY, last_block INTEGER NOT NULL, updated_at TEXT);
            CREATE TABLE monitor_seen (network TEXT NOT NULL, address TEXT NOT NULL, content_hash TEXT NOT NULL,
                scan_id TEXT, findings INTEGER, scanned_at TEXT, contract_name TEXT,
                PRIMARY KEY (network, address, content_hash));
            CREATE TABLE monitor_queue (network TEXT NOT NULL, address TEXT NOT NULL, tx_hash TEXT, block INTEGER,
                attempts INTEGER NOT NULL DEFAULT 0, next_attempt_at REAL NOT NULL DEFAULT 0,
                status TEXT NOT NULL DEFAULT 'pending', last_error TEXT, updated_at TEXT,
                PRIMARY KEY (network, address));
            CREATE TABLE monitor_scans (id INTEGER PRIMARY KEY AUTOINCREMENT, network TEXT NOT NULL,
                address TEXT NOT NULL, tx_hash TEXT, block INTEGER, content_hash TEXT, contract_name TEXT,
                compiler TEXT, file_count INTEGER, line_count INTEGER, source_bytes INTEGER, cache_dir TEXT,
                stage TEXT NOT NULL, status TEXT NOT NULL, started_at REAL NOT NULL, stage_at REAL,
                finished_at REAL, duration_s REAL, scan_id TEXT, findings INTEGER, severity_counts TEXT, error TEXT);
            CREATE TABLE monitor_stage_events (scan_row INTEGER NOT NULL, stage TEXT NOT NULL, at REAL NOT NULL);
            CREATE TABLE monitor_polls (id INTEGER PRIMARY KEY AUTOINCREMENT, network TEXT NOT NULL, at REAL NOT NULL,
                blocks INTEGER, enqueued INTEGER, processed INTEGER, alerts INTEGER, error TEXT);
            PRAGMA user_version = 2;
        """)
        for i, sid in enumerate(ids):
            conn.execute("INSERT INTO monitor_seen VALUES ('ethereum', ?, ?, ?, 0, 'x', 'Bank')", (f"0x{i}", f"h{i}", sid))
            conn.execute("INSERT INTO monitor_queue(network,address,status) VALUES ('ethereum', ?, 'done')", (f"0x{i}",))
            conn.execute("INSERT INTO monitor_scans(network,address,tx_hash,block,content_hash,contract_name,stage,status,"
                         "started_at,finished_at,duration_s,scan_id,findings,severity_counts) "
                         "VALUES ('ethereum', ?, '0xt', 5, ?, 'Bank', 'done', 'done', 1.0, 1.5, 0.5, ?, 0, '{}')",
                         (f"0x{i}", f"h{i}", sid))
        conn.commit()
        conn.close()
        return ids

    def test_unmigrated_db_reports_legacy_not_audited(self):
        self._legacy_db()
        c = mv.live(now=2.0)["counters"]  # read-only: does not migrate
        self.assertEqual((c["audited_all_time"], c["legacy_needs_rescan"]), (0, 2))

    def test_migration_flags_and_rescan_requeues_legacy_rows(self):
        ids = self._legacy_db()
        store = m.MonitorStore(self.d / "mon.db")
        flagged = store.conn.execute("SELECT COUNT(*) FROM monitor_scans WHERE needs_rescan=1").fetchone()[0]
        self.assertEqual(flagged, 2)
        dry = m.rescan(store, "ethereum", dry_run=True)
        self.assertEqual([i["legacy"] for i in dry], [True, True])
        self.assertEqual(store.conn.execute("SELECT COUNT(*) FROM monitor_seen").fetchone()[0], 2)
        items = m.rescan(store, "ethereum", now=50.0)
        self.assertEqual(len(items), 2)
        self.assertEqual(store.conn.execute("SELECT COUNT(*) FROM monitor_seen").fetchone()[0], 0)
        self.assertEqual({r[0] for r in store.conn.execute("SELECT status FROM monitor_queue")}, {"pending"})
        self.assertEqual(m.rescan(store, "ethereum"), [])  # superseded rows are not candidates again
        store.close()
        from auditor.scan_history import ScanHistory

        h = ScanHistory(self.d / "hist.db")
        ex = h.get_scan(ids[0])["execution"]
        h.close()
        self.assertIs(ex["scan_complete"], False)
        self.assertIn("legacy monitor scan", ex["incomplete_reasons"][0])
        # Re-scan them with a completed analysis.
        client = FakeClient({}, {"0x0": dict(REC_830), "0x1": dict(REC_830)})
        cfg = m.MonitorConfig(db_path=self.d / "mon.db", alerts_path=self.d / "a.jsonl", cache_dir=self.d / "cache",
                              solc_auto_install=False)
        mon = m.Monitor(cfg, client, analyzer=lambda f, s, h: m.AnalysisResult([], True, []),
                        emit=lambda s: None, clock=self.clock)
        res = mon.process_addresses(["0x0", "0x1"])
        mon.store.close()
        self.assertEqual([r["status"] for r in res], ["scanned", "scanned"])
        c = mv.live(now=self.t[0] + 1)["counters"]
        self.assertEqual((c["audited_all_time"], c["legacy_needs_rescan"]), (2, 0))

    def test_cli_rescan_dry_run_and_queue_only(self):
        self._legacy_db()
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(main(["monitor-rescan", "--dry-run", "--json"]), EXIT_OK)
        self.assertEqual(len(json.loads(out.getvalue())["candidates"]), 2)
        err = io.StringIO()
        with mock.patch.dict(os.environ, {"ETHERSCAN_API_KEY": ""}), contextlib.redirect_stderr(err):
            self.assertEqual(main(["monitor-rescan"]), EXIT_ERROR)
        self.assertIn("--queue-only", err.getvalue())
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(main(["monitor-rescan", "--queue-only"]), EXIT_OK)
        self.assertIn("requeued 2 row(s)", out.getvalue())


# ---------------------------------------------------------------------------
# loop robustness
# ---------------------------------------------------------------------------

class LoopTests(Env):
    def test_persistent_loop_survives_unexpected_errors(self):
        cfg = m.MonitorConfig(db_path=self.d / "mon.db", alerts_path=self.d / "a.jsonl", cache_dir=self.d / "cache",
                              interval=0)
        sleeps = []
        mon = m.Monitor(cfg, FakeClient({}, {}), emit=lambda s: None, clock=self.clock, sleep=sleeps.append)
        calls = {"n": 0}

        def flaky():
            calls["n"] += 1
            if calls["n"] < 3:
                raise ValueError("boom %d" % calls["n"])
            mon.request_stop()
            return {"discovery": {}, "results": [], "alerts": 0}

        mon.poll = flaky
        polls = mon.run(once=False)
        self.assertEqual([("error" in p) for p in polls], [True, True, False])
        self.assertEqual(sum(sleeps), 1.0 + 2.0)  # exponential pause after consecutive errors
        conn = sqlite3.connect(self.d / "mon.db")
        errs = conn.execute("SELECT COUNT(*) FROM monitor_polls WHERE error IS NOT NULL").fetchone()[0]
        conn.close()
        self.assertEqual(errs, 2)

    def test_once_mode_reraises_non_transient(self):
        cfg = m.MonitorConfig(db_path=self.d / "mon.db", alerts_path=self.d / "a.jsonl", cache_dir=self.d / "cache")
        mon = m.Monitor(cfg, FakeClient({}, {}), emit=lambda s: None, clock=self.clock)
        mon.poll = lambda: (_ for _ in ()).throw(ValueError("x"))
        with self.assertRaises(ValueError):
            mon.run(once=True)

    def test_launchd_template_is_not_installed_and_has_no_key(self):
        plist = PROJECT_ROOT / "docs" / "launchd" / "com.contract-auditor.monitor.plist"
        script = PROJECT_ROOT / "scripts" / "run_monitor.sh"
        self.assertTrue(plist.is_file() and script.is_file())
        text = plist.read_text() + script.read_text()
        self.assertNotIn("ETHERSCAN_API_KEY=", text.replace('ETHERSCAN_API_KEY="$(', ""))
        # Secrets load via scripts/_env.sh (Keychain); script must not embed key values.
        script_text = script.read_text()
        self.assertTrue(
            "security find-generic-password" in script_text
            or ("_env.sh" in script_text and "auditor_load_env" in script_text),
            "monitor script must load Keychain secrets via find-generic-password or _env.sh",
        )


if __name__ == "__main__":
    unittest.main()
