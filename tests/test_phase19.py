"""Phase 19 — library-code / known-benign suppression, privileged-withdraw downgrade,
scam/honeypot analyzer, value-at-risk estimates, schema v4, dashboard/CLI surfaces.

Fully mocked: no network (balances, prices and Slither output are fakes),
temp DBs and dirs only. Never runs Slither.
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import sqlite3
import stat
import sys
import tempfile
import unittest
import unittest.mock as mock
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from auditor import compiler_select as cs  # noqa: E402
from auditor import library_code as lc  # noqa: E402
from auditor import monitor as m  # noqa: E402
from auditor import monitor_view as mv  # noqa: E402
from auditor import triage as tr  # noqa: E402
from auditor import value_at_risk as var  # noqa: E402
from auditor.analysis import honeypot as hp  # noqa: E402
from auditor.analysis import slither_runner as sr  # noqa: E402
from auditor.analysis.base import AnalysisContext  # noqa: E402
from auditor.analysis.slither_runner import SlitherRun  # noqa: E402
from auditor.cli import EXIT_ERROR, EXIT_OK, main  # noqa: E402
from auditor.disk_pressure import RESUME_GIB, free_gib  # noqa: E402
from auditor.model import Confidence, Epistemic, EvidenceItem, Finding, Severity  # noqa: E402

KEY = "SECRETKEY1234567890abcdef"

# JUST_play-shaped quiz honeypot (0.8 syntax), as observed live on the Mac.
JUST_PLAY = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract JUST_play {
    function Try(string memory _response) external payable {
        require(msg.sender == tx.origin);
        if (responseHash == keccak256(abi.encode(_response)) && msg.value > 1 ether) {
            payable(msg.sender).transfer(address(this).balance);
        }
    }

    string public question;
    bytes32 responseHash;
    mapping(bytes32 => bool) admin;

    function Start(string calldata _question, string calldata _response) public payable isAdmin {
        if (responseHash == 0x0) {
            responseHash = keccak256(abi.encode(_response));
            question = _question;
        }
    }

    function Stop() public payable isAdmin {
        payable(msg.sender).transfer(address(this).balance);
    }

    function New(string calldata _question, bytes32 _responseHash) public payable isAdmin {
        question = _question;
        responseHash = _responseHash;
    }

    constructor(bytes32[] memory admins) {
        for (uint256 i = 0; i < admins.length; i++) {
            admin[admins[i]] = true;
        }
    }

    modifier isAdmin() {
        require(admin[keccak256(abi.encodePacked(msg.sender))]);
        _;
    }

    fallback() external {}
}
"""

FAIR_QUIZ = """pragma solidity ^0.8.0;
contract FairQuiz {
    bytes32 public responseHash;
    constructor(bytes32 h) payable { responseHash = h; }
    function Try(string memory r) external payable {
        require(msg.value >= 0.1 ether);
        if (responseHash == keccak256(abi.encode(r))) { payable(msg.sender).transfer(address(this).balance); }
    }
}
"""

# Minimal synthetic stand-in for OpenZeppelin ERC1967Utils (same names/shape).
ERC1967 = """// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts (last updated v5.0.0) (proxy/ERC1967/ERC1967Utils.sol)
pragma solidity ^0.8.20;

library ERC1967Utils {
    error ERC1967NonPayable();
    function upgradeToAndCall(address newImplementation, bytes memory data) internal {
        if (data.length > 0) {
            Address.functionDelegateCall(newImplementation, data);
        } else {
            _checkNonPayable();
        }
    }
    function upgradeBeaconToAndCall(address newBeacon, bytes memory data) internal {
        if (data.length > 0) {
            Address.functionDelegateCall(newBeacon, data);
        } else {
            _checkNonPayable();
        }
    }
    function _checkNonPayable() private {
        if (msg.value > 0) {
            revert ERC1967NonPayable();
        }
    }
}
"""

TOKEN_COPY = """pragma solidity ^0.8.0;
contract Copycat {
    mapping(address => uint256) private _balances;
    constructor() payable { _balances[msg.sender] = 1000; }
    function balanceOf(address a) public view returns (uint256) { return _balances[a]; }
    function transfer(address to, uint256 amount) public returns (bool) { _transfer(msg.sender, to, amount); return true; }
    function _transfer(address from, address to, uint256 amount) internal { _balances[from] -= amount; _balances[to] += amount; }
}
"""


def _std_json(sources: dict) -> str:
    return "{" + json.dumps({"language": "Solidity", "sources": {k: {"content": v} for k, v in sources.items()},
                             "settings": {"optimizer": {"enabled": False, "runs": 200}}}) + "}"


def _det(check, impact, contract, function, filename, lines=(5, 6), conf="Medium"):
    return {"check": check, "impact": impact, "confidence": conf,
            "description": f"{contract}.{function}() ({filename}#{lines[0]}) {check}\n",
            "elements": [{"type": "function", "name": function,
                          "source_mapping": {"filename": filename, "lines": list(lines)},
                          "type_specific_fields": {"parent": {"type": "contract", "name": contract}}}]}


def _finding(title, contract, function, file=None, sev=Severity.HIGH, desc="", category="security"):
    return Finding(title=title, description=desc or f"Slither detector: {title.split()[0]}.", category=category,
                   severity=sev, confidence=Confidence.MEDIUM, affected_contract=contract,
                   affected_function=function, affected_file=file,
                   evidence=[EvidenceItem(source="slither", artifact_type="tool_output", excerpt=title,
                                          epistemic=Epistemic.FACT, tool="slither")])


def _write(root: Path, files: dict) -> list:
    out = []
    for rel, text in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
        out.append(p)
    return out


class Env(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.d = Path(self.tmp.name)
        self.art = self.d / "artifacts"
        self.env = mock.patch.dict(os.environ, {
            "AUDITOR_MONITOR_DB": str(self.d / "mon.db"), "AUDITOR_MONITOR_ALERTS": str(self.d / "a.jsonl"),
            "AUDITOR_MONITOR_CACHE": str(self.d / "cache"), "AUDITOR_HISTORY_DB": str(self.d / "hist.db"),
            "AUDITOR_SOLC_ARTIFACTS": str(self.art), "AUDITOR_SOLC_AUTO_INSTALL": "0",
            "AUDITOR_PRICE_CACHE": str(self.d / "prices.json")})
        self.env.start()
        self.t = [1_760_000_000.0]

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
# library recognition
# ---------------------------------------------------------------------------

class LibraryRecognitionTests(Env):
    def test_shipped_manifest_covers_common_oz_releases(self):
        man = lc.load_manifest()
        self.assertIn("ERC1967Utils", man["names"])
        versions = lc.iter_versions(man["blocks"].values())
        for v in ("4.9.6", "5.0.2", "5.4.0"):
            self.assertIn(v, versions)
        self.assertTrue(any(e["name"] == "ERC1967Utils" for e in man["blocks"].values()))

    def test_hash_level_match_via_manifest(self):
        lib = _write(self.d / "up", {"proxy/ERC1967/ERC1967Utils.sol": ERC1967})
        blocks, files, names = {}, {}, set()
        lc.build_manifest_entries(self.d / "up", "openzeppelin", "9.9.9", blocks, files, names)
        mp = self.d / "man.json"
        mp.write_text(json.dumps({"blocks": blocks, "names": sorted(names)}))
        # flattened, reformatted whitespace + different comments: still hash-equal
        flat = "pragma solidity ^0.8.20;\n// flattened\n" + ERC1967.replace("    ", "\t").replace(
            "// OpenZeppelin Contracts (last updated v5.0.0) (proxy/ERC1967/ERC1967Utils.sol)", "/* x */")
        files_ = _write(self.d / "scan", {"Flat.sol": flat})
        idx = lc.SourceIndex(files_, self.d / "scan", manifest_path=str(mp))
        res = idx.classify("ERC1967Utils", None, "Proxy")
        self.assertTrue(res.is_library)
        self.assertEqual(res.level, "hash")
        self.assertIn("9.9.9", res.version)
        # a modified body no longer hash-matches (and has no header/path): not library
        files2 = _write(self.d / "scan2", {"Flat.sol": flat.replace("msg.value > 0", "msg.value > 1")})
        idx2 = lc.SourceIndex(files2, self.d / "scan2", manifest_path=str(mp))
        self.assertFalse(idx2.classify("ERC1967Utils").is_library)
        del lib

    def test_heuristic_vendored_path_pragma_symbol(self):
        files = _write(self.d, {"@openzeppelin/contracts/proxy/ERC1967/ERC1967Utils.sol": ERC1967.replace(
            "msg.value > 0", "msg.value > 0 && true"),  # not hash-identical
            "contracts/Proxy.sol": "pragma solidity ^0.8.20;\ncontract Proxy {}\n"})
        idx = lc.SourceIndex(files, self.d)
        res = idx.classify("ERC1967Utils", "@openzeppelin/contracts/proxy/ERC1967/ERC1967Utils.sol", "Proxy")
        self.assertEqual((res.is_library, res.level, res.package), (True, "heuristic", "openzeppelin"))
        self.assertIn("not hash-verified", res.detail)

    def test_not_library_cases(self):
        files = _write(self.d, {
            "contracts/ERC1967Utils.sol": "pragma solidity ^0.8.20;\nlibrary ERC1967Utils { function f() internal {} }\n",
            "@openzeppelin/contracts/Evil.sol": "pragma solidity ^0.8.20;\ncontract Evil { function f() public {} }\n",
            "@openzeppelin/contracts/token/ERC20/ERC20.sol": "pragma solidity ^0.8.20;\ncontract ERC20 {}\n"})
        idx = lc.SourceIndex(files, self.d)
        self.assertFalse(idx.classify("ERC1967Utils", "contracts/ERC1967Utils.sol").is_library)  # own code
        self.assertFalse(idx.classify("Evil", "@openzeppelin/contracts/Evil.sol").is_library)     # unknown symbol
        # the deployed contract itself is never library code, even under a vendored path
        self.assertTrue(idx.classify("ERC20", "@openzeppelin/contracts/token/ERC20/ERC20.sol").is_library)
        self.assertFalse(idx.classify("ERC20", "@openzeppelin/contracts/token/ERC20/ERC20.sol", "ERC20").is_library)
        self.assertFalse(idx.classify(None).is_library)

    def test_flattened_oz_header_heuristic(self):
        text = "pragma solidity ^0.8.20;\n" + ERC1967.replace("msg.value > 0", "msg.value != 0") + TOKEN_COPY.split("\n", 1)[1]
        files = _write(self.d, {"Copycat.sol": text})
        idx = lc.SourceIndex(files, self.d)
        self.assertEqual(idx.classify("ERC1967Utils", None, "Copycat").level, "heuristic")
        self.assertFalse(idx.classify("Copycat", None, "Copycat").is_library)

    def test_solmate_and_solady_paths(self):
        self.assertEqual(lc.library_package("lib/solmate/src/tokens/ERC20.sol"), "solmate")
        self.assertEqual(lc.library_package("solady/src/utils/SafeTransferLib.sol"), "solady")
        self.assertEqual(lc.library_package("lib/openzeppelin-contracts/contracts/access/Ownable.sol"), "openzeppelin")
        self.assertIsNone(lc.library_package("src/MyVault.sol"))
        files = _write(self.d, {"lib/solmate/src/tokens/ERC20.sol": "pragma solidity >=0.8.0;\nabstract contract ERC20 {}\n"})
        self.assertEqual(lc.SourceIndex(files, self.d).classify("ERC20", "lib/solmate/src/tokens/ERC20.sol").level,
                         "heuristic")


# ---------------------------------------------------------------------------
# triage rules
# ---------------------------------------------------------------------------

class TriageTests(Env):
    def _files(self, extra=None):
        files = {"@openzeppelin/contracts/proxy/ERC1967/ERC1967Utils.sol": ERC1967, "contracts/JUST_play.sol": JUST_PLAY}
        files.update(extra or {})
        return _write(self.d, files)

    def test_library_finding_suppressed_project_finding_kept(self):
        files = self._files()
        lib_f = _finding("divide-before-multiply in ERC1967Utils.upgradeToAndCall", "ERC1967Utils",
                         "upgradeToAndCall", "@openzeppelin/contracts/proxy/ERC1967/ERC1967Utils.sol", Severity.MEDIUM)
        own = _finding("reentrancy-eth in JUST_play.Try", "JUST_play", "Try", "contracts/JUST_play.sol")
        res = tr.triage([lib_f, own], files, self.d, "JUST_play")
        self.assertEqual(res.kept, [own])
        self.assertEqual(res.suppressed[0][1].reason, tr.SUPPRESS_LIBRARY)
        self.assertEqual(res.summary()["suppressed_by_reason"], {"library-code": 1})
        d = res.suppressed_dicts()[0]
        self.assertEqual(d["triage"]["reason"], "library-code")
        self.assertEqual(d["severity"], "MEDIUM")

    def test_known_benign_erc1967_rules_check_the_body(self):
        files = _write(self.d, {"src/ERC1967Utils.sol": ERC1967})  # NOT under a vendored path
        f1 = _finding("msg-value-in-nonpayable in ERC1967Utils._checkNonPayable", "ERC1967Utils", "_checkNonPayable",
                      sev=Severity.HIGH)
        f2 = _finding("unused-return in ERC1967Utils.upgradeToAndCall", "ERC1967Utils", "upgradeToAndCall",
                      sev=Severity.MEDIUM)
        f3 = _finding("unused-return in ERC1967Utils.upgradeBeaconToAndCall", "ERC1967Utils", "upgradeBeaconToAndCall",
                      sev=Severity.MEDIUM)
        res = tr.triage([f1, f2, f3], files, self.d)
        self.assertEqual(res.kept, [])
        self.assertEqual({r.rule for _, r in res.suppressed},
                         {"oz-erc1967-checknonpayable", "oz-erc1967-upgrade-unused-return"})
        self.assertTrue(all(r.reason == tr.SUPPRESS_BENIGN for _, r in res.suppressed))
        # same names, body that does NOT revert on msg.value: rule must not fire
        no_header = "\n".join(x for x in ERC1967.splitlines() if "OpenZeppelin Contracts" not in x)
        files2 = _write(self.d / "b", {"src/ERC1967Utils.sol": no_header.replace(
            "if (msg.value > 0) {\n            revert ERC1967NonPayable();\n        }", "uint256 v = msg.value;")})
        res2 = tr.triage([_finding("msg-value-in-nonpayable in ERC1967Utils._checkNonPayable", "ERC1967Utils",
                                   "_checkNonPayable")], files2, self.d / "b")
        self.assertEqual(len(res2.kept), 1)
        # other detectors on the same function are not covered by the rule
        files3 = _write(self.d / "c", {"src/ERC1967Utils.sol": no_header})  # no header/vendored path
        res3 = tr.triage([_finding("reentrancy-eth in ERC1967Utils._checkNonPayable", "ERC1967Utils",
                                   "_checkNonPayable")], files3, self.d / "c")
        self.assertEqual(len(res3.kept), 1)
        # with the OZ header comment the same finding is library-code (heuristic level)
        res4 = tr.triage([_finding("reentrancy-eth in ERC1967Utils._checkNonPayable", "ERC1967Utils",
                                   "_checkNonPayable")], files, self.d)
        self.assertEqual(res4.suppressed[0][1].rule, "library:heuristic")

    def test_privileged_withdraw_downgraded_just_play_stop(self):
        files = self._files()
        f = _finding("arbitrary-send-eth in JUST_play.Stop", "JUST_play", "Stop", "contracts/JUST_play.sol")
        res = tr.triage([f], files, self.d, "JUST_play")
        self.assertEqual(res.kept, [f])
        self.assertEqual(f.severity, Severity.INFORMATIONAL)
        rec = res.record_for(f)
        self.assertEqual((rec.action, rec.reason, rec.original_severity), ("downgraded", "privileged-withdraw", "HIGH"))
        self.assertIn("modifier isAdmin", rec.detail)
        self.assertTrue(any("privileged-withdraw" in c for c in f.contradicting_evidence))

    def _priv_case(self, body, modifier="modifier onlyOwner() { require(msg.sender == owner); _; }"):
        src = ("pragma solidity ^0.8.0;\ncontract V {\n address owner; address payable treasury;\n "
               + modifier + "\n function w() public " + body + "\n}\n")
        files = _write(self.d / "p", {"V.sol": src})
        f = _finding("arbitrary-send-eth in V.w", "V", "w")
        tr.triage([f], files, self.d / "p")
        return f.severity

    def test_privileged_withdraw_negative_cases(self):
        # no guard at all
        self.assertEqual(self._priv_case("{ payable(msg.sender).transfer(address(this).balance); }"), Severity.HIGH)
        # guarded, pays someone else: Phase 20 privileged-module-caller (owner-gated) → INFORMATIONAL
        self.assertEqual(self._priv_case("onlyOwner { treasury.transfer(address(this).balance); }"),
                         Severity.INFORMATIONAL)
        # modifier named onlyOwner that does not check msg.sender
        self.assertEqual(self._priv_case("onlyOwner { payable(msg.sender).transfer(1); }",
                                         "modifier onlyOwner() { _; }"), Severity.HIGH)
        # tx.origin guard never counts
        self.assertEqual(self._priv_case("onlyOwner { payable(msg.sender).transfer(1); }",
                                         "modifier onlyOwner() { require(tx.origin == owner); _; }"), Severity.HIGH)
        # positive: inline guard
        self.assertEqual(self._priv_case("{ require(msg.sender == owner); payable(msg.sender).transfer(1); }"),
                         Severity.INFORMATIONAL)

    def test_scam_findings_never_suppressed(self):
        files = self._files()
        f = _finding("quiz-honeypot in ERC1967Utils.upgradeToAndCall", "ERC1967Utils", "upgradeToAndCall",
                     "@openzeppelin/contracts/proxy/ERC1967/ERC1967Utils.sol", category="scam/honeypot")
        self.assertEqual(tr.triage([f], files, self.d).kept, [f])

    def test_triage_fails_open(self):
        f = _finding("x-y in A.b", "A", "b")
        with mock.patch.object(tr, "triage", side_effect=RuntimeError("boom")):
            notes = []
            res = tr.apply_to_pipeline([f], [], None, None, notes.append)
        self.assertEqual(res.kept, [f])
        self.assertIn("triage skipped", notes[0])


# ---------------------------------------------------------------------------
# honeypot analyzer
# ---------------------------------------------------------------------------

def _hp(files, root=None, main=None):
    ctx = AnalysisContext()
    ctx.source_files = list(files)
    ctx.options = {"scope": "standard", "main_contract": main, "source_root": str(root) if root else None}
    return hp.analyze(ctx).findings


class HoneypotTests(Env):
    def test_just_play_quiz_honeypot(self):
        fs = _hp(_write(self.d, {"JUST_play.sol": JUST_PLAY}))
        quiz = [f for f in fs if f.title.startswith("quiz-honeypot")]
        self.assertEqual(len(quiz), 1)
        f = quiz[0]
        self.assertEqual((f.affected_contract, f.affected_function), ("JUST_play", "Try"))
        self.assertEqual((f.category, f.severity, f.confidence), ("scam/honeypot", Severity.HIGH, Confidence.HIGH))
        self.assertIn("RISK TO USERS WHO INTERACT", f.description)
        self.assertIn("not an exploitable bug", f.description)
        for name in ("New", "Stop", "Start"):
            self.assertIn(name, f.description)
        self.assertIn("tx.origin", f.description)
        self.assertIn("Source detector: quiz-honeypot.", f.description)
        self.assertTrue(f.fact_evidence)
        f.validate()
        from auditor.risk_playbook import classify

        self.assertEqual(classify(f.to_dict())[0], "scam_honeypot")

    def test_fair_quiz_is_clean(self):
        self.assertEqual(_hp(_write(self.d, {"Q.sol": FAIR_QUIZ})), [])

    def test_external_log_gate_private_bank(self):
        src = Path(__file__).resolve().parents[1] / "benchmarks/fixtures/HONEY-003-vulnerable.sol"
        fs = _hp([src])
        hits = [f for f in fs if f.title.startswith("external-log-gate")]
        self.assertEqual(len(hits), 1)
        f = hits[0]
        self.assertEqual((f.affected_contract, f.affected_function), ("PrivateBankHoneypot", "Collect"))
        self.assertEqual(f.category, "scam/honeypot")
        self.assertIn("Source detector: external-log-gate.", f.description)
        self.assertIn("RISK TO USERS WHO INTERACT", f.description)
        from auditor.risk_playbook import classify
        self.assertEqual(classify(f.to_dict())[0], "scam_honeypot")
        safe = Path(__file__).resolve().parents[1] / "benchmarks/fixtures/HONEY-004-safe.sol"
        self.assertEqual([x for x in _hp([safe]) if x.title.startswith("external-log-gate")], [])


    def test_payout_lure_and_hidden_owner(self):
        src = """pragma solidity ^0.8.0;
contract Gift {
    address payable owner;
    function GetGift() public payable {
        if (msg.value > 1 ether) { owner.transfer(address(this).balance); payable(msg.sender).transfer(address(this).balance); }
    }
    function sweep() public {
        require(msg.sender == 0x1111111111111111111111111111111111111111);
        payable(msg.sender).transfer(address(this).balance);
    }
}
"""
        slugs = sorted(f.title.split()[0] for f in _hp(_write(self.d, {"G.sol": src})))
        self.assertEqual(slugs, ["hidden-owner-drain", "payout-lure"])

    def test_transfer_blocking_and_owner_mint(self):
        src = """pragma solidity ^0.8.0;
contract Rug {
    mapping(address => uint256) _balances; mapping(address => bool) isBot; address owner; address pair;
    modifier onlyOwner() { require(msg.sender == owner); _; }
    function balanceOf(address a) public view returns (uint256) { return _balances[a]; }
    function setBot(address a, bool v) external onlyOwner { isBot[a] = v; }
    function mint(address to, uint256 amount) external onlyOwner { _mint(to, amount); }
    function _mint(address to, uint256 amount) internal { _balances[to] += amount; }
    function transfer(address to, uint256 amount) public returns (bool) { _transfer(msg.sender, to, amount); return true; }
    function _transfer(address from, address to, uint256 amount) internal {
        require(!isBot[from]);
        require(to != pair || from == owner);
        _balances[from] -= amount; _balances[to] += amount;
    }
}
"""
        fs = {f.title.split()[0]: f for f in _hp(_write(self.d, {"R.sol": src}))}
        self.assertEqual(set(fs), {"transfer-blocking-token", "unlimited-owner-mint"})
        self.assertEqual(fs["transfer-blocking-token"].confidence, Confidence.MEDIUM)
        capped = src.replace("{ _mint(to, amount); }", "{ require(totalSupply + amount <= MAX_SUPPLY); _mint(to, amount); }")
        fs2 = {f.title.split()[0] for f in _hp(_write(self.d / "c", {"R.sol": capped}))}
        self.assertNotIn("unlimited-owner-mint", fs2)

    def test_recognised_library_code_is_skipped(self):
        pausable = ("pragma solidity ^0.8.20;\nabstract contract ERC20Pausable {\n mapping(address=>bool) blocked;"
                    " address owner; mapping(address => uint256) _balances;\n"
                    " modifier onlyOwner() { require(msg.sender == owner); _; }\n"
                    " function balanceOf(address a) public view returns (uint256) { return _balances[a]; }\n"
                    " function block_(address a) external onlyOwner { blocked[a] = true; }\n"
                    " function _update(address from, address to, uint256 v) internal { require(!blocked[from]); }\n}\n")
        path = "@openzeppelin/contracts/token/ERC20/extensions/ERC20Pausable.sol"
        files = _write(self.d, {path: pausable, "contracts/T.sol": "pragma solidity ^0.8.20;\ncontract T {}\n"})
        # Path + name alone are attacker-controlled (standard-JSON paths, header comments):
        # the scam detector only skips HASH-verified upstream code.
        self.assertEqual(len(_hp(files, self.d, "T")), 1)
        blocks, fh, names = {}, {}, set()
        lc.build_manifest_entries(self.d / "@openzeppelin/contracts", "openzeppelin", "t", blocks, fh, names)
        with mock.patch.object(lc, "load_manifest", return_value={"blocks": blocks, "names": sorted(names)}):
            self.assertEqual(_hp(files, self.d, "T"), [])

    def test_benchmark_fixtures(self):
        fx = PROJECT_ROOT / "benchmarks" / "fixtures"
        got = {n: [f.title.split()[0] for f in _hp([fx / f"{n}.sol"])]
               for n in ("HONEY-001-vulnerable", "HONEY-002-safe", "HONEY-003-vulnerable", "HONEY-004-safe",
                         "SCAM-001-vulnerable", "SCAM-002-safe")}
        self.assertEqual(got, {"HONEY-001-vulnerable": ["quiz-honeypot"], "HONEY-002-safe": [],
                               "HONEY-003-vulnerable": ["external-log-gate"], "HONEY-004-safe": [],
                               "SCAM-001-vulnerable": ["transfer-blocking-token"], "SCAM-002-safe": []})

    def test_descriptions_are_defensive(self):
        fs = _hp(_write(self.d, {"JUST_play.sol": JUST_PLAY}))
        for f in fs:
            low = f.description.lower()
            for banned in ("step 1", "payload", "exploit code", "to exploit"):
                self.assertNotIn(banned, low)


# ---------------------------------------------------------------------------
# value at risk
# ---------------------------------------------------------------------------

PRICES = {"ethereum": {"usd": 3000.0, "last_updated_at": 1_759_999_900}, "weth": {"usd": 3000.0},
          "usd-coin": {"usd": 1.0}, "tether": {"usd": 1.0}, "dai": {"usd": 1.0},
          "wrapped-bitcoin": {"usd": 60000.0}, "staked-ether": {"usd": 2990.0}}


class FakeBalances:
    def __init__(self, native=0, tokens=None, fail=()):
        self.native, self.tokens, self.fail = native, tokens or {}, set(fail)

    def native_balance(self, a):
        if "ETH" in self.fail:
            raise m.TransientError("down")
        return self.native

    def token_balance(self, t, a):
        sym = next(s for s, x in var.TOKENS.items() if x["address"] == t)
        if sym in self.fail:
            raise m.TransientError("down")
        return self.tokens.get(sym, 0)


class FakePrices:
    def __init__(self, prices=None, as_of=1_759_999_900.0):
        self.p, self.as_of = prices, as_of

    def prices(self, ids):
        if self.p is None:
            return {"prices": {i: None for i in ids}, "as_of": None, "source": None, "stale": False,
                    "error": "price source unavailable"}
        return {"prices": {i: (self.p.get(i) or {}).get("usd") for i in ids}, "as_of": self.as_of,
                "source": "test", "stale": False, "error": None}


class ValueTests(Env):
    def test_price_source_caches_and_degrades(self):
        calls = []

        def http(url, timeout):
            calls.append(url)
            return json.dumps(PRICES).encode()

        now = [1000.0]
        ps = var.PriceSource(self.d / "p.json", http_get=http, clock=lambda: now[0])
        ids = ["ethereum", "usd-coin"]
        r = ps.prices(ids)
        self.assertEqual(r["prices"], {"ethereum": 3000.0, "usd-coin": 1.0})
        self.assertTrue(calls[0].startswith(var.COINGECKO_URL + "?"))
        self.assertNotIn("key", calls[0].lower())
        ps.prices(ids)
        self.assertEqual(len(calls), 1)  # cached within TTL
        now[0] += var.PRICE_TTL_S + 1

        def down(url, timeout):
            raise OSError("offline")

        ps.http_get = down
        r2 = ps.prices(ids)
        self.assertTrue(r2["stale"])
        self.assertEqual(r2["prices"]["ethereum"], 3000.0)
        now[0] += var.PRICE_MAX_STALE_S + 1
        r3 = ps.prices(ids)
        self.assertEqual(r3["prices"], {"ethereum": None, "usd-coin": None})
        self.assertIsNone(r3["as_of"])

    def test_tvl_math_and_partial_data(self):
        raw = var.fetch_holdings(FakeBalances(2 * 10**18, {"USDC": 1_000 * 10**6, "WBTC": 10**8 // 2}), "0xAB")
        v = var.value_contract(raw, FakePrices(PRICES).prices(["ethereum"] + [t["price_id"] for t in var.TOKENS.values()]))
        self.assertAlmostEqual(v.tvl_usd, 2 * 3000 + 1000 + 30000)
        self.assertAlmostEqual(v.native_usd, 6000)
        self.assertTrue(v.complete)
        # one balance unavailable: lower bound, flagged
        raw2 = var.fetch_holdings(FakeBalances(10**18, {}, fail={"USDT"}), "0xab")
        ids = ["ethereum"] + [t["price_id"] for t in var.TOKENS.values()]
        v2 = var.value_contract(raw2, FakePrices(PRICES).prices(ids))
        self.assertFalse(v2.complete)
        self.assertAlmostEqual(v2.tvl_usd, 3000)
        self.assertTrue(any("lower bound" in n for n in v2.notes))
        # prices down: amounts kept, USD unknown
        v3 = var.value_contract(raw, FakePrices(None).prices(["ethereum"]))
        self.assertIsNone(v3.tvl_usd)
        self.assertEqual([h["symbol"] for h in v3.holdings if h["amount"]], ["ETH", "USDC", "WBTC"])
        # proxy: proxy's own balance, noted
        v4 = var.value_contract(raw, FakePrices(PRICES).prices(ids), {"Proxy": "1", "Implementation": "0xImpl"})
        self.assertTrue(v4.is_proxy)
        self.assertEqual(v4.implementation, "0xImpl")

    def _v(self, tvl=1_000_000.0, native=400.0):
        v = var.ValueAtRisk("0xa", tvl_usd=tvl, native_usd=native)
        return v

    def test_per_finding_estimates(self):
        v = self._v()
        reent = var.estimate_finding({"title": "Reentrancy vulnerability in A.f",
                                      "description": "Slither detector: reentrancy-eth.", "severity": "HIGH"}, v)
        self.assertEqual((reent["model"], reent["est_loss_usd"], reent["est_loss_low_usd"], reent["est_loss_high_usd"]),
                         ("drain_all", 500_000.0, 100_000.0, 1_000_000.0))
        self.assertTrue(reent["is_estimate"])
        locked = var.estimate_finding({"title": "locked-ether in T.constructor", "severity": "MEDIUM"}, v)
        self.assertEqual((locked["model"], locked["est_loss_usd"]), ("locked", 400.0))
        priv = var.estimate_finding({"title": "arbitrary-send-eth in J.Stop", "severity": "INFORMATIONAL"}, v,
                                    {"reason": "privileged-withdraw"})
        self.assertEqual((priv["est_loss_usd"], priv["owner_rug_exposure_usd"]), (0.0, 1_000_000.0))
        honey = var.estimate_finding({"title": "quiz-honeypot in J.Try", "description": "Source detector: quiz-honeypot.",
                                      "severity": "HIGH"}, self._v(tvl=2500.0))
        self.assertTrue(honey["user_funds_at_risk"])
        self.assertEqual(honey["bait_balance_usd"], 2500.0)
        unknown = var.estimate_finding({"title": "x-y in A.b", "severity": "LOW"}, None)
        self.assertIsNone(unknown["est_loss_usd"])
        self.assertTrue(any("unknown" in a for a in unknown["assumptions"]))

    def test_severity_weighted_ranking(self):
        big_med = var.weighted_score(1_000_000, "MEDIUM")
        small_high = var.weighted_score(400, "HIGH")
        self.assertGreater(big_med, small_high)
        self.assertGreater(var.weighted_score(1000, "HIGH"), var.weighted_score(1000, "LOW"))
        self.assertGreater(var.weighted_score(None, "HIGH"), var.weighted_score(None, "LOW"))
        rows = sorted([("small", small_high), ("big", big_med)], key=lambda r: -r[1])
        self.assertEqual(rows[0][0], "big")

    def test_playbook_exposure_blocks(self):
        from auditor.risk_playbook import load_playbook

        pb = load_playbook()
        for name, e in pb["classes"].items():
            x = e.get("exposure")
            self.assertIsNotNone(x, name)
            self.assertTrue(0.0 <= x["low"] <= x["factor"] <= x["high"] <= 1.0 or x["model"] == "honeypot", name)
            self.assertTrue(x["assumption"].strip(), name)
        self.assertIn("scam_honeypot", pb["classes"])

    def test_chain_client_balance_requests_are_read_only_get(self):
        seen = []

        def http(req, timeout):
            seen.append(req)
            q = req.full_url
            if "action=balance" in q:
                return json.dumps({"status": "1", "result": "1500000000000000000"}).encode()
            return json.dumps({"status": "1", "result": "2500000"}).encode()

        c = m.ChainClient(KEY, 1, http=http, sleep=lambda s: None, min_interval=0)
        self.assertEqual(c.native_balance("0x" + "ab" * 20), 1_500_000_000_000_000_000)
        self.assertEqual(c.token_balance(var.TOKENS["USDC"]["address"], "0x" + "ab" * 20), 2_500_000)
        self.assertTrue(all(r.get_method() == "GET" for r in seen))
        self.assertIn("module=account", seen[1].full_url)
        self.assertIn("action=tokenbalance", seen[1].full_url)
        with self.assertRaises(m.MonitorError):
            c.native_balance("0xnot-an-address")

    def test_chain_client_rpc_eth_call_balanceof(self):
        bodies = []

        def http(req, timeout):
            bodies.append(json.loads(req.data.decode()))
            if bodies[-1]["method"] == "eth_getBalance":
                return json.dumps({"jsonrpc": "2.0", "id": 1, "result": "0x10"}).encode()
            return json.dumps({"jsonrpc": "2.0", "id": 1, "result": "0x" + "0" * 63 + "f"}).encode()

        c = m.ChainClient(KEY, 1, rpc_url="https://rpc.example/" + KEY, http=http, sleep=lambda s: None, min_interval=0)
        self.assertEqual(c.native_balance("0x" + "cd" * 20), 16)
        self.assertEqual(c.token_balance(var.TOKENS["DAI"]["address"], "0x" + "cd" * 20), 15)
        self.assertEqual(bodies[1]["method"], "eth_call")
        self.assertTrue(bodies[1]["params"][0]["data"].startswith("0x70a08231"))
        self.assertIn("eth_call", m.READ_ONLY_RPC)
        with self.assertRaises(m.MonitorError):
            c._rpc("eth_sendRawTransaction", ["0x"])


# ---------------------------------------------------------------------------
# monitor integration (mocked Slither + chain + prices)
# ---------------------------------------------------------------------------

class FakeChain(FakeBalances):
    def __init__(self, sources, native=0, tokens=None):
        super().__init__(native, tokens)
        self.sources = sources

    def block_number(self):
        return 10

    def contract_creations(self, block):
        return [{"address": a, "tx_hash": "0xt", "block": block} for a in (["0xa"] if block == 6 else [])]

    def verified_source(self, address):
        return self.sources.get(address)


def _fake_solc(root: Path, version: str) -> Path:
    p = cs.artifact_path(version, root)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text("#!/bin/sh\necho fake solc\n")
    p.chmod(p.stat().st_mode | stat.S_IEXEC)
    return p


OZ_PATH = "@openzeppelin/contracts/proxy/ERC1967/ERC1967Utils.sol"
REC = {"SourceCode": _std_json({"contracts/JUST_play.sol": JUST_PLAY, OZ_PATH: ERC1967}),
       "ContractName": "JUST_play", "CompilerVersion": "v0.8.30+commit.73712a01",
       "OptimizationUsed": "0", "Runs": "200", "EVMVersion": "Default"}
DETECTORS = [
    _det("arbitrary-send-eth", "High", "JUST_play", "Stop", "contracts/JUST_play.sol", (23, 25)),
    _det("msg-value-in-nonpayable", "High", "ERC1967Utils", "_checkNonPayable", OZ_PATH, (20, 24)),
    _det("unused-return", "Medium", "ERC1967Utils", "upgradeToAndCall", OZ_PATH, (7, 13)),
    _det("unused-return", "Medium", "ERC1967Utils", "upgradeBeaconToAndCall", OZ_PATH, (14, 19)),
    _det("divide-before-multiply", "Medium", "ERC1967Utils", "upgradeToAndCall", OZ_PATH, (7, 13)),
]


class MonitorIntegrationTests(Env):
    def _monitor(self, chain, prices=PRICES, **kw):
        cfg = m.MonitorConfig(db_path=self.d / "mon.db", alerts_path=self.d / "a.jsonl",
                              cache_dir=self.d / "cache", interval=0, start_lookback=5,
                              solc_auto_install=False, **kw)
        return m.Monitor(cfg, chain, emit=lambda s: None, clock=self.clock, sleep=lambda s: None,
                         price_source=FakePrices(prices))

    def _run(self, native=5 * 10**18, tokens=None, **kw):
        _fake_solc(self.art, "0.8.30")
        chain = FakeChain({"0xa": dict(REC)}, native, tokens)
        mon = self._monitor(chain, **kw)
        with mock.patch.object(sr, "run_slither", return_value=SlitherRun(status="completed", detectors=DETECTORS)):
            return mon.run(once=True)[0]["results"][0]

    def _db(self):
        conn = sqlite3.connect(self.d / "mon.db")
        conn.row_factory = sqlite3.Row
        return conn

    def setUp(self):
        # All five tests in this class assert a processed scan; skip them at once
        # whenever the real disk-pressure gate would defer heavy scans.
        self._skip_if_disk_gated()
        super().setUp()

    def test_end_to_end_triage_honeypot_value(self):
        r = self._run()
        self.assertEqual(r["status"], "scanned")
        self.assertEqual(r["suppressed"], 4)  # 2 known-benign + 1 known-benign + 1 library-code
        conn = self._db()
        scan = conn.execute("SELECT * FROM monitor_scans").fetchone()
        rows = [dict(x) for x in conn.execute("SELECT * FROM monitor_findings ORDER BY id")]
        conn.close()
        by = {(x["detector"], x["function"]): x for x in rows}
        stop = by[("arbitrary-send-eth", "Stop")]
        self.assertEqual((stop["severity"], stop["original_severity"], stop["triage_reason"], stop["suppressed"]),
                         ("INFORMATIONAL", "HIGH", "privileged-withdraw", 0))
        self.assertEqual(stop["est_loss_usd"], 0.0)
        self.assertEqual(json.loads(stop["estimate_json"])["owner_rug_exposure_usd"], 15000.0)
        quiz = by[("quiz-honeypot", "Try")]
        self.assertEqual((quiz["severity"], quiz["category"], quiz["suppressed"]), ("HIGH", "scam/honeypot", 0))
        self.assertEqual(quiz["est_loss_usd"], 15000.0)  # bait balance 5 ETH x $3000
        self.assertTrue(json.loads(quiz["estimate_json"])["user_funds_at_risk"])
        sup = {(x["detector"], x["function"]): x["triage_reason"] for x in rows if x["suppressed"]}
        self.assertEqual(sup, {("msg-value-in-nonpayable", "_checkNonPayable"): "known-benign",
                               ("unused-return", "upgradeToAndCall"): "known-benign",
                               ("unused-return", "upgradeBeaconToAndCall"): "known-benign",
                               ("divide-before-multiply", "upgradeToAndCall"): "library-code"})
        self.assertEqual((scan["tvl_usd"], scan["est_max_loss_usd"], scan["suppressed_count"], scan["findings"]),
                         (15000.0, 15000.0, 4, 2))
        self.assertEqual(json.loads(scan["severity_counts"]), {"HIGH": 1, "INFORMATIONAL": 1})
        self.assertEqual(scan["user_funds_at_risk"], 1)
        # history keeps the kept findings + value/triage in the execution record
        from auditor.scan_history import ScanHistory

        h = ScanHistory(self.d / "hist.db")
        rec = h.get_scan(scan["scan_id"])
        hf = h.get_findings(scan["scan_id"])
        h.close()
        self.assertEqual(len(hf), 2)
        self.assertEqual(rec["execution"]["triage"]["suppressed"], 4)
        self.assertEqual(rec["execution"]["value_at_risk"]["summary"]["tvl_usd"], 15000.0)
        # alerts: only the HIGH honeypot (Stop was downgraded) with value fields
        alerts = [json.loads(x) for x in (self.d / "a.jsonl").read_text().splitlines()]
        self.assertEqual([a["title"].split()[0] for a in alerts], ["quiz-honeypot"])
        a = alerts[0]
        self.assertEqual((a["tvl_usd"], a["est_loss_usd"], a["value_is_estimate"], a["user_funds_at_risk"]),
                         (15000.0, 15000.0, True, True))
        self.assertEqual(a["category"], "scam/honeypot")
        self.assertNotIn(KEY, json.dumps(alerts))

    def test_min_value_usd_threshold(self):
        # A HIGH non-honeypot finding under the threshold is not alerted; honeypot always is.
        dets = [_det("controlled-delegatecall", "High", "JUST_play", "Try", "contracts/JUST_play.sol")]
        _fake_solc(self.art, "0.8.30")
        mon = self._monitor(FakeChain({"0xa": dict(REC)}, 10**17), min_value_usd=1_000_000.0)
        with mock.patch.object(sr, "run_slither", return_value=SlitherRun(status="completed", detectors=dets)):
            r = mon.run(once=True)[0]["results"][0]
        titles = sorted(a["title"].split()[0] for a in r["alerts"])
        self.assertEqual(titles, ["quiz-honeypot"])
        # unknown value (prices down) still alerts: fail-open
        self.tearDown(); self.setUp()
        _fake_solc(self.art, "0.8.30")
        mon2 = self._monitor(FakeChain({"0xa": dict(REC)}, 10**17), prices=None, min_value_usd=1_000_000.0)
        with mock.patch.object(sr, "run_slither", return_value=SlitherRun(status="completed", detectors=dets)):
            r2 = mon2.run(once=True)[0]["results"][0]
        self.assertEqual(sorted(a["title"].split()[0] for a in r2["alerts"]),
                         ["Access", "quiz-honeypot"])  # controlled-delegatecall surfaces as "Access control issue"
        self.assertIsNone(r2["alerts"][0]["est_loss_usd"])

    def test_value_disabled_and_unsupported_client(self):
        r = self._run(value_enabled=False)
        self.assertIsNone(r["tvl_usd"])
        conn = self._db()
        self.assertIsNone(conn.execute("SELECT tvl_usd FROM monitor_scans").fetchone()[0])
        conn.close()

    def test_status_view_and_sorting(self):
        self._run(native=5 * 10**18)
        conn = self._db()
        # second synthetic scan: bigger TVL / loss, older
        conn.execute("INSERT INTO monitor_scans(network,address,stage,status,started_at,finished_at,findings,"
                     "severity_counts,analysis_complete,tvl_usd,est_max_loss_usd,risk_score) VALUES"
                     "('ethereum','0xbig','done','done',?,?,1,'{\"MEDIUM\": 1}',1,2000000,1000000,400000)",
                     (self.t[0] - 50, self.t[0] - 40))
        conn.execute("INSERT INTO monitor_scans(network,address,stage,status,started_at,finished_at,findings,"
                     "severity_counts,analysis_complete,tvl_usd,est_max_loss_usd,risk_score) VALUES"
                     "('ethereum','0xsmall','done','done',?,?,1,'{\"HIGH\": 1}',1,800,400,320)",
                     (self.t[0] - 30, self.t[0] - 20))
        conn.commit()
        conn.close()
        live = mv.live(now=self.t[0] + 1, sort="loss")
        self.assertEqual([r["address"] for r in live["recent_scans"]][:3], ["0xbig", "0xa", "0xsmall"])
        self.assertEqual(mv.live(now=self.t[0] + 1, sort="risk")["recent_scans"][0]["address"], "0xbig")
        self.assertEqual(mv.live(now=self.t[0] + 1, sort="bogus")["sort"], "recent")
        c = live["counters"]
        # Headline counts confirmed outsider-exploitable only (Phase 25+); synthetic
        # scans above have est_max_loss but no confirmed_exploitable findings.
        self.assertEqual(c["value_at_risk_found_today_usd"], 0.0)
        self.assertIn("unverified_exposure_today_usd", c)
        self.assertEqual(c["suppressed_all_time"], 4)
        self.assertNotIn("value_json", live["recent_scans"][0])
        st = m.monitor_status("ethereum", show_suppressed=True, now=self.t[0] + 1)
        self.assertEqual(st["value"]["all_time"]["top"][0]["address"], "0xbig")
        self.assertEqual(len(st["value"]["all_time"]["suppressed"]), 4)
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(main(["monitor-status", "--show-suppressed"]), EXIT_OK)
        text = out.getvalue()
        self.assertIn("value at risk (ROUGH ESTIMATES", text)
        self.assertIn("suppressed #", text)
        self.assertIn("user funds at risk: honeypot", text)

    def test_scan_detail_includes_suppressed_with_flags(self):
        self._run()
        d = mv.scan_detail(1)
        self.assertEqual(d["suppressed_detail_count"], 4)
        sup = [f for f in d["findings_detail"] if f["suppressed"]]
        self.assertTrue(all(f["triage"]["reason"] in ("library-code", "known-benign") for f in sup))
        kept = [f for f in d["findings_detail"] if not f["suppressed"]]
        self.assertEqual(kept[0]["title"].split()[0], "quiz-honeypot")  # highest weighted score first
        self.assertEqual(kept[0]["risk"]["vulnerability_class"], "scam_honeypot")
        self.assertEqual(d["value"]["summary"]["tvl_usd"], 15000.0)
        self.assertTrue(kept[0]["evidence"])


# ---------------------------------------------------------------------------
# schema v4 migration
# ---------------------------------------------------------------------------

V3_SQL = """
CREATE TABLE monitor_cursor (network TEXT PRIMARY KEY, last_block INTEGER NOT NULL, updated_at TEXT);
CREATE TABLE monitor_seen (network TEXT NOT NULL, address TEXT NOT NULL, content_hash TEXT NOT NULL,
    scan_id TEXT, findings INTEGER, scanned_at TEXT, contract_name TEXT, PRIMARY KEY (network, address, content_hash));
CREATE TABLE monitor_queue (network TEXT NOT NULL, address TEXT NOT NULL, tx_hash TEXT, block INTEGER,
    attempts INTEGER NOT NULL DEFAULT 0, next_attempt_at REAL NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'pending', last_error TEXT, updated_at TEXT, PRIMARY KEY (network, address));
CREATE TABLE monitor_scans (id INTEGER PRIMARY KEY AUTOINCREMENT, network TEXT NOT NULL, address TEXT NOT NULL,
    tx_hash TEXT, block INTEGER, content_hash TEXT, contract_name TEXT, compiler TEXT, file_count INTEGER,
    line_count INTEGER, source_bytes INTEGER, cache_dir TEXT, stage TEXT NOT NULL, status TEXT NOT NULL,
    started_at REAL NOT NULL, stage_at REAL, finished_at REAL, duration_s REAL, scan_id TEXT, findings INTEGER,
    severity_counts TEXT, error TEXT, analysis_complete INTEGER, needs_rescan INTEGER NOT NULL DEFAULT 0,
    solc_version TEXT, compile_settings TEXT, superseded_at REAL);
CREATE TABLE monitor_stage_events (scan_row INTEGER NOT NULL, stage TEXT NOT NULL, at REAL NOT NULL);
CREATE TABLE monitor_polls (id INTEGER PRIMARY KEY AUTOINCREMENT, network TEXT NOT NULL, at REAL NOT NULL,
    blocks INTEGER, enqueued INTEGER, processed INTEGER, alerts INTEGER, error TEXT);
INSERT INTO monitor_scans(network,address,stage,status,started_at,finished_at,findings,severity_counts,analysis_complete)
    VALUES('ethereum','0xold','done','done',1,2,3,'{"HIGH": 3}',1);
PRAGMA user_version = 3;
"""


class MigrationTests(Env):
    def test_v3_to_v4_idempotent_and_views_tolerate_v3(self):
        db = self.d / "mon.db"
        conn = sqlite3.connect(db)
        conn.executescript(V3_SQL)
        conn.close()
        # read-only views on an unmigrated v3 DB must not fail or migrate
        live = mv.live(now=10)
        self.assertEqual(live["counters"]["value_at_risk_found_all_time_usd"], 0.0)
        self.assertEqual(sqlite3.connect(db).execute("PRAGMA user_version").fetchone()[0], 3)
        self.assertIsNone(mv.scan_detail(1, history_findings=[])["value"])
        for _ in range(2):
            m.MonitorStore(db).close()
        conn = sqlite3.connect(db)
        cols = {r[1] for r in conn.execute("PRAGMA table_info(monitor_scans)")}
        tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        ver = conn.execute("PRAGMA user_version").fetchone()[0]
        old = conn.execute("SELECT address, findings, suppressed_count FROM monitor_scans").fetchone()
        conn.close()
        self.assertEqual(ver, m.MonitorStore.SCHEMA_VERSION)
        self.assertTrue({"tvl_usd", "est_max_loss_usd", "risk_score", "price_as_of", "value_json",
                         "suppressed_count", "user_funds_at_risk"} <= cols)
        self.assertIn("monitor_findings", tables)
        self.assertTrue({"hunt_candidates", "hunt_runs"} <= tables)  # Phase 20 schema v5
        self.assertIn("origin", cols)
        self.assertEqual(old, ("0xold", 3, 0))


# ---------------------------------------------------------------------------
# CLI and dashboard surfaces
# ---------------------------------------------------------------------------

class CliTests(Env):
    def test_monitor_rejects_negative_min_value(self):
        err = io.StringIO()
        with contextlib.redirect_stderr(err), mock.patch.dict(os.environ, {"ETHERSCAN_API_KEY": KEY}):
            self.assertEqual(main(["monitor", "--once", "--min-value-usd", "-5"]), EXIT_ERROR)
        self.assertIn("--min-value-usd", err.getvalue())

    def _urlopen(self, record, native="2000000000000000000"):
        def fake(req, timeout=30):
            url = req.full_url if hasattr(req, "full_url") else str(req)
            if "getsourcecode" in url:
                body = {"status": "1", "message": "OK", "result": [record]}
            elif "action=balance" in url:
                body = {"status": "1", "result": native}
            elif "tokenbalance" in url:
                body = {"status": "1", "result": "0"}
            elif "coingecko" in url:
                body = PRICES
            else:
                raise AssertionError("unexpected URL " + url)
            resp = mock.MagicMock()
            resp.read.return_value = json.dumps(body).encode()
            resp.__enter__.return_value = resp
            return resp

        return fake

    def _empty_slither(self):
        return mock.patch.object(sr, "run_slither", return_value=SlitherRun(status="completed", detectors=[]))

    def test_scan_address_json_value_and_suppressed(self):
        _fake_solc(self.art, "0.8.30")
        rec = dict(REC)
        dets = [DETECTORS[1], DETECTORS[0]]
        out, err = io.StringIO(), io.StringIO()
        with mock.patch("urllib.request.urlopen", side_effect=self._urlopen(rec)), \
                mock.patch.dict(os.environ, {"ETHERSCAN_API_KEY": KEY}), \
                mock.patch.object(sr, "run_slither", return_value=SlitherRun(status="completed", detectors=dets)), \
                mock.patch.object(m.ChainClient, "_throttle", lambda self: None), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main(["scan-address", "--network", "ethereum", "--address", "0x" + "ab" * 20, "--json",
                         "--show-suppressed"])
        self.assertEqual(code, EXIT_OK, err.getvalue())
        p = json.loads(out.getvalue())
        self.assertEqual(p["triage"]["suppressed"], 1)
        self.assertEqual(p["suppressed_findings"][0]["triage"]["rule"], "oz-erc1967-checknonpayable")
        self.assertEqual(p["value_at_risk"]["summary"]["tvl_usd"], 6000.0)
        est = {e["title"].split()[0]: e for e in p["value_at_risk"]["finding_estimates"]}
        self.assertEqual(est["quiz-honeypot"]["est_loss_usd"], 6000.0)
        self.assertEqual(est["arbitrary-send-eth"]["est_loss_usd"], 0.0)
        sev = {f["title"].split()[0]: f["severity"] for f in p["findings"]}
        self.assertEqual(sev, {"quiz-honeypot": "HIGH", "arbitrary-send-eth": "INFORMATIONAL"})
        self.assertNotIn(KEY, out.getvalue() + err.getvalue())

    def test_scan_address_no_value_makes_no_balance_requests(self):
        _fake_solc(self.art, "0.8.30")
        calls = []
        fake = self._urlopen(dict(REC))

        def spy(req, timeout=30):
            calls.append(req.full_url)
            return fake(req, timeout)

        out = io.StringIO()
        with mock.patch("urllib.request.urlopen", side_effect=spy), self._empty_slither(), \
                mock.patch.dict(os.environ, {"ETHERSCAN_API_KEY": KEY}), contextlib.redirect_stdout(out), \
                contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(main(["scan-address", "--network", "ethereum", "--address", "0x" + "ab" * 20,
                                   "--json", "--no-value"]), EXIT_OK)
        self.assertEqual(len(calls), 1)
        p = json.loads(out.getvalue())
        self.assertIsNone(p["value_at_risk"])
        self.assertNotIn("suppressed_findings", p)

    def test_plain_scan_suppressed_key_is_opt_in(self):
        proj = self.d / "proj"
        _write(proj, {OZ_PATH: ERC1967, "contracts/JUST_play.sol": JUST_PLAY})
        lib = _finding("divide-before-multiply in ERC1967Utils.upgradeToAndCall", "ERC1967Utils", "upgradeToAndCall",
                       OZ_PATH, Severity.MEDIUM)
        from auditor.analysis.base import AnalysisOutcome

        def gen(ctx):
            o = AnalysisOutcome()
            o.findings, o.evidence, o.notes = [lib], [], []
            return o

        def empty(ctx):
            o = AnalysisOutcome()
            o.findings, o.evidence, o.notes = [], [], []
            return o

        results = {}
        for flag in ([], ["--show-suppressed"]):
            out, err = io.StringIO(), io.StringIO()
            with mock.patch("auditor.analysis.slither_generic.analyze", side_effect=gen), \
                    mock.patch("auditor.analysis.reentrancy.analyze", side_effect=empty), \
                    mock.patch("auditor.analysis.access_control.analyze", side_effect=empty), \
                    contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                main(["scan", "--json", str(proj)] + flag)
            results[bool(flag)] = (json.loads(out.getvalue()), err.getvalue())
        default, _ = results[False]
        self.assertEqual(set(default), {"scan_id", "source_path", "content_hash", "findings", "notes"})
        self.assertNotIn("divide-before-multiply", json.dumps(default["findings"]))
        self.assertIn("suppressed", results[False][1])
        shown, _ = results[True]
        self.assertEqual(shown["suppressed_findings"][0]["triage"]["reason"], "library-code")
        self.assertEqual([f["title"].split()[0] for f in shown["findings"]], ["quiz-honeypot"])


class VarHeadlineApiTests(Env):
    """Confirmed-outsider VaR must not equal raw scan est_max_loss sums."""

    def test_monitor_live_var_is_confirmed_only_not_scan_est_max(self):
        from auditor import hunt as ht
        from auditor import monitor as mon
        from auditor import monitor_view as mv

        store = mon.MonitorStore(self.d / "mon.db")
        conn = store.conn
        # Use wall-clock "now" so /api/monitor/live day_bounds (real clock) includes rows.
        import time as _time
        now = _time.time()
        # High est_max_loss on the scan, but no confirmed_exploitable findings.
        conn.execute(
            "INSERT INTO monitor_scans(network,address,stage,status,started_at,finished_at,findings,"
            "severity_counts,analysis_complete,tvl_usd,est_max_loss_usd,risk_score,suppressed_count) "
            "VALUES('ethereum','0xbig','done','done',?,?,2,'{\"HIGH\": 1}',1,2000000,1750000,900000,0)",
            (now - 10, now - 5),
        )
        scan_id = conn.execute("SELECT id FROM monitor_scans").fetchone()[0]
        # confirmed_exploitable column may exist from Phase EXPLOITABLE migration
        fcols = {r[1] for r in conn.execute("PRAGMA table_info(monitor_findings)")}
        if "confirmed_exploitable" not in fcols:
            conn.execute("ALTER TABLE monitor_findings ADD COLUMN confirmed_exploitable INTEGER DEFAULT 0")
        conn.execute(
            "INSERT INTO monitor_findings(scan_row,network,address,title,detector,category,severity,"
            "confidence,suppressed,est_loss_usd,confirmed_exploitable) "
            "VALUES(?,?,?,?,?,?,?,?,0,1750000,0)",
            (scan_id, "ethereum", "0xbig", "privileged-auth-unprotected in X.withdraw",
             "privileged-auth-unprotected", "privileged_auth", "CRITICAL", "HIGH"),
        )
        conn.execute(
            "INSERT OR REPLACE INTO hunt_candidates(network,address,protocol,status,llama_tvl_usd,"
            "onchain_tvl_usd,holder_value_usd,scanned_at,updated_at,findings,est_max_loss_usd,blue_chip) "
            "VALUES('ethereum','0xhunt','Demo','scanned',5000000,5000000,5000000,?,?,1,1750000,0)",
            (now - 3, now - 3),
        )
        conn.commit()
        store.close()

        live = mv.live(now=now + 1)
        c = live["counters"]
        self.assertEqual(c["value_at_risk_found_today_usd"], 0.0)
        self.assertGreater(c["unverified_exposure_today_usd"], 0.0)
        self.assertNotEqual(c["value_at_risk_found_today_usd"], 1750000.0)

        hconn = sqlite3.connect(self.d / "mon.db")
        hconn.row_factory = sqlite3.Row
        overview = ht.hunt_overview(hconn, "ethereum", since=now - 100, until=now + 100)
        hconn.close()
        hc = overview["counters"]
        self.assertEqual(hc["hunted_value_scanned_today_usd"], 5000000.0)
        # APIs agree on semantics: monitor headline = confirmed-only; hunt = holdings.
        self.assertEqual(c["value_at_risk_found_today_usd"], 0.0)
        self.assertNotEqual(hc["hunted_value_scanned_today_usd"], c["value_at_risk_found_today_usd"])

        try:
            from fastapi.testclient import TestClient
            from auditor.dashboard.app import create_app
        except Exception:  # noqa: BLE001
            self.skipTest("dashboard deps missing")
        client = TestClient(create_app())
        mon_api = client.get("/api/monitor/live").json()["counters"]
        hunt_api = client.get("/api/hunt/live?top=1").json()["counters"]
        self.assertEqual(mon_api["value_at_risk_found_today_usd"], 0.0)
        self.assertIn("unverified_exposure_today_usd", mon_api)
        self.assertGreater(mon_api["unverified_exposure_today_usd"], 0.0)
        self.assertEqual(hunt_api["hunted_value_scanned_today_usd"], 5000000.0)
        self.assertNotEqual(mon_api["value_at_risk_found_today_usd"], 1750000.0)
        self.assertNotEqual(hunt_api.get("hunted_value_scanned_today_usd"), 1750000.0)


class DashboardTests(Env):
    def test_page_and_api(self):
        try:
            from fastapi.testclient import TestClient

            from auditor.dashboard.app import create_app
        except Exception:  # noqa: BLE001
            self.skipTest("dashboard deps missing")
        client = TestClient(create_app())
        html = client.get("/monitor").text
        for s in ("Confirmed outsider value at risk today (est.)",
                  "Unverified exposure today (unconfirmed privileged-auth)",
                  'id="mon-sort"', 'id="mon-show-suppressed"', "TVL (est.)",
                  "Impact estimate"):
            self.assertIn(s, html)
        r = client.get("/api/monitor/live?sort=loss")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()["sort"], "loss")
        self.assertEqual(client.get("/api/monitor/live?sort=;drop").json()["sort"], "recent")
        js = client.get("/static/js/monitor.js").text
        self.assertNotIn("innerHTML", js)
        self.assertIn("Potential impact estimate (heuristic)", js)


if __name__ == "__main__":
    unittest.main()
