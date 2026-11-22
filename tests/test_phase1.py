"""Phase 1 test suite. Standard library only: unittest, no pytest dependency.

Run with:

    python3 -m unittest discover -s tests -v

Coverage intent:
* Address validation, including the EIP-55 honesty boundary.
* Tool-status and version parsing against real observed output formats.
* That unavailable tools are reported unavailable rather than faked healthy.
* Ollama payload parsing and the loopback-only endpoint guard.
* Storage measurement correctness and symlink non-following.
* The finding guardrail: no CONFIRMED verdict without FACT evidence.
"""

from __future__ import annotations

import json
import sys
import os
import json
import unittest
import unittest.mock as mock
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from auditor import ollama as ollama_mod  # noqa: E402
from auditor import report as report_mod  # noqa: E402
from auditor import storage as storage_mod  # noqa: E402
from auditor import target as target_mod  # noqa: E402
from auditor import toolchain as toolchain_mod  # noqa: E402
from auditor.model import (  # noqa: E402
    Confidence,
    Epistemic,
    EvidenceItem,
    Finding,
    FindingValidationError,
    Severity,
    VerificationStatus,
    sha256_text,
)
from auditor.procs import ProcResult, run  # noqa: E402
from auditor.registry import discover_analyzers  # noqa: E402
from auditor.settings import load_settings  # noqa: E402


def _evidence(epistemic: Epistemic = Epistemic.FACT) -> EvidenceItem:
    return EvidenceItem(
        source="unit-test",
        artifact_type="tool_output",
        excerpt="synthetic fixture content",
        epistemic=epistemic,
    )


class TestAddressValidation(unittest.TestCase):
    def test_accepts_lowercase_prefixed(self) -> None:
        result = target_mod.validate_address("0x" + "a" * 40)
        self.assertTrue(result.is_valid)
        self.assertEqual(result.normalized, "0x" + "a" * 40)
        self.assertEqual(result.checksum_status, target_mod.ChecksumStatus.NOT_APPLICABLE)

    def test_accepts_bare_hex_and_adds_prefix(self) -> None:
        result = target_mod.validate_address("B" * 40)
        self.assertTrue(result.is_valid)
        self.assertEqual(result.normalized, "0x" + "b" * 40)

    def test_normalizes_uppercase_body(self) -> None:
        result = target_mod.validate_address("0x" + "F0" * 20)
        self.assertTrue(result.is_valid)
        self.assertEqual(result.normalized, "0x" + "f0" * 20)

    def test_mixed_case_is_unverified_not_claimed_valid_checksum(self) -> None:
        result = target_mod.validate_address("0x" + "aA1" * 12 + "aAbB")
        self.assertTrue(result.is_valid)
        self.assertEqual(result.checksum_status, target_mod.ChecksumStatus.UNVERIFIED)
        self.assertIn("NOT verified", result.reason)

    def test_rejects_short(self) -> None:
        result = target_mod.validate_address("0x" + "a" * 39)
        self.assertFalse(result.is_valid)
        self.assertIsNone(result.normalized)
        self.assertIn("39", result.reason)

    def test_rejects_long(self) -> None:
        result = target_mod.validate_address("0x" + "a" * 41)
        self.assertFalse(result.is_valid)
        self.assertIn("41", result.reason)

    def test_rejects_non_hex(self) -> None:
        result = target_mod.validate_address("0x" + "z" * 40)
        self.assertFalse(result.is_valid)
        self.assertIn("non-hexadecimal", result.reason)

    def test_rejects_embedded_whitespace(self) -> None:
        result = target_mod.validate_address("0x" + "a" * 20 + " " + "b" * 19)
        self.assertFalse(result.is_valid)

    def test_rejects_empty_and_none(self) -> None:
        self.assertFalse(target_mod.validate_address("").is_valid)
        self.assertFalse(target_mod.validate_address("   ").is_valid)
        self.assertFalse(target_mod.validate_address(None).is_valid)

    def test_rejects_prefix_only(self) -> None:
        self.assertFalse(target_mod.validate_address("0x").is_valid)

    def test_surrounding_whitespace_is_tolerated(self) -> None:
        result = target_mod.validate_address("  0x" + "a" * 40 + "  ")
        self.assertTrue(result.is_valid)

    def test_chain_normalization(self) -> None:
        self.assertEqual(target_mod.normalize_chain(None), target_mod.DEFAULT_CHAIN)
        self.assertEqual(target_mod.normalize_chain("  Ethereum "), "ethereum")
        self.assertEqual(target_mod.normalize_chain(""), target_mod.DEFAULT_CHAIN)


class TestToolStatusParsing(unittest.TestCase):
    """Parsing is tested against the real output shapes observed on this machine."""

    def test_forge_banner(self) -> None:
        raw = (
            "forge Version: 1.8.3\n"
            "Commit SHA: cae51ad458f6abb64852b7709eb784352429825d\n"
            "Build Timestamp: 2026-09-15T10:34:23.361078000Z (1789468463)\n"
        )
        self.assertEqual(toolchain_mod.extract_version("forge", raw), "1.8.3")

    def test_cast_banner(self) -> None:
        self.assertEqual(toolchain_mod.extract_version("cast", "cast Version: 1.8.3\n"), "1.8.3")

    def test_anvil_banner(self) -> None:
        self.assertEqual(toolchain_mod.extract_version("anvil", "anvil Version: 1.8.3\n"), "1.8.3")

    def test_python_banner(self) -> None:
        self.assertEqual(toolchain_mod.extract_version("python", "Python 3.11.9\n"), "3.11.9")

    def test_slither_bare_version(self) -> None:
        self.assertEqual(toolchain_mod.extract_version("slither", "0.11.6\n"), "0.11.6")

    def test_solc_banner_on_stderr(self) -> None:
        raw = (
            "solc, the solidity compiler commandline interface\n"
            "Version: 0.8.37+commit.f401782d.Darwin.appleclang\n"
        )
        self.assertEqual(toolchain_mod.extract_version("solc", raw), "0.8.37+commit.f401782d.Darwin.appleclang")

    def test_ollama_banner(self) -> None:
        self.assertEqual(
            toolchain_mod.extract_version("ollama", "ollama version is 0.35.1\n"), "0.35.1"
        )

    def test_git_banner(self) -> None:
        self.assertEqual(
            toolchain_mod.extract_version("git", "git version 2.55.0 (Apple Git-154)\n"), "2.55.0"
        )

    def test_unparseable_returns_none(self) -> None:
        self.assertIsNone(toolchain_mod.extract_version("forge", ""))
        self.assertIsNone(toolchain_mod.extract_version("forge", "no numbers here at all"))

    def test_fallback_recovers_unexpected_banner(self) -> None:
        self.assertEqual(toolchain_mod.extract_version("mystery", "tool v7.1.2 ready"), "7.1.2")

    def test_shim_detection(self) -> None:
        self.assertTrue(toolchain_mod._looks_like_shim("/Users/x/.pyenv/shims/solc"))
        self.assertFalse(toolchain_mod._looks_like_shim("/opt/homebrew/bin/git"))

    def test_pyenv_version_dir_detection(self) -> None:
        self.assertTrue(
            toolchain_mod._is_pyenv_version_dir("/Users/x/.pyenv/versions/3.11.9/bin/solc")
        )
        self.assertFalse(toolchain_mod._is_pyenv_version_dir("/opt/homebrew/bin/git"))

    def test_resolution_labels_distinguish_shim_from_version_dir(self) -> None:
        """A shim and the versioned binary behind it are different observations."""
        base = {
            "key": "solc",
            "display_name": "solc",
            "category": "compiler",
            "required": False,
            "available": True,
            "returncode": 0,
            "error": None,
        }
        shim = toolchain_mod.ToolStatus(
            path="/Users/x/.pyenv/shims/solc",
            version="0.8.37",
            version_line=None,
            resolved_via_shim=True,
            **base,
        )
        versioned = toolchain_mod.ToolStatus(
            path="/Users/x/.pyenv/versions/3.11.9/bin/solc",
            version="0.8.37",
            version_line=None,
            resolved_via_shim=False,
            redirected_by_pyenv=True,
            **base,
        )
        self.assertEqual(shim.resolution, "SHIM")
        self.assertEqual(versioned.resolution, "PYENV_VERSION_DIR")

    def test_unavailable_tool_resolution_is_not_found(self) -> None:
        status = toolchain_mod.ToolStatus(
            key="x",
            display_name="X",
            category="c",
            required=False,
            available=False,
            path=None,
            version=None,
            version_line=None,
            resolved_via_shim=False,
            returncode=None,
            error="missing",
        )
        self.assertEqual(status.resolution, "NOT_FOUND")


class TestToolStatusTruthfulness(unittest.TestCase):
    def test_missing_tool_reports_not_on_path(self) -> None:
        spec = toolchain_mod.ToolSpec(
            key="ghost",
            display_name="Ghost",
            candidates=("definitely-not-a-real-binary-xyz",),
            version_pattern=r"(\d+\.\d+\.\d+)",
        )
        status = toolchain_mod.detect_tool(spec, timeout=5.0)
        self.assertFalse(status.available)
        self.assertEqual(status.status, "NOT_ON_PATH")
        self.assertIsNone(status.path)
        self.assertIsNone(status.version)
        self.assertIn("not found on PATH", status.error or "")

    def test_present_but_unparseable_is_not_available(self) -> None:
        spec = toolchain_mod.ToolSpec(
            key="catish",
            display_name="cat",
            candidates=("echo",),
            version_arg="definitely-not-a-flag",
            version_pattern=r"(\d+\.\d+\.\d+)",
        )
        status = toolchain_mod.detect_tool(spec, timeout=5.0)
        self.assertFalse(status.available, "a nonzero exit must not read as available")
        self.assertEqual(status.status, "PRESENT_BUT_FAILED")
        self.assertIsNotNone(status.path)

    def test_real_python_detected(self) -> None:
        spec = next(s for s in toolchain_mod.TOOL_SPECS if s.key == "python")
        status = toolchain_mod.detect_tool(spec, timeout=10.0)
        self.assertTrue(status.available, f"python3 should be detectable: {status.error}")
        self.assertRegex(status.version or "", r"^\d+\.\d+")

    def test_toolchain_report_lookup(self) -> None:
        report = toolchain_mod.ToolchainReport(
            tools=[
                toolchain_mod.detect_tool(
                    toolchain_mod.ToolSpec("alpha", "Alpha", ("python3",)),
                    timeout=10.0,
                )
            ],
            timeout_seconds=10.0,
        )
        self.assertIsNotNone(report.get("alpha"))
        self.assertIsNone(report.get("beta"))
        self.assertIsNone(report.version_of("beta"))


class TestProcSafety(unittest.TestCase):
    def test_empty_argv_refused(self) -> None:
        result = run([], timeout=5.0)
        self.assertFalse(result.ok)
        self.assertIn("empty argv", result.error or "")

    def test_shell_metacharacters_are_not_interpreted(self) -> None:
        """A metacharacter-laden argument must arrive as a literal, unexpanded."""
        payload = "safe; echo pwned"
        result = run([sys.executable, "-c", "import sys; sys.stdout.write(sys.argv[1])", payload], timeout=10.0)
        self.assertTrue(result.ok, result.error or "")
        self.assertEqual(result.stdout, payload)
        self.assertNotIn("pwned\n", result.stdout.replace(payload, ""))

    def test_command_substitution_not_expanded(self) -> None:
        payload = "$(echo pwned)"
        result = run([sys.executable, "-c", "import sys; sys.stdout.write(sys.argv[1])", payload], timeout=10.0)
        self.assertEqual(result.stdout, payload)

    def test_timeout_is_enforced(self) -> None:
        result = run([sys.executable, "-c", "import time; time.sleep(30)"], timeout=1.0)
        self.assertFalse(result.ok)
        self.assertTrue(result.timed_out)
        self.assertIn("timeout", result.error or "")

    def test_missing_binary_is_error_not_exception(self) -> None:
        result = run(["definitely-not-a-real-binary-xyz", "--version"], timeout=5.0)
        self.assertFalse(result.ok)
        self.assertIsNotNone(result.error)

    def test_nonzero_exit_distinguishable(self) -> None:
        result = run([sys.executable, "-c", "import sys; sys.exit(3)"], timeout=10.0)
        self.assertFalse(result.ok)
        self.assertEqual(result.returncode, 3)

    def test_combined_joins_streams(self) -> None:
        result = ProcResult(argv=("x",), returncode=0, stdout="a", stderr="b")
        self.assertIn("a", result.combined())
        self.assertIn("b", result.combined())
        self.assertEqual(result.first_line(), "a")


class TestOllamaParsing(unittest.TestCase):
    FIXTURE = {
        "models": [
            {
                "name": "qwen3-8b-uncensored-16k:latest",
                "size": 5027792704,
                "digest": "c7daa978b569",
                "details": {
                    "family": "qwen3",
                    "parameter_size": "8.2B",
                    "quantization_level": "Q4_K_M",
                },
                "capabilities": ["completion", "tools", "thinking"],
            },
            {
                "name": "qwen2.5vl:3b",
                "size": 3200627168,
                "details": {"family": "qwen25vl", "quantization_level": "Q4_K_M"},
                "capabilities": ["completion", "vision"],
            },
        ]
    }

    def test_parses_models(self) -> None:
        models = ollama_mod.parse_tags_payload(self.FIXTURE)
        self.assertEqual(len(models), 2)
        first = models[0]
        self.assertEqual(first.name, "qwen3-8b-uncensored-16k:latest")
        self.assertEqual(first.size_bytes, 5027792704)
        self.assertEqual(first.quantization, "Q4_K_M")
        self.assertTrue(first.supports_tools)

    def test_size_human(self) -> None:
        models = ollama_mod.parse_tags_payload(self.FIXTURE)
        self.assertIn("GiB", models[0].size_human or "")

    def test_missing_size_is_none_not_zero(self) -> None:
        models = ollama_mod.parse_tags_payload({"models": [{"name": "x"}]})
        self.assertIsNone(models[0].size_bytes)
        self.assertIsNone(models[0].size_human)

    def test_malformed_payloads_do_not_raise(self) -> None:
        for payload in (None, [], {}, {"models": None}, {"models": [1, "x", {}]}, {"models": [{"no": "name"}]}):
            with self.subTest(payload=payload):
                self.assertEqual(ollama_mod.parse_tags_payload(payload), [])

    def test_partial_model_still_recorded(self) -> None:
        models = ollama_mod.parse_tags_payload({"models": [{"name": "bare:1b"}]})
        self.assertEqual(len(models), 1)
        self.assertEqual(models[0].capabilities, [])

    def test_endpoint_allowlist_blocks_remote_hosts(self) -> None:
        for host in ("http://example.com:11434", "http://10.0.0.5:11434", "https://ollama.ai"):
            with self.subTest(host=host):
                with self.assertRaises(ollama_mod.OllamaEndpointRefused):
                    ollama_mod.check_endpoint_allowed(host)

    def test_endpoint_allowlist_permits_loopback(self) -> None:
        for host in ("http://localhost:11434", "http://127.0.0.1:11434", "http://[::1]:11434"):
            with self.subTest(host=host):
                self.assertEqual(ollama_mod.check_endpoint_allowed(host).rstrip("/"), host.rstrip("/"))

    def test_endpoint_allowlist_blocks_bad_scheme(self) -> None:
        for url in ("file:///etc/passwd", "ftp://localhost", "gopher://localhost"):
            with self.subTest(url=url):
                with self.assertRaises(ollama_mod.OllamaEndpointRefused):
                    ollama_mod.check_endpoint_allowed(url)

    def test_unreachable_endpoint_reports_error_not_success(self) -> None:
        status = ollama_mod.probe_ollama(endpoint="http://localhost:1", selected_model=None, probe_model=False, timeout=0.5)
        self.assertFalse(status.reachable)
        self.assertIsNotNone(status.error)
        self.assertEqual(status.models, [])

    def test_refused_endpoint_does_not_raise_to_caller(self) -> None:
        status = ollama_mod.probe_ollama(endpoint="http://example.com:11434")
        self.assertFalse(status.reachable)
        self.assertIn("loopback", status.error or "")

    def test_http_layer_itself_refuses_remote_host(self) -> None:
        """Defense in depth: the guard is inside _http_json, not only the caller."""
        payload, error = ollama_mod._http_json("http://example.com:11434/api/tags", timeout=1.0)
        self.assertIsNone(payload)
        self.assertIsNotNone(error)
        self.assertIn("loopback", error)

    def test_probe_skipped_reason_recorded(self) -> None:
        status = ollama_mod.probe_ollama(
            endpoint="http://127.0.0.1:1",
            selected_model="qwen3-8b-uncensored-16k:latest",
            probe_model=False,
            timeout=0.5,
        )
        self.assertIn("disabled", status.probe_skipped_reason or "")


class TestStorageMeasurement(unittest.TestCase):
    def test_human_bytes(self) -> None:
        self.assertEqual(storage_mod.human_bytes(0), "0 B")
        self.assertEqual(storage_mod.human_bytes(1024), "1.00 KiB")
        self.assertEqual(storage_mod.human_bytes(1024**3), "1.00 GiB")
        self.assertEqual(storage_mod.human_bytes(None), "unknown")

    def test_measure_directory(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "a.txt").write_text("x" * 100)
            (root / "sub").mkdir()
            (root / "sub" / "b.txt").write_text("y" * 50)
            usage = storage_mod.measure_directory(root)
            self.assertTrue(usage.exists)
            self.assertEqual(usage.file_count, 2)
            self.assertEqual(usage.bytes, 150)

    def test_missing_directory(self) -> None:
        usage = storage_mod.measure_directory(Path("/definitely/not/here"))
        self.assertFalse(usage.exists)
        self.assertEqual(usage.bytes, 0)

    def test_symlinks_are_not_followed(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            outside = root / "outside"
            outside.mkdir()
            (outside / "big.bin").write_bytes(b"z" * 5000)
            project = root / "project"
            project.mkdir()
            (project / "link").symlink_to(outside, target_is_directory=True)
            usage = storage_mod.measure_directory(project)
            # Only the symlink inode itself counts, never the 5000-byte target.
            self.assertLess(usage.bytes, 5000)


class TestFindingGuardrails(unittest.TestCase):
    def test_confirmed_requires_fact_evidence(self) -> None:
        finding = Finding(
            title="Possible reentrancy",
            description="External call precedes state update.",
            category="reentrancy",
            severity=Severity.HIGH,
            confidence=Confidence.LOW,
            verification_status=VerificationStatus.CONFIRMED,
        )
        with self.assertRaises(FindingValidationError):
            finding.validate()

    def test_likely_requires_fact_evidence(self) -> None:
        finding = Finding(
            title="x",
            description="y",
            category="c",
            verification_status=VerificationStatus.LIKELY,
        )
        with self.assertRaises(FindingValidationError):
            finding.validate()

    def test_ai_opinion_alone_cannot_confirm(self) -> None:
        finding = Finding(
            title="Model says vulnerable",
            description="Ollama asserted reentrancy.",
            category="reentrancy",
            verification_status=VerificationStatus.CONFIRMED,
        )
        finding.add_evidence(_evidence(Epistemic.AI_OPINION))
        with self.assertRaises(FindingValidationError):
            finding.validate()

    def test_hypothesis_alone_cannot_confirm(self) -> None:
        finding = Finding(
            title="Speculative",
            description="d",
            category="c",
            verification_status=VerificationStatus.CONFIRMED,
        )
        finding.add_evidence(_evidence(Epistemic.HYPOTHESIS))
        finding.add_evidence(_evidence(Epistemic.INFERENCE))
        with self.assertRaises(FindingValidationError):
            finding.validate()

    def test_fact_evidence_allows_confirmed(self) -> None:
        finding = Finding(
            title="Confirmed issue",
            description="d",
            category="c",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            verification_status=VerificationStatus.CONFIRMED,
        )
        finding.add_evidence(_evidence(Epistemic.FACT))
        finding.validate()
        self.assertEqual(len(finding.fact_evidence), 1)

    def test_possible_does_not_require_fact(self) -> None:
        """POSSIBLE is a plan to look, not an assertion. Guard must not block it."""
        finding = Finding(
            title="Worth checking",
            description="d",
            category="c",
            verification_status=VerificationStatus.POSSIBLE,
        )
        finding.validate()

    def test_false_positive_requires_benign_explanation(self) -> None:
        finding = Finding(
            title="FP",
            description="d",
            category="c",
            verification_status=VerificationStatus.FALSE_POSITIVE,
        )
        with self.assertRaises(FindingValidationError):
            finding.validate()
        finding.benign_explanation = "Guard set before the external call."
        finding.validate()

    def test_empty_title_rejected(self) -> None:
        finding = Finding(title="   ", description="d", category="c")
        with self.assertRaises(FindingValidationError):
            finding.validate()

    def test_zero_line_rejected(self) -> None:
        finding = Finding(title="t", description="d", category="c", affected_lines=[0])
        with self.assertRaises(FindingValidationError):
            finding.validate()

    def test_severity_and_confidence_are_independent(self) -> None:
        high_low = Finding(
            title="a", description="d", category="c",
            severity=Severity.HIGH, confidence=Confidence.LOW,
            verification_status=VerificationStatus.POSSIBLE,
        )
        high_high = Finding(
            title="b", description="d", category="c",
            severity=Severity.HIGH, confidence=Confidence.HIGH,
            verification_status=VerificationStatus.POSSIBLE,
        )
        self.assertNotEqual(high_low.to_dict()["confidence"], high_high.to_dict()["confidence"])
        self.assertEqual(high_low.to_dict()["severity"], high_high.to_dict()["severity"])

    def test_priority_orders_severity_then_confidence(self) -> None:
        crit = Finding(title="c", description="d", category="x", severity=Severity.CRITICAL,
                       confidence=Confidence.LOW, verification_status=VerificationStatus.POSSIBLE)
        high_low = Finding(title="d", description="d", category="x", severity=Severity.HIGH,
                           confidence=Confidence.LOW, verification_status=VerificationStatus.POSSIBLE)
        high_high = Finding(title="e", description="d", category="x", severity=Severity.HIGH,
                            confidence=Confidence.HIGH, verification_status=VerificationStatus.POSSIBLE)
        ordered = sorted([high_low, crit, high_high], key=lambda f: f.priority_score())
        self.assertEqual([f.title for f in ordered], ["c", "e", "d"])

    def test_evidence_content_hash_is_deterministic(self) -> None:
        a = EvidenceItem(source="s", artifact_type="t", excerpt="same")
        b = EvidenceItem(source="s", artifact_type="t", excerpt="same")
        self.assertEqual(a.content_hash, b.content_hash)
        self.assertEqual(a.content_hash, sha256_text("same"))


    def test_validated_findings_drops_invalid_keeps_valid(self) -> None:
        from auditor.model import validated_findings

        good = Finding(
            title="Fine finding",
            description="External call before state change.",
            category="reentrancy",
            severity=Severity.HIGH,
            confidence=Confidence.MEDIUM,
            verification_status=VerificationStatus.UNVERIFIED,
            affected_lines=[1],
        )
        bad = Finding(
            title="Confirmed without evidence",
            description="No FACT evidence behind this verdict.",
            category="reentrancy",
            severity=Severity.HIGH,
            confidence=Confidence.MEDIUM,
            verification_status=VerificationStatus.CONFIRMED,
        )
        kept = validated_findings([good, bad])
        self.assertEqual([f.title for f in kept], ["Fine finding"])

    def test_priority_score_is_deterministic_for_equal_content(self) -> None:
        def make() -> Finding:
            return Finding(
                title="Same content finding",
                description="External call before state change.",
                category="reentrancy",
                severity=Severity.HIGH,
                confidence=Confidence.MEDIUM,
                verification_status=VerificationStatus.UNVERIFIED,
                affected_contract="Vault",
                affected_function="withdraw",
                affected_lines=[10],
            )

        a, b = make(), make()
        # finding_id is a random uuid and must no longer drive ordering.
        self.assertNotEqual(a.finding_id, b.finding_id)
        self.assertEqual(a.priority_score(), b.priority_score())

    def test_fingerprint_survives_empty_title(self) -> None:
        from auditor.model import finding_fingerprint

        finding = Finding(title="", description="d", category="c")
        fingerprint = finding_fingerprint(finding)  # must not raise
        self.assertEqual(fingerprint[3], "")


class TestRegistry(unittest.TestCase):
    def test_missing_analysis_package_is_not_an_error(self) -> None:
        report = discover_analyzers("definitely_not_a_package_xyz")
        self.assertEqual(report.analyzers, [])
        self.assertEqual(report.errors, [])

    def test_default_registry_finds_real_analyzers(self) -> None:
        report = discover_analyzers()
        loadable_names = sorted(e.module_name for e in report.loadable())
        # The package must actually resolve (it used to point at a
        # nonexistent top-level "analysis" package and silently find
        # nothing), and the production analyzers must load.
        self.assertEqual(
            loadable_names,
            [
                "auditor.analysis.access_control",
                "auditor.analysis.erc4626_inflation",
                "auditor.analysis.honeypot",  # Phase 19
                "auditor.analysis.known_exploits",  # Phase 32
                "auditor.analysis.oracle_staleness",
                "auditor.analysis.pool_accounting",
                "auditor.analysis.privileged_auth",  # Phase 25
                "auditor.analysis.reentrancy",
                "auditor.analysis.slither_generic",
            ],
        )
        # Support modules (base, slither_runner) are skipped without errors.
        self.assertEqual(report.errors, [])
        self.assertIn("note", report.to_dict())


class TestCLI(unittest.TestCase):
    """End-to-end CLI checks. Subprocesses run our own code with no network."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.audit_py = str(PROJECT_ROOT / "audit.py")

    def setUp(self) -> None:
        """Isolate scan-history writes and API-key state from the environment.

        The scan-address tests exercise code paths that record scans; without
        this they would write test rows into the production history database,
        and the ETHERSCAN_API_KEY they set would leak into later tests.
        """
        import tempfile

        self._tmpdir = tempfile.TemporaryDirectory(prefix="audit-cli-test-")
        self._env_patch = mock.patch.dict(
            os.environ,
            {"AUDITOR_HISTORY_DB": str(Path(self._tmpdir.name) / "history.db")},
        )
        self._env_patch.__enter__()
        self._saved_key = os.environ.pop("ETHERSCAN_API_KEY", None)

    def tearDown(self) -> None:
        if self._saved_key is None:
            os.environ.pop("ETHERSCAN_API_KEY", None)
        else:
            os.environ["ETHERSCAN_API_KEY"] = self._saved_key
        self._env_patch.__exit__(None, None, None)
        self._tmpdir.cleanup()

    def _run(self, *args: str) -> tuple[int, str, str]:
        import subprocess

        completed = subprocess.run(
            [sys.executable, self.audit_py, *args],
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
        return completed.returncode, completed.stdout, completed.stderr

    def test_help_exits_zero(self) -> None:
        code, out, _ = self._run("--help")
        self.assertEqual(code, 0)
        self.assertIn("usage:", out)
        self.assertIn("Not implemented yet", out)

    def test_version_exits_zero(self) -> None:
        code, out, _ = self._run("--version")
        self.assertEqual(code, 0)
        self.assertIn("contract-auditor", out)

    def test_no_command_prints_help(self) -> None:
        code, out, _ = self._run()
        self.assertEqual(code, 0)
        self.assertIn("usage:", out)

    # -- local scan: history contract (Phase 3 pipeline audit) ------------

    def _run_cmd_local_scan(self, proj: Path, analyzer_findings: list) -> tuple[int, str]:
        """Run ``_cmd_scan`` over proj with the three analyzers mocked out."""
        import argparse
        from io import StringIO

        from auditor.analysis.base import AnalysisOutcome
        from auditor.cli import _cmd_scan

        def outcome(items: list):
            o = AnalysisOutcome()
            o.findings = list(items)
            o.evidence = []
            o.notes = []
            return o

        args = argparse.Namespace(
            path=str(proj),
            json=True,
            fail_on=None,
            verbose=False,
            model=None,
            timeout=None,
            no_probe_model=False,
        )
        settings = load_settings()
        with mock.patch(
            "auditor.analysis.reentrancy.analyze",
            return_value=outcome(analyzer_findings),
        ), mock.patch(
            "auditor.analysis.access_control.analyze", return_value=outcome([])
        ), mock.patch(
            "auditor.analysis.slither_generic.analyze", return_value=outcome([])
        ):
            old_stdout = sys.stdout
            sys.stdout = StringIO()
            try:
                code = _cmd_scan(args, settings)
                output = sys.stdout.getvalue()
            finally:
                sys.stdout = old_stdout
        return code, output

    def _make_project(self) -> tuple[Path, str]:
        proj = Path(self._tmpdir.name) / "cli-proj"
        proj.mkdir(exist_ok=True)
        source = (
            "// SPDX-License-Identifier: MIT\n"
            "pragma solidity ^0.8.0;\n"
            "contract Vault { function withdraw() external {} }\n"
        )
        (proj / "Vault.sol").write_text(source, encoding="utf-8")
        return proj, source

    def test_local_scan_marks_history_completed_with_real_hash(self) -> None:
        import hashlib

        from auditor.scan_history import ScanHistory

        proj, source = self._make_project()
        good = Finding(
            title="Reentrancy in Vault.withdraw",
            description="External call before state change.",
            category="reentrancy",
            severity=Severity.HIGH,
            confidence=Confidence.MEDIUM,
            verification_status=VerificationStatus.UNVERIFIED,
            affected_contract="Vault",
            affected_function="withdraw",
            affected_lines=[2],
        )

        code, output = self._run_cmd_local_scan(proj, [good])
        self.assertEqual(code, 0, output)
        payload = json.loads(output)

        expected_hash = hashlib.sha256(source.encode("utf-8")).hexdigest()
        self.assertEqual(payload["content_hash"], expected_hash)
        self.assertEqual(len(payload["findings"]), 1)

        history = ScanHistory(os.environ["AUDITOR_HISTORY_DB"])
        try:
            record = history.get_scan(payload["scan_id"])
        finally:
            history.close()
        self.assertIsNotNone(record)
        self.assertEqual(
            record["status"],
            "completed",
            "CLI scans used to stay 'started' forever, invisible to get_findings()",
        )
        self.assertEqual(record["content_hash"], expected_hash)
        self.assertEqual(len(record["finding_fingerprints"]), 1)

    def test_local_scan_drops_invalid_findings_from_history_and_json(self) -> None:
        from auditor.scan_history import ScanHistory

        proj, _ = self._make_project()
        invalid = Finding(
            title="Confirmed without evidence",
            description="No FACT evidence behind this verdict.",
            category="reentrancy",
            severity=Severity.HIGH,
            confidence=Confidence.MEDIUM,
            verification_status=VerificationStatus.CONFIRMED,
            affected_contract="Vault",
            affected_function="withdraw",
            affected_lines=[2],
        )

        # Must not crash on f.to_dict() (it validates), and the invalid
        # finding must reach neither JSON nor history.
        code, output = self._run_cmd_local_scan(proj, [invalid])
        self.assertEqual(code, 0, output)
        payload = json.loads(output)
        self.assertEqual(payload["findings"], [])

        history = ScanHistory(os.environ["AUDITOR_HISTORY_DB"])
        try:
            record = history.get_scan(payload["scan_id"])
        finally:
            history.close()
        self.assertEqual(record["status"], "completed")
        self.assertEqual(record["finding_fingerprints"], [])

    def test_modules_text_matches_json_count(self) -> None:
        code, out, err = self._run("modules")
        self.assertEqual(code, 0, err)
        self.assertIn("Registered analysis modules: 9", out)  # + privileged_auth (Phase 25), known_exploits (Phase 32)

        code, out, err = self._run("modules", "--json")
        self.assertEqual(code, 0, err)
        payload = json.loads(out)
        self.assertEqual(payload["loadable"], 9)
        self.assertEqual(payload["errors"], [])

    def test_status_json_is_valid_and_complete(self) -> None:
        code, out, err = self._run("status", "--json")
        self.assertEqual(code, 0, err)
        payload = json.loads(out)
        for key in ("auditor", "environment", "toolchain", "ollama", "storage", "analysis_modules"):
            self.assertIn(key, payload)
        self.assertIn("python", payload["toolchain"]["available"])

    def test_status_json_disclaims_unanalyzed(self) -> None:
        _, out, _ = self._run("status", "--json")
        self.assertIn("No contract has been analyzed", json.loads(out)["disclaimer"])

    def test_logs_do_not_pollute_stdout(self) -> None:
        """stdout must stay pipeable into jq."""
        code, out, _ = self._run("-v", "status", "--json")
        self.assertEqual(code, 0)
        json.loads(out)

    def test_address_cli_exit_codes(self) -> None:
        good, out, _ = self._run("validate-address", "0x" + "a" * 40)
        self.assertEqual(good, 0)
        self.assertIn("valid          : yes", out)

        bad, out, _ = self._run("validate-address", "0xnothex")
        self.assertEqual(bad, 1)
        self.assertIn("valid          : no", out)

    def test_model_flag_records_not_installed(self) -> None:
        code, out, _ = self._run("ollama", "--json", "--model", "no-such-model:999b")
        self.assertEqual(code, 0)
        payload = json.loads(out)
        if payload["reachable"]:
            self.assertIs(payload["selected_resolves"], False)

    def test_refused_endpoint_does_not_crash(self) -> None:
        import tempfile

        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as handle:
            json.dump({"model": {"endpoint": "http://example.com:11434"}}, handle)
            config_path = handle.name
        code, out, _ = self._run("--config", config_path, "ollama", "--json")
        self.assertEqual(code, 0)
        self.assertFalse(json.loads(out)["reachable"])

    def test_flags_work_before_and_after_subcommand(self) -> None:
        """Trailing flags are the common habit; both orders must work."""
        leading, _, _ = self._run("--model", "no-such-model:999b", "ollama", "--json")
        trailing, _, _ = self._run("ollama", "--model", "no-such-model:999b", "--json")
        self.assertEqual((leading, trailing), (0, 0))

    def test_no_probe_model_flag_accepted_on_subcommand(self) -> None:
        code, out, _ = self._run("ollama", "--json", "--no-probe-model")
        self.assertEqual(code, 0)
        payload = json.loads(out)
        if payload["reachable"]:
            self.assertIn("disabled", payload["probe_skipped_reason"] or "")

    def test_unknown_config_survives(self) -> None:
        code, out, _ = self._run("--config", "/definitely/not/here.json", "status", "--json")
        self.assertEqual(code, 0)
        json.loads(out)

    @mock.patch("urllib.request.urlopen")
    def test_scan_address_success(self, mock_urlopen) -> None:
        """Test successful verified-source retrieval with mocked HTTP response."""
        import argparse
        from auditor.cli import _cmd_scan_address
        from auditor.settings import load_settings

        # Mock a successful Etherscan API response for a verified contract
        mock_response = mock.MagicMock()
        source_code = (
            "// SPDX-License-Identifier: MIT\n"
            "pragma solidity ^0.8.0;\n"
            "function safeTransfer(address to, uint256 value) external {\n"
            "require(to != address(0);\n"
            "bool success = false;\n"
            "if (success = ERC20(to).transfer(value)) {\n"
            "    ;\n"
            "}\n"
        )
        # Build proper JSON response using json.dumps
        result_obj = [{"SourceCode": source_code}]
        response_json = json.dumps({"status": "1", "message": "OK", "result": result_obj})
        mock_response = mock.MagicMock()
        mock_response.read.return_value = response_json.encode("utf-8")
        mock_response.__enter__ = mock.Mock(return_value=mock_response)
        mock_response.__exit__ = mock.Mock(return_value=False)
        mock_urlopen.return_value = mock_response

        args = argparse.Namespace(
            network="ethereum",
            address="0x1234567890abcdef1234567890abcdef12345678",
            json=True,
            verbose=False,
            model=None,
            timeout=None,
            no_probe_model=False,
        )
        settings = load_settings()
        os.environ["ETHERSCAN_API_KEY"] = "test_key"

        import sys
        from io import StringIO
        old_stdout = sys.stdout
        sys.stdout = StringIO()
        try:
            code = _cmd_scan_address(args, settings)
            output = sys.stdout.getvalue()
        finally:
            sys.stdout = old_stdout

        self.assertEqual(code, 0)
        self.assertIn("scan_id", output)
        self.assertIn("source_hash", output)
        self.assertIn("findings", output.lower())

    @mock.patch("urllib.request.urlopen")
    def test_scan_address_unverified_contract(self, mock_urlopen) -> None:
        """Test that an unverified contract is handled gracefully."""
        import argparse
        from auditor.cli import _cmd_scan_address
        from auditor.settings import load_settings

        mock_response = mock.MagicMock()
        mock_response.read.return_value = b'{"status":"1","message":"OK","result":[]}'
        mock_response.__enter__ = mock.Mock(return_value=mock_response)
        mock_response.__exit__ = mock.Mock(return_value=False)
        mock_urlopen.return_value = mock_response

        args = argparse.Namespace(
            network="ethereum",
            address="0x1234567890abcdef1234567890abcdef12345678",
            json=True,
            verbose=False,
            model=None,
            timeout=None,
            no_probe_model=False,
        )
        settings = load_settings()
        os.environ["ETHERSCAN_API_KEY"] = "test_key"

        import sys
        from io import StringIO
        old_stdout = sys.stdout
        sys.stdout = StringIO()
        try:
            code = _cmd_scan_address(args, settings)
            output = sys.stdout.getvalue()
        finally:
            sys.stdout = old_stdout

        self.assertEqual(code, 1)
        # For unverified contract, error message goes to stderr
        old_stderr = sys.stderr
        sys.stderr = StringIO()
        try:
            _cmd_scan_address(args, settings)
            err_output = sys.stderr.getvalue()
        finally:
            sys.stderr = old_stderr
        self.assertIn("no source code returned", err_output.lower())

    @mock.patch("urllib.request.urlopen")
    def test_scan_address_malformed_json(self, mock_urlopen) -> None:
        """Test handling of non-JSON or malformed response."""
        import argparse
        from auditor.cli import _cmd_scan_address
        from auditor.settings import load_settings

        mock_response = mock.MagicMock()
        mock_response.read.return_value = b"not json at all"
        mock_response.__enter__ = mock.Mock(return_value=mock_response)
        mock_response.__exit__ = mock.Mock(return_value=False)
        mock_urlopen.return_value = mock_response

        args = argparse.Namespace(
            network="ethereum",
            address="0x1234567890abcdef1234567890abcdef12345678",
            json=True,
            verbose=False,
            model=None,
            timeout=None,
            no_probe_model=False,
        )
        settings = load_settings()
        os.environ["ETHERSCAN_API_KEY"] = "test_key"

        import sys
        from io import StringIO
        old_stdout = sys.stdout
        sys.stdout = StringIO()
        try:
            code = _cmd_scan_address(args, settings)
            output = sys.stdout.getvalue()
        finally:
            sys.stdout = old_stdout

        self.assertNotEqual(code, 0)
        # Error messages go to stderr
        old_stderr = sys.stderr
        sys.stderr = StringIO()
        try:
            _cmd_scan_address(args, settings)
            err_output = sys.stderr.getvalue()
        finally:
            sys.stderr = old_stderr
        self.assertIn("error", err_output.lower())

    @mock.patch("urllib.request.urlopen")
    def test_scan_address_api_error(self, mock_urlopen) -> None:
        """Test handling of Etherscan API errors (status != "1")."""
        import argparse
        from auditor.cli import _cmd_scan_address
        from auditor.settings import load_settings

        mock_response = mock.MagicMock()
        mock_response.read.return_value = b'{"status":"0","message":"Invalid API Key","result":[]}'
        mock_response.__enter__ = mock.Mock(return_value=mock_response)
        mock_response.__exit__ = mock.Mock(return_value=False)
        mock_urlopen.return_value = mock_response

        args = argparse.Namespace(
            network="ethereum",
            address="0x1234567890abcdef1234567890abcdef12345678",
            json=True,
            verbose=False,
            model=None,
            timeout=None,
            no_probe_model=False,
        )
        settings = load_settings()
        os.environ["ETHERSCAN_API_KEY"] = "test_key"

        import sys
        from io import StringIO
        old_stdout = sys.stdout
        sys.stdout = StringIO()
        try:
            code = _cmd_scan_address(args, settings)
            output = sys.stdout.getvalue()
        finally:
            sys.stdout = old_stdout

        self.assertNotEqual(code, 0)
        # Error messages go to stderr
        old_stderr = sys.stderr
        sys.stderr = StringIO()
        try:
            _cmd_scan_address(args, settings)
            err_output = sys.stderr.getvalue()
        finally:
            sys.stderr = old_stderr
        self.assertIn("error", err_output.lower())

    @mock.patch("urllib.request.urlopen")
    def test_scan_address_key_not_leaked(self, mock_urlopen) -> None:
        """Ensure the ETHERSCAN_API_KEY is never printed or persisted."""
        import argparse
        from auditor.cli import _cmd_scan_address
        from auditor.settings import load_settings

        mock_response = mock.MagicMock()
        mock_response.read.return_value = b'{"status":"1","message":"OK","result":[{"SourceCode":"// test"}]}'
        mock_response.__enter__ = mock.Mock(return_value=mock_response)
        mock_response.__exit__ = mock.Mock(return_value=False)
        mock_urlopen.return_value = mock_response

        args = argparse.Namespace(
            network="ethereum",
            address="0x1234567890abcdef1234567890abcdef12345678",
            json=True,
            verbose=False,
            model=None,
            timeout=None,
            no_probe_model=False,
        )
        settings = load_settings()
        os.environ["ETHERSCAN_API_KEY"] = "test_key"

        import sys
        from io import StringIO
        old_stdout = sys.stdout
        sys.stdout = StringIO()
        try:
            code = _cmd_scan_address(args, settings)
            output = sys.stdout.getvalue()
        finally:
            sys.stdout = old_stdout

        self.assertEqual(code, 0)
        self.assertNotIn("ETHERSCAN_API_KEY", output)
        # Also check stderr
        old_stderr = sys.stderr
        sys.stderr = StringIO()
        try:
            _cmd_scan_address(args, settings)
            err_output = sys.stderr.getvalue()
        finally:
            sys.stderr = old_stderr
        self.assertNotIn("ETHERSCAN_API_KEY", err_output)

    @mock.patch("urllib.request.urlopen")
    def test_scan_address_v2_endpoint_used(self, mock_urlopen) -> None:
        """Test that the Etherscan API V2 endpoint with chainid=1 is used."""
        import argparse
        from auditor.cli import _cmd_scan_address
        from auditor.settings import load_settings

        mock_response = mock.MagicMock()
        source_code = "// SPDX-License-Identifier: MIT\npragma solidity ^0.8.0;\n"
        result_obj = [{"SourceCode": source_code}]
        response_json = json.dumps({"status": "1", "message": "OK", "result": result_obj})
        mock_response = mock.MagicMock()
        mock_response.read.return_value = response_json.encode("utf-8")
        mock_response.__enter__ = mock.Mock(return_value=mock_response)
        mock_response.__exit__ = mock.Mock(return_value=False)
        mock_urlopen.return_value = mock_response

        args = argparse.Namespace(
            network="ethereum",
            address="0x1234567890abcdef1234567890abcdef12345678",
            json=True,
            verbose=False,
            model=None,
            timeout=None,
            no_probe_model=False,
        )
        settings = load_settings()
        os.environ["ETHERSCAN_API_KEY"] = "test_key"

        import sys
        from io import StringIO
        old_stdout = sys.stdout
        sys.stdout = StringIO()
        try:
            code = _cmd_scan_address(args, settings)
            output = sys.stdout.getvalue()
        finally:
            sys.stdout = old_stdout

        self.assertEqual(code, 0)
        # Verify the V2 endpoint with chainid=1 was called (first request; Phase 19
        # value-at-risk balance/price GETs may follow it)
        request_obj = mock_urlopen.call_args_list[0][0][0]
        if hasattr(request_obj, 'full_url'):
            call_url = request_obj.full_url
        else:
            call_url = str(request_obj)
        self.assertIn("https://api.etherscan.io/v2/api", call_url)
        self.assertIn("chainid=1", call_url)
        self.assertIn("module=contract", call_url)
        self.assertIn("action=getsourcecode", call_url)
        self.assertIn("address=0x1234567890abcdef1234567890abcdef12345678", call_url)
        self.assertIn("apikey=test_key", call_url)




class TestSettings(unittest.TestCase):
    def test_default_config_loads(self) -> None:
        settings = load_settings()
        self.assertEqual(settings.endpoint, "http://localhost:11434")
        self.assertEqual(settings.default_chain, "ethereum")
        self.assertGreater(settings.tool_timeout, 0)
        self.assertIn("max_evidence_mb", settings.limits)

    def test_missing_config_warns_and_falls_back(self) -> None:
        settings = load_settings("/definitely/not/a/config.json")
        self.assertTrue(settings.warnings)
        self.assertEqual(settings.default_chain, "ethereum")

    def test_invalid_json_config_warns_and_falls_back(self) -> None:
        import tempfile

        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as handle:
            handle.write("{ not json")
            path = handle.name
        settings = load_settings(path)
        self.assertTrue(settings.warnings)
        self.assertEqual(settings.default_chain, "ethereum")

    def test_override_merges_without_dropping_siblings(self) -> None:
        import tempfile

        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as handle:
            json.dump({"model": {"name": "qwen2.5vl:3b"}}, handle)
            path = handle.name
        settings = load_settings(path)
        self.assertEqual(settings.model_name, "qwen2.5vl:3b")
        self.assertEqual(settings.endpoint, "http://localhost:11434")


class TestReportTone(unittest.TestCase):
    def test_disclaimer_present(self) -> None:
        self.assertIn("No contract has been analyzed", report_mod.STATUS_DISCLAIMER)

    def test_not_implemented_list_is_non_empty(self) -> None:
        self.assertGreater(len(report_mod.NOT_IMPLEMENTED), 5)

    def test_no_findings_renders_without_claiming_safety(self) -> None:
        text = report_mod.render_findings_table([])
        self.assertIn("No findings recorded", text)
        self.assertNotIn("no vulnerabilities", text.lower())
        self.assertNotIn("safe", text.lower())


if __name__ == "__main__":
    unittest.main(verbosity=2)