"""Base types and protocol for analysis modules.

Live analyzers are the module-level ``analyze(context)`` functions in
``reentrancy.py``, ``access_control.py``, and ``slither_generic.py`` — they
consume the shared cached Slither JSON run via ``slither_runner``. This
module holds the shared ``AnalysisContext``/``AnalysisOutcome`` types and
the ``BaseAnalyzer`` ABC (the documented extension point for future
analyzers), which encapsulates subprocess invocation with ``shell=False``,
enforced timeouts, and captured stdout/stderr so that broken or malicious
analyzers cannot compromise the audit run.

Earlier class-based ``ReentrancyAnalyzer``/``AccessControlAnalyzer``
implementations (text-only parsers with divergent, false-positive-prone
heuristics) were removed in the detector-validation pass; nothing
referenced them.
"""

from __future__ import annotations

import logging
import subprocess
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Tuple

from ..model import EvidenceItem, Epistemic, Finding

log = logging.getLogger("contract_auditor.analysis")


class AnalysisContext:
    """Everything an analyzer is allowed to rely on.

    Deliberately empty of unverified conclusions: an analyzer receives raw
    inputs and must produce its own evidence.
    """

    audit_id: str | None = None
    chain: str | None = None
    address: str | None = None
    source_files: list[Path] = None
    abi: Any = None
    bytecode: bytes | None = None
    evidence: list[EvidenceItem] = None
    options: dict[str, Any] = None


class AnalysisOutcome:
    """What an analyzer returns."""

    findings: list[Finding] = None
    evidence: list[EvidenceItem] = None
    notes: list[str] = None
    epistemic_ceiling: Epistemic = Epistemic.HYPOTHESIS

    def merge(self, other: "AnalysisOutcome") -> "AnalysisOutcome":
        self.findings.extend(other.findings)
        self.evidence.extend(other.evidence)
        self.notes.extend(other.notes)
        return self


class BaseAnalyzer(ABC):
    """Base class for all analysis modules.

    Subclasses must define ``NAME``, ``CATEGORY``, and implement ``analyze()``.
    The default ``analyze()`` invocation is safe by default: ``shell=False``,
    hard timeout, captured streams, and failure isolation.
    """

    NAME: str
    CATEGORY: str

    @abstractmethod
    def analyze(self, context: AnalysisContext) -> AnalysisOutcome:
        """Run the analysis and return an ``AnalysisOutcome``."""
        ...

    def _run_subprocess(
        self,
        args: list[str],
        timeout: int = 30,
        cwd: Path | None = None,
    ) -> Tuple[str, str, int]:
        """Run a subprocess safely and return stdout, stderr, and returncode.

        Raises ``subprocess.TimeoutExpired`` if the subprocess does not finish
        within ``timeout`` seconds.
        """
        try:
            result = subprocess.run(
                args,
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=str(cwd) if cwd else None,
                shell=False,
            )
            return result.stdout, result.stderr, result.returncode
        except subprocess.TimeoutExpired as exc:
            log.warning("analyzer timeout after %s seconds: %s", timeout, self.NAME)
            return exc.stdout or "", exc.stderr or "", -1
        except Exception as exc:  # noqa: BLE001 - unexpected errors are logged
            log.exception("analyzer subprocess failed: %s", self.NAME)
            return "", str(exc), -1
