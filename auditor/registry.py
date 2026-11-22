"""Analysis module registry.

Phase 1 registers nothing. The point of this module is that adding
``analysis/reentrancy.py`` later must require no change to the CLI: the
registry discovers modules by capability, not by hardcoded import list.

An analyzer is any module exposing::

    NAME: str
    CATEGORY: str
    def analyze(context: "AnalysisContext") -> "AnalysisOutcome"

Discovery is deliberately forgiving: a module that fails to import is recorded
as a registry error rather than crashing the run. One broken future analyzer
must not take down static analysis.
"""

from __future__ import annotations

import importlib
import inspect
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

from .model import Epistemic, EvidenceItem, Finding

__all__ = [
    "AnalysisContext",
    "AnalysisOutcome",
    "Analyzer",
    "RegisteredAnalyzer",
    "RegistryReport",
    "discover_analyzers",
]

log = logging.getLogger("contract_auditor.registry")

ANALYSIS_PACKAGE = "auditor.analysis"


@runtime_checkable
class Analyzer(Protocol):
    """Structural protocol every analysis module must satisfy."""

    NAME: str
    CATEGORY: str

    def analyze(self, context: "AnalysisContext") -> "AnalysisOutcome":  # pragma: no cover - protocol
        ...


@dataclass
class AnalysisContext:
    """Everything an analyzer is allowed to rely on.

    Deliberately empty of unverified conclusions: an analyzer receives raw
    inputs and must produce its own evidence.
    """

    audit_id: str | None = None
    chain: str | None = None
    address: str | None = None
    source_files: list[Path] = field(default_factory=list)
    abi: Any = None
    bytecode: bytes | None = None
    evidence: list[EvidenceItem] = field(default_factory=list)
    options: dict[str, Any] = field(default_factory=dict)


@dataclass
class AnalysisOutcome:
    """What an analyzer returns."""

    findings: list[Finding] = field(default_factory=list)
    evidence: list[EvidenceItem] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    epistemic_ceiling: Epistemic = Epistemic.HYPOTHESIS
    """Analyzers may not exceed this without independently produced FACTs.

    Static analysis, for example, produces observations about code shape. It
    does not prove exploitability, so it is capped at HYPOTHESIS by default.
    """

    def merge(self, other: "AnalysisOutcome") -> "AnalysisOutcome":
        self.findings.extend(other.findings)
        self.evidence.extend(other.evidence)
        self.notes.extend(other.notes)
        return self


@dataclass
class RegisteredAnalyzer:
    module_name: str
    name: str
    category: str
    loadable: bool
    error: str | None = None


@dataclass
class RegistryReport:
    analyzers: list[RegisteredAnalyzer] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def loadable(self) -> list[RegisteredAnalyzer]:
        return [entry for entry in self.analyzers if entry.loadable]

    def to_dict(self) -> dict[str, Any]:
        return {
            "count": len(self.analyzers),
            "loadable": len(self.loadable()),
            "analyzers": [
                {
                    "module": entry.module_name,
                    "name": entry.name,
                    "category": entry.category,
                    "loadable": entry.loadable,
                    "error": entry.error,
                }
                for entry in self.analyzers
            ],
            "errors": list(self.errors),
            "note": (
                "Analyzers are auto-discovered from the analysis package; "
                "modules without a callable analyze() are support modules "
                "and are skipped. New analyzers attach without CLI changes."
            ),
        }


def discover_analyzers(package: str = ANALYSIS_PACKAGE) -> RegistryReport:
    """Discover analyzer modules under ``package`` without importing blindly."""
    report = RegistryReport()

    try:
        pkg = importlib.import_module(package)
    except ModuleNotFoundError:
        log.debug("analysis package %s not present; nothing to register", package)
        return report
    except Exception as exc:  # noqa: BLE001 - a broken package must not kill the run
        message = f"failed to import {package}: {type(exc).__name__}: {exc}"
        log.warning("%s", message)
        report.errors.append(message)
        return report

    search_paths = list(getattr(pkg, "__path__", []) or [])
    module_names: list[str] = []
    for search_path in search_paths:
        for entry in sorted(Path(search_path).glob("*.py")):
            if entry.stem == "__init__":
                continue
            module_names.append(f"{package}.{entry.stem}")

    for module_name in module_names:
        try:
            module = importlib.import_module(module_name)
        except Exception as exc:  # noqa: BLE001 - isolate broken analyzers
            message = f"{module_name}: {type(exc).__name__}: {exc}"
            log.warning("analyzer import failed: %s", message)
            report.analyzers.append(
                RegisteredAnalyzer(module_name, module_name, "unknown", False, message)
            )
            report.errors.append(message)
            continue

        analyze = getattr(module, "analyze", None)
        if not callable(analyze):
            # Support module (e.g. base.py, slither_runner.py): not an
            # analyzer by contract. Skipping silently keeps `modules`/
            # `status` errors meaningful instead of permanently noisy.
            log.debug("%s has no analyze(); treating as support module", module_name)
            continue

        signature_ok = _accepts_context(analyze)
        entry = RegisteredAnalyzer(
            module_name=module_name,
            name=str(getattr(module, "NAME", module_name)),
            category=str(getattr(module, "CATEGORY", "uncategorized")),
            loadable=signature_ok,
            error=None if signature_ok else "analyze() does not accept an AnalysisContext",
        )
        report.analyzers.append(entry)

    return report


def _accepts_context(func: Any) -> bool:
    """True if ``func`` can be called with an AnalysisContext."""
    try:
        signature = inspect.signature(func)
    except (TypeError, ValueError):
        return False

    for parameter in signature.parameters.values():
        if parameter.kind in (parameter.VAR_POSITIONAL, parameter.VAR_KEYWORD):
            continue
        if parameter.name in ("context", "ctx"):
            return True
    return False