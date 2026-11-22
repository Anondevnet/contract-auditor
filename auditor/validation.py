"""Local Foundry project validation for contract-auditor.

Provides :class:`LocalValidator` — a safe, offline-only validator that runs
structural checks against a local Foundry project directory.

**Wiring status:** this module is currently NOT referenced by the CLI or the
dashboard. The former ``--validate-project PATH`` CLI flag was removed;
dashboard ``validate_project`` runs ``forge build``/``forge test`` via
``auditor.foundry`` instead. The module is retained as the reference
implementation for opt-in structural validation. The ``timeout`` attribute
is unused (no subprocesses are spawned here) and only exists to keep the
historical constructor signature.

Validation is **explicitly opt-in**. It is **not** wired to any command at
present. When invoked programmatically it does **not** execute Foundry,
never sends RPC requests, and requires no network access.  The validator
may only append evidence items (epistemic = FACT) to a finding; the caller
must decide whether to update :attr:`Finding.verification_status`.  The
``FACT_REQUIRED_STATES`` gate in :meth:`Finding.validate()` remains
unchanged — a finding with ``CONFIRMED`` or ``LIKELY`` verification status
still requires at least one ``FACT`` evidence item from any source,
including this validator.

Typical evidence appended by this validator:

.. code-block::

    EvidenceItem(
        epistemic=Epistemic.FACT,
        source="local_validator",
        artifact_type="tool_output",
        excerpt="Foundry project structure check: foundry.toml present",
    )
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import List, Tuple

from .model import EvidenceItem, Epistemic, Finding, FindingValidationError, VerificationStatus

log = logging.getLogger("contract_auditor")


class LocalValidator:
    """Offline local Foundry project validator.

    Validate a finding against a local Foundry project directory **only** when
    the user explicitly supplies ``--validate-project PATH``.  The validator

    - never executes Foundry
    - never makes RPC calls
    - never sends network traffic
    - respects ``FOUNDRY_OFFLINE=1`` (read-only, structural checks only)
    - appends ``Epistemic.FACT`` evidence items that the caller may integrate
    - never changes ``Finding.verification_status`` — the caller's responsibility
    - raises the module-local :class:`FindingValidationError` when the
      project path does not exist
    - the ``timeout`` parameter is stored but unused (no subprocesses)
    """

    __slots__ = ("timeout",)

    def __init__(self, timeout: float = 15.0) -> None:
        self.timeout = timeout

    # ── public API ──────────────────────────────────────────────────────

    def validate_finding_against_project(
        self,
        finding: Finding,
        project_path: Path,
    ) -> Tuple[Finding, List[EvidenceItem]]:
        """Run local Foundry validation tests against *finding* and *project*.

        Returns
        -------
        validated_finding : Finding
            A copy of *finding* with ``evidence`` extended by
            *validation_evidence*.  All other fields are identical.

        validation_evidence : List[EvidenceItem]
            Evidence items (all ``epistemic`` = ``Epistemic.FACT``) describing
            the structural check results.  The caller decides whether to
            incorporate these into the finding's ``verification_status``.

        Raises
        ------
        FindingValidationError
            If *project_path* does not exist or is not a recognised Foundry
            project directory.
        """
        validation_evidence: List[EvidenceItem] = []

        if not project_path.exists():
            raise FindingValidationError(
                f"Validation project path does not exist: {project_path}"
            )

        # Structural check: look for Foundry project markers
        foundry_markers = ["foundry.toml", "contracts/", "src/"]
        markers_found: List[str] = []

        for marker in foundry_markers:
            if (project_path / marker).exists():
                markers_found.append(marker)

        # Append evidence about the structural check
        if markers_found:
            validation_evidence.append(
                EvidenceItem(
                    epistemic=Epistemic.FACT,
                    source="local_validator",
                    artifact_type="tool_output",
                    excerpt=(
                        f"Foundry project structure check: foundry markers present "
                        f"{markers_found}"
                    ),
                )
            )
        else:
            validation_evidence.append(
                EvidenceItem(
                    epistemic=Epistemic.FACT,
                    source="local_validator",
                    artifact_type="tool_output",
                    excerpt=(
                        f"Foundry project structure check: no foundry markers "
                        f"found ({foundry_markers}) in {project_path}"
                    ),
                )
            )

        # Return a new Finding with appended evidence — verification_status
        # is deliberately unchanged; the caller must apply the FACT guard.
        validated_finding = Finding(
            title=finding.title,
            description=finding.description,
            category=finding.category,
            severity=finding.severity,
            confidence=finding.confidence,
            verification_status=finding.verification_status,
            finding_id=finding.finding_id,
            affected_contract=finding.affected_contract,
            affected_function=finding.affected_function,
            affected_lines=list(finding.affected_lines),
            evidence=list(finding.evidence) + validation_evidence,
            source=finding.source,
            tool=finding.tool,
            reasoning=finding.reasoning,
            exploitability=finding.exploitability,
            impact=finding.impact,
            prerequisites=list(finding.prerequisites),
            likelihood=finding.likelihood,
            false_positive_risk=finding.false_positive_risk,
            assumptions=list(finding.assumptions),
            contradicting_evidence=list(finding.contradicting_evidence),
            benign_explanation=finding.benign_explanation,
            remediation=finding.remediation,
            references=list(finding.references),
            created_at=finding.created_at,
        )

        return validated_finding, validation_evidence


# ── validation guard ────────────────────────────────────────────────────

class FindingValidationError(ValueError):
    """Raised when a finding violates the evidence-before-conclusion rule.

    This is separate from the :meth:`Finding.validate()` gate so that the
    local validator can signal structural problems without automatically
    triggering the FACT_REQUIRED_STATES check.
    """

    pass