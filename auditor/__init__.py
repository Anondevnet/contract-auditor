"""contract-auditor: local-first smart-contract security analysis engine.

Phase 1 scope: local toolchain / Ollama / storage intelligence only.
No blockchain retrieval, no RPC, no external network access, no installs.

Design invariants enforced by this package:

* Tool availability is *observed*, never assumed. A missing tool is reported
  as unavailable with the underlying error, never faked as success.
* Epistemic status is explicit. FACT / INFERENCE / HYPOTHESIS / UNKNOWN /
  AI_OPINION are distinct and never silently collapsed into one another.
* A finding cannot reach CONFIRMED without at least one FACT-backed evidence
  item. See ``auditor.model.Finding.validate``.
* Subprocess execution never uses a shell. See ``auditor.procs``.
"""

from __future__ import annotations

__all__ = [
    "__version__",
    "AUDITOR_NAME",
    "SCHEMA_VERSION",
]

__version__ = "0.1.0"
AUDITOR_NAME = "contract-auditor"
SCHEMA_VERSION = 1