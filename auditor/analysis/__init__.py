"""Analysis modules for contract-auditor.

Each module under this package exposes ``NAME``, ``CATEGORY``, and an
``analyze(context)`` function that returns an ``AnalysisOutcome``. The registry
discovers modules under the ``analysis`` package by capability — no CLI changes
are required when new modules are added.

Typical usage::

    from auditor.analysis.reentrancy import analyze as reentrancy_analyze
    from auditor.analysis.base import AnalysisContext

    outcome = reentrancy_analyze.analyze(AnalysisContext(
        source_files=[Path("contracts/MyContract.sol")]
    ))
"""

from __future__ import annotations

NAME = "analysis"
CATEGORY = "static-analysis"