"""Pydantic models for the Contract Auditor Dashboard API."""
from __future__ import annotations

from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Optional
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator


class ScanType(str, Enum):
    """Type of scan to perform."""
    LOCAL = "local"
    ADDRESS = "address"
    AI_AUDIT = "ai_audit"
    RETEST = "retest"


class ScanStatus(str, Enum):
    """Status of a scan job."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"


class Confidence(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class VerificationStatus(str, Enum):
    UNVERIFIED = "UNVERIFIED"
    POSSIBLE = "POSSIBLE"
    LIKELY = "LIKELY"
    CONFIRMED = "CONFIRMED"
    DISMISSED = "DISMISSED"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"


class Epistemic(str, Enum):
    FACT = "FACT"
    INFERENCE = "INFERENCE"
    HYPOTHESIS = "HYPOTHESIS"
    UNKNOWN = "UNKNOWN"
    AI_OPINION = "AI_OPINION"


class Network(str, Enum):
    ETHEREUM = "ethereum"


class ToolStatus(str, Enum):
    AVAILABLE = "available"
    MISSING = "missing"
    ERROR = "error"


# Request models
class AddressScanRequest(BaseModel):
    """Request to scan a contract by address."""
    network: Network = Network.ETHEREUM
    address: str = Field(..., pattern=r"^0x[a-fA-F0-9]{40}$", description="EVM contract address")


class ScanMetadataRequest(BaseModel):
    """Analyst-supplied scope metadata recorded with a scan.

    Everything here is optional and labeled as recorded (not independently
    verified) downstream. Unknown fields stay unknown rather than guessed.
    """
    project_name: Optional[str] = Field(None, max_length=200)
    protocol_category: Optional[str] = None
    # No default chain: an unrecorded chain stays Unknown instead of being
    # silently recorded as "ethereum".
    chain: Optional[str] = Field(None, max_length=50)
    contract_address: Optional[str] = Field(None, pattern=r"^0x[a-fA-F0-9]{40}$")
    token_symbol: Optional[str] = Field(None, max_length=20)
    token_address: Optional[str] = Field(None, pattern=r"^0x[a-fA-F0-9]{40}$")
    token_decimals: Optional[str] = Field(None, pattern=r"^\d{1,3}$")
    contract_role: Optional[str] = Field(None, max_length=120)
    notes: Optional[str] = Field(None, max_length=2000)

    @field_validator("protocol_category")
    @classmethod
    def _normalize_category(cls, value: Optional[str]) -> Optional[str]:
        if value is None or not value.strip():
            return None
        from auditor.investigation import PROTOCOL_CATEGORIES

        cleaned = value.strip().lower()
        if cleaned not in PROTOCOL_CATEGORIES:
            raise ValueError(
                f"unknown protocol category {value!r}; allowed: "
                + ", ".join(sorted(PROTOCOL_CATEGORIES))
            )
        return cleaned


class LocalScanRequest(BaseModel):
    """Request to scan a local Solidity project.

    Tool selection is explicit: static analysis (Slither) is on by default;
    Foundry build/test validation is opt-in and recorded separately because
    compilation/tests are not security results.
    """
    path: str = Field(..., description="Path to Solidity file or directory")
    validate_project: bool = Field(False, description="Run forge build as opt-in validation")
    run_static_analysis: bool = Field(True, description="Run Slither static analysis")
    run_tests: bool = Field(False, description="Run forge test as opt-in validation")
    metadata: Optional[ScanMetadataRequest] = None


class AIAuditRequest(BaseModel):
    """Request to run the staged AI audit agent on local sources."""
    path: str = Field(..., description="Local path, or a stored etherscan://<network>/<address> reference")
    scan_id: Optional[str] = Field(None, max_length=64, description="Scan whose exact source version to audit")
    content_hash: Optional[str] = Field(None, max_length=64)
    compile_options: Optional[dict] = None
    deep_tests: bool = Field(False, description="Also run the allowlisted local test suite")
    use_ai: bool = Field(True, description="Allow local LLM enrichment (skipped if unreachable)")
    timeout_seconds: int = Field(600, ge=30, le=3600)
    metadata: Optional[ScanMetadataRequest] = None


class RetestRequest(BaseModel):
    """Request to re-analyze one stored finding and report if it persists.

    ``scan_id`` is optional in the request body; the path parameter is the
    source of truth. When both are present they must match.
    """
    scan_id: Optional[str] = Field(None, min_length=1, max_length=64)
    fingerprint: str = Field(..., min_length=1, max_length=256)


class ScanJobRequest(BaseModel):
    """Unified scan job request."""
    scan_type: ScanType
    local: Optional[LocalScanRequest] = None
    address: Optional[AddressScanRequest] = None
    ai_audit: Optional[AIAuditRequest] = None
    retest: Optional[RetestRequest] = None


# Response models
class ToolInfo(BaseModel):
    key: str
    name: str
    status: ToolStatus
    version: Optional[str] = None
    path: Optional[str] = None
    error: Optional[str] = None
    resolution: Optional[str] = None


class ToolchainStatus(BaseModel):
    tools: list[ToolInfo]
    observations: list[str] = []


class OllamaModel(BaseModel):
    name: str
    size_human: Optional[str] = None
    quantization: Optional[str] = None
    context_length: Optional[int] = None
    capabilities: list[str] = []


class OllamaStatus(BaseModel):
    endpoint: str
    reachable: bool
    error: Optional[str] = None
    models: list[OllamaModel] = []
    selected_model: Optional[str] = None
    selected_resolves: Optional[bool] = None
    selected_loadable: Optional[bool] = None
    selected_error: Optional[str] = None
    probe_skipped_reason: Optional[str] = None


class StorageComponent(BaseModel):
    name: str
    path: str
    exists: bool
    human: str
    file_count: int


class StorageStatus(BaseModel):
    disk_total: str
    disk_free: str
    disk_percent_used: float
    project: StorageComponent
    components: list[StorageComponent]
    temp_artifacts: Optional[StorageComponent] = None
    largest_files: list[tuple[str, str]] = []
    limits: dict[str, Any] = {}
    warnings: list[str] = []


class FindingEvidence(BaseModel):
    evidence_id: str
    source: str
    artifact_type: str
    tool: Optional[str] = None
    location: Optional[str] = None
    contract_address: Optional[str] = None
    chain: Optional[str] = None
    epistemic: Epistemic
    excerpt: str
    content_hash: str
    retrieved_at: str
    proves: list[str] = []
    does_not_prove: list[str] = []
    has_raw: bool = False


class FindingResponse(BaseModel):
    finding_id: str
    title: str
    severity: Severity
    confidence: Confidence
    category: str
    verification_status: VerificationStatus
    description: str
    affected_contract: Optional[str] = None
    affected_function: Optional[str] = None
    affected_lines: list[int] = []
    source: Optional[str] = None
    tool: Optional[str] = None
    reasoning: str = ""
    exploitability: str = ""
    impact: str = ""
    prerequisites: list[str] = []
    likelihood: str = ""
    false_positive_risk: str = ""
    assumptions: list[str] = []
    contradicting_evidence: list[str] = []
    benign_explanation: Optional[str] = None
    remediation: str = ""
    references: list[str] = []
    evidence: list[FindingEvidence] = []
    fact_evidence_count: int = 0
    ai_evidence_count: int = 0
    created_at: str


class ScanSummary(BaseModel):
    """History-list row. History queries do not always carry every field,
    so only the identifiers are strict."""

    scan_id: str
    timestamp: str = ""
    source_path: str = ""
    content_hash: str = ""
    config_fingerprint: str = ""
    status: str = ""
    finding_count: int = 0
    findings_by_severity: dict[str, int] = {}
    error_info: Optional[str] = None


class StoredFinding(BaseModel):
    """A finding as persisted in scan history.

    History stores a minimal summary (fingerprint/title/severity/category/
    status), while live results carry the full record. Both shapes load here;
    unknown keys are preserved rather than dropped.
    """

    model_config = ConfigDict(extra="allow")

    fingerprint: Optional[str] = None
    finding_id: Optional[str] = None
    title: str = ""
    severity: Optional[Severity] = None
    category: Optional[str] = None
    verification_status: Optional[VerificationStatus] = None
    status: Optional[VerificationStatus] = None
    confidence: Optional[Confidence] = None
    description: str = ""
    affected_contract: Optional[str] = None
    affected_function: Optional[str] = None
    affected_lines: list[int] = []
    reasoning: str = ""
    remediation: str = ""
    source: Optional[str] = None
    tool: Optional[str] = None
    evidence: list[FindingEvidence] = []
    fact_evidence_count: int = 0
    ai_evidence_count: int = 0
    created_at: str = ""

    @property
    def effective_status(self) -> Optional[str]:
        return (self.verification_status or self.status)


class ToolRunModel(BaseModel):
    """Recorded execution status of one tool for one scan.

    Statuses are observations, never pass/fail security verdicts: ``failed``
    means the tool did not complete, and ``not_requested`` means it was
    deselected for that scan.
    """

    model_config = ConfigDict(extra="allow")

    key: str
    label: str = ""
    kind: str = "static-analysis"
    status: str = "unknown"
    requested: bool = True
    returncode: Optional[int] = None
    duration_seconds: float = 0.0
    message: str = ""
    error: Optional[str] = None
    finding_count: Optional[int] = None
    severity_counts: dict[str, int] = {}
    detectors: dict[str, int] = {}
    excluded_count: int = 0
    version: Optional[str] = None
    target: Optional[str] = None
    argv: Optional[list[str]] = None


class ScanDetail(ScanSummary):
    findings: list[StoredFinding] = []
    # Fingerprints are tuples serialized as JSON arrays by scan history.
    finding_fingerprints: list[Any] = []
    finding_details: list[Any] = []
    graph_snapshot: Optional[dict[str, Any]] = None
    # Tool execution (Phase 12). None = not recorded for this scan (legacy).
    tool_runs: list[ToolRunModel] = []
    validation: Optional[dict[str, Any]] = None
    scan_complete: Optional[bool] = None
    incomplete_reasons: list[str] = []
    zero_findings_note: Optional[str] = None


class ScanJobResponse(BaseModel):
    job_id: str
    scan_type: ScanType
    status: ScanStatus
    created_at: datetime
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    progress: float = 0.0
    message: str = ""
    result: Optional[ScanDetail] = None
    error: Optional[str] = None
    local_path: Optional[str] = None
    address: Optional[str] = None
    network: Optional[Network] = None
    # AI-audit / retest observability (additive; empty for plain scans)
    stages: list[dict[str, Any]] = []
    log: list[str] = []
    elapsed_seconds: Optional[float] = None
    report: Optional[dict[str, Any]] = None


class FindingStateChangeRequest(BaseModel):
    """Explicit analyst transition for one finding."""
    fingerprint: str = Field(..., min_length=1, max_length=256)
    state: str = Field(..., min_length=1, max_length=64)
    note: Optional[str] = Field(None, max_length=1000)
    evidence_ref: Optional[str] = Field(None, max_length=300)


class BountyCheckRequest(BaseModel):
    """Run a read-only bounty check for one finding's scan."""
    project_name: Optional[str] = Field(None, max_length=200)
    official_url: Optional[str] = Field(None, max_length=800)
    asset: Optional[str] = Field(None, max_length=120)
    category: Optional[str] = Field(None, max_length=50)


class ProposePatchRequest(BaseModel):
    """Ask OpenCode for a proposal (draft only — never applied).

    ``scan_id`` is optional; the path parameter is authoritative. When both
    are present they must match.
    """
    scan_id: Optional[str] = Field(None, min_length=1, max_length=64)
    fingerprint: str = Field(..., min_length=1, max_length=256)


class ApplyPatchRequest(BaseModel):
    """Apply a stored proposal. Approval must be explicit and per-request."""
    approval: bool = False
    expected_before_hash: Optional[str] = Field(None, min_length=64, max_length=64)


class ScanHistoryResponse(BaseModel):
    scans: list[ScanSummary]
    total: int


class OverviewStats(BaseModel):
    total_scans: int
    completed_scans: int
    failed_scans: int
    total_findings: int
    findings_by_severity: dict[str, int]
    recent_scans: list[ScanSummary]


class ToolchainResponse(BaseModel):
    """Raw toolchain/Ollama/storage payloads.

    These are passed through from the CLI status payload verbatim; shaping
    them further in Python would duplicate detection logic for no gain.
    """

    toolchain: dict[str, Any]
    ollama: dict[str, Any]
    storage: dict[str, Any]
    analysis_modules: dict[str, Any]
    configuration: dict[str, Any]


# ---------------------------------------------------------------------------
# Benchmark (Phase 14) — read-only views over benchmark_store
# ---------------------------------------------------------------------------

class BenchmarkFixtureResult(BaseModel):
    """One fixture's scored result (never the production scan history)."""

    fixture_id: str
    category: str
    expected_label: str
    status: str
    verdict: Optional[str] = None
    matched_check: Optional[str] = None
    matched_title: Optional[str] = None
    expected_contract: Optional[str] = None
    expected_function: Optional[str] = None
    actual_contract: Optional[str] = None
    actual_function: Optional[str] = None
    other_findings: list[dict[str, Any]] = Field(default_factory=list)
    evidence: Optional[dict[str, Any]] = None
    na_reason: Optional[str] = None
    reason: Optional[str] = None
    metadata_gaps: int = 0
    evidence_insufficient: int = 0


class BenchmarkRunSummary(BaseModel):
    """Run header without the per-fixture rows (history listing)."""

    run_id: str
    started_at: str = ""
    finished_at: str = ""
    status: str = ""
    toolchain: dict[str, Any] = Field(default_factory=dict)
    totals: dict[str, Any] = Field(default_factory=dict)
    is_baseline: bool = False


class BenchmarkRunDetail(BenchmarkRunSummary):
    """A full stored run: summary + metrics + every fixture result."""

    metrics: dict[str, Any] = Field(default_factory=dict)
    notes: list[str] = Field(default_factory=list)
    results: list[BenchmarkFixtureResult] = Field(default_factory=list)
    manifest: Optional[str] = None
    fixtures_dir: Optional[str] = None
    toolchain_fingerprint: Optional[str] = None
    corpus_fingerprint: Optional[str] = None
    reconciliation: dict[str, Any] = Field(default_factory=dict)


# Error response
class ErrorResponse(BaseModel):
    error: str
    detail: Optional[str] = None