"""Structured data model: epistemic status, evidence, findings, audit runs.

The central rule of this system lives here: severity and confidence are
independent axes, and epistemic status is never silently upgraded. A finding
cannot become CONFIRMED on the strength of an AI_OPINION or a HYPOTHESIS.
"""

from __future__ import annotations

import hashlib
import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Iterable

log = logging.getLogger("contract_auditor")

__all__ = [
    "Confidence",
    "Epistemic",
    "FindingValidationError",
    "Severity",
    "VerificationStatus",
    "EvidenceItem",
    "Finding",
    "AuditRun",
    "sha256_text",
    "utc_now_iso",
]


def utc_now_iso() -> str:
    """Timestamp used across all evidence records."""
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def sha256_text(text: str) -> str:
    """Content hash so evidence can be proven unaltered later."""
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()


class Epistemic(str, Enum):
    """How much weight a piece of information may carry."""

    FACT = "FACT"
    """Directly observed tool output or retrieved artifact."""

    INFERENCE = "INFERENCE"
    """Reasonable conclusion derived from one or more facts."""

    HYPOTHESIS = "HYPOTHESIS"
    """Plausible issue that still requires verification."""

    UNKNOWN = "UNKNOWN"
    """Information unavailable or insufficient to conclude."""

    AI_OPINION = "AI_OPINION"
    """Model-generated interpretation, not independently verified."""


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"


SEVERITY_ORDER: dict[Severity, int] = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFORMATIONAL: 4,
}


class Confidence(str, Enum):
    """Separate axis from severity. HIGH sev + LOW conf != HIGH sev + HIGH conf."""

    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class VerificationStatus(str, Enum):
    """Explicit decision states. No jumping POSSIBLE -> CONFIRMED."""

    UNVERIFIED = "UNVERIFIED"
    POSSIBLE = "POSSIBLE"
    LIKELY = "LIKELY"
    CONFIRMED = "CONFIRMED"
    DISMISSED = "DISMISSED"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"


def finding_fingerprint(finding: Finding) -> tuple:
    """Stable fingerprint for a Finding: contract, function, lines, title prefix, file.

    Two findings with the same fingerprint represent the same underlying
    issue detected by possibly different detectors or reported multiple
    times.  They are merged by keeping the first and combining evidence.

    The detector prefix (e.g. "Reentrancy" vs "Access control") is included
    so that genuinely different vulnerability classes are not incorrectly
    merged even when they share the same contract/function/lines.

    ``affected_file`` is appended as the fifth element (empty when unknown,
    single-file scan, or analyzer could not attribute one) so that two files
    declaring the same contract name are not merged into one finding.
    Fingerprinting remains a pure function of the Finding and is
    deterministic across repeated runs on identical input.
    """
    # Extract the detector/category prefix from the title. A blank title
    # must not crash fingerprinting (the finding is dropped later by
    # validated_findings/validate() instead).
    words = finding.title.split()
    title_prefix = words[0] if words else ""
    return (
        finding.affected_contract or "",
        finding.affected_function or "",
        tuple(sorted(finding.affected_lines)) if finding.affected_lines else (),
        title_prefix,
        finding.affected_file or "",
    )


def validated_findings(findings: Iterable[Finding]) -> list[Finding]:
    """Drop findings that fail their own validation before persistence.

    Shared contract: dashboard scans and CLI scans must store and report
    exactly the same set. A finding that cannot serialize itself (e.g.
    CONFIRMED without FACT evidence) is logged and dropped — never kept
    in history, never counted in a report.
    """
    kept: list[Finding] = []
    for finding in findings:
        try:
            finding.validate()
        except Exception as exc:  # noqa: BLE001 - one bad finding must not sink a scan
            log.warning("Dropping finding that failed validation: %s", exc)
            continue
        kept.append(finding)
    return kept


def deduplicate_findings(findings: list[Finding]) -> tuple[list[Finding], int]:
    """Merge duplicate findings and return (unique_findings, duplicate_count).

    This is the single canonical dedupe implementation for the whole
    pipeline (CLI scans, dashboard scans, AI audits, retests, benchmark).
    Two findings are duplicates when their ``finding_fingerprint`` matches:
    (contract, function, sorted lines, title prefix, affected_file).

    Merging keeps the FIRST finding seen (so output order is deterministic
    and provenance is stable) and folds the duplicate in without discarding
    information:

    * evidence: union by ``content_hash`` (same excerpt is not duplicated;
      different excerpts from the other detector are appended);
    * description: the duplicate's description is appended when it adds
      text (Slither detector slugs from both detectors survive);
    * severity: upgraded to the more severe of the two (unknown severities
      never upgrade an existing known severity);
    * confidence and all other fields: first finding wins (documented,
      deterministic — no silent recalculation).

    Mutates the first finding in place; callers pass freshly collected
    analyzer output, never shared cached objects.

    Returns:
        (unique_findings, duplicate_count) where duplicate_count is
        the number of findings that were merged away.
    """
    merged: dict[tuple, Finding] = {}
    order: list[tuple] = []
    duplicate_count = 0

    for finding in findings:
        key = finding_fingerprint(finding)
        original = merged.get(key)
        if original is None:
            merged[key] = finding
            order.append(key)
            continue
        seen_hashes = {
            getattr(ev, "content_hash", None)
            for ev in original.evidence
        }
        for item in finding.evidence:
            item_hash = getattr(item, "content_hash", None)
            if item_hash not in seen_hashes:
                original.evidence.append(item)
                seen_hashes.add(item_hash)
        second = str(finding.description or "").strip()
        if second and second not in str(original.description or ""):
            original.description = (
                str(original.description or "") + "\n" + second
            ).strip()
        # Severity: keep the more severe. Unknown incoming severity must
        # never "win" against a known one (lookup default is the LEAST
        # severe position); unknown existing severity loses to any known.
        if (
            SEVERITY_ORDER.get(finding.severity, 99)
            < SEVERITY_ORDER.get(original.severity, 99)
        ):
            original.severity = finding.severity
        duplicate_count += 1

    return [merged[key] for key in order], duplicate_count


#: States that assert a real defect is present. Reaching one of these from
#: anything other than CONFIRMED still requires a recorded justification.
DEFECT_STATES = frozenset(
    {VerificationStatus.CONFIRMED, VerificationStatus.LIKELY, VerificationStatus.POSSIBLE}
)

#: States that require at least one FACT-backed evidence item, because they
#: represent an assertion about the target rather than a plan to look.
FACT_REQUIRED_STATES = frozenset({VerificationStatus.CONFIRMED, VerificationStatus.LIKELY})


@dataclass
class EvidenceItem:
    """One retrievable observation with full provenance."""

    source: str
    """Where it came from, e.g. 'forge --version', 'slither', 'ollama'."""

    artifact_type: str
    """e.g. 'tool_output', 'source_file', 'abi', 'bytecode', 'transaction'."""

    excerpt: str
    """The relevant content, possibly truncated. Never fabricated."""

    epistemic: Epistemic = Epistemic.FACT
    tool: str | None = None
    location: str | None = None
    contract_address: str | None = None
    chain: str | None = None
    content_hash: str | None = None
    retrieved_at: str = field(default_factory=utc_now_iso)
    raw: str | None = None
    proves: list[str] = field(default_factory=list)
    does_not_prove: list[str] = field(default_factory=list)
    evidence_id: str = field(default_factory=lambda: f"EV-{uuid.uuid4().hex[:12]}")

    def __post_init__(self) -> None:
        if self.content_hash is None:
            self.content_hash = sha256_text(self.excerpt)

    def to_dict(self) -> dict[str, Any]:
        return {
            "evidence_id": self.evidence_id,
            "source": self.source,
            "artifact_type": self.artifact_type,
            "tool": self.tool,
            "location": self.location,
            "contract_address": self.contract_address,
            "chain": self.chain,
            "epistemic": self.epistemic.value,
            "excerpt": self.excerpt,
            "content_hash": self.content_hash,
            "retrieved_at": self.retrieved_at,
            "proves": list(self.proves),
            "does_not_prove": list(self.does_not_prove),
            "has_raw": self.raw is not None,
        }


class FindingValidationError(ValueError):
    """Raised when a finding violates the evidence-before-conclusion rule."""


@dataclass
class Finding:
    """A single potential security issue, with its full reasoning trail."""

    title: str
    description: str
    category: str
    severity: Severity = Severity.INFORMATIONAL
    confidence: Confidence = Confidence.LOW
    verification_status: VerificationStatus = VerificationStatus.UNVERIFIED
    finding_id: str = field(default_factory=lambda: f"F-{uuid.uuid4().hex[:12]}")
    affected_contract: str | None = None
    affected_function: str | None = None
    affected_lines: list[int] = field(default_factory=list)
    affected_file: str | None = None
    assets_affected: list[str] = field(default_factory=list)
    evidence: list[EvidenceItem] = field(default_factory=list)
    source: str | None = None
    tool: str | None = None
    reasoning: str = ""
    exploitability: str = ""
    impact: str = ""
    prerequisites: list[str] = field(default_factory=list)
    likelihood: str = ""
    false_positive_risk: str = ""
    assumptions: list[str] = field(default_factory=list)
    contradicting_evidence: list[str] = field(default_factory=list)
    benign_explanation: str | None = None
    remediation: str = ""
    references: list[str] = field(default_factory=list)
    created_at: str = field(default_factory=utc_now_iso)
    # Phase 25+.5 — confirmed outsider-exploitable with real money at risk.
    # Never set from an unconfirmed UNPROTECTED/WEAK privileged-auth hit alone.
    confirmed_exploitable: bool = False
    verified_at: str | None = None
    verified_by: str | None = None  # "sim" | "manual"
    takeable_usd: float | None = None

    # -- evidence helpers ------------------------------------------------

    @property
    def fact_evidence(self) -> list[EvidenceItem]:
        return [item for item in self.evidence if item.epistemic is Epistemic.FACT]

    @property
    def ai_evidence(self) -> list[EvidenceItem]:
        return [item for item in self.evidence if item.epistemic is Epistemic.AI_OPINION]

    def add_evidence(self, item: EvidenceItem) -> "Finding":
        self.evidence.append(item)
        return self

    # -- guardrails ------------------------------------------------------

    def validate(self) -> None:
        """Enforce that no conclusion outruns its evidence.

        Raises FindingValidationError on violation. Called before any finding
        is serialized into a report, so an unsupported CONFIRMED verdict cannot
        escape the system.
        """
        if self.verification_status in FACT_REQUIRED_STATES and not self.fact_evidence:
            raise FindingValidationError(
                f"{self.finding_id}: status {self.verification_status.value} requires at "
                f"least one FACT evidence item; found "
                f"{len(self.evidence)} evidence item(s), "
                f"{len(self.ai_evidence)} of them AI_OPINION."
            )

        if self.verification_status is VerificationStatus.FALSE_POSITIVE and not self.benign_explanation:
            raise FindingValidationError(
                f"{self.finding_id}: FALSE_POSITIVE requires a benign_explanation."
            )

        if self.confirmed_exploitable:
            if self.verification_status is not VerificationStatus.CONFIRMED:
                raise FindingValidationError(
                    f"{self.finding_id}: confirmed_exploitable requires verification_status=CONFIRMED."
                )
            if self.verified_by not in ("sim", "manual"):
                raise FindingValidationError(
                    f"{self.finding_id}: confirmed_exploitable requires verified_by sim|manual."
                )
            if not (self.verified_at or "").strip():
                raise FindingValidationError(
                    f"{self.finding_id}: confirmed_exploitable requires verified_at."
                )
            if self.takeable_usd is None or float(self.takeable_usd) < 0:
                raise FindingValidationError(
                    f"{self.finding_id}: confirmed_exploitable requires takeable_usd >= 0."
                )

        if not self.title.strip():
            raise FindingValidationError(f"{self.finding_id}: title must not be empty.")

        if any(line < 1 for line in self.affected_lines):
            raise FindingValidationError(
                f"{self.finding_id}: affected_lines must be 1-based positive integers."
            )

    def priority_score(self) -> tuple[int, int, str]:
        """Sort key: severity, then confidence, then stable content.

        Confidence ranks inversely so that among equal severities the
        better-supported finding surfaces first. The final tie-break is
        content-based (never the random finding_id) so reports and table
        ordering are reproducible across runs on identical input.
        """
        conf_rank = {Confidence.HIGH: 0, Confidence.MEDIUM: 1, Confidence.LOW: 2}
        tie = (
            f"{self.affected_contract or ''}|{self.affected_function or ''}"
            f"|{tuple(self.affected_lines) if self.affected_lines else ()}|{self.title}"
        )
        return (SEVERITY_ORDER[self.severity], conf_rank[self.confidence], tie)

    def to_dict(self) -> dict[str, Any]:
        self.validate()
        return {
            "finding_id": self.finding_id,
            "title": self.title,
            "severity": self.severity.value,
            "confidence": self.confidence.value,
            "category": self.category,
            "verification_status": self.verification_status.value,
            "description": self.description,
            "affected_contract": self.affected_contract,
            "affected_function": self.affected_function,
            "affected_lines": list(self.affected_lines),
            "affected_file": self.affected_file,
            "source": self.source,
            "tool": self.tool,
            "reasoning": self.reasoning,
            "exploitability": self.exploitability,
            "impact": self.impact,
            "prerequisites": list(self.prerequisites),
            "likelihood": self.likelihood,
            "false_positive_risk": self.false_positive_risk,
            "assumptions": list(self.assumptions),
            "contradicting_evidence": list(self.contradicting_evidence),
            "benign_explanation": self.benign_explanation,
            "remediation": self.remediation,
            "references": list(self.references),
            "evidence": [item.to_dict() for item in self.evidence],
            "fact_evidence_count": len(self.fact_evidence),
            "ai_evidence_count": len(self.ai_evidence),
            "created_at": self.created_at,
            "confirmed_exploitable": bool(self.confirmed_exploitable),
            "verified_at": self.verified_at,
            "verified_by": self.verified_by,
            "takeable_usd": self.takeable_usd,
        }


@dataclass
class AuditRun:
    """Reproducibility manifest: what the auditor knew when it concluded."""

    audit_id: str
    chain: str | None
    address: str | None
    tool_versions: dict[str, str | None] = field(default_factory=dict)
    compiler_version: str | None = None
    model_name: str | None = None
    configuration: dict[str, Any] = field(default_factory=dict)
    evidence_hashes: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    started_at: str = field(default_factory=utc_now_iso)
    finished_at: str | None = None
    auditor_version: str = ""
    schema_version: int = 1

    def findings_by_severity(self) -> dict[str, int]:
        counts: dict[str, int] = {sev.value: 0 for sev in Severity}
        for finding in self.findings:
            counts[finding.severity.value] += 1
        return counts

    def to_dict(self) -> dict[str, Any]:
        return {
            "audit_id": self.audit_id,
            "schema_version": self.schema_version,
            "auditor_version": self.auditor_version,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "chain": self.chain,
            "address": self.address,
            "tool_versions": dict(self.tool_versions),
            "compiler_version": self.compiler_version,
            "model_name": self.model_name,
            "configuration": dict(self.configuration),
            "evidence_hashes": list(self.evidence_hashes),
            "findings_summary": self.findings_by_severity(),
            "findings": [finding.to_dict() for finding in sorted(self.findings, key=lambda f: f.priority_score())],
        }
# -- Contract Relationship Graph --



from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple


class NodeType(Enum):
    """Types of nodes in the contract relationship graph."""
    CONTRACT = "contract"
    FUNCTION = "function"


class EdgeType(Enum):
    """Types of edges in the contract relationship graph."""
    CALL = "call"          # Function A calls Function B
    INHERITS = "inherits"  # Contract B inherits from Contract A
    DEPENDS = "depends"    # Contract A depends on Contract B


class Provenance(Enum):
    """Provenance of a graph relationship."""
    OBSERVED = "observed"    # Directly extracted from source/tool output
    INFERRED = "inferred"    # Derived from available evidence
    UNKNOWN = "unknown"      # Insufficient evidence to establish the relationship


@dataclass
class GraphNode:
    """A node in the contract relationship graph."""
    id: str
    node_type: NodeType
    label: str
    # Stable identifier based on contract address or function signature
    # For contracts: the contract address or creation code hash
    # For functions: contract + function name + signature
    metadata: Dict[str, Any] = field(default_factory=dict)
    # Provenance of the node itself
    provenance: Provenance = Provenance.UNKNOWN


@dataclass
class GraphEdge:
    """An edge in the contract relationship graph."""
    id: str
    source: Optional[GraphNode]
    target: Optional[GraphNode]
    edge_type: EdgeType
    # Provenance of the relationship
    provenance: Provenance = Provenance.UNKNOWN
    # Evidence supporting this relationship
    evidence: List[str] = field(default_factory=list)
    # Description of the relationship
    description: str = ""


@dataclass
class Graph:
    """Contract relationship graph managing nodes and edges."""
    nodes: Dict[str, GraphNode] = field(default_factory=dict)
    edges: Dict[str, GraphEdge] = field(default_factory=dict)
    # Edge counter for stable ID generation
    _edge_counter: int = field(default_factory=lambda: 0, repr=False)

    def add_node(self, node: GraphNode) -> str:
        """Add a node and return its ID."""
        self.nodes[node.id] = node
        return node.id

    def add_edge(self, source_id: str, target_id: str, edge_type: EdgeType,
                 provenance: Provenance = Provenance.UNKNOWN,
                 evidence: List[str] = None,
                 description: str = "") -> str:
        """Add an edge and return its ID."""
        edge_id = f"E_{self._edge_counter:04d}"
        self._edge_counter += 1
        source = self.nodes.get(source_id)
        target = self.nodes.get(target_id)
        edge = GraphEdge(
            id=edge_id,
            source=source,
            target=target,
            edge_type=edge_type,
            provenance=provenance,
            evidence=evidence or [],
            description=description,
        )
        self.edges[edge_id] = edge
        return edge_id

    def get_node(self, node_id: str) -> Optional[GraphNode]:
        return self.nodes.get(node_id)

    def get_edge(self, edge_id: str) -> Optional[GraphEdge]:
        return self.edges.get(edge_id)

    def get_callers(self, function_id: str) -> List[GraphEdge]:
        """Get all edges where this function is the target (callers)."""
        return [e for e in self.edges.values() if e.target.id == function_id and e.edge_type == EdgeType.CALL]

    def get_callees(self, function_id: str) -> List[GraphEdge]:
        """Get all edges where this function is the source (callees)."""
        return [e for e in self.edges.values() if e.source.id == function_id and e.edge_type == EdgeType.CALL]

    def get_inheritance_parents(self, contract_id: str) -> List[GraphEdge]:
        """Get inheritance edges where this contract inherits from others."""
        return [e for e in self.edges.values() if e.target.id == contract_id and e.edge_type == EdgeType.INHERITS]

    def get_inheritance_children(self, contract_id: str) -> List[GraphEdge]:
        """Get inheritance edges where this contract is inherited by others."""
        return [e for e in self.edges.values() if e.source.id == contract_id and e.edge_type == EdgeType.INHERITS]

    def get_dependencies(self, contract_id: str) -> List[GraphEdge]:
        """Get dependency edges where this contract depends on others."""
        return [e for e in self.edges.values() if e.target.id == contract_id and e.edge_type == EdgeType.DEPENDS]

    def get_dependents(self, contract_id: str) -> List[GraphEdge]:
        """Get dependency edges where this contract is depended on by others."""
        return [e for e in self.edges.values() if e.source.id == contract_id and e.edge_type == EdgeType.DEPENDS]

    def get_neighbors(self, node_id: str, edge_type: Optional[EdgeType] = None) -> List[GraphEdge]:
        """Get all edges incident on a node."""
        if edge_type:
            return [e for e in self.edges.values() 
                    if (e.source.id == node_id or e.target.id == node_id) and e.edge_type == edge_type]
        return [e for e in self.edges.values() 
                if e.source.id == node_id or e.target.id == node_id]

    def get_connected_component(self, node_id: str, max_hops: int = 2) -> Set[str]:
        """Get all nodes reachable within max_hops edges from node_id."""
        visited = {node_id}
        frontier = {node_id}
        for _ in range(max_hops):
            next_frontier = set()
            for n in frontier:
                for e in self.get_neighbors(n):
                    neighbor = e.target.id if e.source.id == n else e.source.id
                    if neighbor not in visited:
                        next_frontier.add(neighbor)
            visited.update(next_frontier)
            frontier = next_frontier
        return visited

    def to_dict(self) -> dict:
        """Serialize the graph to a dictionary."""
        return {
            "nodes": {
                nid: {
                    "id": node.id,
                    "node_type": node.node_type.value,
                    "label": node.label,
                    "metadata": node.metadata,
                    "provenance": node.provenance.value,
                }
                for nid, node in self.nodes.items()
            },
            "edges": {
                eid: {
                    "id": edge.id,
                    "source_id": edge.source.id if edge.source else None,
                    "target_id": edge.target.id if edge.target else None,
                    "edge_type": edge.edge_type.value,
                    "provenance": edge.provenance.value,
                    "evidence": edge.evidence,
                    "description": edge.description,
                }
                for eid, edge in self.edges.items()
            },
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Graph":
        """Deserialize a graph from a dictionary."""
        graph = cls()
        for nid, ndata in data.get("nodes", {}).items():
            node = GraphNode(
                id=nid,
                node_type=NodeType(ndata["node_type"]),
                label=ndata["label"],
                metadata=ndata.get("metadata", {}),
                provenance=Provenance(ndata["provenance"]),
            )
            graph.add_node(node)
        for eid, edata in data.get("edges", {}).items():
            source_node = graph.get_node(edata["source_id"]) if edata.get("source_id") else None
            target_node = graph.get_node(edata["target_id"]) if edata.get("target_id") else None
            edge = GraphEdge(
                id=eid,
                source=source_node,
                target=target_node,
                edge_type=EdgeType(edata["edge_type"]),
                provenance=Provenance(edata["provenance"]),
                evidence=edata.get("evidence", []),
                description=edata.get("description", ""),
            )
            graph.edges[eid] = edge
            # Also add nodes if not already present
            if source_node:
                graph.nodes[source_node.id] = source_node
            if target_node:
                graph.nodes[target_node.id] = target_node
        return graph
# -- Contract Relationship Graph --

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple


class NodeType(Enum):
    """Types of nodes in the contract relationship graph."""
    CONTRACT = "contract"
    FUNCTION = "function"


class EdgeType(Enum):
    """Types of edges in the contract relationship graph."""
    CALL = "call"          # Function A calls Function B
    INHERITS = "inherits"  # Contract B inherits from Contract A
    DEPENDS = "depends"    # Contract A depends on Contract B


class Provenance(Enum):
    """Provenance of a graph relationship."""
    OBSERVED = "observed"    # Directly extracted from source/tool output
    INFERRED = "inferred"    # Derived from available evidence
    UNKNOWN = "unknown"      # Insufficient evidence to establish the relationship


@dataclass
class GraphNode:
    """A node in the contract relationship graph."""
    id: str
    node_type: NodeType
    label: str
    # Stable identifier based on contract address or function signature
    # For contracts: the contract address or creation code hash
    # For functions: contract + function name + signature
    metadata: Dict[str, Any] = field(default_factory=dict)
    # Provenance of the node itself
    provenance: Provenance = Provenance.UNKNOWN


@dataclass
class GraphEdge:
    """An edge in the contract relationship graph."""
    id: str
    source: Optional[GraphNode]
    target: Optional[GraphNode]
    edge_type: EdgeType
    # Provenance of the relationship
    provenance: Provenance = Provenance.UNKNOWN
    # Evidence supporting this relationship
    evidence: List[str] = field(default_factory=list)
    # Description of the relationship
    description: str = ""


@dataclass
class Graph:
    """Contract relationship graph managing nodes and edges."""
    nodes: Dict[str, GraphNode] = field(default_factory=dict)
    edges: Dict[str, GraphEdge] = field(default_factory=dict)
    # Edge counter for stable ID generation
    _edge_counter: int = field(default_factory=lambda: 0, repr=False)

    def add_node(self, node: GraphNode) -> str:
        """Add a node and return its ID."""
        self.nodes[node.id] = node
        return node.id

    def add_edge(self, source_id: str, target_id: str, edge_type: EdgeType,
                 provenance: Provenance = Provenance.UNKNOWN,
                 evidence: List[str] = None,
                 description: str = "") -> str:
        """Add an edge and return its ID."""
        edge_id = f"E_{self._edge_counter:04d}"
        self._edge_counter += 1
        source = self.nodes.get(source_id)
        target = self.nodes.get(target_id)
        edge = GraphEdge(
            id=edge_id,
            source=source,
            target=target,
            edge_type=edge_type,
            provenance=provenance,
            evidence=evidence or [],
            description=description,
        )
        self.edges[edge_id] = edge
        return edge_id

    def get_node(self, node_id: str) -> Optional[GraphNode]:
        return self.nodes.get(node_id)

    def get_edge(self, edge_id: str) -> Optional[GraphEdge]:
        return self.edges.get(edge_id)

    def get_callers(self, function_id: str) -> List[GraphEdge]:
        """Get all edges where this function is the target (callers)."""
        return [e for e in self.edges.values() if e.target.id == function_id and e.edge_type == EdgeType.CALL]

    def get_callees(self, function_id: str) -> List[GraphEdge]:
        """Get all edges where this function is the source (callees)."""
        return [e for e in self.edges.values() if e.source.id == function_id and e.edge_type == EdgeType.CALL]

    def get_inheritance_parents(self, contract_id: str) -> List[GraphEdge]:
        """Get inheritance edges where this contract inherits from others."""
        return [e for e in self.edges.values() if e.target.id == contract_id and e.edge_type == EdgeType.INHERITS]

    def get_inheritance_children(self, contract_id: str) -> List[GraphEdge]:
        """Get inheritance edges where this contract is inherited by others."""
        return [e for e in self.edges.values() if e.source.id == contract_id and e.edge_type == EdgeType.INHERITS]

    def get_dependencies(self, contract_id: str) -> List[GraphEdge]:
        """Get dependency edges where this contract depends on others."""
        return [e for e in self.edges.values() if e.target.id == contract_id and e.edge_type == EdgeType.DEPENDS]

    def get_dependents(self, contract_id: str) -> List[GraphEdge]:
        """Get dependency edges where this contract is depended on by others."""
        return [e for e in self.edges.values() if e.source.id == contract_id and e.edge_type == EdgeType.DEPENDS]

    def get_neighbors(self, node_id: str, edge_type: Optional[EdgeType] = None) -> List[GraphEdge]:
        """Get all edges incident on a node."""
        if edge_type:
            return [e for e in self.edges.values() 
                    if (e.source.id == node_id or e.target.id == node_id) and e.edge_type == edge_type]
        return [e for e in self.edges.values() 
                if e.source.id == node_id or e.target.id == node_id]

    def get_connected_component(self, node_id: str, max_hops: int = 2) -> Set[str]:
        """Get all nodes reachable within max_hops edges from node_id."""
        visited = {node_id}
        frontier = {node_id}
        for _ in range(max_hops):
            next_frontier = set()
            for n in frontier:
                for e in self.get_neighbors(n):
                    neighbor = e.target.id if e.source.id == n else e.source.id
                    if neighbor not in visited:
                        next_frontier.add(neighbor)
            visited.update(next_frontier)
            frontier = next_frontier
        return visited

    def to_dict(self) -> dict:
        """Serialize the graph to a dictionary."""
        return {
            "nodes": {
                nid: {
                    "id": node.id,
                    "node_type": node.node_type.value,
                    "label": node.label,
                    "metadata": node.metadata,
                    "provenance": node.provenance.value,
                }
                for nid, node in self.nodes.items()
            },
            "edges": {
                eid: {
                    "id": edge.id,
                    "source_id": edge.source.id if edge.source else None,
                    "target_id": edge.target.id if edge.target else None,
                    "edge_type": edge.edge_type.value,
                    "provenance": edge.provenance.value,
                    "evidence": edge.evidence,
                    "description": edge.description,
                }
                for eid, edge in self.edges.items()
            },
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Graph":
        """Deserialize a graph from a dictionary."""
        graph = cls()
        for nid, ndata in data.get("nodes", {}).items():
            node = GraphNode(
                id=nid,
                node_type=NodeType(ndata["node_type"]),
                label=ndata["label"],
                metadata=ndata.get("metadata", {}),
                provenance=Provenance(ndata["provenance"]),
            )
            graph.add_node(node)
        for eid, edata in data.get("edges", {}).items():
            source_node = graph.get_node(edata["source_id"]) if edata.get("source_id") else None
            target_node = graph.get_node(edata["target_id"]) if edata.get("target_id") else None
            edge = GraphEdge(
                id=eid,
                source=source_node,
                target=target_node,
                edge_type=EdgeType(edata["edge_type"]),
                provenance=Provenance(edata["provenance"]),
                evidence=edata.get("evidence", []),
                description=edata.get("description", ""),
            )
            graph.edges[eid] = edge
            # Also add nodes if not already present
            if source_node:
                graph.nodes[source_node.id] = source_node
            if target_node:
                graph.nodes[target_node.id] = target_node
        return graph
