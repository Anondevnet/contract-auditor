"""Task graph management for the engineering loop.

Manages persistent task dependencies, status tracking, and cycle detection.
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from ..model import Finding

STATUS_PENDING = "pending"
STATUS_RUNNING = "running"
STATUS_COMPLETED = "completed"
STATUS_FAILED = "failed"
STATUS_SKIPPED = "skipped"
STATUS_BLOCKED = "blocked"

PRIORITY_HIGH = "high"
PRIORITY_MEDIUM = "medium"
PRIORITY_LOW = "low"

DEFAULT_RETRY_BUDGET = 3


@dataclass
class TaskAcceptanceCriteria:
    """Acceptance criteria for task completion."""
    pass_through_tests: List[str] = field(default_factory=list)
    regression_tests: List[str] = field(default_factory=list)
    manual_verification: bool = False
    evidence_required: List[str] = field(default_factory=list)
    conditions: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Task:
    """Engineering task with full graph integration."""

    objective: str
    description: str
    id: str = ""
    status: str = STATUS_PENDING
    dependencies: List[str] = field(default_factory=list)
    dependents: List[str] = field(default_factory=list)
    parent: Optional[str] = None
    children: List[str] = field(default_factory=list)
    priority: str = PRIORITY_MEDIUM
    retry_budget: int = DEFAULT_RETRY_BUDGET
    retry_count: int = 0
    failure_details: Optional[str] = None
    failure_classification: Optional[str] = None
    acceptance_criteria: TaskAcceptanceCriteria = field(default_factory=TaskAcceptanceCriteria)
    tests: List[str] = field(default_factory=list)
    verification_evidence: List[str] = field(default_factory=list)
    created_at: str = field(default_factory=lambda: __import__("datetime").datetime.utcnow().isoformat())
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    status_history: List[Tuple[str, str, Optional[str]]] = field(default_factory=list)

    def can_run(self, completed_tasks: Set[str]) -> bool:
        """Check if all dependencies are completed."""
        return all(dep in completed_tasks for dep in self.dependencies)

    def mark_running(self):
        self.status = STATUS_RUNNING
        self.started_at = __import__("datetime").datetime.now(__import__("datetime").UTC).isoformat()
        self.status_history.append((STATUS_RUNNING, "", ""))

    def mark_completed(self, note: str = "", evidence: str = ""):
        self.status = STATUS_COMPLETED
        self.completed_at = __import__("datetime").datetime.now(__import__("datetime").UTC).isoformat()
        self.status_history.append((STATUS_COMPLETED, note, evidence))

    def mark_failed(self, failure_details: str, failure_classification: str = ""):
        self.status = STATUS_FAILED
        self.retry_count += 1
        self.failure_details = failure_details
        self.failure_classification = failure_classification
        self.completed_at = __import__("datetime").datetime.now(__import__("datetime").UTC).isoformat()
        self.status_history.append((STATUS_FAILED, failure_details, ""))

    def can_retry(self) -> bool:
        return self.retry_count < self.retry_budget and self.status == STATUS_FAILED

    def __lt__(self, other):
        """Sort by priority then retry count."""
        priority_map = {PRIORITY_HIGH: 0, PRIORITY_MEDIUM: 1, PRIORITY_LOW: 2}
        p_val = priority_map.get(self.priority, 1)
        o_val = priority_map.get(other.priority, 1)
        if p_val != o_val:
            return p_val < o_val
        return self.retry_count < other.retry_count


@dataclass
class EngineeringGraph:
    """Persistent task graph managing all engineering tasks."""

    tasks: Dict[str, Task] = field(default_factory=dict)
    next_id_int: int = field(default_factory=lambda: 1)

    def add_task(self, task: Task) -> str:
        """Add a task and return its stable ID."""
        task.id = f"T_{self.next_id_int:04d}"
        self.next_id_int += 1
        self.tasks[task.id] = task
        # Update dependents/children links
        for dep_id in task.dependencies:
            if dep_id in self.tasks:
                self.tasks[dep_id].dependents.append(task.id)
                self.tasks[task.id].children.append(dep_id)
        # Set parent link
        if task.parent and task.parent in self.tasks:
            self.tasks[task.parent].children.append(task.id)
            task.children.append(task.parent)
        return task.id

    def get_task(self, task_id: str) -> Optional[Task]:
        return self.tasks.get(task_id)

    def get_ready_tasks(self, completed_tasks: Set[str]) -> List[Task]:
        """Tasks whose dependencies are met and status is PENDING."""
        ready = []
        for task in self.tasks.values():
            if (
                task.status == STATUS_PENDING
                and task.can_run(completed_tasks)
            ):
                ready.append(task)
        ready.sort(key=lambda t: (
            0 if t.priority == PRIORITY_HIGH else
            1 if t.priority == PRIORITY_MEDIUM else 2,
            t.retry_count
        ))
        return ready

    def get_blocked_tasks(self) -> List[Task]:
        """Tasks not in PENDING status."""
        return [t for t in self.tasks.values()
                if t.status not in (STATUS_PENDING, STATUS_FAILED)]

    def get_all_status(self) -> Dict[str, int]:
        counts = {STATUS_PENDING: 0, STATUS_RUNNING: 0, STATUS_COMPLETED: 0,
                  STATUS_FAILED: 0, STATUS_SKIPPED: 0, STATUS_BLOCKED: 0}
        for t in self.tasks.values():
            if t.status in counts:
                counts[t.status] += 1
        return counts

    def to_dict(self) -> dict:
        return {
            "tasks": {
                tid: {
                    "id": t.id,
                    "objective": t.objective,
                    "description": t.description,
                    "status": t.status,
                    "dependencies": t.dependencies,
                    "dependents": t.dependents,
                    "parent": t.parent,
                    "children": t.children,
                    "priority": t.priority,
                    "retry_budget": t.retry_budget,
                    "retry_count": t.retry_count,
                    "failure_details": t.failure_details,
                    "failure_classification": t.failure_classification,
                    "acceptance_criteria": {
                        "pass_through_tests": t.acceptance_criteria.pass_through_tests,
                        "regression_tests": t.acceptance_criteria.regression_tests,
                        "manual_verification": t.acceptance_criteria.manual_verification,
                        "evidence_required": t.acceptance_criteria.evidence_required,
                        "conditions": t.acceptance_criteria.conditions,
                    },
                    "tests": t.tests,
                    "verification_evidence": t.verification_evidence,
                    "created_at": t.created_at,
                    "started_at": t.started_at,
                    "completed_at": t.completed_at,
                    "status_history": t.status_history,
                }
                for tid, t in self.tasks.items()
            }
        }

    @classmethod
    def from_dict(cls, data: dict) -> "EngineeringGraph":
        graph = cls()
        for tid, tdata in data.get("tasks", {}).items():
            t = Task(
                id=tid,
                objective=tdata["objective"],
                description=tdata["description"],
                status=tdata["status"],
                dependencies=tdata.get("dependencies", []),
                dependents=tdata.get("dependents", []),
                parent=tdata.get("parent"),
                children=tdata.get("children", []),
                priority=tdata.get("priority", PRIORITY_MEDIUM),
                retry_budget=tdata.get("retry_budget", DEFAULT_RETRY_BUDGET),
                retry_count=tdata.get("retry_count", 0),
                failure_details=tdata.get("failure_details"),
                failure_classification=tdata.get("failure_classification"),
                acceptance_criteria=TaskAcceptanceCriteria(
                    pass_through_tests=tdata["acceptance_criteria"].get("pass_through_tests", []),
                    regression_tests=tdata["acceptance_criteria"].get("regression_tests", []),
                    manual_verification=tdata["acceptance_criteria"].get("manual_verification", False),
                    evidence_required=tdata["acceptance_criteria"].get("evidence_required", []),
                    conditions=tdata["acceptance_criteria"].get("conditions", {}),
                ),
                tests=tdata.get("tests", []),
                verification_evidence=tdata.get("verification_evidence", []),
                created_at=tdata.get("created_at"),
                started_at=tdata.get("started_at"),
                completed_at=tdata.get("completed_at"),
                status_history=tdata.get("status_history", []),
            )
            graph.tasks[tid] = t
        return graph


class FailureClassifier:
    """Classify failures and generate corrective tasks."""

    CLASSIFICATIONS = {
        "syntax_error": "syntax_or_parsing",
        "import_error": "missing_dependency",
        "timeout": "timeout",
        "assertion_error": "test_failure",
        "value_error": "configuration_or_config",
        "key_error": "configuration_or_config",
        "attribute_error": "code_error",
        "name_error": "code_error",
        "type_error": "code_error",
        "connection_error": "network_or_provider",
        "json_decode_error": "serialization_or_parsing",
    }

    def classify(self, error: Exception, context: str = "") -> str:
        error_name = type(error).__name__
        error_msg = str(error).lower()
        for pattern, classification in self.CLASSIFICATIONS.items():
            if pattern in error_msg:
                return classification
        if "not found" in error_msg or "missing" in error_msg:
            return "missing_dependency"
        if "timeout" in error_msg:
            return "timeout"
        if "cannot import" in error_msg:
            return "missing_dependency"
        return "unknown_error"

    def generate_corrective_task(
        self, original_task_id: str, error: Exception,
        context: str, graph: EngineeringGraph
    ) -> Optional[Task]:
        classification = self.classify(error, context)
        corrective_id = f"T_{uuid.uuid4().hex[:8].upper()}"
        corrective = Task(
            id=corrective_id,
            objective=f"Fix: {original_task_id} - {type(error).__name__}",
            description=f"Corrective task for {original_task_id}. Error: {type(error).__name__}: {error}",
            status="pending",
            dependencies=[original_task_id],
            parent=original_task_id,
            priority="high",
            retry_budget=DEFAULT_RETRY_BUDGET,
            failure_classification=classification,
        )
        if original_task_id in graph.tasks:
            graph.tasks[original_task_id].dependents.append(corrective.id)
            corrective.children.append(original_task_id)
        graph.tasks[corrective.id] = corrective
        return corrective


class EngineeringLoop:
    """Main orchestrator engine."""

    def __init__(self, graph_path: Optional[str] = None, retry_budget: int = DEFAULT_RETRY_BUDGET):
        self.graph_path = Path(graph_path) if graph_path else None
        self.retry_budget = retry_budget
        self.graph = EngineeringGraph()
        self.failure_classifier = FailureClassifier()
        self.run_history: List[Dict] = []
        self._loaded_from_disk = False

        if self.graph_path and self.graph_path.exists():
            self._load_from_disk()

    def _load_from_disk(self):
        try:
            with open(self.graph_path, 'r') as f:
                data = json.load(f)
            self.graph = EngineeringGraph.from_dict(data)
            self._loaded_from_disk = True
        except Exception as e:
            print(f"Warning: Could not load graph: {e}")
            self.graph = EngineeringGraph()

    def _save_to_disk(self):
        if self.graph_path:
            try:
                self.graph_path.parent.mkdir(parents=True, exist_ok=True)
                with open(self.graph_path, 'w') as f:
                    json.dump(self.graph.to_dict(), f, indent=2)
            except Exception as e:
                print(f"Warning: Could not save graph: {e}")

    def add_task(self, objective: str, description: str,
                 dependencies: List[str] = None,
                 priority: str = PRIORITY_MEDIUM,
                 retry_budget: int = DEFAULT_RETRY_BUDGET,
                 parent: Optional[str] = None) -> str:
        task = Task(
            objective=objective,
            description=description,
            dependencies=dependencies or [],
            priority=priority,
            retry_budget=retry_budget,
            parent=parent,
        )
        return self.graph.add_task(task)

    def run_next(self) -> Optional[Task]:
        completed = {t.id for t in self.graph.tasks.values()
                     if t.status == STATUS_COMPLETED}
        ready = self.graph.get_ready_tasks(completed)
        if not ready:
            return None
        task = ready[0]
        task.mark_running()
        if self.graph_path:
            self._save_to_disk()
        return task

    def complete_task(self, task_id: str, note: str = "", evidence: str = ""):
        task = self.graph.get_task(task_id)
        if task:
            task.mark_completed(note, evidence)
            if self.graph_path:
                self._save_to_disk()

    def fail_task(self, task_id: str, error: Exception,
                  failure_classification: str = "") -> Optional[Task]:
        task = self.graph.get_task(task_id)
        if task:
            task.mark_failed(str(error), failure_classification)
            corrective = self.failure_classifier.generate_corrective_task(
                task_id, error, f"Failed: {type(error).__name__}", self.graph
            )
            if self.graph_path:
                self._save_to_disk()
            return corrective
        return None

    def run_loop(self, max_iterations: int = 100) -> Dict[str, Any]:
        iteration = 0
        while iteration < max_iterations:
            task = self.run_next()
            if task is None:
                break
            # Execute task logic would go here
            # In real use, this would call the task's work function
            iteration += 1
            if iteration >= 1:
                self.complete_task(task.id, note="Simulated completion")
        return self.get_status_report()

    def get_status_report(self) -> Dict[str, Any]:
        return {
            "graph_status": self.graph.get_all_status(),
            "total_tasks": len(self.graph.tasks),
            "completed_tasks": sum(1 for t in self.graph.tasks.values()
                                  if t.status == STATUS_COMPLETED),
            "failed_tasks": sum(1 for t in self.graph.tasks.values()
                               if t.status == STATUS_FAILED),
            "pending_tasks": sum(1 for t in self.graph.tasks.values()
                                if t.status == STATUS_PENDING),
            "run_history_count": len(self.run_history),
        }

    def export_graph(self, path: Path):
        self.graph_path = path
        self._save_to_disk()
        return path

    def import_graph(self, path: Path):
        self.graph_path = path
        self._load_from_disk()