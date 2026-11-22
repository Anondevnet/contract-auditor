"""Rendering: human-readable text and machine-readable JSON.

Tone rules encoded here, because report wording is where overclaiming usually
creeps in:

* "not detected" is used for tools; it never becomes "clean" or "safe".
* No finding is described as exploitable without a CONFIRMED status.
* Limitations and unknowns are always printed, never truncated away.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .model import Confidence, Finding, Severity, VerificationStatus
from .ollama import OllamaStatus
from .storage import StorageReport, human_bytes
from .toolchain import ToolchainReport

__all__ = [
    "STATUS_DISCLAIMER",
    "NOT_IMPLEMENTED",
    "render_status_text",
    "render_toolchain_text",
    "render_ollama_text",
    "render_storage_text",
    "render_findings_table",
]

STATUS_DISCLAIMER = (
    "Phase 1 status: local toolchain, Ollama and storage only. "
    "No contract has been analyzed. Absence of findings here means "
    "nothing about the security of any contract."
)

NOT_IMPLEMENTED: tuple[str, ...] = (
    "blockchain RPC retrieval",
    "Etherscan / block-explorer integration",
    "transaction and event-log download",
    "automatic source-code download",
    "on-chain bytecode or ABI retrieval",
    "Solidity compiler version download",
    "Ollama model pull",
    "external network access of any kind",
    "exploitation or live transactions",
    "AI inference / prompt execution",
)


def _rule(title: str, char: str = "=", width: int = 72) -> str:
    return f"\n{title}\n{char * width}"


def _mark(available: bool) -> str:
    return "ok" if available else "MISSING"


def render_toolchain_text(report: ToolchainReport) -> str:
    lines: list[str] = [_rule("TOOLCHAIN"), ""]
    lines.append(f"{'tool':<10}{'status':<14}{'version':<21}path")
    for tool in report.tools:
        # Versions carry build suffixes (solc) long enough to break the
        # column grid, so the full value goes on its own indented line.
        version = tool.version or "-"
        path = tool.path or "-"
        if len(version) > 19:
            lines.append(f"{tool.key:<10}{tool.status:<14}{version[:19]:<21}{path}")
            lines.append(f"{'':<45}version: {version}")
        else:
            lines.append(f"{tool.key:<10}{tool.status:<14}{version:<21}{path}")
        if tool.error:
            lines.append(f"{'':<10}error: {tool.error}")
        if tool.resolution != "DIRECT":
            hint = "shim" if tool.resolved_via_shim else "pyenv version dir (shim-resolved)"
            lines.append(f"{'':<10}note: PATH resolution via {hint}")
    if report.observations():
        lines.append("")
        lines.append("Observations:")
        for note in report.observations():
            lines.append(f"  - {note}")
    return "\n".join(lines)


def render_ollama_text(status: OllamaStatus) -> str:
    lines: list[str] = [_rule("OLLAMA"), ""]
    lines.append(f"endpoint : {status.endpoint}")
    lines.append(f"reachable: {'yes' if status.reachable else 'no'}")
    if status.error:
        lines.append(f"error    : {status.error}")
    if not status.reachable:
        return "\n".join(lines)

    lines.append(f"models   : {len(status.models)} installed, {status.total_size_human} total")
    for model in status.models:
        caps = ", ".join(model.capabilities) if model.capabilities else "unknown"
        lines.append(
            f"  - {model.name}  {model.size_human or 'size unknown'}  "
            f"{model.quantization or '?'}  ctx={model.context_length or '?'}  caps=[{caps}]"
        )
    if status.selected_model:
        state = {True: "installed", False: "NOT installed", None: "unknown"}[status.selected_resolves]
        lines.append(f"selected : {status.selected_model} ({state})")
        if status.selected_loadable is True:
            lines.append("           metadata probe succeeded; generation not exercised")
        elif status.selected_loadable is False:
            lines.append(f"           metadata probe failed: {status.selected_error}")
    if status.probe_skipped_reason:
        lines.append(f"probe    : skipped ({status.probe_skipped_reason})")
    for note in status.observations():
        lines.append(f"  - {note}")
    return "\n".join(lines)


def render_storage_text(report: StorageReport) -> str:
    lines: list[str] = [_rule("STORAGE"), ""]
    lines.append(f"volume total : {report.disk.total_human}")
    lines.append(f"volume free  : {report.disk.free_human}  ({report.disk.percent_used}% used)")
    lines.append("")
    lines.append(f"project      : {report.project.human}  {report.project.path}")
    for component in report.components:
        state = component.human if component.exists else "absent"
        lines.append(f"  - {Path(component.path).name:<10} {state:<12} {component.file_count} file(s)")
    if report.temp_artifacts is not None and report.temp_artifacts.file_count:
        lines.append(
            f"temp         : {report.temp_artifacts.human} in "
            f"{report.temp_artifacts.file_count} auditor temp artifact(s)"
        )
    if report.largest_files:
        lines.append("")
        lines.append("Large files (at or above threshold):")
        for path, size in report.largest_files:
            lines.append(f"  - {human_bytes(size):>10}  {path}")
    if report.limits:
        lines.append("")
        lines.append("Configured limits:")
        for check in report.limit_checks():
            flag = "within" if check["within_limit"] else "EXCEEDED"
            lines.append(
                f"  - {check['limit']:<22} {check['measured_human']:<12} / {check['limit_mb']} MB  ({flag})"
            )
    if report.warnings:
        lines.append("")
        lines.append("Warnings:")
        for warning in report.warnings:
            lines.append(f"  - {warning}")
    return "\n".join(lines)


def render_findings_table(findings: list[Finding]) -> str:
    """Phase 1 ships no findings; the renderer exists for Phase 2 reuse."""
    if not findings:
        return "No findings recorded."

    lines = [_rule("FINDINGS"), ""]
    lines.append(f"{'id':<16}{'severity':<15}{'confidence':<12}{'status':<14}title")
    for finding in sorted(findings, key=lambda item: item.priority_score()):
        lines.append(
            f"{finding.finding_id:<16}{finding.severity.value:<15}"
            f"{finding.confidence.value:<12}{finding.verification_status.value:<14}"
            f"{finding.title}"
        )
    lines.append("")
    lines.append("Severity and confidence are independent. Read both columns.")
    return "\n".join(lines)


def render_status_text(
    *,
    auditor_version: str,
    schema_version: int,
    python_version: str,
    platform_info: dict[str, Any],
    toolchain: ToolchainReport,
    ollama: OllamaStatus,
    storage: StorageReport,
    registry: dict[str, Any],
    settings_warnings: list[str],
) -> str:
    parts: list[str] = [
        _rule("CONTRACT-AUDITOR STATUS"),
        "",
        f"auditor version : {auditor_version} (schema {schema_version})",
        f"python          : {python_version}",
        f"platform        : {platform_info.get('system', '?')} {platform_info.get('machine', '?')}",
        f"os release      : {platform_info.get('release', '?')}",
        "",
        STATUS_DISCLAIMER,
    ]
    parts.append(render_toolchain_text(toolchain))
    parts.append(render_ollama_text(ollama))
    parts.append(render_storage_text(storage))

    parts.append(_rule("ANALYSIS MODULES"))
    parts.append("")
    parts.append(f"registered      : {registry.get('loadable', 0)} of {registry.get('count', 0)}")
    if registry.get("note"):
        parts.append(f"note            : {registry['note']}")
    for error in registry.get("errors", []) or []:
        parts.append(f"error           : {error}")

    parts.append(_rule("NOT IMPLEMENTED YET"))
    parts.append("")
    for item in NOT_IMPLEMENTED:
        parts.append(f"  - {item}")

    warnings = list(settings_warnings) + list(registry.get("errors", []) or [])
    if warnings:
        parts.append(_rule("WARNINGS"))
        parts.append("")
        for warning in warnings:
            parts.append(f"  - {warning}")

    return "\n".join(parts)


def summarize_severity(findings: list[Finding]) -> dict[str, int]:
    counts = {sev.value: 0 for sev in Severity}
    for finding in findings:
        counts[finding.severity.value] += 1
    return counts


def summarize_status(findings: list[Finding]) -> dict[str, int]:
    counts = {status.value: 0 for status in VerificationStatus}
    for finding in findings:
        counts[finding.verification_status.value] += 1
    return counts


def summarize_confidence(findings: list[Finding]) -> dict[str, int]:
    counts = {conf.value: 0 for conf in Confidence}
    for finding in findings:
        counts[finding.confidence.value] += 1
    return counts