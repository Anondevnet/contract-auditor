"""OpenCode integration — read-only proposals with explicit approval to apply.

Environment inspected for this integration: ``opencode`` 1.19.0 provides
``opencode run`` with documented ``--format json`` and ``--dir`` options.
Nothing here uses ``--auto`` (the CLI itself labels it "dangerous!"), no
credentials are configured, and no undocumented API is assumed.

Safety model:

* ``probe()`` only runs ``opencode --version`` (fixed argv, hard timeout).
* ``propose_patch()`` copies the target project's Solidity files into a
  scratch directory and runs OpenCode there (``--dir <scratch>``), so the
  assistant cannot modify the real project while drafting. The proposal is a
  full-file content plus a unified diff, computed locally by us — never
  applied automatically.
* ``apply_patch()`` requires ``approval=True`` (an explicit, per-request
  user action) and verifies the on-disk file still matches the hash the
  proposal was drafted against. Any mismatch refuses to write.
* Everything runs through ``auditor.procs.run`` (shell=False, fixed argv,
  timeout).
"""

from __future__ import annotations

import difflib
import hashlib
import json
import re
import shutil
import tempfile
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from auditor.procs import run as procs_run

_DEFAULT_TIMEOUT = 420.0
_PROBE_TIMEOUT = 10.0
_MAX_STAGED_BYTES = 5 * 1024 * 1024
_MAX_STAGED_FILES = 300
_PROPOSAL_TTL = 3600.0
_MAX_PROPOSALS = 50

_lock = threading.Lock()
_proposals: Dict[str, Dict[str, Any]] = {}


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def _binary_candidates() -> List[str]:
    found = shutil.which("opencode")
    candidates = [found] if found else []
    home_candidate = Path.home() / ".opencode" / "bin" / "opencode"
    if home_candidate.is_file():
        candidates.append(str(home_candidate))
    # Preserve order, drop duplicates
    return list(dict.fromkeys(candidates))


def probe(timeout: float = _PROBE_TIMEOUT) -> Dict[str, Any]:
    """Detect OpenCode availability. Fixed argv: ``opencode --version``."""
    for candidate in _binary_candidates():
        result = procs_run([candidate, "--version"], timeout=timeout)
        version = (result.stdout or result.stderr or "").strip().splitlines()
        if not result.error and result.returncode == 0 and version:
            return {
                "available": True,
                "binary": candidate,
                "version": version[0].strip()[:80],
                "error": None,
                "usage": (
                    "Proposals run OpenCode in a scratch copy of the Solidity "
                    "sources; applying a proposal requires explicit approval."
                ),
            }
    reason = "opencode binary not found on PATH or in ~/.opencode/bin"
    if _binary_candidates():
        reason = f"opencode found but could not run: {result.error or result.stderr or 'unknown error'}"  # noqa: F821
    return {"available": False, "binary": None, "version": None, "error": reason, "usage": None}


# ---------------------------------------------------------------------------
# proposal store
# ---------------------------------------------------------------------------

def _prune_store() -> None:
    now = time.time()
    stale = [
        pid for pid, entry in _proposals.items()
        if now - entry.get("created_monotonic", now) > _PROPOSAL_TTL
    ]
    for pid in stale:
        _proposals.pop(pid, None)
    while len(_proposals) >= _MAX_PROPOSALS:
        oldest = min(_proposals, key=lambda k: _proposals[k].get("created_monotonic", 0))
        _proposals.pop(oldest, None)


def get_proposal(proposal_id: str) -> Optional[Dict[str, Any]]:
    with _lock:
        entry = _proposals.get(proposal_id)
        return dict(entry) if entry else None


def list_proposals() -> List[Dict[str, Any]]:
    """Summaries of live proposals (no full contents)."""
    with _lock:
        return [
            {
                "proposal_id": pid,
                "target_file": e.get("target_file"),
                "scan_id": e.get("scan_id"),
                "fingerprint": e.get("fingerprint"),
                "status": e.get("status"),
                "created_at": e.get("created_at"),
                "before_hash": e.get("before_hash"),
                "after_hash": e.get("after_hash"),
                "source": e.get("source"),
            }
            for pid, e in _proposals.items()
        ]


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _stage_copy(project_dir: Path, scratch: Path) -> tuple[int, int]:
    """Copy Solidity files into ``scratch``. Returns (files, bytes)."""
    total_bytes = 0
    count = 0
    paths = [project_dir] if project_dir.is_file() else sorted(project_dir.rglob("*.sol"))
    for path in paths:
        if not path.is_file() or path.suffix.lower() != ".sol":
            continue
        if count >= _MAX_STAGED_FILES or total_bytes >= _MAX_STAGED_BYTES:
            break
        rel = path.relative_to(project_dir) if path != project_dir else Path(path.name)
        dest = scratch / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        try:
            data = path.read_bytes()
        except OSError:
            continue
        dest.write_bytes(data)
        count += 1
        total_bytes += len(data)
    return count, total_bytes


def _extract_text(output: str) -> str:
    """Pull assistant text out of ``opencode run --format json`` output.

    Tolerant of JSON-lines, a single JSON document, or plain text.
    """
    chunks: List[str] = []

    def walk(node: Any) -> None:
        if isinstance(node, dict):
            for key, value in node.items():
                if key == "text" and isinstance(value, str) and value.strip():
                    chunks.append(value)
                else:
                    walk(value)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    try:
        walk(json.loads(output))
    except json.JSONDecodeError:
        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                walk(json.loads(line))
            except json.JSONDecodeError:
                continue
    if chunks:
        return "\n".join(chunks).strip()
    return output.strip()


_FENCE_RE = re.compile(r"```[a-zA-Z0-9]*\n(.*?)```", re.DOTALL)


def _extract_full_file(
    text: str, before: Optional[str] = None
) -> tuple[Optional[str], Optional[str]]:
    """Return ``(new_content, note)`` from an assistant response.

    Preferred shape is a fenced ```solidity block. Models sometimes emit the
    whole file without fences; in that case fall back to a bounded scan for a
    Solidity-looking whole file (balanced braces), so a usable response is not
    discarded as a tool failure.
    """
    if re.search(r"\bNOCHANGE\b", text) and not _FENCE_RE.search(text):
        return None, "assistant proposed no change (NOCHANGE)"
    blocks = _FENCE_RE.findall(text)
    if blocks:
        # Longest fenced block wins: full file content beats short snippets.
        longest = max(blocks, key=len)
        if longest.strip():
            return longest, None

    # Fallback: unfenced whole-file response.
    start_re: Optional[str] = None
    if before:
        first_line = next((ln.strip() for ln in before.splitlines() if ln.strip()), "")
        if first_line:
            start_re = re.escape(first_line)
    if start_re is None:
        start_re = r"(?:pragma\s+solidity\b|contract\s+\w+|library\s+\w+|interface\s+\w+|abstract\s+contract\s+\w+)"
    start = None
    if before:
        idx = text.find(next((ln.strip() for ln in before.splitlines() if ln.strip()), "\0"))
        if idx != -1:
            start = idx
    if start is None:
        m = re.search(start_re, text)
        if m:
            start = m.start()
    if start is not None:
        tail = text[start:]
        last_brace = tail.rfind("}")
        if last_brace != -1:
            candidate = tail[: last_brace + 1].rstrip()
            if (
                candidate.count("{") == candidate.count("}")
                and "pragma" in candidate
                or (candidate.count("{") == candidate.count("}") and re.search(r"\bcontract\s+\w+", candidate))
            ):
                return candidate, "extracted unfenced file contents (fallback)"
    return None, "no fenced file contents found in assistant response"


def _unified_diff(before: str, after: str, rel_path: str) -> str:
    diff = difflib.unified_diff(
        before.splitlines(keepends=True),
        after.splitlines(keepends=True),
        fromfile=f"a/{rel_path}",
        tofile=f"b/{rel_path}",
    )
    return "".join(diff)


def _build_prompt(relative_path: str, finding: Dict[str, Any]) -> str:
    title = str(finding.get("title") or "reported issue")
    severity = str(finding.get("severity") or "unknown severity")
    category = str(finding.get("category") or "security")
    contract = str(finding.get("affected_contract") or "")
    function = str(finding.get("affected_function") or "")
    lines = finding.get("affected_lines") or []
    description = str(finding.get("description") or "")[:600]
    remediation = str(finding.get("remediation") or "")[:400]
    location = f"{contract}.{function}" if contract or function else "unspecified location"
    if lines:
        location += f" (lines {lines[0]}–{lines[-1]})"

    return (
        "You are reviewing one Solidity file for a reported potential security finding. "
        "This is a proposal-only exercise: output the file, do not run commands.\n\n"
        f"Finding: {title}\n"
        f"Severity/category: {severity} / {category}\n"
        f"Location: {location}\n"
        f"Description: {description}\n"
        f"Scanner remediation hint: {remediation}\n\n"
        f"Target file (relative): {relative_path}\n\n"
        "Respond with EITHER:\n"
        "1. The COMPLETE revised contents of the target file inside one fenced "
        "```solidity block, with minimal changes addressing the finding; OR\n"
        "2. The single token NOCHANGE if no safe change should be proposed.\n\n"
        "Rules: keep the change minimal and compile-plausible; do not invent token "
        "amounts, prices, balances, or loss figures; do not include step-by-step "
        "exploitation instructions; no prose outside the block."
    )


# ---------------------------------------------------------------------------
# public API
# ---------------------------------------------------------------------------

def propose_patch(
    *,
    project_dir: Path | str,
    target_file: Path | str,
    finding: Dict[str, Any],
    scan_id: Optional[str] = None,
    fingerprint: Optional[str] = None,
    timeout: float = _DEFAULT_TIMEOUT,
) -> Dict[str, Any]:
    """Draft a full-file patch proposal for ``target_file`` via OpenCode.

    Read-only with respect to the real project: OpenCode runs in a scratch
    copy. The proposal is stored for explicit, separate application.
    """
    root = Path(project_dir).resolve()
    target = Path(target_file).resolve()
    if not root.exists():
        raise ValueError(f"project directory does not exist: {root}")
    if not target.is_file():
        raise ValueError(f"target file does not exist: {target}")
    if target.suffix.lower() != ".sol":
        raise ValueError("only .sol files can be proposed")
    if root.is_dir() and root not in target.parents:
        raise ValueError("target file is outside the project directory")

    status = probe()
    if not status["available"]:
        return {
            "status": "unavailable",
            "reason": status["error"],
            "proposal_id": None,
            "checked_at": _utcnow(),
        }

    original_bytes = target.read_bytes()
    try:
        original_text = original_bytes.decode("utf-8")
    except UnicodeDecodeError:
        return {
            "status": "failed",
            "reason": "target file is not UTF-8 text; refusing to propose a rewrite",
            "proposal_id": None,
            "checked_at": _utcnow(),
        }
    if _sha256(original_bytes) != _sha256(original_text.encode("utf-8")):
        return {
            "status": "failed",
            "reason": "target file bytes do not round-trip as UTF-8; refusing",
            "proposal_id": None,
            "checked_at": _utcnow(),
        }

    rel = str(target.relative_to(root)) if root.is_dir() else target.name
    prompt = _build_prompt(rel, finding)

    scratch = Path(tempfile.mkdtemp(prefix="opencode-review-"))
    try:
        _stage_copy(root if root.is_dir() else target, scratch)
        staged_target = scratch / rel
        if not staged_target.is_file():
            # Single-file project: stage target under its own name.
            staged_target = scratch / target.name
            if not staged_target.is_file():
                return {
                    "status": "failed",
                    "reason": "target file could not be staged for review",
                    "proposal_id": None,
                    "checked_at": _utcnow(),
                }

        argv = [
            status["binary"],
            "run",
            "--format",
            "json",
            "--dir",
            str(scratch),
            "--",
            prompt,
        ]
        result = procs_run(argv, timeout=timeout)
        if result.error:
            return {
                "status": "failed",
                "reason": f"opencode failed: {result.error}",
                "proposal_id": None,
                "checked_at": _utcnow(),
            }
        if getattr(result, "timed_out", False):
            return {
                "status": "failed",
                "reason": f"opencode timed out after {timeout:g}s",
                "proposal_id": None,
                "checked_at": _utcnow(),
            }

        text = _extract_text((result.stdout or "") + "\n" + (result.stderr or ""))
        new_content, note = _extract_full_file(text, before=original_text)

        # OpenCode sometimes applies its edit through the ``write`` tool inside
        # the scratch copy instead of printing the file in chat. The scratch
        # file is the authoritative proposal in that case.
        try:
            scratch_bytes = staged_target.read_bytes() if staged_target.is_file() else None
        except OSError:
            scratch_bytes = None
        if scratch_bytes is not None and scratch_bytes != original_bytes:
            scratch_text = scratch_bytes.decode("utf-8", errors="replace")
            if scratch_text.strip():
                new_content = scratch_text
                note = "read from scratch copy (assistant edited the staged file)"
        if new_content is None:
            return {
                "status": "no_change" if note and "NOCHANGE" in note else "failed",
                "reason": note or "empty assistant response",
                "proposal_id": None,
                "checked_at": _utcnow(),
                "assistant_excerpt": text[:400],
            }

        if new_content == original_text:
            return {
                "status": "no_change",
                "reason": "assistant returned identical contents",
                "proposal_id": None,
                "checked_at": _utcnow(),
            }

        before_hash = _sha256(original_bytes)
        after_hash = _sha256(new_content.encode("utf-8"))
        diff = _unified_diff(original_text, new_content, rel)
        if not diff.strip():
            return {
                "status": "no_change",
                "reason": "proposed contents produce an empty diff",
                "proposal_id": None,
                "checked_at": _utcnow(),
            }

        proposal_id = uuid.uuid4().hex
        with _lock:
            _prune_store()
            _proposals[proposal_id] = {
                "proposal_id": proposal_id,
                "source": "opencode",
                "opencode_version": status.get("version"),
                "project_dir": str(root),
                "target_file": str(target),
                "relative_path": rel,
                "scan_id": scan_id,
                "fingerprint": fingerprint,
                "before_hash": before_hash,
                "after_hash": after_hash,
                "new_content": new_content,
                "diff": diff,
                "status": "proposed",
                "created_at": _utcnow(),
                "created_monotonic": time.time(),
            }

        return {
            "status": "proposed",
            "proposal_id": proposal_id,
            "target_file": str(target),
            "relative_path": rel,
            "before_hash": before_hash,
            "after_hash": after_hash,
            "diff": diff,
            "created_at": _utcnow(),
            "source": "opencode",
            "assistant_excerpt": text[:400],
            "apply_requires": "explicit approval + unchanged on-disk file",
        }
    finally:
        shutil.rmtree(scratch, ignore_errors=True)


def apply_patch(
    proposal_id: str,
    *,
    approval: bool,
    expected_before_hash: Optional[str] = None,
) -> Dict[str, Any]:
    """Apply a stored proposal. Requires explicit approval and hash match."""
    if not approval:
        raise ValueError("explicit approval is required before any code change is applied")

    entry = get_proposal(proposal_id)
    if entry is None:
        raise ValueError(f"unknown or expired proposal: {proposal_id}")

    target = Path(entry["target_file"])
    if not target.is_file():
        raise ValueError(f"target file no longer exists: {target}")

    project_dir = Path(entry["project_dir"]).resolve()
    resolved = target.resolve()
    if project_dir.is_dir() and project_dir not in resolved.parents and resolved != project_dir:
        raise ValueError("target file is outside the recorded project directory")

    current_bytes = target.read_bytes()
    current_hash = _sha256(current_bytes)
    if current_hash != entry["before_hash"]:
        raise ValueError(
            "file changed since the proposal was drafted; re-propose before applying"
        )
    if expected_before_hash and expected_before_hash != current_hash:
        raise ValueError("before-hash confirmation mismatch; re-propose before applying")

    payload = entry["new_content"].encode("utf-8")
    if _sha256(payload) != entry["after_hash"]:
        raise ValueError("stored proposal content failed its own hash check; refusing")

    tmp = target.with_name(target.name + f".opencode-new-{uuid.uuid4().hex[:8]}")
    try:
        tmp.write_bytes(payload)
        tmp.replace(target)
    finally:
        if tmp.exists():
            try:
                tmp.unlink()
            except OSError:
                pass

    with _lock:
        if proposal_id in _proposals:
            _proposals[proposal_id]["status"] = "applied"
            _proposals[proposal_id]["applied_at"] = _utcnow()

    return {
        "applied": True,
        "proposal_id": proposal_id,
        "target_file": str(target),
        "bytes_written": len(payload),
        "before_hash": entry["before_hash"],
        "after_hash": entry["after_hash"],
        "applied_at": _utcnow(),
        "note": "Applied after explicit approval and hash verification. Review with git diff.",
    }
