"""Reproduce + disclose package (hunting strategy 7).

Assembles a PRIVATE report for a finding ONLY when it was dynamically
reproduced (or independently confirmed) on a local fork pinned to a block,
with an outsider take >= $1k. Writes under the gitignored
``reports/research/disclosures/``. It identifies a security contact from
local data only (NatSpec ``@custom:security-contact`` / ``security.txt``-
style lines in the verified source, the local bounty registry) and NEVER
contacts anyone, sends a transaction or publishes calldata.

``confirmation_gate`` is the single rule for ``confirmed_exploitable=1``.
"""
from __future__ import annotations

import json
import re
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DISCLOSURE_DIR = PROJECT_ROOT / "reports" / "research" / "disclosures"
POC_ROOT = PROJECT_ROOT / "reports" / "research" / "poc"
MIN_TAKE_USD = 1000.0
DYNAMIC = {"dynamically_reproduced", "independently_confirmed"}


def confirmation_gate(evidence: Dict[str, Any]) -> Tuple[bool, str]:
    """True only for a dynamic/independent confirmation with a pinned block,
    an outsider attacker and a measured take >= $1k."""
    kind = str(evidence.get("kind") or "")
    if kind not in DYNAMIC:
        return False, f"evidence kind {kind or 'missing'!r} is not dynamic reproduction/independent confirmation"
    if kind == "dynamically_reproduced" and not evidence.get("fork_block"):
        return False, "no pinned fork block recorded"
    if not evidence.get("attacker_is_outsider"):
        return False, "attacker was not an unprivileged outsider"
    take = evidence.get("outsider_take_usd")
    if take is None:
        return False, "outsider take is unknown"
    if float(take) < MIN_TAKE_USD:
        return False, f"outsider take ${float(take):,.0f} < ${MIN_TAKE_USD:,.0f}"
    poc = evidence.get("poc_path")
    if kind == "dynamically_reproduced":
        if not poc:
            return False, "no PoC path"
        try:
            Path(poc).resolve().relative_to(POC_ROOT.resolve())
        except ValueError:
            return False, "PoC is not under the gitignored reports/research/poc/"
    return True, "gate passed"


_CONTACT_RES = [re.compile(r"@custom:security-contact\s+(\S+)"),
                re.compile(r"(?im)^\s*(?://|\*)?\s*Contact:\s*(\S+)"),
                re.compile(r"(?i)security@[\w.-]+\.[a-z]{2,}")]


def security_contacts(source_text: str, project: Optional[str] = None,
                      registry_path: Optional[Path] = None) -> List[Dict[str, str]]:
    out: List[Dict[str, str]] = []
    for rx in _CONTACT_RES:
        for m in rx.finditer(source_text or ""):
            v = (m.group(1) if m.groups() else m.group(0)).strip().rstrip(".,;")
            if v and not any(o["value"] == v for o in out):
                out.append({"value": v, "source": "verified source"})
    if project:
        from auditor.bounty import _registry_lookup
        url = _registry_lookup(project, registry_path)
        if url:
            out.append({"value": url, "source": "local bounty registry"})
    return out


def build_package(finding: Dict[str, Any], evidence: Dict[str, Any], source_text: str = "",
                  project: Optional[str] = None, out_dir: Optional[Path] = None,
                  registry_path: Optional[Path] = None) -> Dict[str, Any]:
    ok, why = confirmation_gate(evidence)
    if not ok:
        return {"created": False, "reason": why, "confirmed_exploitable": 0}
    contacts = security_contacts(source_text, project, registry_path)
    d = Path(out_dir or DISCLOSURE_DIR)
    d.mkdir(parents=True, exist_ok=True)
    addr = str(finding.get("address") or "unknown").lower()
    path = d / f"{addr}-{int(time.time())}.md"
    lines = [
        f"# PRIVATE — do not publish\n",
        f"- Address: {addr} ({finding.get('network') or 'ethereum'})",
        f"- Finding: {finding.get('title')}",
        f"- Location: {finding.get('contract')}.{finding.get('function')} L{finding.get('lines')}",
        f"- Epistemic label: {evidence['kind'].replace('_', ' ')}",
        f"- Fork block: {evidence.get('fork_block')} (local fork; nothing broadcast)",
        f"- Outsider take (measured): ${float(evidence['outsider_take_usd']):,.0f}",
        f"- Confidence: {evidence.get('confidence', 'unknown')}",
        "\n## Mechanism\n", str(evidence.get("mechanism") or finding.get("description") or "unknown"),
        "\n## Prerequisites\n", "\n".join(f"- {p}" for p in evidence.get("prerequisites") or []) or "- unknown",
        "\n## Impact\n", str(evidence.get("impact") or "unknown"),
        "\n## PoC\n", f"Local path (gitignored): {evidence.get('poc_path') or 'n/a'} — no calldata in this report.",
        "\n## Security contact (identified, NOT contacted)\n",
        "\n".join(f"- {c['value']} ({c['source']})" for c in contacts) or "- none found in local data",
    ]
    path.write_text("\n".join(lines) + "\n")
    meta = {"created": True, "path": str(path), "contacts": contacts, "confirmed_exploitable": 1,
            "contacted": False}
    (path.with_suffix(".json")).write_text(json.dumps(dict(meta, finding=finding, evidence=evidence), default=str, indent=1))
    return meta
