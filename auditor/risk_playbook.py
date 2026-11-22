"""Phase 18 — static per-category risk & remediation playbook.

Maps a stored finding to a vulnerability class and returns the heuristic
exploitability / time bands, a DEFENSIVE description of the attack class
and remediation guidance from ``auditor/data/risk_playbook.json``.

Everything here is a static lookup table: it is labelled as a heuristic,
never measured against the contract, never a finding by itself, and it
deliberately contains no exploit steps, exploit code or payloads.
"""

from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, Mapping, Optional

PLAYBOOK_PATH = Path(__file__).resolve().parent / "data" / "risk_playbook.json"

_DESC_SLUG_RE = re.compile(r"(?:Slither|Source) detector: ([a-z0-9-]+)\.")
_TITLE_PREFIX_RE = re.compile(r"^([a-z0-9]+(?:-[a-z0-9]+)+)\b")
_TITLE_FAMILIES = (
    ("Reentrancy vulnerability", "reentrancy"),
    ("Access control issue", "access_control"),
    ("ERC-4626", "erc4626_inflation"),
)


@lru_cache(maxsize=1)
def load_playbook(path: Optional[str] = None) -> Dict[str, Any]:
    data = json.loads(Path(path or PLAYBOOK_PATH).read_text(encoding="utf-8"))
    if data.get("fallback") not in data.get("classes", {}):
        raise ValueError("risk playbook: fallback class missing")
    return data


@lru_cache(maxsize=1)
def slug_index() -> Dict[str, str]:
    idx: Dict[str, str] = {}
    for cls, entry in load_playbook()["classes"].items():
        for slug in entry.get("slugs", []):
            idx[slug] = cls
    return idx


def detector_slugs(finding: Mapping[str, Any]) -> list[str]:
    desc = str(finding.get("description") or "")
    title = str(finding.get("title") or "")
    slugs = _DESC_SLUG_RE.findall(desc)
    m = _TITLE_PREFIX_RE.match(title)
    if m and m.group(1) not in slugs:
        slugs.append(m.group(1))
    return slugs


def classify(finding: Mapping[str, Any]) -> tuple[str, Optional[str]]:
    """(vulnerability class, detector slug or None). Never raises."""
    idx = slug_index()
    slugs = detector_slugs(finding)
    for s in slugs:
        if s in idx:
            return idx[s], s
    title = str(finding.get("title") or "")
    for prefix, cls in _TITLE_FAMILIES:
        if title.startswith(prefix):
            return cls, (slugs[0] if slugs else None)
    return load_playbook()["fallback"], (slugs[0] if slugs else None)


def risk_for(finding: Mapping[str, Any]) -> Dict[str, Any]:
    pb = load_playbook()
    cls, slug = classify(finding)
    e = pb["classes"][cls]
    return {
        "vulnerability_class": cls,
        "label": e["label"],
        "detector": slug,
        "heuristic": True,
        "heuristic_note": pb["heuristic_note"],
        "exploitability": e["exploitability"],
        "time_to_exploit": e["time_to_exploit"],
        "attack_class": e["attack_class"],
        "remediation": e["remediation"],
        "fix_pattern": e["fix_pattern"],
        "time_to_fix": e["time_to_fix"],
    }
