"""Resolve a stored scan ``source_path`` to local, verified source files.

Scans recorded by the monitor/hunt/scan-address store a *virtual* reference
``etherscan://<network>/<address>`` (older rows: ``etherscan://<address>``).
The verified source (all files, imports included) was materialized under the
monitor cache at ``<cache>/<network>/<address>/<content_hash[:16]>`` or
``<cache>/hunt/sources/<network>/<address>/<content_hash[:16]>``.

This module never fetches, fabricates, or substitutes source: if the exact
cached directory is not present it returns an actionable diagnostic.
Local paths are confined to allowed roots (no traversal outside them).
"""
from __future__ import annotations

import os
import re
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

_ADDR_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")
_NET_RE = re.compile(r"^[a-z0-9-]{1,32}$")
_PROJECT_ROOT = Path(__file__).resolve().parent.parent


class SourceResolutionError(ValueError):
    """Source could not be resolved; ``code`` is machine readable."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass
class ResolvedSource:
    path: Path
    kind: str                     # "local" | "verified-cache"
    ref: str
    network: Optional[str] = None
    address: Optional[str] = None
    content_hash: Optional[str] = None
    file_count: int = 0


def _cache_root() -> Path:
    override = os.environ.get("AUDITOR_MONITOR_CACHE", "").strip()
    return Path(override) if override else _PROJECT_ROOT / "monitor_cache"


def allowed_roots() -> List[Path]:
    roots = [_PROJECT_ROOT, _cache_root(), Path(tempfile.gettempdir()), Path.home()]
    extra = os.environ.get("AUDITOR_SOURCE_ROOTS", "")
    roots += [Path(p) for p in extra.split(os.pathsep) if p.strip()]
    out = []
    for r in roots:
        try:
            out.append(r.expanduser().resolve())
        except OSError:
            continue
    return out


def _is_within(child: Path, root: Path) -> bool:
    try:
        child.relative_to(root)
        return True
    except ValueError:
        return False


def _confine_local(raw: str) -> Path:
    if "\x00" in raw:
        raise SourceResolutionError("unsafe_path", "source path contains a NUL byte")
    p = Path(raw).expanduser()
    try:
        resolved = p.resolve(strict=False)
    except (OSError, RuntimeError) as exc:
        raise SourceResolutionError("unsafe_path", f"source path cannot be resolved: {exc}") from exc
    home = Path.home().resolve()
    # Never read hidden top-level home dirs (~/.ssh, ~/.aws, ...) or ~/Library.
    if _is_within(resolved, home) and resolved != home:
        first = resolved.relative_to(home).parts[0]
        if first.startswith(".") or first == "Library":
            raise SourceResolutionError(
                "unsafe_path", f"source path is in a protected location: ~/{first}")
    if not any(_is_within(resolved, r) for r in allowed_roots()):
        raise SourceResolutionError(
            "unsafe_path",
            "source path is outside the allowed roots (project, monitor cache, temp, home, "
            "AUDITOR_SOURCE_ROOTS)")
    if not resolved.exists():
        raise SourceResolutionError("not_found", f"source path does not exist: {raw}")
    return resolved


def parse_etherscan_ref(ref: str):
    body = ref[len("etherscan://"):].strip("/")
    parts = body.split("/")
    if len(parts) == 1:
        net, addr = "ethereum", parts[0]
    elif len(parts) == 2:
        net, addr = parts
    else:
        raise SourceResolutionError("bad_ref", f"malformed etherscan reference: {ref}")
    if not _NET_RE.match(net) or not _ADDR_RE.match(addr):
        raise SourceResolutionError("bad_ref", f"malformed etherscan reference: {ref}")
    return net, addr.lower()


def _sol_count(d: Path) -> int:
    return sum(1 for _ in d.rglob("*.sol"))


def resolve_source(ref: str, content_hash: Optional[str] = None) -> ResolvedSource:
    """Map a stored source reference to an existing local directory/file."""
    if not ref or not str(ref).strip():
        raise SourceResolutionError("missing", "no source path recorded for this scan")
    ref = str(ref).strip()
    if ref.startswith("etherscan://"):
        net, addr = parse_etherscan_ref(ref)
        cache = _cache_root().resolve()
        bases = [cache / net / addr, cache / "hunt" / "sources" / net / addr]
        candidates: List[Path] = []
        if content_hash:
            if not re.fullmatch(r"[0-9a-fA-F]{16,64}", content_hash):
                raise SourceResolutionError("bad_ref", "content hash is malformed")
            candidates = [b / content_hash[:16].lower() for b in bases]
        else:
            for b in bases:
                if b.is_dir():
                    candidates += sorted((d for d in b.iterdir() if d.is_dir()),
                                         key=lambda d: d.stat().st_mtime, reverse=True)
        for c in candidates:
            if c.is_dir() and _is_within(c.resolve(), cache) and _sol_count(c) > 0:
                return ResolvedSource(path=c.resolve(), kind="verified-cache", ref=ref, network=net,
                                      address=addr, content_hash=content_hash, file_count=_sol_count(c))
        # A requested content hash must match exactly. Substituting another
        # cached version for the same address would silently audit the wrong code.
        want = f" for content hash {content_hash[:16]}" if content_hash else ""
        raise SourceResolutionError(
            "source_unavailable",
            f"verified source for {net}:{addr}{want} is not in the local cache "
            f"({', '.join(str(b) for b in bases)}). Re-fetch it with "
            f"`audit.py scan-address {addr}` (or Retest), then run the AI audit again.")
    p = _confine_local(ref)
    n = _sol_count(p) if p.is_dir() else (1 if p.suffix == ".sol" else 0)
    return ResolvedSource(path=p, kind="local", ref=ref, file_count=n)


def recorded_compile_options(cache_dir: Path) -> Optional[Dict[str, Any]]:
    """Read-only: the compile plan the monitor recorded for this verified-source
    cache (solc binary, args, remappings, target). None when unknown."""
    import json as _json
    import sqlite3
    from auditor.monitor import default_monitor_db_path

    db = default_monitor_db_path()
    if not Path(db).exists():
        return None
    try:
        con = sqlite3.connect(f"file:{db}?mode=ro", uri=True, timeout=2)
        row = con.execute("SELECT compile_settings FROM monitor_scans WHERE cache_dir=? AND "
                          "compile_settings IS NOT NULL ORDER BY id DESC LIMIT 1",
                          (str(cache_dir),)).fetchone()
        con.close()
        cs = _json.loads(row[0]) if row and row[0] else None
    except (sqlite3.Error, ValueError):
        return None
    if not isinstance(cs, dict) or not cs.get("solc_path"):
        return None
    return {"solc": cs.get("solc_path"), "solc_args": cs.get("solc_args"),
            "solc_remaps": cs.get("solc_remaps"), "slither_target": cs.get("target"),
            "slither_cwd": str(cache_dir), "source_root": str(cache_dir)}
