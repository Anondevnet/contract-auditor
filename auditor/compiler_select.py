"""Phase 18.1 — per-scan solc selection for verified (Etherscan) sources.

Picks the exact compiler a contract was verified with (Etherscan
``CompilerVersion``), falling back to the ``pragma solidity`` constraints,
ensures that solc binary exists in the solc-select artifacts cache
(``solc-select install X`` — a GET download of the official binary — only
when allowed), and builds per-scan Slither options:

* ``solc``         absolute path to that binary (Slither ``--solc``)
* ``solc_args``    ``--base-path``/``--optimize``/``--optimize-runs``/
                   ``--evm-version``/``--via-ir`` from the verification settings
* ``solc_remaps``  remappings from standard-JSON ``settings.remappings``
* ``slither_target`` / ``slither_cwd``  the main contract file, relative to
                   the materialised source root, so source-unit names (and
                   therefore ``@openzeppelin/...`` imports) match the
                   original compilation.

The global solc-select default (``solc-select use``) is NEVER changed: the
binary is passed by absolute path to the one Slither subprocess.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence

VERSION_RE = re.compile(r"^\d+\.\d+\.\d+$")
_ETHERSCAN_VER_RE = re.compile(r"^v?(\d+\.\d+\.\d+)(?:\+commit\.[0-9a-f]+)?$")
_PRAGMA_RE = re.compile(r"pragma\s+solidity\s+([^;]+);")
_EVM_RE = re.compile(r"^[a-z][a-zA-Z]+$")

#: Known solc releases used only to resolve a *range* pragma when nothing
#: installed satisfies it. Exact Etherscan versions never need this list.
KNOWN_RELEASES: tuple[str, ...] = tuple(
    [f"0.4.{p}" for p in range(11, 27)]
    + [f"0.5.{p}" for p in range(0, 18)]
    + [f"0.6.{p}" for p in range(0, 13)]
    + [f"0.7.{p}" for p in range(0, 7)]
    + [f"0.8.{p}" for p in range(0, 31)]
)


class CompilerSelectionError(RuntimeError):
    """Compiler could not be determined or provisioned (scan is incomplete)."""


def _vt(v: str) -> tuple[int, int, int]:
    a, b, c = (int(x) for x in v.split("."))
    return a, b, c


def parse_etherscan_version(raw: Optional[str]) -> Optional[str]:
    """``v0.8.30+commit.73712a01`` -> ``0.8.30``; nightlies/vyper -> None."""
    if not raw:
        return None
    m = _ETHERSCAN_VER_RE.match(str(raw).strip())
    return m.group(1) if m else None


# ---------------------------------------------------------------------------
# pragma constraints
# ---------------------------------------------------------------------------

def _pad(v: str) -> str:
    parts = v.split(".")
    while len(parts) < 3:
        parts.append("0")
    return ".".join(parts[:3])


def _comparator_ok(op: str, ver: str, cand: str) -> bool:
    c, v = _vt(cand), _vt(_pad(ver))
    if op in ("", "="):
        return c == v
    if op == ">=":
        return c >= v
    if op == ">":
        return c > v
    if op == "<=":
        return c <= v
    if op == "<":
        return c < v
    if op == "^":
        if v[0] == 0:
            return c >= v and c[:2] == v[:2]  # ^0.8.x -> <0.9.0
        return c >= v and c[0] == v[0]
    if op == "~":
        return c >= v and c[:2] == v[:2]
    return False


def satisfies(constraint: str, cand: str) -> bool:
    """Minimal solc pragma matcher: ``^ ~ >= > <= < =``, AND by space, ``||``."""
    for alt in constraint.split("||"):
        toks = re.findall(r"(\^|~|>=|<=|>|<|=)?\s*(\d+(?:\.\d+){0,2})", alt)
        if toks and all(_comparator_ok(op, v, cand) for op, v in toks):
            return True
    return False


def pragma_constraints(sources: Iterable[str]) -> List[str]:
    out = []
    for text in sources:
        for m in _PRAGMA_RE.finditer(_strip_comments(text)):
            out.append(m.group(1).strip())
    return out


def _strip_comments(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", " ", text, flags=re.S)
    return re.sub(r"//[^\n]*", " ", text)


def choose_pragma_version(constraints: Sequence[str], installed: Iterable[str]) -> Optional[str]:
    """Highest version satisfying every constraint, preferring installed ones."""
    if not constraints:
        return None
    inst = sorted({v for v in installed if VERSION_RE.match(v)}, key=_vt, reverse=True)
    for pool in (inst, sorted(KNOWN_RELEASES, key=_vt, reverse=True)):
        for cand in pool:
            if all(satisfies(c, cand) for c in constraints):
                return cand
    return None


# ---------------------------------------------------------------------------
# solc-select artifacts (scoped; never `solc-select use`)
# ---------------------------------------------------------------------------

def artifacts_dir() -> Path:
    override = os.environ.get("AUDITOR_SOLC_ARTIFACTS", "").strip()
    if override:
        return Path(override)
    try:  # solc-select's own resolution (honours VIRTUAL_ENV)
        from solc_select.constants import ARTIFACTS_DIR  # type: ignore

        return Path(ARTIFACTS_DIR)
    except Exception:  # noqa: BLE001
        return Path.home() / ".solc-select" / "artifacts"


def artifact_path(version: str, root: Optional[Path] = None) -> Path:
    root = root or artifacts_dir()
    return root / f"solc-{version}" / f"solc-{version}"


def installed_versions(root: Optional[Path] = None) -> List[str]:
    root = root or artifacts_dir()
    if not root.is_dir():
        return []
    out = []
    for d in root.iterdir():
        v = d.name[5:] if d.name.startswith("solc-") else ""
        if VERSION_RE.match(v) and artifact_path(v, root).is_file():
            out.append(v)
    return sorted(out, key=_vt)


def _default_installer(version: str) -> None:
    """`solc-select install X`: GET download of the official binary, cached.

    ``install`` does not change the global default (that is ``use``)."""
    import shutil

    exe = shutil.which("solc-select")
    if not exe:
        raise CompilerSelectionError(
            f"solc {version} is not installed and solc-select is not on PATH; "
            f"run: solc-select install {version}")
    proc = subprocess.run([exe, "install", version], capture_output=True, text=True, timeout=300)
    if proc.returncode != 0:
        raise CompilerSelectionError(
            f"solc-select install {version} failed: {(proc.stderr or proc.stdout).strip()[:200]}")


def ensure_solc(version: str, allow_install: bool = True,
                installer: Callable[[str], None] = _default_installer,
                root: Optional[Path] = None) -> str:
    if not VERSION_RE.match(version or ""):
        raise CompilerSelectionError(f"invalid solc version {version!r}")
    path = artifact_path(version, root)
    if not path.is_file():
        if not allow_install:
            raise CompilerSelectionError(
                f"solc {version} is not installed (auto-install disabled); run: solc-select install {version}")
        installer(version)
        path = artifact_path(version, root)
        if not path.is_file():
            raise CompilerSelectionError(f"solc {version} still missing after install at {path}")
    if not os.access(str(path), os.X_OK):
        raise CompilerSelectionError(f"solc {version} at {path} is not executable")
    return str(path)


# ---------------------------------------------------------------------------
# settings -> Slither options
# ---------------------------------------------------------------------------

@dataclass
class CompilePlan:
    version: str
    version_source: str  # "etherscan" | "pragma"
    solc_path: str
    solc_args: str
    solc_remaps: Optional[str]
    target: str
    cwd: str
    settings: Dict[str, Any] = field(default_factory=dict)

    def options(self) -> Dict[str, Any]:
        return {"solc": self.solc_path, "solc_args": self.solc_args,
                "solc_remaps": self.solc_remaps, "slither_target": self.target,
                "slither_cwd": self.cwd}

    def to_dict(self) -> Dict[str, Any]:
        return {"solc_version": self.version, "version_source": self.version_source,
                "solc_path": self.solc_path, "solc_args": self.solc_args,
                "solc_remaps": self.solc_remaps, "target": self.target, **self.settings}


def standard_json_settings(source_code: str) -> Optional[Dict[str, Any]]:
    text = (source_code or "").strip()
    if not text.startswith("{"):
        return None
    raw = text[1:-1] if text.startswith("{{") else text
    try:
        obj = json.loads(raw)
    except ValueError:
        return None
    s = obj.get("settings") if isinstance(obj, dict) else None
    return s if isinstance(s, dict) else {}


def _supports(version: str, minimum: str) -> bool:
    return _vt(version) >= _vt(minimum)


def _main_file(files: Sequence[Path], root: Path, contract_name: Optional[str]) -> Path:
    if contract_name:
        pat = re.compile(r"\b(?:contract|library|interface)\s+" + re.escape(contract_name) + r"\b")
        hits = [f for f in files if pat.search(_strip_comments(f.read_text(encoding="utf-8", errors="replace")))]
        if hits:
            return sorted(hits, key=lambda p: (len(p.parts), str(p)))[0]
    return sorted(files, key=lambda p: (len(p.parts), str(p)))[0]


def plan_compile(record: Mapping[str, Any], files: Sequence[Path], root: Path,
                 allow_install: bool = True, installer: Callable[[str], None] = _default_installer,
                 artifacts: Optional[Path] = None) -> CompilePlan:
    """Build the per-scan compile plan or raise CompilerSelectionError."""
    if not files:
        raise CompilerSelectionError("no .sol files to compile")
    root = Path(root).resolve()
    if any(ch.isspace() for ch in str(root)):
        raise CompilerSelectionError(f"source cache path contains whitespace: {root}")
    source_code = str(record.get("SourceCode") or "")
    sj = standard_json_settings(source_code)

    version = parse_etherscan_version(record.get("CompilerVersion"))
    vsrc = "etherscan"
    if version is None:
        texts = [f.read_text(encoding="utf-8", errors="replace") for f in files]
        version = choose_pragma_version(pragma_constraints(texts), installed_versions(artifacts))
        vsrc = "pragma"
    if version is None:
        raise CompilerSelectionError("could not determine solc version (no Etherscan CompilerVersion, no pragma)")
    solc_path = ensure_solc(version, allow_install=allow_install, installer=installer, root=artifacts)

    settings: Dict[str, Any] = {}
    if sj is not None:
        opt = sj.get("optimizer") or {}
        settings["optimize"] = bool(opt.get("enabled"))
        settings["optimize_runs"] = opt.get("runs")
        settings["evm_version"] = sj.get("evmVersion")
        settings["via_ir"] = bool(sj.get("viaIR"))
        remaps = [r for r in (sj.get("remappings") or []) if isinstance(r, str)]
    else:
        settings["optimize"] = str(record.get("OptimizationUsed") or "0").strip() == "1"
        runs = str(record.get("Runs") or "").strip()
        settings["optimize_runs"] = int(runs) if runs.isdigit() else None
        evm = str(record.get("EVMVersion") or "").strip()
        settings["evm_version"] = None if evm.lower() in ("", "default") else evm
        settings["via_ir"] = False
        remaps = []

    args: List[str] = []
    if _supports(version, "0.6.9"):
        args += ["--base-path", "."]
    if settings["optimize"]:
        args.append("--optimize")
        runs = settings.get("optimize_runs")
        if isinstance(runs, int) or (isinstance(runs, str) and runs.isdigit()):
            args += ["--optimize-runs", str(int(runs))]
    evm = settings.get("evm_version")
    if evm:
        if not _EVM_RE.match(str(evm)):
            raise CompilerSelectionError(f"invalid EVM version {evm!r}")
        args += ["--evm-version", str(evm)]
    if settings.get("via_ir") and _supports(version, "0.8.13"):
        args.append("--via-ir")

    remap_tokens = []
    for r in remaps:
        r = r.strip()
        if not r or any(ch.isspace() or ch in "\"'" for ch in r) or "=" not in r:
            raise CompilerSelectionError(f"unsupported remapping {r!r}")
        ctx_prefix, _, tgt = r.partition("=")
        if tgt.startswith("/") or ".." in Path(tgt).parts:
            raise CompilerSelectionError(f"remapping escapes the source root: {r!r}")
        remap_tokens.append(r)
    main = _main_file(files, root, str(record.get("ContractName") or "") or None)
    target = str(main.resolve().relative_to(root))
    return CompilePlan(version=version, version_source=vsrc, solc_path=solc_path,
                       solc_args=" ".join(args), solc_remaps=" ".join(remap_tokens) or None,
                       target=target, cwd=str(root), settings=settings)
