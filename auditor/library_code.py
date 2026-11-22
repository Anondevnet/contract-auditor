"""Phase 19 — recognise vendored, audited library code (OpenZeppelin, solmate, ...).

Used to keep known-library findings out of the default report. Nothing
here deletes a finding: :mod:`auditor.triage` marks it *suppressed* with a
reason, the monitor keeps it in its DB, and ``--show-suppressed`` / the
dashboard filter make it visible again.

Recognition levels (strongest first):

``hash``
    The normalized content of the contract block (comments removed,
    whitespace collapsed) matches an upstream OpenZeppelin release in the
    shipped manifest ``auditor/data/library_hashes.json``. Works for
    multi-file and flattened sources.
``heuristic``
    The file sits under a known vendored-dependency path
    (``@openzeppelin/contracts/``, ``lib/solmate/``, ``solady/``, ...),
    has a ``pragma solidity`` line, and declares the finding's contract
    under a known library symbol name (OpenZeppelin: a name from the
    manifest; others: the file stem). In a flattened file a block counts
    when it is preceded by an ``// OpenZeppelin Contracts ... (<path>/<Name>.sol)``
    header naming the same contract. Heuristic matches are NOT proof that
    the code is unmodified; the level is recorded with every suppression.

Never library code: the deployed (main) contract itself, and anything that
matches neither level.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path, PurePosixPath
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

MANIFEST_PATH = Path(__file__).resolve().parent / "data" / "library_hashes.json"
HASH_LEN = 24

# Vendored-dependency path markers (posix, lower-case match on the path).
LIBRARY_PATH_MARKERS: Tuple[Tuple[str, str], ...] = (
    ("@openzeppelin/contracts-upgradeable/", "openzeppelin-upgradeable"),
    ("@openzeppelin/contracts/", "openzeppelin"),
    ("openzeppelin-contracts-upgradeable/contracts/", "openzeppelin-upgradeable"),
    ("openzeppelin-contracts/contracts/", "openzeppelin"),
    ("lib/openzeppelin-contracts-upgradeable/", "openzeppelin-upgradeable"),
    ("lib/openzeppelin-contracts/", "openzeppelin"),
    ("solmate/src/", "solmate"),
    ("lib/solmate/", "solmate"),
    ("solmate/", "solmate"),
    ("solady/src/", "solady"),
    ("lib/solady/", "solady"),
    ("solady/", "solady"),
    ("@uniswap/v2-core/", "uniswap-v2-core"),
    ("@uniswap/v3-core/", "uniswap-v3-core"),
    ("@uniswap/v2-periphery/", "uniswap-v2-periphery"),
    ("@uniswap/v3-periphery/", "uniswap-v3-periphery"),
    ("@chainlink/contracts/", "chainlink"),
    ("forge-std/", "forge-std"),
    ("lib/forge-std/", "forge-std"),
)

_OZ_HEADER_RE = re.compile(
    r"//\s*OpenZeppelin Contracts(?:-upgradeable)?\s*(?:\(last updated v?([\w.\-]+)\)|v?([\w.\-]+))?"
    r"\s*\(([\w/.\-]+?)/([A-Za-z_]\w*)\.sol\)")
_BLOCK_RE = re.compile(r"\b(?:abstract\s+)?(contract|library|interface)\s+([A-Za-z_]\w*)\b[^{;]*\{")
_PRAGMA_RE = re.compile(r"^\s*pragma\s+solidity\s+[^;]+;", re.MULTILINE)


# ---------------------------------------------------------------------------
# Offset-preserving lexing helpers
# ---------------------------------------------------------------------------

def _blank(text: str, strip_strings: bool) -> str:
    """Replace comments (and optionally string literals) with spaces; keep offsets/newlines."""
    out = list(text)
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        nxt = text[i + 1] if i + 1 < n else ""
        if c == "/" and nxt == "/":
            while i < n and text[i] != "\n":
                out[i] = " "
                i += 1
            continue
        if c == "/" and nxt == "*":
            out[i] = out[i + 1] = " "
            i += 2
            while i < n and not (text[i] == "*" and i + 1 < n and text[i + 1] == "/"):
                if text[i] != "\n":
                    out[i] = " "
                i += 1
            if i < n:
                out[i] = " "
                if i + 1 < n:
                    out[i + 1] = " "
            i += 2
            continue
        if c in "\"'":
            q = c
            i += 1
            while i < n and text[i] != q and text[i] != "\n":
                if strip_strings:
                    out[i] = " "
                if text[i] == "\\" and i + 1 < n:
                    if strip_strings:
                        out[i + 1] = " "
                    i += 2
                    continue
                i += 1
            i += 1
            continue
        i += 1
    return "".join(out)


def strip_comments(text: str) -> str:
    return _blank(text, strip_strings=False)


def code_only(text: str) -> str:
    """Comments AND string contents blanked (offsets preserved)."""
    return _blank(text, strip_strings=True)


def match_brace(code: str, open_idx: int) -> int:
    """Index of the ``}`` matching ``code[open_idx] == '{'`` (or len-1 when unbalanced)."""
    depth = 0
    for j in range(open_idx, len(code)):
        ch = code[j]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return j
    return len(code) - 1


@dataclass
class Block:
    kind: str           # contract | library | interface
    name: str
    start: int          # offset of the keyword
    body_open: int      # offset of '{'
    end: int            # offset of matching '}'
    header_version: Optional[str] = None  # OZ header comment, when present
    header_path: Optional[str] = None
    header_name: Optional[str] = None


def blocks(text: str) -> List[Block]:
    """Top-level contract/library/interface blocks with their spans."""
    code = code_only(text)
    out: List[Block] = []
    pos = 0
    while True:
        m = _BLOCK_RE.search(code, pos)
        if not m:
            break
        open_idx = m.end() - 1
        end = match_brace(code, open_idx)
        b = Block(m.group(1), m.group(2), m.start(), open_idx, end)
        # Header comment in the original text between the previous block and this one.
        prev_end = out[-1].end if out else 0
        heads = list(_OZ_HEADER_RE.finditer(text, prev_end, m.start()))
        if heads:
            h = heads[-1]
            b.header_version = h.group(1) or h.group(2)
            b.header_path = f"{h.group(3)}/{h.group(4)}.sol"
            b.header_name = h.group(4)
        out.append(b)
        pos = end + 1
    return out


def normalize(snippet: str) -> str:
    return " ".join(strip_comments(snippet).split())


def block_hash(text: str, b: Block) -> str:
    return hashlib.sha256(normalize(text[b.start:b.end + 1]).encode("utf-8")).hexdigest()[:HASH_LEN]


def file_hash(text: str) -> str:
    return hashlib.sha256(normalize(text).encode("utf-8")).hexdigest()[:HASH_LEN]


# ---------------------------------------------------------------------------
# Manifest
# ---------------------------------------------------------------------------

@lru_cache(maxsize=4)
def load_manifest(path: Optional[str] = None) -> Dict[str, object]:
    p = Path(path) if path else MANIFEST_PATH
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {"blocks": {}, "files": {}, "names": [], "packages": {}}
    data.setdefault("blocks", {})
    data.setdefault("files", {})
    data.setdefault("names", [])
    return data


@lru_cache(maxsize=4)
def _oz_names(path: Optional[str] = None) -> frozenset:
    return frozenset(load_manifest(path).get("names") or [])


def library_package(rel_path: Optional[str]) -> Optional[str]:
    """Vendored package name for a source path, or None."""
    if not rel_path:
        return None
    p = "/" + str(PurePosixPath(str(rel_path).replace("\\", "/"))).lstrip("/").lower()
    for marker, pkg in LIBRARY_PATH_MARKERS:
        if "/" + marker in p or p.startswith("/" + marker):
            return pkg
    if "/node_modules/" in p:
        return "node_modules"
    return None


@dataclass
class LibraryMatch:
    is_library: bool
    level: Optional[str] = None      # hash | heuristic
    package: Optional[str] = None
    version: Optional[str] = None    # upstream release(s) matched, hash level only
    upstream_path: Optional[str] = None
    detail: str = ""

    def to_dict(self) -> Dict[str, object]:
        return {"is_library": self.is_library, "level": self.level, "package": self.package,
                "version": self.version, "upstream_path": self.upstream_path, "detail": self.detail}


NOT_LIBRARY = LibraryMatch(False, detail="not recognised as library code")


class SourceIndex:
    """Source files of one scan, indexed by relative name, with parsed blocks."""

    def __init__(self, files: Sequence[Path], root: Optional[Path] = None,
                 manifest_path: Optional[str] = None):
        self.files = [Path(f) for f in files]
        self.root = Path(root) if root else _common_root(self.files)
        self.manifest_path = manifest_path
        self.text: Dict[str, str] = {}
        self.code: Dict[str, str] = {}
        self.blocks: Dict[str, List[Block]] = {}
        for f in self.files:
            rel = _rel(f, self.root)
            try:
                t = f.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            self.text[rel] = t
            self.code[rel] = code_only(t)
            self.blocks[rel] = blocks(t)

    def find_block(self, contract: Optional[str], file: Optional[str] = None
                   ) -> Optional[Tuple[str, Block]]:
        if not contract:
            return None
        cands = [file] if file and file in self.blocks else list(self.blocks)
        if file and file not in self.blocks:
            # affected_file may be relative to a different root: suffix match
            cands = [k for k in self.blocks if k.endswith(str(file).lstrip("./"))] or list(self.blocks)
        for rel in cands:
            for b in self.blocks.get(rel, []):
                if b.name == contract:
                    return rel, b
        return None

    def classify(self, contract: Optional[str], file: Optional[str] = None,
                 main_contract: Optional[str] = None) -> LibraryMatch:
        if not contract:
            return LibraryMatch(False, detail="finding has no contract location")
        if main_contract and contract == main_contract:
            return LibraryMatch(False, detail="the deployed (main) contract is never library code")
        hit = self.find_block(contract, file)
        if hit is None:
            return LibraryMatch(False, detail=f"contract {contract} not found in the sources")
        rel, b = hit
        text = self.text[rel]
        man = load_manifest(self.manifest_path)
        h = block_hash(text, b)
        entry = (man.get("blocks") or {}).get(h)
        if entry and entry.get("name") == b.name:
            return LibraryMatch(True, "hash", entry.get("package", "openzeppelin"),
                                ",".join(entry.get("versions") or []), entry.get("path"),
                                "contract body matches an upstream release by normalized content hash")
        pkg = library_package(rel)
        has_pragma = bool(_PRAGMA_RE.search(self.code[rel])) or bool(re.search(r"pragma\s+solidity", text))
        if pkg and has_pragma:
            stem = PurePosixPath(rel).stem
            if pkg.startswith("openzeppelin"):
                base = b.name[:-len("Upgradeable")] if b.name.endswith("Upgradeable") else b.name
                if base in _oz_names(self.manifest_path) or b.name in _oz_names(self.manifest_path):
                    return LibraryMatch(True, "heuristic", pkg, None, rel,
                                        "vendored OpenZeppelin path + pragma + known OpenZeppelin symbol "
                                        "(content not hash-verified)")
            elif b.name == stem:
                return LibraryMatch(True, "heuristic", pkg, None, rel,
                                    f"vendored {pkg} path + pragma + file-named symbol (content not hash-verified)")
        if b.header_name and b.header_name == b.name and has_pragma:
            base = b.name[:-len("Upgradeable")] if b.name.endswith("Upgradeable") else b.name
            if base in _oz_names(self.manifest_path) or b.name in _oz_names(self.manifest_path):
                return LibraryMatch(True, "heuristic", "openzeppelin", b.header_version, b.header_path,
                                    "flattened block with OpenZeppelin header + known symbol "
                                    "(content not hash-verified)")
        return LibraryMatch(False, detail="not recognised as library code")

    def library_block_names(self, main_contract: Optional[str] = None) -> Dict[Tuple[str, str], LibraryMatch]:
        """{(file, contract): match} for every recognised library block."""
        out = {}
        for rel, bl in self.blocks.items():
            for b in bl:
                m = self.classify(b.name, rel, main_contract)
                if m.is_library:
                    out[(rel, b.name)] = m
        return out


def _common_root(files: Sequence[Path]) -> Path:
    import os

    if not files:
        return Path(".")
    if len(files) == 1:
        return files[0].parent
    return Path(os.path.commonpath([str(f) for f in files]))


def _rel(f: Path, root: Path) -> str:
    try:
        return f.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return f.name


def build_manifest_entries(package_root: Path, package: str, version: str,
                           blocks_out: Dict[str, dict], files_out: Dict[str, dict],
                           names_out: set) -> int:
    """Hash every .sol file / block under an extracted npm package (dev tool helper)."""
    n = 0
    for f in sorted(package_root.rglob("*.sol")):
        rel = f.relative_to(package_root).as_posix()
        text = f.read_text(encoding="utf-8", errors="replace")
        fh = file_hash(text)
        e = files_out.setdefault(fh, {"package": package, "path": rel, "versions": []})
        if version not in e["versions"]:
            e["versions"].append(version)
        for b in blocks(text):
            names_out.add(b.name)
            bh = block_hash(text, b)
            be = blocks_out.setdefault(bh, {"package": package, "name": b.name, "path": rel, "versions": []})
            if version not in be["versions"]:
                be["versions"].append(version)
            n += 1
    return n


def iter_versions(entries: Iterable[dict]) -> List[str]:
    vs = set()
    for e in entries:
        vs.update(e.get("versions") or [])
    return sorted(vs)
