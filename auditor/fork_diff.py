"""Fork-diff (hunting strategy 2): which functions of a likely fork were changed?

Offline and read-only. The upstream is inferred by function-signature overlap
with well-known families (Compound v2, Uniswap v2/v3, ERC-4626, Aave, MasterChef
/ reward staking). There is no network fetch of a pinned upstream: the
reference is the local verified-source corpus (``monitor_cache``). For each
function of the candidate, the normalized body is hashed; a function whose
name is common in the family corpus (>= ``min_common`` contracts) but whose
body matches NO other contract's body is reported as *changed*. Those changed
functions are what deeper verification should look at first.

Pinned upstream (Phase 36): when ``corpus/upstream`` (fetched by
``scripts/fetch_upstream_corpus.sh`` from the commits pinned in
``auditor/data/upstream_corpus.json``) is present, functions are compared to
the upstream bodies of the same family first: *upstream_match* (identical to a
pinned upstream body), *changed* with basis ``upstream`` (name exists upstream
in that family, body differs) or *added* (not in upstream). Without an upstream
reference for the family the corpus-majority rule above applies (basis
``corpus``) and an empty result stays "inconclusive".

Labels: a "changed" function is only a review priority, never a finding.
"""
from __future__ import annotations

import hashlib
import json
import re
import sqlite3
import time
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence

from auditor.analysis.sol_parse import contracts_in

FAMILIES: Dict[str, set] = {
    "compound_v2": {"exchangeRateStored", "mint", "redeem", "borrow", "repayBorrow", "liquidateBorrow", "accrueInterest"},
    "uniswap_v2": {"getReserves", "swap", "skim", "sync", "mint", "burn"},
    "uniswap_v3": {"slot0", "swap", "mint", "burn", "collect", "flash", "observe"},
    "erc4626": {"totalAssets", "convertToShares", "convertToAssets", "previewDeposit", "deposit", "redeem", "withdraw"},
    "aave": {"supply", "deposit", "borrow", "repay", "liquidationCall", "flashLoan", "withdraw"},
    "masterchef": {"deposit", "withdraw", "updatePool", "massUpdatePools", "emergencyWithdraw", "add", "set"},
}
MIN_OVERLAP = 0.6


def _norm(body: str) -> str:
    b = re.sub(r"//[^\n]*|/\*.*?\*/", "", body, flags=re.S)
    return re.sub(r"\s+", "", b)


def body_hash(body: str) -> str:
    return hashlib.sha256(_norm(body).encode()).hexdigest()[:16]


def family_of(fn_names: Iterable[str]) -> Optional[str]:
    names = set(fn_names)
    best, score = None, 0.0
    for fam, sig in FAMILIES.items():
        s = len(names & sig) / len(sig)
        if s > score:
            best, score = fam, s
    return best if score >= MIN_OVERLAP else None


def _contracts(root: Path):
    for f in sorted(root.rglob("*.sol")):
        if re.search(r"(openzeppelin|solmate|solady|forge-std|/lib/)", str(f), re.I):
            continue
        try:
            for c in contracts_in(f.read_text(errors="replace")):
                yield f, c
        except Exception:  # noqa: BLE001
            continue


def build_index(cache_roots: Sequence[Path]) -> Dict[str, Any]:
    """{family: {fn_name: Counter(body_hash -> #contracts)}} over the corpus.
    Each (root, contract) counts once per body hash."""
    idx: Dict[str, Dict[str, Counter]] = defaultdict(lambda: defaultdict(Counter))
    n = 0
    for root in cache_roots:
        for _f, c in _contracts(root):
            fam = family_of(fn.name for fn in c.functions)
            if not fam:
                continue
            n += 1
            for fn in c.functions:
                if fn.body.strip():
                    idx[fam][fn.name][body_hash(fn.body)] += 1
    return {"families": idx, "contracts": n}


UPSTREAM_DIR = Path(__file__).resolve().parent.parent / "corpus" / "upstream"


def build_upstream_index(root: Path = UPSTREAM_DIR) -> Optional[Dict[str, Any]]:
    """{family: {fn_name: {body_hash: [ref, ...]}}} over the pinned upstream sources.
    None when the corpus has not been fetched (unknown, not "no differences")."""
    root = Path(root)
    if not root.is_dir():
        return None
    idx: Dict[str, Dict[str, Dict[str, List[str]]]] = defaultdict(lambda: defaultdict(lambda: defaultdict(list)))
    refs, n = [], 0
    for entry in sorted(p for p in root.iterdir() if p.is_dir()):
        pin = entry / ".pinned_commit"
        ref = f"{entry.name}@{pin.read_text().strip()[:10]}" if pin.exists() else entry.name
        refs.append(ref)
        for f in sorted(entry.rglob("*.sol")):
            rel = "/" + str(f.relative_to(entry)).lower()
            if "/test" in rel or "/mocks/" in rel:
                continue
            try:
                cs = contracts_in(f.read_text(errors="replace"))
            except Exception:  # noqa: BLE001
                continue
            for c in cs:
                fam = family_of(fn.name for fn in c.functions)
                if not fam:
                    continue
                n += 1
                for fn in c.functions:
                    if fn.body.strip():
                        lst = idx[fam][fn.name][body_hash(fn.body)]
                        tag = f"{ref}:{c.name}"
                        if tag not in lst:
                            lst.append(tag)
    return {"families": idx, "refs": refs, "contracts": n}


def diff_candidate(root: Path, index: Dict[str, Any], min_common: int = 3,
                   upstream: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
    out = []
    fams = index["families"]
    for f, c in _contracts(root):
        fam = family_of(fn.name for fn in c.functions)
        if not fam:
            continue
        changed, same, unknown = [], [], []
        up = (upstream or {}).get("families", {}).get(fam) if upstream else None
        up_info = {"refs": sorted({r.split(":")[0] for v in (up or {}).values() for rs in v.values() for r in rs}),
                   "matched": [], "added": []} if up else None
        for fn in c.functions:
            if not fn.body.strip():
                continue
            h = body_hash(fn.body)
            if up is not None:
                variants = up.get(fn.name)
                if variants is None:
                    up_info["added"].append(fn.name)
                    continue
                if h in variants:
                    up_info["matched"].append(fn.name)
                    same.append(fn.name)
                else:
                    changed.append({"function": fn.name, "line": fn.line, "basis": "upstream",
                                    "upstream_variants": len(variants),
                                    "closest_refs": sorted({r for rs in variants.values() for r in rs})[:4]})
                continue
            counts = fams.get(fam, {}).get(fn.name) or Counter()
            others = sum(counts.values()) - 1  # minus this contract
            if others + 1 < min_common:
                unknown.append(fn.name)
            elif counts.get(h, 0) <= 1:
                changed.append({"function": fn.name, "line": fn.line, "variants_in_corpus": len(counts),
                                "basis": "corpus"})
            else:
                same.append(fn.name)
        d = {"file": str(f.relative_to(root)), "contract": c.name, "family": fam,
             "changed": changed, "unchanged": len(same), "no_reference": len(unknown)}
        if up_info is not None:
            d["upstream"] = up_info
            d["unmodified_upstream"] = not changed and not up_info["added"] and bool(up_info["matched"])
        out.append(d)
    return out


SCHEMA = """CREATE TABLE IF NOT EXISTS fork_diffs(
  network TEXT NOT NULL, address TEXT NOT NULL, content_hash TEXT, family TEXT,
  changed_json TEXT NOT NULL, corpus_contracts INTEGER, computed_at REAL NOT NULL,
  PRIMARY KEY(network, address, content_hash));"""


def record(conn: sqlite3.Connection, network: str, address: str, content_hash: str,
           diffs: List[Dict[str, Any]], corpus: int) -> None:
    conn.execute(SCHEMA)
    fam = ",".join(sorted({d["family"] for d in diffs})) or None
    conn.execute("INSERT OR REPLACE INTO fork_diffs VALUES(?,?,?,?,?,?,?)",
                 (network, address.lower(), content_hash, fam, json.dumps(diffs), corpus, time.time()))
    conn.commit()


def changed_count(conn: sqlite3.Connection, network: str, address: str) -> Optional[int]:
    try:
        r = conn.execute("SELECT changed_json FROM fork_diffs WHERE network=? AND address=? "
                         "ORDER BY computed_at DESC LIMIT 1", (network, address.lower())).fetchone()
    except sqlite3.Error:
        return None
    if not r:
        return None
    return sum(len(d.get("changed") or []) for d in json.loads(r[0]))
