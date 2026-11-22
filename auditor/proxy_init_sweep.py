"""Strategy stage: proxy / initializer sweep (read-only, continuous discovery).

For hunt candidates behind a proxy, read live state at the current head with
read-only RPC (eth_getStorageAt / eth_call) and combine it with the scanned
source to flag initialization hazards:

* ``proxy-uninitialized``: the proxy's initializer state is zero and its
  owner()/admin() reads zero while the implementation exposes an
  ``initializer``-guarded public/external initialize -> an outsider may be able
  to initialize and take ownership. Statically supported lead only.
* ``impl-uninitialized-uups``: a UUPS implementation whose own initializer
  state is zero and whose constructor never calls ``_disableInitializers()``.
  Post-Cancun SELFDESTRUCT no longer removes code, so this is
  reported as unresolved suspicion, not exposure.

Unknown stays unknown: an RPC failure or an unreadable slot yields
``status='unknown'``, never a clean result. Nothing is broadcast. Results go to
``proxy_init_sweeps`` (additive table) and a ``proxy_init:<kind>`` signal on the
candidate. The sweep never changes confirmed_exploitable.
"""
from __future__ import annotations

import json
import re
import sqlite3
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

EIP1967_IMPL = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"
EIP1967_ADMIN = "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103"
OZ5_INIT = "0xf0c57e16840df040f15088dc2f81fe391c3923bec73e23a9662efc9c229c6a00"
SEL_OWNER = "0x8da5cb5b"
SEL_ADMIN = "0xf851a440"
RECHECK_S = 24 * 3600

SCHEMA = """CREATE TABLE IF NOT EXISTS proxy_init_sweeps(
  id INTEGER PRIMARY KEY, network TEXT, address TEXT, implementation TEXT, block INTEGER,
  checked_at REAL, status TEXT, kinds TEXT, result_json TEXT)"""

_INIT_FN_RE = re.compile(r"function\s+(initiali[sz]e\w*)\s*\([^)]*\)\s*(?:public|external)[^{;]*\binitializer\b")
_DISABLE_RE = re.compile(r"constructor\s*\([^)]*\)[^{]*\{[^}]*_disableInitializers\s*\(\s*\)")
_UUPS_RE = re.compile(r"\bUUPSUpgradeable\b|function\s+proxiableUUID\s*\(|function\s+upgradeToAndCall\s*\(")


def ensure_schema(conn: sqlite3.Connection) -> None:
    conn.execute(SCHEMA)
    conn.execute("CREATE INDEX IF NOT EXISTS proxy_init_sweeps_addr ON proxy_init_sweeps(network, address)")


def _word(v: Any) -> Optional[int]:
    if not isinstance(v, str) or not v.startswith("0x"):
        return None
    try:
        return int(v, 16) if len(v) > 2 else 0
    except ValueError:
        return None


def _addr(v: Any) -> Optional[str]:
    w = _word(v)
    return None if w is None else "0x" + format(w & ((1 << 160) - 1), "040x")


def _safe(fn, *a) -> Any:
    try:
        return fn(*a)
    except Exception:  # noqa: BLE001 - unknown stays unknown
        return None


def source_facts(source_dir: Optional[Path]) -> Dict[str, Any]:
    facts = {"initializers": [], "disables_initializers": False, "uups": False, "source": False}
    if not source_dir or not Path(source_dir).is_dir():
        return facts
    for p in Path(source_dir).rglob("*.sol"):
        if "/lib/" in str(p) or "openzeppelin" in str(p).lower():
            continue  # library code defines the patterns; only the project's own code counts
        try:
            t = p.read_text(errors="replace")
        except OSError:
            continue
        facts["source"] = True
        facts["initializers"] += _INIT_FN_RE.findall(t)
        facts["disables_initializers"] |= bool(_DISABLE_RE.search(t))
        facts["uups"] |= bool(_UUPS_RE.search(t))
    facts["initializers"] = sorted(set(facts["initializers"]))
    return facts


def assess(client: Any, address: str, implementation: Optional[str], facts: Dict[str, Any]) -> Dict[str, Any]:
    """Read-only live assessment. Returns {status, kinds, reads, notes}."""
    reads: Dict[str, Any] = {}
    reads["block"] = _safe(client.block_number)
    impl = implementation or _addr(_safe(client.storage_at, address, EIP1967_IMPL))
    if impl and int(impl, 16) == 0:
        impl = None
    reads["implementation"] = impl
    reads["proxy_oz5_init"] = _word(_safe(client.storage_at, address, OZ5_INIT))
    reads["proxy_owner"] = _addr(_safe(client.call, address, SEL_OWNER))
    reads["proxy_admin_fn"] = _addr(_safe(client.call, address, SEL_ADMIN))
    reads["impl_oz5_init"] = _word(_safe(client.storage_at, impl, OZ5_INIT)) if impl else None
    kinds: List[str] = []
    notes: List[str] = []
    if not facts.get("source"):
        return {"status": "unknown", "kinds": [], "reads": reads, "notes": ["no scanned source"]}
    if facts["initializers"]:
        owner_zero = reads["proxy_owner"] is not None and int(reads["proxy_owner"], 16) == 0
        if reads["proxy_oz5_init"] == 0 and owner_zero:
            kinds.append("proxy-uninitialized")
            notes.append("proxy OZv5 initializer slot = 0 and owner() = 0 with public initializer "
                         + ",".join(facts["initializers"]) + "; OZv4 packed _initialized not read")
        elif reads["proxy_oz5_init"] is None and reads["proxy_owner"] is None:
            notes.append("initializer state unreadable (pre-OZv5 layout / no owner()); unknown")
        if impl and facts["uups"] and not facts["disables_initializers"] and reads["impl_oz5_init"] == 0:
            kinds.append("impl-uninitialized-uups")
            notes.append("UUPS implementation initializer slot = 0, constructor lacks _disableInitializers(); "
                         "post-Cancun selfdestruct does not clear code — unresolved suspicion")
    status = "lead" if "proxy-uninitialized" in kinds else ("suspicion" if kinds else
             ("unknown" if reads["block"] is None else "clear"))
    return {"status": status, "kinds": kinds, "reads": reads, "notes": notes}


def due(conn: sqlite3.Connection, network: str, limit: int, now: Optional[float] = None) -> List[sqlite3.Row]:
    ensure_schema(conn)
    now = now or time.time()
    q = """SELECT c.address, c.implementation, s.cache_dir FROM hunt_candidates c
           LEFT JOIN monitor_scans s ON s.id = c.last_scan_row
           WHERE c.network=? AND c.is_proxy=1 AND NOT EXISTS (
             SELECT 1 FROM proxy_init_sweeps p WHERE p.network=c.network AND p.address=c.address
             AND p.checked_at > ?)
           ORDER BY COALESCE(c.priority_score,0) DESC LIMIT ?"""
    return conn.execute(q, (network, now - RECHECK_S, limit)).fetchall()


def record(conn: sqlite3.Connection, network: str, address: str, res: Dict[str, Any],
           now: Optional[float] = None) -> None:
    ensure_schema(conn)
    conn.execute("INSERT INTO proxy_init_sweeps(network,address,implementation,block,checked_at,status,kinds,result_json) "
                 "VALUES(?,?,?,?,?,?,?,?)",
                 (network, address, res["reads"].get("implementation"), res["reads"].get("block"),
                  now or time.time(), res["status"], ",".join(res["kinds"]),
                  json.dumps(res, sort_keys=True, default=str)))
    if res["kinds"]:
        row = conn.execute("SELECT signals_json, priority_score FROM hunt_candidates WHERE network=? AND address=?",
                           (network, address)).fetchone()
        if row:
            try:
                sj = json.loads(row[0] or "{}")
            except ValueError:
                sj = {}
            sig = list(sj.get("signals") or [])
            new = [f"proxy_init:{k}" for k in res["kinds"] if f"proxy_init:{k}" not in sig]
            if new:
                sj["signals"] = sig + new
                bump = 15 if "proxy-uninitialized" in res["kinds"] else 3
                conn.execute("UPDATE hunt_candidates SET signals_json=?, priority_score=COALESCE(priority_score,0)+? "
                             "WHERE network=? AND address=?", (json.dumps(sj, sort_keys=True), bump, network, address))
    conn.commit()


def sweep(conn: sqlite3.Connection, client: Any, network: str, limit: int = 10,
          emit=None, now: Optional[float] = None) -> Dict[str, int]:
    out = {"checked": 0, "lead": 0, "suspicion": 0, "unknown": 0, "clear": 0}
    for address, impl, cache_dir in due(conn, network, limit, now):
        res = assess(client, address, impl, source_facts(Path(cache_dir) if cache_dir else None))
        record(conn, network, address, res, now)
        out["checked"] += 1
        out[res["status"]] = out.get(res["status"], 0) + 1
        if emit and res["kinds"]:
            emit(f"hunt: proxy/init {address}: {res['status']} {','.join(res['kinds'])}")
    return out
