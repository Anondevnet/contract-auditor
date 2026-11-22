"""Compare Etherscan-verified source metadata with on-chain runtime bytecode.

Honest outcomes only:
  * matched — explorer marks verified AND on-chain code is non-empty; codehash recorded
  * etherscan_verified_code_present — verified source on explorer, code on chain, no compile-compare
  * empty_onchain — address has no code
  * not_verified — explorer has no verified source
  * unknown — RPC/explorer unavailable

We do not claim solc-output identity unless a compile-compare is actually run.
"""
from __future__ import annotations

import hashlib
import os
import re
from typing import Any, Dict, Optional

_ADDR_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")



def _ensure_env() -> None:
    """Load ETHERSCAN_API_KEY / RPC from Keychain into os.environ if missing.

    Never logs or returns secret values. Mirrors scripts/_env.sh.
    """
    if not os.environ.get("ETHERSCAN_API_KEY"):
        try:
            import subprocess
            r = subprocess.run(
                ["security", "find-generic-password", "-s", "etherscan-api-key", "-w"],
                capture_output=True, text=True, timeout=5,
            )
            if r.returncode == 0 and r.stdout.strip():
                os.environ["ETHERSCAN_API_KEY"] = r.stdout.strip()
        except Exception:
            pass
    if not os.environ.get("ETH_RPC_URL") and not os.environ.get("AUDITOR_MONITOR_RPC_URL"):
        try:
            import subprocess
            r = subprocess.run(
                ["security", "find-generic-password", "-s", "eth-rpc-url", "-w"],
                capture_output=True, text=True, timeout=5,
            )
            if r.returncode == 0 and r.stdout.strip():
                os.environ["AUDITOR_MONITOR_RPC_URL"] = r.stdout.strip()
                os.environ["ETH_RPC_URL"] = r.stdout.strip()
            else:
                os.environ.setdefault("AUDITOR_MONITOR_RPC_URL", "https://ethereum.publicnode.com")
                os.environ.setdefault("ETH_RPC_URL", os.environ["AUDITOR_MONITOR_RPC_URL"])
        except Exception:
            os.environ.setdefault("AUDITOR_MONITOR_RPC_URL", "https://ethereum.publicnode.com")
            os.environ.setdefault("ETH_RPC_URL", os.environ.get("AUDITOR_MONITOR_RPC_URL", ""))
    elif os.environ.get("AUDITOR_MONITOR_RPC_URL") and not os.environ.get("ETH_RPC_URL"):
        os.environ["ETH_RPC_URL"] = os.environ["AUDITOR_MONITOR_RPC_URL"]
    elif os.environ.get("ETH_RPC_URL") and not os.environ.get("AUDITOR_MONITOR_RPC_URL"):
        os.environ["AUDITOR_MONITOR_RPC_URL"] = os.environ["ETH_RPC_URL"]


def normalize_address(raw: str) -> Optional[str]:
    """Return lowercase 0x + 40 hex, or None if malformed (rejects typos / wrong length).

    Bare addresses must be exactly 42 chars. Longer strings (paths / URIs) may
    embed a 40-hex address; we extract only when the whole strip is not itself
    a near-address of wrong length (e.g. 41 hex digits).
    """
    if not raw:
        return None
    s = str(raw).strip()
    if _ADDR_RE.match(s):
        return s.lower()
    # Wrong-length hex-looking token (0x + not-40 hex) — reject, do not clip
    if re.match(r"^0x[0-9a-fA-F]+$", s) and len(s) != 42:
        return None
    # Path / URI: extract embedded address
    m = re.search(r"0x[0-9a-fA-F]{40}", s)
    if not m:
        return None
    return m.group(0).lower()


def _keccak_hex(data: bytes) -> str:
    try:
        from eth_hash.auto import keccak  # type: ignore
        return "0x" + keccak(data).hex()
    except Exception:
        # fallback: sha256 labeled as such (not keccak) — prefer unknown over lying
        return "sha256:" + hashlib.sha256(data).hexdigest()


def onchain_runtime(address: str, rpc_url: Optional[str] = None) -> Dict[str, Any]:
    """Fetch runtime bytecode via cast (RPC from env). Never puts URL on argv logs."""
    _ensure_env()
    addr = normalize_address(address)
    out: Dict[str, Any] = {"address": addr, "code_hex": None, "code_bytes": 0,
                           "codehash": None, "error": None}
    if not addr:
        out["error"] = "invalid_address"
        return out
    rpc = rpc_url or os.environ.get("ETH_RPC_URL") or os.environ.get("AUDITOR_MONITOR_RPC_URL")
    if not rpc:
        out["error"] = "no_rpc"
        return out
    try:
        import subprocess
        # --rpc-url from env file via cast's default; pass via env only when needed
        env = os.environ.copy()
        env["ETH_RPC_URL"] = rpc
        proc = subprocess.run(
            ["cast", "code", addr, "--rpc-url", rpc],
            capture_output=True, text=True, timeout=60, env=env,
        )
        code = (proc.stdout or "").strip()
        if proc.returncode != 0 or not code:
            out["error"] = (proc.stderr or "cast_failed").strip()[:200]
            return out
        if code in ("0x", "0x0"):
            out["code_hex"] = "0x"
            out["code_bytes"] = 0
            return out
        raw = bytes.fromhex(code[2:] if code.startswith("0x") else code)
        out["code_hex"] = code
        out["code_bytes"] = len(raw)
        out["codehash"] = _keccak_hex(raw)
        return out
    except Exception as exc:  # noqa: BLE001
        out["error"] = f"{type(exc).__name__}: {exc}"
        return out


def etherscan_verified(address: str, api_key: Optional[str] = None) -> Dict[str, Any]:
    """Read-only Etherscan getsourcecode: ContractName + whether SourceCode present."""
    _ensure_env()
    addr = normalize_address(address)
    out: Dict[str, Any] = {"address": addr, "verified": False, "contract_name": None,
                           "compiler": None, "proxy": None, "error": None}
    if not addr:
        out["error"] = "invalid_address"
        return out
    key = api_key or os.environ.get("ETHERSCAN_API_KEY") or ""
    if not key:
        out["error"] = "no_etherscan_key"
        return out
    try:
        import json
        import urllib.request
        url = (f"https://api.etherscan.io/v2/api?chainid=1&module=contract"
               f"&action=getsourcecode&address={addr}&apikey={key}")
        data = json.load(urllib.request.urlopen(url, timeout=60))
        row = (data.get("result") or [None])[0] or {}
        src = row.get("SourceCode") or ""
        out["verified"] = bool(str(src).strip())
        out["contract_name"] = row.get("ContractName") or None
        out["compiler"] = row.get("CompilerVersion") or None
        out["proxy"] = row.get("Proxy")
        out["implementation"] = row.get("Implementation") or None
        return out
    except Exception as exc:  # noqa: BLE001
        out["error"] = f"{type(exc).__name__}: {exc}"
        return out


def verify_deployed_source(address: str) -> Dict[str, Any]:
    """Combine explorer verification + on-chain code presence into a classification hint."""
    addr = normalize_address(address)
    if not addr:
        return {"value": "unknown", "label": "Address malformed — cannot verify",
                "basis": "input failed 0x+40-hex normalization", "address": None,
                "codehash": None, "etherscan_verified": False}
    es = etherscan_verified(addr)
    oc = onchain_runtime(addr)
    basis_parts = []
    if es.get("verified"):
        basis_parts.append(
            f"Etherscan reports verified source ({es.get('contract_name') or 'unnamed'}, "
            f"{es.get('compiler') or 'compiler unknown'})"
        )
    elif es.get("error"):
        basis_parts.append(f"Etherscan check: {es['error']}")
    else:
        basis_parts.append("Etherscan has no verified source for this address")

    if oc.get("code_bytes"):
        basis_parts.append(
            f"on-chain runtime bytecode present ({oc['code_bytes']} bytes, "
            f"codehash {oc.get('codehash')})"
        )
    elif oc.get("error"):
        basis_parts.append(f"on-chain code fetch: {oc['error']}")
    else:
        basis_parts.append("on-chain runtime bytecode empty (EOA or destroyed)")

    if es.get("verified") and oc.get("code_bytes"):
        return {
            "value": "deployed_verified",
            "label": "Deployed target — Etherscan-verified source; on-chain runtime code present",
            "basis": "; ".join(basis_parts) + (
                ". Compile-output identity vs solc artifact was not compared in this pass."
            ),
            "address": addr,
            "codehash": oc.get("codehash"),
            "code_bytes": oc.get("code_bytes"),
            "etherscan_verified": True,
            "contract_name": es.get("contract_name"),
        }
    if not oc.get("code_bytes") and not oc.get("error"):
        return {
            "value": "empty_onchain",
            "label": "Address has no on-chain runtime code",
            "basis": "; ".join(basis_parts),
            "address": addr,
            "codehash": None,
            "etherscan_verified": bool(es.get("verified")),
        }
    if es.get("verified"):
        return {
            "value": "deployed_unverified",
            "label": "Deployed target — source NOT verified against on-chain bytecode",
            "basis": "; ".join(basis_parts),
            "address": addr,
            "codehash": oc.get("codehash"),
            "etherscan_verified": True,
        }
    return {
        "value": "deployed_unverified",
        "label": "Deployed target — source NOT verified against on-chain bytecode",
        "basis": "; ".join(basis_parts),
        "address": addr,
        "codehash": oc.get("codehash"),
        "etherscan_verified": False,
    }
