"""Supplemental, read-only discovery and provenance sources for Ethereum.

This module treats market directories and historical audit data as discovery
signals. They never establish bytecode/source identity or a vulnerability.
Source files still enter the scan pipeline through the verified-source path.
"""
from __future__ import annotations

import csv
import io
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Iterable

DEXSCREENER = "https://api.dexscreener.com"
DEXTOOLS = "https://public-api.dextools.io"
ARKHAM = "https://api.arkm.com"
CODE4RENA_FINDINGS = "https://code4rena.com/community-resources/findings.csv"
GITHUB_API = "https://api.github.com"
_ADDR = re.compile(r"^0x[0-9a-fA-F]{40}$")


def _etherscan_configured() -> bool:
    if os.getenv("ETHERSCAN_API_KEY", "").strip():
        return True
    if sys.platform != "darwin":
        return False
    try:
        result = subprocess.run(["security", "find-generic-password", "-s",
                                 "etherscan-api-key", "-w"], capture_output=True,
                                text=True, timeout=3)
        return result.returncode == 0 and bool(result.stdout.strip())
    except Exception:  # noqa: BLE001
        return False


def provider_status() -> list[dict[str, Any]]:
    """Safe configuration summary. Secret values are never returned."""
    return [
        {"id": "ethereum", "name": "Ethereum blocks / events", "state": "ready",
         "detail": "Contract creations and token/pool events via the configured RPC."},
        {"id": "defillama", "name": "DeFiLlama", "state": "ready",
         "detail": "Protocol registry, TVL context, and official adapter addresses."},
        {"id": "etherscan", "name": "Etherscan", "state": "ready" if _etherscan_configured() else "needs_key",
         "detail": "Verified source, ABI, creation metadata, and explorer context."},
        {"id": "sourcify", "name": "Sourcify", "state": "ready",
         "detail": "Contract-level verified-source lookup; bulk imports should use Sourcify datasets."},
        {"id": "dexscreener", "name": "DEX Screener", "state": "ready",
         "detail": "Public Ethereum token/pair discovery and liquidity context."},
        {"id": "dextools", "name": "DEXTools", "state": "ready" if os.getenv("DEXTOOLS_API_KEY") else "needs_key",
         "detail": "Optional hot-pair feed; set DEXTOOLS_API_KEY to enable."},
        {"id": "arkham", "name": "Arkham", "state": "ready" if os.getenv("ARKHAM_API_KEY") else "needs_key",
         "detail": "Optional contract intelligence enrichment; set ARKHAM_API_KEY to enable."},
        {"id": "code4rena", "name": "Code4rena", "state": "ready",
         "detail": "Public historical findings index for audit-history context."},
        {"id": "github", "name": "Official GitHub repositories", "state": "ready" if os.getenv("GITHUB_TOKEN") else "public",
         "detail": "Repository provenance from protocol metadata; token is optional for higher API limits."},
    ]


def _get_json(url: str, *, headers: dict[str, str] | None = None, timeout: float = 15.0) -> Any:
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "https" or parsed.hostname not in {
        "api.dexscreener.com", "public-api.dextools.io", "api.arkm.com", "api.github.com"
    }:
        raise ValueError("refusing non-allow-listed provider URL")
    req = urllib.request.Request(url, headers={
        "User-Agent": "contract-auditor/discovery",
        "Accept": "application/json",
        **(headers or {}),
    }, method="GET")
    with urllib.request.urlopen(req, timeout=timeout) as response:  # noqa: S310
        raw = response.read(5_000_001)
    if len(raw) > 5_000_000:
        raise ValueError("provider response exceeds 5 MB")
    import json
    return json.loads(raw.decode("utf-8", errors="replace"))


def dexscreener_pairs(cache: Any, *, max_tokens: int = 16,
                      min_liquidity_usd: float = 25_000.0,
                      max_pairs: int = 40) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Find current Ethereum pool contracts from DEX Screener token profiles."""
    try:
        profiles = cache.get("dexscreener:profiles", f"{DEXSCREENER}/token-profiles/latest/v1",
                             ttl=300)
        if isinstance(profiles, dict):
            profiles = profiles.get("data") or profiles.get("profiles") or []
        tokens: list[str] = []
        for item in profiles if isinstance(profiles, list) else []:
            if not isinstance(item, dict) or str(item.get("chainId", "")).lower() != "ethereum":
                continue
            token = str(item.get("tokenAddress") or "").lower()
            if _ADDR.fullmatch(token) and token not in tokens:
                tokens.append(token)
            if len(tokens) >= max_tokens:
                break
        pairs_by_address: dict[str, dict[str, Any]] = {}
        for token in tokens:
            try:
                pairs = cache.get("dexscreener:pairs:" + token,
                                 f"{DEXSCREENER}/token-pairs/v1/ethereum/{token}", ttl=300)
            except Exception:
                continue
            if isinstance(pairs, dict):
                pairs = pairs.get("pairs") or pairs.get("data") or []
            for pair in pairs if isinstance(pairs, list) else []:
                if not isinstance(pair, dict) or str(pair.get("chainId", "")).lower() != "ethereum":
                    continue
                address = str(pair.get("pairAddress") or "").lower()
                liquidity = (pair.get("liquidity") or {}).get("usd")
                try:
                    liquidity = float(liquidity or 0)
                except (TypeError, ValueError):
                    liquidity = 0.0
                if not _ADDR.fullmatch(address) or liquidity < min_liquidity_usd:
                    continue
                old = pairs_by_address.get(address)
                if old and float(old.get("liquidity_usd") or 0) >= liquidity:
                    continue
                base, quote = pair.get("baseToken") or {}, pair.get("quoteToken") or {}
                pairs_by_address[address] = {
                    "address": address,
                    "protocol": "DEX Screener: " + str(pair.get("dexId") or "Ethereum pool"),
                    "slug": "dexscreener-" + str(pair.get("dexId") or "pool"),
                    "category": "Dexs", "category_group": "pools",
                    "liquidity_usd": liquidity,
                    "volume_24h_usd": float((pair.get("volume") or {}).get("h24") or 0),
                    "base_symbol": str(base.get("symbol") or ""),
                    "quote_symbol": str(quote.get("symbol") or ""),
                    "token_address": token,
                    "dex_id": str(pair.get("dexId") or ""),
                    "url": str(pair.get("url") or ""),
                }
        results = sorted(pairs_by_address.values(), key=lambda p: p["liquidity_usd"], reverse=True)[:max_pairs]
        return results, {"state": "ready", "profiles": len(tokens), "pairs": len(results)}
    except Exception as exc:  # noqa: BLE001
        return [], {"state": "error", "error": type(exc).__name__}


def dextools_pairs(*, max_pairs: int = 20, min_liquidity_usd: float = 25_000.0) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Optional DEXTools hot-pair feed. It is inactive until an API key exists."""
    key = os.getenv("DEXTOOLS_API_KEY", "").strip()
    if not key:
        return [], {"state": "needs_key", "pairs": 0}
    try:
        payload = _get_json(f"{DEXTOOLS}/v3/features/ether/hotpairs",
                            headers={"X-API-Key": key})
        rows = payload if isinstance(payload, list) else (payload.get("data") or payload.get("results") or [])
        found: dict[str, dict[str, Any]] = {}
        for item in rows if isinstance(rows, list) else []:
            if not isinstance(item, dict):
                continue
            pair = item.get("pool") or item.get("pair") or item
            if not isinstance(pair, dict):
                continue
            address = str(pair.get("poolAddress") or pair.get("pairAddress") or pair.get("address") or "").lower()
            if not _ADDR.fullmatch(address):
                continue
            try:
                liquidity = float(pair.get("liquidityUsd") or pair.get("liquidity") or 0)
            except (TypeError, ValueError):
                liquidity = 0.0
            if liquidity < min_liquidity_usd:
                continue
            found[address] = {"address": address, "protocol": "DEXTools: " + str(pair.get("name") or "Ethereum pool"),
                              "slug": "dextools-pool", "category": "Dexs", "category_group": "pools",
                              "liquidity_usd": liquidity, "dex_id": str(pair.get("exchange") or ""),
                              "url": str(pair.get("url") or "")}
        result = sorted(found.values(), key=lambda p: p["liquidity_usd"], reverse=True)[:max_pairs]
        return result, {"state": "ready", "pairs": len(result)}
    except (urllib.error.URLError, TimeoutError, ValueError, KeyError) as exc:
        return [], {"state": "error", "error": type(exc).__name__, "pairs": 0}


def arkham_contract(address: str) -> dict[str, Any] | None:
    """Return bounded Arkham contract-label context when the API is configured."""
    key = os.getenv("ARKHAM_API_KEY", "").strip()
    addr = str(address).lower()
    if not key or not _ADDR.fullmatch(addr):
        return None
    try:
        data = _get_json(f"{ARKHAM}/intelligence/contract/ethereum/{addr}",
                         headers={"API-Key": key})
        if not isinstance(data, dict):
            return None
        allowed = ("address", "name", "entity", "arkhamEntity", "tags", "labels", "confidence", "contractType")
        return {k: data[k] for k in allowed if k in data}
    except Exception:  # noqa: BLE001
        return None


def github_repository_urls(raw: Any) -> list[str]:
    """Keep only ordinary GitHub repository URLs from protocol registry metadata."""
    if isinstance(raw, str):
        values: Iterable[Any] = [raw]
    elif isinstance(raw, (list, tuple)):
        values = raw
    else:
        return []
    out: list[str] = []
    for value in values:
        text = str(value or "").strip()
        match = re.fullmatch(r"(?:https://)?github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+?)(?:\.git)?/?", text)
        if not match:
            continue
        url = f"https://github.com/{match.group(1)}/{match.group(2)}"
        if url not in out:
            out.append(url)
    return out[:8]


_C4_ROWS: list[dict[str, str]] | None = None
_C4_FETCHED_AT = 0.0


def code4rena_context(protocol: str, *, timeout: float = 15.0) -> dict[str, Any] | None:
    """Match public, released Code4rena findings by protocol name, best-effort."""
    global _C4_ROWS, _C4_FETCHED_AT
    try:
        if _C4_ROWS is None or time.time() - _C4_FETCHED_AT > 7 * 86400:
            req = urllib.request.Request(CODE4RENA_FINDINGS, headers={
                "User-Agent": "contract-auditor/discovery", "Accept": "text/csv"}, method="GET")
            parsed = urllib.parse.urlparse(CODE4RENA_FINDINGS)
            if parsed.scheme != "https" or parsed.hostname != "code4rena.com":
                return None
            with urllib.request.urlopen(req, timeout=timeout) as response:  # noqa: S310
                raw = response.read(5_000_001)
            if len(raw) > 5_000_000:
                return None
            _C4_ROWS = list(csv.DictReader(io.StringIO(raw.decode("utf-8-sig", errors="replace"))))
            _C4_FETCHED_AT = time.time()
        rows = _C4_ROWS or []
        target = re.sub(r"[^a-z0-9]", "", protocol.lower())
        if len(target) < 4:
            return None
        matches = []
        for row in rows:
            labels = [re.sub(r"[^a-z0-9]", "", str(value or "").lower())
                      for key, value in row.items()
                      if any(term in str(key).lower() for term in
                             ("contest", "protocol", "project", "sponsor"))]
            if any(label and (label == target or
                              (len(label) >= 4 and (label in target or target in label)))
                   for label in labels):
                matches.append(row)
                if len(matches) >= 100:
                    break
        return {"source": CODE4RENA_FINDINGS, "public_findings": len(matches)} if matches else None
    except Exception:  # noqa: BLE001
        return None

