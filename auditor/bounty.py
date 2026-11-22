"""Bounty program eligibility check — read-only, evidence-based, never speculative.

Rules encoded here:

* A check only runs when a project is actually identified (name and/or an
  official program URL). Otherwise the result is ``not_checked``.
* Eligibility is never asserted. Keyword matches on an official page are
  recorded as *signals* with quoted snippets and a timestamp; the verdict
  always stays ``not_verified_automatically`` with a reminder to verify scope
  and safe-harbor terms on the official page.
* Rewards, payout percentages, and dollar figures are never reported.
* Fetches are read-only HTTP GET with a hard timeout, a redirect handler that
  re-validates every hop, and blocking of private/loopback/link-local targets
  (SSRF guard).
"""

from __future__ import annotations

import ipaddress
import json
import re
import socket
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_REGISTRY_PATH = _PROJECT_ROOT / "config" / "bounty_registry.json"

DEFAULT_TIMEOUT = 8.0
_MAX_BYTES = 512 * 1024
_MAX_SNIPPETS = 6

_ELIGIBILITY_REMINDER = (
    "Bounty eligibility and rewards are never asserted automatically. Read the "
    "official program page yourself and verify scope, exclusions, safe-harbor / "
    "authorization terms, and duplicate rules before testing anything. Testing "
    "outside a program's authorized scope is not covered by this tool."
)

_CATEGORY_KEYWORDS = {
    "exchange": ["exchange", "cex", "custody"],
    "dex": ["dex", "swap", "amm", "liquidity pool"],
    "swap": ["swap", "routing"],
    "bridge": ["bridge", "cross-chain"],
    "lending": ["lending", "borrow", "money market"],
    "staking": ["staking", "yield", "rewards"],
    "wallet": ["wallet", "custody"],
    "oracle": ["oracle", "price feed"],
    "nft": ["nft", "marketplace"],
    "governance": ["governance", "dao", "proposal"],
    "other": [],
    "unknown": [],
}

_SIGNAL_KEYWORDS = ["bug bounty", "bounty", "safe harbor", "safe-harbor", "vulnerability disclosure"]


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def load_registry(registry_path: Path | str | None = None) -> List[Dict[str, str]]:
    """Load the local registry of official program URLs (may be empty)."""
    path = Path(registry_path) if registry_path else DEFAULT_REGISTRY_PATH
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    programs = raw.get("programs") if isinstance(raw, dict) else raw
    if not isinstance(programs, list):
        return []
    out = []
    for entry in programs:
        if isinstance(entry, dict) and entry.get("name") and entry.get("official_url"):
            out.append({"name": str(entry["name"]), "official_url": str(entry["official_url"])})
    return out


def _registry_lookup(project_name: str, registry_path: Path | str | None) -> Optional[str]:
    needle = project_name.strip().lower()
    if not needle:
        return None
    for entry in load_registry(registry_path):
        if entry["name"].strip().lower() == needle:
            return entry["official_url"]
    return None


def _safe_url(url: str) -> Tuple[bool, str]:
    """Validate that ``url`` is a fetchable http(s) URL to a public host."""
    try:
        parsed = urllib.parse.urlparse(url)
    except ValueError as exc:
        return False, f"unparseable URL: {exc}"
    if parsed.scheme not in ("http", "https"):
        return False, f"refusing scheme {parsed.scheme!r} (only http/https)"
    if not parsed.hostname:
        return False, "URL has no host"
    try:
        infos = socket.getaddrinfo(parsed.hostname, None)
    except (socket.gaierror, UnicodeError) as exc:
        return False, f"could not resolve host {parsed.hostname!r}: {exc}"
    if not infos:
        return False, f"could not resolve host {parsed.hostname!r}"
    for info in infos:
        addr = info[4][0]
        try:
            ip = ipaddress.ip_address(addr)
        except ValueError:
            return False, f"unparseable resolved address {addr!r}"
        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_reserved
            or ip.is_unspecified
        ):
            return False, f"host {parsed.hostname!r} resolves to a non-public address ({addr})"
    return True, "ok"


class _SafeRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Re-validate every redirect hop so a public URL cannot bounce inward."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        ok, why = _safe_url(newurl)
        if not ok:
            raise urllib.error.URLError(f"redirect blocked: {why}")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _fetch_read_only(url: str, timeout: float) -> Tuple[int, str, bytes]:
    """Read-only GET returning ``(status, final_url, body)``. Raises on error."""
    request = urllib.request.Request(
        url,
        method="GET",
        headers={"User-Agent": "contract-auditor-bounty-check/0.1 (+read-only)"},
    )
    opener = urllib.request.build_opener(_SafeRedirectHandler())
    with opener.open(request, timeout=timeout) as response:  # noqa: S310 - scheme/host validated
        status = getattr(response, "status", None) or response.getcode() or 0
        final_url = response.geturl() or url
        body = response.read(_MAX_BYTES)
    return int(status), str(final_url), body


def _not_checked(reason: str, project_name: Optional[str] = None) -> Dict[str, Any]:
    return {
        "status": "not_checked",
        "eligibility": "Not assessed",
        "eligibility_basis": reason,
        "project_name": project_name or None,
        "source_url": None,
        "checked_at": None,
        "http_status": None,
        "page_title": None,
        "signals": {},
        "evidence": [],
        "reminder": _ELIGIBILITY_REMINDER,
        "error": None,
    }


def _extract_title(html: str) -> Optional[str]:
    match = re.search(r"<title[^>]*>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
    if not match:
        return None
    return re.sub(r"\s+", " ", match.group(1)).strip()[:200] or None


def _snippet_around(text: str, keyword: str, radius: int = 90) -> Optional[Dict[str, str]]:
    match = re.search(re.escape(keyword), text, re.IGNORECASE)
    if not match:
        return None
    start = max(0, match.start() - radius)
    end = min(len(text), match.end() + radius)
    snippet = re.sub(r"\s+", " ", text[start:end]).strip()
    if start > 0:
        snippet = "…" + snippet
    if end < len(text):
        snippet = snippet + "…"
    return {"keyword": keyword, "snippet": snippet[:240]}


def check_eligibility(
    project_name: Optional[str] = None,
    asset: Optional[str] = None,
    category: Optional[str] = None,
    official_url: Optional[str] = None,
    registry_path: Path | str | None = None,
    timeout: float = DEFAULT_TIMEOUT,
) -> Dict[str, Any]:
    """Check an official bounty page (when one is known) and record evidence.

    Never claims eligibility. Returns a dict whose ``status`` is one of
    ``not_checked`` / ``blocked`` / ``fetch_failed`` / ``checked``.
    """
    project_name = (project_name or "").strip() or None
    asset = (asset or "").strip() or None
    category = (category or "").strip().lower() or "unknown"

    if not project_name and not official_url:
        return _not_checked(
            "No project identified for this scan — provide a project name or an "
            "official program URL before a check can run.",
        )

    url = (official_url or "").strip() or None
    if url is None and project_name:
        url = _registry_lookup(project_name, registry_path)
    if url is None:
        return _not_checked(
            "No official program URL is known for this project (nothing in the "
            "local registry, none supplied). Supply the official URL to run a check.",
            project_name,
        )

    ok, why = _safe_url(url)
    if not ok:
        return {
            "status": "blocked",
            "eligibility": "Not assessed",
            "eligibility_basis": f"URL rejected before fetching: {why}",
            "project_name": project_name,
            "source_url": url,
            "checked_at": _utcnow(),
            "http_status": None,
            "page_title": None,
            "signals": {},
            "evidence": [],
            "reminder": _ELIGIBILITY_REMINDER,
            "error": why,
        }

    checked_at = _utcnow()
    try:
        status, final_url, body = _fetch_read_only(url, timeout)
    except Exception as exc:  # noqa: BLE001 - report fetch failures honestly
        return {
            "status": "fetch_failed",
            "eligibility": "Not assessed",
            "eligibility_basis": "The official page could not be retrieved; nothing was verified.",
            "project_name": project_name,
            "source_url": url,
            "checked_at": checked_at,
            "http_status": None,
            "page_title": None,
            "signals": {},
            "evidence": [],
            "reminder": _ELIGIBILITY_REMINDER,
            "error": f"{type(exc).__name__}: {exc}",
        }

    text = body.decode("utf-8", errors="replace")
    lower = text.lower()

    keywords: List[str] = []
    if project_name:
        keywords.append(project_name)
    if asset:
        keywords.append(asset)
    keywords.extend(_SIGNAL_KEYWORDS)
    for kw in _CATEGORY_KEYWORDS.get(category, []):
        if kw not in keywords:
            keywords.append(kw)

    evidence: List[Dict[str, str]] = []
    for keyword in keywords:
        if len(evidence) >= _MAX_SNIPPETS:
            break
        hit = _snippet_around(text, keyword)
        if hit:
            evidence.append(hit)

    signals = {
        "mentions_bounty": bool(re.search(r"\bbounty\b", lower)),
        "mentions_safe_harbor": bool(re.search(r"safe[- ]harbor", lower)),
        "mentions_asset_address": bool(asset and asset.lower() in lower),
        "mentions_project_name": bool(project_name and project_name.lower() in lower),
        "category_keyword_hits": [
            kw for kw in _CATEGORY_KEYWORDS.get(category, []) if kw in lower
        ],
        "http_status": status,
    }

    return {
        "status": "checked",
        "eligibility": "not_verified_automatically",
        "eligibility_basis": (
            "Signals below were read from the official page at the recorded "
            "timestamp. Keyword presence is not proof of scope or eligibility; "
            "scope and safe-harbor terms must be verified on the page itself."
        ),
        "project_name": project_name,
        "asset": asset,
        "category": category,
        "source_url": final_url,
        "checked_at": checked_at,
        "http_status": status,
        "page_title": _extract_title(text),
        "signals": signals,
        "evidence": evidence,
        "reminder": _ELIGIBILITY_REMINDER,
        "error": None,
    }
