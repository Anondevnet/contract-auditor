"""Audit target identity: chain handling and address validation.

Deliberate honesty about a real limitation: EIP-55 mixed-case checksum
verification requires keccak-256, which is **not** in the Python standard
library and is not installed here (constraints forbid adding dependencies).
Rather than fake a checksum check with an unrelated hash, this module accepts
a well-formed 20-byte hex address and reports the checksum state honestly:

* all-lowercase or all-uppercase -> casing is not a checksum encoding
* mixed-case                  -> looks EIP-55 encoded but is UNVERIFIED here

That distinction is exactly the FACT/UNKNOWN discipline the system is built
on, so it is surfaced rather than papered over.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

__all__ = [
    "DEFAULT_CHAIN",
    "KNOWN_CHAINS",
    "ChecksumStatus",
    "AddressValidation",
    "validate_address",
    "normalize_chain",
]

DEFAULT_CHAIN = "ethereum"

KNOWN_CHAINS: frozenset[str] = frozenset(
    {
        "ethereum",
        "arbitrum",
        "optimism",
        "base",
        "polygon",
        "bsc",
        "avalanche",
        "fantom",
        "gnosis",
        "linea",
        "scroll",
        "zksync",
        "sepolia",
        "holesky",
        "anvil",
        "hardhat",
    }
)

_HEX40 = re.compile(r"^(0x)?[0-9a-fA-F]{40}$")


class ChecksumStatus:
    """Checksum verification outcomes. Strings, not enums, to stay serialisable."""

    NOT_APPLICABLE = "NOT_APPLICABLE"
    """All one case: checksum encoding is not in use."""

    UNVERIFIED = "UNVERIFIED"
    """Mixed case, presumably EIP-55, but keccak-256 is unavailable to verify."""

    REJECTED = "REJECTED"
    """Mixed case but with non-hex characters, or otherwise malformed."""


@dataclass(frozen=True)
class AddressValidation:
    is_valid: bool
    normalized: str | None
    reason: str
    checksum_status: str
    length: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "is_valid": self.is_valid,
            "normalized": self.normalized,
            "reason": self.reason,
            "checksum_status": self.checksum_status,
            "length": self.length,
        }


def normalize_chain(chain: str | None) -> str:
    """Lowercase and trim a chain identifier; default when empty."""
    if chain is None:
        return DEFAULT_CHAIN
    cleaned = chain.strip().lower()
    return cleaned or DEFAULT_CHAIN


def validate_address(address: str | None) -> AddressValidation:
    """Validate an EVM address without any network access.

    Pure and offline: no RPC, no registry lookup, no checksum oracle.
    """
    if address is None:
        return AddressValidation(False, None, "address is None", ChecksumStatus.NOT_APPLICABLE, 0)

    raw = address.strip()
    if not raw:
        return AddressValidation(False, None, "address is empty", ChecksumStatus.NOT_APPLICABLE, 0)

    if any(ch.isspace() for ch in raw):
        return AddressValidation(
            False, None, "address contains whitespace", ChecksumStatus.REJECTED, len(raw)
        )

    if not _HEX40.match(raw):
        reason = _describe_mismatch(raw)
        return AddressValidation(False, None, reason, ChecksumStatus.REJECTED, len(raw))

    body = raw[2:] if raw.startswith("0x") or raw.startswith("0X") else raw
    normalized = "0x" + body.lower()

    has_lower = any(c.islower() for c in body)
    has_upper = any(c.isupper() for c in body)
    if has_lower and has_upper:
        return AddressValidation(
            True,
            normalized,
            "mixed-case address accepted; EIP-55 checksum NOT verified (keccak-256 unavailable)",
            ChecksumStatus.UNVERIFIED,
            40,
        )

    return AddressValidation(
        True,
        normalized,
        "20-byte hex address accepted; no checksum encoding present",
        ChecksumStatus.NOT_APPLICABLE,
        40,
    )


def _describe_mismatch(raw: str) -> str:
    body = raw[2:] if raw[:2].lower() == "0x" else raw
    if not body:
        return "address has no hexadecimal body"
    if len(body) != 40:
        return f"expected 40 hex characters, found {len(body)}"
    bad = sorted({ch for ch in body if ch not in "0123456789abcdefABCDEF"})
    return f"non-hexadecimal characters present: {''.join(bad)}"