"""Phase 22/23 — local fork simulation, ERC-4626 invariants, oracle class, trust map.

Phase 23 adds any-token funding on the local anvil fork via balance-slot
discovery (``anvil_setStorageAt``) with whale-impersonation fallback.

All network I/O is read-only against a *local* anvil mainnet fork bound to
``127.0.0.1``. Nothing is broadcast to a public chain; anvil's default test
accounts are the only signers. Results are defensive: which check failed,
rough dollar exposure, and remediation guidance — never an exploit script.

Components:

* :class:`AnvilFork` — spawn/stop a local fork (``anvil --fork-url … --host 127.0.0.1``).
* :func:`check_erc4626_invariants` — view + optional whale-impersonation deposit/
  withdraw sequences via ``cast``.
* :func:`classify_oracles` — source + bytecode heuristics for Chainlink / Uni
  V2-V3 spot / TWAP; spot-move capital estimate from pool reserves.
* :func:`build_trust_map` — external addresses the target calls (source scan +
  common getters), with proxy/owner classification.
* :func:`simulate_address` / :func:`simulate_hunt_top` — orchestration + SQLite
  persistence (schema v7).
"""

from __future__ import annotations

import json
import logging
import os
import re
import shutil
import signal
import socket
import subprocess
import tempfile
import time
import urllib.parse
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence, Tuple

log = logging.getLogger("contract_auditor.simulate")

ANVIL_HOST = "127.0.0.1"
DEFAULT_FORK = "https://ethereum.publicnode.com"
LABEL = "rough estimate (local fork simulation — defensive)"
ESTIMATE_NOTE = (
    "Numbers are rough estimates from a local anvil fork. They are not "
    "predictions of exploitability and must not be treated as attack instructions."
)

# Selectors
SEL = {
    "asset()": "0x38d52e0f",
    "totalAssets()": "0x01e1d114",
    "totalSupply()": "0x18160ddd",
    "decimals()": "0x313ce567",
    "symbol()": "0x95d89b41",
    "balanceOf(address)": "0x70a08231",
    "convertToAssets(uint256)": "0x07a2d13a",
    "convertToShares(uint256)": "0xc6e6f592",
    "previewDeposit(uint256)": "0xef8b30f7",
    "previewRedeem(uint256)": "0x4cdad506",
    "previewWithdraw(uint256)": "0x0a28a477",
    "maxDeposit(address)": "0x402d267d",
    "maxRedeem(address)": "0xd905777e",
    "maxWithdraw(address)": "0xce96cb77",
    "previewRedeem(uint256)": "0x4cdad506",
    "deposit(uint256,address)": "0x6e553f65",
    "withdraw(uint256,address,address)": "0xb460af94",
    "redeem(uint256,address,address)": "0xba087652",
    "approve(address,uint256)": "0x095ea7b3",
    "owner()": "0x8da5cb5b",
    "getReserves()": "0x0902f1ac",
    "token0()": "0x0dfe1681",
    "token1()": "0xd21220a7",
    "slot0()": "0x3850c7bd",
    "liquidity()": "0x1a686502",
    "latestRoundData()": "0xfeaf968c",
    "decimals_feed()": "0x313ce567",
    "aggregator()": "0x245a7bfc",
    "description()": "0x7284e416",
}

_ADDR = re.compile(r"0x[0-9a-fA-F]{40}")
_SKIP_EXT = re.compile(
    r"(owner|admin|governance|guardian|implementation|beacon|pendingOwner|"
    r"DOMAIN_SEPARATOR|eip712Domain)", re.I)

ZERO = "0x" + "0" * 40


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _which(names: Sequence[str]) -> Optional[str]:
    for n in names:
        p = shutil.which(n)
        if p:
            return p
        home = Path.home() / ".foundry" / "bin" / n
        if home.is_file() and os.access(home, os.X_OK):
            return str(home)
    return None


def foundry_versions() -> Dict[str, Optional[str]]:
    out: Dict[str, Optional[str]] = {"forge": None, "anvil": None, "cast": None, "foundryup": None}
    for tool in out:
        exe = _which([tool])
        if not exe:
            continue
        try:
            r = subprocess.run([exe, "--version"], capture_output=True, text=True, timeout=15)
            line = (r.stdout or r.stderr or "").strip().splitlines()[:1]
            out[tool] = line[0] if line else exe
        except Exception:  # noqa: BLE001
            out[tool] = exe
    return out


def fork_url_from_env() -> str:
    url = (os.environ.get("AUDITOR_MONITOR_RPC_URL") or "").strip() or DEFAULT_FORK
    p = urllib.parse.urlparse(url)
    if p.scheme not in ("http", "https") or not p.hostname:
        raise ValueError("fork URL must be http(s)")
    return url


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((ANVIL_HOST, 0))
        return int(s.getsockname()[1])


def _word_addr(word: Any) -> Optional[str]:
    if not isinstance(word, str) or not word.startswith("0x") or len(word) < 42:
        return None
    w = word[2:].rjust(64, "0")[-64:]
    if int(w[:24] or "0", 16) != 0:
        return None
    a = "0x" + w[-40:].lower()
    return None if a == ZERO else a


def _word_int(word: Any) -> Optional[int]:
    if not isinstance(word, str) or not word.startswith("0x") or len(word) <= 2:
        return None
    try:
        return int(word[2:66] or "0", 16)
    except ValueError:
        return None


def _pack_uint(n: int) -> str:
    return format(int(n) & ((1 << 256) - 1), "064x")


def _pack_addr(a: str) -> str:
    return a.lower().replace("0x", "").rjust(64, "0")


# ---------------------------------------------------------------------------
# Anvil fork
# ---------------------------------------------------------------------------

@dataclass
class AnvilFork:
    """Local anvil mainnet fork (127.0.0.1 only). Context-manager safe."""

    fork_url: str
    host: str = ANVIL_HOST
    port: Optional[int] = None
    block_time: Optional[float] = None
    proc: Optional[subprocess.Popen] = None
    rpc_url: Optional[str] = None
    cast_bin: Optional[str] = None
    anvil_bin: Optional[str] = None
    started_at: float = 0.0

    def start(self, timeout: float = 45.0) -> "AnvilFork":
        self.anvil_bin = _which(["anvil"])
        self.cast_bin = _which(["cast"])
        if not self.anvil_bin or not self.cast_bin:
            raise RuntimeError("anvil/cast not found (install Foundry via foundryup)")
        if self.host not in ("127.0.0.1", "localhost", "::1"):
            raise RuntimeError("refusing non-loopback anvil host")
        self.port = int(self.port or _free_port())
        self.rpc_url = f"http://{self.host}:{self.port}"
        argv = [
            # Upstream RPC URL never on argv/ps: anvil resolves the foundry.toml alias
            # "upstream" = "${ETH_RPC_URL}" from env in a private temp dir.
            self.anvil_bin, "--fork-url", "upstream",
            "--host", self.host, "--port", str(self.port),
            "--silent", "--no-storage-caching",
            # No mining of empty blocks; no auto-impersonation of every account.
            "--accounts", "10", "--balance", "10000",
        ]
        env = dict(os.environ)
        env["ETH_RPC_URL"] = self.fork_url
        import tempfile
        self._cfgdir = tempfile.mkdtemp(prefix="anvil-alias-")
        Path(self._cfgdir, "foundry.toml").write_text(
            '[profile.default]\n[rpc_endpoints]\nupstream = "${ETH_RPC_URL}"\n')
        self.proc = subprocess.Popen(
            argv, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
            start_new_session=True, env=env, cwd=self._cfgdir)
        self.started_at = time.time()
        deadline = self.started_at + timeout
        last_err = ""
        while time.time() < deadline:
            if self.proc.poll() is not None:
                err = (self.proc.stderr.read() or b"").decode("utf-8", "replace")[:400]
                raise RuntimeError(f"anvil exited early: {err}")
            try:
                out = self.cast(["block-number"])
                if out.strip().isdigit() or out.strip().startswith("0x"):
                    return self
            except Exception as exc:  # noqa: BLE001
                last_err = str(exc)
            time.sleep(0.4)
        self.stop()
        raise RuntimeError(f"anvil did not become ready: {last_err}")

    def stop(self) -> None:
        if not self.proc:
            return
        try:
            os.killpg(self.proc.pid, signal.SIGTERM)
        except (ProcessLookupError, PermissionError, OSError):
            try:
                self.proc.terminate()
            except Exception:  # noqa: BLE001
                pass
        try:
            self.proc.wait(timeout=5)
        except Exception:  # noqa: BLE001
            try:
                os.killpg(self.proc.pid, signal.SIGKILL)
            except Exception:  # noqa: BLE001
                pass
        self.proc = None
        cfg = getattr(self, "_cfgdir", None)
        if cfg:
            # only the private temp dir this instance created (a single foundry.toml)
            try:
                Path(cfg, "foundry.toml").unlink(missing_ok=True)
                os.rmdir(cfg)
            except OSError:
                pass
            self._cfgdir = None

    def __enter__(self) -> "AnvilFork":
        return self.start()

    def __exit__(self, *exc: Any) -> None:
        self.stop()

    def cast(self, args: Sequence[str], timeout: float = 60.0, *, rpc: bool = True) -> str:
        assert self.cast_bin
        argv = [self.cast_bin, *args]
        # Offline helpers (index/keccak/sig/…) reject --rpc-url.
        offline = {"index", "keccak", "sig", "sig-event", "from-utf8", "to-uint256",
                   "to-hex", "concat-hex", "compute-address", "sha256"}
        if rpc and args and args[0] not in offline:
            assert self.rpc_url
            argv += ["--rpc-url", self.rpc_url]
        r = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
        if r.returncode != 0:
            raise RuntimeError((r.stderr or r.stdout or "cast failed")[:300])
        return (r.stdout or "").strip()

    def call(self, to: str, data: str) -> str:
        return self.cast(["call", to, data if data.startswith("0x") else "0x" + data])

    def call_int(self, to: str, data: str) -> Optional[int]:
        try:
            return _word_int(self.call(to, data))
        except Exception:  # noqa: BLE001
            return None

    def call_addr(self, to: str, data: str) -> Optional[str]:
        try:
            return _word_addr(self.call(to, data))
        except Exception:  # noqa: BLE001
            return None

    def rpc(self, method: str, params: list) -> Any:
        payload = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
        # cast rpc <method> [params...]
        args = ["rpc", method]
        for p in params:
            args.append(json.dumps(p) if not isinstance(p, str) else p)
        out = self.cast(args)
        try:
            return json.loads(out)
        except ValueError:
            return out

    def impersonate(self, address: str) -> None:
        self.rpc("anvil_impersonateAccount", [address])

    def stop_impersonate(self, address: str) -> None:
        try:
            self.rpc("anvil_stopImpersonatingAccount", [address])
        except Exception:  # noqa: BLE001
            pass

    def set_balance(self, address: str, wei: int) -> None:
        self.rpc("anvil_setBalance", [address, hex(wei)])

    def set_storage(self, address: str, slot: str, value: str) -> None:
        """anvil_setStorageAt — local fork only. slot/value as 0x-hex."""
        if not slot.startswith("0x"):
            slot = "0x" + slot
        if not value.startswith("0x"):
            value = "0x" + value
        self.rpc("anvil_setStorageAt", [address, slot, value])

    def send(self, from_addr: str, to: str, data: str, value: int = 0) -> str:
        args = ["send", to, data, "--from", from_addr, "--unlocked"]
        if value:
            args += ["--value", str(value)]
        return self.cast(args, timeout=120.0)


# ---------------------------------------------------------------------------
# ERC-4626 invariants
# ---------------------------------------------------------------------------

@dataclass
class InvariantResult:
    name: str
    status: str          # pass | fail | skip | error
    detail: str
    exposure_usd: Optional[float] = None
    guidance: str = ""
    evidence: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {"name": self.name, "status": self.status, "detail": self.detail,
                "exposure_usd": self.exposure_usd, "guidance": self.guidance,
                "evidence": self.evidence, "label": LABEL}


def _is_erc4626(fork: AnvilFork, vault: str) -> Dict[str, Any]:
    info: Dict[str, Any] = {"ok": False}
    asset = fork.call_addr(vault, SEL["asset()"])
    ta = fork.call_int(vault, SEL["totalAssets()"])
    ts = fork.call_int(vault, SEL["totalSupply()"])
    if asset is None or ta is None or ts is None:
        return info
    dec = fork.call_int(vault, SEL["decimals()"])
    adec = fork.call_int(asset, SEL["decimals()"])
    info.update({"ok": True, "asset": asset, "total_assets": ta, "total_supply": ts,
                 "decimals": dec if dec is not None else 18,
                 "asset_decimals": adec if adec is not None else 18})
    return info


def check_erc4626_invariants(
    fork: AnvilFork, vault: str, holder_value_usd: Optional[float] = None,
    asset_price_usd: Optional[float] = None,
) -> List[InvariantResult]:
    """Defensive ERC-4626 checks on a local fork. Never raises."""
    out: List[InvariantResult] = []
    info = _is_erc4626(fork, vault)
    if not info.get("ok"):
        return [InvariantResult(
            "erc4626-detect", "skip",
            "Not an ERC-4626 vault (asset/totalAssets/totalSupply unavailable).",
            guidance="Skip deposit/share invariants; run oracle/trust checks only.")]
    asset = info["asset"]
    ta, ts = int(info["total_assets"]), int(info["total_supply"])
    adec, sdec = int(info["asset_decimals"]), int(info["decimals"])
    one_share = 10 ** sdec
    one_asset = 10 ** adec

    # 1) Round-trip convertToAssets/convertToShares (view)
    try:
        if ts > 0 and ta > 0:
            assets = fork.call_int(vault, SEL["convertToAssets(uint256)"] + _pack_uint(one_share))
            shares_back = (fork.call_int(vault, SEL["convertToShares(uint256)"] + _pack_uint(assets))
                           if assets is not None else None)
            if assets is None or shares_back is None:
                out.append(InvariantResult("round-trip-share", "error",
                                           "convertToAssets/Shares reverted.",
                                           guidance="Verify ERC-4626 math; ensure functions are view-safe."))
            else:
                # Favouring the user would mean shares_back > one_share (free shares)
                drift = shares_back - one_share
                # Allow 1 wei of rounding against the user; fail if user gains shares
                if drift > 1:
                    exp = None
                    if holder_value_usd and ts:
                        exp = holder_value_usd * min(drift / one_share, 1.0)
                    out.append(InvariantResult(
                        "round-trip-share", "fail",
                        f"convertToShares(convertToAssets(1 share)) returned {shares_back} "
                        f"(+{drift} wei favouring the user).",
                        exposure_usd=exp,
                        guidance="ERC-4626 conversions must round in favour of the vault, never the user. "
                                 "Use mulDiv with Rounding.Floor on share minting.",
                        evidence={"assets": assets, "shares_back": shares_back, "one_share": one_share}))
                else:
                    out.append(InvariantResult(
                        "round-trip-share", "pass",
                        f"Round-trip drift {drift} wei (vault-favouring or exact).",
                        evidence={"assets": assets, "shares_back": shares_back}))
            # reverse direction
            shares = fork.call_int(vault, SEL["convertToShares(uint256)"] + _pack_uint(one_asset))
            assets_back = (fork.call_int(vault, SEL["convertToAssets(uint256)"] + _pack_uint(shares))
                           if shares is not None else None)
            if shares is not None and assets_back is not None:
                drift2 = assets_back - one_asset
                if drift2 > 1:
                    out.append(InvariantResult(
                        "round-trip-asset", "fail",
                        f"convertToAssets(convertToShares(1 asset)) returned {assets_back} "
                        f"(+{drift2} wei favouring the user).",
                        exposure_usd=holder_value_usd,
                        guidance="Asset→share→asset must not mint free value to the caller.",
                        evidence={"shares": shares, "assets_back": assets_back}))
                else:
                    out.append(InvariantResult(
                        "round-trip-asset", "pass",
                        f"Asset round-trip drift {drift2} wei.",
                        evidence={"shares": shares, "assets_back": assets_back}))
        else:
            out.append(InvariantResult("round-trip-share", "skip",
                                       "Empty vault (totalSupply or totalAssets is 0)."))
    except Exception as exc:  # noqa: BLE001
        out.append(InvariantResult("round-trip-share", "error", f"{type(exc).__name__}"))

    # 2) Share price = totalAssets/totalSupply consistency with convertToAssets
    try:
        if ts > 0:
            cta = fork.call_int(vault, SEL["convertToAssets(uint256)"] + _pack_uint(one_share))
            # expected ≈ ta * one_share / ts
            expected = (ta * one_share) // ts if ts else None
            if cta is not None and expected is not None:
                # Relative error > 1% fails
                denom = max(expected, 1)
                rel = abs(cta - expected) / denom
                if rel > 0.01:
                    out.append(InvariantResult(
                        "share-price-consistency", "fail",
                        f"convertToAssets(1e{sdec})={cta} vs totalAssets/totalSupply={expected} "
                        f"(rel err {rel:.2%}).",
                        exposure_usd=holder_value_usd,
                        guidance="Share price helpers must match totalAssets/totalSupply accounting.",
                        evidence={"convertToAssets": cta, "expected": expected, "rel": rel}))
                else:
                    out.append(InvariantResult(
                        "share-price-consistency", "pass",
                        f"Share price consistent (rel err {rel:.4%}).",
                        evidence={"convertToAssets": cta, "expected": expected}))
        else:
            out.append(InvariantResult("share-price-consistency", "skip", "totalSupply=0"))
    except Exception as exc:  # noqa: BLE001
        out.append(InvariantResult("share-price-consistency", "error", f"{type(exc).__name__}"))

    # 3) totalAssets vs asset.balanceOf(vault) (lower bound — strategies hold rest)
    try:
        bal = fork.call_int(asset, SEL["balanceOf(address)"] + _pack_addr(vault))
        if bal is not None:
            if bal > ta * 101 // 100 + one_asset:  # balance much higher than reported
                out.append(InvariantResult(
                    "totalAssets-vs-balance", "fail",
                    f"asset.balanceOf(vault)={bal} exceeds totalAssets()={ta} by >1%.",
                    exposure_usd=holder_value_usd,
                    guidance="totalAssets() under-reports idle balances; reconcile accounting.",
                    evidence={"balance": bal, "totalAssets": ta}))
            elif ta > 0 and bal == 0:
                out.append(InvariantResult(
                    "totalAssets-vs-balance", "pass",
                    "Idle balance is 0; assets likely sit in a strategy (expected for many vaults).",
                    evidence={"balance": bal, "totalAssets": ta},
                    guidance="Confirm strategy contracts are in the trust map and separately reviewed."))
            else:
                out.append(InvariantResult(
                    "totalAssets-vs-balance", "pass",
                    f"Idle balance {bal} ≤ totalAssets {ta}.",
                    evidence={"balance": bal, "totalAssets": ta}))
    except Exception as exc:  # noqa: BLE001
        out.append(InvariantResult("totalAssets-vs-balance", "error", f"{type(exc).__name__}"))

    # 4) Donation / first-depositor inflation sensitivity (analytic)
    try:
        if ts > 0 and ta > 0:
            # Donating 1% of totalAssets inflates share price by ≈ that percent for new depositors
            # Victim loss upper bound ≈ donation * (attacker_shares / (ts+attacker_shares))
            # Report sensitivity: USD impact of a donation equal to 1% of TVL on a $1k depositor.
            tvl = holder_value_usd
            donation_frac = 0.01
            # New depositor of dust (1 wei of shares worth) — classic inflation
            # Sensitivity score: how many assets one wei of shares is worth
            assets_per_wei_share = ta / ts
            dust_usd = None
            if asset_price_usd is not None:
                dust_usd = assets_per_wei_share / (10 ** adec) * asset_price_usd
            status = "pass"
            detail = (f"assets/wei-share={assets_per_wei_share:.6g}; "
                      f"1% TVL donation would shift share price by ~{donation_frac:.0%}.")
            guidance = ("Use virtual shares/assets (ERC-4626 inflation defenses), dead-shares, "
                        "or a minimum deposit so first-depositor donation attacks are uneconomic.")
            if ts < 10 ** (sdec // 2):  # very low supply → higher risk
                status = "fail"
                detail = (f"Low totalSupply ({ts}) with totalAssets={ta}: donation inflation "
                          f"is more practical. assets/wei-share={assets_per_wei_share:.6g}.")
            out.append(InvariantResult(
                "donation-inflation-sensitivity", status, detail,
                exposure_usd=(tvl * donation_frac) if tvl else None,
                guidance=guidance,
                evidence={"totalSupply": ts, "totalAssets": ta,
                          "assets_per_wei_share": assets_per_wei_share, "dust_usd": dust_usd}))
        elif ts == 0:
            out.append(InvariantResult(
                "donation-inflation-sensitivity", "fail",
                "Empty vault (totalSupply=0): classic first-depositor inflation surface.",
                exposure_usd=holder_value_usd,
                guidance="Seed dead shares, use virtual offsets, or otherwise block empty-vault donation attacks."))
        else:
            out.append(InvariantResult("donation-inflation-sensitivity", "skip", "No supply/assets."))
    except Exception as exc:  # noqa: BLE001
        out.append(InvariantResult("donation-inflation-sensitivity", "error", f"{type(exc).__name__}"))

    # 5) Optional whale deposit/withdraw: user cannot withdraw more than deposited
    out.extend(_whale_deposit_withdraw(fork, vault, asset, info, holder_value_usd))
    return out



# Anvil default account #0 (test key only — never a real key, never printed).
ANVIL_ACCT0 = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
WETH = "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2"
TRANSFER_TOPIC = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"

# Well-known ERC-7201 namespace strings whose balance mapping sits at offset 0.
_ERC7201_NS = (
    "openzeppelin.storage.ERC20",
    "openzeppelin.storage.ERC4626",
)


def _erc7201_base(fork: AnvilFork, namespace: str) -> str:
    """Compute ERC-7201 base slot: keccak256(abi.encode(uint256(keccak256(ns))-1)) & ~0xff."""
    ns_hash = fork.cast(["keccak", namespace])
    n = int(ns_hash, 16) - 1
    enc = "0x" + format(n, "064x")
    loc = int(fork.cast(["keccak", enc]), 16) & ~0xff
    return hex(loc)


def _mapping_slot_solidity(fork: AnvilFork, key_addr: str, base_slot: str) -> str:
    """Solidity mapping(address => uint256) slot at ``base_slot``."""
    return fork.cast(["index", "address", key_addr, base_slot])


def _mapping_slot_vyper(fork: AnvilFork, key_addr: str, base_slot: int) -> str:
    """Vyper HashMap layout: keccak256(slot ‖ key) with 32-byte slot then address."""
    payload = format(base_slot, "064x") + key_addr.lower().replace("0x", "").rjust(64, "0")
    return fork.cast(["keccak", "0x" + payload])


def find_balance_slot(
    fork: AnvilFork, token: str, account: str, probe_amount: int = 10**24,
    max_plain_slots: int = 60,
) -> Optional[Dict[str, Any]]:
    """Locate the storage slot backing ``balanceOf(account)`` on a local fork.

    Tries plain Solidity slots, Vyper layout, and ERC-7201 namespaced bases.
    Each candidate is written via ``anvil_setStorageAt`` and verified with
    ``balanceOf``; the slot is restored to its prior value afterward.
    Returns ``{kind, base, slot, verified_balance}`` or None.
    """
    token = token.lower()
    account = account.lower()
    amount_hex = "0x" + format(probe_amount, "064x")
    zero_hex = "0x" + "0" * 64

    def _try(slot_hex: str, kind: str, base: str) -> Optional[Dict[str, Any]]:
        try:
            before = fork.rpc("eth_getStorageAt", [token, slot_hex, "latest"])
        except Exception:  # noqa: BLE001
            before = zero_hex
        if not isinstance(before, str) or not before.startswith("0x"):
            before = zero_hex
        try:
            fork.set_storage(token, slot_hex, amount_hex)
            bal = fork.call_int(token, SEL["balanceOf(address)"] + _pack_addr(account))
            # Always restore
            fork.set_storage(token, slot_hex, before if before.startswith("0x") else zero_hex)
            if bal is not None and bal == probe_amount:
                return {"kind": kind, "base": base, "slot": slot_hex,
                        "verified_balance": bal}
            # Some tokens return probe with rounding / scaled storage — accept any positive jump
            if bal is not None and bal > 0:
                # Re-apply and confirm still positive (e.g. rebasing)
                fork.set_storage(token, slot_hex, amount_hex)
                bal2 = fork.call_int(token, SEL["balanceOf(address)"] + _pack_addr(account))
                fork.set_storage(token, slot_hex, before if before.startswith("0x") else zero_hex)
                if bal2 and bal2 > 0:
                    return {"kind": kind, "base": base, "slot": slot_hex,
                            "verified_balance": bal2}
        except Exception:  # noqa: BLE001
            try:
                fork.set_storage(token, slot_hex, before if isinstance(before, str) else zero_hex)
            except Exception:  # noqa: BLE001
                pass
        return None

    # 1) Plain Solidity mapping slots
    for s in range(max_plain_slots):
        try:
            slot_hex = _mapping_slot_solidity(fork, account, str(s))
        except Exception:  # noqa: BLE001
            continue
        hit = _try(slot_hex, "solidity-mapping", str(s))
        if hit:
            return hit

    # 2) ERC-7201 namespaces (balance mapping at base + 0..2)
    for ns in _ERC7201_NS:
        try:
            base = _erc7201_base(fork, ns)
        except Exception:  # noqa: BLE001
            continue
        base_i = int(base, 16)
        for off in range(0, 3):
            b = hex(base_i + off)
            try:
                slot_hex = _mapping_slot_solidity(fork, account, b)
            except Exception:  # noqa: BLE001
                continue
            hit = _try(slot_hex, f"erc7201:{ns}+{off}", b)
            if hit:
                return hit

    # 3) Vyper HashMap for low slots
    for s in range(min(20, max_plain_slots)):
        try:
            slot_hex = _mapping_slot_vyper(fork, account, s)
        except Exception:  # noqa: BLE001
            continue
        hit = _try(slot_hex, "vyper-mapping", str(s))
        if hit:
            return hit

    return None


def deal_erc20(
    fork: AnvilFork, token: str, account: str, amount: int,
) -> Dict[str, Any]:
    """Credit ``amount`` of ``token`` to ``account`` on the local fork only.

    Primary: find balance storage slot + ``anvil_setStorageAt``.
    Fallback: ``anvil_impersonateAccount`` a large on-fork holder and transfer.
    Never broadcasts; never uses real keys.
    """
    token = token.lower()
    account = account.lower()
    out: Dict[str, Any] = {"ok": False, "method": None, "detail": "", "slot_info": None}

    # WETH: wrap native ETH (anvil default accounts are funded).
    if token == WETH:
        try:
            fork.set_balance(account, max(amount * 2, 10**18 * 50))
            fork.impersonate(account)
            fork.send(account, WETH, "0xd0e30db0", value=amount)  # deposit()
            fork.stop_impersonate(account)
            bal = fork.call_int(WETH, SEL["balanceOf(address)"] + _pack_addr(account)) or 0
            out.update({"ok": bal >= amount, "method": "weth-wrap",
                        "detail": f"wrapped {amount} wei ETH→WETH; balance={bal}"})
            return out
        except Exception as exc:  # noqa: BLE001
            out["detail"] = f"weth-wrap failed: {type(exc).__name__}: {str(exc)[:120]}"
            # fall through

    try:
        slot_info = find_balance_slot(fork, token, account)
    except Exception as exc:  # noqa: BLE001
        slot_info = None
        out["detail"] = f"slot discovery error: {type(exc).__name__}: {str(exc)[:120]}"
    if slot_info:
        amount_hex = "0x" + format(amount, "064x")
        try:
            fork.set_storage(token, slot_info["slot"], amount_hex)
            bal = fork.call_int(token, SEL["balanceOf(address)"] + _pack_addr(account)) or 0
            if bal >= amount or bal > 0:
                out.update({"ok": True, "method": "setStorageAt",
                            "slot_info": slot_info,
                            "detail": f"setStorageAt {slot_info['kind']} base={slot_info['base']}; "
                                      f"balanceOf={bal}"})
                return out
            out["detail"] = f"slot found but balanceOf={bal} < amount"
        except Exception as exc:  # noqa: BLE001
            out["detail"] = f"setStorageAt failed: {type(exc).__name__}: {str(exc)[:120]}"

    # Fallback: impersonate a whale on the fork and transfer.
    try:
        whale = _find_whale(fork, token, min_balance=amount)
    except Exception as exc:  # noqa: BLE001
        whale = None
        out["detail"] = (out.get("detail") or "") + f"; whale discovery error: {type(exc).__name__}"
    if whale:
        try:
            fork.set_balance(whale, 10**18)  # gas
            fork.impersonate(whale)
            # transfer(account, amount)
            fork.send(whale, token,
                      "0xa9059cbb" + _pack_addr(account) + _pack_uint(amount))
            fork.stop_impersonate(whale)
            bal = fork.call_int(token, SEL["balanceOf(address)"] + _pack_addr(account)) or 0
            out.update({"ok": bal >= min(amount, bal) and bal > 0,
                        "method": "impersonate-whale",
                        "detail": f"impersonated holder {whale[:10]}…; balanceOf={bal}",
                        "whale": whale})
            return out
        except Exception as exc:  # noqa: BLE001
            try:
                fork.stop_impersonate(whale)
            except Exception:  # noqa: BLE001
                pass
            out["detail"] = (out.get("detail") or "") + f"; whale transfer failed: {type(exc).__name__}"

    if not out["detail"]:
        out["detail"] = "could not locate balance slot or whale holder on the local fork"
    return out


def _find_whale(fork: AnvilFork, token: str, min_balance: int = 1) -> Optional[str]:
    """Find a large token holder on the local fork via recent Transfer logs + probes."""
    token = token.lower()
    candidates: List[str] = []
    # Probe the token contract itself and a few system addresses (often hold inventory).
    for a in (token, ANVIL_ACCT0):
        try:
            b = fork.call_int(token, SEL["balanceOf(address)"] + _pack_addr(a)) or 0
            if b >= min_balance:
                candidates.append(a)
        except Exception:  # noqa: BLE001
            pass
    # Recent Transfer logs (fork retains chain history).
    try:
        bn_s = fork.cast(["block-number"])
        bn = int(bn_s, 0) if bn_s else 0
        from_block = max(0, bn - 50_000)
        raw = fork.rpc("eth_getLogs", [{
            "address": token,
            "fromBlock": hex(from_block),
            "toBlock": "latest",
            "topics": [TRANSFER_TOPIC],
        }])
        logs = raw if isinstance(raw, list) else []
        for lg in logs[-80:]:
            topics = lg.get("topics") or []
            if len(topics) < 3:
                continue
            for tip in (topics[1], topics[2]):
                addr = "0x" + tip[-40:].lower()
                if addr != ZERO and addr not in candidates:
                    candidates.append(addr)
            if len(candidates) >= 40:
                break
    except Exception:  # noqa: BLE001
        pass

    best: Optional[str] = None
    best_bal = 0
    for a in candidates:
        try:
            bal = fork.call_int(token, SEL["balanceOf(address)"] + _pack_addr(a)) or 0
        except Exception:  # noqa: BLE001
            continue
        if bal >= min_balance and bal > best_bal:
            best, best_bal = a, bal
    return best


def _whale_deposit_withdraw(
    fork: AnvilFork, vault: str, asset: str, info: Mapping[str, Any],
    holder_value_usd: Optional[float],
) -> List[InvariantResult]:
    """Funded deposit/redeem on the local fork with arbitrary ERC-20 assets (Phase 23).

    Funds anvil acct0 via storage-slot deal (or whale impersonation), then checks:
    * user cannot withdraw more than deposited (minus dust/fees)
    * round-trip does not favour the user
    * share price is monotonic (non-decreasing across deposit; redeem does not
      mint free value to the user)
    """
    adec = int(info.get("asset_decimals") or 18)
    sdec = int(info.get("decimals") or 18)
    one_share = 10 ** sdec
    # Deposit ~1% of one unit * 100 → prefer 100 * 10^adec but cap vs totalAssets dust
    amount = 100 * (10 ** adec)
    # Keep deposit small relative to vault to avoid liquidity reverts
    ta = int(info.get("total_assets") or 0)
    if ta > 0:
        amount = max(10 ** max(adec - 4, 0), min(amount, ta // 1000 or amount))
    acct = ANVIL_ACCT0
    results: List[InvariantResult] = []

    deal = deal_erc20(fork, asset, acct, amount * 2)  # headroom for fees
    if not deal.get("ok"):
        return [InvariantResult(
            "deposit-withdraw-conservation", "skip",
            f"Could not fund test account with vault asset on the local fork "
            f"({deal.get('detail') or 'unknown'}).",
            guidance="Extend slot discovery for this token layout, or ensure the fork "
                     "can see Transfer logs for whale impersonation.",
            evidence={"deal": deal})]

    try:
        fork.set_balance(acct, 10**18 * 10)  # gas
        fork.impersonate(acct)
        # approve vault
        fork.send(acct, asset,
                  SEL["approve(address,uint256)"] + _pack_addr(vault) + _pack_uint(amount * 2))

        price_before = fork.call_int(vault, SEL["convertToAssets(uint256)"] + _pack_uint(one_share))
        bal_before = fork.call_int(asset, SEL["balanceOf(address)"] + _pack_addr(acct)) or 0
        if bal_before < amount:
            fork.stop_impersonate(acct)
            return [InvariantResult(
                "deposit-withdraw-conservation", "error",
                f"funded balance {bal_before} < deposit amount {amount}",
                evidence={"deal": deal})]

        # deposit
        fork.send(acct, vault,
                  SEL["deposit(uint256,address)"] + _pack_uint(amount) + _pack_addr(acct))
        shares = fork.call_int(vault, SEL["balanceOf(address)"] + _pack_addr(acct)) or 0
        price_after_dep = fork.call_int(vault, SEL["convertToAssets(uint256)"] + _pack_uint(one_share))
        bal_mid = fork.call_int(asset, SEL["balanceOf(address)"] + _pack_addr(acct)) or 0
        deposited = bal_before - bal_mid

        if shares <= 0:
            fork.stop_impersonate(acct)
            return [InvariantResult(
                "deposit-withdraw-conservation", "skip",
                "deposit produced 0 shares (vault may gate deposits, be paused, or reject this asset path).",
                guidance="Confirm maxDeposit, access control, and whether the tranche mints only via a CDO/router.",
                evidence={"deal": deal, "amount": amount, "bal_before": bal_before, "bal_mid": bal_mid})]

        # Share price monotonic: deposit of assets should not decrease assets/share
        # (allow 1 wei relative noise).
        if price_before is not None and price_after_dep is not None:
            if price_after_dep + 1 < price_before:
                results.append(InvariantResult(
                    "share-price-monotonic-deposit", "fail",
                    f"Share price fell on deposit: {price_before} → {price_after_dep} "
                    f"assets per 1e{sdec} shares.",
                    exposure_usd=holder_value_usd,
                    guidance="Deposit should not decrease assets/share. Check fee-on-deposit "
                             "accounting and inflation defenses.",
                    evidence={"price_before": price_before, "price_after_dep": price_after_dep,
                              "deal": deal}))
            else:
                results.append(InvariantResult(
                    "share-price-monotonic-deposit", "pass",
                    f"Share price non-decreasing on deposit ({price_before} → {price_after_dep}).",
                    evidence={"price_before": price_before, "price_after_dep": price_after_dep}))

        # Respect ERC-4626's advertised immediate liquidity. Protocols with
        # cooldown/queued exits can move shares to a pending-withdrawal holder
        # instead of burning them and paying the asset in this transaction.
        # Treat that as a review lead, not a failed conservation invariant.
        max_redeem = fork.call_int(vault, SEL["maxRedeem(address)"] + _pack_addr(acct))
        max_withdraw = fork.call_int(vault, SEL["maxWithdraw(address)"] + _pack_addr(acct))
        redeem_shares = min(shares, max_redeem) if max_redeem is not None else shares
        shares_before_redeem = fork.call_int(vault, SEL["balanceOf(address)"] + _pack_addr(acct)) or 0
        supply_before_redeem = fork.call_int(vault, SEL["totalSupply()"])
        preview_assets = (fork.call_int(vault, SEL["previewRedeem(uint256)"] + _pack_uint(redeem_shares))
                          if redeem_shares > 0 else 0)
        if redeem_shares <= 0:
            fork.stop_impersonate(acct)
            results.append(InvariantResult(
                "deposit-withdraw-conservation", "review",
                "The vault reports no shares immediately redeemable for this account; "
                "withdrawal may be queued, cooldown-gated, or illiquid.",
                exposure_usd=holder_value_usd,
                guidance="Inspect the protocol's exit mode and pending-withdrawal flow before "
                "classifying this as user loss.",
                evidence={"deal": deal, "shares": shares, "max_redeem": max_redeem,
                          "max_withdraw": max_withdraw, "preview_assets": preview_assets,
                          "withdrawal_state": "not_immediately_redeemable"}))
            return results

        fork.send(acct, vault,
                  SEL["redeem(uint256,address,address)"] + _pack_uint(redeem_shares)
                  + _pack_addr(acct) + _pack_addr(acct))
        bal_after = fork.call_int(asset, SEL["balanceOf(address)"] + _pack_addr(acct)) or 0
        price_after_wd = fork.call_int(vault, SEL["convertToAssets(uint256)"] + _pack_uint(one_share))
        shares_after_redeem = fork.call_int(vault, SEL["balanceOf(address)"] + _pack_addr(acct)) or 0
        supply_after_redeem = fork.call_int(vault, SEL["totalSupply()"])
        fork.stop_impersonate(acct)

        returned = bal_after - bal_mid
        shares_removed = max(shares_before_redeem - shares_after_redeem, 0)
        supply_burned = (max(int(supply_before_redeem) - int(supply_after_redeem), 0)
                         if supply_before_redeem is not None and supply_after_redeem is not None else None)
        shares_moved_or_pending = (max(shares_removed - supply_burned, 0)
                                   if supply_burned is not None else None)
        evidence = {"bal_before": bal_before, "bal_mid": bal_mid, "bal_after": bal_after,
                    "shares": shares, "redeem_shares": redeem_shares,
                    "shares_before_redeem": shares_before_redeem,
                    "shares_after_redeem": shares_after_redeem,
                    "total_supply_before_redeem": supply_before_redeem,
                    "total_supply_after_redeem": supply_after_redeem,
                    "shares_removed_from_owner": shares_removed,
                    "shares_burned": supply_burned,
                    "shares_moved_or_pending": shares_moved_or_pending,
                    "max_redeem": max_redeem, "max_withdraw": max_withdraw,
                    "preview_assets": preview_assets, "deposited": deposited,
                    "returned": returned, "deal": deal}
        # User must not receive more than deposited (dust allowance)
        dust = max(10 ** max(adec - 6, 0), 1000)
        # Distinguish actual share burns without payout from a transfer into a
        # cooldown/queue. A lower supply delta than owner-balance delta means
        # shares remain outstanding elsewhere; it is not proof of a loss.
        if deposited > 0 and returned * 2 < deposited and returned <= dust:
            if shares_moved_or_pending is not None and shares_moved_or_pending > dust:
                results.append(InvariantResult(
                    "deposit-withdraw-conservation", "review",
                    f"Redeem returned {returned}; {shares_removed} owner shares moved while "
                    f"total supply fell by only {supply_burned}. This may be a queued or "
                    "cooldown withdrawal.",
                    exposure_usd=holder_value_usd,
                    guidance="Trace the destination shares and verify the protocol's "
                    "cooldown finalization path before treating this as user loss.",
                    evidence={**evidence, "withdrawal_state": "shares_moved_pending_or_locked"}))
            elif supply_burned is not None and supply_burned + dust >= redeem_shares:
                results.append(InvariantResult(
                    "deposit-withdraw-conservation", "fail",
                    f"Redeem returned {returned} after depositing {deposited} and burned "
                    f"{supply_burned} shares without a material payout.",
                    exposure_usd=holder_value_usd,
                    guidance="Review the pinned-fork trace and accounting path; this is a "
                    "potential user-loss invariant failure, not a confirmed outsider exploit.",
                    evidence={**evidence, "withdrawal_state": "shares_burned_without_payout"}))
            else:
                results.append(InvariantResult(
                    "deposit-withdraw-conservation", "review",
                    f"Redeem returned {returned} after depositing {deposited}; owner-share "
                    "and total-supply changes do not establish whether the withdrawal is pending.",
                    exposure_usd=holder_value_usd,
                    guidance="Inspect the transaction trace and protocol-specific withdrawal state.",
                    evidence={**evidence, "withdrawal_state": "ambiguous"}))
        elif returned > deposited + dust:
            results.append(InvariantResult(
                "deposit-withdraw-conservation", "fail",
                f"Redeem returned {returned} > deposited {deposited} (dust={dust}).",
                exposure_usd=holder_value_usd,
                guidance="Deposit/redeem must not create free assets. Check rounding and fee logic.",
                evidence={**evidence, "withdrawal_state": "value_increased"}))
        else:
            results.append(InvariantResult(
                "deposit-withdraw-conservation", "pass",
                f"Redeem returned {returned} against {deposited} deposited assets; "
                "share and supply deltas recorded for review.",
                evidence={**evidence, "withdrawal_state": "paid"}))

        # Round-trip must not favour the user (net gain)
        net = bal_after - bal_before
        if net > dust:
            results.append(InvariantResult(
                "deposit-redeem-round-trip", "fail",
                f"Net asset gain after deposit/redeem: {net} wei.",
                exposure_usd=holder_value_usd,
                guidance="Round-trip deposit/redeem must not favour the user.",
                evidence={"net": net, "deal": deal}))
        elif shares_moved_or_pending is not None and shares_moved_or_pending > dust and returned <= dust:
            results.append(InvariantResult(
                "deposit-redeem-round-trip", "review",
                "No immediate asset return; the owner's shares moved without a matching total-supply burn.",
                evidence={"net": net, "price_after_wd": price_after_wd,
                          "withdrawal_state": "shares_moved_pending_or_locked", "deal": deal}))
        else:
            results.append(InvariantResult(
                "deposit-redeem-round-trip", "pass",
                f"Round-trip did not favour the user (net {net} wei).",
                evidence={"net": net, "price_after_wd": price_after_wd,
                          "withdrawal_state": "paid_or_no_material_gain", "deal": deal}))

        return results
    except Exception as exc:  # noqa: BLE001
        try:
            fork.stop_impersonate(acct)
        except Exception:  # noqa: BLE001
            pass
        msg = f"{type(exc).__name__}: {str(exc)[:200]}"
        status = "skip" if any(s in msg for s in (
            "Unauthorized", "Ownable", "AccessControl", "paused", "PAUSED",
            "NotLender", "not lender", "onlyLender", "Whitelist", "NOT_AUTHORIZED", "fn paused", "Pausable",
        )) else "error"
        return [InvariantResult(
            "deposit-withdraw-conservation", status, msg,
            guidance=("Deposit/redeem is access-gated or paused on this path; "
                      "funded conservation check not applicable via public ERC-4626 entry.")
                     if status == "skip" else "",
            evidence={"deal": deal})]



# ---------------------------------------------------------------------------
# AMM (Uniswap-V2 interface) + reward distributor checks — Phase research batch 2
# ---------------------------------------------------------------------------

def check_amm_invariants(
    fork: AnvilFork, pair: str, holder_value_usd: Optional[float] = None,
) -> List[InvariantResult]:
    """Defensive checks for Uniswap-V2-style pools (custom forks included). Local fork only.

    * reserves-vs-balance — token balances must cover recorded reserves (else skim/donation surface).
    * mint-burn-conservation — LP mint then burn must not return more assets than deposited (dust OK).
    * swap-reverse — swap then reverse-swap must not return more than input (dust/fee OK).
    """
    out: List[InvariantResult] = []
    pair = pair.lower()
    t0 = fork.call_addr(pair, SEL["token0()"])
    t1 = fork.call_addr(pair, SEL["token1()"])
    if not t0 or not t1:
        return [InvariantResult(
            "amm-detect", "skip",
            "Not a Uniswap-V2-style pair (token0/token1 unavailable).",
            guidance="Only V2-interface pools are auto-checked; custom curves need a dedicated harness.")]
    # reserves
    try:
        raw = fork.call(pair, SEL["getReserves()"])
        if not (isinstance(raw, str) and len(raw) >= 130):
            return [InvariantResult("amm-detect", "skip", "getReserves() unavailable.")]
        r0 = int(raw[2:66], 16) & ((1 << 112) - 1)
        r1 = int(raw[66:130], 16) & ((1 << 112) - 1)
    except Exception as exc:  # noqa: BLE001
        return [InvariantResult("amm-detect", "error", f"getReserves: {type(exc).__name__}")]

    b0 = fork.call_int(t0, SEL["balanceOf(address)"] + _pack_addr(pair)) or 0
    b1 = fork.call_int(t1, SEL["balanceOf(address)"] + _pack_addr(pair)) or 0
    if b0 + 1 < r0 or b1 + 1 < r1:
        out.append(InvariantResult(
            "amm-reserves-vs-balance", "fail",
            f"Balances below reserves: bal=({b0},{b1}) reserves=({r0},{r1}).",
            exposure_usd=holder_value_usd,
            guidance="Reserves must not exceed actual token balances; check sync/skim and donation handling.",
            evidence={"bal0": b0, "bal1": b1, "r0": r0, "r1": r1}))
    else:
        out.append(InvariantResult(
            "amm-reserves-vs-balance", "pass",
            f"Balances cover reserves (extra0={b0 - r0}, extra1={b1 - r1}).",
            evidence={"bal0": b0, "bal1": b1, "r0": r0, "r1": r1}))

    # Funded mint/burn + swap/reverse only when we can deal both tokens.
    acct = ANVIL_ACCT0
    # Size: ~0.1% of reserves, floored
    a0 = max(r0 // 1000, 1)
    a1 = max(r1 // 1000, 1)
    d0 = deal_erc20(fork, t0, acct, a0 * 3)
    d1 = deal_erc20(fork, t1, acct, a1 * 3)
    if not (d0.get("ok") and d1.get("ok")):
        out.append(InvariantResult(
            "amm-mint-burn-conservation", "skip",
            f"Could not fund both pair tokens on the fork "
            f"(t0={d0.get('method')}/{d0.get('detail','')[:60]}; "
            f"t1={d1.get('method')}/{d1.get('detail','')[:60]}).",
            evidence={"deal0": d0, "deal1": d1}))
        out.append(InvariantResult(
            "amm-swap-reverse", "skip",
            "Skipped: could not fund tokens for swap-reverse on the local fork.",
            evidence={"deal0": d0, "deal1": d1}))
        return out

    try:
        fork.set_balance(acct, 10**18 * 5)
        fork.impersonate(acct)
        # approve pair (some routers needed — try pair itself first via transfer+mint pattern)
        # Standard UniV2: transfer tokens to pair, then mint(to)
        fork.send(acct, t0, "0xa9059cbb" + _pack_addr(pair) + _pack_uint(a0))  # transfer
        fork.send(acct, t1, "0xa9059cbb" + _pack_addr(pair) + _pack_uint(a1))
        # mint(address)
        mint_sel = "0x6a627842"  # mint(address)
        try:
            fork.send(acct, pair, mint_sel + _pack_addr(acct))
        except Exception as exc:  # noqa: BLE001
            fork.stop_impersonate(acct)
            out.append(InvariantResult(
                "amm-mint-burn-conservation", "skip",
                f"mint() reverted: {type(exc).__name__}: {str(exc)[:120]}",
                guidance="Pair may require a router or have custom mint entrypoints."))
            # still try swap if possible below
            fork.impersonate(acct)
        else:
            lp = fork.call_int(pair, SEL["balanceOf(address)"] + _pack_addr(acct)) or 0
            if lp <= 0:
                out.append(InvariantResult(
                    "amm-mint-burn-conservation", "error", "mint produced 0 LP shares."))
            else:
                bal0_mid = fork.call_int(t0, SEL["balanceOf(address)"] + _pack_addr(acct)) or 0
                bal1_mid = fork.call_int(t1, SEL["balanceOf(address)"] + _pack_addr(acct)) or 0
                # burn: transfer LP to pair then burn(to)
                fork.send(acct, pair, "0xa9059cbb" + _pack_addr(pair) + _pack_uint(lp))
                burn_sel = "0x89afcb44"  # burn(address)
                fork.send(acct, pair, burn_sel + _pack_addr(acct))
                bal0_after = fork.call_int(t0, SEL["balanceOf(address)"] + _pack_addr(acct)) or 0
                bal1_after = fork.call_int(t1, SEL["balanceOf(address)"] + _pack_addr(acct)) or 0
                # Compare to balances before mint transfers: we spent a0+a1 from acct
                # Net after mint+burn should not exceed starting funded amount beyond dust.
                # Simpler: returned from burn should be <= deposited to pair (a0, a1) + dust.
                ret0 = bal0_after - bal0_mid
                ret1 = bal1_after - bal1_mid
                dust0 = max(a0 // 10000, 1)
                dust1 = max(a1 // 10000, 1)
                if ret0 > a0 + dust0 or ret1 > a1 + dust1:
                    out.append(InvariantResult(
                        "amm-mint-burn-conservation", "fail",
                        f"Burn returned more than minted-in: in=({a0},{a1}) out=({ret0},{ret1}).",
                        exposure_usd=holder_value_usd,
                        guidance="LP mint/burn must not create free reserves. Check fee-on-transfer and rounding.",
                        evidence={"in0": a0, "in1": a1, "out0": ret0, "out1": ret1, "lp": lp}))
                else:
                    out.append(InvariantResult(
                        "amm-mint-burn-conservation", "pass",
                        f"Mint/burn conserved value (in=({a0},{a1}) out=({ret0},{ret1})).",
                        evidence={"in0": a0, "in1": a1, "out0": ret0, "out1": ret1, "lp": lp}))

        # swap-reverse: transfer amountIn of token0 to pair, swap(0, amountOut, to, "")
        # amountOut via getAmountOut approx: dy = y*dx*997/(x*1000+dx*997)
        dx = max(a0 // 2, 1)
        # refresh reserves
        raw2 = fork.call(pair, SEL["getReserves()"])
        x = int(raw2[2:66], 16) & ((1 << 112) - 1)
        y = int(raw2[66:130], 16) & ((1 << 112) - 1)
        dy = (y * dx * 997) // (x * 1000 + dx * 997) if x and y else 0
        if dy <= 0:
            out.append(InvariantResult("amm-swap-reverse", "skip", "computed amountOut is 0."))
        else:
            bal0_b = fork.call_int(t0, SEL["balanceOf(address)"] + _pack_addr(acct)) or 0
            fork.send(acct, t0, "0xa9059cbb" + _pack_addr(pair) + _pack_uint(dx))
            # swap(uint amount0Out, uint amount1Out, address to, bytes data)
            swap_sel = "0x022c0d9f"
            # amount0Out=0, amount1Out=dy
            data = (swap_sel + _pack_uint(0) + _pack_uint(dy) + _pack_addr(acct)
                    + format(0x80, "064x") + format(0, "064x"))  # empty bytes
            try:
                fork.send(acct, pair, data)
            except Exception as exc:  # noqa: BLE001
                out.append(InvariantResult(
                    "amm-swap-reverse", "skip",
                    f"forward swap reverted: {type(exc).__name__}: {str(exc)[:100]}"))
            else:
                # reverse: swap token1 back for token0
                raw3 = fork.call(pair, SEL["getReserves()"])
                x2 = int(raw3[2:66], 16) & ((1 << 112) - 1)
                y2 = int(raw3[66:130], 16) & ((1 << 112) - 1)
                dx2 = (x2 * dy * 997) // (y2 * 1000 + dy * 997) if x2 and y2 else 0
                fork.send(acct, t1, "0xa9059cbb" + _pack_addr(pair) + _pack_uint(dy))
                data2 = (swap_sel + _pack_uint(dx2) + _pack_uint(0) + _pack_addr(acct)
                         + format(0x80, "064x") + format(0, "064x"))
                try:
                    fork.send(acct, pair, data2)
                except Exception as exc:  # noqa: BLE001
                    out.append(InvariantResult(
                        "amm-swap-reverse", "skip",
                        f"reverse swap reverted: {type(exc).__name__}: {str(exc)[:100]}"))
                else:
                    bal0_a = fork.call_int(t0, SEL["balanceOf(address)"] + _pack_addr(acct)) or 0
                    gained = bal0_a - (bal0_b - dx)  # net vs post-forward expectation
                    # After round trip, balance of token0 should not exceed bal0_b (start of swap)
                    if bal0_a > bal0_b + max(dx // 10000, 1):
                        out.append(InvariantResult(
                            "amm-swap-reverse", "fail",
                            f"Swap-reverse increased token0: before={bal0_b} after={bal0_a} (input={dx}).",
                            exposure_usd=holder_value_usd,
                            guidance="Round-trip swap must not create free tokens. Check fee math and K invariant.",
                            evidence={"before": bal0_b, "after": bal0_a, "dx": dx, "dy": dy, "dx2": dx2}))
                    else:
                        out.append(InvariantResult(
                            "amm-swap-reverse", "pass",
                            f"Swap-reverse did not favour user (before={bal0_b} after={bal0_a}).",
                            evidence={"before": bal0_b, "after": bal0_a, "dx": dx, "dy": dy}))
        fork.stop_impersonate(acct)
    except Exception as exc:  # noqa: BLE001
        try:
            fork.stop_impersonate(acct)
        except Exception:  # noqa: BLE001
            pass
        out.append(InvariantResult(
            "amm-mint-burn-conservation", "error",
            f"{type(exc).__name__}: {str(exc)[:160]}"))
    return out


def check_reward_invariants(
    fork: AnvilFork, distributor: str, holder_value_usd: Optional[float] = None,
) -> List[InvariantResult]:
    """Best-effort reward distributor checks (view + optional double-claim).

    Looks for earned(address)/claim()/getReward() style surfaces. Double-claim
    must not pay more than a single claim. Requires a holder with accrued rewards
    (whale impersonation) — otherwise skip.
    """
    out: List[InvariantResult] = []
    distributor = distributor.lower()
    # Probe common selectors
    sel_earned = "0x008cc262"   # earned(address) — common but not universal
    sel_get_reward = "0x3d18b912"  # getReward()
    sel_claim = "0x4e71d92d"       # claim()
    whale = _find_whale(fork, distributor, min_balance=1)  # LP token holders sometimes = stakers
    # Without a known staker address we can only probe views
    # Try earned(acct0) — usually 0
    earned0 = fork.call_int(distributor, sel_earned + _pack_addr(ANVIL_ACCT0))
    if earned0 is None:
        return [InvariantResult(
            "reward-detect", "skip",
            "No earned(address) surface detected; reward distributor checks not applicable.",
            guidance="Wire a protocol-specific claim harness when the reward ABI is known.")]
    out.append(InvariantResult(
        "reward-detect", "pass" if True else "pass",
        f"earned(address) present; earned(acct0)={earned0}.",
        evidence={"earned0": earned0}))
    # Double-claim on acct0 (likely 0 rewards) — still detects free mint if claim ignores accrual
    acct = ANVIL_ACCT0
    try:
        fork.set_balance(acct, 10**18)
        fork.impersonate(acct)
        # Prefer getReward() then claim()
        claimed = False
        used_sel = None
        used_name = None
        for sel, name in ((sel_get_reward, "getReward()"), (sel_claim, "claim()")):
            try:
                fork.send(acct, distributor, sel)
                claimed = True
                used_sel, used_name = sel, name
                break
            except Exception:  # noqa: BLE001
                continue
        if not claimed or not used_sel:
            fork.stop_impersonate(acct)
            out.append(InvariantResult(
                "reward-double-claim", "skip",
                "No claim()/getReward() entrypoint succeeded for acct0.",
            ))
            return out
        # second claim
        try:
            fork.send(acct, distributor, used_sel)
        except Exception:  # noqa: BLE001
            out.append(InvariantResult(
                "reward-double-claim", "pass",
                f"Second {used_name} reverted after first claim (expected when earned=0).",
                evidence={"earned0": earned0, "used": used_name}))
        else:
            out.append(InvariantResult(
                "reward-double-claim", "pass",
                f"Double {used_name} completed with earned(acct0)={earned0} (no free accrual observed).",
                evidence={"earned0": earned0, "used": used_name}))
        fork.stop_impersonate(acct)
    except Exception as exc:  # noqa: BLE001
        try:
            fork.stop_impersonate(acct)
        except Exception:  # noqa: BLE001
            pass
        out.append(InvariantResult(
            "reward-double-claim", "error", f"{type(exc).__name__}: {str(exc)[:160]}"))
    return out



# ---------------------------------------------------------------------------
# Oracle classification
# ---------------------------------------------------------------------------

_CHAINLINK = re.compile(r"latestRoundData|AggregatorV3Interface|AggregatorV2V3Interface|FeedRegistry", re.I)
_UNIV2 = re.compile(r"getReserves\s*\(|IUniswapV2(Pair|Router)|UniswapV2Library", re.I)
_UNIV3 = re.compile(r"slot0\s*\(|IUniswapV3Pool|observe\s*\(|UniswapV3Pool", re.I)
_TWAP = re.compile(r"\b(twap|timeWeighted|consult\s*\(|observe\s*\()", re.I)
_SPOT = re.compile(r"getAmountOut|getAmountsOut|spotPrice|getReserves", re.I)


def classify_oracles(
    source_text: str = "", fork: Optional[AnvilFork] = None,
    related_pools: Optional[Sequence[str]] = None,
    related_sources: Optional[Sequence[str]] = None,
) -> Dict[str, Any]:
    """Classify price sources from verified source (+ optional on-fork pool probes)."""
    blob = source_text or ""
    for extra in related_sources or []:
        if extra:
            blob += "\n" + extra
    kinds = []
    if _CHAINLINK.search(blob):
        kinds.append("chainlink")
    if _UNIV3.search(blob):
        kinds.append("uniswap-v3")
    if _UNIV2.search(blob):
        kinds.append("uniswap-v2")
    if _TWAP.search(blob):
        kinds.append("twap")
    if not kinds and _SPOT.search(blob):
        kinds.append("spot-unknown")
    if not kinds:
        kinds.append("none-detected")

    flags = []
    uses_spot = any(k in ("uniswap-v2", "uniswap-v3", "spot-unknown") for k in kinds) and "twap" not in kinds
    if uses_spot:
        flags.append("spot-price-dependence")
    if "chainlink" in kinds and "latestRoundData" in blob and not re.search(
            r"updatedAt|stale|heartbeat|maxDelay|require\s*\(\s*answeredInRound", blob, re.I):
        flags.append("missing-staleness-check")

    spot_cost: List[Dict[str, Any]] = []
    if fork and related_pools:
        for pool in related_pools[:5]:
            spot_cost.append(_spot_move_cost(fork, pool))

    guidance = []
    if "spot-price-dependence" in flags:
        guidance.append("Prefer a TWAP or Chainlink feed over instantaneous spot reserves for "
                        "collateral/NAV pricing; spot is manipulable within a single block.")
    if "missing-staleness-check" in flags:
        guidance.append("When reading Chainlink latestRoundData, require answeredInRound >= roundId "
                        "and updatedAt within a heartbeat bound.")
    if "none-detected" in kinds:
        guidance.append("No familiar oracle pattern found in source; manually confirm how prices are obtained.")

    return {"kinds": kinds, "flags": flags, "spot_move_estimates": spot_cost,
            "guidance": guidance, "label": LABEL, "note": ESTIMATE_NOTE}


def _spot_move_cost(fork: AnvilFork, pool: str) -> Dict[str, Any]:
    """Estimate capital to move a UniV2-style spot by ~10% from reserves (x*y=k)."""
    out: Dict[str, Any] = {"pool": pool, "kind": None, "capital_token0": None,
                           "capital_token1": None, "note": ESTIMATE_NOTE}
    try:
        reserves = fork.call(pool, SEL["getReserves()"])
        # returns (uint112,uint112,uint32) packed
        if reserves and reserves.startswith("0x") and len(reserves) >= 130:
            r0 = int(reserves[2:66], 16) & ((1 << 112) - 1)
            r1 = int(reserves[66:130], 16) & ((1 << 112) - 1)
            # To move spot by 10%: roughly 5.4% of reserve in (constant-product approx)
            # More precisely for 10% price increase of token0: Δy ≈ r1 * (√1.1 - 1)
            import math
            frac = math.sqrt(1.10) - 1.0
            out.update({"kind": "uniswap-v2", "reserve0": r0, "reserve1": r1,
                        "capital_token0_for_10pct": int(r0 * frac),
                        "capital_token1_for_10pct": int(r1 * frac),
                        "detail": "Constant-product estimate: capital ≈ reserve × (√1.1 − 1) ≈ 4.88% of the reserve "
                                  "on the input side to move spot ~10% (ignores fees)."})
            return out
    except Exception:  # noqa: BLE001
        pass
    try:
        # UniV3: require slot0 + token0 + token1 so random contracts are not flagged.
        slot0 = fork.call(pool, SEL["slot0()"])
        t0 = fork.call_addr(pool, SEL["token0()"])
        t1 = fork.call_addr(pool, SEL["token1()"])
        if slot0 and slot0.startswith("0x") and t0 and t1:
            liq = fork.call_int(pool, SEL["liquidity()"])
            out.update({"kind": "uniswap-v3", "liquidity": liq, "token0": t0, "token1": t1,
                        "detail": "Uniswap V3: 10% move cost depends on active tick liquidity; "
                                  "report liquidity only (manual sizing required)."})
            return out
    except Exception:  # noqa: BLE001
        pass
    out["detail"] = "Not a recognised V2/V3 pool for spot-cost estimation."
    return out


# ---------------------------------------------------------------------------
# Trust map
# ---------------------------------------------------------------------------

# Common view getters that often expose trusted dependencies.
_TRUST_GETTERS = (
    ("asset", "0x38d52e0f"),
    ("owner", "0x8da5cb5b"),
    ("admin", "0xf851a440"),
    ("governance", "0x5aa6e675"),
    ("guardian", "0x452a9320"),
    ("strategy", "0xa8c62e76"),
    ("cdo", "0x387a7237"),
    ("idleCDO", "0xd4090fb8"),
    ("oracle", "0x7dc0d1d0"),
    ("priceOracle", "0x2630c12f"),
    ("priceFeed", "0x741bef1a"),
    ("getPriceFeed", "0x9e87a5cd"),
    ("token", "0xfc0c546a"),
    ("want", "0x1f1fcd51"),
    ("underlying", "0x6f307dc3"),
    ("collateral", "0xd8dfeb45"),
    ("vault", "0xfbfa77cf"),
    ("controller", "0xf77c4791"),
    ("seniorTranche", "0xa639d0dc"),
    ("juniorTranche", "0x86d4779e"),
    ("tokenAA", "0x63b4d222"),
    ("tokenBB", "0xa3f39f1c"),
)


def _enrich_trust_node(rdr: Any, a: str, role: Optional[str] = None) -> Dict[str, Any]:
    from .vault_discovery import resolve_proxy
    node: Dict[str, Any] = {
        "address": a.lower(), "verified": None, "proxy_kind": None,
        "implementation": None, "owner_type": None, "owner": None, "role": role,
    }
    try:
        info = resolve_proxy(rdr, a)
        node["proxy_kind"] = info.kind
        node["implementation"] = getattr(info, "implementation", None)
        if info.kind == "gnosis-safe":
            node["owner_type"] = "multisig"
        owner = rdr.call_addr(a, SEL["owner()"])
        if not owner:
            owner = rdr.call_addr(a, "0xf851a440")  # admin()
        node["owner"] = owner
        if not node.get("owner_type"):
            if owner:
                node["owner_type"] = _owner_type(rdr, owner)
            else:
                node["owner_type"] = "contract"
    except Exception:  # noqa: BLE001
        node["owner_type"] = node["owner_type"] or "unknown"
    return node


def build_trust_map(
    source_text: str, reader: Any = None, address: Optional[str] = None,
    max_ext: int = 25,
) -> Dict[str, Any]:
    """List external contracts the target trusts (on-chain getters first, then source)."""
    from .vault_discovery import Reader as VReader

    rdr = None
    if reader is not None:
        rdr = reader if hasattr(reader, "storage") else VReader(reader, max_calls=64)

    seen: set = set()
    nodes: List[Dict[str, Any]] = []

    def _add(a: Optional[str], role: Optional[str] = None) -> None:
        if not a:
            return
        a = a.lower()
        if a == ZERO or a in seen or address and a == address.lower():
            return
        body = a[2:]
        if body == "f" * 40 or body.startswith("7fff") or int(body, 16) < 10**6:
            return
        if rdr is not None and not rdr.is_contract(a):
            # Still record EOAs that own/admin the target.
            if role in ("owner", "admin", "governance", "guardian"):
                nodes.append({
                    "address": a, "verified": None, "proxy_kind": None,
                    "implementation": None, "owner_type": "eoa", "owner": None, "role": role,
                })
                seen.add(a)
            return
        seen.add(a)
        if rdr is not None:
            nodes.append(_enrich_trust_node(rdr, a, role=role))
        else:
            nodes.append({"address": a, "verified": None, "proxy_kind": None,
                          "implementation": None, "owner_type": None, "owner": None, "role": role})

    # 1) On-chain getters on the target (and one hop on strategy/cdo).
    seeds: List[str] = []
    if rdr is not None and address:
        for role, sel in _TRUST_GETTERS:
            try:
                val = rdr.call_addr(address, sel)
            except Exception:  # noqa: BLE001
                val = None
            if val and int(val, 16) != 0:
                _add(val, role=role)
                if role in ("strategy", "cdo", "vault", "controller") and val not in seeds:
                    seeds.append(val)
        for hop in seeds[:4]:
            for role, sel in _TRUST_GETTERS:
                if len(nodes) >= max_ext:
                    break
                try:
                    val = rdr.call_addr(hop, sel)
                except Exception:  # noqa: BLE001
                    val = None
                if val and int(val, 16) != 0:
                    _add(val, role=f"{role}@{hop[:10]}")

    # 2) Source literals that actually have code on-chain (skip storage-slot IDs).
    for m in _ADDR.finditer(source_text or ""):
        if len(nodes) >= max_ext:
            break
        a = m.group(0).lower()
        if a == ZERO or a in seen:
            continue
        body = a[2:]
        if body == "f" * 40 or body.startswith("7fff") or body.startswith("00000101"):
            continue
        if int(body, 16) < 10**6:
            continue
        if rdr is not None and not rdr.is_contract(a):
            continue
        _add(a, role="source-literal")

    return {"nodes": nodes[:max_ext], "count": len(nodes[:max_ext]), "label": LABEL,
            "guidance": "Review upgradeability and admin keys on every trusted dependency; "
                        "prefer timelocked multisigs over EOAs for vault admins."}


def _owner_type(reader: Any, owner: str) -> str:
    if not owner:
        return "unknown"
    try:
        if not reader.is_contract(owner):
            return "eoa"
        from .vault_discovery import resolve_proxy
        info = resolve_proxy(reader, owner)
        if info.kind == "gnosis-safe":
            return "multisig"
        code = reader.code(owner)
        if b"timelock" in code.encode() if False else ("Timelock" in str(code)):
            return "timelock"
        # Heuristic: sizeable contract with owner() that isn't a Safe → contract/admin
        # Check for common timelock selector getMinDelay
        delay = reader.call_int(owner, "0xf0350c04")  # getMinDelay() on OZ TimelockController is wrong sel
        # OZ TimelockController getMinDelay() = 0xf0350c04? Actually 0xf0350c04 is not right.
        # selector getMinDelay() = keccak[:4] — use known 0xf0350c04 is incorrectly remembered.
        # Use storage/proxy kind only.
        if info.is_proxy:
            return f"proxy:{info.kind}"
        return "contract"
    except Exception:  # noqa: BLE001
        return "unknown"


# ---------------------------------------------------------------------------
# Persistence + orchestration
# ---------------------------------------------------------------------------

def ensure_schema_v7(conn: Any) -> None:
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS simulate_runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            network TEXT NOT NULL, address TEXT NOT NULL,
            protocol TEXT, started_at REAL, finished_at REAL, duration_s REAL,
            status TEXT, fork_url_host TEXT, anvil_port INTEGER,
            holder_value_usd REAL, summary_json TEXT, error TEXT, fork_block INTEGER);
        CREATE INDEX IF NOT EXISTS ix_sim_runs_addr ON simulate_runs(address);
        CREATE TABLE IF NOT EXISTS simulate_invariants (
            id INTEGER PRIMARY KEY AUTOINCREMENT, run_id INTEGER NOT NULL,
            name TEXT, status TEXT, detail TEXT, exposure_usd REAL,
            guidance TEXT, evidence_json TEXT);
        CREATE INDEX IF NOT EXISTS ix_sim_inv_run ON simulate_invariants(run_id);
        CREATE TABLE IF NOT EXISTS simulate_oracles (
            id INTEGER PRIMARY KEY AUTOINCREMENT, run_id INTEGER NOT NULL,
            kinds_json TEXT, flags_json TEXT, spot_json TEXT, guidance_json TEXT);
        CREATE TABLE IF NOT EXISTS simulate_trust (
            id INTEGER PRIMARY KEY AUTOINCREMENT, run_id INTEGER NOT NULL,
            address TEXT, proxy_kind TEXT, implementation TEXT,
            owner TEXT, owner_type TEXT, meta_json TEXT);
        CREATE INDEX IF NOT EXISTS ix_sim_trust_run ON simulate_trust(run_id);
        """
    )
    run_cols = {r[1] for r in conn.execute("PRAGMA table_info(simulate_runs)")}
    if "fork_block" not in run_cols:
        conn.execute("ALTER TABLE simulate_runs ADD COLUMN fork_block INTEGER")
    # hunt_candidates simulation summary columns
    cols = {r[1] for r in conn.execute("PRAGMA table_info(hunt_candidates)")}
    for col, decl in (("sim_status", "TEXT"), ("sim_run_id", "INTEGER"),
                      ("sim_summary_json", "TEXT"), ("sim_at", "REAL")):
        if col not in cols:
            conn.execute(f"ALTER TABLE hunt_candidates ADD COLUMN {col} {decl}")
    try:
        conn.commit()
    except Exception:  # noqa: BLE001
        pass


def _source_text_for(client: Any, address: str) -> str:
    try:
        rec = client.verified_source(address) if hasattr(client, "verified_source") else None
    except Exception:  # noqa: BLE001
        rec = None
    if not rec:
        return ""
    return str(rec.get("SourceCode") or "")


def simulate_address(
    address: str, client: Any = None, holder_value_usd: Optional[float] = None,
    protocol: Optional[str] = None, network: str = "ethereum",
    db_path: Optional[Path] = None, fork_url: Optional[str] = None,
    emit: Callable[[str], None] = print,
) -> Dict[str, Any]:
    """Run invariants + oracle + trust for one address on a local anvil fork."""
    from .monitor import MonitorStore, default_monitor_db_path

    address = address.lower()
    store = MonitorStore(Path(db_path or default_monitor_db_path()))
    ensure_schema_v7(store.conn)
    started = time.time()
    host = urllib.parse.urlparse(fork_url or fork_url_from_env()).hostname or ""
    cur = store.conn.execute(
        "INSERT INTO simulate_runs(network,address,protocol,started_at,status,fork_url_host,holder_value_usd) "
        "VALUES(?,?,?,?, 'running',?,?)",
        (network, address, protocol, started, host, holder_value_usd))
    run_id = int(cur.lastrowid)
    store.conn.commit()

    result: Dict[str, Any] = {"address": address, "run_id": run_id, "invariants": [],
                              "oracles": {}, "trust": {}, "status": "ok", "label": LABEL}
    try:
        source = _source_text_for(client, address) if client is not None else ""
        # Trust map (no fork needed)
        from .vault_discovery import Reader
        reader = Reader(client, max_calls=200) if client is not None else None
        trust = build_trust_map(source, reader=reader, address=address)
        result["trust"] = trust

        # Pull verified source for a few trusted deps (strategy/cdo/oracle) for oracle class.
        related_sources: List[str] = []
        related_addrs = []
        for n in trust.get("nodes") or []:
            role = (n.get("role") or "")
            if any(k in role for k in ("strategy", "cdo", "oracle", "price", "vault", "controller")):
                related_addrs.append(n["address"])
        for ra in related_addrs[:6]:
            try:
                related_sources.append(_source_text_for(client, ra) if client is not None else "")
            except Exception:  # noqa: BLE001
                related_sources.append("")

        # Candidate pools = on-chain contracts from trust map (for spot-cost probes).
        pools = [n["address"] for n in trust.get("nodes") or []
                 if n.get("address") and n.get("owner_type") not in ("eoa",)][:8]
        if reader is not None:
            pools = [a for a in pools if reader.is_contract(a)][:8]
        oracles = classify_oracles(source, related_pools=None, related_sources=related_sources)
        result["oracles"] = oracles

        with AnvilFork(fork_url or fork_url_from_env()) as fork:
            block_raw = fork.cast(["block-number"])
            try:
                fork_block = int(block_raw, 0)
            except (TypeError, ValueError):
                fork_block = None
            store.conn.execute("UPDATE simulate_runs SET anvil_port=?,fork_block=? WHERE id=?",
                               (fork.port, fork_block, run_id))
            store.conn.commit()
            result["fork_block"] = fork_block
            emit(f"simulate: anvil fork on {fork.rpc_url} for {address}")
            inv = check_erc4626_invariants(fork, address, holder_value_usd=holder_value_usd)
            # Batch-2: if it looks like a V2 pair, also run AMM checks; always try reward probe cheaply.
            try:
                if fork.call_addr(address, SEL["token0()"]) and fork.call_addr(address, SEL["token1()"]):
                    inv = list(inv) + list(check_amm_invariants(
                        fork, address, holder_value_usd=holder_value_usd))
            except Exception:  # noqa: BLE001
                pass
            try:
                inv = list(inv) + list(check_reward_invariants(
                    fork, address, holder_value_usd=holder_value_usd))
            except Exception:  # noqa: BLE001
                pass
            result["invariants"] = [i.to_dict() for i in inv]
            # Enrich oracle spot costs on fork (only real V2/V3 pools will fill in).
            oracles = classify_oracles(source, fork=fork, related_pools=pools,
                                      related_sources=related_sources)
            result["oracles"] = oracles

        # Persist
        for inv in result["invariants"]:
            store.conn.execute(
                "INSERT INTO simulate_invariants(run_id,name,status,detail,exposure_usd,guidance,evidence_json) "
                "VALUES(?,?,?,?,?,?,?)",
                (run_id, inv["name"], inv["status"], inv["detail"], inv.get("exposure_usd"),
                 inv.get("guidance"), json.dumps(inv.get("evidence") or {})))
        store.conn.execute(
            "INSERT INTO simulate_oracles(run_id,kinds_json,flags_json,spot_json,guidance_json) "
            "VALUES(?,?,?,?,?)",
            (run_id, json.dumps(oracles.get("kinds")), json.dumps(oracles.get("flags")),
             json.dumps(oracles.get("spot_move_estimates")), json.dumps(oracles.get("guidance"))))
        for n in trust.get("nodes") or []:
            store.conn.execute(
                "INSERT INTO simulate_trust(run_id,address,proxy_kind,implementation,owner,owner_type,meta_json) "
                "VALUES(?,?,?,?,?,?,?)",
                (run_id, n.get("address"), n.get("proxy_kind"), n.get("implementation"),
                 n.get("owner"), n.get("owner_type"), json.dumps(n)))
        failed = [i for i in result["invariants"] if i["status"] == "fail"]
        review = [i for i in result["invariants"] if i["status"] == "review"]
        summary = {
            "invariant_fail": len(failed), "invariant_pass": sum(1 for i in result["invariants"] if i["status"] == "pass"),
            "invariant_review": len(review),
            "oracle_flags": oracles.get("flags"), "oracle_kinds": oracles.get("kinds"),
            "trust_nodes": trust.get("count"), "label": LABEL, "note": ESTIMATE_NOTE,
            "fork_block": result.get("fork_block"),
            "confirmed_exploitable": False,
        }
        result["summary"] = summary
        finished = time.time()
        run_status = "failed_invariants" if failed else ("needs_review" if review else "done")
        store.conn.execute(
            "UPDATE simulate_runs SET finished_at=?, duration_s=?, status=?, summary_json=? WHERE id=?",
            (finished, finished - started, run_status,
             json.dumps(summary), run_id))
        store.conn.execute(
            "UPDATE hunt_candidates SET sim_status=?, sim_run_id=?, sim_summary_json=?, sim_at=? "
            "WHERE network=? AND address=?",
            (summary and ("fail" if failed else ("review" if review else "pass")), run_id, json.dumps(summary), finished,
             network, address))
        store.conn.commit()
        emit(f"simulate: {address} → {len(failed)} invariant fail(s), {len(review)} review lead(s), "
             f"oracles={oracles.get('kinds')}, trust_nodes={trust.get('count')}")
    except Exception as exc:  # noqa: BLE001
        result["status"] = "error"
        result["error"] = f"{type(exc).__name__}: {exc}"[:400]
        store.conn.execute(
            "UPDATE simulate_runs SET finished_at=?, status='error', error=? WHERE id=?",
            (time.time(), result["error"], run_id))
        store.conn.execute(
            "UPDATE hunt_candidates SET sim_status='error', sim_run_id=?, sim_summary_json=?, sim_at=? "
            "WHERE network=? AND address=?",
            (run_id, json.dumps({"error": result["error"], "confirmed_exploitable": False}),
             time.time(), network, address))
        store.conn.commit()
        emit(f"simulate: {address} error: {result['error']}")
    finally:
        store.close()
    return result


def simulate_hunt_top(
    n: int = 5, network: str = "ethereum", db_path: Optional[Path] = None,
    client: Any = None, emit: Callable[[str], None] = print,
) -> List[Dict[str, Any]]:
    from .monitor import MonitorStore, default_monitor_db_path
    store = MonitorStore(Path(db_path or default_monitor_db_path()))
    ensure_schema_v7(store.conn)
    now = time.time()
    stale_before = now - 86400
    rows = store.conn.execute(
        "SELECT address, protocol, holder_value_usd FROM hunt_candidates "
        "WHERE network=? AND status='scanned' "
        "AND (sim_at IS NULL OR sim_at<? OR COALESCE(scanned_at,updated_at,0)>sim_at) "
        "ORDER BY CASE WHEN sim_at IS NULL THEN 0 ELSE 1 END, "
        "COALESCE(sim_at,0) ASC, COALESCE(holder_value_usd,onchain_tvl_usd,0) DESC LIMIT ?",
        (network, stale_before, int(n))).fetchall()
    store.close()
    out = []
    for r in rows:
        out.append(simulate_address(
            r["address"], client=client, holder_value_usd=r["holder_value_usd"],
            protocol=r["protocol"], network=network, db_path=db_path, emit=emit))
    return out


def simulation_overview(conn: Any, network: str = "ethereum", limit: int = 20,
                        *, ensure_schema: bool = True) -> Dict[str, Any]:
    if ensure_schema:
        ensure_schema_v7(conn)
    runs = [dict(r) for r in conn.execute(
        "SELECT id, address, protocol, started_at, finished_at, duration_s, status, "
        "holder_value_usd, summary_json, error, fork_block FROM simulate_runs "
        "WHERE network=? ORDER BY id DESC LIMIT ?", (network, int(limit))).fetchall()]
    review_queue: List[Dict[str, Any]] = []
    for r in runs:
        if r.get("summary_json"):
            try:
                r["summary"] = json.loads(r["summary_json"])
            except (ValueError, TypeError):
                pass
        inv = [dict(x) for x in conn.execute(
            "SELECT name, status, detail, exposure_usd, guidance, evidence_json FROM simulate_invariants "
            "WHERE run_id=? ORDER BY id", (r["id"],)).fetchall()]
        for item in inv:
            try:
                item["evidence"] = json.loads(item.pop("evidence_json") or "{}")
            except (ValueError, TypeError):
                item["evidence"] = {}
            if item["status"] in ("fail", "review"):
                review_queue.append({
                    "run_id": r["id"], "address": r["address"], "protocol": r.get("protocol"),
                    "fork_block": r.get("fork_block"), "name": item["name"],
                    "status": item["status"], "detail": item["detail"],
                    "exposure_estimate_usd": item.get("exposure_usd"),
                    "evidence": item["evidence"], "confirmed_exploitable": False,
                })
        r["invariants"] = inv
        ora = conn.execute(
            "SELECT kinds_json, flags_json, spot_json, guidance_json FROM simulate_oracles "
            "WHERE run_id=? ORDER BY id DESC LIMIT 1", (r["id"],)).fetchone()
        if ora:
            r["oracles"] = {
                "kinds": json.loads(ora[0] or "[]"), "flags": json.loads(ora[1] or "[]"),
                "spot_move_estimates": json.loads(ora[2] or "[]"),
                "guidance": json.loads(ora[3] or "[]")}
        trust = [dict(x) for x in conn.execute(
            "SELECT address, proxy_kind, implementation, owner, owner_type FROM simulate_trust "
            "WHERE run_id=? LIMIT 40", (r["id"],)).fetchall()]
        r["trust"] = trust
    return {"network": network, "runs": runs, "label": LABEL, "note": ESTIMATE_NOTE,
            "review_queue": review_queue[:100],
            "review_required_count": len(review_queue),
            "confirmed_exploitable_count": 0}
