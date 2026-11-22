"""Foundry invariant-fuzz generator (hunting strategy: flash-loan + price-swing sequences).

``generate()`` writes a self-contained Foundry project into the gitignored
``reports/research/poc/<name>/``. Modes:

* ``local`` / ``fork``: ERC-4626 Handler (deposit / mint / withdraw / redeem,
  donation = price swing, single-call flash-loan sequence with mandatory
  repayment; no time warp, so honest yield is not counted as profit). Invariants
  ``invariant_attackerNoProfit`` and ``invariant_lenderRepaid``.
* ``async_fork``: ERC-7540 request/claim Handler (requestDeposit / cancel /
  claim deposit, requestRedeem / claim redeem, syncDeposit, donate to vault or
  safe, honest settlement via the real valuationManager + safe roles). Pending
  and claimable requests count toward the attacker's value. Invariant
  ``invariant_attackerNoProfit`` only (no lender).

``run()`` executes against a local deploy or a local anvil fork pinned to a
block. The upstream RPC URL is resolved via a foundry.toml ``upstream`` alias
from ``ETH_RPC_URL`` (never on argv, never logged). Nothing is broadcast.

Results are evidence labels only: a counterexample is "fuzz counterexample -
requires manual validation" until reproduced by a standalone PoC; this module
never sets confirmed_exploitable.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import socket
import subprocess
import time
from pathlib import Path
from typing import Any, Dict, Optional

ROOT = Path(__file__).resolve().parent.parent
TEMPLATES = Path(__file__).resolve().parent / "data" / "fuzz_templates"
POC_DIR = ROOT / "reports" / "research" / "poc"
_ADDR = re.compile(r"^0x[0-9a-fA-F]{40}$")


def _forge_std() -> Optional[Path]:
    """A local forge-std checkout (no download)."""
    for p in sorted(POC_DIR.glob("*/lib/forge-std")):
        if (p / "src" / "Test.sol").exists():
            return p
    return None


def generate(name: str, *, mode: str = "fork", vault: Optional[str] = None, budget: int = 10**24,
             victim: int = 10**24, dust: int = 10**6, offset: int = 0, leak_bps: int = 0,
             runs: int = 256, depth: int = 32, out_root: Path = POC_DIR) -> Path:
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", name):
        raise ValueError("bad project name")
    if mode in ("fork", "async_fork"):
        if not vault or not _ADDR.match(vault):
            raise ValueError(f"{mode} needs a vault address")
        iface = "I7540" if mode == "async_fork" else "IERC4626Like"
        setup = f"v = {iface}({_checksum_free(vault)});"
        tmpl = "AsyncVaultInvariant.t.sol.tmpl" if mode == "async_fork" else "VaultInvariant.t.sol.tmpl"
        out_sol = "AsyncVaultInvariant.t.sol" if mode == "async_fork" else "VaultInvariant.t.sol"
        match = "AsyncVaultInvariant" if mode == "async_fork" else "VaultInvariant"
    elif mode == "local":
        setup = (f"MockToken t = new MockToken(); v = IERC4626Like(address(new MockVault(t, {int(offset)}, {int(leak_bps)})));")
        tmpl, out_sol, match = "VaultInvariant.t.sol.tmpl", "VaultInvariant.t.sol", "VaultInvariant"
    else:
        raise ValueError("mode must be fork, async_fork or local")
    d = Path(out_root) / name
    (d / "test").mkdir(parents=True, exist_ok=True)
    (d / "lib").mkdir(exist_ok=True)
    fs = _forge_std()
    if fs is None:
        raise RuntimeError("no local forge-std found under reports/research/poc/*/lib (not downloading)")
    link = d / "lib" / "forge-std"
    if not link.exists():
        link.symlink_to(fs)
    t = (TEMPLATES / tmpl).read_text()
    t = (t.replace("{{SETUP}}", setup).replace("{{BUDGET}}", str(int(budget)))
          .replace("{{VICTIM}}", str(int(victim))).replace("{{DUST}}", str(int(dust))))
    if mode == "local":
        shutil.copy(TEMPLATES / "MockVaults.sol", d / "test" / "MockVaults.sol")
        t = t.replace('import "forge-std/Test.sol";', 'import "forge-std/Test.sol";\nimport "./MockVaults.sol";')
    (d / "test" / out_sol).write_text(t)
    (d / "foundry.toml").write_text(
        "[profile.default]\nsrc = 'test'\ntest = 'test'\nlibs = ['lib']\nsolc_version = '0.8.24'\noffline = true\n"
        # Alias resolved by anvil from env at runtime; the URL itself never appears in argv or files.
        "[rpc_endpoints]\nupstream = \"${ETH_RPC_URL}\"\n"
        f"[invariant]\nruns = {int(runs)}\ndepth = {int(depth)}\nfail_on_revert = false\n")
    (d / "GENERATED.json").write_text(json.dumps({"mode": mode, "vault": vault, "budget": budget, "victim": victim,
                                                  "match_contract": match, "generated_at": time.time()}, indent=1))
    return d


def _checksum_free(a: str) -> str:
    # Solidity requires checksummed literals; use address(uint160(...)) to avoid needing keccak here.
    return f"address(uint160({int(a, 16)}))"


def _free_port() -> int:
    s = socket.socket(); s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close(); return p


def _redact(text: str) -> str:
    return re.sub(r"https?://[^\s\"']+", "<redacted-url>", text or "")


def run(project: Path, *, fork_block: Optional[int] = None, timeout: int = 900) -> Dict[str, Any]:
    """Run forge invariants. Fork mode: spawn anvil on 127.0.0.1 pinned to ``fork_block``,
    upstream URL via env ETH_RPC_URL only; forge talks to the local anvil."""
    meta = json.loads((Path(project) / "GENERATED.json").read_text())
    anvil = None
    match = meta.get("match_contract") or ("AsyncVaultInvariant" if meta.get("mode") == "async_fork" else "VaultInvariant")
    args = ["forge", "test", "--match-contract", match, "-vv"]
    env = {k: v for k, v in os.environ.items() if k != "ETH_RPC_URL"}
    try:
        if meta["mode"] in ("fork", "async_fork"):
            if not fork_block:
                raise ValueError("fork mode requires a pinned fork_block")
            if not os.environ.get("ETH_RPC_URL"):
                return {"status": "unknown", "reason": "ETH_RPC_URL not set (load via scripts/_env.sh)"}
            port = _free_port()
            anvil = subprocess.Popen(["anvil", "--fork-url", "upstream", "--host", "127.0.0.1", "--port", str(port),
                                      "--fork-block-number", str(int(fork_block)), "--silent",
                                      # respect upstream rate limits
                                      "--compute-units-per-second", "200", "--retries", "8",
                                      "--fork-retry-backoff", "2000"],
                                     cwd=project, env=dict(os.environ), stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                                     start_new_session=True)
            deadline = time.time() + 60
            while time.time() < deadline:
                try:
                    socket.create_connection(("127.0.0.1", port), 1).close(); break
                except OSError:
                    if anvil.poll() is not None:
                        return {"status": "unknown", "reason": "anvil exited: " + _redact(anvil.stderr.read().decode()[-300:])}
                    time.sleep(0.5)
            args += ["--fork-url", f"http://127.0.0.1:{port}"]
        p = subprocess.run(args, cwd=project, env=env, capture_output=True, text=True, timeout=timeout)
        out = _redact(p.stdout + p.stderr)
    finally:
        if anvil is not None:
            anvil.terminate()
            try:
                anvil.wait(10)
            except subprocess.TimeoutExpired:
                anvil.kill()
    (Path(project) / "last_run.log").write_text(out)
    infra = re.search(r"failed to set up invariant|database error|HTTP error 429|Max retries exceeded|"
                      r"Could not make raw evm call", out)
    viol = sorted(set(m.group(2) for m in re.finditer(
        r"\[FAIL: (attacker profit|lender not repaid)[^\]]*\]\s*(invariant_\w+)", out)))
    res = {"status": "pass" if p.returncode == 0 else ("unknown" if infra and not viol else "fail"),
           "fork_block": fork_block,
           "violations": viol,
           "compiled": "Compiler run successful" in out or "No files changed" in out or p.returncode == 0,
           "label": None}
    if res["violations"]:
        res["label"] = "fuzz counterexample - requires manual validation (not dynamically reproduced as PoC)"
    elif p.returncode != 0:
        if res["status"] != "unknown":
            res["status"] = "error"
        res["reason"] = "infrastructure (RPC/fork) error - not a result" if infra else "forge error"
        res["tail"] = out[-1500:]
    return res
