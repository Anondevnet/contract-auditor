"""Bounded local Foundry invariant fuzzing for discovered verified vaults."""
from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any


def run_top_verified_vault(*, runs: int = 128, depth: int = 24,
                           timeout: int = 900) -> dict[str, Any]:
    """Fuzz the highest-value already-scanned ERC-4626-like hunt candidate.

    The generated test runs only against a pinned local Anvil fork. If there is
    no eligible vault, local forge-std, or RPC, the result is inconclusive.
    """
    from auditor.bytecode_verify import _ensure_env
    from auditor.invariant_fuzz import generate, run
    from auditor.monitor import ChainClient, MonitorStore, NETWORKS, default_monitor_db_path

    _ensure_env()
    rpc = (os.environ.get("ETH_RPC_URL") or os.environ.get("AUDITOR_MONITOR_RPC_URL") or
           "https://ethereum.publicnode.com")
    store = MonitorStore(default_monitor_db_path())
    try:
        row = store.conn.execute(
            "SELECT address, protocol, slug, holder_value_usd, onchain_tvl_usd, discovery_json "
            "FROM hunt_candidates WHERE network='ethereum' AND category_group='vaults' "
            "AND verified=1 AND status='scanned' "
            "ORDER BY COALESCE(holder_value_usd,onchain_tvl_usd,llama_tvl_usd,0) DESC LIMIT 1"
        ).fetchone()
        if not row:
            return {"status": "inconclusive", "reason": "no already-scanned verified vault candidate"}
        client = ChainClient("", NETWORKS["ethereum"], rpc_url=rpc, min_interval=0.1)
        try:
            fork_block = client.block_number()
        except Exception as exc:  # noqa: BLE001
            return {"status": "inconclusive", "address": row["address"],
                    "reason": f"could not get a current Ethereum block ({type(exc).__name__})"}
        name = f"hunt-vault-{str(row['address'])[2:10]}-{int(time.time())}"
        try:
            project = generate(name, mode="fork", vault=row["address"],
                               runs=int(runs), depth=int(depth))
        except Exception as exc:  # noqa: BLE001
            return {"status": "inconclusive", "address": row["address"],
                    "reason": f"fuzz harness unavailable ({type(exc).__name__})"}
        result = run(project, fork_block=fork_block, timeout=int(timeout))
        result.update({"address": row["address"], "protocol": row["protocol"],
                       "fork_block": fork_block, "runs": int(runs), "depth": int(depth),
                       "project": str(Path(project).relative_to(Path.cwd()))
                       if Path(project).is_relative_to(Path.cwd()) else str(project),
                       "at": time.time()})
        try:
            details = json.loads(row["discovery_json"] or "{}")
        except (ValueError, TypeError):
            details = {}
        details["invariant_fuzz"] = result
        store.conn.execute(
            "UPDATE hunt_candidates SET discovery_json=?, updated_at=? WHERE network='ethereum' AND address=?",
            (json.dumps(details, sort_keys=True), time.time(), row["address"]))
        store.conn.commit()
        return result
    finally:
        store.close()
