"""Command-line interface.

Phase 1 commands are deliberately small: they observe the local environment and
report it honestly. The ``ADDRESS --chain`` surface is not implemented yet, so
it is not offered; advertising a command that cannot work is worse than
documenting its absence.
"""

from __future__ import annotations

import argparse
import json
import logging
import platform
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional, Sequence

from . import AUDITOR_NAME, SCHEMA_VERSION, __version__
from .model import SEVERITY_ORDER, Severity
from .ollama import DEFAULT_ENDPOINT, OllamaStatus, probe_ollama
from .registry import discover_analyzers
from .report import (
    NOT_IMPLEMENTED,
    STATUS_DISCLAIMER,
    render_ollama_text,
    render_status_text,
    render_storage_text,
    render_toolchain_text,
)
from .settings import Settings, load_settings
from .storage import StorageReport, probe_storage
# Worker "already running" exit code — defined once in supervisor.py
# (stdlib-only module: no import cycle).
from .supervisor import EXIT_BUSY  # noqa: E402
from .target import validate_address
from .toolchain import ToolchainReport, detect_toolchain

__all__ = ["build_parser", "main"]

log = logging.getLogger("contract_auditor")

PROJECT_ROOT = Path(__file__).resolve().parent.parent

EXIT_OK = 0
EXIT_ERROR = 1

# Phase 13 — severity-based release gate (CI exit codes).
# Ordered most severe first, reusing the shared Severity definition so the
# gate can never drift from the rest of the engine.
FAIL_ON_CHOICES: tuple[str, ...] = tuple(sev.value for sev in Severity)


def _severity_rank(name: Any) -> int | None:
    """Rank of a severity using the shared SEVERITY_ORDER; None if unknown.

    Lower rank = more severe (CRITICAL=0). Unknown or missing values return
    None so the gate can skip them instead of crashing.
    """
    if isinstance(name, Severity):
        return SEVERITY_ORDER.get(name)
    if isinstance(name, str):
        try:
            return SEVERITY_ORDER[Severity(name.upper())]
        except ValueError:
            return None
    return None


def _fail_on_gate(fail_on: str | None, findings: Sequence[Any], complete: Optional[bool] = True) -> int:
    """Release gate: EXIT_ERROR when a finding meets or exceeds ``fail_on``.

    * Gate omitted (None/empty) → exact legacy behavior: EXIT_OK, silent.
    * Decision messages go to stderr so stdout (text or JSON) stays intact.
    * Findings with unknown or missing severities never qualify and never
      raise — a gate must not turn an odd finding into a crash.
    """
    if not fail_on:
        return EXIT_OK
    threshold = _severity_rank(fail_on)
    if threshold is None:
        # argparse choices make this unreachable from the CLI; stay strict.
        print(f"error: unknown --fail-on severity: {fail_on!r}", file=sys.stderr)
        return EXIT_ERROR
    rows = list(findings or ())
    if complete is False and not any(
        (rank := _severity_rank(getattr(f, "severity", None))) is not None and rank <= threshold
        for f in rows
    ):
        # Phase 18.1: an incomplete scan can never certify "nothing at/above X".
        print(f"gate: fail-on {fail_on} cannot pass: the scan is incomplete", file=sys.stderr)
        return EXIT_ERROR
    qualifying = sum(
        1
        for f in rows
        if (rank := _severity_rank(getattr(f, "severity", None))) is not None
        and rank <= threshold
    )
    if qualifying:
        print(
            f"gate: fail-on {fail_on} triggered by {qualifying} finding(s)",
            file=sys.stderr,
        )
        return EXIT_ERROR
    print(
        f"gate: fail-on {fail_on} not triggered "
        f"(0 of {len(rows)} finding(s) meet or exceed {fail_on})",
        file=sys.stderr,
    )
    return EXIT_OK


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="audit.py",
        description=(
            "Local-first smart-contract security auditing engine. "
            "Phase 1: toolchain, Ollama and storage intelligence. "
            "AI output is treated as unverified opinion; deterministic tool "
            "evidence takes precedence."
        ),
        epilog=(
            "Not implemented yet: " + "; ".join(NOT_IMPLEMENTED) + "."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"{AUDITOR_NAME} {__version__} (schema {SCHEMA_VERSION})",
    )
    parser.add_argument(
        "--config",
        metavar="PATH",
        help="path to an alternative JSON config file",
    )
    parser.add_argument(
        "--model",
        metavar="NAME",
        help="Ollama model to report on, e.g. qwen3-8b-uncensored-16k:latest",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=None,
        metavar="SECONDS",
        help="per-tool subprocess timeout (default from config, 15s)",
    )
    parser.add_argument(
        "--no-probe-model",
        action="store_true",
        help="skip the read-only /api/show metadata probe for the selected model",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="log detection steps to stderr",
    )

    # Seeded here so every attribute exists even when a subparser used
    # SUPPRESS and the user did not pass the flag.
    parser.set_defaults(json=False, model=None, timeout=None, no_probe_model=False)

    subparsers = parser.add_subparsers(dest="command", metavar="COMMAND")

    # Shared options are attached to every subcommand as well as the top level,
    # so both `audit.py --model X status` and `audit.py status --model X` work.
    # Trailing flags are the habit people already have; requiring them first
    # would read as a broken tool.
    common = argparse.ArgumentParser(add_help=False)
    # SUPPRESS matters: without it a subparser default (None/False) overwrites a
    # value the user already gave at the top level, so `--model X status` would
    # silently lose X. With SUPPRESS the attribute is left untouched unless the
    # user actually passes the flag.
    common.add_argument(
        "--json", action="store_true", default=argparse.SUPPRESS, help="emit machine-readable JSON"
    )
    common.add_argument(
        "--model", metavar="NAME", default=argparse.SUPPRESS, help="Ollama model to report on"
    )
    common.add_argument(
        "--timeout",
        type=float,
        default=argparse.SUPPRESS,
        metavar="SECONDS",
        help="per-tool subprocess timeout",
    )
    common.add_argument(
        "--no-probe-model",
        action="store_true",
        default=argparse.SUPPRESS,
        help="skip the read-only /api/show metadata probe",
    )

    subparsers.add_parser(
        "status",
        parents=[common],
        help="full environment status: toolchain, Ollama, storage, modules",
        description="Report observed environment state. Reads only; writes nothing.",
    )

    focus_commands = (
        ("tools", "toolchain detection only"),
        ("ollama", "Ollama health and model discovery only"),
        ("disk", "disk and project storage usage only"),
        ("modules", "registered analysis modules"),
    )
    for command_name, command_help in focus_commands:
        subparsers.add_parser(command_name, parents=[common], help=f"{command_help} (text)")

    validate = subparsers.add_parser(
        "validate-address",
        help="validate an EVM address offline (no network access)",
        description=(
            "Validate address syntax only. Mixed-case addresses are reported as "
            "EIP-55 UNVERIFIED because keccak-256 is not available in this "
            "standard-library-only build."
        ),
    )
    validate.add_argument("address", help="0x-prefixed or bare 40-hex address")
    validate.add_argument(
        "--json", action="store_true", default=argparse.SUPPRESS, help="emit machine-readable JSON"
    )

    scan = subparsers.add_parser(
        "scan",
        parents=[common],
        help="scan Solidity source files for vulnerabilities",
        description="Scan one or more .sol files using loaded analysis modules",
    )
    scan.add_argument(
        "path",
        metavar="PATH",
        help="path to a .sol file or directory to scan",
    )
    scan.add_argument(
        "--fail-on",
        metavar="SEVERITY",
        type=str.upper,
        choices=list(FAIL_ON_CHOICES),
        default=None,
        help=(
            "release gate: exit 1 when any finding meets or exceeds this "
            "severity (one of: " + ", ".join(FAIL_ON_CHOICES) + "); "
            "omitted = always exit 0 when the scan itself succeeds"
        ),
    )
    scan.add_argument(
        "--solc",
        metavar="PATH",
        default=None,
        help=(
            "opt-in: path to an installed solc executable for this scan "
            "only. Must be an existing executable file — bare versions such "
            "as 0.8.20 are rejected so nothing is ever downloaded. Omitted "
            "= Slither resolves the compiler exactly as it always has"
        ),
    )
    scan.add_argument(
        "--solc-remaps",
        metavar="PREFIX=PATH",
        default=None,
        help=(
            "opt-in: space-separated solc import remappings for this scan "
            "only, e.g. \"@openzeppelin/=lib/openzeppelin-contracts/\". "
            "Omitted = no remapping override"
        ),
    )
    scan.add_argument(
        "--show-suppressed", action="store_true",
        help=("also list findings suppressed as recognised library code / known-benign patterns "
              "(JSON key suppressed_findings); default: counted on stderr only"),
    )
    scan.add_argument(
        "--scope",
        choices=("standard", "all"),
        default="standard",
        help=(
            "file-collection scope for directory scans: 'standard' (default) "
            "prunes dependency/build/test/mock directories but keeps lib/ "
            "production code; 'all' is the legacy Phase-12 walk (dependencies "
            "and build output only)"
        ),
    )

    scan_address = subparsers.add_parser(
        "scan-address",
        parents=[common],
        help="read-only verified-source retrieval by EVM contract address",
        description=(
            "Retrieve verified Solidity source from a public explorer for the given EVM contract "
            "address and run the local analysis pipeline on it. GET-only; no API key required. "
            "Fails clearly if no explorer credential is configured."
        ),
    )
    scan_address.add_argument(
        "--network",
        required=True,
        choices=["ethereum"],
        help="EVM network name",
    )
    scan_address.add_argument(
        "--address",
        required=True,
        help="EVM address (0x-prefixed or bare 40-hex)",
    )
    scan_address.add_argument(
        "--no-solc-install", action="store_true",
        help="never download a missing solc (the scan is reported incomplete instead)",
    )
    scan_address.add_argument(
        "--show-suppressed", action="store_true",
        help="include findings suppressed as library code / known-benign (with reasons)",
    )
    scan_address.add_argument(
        "--no-value", action="store_true",
        help="skip the value-at-risk estimate (no balance or price requests)",
    )
    scan_address.add_argument(
        "--fail-on",
        metavar="SEVERITY",
        type=str.upper,
        choices=list(FAIL_ON_CHOICES),
        default=None,
        help=(
            "release gate: exit 1 when any finding meets or exceeds this "
            "severity (one of: " + ", ".join(FAIL_ON_CHOICES) + "); "
            "omitted = always exit 0 when the scan itself succeeds"
        ),
    )

    monitor = subparsers.add_parser(
        "monitor",
        parents=[common],
        help="watch a chain for new contract deployments and scan verified ones",
        description=(
            "Poll the chain for contract-creation transactions since a persisted block "
            "cursor, fetch verified source (Etherscan V2, GET-only), run the local "
            "analysis pipeline and alert on findings at or above --min-severity. "
            "Needs ETHERSCAN_API_KEY; optional AUDITOR_MONITOR_RPC_URL for block data."
        ),
    )
    monitor.add_argument("--network", default="ethereum", choices=["ethereum"], help="EVM network")
    monitor.add_argument("--once", action="store_true", help="run a single poll and exit")
    monitor.add_argument("--interval", type=float, default=60.0, metavar="S",
                         help="seconds between polls (default 60)")
    monitor.add_argument("--min-severity", type=str.upper, choices=list(FAIL_ON_CHOICES),
                         default="HIGH", help="alert threshold (default HIGH)")
    monitor.add_argument("--max-per-poll", type=int, default=5, metavar="N",
                         help="max contracts scanned per poll (default 5)")
    monitor.add_argument("--max-blocks-per-poll", type=int, default=20, metavar="N",
                         help="max blocks enumerated per poll (default 20)")
    monitor.add_argument("--webhook", default=None, metavar="URL",
                         help="optional loopback-only webhook for alerts (off by default)")
    monitor.add_argument("--no-solc-install", action="store_true",
                         help="never download a missing solc (scan is recorded as incomplete instead)")
    monitor.add_argument("--min-value-usd", type=float, default=None, metavar="USD",
                         help="only alert when the finding's estimated loss is >= USD (rough estimate; "
                              "unknown value and honeypots still alert)")
    monitor.add_argument("--no-value", action="store_true",
                         help="skip value-at-risk estimates (no balance or price requests)")

    rescan_p = subparsers.add_parser(
        "monitor-rescan",
        parents=[common],
        help="re-run monitor scans that could not be analyzed (incl. legacy Phase 18 rows)",
        description=(
            "Requeue monitor scans whose required analyzer (Slither) did not complete: "
            "status incomplete/failed, plus legacy rows recorded before Phase 18.1 whose "
            "completion was never verified. Then re-fetch and re-scan them now unless "
            "--queue-only. Needs ETHERSCAN_API_KEY to re-scan."
        ),
    )
    rescan_p.add_argument("--network", default="ethereum", choices=["ethereum"], help="EVM network")
    rescan_p.add_argument("--row", type=int, action="append", default=None, metavar="ID",
                          help="only these monitor_scans row ids (repeatable)")
    rescan_p.add_argument("--dry-run", action="store_true", help="list candidates, change nothing")
    rescan_p.add_argument("--queue-only", action="store_true",
                          help="requeue only; the running monitor picks them up")
    rescan_p.add_argument("--min-severity", type=str.upper, choices=list(FAIL_ON_CHOICES),
                          default="HIGH", help="alert threshold (default HIGH)")
    rescan_p.add_argument("--no-solc-install", action="store_true",
                          help="never download a missing solc")

    mstatus = subparsers.add_parser(
        "monitor-status",
        parents=[common],
        help="read-only monitor cursor, queue and recent alerts",
    )
    mstatus.add_argument("--network", default="ethereum", choices=["ethereum"], help="EVM network")
    mstatus.add_argument("--show-suppressed", action="store_true",
                         help="list findings suppressed as library code / known-benign")

    hunt = subparsers.add_parser(
        "hunt",
        parents=[common],
        help="proactively discover and scan live high-value DeFi contracts",
        description=(
            "Build a candidate list of Ethereum contracts holding real value from free "
            "public sources (DefiLlama protocols/pools + optional large-transfer logs), "
            "rank them with a labelled priority hint, and scan the top unscanned ones "
            "through the same pipeline as scan-address / monitor. Needs ETHERSCAN_API_KEY "
            "to scan (Sourcify is used as a no-key fallback for source). Read-only network."
        ),
    )
    hunt.add_argument("--network", default="ethereum", choices=["ethereum"], help="EVM network")
    hunt.add_argument("--once", action="store_true", help="run a single discover/measure/scan cycle and exit")
    hunt.add_argument("--interval", type=float, default=3600.0, metavar="S",
                      help="seconds between cycles in continuous mode (default 3600)")
    hunt.add_argument("--min-tvl", type=float, default=100_000.0, metavar="USD",
                      help="minimum DefiLlama Ethereum TVL to consider (default 100000)")
    hunt.add_argument("--categories", default="pools,swaps,bridges,lending,vaults",
                      help="comma-separated groups: pools,swaps,bridges,lending,vaults")
    hunt.add_argument("--max-scan", type=int, default=10, metavar="N",
                      help="max candidates to scan per cycle (default 10)")
    hunt.add_argument("--max-measure", type=int, default=20, metavar="N",
                      help="max candidates to measure (code+TVL) per cycle (default 20)")
    hunt.add_argument("--max-sim-per-cycle", type=int, default=1, metavar="N",
                      help="max local fork simulations per cycle (default 1; set 0 to disable)")
    hunt.add_argument("--max-protocols", type=int, default=80, metavar="N",
                      help="max DefiLlama protocols considered per refresh (default 80)")
    hunt.add_argument("--no-blue-chips", action="store_true",
                      help="skip Uniswap/Aave/Compound/Lido/… entirely (default: demote, not ban)")
    hunt.add_argument("--with-transfers", action="store_true",
                      help="also discover from recent large ERC-20 transfers (extra RPC/Etherscan calls)")
    hunt.add_argument("--refresh-only", action="store_true",
                      help="refresh the candidate list only; do not measure or scan")
    hunt.add_argument("--measure-only", action="store_true",
                      help="refresh + measure on-chain TVL; do not scan")
    hunt.add_argument("--min-severity", type=str.upper, choices=list(FAIL_ON_CHOICES),
                      default="HIGH", help="alert threshold (default HIGH)")
    hunt.add_argument("--min-value-usd", type=float, default=None, metavar="USD",
                      help="only alert when estimated loss is >= USD (rough estimate)")
    hunt.add_argument("--no-value", action="store_true", help="skip value-at-risk estimates")
    hunt.add_argument("--no-solc-install", action="store_true",
                      help="never download a missing solc")
    hunt.add_argument("--target-tvl-band", default="500000,3000000", metavar="LO,HI",
                      help="prefer scanning contracts whose on-chain TVL is in this USD band first")
    hunt.add_argument("--slugs", default="", metavar="S,S",
                      help="only these DefiLlama slugs (comma-separated), e.g. noon,strata-markets")
    hunt.add_argument("--no-vault-discovery", action="store_true",
                      help="skip Phase-21 proxy/vault holder discovery")
    hunt.add_argument("--with-pools", action="store_true",
                     help="discover pools from recent PairCreated/PoolCreated factory logs")
    hunt.add_argument("--pool-lookback", type=int, default=50_000, metavar="BLOCKS",
                     help="block lookback for --with-pools (default 50000; use 200000+ with Alchemy)")
    hunt.add_argument("--min-holder-usd", type=float, default=10_000.0, metavar="USD",
                      help="upsert discovered holders with at least this live value (default 10000)")

    hstatus = subparsers.add_parser(
        "hunt-status",
        parents=[common],
        help="read-only hunt candidates, priority scores and scan outcomes",
    )
    hstatus.add_argument("--network", default="ethereum", choices=["ethereum"], help="EVM network")
    hstatus.add_argument("--sort", default="priority", choices=["priority", "tvl", "recent", "loss"],
                         help="candidate sort order (default priority)")
    hstatus.add_argument("--top", type=int, default=25, metavar="N", help="rows to show (default 25)")

    exploitable_p = subparsers.add_parser(
        "exploitable",
        parents=[common],
        help="list confirmed EXPLOITABLE_REAL_MONEY findings (outsider TP with real $)",
        description=(
            "List findings explicitly confirmed as outsider-exploitable true positives "
            "with takeable value at or above the threshold (default $1,000). "
            "Unconfirmed UNPROTECTED/WEAK hits are never listed."
        ),
    )
    exploitable_p.add_argument(
        "--min-usd", type=float, default=None, metavar="USD",
        help="override takeable-$ threshold (default $1000 / AUDITOR_EXPLOITABLE_MIN_USD)",
    )

    simulate = subparsers.add_parser(
        "simulate",
        parents=[common],
        help="local anvil-fork invariants, oracle class and trust map (defensive)",
        description=(
            "Spin up a local anvil mainnet fork (127.0.0.1 only) and run defensive "
            "ERC-4626 invariant checks, oracle classification and a cross-contract "
            "trust map. Never broadcasts; uses anvil test accounts only. "
            "Needs forge/anvil/cast on PATH (foundryup)."
        ),
    )
    simulate.add_argument("--address", action="append", default=[], metavar="0x…",
                          help="address to simulate (repeatable)")
    simulate.add_argument("--hunt-top", type=int, default=0, metavar="N",
                          help="simulate the top N scanned hunt candidates by holder value")
    simulate.add_argument("--network", default="ethereum", choices=["ethereum"])
    simulate.add_argument("--fork-url", default="",
                          help="mainnet RPC used only as anvil --fork-url "
                               "(default AUDITOR_MONITOR_RPC_URL or publicnode)")

    watch = subparsers.add_parser(
        "watch",
        help="watch addresses for holder value / pool liquidity crossing a USD threshold",
    )
    watch_sub = watch.add_subparsers(dest="watch_cmd", required=True)
    w_add = watch_sub.add_parser("add", help="add an address to the watch list")
    w_add.add_argument("address", help="0x… contract address")
    w_add.add_argument("--network", default="ethereum", choices=["ethereum"])
    w_add.add_argument("--note", default="", help="free-text note stored with the watch")
    w_add.add_argument("--related", default="", metavar="0x…",
                       help="optional related address (e.g. proxy for an implementation)")
    w_add.add_argument("--min-value-usd", type=float, default=1000.0, metavar="USD",
                       help="alert threshold (default 1000)")
    w_list = watch_sub.add_parser("list", help="list watched addresses")
    w_list.add_argument("--network", default="ethereum", choices=["ethereum"])
    w_rm = watch_sub.add_parser("remove", help="remove an address from the watch list")
    w_rm.add_argument("address", help="0x… contract address")
    w_rm.add_argument("--network", default="ethereum", choices=["ethereum"])
    w_check = watch_sub.add_parser("check", help="re-measure all watches once and alert if due")
    w_check.add_argument("--network", default="ethereum", choices=["ethereum"])
    w_check.add_argument("--min-value-usd", type=float, default=None, metavar="USD",
                         help="override default threshold for this run only (per-target still wins)")

    watchdog = subparsers.add_parser(
        "watchdog",
        help="supervise the monitor and hunt workers: restart on unexpected exit, single-instance locks",
        description=(
            "Standalone worker supervisor (P1 step 1). Workers remain the existing "
            "per-worker CLI processes; a per-worker kernel lock guarantees no two "
            "copies of the same worker ever run at once, and each worker records a "
            "heartbeat in the monitor database. The watchdog restarts a worker that "
            "exits unexpectedly, with bounded exponential backoff, and stops "
            "children cleanly on Ctrl-C / SIGTERM. Run 'audit.py watchdog status' "
            "for worker states and 'audit.py watchdog check' with a non-zero exit "
            "code on stale worker heartbeats."
        ),
    )
    wd_sub = watchdog.add_subparsers(dest="watchdog_cmd", required=True)
    wd_run = wd_sub.add_parser(
        "run",
        help="supervise workers until Ctrl-C/SIGTERM (or one round with --once)",
    )
    wd_run.add_argument("--network", default="ethereum", choices=["ethereum"])
    wd_run.add_argument("--once", action="store_true",
                        help="one supervision round, then stop children and exit")
    wd_run.add_argument("--no-hunt", action="store_true",
                        help="supervise only the monitor worker")
    wd_run.add_argument("--monitor-cmd", default="scripts/run_monitor.sh", metavar="CMD",
                        help="monitor worker command (shlex-split; resolved from the project root; "
                             "default: the existing scripts/run_monitor.sh)")
    wd_run.add_argument("--hunt-cmd", default="scripts/run_hunt.sh", metavar="CMD",
                        help="hunt worker command (default: the existing scripts/run_hunt.sh)")
    wd_run.add_argument("--poll-interval", type=float, default=2.0, metavar="S",
                        help="supervision round cadence (default 2s)")
    wd_run.add_argument("--restart-backoff-base", type=float, default=5.0, metavar="S",
                        help="first restart delay after an unexpected exit (default 5s)")
    wd_run.add_argument("--restart-backoff-cap", type=float, default=300.0, metavar="S",
                        help="maximum restart delay (default 300s)")
    wd_run.add_argument("--max-restarts", type=int, default=20, metavar="N",
                        help="consecutive crashes or rapid clean exits before giving up on a worker (default 20)")
    wd_run.add_argument("--stable-reset-seconds", type=float, default=600.0, metavar="S",
                        help="a worker alive this long resets the restart backoff (default 600s)")
    wd_run.add_argument("--child-grace", type=float, default=10.0, metavar="S",
                        help="seconds between SIGINT and SIGTERM when stopping children (default 10s)")
    wd_run.add_argument("--stale-recovery", choices=("on", "off"), default="on",
                        help="heartbeat-wedge recovery: stop and restart a worker that stays alive "
                             "but stops updating its heartbeat (default on)")
    wd_run.add_argument("--stale-recovery-seconds", type=float, default=0.0, metavar="S",
                        help="override the sustained heartbeat staleness threshold (default: auto — "
                             "monitor 900s, hunt 1800s)")
    wd_run.add_argument("--stale-observations", type=int, default=3, metavar="N",
                        help="distinct stale heartbeat observations required before recovery (default 3)")
    wd_run.add_argument("--json", action="store_true", help="emit the final summary as JSON on stdout")
    wd_status = wd_sub.add_parser("status", help="show worker lock/heartbeat/supervisor states")
    wd_status.add_argument("--network", default="ethereum", choices=["ethereum"])
    wd_status.add_argument("--stale-threshold", type=float, default=600.0, metavar="S",
                           help="heartbeat age (seconds) above which a worker is reported stale")
    wd_status.add_argument("--json", action="store_true")
    wd_check = wd_sub.add_parser(
        "check",
        help="exit 0 fresh, 1 stale/missing-when-expected, 2 monitor DB unavailable",
    )
    wd_check.add_argument("--network", default="ethereum", choices=["ethereum"])
    wd_check.add_argument("--stale-threshold", type=float, default=600.0, metavar="S")
    wd_check.add_argument("--expect-running", action="store_true",
                          help="also fail when a worker is stopped or was never started")
    wd_check.add_argument("--json", action="store_true")

    dashboard = subparsers.add_parser(
        "dashboard",
        parents=[common],
        help="serve the local web dashboard (loopback only)",
        description=(
            "Serve the Contract Auditor dashboard on 127.0.0.1. The server binds "
            "to loopback only; non-loopback hosts are rejected so the dashboard "
            "is never exposed to the network."
        ),
    )
    dashboard.add_argument(
        "--host",
        default="127.0.0.1",
        help="bind address (loopback only; default 127.0.0.1)",
    )
    dashboard.add_argument(
        "--port",
        type=int,
        default=8080,
        help="port to listen on (default 8080)",
    )
    dashboard.add_argument(
        "--reload",
        action="store_true",
        help="auto-reload on code changes (development only)",
    )

    benchmark = subparsers.add_parser(
        "benchmark",
        parents=[common],
        help="run the vulnerability-detection benchmark over the fixture corpus",
        description=(
            "Run benchmarks/fixtures/*.sol through the existing analysis "
            "pipeline and score detections against ground truth "
            "(benchmarks/manifest.json) per benchmarks/PROTOCOL.md. Results "
            "are stored in benchmark_store.db — never in scan history."
        ),
    )
    benchmark.add_argument(
        "--fixtures",
        metavar="DIR",
        default=None,
        help="fixture directory (default: fixtures/ next to the manifest)",
    )
    benchmark.add_argument(
        "--manifest",
        metavar="PATH",
        default=None,
        help="manifest path (default: benchmarks/manifest.json)",
    )
    benchmark.add_argument(
        "--db",
        metavar="PATH",
        default=None,
        help="benchmark store path (default: $AUDITOR_BENCHMARK_DB or benchmark_store.db)",
    )
    benchmark.add_argument(
        "--limit",
        type=int,
        default=None,
        help="evaluate only the first N fixtures (development aid)",
    )
    benchmark.add_argument(
        "--no-save",
        action="store_true",
        help="run without persisting to the benchmark store",
    )
    benchmark.add_argument(
        "--baseline",
        action="store_true",
        help=(
            "compare this run against the stored baseline (PROTOCOL.md §9.6); "
            "exits 1 when regressions are found or the comparison is not "
            "like-for-like (toolchain/corpus mismatch)"
        ),
    )
    benchmark.add_argument(
        "--set-baseline",
        action="store_true",
        help=(
            "store this run as the benchmark baseline; rejected for "
            "incomplete runs, and an existing baseline requires --force"
        ),
    )
    benchmark.add_argument(
        "--force",
        action="store_true",
        help="with --set-baseline: explicitly replace an existing baseline",
    )

    return parser


def _configure_logging(verbose: bool) -> None:
    # Logs go to stderr only. stdout carries report data and must stay clean
    # for piping into jq.
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.WARNING,
        format="%(levelname)s %(name)s: %(message)s",
        stream=sys.stderr,
    )


def _platform_info() -> dict[str, Any]:
    mac_version = platform.mac_ver()[0] or "unknown"
    return {
        "system": platform.system(),
        "machine": platform.machine(),
        "release": platform.release(),
        "macos_version": mac_version,
        "python_version": platform.python_version(),
        "python_executable": sys.executable,
    }


def _resolve_endpoint(settings: Settings, override: str | None) -> str:
    return override or settings.endpoint or DEFAULT_ENDPOINT


def _emit_json(payload: dict[str, Any]) -> int:
    json.dump(payload, sys.stdout, indent=2, sort_keys=False, default=str)
    sys.stdout.write("\n")
    return EXIT_OK


@dataclass
class _Observation:
    """Everything a status run observed, collected exactly once.

    Detection is not free: each tool probe is a subprocess, and re-running it
    for the text renderer after building the JSON payload would double every
    probe and could report two different states if a tool changed mid-run.
    """

    toolchain: ToolchainReport
    ollama: OllamaStatus
    storage: StorageReport
    registry: dict[str, Any]
    platform_info: dict[str, Any]


def _observe(settings: Settings, args: argparse.Namespace) -> _Observation:
    timeout = args.timeout if args.timeout and args.timeout > 0 else settings.tool_timeout
    limits = settings.limits
    return _Observation(
        toolchain=detect_toolchain(timeout=timeout),
        ollama=probe_ollama(
            endpoint=settings.endpoint,
            selected_model=args.model or settings.model_name,
            probe_model=settings.probe_on_status and not args.no_probe_model,
        ),
        storage=probe_storage(
            root=PROJECT_ROOT,
            limits=limits,
            large_file_threshold_bytes=limits.get("large_file_threshold_mb", 10) * 1024 * 1024,
        ),
        registry=discover_analyzers().to_dict(),
        platform_info=_platform_info(),
    )


def _status_payload(observed: _Observation, settings: Settings) -> dict[str, Any]:
    return {
        "auditor": {
            "name": AUDITOR_NAME,
            "version": __version__,
            "schema_version": SCHEMA_VERSION,
            "project_root": str(PROJECT_ROOT),
            "phase": 1,
        },
        "environment": observed.platform_info,
        "disclaimer": STATUS_DISCLAIMER,
        "not_implemented": list(NOT_IMPLEMENTED),
        "toolchain": observed.toolchain.to_dict(),
        "ollama": observed.ollama.to_dict(),
        "storage": observed.storage.to_dict(),
        "analysis_modules": observed.registry,
        "configuration": settings.to_dict(),
    }


def _cmd_status(args: argparse.Namespace, settings: Settings) -> int:
    observed = _observe(settings, args)

    if args.json:
        return _emit_json(_status_payload(observed, settings))

    print(
        render_status_text(
            auditor_version=__version__,
            schema_version=SCHEMA_VERSION,
            python_version=str(observed.platform_info.get("python_version", "?")),
            platform_info=observed.platform_info,
            toolchain=observed.toolchain,
            ollama=observed.ollama,
            storage=observed.storage,
            registry=observed.registry,
            settings_warnings=settings.warnings,
        )
    )
    return EXIT_OK


def _cmd_tools(args: argparse.Namespace, settings: Settings) -> int:
    timeout = args.timeout if args.timeout and args.timeout > 0 else settings.tool_timeout
    report = detect_toolchain(timeout=timeout)
    if getattr(args, "json", False):
        return _emit_json(report.to_dict())
    print(render_toolchain_text(report))
    return EXIT_OK


def _cmd_ollama(args: argparse.Namespace, settings: Settings) -> int:
    status = probe_ollama(
        endpoint=settings.endpoint,
        selected_model=args.model or settings.model_name,
        probe_model=settings.probe_on_status and not args.no_probe_model,
    )
    if getattr(args, "json", False):
        return _emit_json(status.to_dict())
    print(render_ollama_text(status))
    return EXIT_OK


def _cmd_disk(args: argparse.Namespace, settings: Settings) -> int:
    report = probe_storage(PROJECT_ROOT, limits=settings.limits)
    if getattr(args, "json", False):
        return _emit_json(report.to_dict())
    print(render_storage_text(report))
    return EXIT_OK


def _cmd_modules(args: argparse.Namespace, settings: Settings) -> int:
    report = discover_analyzers()
    if getattr(args, "json", False):
        return _emit_json(report.to_dict())
    print(f"Registered analysis modules: {len(report.loadable())}")
    for entry in report.loadable():
        print(f"  - {entry.module_name} [{entry.category}]")
    print(report.to_dict()["note"])
    for error in report.errors:
        print(f"  error: {error}")
    return EXIT_OK


def _cmd_validate_address(args: argparse.Namespace, settings: Settings) -> int:
    result = validate_address(args.address)
    if args.json:
        return _emit_json(result.to_dict())
    print(f"address        : {args.address}")
    print(f"valid          : {'yes' if result.is_valid else 'no'}")
    print(f"normalized     : {result.normalized or '-'}")
    print(f"checksum       : {result.checksum_status}")
    print(f"reason         : {result.reason}")
    return EXIT_OK if result.is_valid else EXIT_ERROR


def _cmd_scan(args: argparse.Namespace, settings: Settings) -> int:
    import hashlib
    import os
    from pathlib import Path

    path = Path(args.path)
    if not path.exists():
        print(f"error: path does not exist: {args.path}", file=sys.stderr)
        return EXIT_ERROR

    # Opt-in compiler selection is validated before any analyzer runs, i.e.
    # before Slither can be invoked: a bad --solc must fail as a usage error
    # here rather than as a silent failed (zero-finding) scan later.
    from auditor.analysis.slither_runner import (
        collect_sol_files,
        parse_solc_remappings,
        validate_solc_path,
    )

    solc_requested, solc_error = validate_solc_path(getattr(args, "solc", None))
    remap_tokens, remap_error = parse_solc_remappings(
        getattr(args, "solc_remaps", None)
    )
    for message in (solc_error, remap_error):
        if message:
            print(f"error: {message}", file=sys.stderr)
            return EXIT_ERROR
    remaps_requested = " ".join(remap_tokens) if remap_tokens else None
    scope_requested = getattr(args, "scope", "standard") or "standard"

    sol_files = (
        collect_sol_files([path], scope=scope_requested)
        if path.is_dir()
        else ([path] if path.suffix == ".sol" else [])
    )
    if not sol_files:
        print(f"error: no .sol files found in {args.path}", file=sys.stderr)
        return EXIT_ERROR

    # Read all .sol files and compute combined content hash. A NUL
    # separator between files keeps ["ab","c"] from colliding with
    # ["a","bc"] — a single file still hashes to exactly its own bytes.
    parts: list[bytes] = []
    for sf in sol_files:
        if sf.is_file():
            with open(sf, "rb") as f:
                parts.append(f.read())
    combined = b"\x00".join(parts)

    if not combined:
        print("error: no readable .sol file content", file=sys.stderr)
        return EXIT_ERROR

    content_hash = hashlib.sha256(combined).hexdigest()

    # Run the existing analysis pipeline over ALL collected files (a
    # directory scan previously analyzed only the first file).
    from auditor.analysis.reentrancy import analyze as reentrancy_analyze
    from auditor.analysis.access_control import analyze as access_control_analyze
    from auditor.analysis.slither_generic import analyze as generic_analyze
    from auditor.analysis.oracle_staleness import analyze as oracle_analyze
    from auditor.analysis.erc4626_inflation import analyze as erc4626_analyze
    from auditor.analysis.pool_accounting import analyze as pool_analyze
    from auditor.analysis.honeypot import analyze as honeypot_analyze
    from auditor.analysis.privileged_auth import analyze as privileged_auth_analyze
    from auditor.analysis.base import AnalysisContext

    # Identity of the analyzers this path runs — the effective-configuration
    # fingerprint below is keyed on it, so adding an analyzer here must add
    # it here too or equal fingerprints would stop meaning equal analysis.
    analyzer_keys = (
        "access_control",
        "reentrancy",
        "slither_generic",
        "oracle_staleness",
        "erc4626_inflation",
        "pool_accounting",
        "honeypot",
        "privileged_auth",
    )

    context = AnalysisContext()
    context.source_files = sol_files
    # Always set options so scope is visible to every analyzer; solc/remaps
    # keys remain absent unless the user opted in, so Slither argv is
    # unchanged for default invocations.
    context.options = {"scope": scope_requested}
    if solc_requested or remaps_requested:
        context.options["solc"] = solc_requested
        context.options["solc_remaps"] = remaps_requested

    reentrancy_outcome = reentrancy_analyze(context)
    access_outcome = access_control_analyze(context)
    generic_outcome = generic_analyze(context)
    oracle_outcome = oracle_analyze(context)
    erc4626_outcome = erc4626_analyze(context)
    pool_outcome = pool_analyze(context)
    honeypot_outcome = honeypot_analyze(context)
    privileged_auth_outcome = privileged_auth_analyze(context)

    findings = list(reentrancy_outcome.findings) + list(access_outcome.findings)
    findings += list(generic_outcome.findings)
    findings += list(oracle_outcome.findings)
    findings += list(erc4626_outcome.findings)
    findings += list(pool_outcome.findings)
    findings += list(honeypot_outcome.findings)
    findings += list(privileged_auth_outcome.findings)
    # Same contract as dashboard scans: merge detector duplicates first
    # (canonical dedupe in auditor.model), then drop findings that fail
    # their own validation — they never reach history, reports, or the
    # fail-on gate.
    from auditor.model import deduplicate_findings, validated_findings

    findings, _merged = deduplicate_findings(findings)
    findings = validated_findings(findings)
    notes = []
    # Phase 19: recognised library code / known-benign patterns are suppressed
    # (kept with reasons), admin-gated withdraws downgraded.
    from auditor.triage import apply_to_pipeline

    triage_result = apply_to_pipeline(findings, sol_files, path if path.is_dir() else None, None, notes.append)
    findings = triage_result.kept
    for outcome in (
        reentrancy_outcome,
        access_outcome,
        generic_outcome,
        oracle_outcome,
        erc4626_outcome,
        pool_outcome,
        honeypot_outcome,
        privileged_auth_outcome,
    ):
        for note in outcome.notes or []:
            if note and note not in notes:
                notes.append(note)

    # Record in scan history
    from auditor.scan_history import ScanHistory, default_history_db_path
    from auditor.scan_evidence import collect_scan_evidence, probe_binary_version
    from pathlib import Path

    # Evidence is gathered before any row exists so a probe failure can never
    # strand a STARTED record, and it feeds detector selection nowhere — it is
    # recorded, never consulted. ``settings`` is optional at this call site
    # (tests drive ``_cmd_scan`` directly), so the probe budget falls back to
    # the same default Settings would apply.
    probe_timeout = getattr(settings, "tool_timeout", None)
    if not isinstance(probe_timeout, (int, float)) or probe_timeout <= 0:
        probe_timeout = 15.0

    # Identity of the opt-in compiler selection for the fingerprint: its
    # probed version, falling back to its path when the binary could not be
    # interrogated. PATH solc is never used here — an unrequested scan must
    # fingerprint exactly as it did before --solc existed.
    solc_identity: str | None = None
    if solc_requested:
        probe = probe_binary_version(solc_requested, timeout=float(probe_timeout))
        solc_identity = probe.get("version") or solc_requested

    evidence = collect_scan_evidence(
        sol_files=sol_files,
        analyzer_keys=analyzer_keys,
        fail_on=getattr(args, "fail_on", None),
        auditor_version=__version__,
        schema_version=SCHEMA_VERSION,
        probe_timeout=float(probe_timeout),
        notes=notes,
        # The shared cached run, when one happened: the only admissible
        # source of "which compiler Slither actually invoked".
        slither_run=getattr(context, "_slither_run", None),
        solc_requested=solc_requested,
        solc_version_requested=solc_identity,
        solc_remaps_requested=remaps_requested,
        scope=scope_requested,
    )

    # Phase 18.1: the completion verdict comes from the OBSERVED shared Slither
    # run — a compile failure must never be persisted as a clean scan.
    from auditor.analysis.slither_runner import required_analysis_verdict

    scan_complete, incomplete_reasons = required_analysis_verdict(
        getattr(context, "_slither_run", None))
    evidence["scan_complete"] = scan_complete
    evidence["incomplete_reasons"] = incomplete_reasons
    evidence["triage"] = dict(triage_result.summary(), suppressed_findings=triage_result.suppressed_dicts())
    if not findings and scan_complete is not None:
        evidence["zero_findings_note"] = (
            "No findings from completed static analysis." if scan_complete else
            "No findings, but the scan is INCOMPLETE; this is not a clean result.")

    db_path = default_history_db_path()
    history = ScanHistory(db_path)
    try:
        scan_id = history.record_scan(
            source_path=Path(args.path),
            config_fingerprint=evidence["config_fingerprint"],
            findings=findings,
            content_hash=content_hash,
        )
        # Execution before completed, matching the dashboard: a persistence
        # failure can never overwrite a completed status.
        history.set_execution(scan_id, evidence)
        # record_scan defaults to STARTED; a completed CLI scan must be
        # terminal or get_findings() hides it forever.
        history.mark_completed(scan_id, findings)
    finally:
        history.close()

    if scan_complete is False:
        # stderr: the stdout contract (text and JSON) stays unchanged (C1).
        print("warning: scan INCOMPLETE - required analysis did not complete; "
              "this is NOT a clean result", file=sys.stderr)
        for reason in incomplete_reasons:
            print(f"  reason: {reason}", file=sys.stderr)

    tsum = triage_result.summary()
    if tsum["suppressed"] or tsum["downgraded"]:
        print(f"note: {tsum['suppressed']} finding(s) suppressed {tsum['suppressed_by_reason']}, "
              f"{tsum['downgraded']} downgraded (privileged caller); --show-suppressed lists them",
              file=sys.stderr)
    show_suppressed = getattr(args, "show_suppressed", False)
    if getattr(args, "json", False):
        from .cli import _emit_json
        payload = {
            "scan_id": scan_id,
            "source_path": args.path,
            "content_hash": content_hash,
            "findings": [f.to_dict() for f in findings],
            "notes": notes,
        }
        if show_suppressed:  # opt-in key: the default stdout contract (C1) is unchanged
            payload["suppressed_findings"] = triage_result.suppressed_dicts()
        # Emit stdout first; the gate decision (if any) goes to stderr so the
        # JSON document on stdout stays parseable.
        _emit_json(payload)
        return _fail_on_gate(getattr(args, "fail_on", None), findings, scan_complete)

    print(f"scan: scanned {len(sol_files)} .sol file(s), content hash: {content_hash}")
    print(f"findings: {len(findings)}")
    for f in findings:
        print(f"  - {f.title} ({f.severity.value}/{f.confidence.value})")
    if show_suppressed:
        for d in triage_result.suppressed_dicts():
            print(f"  [suppressed: {d['triage']['reason']}] {d['title']} ({d['severity']})")
    for note in notes:
        print(f"note: {note}")
    return _fail_on_gate(getattr(args, "fail_on", None), findings, scan_complete)


def _cmd_scan_address(args: argparse.Namespace, settings: Settings) -> int:
    """Read-only verified-source retrieval by EVM contract address."""
    import hashlib
    import json as _json
    import os
    import sys
    import tempfile
    import urllib.error
    import urllib.request

    # Validate address syntax
    from .target import validate_address as _va
    va_result = _va(args.address)
    if not va_result.is_valid:
        print(f"error: invalid address: {args.address}: {va_result.reason}", file=sys.stderr)
        return EXIT_ERROR

    network = args.network
    address = args.address

    if network != "ethereum":
        print(f"error: unsupported network: {network}", file=sys.stderr)
        return EXIT_ERROR

    # Etherscan verified-source retrieval (GET-only)
    api_key = os.environ.get("ETHERSCAN_API_KEY")
    if not api_key:
        print(
            "error: ETHERSCAN_API_KEY not set; cannot retrieve verified source from Etherscan",
            file=sys.stderr,
        )
        return EXIT_ERROR

    base_url = "https://api.etherscan.io/v2/api"
    module = "contract"
    action = "getsourcecode"
    address_norm = va_result.normalized or address

    # Etherscan API V2 requires chainid=1 for Ethereum Mainnet
    chainid = "1"
    url = f"{base_url}?module={module}&action={action}&address={address_norm}&apikey={api_key}&chainid={chainid}"

    def _redact(text: str) -> str:
        # The API key rides in the query string; remote error bodies can
        # echo the request URI. Never let it reach stderr or logs.
        return text.replace(api_key, "***")

    try:
        req = urllib.request.Request(url, headers={"User-Agent": "contract-auditor/1.0"})
        with urllib.request.urlopen(req, timeout=30) as resp:
            body = resp.read().decode("utf-8")
        data = _json.loads(body)
    except urllib.error.HTTPError as e:
        print(f"error: Etherscan HTTP {e.code}: {_redact(e.read().decode('utf-8', errors='replace'))}", file=sys.stderr)
        return EXIT_ERROR
    except urllib.error.URLError as e:
        print(f"error: Etherscan connection error: {_redact(str(e))}", file=sys.stderr)
        return EXIT_ERROR
    except Exception as e:
        print(f"error: unexpected retrieval error: {type(e).__name__}: {_redact(str(e))}", file=sys.stderr)
        return EXIT_ERROR

    if data.get("status") != "1":
        msg = data.get("message", "unknown error")
        result_data = data.get("result", [])
        print(f"error: Etherscan API error: {msg}", file=sys.stderr)
        if isinstance(result_data, list) and len(result_data) == 0:
            print(f"note: contract at {address} on {network} is not verified", file=sys.stderr)
        return EXIT_ERROR

    source_code_list = data.get("result", [])
    if not source_code_list or not isinstance(source_code_list, list) or len(source_code_list) == 0:
        print("error: no source code returned", file=sys.stderr)
        return EXIT_ERROR

    primary_source = source_code_list[0].get("SourceCode", "")
    if not primary_source:
        print("error: no SourceCode in result", file=sys.stderr)
        return EXIT_ERROR

    # Compute content hash from the retrieved source
    content_hash = hashlib.sha256(primary_source.encode("utf-8")).hexdigest()

    # Run the existing local analysis pipeline on the retrieved source
    from auditor.analysis.reentrancy import analyze as reentrancy_analyze
    from auditor.analysis.access_control import analyze as access_control_analyze
    from auditor.analysis.slither_generic import analyze as generic_analyze
    from auditor.analysis.oracle_staleness import analyze as oracle_analyze
    from auditor.analysis.erc4626_inflation import analyze as erc4626_analyze
    from auditor.analysis.pool_accounting import analyze as pool_analyze
    from auditor.analysis.honeypot import analyze as honeypot_analyze
    from auditor.analysis.privileged_auth import analyze as privileged_auth_analyze

    # Phase 18.1: materialise flat OR standard-JSON sources (original unit
    # names, so @openzeppelin/... imports resolve) and compile with the
    # contract's own solc version / settings instead of the global default.
    from pathlib import Path
    import shutil

    from auditor.analysis.base import AnalysisContext
    from auditor.compiler_select import CompilerSelectionError, plan_compile
    from auditor.monitor import _solc_auto_install_default, materialize_sources

    tmp_path = tempfile.mkdtemp(prefix="ca-scan-address-")
    try:
        record = source_code_list[0] if isinstance(source_code_list[0], dict) else {}
        files = materialize_sources(primary_source, Path(tmp_path),
                                    str(record.get("ContractName") or "") or "Contract")
        context = AnalysisContext()
        context.source_files = files
        main_contract = str(record.get("ContractName") or "") or None
        context.options = {"scope": "standard", "main_contract": main_contract, "source_root": tmp_path}
        compile_info = None
        selection_error = None
        allow_install = _solc_auto_install_default() and not getattr(args, "no_solc_install", False)
        try:
            plan = plan_compile(record, files, Path(tmp_path), allow_install=allow_install)
            context.options.update(plan.options())
            compile_info = plan.to_dict()
        except CompilerSelectionError as exc:
            selection_error = f"compiler selection failed: {exc}"

        reentrancy_outcome = reentrancy_analyze(context)
        access_outcome = access_control_analyze(context)
        generic_outcome = generic_analyze(context)
        oracle_outcome = oracle_analyze(context)
        erc4626_outcome = erc4626_analyze(context)
        pool_outcome = pool_analyze(context)
        honeypot_outcome = honeypot_analyze(context)
        privileged_auth_outcome = privileged_auth_analyze(context)

        findings = list(reentrancy_outcome.findings) + list(access_outcome.findings)
        findings += list(generic_outcome.findings)
        findings += list(oracle_outcome.findings)
        findings += list(erc4626_outcome.findings)
        findings += list(pool_outcome.findings)
        findings += list(honeypot_outcome.findings)
        findings += list(privileged_auth_outcome.findings)
        # Same order as the dashboard address path: merge detector
        # duplicates BEFORE attaching the provenance evidence.
        from auditor.model import deduplicate_findings

        findings, _merged = deduplicate_findings(findings)

        # Provenance: the retrieved source itself is a FACT (same as the
        # dashboard address path). Attach BEFORE validation so findings may
        # rely on it for their FACT requirement.
        from auditor.scan_history import ScanHistory, default_history_db_path
        from auditor.model import EvidenceItem, Epistemic

        evidence = EvidenceItem(
            source="etherscan",
            artifact_type="verified_source",
            excerpt=primary_source[:200] if len(primary_source) > 200 else primary_source,
            epistemic=Epistemic.FACT,
            content_hash=content_hash,
        )
        for f in findings:
            f.add_evidence(evidence)

        # Same contract as dashboard scans: drop findings that fail their
        # own validation before they reach history or any report.
        from auditor.model import validated_findings

        findings = validated_findings(findings)

        # Phase 19: library-code / known-benign suppression, privileged-withdraw downgrade.
        from auditor.triage import apply_to_pipeline

        triage_notes: list = []
        triage_result = apply_to_pipeline(findings, files, Path(tmp_path), main_contract, triage_notes.append)
        findings = triage_result.kept

        from auditor.analysis.slither_runner import required_analysis_verdict
        from auditor.monitor import build_execution

        slither_run = getattr(context, "_slither_run", None)
        scan_complete, incomplete_reasons = required_analysis_verdict(slither_run)
        if selection_error:
            scan_complete, incomplete_reasons = False, [selection_error] + incomplete_reasons
        execution = build_execution(slither_run, findings, scan_complete, incomplete_reasons, compile_info,
                                    triage_notes)
        execution["triage"] = dict(triage_result.summary(), suppressed_findings=triage_result.suppressed_dicts())

        # Phase 19: value at risk (ROUGH ESTIMATE) — read-only GET balances + public prices.
        value_block = None
        if not getattr(args, "no_value", False):
            value_block = _scan_address_value(api_key, address_norm, record, findings, triage_result)
            execution["value_at_risk"] = value_block

        db_path = default_history_db_path()
        history = ScanHistory(db_path)
        try:
            scan_id = history.record_scan(
                # Stable display path — the temp file is unlinked at exit.
                # Plain string so the // in the scheme survives Path rules.
                source_path=f"etherscan://{address_norm}",
                config_fingerprint="scan-address-ethereum",
                findings=findings,
                content_hash=content_hash,
            )
            history.set_execution(scan_id, execution)  # before completed (Phase 12 order)
            # record_scan defaults to STARTED; a completed scan must be
            # terminal or get_findings() hides it forever.
            history.mark_completed(scan_id, findings)
        finally:
            history.close()

        if getattr(args, "json", False):
            from .cli import _emit_json
            payload = {
                "scan_id": scan_id,
                "address": address,
                "network": network,
                "source_hash": content_hash,
                "findings": [f.to_dict() for f in findings],
                "scan_complete": scan_complete,
                "incomplete_reasons": incomplete_reasons,
                "compiler": compile_info,
                "triage": triage_result.summary(),
                "value_at_risk": value_block,
            }
            if getattr(args, "show_suppressed", False):
                payload["suppressed_findings"] = triage_result.suppressed_dicts()
            _emit_json(payload)
            return _fail_on_gate(getattr(args, "fail_on", None), findings, scan_complete)

        print(f"scan-address: retrieved source for {address} on {network}")
        print(f"source hash: {content_hash}")
        if compile_info:
            print(f"compiler: solc {compile_info['solc_version']} ({compile_info['version_source']})")
        if scan_complete is False:
            print("warning: scan INCOMPLETE - required analysis did not complete; "
                  "this is NOT a clean result", file=sys.stderr)
            for reason in incomplete_reasons:
                print(f"  reason: {reason}", file=sys.stderr)
        est = {e.get("finding_id"): e for e in ((value_block or {}).get("finding_estimates") or [])}
        if value_block:
            sm = value_block.get("summary") or {}
            print(f"value at risk (rough estimate): TVL {_fmt_usd(sm.get('tvl_usd'))}, "
                  f"est. max loss {_fmt_usd(sm.get('est_max_loss_usd'))}, prices as of "
                  f"{_fmt_ts(sm.get('price_as_of'))}")
        print(f"findings: {len(findings)}")
        for f in findings:
            e = est.get(f.finding_id) or {}
            money = f", est. loss {_fmt_usd(e.get('est_loss_usd'))}" if value_block else ""
            print(f"  - {f.title} ({f.severity.value}/{f.confidence.value}{money})")
        tsum = triage_result.summary()
        if tsum["suppressed"]:
            print(f"suppressed: {tsum['suppressed']} {tsum['suppressed_by_reason']}"
                  + ("" if getattr(args, "show_suppressed", False) else " (--show-suppressed to list)"))
            if getattr(args, "show_suppressed", False):
                for d in triage_result.suppressed_dicts():
                    print(f"  [suppressed: {d['triage']['reason']}] {d['title']} ({d['severity']})")
        return _fail_on_gate(getattr(args, "fail_on", None), findings, scan_complete)
    finally:
        shutil.rmtree(tmp_path, ignore_errors=True)


def _scan_address_value(api_key: str, address: str, record: dict, findings: list, triage_result: Any,
                        client: Any = None, price_source: Any = None) -> dict:
    """Value-at-risk block for scan-address (rough estimate). Never raises."""
    from .monitor import ChainClient, finding_value_rows
    from .value_at_risk import PriceSource, assess

    try:
        client = client or ChainClient(api_key, 1)
        ps = price_source or PriceSource()
        var = assess(client, address, record, ps)
        rows, _est, summary = finding_value_rows(findings, [], triage_result, var)
        return {"is_estimate": True, "label": "rough estimate", "summary": summary, "contract": var.to_dict(),
                "finding_estimates": [{"finding_id": r["finding_id"], "title": r["title"],
                                       **json.loads(r["estimate_json"] or "{}")} for r in rows]}
    except Exception as exc:  # noqa: BLE001 - estimates are best-effort
        return {"is_estimate": True, "label": "rough estimate", "summary": None, "contract": None,
                "finding_estimates": [], "error": f"value estimate unavailable: {type(exc).__name__}"}


def _cmd_monitor(args: argparse.Namespace, settings: Settings) -> int:
    from .monitor import Monitor, MonitorConfig, MonitorError, build_client_from_env, _redact
    from .supervisor import LockHeld

    if args.interval < 0 or args.max_per_poll < 0 or args.max_blocks_per_poll < 1:
        print("error: --interval/--max-per-poll must be >= 0 and --max-blocks-per-poll >= 1",
              file=sys.stderr)
        return EXIT_ERROR
    if getattr(args, "min_value_usd", None) is not None and args.min_value_usd < 0:
        print("error: --min-value-usd must be >= 0", file=sys.stderr)
        return EXIT_ERROR
    as_json = getattr(args, "json", False)
    try:
        client = build_client_from_env(args.network)
        cfg = MonitorConfig(network=args.network, min_severity=args.min_severity,
                            max_per_poll=args.max_per_poll,
                            max_blocks_per_poll=args.max_blocks_per_poll,
                            interval=args.interval, webhook_url=args.webhook,
                            solc_auto_install=not args.no_solc_install,
                            min_value_usd=getattr(args, "min_value_usd", None))
        if getattr(args, "no_value", False):
            cfg.value_enabled = False
        emit = (lambda m: print(m, file=sys.stderr)) if as_json else print
        mon = Monitor(cfg, client, emit=emit)
    except MonitorError as exc:
        print(f"error: {_redact(exc)}", file=sys.stderr)
        return EXIT_ERROR
    if not as_json:
        print(f"monitor: {args.network}, alert >= {args.min_severity}, "
              f"{'single poll' if args.once else f'every {args.interval:g}s (Ctrl-C to stop)'}")
    try:
        polls = mon.run(once=args.once)
    except LockHeld as exc:
        print(f"error: monitor already running (pid {exc.pid}) holds the worker lock; "
              f"not starting a second copy", file=sys.stderr)
        return EXIT_BUSY
    except MonitorError as exc:
        print(f"error: {_redact(exc)}", file=sys.stderr)
        return EXIT_ERROR
    if as_json:
        return _emit_json({"network": args.network, "polls": polls})
    for p in polls:
        if "error" in p:
            continue
        d = p["discovery"]
        print(f"poll: blocks {d['from']}..{d['to']} (head {d['head']}), "
              f"{d['enqueued']} new deployments, {len(p['results'])} processed, {p['alerts']} alerts")
        for r in p["results"]:
            _print_monitor_result(r)
    return EXIT_OK


def _print_monitor_result(r: dict) -> None:
    status = r["status"]
    label = "COULD NOT ANALYZE (incomplete)" if status == "incomplete" else status
    line = f"  {r['address']}: {label}" + (f" ({r['findings']} findings)" if "findings" in r else "")
    if r.get("suppressed"):
        line += f", {r['suppressed']} suppressed"
    if r.get("tvl_usd") is not None:
        line += f", TVL ~${r['tvl_usd']:,.0f}"
    if r.get("est_max_loss_usd") is not None:
        line += f", est. max loss ~${r['est_max_loss_usd']:,.0f} (rough estimate)"
    print(line)
    for reason in r.get("reasons") or ([r["error"]] if r.get("error") else []):
        print(f"      reason: {reason[:300]}")


def _cmd_monitor_rescan(args: argparse.Namespace, settings: Settings) -> int:
    from .monitor import (Monitor, MonitorConfig, MonitorError, MonitorStore, build_client_from_env,
                          _redact, default_monitor_db_path, rescan)

    as_json = getattr(args, "json", False)
    db = default_monitor_db_path()
    if not db.exists():
        print(f"error: no monitor state at {db}", file=sys.stderr)
        return EXIT_ERROR
    client = None
    if not (args.dry_run or args.queue_only):
        try:
            client = build_client_from_env(args.network)
        except MonitorError as exc:
            print(f"error: {_redact(exc)} (use --queue-only to just requeue)", file=sys.stderr)
            return EXIT_ERROR
    store = MonitorStore(db)  # opening migrates a Phase 18 DB (flags legacy rows)
    try:
        items = rescan(store, args.network, rows=args.row, dry_run=args.dry_run or False)
    finally:
        store.close()
    results: list = []
    if client is not None and items:
        cfg = MonitorConfig(network=args.network, min_severity=args.min_severity,
                            solc_auto_install=not args.no_solc_install)
        emit = (lambda m: print(m, file=sys.stderr)) if as_json else print
        mon = Monitor(cfg, client, emit=emit)
        try:
            results = mon.process_addresses(sorted({i["address"] for i in items}))
        finally:
            mon.store.close()
    if as_json:
        return _emit_json({"network": args.network, "dry_run": bool(args.dry_run),
                           "candidates": items, "results": results})
    verb = "would requeue" if args.dry_run else "requeued"
    print(f"monitor-rescan: {verb} {len(items)} row(s)")
    for i in items:
        tag = "legacy (completion unverified)" if i["legacy"] else i["status"]
        print(f"  row {i['row']} {i['address']}: {tag}")
    for r in results:
        _print_monitor_result(r)
    return EXIT_OK


def _cmd_monitor_status(args: argparse.Namespace, settings: Settings) -> int:
    from .monitor import monitor_status

    st = monitor_status(args.network, show_suppressed=getattr(args, "show_suppressed", False))
    if getattr(args, "json", False):
        return _emit_json(st)
    print(f"network: {st['network']}")
    print(f"cursor: {st['cursor'] if st['cursor'] is not None else 'not started'}")
    print(f"queue: {st['queue'] or 'empty'}")
    print(f"scanned contracts: {st['seen']}")
    sc = st.get("scans") or {}
    if sc:
        print(f"audited (analysis complete): {sc.get('audited', 0)}")
        print(f"could not analyze: {sc.get('could_not_analyze', 0)}")
        if sc.get("legacy_needs_rescan"):
            print(f"legacy rows needing re-scan: {sc['legacy_needs_rescan']} (run: audit.py monitor-rescan)")
    val = st.get("value") or {}
    if val:
        t, a = val.get("today") or {}, val.get("all_time") or {}
        print("confirmed outsider value at risk (ROUGH ESTIMATES; prices as of "
              f"{_fmt_ts(a.get('price_as_of'))}):")
        print(f"  found today: est. ${t.get('value_at_risk_found_usd', 0):,.0f} "
              f"(TVL of contracts with findings ${t.get('tvl_with_findings_usd', 0):,.0f})")
        print(f"  unverified exposure today (unconfirmed privileged-auth): "
              f"est. ${t.get('unverified_exposure_usd', 0):,.0f}")
        print(f"  all time:    est. ${a.get('value_at_risk_found_usd', 0):,.0f}; "
              f"unverified est. ${a.get('unverified_exposure_usd', 0):,.0f}; "
              f"suppressed findings: {a.get('suppressed_findings', 0)}")
        for x in a.get("top") or []:
            loss = x.get("est_max_loss_usd")
            print(f"  #{x['row']} {x['address']} {x.get('contract_name') or ''}: "
                  f"TVL {_fmt_usd(x.get('tvl_usd'))}, est. max loss {_fmt_usd(loss)}"
                  + (" (user funds at risk: honeypot)" if x.get("user_funds_at_risk") else ""))
        for x in a.get("suppressed") or []:
            print(f"  suppressed #{x['row']} {x['address']}: {x['title']} [{x['reason']}: {x['rule']}]")
    print(f"alerts: {st['alerts_total']} total")
    for a in st["recent_alerts"]:
        print(f"  {a.get('ts')} [{a.get('severity')}] {a.get('address')}: {a.get('title')}")
    return EXIT_OK


def _fmt_usd(v: Any) -> str:
    return "unknown" if v is None else f"${float(v):,.0f}"


def _fmt_ts(ts: Any) -> str:
    if not ts:
        return "unknown"
    from datetime import datetime
    from zoneinfo import ZoneInfo

    from .monitor_view import local_tz

    tz = local_tz() if callable(local_tz) else ZoneInfo("America/Detroit")
    return datetime.fromtimestamp(float(ts), tz).strftime("%Y-%m-%d %H:%M %Z")



def _cmd_hunt(args: argparse.Namespace, settings: Settings) -> int:
    import os
    from .hunt import DEFAULT_GROUPS, HuntConfig, Hunter
    from .monitor import MonitorError, build_client_from_env, _redact
    from .supervisor import LockHeld

    if args.interval < 0 or args.max_scan < 0 or args.max_measure < 0 or args.max_sim_per_cycle < 0:
        print("error: --interval/--max-scan/--max-measure/--max-sim-per-cycle must be >= 0", file=sys.stderr)
        return EXIT_ERROR
    if args.min_tvl < 0:
        print("error: --min-tvl must be >= 0", file=sys.stderr)
        return EXIT_ERROR
    cats = tuple(c.strip() for c in (args.categories or "").split(",") if c.strip()) or DEFAULT_GROUPS
    try:
        lo_s, _, hi_s = (args.target_tvl_band or "500000,3000000").partition(",")
        lo, hi = float(lo_s), float(hi_s)
    except ValueError:
        print("error: --target-tvl-band must be LO,HI floats", file=sys.stderr)
        return EXIT_ERROR
    as_json = getattr(args, "json", False)
    try:
        client = build_client_from_env(args.network)
    except MonitorError as exc:
        # No Etherscan key: refresh works; measure/scan can still use a public RPC + Sourcify.
        rpc = os.environ.get("AUDITOR_MONITOR_RPC_URL", "").strip()
        if not rpc and not args.refresh_only:
            # well-known public read-only endpoints (best-effort; may rate-limit)
            rpc = "https://ethereum.publicnode.com"
            print(f"note: {_redact(exc)}; using public RPC (URL redacted) + Sourcify (no Etherscan key)",
                  file=sys.stderr)
        if args.refresh_only and not rpc:
            client = None
            print(f"note: no chain client ({_redact(exc)}); refresh-only mode", file=sys.stderr)
        elif rpc:
            from .monitor import ChainClient, NETWORKS
            client = ChainClient("", NETWORKS[args.network], rpc_url=rpc)
        else:
            print(f"error: {_redact(exc)}", file=sys.stderr)
            return EXIT_ERROR
    slugs = tuple(s.strip() for s in (args.slugs or "").split(",") if s.strip())
    cfg = HuntConfig(network=args.network, min_tvl=args.min_tvl, categories=cats,
                     include_blue_chips=not args.no_blue_chips, max_protocols=args.max_protocols,
                     measure_per_cycle=args.max_measure, scan_per_cycle=args.max_scan,
                     simulate_per_cycle=args.max_sim_per_cycle,
                     interval=args.interval, with_transfers=args.with_transfers,
                     min_severity=args.min_severity, min_value_usd=args.min_value_usd,
                     value_enabled=not args.no_value, solc_auto_install=not args.no_solc_install,
                     target_tvl_low=lo, target_tvl_high=hi, slugs=slugs,
                     vault_discovery=not args.no_vault_discovery,
                     min_holder_usd=float(args.min_holder_usd),
                     pool_discovery_enabled=bool(args.with_pools),
                     pool_lookback_blocks=int(args.pool_lookback))
    emit = (lambda m: print(m, file=sys.stderr)) if as_json else print
    hunter = Hunter(cfg, client, emit=emit)
    if not as_json:
        mode = "refresh-only" if args.refresh_only else ("measure-only" if args.measure_only else
               ("single cycle" if args.once else f"every {args.interval:g}s"))
        print(f"hunt: {args.network}, min TVL ${args.min_tvl:,.0f}, categories={','.join(cats)}, {mode}")
        print("      priority scores are a heuristic hint, not evidence a bug exists")
    try:
        if args.refresh_only:
            stats = hunter.refresh()
            hunter.store.close()
            cycles = [{"refresh": stats}]
        elif args.measure_only:
            cycles = [hunter.cycle(scan_limit=0, measure_limit=args.max_measure)]
            hunter.store.close()
        else:
            cycles = hunter.run(once=bool(args.once), scan_limit=args.max_scan)
    except MonitorError as exc:
        print(f"error: {_redact(exc)}", file=sys.stderr)
        return EXIT_ERROR
    except LockHeld as exc:
        print(f"error: hunt already running (pid {exc.pid}) holds the worker lock; "
              f"not starting a second copy", file=sys.stderr)
        return EXIT_BUSY
    if as_json:
        return _emit_json({"network": args.network, "cycles": cycles})
    for c in cycles:
        if c.get("error"):
            print(f"cycle error: {c['error'][:300]}")
            continue
        r = c.get("refresh") or {}
        print(f"cycle: discovered {r.get('discovered', 0)} addresses from {r.get('protocols', '?')} protocols; "
              f"measured {len(c.get('measured') or [])}; scanned {len(c.get('scanned') or [])}")
        for s in c.get("scanned") or []:
            _print_monitor_result(s)
    return EXIT_OK



def _cmd_exploitable(args: argparse.Namespace, settings: Settings) -> int:
    """List confirmed EXPLOITABLE_REAL_MONEY findings."""
    from auditor.exploitable import (
        BANNER_TEXT,
        ansi_banner_line,
        list_exploitable,
        threshold_usd,
    )

    min_usd = getattr(args, "min_usd", None)
    items = list_exploitable(min_usd=min_usd)
    if getattr(args, "json", False):
        return _emit_json({
            "threshold_usd": threshold_usd(min_usd),
            "banner": BANNER_TEXT,
            "count": len(items),
            "items": items,
        })
    if not items:
        print(f"(none) — no confirmed exploitable findings >= ${threshold_usd(min_usd):,.0f}")
        return EXIT_OK
    print(ansi_banner_line(items))
    for it in items:
        addr = it.get("address") or "?"
        name = it.get("contract_name") or "?"
        take = it.get("takeable_usd")
        take_s = f"${float(take):,.0f}" if take is not None else "?"
        print(
            f"  {name}  {addr}  {take_s}  "
            f"{it.get('finding_type') or it.get('category') or '?'}  "
            f"verified_by={it.get('verified_by')} @ {it.get('verified_at')}"
        )
    return EXIT_OK


def _cmd_hunt_status(args: argparse.Namespace, settings: Settings) -> int:
    import sqlite3
    from .hunt import hunt_overview
    from .monitor import default_monitor_db_path, _table_exists

    db = default_monitor_db_path()
    if not db.exists():
        payload = {"network": args.network, "candidates": [], "counters": {}, "db": "absent"}
        return _emit_json(payload) if getattr(args, "json", False) else (print("hunt: no monitor DB yet") or EXIT_OK)
    conn = sqlite3.connect(str(db))
    conn.row_factory = sqlite3.Row
    # Detroit midnight for "today"
    import datetime
    try:
        from zoneinfo import ZoneInfo
        tz = ZoneInfo("America/Detroit")
    except Exception:
        tz = datetime.timezone(datetime.timedelta(hours=-4))
    now = datetime.datetime.now(tz)
    start = now.replace(hour=0, minute=0, second=0, microsecond=0).timestamp()
    overview = hunt_overview(conn, args.network, since=start, top=args.top, sort=args.sort)
    conn.close()
    if getattr(args, "json", False):
        return _emit_json(overview)
    c = overview["counters"]
    print(f"hunt-status ({args.network}): {c.get('total', 0)} candidates, "
          f"{c.get('scanned', 0)} scanned, {c.get('ready', 0)} ready/new")
    print(f"  hunted value scanned today (est.): ${_fmt_usd_num(c.get('hunted_value_scanned_today_usd'))}  "
          f"TVL scanned today ~${_fmt_usd_num(c.get('hunted_tvl_scanned_today_usd'))}")
    print(f"  note: {c.get('priority_label')}")
    print(f"  by status: {c.get('by_status')}")
    for row in overview["candidates"][: args.top]:
        tvl = row.get("onchain_tvl_usd") if row.get("onchain_tvl_usd") is not None else row.get("llama_tvl_usd")
        print(f"  {row['address']}  {row.get('protocol') or '-':20.20}  "
              f"tvl~${_fmt_usd_num(tvl):>10}  score={row.get('priority_score')}  "
              f"status={row.get('status')}  findings={row.get('findings')}  "
              f"est.loss~${_fmt_usd_num(row.get('est_max_loss_usd'))}")
    return EXIT_OK


def _fmt_usd_num(v) -> str:
    try:
        return f"{float(v):,.0f}"
    except (TypeError, ValueError):
        return "-"


def _cmd_dashboard(args: argparse.Namespace, settings: Settings) -> int:
    """Serve the dashboard. Loopback only in local mode; 0.0.0.0 allowed in public mode."""
    from auditor.mode import is_public, public_limits

    host = (args.host or "").strip()
    if is_public():
        if not host or host in ("127.0.0.1", "localhost", "::1"):
            # Public mode's default bind is all interfaces even if the CLI
            # default is still 127.0.0.1 from argparse.
            host = public_limits()["bind_host"]
    elif host not in ("127.0.0.1", "localhost", "::1"):
        print(
            f"error: refusing to bind to {host!r}; the dashboard is loopback-only "
            "(use 127.0.0.1, localhost or ::1). Set AUDITOR_MODE=public for the demo bind.",
            file=sys.stderr,
        )
        return EXIT_ERROR
    if not (1 <= args.port <= 65535):
        print(f"error: port {args.port} out of range (1-65535)", file=sys.stderr)
        return EXIT_ERROR

    from .dashboard.app import run_dashboard

    print(f"dashboard: http://{host}:{args.port} (Ctrl-C to stop)")
    run_dashboard(host=host, port=args.port, reload=args.reload)
    return EXIT_OK


def _fmt_metric(value: Any) -> str:
    """Metrics render 'n/a' on zero denominators — never a fake 0 or 1."""
    if value is None:
        return "n/a"
    try:
        return f"{float(value):.3f}"
    except (TypeError, ValueError):
        return str(value)


def _cmd_benchmark(args: argparse.Namespace, settings: Settings) -> int:
    from .benchmark import ManifestError, compare_runs, run_benchmark

    if getattr(args, "set_baseline", False) and args.no_save:
        print(
            "error: --set-baseline requires the run to be saved (drop --no-save)",
            file=sys.stderr,
        )
        return EXIT_ERROR

    try:
        run = run_benchmark(
            manifest_path=args.manifest,
            fixtures_dir=args.fixtures,
            db_path=args.db,
            save=not args.no_save,
            limit=args.limit,
        )
    except ManifestError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR

    comparison: dict | None = None
    exit_code = EXIT_OK

    if getattr(args, "baseline", False):
        from . import benchmark_store

        conn = benchmark_store.open_store(args.db)
        try:
            baseline = benchmark_store.get_baseline(conn)
        finally:
            conn.close()
        if baseline is None:
            print(
                "error: no baseline stored (run `audit.py benchmark --set-baseline` first)",
                file=sys.stderr,
            )
            return EXIT_ERROR
        comparison = compare_runs(run, baseline)
        run["comparison"] = comparison
        for reg in comparison.get("regressions") or []:
            print(f"regression: {reg}", file=sys.stderr)
        if not comparison.get("comparable"):
            print(
                "regression: comparison not like-for-like — "
                + str(comparison.get("not_comparable_reason")),
                file=sys.stderr,
            )
            exit_code = EXIT_ERROR
        elif comparison.get("regressions"):
            exit_code = EXIT_ERROR

    if getattr(args, "set_baseline", False):
        from . import benchmark_store

        conn = benchmark_store.open_store(args.db)
        try:
            benchmark_store.mark_baseline(
                conn, run["run_id"], replace=bool(getattr(args, "force", False))
            )
        except benchmark_store.BaselineError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return EXIT_ERROR
        finally:
            conn.close()
        run["is_baseline"] = True

    if getattr(args, "json", False):
        _emit_json(run)
        return exit_code

    totals = run["totals"]
    overall = run["metrics"]["overall"]
    print(
        f"benchmark: run {run['run_id']} {run['status']} "
        f"in {totals['duration_seconds']}s"
    )
    tc = run.get("toolchain") or {}
    tools = " | ".join(
        f"{k}={v.get('version') or 'unavailable'}"
        for k, v in tc.items()
        if isinstance(v, dict)
    )
    if tools:
        print(f"toolchain: {tools}")
    print(
        f"verdicts: TP={overall['tp']} FP={overall['fp']} "
        f"FN={overall['fn']} TN={overall['tn']}"
    )
    print(
        f"metrics: precision={_fmt_metric(overall['precision'])} "
        f"recall={_fmt_metric(overall['recall'])} f1={_fmt_metric(overall['f1'])}"
    )
    print(
        "excluded: "
        + " ".join(
            f"{k}={overall.get(k, 0)}"
            for k in (
                "blocked", "not_evaluable", "skipped",
                "pipeline_failure", "harness_error",
            )
        )
        + f" metadata_gaps={overall.get('metadata_gaps', 0)}"
        f" evidence_insufficient={overall.get('evidence_insufficient', 0)}"
        f" other_findings={overall.get('other_findings', 0)}"
    )
    print("categories:")
    for name, m in run["metrics"]["categories"].items():
        print(
            f"  {name:18} tp={m['tp']} fp={m['fp']} fn={m['fn']} tn={m['tn']} "
            f"P={_fmt_metric(m['precision'])} R={_fmt_metric(m['recall'])} "
            f"F1={_fmt_metric(m['f1'])}"
        )
    print("fixtures:")
    for r in run["results"]:
        verdict = r.get("verdict") or "-"
        matched = f" matched={r['matched_check']}" if r.get("matched_check") else ""
        reason = f" ({str(r.get('reason') or '')[:90]})" if r.get("reason") else ""
        print(
            f"  {r['fixture_id']:12} {r['status']:16} verdict={verdict:4} "
            f"others={len(r.get('other_findings') or [])}{matched}{reason}"
        )
    if args.no_save:
        print("store: not saved (--no-save)")
    else:
        from . import benchmark_store
        print(f"store: {benchmark_store.default_benchmark_db_path()}")

    if comparison is not None:
        print(
            f"baseline: {comparison['baseline_run_id']} "
            f"comparable={str(comparison['comparable']).lower()}"
        )
        if not comparison["comparable"]:
            print(f"baseline: {comparison['not_comparable_reason']}")
        else:
            for change in comparison["verdict_changes"]:
                marker = "REGRESSION " if change["regression"] else ""
                print(
                    f"  {marker}{change['fixture_id']}: "
                    f"{change['from']} -> {change['to']}"
                )
            deltas = " ".join(
                f"{k}={v:+.4f}" if v is not None else f"{k}=n/a"
                for k, v in comparison["metric_deltas"].items()
            )
            print(f"  metric deltas: {deltas}")
            print(f"  regressions: {len(comparison['regressions'])}")
    if getattr(args, "set_baseline", False):
        print(f"baseline: run {run['run_id']} stored as baseline")
    return exit_code



def _cmd_simulate(args: argparse.Namespace, settings: Settings) -> int:
    """Phase 22: local fork simulation (invariants / oracle / trust)."""
    import os
    from .simulate import foundry_versions, simulate_address, simulate_hunt_top
    from .monitor import MonitorError, build_client_from_env, _redact

    vers = foundry_versions()
    if not vers.get("anvil") or not vers.get("cast"):
        print("error: anvil/cast not found — install Foundry with foundryup "
              "(https://book.getfoundry.sh)", file=sys.stderr)
        return EXIT_ERROR
    print(f"simulate: foundry forge={vers.get('forge')}")
    print(f"          anvil={vers.get('anvil')}")
    print(f"          cast={vers.get('cast')}")
    print("          fork is local-only (127.0.0.1); nothing is broadcast")
    try:
        client = build_client_from_env(args.network)
    except MonitorError as exc:
        rpc = os.environ.get("AUDITOR_MONITOR_RPC_URL", "").strip() or "https://ethereum.publicnode.com"
        from .monitor import ChainClient, NETWORKS
        client = ChainClient(os.environ.get("ETHERSCAN_API_KEY", "").strip(),
                             NETWORKS[args.network], rpc_url=rpc)
        print(f"note: {_redact(exc)}; using rpc={_redact(rpc)}", file=sys.stderr)
    # Prefer proxy-following source for trust/oracle text.
    try:
        from .hunt import HuntClient
        if not isinstance(client, HuntClient) and hasattr(client, "_etherscan"):
            client = HuntClient(client.api_key, client.chain_id, rpc_url=client.rpc_url,
                                http=client.http, sleep=client.sleep,
                                min_interval=client.min_interval, timeout=client.timeout)
    except Exception:
        pass
    fork = (args.fork_url or "").strip() or None
    results = []
    as_json = getattr(args, "json", False)
    emit = (lambda m: print(m, file=sys.stderr)) if as_json else print
    if args.hunt_top and args.hunt_top > 0:
        results.extend(simulate_hunt_top(n=args.hunt_top, network=args.network,
                                         client=client, emit=emit))
    for addr in args.address or []:
        results.append(simulate_address(addr, client=client, network=args.network,
                                        fork_url=fork, emit=emit))
    if not results:
        print("error: pass --address 0x… and/or --hunt-top N", file=sys.stderr)
        return EXIT_ERROR
    if as_json:
        return _emit_json({"versions": vers, "results": results})
    for r in results:
        print(f"\n=== {r.get('address')} ({r.get('status')}) run_id={r.get('run_id')} ===")
        if r.get("error"):
            print(f"  error: {r['error']}")
        for inv in r.get("invariants") or []:
            exp = inv.get("exposure_usd")
            exp_s = f" exposure~${exp:,.0f}" if isinstance(exp, (int, float)) else ""
            print(f"  invariant [{inv.get('status')}] {inv.get('name')}: {inv.get('detail')}{exp_s}")
            if inv.get("status") == "fail" and inv.get("guidance"):
                print(f"    fix: {inv['guidance']}")
        ora = r.get("oracles") or {}
        print(f"  oracles: kinds={ora.get('kinds')} flags={ora.get('flags')}")
        for g in ora.get("guidance") or []:
            print(f"    guidance: {g}")
        for s in ora.get("spot_move_estimates") or []:
            if s.get("detail"):
                print(f"    spot: {s.get('pool','')[:12]}… {s['detail']}")
        trust = r.get("trust") or {}
        print(f"  trust map: {trust.get('count', 0)} external addresses")
        for n in (trust.get("nodes") or [])[:8]:
            print(f"    {n.get('address')} proxy={n.get('proxy_kind')} owner_type={n.get('owner_type')}")
    return EXIT_OK


def _print_watchdog_report(report: dict, *, headline: str = "watchdog status") -> None:
    print(f"{headline} (network={report.get('network')}, "
          f"stale threshold={float(report.get('stale_after', 0)):g}s)")
    if report.get("db_error"):
        print(f"  monitor DB unavailable: {report['db_error']}")
    for kind, detail in (report.get("workers") or {}).items():
        state = detail.get("state")
        line = f"  {kind}: {state}"
        if detail.get("heartbeat_age_s") is not None:
            line += f" (heartbeat {detail['heartbeat_age_s']:g}s ago)"
        if detail.get("pid") is not None:
            alive = "alive" if detail.get("pid_alive") else "not-alive"
            line += f", pid {detail['pid']} ({alive})"
        if detail.get("heartbeat"):
            hb_status = detail["heartbeat"].get("status")
            if hb_status:
                line += f", last status {hb_status}"
        print(line)
    wd = report.get("watchdog")
    if wd is not None:
        print(f"  watchdog: last heartbeat {wd.get('heartbeat_age_s', '?'):g}s ago "
              f"(status {str((wd.get('heartbeat') or {}).get('status') or '?')})")
    else:
        print("  watchdog: no heartbeat recorded (never started)")
    lock = report.get("watchdog_lock") or {}
    print(f"  watchdog instance lock: {lock.get('status', 'unknown')}")


def _worker_argv(cmdline: str, root: Path) -> list:
    """shlex-split a worker command; resolve a leading relative path from root."""
    import shlex

    parts = shlex.split(cmdline)
    if not parts:
        raise ValueError("empty worker command")
    first = Path(parts[0])
    if not first.is_absolute():
        candidate = root / first
        if candidate.is_file():
            parts[0] = str(candidate)
    return parts


def _cmd_watchdog(args: argparse.Namespace, settings: Settings) -> int:
    from .monitor import default_monitor_db_path
    from .supervisor import (LockHeld, Supervisor, SupervisorSettings, WorkerSpec,
                             evaluate_workers, worker_check_exit)

    cmd = getattr(args, "watchdog_cmd", None)
    db_path = default_monitor_db_path()
    network = args.network
    as_json = bool(getattr(args, "json", False))
    emit = (lambda m: print(m, file=sys.stderr)) if as_json else print
    stale_after = float(getattr(args, "stale_threshold", 600.0) or 600.0)
    root = Path(__file__).resolve().parent.parent

    if cmd == "status":
        report = evaluate_workers(db_path, network=network, stale_after=stale_after)
        if as_json:
            return _emit_json(report)
        _print_watchdog_report(report)
        return EXIT_OK

    if cmd == "check":
        report = evaluate_workers(db_path, network=network, stale_after=stale_after)
        code = worker_check_exit(report, expect_running=bool(getattr(args, "expect_running", False)))
        if as_json:
            _emit_json(report)
        else:
            _print_watchdog_report(report, headline="watchdog check")
        return code

    if cmd == "run":
        cfg = args
        for name, minimum in (("--poll-interval", cfg.poll_interval),
                              ("--restart-backoff-base", cfg.restart_backoff_base),
                              ("--restart-backoff-cap", cfg.restart_backoff_cap),
                              ("--child-grace", cfg.child_grace),
                              ("--stable-reset-seconds", cfg.stable_reset_seconds)):
            if minimum < 0:
                print(f"error: {name} must be >= 0", file=sys.stderr)
                return EXIT_ERROR
        if cfg.max_restarts < 1 or stale_after <= 0:
            print("error: --max-restarts must be >= 1 and --stale-threshold > 0", file=sys.stderr)
            return EXIT_ERROR
        if cfg.stale_recovery_seconds < 0 or cfg.stale_observations < 2:
            print("error: --stale-recovery-seconds must be >= 0 and --stale-observations >= 2",
                  file=sys.stderr)
            return EXIT_ERROR
        sup_settings = SupervisorSettings(
            restart_backoff_base=cfg.restart_backoff_base,
            restart_backoff_cap=cfg.restart_backoff_cap,
            stable_reset_seconds=cfg.stable_reset_seconds,
            max_restarts=cfg.max_restarts,
            child_grace_seconds=cfg.child_grace,
            poll_interval=cfg.poll_interval,
            stale_recovery=cfg.stale_recovery != "off",
            stale_recovery_seconds=cfg.stale_recovery_seconds,
            stale_min_observations=cfg.stale_observations,
        )
        try:
            specs = [WorkerSpec(name="monitor", network=network,
                                argv=_worker_argv(cfg.monitor_cmd, root))]
        except ValueError as exc:
            print(f"error: --monitor-cmd: {exc}", file=sys.stderr)
            return EXIT_ERROR
        if not cfg.no_hunt:
            try:
                specs.append(WorkerSpec(name="hunt", network=network,
                                        argv=_worker_argv(cfg.hunt_cmd, root)))
            except ValueError as exc:
                print(f"error: --hunt-cmd: {exc}", file=sys.stderr)
                return EXIT_ERROR
        sup = Supervisor(db_path, specs, settings=sup_settings, emit=emit)
        if not as_json:
            watched = ",".join(spec.name for spec in specs)
            recovery = ("wedge recovery on" if cfg.stale_recovery != "off" else "wedge recovery off")
            print(f"watchdog: supervising {watched} (network {network}); Ctrl-C to stop; "
                  f"restart backoff {cfg.restart_backoff_base:g}s→{cfg.restart_backoff_cap:g}s, "
                  f"max {cfg.max_restarts} consecutive, {recovery}")
        try:
            code = sup.run(once=bool(cfg.once))
        except LockHeld as exc:
            print(f"error: another watchdog is running (pid {exc.pid}); "
                  f"only one supervisor instance is allowed", file=sys.stderr)
            return EXIT_BUSY
        if code == EXIT_BUSY:
            # sup.run() prints the reason itself (emit → stderr with --json).
            print("error: another watchdog is running; only one supervisor instance "
                  "is allowed per state directory", file=sys.stderr)
            return EXIT_BUSY
        if as_json:
            return _emit_json({"network": network, "exit_code": code,
                               "summary": sup.summary(),
                               "note": "workers exited via graceful stop; overrides are recorded in each child"})
        for name, snap in sup.summary()["children"].items():
            print(f"  {name}: state={snap['state']} attempts={snap['attempts']} "
                  f"last_rc={snap['last_rc']} consecutive_failures={snap['consecutive_failures']}")
        return EXIT_OK if code == 0 else code

    print("error: unknown watchdog subcommand", file=sys.stderr)
    return EXIT_ERROR


def _cmd_watch(args: argparse.Namespace, settings: Settings) -> int:
    from .monitor import MonitorStore, ChainClient, default_monitor_db_path, NETWORKS
    from .watch import add_watch, list_watches, remove_watch, check_watches
    import os
    store = MonitorStore(default_monitor_db_path())
    cmd = getattr(args, "watch_cmd", None)
    if cmd == "add":
        related = (getattr(args, "related", "") or "").strip() or None
        row = add_watch(
            store, args.network, args.address, note=getattr(args, "note", "") or "",
            origin="cli", related_address=related,
            min_value_usd=float(getattr(args, "min_value_usd", 1000) or 1000),
        )
        print(f"watch: added {row['address']} (min ${row['min_value_usd']:,.0f})"
              + (f" related={related}" if related else ""))
        store.close()
        return EXIT_OK
    if cmd == "list":
        rows = list_watches(store, args.network)
        if not rows:
            print("watch: (empty)")
        for r in rows:
            measured = r.get("last_measured_usd")
            print(f"{r['address']}  min=${float(r['min_value_usd'] or 0):,.0f}  "
                  f"measured={measured}  note={r.get('note') or ''}  "
                  f"related={r.get('related_address') or ''}")
        store.close()
        return EXIT_OK
    if cmd == "remove":
        ok = remove_watch(store, args.network, args.address)
        print("watch: removed" if ok else "watch: not found")
        store.close()
        return EXIT_OK if ok else EXIT_ERROR
    if cmd == "check":
        rpc = (os.environ.get("AUDITOR_MONITOR_RPC_URL") or "").strip() or None
        api_key = (os.environ.get("ETHERSCAN_API_KEY") or "").strip()
        chain_id = NETWORKS.get(args.network, 1)
        client = ChainClient(api_key, chain_id, rpc_url=rpc)
        summary = check_watches(
            store, client, network=args.network,
            default_min_value_usd=float(getattr(args, "min_value_usd", None) or 1000),
        )
        print(f"watch: checked={summary['checked']} alerts={summary['alerts']}")
        for r in summary.get("results") or []:
            print(f"  {r.get('address')} measured_usd={r.get('measured_usd')} "
                  f"alerted={r.get('alerted')} err={r.get('error')}")
        store.close()
        return EXIT_OK
    store.close()
    print("error: unknown watch subcommand", file=sys.stderr)
    return EXIT_ERROR



_COMMANDS = {  # Phase 20 adds hunt / hunt-status
    "status": _cmd_status,
    "tools": _cmd_tools,
    "ollama": _cmd_ollama,
    "disk": _cmd_disk,
    "modules": _cmd_modules,
    "validate-address": _cmd_validate_address,
    "scan": _cmd_scan,
    "scan-address": _cmd_scan_address,
    "dashboard": _cmd_dashboard,
    "monitor": _cmd_monitor,
    "monitor-status": _cmd_monitor_status,
    "hunt": _cmd_hunt,
    "hunt-status": _cmd_hunt_status,
    "exploitable": _cmd_exploitable,
    "simulate": _cmd_simulate,
    "watch": _cmd_watch,
    "watchdog": _cmd_watchdog,
    "monitor-rescan": _cmd_monitor_rescan,
    "benchmark": _cmd_benchmark,
}


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)
    _configure_logging(getattr(args, "verbose", False))

    try:
        settings = load_settings(args.config)
    except Exception as exc:  # noqa: BLE001 - config errors must be visible, not fatal
        print(f"configuration error: {type(exc).__name__}: {exc}", file=sys.stderr)
        return EXIT_ERROR

    if not args.command:
        parser.print_help()
        return EXIT_OK

    handler = _COMMANDS.get(args.command)
    if handler is None:
        print(f"unknown command: {args.command}", file=sys.stderr)
        return EXIT_ERROR

    from auditor.mode import PUBLIC_BLOCKED_COMMANDS, is_public
    if is_public() and args.command in PUBLIC_BLOCKED_COMMANDS:
        print(
            f"error: {args.command} is disabled in public demo mode "
            "(paste/upload via `audit.py dashboard` only)",
            file=sys.stderr,
        )
        return EXIT_ERROR

    try:
        return handler(args, settings)
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return 130
    except Exception as exc:  # noqa: BLE001 - surface, never silently swallow
        log.debug("command failed", exc_info=True)
        print(f"error: {type(exc).__name__}: {exc}", file=sys.stderr)
        return EXIT_ERROR
