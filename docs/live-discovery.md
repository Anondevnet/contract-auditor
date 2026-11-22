# Live Ethereum discovery

The Hunt dashboard can run either a bounded **Run one cycle** or a continuous
read-only discovery service. **Start continuous** supervises two workers:

- The monitor follows Ethereum `newHeads` over WebSocket when configured,
  records a durable block cursor and block hashes, backfills missed ranges, and
  rewinds the cursor to a common ancestor when it detects a reorganization.
- The hunt worker refreshes registry and pool feeds, measures candidates,
  rechecks high-value proxies for implementation changes, and periodically
  scans eligible verified contracts. It also requeues up to five already
  scanned high-exposure contracts per cycle after the rescan interval, which
  defaults to six hours and can be changed with `AUDITOR_HUNT_RESCAN_SECONDS`.
- Source-unverified candidates stay in the hunt queue and receive bounded
  retries with exponential backoff (15 minutes up to 24 hours). Scans rotate
  by last scan attempt within the preferred exposure band so a small set of
  high-value rows cannot occupy every cycle. The default cycle scans up to ten
  contracts and measures up to twenty; dashboard workers measure up to forty.
- After static analysis, the hunt can run one local-fork invariant simulation
  per cycle. Each run records its fork block and separates `fail` leads from
  `review` states such as cooldown withdrawals. These are review leads, not
  confirmed exploitable vulnerabilities. Set `--max-sim-per-cycle 0` to turn
  off this stage.
- State reads within a scan are pinned to an RPC `safe` block when available,
  then `finalized`, then a numbered current head. The chosen block and tag are
  saved with each scan; feeds without RPC state access keep their existing
  provider behavior.

Progress and recent events are stored in the existing monitor database in
`dashboard_worker_state`. The Hunt page shows worker heartbeats, the indexed
block, queue depth, candidate counts, exact source matches, latest hunt
counters, disk deferrals, and recent worker output. **Stop** asks workers to
finish their current bounded read-only stage.

## RPC configuration

The existing environment setup supplies `ETHERSCAN_API_KEY` and may supply the
read-only `ETH_RPC_URL`. If the RPC URL uses HTTPS, the monitor derives a WSS
URL by changing its scheme for the `newHeads` subscription. Set
`AUDITOR_MONITOR_WS_URL` to an explicit provider WSS endpoint when its WebSocket
URL differs. Unencrypted `ws://` is accepted only for loopback hosts.

With an RPC endpoint, the monitor also attempts bounded Geth-compatible
`debug_traceBlockByNumber` call traces to discover contracts created through
factories. Providers without this optional method are detected and the worker
continues with top-level contract creation transactions. Set
`AUDITOR_TRACE_INTERNAL_CREATIONS=0` to disable the trace requests.

Source providers and market feeds remain candidate discovery and provenance
inputs. Only the local Sourcify identity check is labelled an exact source
match; an explorer listing or market listing alone does not establish that
the retrieved source is the exact deployed code.

Holdings / TVL are exposure context. Per-finding impact amounts are heuristic
model estimates grouped by potential harm mechanism (for example, withdrawal
availability, bad debt, oracle risk, or accounting). They are not realized
loss or funds an unprivileged user can take. The confirmed outsider-loss
headline remains gated on explicit exploitability evidence.

Live discovery does not send transactions or deploy contracts. Static analyzer
findings remain leads; a confirmed exploit alert still requires validation and
reproducible evidence.
