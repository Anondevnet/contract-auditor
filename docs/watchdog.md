# Standalone worker watchdog (P1 step 1)

The monitor and hunt workers already exist as bounded CLI processes
(`audit.py monitor`, `audit.py hunt`) and are usually launched through
`scripts/run_monitor.sh` / `scripts/run_hunt.sh`. Previously the only
supervisor was the dashboard process (`auditor/discovery_service.py`): close
the tab, and workers eventually die with nobody watching. This phase adds a
dashboard-independent supervisor plus reliable worker-heartbeat reporting.

## What was added

| Piece | File | Behavior |
|---|---|---|
| Watchdog process | `auditor/supervisor.py` (`audit.py watchdog run`) | spawns the existing workers, restarts them after unexpected exits with bounded exponential backoff (default 5s→300s), gives up after 20 consecutive failures of the same worker — crashes *and* rapid repeat clean exits (logged + heartbeat marked `degraded`), stops children cleanly on SIGINT/SIGTERM, and recovers a wedged worker whose heartbeat goes stale (see the recovery section) |
| Per-worker lock | `.worker-{monitor,hunt}-<network>.lock` next to `monitor_state.db` | kernel `flock` held for the entire worker run; released automatically when the process exits or dies. A worker that finds its lock held exits with code 7 |
| Worker self-heartbeat | `dashboard_worker_state` rows `monitor-<network>` / `hunt-<network>` in the monitor DB | written at loop start, after every poll/cycle, and on stop (additive rows; the dashboard's own `ethereum-discovery` row is untouched) |
| Instance lock | `.watchdog.lock` | exactly one watchdog per state directory; a second one exits with code 7 |
| CLI status | `audit.py watchdog status [--json]` | worker states from kernel locks + heartbeats |
| CLI check | `audit.py watchdog check [--json]` | exit 0 fresh, 1 any worker stale (or missing with `--expect-running`), 2 monitor DB unusable |
| Launcher | `scripts/run_watchdog.sh` | same Keychain/PATH bootstrap as `run_monitor.sh`, then `exec python3 audit.py watchdog run …` |
| launchd template | `docs/launchd/com.contract-auditor.watchdog.plist` | RunAtLoad + KeepAlive (crash/failed-exit restarts); **never installed or loaded by the tool** |

## States (watchdog status / check)

* `running` — the worker lock is held (kernel truth: a held lock implies a live
  process on this machine).
* `stale` — lock released and the last heartbeat is older than
  `--stale-threshold` (default 600 s).
* `stopped` — lock released, heartbeat fresh: the worker exited within the
  threshold (normal stop).
* `never_started` — no heartbeat row at all and no lock held.
* `db_unavailable` — the monitor DB cannot be read (corruption/permissions).
  Separate from all of the above and reflected in the check exit code 2.

## Duplicate protection (why two copies can never run)

1. The worker itself acquires the lock inside `Monitor.run()` / `Hunter.run()`
   — this covers every spawn path (manual script, dashboard, watchdog) and
   also plain double-invocation of `scripts/run_monitor.sh`.
2. The dashboard's discovery service probes the same locks before spawning
   (`_worker_lock_held`) and refuses to launch a worker that is running
   elsewhere; a spawned worker that still raced and lost exits with code 7 and
   the dashboard records `running_elsewhere` instead of a failure.
3. The watchdog probes the lock before each spawn and supports takeover: when
   the holder goes away, the watchdog starts its own copy (single attempt, no
   stampede). The watchdog instance lock guarantees one supervisor.
4. Workers started with `--once`, `--refresh-only`, and `--measure-only`, and
   `monitor-rescan` jobs, are interactive single operations and do not fight
   the persistent worker for the lock (only `Monitor.run`/`Hunter.run` loop
   entry takes it; the `--once` flag still enters `run()` and thus holds it
   for the single poll/cycle).

**Never delete the lock files** (`.worker-*.lock`, `.watchdog.lock`) while the
corresponding process is running: the kernel lock lives on the open file, so
removing the path lets the next process create a fresh file and acquire it —
two copies could run even though the directory looks clean. Stop the processes
first (SIGTERM the watchdog or `launchctl bootout`), or just let them exit.

## Running it

### Manual (foreground / nohup)

```sh
scripts/run_watchdog.sh                      # supervise monitor + hunt, defaults
scripts/run_watchdog.sh --no-hunt            # monitor only
scripts/run_watchdog.sh --poll-interval 5    # extra args pass through to the watchdog
nohup scripts/run_watchdog.sh >> reports/watchdog.run.log 2>&1 &
```

Useful flags (`audit.py watchdog run`; see `--help` for all):

* `--monitor-cmd` / `--hunt-cmd` — worker command line (shlex-split, default
  the existing run scripts). The scripts use `exec`, so the tracked PID is the
  worker's own Python process.
* `--once` — one supervision round, then stop children and exit (smoke test).
* `--restart-backoff-base/--restart-backoff-cap/--max-restarts/
  --stable-reset-seconds/--child-grace` — restart policy and shutdown grace.
* `audit.py watchdog check --stale-threshold 600` is for cron/monitoring
  one-shot probes (exit 0 fresh, 1 stale, 2 monitor DB unusable).

### launchd (manual, user steps only)

1. Replace `__PROJECT_DIR__` in
   `docs/launchd/com.contract-auditor.watchdog.plist` with the absolute
   project path.
2. Copy to `~/Library/LaunchAgents/`.
3. Bootstrap (user-invoked, com.contract-auditor.watchdog):
   ```sh
   launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/com.contract-auditor.watchdog.plist
   ```
4. Verify:
   ```sh
   launchctl list | grep com.contract-auditor.watchdog
   python3 audit.py watchdog status
   tail -f reports/watchdog.{out,err}.log
   python3 audit.py watchdog check; echo exit=$?
   ```
5. Remove / stop:
   ```sh
   launchctl bootout gui/$(id -u)/com.contract-auditor.watchdog
   ```

Clean shutdown expected by launchd: `bootout` sends SIGTERM; the watchdog
SIGINT→SIGTERM→SIGKILLs its children within `--child-grace`-bounded windows
(default 10 s) and writes a final heartbeat row (`watchdog` → `stopped`).
On system restart launchd reruns it at login (`RunAtLoad`).

### After the restart limit (status shows `degraded`)

After `--max-restarts` consecutive failures of one worker — crashes, or rapid
repeat clean exits — the watchdog keeps running, marks itself `degraded`, and
stops spawning that worker until the watchdog is restarted:

1. Find and fix the cause first: the worker's own error lands in
   `reports/watchdog.err.log`; running `scripts/run_monitor.sh --interval 60`
   by hand shows it directly (a missing Keychain key is the usual suspect).
2. Restart the watchdog to clear the failure streak:
   * launchd: `launchctl kickstart -k gui/$(id -u)/com.contract-auditor.watchdog`
   * manual: stop with Ctrl-C/SIGTERM and run `scripts/run_watchdog.sh` again.

A worker that stayed alive at least `--stable-reset-seconds` (600 s default)
since it started resets the failure streak automatically on every exit, so
long-lived workers never hit this limit. Restart policy notes: a worker that
is stopped by the watchdog itself (`--once`, SIGTERM/Ctrl-C) is recorded as
`stopped`, never restarted; a worker killed by someone else (direct SIGINT,
reboot) is restarted at the base delay.

## Wedged-worker recovery (heartbeat policy, P1 step 2)

A worker that keeps running but stops making progress (hung RPC call, stuck
subprocess, wedged loop) used to look "running" forever. The watchdog now
stops and restarts such a worker — but only under conservative conditions, so
slow RPC calls, legitimate long scan stages, or brief database contention can
never cause a false restart:

* the worker's own heartbeat row (`dashboard_worker_state`, refreshed by the
  worker itself) must be older than the kind's threshold, and the stale window
  must be *sustained*;
* recovery requires ≥ `--stale-observations` (default 3) distinct stale
  supervision rounds (default cadence 2 s) — a single late beat can never
  trigger anything;
* the heartbeat row must have been written by exactly the watchdog's own
  child (payload pid) **and** the per-worker lock must still be held by that
  same pid — a previous run's beat row, a foreign holder, a released lock, or
  any mismatch resets the check; foreign workers are never signalled;
* a heartbeat read error (database contention/corruption) resets the check —
  fail-safe: no decision, no kill.

Auto thresholds (`--stale-recovery-seconds` to override, `--stale-recovery
off` to disable): **monitor 900 s** — normal heartbeat gaps are 60–100 s and
the longest legal poll (≤20 blocks + ≤5 contract scans at 15 s call timeouts)
stays under ~7 min; **hunt 1800 s** — the hunt cycle now writes heartbeat
milestones between stages (`discover`, `retrieve_source`,
`verify_deployment`, `prioritize`, `fork_validation`) and every 60 s while
waiting between cycles, so even slow stages stay far below it.

When everything qualifies, the watchdog runs its *bounded* ladder against the
child — SIGINT → wait `--child-grace` (10 s) → SIGTERM → wait 2 s → SIGKILL,
escalating across supervision rounds without blocking them — and schedules a
restart with the normal exponential backoff. The reap is labelled
`recovered` (not `crashed`) in the watchdog heartbeat/events. Each recovery
episode counts toward `--max-restarts`; the failure streak is reset only by a
run that stayed healthy longer than `--stable-reset-seconds` *before the
wedge began*, so a worker that keeps wedging in short order eventually ends
in `degraded` exactly like a persistent crasher. User-directed stops
(`--once`, SIGTERM/Ctrl-C, `bootout`) and `running_elsewhere` workers are
unaffected and never restarted by this policy.

## Heartbeat schema

Existing table (unchanged shape):
`dashboard_worker_state(worker TEXT PRIMARY KEY, payload_json TEXT NOT NULL,
updated_at REAL NOT NULL)` in the monitor DB. New rows only:

* `watchdog` — `{status, pid, started_at, children:{name:{state,pid,attempts,…}}}`
* `monitor-<network>` — `{status, pid, once, interval, polls, last_poll{…}}`
* `hunt-<network>` — `{status, pid, once, interval, cycles}`

Nothing else reads the rows today; they are for operators and future checks.

## Limits and risks (honest)

* macOS/Linux only (POSIX `flock`, `killpg`); not Windows.
* A worker exiting 0 on its own (e.g. killed directly by SIGINT outside the
  watchdog) is restarted at the base delay. Rapid repeat clean exits count
  toward the restart limit (backoff, then `degraded`), so a worker that exits
  0 instantly over and over cannot spin forever. A watchdog-requested stop
  (`--once`, SIGTERM/Ctrl-C) is never counted and never restarted.
* A wedged worker — alive but no longer writing heartbeats — is stopped and
  restarted only under the conservative recovery policy above (sustained
  staleness, repeated observations, lock+pid ownership proof). Until the
  threshold is reached it still shows `running (stale heartbeat)` in
  `watchdog check`; nothing is signalled on a single late beat.
* Keychain: the watchdog inherits `run_*` secrets only when started by a user
  session (manual or launchd `gui/` domain). A root/system daemon would not
  reach the user's Keychain, hence the `gui/$(id -u)` domain.
* Free-tier Etherscan rate limits still apply to the underlying workers; the
  workers already back off individually.
* The launchd plist is a template with no secrets and is never installed or
  loaded by any command in this repository.
* This phase doesn't commit anything, prune databases, or change dashboards.
