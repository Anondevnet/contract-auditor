# Real-World Vulnerability Research — Phase 15 Step 3

Date: 2026-10-14 · Worktree branch `phase15-real-world-validation` @
`b868be83` · **Research + acquisition deliverable. No scans, benchmarks,
tests, fuzzers, deployments, or transactions were run. No compiler was
installed or switched. No database was opened for writes.**

## 0. Scope, classification scales, and method

Five candidates were researched (2–4 requested). Two passed full
verification and are vendored with manifest entries (both
`evaluable: false` — see §6); one is partially verified and documented
only; two were rejected.

**Two distinct classification scales are used below. Do not conflate them:**

- **Task confidence** (this step's own scale):
  - **T1** — fully verified: independent report retrieved + pinned
    retrievable source + vulnerable semantics confirmed by reading the
    source. Fit for a manifest entry.
  - **T2** — partially verified: report and source exist, but at least
    one linkage (deployed-version match, license, judging status) is
    unresolved.
  - **T3** — rejected: circular ground truth, unavailable source, or the
    exploited mechanism is outside the accepted detector taxonomy.
- **Fixture tier** (`ground_truth_tier`, per `benchmarks/realworld/README.md`
  §3): T1 official audit of the exact vendored version · T2 public
  exploit/post-mortem + verified source · T3 safe example with documented
  remediation.

Verification procedure followed README §4a–4e for each surviving
candidate: (a) retrieve report, archive URL + retrieval date; (b)
retrieve source matching the described code, record SHA-256; (c) confirm
the vulnerable behavior by reading the source — labels are fixed by
semantics, never by detector output (PROTOCOL §1); (d) assess
compilability on the local toolchain or record `na_reason`; (e) record
license.

## 1. Results summary

| # | Candidate | Task class | Fixture tier | Category | Manifest entry | Status |
|---|---|---|---|---|---|---|
| 1 | Besu `DefaultOnChainPrivacyGroupManagementContract` — `tx.origin` owner checks | **T1** | **T1** | `access_control` | `RW-001` (`evaluable: false`) | Vendored |
| 2 | The DAO — `splitDAO` call-order reentrancy | **T1** | **T2** | `reentrancy` | `RW-002` (`evaluable: false`) | Vendored |
| 3 | Akropolis Delphi — `SavingsModule` reentrancy + share-price manipulation | T2 | unresolved | (would be `reentrancy`) | none | Research-only |
| 4 | Parity multi-sig — library `initWallet`/`kill()` selfdestruct freeze | T3 | — | — | none | Rejected |
| 5 | Forsage (`tandil-dev/forsage-audit`) | T3 | — | — | none | Rejected |

No safe (`expected_label: safe`) counterpart exists yet for either
vulnerable fixture; metrics from a future run would therefore be
recall-side evidence only for their categories (README §4.4).

## 2. RW-001 — Besu tx.origin group-management phishing (task T1 / fixture T1)

**Project/version.** Pinned source at merge commit
`78c458b321903815d2cbc085890bb2fe97da629f` of `hyperledger/besu` (repo
now redirects to `besu-eth/besu`; raw URLs at the pinned commit still
resolve), introduced by PR #1288 "On chain group management api changes"
(merged 2020-08-19). File:
`privacy-contracts/src/main/solidity/DefaultOnChainPrivacyGroupManagementContract.sol`
(+ its relative import `OnChainPrivacyGroupManagementInterface.sol`),
`pragma solidity ^0.5.9`, Apache-2.0.

**Vulnerability.** Every mutating group-management function
(`lock`, `unlock`, `addParticipants`, `removeParticipant`) gates
authorization with

```solidity
require(tx.origin == _owner, "Origin not the owner.");
```

and `canUpgrade()` returns `tx.origin == _owner`. A phishing contract
invoked by the owner passes the check, so group membership/lock state
can be changed without the owner's intent.

**Ground truth.** Immunefi report **#37577 [BC-Insight] "`tx.origin`
Usage in Group Management Contract Allows Phishing Attack for
Unauthorized Actions**" — `https://reports.immunefi.com/ethereum-protocol-or-attackathon/37577-bc-insight-tx.origin-usage-in-group-management-contract-allows-phishing-attack-for-unauthorize`
(submitted Dec 9th 2024, 16:37:44 UTC, by @cheems; page retrieved
2026-10-14). Report body quotes the same PR and mechanism verbatim:

> "In this PR (https://github.com/hyperledger/besu/pull/1288), the
> intention was to ensure that only the creator's account could
> add/remove members and update the management contract. However, using
> tx.origin to validate ownership exposes the contract to phishing
> attacks, where a malicious contract can call the vulnerable contract
> on behalf of the attacker..."

**Source verification.** Both files fetched from the pinned commit and
hashed (§7). The `require(tx.origin == _owner, ...)` lines occur at
source lines 22, 28, 38, 47; `_owner = tx.origin` at line 36. Semantics
confirmed by reading; label fixed before any tool was consulted.

**Persistence (context only, not vendored).** 2020-09-01 `2bfbeefc`
bumped the pragma to 0.6; 2024-10-15 `f0e9f409` renamed the file to
`DefaultFlexiblePrivacyGroupManagementContract.sol` (same `tx.origin`
pattern); 2025-05-28 `9ebf356e` (#8369) deleted the private-tx
management features entirely.

**License.** Apache-2.0 (LICENSE text at the pinned commit vendored as
`LICENSE.apache-2.0`).

**Unresolved.** Immunefi judging status (validated/resolved/paid) not
determinable from the public report page; irrelevant to ground-truth
strength (report text + pinned source + PR agree). The contract targets
Besu private networks, so there is no mainnet Etherscan deployment to
cross-check — the product source itself is the authoritative artifact.

## 3. RW-002 — The DAO splitDAO call-order reentrancy (task T1 / fixture T2)

**Project/version.** Etherscan verified source of the deployed contract
`0xBB9bc244D798123fDe783fCc1C72d3Bb8C189413`
(`https://etherscan.io/address/0xbb9bc244d798123fde783fcc1c72d3bb8c189413#code`,
retrieved 2026-10-14 by extracting the inline verified-source data;
Compiler `v0.3.1-2016-04-12-3ad5e82`, Contract Name `DAO`). Etherscan
lists 4 source files for the deployment; file 1 ("DAO", the flattened
Token + TokenCreation + DAO source, 1236 lines) is vendored; files 2–4
were not retrieved.

**Vulnerability.** `splitDAO` violates checks-effects-interactions:

```solidity
if (p.splitData[0].newDAO.createTokenProxy.value(fundsToBeMoved)(msg.sender) == false)
    throw;
withdrawRewardFor(msg.sender);
totalSupply -= balances[msg.sender];
balances[msg.sender] = 0;
```

ETH leaves the contract before `balances[msg.sender]` is zeroed, so a
malicious fallback re-enters `splitDAO` recursively and drains the
contract.

**Ground truth.** Emin Gün Sirer, "Analysis of the DAO Exploit",
Hacking Distributed, 2016-06-18
(`https://hackingdistributed.com/2016/06/18/analysis-of-the-dao-exploit/`)
— root cause is the call-order (re-entrancy via the ETH transfer inside
`createTokenProxy`) and the exploit path is the recursive `splitDAO`
call. Direct HTTP to hackingdistributed.com failed from this
environment on 2026-10-14 (connection blocked); content was corroborated
via search-index retrieval the same day and multiple secondary citations
(CoinGeek, Crypto Briefing, onchainattack.org) quoting the same
analysis. The official repository `TheDAO/DAO-1.0` (LGPL-3.0, HEAD
`ceb4e8c66857485dbbb130bbcf190c95f3bbd666`, 2016-07-30) provides a
cross-reference: its `DAO.sol` `splitDAO` function region is
**byte-identical** (14948 chars) to the Etherscan-extracted source,
despite overall file-layout differences (flattening).

**Source verification.** Extraction checked for HTML-entity leftovers
(none), ends with a closing brace, and the critical `splitDAO` body was
diffed against the official repository (exact match). SHA-256 in §7.
Label fixed by semantics + report, per PROTOCOL §1.

**License.** In-file header: GNU LGPL v3 "or (at your option) any later
version" → `LGPL-3.0-or-later`; the official repo's LICENSE (LGPL-3.0
text) is vendored as `LICENSE.LGPL-3.0-dao`. LGPL copyleft obligations
reference GPL-3.0 (upstream ships only the LGPL text; the vendored copy
mirrors upstream packaging; attribution retained in-file).

**Unresolved.** Etherscan files 2–4 (Token, TokenCreation,
ManagedAccount companions) not vendored; the `ManagedAccount.payOut`
drain path described in secondary accounts is not present in the
vendored file and is not part of this fixture's expected behavior.
Deployed compiler (`v0.3.1-2016-04-12-3ad5e82`) is not obtainable
locally (§6). Fixture tier is **T2** (public exploit analysis + verified
source), while task confidence is T1 (fully verified for inclusion).

## 4. Akropolis Delphi — research-only (task T2)

**Candidate.** `SavingsModule.deposit`/`withdraw` in
`kaonone/delphi` (formerly `akropolisio/delphi`), branch `release-1.0`,
`SavingsModule.sol`, `pragma solidity ^0.5.12`
(SHA-256 `f4b0c33ffeab8c76f16b28b2e22e3cb1dd74387be812118db4a4ac86a0084c55`).
Exploit class: reentrancy via a malicious ERC223 token transfer callback
plus fake-token donation inflating the share price (Nov 2020 incident).

**Ground truth located.** PeckShield, "Akropolis Incident Root Cause
Analysis", 2020-11-13 (`https://peckshield.medium.com/akropolis-incident-root-cause-analysis-c11ee59e05d4`);
official Akropolis post-mortem "SUSD and yCurve pool Incident Report",
2020-11-13 (`https://medium.com/akropolis/susd-and-ycurve-pool-incident-report-f6cad5e6488`
— existence corroborated by OAK's bibliography and multiple secondary
outlets quoting it; direct fetch blocked by Cloudflare on 2026-10-14).

**Why not vendored / no manifest entry (fails README §4b and §4e).**
1. **No source-to-deployment match.** The mainnet proxy
   (`0x73fC3038B4cD8FfD07482b92a52Ea806505e5748`, from
   `deployment_mainnet.md`) now points at a **post-fix** implementation
   (`0x9ba1Cf4659bB5617A6Aa86Bf1503848Bee9888A9`, verified source has
   `nonReentrant` + `require(isAllTokensRegistered(...))`, solc 0.5.17,
   2301 lines, SHA-256
   `1fdaeddde4f118d173e2438b18de4d68baf7e8d1a76549ee3b225fbbee21a91b`).
   The exact pre-fix deployed bytes were upgraded in place and are not
   retrievable; the repo source cannot be proven to match what ran.
2. **No license.** `kaonone/delphi` states no license (GitHub API
   `license: null`, no LICENSE file) — redistribution of source into
   this repository is unresolved.

Held as a T2 research candidate for a later tranche if either gap closes.

## 5. Rejected candidates (task T3)

**Parity multi-sig library selfdestruct (Nov 2017).** Primary sources:
Parity Technologies "Security Alert" (2017-11-07) and "A Postmortem on
the Parity Multi-Sig Library Self-Destruct" (2017-11-15); GitHub issue
`paritytech/parity#6995` (2017-11-06, devops199, "anyone can kill your
contract"). Mechanism: the shared `WalletLibrary` was never initialized,
so anyone called `initWallet` to seize ownership and then `kill()` →
`selfdestruct`, freezing 587 wallets / 513,774 ETH. Rejected because:
(1) the source repository `paritytech/parity-wallet` returns 404 —
source cannot be retrieved or hash-matched; (2) the mechanism is outside
the accepted detector taxonomy: reading installed Slither 0.11.6
`detectors/functions/suicidal.py` (2026-10-14) shows `suicidal` fires
only on a `selfdestruct`-calling function that is **not** protected —
Parity's `kill()` is owner-guarded (it passes only after ownership is
seized, which the detector cannot model), and the actual bug
(unprotected initializer on a never-initialized library) has no
corresponding accepted slug; the July 2017 incident (public
function-visibility + fixed-address library delegatecall) likewise does
not match `controlled-delegatecall` (target not attacker-controlled).
(3) solc 0.4-era source is off the local toolchain. Reporting it as a
fixture would be unrepresentable, not merely unevaluable.

**Forsage (`tandil-dev/forsage-audit`).** The repository's findings are
verbatim Slither detector output (`reentrancy-unlimited-gas`,
`solc-version`, ...). Tool-derived labels cannot serve as independent
ground truth for the same tool family — circular, violating PROTOCOL §1.

## 6. Toolchain, anti-gaming, and evaluability notes

- **Local toolchain (fixed).** `/opt/homebrew/bin/solc` = 0.5.8
  (PROTOCOL-fixed). `solc-select` artifacts for 0.5.8 and 0.8.37 exist
  on disk; installing or switching compilers was out of scope for this
  step and was not done.
- **Both vendored fixtures are `evaluable: false` by design.** RW-001:
  `pragma ^0.5.9` needs solc ≥ 0.5.9 (README §4d) and the source is
  multi-file (relative import; README §6 first-tranche default). RW-002:
  deployed compiler is the solc 0.3.1-era
  `v0.3.1-2016-04-12-3ad5e82` (README §4d) and the deployment is
  multi-file (README §6). **Neither is excluded because a detector
  failed** — that would be a false negative (PROTOCOL §5). Detector
  channels exist: `tx-origin` was observed on live pipeline output in
  the Phase 14 probe (PROTOCOL §2) and the installed detector
  (`detectors/statements/tx_origin.py`, read 2026-10-14) fires on
  `require`/`if` nodes reading `tx.origin` without `msg.sender` — which
  RW-001's checks are; `reentrancy-*` likewise appeared in the probe.
- **Wording note for the Step 4 reviewer.** PROTOCOL §5 lists two
  `evaluable: false` grounds oriented at the synthetic corpus (no
  detector class / detector inoperable on solc 0.5.8); the real-world
  README §4d/§6 deliberately extends this to pragma and multi-file
  constraints for the real-world tranche. Both readings are
  anti-gaming-compatible (they concern toolchain operability, never
  detector outcomes). This interpretation should be confirmed before
  the first real-world run.
- **`accepted_checks` provenance.** RW-001: `["tx-origin"]` (slug
  observed on the access-control family per PROTOCOL §2; the six
  reentrancy slugs of the synthetic manifest were used for RW-002:
  `reentrancy-eth`, `reentrancy-no-eth`, `reentrancy-balance`,
  `reentrancy-events`, `reentrancy-benign`,
  `reentrancy-unlimited-gas`). `expected_contract`/`expected_function`
  were fixed from the reports and source reading; no detector output
  was consulted (none was run).
- **Anti-gaming.** Labels were fixed by source semantics + independent
  reports before any manifest was written; no fixture exists because a
  detector fired; no `expected_*` value was adjusted toward tool
  behavior; `evaluable: false` entries can never contribute TP/TN.

## 7. Vendored artifacts (SHA-256)

| File | SHA-256 | Origin |
|---|---|---|
| `RW-001-group-mgmt-txorigin.sol` | `e9f8cc31df24ba511bce7caeb678902002e09facd38e0b788843bd667ec4e6d0` | raw pinned `78c458b3` hyperledger/besu (verbatim) |
| `OnChainPrivacyGroupManagementInterface.sol` | `0393d524e1c3be3577fc7f15439a89b1eab06bb9a636b2644c69cf86c68bd1cf` | raw pinned `78c458b3` hyperledger/besu (verbatim; import target of RW-001) |
| `RW-002-dao-split-reentrancy.sol` | `40163dd800c3b5cc85229693687d74bcbce24bdb6161cdf9eb37ef43f3308cba` | Etherscan verified source, file 1 of 4, deployed `0xBB9bc244...9413` (verbatim; entity-unescape checked) |
| `LICENSE.apache-2.0` | `b40930bbcf80744c86c46a12bc9da056641d722716c378f5659b9e555ef833e1` | raw LICENSE at pinned `78c458b3` hyperledger/besu |
| `LICENSE.LGPL-3.0-dao` | `ea8af5e789cb2d4e9b10bce3874982ade163b749b6bfbdb32e2df21c4d106de1` | raw LICENSE at `ceb4e8c6` TheDAO/DAO-1.0 |

No source file was semantically edited (comments-only redaction was not
needed). The RW-001 fixture keeps its original `import
"./OnChainPrivacyGroupManagementInterface.sol"` line; the dependency is
vendored under its original filename in the same directory.

## 8. Isolation proof and next step

- `git status` shows only untracked additions under
  `benchmarks/realworld/` and `benchmarks/realworld_manifest.json`; no
  tracked file (including `benchmarks/manifest.json`) was modified; no
  commit was created.
- Database MD-5s unchanged across the whole step: worktree
  `benchmark_store.db` `61b445e2731327ca5d37cb947a502504`, production
  `audit_scan_history.db` `34fd1543e4a33397cf5b07202c43d598` (matches
  the PLAN.md recorded value), production `benchmark_store.db`
  `61b445e2731327ca5d37cb947a502504`. No scan/benchmark/test/fuzzer was
  executed.
- **Recommended next step (Phase 15 Step 4, on approval):** resolve the
  §6 evaluator-wording note; then run the real-world benchmark under
  the README §7 isolation environment
  (`AUDITOR_BENCHMARK_DB=/tmp/phase15-realworld-bench.db`, `--no-save`,
  no `--set-baseline`), reporting `not_evaluable` outcomes for RW-001/
  RW-002 separately and never folded into the synthetic table. Optional
  follow-ups: obtain a solc ≥ 0.5.9 toolchain decision from the user
  (would make RW-001 possibly evaluable), and continue Akropolis source
  archaeology for a later tranche.

## 9. Step 4 evaluability review (2026-10-14, read-only; supersedes §6's open wording note)

Review of the installed detector inventory, the vendored sources, and the
harness code paths (`auditor/benchmark.py` `validate_manifest` /
`evaluate_fixture` / `run_fixture` / `run_benchmark`,
`auditor/analysis/slither_runner.py`, `auditor/cli.py` benchmark
subcommand). No scan, compile probe, or benchmark was executed in this
review.

### 9.1 Per-fixture answers

| Question | RW-001 (Besu tx.origin) | RW-002 (DAO splitDAO) |
|---|---|---|
| 1. Detector class exists in installed Slither 0.11.6? | **Yes** — `detectors/statements/tx_origin.py` (`ARGUMENT = "tx-origin"`), surfaced by the pipeline's access-control analyzer (slug listed in its severity map, `auditor/analysis/access_control.py`). | **Yes** — all six accepted slugs exist under `detectors/reentrancy/` (`reentrancy-eth`, `reentrancy-no-eth`, `reentrancy-balance`, `reentrancy-events`, `reentrancy-benign`, `reentrancy-unlimited-gas`); the reentrancy analyzer filters checks starting with `reentrancy`. |
| 2. Analyzable with the existing local toolchain (no install/switch/upgrade)? | **No** — the only compiler is solc 0.5.8 (PATH); the vendored source declares `pragma solidity ^0.5.9`, which solc rejects by its deterministic version-gate (documented compiler behavior; a direct compile probe was deliberately not run under this step's restrictions and would be observed only in the run's tool-status/reconciliation if approved). The relative import is *not* the blocker: its dependency is vendored alongside in the same directory. | **No** — two independent reasons: (a) deployed compiler was the solc 0.3.1-era `v0.3.1-2016-04-12-3ad5e82` and the file uses 0.3-era syntax removed by 0.5.0 (e.g. `throw` in `splitDAO`); (b) Etherscan file 1 is not self-contained (references the `ManagedAccount` contract, which lives in a companion file that was not retrieved). |
| 3. Genuinely evaluable under the existing protocol? | **No — must remain `evaluable: false`.** | **No — must remain `evaluable: false`.** |
| 4. Supporting rule | **PROTOCOL §5 condition 2** ("detector inoperable on the local toolchain … provably cannot trigger because a required compiler/tool input does not exist in the only available offline toolchain, verified at the tool-mechanics level") — the AST input the detector requires cannot be produced by solc 0.5.8 for a `^0.5.9` source. Independently: realworld README §4d (record exact reason under `na_reason`) and §6 (multi-file first-tranche default). | **PROTOCOL §5 condition 2** (same tool-mechanics ground: no compiler exists locally that can produce an AST for this era/source set). Independently: README §4d and §6 (multi-file). |
| 5. Meaningful detection result if run? | **No — `not_evaluable` only.** `evaluate_fixture` (`auditor/benchmark.py:664-670`) checks `evaluable is False` before any scoring or error handling: the row records `status: "not_evaluable"` with the `na_reason`, any observations, and reconciliation bookkeeping; it is excluded from TP/FP/FN/TN (PROTOCOL §4) and can never count as TN. Compile-failure noise, if any, is absorbed by this path and never becomes a verdict. | Same, identically. |

Anti-gaming cross-check: neither `evaluable: false` ground is "the
detector failed to fire" — labels and `accepted_checks` remain fixed by
source semantics and the Phase 14 probe (PROTOCOL §5 final paragraph).

### 9.2 Resolution of the §6 wording note

§6 flagged a possible tension between PROTOCOL §5's two synthetic-era
grounds and realworld README §4d/§6. On review the tension dissolves:
§5 condition 2 is written at tool-mechanics level (compiler input
absence), which is exactly the operative fact for both fixtures, so the
real-world entries are PROTOCOL-conformant without any interpretation
stretch; README §6's multi-file default is an *additional*,
stricter first-tranche convention that points the same way. No
protocol change and no manifest change are needed. Residual honesty
item: the deterministic compiler facts above were not re-probed with a
compile invocation in this step; an approved run would record them in
tool status/reconciliation without affecting scores.

### 9.3 What an isolated run would and would not prove

- Harness behavior on this manifest: `run_fixture`
  (`auditor/benchmark.py:801`) invokes the shared pipeline for every
  fixture whose file exists (it does not pre-skip `evaluable: false`),
  so both RW files would be handed to Slither once; expected rows:
  `not_evaluable: 2`, TP/FP/FN/TN all 0, run status `completed`
  (PROTOCOL §4). That is **integration evidence** (manifest accepted by
  `load_manifest`/`validate_manifest` — already verified by direct
  schema validation on 2026-10-14 — pipeline isolation, not-evaluable
  accounting, JSON emission) and **zero detection evidence**.
- Isolation: `--no-save` means `run_benchmark` never opens any database
  (`save=False` short-circuits `open_store`); `open_store` additionally
  hard-rejects the production history filename
  (`benchmark_store.py:54-57`). `AUDITOR_HISTORY_DB` /
  `AUDITOR_BENCHMARK_DB` overrides exist and are honored
  (`scan_history.py:46`, `benchmark_store.py:45`); the analyzers invoked
  by `_collect_findings` contain no database writes (verified by search
  of `auditor/analysis/*.py`).
- Operational detail: `--fixtures benchmarks/realworld` is **required**
  — the default fixture directory is `manifest.parent / "fixtures"`
  (`benchmark.py:934-935`), i.e. `benchmarks/fixtures`, which is the
  synthetic corpus.

### 9.4 Proposed command (requires approval; not run in this step)

```bash
AUDITOR_HISTORY_DB=/tmp/phase15-history.db \
AUDITOR_BENCHMARK_DB=/tmp/phase15-realworld-bench.db \
python3 audit.py benchmark \
  --manifest benchmarks/realworld_manifest.json \
  --fixtures benchmarks/realworld \
  --no-save --json > /tmp/phase15-realworld-run.json
```

Temporary paths: history `/tmp/phase15-history.db`, benchmark store
`/tmp/phase15-realworld-bench.db` (both fresh; with `--no-save` no
database is created or written — the env vars are belt-and-suspenders
per README §7). No `--set-baseline`, no `--force`, no production paths.

### 9.5 Isolated benchmark execution results (2026-10-14)

The §9.4 command was approved and executed once (exit code 0). Output
artifact: `/tmp/phase15-realworld-run.json`.

- Run `B-4b53053a2d4f`, status `completed`, duration ≈ 1.33 s;
  manifest `benchmarks/realworld_manifest.json`, fixtures dir
  `benchmarks/realworld`.
- Totals: 2 fixtures — `not_evaluable: 2`; `passed`/`failed`/`blocked`/
  `skipped`/`pipeline_failure`/`harness_error` all 0; TP = FP = FN = TN
  = 0 (precision/recall/F1 null — no scored fixtures).
- Reconciliation: 2 fixtures, 0 discrepancies; raw tool status `failed`
  for both (Slither was invoked on each file, compilation failed on the
  installed toolchain, 0 raw detectors, 0 surfaced findings). Each row
  carries its `na_reason`; verdict `null` for both.
- Toolchain snapshot recorded in the run: Slither 0.11.6, solc
  `0.5.8+commit.23d335f2.Darwin.appleclang`, Forge 1.8.3.
- The compile failures are the observed tool-mechanics confirmation of
  PROTOCOL §5 condition 2 that §9.2 flagged as not-yet-probed — now
  observed in run data, still with zero effect on any score.

**Interpretation: harness/integration evidence only, not
vulnerability-detection evidence.** Both fixtures remain
`evaluable: false`; neither is a TP, FP, FN, or TN (PROTOCOL §4). The
benchmark command exited successfully, but Slither could not analyze
either fixture because compilation failed with the installed toolchain.
No labels, accepted checks, evaluability flags, scoring logic, or
manifests were changed.

**Isolation re-verified after the run:** `/tmp/phase15-history.db` and
`/tmp/phase15-realworld-bench.db` were not created (`--no-save` →
`open_store` never called); production database hashes unchanged
(`audit_scan_history.db` `34fd1543e4a33397cf5b07202c43d598`,
`benchmark_store.db` `61b445e2731327ca5d37cb947a502504`); synthetic
`benchmarks/manifest.json` SHA-256 unchanged
(`0d610f0abd3fc4418e639968eac6195738349b802abc9fdd373c8aa987985ad0`);
`git status` shows only the untracked `benchmarks/realworld/` and
`benchmarks/realworld_manifest.json` paths; no commit was created.

### 10. RW-003 Search Conclusion (2026-10-14)

**Conclusion: no verified RW-003 candidate was found under the
current requirements.** This section closes the RW-003 research
phase (Step 6A). It is documentation-only: no further candidate
acquisition was attempted in this step, no file outside this
document was edited, and no scan, benchmark, test, compiler probe,
tool install, network download, database write, or commit occurred.

#### 10.1 Gates applied

A candidate had to satisfy **all** of the following to become an
RW-003 fixture (realworld README §4a–4e; PROTOCOL §5 tool-mechanics
clause):

1. **Solidity 0.5.8 compatibility** — the declared `pragma` must
   admit a compiler in the fixed offline set (only solc `0.5.8` on
   PATH for the 0.5.x series; also 0.8.36/0.8.37). A pragma such as
   `^0.5.9`, `^0.5.16`, exact `0.5.10`, `=0.6.10`, `^0.4.x`, or
   `>=0.7` is out of range.
2. **Self-contained source** — a single `.sol` file with no
   relative/external imports the solo `choose_target` path cannot
   resolve, and no Foundry multi-file project.
3. **Accepted detector slug** — the vulnerable semantics must map
   to an installed Slither 0.11.6 detector family
   (`reentrancy-*`, `tx-origin`, `suicidal`, `unchecked-*`,
   `controlled-delegatecall`, `*-send-eth`), not merely to a
   generic “security issue.”
4. **Independent vulnerability evidence** — a real incident
   (Immunefi / post-mortem / audit of the exact version) fixing
   labels by source semantics, never by tool output (PROTOCOL §1).
   Synthetic/educational examples without an incident do not
   qualify.
5. **Reproducible source identity** — a pinned git commit,
   Etherscan-verified source, or archived URL with a recorded
   SHA-256 of the vendored bytes.
6. **Compatible licensing** — an identifiable license permitting
   redistribution of the vendored source.

#### 10.2 Representative rejection reasons (Step 6A)

The search examined famous and audit-report-sourced candidates
spanning tx.origin, reentrancy, and unprotected-selfdestruct
classes. Every candidate failed at least one gate. Representative
failures (task-confidence scale from §0, **not** the fixture
`ground_truth_tier`):

| Candidate class | Task class | Why rejected |
|---|---|---|
| Parity Multisig, SpankChain, FairWin, SmartBugs “real” reentrancy entries | T3 | Compiler window: `^0.4.x` (or earlier); no solc in the offline set can parse them |
| Opyn Convexity (Aug 2020, ~$371K double-exercise) | T1 incident / out of window | `pragma solidity 0.5.10` (exact) — needs solc 0.5.10, not 0.5.8; Gamma successor is `=0.6.10` |
| RW-001 near-miss, 0x v3 Coordinator mixins, GRO 2021-06 (L-01/L-17) | T1/T2 | `^0.5.9` / `^0.5.16` / `>=0.6.0 <0.7.0` — all above 0.5.8 |
| Rari Capital cEther reentrancy (~$80M), Lendf.Me/dForce (~$25M), Cheese Bank, Cream, Hundred Finance, BurgerSwap, Visor, Grim | T1 incidents | Multi-file Compound/Uniswap/Bezier forks (`^0.5.16` or `0.7`/`0.8`); solo single-file analysis cannot resolve the import graph |
| Parity `kill()` / Parity library selfdestruct freeze | T3 | `kill()` is `onlyowner`-guarded after `initWallet` — not Slither `suicidal` (unprotected selfdestruct); real bug is re-initialization, outside taxonomy |
| DODO “Unauthorized Self-Destruct” (PeckShield 2020-16), 3FMutual, InstaDApp, Aave v2 | checklist rows | PeckShield reports list the item; result is “Not found” — no finding, no ground truth |
| FairWin invite-code front-run / `remedy()` forgery | T3 | Real ~$125M incident but mechanism is front-running / auth bypass, not an accepted slug; also `^0.4.24` |
| ETH_RUNE tx.origin (Jul 2021, ~$76K) | T1 incident / out of window | `pragma solidity 0.7.6` |
| Uniswap V1 ERC777 reentrancy | T1 incident | Vyper, not Solidity |
| Academic `ReentrantContract` (`^0.5.0`), SmartBugs synthetic 0.5.x rows, Solidity-docs “Fund” example | synthetic | Would compile on 0.5.8 but have no independent incident — ground-truth gate fails (README §4d intent) |
| G_GAME / other honeypots using `require(msg.sender == tx.origin)` | T3 | EOA anti-contract check, not auth phishing; intentional trap, no accident ground truth |
| UUPS/proxy selfdestruct (iosiro / Raymond Yeh 2021) | T3 | 0.8.x OZ4 multi-contract proxy pattern; no single-file extract with stable identity |

**Structural observation (limited to this search):** every famous
exploited single-contract vulnerability class encountered falls
outside the solc-0.5.8 window — either pre-0.5.x (`^0.4.x`),
multi-file Compound/Uniswap forks from the `^0.5.16`+ era, exact
0.5.10, 0.6+/0.7/0.8.x, or non-Solidity. Single-file educational
examples that **would** parse on 0.5.8 lack independent incident
evidence. This is an observation about the candidates examined, not
a proof that no compatible real-world contract exists anywhere.

#### 10.3 Status of existing fixtures and prior run

- **RW-001** and **RW-002** remain unchanged, `evaluable: false`,
  with their original `na_reason` text (§9.1–§9.2). They are
  negative controls only: the tool-mechanics branch of PROTOCOL §5
  (condition 2) excludes them from scoring, never a detector result.
- **§9.5 isolated run** `B-4b53053a2d4f` remains the only execution
  record: 2 `not_evaluable`, TP = FP = FN = TN = 0, no scored
  fixtures, zero reconciliation discrepancies. It is
  **harness/integration evidence only** and provides **no evidence
  of detection accuracy** for the auditor’s detectors on real-world
  code.

#### 10.4 Scope limitation

This conclusion is limited to the candidates and evidence examined
in Steps 3–6A under the constraints then in force (websearch-only
research, no raw source fetch, fixed offline toolchain). It must
not be read as “no compatible real-world vulnerable contract
exists.”

#### 10.5 Future paths (require separate approval; not started)

Any of the following would need explicit approval before
implementation; none was authorized in this step:

1. **Authorize an additional compiler** (e.g. solc 0.5.10, 0.5.16,
   or 0.7.6 via solc-select) so an already-researched incident
   (Opyn Convexity, ETH_RUNE, Rari cEther) can be vendored and
   evaluated under PROTOCOL §5 condition 1 instead of condition 2.
2. **Authorize a carefully documented multi-file fixture design**
   (flattening, vendored import trees, or a project-level
   `choose_target` mode) with explicit integrity rules so source
   identity remains reproducible.
3. **Continue research under the same constraints** (same gates,
   same offline toolchain) with a broader candidate sweep or
   different vulnerability classes.

Until one of those paths is approved and executed, Phase 15’s
real-world validation story is: two vetted `evaluable: false`
negative controls, zero scored fixtures, and a closed RW-003 search.

### 11. Post-§10 developments: Opyn/MISO verification and RW-001 re-evaluation (2026-10-14)

Documentation written **before** the evaluation run of this step; no
detector output from that run had been produced or consulted when the
decisions below were made. No tracked application code, detector,
scoring logic, or PROTOCOL/README file was edited.

#### 11.1 Candidate 1 — Opyn Convexity: license BLOCKED

Fetched `LICENSE` from `opynfinance/ConvexityProtocol` (branch `dev`,
and the archived fork): proprietary — grants only permission to
"privately study, review, and analyze the Software" and states
licensees "shall not modify, transfer, assign, share, or sub-license
the Software or any derivative works." Flattening the multi-file
source (OptionsContract.sol + OpenZeppelin imports) would create a
forbidden derivative; vendoring a copy into a distributable project
risks "share". **Not vendored; no bytes added to the worktree.**
Ground-truth facts (post-mortems, deployed address, incident class)
remain usable as research references only. Gate 6 (licensing) fails.

#### 11.2 Candidate 2 — SushiSwap MISO: compiler BLOCKED

- License: GPL-3.0 with Apache-2.0 §7 additional terms (LICENSE
  fetched and read) — would have passed gate 6.
- Detector class: `delegatecall-loop` (payable `batch()` looping
  `address(this).delegatecall`) — present in installed Slither 0.11.6
  (detector row 21, High impact).
- **Gate 1 fails:** `contracts/Utils/BoringBatchable.sol` declares
  `pragma solidity 0.6.12;` (exact) and imports `./BoringERC20.sol`.
  No installed compiler (0.5.8, 0.5.10, 0.8.36, 0.8.37) satisfies
  exact 0.6.12; installing 0.6.12 is a new dependency requiring
  separate authorization. Multi-file import is a secondary obstacle.
  **Not vendored.**

#### 11.3 RW-001 re-evaluation: condition 2 refuted → `evaluable: true`

RW-001's `na_reason` (Step 3) rested on two tool-mechanics claims:
(a) pragma `^0.5.9` needs solc ≥ 0.5.9, absent from the offline set;
(b) the source is multi-file (sibling relative import, vendored
alongside). Step 9B (authorized) installed solc **0.5.10** without
touching the global version. Under PROTOCOL §5, `evaluable: false`
is permitted **only** when no detector class exists (condition 1) or
a required compiler/tool input does not exist (condition 2):

- `tx-origin` exists in Slither 0.11.6 and in the pipeline
  (`ACCESS_CONTROL_CHECKS`, `access_control.py` severity map) →
  condition 1 never applied.
- **Compile-only probe (this step, before any scan):** invoking the
  0.5.10 artifact directly from the fixture directory (the pipeline's
  cwd/target shape) on `RW-001-group-mgmt-txorigin.sol` exited 0 with
  zero diagnostics and emitted bytecode for
  `DefaultOnChainPrivacyGroupManagementContract`, resolving the
  sibling import `OnChainPrivacyGroupManagementInterface.sol`
  (both files declare `pragma ^0.5.9`, satisfied by 0.5.10).
  Condition 2 is therefore **refuted** for RW-001.

PROTOCOL §5 requires an operable fixture not to be marked
`evaluable: false`; keeping the flag would itself violate the
anti-gaming rule. RW-001 was flipped `false → true` on compile
evidence alone. `expected_label`, `expected_contract`,
`expected_function`, `accepted_checks`, `source_sha256`, provenance,
and ground-truth references are byte-identical to Step 3 — no label
or scoring input was touched, and no detector output informed the
decision. `na_reason` was removed (it is only required/meaningful
for `evaluable: false`); its historical text is preserved in §9.1–§9.2
above. The manifest `toolchain.solc` note was updated to match
reality. RW-002 is unchanged: a solc v0.3.1-2016-04-12-era compiler
remains absent (0.5.10 does not reach 2016 source), so its
condition-2 exclusion still holds.

#### 11.4 Status at the moment of this writing

- RW-001: `evaluable: true`, toolchain verified, **evaluation run
  pending** (isolated PATH → 0.5.10 symlink, temp DB env vars,
  `--no-save`, JSON to /tmp). Ground truth was fixed at acquisition
  (Step 3, §2) — months-equivalent before any scored run.
- RW-002: `evaluable: false`, unchanged (condition 2 still holds).
- Candidates consumed: 1 Opyn (license), 2 MISO (compiler). The
  RW-003 acquisition path is superseded for now by the RW-001
  promotion; if RW-001's run does not yield a scored TP, candidate 3
  remains available.

### 12. Isolated evaluation runs and integrity verification (2026-10-14)

Two benchmark attempts were made with the same command shape as §9.4,
plus process-local solc-0.5.10 isolation (a symlink dir
`/tmp/phase15-solc0510-bin/solc` → `~/.solc-select/artifacts/solc-0.5.10/solc-0.5.10`
prepended to `PATH`; `solc-select use` never run; global
`global-version` remained `0.5.8` throughout).

#### 12.1 Attempt 1 — isolation defect (harness debugging only)

Run `B-18ad8a659a35` (artifact `/tmp/phase15-realworld-run-2.json`).
RW-001 came back `blocked`: slither still compiled with solc 0.5.8.
Root cause found and documented: invoking `python3` through the pyenv
**shim** prepends `~/.pyenv/versions/3.11.9/bin` (which itself contains
solc 0.5.8) ahead of the isolation dir, and the same applies to the
`slither` shim. This attempt produced no detector results for RW-001
(compile failed before detectors) and is recorded solely as
isolation-debugging evidence.

#### 12.2 Attempt 2 — valid evaluation run

Fixed by invoking the interpreter at its absolute path
(`~/.pyenv/versions/3.11.9/bin/python3`) with
`PATH=<isolation-dir>:<versions-bin>:$PATH`, so
`shutil.which("solc")` resolves to the 0.5.10 artifact and
`shutil.which("slither")` resolves to the non-shim entry point
(shebang `python3.11`, absolute — no PATH rewrite).

**Run `B-e817970f01b0`** (artifact `/tmp/phase15-realworld-run-3.json`),
status `completed`, duration 0.92 s, `notes: []`, corpus fingerprint
`4cd740f82503f487`, toolchain fingerprint `acb05055a908252b`.
Run-toolchain snapshot recorded **solc 0.5.10+commit.5a6ea5b1 at
`/tmp/phase15-solc0510-bin/solc`** and slither 0.11.6 — isolation
confirmed from inside the run itself.

| Fixture | status | verdict | notes |
|---|---|---|---|
| RW-001 | `passed` | **TP** | matched check `tx-origin`; finding `F-1d4eb97f25e9` “Access control issue in DefaultOnChainPrivacyGroupManagementContract.lock”; contract/function = `DefaultOnChainPrivacyGroupManagementContract` / `lock` (exact expected match); FACT evidence (1), lines 20–24, excerpt quotes `require(tx.origin == _owner…)` |
| RW-002 | `not_evaluable` | — | condition 2 unchanged (solc v0.3.1-2016-04-12 era absent) |

- Totals: `passed 1`, `not_evaluable 1`; **TP 1, FP 0, FN 0, TN 0**;
  precision = recall = F1 = **1.0** over the **1 scored fixture**
  (access_control family: evaluable 1, tp 1; reentrancy family: 0 scored).
- Raw Slither: 15 detectors — `tx-origin` fired **4×** (lock, unlock,
  addParticipants, removeParticipant — exactly the four mutating
  functions named in the ground truth), all 4 surfaced; plus
  `controlled-array-length` (High) and `boolean-cst` surfaced as
  other-channel findings (recorded `channel_mismatch`/`wrong_location`,
  never scored against the fixture).
- Reconciliation (§9.3, consistency-only): 1 discrepancy —
  `RW-001:external-function` absent from surfaced findings.
  Characterized: `external-function` has impact **Optimization**;
  `slither_generic` surfaces only High/Medium/Low impacts (documented
  scope) while `reconcile_raw` exempts only impact `Informational`, so
  Optimization-class raw hits fall through the exemption. It is not on
  the expected channel, does not affect the §3 matcher, and per §9.3
  “a `missing` entry alone is not an FN”. No scoring code was changed.

#### 12.3 Integrity verification after the run

| Anchor | Expected | Observed |
|---|---|---|
| `benchmarks/manifest.json` SHA-256 | `0d610f0abd3fc4418e639968eac6195738349b802abc9fdd373c8aa987985ad0` | unchanged |
| RW-001 source SHA-256 | `e9f8cc31df24ba511bce7caeb678902002e09facd38e0b788843bd667ec4e6d0` | unchanged |
| RW-002 source SHA-256 | `40163dd800c3b5cc85229693687d74bcbce24bdb6161cdf9eb37ef43f3308cba` | unchanged |
| RW-001 interface SHA-256 | `0393d524e1c3be3577fc7f15439a89b1eab06bb9a636b2644c69cf86c68bd1cf` | unchanged |
| prod `audit_scan_history.db` MD5 | `34fd1543e4a33397cf5b07202c43d598` | unchanged |
| prod `benchmark_store.db` MD5 (+ worktree copy) | `61b445e2731327ca5d37cb947a502504` | unchanged (both) |
| `~/.solc-select/global-version` / bare `solc` | `0.5.8` / `0.5.8+commit.23d335f2` | unchanged |
| `git status` | only untracked `benchmarks/realworld/`, `benchmarks/realworld_manifest.json` | confirmed; HEAD still `b868be8` |
| `/tmp/phase15-history.db`, `/tmp/phase15-realworld-bench.db` | not created (`--no-save`) | confirmed absent |
| `benchmarks/realworld_manifest.json` SHA-256 | changed **by design** (RW-001 flip + toolchain note, §11.3) | `d452fc109c9cffefd34bf838a848af7f972511308651f5a4e0fba13adb8db6fc` |

#### 12.4 Verdict of this run

**RW-001 is a validated real-world true positive**: ground truth fixed
at acquisition (Step 3, §2) from Immunefi #37577 + pinned Besu commit —
before any scan; correct detector (`tx-origin`) on vulnerable code
(vendored Apache-2.0 source, SHA-pinned); finding maps to the expected
contract and function; the pipeline surfaced it as a FACT-evidence
finding; the benchmark reconciled it to the expected label; raw Slither
evidence supports it (4/4 channel hits). Evaluable-flag mechanics were
decided on compile evidence before the run (§11.3), never on detector
output. RW-002 remains a documented negative control. Limitations to
state honestly: n = 1 scored fixture, one family (access_control), one
run, and the §12.2 Optimization-scope reconciliation note.

---

### 13. Phase 15B — RW-003 acquisition: Jaypeggers JAY (`buyJay` reentrancy) (2026-10-14)

**This section is the ground-truth firewall for RW-003.** Everything
label-shaped below (§13.4–§13.5: `expected_label`, `expected_contract`,
`expected_function`, `category`, `analyzer_family`, `accepted_checks`,
and the predicted detector channel) was fixed and written here
*before any Slither scan, benchmark run, or analyzer invocation of
`RW-003-jay-reentrancy.sol` was performed*. No result of any scan may
be used to relabel this fixture (PROTOCOL §1). §13.5 is an explicit
**prediction** made by reading Slither's detector implementation
against the vulnerable code — it is not an observation, and if the
run contradicts it the contradiction must be reported, not absorbed.

Mission context: Phase 15B requires a second real-world fixture from
a **different analyzer family than RW-001's `tx.origin`
access-control** (priority order: reentrancy → arithmetic/rounding →
delegatecall/storage → unsafe external-call → other). RW-001
(`analyzer_family: access_control`, `accepted_checks: ["tx-origin"]`,
run `B-e817970f01b0`) is left byte-for-byte unchanged and remains the
reproducible baseline.

#### 13.1 Candidate #12 rejected — Furucombo (2026-10-14)

| Gate | Evidence | Verdict |
|---|---|---|
| Compiler window | Pre-exploit `contracts/Proxy.sol` pinned at `dinngo/furucombo-contract` commit `e416ad1baa1ec8dd6efbce98dd465a304ad3e818` declares `pragma solidity ^0.6.0;`; current `master` declares `pragma solidity 0.8.10`. No 0.6.x compiler and no 0.8.10 in the offline set. | FAIL |
| Self-contained source | Imports `@openzeppelin/contracts/...`, `./interface/IRegistry.sol`, `./Config.sol`, `./Storage.sol`, `./lib/LibParam.sol` — `run_slither` passes no `--solc` and no remappings, so the import graph cannot resolve. | FAIL |
| Family distinct from RW-001 | Root cause is `_exec(address _to, bytes _data)` performing `delegatecall` to an attacker-supplied `_to` after `require(_isValid(_to))` — maps to Slither `controlled-delegatecall`, which `ACCESS_CONTROL_CHECKS` routes to `analyzer_family: access_control`, i.e. the **same family as RW-001**. | FAIL |
| License | MIT at the pinned commit — moot given the three failures above. | n/a |

Rejection recorded so the sweep is not repeated. Candidate count now
12 rejected / 1 selected.

#### 13.2 Candidate #13 selected — JAY, `0xf2919D1D80Aff2940274014bef534f7791906FF2`

Jaypeggers is a tax-loss-harvesting app for NFTs. On **2022-12-29** it
was exploited for **15.32 ETH** (~$18k) in a contract-level
reentrancy against the `JAY` token's `buyJay` function.

**Gate 5 — reproducible source identity (pass).**

| Property | Value |
|---|---|
| Deployed address | `0xf2919D1D80Aff2940274014bef534f7791906FF2` (Ethereum mainnet, chainId 1) |
| Etherscan | verified, "**Exact Match**" on `/address/0xf2919d1d80aff2940274014bef534f7791906ff2#code` |
| Sourcify | `GET /server/v2/contract/1/0xf2919D1D80Aff2940274014bef534f7791906FF2?fields=sources` → `match: "match"`, `creationMatch: "match"`, `runtimeMatch: "match"` (full match), `verifiedAt: 2024-08-08T16:35:24Z`, single source unit `JAY.sol` |
| Vendored bytes | `benchmarks/realworld/RW-003-jay-reentrancy.sol`, **SHA-256 `96333c9e01d7d548fc34a6343c4f68402a6bbff0f01f57a6a091fe04ed0f8c91`**, 42 166 bytes / 1338 lines, **byte-identical** to the Sourcify `JAY.sol` content (verified by direct byte comparison before vendoring) |
| Source shape | single flattened file, hardhat v2.9.1 header, **0 `import` statements**, all 11 pragmas `pragma solidity ^0.8.0` |

Note on a decoy: `0xDA7C0810cE6F8329786160bb3d1734cf6661CA6E` is a
*different, later* JAY deployment (`pragma solidity 0.8.16`,
`ReentrancyGuard`, `@openzeppelin` imports, no `buyJay` function). It
is not the exploit target and is not vendored.

**Gate 4 — independent vulnerability evidence (pass, T2).** Two
independent post-mortems retrieved 2026-10-14, both HTTP 200, both
naming the same contract, the same function, and the same mechanism:

1. **Hypernative**, *Jaypeggers Exploit*, 2023-01-10 —
   `https://www.hypernative.io/insights/blog/jaypeggers-exploit`
   > "On December 29, 2022, Jaypeggers, a tax-loss harvesting app for
   > NFTs, suffered a reentrancy attack that resulted in the theft of
   > 15.32 ETH … The remaining borrowed WETH (50.5 WETH) was used to
   > call the **buyJay function**, which, due to a lack of validation,
   > allowed the attacker to insert their own malicious contract as if
   > it were an ERC-721 token. The buyJay function then called the
   > **transferFrom** function of the provided token, which was
   > actually the attacker's malicious contract. This enabled the
   > attacker to reenter the contract by calling the **sell** function
   > of the JAY contract, allowing them to sell JAY tokens using a
   > miscalculated price, and thus profit."
2. **SolidityScan / CredShields**, *JAY Token Exploit — Reentrancy
   Attack* —
   `https://blog.solidityscan.com/jay-token-exploit-reentrancy-attack-d7a4923b6333/`
   > "JAY Token's official contract: **0xf2919d1** … The **buyJay()**
   > method in the JAY contract supported any ERC-721 token as a
   > parameter. JAY Token price = Total Ether balance in JAY contract /
   > Total Supply of JAY token … During the transfer, the attacker
   > executed and reentered the JAY contract by invoking the **sell**
   > function on the fake ERC-721 token and sold all JAY tokens. The
   > JAY token price got manipulated since the Ether balance was raised
   > before the buyJay function was initiated."

Tier = **T2** (identified incident + independent post-mortems +
verified source of the deployed contract; no security advisory or
formal audit of this exact version). Labels are fixed by source
semantics corroborated by both write-ups, never by tool output.

#### 13.3 Gate 1–3 and 6 — compiler, self-containment, slug, license

| Gate | Finding |
|---|---|
| 1 Compiler window | `^0.8.0` admits solc 0.8.36 (homebrew `/opt/homebrew/bin/solc`) and 0.8.37 (`~/.solc-select/artifacts/solc-0.8.37`). |
| 2 Self-contained | Single `.sol`, zero `import` statements; contract/library/interface declarations needed by `contract JAY is ERC20, Ownable` (`SafeMath` L20, `IERC20` L244, `IERC20Metadata` L332, `Context` L367, `ERC20` L412, `IERC165` L779, `IERC1155Receiver` L802, `AggregatorV3Interface` L857, `Ownable` L910, `IERC721` L983, `IERC1155` L997) are all in the same file. No Foundry project, no node_modules. |
| 3 Accepted slug | Vulnerable semantics are a classic reentrancy (external call → state/price effect → later code), mapping to the installed `reentrancy-*` family (see §10.1 gate 3 list). **Distinct from RW-001's `tx-origin` / `analyzer_family: access_control`.** |
| 6 License | `//SPDX-License-Identifier: MIT` at vendored line 978 covers the `JAY` contract. Bundled components are also MIT: OpenZeppelin Contracts **v4.7.0** (declared in the `// File @openzeppelin/contracts/...@v4.7.0` markers) and Chainlink `AggregatorV3Interface` from `@chainlink/contracts` v0.4.1, which the `smartcontractkit/chainlink` root `LICENSE` places under *"Content outside of the above mentioned directories or restrictions above is available under the MIT license"*. `LICENSE.MIT` vendored verbatim = OpenZeppelin `openzeppelin-contracts` tag `v4.7.0` `LICENSE` (SHA-256 `8c21a3d62814a86c6e6db50768e5a885a1f586873628e9be79a93f4eb6c18820`, 1107 bytes) — the origin is recorded here exactly as `LICENSE.apache-2.0` / `LICENSE.LGPL-3.0-dao` origins are recorded in §7. No `license: NOASSERTION` needed. |

**Compile-only probe (tool mechanics, PROTOCOL §5 condition 2)** —
performed on the bytes now at `RW-003-jay-reentrancy.sol`, *before* any
scan, from a scratch copy of the identical file:

```
/opt/homebrew/bin/solc --bin --abi JAY.sol -o out --overwrite
→ exit 0; warnings only ("Unused function parameter"); bytecode emitted
  for JAY, ERC20, SafeMath (JAY.bin non-empty)
```

This satisfies PROTOCOL §5 condition 2 on compile evidence alone, so
`evaluable: true` is set at acquisition (the RW-001 §11.3 pattern):
compile evidence, not detector output. Labels are unchanged by it.

#### 13.4 Ground truth fixed before any scan (the firewall record)

```json
{
  "fixture_id": "RW-003",
  "file": "RW-003-jay-reentrancy.sol",
  "source_sha256": "96333c9e01d7d548fc34a6343c4f68402a6bbff0f01f57a6a091fe04ed0f8c91",
  "expected_label": "vulnerable",
  "expected_contract": "JAY",
  "expected_function": "buyJay",
  "category": "reentrancy",
  "analyzer_family": "reentrancy",
  "ground_truth_tier": "T2",
  "license": "MIT"
}
```

Source semantics justifying `vulnerable` (vendored line numbers):

- `contract JAY is ERC20, Ownable` — **L1007**; `function buyJay(...)`
  **public payable** — **L1111–L1150**; no `nonReentrant` modifier
  anywhere in the file, so `Function.is_reentrant` is `True`.
- **L1118** `require(start, "Not started!");` is the only state read
  before the first external call.
- **L1120** `if (total != 0) buyJayWithERC721(...)` → `internal`
  function **L1152**, whose loop body **L1157** does
  `IERC721(_tokenAddress[id]).transferFrom(msg.sender, address(this), ids[id])`
  on an **attacker-supplied** token address — the untrusted external
  call, and the exact call both post-mortems identify.
- **L1142** `_mint(msg.sender, ETHtoJAY(msg.value).mul(97).div(100))`
  writes `_totalSupply` / `_balances`; **L1144**
  `(bool success, ) = dev.call{value: msg.value.div(34)}("")` sends
  ETH; **L1147** `nftsSold += total`; **L1149**
  `emit Price(block.timestamp, JAYtoETH(1 * 10**18))`.
- `JAYtoETH` (**L1227–1229**) returns
  `(value * address(this).balance).div(totalSupply())` — the
  reentrancy-sensitive price; `ETHtoJAY` (**L1231–1233**) is its
  inverse; `sell(uint256)` **L1185** burns and pays out on that
  price. This is the "Ether balance was raised before … / miscalculated
  price" both write-ups describe.
- Therefore: untrusted `transferFrom` (L1157, reached from L1120)
  executes **before** the `_mint`/`nftsSold` effects and before the
  price-dependent `emit`, letting a malicious ERC-721 reenter `sell`
  (L1185) mid-`buyJay` — the reported 15.32 ETH loss.

`accepted_checks` = the six installed reentrancy slugs, following the
RW-002 precedent (an established reentrancy fixture accepts the whole
`reentrancy-*` channel rather than guessing which sub-detector fires):
`reentrancy-eth`, `reentrancy-no-eth`, `reentrancy-balance`,
`reentrancy-events`, `reentrancy-benign`, `reentrancy-unlimited-gas`.
The `analyzer_family: reentrancy` gates the *surfacing* channel;
`accepted_checks` gates the *slug*; `expected_contract`/`expected_function`
gate the *location*. Both `JAY` and `buyJay` occur in the vendored
source (PROTOCOL §9.2).

#### 13.5 Pre-scan detector prediction (read of Slither 0.11.6 source only)

Performed by reading
`~/.pyenv/versions/3.11.9/lib/python3.11/site-packages/slither/detectors/reentrancy/`
against the code above. **No scan of this fixture had been run at the
time of writing.**

| Detector | Expected on `JAY.buyJay` | Reason (detector source) |
|---|---|---|
| `reentrancy-benign` (Low) | **YES** | `find_reentrancies`: needs `calls` containing some node `≠ node`, a non-empty `written`, and at least one written var not in `reads_prior_calls`. At the L1142 `_mint` node: `written = {_totalSupply, _balances}` (pulled in from the internal call, `analyze_node`), `calls` contains the L1157 `transferFrom` node from the father, and `reads_prior_calls[transferFrom] = {start}` — no overlap → fires. Same at L1147 `nftsSold += total`. |
| `reentrancy-events` (Low) | **YES** | `find_reentrancies`: `f.is_reentrant` (public, no guard → True) + `calls` with a node `≠ node` + non-empty `_events` at that node. At the L1149 `emit Price` node: `merge_fathers` unions `_calls` (so the L1157 and L1144 nodes are present) and `_events` is populated at this node by `analyze_node` for the `EventCall` → fires. |
| `reentrancy-eth` (High) | **NO** | Requires a state variable that is *read before* the call and *written after* it, plus an ETH send from a different node. The only pre-call read is `start` (L1118), which `buyJay` never writes. |
| `reentrancy-no-eth` (Medium) | **NO** | Same read-before/write-after condition (`ReentrancyReadBeforeWritten`), and it additionally requires `send_eth` empty at the node; `start` is never written. |
| `reentrancy-balance` (Low) | **NO** | Requires a prior `balanceOf(address)` high-level call; `buyJay` reads `totalSupply()` / `address(this).balance` instead. |
| `reentrancy-unlimited-gas` (Informational) | **NO** | Not applicable (no `.call{gas:}` pattern). |

Location mapping: `detector_location` takes the first
`type == "function"` element → `name.split("(")[0]`, plus its
`type_specific_fields.parent` contract. For these findings the element
is the `buyJay` function declared in `JAY`, with the description
header `Reentrancy in JAY.buyJay(...)` as an independent fallback — so
`affected_contract == "JAY"` and `affected_function == "buyJay"`,
matching the fixed labels. The finding `title` is
`Reentrancy vulnerability in JAY.buyJay`, which satisfies
`title_family == "reentrancy"`, and `_make_finding` embeds
`Slither detector: <slug>.`, which is what `_DESC_SLUGS_RE` reads.

Also expected but **not** required for a TP: `reentrancy-events` on
`sell` (L1196) and `buyJayNoNFT` (L1209), and possibly
`reentrancy-benign`/`reentrancy-events` on `buyNFTs` (L1052/L1076).
`evaluate_fixture` is **fixture-level**: the first finding whose slug
∈ `accepted_checks`, contract and function match, and which carries
≥1 FACT evidence item decides one verdict; every other finding is
appended to `other_findings` and can never turn a vulnerable fixture
into an FP (`benchmark.py` only assigns `FP` when
`expected_label == "safe"`).

**Stated risk, recorded pre-scan:** if — contrary to §13.5 — no
`reentrancy-*` finding is surfaced on `JAY.buyJay`, RW-003 scores
`FN` (or `pipeline_failure` if raw Slither did fire but surfacing
dropped it). That outcome would be reported as a genuine detection
miss; the labels above must not be edited afterwards to convert it.

#### 13.6 What had *not* happened when §13 was written

No Slither invocation of any kind on `RW-003-jay-reentrancy.sol`, no
benchmark run, no analyzer output consulted, no temp `history.db` /
`benchmark_store.db` created, no database write, no commit. The only
executed tooling on these bytes was the read-only source/identity
fetches and the compile-only probe of §13.3.

### 14. Phase 15B isolated runs, ground-truth comparison, and integrity (2026-10-14)

#### 14.1 Isolation recipe (identical shape to §12.1)

Per run, from the project root, with a fresh `mktemp -d` PATH dir
containing a single `solc` symlink, the real (non-shim) interpreter and
the real `slither`, and throwaway databases:

```
T=$(mktemp -d /tmp/phase15b-solc0XXX-bin.XXXXXX); ln -s <solc> "$T/solc"
env PATH="$T:$HOME/.pyenv/versions/3.11.9/bin:$PATH" \
    AUDITOR_HISTORY_DB=/tmp/phase15b-realworld-history.db \
    AUDITOR_BENCHMARK_DB=/tmp/phase15b-realworld-bench.db \
    $HOME/.pyenv/versions/3.11.9/bin/python3 audit.py benchmark \
      --manifest benchmarks/realworld_manifest.json \
      --fixtures benchmarks/realworld --no-save --json > <artifact>
```

`--no-save` used for both; neither throwaway database was ever
created. The pyenv shims (`python3`, `slither`, `solc`) are bypassed by
prepending the real `~/.pyenv/versions/3.11.9/bin` — the defect already
documented in §12.1. No `--baseline`, no `--set-baseline`, no
`solc-select use`; the global PATH compiler stays **0.5.8**.

#### 14.2 Run A — RW-003 evaluation, solc 0.8.36 (`B-7f768b4b5637`)

Artifact `/tmp/phase15b-realworld-run-1.json`, SHA-256
`8ef4689fa516cefbc2a10a7f051ecb67e788202fa6269ec3fe876864160d6804`;
`status: completed`, duration 1.145 s, corpus fingerprint
`ac6c5fe709d8835d`, toolchain fingerprint `daee52e5485e0766`
(solc `0.8.36+commit.8a079791.Darwin.appleclang` resolved from the temp
dir; slither 0.11.6 from the real pyenv bin).

| Fixture | status | verdict | matched check | location |
|---|---|---|---|---|
| RW-001 | `blocked` | — | — | tool/compiler failure: `Source file requires different compiler version (current compiler is 0.8.36…)` |
| RW-002 | `not_evaluable` | — | — | unchanged (`na_reason`) |
| **RW-003** | **`passed`** | **TP** | **`reentrancy-benign`** | **`JAY` . `buyJay`** |

Totals: `passed 1, blocked 1, not_evaluable 1, tp 1, fp 0, fn 0, tn 0`;
`precision = recall = f1 = 1.0`; `metadata_gaps 0`,
`evidence_insufficient 0`, `raw_unsurfaced_hits 0`,
`other_findings 10`, `reconciliation_discrepancies 1`.

Matched finding `F-41b3f5319951`, title
`Reentrancy vulnerability in JAY.buyJay`, severity LOW, confidence LOW,
`affected_lines` 1111–1150 (the whole `buyJay` body), 9 FACT evidence
items, source/tool `slither`. Raw report for RW-003: `completed`,
30 detectors; surfaced 15; excluded 14 informational; the single
reconciliation discrepancy is `missing: ["immutable-states"]` — an
Informational-only raw hit that `reconcile_raw` exempts by rule, the
same *class* of documented note as RW-001's §12.2 Optimization entry.
Raw channel counts: `reentrancy-benign 3`, `reentrancy-events 5`,
plus non-accepted channels (`naming-convention 7`, `calls-loop 4`,
`low-level-calls 4`, `divide-before-multiply 2`, `boolean-equal 1`,
`dead-code 1`, `immutable-states 1`, `missing-zero-check 1`,
`solc-version 1`). The 10 `other_findings` are 6 `wrong_location`
(reentrancy hits on other JAY functions) and 4 `channel_mismatch`; they
are recorded, never scored — `evaluate_fixture` is fixture-level and a
`vulnerable` fixture can only ever be TP or FN.

#### 14.3 Run B — baseline reproducibility, solc 0.5.10 (`B-0f4f71cc89a0`)

Artifact `/tmp/phase15b-realworld-run-2.json`, SHA-256
`8b3ae60b1a285448ed0e7dd164ee9dfa6d110e3609db199cc180cf6f1728e557`;
`status: completed`, duration 0.947 s, corpus fingerprint
`ac6c5fe709d8835d` (**identical to run A**), toolchain fingerprint
`acb05055a908252b` — **identical to the Phase 15 baseline run
`B-e817970f01b0`**, so run B is like-for-like with §12.2.

| Fixture | status | verdict | matched check | location |
|---|---|---|---|---|
| **RW-001** | **`passed`** | **TP** | **`tx-origin`** | **`DefaultOnChainPrivacyGroupManagementContract` . `lock`** |
| RW-002 | `not_evaluable` | — | — | unchanged |
| RW-003 | `blocked` | — | — | tool/compiler failure under solc 0.5.10 |

Totals identical in shape to run A: `tp 1, fp 0, fn 0, tn 0`,
`precision = recall = f1 = 1.0`.

**RW-001's baseline behaviour is reproduced unchanged**: same detector,
same contract, same function, same toolchain fingerprint as run
`B-e817970f01b0`. The Phase 15 record is not disturbed.

#### 14.4 Ground-truth comparison — prediction (§13.5) vs observation (run A)

Written before the scan; compared after:

| Item | §13.5 prediction (pre-scan) | Run A observation | Match |
|---|---|---|---|
| `reentrancy-benign` on `JAY.buyJay` | YES | **fired, surfaced, matched** | ✅ |
| `reentrancy-events` on `JAY.buyJay` | YES | fired (raw `reentrancy-events 5`, surfaced) | ✅ |
| `reentrancy-eth` | NO | not present in the raw report | ✅ |
| `reentrancy-no-eth` | NO | not present in the raw report | ✅ |
| `reentrancy-balance` | NO | not present in the raw report | ✅ |
| `reentrancy-unlimited-gas` | NO | not present in the raw report | ✅ |
| location `JAY` / `buyJay`, lines 1111–1150 | YES | `actual_contract=JAY`, `actual_function=buyJay`, lines 1111–1150 | ✅ |
| extra reentrancy hits on other functions | possible, must not create FP | 6 `wrong_location` in `other_findings`, no FP | ✅ |
| verdict if nothing fires | FN / `pipeline_failure` | not reached | ✅ |

The prediction was made by reading Slither's detector source against the
vulnerable code (§13.5); **no label was touched afterwards**, and the
outcome did not depend on it — `accepted_checks` and the location labels
were already frozen in §13.4.

#### 14.5 Finding: the benchmark runs every fixture under ONE PATH `solc`

Runs A and B together demonstrate a real, previously unrecorded harness
limitation:

- `run_slither` invokes `[slither, target, "--json", out]` with **no
  `--solc` flag and no remapping**, so Slither resolves `solc` purely
  from `PATH` (`slither_runner.py:305`).
- `run_benchmark` evaluates the whole corpus in one process with one
  inherited `PATH`, so **a single run can only serve fixtures whose
  pragmas admit the same compiler**.
- The real-world corpus now spans three windows — RW-001 `^0.5.9`,
  RW-002 `v0.3.1-2016-04-12`, RW-003 `^0.8.0` — so **no single PATH
  `solc` can score more than one evaluable fixture at a time**. Each
  run therefore scores exactly one TP and reports the others as
  `blocked` (compile failure) or `not_evaluable` (toolchain absent).

Consequences stated honestly:

- There is **no** run in which RW-001 and RW-003 are both scored TP.
  Each fixture's TP is individually demonstrated, under its own
  isolated compiler, in a run whose `status` is `completed`.
- The `blocked` rows are **toolchain-operability outcomes**, not
  detection failures (PROTOCOL §5): the reason strings are compiler
  version mismatches, and they are never folded into TP/FP/FN/TN.
- Aggregate `precision = recall = f1 = 1.0` in both runs is computed
  over **n = 1 scored fixture each**. It must not be read as a
  two-fixture 1.0.

**Recommended fix (app code change → requires explicit approval; not
made):** resolve `solc` per fixture — e.g. `run_slither` accepting a
`--solc` path, or `run_benchmark` selecting the PATH dir from each
fixture's `compiler` field / declared pragma. Until then, report the
per-compiler runs separately, as done here. Also outstanding: RW-002's
2016-era compiler is still absent.

#### 14.6 Integrity verification after the runs

| Anchor | Expected | Observed | Result |
|---|---|---|---|
| `benchmarks/manifest.json` SHA-256 | `0d610f0abd3fc4418e639968eac6195738349b802abc9fdd373c8aa987985ad0` | same | unchanged |
| RW-001 source SHA-256 | `e9f8cc31df24ba511bce7caeb678902002e09facd38e0b788843bd667ec4e6d0` | same | unchanged |
| RW-002 source SHA-256 | `40163dd800c3b5cc85229693687d74bcbce24bdb6161cdf9eb37ef43f3308cba` | same | unchanged |
| RW-001 interface SHA-256 | `0393d524e1c3be3577fc7f15439a89b1eab06bb9a636b2644c69cf86c68bd1cf` | same | unchanged |
| RW-003 source SHA-256 | `96333c9e01d7d548fc34a6343c4f68402a6bbff0f01f57a6a091fe04ed0f8c91` | same | unchanged (new, as vendored) |
| `LICENSE.apache-2.0` / `LICENSE.LGPL-3.0-dao` | `b40930bb…` / `ea8af5e7…` | same / same | unchanged |
| `LICENSE.MIT` (new) | `8c21a3d62814a86c6e6db50768e5a885a1f586873628e9be79a93f4eb6c18820` | same | as vendored |
| `benchmarks/realworld/README.md` SHA-256 | `9ace48d6f7e4bc633fbc576248b9e77d2700f1b89d6f3e62d1dc2532e13c1433` | same | unchanged |
| `benchmarks/PROTOCOL.md` SHA-256 | `2bd6a29e6ad5e89613a78bafe7fae80de642aa32ce0f46ab7cd64f07fe135d19` | same | unchanged |
| `benchmarks/README.md` SHA-256 | `ce21074f02fe83bfb785732ce9af6098f1f8585dc4000b5e336a4e1c9ada7fe0` | same | unchanged |
| `benchmarks/realworld_manifest.json` SHA-256 | `d452fc109c9cffefd34bf838a848af7f972511308651f5a4e0fba13adb8db6fc` (Phase 15) | `2c6f5344fd0e07661fd60fc012362c24bdde0f5db5e25ea13d9394190e66b122` | changed **by design** (RW-003 entry + toolchain note, §13/§14) |
| prod `audit_scan_history.db` MD5 | `34fd1543e4a33397cf5b07202c43d598` | `34fd1543e4a33397cf5b07202c43d598` at `<local-project>/audit_scan_history.db` (mtime Oct 13 11:18) | unchanged |
| prod `benchmark_store.db` MD5 | `61b445e2731327ca5d37cb947a502504` | `61b445e2731327ca5d37cb947a502504` at `<local-project>/` | unchanged |
| worktree `benchmark_store.db` MD5 | `61b445e2731327ca5d37cb947a502504` | same (mtime Oct 14 09:04) | unchanged |
| `~/.solc-select/global-version` / bare `solc` | `0.5.8` / `0.5.8+commit.23d335f2` | `0.5.8` / `0.5.8+commit.23d335f2` | unchanged |
| `/tmp/phase15b-realworld-history.db`, `/tmp/phase15b-realworld-bench.db` | not created (`--no-save`) | absent | confirmed |
| protected baseline `/tmp/phase15-realworld-run-3.json` | run `B-e817970f01b0` | run `B-e817970f01b0`, SHA-256 `b6707a76796c2ab6c4801188728ae4e5d0b954f808b83f7c2141f9da9f70d2e0` | untouched |
| `git status` | only untracked `benchmarks/realworld/`, `benchmarks/realworld_manifest.json` | same; HEAD `b868be8` | no tracked file modified, no commit |

#### 14.7 Verdict of Phase 15B

**RW-003 is a validated real-world true positive in a second,
distinct analyzer family.** Ground truth was fixed in §13.4 *before*
any scan; the predicted detector channel (§13.5) was confirmed by run
A; the finding maps to the expected contract and function on the exact
lines; the source is a Sourcify **full match** of the deployed,
exploited contract at `0xf2919D1D80Aff2940274014bef534f7791906FF2`,
MIT-licensed and byte-pinned; RW-001's baseline reproduced unchanged in
run B under an identical toolchain fingerprint.

Honest limitations: (a) `analyzer_family: reentrancy` — the second
family, but only two of the taxonomy's three families are now
represented, and `generic` is untested on real-world code; (b) both
runs score **n = 1** because of the single-`PATH`-`solc` limitation in
§14.5 — no run has both fixtures scored; (c) RW-003 was matched on a
**Low**-severity detector (`reentrancy-benign`, confidence LOW), which
is the channel Slither 0.11.6 offers for this code shape because no
state variable is read before the untrusted call — the *class* is
correct but the severity/confidence are the tool's, not an exploit
verdict; (d) one run per fixture, no repetition; (e) RW-002 remains
`not_evaluable`.
