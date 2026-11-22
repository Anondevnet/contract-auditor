# Phase 14 Benchmark Corpus

Ground truth for the Contract Auditor vulnerability-detection benchmark.
Scoring rules live in [PROTOCOL.md](PROTOCOL.md) (written before any
run); fixture metadata lives in [manifest.json](manifest.json).

## Provenance

Every fixture is **synthetic, original code written for this repository**
for Phase 14 benchmarking. Nothing is copied from third-party projects,
public exploits, or unlicensed sources. Each `.sol` file repeats its
provenance in a header comment.

All fixtures are deterministic and local: `pragma solidity ^0.5.8`,
compiled by the PATH solc **0.5.8** already installed on this machine and
analyzed by the already-installed Slither **0.11.6**. No network, remote
API, deployment, live target, or blockchain transaction is involved.

## Fixture inventory (12 fixtures, 6 category pairs)

| ID | File | Category | Label | Expected contract.function | Expected channel (accepted_checks) |
|---|---|---|---|---|---|
| REENT-001 | REENT-001-vulnerable.sol | reentrancy | vulnerable | ReentrancyVault.withdraw | reentrancy-* family |
| REENT-002 | REENT-002-safe.sol | reentrancy | safe | ReentrancyVaultSafe.withdraw | reentrancy-* family |
| ACCESS-001 | ACCESS-001-vulnerable.sol | access_control | vulnerable | TxOriginWallet.transferTo | tx-origin |
| ACCESS-002 | ACCESS-002-safe.sol | access_control | safe | MsgSenderWallet.transferTo | tx-origin |
| ACCESS-003 | ACCESS-003-vulnerable.sol | access_control | vulnerable | KillSwitch.destroy | suicidal |
| ACCESS-004 | ACCESS-004-safe.sol | access_control | safe | KillSwitchSafe.destroy | suicidal |
| CALL-001 | CALL-001-vulnerable.sol | unchecked_call | vulnerable | RewardPusher.pushReward | unchecked-lowlevel, unchecked-send |
| CALL-002 | CALL-002-safe.sol | unchecked_call | safe | RewardPusherSafe.pushReward | unchecked-lowlevel, unchecked-send |
| ARITH-001 | ARITH-001-vulnerable.sol | arithmetic | vulnerable | FeeCalculator.computeFee | divide-before-multiply |
| ARITH-002 | ARITH-002-safe.sol | arithmetic | safe | FeeCalculatorSafe.computeFee | divide-before-multiply |
| PRIV-001 | PRIV-001-vulnerable.sol | privileged_change | vulnerable | PrivilegedConfig.setAdmin | protected-vars (**not evaluable**) |
| PRIV-002 | PRIV-002-safe.sol | privileged_change | safe | PrivilegedConfigSafe.setAdmin | protected-vars (**not evaluable**) |

Vulnerable/safe labels are fixed by the documented code semantics in each
file header and `manifest.json` (`expected_behavior` /
`protection_control`) — never by what the tool reports.

## Detector inventory record (`slither --list-detectors`, v0.11.6, 2026-10-13)

Relevant detector classes present (impact): `reentrancy-eth` (High),
`reentrancy-balance` (High), `reentrancy-no-eth` (Medium),
`reentrancy-benign` (Low), `reentrancy-events` (Low),
`reentrancy-unlimited-gas` (Informational), `tx-origin` (Medium),
`suicidal` (High), `controlled-delegatecall` (High),
`missing-zero-check` (Low), `unchecked-lowlevel` (Medium),
`unchecked-send` (Medium), `divide-before-multiply` (Medium),
`protected-vars` (High), `arbitrary-send-eth` (High),
`low-level-calls` (Informational).

**No overflow/underflow ("unchecked arithmetic") detector exists** in
Slither 0.11.6 — this is the inventory-based justification for why a
0.5.x balance-underflow fixture is *not* included as a scored category;
the scored `arithmetic` pair uses `divide-before-multiply`, which does
exist.

**Toolchain-inoperable detector (PROTOCOL §5 case 2):** `protected-vars`
requires state-variable NatSpec in the solc AST (`documentation` field,
parsed in `slither/solc_parsing/variables/variable_declaration.py`).
solc 0.5.8 emits `documentation: null` for state variables in both the
legacy (`--combined-json ast`) and compact (`--ast-compact-json`) AST —
verified by direct AST dump on PRIV-001. The detector class exists but
cannot trigger for *any* fixture on the only locally available offline
compiler; installing another compiler is out of scope for Phase 14.
PRIV-001/PRIV-002 therefore ship as **not evaluable** (never scored as
TN or FN), with the vulnerable/safe ground truth still documented.

## Pre-scoring pipeline probe (2026-10-13)

Ran the real three-analyzer pipeline over each fixture once, before any
scoring, to verify matcher inputs (PROTOCOL §2) and record actual
behavior:

- Matcher inputs confirmed on every surfaced finding: detector slug
  (description regex for reentrancy/access-control families, title-prefix
  fallback for generic), `affected_contract`, `affected_function`,
  `affected_lines`, ≥1 FACT evidence item with source/tool `slither`.
- Expected channels fired exactly where designed: `reentrancy-eth` on
  REENT-001 (FACT×5), `tx-origin` on ACCESS-001, `suicidal` on
  ACCESS-003, `unchecked-lowlevel` on CALL-001, `divide-before-multiply`
  on ARITH-001; all five safe counterparts produced **no** finding in
  their declared channel.
- Cross-category output observed and recorded as `other_findings`
  (unscored per PROTOCOL §3): `arbitrary-send-eth` (High, generic) on
  ACCESS-001/CALL-001/CALL-002, `reentrancy-events` (Low) on
  CALL-001/CALL-002, `missing-zero-check` (Low) on the PRIV pair before
  the zero-check hygiene patch.
- `protected-vars` produced no finding on PRIV-001 — root-caused to the
  AST limitation above (not recorded as an FN, because the fixture is
  `evaluable: false` for the toolchain-inoperability reason).

## Known limitations

- One scored category pair per fixture; findings from other categories on
  the same file are listed as `other_findings`, never silently converted
  into TP/FP/TN/FN.
- `privileged_change` is represented but not scored (toolchain-inoperable
  detector, above). An inventory-based unscored case (0.5.x
  balance-underflow) is documented rather than shipped, because no
  detector class exists to evaluate.
- Fixtures exercise Slither-derived detectors only; no AI model
  participates in detection or ground truth.

## Phase 15 additions (2026-10-13) — protocol v2

`manifest.json` now carries `schema_version: 2` and **18 fixtures** (was 12).
Two categories joined the scored corpus after probe evidence was recorded
under the local toolchain (solc 0.5.8 + slither 0.11.6), per PROTOCOL.md §9:

| Fixture | Category | Expected channel | Probe result (2026-10-13) |
|---|---|---|---|
| DELEG-001 | `delegatecall` | `controlled-delegatecall` | **High** on `DelegateVault.forward` (also `missing-zero-check` Low on `setTarget` → recorded as `other_findings`) |
| DELEG-002 | `delegatecall` | must NOT fire | no non-informational detectors |
| SEND-001 | `unchecked_call` | `unchecked-send` | **Medium** on `RewardDistributor.claim`, no other detections |
| SEND-002 | `unchecked_call` | must NOT fire | no non-informational detectors |
| ARB-001 | `arbitrary_transfer` | `arbitrary-send-eth` | **High** on `Escrow.drain` (also `missing-zero-check` Low → `other_findings`) |
| ARB-002 | `arbitrary_transfer` | must NOT fire | no non-informational detectors |

Arbitrary-send probe finding recorded in ground truth: slither 0.11.6 does
**not** raise `arbitrary-send-eth` when the drain is owner-gated (verified
separately); the vulnerable fixture therefore uses the unrestricted
pattern that the detector actually flags.

New validation in the harness (PROTOCOL.md §9.2): every evaluable fixture's
`expected_contract` and `expected_function` must occur in its source file —
a manifest typo is a fatal `ManifestError`, never a silent false negative.

### Unsupported / not-evaluable cases (reported, never scored as TN)

| Case | Reason |
|---|---|
| cross-function reentrancy | no detector in slither 0.11.6 produces output for the probe; unsupported — no fixture shipped |
| integer overflow/underflow | no detector class active for solc 0.5.8; documented, not shipped |
| `protected-vars` (PRIV-001/002) | detector inoperable on solc 0.5.8 AST (state-variable docs null); `evaluable: false` |
| owner-gated `arbitrary-send-eth` | detector does not fire; recorded as detector-behavior note above |

## Mission Phase 5 — detector validation pass (2026-10-14)

Follow-up validation of every detector family the pipeline can surface,
beyond the scored corpus:

### Generic-family operability probe (solc 0.5.8 + slither 0.11.6)

Probe source exercising weak PRNG, timestamp branching, state writes, and
pure arithmetic (recorded probe output; `slither Probe.sol --json`):

| Check | Slither impact | Surfaced by generic analyzer? | Verdict |
|---|---|---|---|
| `weak-prng` | High | yes | **operable** |
| `incorrect-equality` | Medium | yes | **operable** |
| `timestamp` | Low | yes | **operable** |
| `solc-version` | Informational | no (excluded by policy, counted) | excluded by design |
| `constant-function-state` | Medium | not triggered by probe | unprobed — no claim |

Informational/optimization results remain policy-excluded and are counted
in the tool status (`surfaced_checks` excluded count; covered by
`tests/test_phase12.py` and `tests/test_phase15.py`).

### Access-control severity map (text fallback)

`slither --list-detectors` impacts verified and hard-coded as the
text-fallback slug map (`auditor/analysis/access_control.py
_DETECTOR_SEVERITY`): `suicidal`/`controlled-delegatecall` → HIGH,
`tx-origin` → MEDIUM, `missing-zero-check`/`missing-msg-sender-check` →
LOW. The JSON path still prefers the impact Slither reported. Regression
tests: `tests/test_phase5_detectors.py`.

### Dead class-based analyzers removed

`base.py` shipped never-instantiated `ReentrancyAnalyzer`/
`AccessControlAnalyzer` classes whose text parser invented "access
control" findings from any line containing `onlyOwner`/`AccessControl`
and passed a nonexistent `created_from_analyzer` field (crash if ever
wired). Removed in this pass; `AnalysisContext`/`AnalysisOutcome`/
`BaseAnalyzer` (the real extension point) remain.

### Phase 16 probe evidence (2026-10-15, solc 0.5.8 + slither 0.11.6)

- `VAULT-001-vulnerable.sol` (`NaiveVault.convertToShares`): compiles;
  Slither emits `incorrect-equality`, `locked-ether` (+ informational
  `solc-version`) — unscored other findings. `erc4626-inflation` fires
  on line 23 with a FACT source excerpt → TP under §10.
- `VAULT-002-safe.sol` (`OffsetVault`): compiles; Slither emits
  `locked-ether` only; `erc4626-inflation` silent → TN.
- Unsaved full run: TP=9 FP=0 FN=0 TN=9, not_evaluable=2 (PRIV-001/002).
  Synthetic two-fixture smoke test only — not a recall estimate.
