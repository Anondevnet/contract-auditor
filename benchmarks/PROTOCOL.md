# Phase 14 Benchmark — Evaluation Protocol

Written **before** any benchmark run, before any scoring, and before any
metrics were computed. Ground truth comes exclusively from this document,
`manifest.json`, and the fixture source code itself. No AI-generated opinion
is used as ground truth anywhere in this benchmark.

## 1. Ground truth

Each fixture in `manifest.json` records:

- `fixture_id` — stable identifier.
- `category` — one of: `reentrancy`, `access_control`, `unchecked_call`,
  `arithmetic`, `privileged_change`.
- `expected_label` — `vulnerable` or `safe`, decided by the code semantics
  documented in `expected_behavior` / `protection_control` (never by what
  the tool reports).
- `expected_contract` / `expected_function` — the location where the
  vulnerable behavior (or its protective control) lives.
- `accepted_checks` — the Slither detector slug(s) that represent this
  category *through the existing pipeline* (see §3).
- `evaluable` — whether Slither 0.11.6 has a detector class for this
  pattern at all (see §5). `evaluable: false` fixtures are `not_evaluable`
  and are never scored as success or failure.
- `compiler` / `requires_tools` — local tool assumptions.
- `provenance` — fixture origin (all fixtures are synthetic, original
  code written for this repository).

Fixtures are deterministic and local: plain `.sol` files with
`pragma solidity ^0.5.8;`, compiled by the PATH solc 0.5.8 already present
on this machine. No network, deployment, live target, or remote API is
involved in any test or run.

## 2. Detector outputs actually available to the matcher (verified against source)

The benchmark consumes findings produced by the **existing pipeline only**
(`reentrancy.analyze` + `access_control.analyze` + `slither_generic.analyze`
over one shared `SlitherRun`) — the same call sequence the scan job uses.
No competing detector is implemented. Verified fields:

| Family | Title format | Detector slug location | Location fields | Evidence |
|---|---|---|---|---|
| Reentrancy | `Reentrancy vulnerability in {contract}.{function}` | description: `Slither detector: {slug}.` | `affected_contract`, `affected_function`, `affected_lines` | ≥1 `EvidenceItem(epistemic=FACT, source="slither", tool="slither")` |
| Access control | `Access control issue in {contract}.{function}` | description: `Slither detector: {slug}.` | same | same |
| Generic | `{slug} in {contract}.{function}` | title prefix (Slither's own `check` slug) | same | same |

**Verification status (probe run 2026-10-13, before any scoring):** all three
families confirmed to expose every matcher input. Actual slug extraction on
live pipeline output: `reentrancy-eth` (description regex, FACT×5),
`tx-origin` and `suicidal` (description regex, FACT×1), `unchecked-lowlevel`
and `arbitrary-send-eth` (title-prefix fallback, FACT×1); every finding
carried non-empty `affected_contract`/`affected_function` and ≥1 FACT item.

**Documented limitations (matcher adapts, never silently fails):**

- L1 — If `affected_function`/`affected_contract` is empty (Slither JSON
  lacked elements and the description regex failed), the pipeline itself
  already drops the finding with an explicit note; such raw detections
  surface as `pipeline_failure` (§4), not as a matcher miss.
- L2 — Slither's `detector_location` may attribute a line list that is
  wider than the expected function; the matcher therefore requires
  **contract + function** equality and does **not** require line overlap.
- L3 — Detector slug extraction falls back in order: description regex →
  title prefix (generic family) → family-by-title-prefix. If no slug can
  be extracted, the finding is classified `unmatched_metadata` and counted
  in the run's `metadata_gaps` counter (reported, never silently treated
  as a detection failure or as a correct detection).

## 3. Matching rule (a finding matches a fixture iff ALL hold)

1. **Category channel**: the extracted detector slug is in the fixture's
   `accepted_checks`, *or* (fallback when slug extraction failed) the
   finding's title family equals the fixture's `analyzer_family`
   (`reentrancy` → title starts `Reentrancy`, `access_control` → title
   starts `Access control issue`, otherwise generic family → title starts
   with one of `accepted_checks`). Severity and wording similarity are
   **never** sufficient.
2. **Location**: `affected_contract == expected_contract` **and**
   `affected_function == expected_function` (exact string equality).
3. **Evidence**: the finding carries ≥1 `FACT` evidence item. Findings
   whose evidence is only `AI_OPINION`/`HYPOTHESIS` never count as
   correct; they are reported as `evidence_insufficient` (distinct bucket).

Per-fixture scoring (one declared category per fixture):

| Fixture label | Matching finding present | Verdict |
|---|---|---|
| vulnerable | yes | **TP** (correct detection) |
| vulnerable | no (tools OK) | **FN** (missed vulnerability) |
| safe | yes | **FP** (false positive) |
| safe | no | **TN** (correct rejection) |

Findings on the fixture that do **not** match the declared category are
recorded as `other_findings` (listed for transparency, unscored — a
fixture demonstrates one category; unrelated output is not silently
converted into FP/TN either way).

## 4. Outcome taxonomy (kept strictly distinct)

- `passed` — TP or TN.
- `failed` — FP or FN (metrics-bearing).
- `blocked` — tool unavailable (`slither not_found`) or compiler/tool
  failure for that fixture (`SlitherRun.status != completed`, missing JSON
  report, compile failure, timeout). Excluded from TP/FP/FN/TN.
- `pipeline_failure` — the **raw** `SlitherRun.detectors` contains the
  expected check **and** expected contract/function, but the analyzer
  pipeline surfaced no matching finding (detector-to-finding surfacing
  failure). Counted in `pipeline_failures`, excluded from FN.
- `not_evaluable` — `evaluable: false` in the manifest (no detector class
  exists for the pattern). Excluded from all confusion-matrix counts;
  never counted as TN.
- `skipped` — manifest invalid for this fixture (missing file, bad label).
- `harness_error` — exception inside the harness for this fixture.
- `metadata_gaps` — matcher could not extract slug/location from a
  surfaced finding (limitation L3); reported separately.

Blocked, not-evaluable, skipped, harness-error, pipeline-failure and
metadata-gap outcomes are **never** counted as true negatives or false
negatives.

## 5. `evaluable` rule (anti-gaming)

`evaluable: false` may be set **only** under one of these two conditions,
and the reason must be recorded in the manifest (`na_reason`) and
`README.md`:

1. **No detector class**: Slither 0.11.6's detector inventory
   (`slither --list-detectors`, recorded in `benchmarks/README.md`) has no
   detector class for the pattern.
2. **Detector inoperable on the local toolchain**: a detector class exists
   but provably cannot trigger because a required compiler/tool input does
   not exist in the only available offline toolchain, verified at the
   tool-mechanics level (not merely "it did not fire on our fixture").
   Recorded case: `protected-vars` requires state-variable NatSpec in the
   solc AST (`documentation` field); solc 0.5.8 — the only compiler usable
   for offline single-file Slither runs here — emits
   `documentation: null` for state variables in **both** legacy and compact
   AST (verified by direct AST dump). Any fixture would fail identically;
   installing another compiler is out of scope.

`evaluable: false` may **never** be set because a detector exists, is
operable, but failed to fire — that is an FN. Labels
(`vulnerable`/`safe`) are fixed by code semantics and are never changed
based on tool output.

## 6. Metrics

Over `evaluable && status in {passed, failed}` fixtures only:

- `precision = TP / (TP + FP)`; denominator 0 → `null` ("n/a").
- `recall = TP / (TP + FN)`; denominator 0 → `null` ("n/a").
- `f1 = 2·TP / (2·TP + FP + FN)`; denominator 0 → `null` ("n/a").
- Per-category metrics computed identically within each category.
- Reported alongside: counts of passed/failed/blocked/not_evaluable/
  pipeline_failure/metadata_gaps/harness errors, per-fixture rows, FP and
  FN details, and `other_findings`.

`null` is rendered as "n/a" in the dashboard. A metric is never coerced
to 0 or 1 when mathematically undefined.

## 7. Evidence quality checks (per matched detection)

For each TP detection the harness validates and stores:

1. Location present (`affected_contract` + `affected_function`, and
   `affected_lines` when Slither provided them — never invented).
2. ≥1 `FACT` evidence item with `source`/`tool` recorded (provenance:
   static-analysis tool).
3. `description` explains the unsafe behavior (non-empty; verbatim tool
   description is preserved in evidence excerpts).
4. `remediation` presence recorded per finding (recorded as a boolean;
   absence is a documented gap, not a failure).
5. `prerequisites`/`assumptions` recorded (conditions for exploitation).
6. Count of `AI_OPINION` items — must be reported separately and never
   substituted for facts. Pipeline findings are `UNVERIFIED` with FACT
   tool evidence; the benchmark never upgrades epistemic status.

Confirmed fact vs hypothesis: a matching finding is reported as
"static-analysis detection with FACT tool evidence, status UNVERIFIED" —
the benchmark does not assert exploitability beyond what the tool output
states.

## 8. Isolation

- Results persist to `benchmark_store.db` (override: `AUDITOR_BENCHMARK_DB`).
  `audit_scan_history.db` is never opened for writes by benchmark code or
  tests.
- Tests use temporary fixture copies and temporary databases only.
- The harness shells out to local Slither only when invoked explicitly
  (`audit.py benchmark`); the automated test suite mocks the pipeline for
  determinism.

## 9. Phase 15 amendments (versioned: protocol v2, 2026-10-13)

Written before any Phase 15 fixture was scored. Amendments only — §1–§8
remain in force.

### 9.1 Categories
Two categories join the scored set, same pairing and evaluable rules as
§5: `delegatecall` (detector: `controlled-delegatecall`) and
`arbitrary_transfer` (detector: `arbitrary-send-eth`). Manifest entries
carry `schema_version: 2`; fixtures of either new category enter the
scored corpus only after the vulnerable case fires the expected channel
and the safe case has been reviewed for relevant false positives under
solc 0.5.8 + slither 0.11.6 (probe evidence recorded in
`benchmarks/README.md`).

### 9.2 Manifest validation additions
- `schema_version` is required and must be 1 or 2.
- **Source-label consistency**: for every fixture with `evaluable: true`,
  the strings `expected_contract` and `expected_function` must both occur
  in the fixture source file. A violation is a fatal `ManifestError`
  (configuration defect — never silently scored as a false negative).
- Missing fixture files remain per-fixture `skipped` (§4), not fatal.

### 9.3 Independent reconciliation (consistency check, NOT truth)
For each fixture the harness compares the raw Slither detector list of
the completed run against the application's surfaced findings:

| Observation | Meaning |
|---|---|
| `surfaced` | raw detector maps to ≥1 surfaced finding (by slug) |
| `excluded_informational` | raw detector is policy-excluded (Informational impact) |
| `missing` | raw non-informational detector has no surfaced finding |
| `surfaced_without_raw` | surfaced finding's slug absent from raw detectors |

Counts are reported per fixture and aggregated. Reconciliation NEVER
changes a verdict: a raw emission alone cannot establish a TP, and a
`missing` observation alone cannot establish an FN — the §3 matcher
remains the sole verdict path. Analyzer execution failures, compilation
failures, and unsupported detector/compiler combinations are reported in
their existing §4 buckets and additionally flagged in the reconciliation
block (`raw_status != completed`).

### 9.4 Metrics additions
Reported alongside §6: corpus size, evaluable denominator, counts of
`not_evaluable`, `blocked`, `skipped`, `pipeline_failure`,
`harness_error`, reconciliation discrepancies, cross-category
(`other_findings`) totals, toolchain versions, and duration. Unevaluable
fixtures are never TN; pipeline failures are never hidden by exclusion —
they appear in their own counters and in the fixture table.

### 9.5 Determinism
Two runs are compared on a normalized fingerprint: fixture rows
(identifiers, statuses, verdicts, matches, other-findings, reconciliation)
+ metrics + totals excluding `duration_seconds`, timestamps, and
`run_id`. Any diff beyond those unstable fields is nondeterminism and
must be investigated, not tolerated.

### 9.6 Baselines and regression gates
- A baseline is an explicitly stored run marked in `benchmark_store.db`
  (additive columns `is_baseline`, `toolchain_fingerprint`,
  `corpus_fingerprint`; single-baseline invariant; migration idempotent).
- Baseline rejection rules: run `status != completed`, any `skipped` or
  `harness_error` fixture, or an existing baseline unless explicitly
  overridden — never an implicit overwrite.
- **Fingerprints**: toolchain = slither/solc/forge versions (and
  availability); corpus = manifest fixture ids + labels + accepted
  channels. Both recorded on the baseline and on comparison.
- **Comparison output** (`compare_runs(current, baseline)`): toolchain
  match flag, corpus match flag, added/removed fixture ids, per-fixture
  verdict transitions on common fixtures, metric deltas, and
  `regressions`.
- **Regression definition**: (a) any common fixture whose verdict
  downgrades TP→FN, TP→FP, TN→FP, or any verdict → blocked/pipeline_
  failure is a regression, whatever the corpus; (b) when corpora match,
  any decrease in precision, recall, or F1 is a regression. Corpus
  changes are reported as `corpus_changed: true` and never silently
  become verdict regressions. Toolchain mismatch ⇒ `comparable: false`;
  verdict/metric judgments are suppressed (explicitly reported as
  not-comparable), never presented as like-for-like.
- CLI: `audit.py benchmark --baseline` exits nonzero when `regressions`
  is non-empty **or** the comparison is not like-for-like (missing
  fingerprints, toolchain or corpus mismatch — fail-closed gate; gate
  lines on stderr; JSON stdout stays parseable and carries the
  comparison under `comparison`). `--set-baseline` records the current
  run as baseline; rejected for incomplete runs (`status != completed`,
  skipped/harness-error fixtures) and, when a different baseline exists,
  only accepted together with `--force` (explicit override).

## 10. Phase 16 amendments (versioned: protocol v3, 2026-10-15)

Amendments only — §1–§9 remain in force. Written before any Phase 16
benchmark run was stored or marked as a baseline; the two fixtures below
were probe-run (unsaved, `--no-save`) to gather the evidence in
`benchmarks/README.md`, exactly as §9.1 requires.

### 10.1 Source-analysis channel
The scored pipeline now includes the source-pattern analyzers the scan
job runs (`oracle_staleness`, `erc4626_inflation`, `pool_accounting`)
alongside the three Slither families. A source-analysis finding can be a
category channel **only** when its description carries
`Source detector: <slug>.`; the slug is extracted by the same rule as
`Slither detector: <slug>.` (§2 L3 order unchanged). Today only
`erc4626-inflation` emits a slug; the other source analyzers have none
and stay `other_findings` (unscored) on every fixture.

The §3 rules are unchanged: contract + function equality and ≥1 `FACT`
evidence item (for a source analyzer, the matched source excerpt) are
still required. A source-analysis finding remains a hypothesis
(`UNVERIFIED`); a TP here means "the pattern scanner fired where the
ground truth says it should", not that the vault is exploitable.

### 10.2 Category
`erc4626_inflation` (slug `erc4626-inflation`, family `generic`),
fixtures VAULT-001 (vulnerable) / VAULT-002 (safe, virtual offset).
Manifest `schema_version: 3` (1–3 accepted).

### 10.3 Reconciliation
Source-analysis findings have no raw Slither counterpart by construction
and are excluded from §9.3 reconciliation input (they never appear as
`surfaced_without_raw`).

### 10.4 Comparability
Adding the category changes the corpus fingerprint; per §9.6 a v2
baseline compared with a v3 run reports `corpus_changed: true` and needs
a fresh baseline (`--set-baseline --force`) — never a silent
like-for-like comparison.

## 11. Phase 19 amendments (versioned: protocol v4, 2026-10-18)

Amendments only — §1–§10 remain in force. Written before any Phase 19
benchmark run was stored; the four fixtures below were probe-run unsaved
(`--no-save`) exactly as §9.1 requires.

### 11.1 Category and channel
`scam_honeypot` (family `generic`), produced by the source-level
`honeypot` analyzer, whose descriptions carry `Source detector: <slug>.`
(§10.1 extraction rule). Scored slugs: `quiz-honeypot` (HONEY-001
vulnerable / HONEY-002 safe: answer hash fixed at deployment, no
privileged change/withdraw) and `transfer-blocking-token` (SCAM-001
vulnerable / SCAM-002 safe plain token). The analyzer's other slugs
(`payout-lure`, `hidden-owner-drain`, `unlimited-owner-mint`) have no
fixture yet and stay `other_findings` wherever they fire. A TP means the
pattern scanner fired where the ground truth says the contract is a
scam/honeypot shape — the risk is to users who interact, not an
exploitable bug. Manifest `schema_version: 4` (1–4 accepted).

### 11.2 Triage in the scored pipeline
The scored pipeline applies the same triage as the scan paths
(`auditor/triage.py`): findings in recognised library code and curated
known-benign patterns are suppressed; admin-gated withdraws to msg.sender
are downgraded to INFORMATIONAL. No benchmark fixture contains library
code, and a downgrade changes severity only (never used by §3), so triage
cannot change a verdict on the current corpus. Suppressed findings are not
`other_findings`.

### 11.3 Comparability
The new category changes the corpus fingerprint; a v3 baseline compared
with a v4 run reports `corpus_changed: true` and needs a fresh baseline
(`--set-baseline --force`).

## §12 Privileged-function authorization (Phase 25)

Source-analysis channel (`category: privileged_auth`, analyzer
`privileged_auth`). Detectors:

- `privileged-auth-unprotected` — privileged entry point with no msg.sender/role guard
- `privileged-auth-weak` — tx.origin auth, check-after-effect, open initializer, etc.
- `privileged-auth-protected` — INFORMATIONAL centralization note (does not match
  vulnerable fixtures' accepted_checks; safe fixtures use unprotected/weak as the
  channel they must *not* fire)

Fixtures PAUTH-001..008. Manifest may keep `schema_version: 4`.

