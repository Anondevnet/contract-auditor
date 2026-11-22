# Real-World Validation Corpus — Design & Acquisition Plan

Status: **Step 2 deliverable (design only). Zero fixtures. Zero scored
entries.** Written before any real-world scan, download, or scoring run.
This directory holds the acquisition plan and schema; no `.sol` sources
are vendored here yet.

## 1. Purpose and separation policy

The synthetic benchmark (`benchmarks/manifest.json`, `benchmarks/fixtures/`)
proves harness consistency on original code. It does **not** establish
real-world detection accuracy. This corpus exists to evaluate the same
pipeline against **independently documented** real-world vulnerability
reports (and appropriately selected safe examples).

Hard separation rules:

- Separate manifest: `benchmarks/realworld_manifest.json` (created only
  when at least one fixture has defensible ground truth — see §3).
  Never modify `benchmarks/manifest.json`.
- Separate store and runs: `AUDITOR_BENCHMARK_DB` points at a
  dedicated file (e.g. `/tmp/phase15-bench.db` or
  `realworld_store.db`); the synthetic baseline
  (`benchmark_store.db`, baseline `B-1703e6278d78`) is never opened for
  writes and never receives real-world runs.
- Separate reporting: real-world results are reported as their own
  table and are **never** folded into synthetic precision/recall/F1
  aggregate claims.

## 2. Locally surveyed sources (Step 2, read-only)

| Source | License | Independent ground truth? | Decision |
|---|---|---|---|
| `~/contract-auditor/protocol/` (Hydro Protocol, 48 `.sol` under `contracts/`) | Apache-2.0 (LICENSE.txt) | **No** — repository contains README/CI/tests only; no audit report, advisory, or documented exploit for this source version. The 12 pipeline findings from the earlier smoke scan are detector output, not ground truth. | Not eligible as scored fixtures. May later enter only as `evaluable: false` execution-evidence entries, or as Tier-3 safe examples *if* an external audit/fix record is obtained. |
| `~/my-truffle-project/contracts/ERC20.sol` | Unknown | **No** — scratch project, no documentation | Not eligible |

No other local Solidity sources with documentation were found (Downloads
and project-adjacent directories surveyed). Therefore Step 2 ships **no
fixture entries**: fabricating vulnerability labels without independent
documentation would violate PROTOCOL §1 and the anti-gaming rule §5.

## 3. Ground-truth tiers (entry requirement)

Every future fixture must cite exactly one tier in `ground_truth_tier`:

- **T1 — Official audit report**: a public audit of the *exact source
  version* vendored (file hash recorded). Finding reference: firm,
  report URL, page/section, finding title.
- **T2 — Public exploit/post-mortem**: an independent write-up
  (project post-mortem, researcher disclosure, incident report)
  describing the vulnerable behavior in *this* contract's function,
  plus verified source (e.g. Etherscan/Sourcify match to the vendored
  hash).
- **T3 — Safe example with documented remediation**: code paired with a
  public fix commit or audit re-test showing the protective pattern;
  used only for `expected_label: safe` fixtures.

Anything weaker → `evaluable: false` with a specific `na_reason`
(e.g. "behavioral smoke only; no independent ground truth"), never
scored, never counted as TN.

## 4. Acquisition plan (requires separate approval before execution)

No downloads occur in Step 2. When approved:

1. **Candidate classes** (chosen for detector-operable patterns under
   the local toolchain — solc 0.5.8-era single-file sources preferred):
   historical public disclosures matching the accepted detector slugs
   (`reentrancy-eth`, `tx-origin`, `suicidal`, `unchecked-lowlevel`,
   `unchecked-send`, `divide-before-multiply`, `controlled-delegatecall`,
   `arbitrary-send-eth`). Examples of *document classes to research*,
   not pre-committed fixtures: The DAO-style call-order reentrancy,
   Parity-style delegatecall/library issues, tx.origin phishing
   disclosures, unchecked `.send`/`.call` loss reports.
2. **Verification per candidate** (all steps mandatory):
   a. Retrieve the independent report (T1/T2/T3) and archive its URL +
   retrieval date in the fixture's `ground_truth_ref`.
   b. Retrieve the verified source (Etherscan verified-source JSON or
   Sourcify metadata) matching the deployed code the report describes;
   record keccak/SHA-256 of the vendored file.
   c. Confirm the vulnerable (or protective) behavior **by reading the
   source** — the label is fixed by semantics, never by detector output
   (PROTOCOL §1).
   d. Confirm the pragma compiles under local solc 0.5.8 (or record the
   exact reason under `na_reason` if a newer pragma forces
   `evaluable: false`).
   e. Record license/terms of the source (Etherscan verified source is
   publicly displayed; vendoring respects the repository's stated
   license where one exists — note when none is stated).
3. **Vendoring**: copy sources into `benchmarks/realworld/` with stable
   names `RW-<NNN>-<slug>.sol`; one contract focus per file where
   practical; do not edit semantics (comments-only redaction of
   unrelated code is allowed if noted in `provenance`).
4. **Safe pairs**: for each vulnerable fixture, research a T3 safe
   counterpart where one exists; otherwise the vulnerable fixture may
   stand alone (metrics then reflect recall-side evidence only for that
   category — stated explicitly in results).
5. **Manifest**: create `benchmarks/realworld_manifest.json` with
   `schema_version: 2` and only entries that passed steps 2a–2e.

## 5. Manifest schema (superset of `validate_manifest` requirements)

Required core fields (identical names to the synthetic manifest —
enforced by `auditor.benchmark.validate_manifest`):

| Field | Real-world rule |
|---|---|
| `fixture_id` | `RW-<NNN>` prefix, stable |
| `file` | filename under `benchmarks/realworld/` |
| `category` | one of the seven protocol categories (`reentrancy`, `access_control`, `unchecked_call`, `arithmetic`, `privileged_change`, `delegatecall`, `arbitrary_transfer`) |
| `expected_label` | `vulnerable` or `safe`, fixed by source semantics + ground-truth tier |
| `expected_contract` / `expected_function` | exact identifiers occurring in the vendored source (validator cross-checks) |
| `expected_behavior` | plain-language description of the vulnerable/protective semantics, citing the ground-truth section |
| `accepted_checks` | detector slugs from the existing pipeline only (§2 of PROTOCOL.md) |
| `analyzer_family` | `reentrancy` \| `access_control` \| `generic` |
| `compiler` | exact local toolchain expectation (e.g. `solc 0.5.8 (PATH); pragma ^0.5.8`) |
| `requires_tools` | e.g. `["slither"]` |
| `evaluable` | `true` only when T1/T2/T3 ground truth exists **and** the detector is operable on the local toolchain (PROTOCOL §5) |
| `provenance` | synthetic-provenance string replaced by: acquisition method, retrieval date, source hash, ground-truth tier + citation |
| `na_reason` | required whenever `evaluable: false` (specific, per PROTOCOL §5) |

Real-world mandatory additions (validated by review checklist, since
`validate_manifest` ignores unknown keys):

| Field | Rule |
|---|---|
| `source_url` | Etherscan/Sourcify/GitHub URL the file was retrieved from |
| `local_source_ref` | path or URL of the exact bytes vendored |
| `source_sha256` | SHA-256 of the vendored file |
| `license` | SPDX id or `NOASSERTION` with note |
| `ground_truth_tier` | `T1` \| `T2` \| `T3` \| `none` |
| `ground_truth_ref` | report URL + section/page + retrieval date |

Template entry (documentation only — **not** a fixture, not part of any
manifest):

```json
{
  "fixture_id": "RW-001",
  "file": "RW-001-vulnerable.sol",
  "category": "reentrancy",
  "expected_label": "vulnerable",
  "expected_contract": "ExampleVault",
  "expected_function": "withdraw",
  "expected_behavior": "State update occurs after external call, per <report §N>.",
  "protection_control": null,
  "accepted_checks": ["reentrancy-eth"],
  "analyzer_family": "reentrancy",
  "compiler": "solc 0.5.8 (PATH); pragma ^0.5.8",
  "requires_tools": ["slither"],
  "evaluable": true,
  "na_reason": null,
  "provenance": "T2 acquisition YYYY-MM-DD from <URL>; source_sha256 <hash>; label fixed by source semantics + report.",
  "source_url": "<verified-source URL>",
  "local_source_ref": "<retrieval URL or archive ref>",
  "source_sha256": "<sha256>",
  "license": "NOASSERTION",
  "ground_truth_tier": "T2",
  "ground_truth_ref": "<report URL> §<section> (retrieved YYYY-MM-DD)"
}
```

## 6. Evaluability and toolchain constraints

- Same anti-gaming rules as PROTOCOL §5: `evaluable: false` only for
  (1) no detector class or (2) detector inoperable on solc 0.5.8 —
  never because a detector failed to fire (that is an FN).
- Multi-file/dependency-heavy contracts (imports, proxies, libraries
  outside the file) default to `evaluable: false` with `na_reason`
  citing the single-file offline constraint, unless the pipeline's
  project-aware path is explicitly exercised later (out of scope for
  the first real-world tranche).
- Findings for the wrong contract/function are misses under the
  existing three-rule matcher; do not adjust `expected_*` to match
  tool output.

## 7. Isolation requirements for all future runs

```bash
export AUDITOR_HISTORY_DB=/tmp/phase15-history.db
export AUDITOR_BENCHMARK_DB=/tmp/phase15-realworld-bench.db   # never the synthetic store
python3 audit.py benchmark --manifest benchmarks/realworld_manifest.json \
    --fixtures benchmarks/realworld --no-save --json
```

- Never pass `--set-baseline` or `--force` for real-world runs.
- Never point `AUDITOR_BENCHMARK_DB` at `~/contract-auditor/benchmark_store.db`
  or at any file named `audit_scan_history.db` (hard-rejected by
  `benchmark_store.open_store`).
- Synthetic regression gate remains a separate command against the
  copied baseline (Step 1), run independently.

## 8. Next step (awaiting approval)

Obtain approval to research and fetch 2–4 T2 candidates whose patterns
map to operable local detectors; vendor with hashes; write
`benchmarks/realworld_manifest.json` with only verified entries; run
the real-world benchmark with the isolation env above; report Tier-2
results separately from the synthetic table.
