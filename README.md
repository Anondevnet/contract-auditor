# Contract Auditor

[![CI](https://github.com/Anondevnet/contract-auditor-demo/actions/workflows/ci.yml/badge.svg)](https://github.com/Anondevnet/contract-auditor-demo/actions/workflows/ci.yml)

![Demo](docs/demo.gif)

*Demo GIF placeholder — add a short recording of a paste/upload scan here.*

*Live URL placeholder — this repository stays private until a public deploy is approved.*

A local-first Solidity static analyzer (Slither + pragma-picked solc) with an optional public paste/upload demo. Epistemic labels keep tool output distinct from AI commentary.

This is a defensive auditing tool. It does not send transactions, it does not touch funds, and in public demo mode it never reads a local filesystem path, a chain address, Keychain secrets, or live-network hunt/monitor surfaces.

## What it is

- **Local mode** (default): the existing loopback dashboard and CLI (`audit.py scan PATH`, scan-address, history, investigation). Binds `127.0.0.1` only.
- **Public demo mode** (`AUDITOR_MODE=public`): a small page where you paste or upload a single `.sol` file (200 KB cap). Findings are grouped by severity and labeled `FACT` / `INFERENCE` / `HYPOTHESIS` / `UNKNOWN` / `AI_OPINION`. JSON API plus `/health`.

## Architecture

```mermaid
flowchart LR
  subgraph publicMode ["Public mode"]
    Browser["Browser paste / upload"] --> PublicApp["FastAPI public demo"]
    PublicApp --> Limits["IP rate limit + concurrency cap"]
    Limits --> Scan["Temp dir + solc-select + Slither"]
    Scan --> Findings["Findings + epistemic labels"]
  end
  subgraph localMode ["Local mode"]
    CLI["audit.py CLI"] --> Pipeline["Analyzers + scan history"]
    Dash["Loopback dashboard"] --> Pipeline
    Pipeline --> Tools["Slither / solc / optional Foundry"]
  end
  subgraph llm ["Optional LLM"]
    Provider["provider: none | ollama | openai_compatible"]
    Provider --> Opinion["AI_OPINION only"]
    Provider --> Cap["Daily spend cap"]
  end
  Findings -.-> Provider
```

Public mode does not mount monitor, hunt, discovery, fork/anvil, finrisk, bounty/patch, or price/RPC routes.

## Epistemic labels

| Label | Meaning |
|---|---|
| `FACT` | Directly observed (tool output, source text, a retrieved artifact). |
| `INFERENCE` | A reasoned conclusion from facts, still not a proof. |
| `HYPOTHESIS` | A possible explanation that needs more evidence. |
| `UNKNOWN` | The system does not have the information. |
| `AI_OPINION` | Model-generated text. It cannot, by itself, make a finding `CONFIRMED` or `LIKELY`. |

Severity and confidence are independent of these labels.

## How to run

### Local (default)

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
# system tools: slither, solc-select (and optional Foundry for the local research path)
python3 audit.py status
python3 audit.py scan path/to/Contract.sol
python3 audit.py dashboard          # http://127.0.0.1:8080
```

### Public demo mode

```bash
export AUDITOR_MODE=public
export AUDITOR_LLM_PROVIDER=none    # default in public mode
python3 audit.py dashboard          # binds 0.0.0.0:8080
```

CLI commands that use a local path, a chain address, monitor, hunt, or a fork refuse to run in public mode.

### Docker

```bash
docker compose up --build
# then POST a sample:
curl -sS -X POST http://127.0.0.1:8080/api/scan \
  -H 'Content-Type: application/json' \
  --data-binary @- <<'EOF'
{"filename":"reentrancy.sol","source":"pragma solidity ^0.8.0; contract InsecureVault { mapping(address=>uint256) public balances; function deposit() external payable { balances[msg.sender]+=msg.value; } function withdraw() external { uint256 a=balances[msg.sender]; (bool ok,)=msg.sender.call{value:a}(""); require(ok); balances[msg.sender]=0; } }"}
EOF
```

The image is `python:3.11-slim` with Slither, solc-select, and a set of solc versions preinstalled, running as a non-root user. Foundry is not included because the demo path does not need it.

## Config

`config/default.json` plus environment variables:

| Variable | Role |
|---|---|
| `AUDITOR_MODE` | `local` (default) or `public` |
| `AUDITOR_LLM_PROVIDER` | `none` / `ollama` / `openai_compatible` |
| `AUDITOR_LLM_API_KEY` | Key for `openai_compatible` only; never committed |
| `AUDITOR_LLM_BASE_URL` | OpenAI-compatible base URL |
| `AUDITOR_LLM_MODEL` | Model name |
| `AUDITOR_MAX_UPLOAD_BYTES` | Default 204800 (200 KB) |
| `AUDITOR_RATE_LIMIT_PER_HOUR` | Default 10 scans / IP / hour |
| `AUDITOR_MAX_CONCURRENT_SCANS` | Default 2 |
| `AUDITOR_SCAN_TIMEOUT_SECONDS` | Default 90 |
| `AUDITOR_DAILY_SPEND_USD` | Daily LLM spend cap; **0** in public mode unless you set it |
| `AUDITOR_MAX_OUTPUT_TOKENS` | Per-request output cap (default 1500) |
| `AUDITOR_PUBLIC_DATA_DIR` | Rate-limit + spend SQLite files |
| `AUDITOR_TRUST_X_FORWARDED_FOR` | Set to `1` only behind a trusted proxy |

Ollama remains the existing loopback-only client. Public mode defaults the provider to `none` even if `default.json` still names an Ollama model.

## Safety limits

- Single `.sol` file, size cap, subprocess timeout.
- Per-IP rate limit and a global concurrency cap.
- Daily token/$ ledger in SQLite; a request that would exceed the cap is refused **before** any HTTP call.
- No Keychain reads, no Etherscan, no RPC, no anvil forks in public mode.
- Structured JSON logs record request id, route, duration, and scan outcome — not source code or secrets.

## Tests and CI

```bash
pip install -r requirements.txt pytest
python -m pytest tests/ -q
```

GitHub Actions runs the full suite on push and pull request (Python 3.11, Slither, solc-select, a matrix of solc versions, pip cache).

## License

This repository is private. A public license has not been chosen yet; all rights reserved until then.
