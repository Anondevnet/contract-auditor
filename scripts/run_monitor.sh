#!/bin/zsh
# Phase 18.1 — run the deployment monitor persistently (macOS).
#
# Secrets come from the macOS Keychain via scripts/_env.sh (never logged):
#   security add-generic-password -a "$USER" -s etherscan-api-key -w
#   security add-generic-password -a "$USER" -s eth-rpc-url -w
set -euo pipefail
cd "$(dirname "$0")/.."
# Tools (python, slither, solc-select) — adjust if they live elsewhere.
export PATH="$HOME/.local/bin:/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:$PATH"
[[ -d .venv/bin ]] && export PATH="$PWD/.venv/bin:$PATH"
[[ -d "$HOME/.foundry/bin" ]] && export PATH="$HOME/.foundry/bin:$PATH"
[[ -d "$HOME/.pyenv/versions/3.11.9/bin" ]] && export PATH="$HOME/.pyenv/versions/3.11.9/bin:$PATH"

# shellcheck source=scripts/_env.sh
source "$(dirname "$0")/_env.sh"
auditor_load_env

if [[ -z "${ETHERSCAN_API_KEY:-}" ]]; then
  echo "error: ETHERSCAN_API_KEY missing (Keychain service etherscan-api-key)" >&2
  exit 1
fi
# Do not print which RPC was selected (may contain an Alchemy path key).
echo "monitor: starting (RPC from Keychain eth-rpc-url or public fallback; URL not logged)" >&2

mkdir -p reports
exec python3 audit.py monitor --network ethereum --interval 60 --min-severity high "$@"
