#!/bin/zsh
# Run a hunt cycle with Keychain-backed RPC (macOS).
# Secrets via scripts/_env.sh — never echoed.
#
# Full-coverage pool example (after eth-rpc-url is saved):
#   scripts/run_hunt.sh --once --with-pools --pool-lookback 200000 --min-holder-usd 10000 \
#     --no-blue-chips --max-scan 10 --max-measure 40
set -euo pipefail
cd "$(dirname "$0")/.."
export PATH="$HOME/.local/bin:/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:$PATH"
[[ -d .venv/bin ]] && export PATH="$PWD/.venv/bin:$PATH"
[[ -d "$HOME/.foundry/bin" ]] && export PATH="$HOME/.foundry/bin:$PATH"
[[ -d "$HOME/.pyenv/versions/3.11.9/bin" ]] && export PATH="$HOME/.pyenv/versions/3.11.9/bin:$PATH"

# shellcheck source=scripts/_env.sh
source "$(dirname "$0")/_env.sh"
auditor_load_env

echo "hunt: starting (RPC from Keychain eth-rpc-url or public fallback; URL not logged)" >&2
# Disk pressure gate lives inside Hunter.cycle (auditor.disk_pressure).
python3 -c "from auditor.disk_pressure import get_controller; import json; print('disk:', json.dumps(get_controller().status(), default=str)[:400])" >&2 || true
exec python3 audit.py hunt "$@"
