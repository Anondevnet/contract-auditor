# Shared env bootstrap for monitor / hunt (macOS Keychain).
# Sourced by run_monitor.sh / run_hunt.sh — never echo secrets or RPC URLs.
#
# Keychain entries (create once, not stored in this repo):
#   security add-generic-password -a "$USER" -s etherscan-api-key -w
#   security add-generic-password -a "$USER" -s eth-rpc-url -w   # Alchemy HTTPS URL
#
# If eth-rpc-url is absent, AUDITOR_MONITOR_RPC_URL falls back to a public RPC.

_AUDITOR_PUBLIC_RPC_FALLBACK="https://ethereum.publicnode.com"

_auditor_keychain_get() {
  # Quietly read a generic password; empty stdout on miss. Never prints the value.
  local service="$1"
  security find-generic-password -s "$service" -w 2>/dev/null || true
}

auditor_load_env() {
  # Public demo must never read the macOS Keychain (or load explorer/RPC secrets).
  if [[ "${AUDITOR_MODE:-}" == "public" ]]; then
    return 0
  fi

  # Etherscan (required for most live scans)
  if [[ -z "${ETHERSCAN_API_KEY:-}" ]]; then
    local _ek
    _ek="$(_auditor_keychain_get etherscan-api-key)"
    if [[ -n "$_ek" ]]; then
      export ETHERSCAN_API_KEY="$_ek"
    fi
  fi

  # Ethereum HTTPS RPC — prefer Keychain eth-rpc-url when present
  if [[ -z "${AUDITOR_MONITOR_RPC_URL:-}" ]]; then
    local _rpc
    _rpc="$(_auditor_keychain_get eth-rpc-url)"
    if [[ -n "$_rpc" ]]; then
      export AUDITOR_MONITOR_RPC_URL="$_rpc"
    else
      export AUDITOR_MONITOR_RPC_URL="$_AUDITOR_PUBLIC_RPC_FALLBACK"
    fi
  fi
  # Intentionally do not echo AUDITOR_MONITOR_RPC_URL or ETHERSCAN_API_KEY.
}
