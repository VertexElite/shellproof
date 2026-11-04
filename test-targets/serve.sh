#!/usr/bin/env bash
# Start the local shellproof test targets. For development/validation only —
# everything binds to 127.0.0.1. Ctrl-C to stop both.
#
#   PHP app   → http://127.0.0.1:8099/   (sessions + json_decode)
#   Node br   → http://127.0.0.1:8090/   (Brotli request decode)
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PHP_PORT="${PHP_PORT:-8099}"
NODE_PORT="${NODE_PORT:-8090}"
pids=()
cleanup(){ for p in "${pids[@]:-}"; do kill "$p" 2>/dev/null || true; done; }
trap cleanup EXIT INT TERM

if command -v php >/dev/null 2>&1; then
  ( cd "$HERE/php-app" && php -S "127.0.0.1:$PHP_PORT" ) & pids+=($!)
  echo "[*] PHP app   → http://127.0.0.1:$PHP_PORT/"
else
  echo "[!] php not found — PHP target skipped"
fi
if command -v node >/dev/null 2>&1; then
  ( PORT="$NODE_PORT" node "$HERE/node-brotli/server.js" ) & pids+=($!)
  echo "[*] Node br    → http://127.0.0.1:$NODE_PORT/"
else
  echo "[!] node not found — Node target skipped"
fi
echo "[*] Ctrl-C to stop."
wait
