#!/usr/bin/env bash
# shellproof — full pipeline runner
# Usage: ./run.sh <target-url> [extra shellproof flags...]
#   e.g. ./run.sh https://target.example.com
#        ./run.sh https://target.example.com --node2shell --insecure
#
# Runs the Rust probe layer (--json → stdout), then pipes the JSON through the
# OCaml interpreter for the final schema-conformant verdict report.
#
# VertexElite Security Research

set -euo pipefail

TARGET="${1:-}"
if [[ -z "$TARGET" ]]; then
    echo "Usage: $0 <target-url> [extra shellproof flags...]"
    echo "  default: runs all four probes (111497, 109618, 109619, 115560)"
    echo "  per-CVE: --node2shell --php-oom --php-stale --php-session"
    exit 1
fi
shift || true
EXTRA=("$@")

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Pick up a rustup toolchain if cargo isn't already on PATH.
if ! command -v cargo >/dev/null 2>&1 && [[ -f "$HOME/.cargo/env" ]]; then
    # shellcheck disable=SC1091
    . "$HOME/.cargo/env"
fi

BIN="target/release/shellproof"
if [[ ! -x "$BIN" ]]; then
    echo "[*] Building Rust probe layer (release)..." >&2
    cargo build --release
fi

echo "╔══════════════════════════════════════════════════════╗" >&2
echo "║  shellproof — VertexElite Security Research          ║" >&2
echo "║  PHP2Shell + Node2Shell behavioral patch-diff scan   ║" >&2
echo "╚══════════════════════════════════════════════════════╝" >&2
echo "[*] Target : $TARGET" >&2
echo "" >&2

RAW="/tmp/shellproof_raw_$(date +%s).json"

# Run probes — JSON report to stdout (progress goes to stderr). `|| true` so a
# vulnerable exit code (1) does not abort the pipeline under `set -e`.
"$BIN" "$TARGET" --json "${EXTRA[@]}" > "$RAW" || true

echo "[*] Raw probe JSON → $RAW" >&2

INTERP="ocaml/_build/default/shellproof_interp.exe"
if [[ -x "$INTERP" ]]; then
    echo "[*] Running OCaml interpreter..." >&2
    echo "" >&2
    "$INTERP" < "$RAW"
else
    echo "[!] OCaml interpreter not built — emitting raw Rust JSON." >&2
    echo "[!] To build: cd ocaml && dune build  (needs: opam install dune yojson)" >&2
    cat "$RAW"
fi
