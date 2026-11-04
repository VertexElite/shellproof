# shellproof

**Prove whether your server is patched** against the late-2026 "shell" vulnerability
cluster — without guessing and without deep internals knowledge.

shellproof is a *patch-proof* scanner. It works backwards from each public patch:
it asks whether your server behaves like the **pre-patch (broken)** path or the
**post-patch (fixed)** path, and reports a clear verdict — `PATCHED`,
`VULNERABLE`, `INCONCLUSIVE`, or `N/A` — with the fix you need.

It is written in **Rust** (network + payload + observation) and **OCaml** (typed
result interpretation + report generation): memory-safe languages, so the prover
cannot itself trigger the memory-corruption bug class it measures.

## Coverage

| CVE | Alias | Class | Patched in |
|-----|-------|-------|-----------|
| CVE-2026-111497 | Node2Shell / HTTP2Shell | Brotli decoder OOB write | Node 22.23.4 / 24.22.1 / 26.12.1 · Brotli 1.2.1 |
| CVE-2026-109618 | PHP2Shell-OOM | OOM corruption on request cleanup | PHP 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 |
| CVE-2026-109619 | PHP2Shell-Stale | Stale FPM global state (UAF) | PHP 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 |
| CVE-2026-115560 | PHP-Session | upload-progress serializer mismatch | *no code patch* — set `session.upload_progress.enabled=0` |

## Safe by default

A plain run is **passive**: it compares the server's fingerprinted version against
the patch lines and inspects features. **No crash-inducing payloads are sent.**

```bash
shellproof https://your-site.example          # passive, safe — just tells you if you're patched
```

The behavioral crash-diff probes are **opt-in** and gated:

```bash
shellproof https://127.0.0.1:8099 --active                 # local target: allowed
shellproof https://your-site.example --active --authorized # remote: requires you to confirm authorization
```

`--active` sends malformed Brotli / memory-pressure / stale-state payloads and can
disrupt an **unpatched** worker — only ever point it at infrastructure you own or
are explicitly authorized to test.

## Output

Human summary by default, or machine-readable JSON (`report_schema.json`):

```bash
shellproof https://your-site.example --json            # JSON report to stdout
shellproof https://your-site.example -o report.json    # write JSON to a file
./run.sh https://your-site.example                     # full Rust → OCaml pipeline
```

## Build

```bash
# Rust layer
cargo build --release          # → target/release/shellproof

# OCaml interpreter (optional, for the final report shaping)
cd ocaml && dune build         # needs: opam install dune yojson
```

## Local test targets

`test-targets/` ships a PHP app (sessions + json_decode) and a zero-dep Node Brotli
decoder for validating the probes against real stacks on `127.0.0.1`:

```bash
./test-targets/serve.sh        # PHP on :8099, Node on :8090
```

## Scope & ethics

shellproof is a **defensive patch-verification** tool for operators to check their
own servers and for authorized security testing. It is not a mass scanner and ships
no exploit. See [SECURITY.md](SECURITY.md).

---
VertexElite Security Research · MIT License
