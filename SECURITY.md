# Security & Responsible Use

## What shellproof is for

shellproof is a **defensive patch-verification** tool. It is intended for:

- Operators checking whether **their own** servers are patched.
- Security testing with the **explicit authorization** of the system owner.

It ships **no exploit code**. The default mode sends no crash-inducing payloads —
it compares versions and inspects features only.

## What it is not for

Do not use shellproof against systems you do not own or are not authorized to test.
The `--active` probes send malformed Brotli / memory-pressure / stale-state request
payloads that can disrupt an **unpatched** worker. Running them against third-party
infrastructure without permission may be unlawful and is not supported. `--active`
refuses non-local targets unless you pass `--authorized`.

## Reporting a vulnerability in shellproof

Email **research@vertexelite.io** with details. Please do not open a public issue
for a security report. We aim to acknowledge within 72 hours.

## Coordinated disclosure stance

shellproof detects already-public, already-patched CVEs. It exists to help
defenders confirm remediation quickly. Findings and detection logic are published
in that spirit — behavioral signals only, no weaponization.
