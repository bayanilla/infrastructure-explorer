# Infrastructure Explorer contributor instructions

## Product boundary

This repository contains the current passive Múcaro Infrastructure Explorer
prototype. IP/prefix lookup is primary; ASN exploration provides broader context.
Preserve the user's explicit mission: observe, identify, enrich, map, explain,
report, then stop. Do not add enforcement advice, active probes, automatic blocking,
or firewall changes without a separate explicit request.

The BGP lookup application is a read-only subject-matter and visual reference.
Do not modify it or introduce a runtime dependency on its checkout.

## Evidence

- Separate observed evidence, reproducible derived measurements, inferred
  relationships, and unknown findings. Preserve provenance and source dates.
- BGP advertisements are not packet paths. Current prefix-origin mapping is not
  historical evidence or verified router ownership. Adjacency is not proof of a
  provider relationship, government control, or traffic share.
- Never label networks, ASNs, providers, or organizations malicious or safe.
- Keep failed, unrequested, unknown, and successfully observed empty results
  distinct. Show sample denominators, filtering, truncation, and coverage limits.
- UI and exports consume one canonical report model; escape all untrusted content.

## Engineering

These are applications of [The Pragmatic Programmer](https://pragprog.com/tips/)
and [A Philosophy of Software Design](https://web.stanford.edu/~ouster/cgi-bin/book.php),
not quotations from those books.

- Keep each domain rule authoritative in one place; minimize coupling.
- Prefer cohesive modules with small interfaces that hide parsing and source quirks.
- Validate input explicitly; define invariants and failure outcomes.
- Prefer small, reversible changes and appropriate automated verification.
- Avoid unrelated refactoring, premature frameworks, and duplicated policy logic.

## Source access and privacy

- Read existing public data only; never contact investigated hosts.
- Keep fixed source adapters, bounded jobs/responses, cancellation, TLS verification,
  Host/Origin checks, and the shared RIPE request gate with at least two-second spacing.
- Disclose targets and measurement IDs sent to RIPE. Do not claim anonymity,
  encrypted storage, or production readiness without implemented verification.
- Do not commit credentials, reports, captures, cache contents, lookup history,
  or private observations. Synthetic fixtures must be unmistakably labeled.
- Preserve user work; do not commit, push, publish, or deploy without authorization.

## Verification

Run `python3 -m unittest -v` and
`node test_report_rendering.js report_fixtures.json` for relevant source changes.
Use frozen fixtures for routine tests; live-source checks remain separate.
Inspect UI interaction/layout when touched, and inspect the final Git diff/status
including `git diff --check`. Report only checks that actually ran.
