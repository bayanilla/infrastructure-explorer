# Architecture and engineering decisions

The design applies principles from the four books to a local routing-context
proof of concept. It does not claim to implement every technique in those books
or to meet a production-service standard.

## Responsibilities

```text
Browser inputs
  → local HTTP validation
  → IP / ASN / Footprint orchestration
  → RIPE adapters behind one paced HTTPS gate
  → normalized source evidence
  → pure routing / footprint calculations
  → canonical report builders
  → optional read-only Shodan retrieval, retained as separate service evidence
  → UI / JSON / CSV / standalone HTML / browser PDF
```

| Module | Knowledge hidden behind its interface |
| --- | --- |
| `validation.py` | Address syntax, reserved ranges, CSV rejection and normalization rules |
| `sources/gateway.py` | Verified TLS, allowlisted redirects, pacing, retries, cancellation, response/cache bounds |
| `sources/stat.py`, `sources/atlas.py` | Endpoint formats, response fields, measurement eligibility and source times |
| `sources/shodan.py`, `sources/service_inputs.py` | Server-memory credentials, fixed read-only Shodan endpoints, separate pacing, bounded resources/responses/details, and source states |
| `model.py` | BGP evidence-state invariants, immutable nested snapshots, coverage propagation |
| `analysis/` | Reproducible route selection, aggregation, graph counts, safe covering-prefix reuse |
| `workflows/` | Which sources to request, bounded enrichment, progress, analyst confirmation |
| `reports/` | Report shape, mode-specific explanations, schema and saved-report migration |
| `jobs.py` | Run lifecycle, completion, cancellation, capacity, retention and snapshot isolation |
| `server.py` | Loopback HTTP, request limits, Host/Origin checks and explicit asset routes |
| `web/render/` | Pure formatting, tables, maps, CSV and HTML, plus the shared asynchronous poller |
| `web/app.js` | Browser events and application state |

The compatibility entry point calls the package. A separate `test_support.py`
facade lets the existing regression fixtures exercise moved functions without
making production modules depend on the old monolith.

## A Philosophy of Software Design

Source access is a deep module: callers ask for public evidence instead of
coordinating TLS, retries and cache behavior. Pure calculations hide routing
counting details; report builders own report wording. Footprint resolution now
has explicit per-run state instead of several closures sharing mutable knowledge.

Modules follow responsibilities, not a rule that every function needs its own
file. IP and ASN orchestration share normalization and calculations where their
meaning agrees. A dedicated report builder owns their differing summaries and
unknown-count treatment; ASN mode no longer patches IP summaries.

Tradeoff: dictionaries remain at the existing report/export boundary to preserve
compatibility. BGP evidence is typed internally; Atlas and Footprint adapter
records remain normalized dictionaries with their established source states.
Moving every field to a class is not required for this refactoring.

## The Pragmatic Programmer

The existing behavior is the starting contract. Five representative reports were
captured from the unchanged application using synthetic responses. Characterization
checks compare the revised reports with those baselines, excluding documented
transport metadata changes. Existing regression assertions remain alongside new
invariant and failure tests.

Configuration owns limits and source endpoints. A generated limits document is
checked for drift. Pure renderers consume one report record; presentation filters
do not recalculate routing evidence. Migration has one server-side implementation.

Changes are reversible: this edition runs in a separate directory and on a
separate port. It introduces neither enforcement nor active measurement scheduling.

## Software Engineering at Google

Tests cover behavior and contracts rather than file layout: source validation,
more-specific routing, unknown versus empty evidence, immutable snapshots,
cancellation, cache bounds, imports, HTML escaping, CSV formulas and HTTP boundaries.
Renderers are imported directly in Node, removing the old function-extraction tests.

CI is configured for Python 3.10 and 3.14, with Node-based renderer/poller checks,
Ruff lint/format checks, and generated-document checks. Tooling is separate from
runtime dependencies. Locally, verification used Python 3.14 and Node 24.

Remaining maturity work includes independent review, a published release process,
compatibility tests on additional platforms, and verification of remote CI results.
Automated tests are evidence of checked behavior, not a routing-accuracy benchmark.

## Designing Data-Intensive Applications

Available-empty, partial, unavailable and unrequested are distinct evidence
states. An immutable BGP snapshot records source query, observation time,
retrieval time and coverage. A derived partial count retains its partial status
and coverage rather than becoming a complete total. Retrieval times are kept
with cached responses and are never substituted for source observation times.

Reports have an explicit schema version. Migration copies inputs and preserves
historical times; future schemas and conflicting old/new fields are rejected.
Imported data remains a user-supplied record, not authenticated RIPE evidence.

The shared HTTP gate provides backpressure. Bounds limit uploads, responses,
lookups, expansion, runs and serialized cache size. Cache exhaustion causes a
later request to refetch; it never discards a lookup result or reports zero.
Cancelled jobs can leave the gate while another job holds it; in-flight I/O is
limited by a timeout. Retry-After waits over an hour end with an explicit error
rather than issuing an early retry.

Tradeoff: the run store is ephemeral. There is no transactional durable evidence
store, crash recovery or distributed processing. Explicit exports suit the
current local privacy boundary. If resumability becomes a requirement, introduce
SQLite behind the run-store interface with transactional snapshots, schema
migrations, retention/deletion rules, restart handling and analyst-confirmation
provenance. That would be a distinct feature with its own tests.

## Contracts and limits

- Calculations accept normalized evidence and produce context without I/O or a
  wall-clock dependency. Source capture and generation clocks are orchestration concerns.
- Successfully empty evidence may yield zero. Unavailable or unrequested BGP
  evidence yields unknown totals. Partial totals describe processed evidence only.
- A job's terminal state and report become visible together under its lock.
  Browser polling is sequential, with bounded retries for transport failures.
- Report schema `/1` adds version identification while preserving the existing
  report structure. Unknown fields can be retained; imports validate the envelope
  and key structures, not every nested source field. Renderer errors remain explicit.
- Local APIs have no authentication and are not suitable for shared deployment.
- The JSON cache budget bounds serialized size; Python object overhead and
  calculated reports consume additional memory.
- Source observations do not prove packet paths, topology or commercial relationships.

## References

These are engineering applications, not quotations or claims of author endorsement.

- John Ousterhout, *A Philosophy of Software Design*.
- Andrew Hunt and David Thomas, *The Pragmatic Programmer*.
- Titus Winters, Tom Manshreck and Hyrum Wright, *Software Engineering at Google*.
- Martin Kleppmann and Chris Riccomini, *Designing Data-Intensive Applications*, second edition.


## Optional service observations

The Shodan adapter has its own serialized one-second request gate, verified TLS,
redirect rejection, 20-second timeout, and 2 MiB response bound. It does not use
RIPE transport retries or the RIPE per-run cache. Its allowlist permits existing
host/search records and account checks only. There is no scan endpoint.

Credentials live on the local server's adapter instance and never enter report
records. Browser Settings submits a key, clears the input, and displays only
configuration/check status. Tabs share the server credential; removal/restart
clears it. This is an ephemeral local connection, not a multi-user secret store.

Browser orchestration optionally retrieves Shodan evidence after a routing run
and attaches `service_observations`. Source failures remain distinct from empty
results and do not replace routing evidence. Report renderers consume those
records for live tables and exports. Twenty-row display pagination is independent
of explicit 100-record source paging. Page merges preserve source provenance and
deduplicate service identities; they are not a transactional upstream snapshot.

Tradeoffs: the browser currently coordinates service enrichment and additional
page merging; those responsibilities are not yet server-side workflow contracts.
Shodan limits are adapter-local rather than part of the generated limits table.
Imported report envelopes are validated, but not every nested service field is
schema-validated. These remain maintainability and validation considerations,
not reasons to claim that existing observations are independently verified.

Footprint per-ASN map requests are separate Explore ASN jobs. The live report
renders their map above the expandable ASN rows without merging that lookup into
the Footprint JSON/CSV model. This export boundary is explicit in the analyst
documentation.
