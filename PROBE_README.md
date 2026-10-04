# Múcaro | Infrastructure Explorer

A local, passive resource for exploring public routing context for an externally
observed IP. Start with one IP address, review its covering prefix and
origin ASN, then optionally **Explore ASN** for broader routing context.

The BGP reference repository remains read-only. This application runs independently
and preserves its seven visual themes.

## Run locally

Python 3.10+, standard library only:

```
python3 probe_server.py
```

Open <http://127.0.0.1:8767/>. Use a Python runtime with a working trusted CA store;
never disable certificate verification to fix a source-access error.

## Lookup workflow

- **Your footprint** is the default. Enter one IP or prefix, or upload a CSV or
  text file of IPs and prefixes,
  confirm which resolved origin ASNs are yours, and read their RIS-observed
  neighbours. See "Footprint adjacency" in README.md for the full workflow.
- **Public routing context** gives context for one address. Enter one public IPv4 or IPv6
  address; ranges are rejected here and handled in footprint mode. The report shows the announced prefix covering the address, and BGP
  observations are read for that prefix. Nothing is enumerated or probed.
- **Explore ASN** is optional broader context. Enter `AS3333` or `3333`, or use
  the **Explore AS…** button on an IP report. That button prepares the lookup;
  it does not automatically start another request.
- All modes read existing public RIPE data. No API key is needed or accepted.
  Active scheduling, suspect-network inputs, blocklists and mitigation advice
  are disabled in the UI and API.
- A lookup can take several minutes. Requests are made serially, with at least
  two seconds between them. Progress shows the current step and count.
- Responses are cached only within one run, to avoid duplicate requests. Every
  run re-reads its sources, so retrieval times in the report are when that run
  fetched the data. The request count in each report covers that run only.

## Evidence and limitations

RIPEstat supplies current prefix-origin mapping, reported ASN holders and RIS BGP
observations. RIPE Atlas supplies existing traceroute samples. IP mode can fall
back to samples targeting other addresses in the selected origin ASN; the report
shows their destinations and dates. Supplied measurement IDs remain analyst-selected
samples, not complete or necessarily representative coverage. Each supplied or
discovered measurement is checked against its own definition: it must be a
traceroute whose target is the requested address, or another address Atlas
classifies under the selected origin ASN (labeled as such). Others are excluded with
a warning. Results whose destination differs from the measurement target, or whose
timestamp is malformed, are dropped and counted.

Dashed graph edges represent collector-observed BGP advertisements. Solid edges in
IP mode are **inferred hop prefix-origin mappings**, not verified router operators
or AS transitions. ASN mode graphs only BGP observations and leaves Atlas hop-to-AS
mapping unperformed. Neither reconstructs the route of a perimeter event.

Adjacency does not prove a provider relationship, ownership, government association,
physical location, traffic share, maliciousness or an enforcement boundary. Reported
holders are names from RIPE, not independently verified operators. Multiple origins
are preserved; the IP graph focuses on the selected origin. BGP records within the
queried resource that end at other origins are listed by prefix, origin ASN and
peer count, without judging whether they are legitimate.

BGP record fractions use records with a preceding ASN as their denominator. Mapped
sample fractions use retained samples with an inferred preceding ASN. The report
model records those denominators and four-decimal rounding. Unknown denominators
remain unknown. Failed sources, unrequested sources and observed empty results have
separate states.

At most 20,000 BGP records are processed, 400 BGP path records and 4,000 ASN prefixes
are listed, and 400 Atlas samples are retained. IP hop mapping has a 150-lookup
limit; name enrichment has a 60-name limit; 50 other-origin groups are listed. Graphs and exported path lists can be
truncated independently; limits are disclosed. Current mappings are not historical
evidence, and cached covering prefixes can miss more-specific origins.

This prototype has software tests but no operator-ground-truth accuracy benchmark.
It does not implement a validated router-ownership inference method such as bdrmapIT.

## Reports, privacy and retention

Screen reports, standalone HTML, embedded/exported JSON and the printable view use
the same routing-context report model. JSON schema version 0.2 replaced the
`enforcement` output with `routing_context`. Version 0.3 adds `meta.evidence_resource`
(the covering prefix queried for BGP observations), `control_plane.other_origins`,
`raw_path` on every exported BGP path, and `measurement_evidence` in IP mode. Range
input is no longer accepted. HTML
exports include the retained evidence, sample destinations and source/coverage notes.
The print control supports the browser's print/save-PDF flow; there is no separate
server PDF generator or firewall export.

Your target, measurement IDs, and in footprint mode every entry and confirmed ASN
are sent to RIPE, which also sees your public IP.
The application does not contact investigated hosts. Response caches last one run.
Job results are in memory, expire an hour after they finish, and restart clears them. Saved exports remain until
you delete them. Storage encryption is not implemented. Only theme selection is
persisted in browser storage.

The server binds to loopback and checks Host and Origin. It is a local prototype,
not a security design for shared/public deployment. Source responses and uploads are
bounded. Cancellation stops local work after the current request.

## Verification

```
python3 -m unittest -v
```

Tests use frozen synthetic source responses. They verify IP/ASN validation, rejection
of active and enforcement inputs, routing counts, unsupported paths, source failures,
unknown versus empty evidence, cancellation and report completeness limits. Regression
tests cover per-run caching, measurement validation on both paths, single-IP input
and other-origin listing.

`test_report_rendering.js` additionally checks UI syntax, canonical JSON embedded in
HTML, escaping and absence of action advice against backend fixture reports. It takes
a JSON array of synthetic reports as its command-line argument. Browser checks use a
separate fixture server; they must never be presented as live intelligence.
