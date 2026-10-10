# Pathfinder methods, sources, and limits

This reference explains the evidence behind a Pathfinder report. It is intended
for analysts who need to assess a result's scope and limitations.

## Evidence categories

| Category | Pathfinder records | It does not establish |
| --- | --- | --- |
| Collector-observed BGP path | A route collector reported the displayed AS sequence for a resource. | Packet path, reachability, traffic share, or contractual relationship. |
| Current prefix-origin mapping | RIPEstat associated the target with a prefix and ASN at retrieval time. | Historical routing at the time of an event. |
| Existing Atlas sample | RIPE Atlas previously published a traceroute to its destination. | A measurement scheduled by Pathfinder, complete coverage, or an inbound path. |
| Inferred hop mapping | A public reply address was mapped to a current prefix origin. | Router ownership, a confirmed AS transition, or operator control. |
| Existing Shodan observation | Shodan reported a service on an IP/port, with its supplied timestamp. | Current exposure, vulnerability, system ownership, or complete service coverage. |
| Analyst assessment | A conclusion an analyst draws using this evidence and independent records. | A conclusion made or endorsed by Pathfinder. |

Every result records source status, query/retrieval times, warnings, and the
number of RIPE requests made. Shodan records retain their own queries, page
retrieval times, statuses, and limits. Failed access, an unrequested source, and a
successful response with no retained evidence remain distinct states.

## Footprint resolution and adjacency

Pathfinder reads the first non-empty cell in each input row. It skips blank rows
and comments beginning with `#`; treats the first row as a header only when it
is not an address or prefix; normalizes duplicates; and reports rejected rows
with their line number and reason. It accepts one globally routed IPv4/IPv6
address or prefix per row, up to 5,000 distinct entries and 1 MiB. Start-end
ranges, private/special-use addresses, malformed values, prefixes broader than
IPv4 `/8` or IPv6 `/16`, and invalid CSV entries are rejected visibly.

Each entry is resolved with RIPEstat Prefix Overview. An IP maps to its most
specific covering announcement. A prefix maps to its covering announcement and
to origins in more-specific announcements contained inside it. A prefix may
therefore map to more than one origin ASN; Pathfinder does not force these into
a single ownership hierarchy. It reuses an earlier covering lookup only when its
more-specific list is complete and cannot hide the later entry.

RIPEstat normally omits routes seen by fewer than its visibility threshold of
RIS peers (10 at the time this document was written). A run records filtered
routes; **Include low-visibility routes** requests all available routes.

After you confirm origin ASNs, Pathfinder reads RIPEstat ASN Neighbors for each
confirmed ASN. The source's `type` field has the following limited meaning:

| Position | Meaning |
| --- | --- |
| `left` | The neighbor was before your ASN in an observed AS path, toward the collector. |
| `right` | The neighbor was after your ASN in an observed AS path. |
| `uncertain` | The neighbor appeared on the left only as a direct peer of a RIS collector. |

This does not identify a provider, transit, customer, peer, business
relationship, traffic share, or risk. RIPE's `v4_peers` and `v6_peers` fields
count routes, despite their names; `power` counts observed AS paths.

## Existing Atlas samples

Pathfinder reads existing public Atlas data only. It never creates a
measurement. A supplied or discovered measurement must be a traceroute and must
target the requested IP, or an IP Atlas classifies under the selected origin ASN
when that broader IP-mode fallback is used and labeled. Samples whose reported
destination conflicts with the measurement definition, or whose timestamp is
malformed, are excluded.

## Calculations and presentation

The adjacent-network table maintains separate BGP and inferred-sample fractions:
retained records with a preceding ASN divided by records with a preceding ASN.
The report records numerators, denominators, units, and four-decimal rounding.
Fractions are never traffic shares, confidence, likelihood, or estimates of
active address use. Unknown denominators remain unknown.

The UI initially shows five adjacent networks ordered by retained BGP records,
then inferred samples, then ASN; the remainder is available on demand. Exports
retain the full table. The five-hop routing map is a presentation subset, while
the report records documented BGP path subsets separately.

## Processing limits

| Area | Current behavior |
| --- | --- |
| RIPE response | 32 MiB maximum response body per request |
| IP hop mapping | 150 uncached RIPEstat address-to-network lookups per run |
| Atlas samples | 400 retained samples |
| ASN names | 60 name lookups per IP/ASN run; 150 neighbor-name lookups per footprint run |
| BGP processing | 20,000 accepted records; 400 retained detailed paths |
| ASN prefixes | 4,000 listed prefixes |
| Other origins | 50 prefix/origin groups |
| Routing-map source graph | 80 networks before compact presentation |
| Atlas discovery | 5 discovered measurements per search scope |
| Footprint resolution | 2,500 RIPEstat lookups per run; 100 more-specific announcements per prefix |
| Footprint adjacency | 50 confirmed ASNs; 5,000 neighbors per ASN; 1,000 neighbor rows on screen |

The report warns whenever a relevant limit truncates evidence. Large runs may
take over an hour: requests are globally serialized and separated by at least
one second for RIPEstat by default, or two seconds for Atlas, with up to three attempts and bounded retry backoff.

## Privacy and local operation

**A local interface does not make public-data queries private.** Pathfinder
sends normalized targets, supplied measurement IDs, footprint entries, and
confirmed ASNs to fixed RIPEstat and RIPE Atlas endpoints. RIPE can see the
public IP address that makes those requests. Optional Shodan lookups send the supplied IPs/prefixes to Shodan, which also
sees the requesting public IP. The app never contacts the target
IP or ASN and does not fetch imported URLs.

The server binds to `127.0.0.1` by default. Finished jobs and request caches are
memory-only, clear on restart, and expire one hour after completion; running jobs
are not evicted. Shodan credentials are held only in server memory, shared across tabs using
that server, until removed or restarted. They are not included in reports,
browser storage, or application logs. Browser theme preference is stored in the browser. Exports
remain wherever you save them and are not encrypted by Pathfinder.

## Sources

| Source | Pathfinder use |
| --- | --- |
| [RIPEstat Prefix Overview](https://stat.ripe.net/docs/data-api/api-endpoints/prefix-overview) | Footprint resolution, covering announcements, origin ASNs, holders, related prefixes, visibility filtering. |
| [RIPEstat ASN Neighbors](https://stat.ripe.net/docs/data-api/api-endpoints/asn-neighbours) | Observed ASN neighbors, position, route, and path counts. |
| [RIPEstat Network Info](https://stat.ripe.net/docs/data-api/api-endpoints/network-info) | Current IP-to-prefix and prefix-to-origin context. |
| [RIPEstat BGP State / RIPE RIS](https://stat.ripe.net/docs/data-api/api-endpoints/bgp-state) | Collector-observed BGP paths and ASN-prefix context. |
| [RIPEstat ASN Overview](https://stat.ripe.net/docs/data-api/api-endpoints/as-overview) | Holder names when available. |
| [Shodan API](https://developer.shodan.io/api) | Existing host/service records, prefix search, and read-only account connection checks; no scans requested. |
| [RIPE Atlas API](https://atlas.ripe.net/docs/apis/rest-api-manual/) | Existing public traceroute definitions and results. |

Sources are time-dependent and subject to their own availability, terms, and
rate limits. Public availability does not authorize unrestricted redistribution
or commercial hosting of their data.

## What Pathfinder cannot establish

Pathfinder cannot establish an exact inbound or attacker path; identity, intent,
location, ownership, provider relationship, government connection, router
ownership, complete address-space membership, active use, traffic volume,
historical routing, safety, risk, reachability, or a reason to block. Missing
coverage and source failures are not evidence of absence, safety, or
non-involvement.

## Revised edition operational changes

See [generated limits](docs/LIMITS.md) for configured bounds. Per-run response
caching has a serialized-JSON byte budget; responses beyond that budget remain
usable but are not cached. Source time and cached retrieval time remain distinct.
The transport validates HTTPS redirects and honors Retry-After. Cancellation
interrupts waiting/retries; in-flight socket I/O remains subject to its timeout.

Saved JSON records are validated/migrated by the local server without new source
requests. This checks supported structure, not source authenticity. Reports carry
`pathfinder.report/1`; migration preserves their historical times.


## Shodan service observations

Shodan is the only optional service-observation provider currently supported.
Its records are separate from RIPE routing evidence. Footprint queries use the
supplied entries, including those mapped to unconfirmed provider ASNs; confirming
ASNs determines RIPE adjacency requests only. Shodan reads occur after routing
completes, when the analyst opted in. Saved-report imports make no source request.

Single IPs use Shodan's existing host records. Prefixes use filtered search,
which can consume query credits according to the account plan. A connection
check reads account information; it does not establish access or sufficient
credits for every subsequent query. Failures leave routing evidence intact.
Pathfinder neither invokes scan endpoints nor requests refreshed observations.
Shodan's collection activities are distinct from Pathfinder's passive retrieval.

Each retained service has an IP, port, TCP/UDP transport, reported service,
original observation timestamp, and bounded source details. Invalid or out-of-scope
records are rejected and counted. A missing search total remains unknown and
produces partial evidence. Failed, successfully empty, available, and partial
states are distinct; no retained records is not proof of no exposed services.
Reported totals describe service records, not unique hosts or independently
verified current exposures.

| Shodan boundary | Current behavior |
| --- | --- |
| Initial resources | At most 20 explicit public IPs or canonical prefixes; larger Footprints are not silently sampled. |
| Response size | 2 MiB per response; 20-second socket timeout. |
| Retained records | At most 100 service records per response, including single-IP responses. |
| Prefix paging | Explicit requests for pages 2–100; at most 10,000 candidate records per prefix, before rejection/deduplication. |
| Live display | 20 rows per display page; display navigation makes no source request. |
| Request pacing | Serialized within the Shodan adapter, at least one second after the preceding request finishes. No automatic retry. |
| Banner | 2,048 characters; longer banners have an explicit truncation marker. |
| Other details | Product/version, organization/ISP/ASN, and certificate name fields: 256 characters; HTTP title: 512; hostnames/domains: up to 20 strings of 256 characters each. |

Each fetched search page retains its retrieval time, source total, and returned
record count. Additional-page merging deduplicates services by IP, port,
transport, service, and observation timestamp. Overlapping supplied resources
retain their own records; counts should not be summed as a unique footprint-wide
service inventory. Search results can change between page requests, so fetching
all reported pages does not establish a consistent snapshot or complete coverage.
Unknown totals do not provide a known next-page count.

Shodan observation timestamps are preserved as supplied, separately from
retrieval time. Certificate date strings and software names remain source claims.
Missing details are labeled Not reported. Banners are escaped plain text; no
banner links, scripts, or remote assets are executed or fetched.

JSON, service CSV, single-IP HTML, and browser print/PDF retain fetched service
records independently of live display pagination. No credential enters those
exports. Routing CSVs keep their original scope. Shodan-specific limits live in
the adapter and are not currently included in the generated routing/job limits
document.

## Footprint per-ASN path context

The interactive path area appears under Per-ASN detail, above collapsed ASN rows.
Choosing an ASN starts a separate Explore ASN lookup. The map shows a filtered
subset of collector-observed BGP paths; selecting a node highlights adjacent
displayed edges and shows retained counts. This interaction does not establish
an end-to-end packet path. Existing Atlas samples remain separate and are not
plotted on this BGP map.

The path area's source observation and retrieval times belong to that separate
lookup. Its evidence is not merged into Footprint JSON or CSV exports. A loaded
map may appear in a browser printout; use Explore ASN for its own report exports.
