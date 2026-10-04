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
| Analyst assessment | A conclusion an analyst draws using this evidence and independent records. | A conclusion made or endorsed by Pathfinder. |

Every result records source status, query/retrieval times, warnings, and the
number of RIPE requests made. Failed access, an unrequested source, and a
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
two seconds, with up to three attempts and bounded retry backoff.

## Privacy and local operation

**A local interface does not make public-data queries private.** Pathfinder
sends normalized targets, supplied measurement IDs, footprint entries, and
confirmed ASNs to fixed RIPEstat and RIPE Atlas endpoints. RIPE can see the
public IP address that makes those requests. The app never contacts the target
IP or ASN and does not fetch imported URLs.

The server binds to `127.0.0.1` by default. Finished jobs and request caches are
memory-only, clear on restart, and expire one hour after completion; running jobs
are not evicted. Browser theme preference is stored in the browser. Exports
remain wherever you save them and are not encrypted by Pathfinder.

## Sources

| Source | Pathfinder use |
| --- | --- |
| [RIPEstat Prefix Overview](https://stat.ripe.net/docs/data-api/api-endpoints/prefix-overview) | Footprint resolution, covering announcements, origin ASNs, holders, related prefixes, visibility filtering. |
| [RIPEstat ASN Neighbors](https://stat.ripe.net/docs/data-api/api-endpoints/asn-neighbours) | Observed ASN neighbors, position, route, and path counts. |
| [RIPEstat Network Info](https://stat.ripe.net/docs/data-api/api-endpoints/network-info) | Current IP-to-prefix and prefix-to-origin context. |
| [RIPEstat BGP State / RIPE RIS](https://stat.ripe.net/docs/data-api/api-endpoints/bgp-state) | Collector-observed BGP paths and ASN-prefix context. |
| [RIPEstat ASN Overview](https://stat.ripe.net/docs/data-api/api-endpoints/as-overview) | Holder names when available. |
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
