# Múcaro | Pathfinder

**Public routing context for IPs and networks.**

Múcaro | Pathfinder shows which networks the internet observes next to yours.
Start with your external footprint, for example the IPs and prefixes from an
Expanse export. Pathfinder resolves each entry to its announced prefix and
origin ASN, lets you confirm which origin ASNs are yours, and reads the BGP
neighbours that RIPE's route collectors observe for them. Those neighbours are
the part an inside-out view tends to miss: sessions and upstreams that the rest
of the internet sees, whether or not your own records do.

For a single address or network, the IP and ASN lookups give the same public
routing context one resource at a time.

Think of it as a map of public road observations around an address: it shows
routes that public sources reported, but it does not show the route a particular
visitor took to reach a building.

The application is a local analyst prototype. It supports investigation and
documentation; it does not establish source identity, traffic flow,
reachability, physical location, provider status, government control, malicious
intent, or an enforcement boundary.

**Status:** local footprint, single-IP and single-ASN workflows. The server binds
only to loopback by default. It is not a shared or public service design.

## Contents

- [Quick start](#quick-start)
- [Choose a lookup mode](#choose-a-lookup-mode)
- [Footprint adjacency](#footprint-adjacency)
- [Worked investigation](#worked-investigation)
- [Reading the routing map](#reading-the-routing-map)
- [Evidence, calculations, and limits](#evidence-calculations-and-limits)
- [Progress, cancellation, and retention](#progress-cancellation-and-retention)
- [Privacy and local operation](#privacy-and-local-operation)
- [Reports and exports](#reports-and-exports)
- [Local API](#local-api)
- [What the evidence cannot establish](#what-the-evidence-cannot-establish)
- [Verification and development](#verification-and-development)
- [Data sources and terms](#data-sources-and-terms)

## Quick start

You need **Python 3.10+**, a modern browser, a working HTTPS certificate trust
store, and Internet access to RIPE's public services. No Python packages,
Node.js runtime, API key, database, account, or active-measurement credit is
needed to use the application. Node.js is needed only for the renderer test.

### 1. Get the code and start the local server

If you have repository access, clone it; otherwise extract a supplied archive
and open a terminal in the extracted folder.

```sh
git clone https://github.com/bayanilla/infrastructure-explorer.git
cd infrastructure-explorer
python3 --version
python3 probe_server.py
```

Open [http://127.0.0.1:8767](http://127.0.0.1:8767). Keep the terminal running
while using the application and stop it with `Ctrl+C` when finished.

Opening `probe_web/index.html` directly does not run the application. If port
8767 is occupied, choose another local port:

```sh
python3 probe_server.py --port 8768
```

Then open [http://127.0.0.1:8768](http://127.0.0.1:8768).

Do not disable certificate verification to work around a RIPE connection error.
Fix the local certificate trust configuration instead. Disabling verification
would weaken the evidence-source connection.

### 2. Run a first lookup

For your footprint:

1. Enter one public IP address or prefix, or put your IPs and prefixes in one
   column of a CSV or text file. A header row is fine.
2. Open the local address above. **Your footprint** is selected by default.
3. Enter the single IP or prefix, or choose the file. Optionally enter your organization's holder name as RIPE
   records it, such as `Example Org`, so your own ASNs are pre-checked.
4. Select **Resolve footprint**, review the origin ASNs, check the ones that are
   yours, and select **Read adjacency**.

For one resource:

1. Open the local address above.
2. Select **Public routing context** and enter one public IPv4 or IPv6 address, or select
   **Explore ASN** and enter a public ASN such as `AS3333`.
3. Leave **Include RIS routing observations** enabled unless you deliberately
   want to omit that source from this run.
4. Select **Analyze public routing context** or **Explore ASN**.
5. Review source status, timestamps, warnings, and coverage notes before
   reading the diagram or exporting a report.

`AS3333` is a public RIPE NCC example commonly used for routing
demonstrations. It can still have substantial public routing context, so an ASN
lookup may take several minutes. No affiliation with or endorsement by RIPE NCC
is implied.

The application reads existing public data. It does not contact the target IP,
schedule a traceroute, scan an address, or send a packet to the investigated
network.

## Choose a lookup mode

| | Your footprint | Public routing context | Explore ASN |
| --- | --- | --- | --- |
| Primary question | Which networks are observed adjacent to the origin ASNs behind my IPs and prefixes? | What public prefix, selected origin ASN, routing observations, and existing samples provide context for this address? | What observed prefixes, BGP paths, and existing Atlas samples provide context for this ASN? |
| Input | One public IP or prefix, or a CSV or text file of IPs and prefixes up to 5,000 entries | One globally routed IPv4 or IPv6 address | One public ASN, with or without the `AS` prefix |
| BGP resource | Each entry's covering announcement, then each confirmed ASN | The covering prefix | The requested ASN |
| Prefix handling | Each entry is resolved to its announced prefix and origin ASN; prefix entries include their more-specific announcements | RIPEstat identifies the announced prefix covering the address | Lists retained prefixes announced by the ASN in BGP observations |
| Atlas treatment | Not used | Existing samples to the IP, then possibly to other addresses Atlas classifies under the selected origin ASN | Existing samples to specific addresses Atlas classifies under the ASN |
| Adjacency source | RIPEstat asn-neighbours for each confirmed ASN | BGP paths for the covering prefix, plus inferred hop mappings | BGP paths ending at the ASN |
| Typical use | Your whole external footprint, at a point in time | Context for one observed address | Broader routing context after reviewing an IP result |

All modes use RIPEstat and RIPE Atlas public data only. None establishes the
actual path of an inbound perimeter event.

### Accepted and rejected input

- **Accepted IPs:** one globally routed IPv4 or IPv6 address.
- **Accepted ASNs:** public ASNs in the range supported by the application,
  entered as `AS3333` or `3333`.
- **Footprint files:** one IP or prefix per row, CSV or plain text, up to 5,000
  distinct entries and 1 MB. See [Footprint adjacency](#footprint-adjacency).
- **Not accepted in IP or ASN mode:** CIDRs, address ranges, private or
  special-use IPs, private or reserved ASNs, DNS names, URLs, and multiple
  targets in one request. Use footprint mode for prefixes and lists.
- **Optional measurement IDs:** up to ten existing RIPE Atlas measurement IDs,
  separated by spaces, commas, or semicolons. They are validated before their
  results are used.

RPKI validation, scheduled monitoring and comparison between runs are not
implemented. Each footprint run is a point-in-time record.

## Footprint adjacency

**Question:** Which networks does the rest of the internet observe next to the
networks behind my external footprint?

### 1. Upload and resolve

Pathfinder reads the first non-empty cell of each row. Blank rows and rows
starting with `#` are skipped. The first row is treated as a header only if it
isn't an address or prefix at all. Every other row that can't be used is listed
with its line number and reason: private or special-use space, malformed
values, start-end ranges, and prefixes broader than /8 (IPv4) or /16 (IPv6).
Exact duplicates are counted and dropped after normalization, so `193.0.6.139`
and `193.0.6.139/32` are one entry. Overlapping entries are kept, because each is
something you listed.

Each entry is resolved with RIPEstat prefix-overview to the announced prefix
that covers it and that prefix's origin ASN or ASNs:

- **IP inside an announcement:** mapped to the most specific covering prefix.
- **Prefix entry:** mapped to its covering announcement, plus the origins of any
  more-specific announcements inside it. A /21 containing a /24 announced by a
  hosting provider maps to both.
- **Range not announced as a whole:** expanded into the announcements inside it,
  up to 100 per entry.
- **Nothing covering it:** listed as having no covering announcement.

An already-read covering prefix answers later entries only when Pathfinder read
that prefix directly, its list of more-specific announcements is complete, and
the entry falls outside all of them. Otherwise the entry is looked up on its
own. This keeps large, clustered lists fast without hiding a more-specific route.

RIPEstat leaves out routes seen by fewer RIS peers than its visibility threshold
(10 at the time of writing). The resolution records how many were left out.
Select **Include low-visibility routes** to request every route RIPE has.

### 2. Confirm which origin ASNs are yours

Every origin ASN is listed with its RIPE holder name, the number and share of
your entries that map to it, and its announced prefixes. An ASN is pre-checked
only when its holder name contains a keyword you entered. Pathfinder doesn't
guess from share alone, because a cloud provider can hold most of a footprint.

Checked ASNs are treated as yours. Unchecked ASNs stay in the record and their
neighbours are not read. For entries in cloud, CDN or hosting space, the origin
and its neighbours belong to the provider, so leaving those unchecked keeps the
result about your own networks.

### 3. Read adjacency

For each confirmed ASN, Pathfinder reads RIPEstat asn-neighbours: the BGP
neighbours RIS observes for that ASN. The report shows:

- **Your confirmed ASNs:** footprint entries, neighbour count and data time.
- **Networks adjacent to your footprint:** one row per neighbour, with each of
  your ASNs it touches. Sort by any column. Nothing is flagged or ranked by
  importance.
- **Combined view:** drawn when there are up to 5 confirmed ASNs and 40
  neighbours. A network adjacent to more than one of your ASNs has a thicker
  circle; arcs join two of your own ASNs.
- **Per-ASN detail:** each ASN's neighbours, source times and RIPE messages, and
  an option to load that ASN's observed BGP path overview. That overview is a
  separate Explore ASN run and isn't added to the footprint record.

The counts keep RIPE's own fields and meanings:

| Column | RIPE field | Meaning |
| --- | --- | --- |
| Position | `type` | `left`: the neighbour appears before your ASN in observed AS paths (toward the collector). `right`: after it. `uncertain`: seen on the left only as a direct peer of a RIS collector. |
| IPv4 routes, IPv6 routes | `v4_peers`, `v6_peers` | Routes with this neighbour relationship seen by RIS peers. Despite the names, these count routes, not distinct peers. |
| AS paths | `power` | AS paths containing the neighbour relationship with that position. |

Position is not a business relationship. Route and path counts are not traffic
share. Collectors miss sessions whose routes never propagate toward a RIS peer,
including much private peering.

## Worked investigation

**Question:** What public routing context can help explain the infrastructure
around an address observed at a perimeter?

### 1. Start with the observed address

Enter the address as a **Public routing context** lookup. The report records the submitted
address separately from the prefix used for BGP evidence. This distinction
matters: the report does not silently substitute the covering prefix for the
input address.

Review the initial identity context:

- The IP address submitted by the analyst.
- The announced prefix reported by RIPEstat at retrieval time.
- The selected origin ASN and the holder name reported by RIPEstat, if
  available.
- Other BGP origins seen within the queried resource, when present.

Holder names are registration context, not verified operator, provider,
government, or physical-location claims.

### 2. Separate the evidence types

The report keeps these statements distinct:

| Category | What it means | What it does not mean |
| --- | --- | --- |
| BGP observation | A collector reported an AS path for the displayed resource. | A packet path to your perimeter, reachability, traffic share, or a contractual provider relationship. |
| Current prefix-origin mapping | RIPEstat associated an address with a prefix and ASN when the lookup ran. | Historical routing at the time a traceroute or security event occurred. |
| Existing Atlas sample | RIPE Atlas previously recorded a traceroute to the displayed destination and time. | A measurement created by this application, a complete path census, or an inbound attacker route. |
| Inferred hop mapping | A publicly replying hop address was mapped to a current prefix origin. | Verified router ownership, a confirmed AS transition, or operator control. |
| Analyst assessment | Your own conclusion drawn from this evidence and outside records. | A conclusion generated or endorsed by the application. |

For example, a BGP path ending `AS2914 → AS1103 → AS3333` supports the narrow
statement that a collector observed AS1103 immediately before AS3333 in that
advertisement. It does not prove that AS1103 is AS3333's provider, that a packet
traversed that path, or that either ASN sent traffic to your environment.

### 3. Review the ASN only when broader context is useful

Select **Explore AS…** from an IP report, or enter the ASN directly. The button
prepares the ASN target; it does not automatically start another public query.

ASN mode can return far more BGP context than an IP lookup. Review the listed
prefixes, BGP source status, reported sample destinations, and truncation notes.
Existing Atlas samples in this mode are samples to particular addresses that
Atlas classifies under the ASN. They are not a measurement of every address in
the AS and receive no hop-to-AS mapping in the report.

## Reading the routing map

The routing map is a five-hop, full-width overview, not a topology diagram or
geographic map.

- The **selected origin** appears in the highlighted band on the right.
- Columns to the left indicate networks one, two, or more AS hops before that
  origin in displayed BGP or inferred mapping evidence. The view always shows
  adjacent through five-or-more-hop columns across the chart width.
- Dashed edges are collector-observed BGP advertisements.
- Solid edges are inferred only from reply-address prefix-origin mappings in IP
  mode.
- Up to three higher-frequency displayed networks in each hop column are
  emphasized. Up to two lower-frequency displayed networks are faded as context.
  This is a presentation rule, not a confidence score or a judgment about a
  network.
- The evidence section and JSON/HTML exports retain their documented path
  subsets even when the map omits lower-frequency nodes for readability.

Select a displayed network on the map to dim unrelated displayed paths and open
a detail card with counts and the network's nearest displayed hop depth.
Changing map layers does not alter the saved report model, source records, or
calculations. Standalone HTML and PDF exports use a static version of the map so
they can be read without the application.

The map does not claim a packet path, an attack path, an AS relationship, router
ownership, or a physical path. A network in the leftmost visible column is not
necessarily adjacent to the selected origin.

## Evidence, calculations, and limits

Every result includes source status, relevant retrieval time, warnings, and the
number of RIPE requests made during that run. Failed source access, an
unrequested source, and a successful source response with no retained evidence
are different states and are shown separately.

### Measurement validation

Supplied and discovered Atlas measurements are checked against their own
definitions. A retained measurement must be a traceroute and must target either:

1. the requested IP address, or
2. another address Atlas classifies under the selected origin ASN, when that
   broader IP-mode fallback is used and labeled.

Results whose destination differs from the measurement definition, and results
with malformed timestamps, are excluded. A retained sample remains a sample;
its inclusion does not establish complete coverage or a connection to the
perimeter event.

### Counts and fractions

The **Adjacent network context** table reports two different measures:

- **BGP fraction:** retained BGP records with a preceding ASN divided by all
  retained records with a preceding ASN.
- **Inferred-sample fraction:** retained samples with a preceding mapped ASN
  divided by all retained samples with a preceding mapped ASN.

On screen, the table initially shows the five networks with the most retained
BGP records, then inferred samples, with ASN as the final tie-breaker. Expand
**Show more adjacent networks** to review the rest. HTML, JSON, and PDF reports
retain the complete table.

The report records the numerators, denominators, units, and four-decimal
rounding rule. These fractions are not traffic share, likelihood, confidence,
or active-address estimates. An unavailable denominator remains unknown rather
than being replaced with zero.

### Processing and presentation bounds

| Area | Current bound or behavior |
| --- | --- |
| RIPE response | 32 MiB maximum response body per request |
| IP hop mapping | Up to 150 uncached RIPEstat address-to-network lookups per run |
| Atlas samples | Up to 400 retained samples |
| ASN names | Up to 60 name lookups per run |
| BGP processing | Up to 20,000 accepted BGP records |
| BGP path details | Up to 400 retained path records in a report/export |
| ASN prefixes | Up to 4,000 listed prefixes |
| Other origins | Up to 50 prefix/origin groups |
| Diagram source graph | Up to 80 networks before compact-diagram presentation |
| Atlas discovery | Up to five discovered measurements per search scope |
| Footprint file | 1 MB and 5,000 distinct entries; up to 500 rejected rows listed |
| Footprint resolution | Up to 2,500 RIPEstat lookups per run; up to 100 more-specific announcements resolved per prefix entry |
| Footprint adjacency | Up to 50 confirmed ASNs, 5,000 neighbours per ASN, and 150 neighbour name lookups; 1,000 neighbour rows on screen (exports keep all) |

The report warns when a relevant bound truncates evidence. Counts can cover more
accepted records than the detailed browser path list; do not treat a rendered
subset as complete source coverage.

## Progress, cancellation, and retention

The page shows the current stage and a bounded event log while a lookup runs.
Only two analyses can run at once. Choose **Cancel** to request cancellation;
the current RIPE request may finish before the job stops.

Requests are globally serialized and separated by at least two seconds. Each
network request has up to three attempts. Temporary HTTP failures use bounded
backoff, and network failures are surfaced as source errors instead of silently
becoming empty evidence. A large ASN or an IP run that reaches the hop-mapping
limit can take several minutes. A footprint resolution makes at most one request
per distinct entry and usually far fewer, but a list of thousands of scattered
addresses can still take over an hour at two seconds per request.

Responses are cached only within one job to avoid duplicate requests during that
run. A subsequent run reads its sources again, so its retrieval times refer to
that run rather than to an indefinite server cache.

Finished jobs live in memory for one hour after they finish; a running job is
never evicted. The server retains at most 30 jobs and may evict an older
finished result first. A footprint resolution must still be held when you read
adjacency; if it has expired, upload the file again. Restarting the server clears jobs and
their in-memory caches. Download reports you need to preserve.

## Privacy and local operation

**A local interface does not make public-data queries private.** When you run a
lookup, the application sends the normalized IP address or ASN, any supplied
measurement IDs, and in footprint mode every entry in your file and every ASN
you confirm, to RIPE services. A footprint file describes your external attack
surface, so treat the run and its exports accordingly. RIPE can also see the public IP address of
the network making those requests.

The application never contacts the investigated IP address or ASN. It does not
send a traceroute, scan, probe, DNS request, or connection attempt to the
target. It makes HTTPS requests only to fixed RIPEstat and RIPE Atlas endpoints
defined in the server; it does not fetch imported URLs.

| Local behavior | What to expect |
| --- | --- |
| Binding | Listens on `127.0.0.1` by default, not on a public interface. |
| Browser requests | The browser talks only to the local server. The local server makes RIPE requests. |
| Request history | Finished results and request caches are memory-only and clear on restart. |
| Browser storage | The selected visual theme is stored in that browser. |
| Exports | Downloaded HTML, JSON, and PDF files remain where you save them; they are not encrypted by this application. |
| Logging | The server logs request paths and status codes, not request bodies. |

The local server checks expected Host and Origin headers, rejects cross-origin
POSTs, sets a restrictive content-security policy for its HTML response, and
limits request bodies to 64 KiB, or about 1 MiB for a footprint upload. Those controls do not make it appropriate to
expose on a shared network without a separate security design.

## Reports and exports

The screen report, standalone HTML report, JSON evidence download, and browser
print/save-PDF flow are derived from the same routing-context report model.

| Format | Contents and use |
| --- | --- |
| Screen report | Interactive review of identity context, adjacent networks, compact map, source status, samples, BGP paths, warnings, and methodology. |
| HTML report | A standalone report with retained evidence embedded as JSON. It can be opened without the local server. |
| JSON evidence | The canonical structured result, including sources, timestamps, calculations, warnings, selected graph data, samples, and retained paths. |
| Print or save PDF | Uses the browser's print dialog to produce a visual report. There is no server-side PDF generator. |
| Footprint JSON record | The complete point-in-time run: inputs, rejected rows, resolution of every entry, origin ASNs with your confirmation, neighbours per ASN, RIPE field definitions, source times and messages, warnings and request counts. |
| Adjacency CSV | One row per confirmed ASN and neighbour, with RIPE's position, `power`, `v4_peers` and `v6_peers`, data time and source URL. |
| Resolution CSV | One row per footprint entry: status, covering prefix, origin ASNs, more-specific announcements and errors. |

**Open a saved run** displays a JSON export from this tool, footprint or
single-resource, without making any lookups. CSV cells that a spreadsheet would
run as a formula are prefixed with an apostrophe, because holder names come from
outside data.

Firewall formats, SIEM delivery, SOAR actions, and automatic enforcement are not
implemented. The application does not
recommend blocking an IP, prefix, ASN, or provider.

Treat exports as potentially sensitive investigation material. Before sharing an
export, review targets, source dates, sample destinations, organization names,
and any notes added outside this application.

## Local API

The browser UI uses a small loopback-only JSON API. It is useful for local
integration experiments, but it has no authentication and is not designed as a
remote multi-user API.

| Method and path | Purpose |
| --- | --- |
| `GET /api/health` | Returns the local application version. |
| `POST /api/analyze` | Starts one passive IP or ASN analysis. |
| `POST /api/footprint/resolve` | Starts a footprint resolution. Body: `{"csv": "<file text>", "org_keywords": "Example Org", "include_low_visibility": false}`. |
| `POST /api/footprint/adjacency` | Reads adjacency for confirmed ASNs. Body: `{"resolution_job": "<job id>", "asns": [3333]}`. The ASNs must come from that resolution. |
| `GET /api/job/<job-id>` | Returns progress, error state, or the completed report. |
| `POST /api/job/<job-id>/cancel` | Requests cancellation of an in-progress analysis. |

Example request body:

```json
{
  "target": "AS3333",
  "tier": "public",
  "measurement_ids": "",
  "control_plane": true
}
```

`tier` must be `public`. API keys, active probe schedules, suspect-network
inputs, and enforcement inputs are rejected. A `202` response includes a job ID;
poll the job endpoint until `status` is `done`, `failed`, or `cancelled`.

## What the evidence cannot establish

Public routing and measurement sources have incomplete and time-dependent
coverage. This tool cannot establish any of the following from its own output:

- The exact path taken by an observed connection or an attacker.
- The identity, intent, location, or ownership of the person behind an IP.
- That an ASN, organization, or provider is malicious or responsible for an
  event.
- A provider, transit, customer, peer, or government relationship from ASN
  adjacency alone.
- Router ownership or an AS-to-AS handoff from a reply-address prefix mapping.
- Complete address-space membership, active use, traffic volume, or a network's
  complete routing architecture.
- Historical routing from a current prefix-origin lookup.
- Safety, risk, reachability, or a recommendation to block.

Use independent records, authorized measurements, and operator confirmation when
those questions matter. Source failures and missing samples are not proof of
absence, safety, or non-involvement.

## Verification and development

Run the Python test suite:

```sh
python3 -m unittest -v
```

Run the renderer and export check when Node.js is available:

```sh
node test_report_rendering.js report_fixtures.json
node test_footprint_rendering.js footprint_fixtures.json
```

Tests use frozen synthetic responses. They cover input validation, public-only
operation, per-run caching, measurement-definition checks, source failures,
unknown-versus-empty evidence, cancellation, path handling, other-origin
reporting, report export, and escaping of untrusted content. Footprint tests
cover parsing edge cases, safe reuse around more-specific announcements, range
expansion, lookup limits, low-visibility filtering, multiple origins,
confirmation checks, aggregation, unknown-versus-empty neighbour data, job
retention, CSV formula safety and the absence of editorial wording. The renderer
fixtures contain fabricated values and an intentional injection test string;
they are not live intelligence or an accuracy benchmark.

The BGP Lookup project was used as a design reference only. Pathfinder
is a standalone codebase and does not depend on a local BGP Lookup
checkout. It includes a local copy of the supplied decorative Coquí artwork in
the lower-right background; it is not loaded from the reference project at
runtime.

## Data sources and terms

| Source | Use in this application |
| --- | --- |
| [RIPEstat Prefix Overview](https://stat.ripe.net/docs/data-api/api-endpoints/prefix-overview) | Footprint resolution: covering announcement, origin ASNs and holders, related prefixes, visibility filtering. |
| [RIPEstat ASN Neighbours](https://stat.ripe.net/docs/data-api/api-endpoints/asn-neighbours) | Footprint adjacency: observed BGP neighbours, position, route and path counts. |
| [RIPEstat Network Info](https://stat.ripe.net/docs/data-api/api-endpoints/network-info) | Current IP-to-prefix and prefix-to-origin context. |
| [RIPEstat BGP State / RIPE RIS](https://stat.ripe.net/docs/data-api/api-endpoints/bgp-state) | Collector-observed BGP paths and ASN prefix context. |
| [RIPEstat ASN Overview](https://stat.ripe.net/docs/data-api/api-endpoints/as-overview) | Reported ASN holder names when available. |
| [RIPE Atlas API](https://atlas.ripe.net/docs/apis/rest-api-manual/) | Existing public traceroute measurement definitions and results. |

Each source remains subject to its own availability, documentation, rate limits,
and terms. Public availability does not automatically authorize redistribution or
commercial hosting of source data. Review provider terms before publishing
exports or operating a shared service.

This repository currently has no `LICENSE` file. Do not infer unrestricted reuse
rights from repository visibility. Do not include credentials, private
observations, or unredacted reports in commits, issues, screenshots, or bug
reports.
