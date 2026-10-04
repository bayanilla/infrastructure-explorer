# Múcaro | Pathfinder

**Public routing context for IPs and networks.**

Múcaro | Pathfinder helps an analyst document what public Internet-routing sources
currently report around an external IP address, network prefix, ASN, or an
organization's external footprint. It resolves public routing identity, preserves
the source records and times behind each finding, and presents the context in a
reviewable report.

> **Project status:** Pathfinder is an AI-assisted proof of concept. AI assisted
> its development, but no AI is used at runtime to collect, evaluate, score, or
> interpret evidence, or to produce routing or enforcement assessments. Analysts
> remain responsible for reviewing every result alongside independent evidence.

It is a passive, local tool. It does **not** contact the IP or network under
review, send a traceroute, scan, probe, make a DNS request, or recommend a block.
It cannot establish who is behind an address, the route a packet took, a provider
relationship, physical location, government control, intent, or maliciousness.

> **Before you look up a target:** Pathfinder sends normalized IPs, prefixes,
> ASNs, supplied Atlas measurement IDs, and—when used—footprint entries and
> confirmed ASNs to RIPE's public services. A local interface does not make those
> public-data queries private. See [privacy and local operation](METHODS.md#privacy-and-local-operation).

## Start here

You need Python 3.10+, a modern browser, and Internet access to RIPE's public
services. No account, API key, database, or active-measurement credit is needed.

```sh
git clone https://github.com/bayanilla/infrastructure-explorer.git
cd infrastructure-explorer
python3 probe_server.py
```

Open [http://127.0.0.1:8767](http://127.0.0.1:8767). Keep the terminal open
while working, then use `Ctrl+C` to stop the local server. If that port is in
use, start the server with `python3 probe_server.py --port 8768` and use the
matching local address.

## Choose the question you need answered

| Mode | Start with | What you receive |
| --- | --- | --- |
| **Your footprint** | One public IP or prefix, or a CSV/text list of them | The announced prefix and origin ASN for each entry; then the RIPE-observed neighbors for origin ASNs you confirm as yours. |
| **Public routing context** | One public IPv4 or IPv6 address | The current covering prefix, selected origin ASN, collector-observed BGP paths, and existing public Atlas samples. |
| **Explore ASN** | One public ASN, such as `AS3333` | Broader BGP context, retained prefixes, and existing public Atlas samples for that ASN. |

Use **Your footprint** when you need to understand the public routing context
around infrastructure you operate. Use **Public routing context** for a single
address observed at your perimeter. Use **Explore ASN** only after you need
broader context; it can take longer and does not establish that an ASN owns,
operates, or controls every address associated with it.

## Run your first investigation

### Your footprint

1. Select **Your footprint**.
2. Enter one public IP or prefix, or choose a CSV/text file with one item per
   row. A header row, quotes, comments, and duplicates are handled; rejected
   input stays visible with its line number and reason.
3. Optionally enter your organization's RIPE holder name. Pathfinder uses it
   only to pre-check matching origin ASNs; review every selection yourself.
4. Select **Resolve footprint**. Review the resolved origin ASNs and check only
   the ASNs that are genuinely yours.
5. Select **Read adjacency**.

The report keeps unconfirmed origins for completeness but does not query their
neighbors. This is useful when a listed address belongs to a cloud, CDN, or
hosting provider rather than to your organization.

### A single IP or ASN

1. Select **Public routing context** for an IP, or **Explore ASN** for an ASN.
2. Enter one valid public target and select the analysis button.
3. Read the source status, retrieval times, warnings, and limits before drawing
   conclusions from the visualizations.
4. Export the report when you need a record of the investigation.

`AS3333` is a public RIPE NCC example often used in routing demonstrations. An
ASN lookup can still take several minutes because it may contain extensive public
routing context.

## Read the results in this order

1. **Identity context.** Confirm the submitted IP/prefix, the announced prefix,
   selected origin ASN, and reported holder name. A holder name is registration
   context only; it does not prove operator, provider, government, or location.
2. **Evidence and warnings.** Check sources, their retrieval times, errors,
   truncation, and missing coverage. A failed lookup, no returned evidence, and
   an unrequested source are different conditions.
3. **Footprint adjacency.** Each row is a neighbor RIPE's route collectors
   observed beside a confirmed ASN. `left` and `right` describe position in
   displayed BGP advertisements. They are not customer, transit, peering,
   ownership, traffic, or risk labels. IPv4/IPv6 values are route counts, not
   counts of distinct peers.
4. **Maps.** The footprint **Combined view** intentionally shows only immediate
   observed neighbors of your confirmed ASNs. A simple footprint may therefore
   show one hop. The separate **routing map** used in IP/ASN reports is a
   five-column presentation of retained BGP observations and inferred mappings;
   it is not a topology, geographic map, or packet path.
5. **Report and exports.** Use JSON for the full structured record, CSV for
   footprint resolution or adjacency rows, standalone HTML for a portable report,
   and the browser print dialog for a PDF. **Open a saved run** reloads a JSON
   export without making new lookups.

### What the routing map means

The selected origin is in the band at the right. Columns to the left group
networks by recorded AS-hop depth before that origin. Dashed lines are
collector-observed BGP advertisements; solid lines in IP mode are inferred from
current prefix-origin mappings of replying addresses in existing Atlas samples.

The map emphasizes frequent displayed nodes and retains some lower-frequency
nodes for context; it can also keep nodes needed to connect shown paths. Those
choices improve readability and are not confidence scores or judgments about a
network. Selecting a node filters the displayed paths and opens its detail card.
It does not change the saved data or calculations. The card reports the nearest
**displayed** hop position for that node.

A network in the first visible column is not necessarily adjacent to the selected
origin. Neither map claims an attack path, packet path, AS relationship, router
ownership, physical path, or verified operator relationship.

## Work safely with the output

Pathfinder reports public observations and explicit inference, not conclusions
about people or organizations. Use independent records and authorized
measurements when identity, traffic flow, ownership, provider status, or physical
location matters. Missing data never proves safety, absence, or non-involvement.

The app is a loopback-only local analyst prototype, not a shared service. It
keeps completed jobs in memory for a limited time and clears them on restart;
download reports you need to retain. Do not commit, publish, or share exports
without reviewing their targets, source dates, organization names, and other
investigation material.

## Further reference

- [Methods, sources, limits, and privacy](METHODS.md) — evidence definitions,
  processing limits, source behavior, retention, and the statements Pathfinder
  cannot support.
- [Local API](API.md) — the loopback JSON endpoints for local integration.
- [Development and verification](DEVELOPMENT.md) — trust-store behavior, test
  commands, security controls, and project-maintenance notes.

The application currently supports passive routing context only. RPKI validation,
SIEM/SOAR delivery, firewall formats, scheduled monitoring, active measurements,
and automatic enforcement are not implemented.
