# Múcaro | Pathfinder

**Public routing context for IPs and networks.**

Pathfinder provides a timestamped, outside-in view of how public routing
collectors see your internet footprint. Network teams can compare that view with
router configuration, policy, provider records, and recent changes.

**AI-assisted proof of concept.** Pathfinder is a local investigation aid for
analysts. It reads existing RIPE data and, optionally, Shodan service observations.
It never scans your addresses or requests new measurements. No AI runs in the
application to collect, score, or interpret evidence. Its reports support
validation; they do not establish actual traffic paths, system ownership, or
current exposure.

## Contents

- [Start Pathfinder](#start-pathfinder)
- [Review your footprint](#review-your-footprint)
- [Add Shodan observations](#add-shodan-observations)
- [Interpret and validate the report](#interpret-and-validate-the-report)
- [Save and share results](#save-and-share-results)
- [Privacy and practical limits](#privacy-and-practical-limits)
- [Further documentation](#further-documentation)

## Start Pathfinder

With Python 3.10 or later, clone the project and start it:

```sh
git clone https://github.com/bayanilla/pathfinder.git
cd pathfinder
```

From the project directory:

```sh
python3 -m pathfinder
```

The familiar `python3 probe_server.py` startup command remains supported.

Open **http://127.0.0.1:8767/** in your browser. No additional runtime packages,
database, or BGP Lookup installation are required. To use a different port,
start with `python3 -m pathfinder --port 8770`.

Internet access and working HTTPS certificates are required for live lookups.
If certificate verification fails, repair your certificate configuration rather
than disabling verification. Use **Settings → Appearance** to choose a theme.

To try the interface without live lookups, select **Open a saved run** and choose
`examples/synthetic-footprint.json` or `examples/synthetic-ip.json`. These contain
fabricated test data, not live intelligence.

Already using Pathfinder? Read [the upgrade instructions](UPGRADE.md) before
updating your local copy.

## Review your footprint

1. Select **Your footprint**. Enter one public IP or prefix, or upload a
   one-column CSV of your public addresses and prefixes.
2. Review the resolved origin ASNs, holder names, announced prefixes, rejected
   rows, and source dates. An origin ASN is the network observed announcing that
   address space; its holder name does not establish who operates each host.
3. Confirm which origin ASNs your organization operates. An organization-name
   match can preselect a candidate, but you must review it. Cloud, CDN, and hosting
   origins may belong to your providers rather than your organization.
4. Select **Read adjacency** to see the networks RIPE observed immediately next
   to your confirmed ASNs in BGP advertisements.
5. Under **Per-ASN detail**, choose an ASN to load its interactive BGP path map.
   Select a network on the map to inspect its context. Expand the ASN rows below
   to compare footprint entries with announced prefixes and read source details.

Use **Public routing context** for a focused review of one IP, or **Explore ASN**
for broader observed BGP paths. Existing Atlas traceroute samples are labeled
separately. They are not plotted on the Footprint per-ASN BGP map.

## Add Shodan observations

Shodan adds dated records of services it observed, such as an IP, port, transport,
and reported service. It is optional and separate from the routing evidence.

1. Open **Settings → Shodan connection** and enter your Shodan API key.
2. Select **Use for this session**, then **Check connection**. A successful check
   verifies account access, not permission or available credits for every query.
3. Before starting **Your footprint** or **Public routing context**, select
   **Include Shodan observations**. Explore ASN does not offer this option.

For Footprint, Shodan queries the supplied entries, including entries mapped to
unconfirmed provider ASNs. ASN confirmation controls RIPE adjacency only.

Tables show **20 service rows per display page** with numbered navigation.
The arrow beside an IP expands that particular IP/port observation: reported
software, hostnames, web-service details, certificate details, and banner text,
when available. Missing details say **Not reported**.

For a prefix with additional reported results, **Load next 100 records from
Shodan** retrieves another source page and adds display pages. It may consume
query credits. A missing total is shown as unknown coverage; it is not proof
that all results were retrieved. Single-IP responses are capped and do not have
this prefix-search paging control.

Shodan support is currently limited to 20 supplied resources per initial run,
100 service records per response, and up to 100 source pages per prefix.
Larger footprints receive an explicit not-requested explanation. A failed lookup
or an empty table does not establish that an address has no exposed services.

## Interpret and validate the report

Treat the report as a precise question for network operations:

> RIPE observed these origin assignments and adjacent ASNs at the recorded source
> times. Do they match our intended routing design and provider arrangements?
> Are the services recorded by Shodan expected to be publicly accessible?

**Worked example:** enter one known public IP, confirm its resolved origin only
if your team operates that ASN, and review the observed neighbors. Give network
operations the prefix, ASN, source dates, and report. They can compare these with
live router state, BGP policy, provider records, and change history. If Shodan
shows a service, the asset owner can validate its current configuration and
whether public access is intended.

In adjacency results, **left** means the neighbor appeared before your ASN in an
observed AS path, toward the collector. **Right** means it appeared after your
ASN, toward the route's origin. Neither position alone establishes a provider,
peer, customer, or actual packet path.

For a right-side neighbor, ask: **“Do we expect routes toward this ASN, and any
origin ASNs beyond it, to be advertised through our ASN?”** The neighbor itself
need not be the final origin in that path.

Route and path counts describe source observations, not traffic volume or
confidence. Source observation time and Pathfinder retrieval time are different;
when an observation time is missing, the report says so. Shodan observations may
be older than the routing lookup. Unfamiliar results warrant validation, not an
automatic incident declaration or blocking decision.

## Save and share results

- **JSON:** saves the report record, including fetched Shodan observations.
- **CSV:** Footprint provides adjacency and resolution CSVs. Shodan has a separate
  **Service observations CSV**; routing CSVs do not include service records.
- **Standalone HTML:** available in IP/ASN mode.
- **Print or save PDF:** available through your browser.

Service exports and printing retain all fetched service rows, regardless of the
selected display page. Results not yet fetched remain outside the report.

The Footprint per-ASN path map is a separate lookup. Its evidence is not added
to the Footprint JSON or CSV; use Explore ASN for that lookup's own exports.
A map loaded in the live Footprint page can appear in its browser printout.

**Open a saved run** reloads a JSON export without new RIPE or Shodan lookups.
Imported reports remain historical, user-supplied records; importing does not
verify their authenticity or refresh their evidence.

## Privacy and practical limits

| Consideration | What to expect |
| --- | --- |
| Target contact | Pathfinder never scans or contacts investigated hosts, or requests Shodan scans or new Atlas measurements. |
| External queries | RIPE receives routing lookup targets. When enabled, Shodan receives the supplied service lookup resources. Both can see the requesting public IP. |
| Shodan key | Held only in local server memory, shared by tabs using that server, until removed or restarted. Not saved in browser storage, logs, or reports. |
| Source coverage | Public collectors and Shodan provide partial observations. Failed, empty, unknown, and partial results have different meanings. |
| Footprint size | Up to 5,000 distinct entries and a 1 MiB upload; resolution and expansion limits can leave a run incomplete. Start with a small known sample. |
| Lookup time | RIPE requests are serialized. Default pauses are one second for RIPEstat and at least two seconds for Atlas; large runs and retries can take substantial time. |
| Local retention | Runs are held in memory. Finished runs expire after an hour and can be evicted sooner when capacity is reached. Restart clears runs and the Shodan key. Save reports you need. |
| Continuing later | A saved resolution can be viewed, but cannot resume adjacency after its original in-memory job expires or the server restarts. |
| Deployment | Intended for local use. Shared or remote deployment needs a separate security design. |

Review sensitive inputs and source-data terms before sharing an export.
Pathfinder does not encrypt saved reports.

## Further documentation

- [Methods, sources, and interpretation limits](METHODS.md) — detailed evidence
  meanings, coverage, and source-specific limits.
- [Architecture](ARCHITECTURE.md) — implementation responsibilities and engineering
  decisions.
- [Development and verification](DEVELOPMENT.md) — checks and validation limits.
- [Local API](API.md) — integration contracts for developers.
- [Configured routing and job limits](docs/LIMITS.md) — generated technical reference;
  Shodan-specific bounds are documented in Methods.
