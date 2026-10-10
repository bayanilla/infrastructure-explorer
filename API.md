# Local API

The browser uses a small JSON API on the loopback-only Pathfinder server. It is
for local experiments and has no authentication; do not expose it as a remote or
multi-user API.

| Method and path | Purpose |
| --- | --- |
| `GET /api/settings/shodan` | Returns whether a server-memory key is configured, never the key. |
| `POST /api/settings/shodan` | Sets or removes the server-memory Shodan key. |
| `POST /api/settings/shodan/check` | Checks read-only Shodan account access. |
| `POST /api/shodan` | Starts retrieval of existing service records for explicit resources. |
| `POST /api/shodan/page` | Starts retrieval of one additional prefix search page. |
| `POST /api/import` | Validates and migrates a saved report without source lookups. |
| `GET /api/health` | Returns the local application version. |
| `POST /api/analyze` | Starts one passive IP or ASN analysis. |
| `POST /api/footprint/resolve` | Starts footprint resolution. |
| `POST /api/footprint/adjacency` | Reads neighbors for confirmed ASNs from a footprint-resolution job. |
| `GET /api/job/<job-id>` | Returns job progress, error state, or its completed report. |
| `POST /api/job/<job-id>/cancel` | Requests cancellation of an in-progress analysis. |

## IP or ASN analysis

```json
{
  "target": "AS3333",
  "tier": "public",
  "measurement_ids": "",
  "control_plane": true
}
```

`tier` must be `public`. This analysis endpoint rejects API keys, active-probe schedules,
suspect-network inputs, and enforcement inputs. A successful start returns
`202` and a job ID; read the job until its status is `done`, `failed`, or
`cancelled`.

## Footprint resolution

`POST /api/footprint/resolve` accepts:

```json
{
  "csv": "ip_or_cidr\n193.0.6.139\n2001:db8::/32\n",
  "org_keywords": "Example Org",
  "include_low_visibility": false
}
```

Use the returned resolution job ID with `POST /api/footprint/adjacency`:

```json
{
  "resolution_job": "job-id-from-resolution",
  "asns": [3333]
}
```

Each ASN must have appeared in that footprint resolution. See [methods and
limits](METHODS.md) for target validation, privacy, timing, and source behavior.

## Report compatibility

New reports carry `schema: "pathfinder.report/1"`. Submit the entire saved JSON
record to `/api/import` to normalize older exports. Historical source and generation
times remain intact. Imports are limited to 16 MB; future schemas and conflicting
legacy/current fields are rejected. This endpoint does not register a resumable
resolution job.


## Optional Shodan API

Configure a key with `POST /api/settings/shodan` and an object containing `key`.
Keys must be 16–128 alphanumeric characters. Send `{"key": null}` to remove it.
The settings endpoint has a 2 KiB body limit. Credentials remain in server
memory only, shared by tabs using the service. Configuration validates syntax;
it does not verify account access.

`POST /api/settings/shodan/check` accepts `{}` and reads Shodan account info.
Success returns a configured status and connection message, not the account
response. It does not guarantee prefix-search permissions or remaining credits.

Start retrieval with `POST /api/shodan`:

```json
{"resources": ["193.0.6.139", "193.0.6.0/24"]}
```

Inputs must be 1–20 public IPs or canonical public prefixes. Duplicate resources
are normalized. Service request bodies are limited to 8 KiB. Successful starts
return `202` and a job ID; poll/cancel through the existing job endpoints.

To request another prefix page, use `POST /api/shodan/page`:

```json
{"resources": ["193.0.6.0/24"], "page": 2}
```

Exactly one prefix and an integer page from 2 through 100 are required. Paging
is explicit and may consume credits. The endpoint returns that page's records;
it does not accumulate earlier pages. The browser merges retained records and
preserves page provenance.

Results contain `source`, `limits`, and per-resource `records`, including status,
query, retrieval time, reported total, coverage/truncation, rejected counts, page
provenance, and service observations. Failures are per resource and do not imply
an empty source result. The browser attaches these to the routing/Footprint
report as `service_observations`; the source job itself returns the service result.
Source bounds and timestamp meanings are documented in [Methods](METHODS.md).
Only read-only account, host, and search endpoints are used. No scan is requested.
