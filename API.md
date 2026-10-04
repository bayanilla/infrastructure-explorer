# Local API

The browser uses a small JSON API on the loopback-only Pathfinder server. It is
for local experiments and has no authentication; do not expose it as a remote or
multi-user API.

| Method and path | Purpose |
| --- | --- |
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

`tier` must be `public`. The server rejects API keys, active-probe schedules,
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
