# Development and verification

## Local startup and source trust

Pathfinder requires Python 3.10+ and uses the standard library. Start it with:

```sh
python3 probe_server.py
```

The application uses Python's normal verified HTTPS setup. If the runtime points
to a missing CA file, it uses the operating system CA bundle while keeping
certificate and hostname verification enabled. Do not disable verification to
work around a RIPE connection error; repair the local trust configuration if no
valid trust store is available.

## Verification

Run the Python suite:

```sh
python3 -m unittest -v
```

When Node.js is available, run renderer and export checks:

```sh
node test_report_rendering.js report_fixtures.json
node test_footprint_rendering.js footprint_fixtures.json
```

Tests use frozen synthetic source responses. They cover validation, public-only
operation, per-run caching, source and measurement checks, cancellation,
unknown-versus-empty evidence, reports and exports, escaping untrusted content,
and footprint resolution/adjacency behaviors. Fixture data is fabricated and is
not live intelligence or an accuracy benchmark.

## Local security characteristics

The server binds to loopback by default, checks expected Host and Origin headers,
rejects cross-origin POSTs, sets a restrictive content-security policy, and
limits request bodies. These measures do not make it appropriate to expose on a
shared network without a separate security design.

The BGP Lookup repository informed visual design and domain research only.
Pathfinder is standalone and does not depend on a local BGP Lookup checkout.
The supplied Coquí artwork is stored locally and is not retrieved from the
reference project at runtime.

This repository has no `LICENSE` file. Do not infer unrestricted reuse rights
from repository visibility. Never commit credentials, private observations, or
unredacted reports.
