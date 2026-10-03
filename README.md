# Múcaro | Infrastructure Explorer

A local, passive application for exploring an observed IP's public infrastructure
context. Look up an IP or CIDR, review its origin ASN and routing evidence, then
optionally explore broader ASN context. Includes seven themes and HTML/JSON exports
with a browser print/save-PDF flow.

It reads existing public RIPE data. It does not schedule probes, contact investigated
hosts, recommend blocking, or reconstruct the packet path of a perimeter event.
BGP advertisements and inferred hop mappings are presented separately.

## Run

Requires Python 3.10+ with a trusted CA store; no Python packages are required.

```sh
python3 probe_server.py
```

Open <http://127.0.0.1:8767/>. See [the application guide](PROBE_README.md) for
source disclosures, privacy, retention, sampling limits, and interpretation.

## Offline checks

```sh
python3 -m unittest -v
node test_report_rendering.js report_fixtures.json
```

The renderer check additionally requires Node.js. The committed report fixtures
contain fabricated source responses and an intentional injection test string;
they are not live investigation data or accuracy validation.

This is a local prototype. Shared deployment and operator-ground-truth validation
require additional work. The BGP lookup reference application remains independent.
