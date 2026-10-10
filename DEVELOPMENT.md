# Development and verification

Run from this directory with Python 3.10+:

```sh
python3 -m pathfinder
```

Verification uses frozen synthetic responses and never contacts an investigated
host. Run:

```sh
python3 -m unittest
node test_rendering.mjs
node test_jobs.mjs
node test_services.mjs
python3 tools/gen_limits.py --check
```

For optional development tooling:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements-dev.txt
.venv/bin/ruff check --no-respect-gitignore pathfinder probe_server.py test_*.py tools
.venv/bin/ruff format --check --no-respect-gitignore pathfinder probe_server.py test_*.py tools
```

The application needs no third-party runtime packages. The supplied CI configuration
runs these checks on Python 3.10/3.14 and Node 22. Remote CI results must be checked on GitHub; local checks do not establish
remote CI success. The npm/CI commands run the renderer, poller, and service-renderer checks.

`tests/baseline_reports.json` contains five reports generated from the original
application at commit `57585a9`, using fabricated fixture responses. The normalization
helper excludes generation/retrieval times, run IDs, version metadata, a new BGP
error detail and the renamed sourceapp query parameter. It retains observation
times, evidence records, unknown states, calculations, warnings and other behavior.

The Python suite includes baseline regressions, characterization comparisons,
evidence, source-gate, import, HTTP-boundary, and Shodan adapter tests. Use the
test runner output for the current count. Node checks cover report rendering,
service details/pagination markup, and the shared poller.

Manual checks completed locally: saved Footprint/IP imports, neighbor sorting,
expandable details, map selection, BGP layer filtering, and no browser console
errors. A live Footprint lookup for `193.0.6.139` completed with AS3333 using one
RIPE request. Bulk live performance, upstream schema evolution and PDF pagination
were not revalidated in this edition.

Use `examples/` only for interface testing: all data is synthetic. Never publish
private inputs, credentials or unredacted exports. There is no LICENSE supplied;
do not infer unrestricted redistribution rights from public data availability.


## Optional Shodan verification

Shodan fixtures cover credential validation, read-only endpoint restrictions,
response and resource bounds, source failures, unknown totals, timestamp and
service validation, and bounded detail fields. HTTP tests cover settings and
service routes and rejection of removed Censys/Netlas routes. Renderer checks
exercise escaped service details and complete export content.

Recent local verification passed 83 Python tests plus the renderer, poller, and
service-renderer checks. A synthetic browser exercise checked 20-row pagination,
service disclosure, escaped banners, and explicit additional-page loading.
These checks do not validate live Shodan coverage, account permissions, or bulk
performance. No production-readiness or comparative-accuracy claim follows.

The baseline refactoring came from commit `57585a9`. The original application
and BGP reference checkout remain separate; they are not runtime dependencies.
Do not restart a live local session without explaining that its jobs and Shodan
credential will be cleared. Never read or print a configured key for debugging.
