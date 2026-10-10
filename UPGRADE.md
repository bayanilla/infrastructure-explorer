# Pathfinder update

Pathfinder now uses the reorganized implementation developed in Pathfinder v2.
The repository link, familiar startup command, and default port remain the same.

## What changed

- Optional Shodan service observations, kept separate from routing evidence.
- Settings for appearance and a session-only Shodan connection.
- Interactive per-ASN BGP path context and paginated service details.
- Stronger source safeguards, saved-report validation, and automated checks.

Pathfinder remains an AI-assisted proof of concept. It reads existing records;
it does not scan targets, request new measurements, or make enforcement decisions.
Shodan is off by default and requires your own API key only if you enable it.

## Update an existing installation

Stop Pathfinder. In an unchanged checkout on the main branch:

```sh
git pull --ff-only origin main
python3 probe_server.py
```

Open http://127.0.0.1:8767/ and refresh. Keep your custom port if you configured one.
If you downloaded a ZIP instead of cloning, download a fresh copy from the same
repository and start it with the command above.

Preserve any local code changes or files before updating. Restart clears
in-memory runs and Shodan credentials. Export reports first if you need them.
Python 3.10 or later is still required; there are no additional runtime packages
or database requirements.

Earlier JSON exports can be opened without new source lookups. They remain
historical records, and cannot resume an expired Footprint confirmation job.
Representative original exports pass compatibility checks; modified reports may
be rejected.

Source files now live under pathfinder/ and browser files under web/. Custom
integrations that imported functions from probe_server.py or changed the old
probe_web/index.html need adaptation. Startup compatibility does not preserve
all internal Python imports. The original Git history remains available.
