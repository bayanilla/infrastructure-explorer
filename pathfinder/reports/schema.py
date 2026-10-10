"""Versioned report contract and the only saved-report migration boundary.

An import is user-supplied evidence, not proof of source authenticity. Migration
preserves historical timestamps and never fetches sources or refreshes a result.
"""

from __future__ import annotations

from copy import deepcopy

from pathfinder.errors import UserError

SCHEMA = "pathfinder.report/1"


def stamp_report(record):
    return {**record, "schema": SCHEMA}


def upgrade(record):
    if not isinstance(record, dict):
        raise UserError("That file isn't a Pathfinder report object.")
    if record.get("schema") not in (None, SCHEMA):
        raise UserError("Unsupported report schema. Use the Pathfinder version that exported this file.")
    # Bound nesting/element count before migration or rendering.
    pending = [(record, 0)]
    total = 0
    while pending:
        value, depth = pending.pop()
        total += 1
        if depth > 40 or total > 500000:
            raise UserError("The saved report exceeds import structure limits.")
        if isinstance(value, dict):
            pending.extend((v, depth + 1) for v in value.values())
        elif isinstance(value, list):
            pending.extend((v, depth + 1) for v in value)
    rec = deepcopy(record)
    meta = rec.get("meta")
    if not isinstance(meta, dict) or not isinstance(meta.get("generated_utc"), str):
        raise UserError("The report is missing its original generation time.")
    kind = rec.get("kind")
    if kind in ("footprint_resolution", "footprint_run"):
        required = {
            "inputs": dict,
            "origins": list,
            "resolution": list,
            "settings": dict,
            "warnings": list,
            "sources": dict,
            "status_counts": dict,
        }
        if kind == "footprint_run":
            required.update(adjacency=dict, confirmed_asns=list, summary=list, methodology=list)
    elif meta.get("target_kind") in ("ip", "asn"):
        required = {
            "graph": dict,
            "control_plane": dict,
            "routing_context": dict,
            "traces": list,
            "summary": list,
            "warnings": list,
            "methodology": list,
            "vantage": list,
        }
    else:
        raise UserError("That file isn't a supported Pathfinder export.")
    for name, expected in required.items():
        if not isinstance(rec.get(name), expected):
            raise UserError(f"The saved report has an invalid or missing {name} field.")
    if kind == "footprint_run":
        adjacency = rec["adjacency"]
        rename(adjacency, "neighbours", "neighbors")
        for item in adjacency.get("per_asn", []):
            if not isinstance(item, dict):
                raise UserError("Invalid per-ASN report record.")
            rename(item, "neighbours", "neighbors")
            if isinstance(item.get("source"), dict):
                rename(item["source"], "neighbour_counts", "neighbor_counts")
        rename(rec["sources"], "asn_neighbours", "asn_neighbors")
        if not isinstance(adjacency.get("neighbors"), list) or not isinstance(adjacency.get("per_asn"), list):
            raise UserError("The adjacency record is incomplete.")
    return stamp_report(rec)


def rename(obj, old, new):
    if old in obj and new in obj and obj[old] != obj[new]:
        raise UserError(f"Conflicting legacy and current {new} fields.")
    if old in obj:
        obj[new] = obj.pop(old)
