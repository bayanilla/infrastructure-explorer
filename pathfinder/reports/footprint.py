"""Canonical footprint reports. Source snapshots and generation time are explicit inputs."""

from __future__ import annotations

import collections

from pathfinder import config
from pathfinder.analysis.footprint import group_origins
from pathfinder.reports.wording import FOOTPRINT_FIELDS, FOOTPRINT_METHODOLOGY
from pathfinder.sources.stat import stat_url


def build_resolution(
    *, parsed, keywords, include_low_visibility, results, stats, warnings, generated_utc, job_id, requests
):
    min_peers = 1 if include_low_visibility else None
    warnings = list(warnings)
    origins = group_origins(results, keywords)
    counts = collections.Counter(r["status"] for r in results)
    threshold = sorted(stats["thresholds"])
    if stats["filtered_routes"]:
        warnings.append(
            f"RIPE left out {stats['filtered_routes']} low-visibility route(s) across {stats['lookups_with_filtering']} "
            f"lookup(s) (minimum RIS peers: {', '.join(map(str, threshold)) or 'not reported'}). They are not in this "
            "resolution. Run again with low-visibility routes included to see them."
        )
    truncated = sum(1 for r in results if r["more_specifics_truncated"])
    if truncated:
        warnings.append(
            f"{truncated} prefix entr{'y lists' if truncated == 1 else 'ies list'} more-specific "
            f"announcements beyond what was resolved (RIPE truncation or the {config.MAX_RANGE_EXPANSION}-per-entry limit)."
        )
    if counts.get("lookup_failed"):
        warnings.append(
            f"{counts['lookup_failed']} entr{'y' if counts['lookup_failed'] == 1 else 'ies'} could not be "
            "looked up. They are listed with the error RIPE returned."
        )
    multi = sum(1 for r in results if len(r["origins"]) > 1)
    if multi:
        warnings.append(
            f"{multi} entr{'y is' if multi == 1 else 'ies are'} covered by a prefix announced by more than one origin ASN. "
            "Each origin is listed."
        )
    return {
        "kind": "footprint_resolution",
        "meta": {
            "tool": "Múcaro | Pathfinder",
            "version": config.VERSION,
            "generated_utc": generated_utc,
            "job_id": job_id,
        },
        "settings": {
            "org_keywords": keywords,
            "include_low_visibility": include_low_visibility,
            "visibility_threshold": 1 if min_peers else (threshold[0] if len(threshold) == 1 else None),
            "visibility_threshold_note": (
                "min_peers_seeing=1 was requested."
                if min_peers
                else "RIPEstat default; the value is taken from RIPE's response messages."
            ),
        },
        "inputs": {
            k: parsed[k]
            for k in (
                "rows_read",
                "header",
                "accepted",
                "duplicates",
                "rejected_total",
                "rejected",
                "rejected_truncated",
                "entries",
            )
        },
        "resolution": results,
        "status_counts": dict(counts),
        "origins": origins,
        "sources": {
            "prefix_overview": {
                "name": "RIPEstat prefix-overview",
                "url": stat_url("prefix-overview", resource="{entry}"),
                "lookups": stats["lookups"],
                "reused": stats["reused"],
                "query_times": sorted(stats["query_times"]),
                "filtered_routes": stats["filtered_routes"],
                "messages": [{"message": m, "count": c} for m, c in stats["messages"].most_common(50)],
            }
        },
        "warnings": warnings,
        "requests": requests,
    }


def build_footprint_run(*, resolution, confirmed, per_asn, neighbors, warnings, generated_utc, requests):
    warnings = list(warnings)
    available = [p for p in per_asn if p["source"]["status"] == "available"]
    times = sorted({p["source"]["query_starttime"] for p in available if p["source"]["query_starttime"]})
    shared = sum(1 for n in neighbors if n["your_asn_count"] > 1)
    summary = [
        f"{resolution['inputs']['accepted']} footprint entries map to {len(resolution['origins'])} origin "
        f"ASN{'s' if len(resolution['origins']) != 1 else ''}; {len(confirmed)} confirmed as yours.",
        f"RIS observes {len(neighbors)} distinct network{'s' if len(neighbors) != 1 else ''} adjacent to the "
        f"confirmed ASNs" + (f" (RIPEstat ASN Neighbors, {', '.join(times)})." if times else "."),
    ]
    if shared:
        summary.append(
            f"{shared} of them {'is' if shared == 1 else 'are'} adjacent to more than one confirmed ASN."
        )
    if len(available) != len(per_asn):
        summary.append(f"Neighbor data is unavailable for {len(per_asn) - len(available)} confirmed ASN(s).")
    summary.append(
        "Adjacency is observed BGP position. It does not establish a business relationship, traffic share, "
        "ownership or intent."
    )
    origins = [{**o, "confirmed": o["asn"] in confirmed} for o in resolution["origins"]]
    return {
        "kind": "footprint_run",
        "meta": {
            "tool": "Múcaro | Pathfinder",
            "version": config.VERSION,
            "generated_utc": generated_utc,
            "resolution_generated_utc": resolution["meta"]["generated_utc"],
        },
        "settings": resolution["settings"],
        "inputs": resolution["inputs"],
        "resolution": resolution["resolution"],
        "status_counts": resolution["status_counts"],
        "origins": origins,
        "confirmed_asns": confirmed,
        "adjacency": {"per_asn": per_asn, "neighbors": neighbors, "field_definitions": FOOTPRINT_FIELDS},
        "sources": {
            **resolution["sources"],
            "asn_neighbors": {
                "name": "RIPEstat ASN Neighbors",
                "url": stat_url("asn-neighbours", resource="AS{asn}"),
                "query_times": times,
            },
        },
        "summary": summary,
        "warnings": warnings,
        "methodology": FOOTPRINT_METHODOLOGY,
        "requests": {"resolution": resolution["requests"], "adjacency": requests},
    }
