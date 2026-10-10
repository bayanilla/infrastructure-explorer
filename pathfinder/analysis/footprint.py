"""Pathfinder analysis footprint responsibilities."""

from __future__ import annotations

import collections

from pathfinder import config


def mapped_asns(row) -> list[int]:
    out = [o["asn"] for o in row["origins"]]
    for part in row["more_specifics"]:
        out += [o["asn"] for o in part["origins"]]
    return list(dict.fromkeys(out))


def group_origins(results, keywords) -> list[dict]:
    groups: dict[int, dict] = {}
    total = len(results)
    for row in results:
        asns = mapped_asns(row)
        multi = len(row["origins"]) > 1
        prefix_by_asn = collections.defaultdict(set)
        for o in row["origins"]:
            if row["covering_prefix"]:
                prefix_by_asn[o["asn"]].add(row["covering_prefix"])
        holders = {o["asn"]: o["holder"] for o in row["origins"]}
        for part in row["more_specifics"]:
            for o in part["origins"]:
                prefix_by_asn[o["asn"]].add(part["covering_prefix"] or part["prefix"])
                holders.setdefault(o["asn"], o["holder"])
        for a in asns:
            g = groups.setdefault(
                a,
                {
                    "asn": a,
                    "holder": None,
                    "entries": 0,
                    "inputs": [],
                    "prefixes": set(),
                    "multi_origin_entries": 0,
                },
            )
            g["holder"] = g["holder"] or holders.get(a)
            g["entries"] += 1
            if len(g["inputs"]) < config.MAX_INPUTS_PER_ORIGIN:
                g["inputs"].append(row["input"])
            g["prefixes"] |= prefix_by_asn.get(a, set())
            g["multi_origin_entries"] += 1 if multi else 0
    out = []
    for g in groups.values():
        holder = (g["holder"] or "").lower()
        match = next((k for k in keywords if k in holder), None)
        out.append(
            {
                **g,
                "prefixes": sorted(g["prefixes"], key=lambda p: (":" in p, p)),
                "share": round(g["entries"] / total, 4) if total else None,
                "inputs_truncated": g["entries"] > len(g["inputs"]),
                "default_selected": match is not None,
                "matched_keyword": match,
            }
        )
    out.sort(key=lambda g: (-g["entries"], g["asn"]))
    return out


def aggregate_neighbors(per_asn, confirmed) -> list[dict]:
    rows: dict[int, dict] = {}
    for entry in per_asn:
        for n in entry["neighbors"]:
            r = rows.setdefault(
                n["asn"],
                {"asn": n["asn"], "name": None, "relations": [], "is_confirmed_asn": n["asn"] in confirmed},
            )
            r["relations"].append(
                {
                    "your_asn": entry["asn"],
                    "type": n["type"],
                    "power": n["power"],
                    "v4_peers": n["v4_peers"],
                    "v6_peers": n["v6_peers"],
                }
            )
    out = []
    for r in rows.values():
        rel = r["relations"]
        out.append(
            {
                **r,
                "your_asn_count": len({x["your_asn"] for x in rel}),
                "positions": sorted({x["type"] for x in rel}),
                "max_power": max(x["power"] for x in rel),
                "max_v4_peers": max(x["v4_peers"] for x in rel),
                "max_v6_peers": max(x["v6_peers"] for x in rel),
            }
        )
    out.sort(key=lambda r: (-r["your_asn_count"], -(r["max_v4_peers"] + r["max_v6_peers"]), r["asn"]))
    return out


def covering_is_reusable(net, known):
    """Reuse only directly read, complete coverage that excludes all more-specifics."""
    return (
        known["complete"]
        and net.version == known["net"].version
        and net.subnet_of(known["net"])
        and not any(net.overlaps(part) for part in known["more_specifics"])
    )
