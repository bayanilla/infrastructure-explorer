"""Reproducible calculations over already-normalized evidence."""

from __future__ import annotations

import collections

from pathfinder import config
from pathfinder.analysis.routes import collapse
from pathfinder.model import Warning
from pathfinder.validation import is_public_ip


def entry_of(path: list[int], origin: int) -> int | None:
    if origin not in path:
        return None
    i = path.index(origin)
    return path[i - 1] if i > 0 else None


def calculate_context(*, origin_asn, traces, probe_meta, ipmap, cp_routes) -> dict:
    """cp_routes must already be selected by select_as_routes for origin['asn']."""
    warnings: list[Warning] = []

    # Inferred hop mappings ----------------------------------------------------
    trace_rows = []
    data_paths: list[list[int]] = []
    entry_data = collections.Counter()
    vantage = collections.defaultdict(
        lambda: {
            "traces": 0,
            "reached": 0,
            "entries": collections.Counter(),
            "countries": collections.Counter(),
        }
    )
    for t in traces:
        meta = probe_meta.get(t.get("probe_id")) or {}
        v6 = ":" in str(t.get("dst") or "")
        probe_asn = meta.get("asn_v6" if v6 else "asn_v4")
        probe_asn = probe_asn if isinstance(probe_asn, int) and probe_asn > 0 else None
        seq = [probe_asn] if probe_asn else []
        hops = []
        for h in t.get("hops") or []:
            ip, asn, scope = h.get("ip"), None, None
            if ip:
                if is_public_ip(ip):
                    asn = (ipmap.get(ip) or {}).get("asn")
                    seq.append(asn)
                else:
                    scope = "special-use"
            hops.append({**h, "asn": asn, "scope": scope})
        path = collapse(seq)
        reached_target = bool(t.get("dst")) and any(h.get("ip") == t.get("dst") for h in hops)
        in_origin = origin_asn in path
        entry = entry_of(path, origin_asn)
        if entry is not None:
            entry_data[entry] += 1
        if in_origin and path.index(origin_asn) > 0:
            data_paths.append(path[: path.index(origin_asn) + 1])
        key = probe_asn or 0
        vantage[key]["traces"] += 1
        vantage[key]["reached"] += 1 if in_origin else 0
        if entry is not None:
            vantage[key]["entries"][entry] += 1
        if meta.get("country_code"):
            vantage[key]["countries"][meta["country_code"]] += 1
        trace_rows.append(
            {
                "msm_id": t.get("msm_id"),
                "probe_id": t.get("probe_id"),
                "probe_asn": probe_asn,
                "probe_country": meta.get("country_code"),
                "src": t.get("src"),
                "dst": t.get("dst"),
                "timestamp": t.get("timestamp"),
                "hops": hops,
                "as_path": path,
                "reached_origin_as": in_origin,
                "reached_target": reached_target,
                "entry_asn": entry,
                "as_loop": len(path) != len(set(path)),
                "mapping_status": "prefix_origin_inference",
            }
        )

    # BGP observations ---------------------------------------------------------
    entry_cp = collections.Counter()
    cp_paths = []
    for r in cp_routes:
        path = r["path"]
        if not path or path[-1] != origin_asn:
            continue  # defensive: callers pass selected routes only
        cp_paths.append(
            {
                "prefix": r["target_prefix"],
                "path": path,
                "raw_path": r.get("raw_path", path),
                "source_id": r["source_id"],
            }
        )
        e = entry_of(path, origin_asn)
        if e is not None:
            entry_cp[e] += 1

    # Graph --------------------------------------------------------------------
    depth: dict[int, int] = {}
    w_data = collections.Counter()
    w_cp = collections.Counter()
    edges = collections.defaultdict(lambda: {"data": 0, "cp": 0})

    def add(path, layer):
        n = len(path)
        for i, a in enumerate(path):
            d = n - 1 - i
            depth[a] = min(depth.get(a, d), d)
            (w_data if layer == "data" else w_cp)[a] += 1
        for a, b in zip(path, path[1:]):
            if a != b:
                edges[(a, b)][layer] += 1

    for p in data_paths:
        add(p, "data")
    for p in cp_paths:
        add(p["path"], "cp")
    depth.setdefault(origin_asn, 0)

    entries = set(entry_data) | set(entry_cp)
    vantage_asns = {a for a in vantage if a}
    keep = [origin_asn] + sorted(entries - {origin_asn})
    for a in sorted(depth, key=lambda a: (-(w_data[a] * 4 + w_cp[a]), a)):
        if len(keep) >= config.MAX_GRAPH_NODES:
            break
        if a not in keep:
            keep.append(a)
    keep_set = set(keep)
    if len(depth) > len(keep_set):
        warnings.append(Warning("map.presentation_limit", (("kept", len(keep_set)), ("total", len(depth)))))

    nodes = []
    for a in keep:
        roles = []
        if a == origin_asn:
            roles.append("origin")
        if a in entries:
            roles.append("adjacent")
        if a in vantage_asns:
            roles.append("vantage")
        nodes.append(
            {"asn": a, "name": None, "roles": roles, "depth": depth[a], "data": w_data[a], "cp": w_cp[a]}
        )
    graph_edges = [
        {"from": a, "to": b, **c} for (a, b), c in edges.items() if a in keep_set and b in keep_set
    ]

    # Routing context: sample counts and inferred adjacency, never action advice.
    total_data = sum(entry_data.values())
    total_cp = sum(entry_cp.values())
    adjacencies = []
    for a in entries:
        adjacencies.append(
            {
                "asn": a,
                "name": None,
                "data_paths": entry_data[a],
                "data_share": round(entry_data[a] / total_data, 4) if total_data else None,
                "cp_routes": entry_cp[a],
                "cp_share": round(entry_cp[a] / total_cp, 4) if total_cp else None,
                "interpretation": None,
            }
        )
    adjacencies.sort(key=lambda row: (-row["cp_routes"], -row["data_paths"], row["asn"]))
    reached = sum(1 for row in trace_rows if row["reached_origin_as"])
    if len(trace_rows) != reached:
        warnings.append(
            Warning("samples.origin_unmapped", (("count", len(trace_rows) - reached), ("asn", origin_asn)))
        )

    vantage_rows = []
    for a, v in sorted(vantage.items(), key=lambda kv: (-kv[1]["traces"], kv[0])):
        vantage_rows.append(
            {
                "asn": a or None,
                "name": None,
                "traces": v["traces"],
                "reached": v["reached"],
                "countries": dict(v["countries"]),
                "entries": [{"asn": e, "traces": c} for e, c in v["entries"].most_common()],
            }
        )

    return {
        "routing_context": {
            "adjacencies": adjacencies,
            "calculations": {
                "bgp_fraction": {
                    "numerator": "cp_routes",
                    "denominator": total_cp,
                    "unit": "fraction of retained BGP records with a preceding ASN",
                    "rounding": "4 decimal places",
                },
                "mapped_sample_fraction": {
                    "numerator": "data_paths",
                    "denominator": total_data,
                    "unit": "fraction of retained samples with an inferred preceding ASN",
                    "rounding": "4 decimal places",
                },
            },
        },
        "graph": {"nodes": nodes, "edges": graph_edges},
        "traces": trace_rows,
        "vantage": vantage_rows,
        "control_plane": {
            "routes": len(cp_paths),
            "entry_counts": [{"asn": a, "routes": c} for a, c in entry_cp.most_common()],
            "paths": cp_paths[: config.MAX_CP_PATHS_KEPT],
            "truncated": len(cp_paths) > config.MAX_CP_PATHS_KEPT,
        },
        "warnings": warnings,
    }
