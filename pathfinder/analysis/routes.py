"""Pathfinder analysis routes responsibilities."""

from __future__ import annotations

import collections
import ipaddress

from pathfinder import config


def _valid_path(raw) -> bool:
    return (
        isinstance(raw, list)
        and 1 <= len(raw) <= 255
        and all(isinstance(a, int) and not isinstance(a, bool) and 1 <= a <= 4294967295 for a in raw)
    )


def collapse(seq) -> list[int]:
    out: list[int] = []
    for x in seq:
        if x is None:
            continue
        if not out or out[-1] != x:
            out.append(x)
    return out


def select_as_routes(rows, asn):
    """Select complete origin paths; do not bridge AS sets, loops, or transit-only matches."""
    selected, seen, excluded = [], set(), collections.Counter()
    for row in rows[: config.MAX_AS_ROUTES]:
        if not isinstance(row, dict):
            excluded["invalid"] += 1
            continue
        raw = row.get("path")
        if not _valid_path(raw):
            excluded["unsupported_path"] += 1
            continue
        if raw[-1] != asn:
            excluded["other_origin"] += 1
            continue
        path = collapse(raw)
        if len(path) != len(set(path)):
            excluded["loop"] += 1
            continue
        try:
            prefix = str(ipaddress.ip_network(row.get("target_prefix"), strict=True))
        except (ValueError, TypeError):
            excluded["invalid"] += 1
            continue
        peer = row.get("source_id")
        if not isinstance(peer, str) or not peer or len(peer) > 128:
            excluded["invalid"] += 1
            continue
        identity = (peer, prefix, tuple(raw))
        if identity in seen:
            excluded["duplicate"] += 1
            continue
        seen.add(identity)
        selected.append({"source_id": peer, "target_prefix": prefix, "path": path, "raw_path": list(raw)})
    selected.sort(key=lambda r: (r["source_id"], r["target_prefix"], r["raw_path"]))
    return selected, dict(excluded)


def other_origins(rows, asn) -> list[dict]:
    """Group well-formed records that end at an origin other than `asn`, by (prefix, origin)."""
    groups: dict[tuple, set] = collections.defaultdict(set)
    for row in rows[: config.MAX_AS_ROUTES]:
        if not isinstance(row, dict) or not _valid_path(row.get("path")):
            continue
        origin = row["path"][-1]
        if origin == asn:
            continue
        try:
            prefix = str(ipaddress.ip_network(row.get("target_prefix"), strict=True))
        except (ValueError, TypeError):
            continue
        peer = row.get("source_id")
        groups[(prefix, origin)].add(peer if isinstance(peer, str) else None)
    out = [{"prefix": p, "asn": o, "name": None, "peers": len(peers)} for (p, o), peers in groups.items()]
    out.sort(key=lambda r: (-r["peers"], r["prefix"], r["asn"]))
    return out
