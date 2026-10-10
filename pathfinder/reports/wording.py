"""Pathfinder reports wording responsibilities."""

from __future__ import annotations

METHODOLOGY = [
    "This analysis reads public RIPE data and existing Atlas measurements only. It never schedules a probe.",
    "Every run re-reads its sources. Retrieval times are when this run fetched the data.",
    "BGP paths are collector-observed advertisements, not packet paths or complete network architecture.",
    "Solid graph edges are inferred by mapping Atlas reply addresses to current prefix origins. They are not verified router ownership or AS transitions. Dashed edges are BGP observations.",
    "An adjacent ASN is context only. Adjacency does not establish a provider, ownership, government association, or physical location.",
    "Counts and fractions describe the retained sample, not traffic share, maliciousness, confidence, or complete network coverage.",
    "Current hop mappings are not historical routing evidence. Prefix reuse can miss more-specific routes; multiple origins and unanswered hops add uncertainty.",
    "Existing Atlas results describe their probe, destination, and time. They do not reconstruct an observed perimeter connection or an attacker's route.",
    "Records ending at other origins are listed separately. Multiple origins can be legitimate (anycast, mitigation services, provider-originated space) or a misorigination; this tool does not decide which.",
]


ASN_METHODOLOGY = [
    "ASN analysis reads public sources only. It does not choose an IP or schedule measurements.",
    "Every run re-reads its sources. Retrieval times are when this run fetched the data.",
    "BGP paths are collector-observed advertisements ending at the requested ASN, not packet paths to your perimeter.",
    "Prefix lists and route counts cover retained source observations, not a complete inventory or traffic share.",
    "Atlas classifies measurement targets by ASN. That classification can differ from current or historical routing.",
    "Existing traceroutes are samples to the displayed destination addresses and timestamps. Hop-to-AS mapping is not performed in this overview.",
    "Adjacency does not establish provider, ownership, government association, or physical location.",
]


FOOTPRINT_FIELDS = {
    "position": "RIPEstat ASN Neighbors 'type' field. left: the neighbor appears before your ASN in observed AS "
    "paths (toward the route collector). right: it appears after your ASN. uncertain: seen on the "
    "left only as a direct peer of a RIS route collector.",
    "power": "RIPEstat 'power': the number of AS paths containing this neighbor relationship with the stated position.",
    "v4_peers": "RIPEstat 'v4_peers': total number of IPv4 routes with this neighbor relationship seen by RIS peers. "
    "Despite the field name, this counts routes, not distinct peers.",
    "v6_peers": "RIPEstat 'v6_peers': the same count for IPv6 routes.",
}


FOOTPRINT_METHODOLOGY = [
    "Pathfinder reads public RIPE data only. It does not contact any host in the footprint or schedule measurements.",
    "Each entry is resolved with RIPEstat prefix-overview to the announced prefix covering it and that prefix's "
    "origin ASN(s). A prefix entry that contains more-specific announcements is mapped to their origins as well.",
    "A resolved covering prefix is reused for later entries only when it was read directly, its list of "
    "more-specific announcements is complete, and the entry falls outside all of them.",
    "RIPEstat leaves out routes seen by fewer RIS peers than its visibility threshold unless low-visibility routes "
    "are included. The threshold and the number of filtered routes are recorded with the run.",
    "Origin ASNs are listed with the share of footprint entries that map to them. Only ASNs the analyst confirmed "
    "are queried for neighbors; the rest stay in the record.",
    "Adjacency comes from RIPEstat ASN Neighbors: BGP neighbors of each confirmed ASN as observed by RIS. Position, "
    "path and route counts are RIPE's fields. They describe observed routing, not business relationships, traffic "
    "share, ownership or intent.",
    "Route collectors do not see every session. Private peering and sessions whose routes are not propagated "
    "toward RIS peers can be missing.",
    "For entries in shared provider space (cloud, CDN, hosting), the origin and its neighbors belong to the provider.",
    "This record is a point-in-time snapshot. Source times are recorded per lookup.",
]


def exclusion_warning(excluded: dict) -> str:
    return "Excluded BGP records: " + ", ".join(f"{k}: {v}" for k, v in sorted(excluded.items())) + "."


ROUTING_INTERPRETATION = (
    "Observed BGP adjacency or adjacency inferred from hop prefix-origin mappings. "
    "Neither confirms a provider relationship or a packet path to the perimeter."
)


def warning_text(warning):
    data = dict(warning.data)
    if warning.code == "map.presentation_limit":
        return (
            f"The chart shows the {data['kept']} busiest of {data['total']} networks; "
            "the JSON export retains the underlying path records."
        )
    if warning.code == "samples.origin_unmapped":
        return (
            f"{data['count']} traceroute samples have no hop mapped to AS{data['asn']}. Missing replies, "
            "incomplete mappings, and source-date differences prevent a reachability conclusion."
        )
    raise ValueError(f"Unknown calculation warning: {warning.code}")
