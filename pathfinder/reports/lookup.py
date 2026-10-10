"""Build IP/ASN reports from calculated context. No network requests or hidden clock."""

from __future__ import annotations

from copy import deepcopy

from pathfinder import config
from pathfinder.analysis.routing import calculate_context
from pathfinder.model import Status
from pathfinder.reports.wording import ASN_METHODOLOGY, METHODOLOGY, ROUTING_INTERPRETATION, warning_text


def build_lookup_report(
    *,
    kind,
    target_input,
    target_ip,
    origin,
    traces,
    probe_meta,
    ipmap,
    cp_routes,
    warnings,
    data_scope,
    generated_utc,
    bgp_status,
    samples=(),
):
    context = calculate_context(
        origin_asn=origin["asn"], traces=traces, probe_meta=probe_meta, ipmap=ipmap, cp_routes=cp_routes
    )
    report = deepcopy(context)
    report["warnings"] = [*warnings, *(warning_text(w) for w in context["warnings"])]
    for row in report["routing_context"]["adjacencies"]:
        row["interpretation"] = ROUTING_INTERPRETATION
    report["meta"] = {
        "tool": "Múcaro | Pathfinder",
        "version": config.VERSION,
        "generated_utc": generated_utc,
        "target_input": target_input,
        "target_ip": target_ip,
        "origin": {**origin, "name": None},
        "tier": "public",
        "data_scope": data_scope,
    }
    asn = origin["asn"]
    known = Status(bgp_status) in (Status.AVAILABLE, Status.PARTIAL)
    if kind == "asn":
        summary = [
            f"{len(cp_routes)} retained BGP observations for {origin['prefix_count']} prefixes originated by AS{asn}.",
            f"{len(samples)} retained existing Atlas traceroute samples to specific addresses; no new measurements were scheduled.",
        ]
        report["traces"] = deepcopy(list(samples))
        for row in report["routing_context"]["adjacencies"]:
            row["interpretation"] = (
                "Observed immediately before the selected origin in BGP advertisements. "
                "Adjacency alone does not establish a provider relationship."
            )
        if not known:
            summary[0] = (
                "BGP evidence is " + bgp_status.replace("_", " ") + "; route and prefix counts are unknown."
            )
            report["meta"]["origin"]["prefix_count"] = None
    else:
        retained = report["traces"]
        reached = sum(1 for row in retained if row["reached_origin_as"])
        summary = [f"{len(cp_routes)} retained BGP observations end at the selected origin AS{asn}."]
        if retained:
            summary.append(
                f"{len(retained)} existing Atlas samples retained; {reached} contain a hop mapped to "
                f"AS{asn} using current prefix-origin data. This does not establish router ownership or reachability."
            )
        else:
            summary.append(
                "No traceroutes were retained; this view contains routing observations only. Check source warnings for missing coverage."
            )
        summary.append(
            "Routing context does not identify the path an observed connection took, confirm a service provider, "
            "or support an enforcement recommendation."
        )
        if not known:
            summary[0] = "BGP evidence is " + bgp_status.replace("_", " ") + "; route counts are unknown."
    if not known:
        report["control_plane"]["routes"] = None
        report["routing_context"]["calculations"]["bgp_fraction"]["denominator"] = None
        for row in report["routing_context"]["adjacencies"]:
            row.update(cp_routes=None, cp_share=None)
    report["summary"] = summary
    report["methodology"] = list(ASN_METHODOLOGY if kind == "asn" else METHODOLOGY)
    return report
