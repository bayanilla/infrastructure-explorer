"""Pathfinder sources stat responsibilities."""

from __future__ import annotations

import ipaddress
import urllib.error
import urllib.parse
import urllib.request

from pathfinder import config
from pathfinder.clock import utc_now
from pathfinder.errors import ApiError, UserError
from pathfinder.model import Coverage, Evidence, Source, Status, thaw
from pathfinder.sources.gateway import Http


def stat_url(endpoint: str, **q) -> str:
    q["sourceapp"] = config.SOURCEAPP
    return f"{config.STAT}/{endpoint}/data.json?{urllib.parse.urlencode(q)}"


def network_info(http: Http, ip: str, job) -> dict:
    d = http.get_json(stat_url("network-info", resource=ip), job=job)
    data = d.get("data") or {}
    asns = []
    for a in data.get("asns") or []:
        try:
            asns.append(int(a))
        except (TypeError, ValueError):
            pass
    return {"asns": asns, "prefix": data.get("prefix")}


def as_name(http: Http, asn: int, job) -> str | None:
    try:
        d = http.get_json(stat_url("as-overview", resource=f"AS{asn}"), job=job)
    except ApiError:
        return None
    return (d.get("data") or {}).get("holder") or None


def not_requested_bgp(resource):
    source = Source(
        "RIPE RIS via RIPEstat", stat_url("bgp-state", resource=resource), (("resource", resource),)
    )
    return Evidence(Status.NOT_REQUESTED, source)


def read_bgp_evidence(http, resource, job, warnings):
    """Capture a typed BGP snapshot; failed evidence cannot masquerade as zero routes."""
    pending = not_requested_bgp(resource)
    try:
        response = http.get_json(pending.source.url, job=job)
        data = response.get("data") if isinstance(response, dict) else None
        if not isinstance(data, dict) or not isinstance(data.get("bgp_state"), list):
            raise UserError("RIPE returned an unsupported BGP response.")
        rows = data["bgp_state"]
        reported = data.get("nr_routes")
        reported = reported if type(reported) is int and reported >= 0 else None
        partial = len(rows) > config.MAX_AS_ROUTES or (reported is not None and reported > len(rows))
        note = "BGP results are incomplete or exceed the route limit; summaries cover processed records only."
        if partial:
            warnings.append(note)
        times = getattr(job, "fetch_times", {})
        source = Source(
            pending.source.name,
            pending.source.url,
            pending.source.parameters,
            observed_at=data.get("query_time"),
            retrieved_at=times.get(pending.source.url) or utc_now(),
        )
        return Evidence(
            Status.PARTIAL if partial else Status.AVAILABLE,
            source,
            rows,
            Coverage(len(rows), reported, config.MAX_AS_ROUTES, note if partial else None),
        )
    except (ApiError, UserError) as err:
        warnings.append(f"BGP evidence unavailable: {err}")
        source = Source(pending.source.name, pending.source.url, pending.source.parameters, error=str(err))
        return Evidence(Status.UNAVAILABLE, source)


def read_bgp_state(http, resource, job, warnings):
    """Compatibility adapter for the prior local API."""
    evidence = read_bgp_evidence(http, resource, job, warnings)
    return (thaw(evidence.value) if evidence.usable else []), evidence.source_record()


def _overview(resp) -> dict:
    data = resp.get("data") if isinstance(resp, dict) else None
    if not isinstance(data, dict):
        raise UserError("RIPE returned an unsupported prefix-overview response.")
    asns = []
    for a in data.get("asns") or []:
        if isinstance(a, dict) and isinstance(a.get("asn"), int) and not isinstance(a.get("asn"), bool):
            asns.append(
                {"asn": a["asn"], "holder": a["holder"] if isinstance(a.get("holder"), str) else None}
            )
    try:
        resource = ipaddress.ip_network(data.get("resource"), strict=False)
    except (TypeError, ValueError):
        resource = None
    related = []
    for r in data.get("related_prefixes") or []:
        p = r if isinstance(r, str) else (r.get("prefix") if isinstance(r, dict) else None)
        try:
            related.append(ipaddress.ip_network(p, strict=False))
        except (TypeError, ValueError):
            continue
    total = data.get("actual_num_related")
    total = total if isinstance(total, int) and not isinstance(total, bool) else len(related)
    filtered = data.get("num_filtered_out")
    messages = []
    for m in resp.get("messages") or []:
        if isinstance(m, (list, tuple)) and len(m) == 2 and isinstance(m[1], str):
            messages.append(m[1][:300])
    return {
        "announced": data.get("announced") is True,
        "asns": asns,
        "resource": resource,
        "less_specific": data.get("is_less_specific") is True,
        "related": related,
        "related_total": max(total, len(related)),
        "filtered": filtered if isinstance(filtered, int) and not isinstance(filtered, bool) else 0,
        "query_time": data.get("query_time") if isinstance(data.get("query_time"), str) else None,
        "messages": messages,
    }


def _count(v) -> bool:
    return isinstance(v, int) and not isinstance(v, bool) and v >= 0


def read_neighbors(http, asn, job) -> dict:
    url = stat_url("asn-neighbours", resource=f"AS{asn}")
    source = {
        "name": "RIPEstat ASN Neighbors",
        "url": url,
        "status": "unavailable",
        "retrieved_at": None,
        "query_starttime": None,
        "query_endtime": None,
        "latest_time": None,
        "version": None,
        "messages": [],
        "neighbor_counts": None,
        "excluded": 0,
        "truncated": False,
    }
    try:
        resp = http.get_json(url, job=job)
    except ApiError as e:
        source["error"] = e.detail
        return {"source": source, "neighbors": []}
    data = resp.get("data") if isinstance(resp, dict) else None
    # RIPE's response schema uses British spelling. Normalize it at this adapter
    # boundary so Pathfinder's own report model consistently uses “neighbors”.
    if not isinstance(data, dict) or not isinstance(data.get("neighbours"), list):
        source["error"] = "Unsupported response."
        return {"source": source, "neighbors": []}
    out = []
    for n in data["neighbours"]:
        if (
            isinstance(n, dict)
            and _count(n.get("asn"))
            and 1 <= n["asn"] <= 4294967295
            and n.get("type") in ("left", "right", "uncertain")
            and all(_count(n.get(k)) for k in ("power", "v4_peers", "v6_peers"))
        ):
            out.append(
                {
                    "asn": n["asn"],
                    "type": n["type"],
                    "power": n["power"],
                    "v4_peers": n["v4_peers"],
                    "v6_peers": n["v6_peers"],
                }
            )
        else:
            source["excluded"] += 1
    source.update(
        status="available",
        retrieved_at=utc_now(),
        version=resp.get("version"),
        query_starttime=data.get("query_starttime"),
        query_endtime=data.get("query_endtime"),
        latest_time=data.get("latest_time"),
        neighbor_counts=data.get("neighbour_counts")
        if isinstance(data.get("neighbour_counts"), dict)
        else None,
        messages=[
            m[1][:300]
            for m in resp.get("messages") or []
            if isinstance(m, (list, tuple)) and len(m) == 2 and isinstance(m[1], str)
        ],
    )
    if len(out) > config.MAX_NEIGHBORS_PER_ASN:
        source["truncated"] = True
        out = out[: config.MAX_NEIGHBORS_PER_ASN]
    out.sort(key=lambda n: (n["asn"], n["type"]))
    return {"source": source, "neighbors": out}
