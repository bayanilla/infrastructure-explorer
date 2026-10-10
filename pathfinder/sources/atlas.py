"""Pathfinder sources atlas responsibilities."""

from __future__ import annotations

import collections
import ipaddress
import urllib.error
import urllib.parse
import urllib.request

from pathfinder import config
from pathfinder.clock import utc_now
from pathfinder.errors import ApiError
from pathfinder.sources.gateway import Http
from pathfinder.validation import is_public_ip, valid_timestamp

MSM_FIELDS = "id,type,target,target_ip,target_asn,start_time,status,description"


def atlas_discover(http: Http, job, warnings, *, target_ip=None, target_asn=None):
    """Recent public traceroute definitions matching exactly one filter."""
    q = {"type": "traceroute", "sort": "-start_time", "page_size": "10", "fields": MSM_FIELDS}
    if target_ip:
        q["target_ip"], scope = target_ip, "target"
    else:
        q["target_asn"], scope = str(target_asn), "origin_as"
    try:
        d = http.get_json(f"{config.ATLAS}/measurements/?{urllib.parse.urlencode(q)}", job=job)
    except ApiError as e:
        job.say(f"Atlas search ({scope}) unavailable: {e.detail}")
        warnings.append(
            f"Atlas search ({scope}) unavailable: {e.detail}. Retained sample counts do not establish absence."
        )
        return []
    return [m for m in (d.get("results") or []) if isinstance(m, dict)]


def atlas_definition(http: Http, msm_id: int, job) -> dict:
    return http.get_json(f"{config.ATLAS}/measurements/{msm_id}/?fields={MSM_FIELDS}", job=job)


def atlas_latest(http: Http, msm_id: int, job) -> list[dict]:
    d = http.get_json(f"{config.ATLAS}/measurements/{msm_id}/latest/?format=json", job=job)
    return d if isinstance(d, list) else []


def atlas_probe_meta(http: Http, ids, job) -> dict[int, dict]:
    out: dict[int, dict] = {}
    ids = sorted({i for i in ids if isinstance(i, int)})
    for i in range(0, len(ids), 200):
        chunk = ids[i : i + 200]
        q = urllib.parse.urlencode(
            {
                "id__in": ",".join(map(str, chunk)),
                "fields": "id,asn_v4,asn_v6,country_code",
                "page_size": "500",
            }
        )
        try:
            d = http.get_json(f"{config.ATLAS}/probes/?{q}", job=job)
        except ApiError as e:
            job.say(f"Probe metadata unavailable for {len(chunk)} probes: {e.detail}")
            continue
        for p in d.get("results") or []:
            if isinstance(p, dict) and isinstance(p.get("id"), int):
                out[p["id"]] = p
    return out


def parse_trace(res: dict) -> dict | None:
    if not isinstance(res, dict) or res.get("type", "traceroute") != "traceroute":
        return None
    hops = []
    for h in res.get("result") or []:
        if not isinstance(h, dict):
            continue
        replies = [r for r in (h.get("result") or []) if isinstance(r, dict)]
        ips = [r["from"] for r in replies if isinstance(r.get("from"), str)]
        rtts = [
            r["rtt"]
            for r in replies
            if isinstance(r.get("rtt"), (int, float)) and not isinstance(r.get("rtt"), bool)
        ]
        ip = collections.Counter(ips).most_common(1)[0][0] if ips else None
        hops.append({"hop": h.get("hop"), "ip": ip, "rtt": round(min(rtts), 1) if rtts else None})
    return {
        "msm_id": res.get("msm_id"),
        "probe_id": res.get("prb_id"),
        "src": res.get("from"),
        "dst": res.get("dst_addr"),
        "timestamp": res.get("timestamp"),
        "hops": hops,
    }


def _msm_id(definition) -> int | None:
    mid = definition.get("id") if isinstance(definition, dict) else None
    if isinstance(mid, int) and not isinstance(mid, bool) and 0 < mid < 10**9:
        return mid
    return None


def classify_definition(definition, *, target_ip=None, origin_asn=None) -> str | None:
    """Return 'target', 'origin_as', or None if the measurement doesn't belong to this analysis."""
    if not isinstance(definition, dict) or definition.get("type") != "traceroute":
        return None
    tip = definition.get("target_ip")
    if not is_public_ip(tip):
        return None
    if target_ip and ipaddress.ip_address(tip) == ipaddress.ip_address(target_ip):
        return "target"
    if origin_asn is not None and definition.get("target_asn") == origin_asn:
        return "origin_as"
    return None


def load_samples(http: Http, definitions: list[dict], job, warnings: list[str]):
    """Read results for already-validated definitions.

    Keeps only traceroutes whose destination equals the measurement's target and
    whose timestamp is well formed. Returns (traces, measurement_evidence).
    """
    traces: list[dict] = []
    evidence: list[dict] = []
    total = 0
    for definition in definitions:
        job.check()
        mid = definition["id"]
        try:
            raw_results = atlas_latest(http, mid, job)
        except ApiError as e:
            warnings.append(f"Measurement {mid} results unavailable: {e.detail}")
            continue
        job.say(f"Measurement {mid}: {len(raw_results)} results")
        total += len(raw_results)
        kept = wrong_dst = bad_ts = 0
        for raw in raw_results:
            parsed = parse_trace(raw)
            if parsed is None:
                continue
            if parsed["dst"] != definition["target_ip"]:
                wrong_dst += 1
                continue
            if not valid_timestamp(parsed["timestamp"]):
                bad_ts += 1
                continue
            if len(traces) >= config.MAX_TRACES:
                continue
            traces.append(parsed)
            kept += 1
        if wrong_dst:
            warnings.append(
                f"Measurement {mid}: {wrong_dst} result(s) with a destination other than {definition['target_ip']} were excluded."
            )
        if bad_ts:
            warnings.append(
                f"Measurement {mid}: {bad_ts} result(s) with an unsupported timestamp were excluded."
            )
        evidence.append(
            {
                "measurement_id": mid,
                "target_ip": definition["target_ip"],
                "target_asn": definition.get("target_asn"),
                "start_time": definition.get("start_time"),
                "scope": definition.get("_scope"),
                "results_returned": len(raw_results),
                "results_retained": kept,
                "url": f"{config.ATLAS}/measurements/{mid}/latest/?format=json",
                "retrieved_at": utc_now(),
            }
        )
    if total > config.MAX_TRACES and len(traces) >= config.MAX_TRACES:
        warnings.append(f"Atlas returned {total} results; at most {config.MAX_TRACES} samples are retained.")
    return traces, evidence


def select_definitions(http, job, warnings, *, supplied, target_ip, origin_asn):
    """Choose which Atlas measurements belong to this analysis.

    Supplied IDs are checked against their own definitions. Discovered ones are
    re-checked too, because a search filter is not proof of a match. Returns
    (definitions_tagged_with__scope, data_scope).
    """
    chosen: list[dict] = []
    if supplied:
        for mid in supplied:
            job.check()
            try:
                definition = atlas_definition(http, mid, job)
            except ApiError as e:
                warnings.append(f"Measurement {mid} metadata unavailable: {e.detail}")
                continue
            scope = classify_definition(definition, target_ip=target_ip, origin_asn=origin_asn)
            if scope is None or _msm_id(definition) != mid:
                shown = definition.get("target_ip") if isinstance(definition, dict) else None
                warnings.append(
                    f"Measurement {mid} was excluded: its target ({shown or 'unknown'}) or type "
                    f"could not be matched to {target_ip or f'AS{origin_asn}'}."
                )
                continue
            if scope == "origin_as" and target_ip:
                warnings.append(
                    f"Measurement {mid} targets {definition['target_ip']}, another address Atlas "
                    f"classifies under AS{origin_asn}. Its samples may not represent the requested target."
                )
            chosen.append({**definition, "_scope": scope})
        return chosen, "supplied"

    if target_ip:
        job.say("Searching public Atlas traceroutes to this address")
        rows = atlas_discover(http, job, warnings, target_ip=target_ip)
        chosen = [
            {**d, "_scope": "target"}
            for d in rows
            if classify_definition(d, target_ip=target_ip) == "target" and _msm_id(d)
        ][: config.MAX_DISCOVERED]
        if chosen:
            return chosen, "target"
    job.say(f"Searching public Atlas traceroutes classified under AS{origin_asn}")
    rows = atlas_discover(http, job, warnings, target_asn=origin_asn)
    tagged = [
        {**d, "_scope": classify_definition(d, target_ip=target_ip, origin_asn=origin_asn)}
        for d in rows
        if _msm_id(d)
    ]
    in_target = [d for d in tagged if d["_scope"] == "target"]
    if in_target:
        return in_target[: config.MAX_DISCOVERED], "target"
    in_origin = [d for d in tagged if d["_scope"] == "origin_as"][: config.MAX_DISCOVERED]
    if len(tagged) > len([d for d in tagged if d["_scope"]]):
        warnings.append(
            "Some Atlas search results were excluded because their target or type did not match the search."
        )
    return in_origin, ("origin_as" if in_origin else None)
