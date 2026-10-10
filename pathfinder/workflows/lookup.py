"""IP and ASN workflows: gather public evidence and build reports."""

from __future__ import annotations

import collections
import ipaddress

from pathfinder import config
from pathfinder.analysis.routes import other_origins, select_as_routes
from pathfinder.clock import utc_now
from pathfinder.errors import ApiError, UserError
from pathfinder.jobs import Job, _guarded
from pathfinder.model import thaw
from pathfinder.reports.lookup import build_lookup_report
from pathfinder.reports.wording import ASN_METHODOLOGY, exclusion_warning
from pathfinder.sources.atlas import atlas_probe_meta, load_samples, select_definitions
from pathfinder.sources.gateway import Http
from pathfinder.sources.stat import as_name, network_info, not_requested_bgp, read_bgp_evidence
from pathfinder.validation import is_public_ip


def fill_names(obj, names: dict[int, str]) -> None:
    if isinstance(obj, dict):
        if "asn" in obj and "name" in obj and isinstance(obj["asn"], int):
            obj["name"] = names.get(obj["asn"])
        for v in obj.values():
            fill_names(v, names)
    elif isinstance(obj, list):
        for v in obj:
            fill_names(v, names)


def name_networks(http, job, result, wanted: list[int]) -> None:
    order = [a for a in dict.fromkeys(wanted) if isinstance(a, int)]
    if len(order) > config.MAX_NAME_LOOKUPS:
        result["warnings"].append(
            f"Organization names were looked up for the first {config.MAX_NAME_LOOKUPS} of {len(order)} networks."
        )
    names: dict[int, str] = {}
    for i, a in enumerate(order[: config.MAX_NAME_LOOKUPS], 1):
        job.check()
        job.set_progress(f"Naming networks ({i} of {min(len(order), config.MAX_NAME_LOOKUPS)}): AS{a}")
        n = as_name(http, a, job)
        if n:
            names[a] = n
    fill_names(result, names)


def run_asn_job(job, params, http):
    """Read AS-scoped public evidence without selecting or probing an IP."""
    asn = params["target_asn"]
    resource = f"AS{asn}"
    warnings: list[str] = []
    selected, excluded = [], {}
    bgp = not_requested_bgp(resource)
    source = bgp.source_record()
    if params["control_plane"]:
        job.say(f"Reading observed BGP routes for {resource}")
        bgp = read_bgp_evidence(http, resource, job, warnings)
        source = bgp.source_record()
        if bgp.usable:
            selected, excluded = thaw(bgp.map(lambda rows: select_as_routes(rows, asn)).value)
            if excluded:
                warnings.append(exclusion_warning(excluded))

    # Existing Atlas results are address-specific samples, not an AS-wide measured path.
    definitions, _ = select_definitions(
        http, job, warnings, supplied=params["measurement_ids"], target_ip=None, origin_asn=asn
    )
    samples, measurement_evidence = load_samples(http, definitions, job, warnings)
    for parsed in samples:
        parsed.update(
            probe_asn=None,
            probe_country=None,
            as_path=[],
            mapping_status="not_performed",
            reached_origin_as=None,
            entry_asn=None,
            reached_target=any(h["ip"] == parsed["dst"] for h in parsed["hops"]),
        )
        parsed["hops"] = [{**h, "asn": None, "scope": None} for h in parsed["hops"]]

    prefixes = sorted({r["target_prefix"] for r in selected})
    origin = {
        "asn": asn,
        "all_asns": [asn],
        "prefix": None,
        "prefixes": prefixes[: config.MAX_AS_PREFIXES],
        "prefix_count": len(prefixes),
        "prefixes_truncated": len(prefixes) > config.MAX_AS_PREFIXES,
    }
    result = build_lookup_report(
        target_input=params["target_input"],
        target_ip=None,
        origin=origin,
        traces=[],
        probe_meta={},
        ipmap={},
        cp_routes=selected,
        warnings=warnings,
        kind="asn",
        bgp_status=source["status"],
        samples=samples,
        generated_utc=utc_now(),
        data_scope="asn_samples" if samples else None,
    )
    result["meta"].update(
        target_kind="asn",
        target_resource=resource,
        target_asn=asn,
        measurement_ids=[e["measurement_id"] for e in measurement_evidence],
    )
    result["control_plane"].update(
        source=source,
        excluded_records=excluded,
        other_origins=[],
        distinct_peers=len({r["source_id"] for r in selected})
        if source["status"] in ("available", "partial")
        else None,
    )
    result["measurement_evidence"] = measurement_evidence
    if result["control_plane"]["truncated"]:
        result["warnings"].append(
            f"Exports retain the first {len(result['control_plane']['paths'])} of {len(selected)} "
            "processed BGP path records; summaries and graph counts use all processed records."
        )
    if len(prefixes) > config.MAX_AS_PREFIXES:
        result["warnings"].append(
            f"The prefix list is limited to {config.MAX_AS_PREFIXES} of {len(prefixes)} observed prefixes."
        )
    result["methodology"] = ASN_METHODOLOGY
    name_networks(
        http,
        job,
        result,
        [asn]
        + [e["asn"] for e in result["routing_context"]["adjacencies"]]
        + [n["asn"] for n in result["graph"]["nodes"]],
    )
    result["meta"]["requests"] = job.requests
    job.result = result
    job.say("Done")


def run_ip_job(job, params, http):
    warnings: list[str] = []
    tip = params["target_ip"]
    job.say(f"Looking up the AS that announces {tip}")
    info = network_info(http, tip, job)
    if not info["asns"]:
        raise UserError(
            f"No AS currently announces a prefix covering {tip}, per RIPEstat. "
            "Check the address, or whether the prefix is withdrawn."
        )
    origin_asn = info["asns"][0]
    if len(info["asns"]) > 1:
        warnings.append(
            f"{info['prefix']} is announced by several ASes ({', '.join('AS%d' % a for a in info['asns'])}). "
            f"This run treats AS{origin_asn} as the selected origin."
        )
    origin = {"asn": origin_asn, "all_asns": info["asns"], "prefix": info["prefix"]}
    job.say(f"Origin AS{origin_asn}, prefix {info['prefix']}")
    resource = info["prefix"] or tip  # BGP observations for the covering prefix

    # Existing Atlas samples, validated against their own definitions.
    definitions, data_scope = select_definitions(
        http, job, warnings, supplied=params["measurement_ids"], target_ip=tip, origin_asn=origin_asn
    )
    if data_scope == "origin_as":
        warnings.append(
            f"No public traceroutes target {tip}. Using traceroutes to other addresses Atlas classifies "
            f"under AS{origin_asn}; samples may not represent the requested target."
        )
    elif data_scope is None:
        warnings.append(
            "No public Atlas traceroutes were found for this target or its AS. Supply existing "
            "measurement IDs. No new measurements are scheduled."
        )
    traces, measurement_evidence = load_samples(http, definitions, job, warnings)
    probe_meta = atlas_probe_meta(http, {t["probe_id"] for t in traces}, job) if traces else {}

    # Hop enrichment, most frequent first, reusing resolved prefixes within this run.
    freq = collections.Counter(h["ip"] for t in traces for h in t["hops"] if is_public_ip(h["ip"]))
    ipmap: dict[str, dict] = {}
    known: list[tuple] = []
    if info["prefix"]:
        try:
            known.append((ipaddress.ip_network(info["prefix"]), info["asns"]))
        except ValueError:
            pass
    lookups = skipped = 0
    ordered = [ip for ip, _ in freq.most_common()]
    for i, ip in enumerate(ordered, 1):
        addr = ipaddress.ip_address(ip)
        hit = next((k for k in known if k[0].version == addr.version and addr in k[0]), None)
        if hit:
            ipmap[ip] = {"asn": hit[1][0] if hit[1] else None}
            continue
        if lookups >= config.MAX_HOP_LOOKUPS:
            skipped += 1
            continue
        job.set_progress(f"Mapping hop addresses to networks ({i} of {len(ordered)})")
        try:
            ni = network_info(http, ip, job)
        except ApiError:
            continue
        lookups += 1
        ipmap[ip] = {"asn": ni["asns"][0] if ni["asns"] else None}
        if ni["prefix"]:
            try:
                known.append((ipaddress.ip_network(ni["prefix"]), ni["asns"]))
            except ValueError:
                pass
    if ordered:
        job.say(f"Mapped {len(ipmap)} hop addresses with {lookups} RIPEstat lookups")
    if skipped:
        warnings.append(
            f"{skipped} rarely seen hop addresses were left unmapped to stay within request limits."
        )

    # BGP: keep successful absence separate from failed or unrequested evidence.
    cp_routes, excluded, others = [], {}, []
    bgp = not_requested_bgp(resource)
    cp_source = bgp.source_record()
    if params["control_plane"]:
        job.say(f"Reading BGP observations for {resource}")
        bgp = read_bgp_evidence(http, resource, job, warnings)
        cp_source = bgp.source_record()
        raw_routes = thaw(bgp.value) if bgp.usable else []
        if bgp.usable:
            cp_routes, excluded = select_as_routes(raw_routes, origin_asn)
            others = other_origins(raw_routes, origin_asn)
            if excluded:
                warnings.append(exclusion_warning(excluded))
            if others:
                shown = "; ".join(
                    f"AS{o['asn']} for {o['prefix']} ({o['peers']} peer{'s' if o['peers'] != 1 else ''})"
                    for o in others[:5]
                )
                more = f"; {len(others) - 5} more in the export" if len(others) > 5 else ""
                warnings.append(
                    f"BGP records within {resource} end at other origin ASes: {shown}{more}. "
                    "Review whether these are expected."
                )

    job.say("Analyzing paths")
    result = build_lookup_report(
        target_input=params["target_input"],
        target_ip=tip,
        origin=origin,
        traces=traces,
        probe_meta=probe_meta,
        ipmap=ipmap,
        cp_routes=cp_routes,
        warnings=warnings,
        kind="ip",
        bgp_status=cp_source["status"],
        generated_utc=utc_now(),
        data_scope=data_scope,
    )

    result["meta"].update(
        target_kind="ip",
        target_resource=tip,
        evidence_resource=resource,
        measurement_ids=[e["measurement_id"] for e in measurement_evidence],
    )
    result["control_plane"].update(
        source=cp_source,
        excluded_records=excluded,
        other_origins=others[: config.MAX_OTHER_ORIGINS],
        other_origins_truncated=len(others) > config.MAX_OTHER_ORIGINS,
        distinct_peers=len({row["source_id"] for row in cp_routes})
        if cp_source["status"] in ("available", "partial")
        else None,
    )
    result["measurement_evidence"] = measurement_evidence
    if result["control_plane"]["truncated"]:
        result["warnings"].append(
            f"Exports retain {len(result['control_plane']['paths'])} of {len(cp_routes)} processed "
            "BGP path records; summary counts use all processed records."
        )

    wanted = [origin_asn] + [e["asn"] for e in result["routing_context"]["adjacencies"]]
    wanted += [o["asn"] for o in others[: config.MAX_OTHER_ORIGINS]]
    wanted += [n["asn"] for n in sorted(result["graph"]["nodes"], key=lambda n: -(n["data"] * 4 + n["cp"]))]
    wanted += [v["asn"] for v in result["vantage"] if v["asn"]]
    name_networks(http, job, result, wanted)
    result["meta"]["requests"] = job.requests
    job.result = result
    job.say("Done")


def run_job(job: Job, params: dict, http: Http) -> None:
    def work():
        if params["tier"] != "public":
            raise UserError("Only passive public-data analysis is supported.")
        job.check()
        if params.get("target_asn"):
            run_asn_job(job, params, http)
        else:
            run_ip_job(job, params, http)

    _guarded(job, work)
