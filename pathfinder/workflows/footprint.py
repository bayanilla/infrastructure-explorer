"""Footprint resolution and analyst-confirmed adjacency workflows."""

from __future__ import annotations

import collections
import copy
import ipaddress
import re

from pathfinder import config
from pathfinder.analysis.footprint import aggregate_neighbors, covering_is_reusable
from pathfinder.clock import utc_now
from pathfinder.errors import ApiError, UserError
from pathfinder.jobs import STORE
from pathfinder.reports.footprint import build_footprint_run, build_resolution
from pathfinder.sources.stat import _overview, as_name, read_neighbors, stat_url
from pathfinder.validation import _ASN_TOKEN, public_asn

_THRESHOLD = re.compile(r"min peers:\s*(\d+)", re.I)


class _LookupBudget(Exception):
    pass


class Resolver:
    """A bounded resolution run. Reuse knowledge and source captures belong to this run."""

    def __init__(self, http, job, entries, min_peers, warnings):
        self.http, self.job = http, job
        self.entries, self.min_peers, self.warnings = entries, min_peers, warnings
        self.nets = [ipaddress.ip_network(e["value"]) for e in self.entries]
        self.order = sorted(
            range(len(self.entries)),
            key=lambda i: (self.nets[i].version, int(self.nets[i].network_address), self.nets[i].prefixlen),
        )
        self.results: list = [None] * len(self.entries)
        self.known: list[dict] = []
        self.learned: set[str] = set()
        self.stats = {
            "lookups": 0,
            "reused": 0,
            "filtered_routes": 0,
            "lookups_with_filtering": 0,
            "query_times": set(),
            "messages": collections.Counter(),
            "thresholds": set(),
        }

    def lookup(self, resource: str):
        if self.stats["lookups"] >= config.MAX_RESOLVE_LOOKUPS:
            raise _LookupBudget()
        self.stats["lookups"] += 1
        q = {"resource": resource}
        if self.min_peers is not None:
            q["min_peers_seeing"] = str(self.min_peers)
        ov = _overview(self.http.get_json(stat_url("prefix-overview", **q), job=self.job))
        if ov["query_time"]:
            self.stats["query_times"].add(ov["query_time"])
        for m in ov["messages"]:
            match = _THRESHOLD.search(m)
            if match:
                self.stats["thresholds"].add(int(match.group(1)))
            self.stats["messages"][re.sub(r"\d+", "N", m)] += 1
        if ov["filtered"]:
            self.stats["filtered_routes"] += ov["filtered"]
            self.stats["lookups_with_filtering"] += 1
        return ov

    def learn(self, ov):
        res = ov["resource"]
        if (
            ov["announced"]
            and ov["asns"]
            and res is not None
            and not ov["less_specific"]
            and str(res) not in self.learned
        ):
            self.learned.add(str(res))
            self.known.append(
                {
                    "net": res,
                    "asns": ov["asns"],
                    "more_specifics": [
                        r for r in ov["related"] if r.version == res.version and r != res and r.subnet_of(res)
                    ],
                    "complete": ov["related_total"] <= len(ov["related"]),
                }
            )

    def resolve_part(self, prefix):
        k = self.reusable(prefix)
        if k is not None:
            self.stats["reused"] += 1
            return {
                "prefix": str(prefix),
                "covering_prefix": str(k["net"]),
                "origins": k["asns"],
                "method": "reused",
            }
        ov = self.lookup(str(prefix))
        self.learn(ov)
        if ov["announced"] and ov["asns"]:
            return {
                "prefix": str(prefix),
                "covering_prefix": str(ov["resource"]),
                "origins": ov["asns"],
                "method": "queried",
            }
        return {"prefix": str(prefix), "covering_prefix": None, "origins": [], "method": "queried"}

    def reusable(self, net):
        return next((k for k in self.known if covering_is_reusable(net, k)), None)

    def resolve(self):
        budget_hit = 0
        for pos, i in enumerate(self.order, 1):
            self.job.check()
            e, net = self.entries[i], self.nets[i]
            self.job.set_progress(
                f"Resolving {pos} of {len(self.entries)} · {self.stats['lookups']} RIPE lookups so far"
            )
            base = {
                "input": e["value"],
                "kind": e["kind"],
                "line": e.get("line"),
                "covering_prefix": None,
                "origins": [],
                "more_specifics": [],
                "more_specifics_total": 0,
                "more_specifics_truncated": False,
                "method": None,
                "filtered_routes": 0,
                "error": None,
            }
            k = self.reusable(net)
            if k is not None:
                self.stats["reused"] += 1
                self.results[i] = {
                    **base,
                    "status": "announced",
                    "covering_prefix": str(k["net"]),
                    "origins": k["asns"],
                    "method": "reused",
                }
                continue
            try:
                ov = self.lookup(e["value"])
            except _LookupBudget:
                budget_hit += 1
                self.results[i] = {**base, "status": "not_resolved"}
                continue
            except (ApiError, UserError) as err:
                self.results[i] = {
                    **base,
                    "status": "lookup_failed",
                    "error": str(getattr(err, "detail", err))[:300],
                }
                continue
            self.learn(ov)
            row = {**base, "method": "queried", "filtered_routes": ov["filtered"]}
            if ov["announced"] and ov["asns"]:
                row.update(
                    status="announced",
                    covering_prefix=str(ov["resource"]) if ov["resource"] else None,
                    origins=ov["asns"],
                )
            else:
                row.update(status="not_announced")
            if e["kind"] == "prefix":
                parts = [
                    r for r in ov["related"] if r.version == net.version and r != net and r.subnet_of(net)
                ]
                row["more_specifics_total"] = len(parts)
                row["more_specifics_truncated"] = (
                    ov["related_total"] > len(ov["related"]) or len(parts) > config.MAX_RANGE_EXPANSION
                )
                for part in parts[: config.MAX_RANGE_EXPANSION]:
                    self.job.check()
                    try:
                        row["more_specifics"].append(self.resolve_part(part))
                    except _LookupBudget:
                        row["more_specifics_truncated"] = True
                        budget_hit += 1
                        break
                    except (ApiError, UserError) as err:
                        row["more_specifics"].append(
                            {
                                "prefix": str(part),
                                "covering_prefix": None,
                                "origins": [],
                                "method": "queried",
                                "error": str(getattr(err, "detail", err))[:300],
                            }
                        )
                if row["status"] == "not_announced" and any(p["origins"] for p in row["more_specifics"]):
                    row["status"] = "partially_announced"
            self.results[i] = row
            # Read a covering prefix directly when it will serve at least two more self.entries.
            cov = ov["resource"] if ov["announced"] and ov["less_specific"] else None
            if cov is not None and str(cov) not in self.learned:
                pending = sum(
                    1
                    for j in self.order[pos:]
                    if self.nets[j].version == cov.version and self.nets[j].subnet_of(cov)
                )
                if pending >= 2:
                    try:
                        self.learn(self.lookup(str(cov)))
                    except (_LookupBudget, ApiError, UserError):
                        pass
        if budget_hit:
            self.warnings.append(
                f"The run reached its limit of {config.MAX_RESOLVE_LOOKUPS} RIPE lookups. {budget_hit} entr"
                f"{'y was' if budget_hit == 1 else 'ies were'} not fully resolved; split the file to resolve the rest."
            )
        return self.results, self.stats


def resolve_footprint(http, job, entries, min_peers, warnings):
    return Resolver(http, job, entries, min_peers, warnings).resolve()


def run_footprint_resolution(job, params, http):
    parsed, keywords = params["parsed"], params["keywords"]
    min_peers = 1 if params["include_low_visibility"] else None
    entries = parsed["entries"]
    warnings: list[str] = []
    job.say(
        f"{parsed['accepted']} entries accepted, {parsed['duplicates']} duplicates removed, "
        f"{parsed['rejected_total']} rows rejected"
    )
    results, stats = resolve_footprint(http, job, entries, min_peers, warnings)
    job.result = build_resolution(
        parsed=parsed,
        keywords=keywords,
        include_low_visibility=params["include_low_visibility"],
        results=results,
        stats=stats,
        warnings=warnings,
        generated_utc=utc_now(),
        job_id=job.id,
        requests=job.requests,
    )
    origins = job.result["origins"]
    job.say(
        f"Resolved to {len(origins)} origin ASNs with {stats['lookups']} lookups ({stats['reused']} reused)"
    )


def validate_adjacency_request(body) -> dict:
    if not isinstance(body, dict):
        raise UserError("Request body must be a JSON object.")
    jid = body.get("resolution_job")
    if not isinstance(jid, str) or not re.fullmatch(r"[0-9a-f]{32}", jid):
        raise UserError("Missing resolution reference. Resolve the footprint again.")
    job = STORE.get(jid)
    if (
        job is None
        or job.status != "done"
        or not isinstance(job.result, dict)
        or job.result.get("kind") != "footprint_resolution"
    ):
        raise UserError("That resolution has expired or didn't finish. Upload the file again to resolve it.")
    available = {o["asn"] for o in job.result["origins"]}
    raw = body.get("asns")
    if not isinstance(raw, list) or not raw:
        raise UserError("Select at least one origin ASN as yours.")
    asns = []
    for a in raw:
        m = (
            _ASN_TOKEN.fullmatch(str(a).strip())
            if isinstance(a, (str, int)) and not isinstance(a, bool)
            else None
        )
        if not m or int(m.group(1)) not in available:
            raise UserError(f"{str(a)[:20]} isn't one of the origin ASNs in this resolution.")
        if int(m.group(1)) not in asns:
            asns.append(int(m.group(1)))
    if len(asns) > config.MAX_CONFIRMED_ASNS:
        raise UserError(f"Select at most {config.MAX_CONFIRMED_ASNS} ASNs per run.")
    return {"resolution": copy.deepcopy(job.result), "asns": asns}


def run_footprint_adjacency(job, params, http):
    resolution, confirmed = params["resolution"], params["asns"]
    holders = {o["asn"]: o["holder"] for o in resolution["origins"]}
    per_asn, warnings = [], list(resolution["warnings"])
    for i, asn in enumerate(confirmed, 1):
        job.check()
        job.say(f"Reading observed neighbors for AS{asn} ({i} of {len(confirmed)})")
        got = read_neighbors(http, asn, job)
        per_asn.append({"asn": asn, "holder": holders.get(asn), **got})
        if got["source"]["status"] != "available":
            warnings.append(
                f"Neighbor data for AS{asn} is unavailable ({got['source'].get('error') or 'no detail'}). "
                "Its neighbors are unknown, not absent."
            )
        if got["source"]["excluded"]:
            warnings.append(
                f"{got['source']['excluded']} malformed neighbor record(s) for AS{asn} were excluded."
            )
        if got["source"]["truncated"]:
            warnings.append(
                f"AS{asn} has more than {config.MAX_NEIGHBORS_PER_ASN} neighbors; the record keeps the first "
                f"{config.MAX_NEIGHBORS_PER_ASN} by ASN."
            )
    neighbors = aggregate_neighbors(per_asn, set(confirmed))
    names = {a: h for a, h in holders.items() if h}
    wanted = [n["asn"] for n in neighbors if n["asn"] not in names and public_asn(n["asn"])]
    if len(wanted) > config.MAX_FOOTPRINT_NAMES:
        warnings.append(
            f"Holder names were looked up for {config.MAX_FOOTPRINT_NAMES} of {len(wanted)} neighbors, in table "
            "order; the rest show the ASN only."
        )
    for i, a in enumerate(wanted[: config.MAX_FOOTPRINT_NAMES], 1):
        job.check()
        job.set_progress(f"Naming neighbors ({i} of {min(len(wanted), config.MAX_FOOTPRINT_NAMES)}): AS{a}")
        name = as_name(http, a, job)
        if name:
            names[a] = name
    for n in neighbors:
        n["name"] = names.get(n["asn"])
    job.result = build_footprint_run(
        resolution=resolution,
        confirmed=confirmed,
        per_asn=per_asn,
        neighbors=neighbors,
        warnings=warnings,
        generated_utc=utc_now(),
        requests=job.requests,
    )
    job.say("Done")
