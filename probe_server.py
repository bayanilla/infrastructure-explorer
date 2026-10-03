#!/usr/bin/env python3
"""
Múcaro | Routing Exposure Probe

Passive infrastructure context from RIPEstat BGP observations and existing RIPE
Atlas samples. IP/prefix lookup is primary; ASN exploration is broader context.
No active measurement scheduling, provider attribution, or enforcement advice.

Standard library only. Python 3.10+.

    python3 probe_server.py              # http://127.0.0.1:8767
    python3 probe_server.py --port 8768

Investigation inputs remain local except for public-data lookups sent to RIPE.
API keys and active measurements are not accepted.
"""
from __future__ import annotations

import argparse
import collections
import ipaddress
import json
import re
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

VERSION = "0.2.0"
SOURCEAPP = "mucaro-exposure-probe"
USER_AGENT = f"mucaro-exposure-probe/{VERSION} (+https://github.com/bayanilla/bgp-routing-exposure-lookup)"
ATLAS = "https://atlas.ripe.net/api/v2"
STAT = "https://stat.ripe.net/data"

DEFAULT_PORT = 8767
MAX_RESPONSE_BYTES = 32 * 1024 * 1024
MAX_BODY_BYTES = 64 * 1024
MAX_HOP_LOOKUPS = 250          # uncached RIPEstat network-info calls per run
MAX_TRACES = 400
MAX_NAME_LOOKUPS = 120
MAX_GRAPH_NODES = 80
MAX_CP_PATHS_KEPT = 400
MAX_AS_ROUTES = 20000
MAX_AS_PREFIXES = 4000
JOB_TTL_SECONDS = 3600
MAX_JOBS = 30
ATLAS_AREAS = {"WW", "West", "North-Central", "South-Central", "North-East", "South-East"}

def public_asn(n: int) -> bool:
    return (
        0 < n <= 4294967295
        and n != 23456
        and not (64496 <= n <= 131071)
        and not (n >= 4200000000)
    )


def is_public_ip(ip: str | None) -> bool:
    if not ip:
        return False
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


# --- Errors ---------------------------------------------------------------------
class UserError(Exception):
    """Input or condition the analyst can fix. Message is shown verbatim."""


class ApiError(Exception):
    def __init__(self, status: int, detail: str, url: str):
        super().__init__(f"{status}: {detail}")
        self.status = status
        self.detail = detail
        self.url = url


class Cancelled(Exception):
    pass


# --- Paced HTTP -----------------------------------------------------------------
class Http:
    """One request at a time with a pause between them, shared by every job."""

    def __init__(self, pause: float):
        self.pause = pause
        self._lock = threading.Lock()
        self._last = 0.0
        self._cache: dict[str, object] = {}
        self._cache_lock = threading.Lock()
        self.count = 0

    def get_json(self, url, headers=None, cache=True, job=None, timeout=45):
        if cache:
            with self._cache_lock:
                if url in self._cache:
                    return self._cache[url]
        data = self._request(url, None, headers, job, timeout)
        if cache:
            with self._cache_lock:
                self._cache[url] = data
        return data

    def post_json(self, url, body, headers=None, job=None, timeout=45):
        h = {"Content-Type": "application/json", **(headers or {})}
        return self._request(url, json.dumps(body).encode(), h, job, timeout)

    def _request(self, url, body, headers, job, timeout):
        attempts = 3
        for attempt in range(attempts):
            retry_after = None
            with self._lock:
                if job:
                    job.check()
                wait = self.pause - (time.monotonic() - self._last)
                if wait > 0:
                    time.sleep(wait)
                req = urllib.request.Request(
                    url,
                    data=body,
                    method="POST" if body is not None else "GET",
                    headers={"User-Agent": USER_AGENT, "Accept": "application/json", **(headers or {})},
                )
                try:
                    with urllib.request.urlopen(req, timeout=timeout) as resp:
                        raw = resp.read(MAX_RESPONSE_BYTES + 1)
                    self._last = time.monotonic()
                    self.count += 1
                    if len(raw) > MAX_RESPONSE_BYTES:
                        raise ApiError(0, "response exceeded the size limit", _redact(url))
                    return json.loads(raw.decode("utf-8")) if raw else {}
                except urllib.error.HTTPError as e:
                    self._last = time.monotonic()
                    self.count += 1
                    detail = _error_detail(e)
                    if e.code in (429, 500, 502, 503, 504) and attempt < attempts - 1:
                        retry_after = 4 * (attempt + 1)
                    else:
                        raise ApiError(e.code, detail, _redact(url)) from None
                except (urllib.error.URLError, TimeoutError, ConnectionError) as e:
                    self._last = time.monotonic()
                    if attempt < attempts - 1:
                        retry_after = 3 * (attempt + 1)
                    else:
                        reason = getattr(e, "reason", e)
                        raise ApiError(0, f"network error: {reason}", _redact(url)) from None
            if retry_after:
                _sleep_checked(retry_after, job)
        raise ApiError(0, "retries exhausted", _redact(url))


def _redact(url: str) -> str:
    return url.split("?", 1)[0]


def _error_detail(e: urllib.error.HTTPError) -> str:
    try:
        body = json.loads(e.read(65536).decode("utf-8", "replace"))
    except Exception:
        return e.reason or "HTTP error"
    err = body.get("error") if isinstance(body, dict) else None
    if isinstance(err, dict):
        parts = [err.get("detail") or err.get("title") or ""]
        for sub in err.get("errors") or []:
            if isinstance(sub, dict):
                src = (sub.get("source") or {}).get("pointer", "")
                parts.append(f"{src} {sub.get('detail', '')}".strip())
        text = "; ".join(p for p in parts if p)
        if text:
            return text[:400]
    if isinstance(body, dict) and body.get("messages"):
        return str(body["messages"])[:400]
    return e.reason or "HTTP error"


def _sleep_checked(seconds: float, job) -> None:
    end = time.monotonic() + seconds
    while True:
        if job:
            job.check()
        left = end - time.monotonic()
        if left <= 0:
            return
        time.sleep(min(0.5, left))


# --- Jobs -----------------------------------------------------------------------
class Job:
    def __init__(self):
        self.id = uuid.uuid4().hex
        self.created = time.time()
        self.status = "running"
        self.progress = "Starting"
        self.log: list[str] = []
        self.result = None
        self.error = None
        self._cancel = threading.Event()
        self._lock = threading.Lock()

    def say(self, msg: str) -> None:
        with self._lock:
            self.log.append(f"{time.strftime('%H:%M:%S')}  {msg}")
            del self.log[:-200]
            self.progress = msg

    def set_progress(self, msg: str) -> None:
        with self._lock:
            self.progress = msg

    def check(self) -> None:
        if self._cancel.is_set():
            raise Cancelled()

    def cancel(self) -> None:
        self._cancel.set()

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "id": self.id,
                "status": self.status,
                "progress": self.progress,
                "log": list(self.log),
                "error": self.error,
                "result": self.result if self.status == "done" else None,
            }


JOBS: dict[str, Job] = {}
JOBS_LOCK = threading.Lock()


def register_job() -> Job:
    now = time.time()
    with JOBS_LOCK:
        for jid in [k for k, j in JOBS.items() if now - j.created > JOB_TTL_SECONDS]:
            del JOBS[jid]
        running = sum(1 for j in JOBS.values() if j.status == "running")
        if running >= 2:
            raise UserError("Two probes are already running. Wait for one to finish or cancel it.")
        while len(JOBS) >= MAX_JOBS:
            oldest = min(JOBS.values(), key=lambda j: j.created)
            del JOBS[oldest.id]
        job = Job()
        JOBS[job.id] = job
        return job


# --- Input validation -----------------------------------------------------------
_ASN_TOKEN = re.compile(r"^(?:AS)?([0-9]{1,10})$", re.I)


def parse_target(raw: str):
    s = str(raw or "").strip()
    if not s:
        raise UserError("Enter a target IP address or CIDR.")
    if len(s) > 64:
        raise UserError("The target is too long to be an address or CIDR.")
    note = None
    try:
        ip = ipaddress.ip_address(s)
    except ValueError:
        try:
            net = ipaddress.ip_network(s, strict=False)
        except ValueError:
            raise UserError(
                "Enter an IP address or CIDR. For an AS-wide view, use Observed BGP paths in the lookup tool."
            ) from None
        ip = net.network_address + 1 if net.num_addresses > 2 else net.network_address
        note = (
            f"Traceroutes need one address, so this run probes {ip} inside {net}. "
            "A host that answers ICMP gives more complete paths."
        )
    if not ip.is_global:
        raise UserError(f"{ip} is a special-use address and can't be reached from the internet.")
    return str(ip), ip.version, note


def parse_analysis_target(raw):
    """An ASN is a passive resource, never an address chosen for a traceroute."""
    if not isinstance(raw, str) or not raw.strip() or len(raw.strip()) > 64:
        raise UserError("Enter an IP, CIDR, or ASN such as AS3333.")
    value = raw.strip()
    match = _ASN_TOKEN.fullmatch(value)
    if match:
        asn = int(match.group(1))
        if not public_asn(asn):
            raise UserError("Enter a public ASN; reserved and private ASNs are not supported.")
        return {"target_asn": asn, "target_ip": None, "af": None,
                "target_resource": f"AS{asn}", "target_note": None}
    ip, af, note = parse_target(value)
    return {"target_asn": None, "target_ip": ip, "af": af,
            "target_resource": ip, "target_note": note}


def parse_asns(raw, limit=25) -> list[int]:
    out: list[int] = []
    for tok in re.split(r"[\s,;]+", str(raw or "").strip()):
        if not tok:
            continue
        m = _ASN_TOKEN.match(tok)
        if not m:
            raise UserError(f"“{tok[:24]}” isn't an AS number. Use AS64500 or 64500.")
        n = int(m.group(1))
        if not public_asn(n):
            raise UserError(f"AS{n} is reserved or private and never originates internet routes.")
        if n not in out:
            out.append(n)
    if len(out) > limit:
        raise UserError(f"Enter at most {limit} suspect ASNs per run.")
    return out


def parse_measurement_ids(raw) -> list[int]:
    out: list[int] = []
    for tok in re.split(r"[\s,;]+", str(raw or "").strip()):
        if not tok:
            continue
        if not tok.isdigit() or not (0 < int(tok) < 10**9):
            raise UserError(f"“{tok[:24]}” isn't an Atlas measurement ID.")
        if int(tok) not in out:
            out.append(int(tok))
    if len(out) > 10:
        raise UserError("Enter at most 10 measurement IDs.")
    return out


def parse_probe_sets(raw) -> list[dict]:
    sets: list[dict] = []
    total = 0
    for line in str(raw or "").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(":")
        if len(parts) < 3:
            raise UserError(f"Probe set “{line[:40]}” needs type:value:count, for example country:BR:5.")
        kind, value, count = parts[0].strip().lower(), ":".join(parts[1:-1]).strip(), parts[-1].strip()
        if not count.isdigit() or not (1 <= int(count) <= 50):
            raise UserError(f"Probe count in “{line[:40]}” must be between 1 and 50.")
        n = int(count)
        if kind == "area":
            match = next((a for a in ATLAS_AREAS if a.lower() == value.lower()), None)
            if not match:
                raise UserError(f"Area must be one of: {', '.join(sorted(ATLAS_AREAS))}.")
            value = match
        elif kind == "country":
            if not re.fullmatch(r"[A-Za-z]{2}", value):
                raise UserError(f"Country in “{line[:40]}” must be a two-letter code.")
            value = value.upper()
        elif kind == "asn":
            value = parse_asns(value, limit=1)[0] if value else None
            if value is None:
                raise UserError(f"Add an AS number to “{line[:40]}”.")
        elif kind == "prefix":
            try:
                value = str(ipaddress.ip_network(value, strict=False))
            except ValueError:
                raise UserError(f"Prefix in “{line[:40]}” isn't valid CIDR.") from None
        else:
            raise UserError(f"Probe set type must be area, country, asn, or prefix (got “{kind[:12]}”).")
        sets.append({"type": kind, "value": value, "requested": n})
        total += n
    if len(sets) > 6:
        raise UserError("Use at most 6 probe sets per run.")
    if total > 100:
        raise UserError("Request at most 100 probes per run.")
    return sets


def validate_request(body: dict) -> dict:
    if not isinstance(body, dict):
        raise UserError("Request body must be a JSON object.")
    target = parse_analysis_target(body.get("target"))
    tier = body.get("tier", "public")
    if tier != "public":
        raise UserError("Analysis uses public data only. Scheduling active measurements is disabled.")
    suspects = parse_asns(body.get("suspect_asns"))
    if suspects:
        raise UserError("Suspect-network and enforcement inputs are not supported in passive analysis.")
    if body.get("api_key") or body.get("probe_sets"):
        raise UserError("API keys and probe scheduling are not supported in passive analysis.")
    if not isinstance(body.get("control_plane", True), bool):
        raise UserError("control_plane must be true or false.")
    params = {
        "target_input": str(body.get("target")).strip(),
        **target,
        "tier": tier,
        "measurement_ids": parse_measurement_ids(body.get("measurement_ids")),
        "suspects": suspects,
        "control_plane": bool(body.get("control_plane", True)),
        "api_key": None,
        "probe_sets": [],
        "max_wait": 480,
    }
    return params


# --- RIPEstat -------------------------------------------------------------------
def stat_url(endpoint: str, **q) -> str:
    q["sourceapp"] = SOURCEAPP
    return f"{STAT}/{endpoint}/data.json?{urllib.parse.urlencode(q)}"


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
    return ((d.get("data") or {}).get("holder") or None)


def atlas_discover(http: Http, ip: str | None, origin_asn: int, job, warnings=None):
    """Find recent public traceroutes to the target, then to anything in its origin AS."""
    base = {
        "type": "traceroute",
        "sort": "-start_time",
        "page_size": "10",
        "fields": "id,type,target,target_ip,target_asn,start_time,status,description",
    }
    scopes = [("origin_as", {"target_asn": str(origin_asn)})]
    if ip:
        scopes.insert(0, ("target", {"target_ip": ip}))
    for scope, extra in scopes:
        url = f"{ATLAS}/measurements/?{urllib.parse.urlencode({**base, **extra})}"
        try:
            d = http.get_json(url, job=job)
        except ApiError as e:
            job.say(f"Atlas search ({scope}) unavailable: {e.detail}")
            if warnings is not None:
                warnings.append(f"Atlas search ({scope}) unavailable: {e.detail}. Retained sample counts do not establish absence.")
            continue
        rows = [m for m in (d.get("results") or []) if isinstance(m, dict) and m.get("id")]
        if rows:
            return scope, rows[:5]
    return None, []


def atlas_latest(http: Http, msm_id: int, key: str | None, job) -> list[dict]:
    d = http.get_json(f"{ATLAS}/measurements/{msm_id}/latest/?format=json",
                      cache=False, job=job)
    return d if isinstance(d, list) else []


def atlas_probe_meta(http: Http, ids, job) -> dict[int, dict]:
    out: dict[int, dict] = {}
    ids = sorted({i for i in ids if isinstance(i, int)})
    for i in range(0, len(ids), 200):
        chunk = ids[i:i + 200]
        q = urllib.parse.urlencode({
            "id__in": ",".join(map(str, chunk)),
            "fields": "id,asn_v4,asn_v6,country_code",
            "page_size": "500",
        })
        try:
            d = http.get_json(f"{ATLAS}/probes/?{q}", job=job)
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
        rtts = [r["rtt"] for r in replies if isinstance(r.get("rtt"), (int, float))]
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


# --- Analysis (pure; covered by test_probe_analysis.py) --------------------------
def collapse(seq) -> list[int]:
    out: list[int] = []
    for x in seq:
        if x is None:
            continue
        if not out or out[-1] != x:
            out.append(x)
    return out


def entry_of(path: list[int], origin: int) -> int | None:
    if origin not in path:
        return None
    i = path.index(origin)
    return path[i - 1] if i > 0 else None


def collapse_cidrs(prefixes) -> tuple[list[str], list[str]]:
    v4, v6 = [], []
    for p in prefixes:
        try:
            n = ipaddress.ip_network(p, strict=False)
        except ValueError:
            continue
        (v4 if n.version == 4 else v6).append(n)
    return ([str(n) for n in ipaddress.collapse_addresses(v4)],
            [str(n) for n in ipaddress.collapse_addresses(v6)])


def analyze(*, target_input, target_ip, origin, traces, probe_meta, ipmap, cp_routes,
            suspects, suspect_prefixes, warnings, tier, data_scope) -> dict:
    origin_asn = origin["asn"]

    # Data plane ---------------------------------------------------------------
    trace_rows = []
    data_paths: list[list[int]] = []
    entry_data = collections.Counter()
    vantage = collections.defaultdict(lambda: {"traces": 0, "reached": 0, "entries": collections.Counter(),
                                               "countries": collections.Counter()})
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
        loop = len(path) != len(set(path))
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
        trace_rows.append({
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
            "as_loop": loop,
            "mapping_status": "prefix_origin_inference",
        })

    # Control plane ------------------------------------------------------------
    entry_cp = collections.Counter()
    cp_paths = []
    cp_other_origin = 0
    cp_as_set = 0
    for r in cp_routes:
        raw = r.get("path") or []
        ints = [a for a in raw if isinstance(a, int)]
        if len(ints) != len(raw):
            cp_as_set += 1
        path = collapse(ints)
        if not path:
            continue
        if path[-1] != origin_asn:
            cp_other_origin += 1
            continue
        cp_paths.append({"prefix": r.get("target_prefix"), "path": path, "source_id": r.get("source_id")})
        e = entry_of(path, origin_asn)
        if e is not None:
            entry_cp[e] += 1
    if cp_other_origin:
        warnings.append(
            f"{cp_other_origin} RIS route(s) for the covering prefix end at a different origin AS. "
            "These records were excluded from the selected-origin graph; other origins and source dates require separate review."
        )
    if cp_as_set:
        warnings.append(f"{cp_as_set} RIS path(s) contained AS_SET segments; set members were ignored.")

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
    mandatory = {origin_asn} | entries | (set())
    ranked = sorted(depth, key=lambda a: -(w_data[a] * 4 + w_cp[a]))
    keep = list(mandatory)
    for a in ranked:
        if len(keep) >= MAX_GRAPH_NODES:
            break
        if a not in keep:
            keep.append(a)
    keep_set = set(keep)
    if len(depth) > len(keep_set):
        warnings.append(f"The chart shows the {len(keep_set)} busiest of {len(depth)} networks; exports retain {min(len(cp_paths), MAX_CP_PATHS_KEPT)} of {len(cp_paths)} BGP path records.")

    nodes = []
    for a in keep:
        roles = []
        if a == origin_asn:
            roles.append("origin")
        if a in entries:
            roles.append("adjacent")
        if a in suspects:
            roles.append("analyst_named")
        if a in vantage_asns:
            roles.append("vantage")
        nodes.append({"asn": a, "name": None, "roles": roles,
                      "depth": depth[a], "data": w_data[a], "cp": w_cp[a]})
    graph_edges = [{"from": a, "to": b, **c} for (a, b), c in edges.items() if a in keep_set and b in keep_set]

    # Routing context: sample counts and inferred adjacency, never action advice.
    total_data = sum(entry_data.values())
    total_cp = sum(entry_cp.values())
    adjacencies = []
    for a in entries:
        adjacencies.append({
            "asn": a, "name": None,
            "data_paths": entry_data[a],
            "data_share": round(entry_data[a] / total_data, 4) if total_data else None,
            "cp_routes": entry_cp[a],
            "cp_share": round(entry_cp[a] / total_cp, 4) if total_cp else None,
            "interpretation": "Observed BGP adjacency or adjacency inferred from hop prefix-origin mappings. Neither confirms a provider relationship or a packet path to the perimeter.",
        })
    adjacencies.sort(key=lambda row: (-row["cp_routes"], -row["data_paths"], row["asn"]))
    reached = sum(1 for row in trace_rows if row["reached_origin_as"])
    summary = [f"{len(cp_paths)} retained BGP observations end at the selected origin AS{origin_asn}."]
    if trace_rows:
        summary.append(f"{len(trace_rows)} existing Atlas samples retained; {reached} contain a hop mapped to AS{origin_asn} using current prefix-origin data. This does not establish router ownership or reachability.")
    else:
        summary.append("No traceroutes were retained; this view contains routing observations only. Check source warnings for missing coverage.")
    summary.append("Routing context does not identify the path an observed connection took, confirm a service provider, or support an enforcement recommendation.")
    if len(trace_rows) != reached:
        warnings.append(f"{len(trace_rows) - reached} traceroute samples have no hop mapped to AS{origin_asn}. Missing replies, incomplete mappings, and source-date differences prevent a reachability conclusion.")

    vantage_rows = []
    for a, v in sorted(vantage.items(), key=lambda kv: -kv[1]["traces"]):
        vantage_rows.append({
            "asn": a or None, "name": None, "traces": v["traces"], "reached": v["reached"],
            "countries": dict(v["countries"]),
            "entries": [{"asn": e, "traces": c} for e, c in v["entries"].most_common()],
        })

    return {
        "meta": {
            "tool": "Múcaro infrastructure explorer",
            "version": VERSION,
            "generated_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "target_input": target_input,
            "target_ip": target_ip,
            "origin": {**origin, "name": None},
            "tier": tier,
            "data_scope": data_scope,
        },
        "summary": summary,
        "routing_context": {
            "adjacencies": adjacencies,
            "calculations": {
                "bgp_fraction": {"numerator": "cp_routes", "denominator": total_cp,
                                 "unit": "fraction of retained BGP records with a preceding ASN", "rounding": "4 decimal places"},
                "mapped_sample_fraction": {"numerator": "data_paths", "denominator": total_data,
                                           "unit": "fraction of retained samples with an inferred preceding ASN", "rounding": "4 decimal places"},
            },
        },
        "graph": {"nodes": nodes, "edges": graph_edges},
        "traces": trace_rows,
        "vantage": vantage_rows,
        "control_plane": {
            "routes": len(cp_paths),
            "entry_counts": [{"asn": a, "routes": c} for a, c in entry_cp.most_common()],
            "paths": cp_paths[:MAX_CP_PATHS_KEPT],
            "truncated": len(cp_paths) > MAX_CP_PATHS_KEPT,
        },
        "warnings": warnings,
        "methodology": METHODOLOGY,
    }


METHODOLOGY = [
    "This analysis reads public RIPE data and existing Atlas measurements only. It never schedules a probe.",
    "BGP paths are collector-observed advertisements, not packet paths or complete network architecture.",
    "Solid graph edges are inferred by mapping Atlas reply addresses to current prefix origins. They are not verified router ownership or AS transitions. Dashed edges are BGP observations.",
    "An adjacent ASN is context only. Adjacency does not establish a provider, ownership, government association, or physical location.",
    "Counts and fractions describe the retained sample, not traffic share, maliciousness, confidence, or complete network coverage.",
    "Current hop mappings are not historical routing evidence. Prefix reuse can miss more-specific routes; multiple origins and unanswered hops add uncertainty.",
    "Existing Atlas results describe their probe, destination, and time. They do not reconstruct an observed perimeter connection or an attacker's route.",
]


def fill_names(obj, names: dict[int, str]) -> None:
    if isinstance(obj, dict):
        if "asn" in obj and "name" in obj and isinstance(obj["asn"], int):
            obj["name"] = names.get(obj["asn"])
        for v in obj.values():
            fill_names(v, names)
    elif isinstance(obj, list):
        for v in obj:
            fill_names(v, names)


# --- Job runner -----------------------------------------------------------------
def select_as_routes(rows, asn):
    """Select complete origin paths; do not bridge AS sets, loops, or transit-only matches."""
    selected, seen, excluded = [], set(), collections.Counter()
    for row in rows[:MAX_AS_ROUTES]:
        if not isinstance(row, dict):
            excluded["invalid"] += 1
            continue
        raw = row.get("path")
        if (not isinstance(raw, list) or not 1 <= len(raw) <= 255 or
                any(isinstance(a, bool) or not isinstance(a, int) or not 1 <= a <= 4294967295 for a in raw)):
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
        selected.append({"source_id": peer, "target_prefix": prefix,
                         "path": path, "raw_path": list(raw)})
    selected.sort(key=lambda r: (r["source_id"], r["target_prefix"], r["raw_path"]))
    return selected, dict(excluded)


def run_asn_job(job, params, http):
    """Read AS-scoped public evidence without selecting or probing an IP."""
    if params["tier"] != "public":
        raise UserError("ASN analysis uses public data only.")
    job.check()
    asn = params["target_asn"]
    resource = f"AS{asn}"
    warnings, rows, selected = [], [], []
    source = {"name": "RIPE RIS via RIPEstat", "url": stat_url("bgp-state", resource=resource),
              "query_parameters": {"resource": resource}, "observed_at": None,
              "retrieved_at": None, "status": "not_requested"}
    excluded = {}
    if params["control_plane"]:
        job.say(f"Reading observed BGP routes for {resource}")
        try:
            response = http.get_json(source["url"], job=job)
            data = response.get("data") if isinstance(response, dict) else None
            if not isinstance(data, dict) or not isinstance(data.get("bgp_state"), list):
                raise UserError("RIPE returned an unsupported BGP response for this ASN.")
            rows = data["bgp_state"]
            selected, excluded = select_as_routes(rows, asn)
            source.update(status="available", observed_at=data.get("query_time"),
                          retrieved_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                          returned_routes=len(rows), reported_routes=data.get("nr_routes"))
            if not source["observed_at"]:
                source["observation_time_note"] = "Source observation time unavailable."
            reported = data.get("nr_routes")
            if len(rows) > MAX_AS_ROUTES or (isinstance(reported, int) and reported > len(rows)):
                source["status"] = "partial"
                warnings.append("BGP results are incomplete or exceed the route limit; summaries cover processed records only.")
            if excluded:
                warnings.append("Excluded BGP records: " + ", ".join(f"{k}: {v}" for k, v in sorted(excluded.items())) + ".")
        except (ApiError, UserError) as e:
            source["status"] = "unavailable"
            warnings.append(f"AS-scoped BGP evidence unavailable: {e}")

    # Existing Atlas results are address-specific samples, not an AS-wide measured path.
    measurement_ids = list(params["measurement_ids"])
    definitions = []
    if measurement_ids:
        for mid in measurement_ids:
            job.check()
            try:
                definition = http.get_json(f"{ATLAS}/measurements/{mid}/?fields=id,type,target_ip,target_asn,start_time", job=job)
                definitions.append(definition)
            except ApiError as e:
                warnings.append(f"Measurement {mid} metadata unavailable: {e.detail}")
    else:
        job.say(f"Searching existing Atlas measurements classified under {resource}")
        _, definitions = atlas_discover(http, None, asn, job, warnings=warnings)
    samples, accepted_ids, measurement_evidence = [], [], []
    sample_total = 0
    for definition in definitions:
        job.check()
        if (not isinstance(definition, dict) or definition.get("target_asn") != asn or
                definition.get("type") != "traceroute" or not is_public_ip(definition.get("target_ip"))):
            warnings.append("An Atlas measurement was excluded because its target/type could not be matched to the requested AS.")
            continue
        mid = definition.get("id")
        if not isinstance(mid, int) or isinstance(mid, bool) or not 0 < mid < 10**9 or mid in accepted_ids:
            continue
        try:
            raw_samples = atlas_latest(http, mid, None, job)
        except ApiError as e:
            warnings.append(f"Measurement {mid} results unavailable: {e.detail}")
            continue
        accepted_ids.append(mid)
        measurement_evidence.append({"measurement_id": mid, "target_asn": asn,
                                     "target_ip": definition["target_ip"], "start_time": definition.get("start_time"),
                                     "url": f"{ATLAS}/measurements/{mid}/latest/?format=json",
                                     "retrieved_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())})
        sample_total += len(raw_samples)
        for raw in raw_samples[:MAX_TRACES - len(samples)]:
            parsed = parse_trace(raw)
            if parsed is None or parsed["dst"] != definition["target_ip"]:
                continue
            if parsed["timestamp"] is not None and (isinstance(parsed["timestamp"], bool) or
                    not isinstance(parsed["timestamp"], int) or not 946684800 <= parsed["timestamp"] <= 4102444800):
                warnings.append(f"Measurement {mid} contained a result with an unsupported timestamp.")
                continue
            parsed.update(probe_asn=None, probe_country=None, as_path=[], mapping_status="not_performed",
                          reached_origin_as=None, entry_asn=None,
                          reached_target=any(h["ip"] == parsed["dst"] for h in parsed["hops"]))
            parsed["hops"] = [{**h, "asn": None, "scope": None} for h in parsed["hops"]]
            samples.append(parsed)
    if sample_total > MAX_TRACES:
        warnings.append(f"Atlas returned {sample_total} results; at most {MAX_TRACES} samples are retained.")
    prefixes = sorted({r["target_prefix"] for r in selected})
    origin = {"asn": asn, "all_asns": [asn], "prefix": None,
              "prefixes": prefixes[:MAX_AS_PREFIXES], "prefix_count": len(prefixes),
              "prefixes_truncated": len(prefixes) > MAX_AS_PREFIXES}
    result = analyze(target_input=params["target_input"], target_ip=None, origin=origin, traces=[],
                     probe_meta={}, ipmap={}, cp_routes=selected, suspects=[], suspect_prefixes={},
                     warnings=warnings, tier="public", data_scope="asn_samples" if samples else None)
    for adjacency in result["routing_context"]["adjacencies"]:
        adjacency["interpretation"] = "Observed immediately before the selected origin in BGP advertisements. Adjacency alone does not establish a provider relationship."
    result["summary"] = [f"{len(selected)} retained BGP observations for {len(prefixes)} prefixes originated by {resource}.",
                         f"{len(samples)} retained existing Atlas traceroute samples to specific addresses; no new measurements were scheduled."]
    if source["status"] in ("unavailable", "not_requested"):
        result["summary"][0] = "BGP evidence is " + source["status"].replace("_", " ") + "; route and prefix counts are unknown."
        result["meta"]["origin"]["prefix_count"] = None
    result["traces"] = samples
    result["meta"].update(target_kind="asn", target_resource=resource, target_asn=asn,
                          measurement_ids=accepted_ids, requests=http.count)
    result["control_plane"].update(source=source, excluded_records=excluded,
                                   distinct_peers=len({r["source_id"] for r in selected}) if source["status"] in ("available", "partial") else None)
    if source["status"] in ("unavailable", "not_requested"):
        result["control_plane"]["routes"] = None
        result["routing_context"]["calculations"]["bgp_fraction"]["denominator"] = None
    for path, raw in zip(result["control_plane"]["paths"], selected):
        path["raw_path"] = raw["raw_path"]
    result["measurement_evidence"] = measurement_evidence
    if result["control_plane"]["truncated"]:
        result["warnings"].append(f"Exports retain the first {len(result['control_plane']['paths'])} of {len(selected)} processed BGP path records; summaries and graph counts use all processed records.")
    result["methodology"] = [
        "ASN analysis reads public sources only. It does not choose an IP or schedule measurements.",
        "BGP paths are collector-observed advertisements ending at the requested ASN, not packet paths to your perimeter.",
        "Prefix lists and route counts cover retained source observations, not a complete inventory or traffic share.",
        "Atlas classifies measurement targets by ASN. That classification can differ from current or historical routing.",
        "Existing traceroutes are samples to the displayed destination addresses and timestamps. Hop-to-AS mapping is not performed in this overview.",
        "Adjacency does not establish provider, ownership, government association, or physical location.",
    ]
    if len(prefixes) > MAX_AS_PREFIXES:
        result["warnings"].append(f"The prefix list is limited to {MAX_AS_PREFIXES} of {len(prefixes)} observed prefixes.")
    want = [asn] + [e["asn"] for e in result["routing_context"]["adjacencies"]] + [n["asn"] for n in result["graph"]["nodes"]]
    names = {}
    for index, number in enumerate(dict.fromkeys(want)):
        if index >= MAX_NAME_LOOKUPS:
            result["warnings"].append("Organization-name enrichment reached its request limit.")
            break
        job.check()
        job.set_progress(f"Naming networks ({index + 1} of {min(len(set(want)), MAX_NAME_LOOKUPS)}): AS{number}")
        name = as_name(http, number, job)
        if name:
            names[number] = name
    fill_names(result, names)
    result["meta"]["requests"] = http.count
    job.result, job.status = result, "done"
    job.say("Done")


def run_job(job: Job, params: dict, http: Http) -> None:
    key = params.pop("api_key", None)
    warnings: list[str] = []
    try:
        if params["tier"] != "public" or params["suspects"]:
            raise UserError("Only passive public-data analysis is supported.")
        job.check()
        if params.get("target_asn"):
            run_asn_job(job, params, http)
            return
        if params["target_note"]:
            warnings.append(params["target_note"])
        tip = params["target_ip"]
        job.say(f"Looking up the AS that announces {tip}")
        info = network_info(http, tip, job)
        if not info["asns"]:
            raise UserError(f"No AS currently announces a prefix covering {tip}, per RIPEstat. "
                            "Check the address, or whether the prefix is withdrawn.")
        origin_asn = info["asns"][0]
        if len(info["asns"]) > 1:
            warnings.append(f"{info['prefix']} is announced by several ASes ({', '.join('AS%d' % a for a in info['asns'])}). "
                            f"This run treats AS{origin_asn} as the origin.")
        origin = {"asn": origin_asn, "all_asns": info["asns"], "prefix": info["prefix"]}
        job.say(f"Origin AS{origin_asn}, prefix {info['prefix']}")

        # Data plane
        msm_ids = list(params["measurement_ids"])
        data_scope = "supplied" if msm_ids else None
        if not msm_ids:
            job.say("Searching public Atlas traceroutes")
            scope, rows = atlas_discover(http, tip, origin_asn, job, warnings=warnings)
            msm_ids = [int(m["id"]) for m in rows]
            data_scope = scope
            if scope == "origin_as":
                warnings.append(f"No public traceroutes target {tip}. Using traceroutes to other addresses in "
                                f"AS{origin_asn}; samples may not represent the requested address.")
            elif not rows:
                warnings.append("No public Atlas traceroutes were found for this target or its AS. Supply "
                                "existing measurement IDs. No new measurements are scheduled.")

        raw_results: list[dict] = []
        others = msm_ids
        for m in others:
            try:
                res = atlas_latest(http, m, key, job)
            except ApiError as e:
                warnings.append(f"Measurement {m} could not be read: {e.detail}")
                continue
            job.say(f"Measurement {m}: {len(res)} results")
            raw_results.extend(res)

        traces = [t for t in (parse_trace(r) for r in raw_results) if t]
        if len(traces) > MAX_TRACES:
            warnings.append(f"Kept the first {MAX_TRACES} of {len(traces)} traceroutes.")
            traces = traces[:MAX_TRACES]

        probe_meta = atlas_probe_meta(http, {t["probe_id"] for t in traces}, job) if traces else {}

        # Hop enrichment, most frequent first, reusing resolved prefixes
        freq = collections.Counter(h["ip"] for t in traces for h in t["hops"] if is_public_ip(h["ip"]))
        ipmap: dict[str, dict] = {}
        known: list[tuple] = []
        if info["prefix"]:
            try:
                known.append((ipaddress.ip_network(info["prefix"]), info["asns"]))
            except ValueError:
                pass
        lookups = 0
        skipped = 0
        ordered = [ip for ip, _ in freq.most_common()]
        for i, ip in enumerate(ordered, 1):
            addr = ipaddress.ip_address(ip)
            hit = next((k for k in known if k[0].version == addr.version and addr in k[0]), None)
            if hit:
                ipmap[ip] = {"asn": hit[1][0] if hit[1] else None}
                continue
            if lookups >= MAX_HOP_LOOKUPS:
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
            warnings.append(f"{skipped} rarely seen hop addresses were left unmapped to stay within request limits.")

        # Preserve successful absence separately from failed or unrequested evidence.
        cp_routes = []
        resource = info["prefix"] or tip
        cp_source = {"name": "RIPE RIS via RIPEstat", "url": stat_url("bgp-state", resource=resource),
                     "query_parameters": {"resource": resource}, "status": "not_requested",
                     "observed_at": None, "retrieved_at": None}
        if params["control_plane"]:
            job.say(f"Reading BGP observations for {resource}")
            try:
                response = http.get_json(cp_source["url"], job=job)
                data = response.get("data") if isinstance(response, dict) else None
                if not isinstance(data, dict) or not isinstance(data.get("bgp_state"), list):
                    raise UserError("Unsupported BGP response.")
                raw_routes = data["bgp_state"]
                cp_routes, excluded = select_as_routes(raw_routes, origin_asn)
                cp_source.update(status="available", observed_at=data.get("query_time"),
                                 retrieved_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                                 returned_routes=len(raw_routes), reported_routes=data.get("nr_routes"))
                reported = data.get("nr_routes")
                if len(raw_routes) > MAX_AS_ROUTES or (isinstance(reported, int) and reported > len(raw_routes)):
                    cp_source["status"] = "partial"
                    warnings.append("BGP results are partial; summaries cover processed records only.")
                if excluded:
                    warnings.append("Excluded BGP records: " + ", ".join(f"{k}: {v}" for k, v in sorted(excluded.items())) + ".")
            except (ApiError, UserError) as e:
                cp_source["status"] = "unavailable"
                warnings.append(f"BGP evidence unavailable: {e}")

        job.say("Analyzing paths")
        result = analyze(
            target_input=params["target_input"], target_ip=tip, origin=origin, traces=traces,
            probe_meta=probe_meta, ipmap=ipmap, cp_routes=cp_routes, suspects=[],
            suspect_prefixes={}, warnings=warnings, tier=params["tier"], data_scope=data_scope,
        )

        result["meta"].update(target_kind="ip", target_resource=params["target_input"])
        result["control_plane"].update(source=cp_source, distinct_peers=len({row["source_id"] for row in cp_routes}) if cp_source["status"] in ("available", "partial") else None)
        for path, raw in zip(result["control_plane"]["paths"], cp_routes):
            path["raw_path"] = raw["raw_path"]
        if cp_source["status"] in ("unavailable", "not_requested"):
            result["control_plane"]["routes"] = None
            result["summary"][0] = "BGP evidence is " + cp_source["status"].replace("_", " ") + "; route counts are unknown."
            result["routing_context"]["calculations"]["bgp_fraction"]["denominator"] = None
            for row in result["routing_context"]["adjacencies"]:
                row.update(cp_routes=None, cp_share=None)
        if result["control_plane"]["truncated"]:
            result["warnings"].append(f"Exports retain {len(result['control_plane']['paths'])} of {len(cp_routes)} processed BGP path records; summary counts use all processed records.")

        # Names, highest-signal networks first
        want = [origin_asn] + [e["asn"] for e in result["routing_context"]["adjacencies"]] + params["suspects"]
        want += [n["asn"] for n in sorted(result["graph"]["nodes"], key=lambda n: -(n["data"] * 4 + n["cp"]))]
        want += [v["asn"] for v in result["vantage"] if v["asn"]]
        seen, order = set(), []
        for a in want:
            if a not in seen:
                seen.add(a)
                order.append(a)
        names: dict[int, str] = {}
        for i, a in enumerate(order[:MAX_NAME_LOOKUPS], 1):
            job.set_progress(f"Naming networks ({i} of {min(len(order), MAX_NAME_LOOKUPS)})")
            n = as_name(http, a, job)
            if n:
                names[a] = n
        fill_names(result, names)
        result["meta"]["measurement_ids"] = msm_ids
        result["meta"]["requests"] = http.count
        job.result = result
        job.status = "done"
        job.say("Done")
    except Cancelled:
        job.status = "cancelled"
        job.say("Cancelled")
    except UserError as e:
        job.error = str(e)
        job.status = "failed"
    except ApiError as e:
        job.error = f"A RIPE service returned an error ({e.status or 'network'}) for {e.url}: {e.detail}"
        job.status = "failed"
    except Exception as e:  # keep the server alive; surface the type for debugging
        job.error = f"Unexpected {type(e).__name__}: {e}"
        job.status = "failed"
    finally:
        key = None  # noqa: F841  (drop the only reference)


# --- HTTP server ----------------------------------------------------------------
INDEX_PATH = Path(__file__).with_name("probe_web") / "index.html"
CSP = ("default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; "
       "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")


class Handler(BaseHTTPRequestHandler):
    server_version = f"MucaroProbe/{VERSION}"

    def log_message(self, fmt, *args):  # paths only; bodies (and keys) are never logged
        print(f"{self.address_string()} {self.command} {urllib.parse.urlsplit(self.path).path} {args[1] if len(args) > 1 else ''}")

    def _host_ok(self) -> bool:
        return self.headers.get("Host", "") in self.server.allowed_hosts

    def _send(self, code: int, payload, ctype="application/json; charset=utf-8"):
        body = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        if ctype.startswith("text/html"):
            self.send_header("Content-Security-Policy", CSP)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if not self._host_ok():
            return self._send(403, {"error": "Unexpected Host header."})
        path = urllib.parse.urlsplit(self.path).path
        if path in ("/", "/index.html"):
            try:
                return self._send(200, INDEX_PATH.read_bytes(), "text/html; charset=utf-8")
            except OSError:
                return self._send(500, {"error": f"Missing {INDEX_PATH}."})
        if path == "/api/health":
            return self._send(200, {"version": VERSION})
        m = re.fullmatch(r"/api/job/([0-9a-f]{32})", path)
        if m:
            with JOBS_LOCK:
                job = JOBS.get(m.group(1))
            if not job:
                return self._send(404, {"error": "That run has expired. Start a new one."})
            return self._send(200, job.snapshot())
        return self._send(404, {"error": "Not found"})

    def do_POST(self):
        if not self._host_ok():
            return self._send(403, {"error": "Unexpected Host header."})
        origin = self.headers.get("Origin")
        if origin and urllib.parse.urlsplit(origin).netloc not in self.server.allowed_hosts:
            return self._send(403, {"error": "Cross-origin requests are not accepted."})
        path = urllib.parse.urlsplit(self.path).path
        m = re.fullmatch(r"/api/job/([0-9a-f]{32})/cancel", path)
        if m:
            with JOBS_LOCK:
                job = JOBS.get(m.group(1))
            if job:
                job.cancel()
            return self._send(200, {"ok": True})
        if path != "/api/probe":
            return self._send(404, {"error": "Not found"})
        if not (self.headers.get("Content-Type", "").split(";")[0].strip() == "application/json"):
            return self._send(415, {"error": "Send JSON."})
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = 0
        if length <= 0 or length > MAX_BODY_BYTES:
            return self._send(413, {"error": "Request body is empty or too large."})
        try:
            body = json.loads(self.rfile.read(length).decode("utf-8"))
            params = validate_request(body)
            job = register_job()
        except UserError as e:
            return self._send(400, {"error": str(e)})
        except (json.JSONDecodeError, UnicodeDecodeError):
            return self._send(400, {"error": "Request body isn't valid JSON."})
        threading.Thread(target=run_job, args=(job, params, self.server.http), daemon=True).start()
        return self._send(202, {"job_id": job.id})


def main() -> None:
    ap = argparse.ArgumentParser(description="Múcaro infrastructure explorer")
    ap.add_argument("--port", type=int, default=DEFAULT_PORT)
    ap.add_argument("--pause", type=float, default=2.0,
                    help="seconds between RIPE requests (minimum 2.0)")
    args = ap.parse_args()
    server = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    server.allowed_hosts = {f"127.0.0.1:{args.port}", f"localhost:{args.port}"}
    server.http = Http(pause=max(2.0, args.pause))
    print(f"Infrastructure explorer {VERSION} on http://127.0.0.1:{args.port}  (Ctrl+C to stop)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
