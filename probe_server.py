#!/usr/bin/env python3
"""
Múcaro | Infrastructure Explorer

Passive infrastructure context from RIPEstat BGP observations and existing RIPE
Atlas samples. IP/prefix lookup is primary; ASN exploration is broader context.
No active measurement scheduling, provider attribution, or enforcement advice.

Standard library only. Python 3.10+.

    python3 probe_server.py              # http://127.0.0.1:8767
    python3 probe_server.py --port 8768

Investigation inputs remain local except for public-data lookups sent to RIPE.
API keys and active measurements are not accepted. Responses are cached only
within one run, so every run re-reads its sources and retrieval times are true.
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

VERSION = "0.3.0"
SOURCEAPP = "mucaro-infrastructure-explorer"
USER_AGENT = f"mucaro-infrastructure-explorer/{VERSION} (+https://github.com/bayanilla/infrastructure-explorer)"
ATLAS = "https://atlas.ripe.net/api/v2"
STAT = "https://stat.ripe.net/data"

DEFAULT_PORT = 8767
MAX_RESPONSE_BYTES = 32 * 1024 * 1024
MAX_BODY_BYTES = 64 * 1024
MAX_HOP_LOOKUPS = 150          # uncached RIPEstat network-info calls per run
MAX_TRACES = 400
MAX_NAME_LOOKUPS = 60
MAX_GRAPH_NODES = 80
MAX_CP_PATHS_KEPT = 400
MAX_AS_ROUTES = 20000
MAX_AS_PREFIXES = 4000
MAX_OTHER_ORIGINS = 50
MAX_DISCOVERED = 5
JOB_TTL_SECONDS = 3600
MAX_JOBS = 30
TS_MIN, TS_MAX = 946684800, 4102444800   # 2000-01-01 .. 2100-01-01 UTC


def utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def public_asn(n: int) -> bool:
    return (
        0 < n <= 4294967295
        and n != 23456
        and not (64496 <= n <= 131071)
        and not (n >= 4200000000)
    )


def is_public_ip(ip) -> bool:
    if not isinstance(ip, str) or not ip:
        return False
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def valid_timestamp(ts) -> bool:
    """Atlas timestamps are integer UNIX seconds. Missing is allowed; malformed is not."""
    if ts is None:
        return True
    return isinstance(ts, int) and not isinstance(ts, bool) and TS_MIN <= ts <= TS_MAX


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
    """One request at a time with a pause between them, shared by every job.

    There is no cross-run cache. Each job carries its own response cache, which
    deduplicates requests inside that run and is discarded when the run ends.
    """

    def __init__(self, pause: float):
        self.pause = pause
        self._lock = threading.Lock()
        self._last = 0.0
        self.count = 0

    def get_json(self, url, cache=True, job=None, timeout=45):
        store = job.cache if (cache and job is not None) else None
        if store is not None and url in store:
            return store[url]
        data = self._request(url, job, timeout)
        if store is not None:
            store[url] = data
        return data

    def _request(self, url, job, timeout):
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
                    url, method="GET",
                    headers={"User-Agent": USER_AGENT, "Accept": "application/json"},
                )
                try:
                    with urllib.request.urlopen(req, timeout=timeout) as resp:
                        raw = resp.read(MAX_RESPONSE_BYTES + 1)
                    self._count(job)
                    if len(raw) > MAX_RESPONSE_BYTES:
                        raise ApiError(0, "response exceeded the size limit", _redact(url))
                    return json.loads(raw.decode("utf-8")) if raw else {}
                except urllib.error.HTTPError as e:
                    self._count(job)
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

    def _count(self, job):
        self._last = time.monotonic()
        self.count += 1
        if job is not None:
            job.requests += 1


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
        self.cache: dict[str, object] = {}
        self.requests = 0
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
            raise UserError("Two analyses are already running. Wait for one to finish or cancel it.")
        while len(JOBS) >= MAX_JOBS:
            oldest = min(JOBS.values(), key=lambda j: j.created)
            del JOBS[oldest.id]
        job = Job()
        JOBS[job.id] = job
        return job


# --- Input validation -----------------------------------------------------------
_ASN_TOKEN = re.compile(r"^(?:AS)?([0-9]{1,10})$", re.I)


def parse_target(raw: str):
    """Return (ip, address_family) for one public IP address. Ranges are not accepted."""
    s = str(raw or "").strip()
    if not s:
        raise UserError("Enter a public IP address.")
    if len(s) > 64:
        raise UserError("The target is too long to be an IP address.")
    if "/" in s:
        raise UserError("Enter a single IP address, not a range. The report shows the announced prefix that covers it.")
    try:
        ip = ipaddress.ip_address(s)
    except ValueError:
        raise UserError("Enter a public IP address or an ASN such as AS3333.") from None
    if not ip.is_global:
        raise UserError(f"{ip} is a special-use address and isn't routed on the internet.")
    return str(ip), ip.version


def parse_analysis_target(raw):
    """An ASN is a passive resource, never an address chosen for a traceroute."""
    if not isinstance(raw, str) or not raw.strip() or len(raw.strip()) > 64:
        raise UserError("Enter a public IP address or an ASN such as AS3333.")
    value = raw.strip()
    match = _ASN_TOKEN.fullmatch(value)
    if match:
        asn = int(match.group(1))
        if not public_asn(asn):
            raise UserError("Enter a public ASN; reserved and private ASNs are not supported.")
        return {"target_asn": asn, "target_ip": None, "af": None,
                "target_resource": f"AS{asn}"}
    ip, af = parse_target(value)
    return {"target_asn": None, "target_ip": ip, "af": af, "target_resource": ip}


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


def validate_request(body: dict) -> dict:
    if not isinstance(body, dict):
        raise UserError("Request body must be a JSON object.")
    target = parse_analysis_target(body.get("target"))
    tier = body.get("tier", "public")
    if tier != "public":
        raise UserError("Analysis uses public data only. Scheduling active measurements is disabled.")
    if str(body.get("suspect_asns") or "").strip():
        raise UserError("Suspect-network and enforcement inputs are not supported in passive analysis.")
    if body.get("api_key") or body.get("probe_sets"):
        raise UserError("API keys and probe scheduling are not supported in passive analysis.")
    if not isinstance(body.get("control_plane", True), bool):
        raise UserError("control_plane must be true or false.")
    return {
        "target_input": str(body.get("target")).strip(),
        **target,
        "tier": tier,
        "measurement_ids": parse_measurement_ids(body.get("measurement_ids")),
        "control_plane": body.get("control_plane", True),
    }


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


def read_bgp_state(http: Http, resource: str, job, warnings: list[str]):
    """Fetch RIS routes. Returns (raw_rows, source). Failure is recorded, never raised."""
    source = {"name": "RIPE RIS via RIPEstat", "url": stat_url("bgp-state", resource=resource),
              "query_parameters": {"resource": resource}, "status": "not_requested",
              "observed_at": None, "retrieved_at": None}
    try:
        response = http.get_json(source["url"], job=job)
        data = response.get("data") if isinstance(response, dict) else None
        if not isinstance(data, dict) or not isinstance(data.get("bgp_state"), list):
            raise UserError("RIPE returned an unsupported BGP response.")
        rows = data["bgp_state"]
        reported = data.get("nr_routes")
        source.update(status="available", observed_at=data.get("query_time"), retrieved_at=utc_now(),
                      returned_routes=len(rows), reported_routes=reported)
        if not source["observed_at"]:
            source["observation_time_note"] = "Source observation time unavailable."
        if len(rows) > MAX_AS_ROUTES or (isinstance(reported, int) and reported > len(rows)):
            source["status"] = "partial"
            warnings.append("BGP results are incomplete or exceed the route limit; summaries cover processed records only.")
        return rows, source
    except (ApiError, UserError) as e:
        source["status"] = "unavailable"
        warnings.append(f"BGP evidence unavailable: {e}")
        return [], source


# --- RIPE Atlas -----------------------------------------------------------------
MSM_FIELDS = "id,type,target,target_ip,target_asn,start_time,status,description"


def atlas_discover(http: Http, job, warnings, *, target_ip=None, target_asn=None):
    """Recent public traceroute definitions matching exactly one filter."""
    q = {"type": "traceroute", "sort": "-start_time", "page_size": "10", "fields": MSM_FIELDS}
    if target_ip:
        q["target_ip"], scope = target_ip, "target"
    else:
        q["target_asn"], scope = str(target_asn), "origin_as"
    try:
        d = http.get_json(f"{ATLAS}/measurements/?{urllib.parse.urlencode(q)}", job=job)
    except ApiError as e:
        job.say(f"Atlas search ({scope}) unavailable: {e.detail}")
        warnings.append(f"Atlas search ({scope}) unavailable: {e.detail}. Retained sample counts do not establish absence.")
        return []
    return [m for m in (d.get("results") or []) if isinstance(m, dict)]


def atlas_definition(http: Http, msm_id: int, job) -> dict:
    return http.get_json(f"{ATLAS}/measurements/{msm_id}/?fields={MSM_FIELDS}", job=job)


def atlas_latest(http: Http, msm_id: int, job) -> list[dict]:
    d = http.get_json(f"{ATLAS}/measurements/{msm_id}/latest/?format=json", job=job)
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
        rtts = [r["rtt"] for r in replies if isinstance(r.get("rtt"), (int, float)) and not isinstance(r.get("rtt"), bool)]
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
            if len(traces) >= MAX_TRACES:
                continue
            traces.append(parsed)
            kept += 1
        if wrong_dst:
            warnings.append(f"Measurement {mid}: {wrong_dst} result(s) with a destination other than {definition['target_ip']} were excluded.")
        if bad_ts:
            warnings.append(f"Measurement {mid}: {bad_ts} result(s) with an unsupported timestamp were excluded.")
        evidence.append({"measurement_id": mid, "target_ip": definition["target_ip"],
                         "target_asn": definition.get("target_asn"), "start_time": definition.get("start_time"),
                         "scope": definition.get("_scope"), "results_returned": len(raw_results),
                         "results_retained": kept,
                         "url": f"{ATLAS}/measurements/{mid}/latest/?format=json", "retrieved_at": utc_now()})
    if total > MAX_TRACES and len(traces) >= MAX_TRACES:
        warnings.append(f"Atlas returned {total} results; at most {MAX_TRACES} samples are retained.")
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
                warnings.append(f"Measurement {mid} was excluded: its target ({shown or 'unknown'}) or type "
                                f"could not be matched to {target_ip or f'AS{origin_asn}'}.")
                continue
            if scope == "origin_as" and target_ip:
                warnings.append(f"Measurement {mid} targets {definition['target_ip']}, another address Atlas "
                                f"classifies under AS{origin_asn}. Its samples may not represent the requested target.")
            chosen.append({**definition, "_scope": scope})
        return chosen, "supplied"

    if target_ip:
        job.say("Searching public Atlas traceroutes to this address")
        rows = atlas_discover(http, job, warnings, target_ip=target_ip)
        chosen = [{**d, "_scope": "target"} for d in rows
                  if classify_definition(d, target_ip=target_ip) == "target" and _msm_id(d)][:MAX_DISCOVERED]
        if chosen:
            return chosen, "target"
    job.say(f"Searching public Atlas traceroutes classified under AS{origin_asn}")
    rows = atlas_discover(http, job, warnings, target_asn=origin_asn)
    tagged = [{**d, "_scope": classify_definition(d, target_ip=target_ip, origin_asn=origin_asn)}
              for d in rows if _msm_id(d)]
    in_target = [d for d in tagged if d["_scope"] == "target"]
    if in_target:
        return in_target[:MAX_DISCOVERED], "target"
    in_origin = [d for d in tagged if d["_scope"] == "origin_as"][:MAX_DISCOVERED]
    if len(tagged) > len([d for d in tagged if d["_scope"]]):
        warnings.append("Some Atlas search results were excluded because their target or type did not match the search.")
    return in_origin, ("origin_as" if in_origin else None)


# --- BGP record selection -------------------------------------------------------
def _valid_path(raw) -> bool:
    return (isinstance(raw, list) and 1 <= len(raw) <= 255 and
            all(isinstance(a, int) and not isinstance(a, bool) and 1 <= a <= 4294967295 for a in raw))


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
    for row in rows[:MAX_AS_ROUTES]:
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
        selected.append({"source_id": peer, "target_prefix": prefix,
                         "path": path, "raw_path": list(raw)})
    selected.sort(key=lambda r: (r["source_id"], r["target_prefix"], r["raw_path"]))
    return selected, dict(excluded)


def other_origins(rows, asn) -> list[dict]:
    """Group well-formed records that end at an origin other than `asn`, by (prefix, origin)."""
    groups: dict[tuple, set] = collections.defaultdict(set)
    for row in rows[:MAX_AS_ROUTES]:
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


# --- Analysis (pure; covered by test_probe_analysis.py) --------------------------
def entry_of(path: list[int], origin: int) -> int | None:
    if origin not in path:
        return None
    i = path.index(origin)
    return path[i - 1] if i > 0 else None


def analyze(*, target_input, target_ip, origin, traces, probe_meta, ipmap, cp_routes,
            warnings, tier, data_scope) -> dict:
    """cp_routes must already be selected by select_as_routes for origin['asn']."""
    origin_asn = origin["asn"]

    # Inferred hop mappings ----------------------------------------------------
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
            "as_loop": len(path) != len(set(path)),
            "mapping_status": "prefix_origin_inference",
        })

    # BGP observations ---------------------------------------------------------
    entry_cp = collections.Counter()
    cp_paths = []
    for r in cp_routes:
        path = r["path"]
        if not path or path[-1] != origin_asn:
            continue  # defensive: callers pass selected routes only
        cp_paths.append({"prefix": r["target_prefix"], "path": path,
                         "raw_path": r.get("raw_path", path), "source_id": r["source_id"]})
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
        if len(keep) >= MAX_GRAPH_NODES:
            break
        if a not in keep:
            keep.append(a)
    keep_set = set(keep)
    if len(depth) > len(keep_set):
        warnings.append(f"The chart shows the {len(keep_set)} busiest of {len(depth)} networks; "
                        "the JSON export retains the underlying path records.")

    nodes = []
    for a in keep:
        roles = []
        if a == origin_asn:
            roles.append("origin")
        if a in entries:
            roles.append("adjacent")
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
            "interpretation": "Observed BGP adjacency or adjacency inferred from hop prefix-origin mappings. "
                              "Neither confirms a provider relationship or a packet path to the perimeter.",
        })
    adjacencies.sort(key=lambda row: (-row["cp_routes"], -row["data_paths"], row["asn"]))
    reached = sum(1 for row in trace_rows if row["reached_origin_as"])
    summary = [f"{len(cp_paths)} retained BGP observations end at the selected origin AS{origin_asn}."]
    if trace_rows:
        summary.append(f"{len(trace_rows)} existing Atlas samples retained; {reached} contain a hop mapped to "
                       f"AS{origin_asn} using current prefix-origin data. This does not establish router ownership or reachability.")
    else:
        summary.append("No traceroutes were retained; this view contains routing observations only. Check source warnings for missing coverage.")
    summary.append("Routing context does not identify the path an observed connection took, confirm a service provider, "
                   "or support an enforcement recommendation.")
    if len(trace_rows) != reached:
        warnings.append(f"{len(trace_rows) - reached} traceroute samples have no hop mapped to AS{origin_asn}. Missing replies, "
                        "incomplete mappings, and source-date differences prevent a reachability conclusion.")

    vantage_rows = []
    for a, v in sorted(vantage.items(), key=lambda kv: (-kv[1]["traces"], kv[0])):
        vantage_rows.append({
            "asn": a or None, "name": None, "traces": v["traces"], "reached": v["reached"],
            "countries": dict(v["countries"]),
            "entries": [{"asn": e, "traces": c} for e, c in v["entries"].most_common()],
        })

    return {
        "meta": {
            "tool": "Múcaro infrastructure explorer",
            "version": VERSION,
            "generated_utc": utc_now(),
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
    if len(order) > MAX_NAME_LOOKUPS:
        result["warnings"].append(f"Organization names were looked up for the first {MAX_NAME_LOOKUPS} of {len(order)} networks.")
    names: dict[int, str] = {}
    for i, a in enumerate(order[:MAX_NAME_LOOKUPS], 1):
        job.check()
        job.set_progress(f"Naming networks ({i} of {min(len(order), MAX_NAME_LOOKUPS)}): AS{a}")
        n = as_name(http, a, job)
        if n:
            names[a] = n
    fill_names(result, names)


def exclusion_warning(excluded: dict) -> str:
    return "Excluded BGP records: " + ", ".join(f"{k}: {v}" for k, v in sorted(excluded.items())) + "."


# --- Job runners ----------------------------------------------------------------
def run_asn_job(job, params, http):
    """Read AS-scoped public evidence without selecting or probing an IP."""
    asn = params["target_asn"]
    resource = f"AS{asn}"
    warnings: list[str] = []
    selected, excluded = [], {}
    source = {"name": "RIPE RIS via RIPEstat", "url": stat_url("bgp-state", resource=resource),
              "query_parameters": {"resource": resource}, "status": "not_requested",
              "observed_at": None, "retrieved_at": None}
    if params["control_plane"]:
        job.say(f"Reading observed BGP routes for {resource}")
        rows, source = read_bgp_state(http, resource, job, warnings)
        if source["status"] in ("available", "partial"):
            selected, excluded = select_as_routes(rows, asn)
            if excluded:
                warnings.append(exclusion_warning(excluded))

    # Existing Atlas results are address-specific samples, not an AS-wide measured path.
    definitions, _ = select_definitions(http, job, warnings, supplied=params["measurement_ids"],
                                        target_ip=None, origin_asn=asn)
    samples, measurement_evidence = load_samples(http, definitions, job, warnings)
    for parsed in samples:
        parsed.update(probe_asn=None, probe_country=None, as_path=[], mapping_status="not_performed",
                      reached_origin_as=None, entry_asn=None,
                      reached_target=any(h["ip"] == parsed["dst"] for h in parsed["hops"]))
        parsed["hops"] = [{**h, "asn": None, "scope": None} for h in parsed["hops"]]

    prefixes = sorted({r["target_prefix"] for r in selected})
    origin = {"asn": asn, "all_asns": [asn], "prefix": None,
              "prefixes": prefixes[:MAX_AS_PREFIXES], "prefix_count": len(prefixes),
              "prefixes_truncated": len(prefixes) > MAX_AS_PREFIXES}
    result = analyze(target_input=params["target_input"], target_ip=None, origin=origin, traces=[],
                     probe_meta={}, ipmap={}, cp_routes=selected, warnings=warnings, tier="public",
                     data_scope="asn_samples" if samples else None)
    for adjacency in result["routing_context"]["adjacencies"]:
        adjacency["interpretation"] = ("Observed immediately before the selected origin in BGP advertisements. "
                                       "Adjacency alone does not establish a provider relationship.")
    result["summary"] = [f"{len(selected)} retained BGP observations for {len(prefixes)} prefixes originated by {resource}.",
                         f"{len(samples)} retained existing Atlas traceroute samples to specific addresses; no new measurements were scheduled."]
    if source["status"] in ("unavailable", "not_requested"):
        result["summary"][0] = "BGP evidence is " + source["status"].replace("_", " ") + "; route and prefix counts are unknown."
        result["meta"]["origin"]["prefix_count"] = None
        result["control_plane"]["routes"] = None
        result["routing_context"]["calculations"]["bgp_fraction"]["denominator"] = None
    result["traces"] = samples
    result["meta"].update(target_kind="asn", target_resource=resource, target_asn=asn,
                          measurement_ids=[e["measurement_id"] for e in measurement_evidence])
    result["control_plane"].update(source=source, excluded_records=excluded, other_origins=[],
                                   distinct_peers=len({r["source_id"] for r in selected})
                                   if source["status"] in ("available", "partial") else None)
    result["measurement_evidence"] = measurement_evidence
    if result["control_plane"]["truncated"]:
        result["warnings"].append(f"Exports retain the first {len(result['control_plane']['paths'])} of {len(selected)} "
                                  "processed BGP path records; summaries and graph counts use all processed records.")
    if len(prefixes) > MAX_AS_PREFIXES:
        result["warnings"].append(f"The prefix list is limited to {MAX_AS_PREFIXES} of {len(prefixes)} observed prefixes.")
    result["methodology"] = ASN_METHODOLOGY
    name_networks(http, job, result, [asn] + [e["asn"] for e in result["routing_context"]["adjacencies"]]
                  + [n["asn"] for n in result["graph"]["nodes"]])
    result["meta"]["requests"] = job.requests
    job.result = result
    job.status = "done"
    job.say("Done")


def run_ip_job(job, params, http):
    warnings: list[str] = []
    tip = params["target_ip"]
    job.say(f"Looking up the AS that announces {tip}")
    info = network_info(http, tip, job)
    if not info["asns"]:
        raise UserError(f"No AS currently announces a prefix covering {tip}, per RIPEstat. "
                        "Check the address, or whether the prefix is withdrawn.")
    origin_asn = info["asns"][0]
    if len(info["asns"]) > 1:
        warnings.append(f"{info['prefix']} is announced by several ASes ({', '.join('AS%d' % a for a in info['asns'])}). "
                        f"This run treats AS{origin_asn} as the selected origin.")
    origin = {"asn": origin_asn, "all_asns": info["asns"], "prefix": info["prefix"]}
    job.say(f"Origin AS{origin_asn}, prefix {info['prefix']}")
    resource = info["prefix"] or tip  # BGP observations for the covering prefix

    # Existing Atlas samples, validated against their own definitions.
    definitions, data_scope = select_definitions(
        http, job, warnings, supplied=params["measurement_ids"],
        target_ip=tip, origin_asn=origin_asn)
    if data_scope == "origin_as":
        warnings.append(f"No public traceroutes target {tip}. Using traceroutes to other addresses Atlas classifies "
                        f"under AS{origin_asn}; samples may not represent the requested target.")
    elif data_scope is None:
        warnings.append("No public Atlas traceroutes were found for this target or its AS. Supply existing "
                        "measurement IDs. No new measurements are scheduled.")
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

    # BGP: keep successful absence separate from failed or unrequested evidence.
    cp_routes, excluded, others = [], {}, []
    cp_source = {"name": "RIPE RIS via RIPEstat", "url": stat_url("bgp-state", resource=resource),
                 "query_parameters": {"resource": resource}, "status": "not_requested",
                 "observed_at": None, "retrieved_at": None}
    if params["control_plane"]:
        job.say(f"Reading BGP observations for {resource}")
        raw_routes, cp_source = read_bgp_state(http, resource, job, warnings)
        if cp_source["status"] in ("available", "partial"):
            cp_routes, excluded = select_as_routes(raw_routes, origin_asn)
            others = other_origins(raw_routes, origin_asn)
            if excluded:
                warnings.append(exclusion_warning(excluded))
            if others:
                shown = "; ".join(f"AS{o['asn']} for {o['prefix']} ({o['peers']} peer{'s' if o['peers'] != 1 else ''})"
                                  for o in others[:5])
                more = f"; {len(others) - 5} more in the export" if len(others) > 5 else ""
                warnings.append(f"BGP records within {resource} end at other origin ASes: {shown}{more}. "
                                "Review whether these are expected.")

    job.say("Analyzing paths")
    result = analyze(target_input=params["target_input"], target_ip=tip, origin=origin,
                     traces=traces, probe_meta=probe_meta, ipmap=ipmap, cp_routes=cp_routes,
                     warnings=warnings, tier=params["tier"], data_scope=data_scope)

    result["meta"].update(target_kind="ip", target_resource=tip, evidence_resource=resource,
                          measurement_ids=[e["measurement_id"] for e in measurement_evidence])
    result["control_plane"].update(source=cp_source, excluded_records=excluded,
                                   other_origins=others[:MAX_OTHER_ORIGINS],
                                   other_origins_truncated=len(others) > MAX_OTHER_ORIGINS,
                                   distinct_peers=len({row["source_id"] for row in cp_routes})
                                   if cp_source["status"] in ("available", "partial") else None)
    result["measurement_evidence"] = measurement_evidence
    if cp_source["status"] in ("unavailable", "not_requested"):
        result["control_plane"]["routes"] = None
        result["summary"][0] = "BGP evidence is " + cp_source["status"].replace("_", " ") + "; route counts are unknown."
        result["routing_context"]["calculations"]["bgp_fraction"]["denominator"] = None
        for row in result["routing_context"]["adjacencies"]:
            row.update(cp_routes=None, cp_share=None)
    if result["control_plane"]["truncated"]:
        result["warnings"].append(f"Exports retain {len(result['control_plane']['paths'])} of {len(cp_routes)} processed "
                                  "BGP path records; summary counts use all processed records.")

    wanted = [origin_asn] + [e["asn"] for e in result["routing_context"]["adjacencies"]]
    wanted += [o["asn"] for o in others[:MAX_OTHER_ORIGINS]]
    wanted += [n["asn"] for n in sorted(result["graph"]["nodes"], key=lambda n: -(n["data"] * 4 + n["cp"]))]
    wanted += [v["asn"] for v in result["vantage"] if v["asn"]]
    name_networks(http, job, result, wanted)
    result["meta"]["requests"] = job.requests
    job.result = result
    job.status = "done"
    job.say("Done")


def run_job(job: Job, params: dict, http: Http) -> None:
    try:
        if params["tier"] != "public":
            raise UserError("Only passive public-data analysis is supported.")
        job.check()
        if params.get("target_asn"):
            run_asn_job(job, params, http)
        else:
            run_ip_job(job, params, http)
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
        job.cache = {}  # responses never outlive the run


# --- HTTP server ----------------------------------------------------------------
INDEX_PATH = Path(__file__).with_name("probe_web") / "index.html"
COQUI_PATH = Path(__file__).with_name("probe_web") / "assets" / "coqui.png"
CSP = ("default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; "
       "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")


class Handler(BaseHTTPRequestHandler):
    server_version = f"MucaroExplorer/{VERSION}"

    def log_message(self, fmt, *args):  # paths only; request bodies are never logged
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
        if path == "/assets/coqui.png":
            try:
                return self._send(200, COQUI_PATH.read_bytes(), "image/png")
            except OSError:
                return self._send(500, {"error": "Missing Coquí artwork."})
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
        if path != "/api/analyze":
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
