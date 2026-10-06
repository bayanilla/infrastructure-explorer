#!/usr/bin/env python3
"""
Múcaro | Pathfinder — Public routing context for IPs and networks

Passive routing context from RIPEstat and existing RIPE Atlas samples. Footprint
mode (a list of IPs and prefixes) is primary; single-IP and ASN lookups give the
same context for one resource. No active measurement scheduling, provider
attribution, or enforcement advice.

Standard library only. Python 3.10+.

    python3 probe_server.py              # http://127.0.0.1:8767
    python3 probe_server.py --port 8768

Investigation inputs remain local except for public-data lookups sent to RIPE.
Footprint mode resolves each entry to its origin ASN and reads RIS-observed
neighbors for the ASNs the analyst confirms.

API keys and active measurements are not accepted. Responses are cached only
within one run, so every run re-reads its sources and retrieval times are true.
"""
from __future__ import annotations

import argparse
import collections
import copy
import csv
import io
import ipaddress
import json
import re
import ssl
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

VERSION = "0.4.0"
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


def verified_ssl_context():
    """Return a certificate-validating HTTPS context.

    Some macOS Python framework installations advertise a CA-file location that
    is absent until their separate certificate-installation helper has run. When
    that happens, use the operating system CA bundle if it is present. This is a
    trust-store fallback, never a bypass: hostname checks and certificate
    validation remain enabled in both cases.
    """
    paths = ssl.get_default_verify_paths()
    default_bundle = Path(paths.cafile) if paths.cafile else None
    system_bundle = Path("/etc/ssl/cert.pem")
    if default_bundle is not None and default_bundle.is_file():
        return ssl.create_default_context()
    if system_bundle.is_file():
        return ssl.create_default_context(cafile=str(system_bundle))
    return ssl.create_default_context()


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
        self._ssl_context = verified_ssl_context()
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
                    with urllib.request.urlopen(req, timeout=timeout, context=self._ssl_context) as resp:
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
        self.finished: float | None = None
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
    """Retention counts from when a job finished. Running jobs are never evicted."""
    now = time.time()
    with JOBS_LOCK:
        for jid in [k for k, j in JOBS.items()
                    if j.status != "running" and now - (j.finished or j.created) > JOB_TTL_SECONDS]:
            del JOBS[jid]
        running = sum(1 for j in JOBS.values() if j.status == "running")
        if running >= 2:
            raise UserError("Two analyses are already running. Wait for one to finish or cancel it.")
        while len(JOBS) >= MAX_JOBS:
            idle = [j for j in JOBS.values() if j.status != "running"]
            if not idle:
                break
            oldest = min(idle, key=lambda j: j.finished or j.created)
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
            "tool": "Múcaro | Pathfinder",
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


def _guarded(job: Job, work) -> None:
    """Run a job body; translate failures into job state. Caches never outlive the run."""
    try:
        work()
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
        job.cache = {}
        job.finished = time.time()


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


# --- Footprint: IP/prefix list -> origin ASNs -> observed BGP adjacency -----------
#
# Input is an analyst's external footprint (for example an Expanse export reduced to
# one column of IPs and prefixes). Pathfinder resolves each entry to the announced
# prefix and origin ASN that public routing data shows for it, lets the analyst
# confirm which origin ASNs are theirs, then reads RIS-observed neighbors for those
# ASNs only. Nothing is ranked, flagged or interpreted; every count keeps RIPE's own
# field name and documented meaning.

MAX_UPLOAD_BYTES = 1024 * 1024
MAX_FOOTPRINT_ROWS = 5000
MAX_REJECTED_LISTED = 500
MAX_RESOLVE_LOOKUPS = 2500
MAX_RANGE_EXPANSION = 100
MAX_CONFIRMED_ASNS = 50
MAX_NEIGHBORS_PER_ASN = 5000
MAX_FOOTPRINT_NAMES = 150
MAX_INPUTS_PER_ORIGIN = 200
MIN_PREFIXLEN = {4: 8, 6: 16}
_THRESHOLD = re.compile(r"min peers:\s*(\d+)", re.I)

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


def _parse_footprint_value(value: str):
    """Return (entry, reason, syntax_ok). entry is None when the value is rejected."""
    if len(value) > 64:
        return None, "Too long to be an IP address or prefix.", False
    if re.fullmatch(r"[0-9A-Fa-f:.]+\s*-\s*[0-9A-Fa-f:.]+", value):
        return None, "Start-end ranges aren't supported. Use CIDR notation.", True
    note = None
    try:
        if "/" in value:
            try:
                net = ipaddress.ip_network(value, strict=True)
            except ValueError:
                net = ipaddress.ip_network(value, strict=False)
                note = f"Host bits set in {value}; normalized to {net}."
            if net.prefixlen == net.max_prefixlen:
                addr, kind = net.network_address, "ip"
            else:
                if net.prefixlen < MIN_PREFIXLEN[net.version]:
                    return None, (f"/{net.prefixlen} is broader than this tool resolves "
                                  f"(minimum /{MIN_PREFIXLEN[net.version]} for IPv{net.version})."), True
                if not net.is_global:
                    return None, f"{net} is special-use or private address space.", True
                return {"value": str(net), "kind": "prefix", "note": note}, None, True
        else:
            addr, kind = ipaddress.ip_address(value), "ip"
    except ValueError:
        return None, "Not an IP address or CIDR prefix.", False
    if not addr.is_global:
        return None, f"{addr} is special-use or private address space.", True
    return {"value": str(addr), "kind": kind, "note": note}, None, True


def parse_footprint(text) -> dict:
    """Parse a one-column CSV or text list of IPs and prefixes.

    Reads the first non-empty cell of each row. Blank rows and rows starting with '#'
    are skipped. The first content row is treated as a header only if it isn't an
    address or prefix at all. Exact duplicates (after normalization) are counted and
    dropped; overlapping entries are kept, because each is a distinct input.
    """
    if not isinstance(text, str) or not text.strip():
        raise UserError("The file is empty. Upload a CSV or text file with one IP or prefix per row.")
    if "\x00" in text:
        raise UserError("The file contains binary data. Upload a CSV or plain-text list.")
    entries, rejected, seen = [], [], set()
    duplicates = rows = rejected_total = 0
    header = None
    first = True
    reader = csv.reader(io.StringIO(text.lstrip("﻿")))
    try:
        for row in reader:
            value = next((c.strip().strip('"\'').strip() for c in row if c.strip().strip('"\'').strip()), "")
            if not value or value.startswith("#"):
                continue
            rows += 1
            entry, reason, syntax_ok = _parse_footprint_value(value)
            if first and entry is None and not syntax_ok:
                header = value[:64]
                first = False
                continue
            first = False
            if entry is None:
                rejected_total += 1
                if len(rejected) < MAX_REJECTED_LISTED:
                    rejected.append({"line": reader.line_num, "value": value[:80], "reason": reason})
                continue
            if entry["value"] in seen:
                duplicates += 1
                continue
            seen.add(entry["value"])
            entry["line"] = reader.line_num
            entries.append(entry)
            if len(entries) > MAX_FOOTPRINT_ROWS:
                raise UserError(f"The file has more than {MAX_FOOTPRINT_ROWS} distinct entries. Split it into smaller files.")
    except csv.Error as e:
        raise UserError(f"The file couldn't be read as CSV near line {reader.line_num}: {e}.") from None
    if not entries:
        detail = f" First problem: line {rejected[0]['line']}, {rejected[0]['reason']}" if rejected else ""
        raise UserError(f"No usable IPs or prefixes were found ({rejected_total} rows rejected).{detail}")
    return {"rows_read": rows, "header": header, "accepted": len(entries), "duplicates": duplicates,
            "rejected_total": rejected_total, "rejected": rejected,
            "rejected_truncated": rejected_total > len(rejected), "entries": entries}


def parse_keywords(raw) -> list[str]:
    words = []
    for w in re.split(r"[,;\n]+", str(raw or "")):
        w = w.strip().lower()
        if len(w) >= 3 and w not in words:
            words.append(w[:60])
    return words[:10]


def validate_footprint_request(body) -> dict:
    if not isinstance(body, dict):
        raise UserError("Request body must be a JSON object.")
    if not isinstance(body.get("include_low_visibility", False), bool):
        raise UserError("include_low_visibility must be true or false.")
    return {"parsed": parse_footprint(body.get("csv")),
            "keywords": parse_keywords(body.get("org_keywords")),
            "include_low_visibility": body.get("include_low_visibility", False)}


def _overview(resp) -> dict:
    data = resp.get("data") if isinstance(resp, dict) else None
    if not isinstance(data, dict):
        raise UserError("RIPE returned an unsupported prefix-overview response.")
    asns = []
    for a in data.get("asns") or []:
        if isinstance(a, dict) and isinstance(a.get("asn"), int) and not isinstance(a.get("asn"), bool):
            asns.append({"asn": a["asn"], "holder": a["holder"] if isinstance(a.get("holder"), str) else None})
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
    return {"announced": data.get("announced") is True, "asns": asns, "resource": resource,
            "less_specific": data.get("is_less_specific") is True, "related": related,
            "related_total": max(total, len(related)),
            "filtered": filtered if isinstance(filtered, int) and not isinstance(filtered, bool) else 0,
            "query_time": data.get("query_time") if isinstance(data.get("query_time"), str) else None,
            "messages": messages}


class _LookupBudget(Exception):
    pass


def resolve_footprint(http, job, entries, min_peers, warnings):
    """Resolve each entry to covering announcement(s) and origin ASN(s).

    Returns (results aligned with entries, stats).
    """
    nets = [ipaddress.ip_network(e["value"]) for e in entries]
    order = sorted(range(len(entries)), key=lambda i: (nets[i].version, int(nets[i].network_address), nets[i].prefixlen))
    results: list = [None] * len(entries)
    known: list[dict] = []
    learned: set[str] = set()
    stats = {"lookups": 0, "reused": 0, "filtered_routes": 0, "lookups_with_filtering": 0,
             "query_times": set(), "messages": collections.Counter(), "thresholds": set()}

    def lookup(resource: str) -> dict:
        if stats["lookups"] >= MAX_RESOLVE_LOOKUPS:
            raise _LookupBudget()
        stats["lookups"] += 1
        q = {"resource": resource}
        if min_peers is not None:
            q["min_peers_seeing"] = str(min_peers)
        ov = _overview(http.get_json(stat_url("prefix-overview", **q), job=job))
        if ov["query_time"]:
            stats["query_times"].add(ov["query_time"])
        for m in ov["messages"]:
            match = _THRESHOLD.search(m)
            if match:
                stats["thresholds"].add(int(match.group(1)))
            stats["messages"][re.sub(r"\d+", "N", m)] += 1
        if ov["filtered"]:
            stats["filtered_routes"] += ov["filtered"]
            stats["lookups_with_filtering"] += 1
        return ov

    def learn(ov):
        res = ov["resource"]
        if ov["announced"] and ov["asns"] and res is not None and not ov["less_specific"] and str(res) not in learned:
            learned.add(str(res))
            known.append({"net": res, "asns": ov["asns"],
                          "more_specifics": [r for r in ov["related"] if r.version == res.version and r != res and r.subnet_of(res)],
                          "complete": ov["related_total"] <= len(ov["related"])})

    def reusable(net):
        for k in known:
            if (k["complete"] and net.version == k["net"].version and net.subnet_of(k["net"])
                    and not any(net.overlaps(m) for m in k["more_specifics"])):
                return k
        return None

    def resolve_part(prefix):
        k = reusable(prefix)
        if k is not None:
            stats["reused"] += 1
            return {"prefix": str(prefix), "covering_prefix": str(k["net"]), "origins": k["asns"], "method": "reused"}
        ov = lookup(str(prefix))
        learn(ov)
        if ov["announced"] and ov["asns"]:
            return {"prefix": str(prefix), "covering_prefix": str(ov["resource"]), "origins": ov["asns"], "method": "queried"}
        return {"prefix": str(prefix), "covering_prefix": None, "origins": [], "method": "queried"}

    budget_hit = 0
    for pos, i in enumerate(order, 1):
        job.check()
        e, net = entries[i], nets[i]
        job.set_progress(f"Resolving {pos} of {len(entries)} · {stats['lookups']} RIPE lookups so far")
        base = {"input": e["value"], "kind": e["kind"], "line": e.get("line"), "covering_prefix": None,
                "origins": [], "more_specifics": [], "more_specifics_total": 0,
                "more_specifics_truncated": False, "method": None, "filtered_routes": 0, "error": None}
        k = reusable(net)
        if k is not None:
            stats["reused"] += 1
            results[i] = {**base, "status": "announced", "covering_prefix": str(k["net"]),
                          "origins": k["asns"], "method": "reused"}
            continue
        try:
            ov = lookup(e["value"])
        except _LookupBudget:
            budget_hit += 1
            results[i] = {**base, "status": "not_resolved"}
            continue
        except (ApiError, UserError) as err:
            results[i] = {**base, "status": "lookup_failed", "error": str(getattr(err, "detail", err))[:300]}
            continue
        learn(ov)
        row = {**base, "method": "queried", "filtered_routes": ov["filtered"]}
        if ov["announced"] and ov["asns"]:
            row.update(status="announced", covering_prefix=str(ov["resource"]) if ov["resource"] else None,
                       origins=ov["asns"])
        else:
            row.update(status="not_announced")
        if e["kind"] == "prefix":
            parts = [r for r in ov["related"] if r.version == net.version and r != net and r.subnet_of(net)]
            row["more_specifics_total"] = len(parts)
            row["more_specifics_truncated"] = ov["related_total"] > len(ov["related"]) or len(parts) > MAX_RANGE_EXPANSION
            for part in parts[:MAX_RANGE_EXPANSION]:
                job.check()
                try:
                    row["more_specifics"].append(resolve_part(part))
                except _LookupBudget:
                    row["more_specifics_truncated"] = True
                    budget_hit += 1
                    break
                except (ApiError, UserError) as err:
                    row["more_specifics"].append({"prefix": str(part), "covering_prefix": None, "origins": [],
                                                  "method": "queried", "error": str(getattr(err, "detail", err))[:300]})
            if row["status"] == "not_announced" and any(p["origins"] for p in row["more_specifics"]):
                row["status"] = "partially_announced"
        results[i] = row
        # Read a covering prefix directly when it will serve at least two more entries.
        cov = ov["resource"] if ov["announced"] and ov["less_specific"] else None
        if cov is not None and str(cov) not in learned:
            pending = sum(1 for j in order[pos:] if nets[j].version == cov.version and nets[j].subnet_of(cov))
            if pending >= 2:
                try:
                    learn(lookup(str(cov)))
                except (_LookupBudget, ApiError, UserError):
                    pass
    if budget_hit:
        warnings.append(f"The run reached its limit of {MAX_RESOLVE_LOOKUPS} RIPE lookups. {budget_hit} entr"
                        f"{'y was' if budget_hit == 1 else 'ies were'} not fully resolved; split the file to resolve the rest.")
    return results, stats


def mapped_asns(row) -> list[int]:
    out = [o["asn"] for o in row["origins"]]
    for part in row["more_specifics"]:
        out += [o["asn"] for o in part["origins"]]
    return list(dict.fromkeys(out))


def group_origins(results, keywords) -> list[dict]:
    groups: dict[int, dict] = {}
    total = len(results)
    for row in results:
        asns = mapped_asns(row)
        multi = len(row["origins"]) > 1
        prefix_by_asn = collections.defaultdict(set)
        for o in row["origins"]:
            if row["covering_prefix"]:
                prefix_by_asn[o["asn"]].add(row["covering_prefix"])
        holders = {o["asn"]: o["holder"] for o in row["origins"]}
        for part in row["more_specifics"]:
            for o in part["origins"]:
                prefix_by_asn[o["asn"]].add(part["covering_prefix"] or part["prefix"])
                holders.setdefault(o["asn"], o["holder"])
        for a in asns:
            g = groups.setdefault(a, {"asn": a, "holder": None, "entries": 0, "inputs": [], "prefixes": set(),
                                      "multi_origin_entries": 0})
            g["holder"] = g["holder"] or holders.get(a)
            g["entries"] += 1
            if len(g["inputs"]) < MAX_INPUTS_PER_ORIGIN:
                g["inputs"].append(row["input"])
            g["prefixes"] |= prefix_by_asn.get(a, set())
            g["multi_origin_entries"] += 1 if multi else 0
    out = []
    for g in groups.values():
        holder = (g["holder"] or "").lower()
        match = next((k for k in keywords if k in holder), None)
        out.append({**g, "prefixes": sorted(g["prefixes"], key=lambda p: (":" in p, p)),
                    "share": round(g["entries"] / total, 4) if total else None,
                    "inputs_truncated": g["entries"] > len(g["inputs"]),
                    "default_selected": match is not None, "matched_keyword": match})
    out.sort(key=lambda g: (-g["entries"], g["asn"]))
    return out


def run_footprint_resolution(job, params, http):
    parsed, keywords = params["parsed"], params["keywords"]
    min_peers = 1 if params["include_low_visibility"] else None
    entries = parsed["entries"]
    warnings: list[str] = []
    job.say(f"{parsed['accepted']} entries accepted, {parsed['duplicates']} duplicates removed, "
            f"{parsed['rejected_total']} rows rejected")
    results, stats = resolve_footprint(http, job, entries, min_peers, warnings)
    origins = group_origins(results, keywords)
    counts = collections.Counter(r["status"] for r in results)
    threshold = sorted(stats["thresholds"])
    if stats["filtered_routes"]:
        warnings.append(
            f"RIPE left out {stats['filtered_routes']} low-visibility route(s) across {stats['lookups_with_filtering']} "
            f"lookup(s) (minimum RIS peers: {', '.join(map(str, threshold)) or 'not reported'}). They are not in this "
            "resolution. Run again with low-visibility routes included to see them.")
    truncated = sum(1 for r in results if r["more_specifics_truncated"])
    if truncated:
        warnings.append(f"{truncated} prefix entr{'y lists' if truncated == 1 else 'ies list'} more-specific "
                        f"announcements beyond what was resolved (RIPE truncation or the {MAX_RANGE_EXPANSION}-per-entry limit).")
    if counts.get("lookup_failed"):
        warnings.append(f"{counts['lookup_failed']} entr{'y' if counts['lookup_failed'] == 1 else 'ies'} could not be "
                        "looked up. They are listed with the error RIPE returned.")
    multi = sum(1 for r in results if len(r["origins"]) > 1)
    if multi:
        warnings.append(f"{multi} entr{'y is' if multi == 1 else 'ies are'} covered by a prefix announced by more than one origin ASN. "
                        "Each origin is listed.")
    job.result = {
        "kind": "footprint_resolution",
        "meta": {"tool": "Múcaro | Pathfinder", "version": VERSION, "generated_utc": utc_now(), "job_id": job.id},
        "settings": {"org_keywords": keywords, "include_low_visibility": params["include_low_visibility"],
                     "visibility_threshold": 1 if min_peers else (threshold[0] if len(threshold) == 1 else None),
                     "visibility_threshold_note": ("min_peers_seeing=1 was requested." if min_peers else
                                                   "RIPEstat default; the value is taken from RIPE's response messages.")},
        "inputs": {k: parsed[k] for k in ("rows_read", "header", "accepted", "duplicates", "rejected_total",
                                          "rejected", "rejected_truncated", "entries")},
        "resolution": results,
        "status_counts": dict(counts),
        "origins": origins,
        "sources": {"prefix_overview": {"name": "RIPEstat prefix-overview",
                                        "url": stat_url("prefix-overview", resource="{entry}"),
                                        "lookups": stats["lookups"], "reused": stats["reused"],
                                        "query_times": sorted(stats["query_times"]),
                                        "filtered_routes": stats["filtered_routes"],
                                        "messages": [{"message": m, "count": c} for m, c in stats["messages"].most_common(50)]}},
        "warnings": warnings,
        "requests": job.requests,
    }
    job.status = "done"
    job.say(f"Resolved to {len(origins)} origin ASNs with {stats['lookups']} lookups ({stats['reused']} reused)")


def _count(v) -> bool:
    return isinstance(v, int) and not isinstance(v, bool) and v >= 0


def read_neighbors(http, asn, job) -> dict:
    url = stat_url("asn-neighbours", resource=f"AS{asn}")
    source = {"name": "RIPEstat ASN Neighbors", "url": url, "status": "unavailable", "retrieved_at": None,
              "query_starttime": None, "query_endtime": None, "latest_time": None, "version": None,
              "messages": [], "neighbor_counts": None, "excluded": 0, "truncated": False}
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
        if (isinstance(n, dict) and _count(n.get("asn")) and 1 <= n["asn"] <= 4294967295
                and n.get("type") in ("left", "right", "uncertain")
                and all(_count(n.get(k)) for k in ("power", "v4_peers", "v6_peers"))):
            out.append({"asn": n["asn"], "type": n["type"], "power": n["power"],
                        "v4_peers": n["v4_peers"], "v6_peers": n["v6_peers"]})
        else:
            source["excluded"] += 1
    source.update(status="available", retrieved_at=utc_now(), version=resp.get("version"),
                  query_starttime=data.get("query_starttime"), query_endtime=data.get("query_endtime"),
                  latest_time=data.get("latest_time"),
                  neighbor_counts=data.get("neighbour_counts") if isinstance(data.get("neighbour_counts"), dict) else None,
                  messages=[m[1][:300] for m in resp.get("messages") or []
                            if isinstance(m, (list, tuple)) and len(m) == 2 and isinstance(m[1], str)])
    if len(out) > MAX_NEIGHBORS_PER_ASN:
        source["truncated"] = True
        out = out[:MAX_NEIGHBORS_PER_ASN]
    out.sort(key=lambda n: (n["asn"], n["type"]))
    return {"source": source, "neighbors": out}


def aggregate_neighbors(per_asn, confirmed) -> list[dict]:
    rows: dict[int, dict] = {}
    for entry in per_asn:
        for n in entry["neighbors"]:
            r = rows.setdefault(n["asn"], {"asn": n["asn"], "name": None, "relations": [],
                                           "is_confirmed_asn": n["asn"] in confirmed})
            r["relations"].append({"your_asn": entry["asn"], "type": n["type"], "power": n["power"],
                                   "v4_peers": n["v4_peers"], "v6_peers": n["v6_peers"]})
    out = []
    for r in rows.values():
        rel = r["relations"]
        out.append({**r, "your_asn_count": len({x["your_asn"] for x in rel}),
                    "positions": sorted({x["type"] for x in rel}),
                    "max_power": max(x["power"] for x in rel),
                    "max_v4_peers": max(x["v4_peers"] for x in rel),
                    "max_v6_peers": max(x["v6_peers"] for x in rel)})
    out.sort(key=lambda r: (-r["your_asn_count"], -(r["max_v4_peers"] + r["max_v6_peers"]), r["asn"]))
    return out


def validate_adjacency_request(body) -> dict:
    if not isinstance(body, dict):
        raise UserError("Request body must be a JSON object.")
    jid = body.get("resolution_job")
    if not isinstance(jid, str) or not re.fullmatch(r"[0-9a-f]{32}", jid):
        raise UserError("Missing resolution reference. Resolve the footprint again.")
    with JOBS_LOCK:
        job = JOBS.get(jid)
    if job is None or job.status != "done" or not isinstance(job.result, dict) \
            or job.result.get("kind") != "footprint_resolution":
        raise UserError("That resolution has expired or didn't finish. Upload the file again to resolve it.")
    available = {o["asn"] for o in job.result["origins"]}
    raw = body.get("asns")
    if not isinstance(raw, list) or not raw:
        raise UserError("Select at least one origin ASN as yours.")
    asns = []
    for a in raw:
        m = _ASN_TOKEN.fullmatch(str(a).strip()) if isinstance(a, (str, int)) and not isinstance(a, bool) else None
        if not m or int(m.group(1)) not in available:
            raise UserError(f"{str(a)[:20]} isn't one of the origin ASNs in this resolution.")
        if int(m.group(1)) not in asns:
            asns.append(int(m.group(1)))
    if len(asns) > MAX_CONFIRMED_ASNS:
        raise UserError(f"Select at most {MAX_CONFIRMED_ASNS} ASNs per run.")
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
            warnings.append(f"Neighbor data for AS{asn} is unavailable ({got['source'].get('error') or 'no detail'}). "
                            "Its neighbors are unknown, not absent.")
        if got["source"]["excluded"]:
            warnings.append(f"{got['source']['excluded']} malformed neighbor record(s) for AS{asn} were excluded.")
        if got["source"]["truncated"]:
            warnings.append(f"AS{asn} has more than {MAX_NEIGHBORS_PER_ASN} neighbors; the record keeps the first "
                            f"{MAX_NEIGHBORS_PER_ASN} by ASN.")
    neighbors = aggregate_neighbors(per_asn, set(confirmed))
    names = {a: h for a, h in holders.items() if h}
    wanted = [n["asn"] for n in neighbors if n["asn"] not in names and public_asn(n["asn"])]
    if len(wanted) > MAX_FOOTPRINT_NAMES:
        warnings.append(f"Holder names were looked up for {MAX_FOOTPRINT_NAMES} of {len(wanted)} neighbors, in table "
                        "order; the rest show the ASN only.")
    for i, a in enumerate(wanted[:MAX_FOOTPRINT_NAMES], 1):
        job.check()
        job.set_progress(f"Naming neighbors ({i} of {min(len(wanted), MAX_FOOTPRINT_NAMES)}): AS{a}")
        name = as_name(http, a, job)
        if name:
            names[a] = name
    for n in neighbors:
        n["name"] = names.get(n["asn"])
    available = [p for p in per_asn if p["source"]["status"] == "available"]
    times = sorted({p["source"]["query_starttime"] for p in available if p["source"]["query_starttime"]})
    shared = sum(1 for n in neighbors if n["your_asn_count"] > 1)
    summary = [f"{resolution['inputs']['accepted']} footprint entries map to {len(resolution['origins'])} origin "
               f"ASN{'s' if len(resolution['origins']) != 1 else ''}; {len(confirmed)} confirmed as yours.",
               f"RIS observes {len(neighbors)} distinct network{'s' if len(neighbors) != 1 else ''} adjacent to the "
               f"confirmed ASNs" + (f" (RIPEstat ASN Neighbors, {', '.join(times)})." if times else ".")]
    if shared:
        summary.append(f"{shared} of them {'is' if shared == 1 else 'are'} adjacent to more than one confirmed ASN.")
    if len(available) != len(per_asn):
        summary.append(f"Neighbor data is unavailable for {len(per_asn) - len(available)} confirmed ASN(s).")
    summary.append("Adjacency is observed BGP position. It does not establish a business relationship, traffic share, "
                   "ownership or intent.")
    origins = [{**o, "confirmed": o["asn"] in confirmed} for o in resolution["origins"]]
    job.result = {
        "kind": "footprint_run",
        "meta": {"tool": "Múcaro | Pathfinder", "version": VERSION, "generated_utc": utc_now(),
                 "resolution_generated_utc": resolution["meta"]["generated_utc"]},
        "settings": resolution["settings"],
        "inputs": resolution["inputs"],
        "resolution": resolution["resolution"],
        "status_counts": resolution["status_counts"],
        "origins": origins,
        "confirmed_asns": confirmed,
        "adjacency": {"per_asn": per_asn, "neighbors": neighbors, "field_definitions": FOOTPRINT_FIELDS},
        "sources": {**resolution["sources"],
                    "asn_neighbors": {"name": "RIPEstat ASN Neighbors",
                                       "url": stat_url("asn-neighbours", resource="AS{asn}"),
                                       "query_times": times}},
        "summary": summary,
        "warnings": warnings,
        "methodology": FOOTPRINT_METHODOLOGY,
        "requests": {"resolution": resolution["requests"], "adjacency": job.requests},
    }
    job.status = "done"
    job.say("Done")


# --- HTTP server ----------------------------------------------------------------
INDEX_PATH = Path(__file__).with_name("probe_web") / "index.html"
COQUI_PATH = Path(__file__).with_name("probe_web") / "assets" / "coqui.png"
FAVICON_PATH = Path(__file__).with_name("probe_web") / "assets" / "mucaro-mark.svg"
CSP = ("default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; "
       "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")


class Handler(BaseHTTPRequestHandler):
    server_version = f"MucaroPathfinder/{VERSION}"

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

    def _discard(self, length: int) -> None:
        """Read and drop an oversized body so the client receives the 413 instead of a reset."""
        remaining = min(max(length, 0), 16 * 1024 * 1024)
        while remaining > 0:
            chunk = self.rfile.read(min(65536, remaining))
            if not chunk:
                break
            remaining -= len(chunk)

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
        if path == "/assets/mucaro-mark.svg":
            try:
                return self._send(200, FAVICON_PATH.read_bytes(), "image/svg+xml")
            except OSError:
                return self._send(500, {"error": "Missing Múcaro favicon."})
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
        routes = {
            "/api/analyze": (MAX_BODY_BYTES, validate_request, run_job),
            "/api/footprint/resolve": (MAX_UPLOAD_BYTES + MAX_BODY_BYTES, validate_footprint_request,
                                       lambda job, params, http: _guarded(job, lambda: run_footprint_resolution(job, params, http))),
            "/api/footprint/adjacency": (MAX_BODY_BYTES, validate_adjacency_request,
                                         lambda job, params, http: _guarded(job, lambda: run_footprint_adjacency(job, params, http))),
        }
        if path not in routes:
            return self._send(404, {"error": "Not found"})
        limit, validate, runner = routes[path]
        if not (self.headers.get("Content-Type", "").split(";")[0].strip() == "application/json"):
            return self._send(415, {"error": "Send JSON."})
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = 0
        if length <= 0 or length > limit:
            self._discard(length)
            return self._send(413, {"error": "The upload is empty or larger than 1 MB." if path == "/api/footprint/resolve"
                                    else "Request body is empty or too large."})
        try:
            body = json.loads(self.rfile.read(length).decode("utf-8"))
            params = validate(body)
            job = register_job()
        except UserError as e:
            return self._send(400, {"error": str(e)})
        except (json.JSONDecodeError, UnicodeDecodeError):
            return self._send(400, {"error": "Request body isn't valid JSON."})
        threading.Thread(target=runner, args=(job, params, self.server.http), daemon=True).start()
        return self._send(202, {"job_id": job.id})


def main() -> None:
    ap = argparse.ArgumentParser(description="Múcaro | Pathfinder: public routing context for IPs and networks")
    ap.add_argument("--port", type=int, default=DEFAULT_PORT)
    ap.add_argument("--pause", type=float, default=2.0,
                    help="seconds between RIPE requests (minimum 2.0)")
    args = ap.parse_args()
    server = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    server.allowed_hosts = {f"127.0.0.1:{args.port}", f"localhost:{args.port}"}
    server.http = Http(pause=max(2.0, args.pause))
    print(f"Pathfinder {VERSION} on http://127.0.0.1:{args.port}  (Ctrl+C to stop)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
