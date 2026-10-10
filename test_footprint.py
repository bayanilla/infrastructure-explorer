"""Footprint mode: CSV parsing, origin resolution, confirmation and adjacency.

Every RIPE response is a fixture shaped like live RIPEstat output (prefix-overview
alignment to the covering prefix, plain-string related_prefixes, low-visibility
filtering, asn-neighbours fields). No network access.

    python3 -m unittest test_footprint -v
"""

import copy
import ipaddress
import json
import threading
import time
import unittest
import urllib.parse
import urllib.request
from http.server import ThreadingHTTPServer
from unittest.mock import patch

import test_support as ps

OWN_A, OWN_B, HOSTING, CLOUD, CDN_A, CDN_B, OTHER = 3333, 5555, 4200, 16509, 13335, 209242, 7000

ANNOUNCED = [
    ("193.0.0.0/21", [OWN_A], "EXAMPLE-ORG-NET Example Org Site A"),
    ("193.0.4.0/24", [HOSTING], "HOSTCO Hosting Provider"),  # more-specific inside 193.0.0.0/21
    ("46.20.0.0/22", [OWN_A], "EXAMPLE-ORG-NET Example Org Site A"),
    ("81.10.0.0/20", [OWN_B], "EXAMPLE-ORG-EU Example Org Site B"),
    ("52.0.0.0/16", [CLOUD], "AMAZON-02"),
    ("104.16.0.0/20", [CDN_A, CDN_B], "CDN Edge"),  # multiple origins
    ("62.0.1.0/24", [OWN_B], "EXAMPLE-ORG-EU Example Org Site B"),  # 62.0.0.0/16 itself is not announced
    ("62.0.2.0/24", [OTHER], "TRANSITCO Transit"),
]
LOW_VISIBILITY = [("81.10.8.0/24", [64999], "LEAKY Leaked Route")]  # seen only below the default threshold

NEIGHBORS = {
    OWN_A: [
        {"asn": 1299, "type": "left", "power": 120, "v4_peers": 900, "v6_peers": 0},
        {"asn": 174, "type": "left", "power": 40, "v4_peers": 300, "v6_peers": 0},
        {"asn": OWN_B, "type": "right", "power": 5, "v4_peers": 12, "v6_peers": 0},
    ],
    OWN_B: [
        {"asn": 1299, "type": "left", "power": 80, "v4_peers": 500, "v6_peers": 20},
        {"asn": 64999, "type": "uncertain", "power": 1, "v4_peers": 1, "v6_peers": 0},
        {"asn": "x", "type": "left", "power": 1, "v4_peers": 1, "v6_peers": 0},
    ],
    CLOUD: [
        {"asn": n, "type": "right", "power": 1, "v4_peers": 1, "v6_peers": 0} for n in range(60000, 60020)
    ],
}


def net(p):
    return ipaddress.ip_network(p, strict=False)


class FakeRipe:
    def __init__(self):
        self.urls = []
        self.count = 0
        self.max_related = 100
        self.fail_resources = set()
        self.fail_neighbors = set()
        self.holders = {}

    def table(self, min_peers):
        return ANNOUNCED + (LOW_VISIBILITY if min_peers == "1" else [])

    def prefix_overview(self, resource, min_peers):
        if resource in self.fail_resources:
            raise ps.ApiError(503, "fixture outage", "prefix-overview")
        q = net(resource)
        table = self.table(min_peers)
        hidden = [p for p, _, _ in LOW_VISIBILITY if min_peers != "1"]
        exact = next(((p, a, h) for p, a, h in table if net(p) == q), None)
        covering = sorted(
            [
                (p, a, h)
                for p, a, h in table
                if q.version == net(p).version and q.subnet_of(net(p)) and net(p) != q
            ],
            key=lambda x: -net(x[0]).prefixlen,
        )
        hit = exact or (covering[0] if covering else None)
        base = net(hit[0]) if exact else q
        related = [
            p
            for p, _, _ in table
            if net(p).version == base.version
            and net(p) != base
            and (net(p).subnet_of(base) or base.subnet_of(net(p)))
        ]
        filtered = sum(1 for p in hidden if net(p).version == q.version and (net(p).overlaps(q)))
        messages = []
        if filtered:
            messages.append(
                ["info", f"{filtered} routes were filtered due to low visibility (min peers:10)."]
            )
        data = {
            "is_less_specific": bool(hit) and not exact,
            "announced": bool(hit),
            "asns": [{"asn": a, "holder": self.holders.get(a, hit[2])} for a in hit[1]] if hit else [],
            "related_prefixes": related[: self.max_related],
            "resource": hit[0] if hit else str(q),
            "actual_num_related": len(related),
            "query_time": "2026-10-04T08:00:00",
            "num_filtered_out": filtered,
        }
        return {"messages": messages, "data": data, "status": "ok"}

    def get_json(self, url, cache=True, job=None, timeout=45):
        self.count += 1
        self.urls.append(url)
        if job is not None:
            job.requests += 1
        u = urllib.parse.urlsplit(url)
        q = dict(urllib.parse.parse_qsl(u.query))
        if "prefix-overview" in u.path:
            return self.prefix_overview(q["resource"], q.get("min_peers_seeing"))
        if "asn-neighbours" in u.path:
            asn = int(q["resource"][2:])
            if asn in self.fail_neighbors:
                raise ps.ApiError(503, "fixture neighbor outage", url)
            return {
                "version": "3.2",
                "messages": [["info", "Query time has been set to the latest available time"]],
                "data": {
                    "resource": str(asn),
                    "query_starttime": "2026-10-04T00:00:00",
                    "query_endtime": "2026-10-04T00:00:00",
                    "latest_time": "2026-10-04T00:00:00",
                    "neighbour_counts": {"left": 1, "right": 0, "unique": 1, "uncertain": 0},
                    "neighbours": copy.deepcopy(NEIGHBORS.get(asn, [])),
                },
            }
        if "as-overview" in u.path:
            return {"data": {"holder": f"Holder {q['resource']}"}}
        raise AssertionError(f"unexpected GET {url}")

    def queried(self, endpoint="prefix-overview"):
        return [
            dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(u).query))["resource"]
            for u in self.urls
            if f"/{endpoint}/" in u
        ]


def resolve(text, http=None, keywords="", low_visibility=False):
    http = http or FakeRipe()
    job = ps.Job()
    params = ps.validate_footprint_request(
        {"csv": text, "org_keywords": keywords, "include_low_visibility": low_visibility}
    )
    ps._guarded(job, lambda: ps.run_footprint_resolution(job, params, http))
    return job, http


def by_input(result):
    return {r["input"]: r for r in result["resolution"]}


class Parsing(unittest.TestCase):
    def test_header_bom_quotes_comments_and_line_numbers(self):
        text = '﻿ip_or_cidr\r\n"193.0.1.1"\r\n\r\n# comment\r\n 46.20.0.0/22 ,ignored\r\n'
        p = ps.parse_footprint(text)
        self.assertEqual(p["header"], "ip_or_cidr")
        self.assertEqual(
            [(e["value"], e["kind"], e["line"]) for e in p["entries"]],
            [("193.0.1.1", "ip", 2), ("46.20.0.0/22", "prefix", 5)],
        )
        self.assertEqual(p["rows_read"], 3)

    def test_normalization_and_duplicates(self):
        p = ps.parse_footprint(
            "193.0.1.1\n193.0.1.1/32\n193.0.6.7/24\n193.0.6.0/24\n2001:67C:2E8::1\n2001:67c:2e8::1\n"
        )
        self.assertEqual([e["value"] for e in p["entries"]], ["193.0.1.1", "193.0.6.0/24", "2001:67c:2e8::1"])
        self.assertEqual(p["duplicates"], 3)
        self.assertIn("normalized to 193.0.6.0/24", p["entries"][1]["note"])

    def test_rejections_are_listed_with_reasons(self):
        p = ps.parse_footprint(
            "193.0.1.1\n10.0.0.1\n2001:db8::1\nnot-an-ip\n1.2.3.4-1.2.3.9\n0.0.0.0/4\n46.0.0.0/7\n"
        )
        reasons = {r["value"]: (r["line"], r["reason"]) for r in p["rejected"]}
        self.assertEqual(p["rejected_total"], 6)
        self.assertIn("special-use", reasons["10.0.0.1"][1])
        self.assertIn("special-use", reasons["2001:db8::1"][1])
        self.assertEqual(reasons["not-an-ip"], (4, "Not an IP address or CIDR prefix."))
        self.assertIn("Start-end ranges", reasons["1.2.3.4-1.2.3.9"][1])
        self.assertIn("broader than", reasons["46.0.0.0/7"][1])
        self.assertIsNone(p["header"])  # the first row was an address, so no header

    def test_first_row_header_only_when_not_address_syntax(self):
        self.assertEqual(ps.parse_footprint("10.0.0.1\n193.0.1.1")["rejected_total"], 1)
        self.assertIsNone(ps.parse_footprint("10.0.0.1\n193.0.1.1")["header"])

    def test_empty_binary_unusable_and_oversized_files(self):
        for bad in ("", "  \n\n", "a\x00b"):
            with self.subTest(bad=bad), self.assertRaises(ps.UserError):
                ps.parse_footprint(bad)
        with self.assertRaisesRegex(ps.UserError, "line 2, 10.0.0.1 is special-use"):
            ps.parse_footprint("header\n10.0.0.1\n")
        with (
            patch.object(ps.config, "MAX_FOOTPRINT_ROWS", 2),
            self.assertRaisesRegex(ps.UserError, "more than 2"),
        ):
            ps.parse_footprint("193.0.1.1\n193.0.1.2\n193.0.1.3\n")

    def test_keywords(self):
        self.assertEqual(ps.parse_keywords("Example Org, ex, example org; Site B"), ["example org", "site b"])
        self.assertEqual(ps.parse_keywords(None), [])

    def test_request_validation(self):
        with self.assertRaises(ps.UserError):
            ps.validate_footprint_request({"csv": "193.0.1.1", "include_low_visibility": "yes"})
        with self.assertRaises(ps.UserError):
            ps.validate_footprint_request(["193.0.1.1"])


class Resolution(unittest.TestCase):
    def test_reuse_is_safe_around_more_specifics(self):
        job, http = resolve("193.0.1.1\n193.0.2.2\n193.0.3.3\n193.0.4.4\n")
        self.assertEqual(job.status, "done", job.error)
        r = by_input(job.result)
        for ip in ("193.0.1.1", "193.0.2.2", "193.0.3.3"):
            self.assertEqual(
                (r[ip]["covering_prefix"], [o["asn"] for o in r[ip]["origins"]]), ("193.0.0.0/21", [OWN_A])
            )
        self.assertEqual(
            (r["193.0.4.4"]["covering_prefix"], r["193.0.4.4"]["origins"][0]["asn"]),
            ("193.0.4.0/24", HOSTING),
        )
        # First IP is queried, the covering /21 is read once, two IPs reuse it, the IP in the more-specific is queried.
        self.assertEqual(http.queried(), ["193.0.1.1", "193.0.0.0/21", "193.0.4.4"])
        self.assertEqual(
            [r[ip]["method"] for ip in ("193.0.1.1", "193.0.2.2", "193.0.3.3", "193.0.4.4")],
            ["queried", "reused", "reused", "queried"],
        )

    def test_no_reuse_when_more_specific_list_is_truncated(self):
        http = FakeRipe()
        http.max_related = 0
        job, _ = resolve("193.0.1.1\n193.0.2.2\n193.0.3.3\n", http)
        self.assertEqual(http.queried(), ["193.0.1.1", "193.0.0.0/21", "193.0.2.2", "193.0.3.3"])
        self.assertEqual(job.status, "done")

    def test_prefix_entry_includes_its_more_specific_origins(self):
        job, _ = resolve("193.0.0.0/21\n")
        row = job.result["resolution"][0]
        self.assertEqual(row["status"], "announced")
        self.assertEqual([o["asn"] for o in row["origins"]], [OWN_A])
        self.assertEqual(
            [(p["prefix"], p["origins"][0]["asn"]) for p in row["more_specifics"]],
            [("193.0.4.0/24", HOSTING)],
        )
        self.assertEqual(ps.mapped_asns(row), [OWN_A, HOSTING])
        self.assertEqual({o["asn"] for o in job.result["origins"]}, {OWN_A, HOSTING})

    def test_unannounced_range_expands_into_its_announcements(self):
        job, _ = resolve("62.0.0.0/16\n")
        row = job.result["resolution"][0]
        self.assertEqual(row["status"], "partially_announced")
        self.assertIsNone(row["covering_prefix"])
        self.assertEqual(
            {p["prefix"]: p["origins"][0]["asn"] for p in row["more_specifics"]},
            {"62.0.1.0/24": OWN_B, "62.0.2.0/24": OTHER},
        )

    def test_expansion_truncation_is_recorded(self):
        with patch.object(ps.config, "MAX_RANGE_EXPANSION", 1):
            job, _ = resolve("62.0.0.0/16\n")
        row = job.result["resolution"][0]
        self.assertEqual(len(row["more_specifics"]), 1)
        self.assertTrue(row["more_specifics_truncated"])
        self.assertTrue(any("more-specific announcements beyond" in w for w in job.result["warnings"]))

    def test_unannounced_and_failed_lookups_are_kept(self):
        http = FakeRipe()
        http.fail_resources = {"46.20.1.1"}
        job, _ = resolve("31.0.5.5\n46.20.1.1\n81.10.1.1\n", http)
        r = by_input(job.result)
        self.assertEqual(r["31.0.5.5"]["status"], "not_announced")
        self.assertEqual(
            (r["46.20.1.1"]["status"], r["46.20.1.1"]["error"]), ("lookup_failed", "fixture outage")
        )
        self.assertEqual(r["81.10.1.1"]["origins"][0]["asn"], OWN_B)
        self.assertEqual(
            job.result["status_counts"], {"not_announced": 1, "lookup_failed": 1, "announced": 1}
        )
        self.assertTrue(any("could not be looked up" in w for w in job.result["warnings"]))

    def test_lookup_budget(self):
        with patch.object(ps.config, "MAX_RESOLVE_LOOKUPS", 2):
            job, http = resolve("31.0.5.5\n46.20.1.1\n81.10.1.1\n")
        self.assertEqual(http.count, 2)
        self.assertEqual(job.result["status_counts"].get("not_resolved"), 1)
        self.assertTrue(any("limit of 2 RIPE lookups" in w for w in job.result["warnings"]))

    def test_low_visibility_filtering_is_disclosed_and_optional(self):
        job, http = resolve("81.10.8.8\n")
        self.assertEqual(job.result["resolution"][0]["origins"][0]["asn"], OWN_B)
        self.assertTrue(
            any(
                "left out 1 low-visibility route" in w and "minimum RIS peers: 10" in w
                for w in job.result["warnings"]
            )
        )
        self.assertEqual(job.result["settings"]["visibility_threshold"], 10)
        self.assertFalse(any("min_peers_seeing" in u for u in http.urls))
        job, http = resolve("81.10.8.8\n", low_visibility=True)
        self.assertEqual(job.result["resolution"][0]["origins"][0]["asn"], 64999)
        self.assertTrue(all("min_peers_seeing=1" in u for u in http.urls))
        self.assertEqual(job.result["settings"]["visibility_threshold"], 1)

    def test_multiple_origins_are_all_kept(self):
        job, _ = resolve("104.16.1.1\n")
        groups = {o["asn"]: o for o in job.result["origins"]}
        self.assertEqual(set(groups), {CDN_A, CDN_B})
        self.assertTrue(all(g["multi_origin_entries"] == 1 for g in groups.values()))
        self.assertTrue(any("more than one origin ASN" in w for w in job.result["warnings"]))

    def test_origin_groups_shares_and_keyword_preselection(self):
        text = "193.0.1.1\n193.0.2.2\n46.20.1.1\n81.10.1.1\n52.0.1.1\n52.0.2.2\n"
        job, _ = resolve(text, keywords="example org")
        g = {o["asn"]: o for o in job.result["origins"]}
        self.assertEqual(
            [o["asn"] for o in job.result["origins"]], [OWN_A, CLOUD, OWN_B]
        )  # by entries, then ASN
        self.assertEqual((g[OWN_A]["entries"], g[OWN_A]["share"]), (3, 0.5))
        self.assertEqual(g[OWN_A]["prefixes"], ["193.0.0.0/21", "46.20.0.0/22"])
        self.assertTrue(g[OWN_A]["default_selected"] and g[OWN_B]["default_selected"])
        self.assertFalse(g[CLOUD]["default_selected"])
        self.assertEqual(g[OWN_B]["matched_keyword"], "example org")
        job, _ = resolve(text)
        self.assertFalse(any(o["default_selected"] for o in job.result["origins"]))  # no keyword, no guess

    def test_cancel_stops_resolution(self):
        job = ps.Job()
        job.cancel()
        params = ps.validate_footprint_request({"csv": "193.0.1.1\n"})
        http = FakeRipe()
        ps._guarded(job, lambda: ps.run_footprint_resolution(job, params, http))
        self.assertEqual((job.status, http.count), ("cancelled", 0))


class Adjacency(unittest.TestCase):
    TEXT = "193.0.1.1\n193.0.2.2\n46.20.1.1\n81.10.1.1\n52.0.1.1\n"

    def setUp(self):
        ps.JOBS.clear()
        self.resolution, self.http = resolve(self.TEXT, keywords="example org")
        ps.JOBS[self.resolution.id] = self.resolution

    def tearDown(self):
        ps.JOBS.clear()

    def adjacency(self, asns, http=None):
        params = ps.validate_adjacency_request({"resolution_job": self.resolution.id, "asns": asns})
        job, http = ps.Job(), http or FakeRipe()
        ps._guarded(job, lambda: ps.run_footprint_adjacency(job, params, http))
        self.assertEqual(job.status, "done", job.error)
        return job.result, http

    def test_validation(self):
        for body in (
            {"resolution_job": "0" * 32, "asns": [OWN_A]},
            {"resolution_job": "bad", "asns": [OWN_A]},
            {"resolution_job": self.resolution.id, "asns": []},
            {"resolution_job": self.resolution.id, "asns": [174]},
            {"resolution_job": self.resolution.id, "asns": [True]},
        ):
            with self.subTest(body=body), self.assertRaises(ps.UserError):
                ps.validate_adjacency_request(body)
        self.assertEqual(
            ps.validate_adjacency_request(
                {"resolution_job": self.resolution.id, "asns": ["AS3333", 3333, "5555"]}
            )["asns"],
            [OWN_A, OWN_B],
        )
        with patch.object(ps.config, "MAX_CONFIRMED_ASNS", 1), self.assertRaises(ps.UserError):
            ps.validate_adjacency_request({"resolution_job": self.resolution.id, "asns": [OWN_A, OWN_B]})

    def test_aggregated_view_and_record(self):
        rec, http = self.adjacency([OWN_A, OWN_B])
        rows = {n["asn"]: n for n in rec["adjacency"]["neighbors"]}
        self.assertEqual(set(rows), {1299, 174, OWN_B, 64999})
        self.assertEqual(rows[1299]["your_asn_count"], 2)
        self.assertEqual(
            (rows[1299]["max_v4_peers"], rows[1299]["max_v6_peers"], rows[1299]["max_power"]), (900, 20, 120)
        )
        self.assertEqual(rows[64999]["positions"], ["uncertain"])
        self.assertTrue(rows[OWN_B]["is_confirmed_asn"])
        self.assertEqual(rec["adjacency"]["neighbors"][0]["asn"], 1299)  # shared neighbor first
        self.assertEqual(rows[OWN_B]["name"], "EXAMPLE-ORG-EU Example Org Site B")  # holder from resolution
        self.assertNotIn(
            f"AS{OWN_B}", " ".join(http.queried("as-overview"))
        )  # no extra lookup for known holders
        self.assertEqual(rec["confirmed_asns"], [OWN_A, OWN_B])
        self.assertEqual(
            {o["asn"]: o["confirmed"] for o in rec["origins"]}, {OWN_A: True, OWN_B: True, CLOUD: False}
        )
        self.assertIn("v4_peers", rec["adjacency"]["field_definitions"])
        self.assertIn("counts routes, not distinct peers", rec["adjacency"]["field_definitions"]["v4_peers"])
        self.assertTrue(any("1 malformed neighbor record(s) for AS5555" in w for w in rec["warnings"]))
        self.assertEqual(rec["inputs"]["accepted"], 5)
        self.assertEqual(rec["sources"]["asn_neighbors"]["query_times"], ["2026-10-04T00:00:00"])
        self.assertEqual(rec["requests"]["resolution"], self.resolution.result["requests"])
        self.assertTrue(
            any(
                "2 of them" not in s and "1 of them is adjacent to more than one" in s for s in rec["summary"]
            )
        )
        forbidden = ("suspicious", "risk", "unexpected", "should", "block")
        self.assertFalse(any(word in " ".join(rec["summary"]).lower() for word in forbidden))
        json.dumps(rec)

    def test_unavailable_neighbors_are_unknown_not_empty(self):
        http = FakeRipe()
        http.fail_neighbors = {OWN_B}
        rec, _ = self.adjacency([OWN_A, OWN_B], http)
        per = {p["asn"]: p for p in rec["adjacency"]["per_asn"]}
        self.assertEqual(per[OWN_B]["source"]["status"], "unavailable")
        self.assertTrue(any("unknown, not absent" in w for w in rec["warnings"]))
        self.assertTrue(any("unavailable for 1 confirmed ASN" in s for s in rec["summary"]))

    def test_name_cap_and_resolution_is_not_mutated(self):
        before = copy.deepcopy(self.resolution.result)
        with patch.object(ps.config, "MAX_FOOTPRINT_NAMES", 3):
            rec, http = self.adjacency([CLOUD])
        self.assertEqual(len(http.queried("as-overview")), 3)
        self.assertTrue(any("for 3 of 20 neighbors" in w for w in rec["warnings"]))
        rec["origins"][0]["holder"] = "changed"
        self.assertEqual(self.resolution.result, before)


class Retention(unittest.TestCase):
    def tearDown(self):
        ps.JOBS.clear()

    def test_running_and_recently_finished_jobs_survive(self):
        ps.JOBS.clear()
        old = time.time() - ps.JOB_TTL_SECONDS - 60
        running, recent, stale = ps.Job(), ps.Job(), ps.Job()
        for j in (running, recent, stale):
            j.created = old
        recent.status, recent.finished = "done", time.time()
        stale.status, stale.finished = "done", old
        ps.JOBS.update({j.id: j for j in (running, recent, stale)})
        ps.register_job()
        self.assertIn(running.id, ps.JOBS)
        self.assertIn(recent.id, ps.JOBS)
        self.assertNotIn(stale.id, ps.JOBS)


class Http(unittest.TestCase):
    def setUp(self):
        ps.JOBS.clear()
        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), ps.Handler)
        port = self.srv.server_address[1]
        self.base = f"http://127.0.0.1:{port}"
        self.srv.allowed_hosts = {f"127.0.0.1:{port}"}
        self.srv.http = FakeRipe()
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def tearDown(self):
        self.srv.shutdown()
        self.srv.server_close()
        ps.JOBS.clear()

    def post(self, path, body):
        data = body if isinstance(body, bytes) else json.dumps(body).encode()
        req = urllib.request.Request(
            self.base + path, data=data, method="POST", headers={"Content-Type": "application/json"}
        )
        try:
            with urllib.request.urlopen(req) as r:
                return r.status, json.loads(r.read())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read())

    def wait(self, jid):
        for _ in range(200):
            with urllib.request.urlopen(f"{self.base}/api/job/{jid}") as r:
                s = json.loads(r.read())
            if s["status"] != "running":
                return s
            time.sleep(0.02)
        raise AssertionError("job did not finish")

    def test_upload_confirm_adjacency_flow(self):
        code, body = self.post(
            "/api/footprint/resolve", {"csv": "ip\n193.0.1.1\n81.10.1.1\n", "org_keywords": "example"}
        )
        self.assertEqual(code, 202, body)
        res = self.wait(body["job_id"])
        self.assertEqual(res["status"], "done")
        code, body = self.post(
            "/api/footprint/adjacency", {"resolution_job": res["id"], "asns": [OWN_A, OWN_B]}
        )
        self.assertEqual(code, 202, body)
        rec = self.wait(body["job_id"])["result"]
        self.assertEqual(rec["kind"], "footprint_run")
        self.assertEqual(rec["confirmed_asns"], [OWN_A, OWN_B])

    def test_upload_limits_and_errors(self):
        big = json.dumps({"csv": "193.0.1.1\n" * 120000}).encode()
        self.assertGreater(len(big), ps.MAX_UPLOAD_BYTES + ps.MAX_BODY_BYTES)
        code, body = self.post("/api/footprint/resolve", big)
        self.assertEqual((code, body["error"]), (413, "The upload is empty or larger than 1 MB."))
        code, body = self.post("/api/footprint/resolve", {"csv": "header\nnot-an-ip\n"})
        self.assertEqual(code, 400)
        self.assertIn("No usable IPs or prefixes", body["error"])
        code, body = self.post("/api/footprint/adjacency", {"resolution_job": "a" * 32, "asns": [OWN_A]})
        self.assertEqual(code, 400)
        self.assertIn("expired", body["error"])


if __name__ == "__main__":
    unittest.main()
