"""Offline tests for probe_server. No network access: RIPE responses are canned.

python3 -m unittest test_probe_analysis -v
"""

import copy
import io
import json
import re
import ssl
import unittest
import urllib.parse
from unittest.mock import patch

import test_support as ps

ORIGIN = 3333
UP_A, UP_B = 1103, 3356  # adjacent networks
MID = 2914  # mid-path network
SRC_HOSTING, SRC_OTHER = 14061, 9999  # vantage networks


def hop(n, ip, rtt=10.0):
    return {"hop": n, "result": [{"from": ip, "rtt": rtt}, {"from": ip, "rtt": rtt + 1}, {"x": "*"}]}


def trace(prb, hops, dst="193.0.6.139", msm=1001, ts=1790000000):
    return {
        "type": "traceroute",
        "msm_id": msm,
        "prb_id": prb,
        "from": "198.51.100.1",
        "dst_addr": dst,
        "timestamp": ts,
        "result": hops,
    }


def definition(mid, target_ip, target_asn=ORIGIN, kind="traceroute"):
    return {
        "id": mid,
        "type": kind,
        "target_ip": target_ip,
        "target_asn": target_asn,
        "start_time": 1790000000,
    }


RAW = [
    # probe 1 in SRC_HOSTING: private hop, then hosting, mid-path, adjacent A, origin
    trace(
        1,
        [hop(1, "10.0.0.1"), hop(2, "8.8.4.1"), hop(3, "9.9.9.1"), hop(4, "20.0.0.1"), hop(5, "193.0.6.139")],
    ),
    # probe 2 in SRC_OTHER: via adjacent A
    trace(2, [hop(1, "30.0.0.1"), hop(2, "9.9.9.2"), hop(3, "20.0.0.2"), hop(4, "193.0.6.139")]),
    # probe 3 (no metadata): via adjacent B
    trace(3, [hop(1, "40.0.0.1"), hop(2, "50.0.0.1"), hop(3, "193.0.6.1")]),
    # probe 4: no hop maps to the origin (ICMP filtered)
    trace(4, [hop(1, "30.0.0.9"), {"hop": 2, "result": [{"x": "*"}, {"x": "*"}]}]),
]
IP_ASN = {
    "8.8.4.0/24": SRC_HOSTING,
    "9.9.9.0/24": MID,
    "20.0.0.0/24": UP_A,
    "30.0.0.0/24": SRC_OTHER,
    "40.0.0.0/24": 7777,
    "50.0.0.0/24": UP_B,
    "193.0.0.0/21": ORIGIN,
}
BGP_ROWS = [
    {"target_prefix": "193.0.0.0/21", "source_id": "00-1", "path": [6939, UP_A, ORIGIN]},
    {"target_prefix": "193.0.0.0/21", "source_id": "00-2", "path": [174, UP_A, UP_A, ORIGIN]},
    {"target_prefix": "193.0.0.0/21", "source_id": "01-1", "path": [2914, UP_B, ORIGIN]},
    {"target_prefix": "193.0.0.0/21", "source_id": "01-2", "path": [2914, 65000]},
    {"target_prefix": "193.0.0.0/21", "source_id": "01-3", "path": [2914, [1, 2], UP_B, ORIGIN]},
]


class FakeHttp:
    """Canned RIPE responses. Configure ip_asn, bgp_rows, definitions, and searches per test."""

    def __init__(self):
        self.count = 0
        self.urls = []
        self.ip_asn = dict(IP_ASN)
        self.bgp_rows = copy.deepcopy(BGP_ROWS)
        self.definitions = {1001: definition(1001, "193.0.6.139")}
        self.latest = {1001: RAW}
        self.ip_search = None  # None: return definitions whose target_ip matches the filter
        self.asn_search = []

    def network_info(self, ip):
        import ipaddress

        a = ipaddress.ip_address(ip)
        best = None
        for p, asn in self.ip_asn.items():
            n = ipaddress.ip_network(p)
            if a in n and (best is None or n.prefixlen > best[0].prefixlen):
                best = (n, asn)
        if best:
            return {"data": {"asns": [str(best[1])], "prefix": str(best[0])}}
        return {"data": {"asns": [], "prefix": None}}

    def get_json(self, url, cache=True, job=None, timeout=45):
        self.count += 1
        self.urls.append(url)
        u = urllib.parse.urlsplit(url)
        q = dict(urllib.parse.parse_qsl(u.query))
        if "network-info" in u.path:
            return self.network_info(q["resource"])
        if "as-overview" in u.path:
            return {"data": {"holder": f"Holder {q['resource']}"}}
        if "bgp-state" in u.path:
            return {"data": {"bgp_state": copy.deepcopy(self.bgp_rows)}}
        if u.path.endswith("/measurements/"):
            if "target_ip" in q:
                rows = (
                    self.ip_search
                    if self.ip_search is not None
                    else [d for d in self.definitions.values() if d["target_ip"] == q["target_ip"]]
                )
            else:
                rows = self.asn_search
            return {"results": copy.deepcopy(rows)}
        m = re.search(r"/measurements/(\d+)/latest/$", u.path)
        if m:
            return copy.deepcopy(self.latest.get(int(m.group(1)), []))
        m = re.search(r"/measurements/(\d+)/$", u.path)
        if m:
            mid = int(m.group(1))
            if mid not in self.definitions:
                raise ps.ApiError(404, "No measurement found", url)
            return copy.deepcopy(self.definitions[mid])
        if u.path.endswith("/probes/"):
            return {
                "results": [
                    {"id": 1, "asn_v4": SRC_HOSTING, "country_code": "US"},
                    {"id": 2, "asn_v4": SRC_OTHER, "country_code": "BR"},
                    {"id": 4, "asn_v4": SRC_OTHER, "country_code": "BR"},
                ]
            }
        raise AssertionError(f"unexpected GET {url}")

    def resources(self, endpoint):
        return [
            dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(u).query)).get("resource")
            for u in self.urls
            if f"/{endpoint}/" in u
        ]


def run(body, http=None):
    http = http or FakeHttp()
    job = ps.Job()
    ps.run_job(job, ps.validate_request(body), http)
    return job, http


class Validation(unittest.TestCase):
    def test_target(self):
        self.assertEqual(ps.parse_target("193.0.6.139"), ("193.0.6.139", 4))
        self.assertEqual(ps.parse_target(" 2001:67c:2e8:22::c100:68b "), ("2001:67c:2e8:22::c100:68b", 6))
        for bad in ("10.0.0.1", "AS3333", "", "::1", "193.0.6.999", "not-an-ip"):
            with self.subTest(bad=bad), self.assertRaises(ps.UserError):
                ps.parse_target(bad)

    def test_ranges_are_rejected_with_guidance(self):
        for rng in ("193.0.0.0/21", "193.0.6.139/32", "2001:67c:2e8::/48"):
            with (
                self.subTest(rng=rng),
                self.assertRaisesRegex(ps.UserError, "single IP address, not a range"),
            ):
                ps.validate_request({"target": rng})
        params = ps.validate_request({"target": "193.0.6.139"})
        self.assertEqual(params["target_resource"], "193.0.6.139")
        self.assertNotIn("target_network", params)

    def test_ip_report_names_the_covering_prefix_it_queried(self):
        job, http = run({"target": "193.0.6.139"})
        self.assertEqual(http.resources("bgp-state"), ["193.0.0.0/21"])
        self.assertEqual(job.result["meta"]["evidence_resource"], "193.0.0.0/21")
        self.assertEqual(job.result["meta"]["target_resource"], "193.0.6.139")


class EndToEnd(unittest.TestCase):
    def test_public_tier(self):
        job, http = run({"target": "193.0.6.139", "tier": "public"})
        self.assertEqual(job.status, "done", job.error)
        r = job.result
        self.assertNotIn("enforcement", r)
        self.assertEqual(r["meta"]["origin"]["asn"], ORIGIN)
        self.assertEqual(r["meta"]["data_scope"], "target")
        self.assertEqual(r["meta"]["measurement_ids"], [1001])
        self.assertEqual(r["measurement_evidence"][0]["scope"], "target")
        context = r["routing_context"]
        entries = {x["asn"]: x for x in context["adjacencies"]}
        self.assertEqual(set(entries), {UP_A, UP_B})
        self.assertEqual(entries[UP_A]["data_paths"], 2)
        self.assertEqual(entries[UP_B]["data_paths"], 1)
        self.assertEqual(entries[UP_A]["cp_routes"], 2)
        self.assertEqual(entries[UP_B]["cp_routes"], 1)  # AS_SET excluded, not flattened.
        self.assertEqual(context["calculations"]["bgp_fraction"]["denominator"], 3)
        self.assertTrue(all("provider relationship" in x["interpretation"] for x in entries.values()))
        self.assertFalse(any("class" in n for n in r["graph"]["nodes"]))
        traces = {x["probe_id"]: x for x in r["traces"]}
        self.assertEqual(traces[1]["as_path"], [SRC_HOSTING, MID, UP_A, ORIGIN])
        self.assertEqual(traces[1]["mapping_status"], "prefix_origin_inference")
        self.assertEqual(traces[1]["hops"][0]["scope"], "special-use")
        self.assertFalse(traces[4]["reached_origin_as"])
        self.assertTrue(any("no hop mapped" in w for w in r["warnings"]))
        self.assertTrue(any("other_origin" in w and "unsupported_path" in w for w in r["warnings"]))
        forbidden = (
            "mitigation contact",
            "single point of failure",
            "carried",
            "qualify for a perimeter blocklist",
        )
        self.assertFalse(any(term in json.dumps(r) for term in forbidden))
        names = {n["asn"]: n["name"] for n in r["graph"]["nodes"]}
        self.assertEqual(names[ORIGIN], f"Holder AS{ORIGIN}")
        json.dumps(r)

    def test_raw_path_travels_with_its_record(self):
        job, _ = run({"target": "193.0.6.139"})
        paths = {p["source_id"]: p for p in job.result["control_plane"]["paths"]}
        self.assertEqual(paths["00-2"]["path"], [174, UP_A, ORIGIN])
        self.assertEqual(paths["00-2"]["raw_path"], [174, UP_A, UP_A, ORIGIN])
        self.assertTrue(all(p["raw_path"][-1] == ORIGIN for p in paths.values()))

    def test_other_origins_are_listed_not_just_counted(self):
        job, _ = run({"target": "193.0.6.139"})
        others = job.result["control_plane"]["other_origins"]
        self.assertEqual(
            others, [{"prefix": "193.0.0.0/21", "asn": 65000, "name": "Holder AS65000", "peers": 1}]
        )
        self.assertTrue(any("AS65000 for 193.0.0.0/21" in w for w in job.result["warnings"]))

    def test_active_or_enforcement_inputs_rejected(self):
        for body in (
            {"tier": "atlas", "api_key": "secret", "probe_sets": "area:WW:1"},
            {"suspect_asns": "AS14061"},
            {"suspect_asns": "not-even-an-asn"},
            {"api_key": "secret"},
            {"control_plane": "false"},
        ):
            with self.subTest(body=body), self.assertRaises(ps.UserError):
                ps.validate_request({"target": "193.0.6.139", **body})
        params = ps.validate_request({"target": "193.0.6.139"})
        params["tier"] = "atlas"
        job, http = ps.Job(), FakeHttp()
        ps.run_job(job, params, http)
        self.assertEqual(job.status, "failed")
        self.assertEqual(http.count, 0)

    def test_unknown_bgp_is_not_zero(self):
        for control in (False, True):
            http = FakeHttp()
            original = http.get_json

            def unavailable(url, **kw):
                if "bgp-state" in url:
                    raise ps.ApiError(503, "fixture unavailable", url)
                return original(url, **kw)

            http.get_json = unavailable
            job, _ = run({"target": "193.0.6.139", "control_plane": control}, http)
            self.assertEqual(job.status, "done", job.error)
            r = job.result
            self.assertIsNone(r["control_plane"]["routes"])
            self.assertIsNone(r["routing_context"]["calculations"]["bgp_fraction"]["denominator"])
            self.assertTrue(all(x["cp_routes"] is None for x in r["routing_context"]["adjacencies"]))
            self.assertEqual(
                r["control_plane"]["source"]["status"], "unavailable" if control else "not_requested"
            )

    def test_no_measurements(self):
        http = FakeHttp()
        http.ip_search = []
        job, _ = run({"target": "193.0.6.139", "measurement_ids": ""}, http)
        self.assertEqual(job.status, "done", job.error)
        r = job.result
        self.assertEqual(r["traces"], [])
        self.assertIsNone(r["meta"]["data_scope"])
        self.assertTrue(r["routing_context"]["adjacencies"])  # still derived from RIS
        self.assertTrue(any("routing observations only" in s for s in r["summary"]))


class SuppliedMeasurements(unittest.TestCase):
    """Bug: the IP path used to accept any measurement ID without checking its target."""

    def test_unrelated_measurement_is_excluded(self):
        http = FakeHttp()
        http.definitions[777] = definition(777, "8.8.8.8", target_asn=15169)
        http.latest[777] = [trace(1, [hop(1, "20.0.0.1"), hop(2, "8.8.8.8")], dst="8.8.8.8", msm=777)]
        job, _ = run({"target": "193.0.6.139", "measurement_ids": "777"}, http)
        self.assertEqual(job.status, "done", job.error)
        self.assertEqual(job.result["traces"], [])
        self.assertFalse(any("/777/latest/" in u for u in http.urls))
        self.assertTrue(any("777 was excluded" in w and "8.8.8.8" in w for w in job.result["warnings"]))

    def test_non_traceroute_and_missing_measurements_are_excluded(self):
        http = FakeHttp()
        http.definitions[778] = definition(778, "193.0.6.139", kind="ping")
        job, _ = run({"target": "193.0.6.139", "measurement_ids": "778 779"}, http)
        self.assertEqual(job.result["traces"], [])
        warnings = " ".join(job.result["warnings"])
        self.assertIn("778 was excluded", warnings)
        self.assertIn("779 metadata unavailable", warnings)

    def test_other_address_in_origin_is_accepted_and_labeled(self):
        http = FakeHttp()
        http.definitions[780] = definition(780, "193.0.6.200")
        http.latest[780] = [trace(9, [hop(1, "20.0.0.1"), hop(2, "193.0.6.200")], dst="193.0.6.200", msm=780)]
        job, _ = run({"target": "193.0.6.139", "measurement_ids": "780"}, http)
        r = job.result
        self.assertEqual(len(r["traces"]), 1)
        self.assertEqual(r["measurement_evidence"][0]["scope"], "origin_as")
        self.assertTrue(any("780 targets 193.0.6.200" in w for w in r["warnings"]))

    def test_results_with_wrong_destination_or_timestamp_are_dropped(self):
        http = FakeHttp()
        http.latest[1001] = RAW + [
            trace(5, [hop(1, "20.0.0.1")], dst="192.0.2.99"),
            trace(6, [hop(1, "20.0.0.1")], ts="yesterday"),
            trace(7, [hop(1, "20.0.0.1")], ts=True),
        ]
        job, _ = run({"target": "193.0.6.139"}, http)
        r = job.result
        self.assertEqual(sorted(t["probe_id"] for t in r["traces"]), [1, 2, 3, 4])
        warnings = " ".join(r["warnings"])
        self.assertIn("1 result(s) with a destination other than 193.0.6.139", warnings)
        self.assertIn("2 result(s) with an unsupported timestamp", warnings)
        self.assertEqual(r["measurement_evidence"][0]["results_returned"], 7)
        self.assertEqual(r["measurement_evidence"][0]["results_retained"], 4)

    def test_discovered_definitions_are_rechecked(self):
        http = FakeHttp()
        http.ip_search = [definition(1001, "198.51.100.7")]  # search filter ignored upstream
        http.asn_search = []
        job, _ = run({"target": "193.0.6.139"}, http)
        self.assertEqual(job.result["traces"], [])
        self.assertIsNone(job.result["meta"]["data_scope"])


class PerRunCache(unittest.TestCase):
    def test_https_context_keeps_certificate_and_hostname_validation(self):
        context = ps.verified_ssl_context()
        self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(context.check_hostname)

    """Bug: a process-wide cache served stale data labeled with a fresh retrieval time."""

    def setUp(self):
        self.state = {"origin": ORIGIN, "query_time": "2026-10-03T08:00:00"}
        self.calls = []

    def urlopen(self, req, timeout=0, context=None):
        url = req.full_url
        self.calls.append(url)
        if "network-info" in url:
            body = {"data": {"asns": [str(self.state["origin"])], "prefix": "193.0.0.0/21"}}
        elif "bgp-state" in url:
            body = {
                "data": {
                    "query_time": self.state["query_time"],
                    "nr_routes": 1,
                    "bgp_state": [
                        {
                            "target_prefix": "193.0.0.0/21",
                            "source_id": "00-1",
                            "path": [6939, UP_A, self.state["origin"]],
                        }
                    ],
                }
            }
        elif "as-overview" in url:
            body = {"data": {"holder": "Example"}}
        else:
            body = {"results": []}

        class Response(io.BytesIO):
            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

        return Response(json.dumps(body).encode())

    def test_each_run_refetches_and_reports_true_times(self):
        http = ps.Http(pause=0)
        with patch.object(http, "_open", self.urlopen):
            first, _ = run({"target": "193.0.6.139"}, http)
            calls_first = len(self.calls)
            self.state.update(origin=64999, query_time="2026-10-03T20:00:00")
            second, _ = run({"target": "193.0.6.139"}, http)
        self.assertEqual(first.result["meta"]["origin"]["asn"], ORIGIN)
        self.assertEqual(second.result["meta"]["origin"]["asn"], 64999)
        self.assertEqual(second.result["control_plane"]["source"]["observed_at"], "2026-10-03T20:00:00")
        self.assertEqual(len(self.calls) - calls_first, calls_first)
        self.assertEqual(first.result["meta"]["requests"], second.result["meta"]["requests"])
        self.assertEqual(first.cache, {})

    def test_duplicate_requests_within_a_run_are_deduplicated(self):
        http, job = ps.Http(pause=0), ps.Job()
        url = ps.stat_url("as-overview", resource="AS3333")
        with patch.object(http, "_open", self.urlopen):
            http.get_json(url, job=job)
            http.get_json(url, job=job)
            http.get_json(url, job=ps.Job())
        self.assertEqual(len(self.calls), 2)
        self.assertEqual(job.requests, 1)


if __name__ == "__main__":
    unittest.main()
