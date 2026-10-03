"""Offline tests for probe_server. No network access: RIPE responses are canned.

    python3 -m unittest test_probe_analysis -v
"""
import json
import unittest
import urllib.parse

import probe_server as ps

ORIGIN = 3333
UP_A, UP_B = 1103, 3356          # entry networks (3356 is on the transit list)
MID = 2914                       # transit mid-path
SRC_HOSTING, SRC_OTHER = 14061, 9999  # suspects: hosting, unlisted


def hop(n, ip, rtt=10.0):
    return {"hop": n, "result": [{"from": ip, "rtt": rtt}, {"from": ip, "rtt": rtt + 1}, {"x": "*"}]}


def trace(prb, hops, dst="193.0.6.139", msm=1001):
    return {"type": "traceroute", "msm_id": msm, "prb_id": prb, "from": "198.51.100.1",
            "dst_addr": dst, "timestamp": 1790000000, "result": hops}


RAW = [
    # probe 1 in SRC_HOSTING: 10.x private, hosting hop, transit, entry A, origin
    trace(1, [hop(1, "10.0.0.1"), hop(2, "8.8.4.1"), hop(3, "9.9.9.1"), hop(4, "20.0.0.1"), hop(5, "193.0.6.139")]),
    # probe 2 in SRC_OTHER: via entry A
    trace(2, [hop(1, "30.0.0.1"), hop(2, "9.9.9.2"), hop(3, "20.0.0.2"), hop(4, "193.0.6.139")]),
    # probe 3 in 64600-ish (unknown meta): via entry B
    trace(3, [hop(1, "40.0.0.1"), hop(2, "50.0.0.1"), hop(3, "193.0.6.1")]),
    # probe 4: never reaches origin (ICMP filtered)
    trace(4, [hop(1, "30.0.0.9"), {"hop": 2, "result": [{"x": "*"}, {"x": "*"}]}]),
]
IP_ASN = {
    "8.8.4.0/24": SRC_HOSTING, "9.9.9.0/24": MID, "20.0.0.0/24": UP_A, "30.0.0.0/24": SRC_OTHER,
    "40.0.0.0/24": 7777, "50.0.0.0/24": UP_B, "193.0.0.0/21": ORIGIN,
}


def ripestat_network_info(ip):
    import ipaddress
    a = ipaddress.ip_address(ip)
    for p, asn in IP_ASN.items():
        if a in ipaddress.ip_network(p):
            return {"data": {"asns": [str(asn)], "prefix": p}}
    return {"data": {"asns": [], "prefix": None}}


class FakeHttp:
    def __init__(self):
        self.count = 0
        self.posted = None
        self.seen_headers = []

    def get_json(self, url, headers=None, cache=True, job=None, timeout=45):
        self.count += 1
        self.seen_headers.append(headers or {})
        u = urllib.parse.urlsplit(url)
        q = dict(urllib.parse.parse_qsl(u.query))
        if "network-info" in u.path:
            return ripestat_network_info(q["resource"])
        if "as-overview" in u.path:
            return {"data": {"holder": f"Holder {q['resource']}"}}
        if "announced-prefixes" in u.path:
            asn = int(q["resource"][2:])
            return {"data": {"prefixes": [{"prefix": f"{asn % 200 + 1}.1.0.0/24"},
                                          {"prefix": f"{asn % 200 + 1}.1.1.0/24"},
                                          {"prefix": "2001:db8::/48"}]}}
        if "bgp-state" in u.path:
            return {"data": {"bgp_state": [
                {"target_prefix": "193.0.0.0/21", "source_id": "00-1", "path": [6939, UP_A, ORIGIN]},
                {"target_prefix": "193.0.0.0/21", "source_id": "00-2", "path": [174, UP_A, UP_A, ORIGIN]},
                {"target_prefix": "193.0.0.0/21", "source_id": "01-1", "path": [2914, UP_B, ORIGIN]},
                {"target_prefix": "193.0.0.0/21", "source_id": "01-2", "path": [2914, 65000]},
                {"target_prefix": "193.0.0.0/21", "source_id": "01-3", "path": [2914, [1, 2], UP_B, ORIGIN]},
            ]}}
        if u.path.endswith("/measurements/"):
            return {"results": [{"id": 1001}] if q.get("target_ip") else []}
        if "/latest/" in u.path:
            return RAW
        if u.path.endswith("/measurements/2002/"):
            return {"status": {"name": "Stopped"}}
        if u.path.endswith("/probes/"):
            return {"results": [{"id": 1, "asn_v4": SRC_HOSTING, "country_code": "US"},
                                {"id": 2, "asn_v4": SRC_OTHER, "country_code": "BR"},
                                {"id": 4, "asn_v4": SRC_OTHER, "country_code": "BR"}]}
        raise AssertionError(f"unexpected GET {url}")

    def post_json(self, url, body, headers=None, job=None, timeout=45):
        self.posted = (url, body, headers)
        return {"measurements": [2002]}


class Validation(unittest.TestCase):
    def test_target(self):
        self.assertEqual(ps.parse_target("193.0.6.139")[0], "193.0.6.139")
        ip, af, note = ps.parse_target("193.0.0.0/21")
        self.assertEqual((ip, af), ("193.0.0.1", 4))
        self.assertIn("193.0.0.0/21", note)
        for bad in ("10.0.0.1", "AS3333", "", "::1"):
            with self.assertRaises(ps.UserError):
                ps.parse_target(bad)

    def test_asns(self):
        self.assertEqual(ps.parse_asns("AS3333, 174\nas13335 174"), [3333, 174, 13335])
        for bad in ("AS64512", "65000", "AS23456", "4200000001", "ASX"):
            with self.assertRaises(ps.UserError):
                ps.parse_asns(bad)

    def test_probe_sets(self):
        sets = ps.parse_probe_sets("area:ww:10\ncountry:br:5\nasn:AS4134:3\nprefix:2001:db8::/32:2\n# note")
        self.assertEqual([s["value"] for s in sets], ["WW", "BR", 4134, "2001:db8::/32"])
        for bad in ("area:Mars:1", "country:BRA:1", "asn:64512:1", "foo:1:1", "area:WW:0", "area:WW:51"):
            with self.assertRaises(ps.UserError):
                ps.parse_probe_sets(bad)

    def test_key_required_for_atlas(self):
        with self.assertRaises(ps.UserError):
            ps.validate_request({"target": "193.0.6.139", "tier": "atlas", "api_key": "nope", "probe_sets": "area:WW:1"})


class EndToEnd(unittest.TestCase):
    def run_job(self, body):
        params = ps.validate_request(body)
        job = ps.Job()
        http = FakeHttp()
        ps.run_job(job, params, http)
        self.assertEqual(job.status, "done", job.error)
        return job.result, http

    def test_public_tier(self):
        r, http = self.run_job({"target": "193.0.6.139", "tier": "public"})
        self.assertIsNone(http.posted)
        self.assertNotIn("enforcement", r)
        self.assertEqual(r["meta"]["origin"]["asn"], ORIGIN)
        self.assertEqual(r["meta"]["data_scope"], "target")
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
        forbidden = ("mitigation contact", "single point of failure", "carried", "qualify for a perimeter blocklist")
        self.assertFalse(any(term in json.dumps(r) for term in forbidden))
        names = {n["asn"]: n["name"] for n in r["graph"]["nodes"]}
        self.assertEqual(names[ORIGIN], f"Holder AS{ORIGIN}")
        json.dumps(r)

    def test_active_or_enforcement_inputs_rejected(self):
        for body in ({"tier": "atlas", "api_key": "secret", "probe_sets": "area:WW:1"},
                     {"suspect_asns": "AS14061"}, {"api_key": "secret"}, {"control_plane": "false"}):
            with self.subTest(body=body), self.assertRaises(ps.UserError):
                ps.validate_request({"target": "193.0.6.139", **body})
        params = ps.validate_request({"target": "193.0.6.139"})
        params["tier"] = "atlas"
        job, http = ps.Job(), FakeHttp()
        ps.run_job(job, params, http)
        self.assertEqual(job.status, "failed")
        self.assertIsNone(http.posted)
        self.assertEqual(http.count, 0)

    def test_unknown_bgp_is_not_zero(self):
        from unittest.mock import patch
        for control in (False, True):
            http = FakeHttp()
            original = http.get_json
            def unavailable(url, **kw):
                if "bgp-state" in url:
                    raise ps.ApiError(503, "fixture unavailable", url)
                return original(url, **kw)
            http.get_json = unavailable
            job = ps.Job()
            ps.run_job(job, ps.validate_request({"target": "193.0.6.139", "control_plane": control}), http)
            self.assertEqual(job.status, "done", job.error)
            r = job.result
            self.assertIsNone(r["control_plane"]["routes"])
            self.assertIsNone(r["routing_context"]["calculations"]["bgp_fraction"]["denominator"])
            self.assertTrue(all(x["cp_routes"] is None for x in r["routing_context"]["adjacencies"]))
            self.assertEqual(r["control_plane"]["source"]["status"], "unavailable" if control else "not_requested")

    def test_no_measurements(self):
        params = ps.validate_request({"target": "193.0.6.139", "tier": "public", "measurement_ids": ""})
        http = FakeHttp()
        orig = http.get_json

        def no_msm(url, **kw):
            if "/measurements/" in url and "/latest/" not in url:
                return {"results": []}
            return orig(url, **kw)
        http.get_json = no_msm
        job = ps.Job()
        ps.run_job(job, params, http)
        self.assertEqual(job.status, "done", job.error)
        r = job.result
        self.assertEqual(r["traces"], [])
        self.assertTrue(r["routing_context"]["adjacencies"])      # still derived from RIS
        self.assertTrue(any("routing observations only" in s for s in r["summary"]))


if __name__ == "__main__":
    unittest.main()
