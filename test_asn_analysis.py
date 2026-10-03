"""ASN public-data regression coverage. Every external response is a fixture."""
import copy
import json
import unittest
import urllib.parse
from unittest.mock import patch

import probe_server as ps
from test_probe_analysis import FakeHttp, ORIGIN, RAW


class AsHttp(FakeHttp):
    def __init__(self):
        super().__init__()
        self.urls = []
        self.bgp_failure = False
        self.no_routes = False
        self.no_measurements = False
        self.atlas_failure = False
        self.measurement_asn = ORIGIN

    def get_json(self, url, **kwargs):
        self.urls.append(url)
        path = urllib.parse.urlsplit(url).path
        query = urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)
        if "bgp-state" in path:
            if self.bgp_failure:
                raise ps.ApiError(503, "fixture unavailable", url)
            data = super().get_json(url, **kwargs)
            data["data"]["query_time"] = "2026-10-03T12:00:00"
            if self.no_routes:
                data["data"]["bgp_state"] = []
            return data
        definition = {"id": 1001, "type": "traceroute", "target_asn": self.measurement_asn,
                      "target_ip": "193.0.6.139", "start_time": 1790000000}
        if path.endswith("/measurements/"):
            if self.atlas_failure:
                raise ps.ApiError(503, "fixture Atlas unavailable", url)
            self.assert_as_filter(query)
            return {"results": [] if self.no_measurements else [definition]}
        if path.endswith("/measurements/1001/"):
            return definition
        if "/latest/" in path:
            return copy.deepcopy(RAW)
        return super().get_json(url, **kwargs)

    @staticmethod
    def assert_as_filter(query):
        if query.get("target_asn") != [str(ORIGIN)] or "target_ip" in query:
            raise AssertionError("AS search must not choose a representative IP")

    def post_json(self, *args, **kwargs):
        raise AssertionError("ASN analysis must never schedule measurements")


class AsnValidation(unittest.TestCase):
    def test_canonical_asn_and_original_input(self):
        for raw in ("AS3333", "as3333", "3333", " AS003333 "):
            params = ps.validate_request({"target": raw})
            self.assertEqual(params["target_asn"], ORIGIN)
            self.assertEqual(params["target_resource"], "AS3333")
            self.assertEqual(params["target_input"], raw.strip())
            self.assertIsNone(params["target_ip"])
            self.assertIsNone(params["af"])

    def test_reserved_and_malformed_targets(self):
        for raw in ("AS0", "AS23456", "AS64512", "AS4294967295", "AS4294967296", "AS-3333", "AS٣٣٣٣", "AS3333 AS174", None, True):
            with self.subTest(raw=raw), self.assertRaises(ps.UserError):
                ps.validate_request({"target": raw})

    def test_active_asn_rejected_before_key_or_network(self):
        with self.assertRaisesRegex(ps.UserError, "public data only"):
            ps.validate_request({"target": "AS3333", "tier": "atlas"})

    def test_asn_blocklist_inputs_rejected(self):
        with self.assertRaisesRegex(ps.UserError, "enforcement inputs"):
            ps.validate_request({"target": "AS3333", "suspect_asns": "AS174"})


class AsnRoutes(unittest.TestCase):
    def test_origin_only_no_sets_no_loops_and_duplicate_identity(self):
        rows = [
            {"path": [174, ORIGIN, ORIGIN], "target_prefix": "193.0.0.0/21", "source_id": "00-192.0.2.1"},
            {"path": [174, ORIGIN, 1103], "target_prefix": "193.0.0.0/21", "source_id": "00-192.0.2.2"},
            {"path": [174, [1103, 3356], ORIGIN], "target_prefix": "193.0.0.0/21", "source_id": "00-192.0.2.3"},
            {"path": [174, 1103, 174, ORIGIN], "target_prefix": "193.0.0.0/21", "source_id": "00-192.0.2.4"},
            {"path": [1103, ORIGIN], "target_prefix": "2001:db8::/32", "source_id": "01-2001:db8::1"},
            {"path": [True, ORIGIN], "target_prefix": "193.0.0.0/21", "source_id": "00-192.0.2.5"},
        ]
        selected, exclusions = ps.select_as_routes(rows + [rows[0]], ORIGIN)
        self.assertEqual(len(selected), 2)
        self.assertEqual(selected[0]["path"], [174, ORIGIN])
        self.assertEqual(selected[0]["raw_path"], [174, ORIGIN, ORIGIN])
        self.assertEqual(exclusions, {"other_origin": 1, "unsupported_path": 2, "loop": 1, "duplicate": 1})
        self.assertEqual(ps.select_as_routes(list(reversed(rows + [rows[0]])), ORIGIN), (selected, exclusions))

    def test_invalid_prefix_and_missing_observer(self):
        rows = [{"path": [174, ORIGIN], "target_prefix": "193.0.0.1/21", "source_id": "peer"},
                {"path": [174, ORIGIN], "target_prefix": "193.0.0.0/21"}]
        self.assertEqual(ps.select_as_routes(rows, ORIGIN), ([], {"invalid": 2}))


class AsnEndToEnd(unittest.TestCase):
    def run_asn(self, http=None, **body):
        http = http or AsHttp()
        job = ps.Job()
        ps.run_job(job, ps.validate_request({"target": "AS3333", **body}), http)
        self.assertEqual(job.status, "done", job.error)
        return job.result, http

    def test_passive_asn_report_and_samples(self):
        result, http = self.run_asn()
        self.assertIsNone(result["meta"]["target_ip"])
        self.assertEqual(result["meta"]["target_kind"], "asn")
        self.assertEqual(result["meta"]["origin"]["prefixes"], ["193.0.0.0/21"])
        self.assertEqual(result["control_plane"]["routes"], 3)
        self.assertEqual(result["control_plane"]["source"]["observed_at"], "2026-10-03T12:00:00")
        self.assertEqual(len(result["traces"]), 4)
        self.assertTrue(all(t["as_path"] == [] and t["reached_origin_as"] is None for t in result["traces"]))
        self.assertNotIn("enforcement", result)
        self.assertTrue(result["routing_context"]["adjacencies"])
        self.assertFalse(any("network-info" in u for u in http.urls))
        self.assertFalse(any("mitigation" in s or "blocklist" in s for s in result["summary"]))
        json.dumps(result)

    def test_unrelated_supplied_measurement_is_excluded(self):
        http = AsHttp()
        http.measurement_asn = 174
        result, _ = self.run_asn(http, measurement_ids="1001")
        self.assertEqual(result["traces"], [])
        self.assertFalse(any("/latest/" in u for u in http.urls))
        self.assertTrue(any("could not be matched" in w for w in result["warnings"]))

    def test_routing_survives_absent_atlas_samples(self):
        http = AsHttp()
        http.no_measurements = True
        result, _ = self.run_asn(http)
        self.assertEqual(result["traces"], [])
        self.assertEqual(result["control_plane"]["routes"], 3)

    def test_atlas_failure_remains_visible_with_routing_results(self):
        http = AsHttp()
        http.atlas_failure = True
        result, _ = self.run_asn(http)
        self.assertEqual(result["control_plane"]["routes"], 3)
        self.assertTrue(any("Atlas search" in w and "unavailable" in w for w in result["warnings"]))

    def test_unavailable_and_observed_empty_are_distinct(self):
        unavailable = AsHttp()
        unavailable.bgp_failure = True
        result, _ = self.run_asn(unavailable)
        self.assertEqual(result["control_plane"]["source"]["status"], "unavailable")
        self.assertIsNone(result["meta"]["origin"]["prefix_count"])
        self.assertIsNone(result["control_plane"]["distinct_peers"])
        self.assertIsNone(result["control_plane"]["routes"])
        empty = AsHttp()
        empty.no_routes = True
        result, _ = self.run_asn(empty)
        self.assertEqual(result["control_plane"]["source"]["status"], "available")
        self.assertEqual(result["meta"]["origin"]["prefix_count"], 0)

    def test_not_requested_and_partial_results(self):
        result, http = self.run_asn(control_plane=False)
        self.assertEqual(result["control_plane"]["source"]["status"], "not_requested")
        self.assertIsNone(result["meta"]["origin"]["prefix_count"])
        self.assertFalse(any("bgp-state" in u for u in http.urls))
        with patch.object(ps, "MAX_AS_ROUTES", 1):
            result, _ = self.run_asn()
        self.assertEqual(result["control_plane"]["source"]["status"], "partial")
        self.assertEqual(result["control_plane"]["routes"], 1)
        with patch.object(ps, "MAX_CP_PATHS_KEPT", 1):
            result, _ = self.run_asn()
        self.assertEqual(len(result["control_plane"]["paths"]), 1)
        self.assertTrue(any("first 1 of 3 processed BGP" in w for w in result["warnings"]))

    def test_cancelled_asn_stops_before_access(self):
        job, http = ps.Job(), AsHttp()
        job.cancel()
        ps.run_job(job, ps.validate_request({"target": "AS3333"}), http)
        self.assertEqual(job.status, "cancelled")
        self.assertEqual(http.urls, [])


if __name__ == "__main__":
    unittest.main()
