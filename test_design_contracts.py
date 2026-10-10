"""Regression coverage for evidence invariants, migration and cancellation boundaries."""

import ast
import copy
import io
import json
import threading
import unittest
import urllib.error
from pathlib import Path
from unittest.mock import patch

from pathfinder.analysis.routing import calculate_context
from pathfinder.errors import ApiError, Cancelled, UserError
from pathfinder.jobs import Job, JobStore, _guarded
from pathfinder.model import Coverage, Evidence, Source, Status, thaw
from pathfinder.reports.schema import SCHEMA, upgrade
from pathfinder.sources.gateway import Http, SourceRedirects, retry_delay


class EvidenceContracts(unittest.TestCase):
    def setUp(self):
        self.source = Source(
            "fixture", "https://stat.ripe.net/data/", (), retrieved_at="2026-10-08T00:00:00Z"
        )

    def test_available_empty_is_known_and_failed_cannot_have_value(self):
        self.assertEqual(Evidence(Status.AVAILABLE, self.source, []).map(len).value, 0)
        unknown = Evidence(Status.UNAVAILABLE, self.source)
        self.assertIsNone(unknown.map(lambda _: self.fail("Unknown data must not be calculated")).value)
        with self.assertRaises(ValueError):
            Evidence(Status.UNAVAILABLE, self.source, [])
        with self.assertRaises(ValueError):
            Evidence(Status.AVAILABLE, self.source)

    def test_partial_coverage_survives_calculation(self):
        cov = Coverage(2, 10, 2, "Only two records were retained.")
        result = Evidence(Status.PARTIAL, self.source, [1, 2], cov).map(len)
        self.assertEqual((result.status, result.value, result.coverage.reported), (Status.PARTIAL, 2, 10))
        with self.assertRaises(ValueError):
            Evidence(Status.PARTIAL, self.source, [])

    def test_nested_snapshots_are_immutable_and_isolated(self):
        raw = [{"path": [1, 2]}]
        snap = Evidence(Status.AVAILABLE, self.source, raw)
        raw[0]["path"].append(3)
        self.assertEqual(thaw(snap.value), [{"path": [1, 2]}])
        with self.assertRaises(TypeError):
            snap.value[0]["path"] = []
        snap.map(lambda rows: rows.clear() or [])
        self.assertEqual(thaw(snap.value), [{"path": [1, 2]}])

    def test_calculations_are_repeatable_and_do_not_read_clock_or_mutate_inputs(self):
        args = dict(
            origin_asn=3333,
            traces=[],
            probe_meta={},
            ipmap={},
            cp_routes=[{"target_prefix": "193.0.0.0/21", "source_id": "fixture", "path": [174, 3333]}],
        )
        before = copy.deepcopy(args)
        with patch("time.time", side_effect=AssertionError("Hidden clock")):
            self.assertEqual(calculate_context(**args), calculate_context(**args))
        self.assertEqual(args, before)

    def test_analysis_has_no_network_or_clock_dependencies(self):
        banned = {"time", "datetime", "urllib", "http", "requests", "pathfinder.clock", "pathfinder.sources"}
        for file in Path("pathfinder/analysis").glob("*.py"):
            for node in ast.walk(ast.parse(file.read_text())):
                names = (
                    [a.name for a in node.names]
                    if isinstance(node, ast.Import)
                    else ([node.module] if isinstance(node, ast.ImportFrom) else [])
                )
                for name in names:
                    self.assertFalse(any(name == b or name.startswith(b + ".") for b in banned), (file, name))


class GatewayContracts(unittest.TestCase):
    def test_allowlist_and_redirects_prevent_target_access(self):
        http = Http(0)
        for url in [
            "http://stat.ripe.net/data/",
            "https://8.8.8.8/",
            "https://stat.ripe.net.evil.example/",
            "https://user@stat.ripe.net/",
        ]:
            with self.subTest(url=url), self.assertRaises(ApiError):
                http.get_json(url)
        with self.assertRaises(ApiError):
            SourceRedirects().redirect_request(None, None, 302, "redirect", {}, "https://8.8.8.8/")

    def test_retry_after_and_invalid_json(self):
        self.assertEqual(retry_delay("17", 4), 17)
        with patch("time.time", return_value=0):
            self.assertEqual(retry_delay("Thu, 01 Jan 1970 00:00:09 GMT", 4), 9)
        self.assertEqual(retry_delay("invalid", 4), 4)
        with self.assertRaises(ValueError):
            retry_delay("99999", 4)
        http = Http(0)
        with patch.object(http, "_open", return_value=io.BytesIO(b"<html>unavailable</html>")):
            with self.assertRaisesRegex(ApiError, "valid UTF-8 JSON"):
                http.get_json("https://stat.ripe.net/data/", job=Job())

    def test_cancelled_job_exits_while_another_request_holds_gate(self):
        http, job = Http(0), Job()
        result = []

        def work():
            try:
                http.get_json("https://stat.ripe.net/data/", job=job)
            except Cancelled:
                result.append("cancelled")

        http._lock.acquire()
        thread = threading.Thread(target=work)
        thread.start()
        job.cancel()
        thread.join(2)
        try:
            self.assertFalse(thread.is_alive())
            self.assertEqual(result, ["cancelled"])
        finally:
            http._lock.release()

    def test_retry_header_controls_wait(self):
        http = Http(0)
        err = urllib.error.HTTPError(
            "https://stat.ripe.net/", 429, "limited", {"Retry-After": "17"}, io.BytesIO(b"{}")
        )
        with (
            patch.object(http, "_open", side_effect=[err, io.BytesIO(b"{}")]),
            patch("pathfinder.sources.gateway._sleep_checked") as sleep,
        ):
            http.get_json("https://stat.ripe.net/data/", job=Job())
        self.assertTrue(any(args[0] == 17 for args, kwargs in sleep.call_args_list))


class SavedReports(unittest.TestCase):
    def test_migration_preserves_times_and_does_not_change_input(self):
        rec = json.loads(Path("footprint_fixtures.json").read_text())["run"]
        legacy = copy.deepcopy(rec)
        legacy["adjacency"]["neighbours"] = legacy["adjacency"].pop("neighbors")
        for item in legacy["adjacency"]["per_asn"]:
            item["neighbours"] = item.pop("neighbors")
        before = copy.deepcopy(legacy)
        current = upgrade(legacy)
        self.assertEqual(current["schema"], SCHEMA)
        self.assertEqual(current["meta"], rec["meta"])
        self.assertEqual(current["adjacency"]["neighbors"], rec["adjacency"]["neighbors"])
        self.assertEqual(legacy, before)

    def test_future_conflicting_and_missing_exports_are_rejected(self):
        rec = json.loads(Path("footprint_fixtures.json").read_text())["run"]
        with self.assertRaises(UserError):
            upgrade({**rec, "schema": "pathfinder.report/99"})
        rec["adjacency"]["neighbours"] = []
        with self.assertRaisesRegex(UserError, "Conflicting"):
            upgrade(rec)
        with self.assertRaises(UserError):
            upgrade({"meta": {"generated_utc": "old"}})

    def test_saved_snapshot_does_not_mutate_job(self):
        job = Job()
        _guarded(job, lambda: setattr(job, "result", {"meta": {}, "data": [1]}))
        snapshot = job.snapshot()
        snapshot["result"]["data"].append(2)
        self.assertEqual(job.result["data"], [1])
        self.assertEqual(job.result["schema"], SCHEMA)
        self.assertEqual(job.cache, {})

    def test_running_capacity_and_completed_retention(self):
        store = JobStore()
        a, b = store.register(), store.register()
        with self.assertRaises(UserError):
            store.register()
        _guarded(a, lambda: setattr(a, "result", {}))
        self.assertIsNotNone(store.register())
        self.assertIs(store.get(b.id), b)


class CacheBudget(unittest.TestCase):
    def test_cache_budget_refetches_without_losing_observations(self):
        from pathfinder import config

        http, job = Http(0), Job()
        with (
            patch.object(config, "MAX_CACHE_BYTES", 1),
            patch.object(http, "_open", side_effect=lambda *args: io.BytesIO(b'{"value":42}')) as opened,
        ):
            a = http.get_json("https://stat.ripe.net/data/", job=job)
            b = http.get_json("https://stat.ripe.net/data/", job=job)
        self.assertEqual((a, b), ({"value": 42}, {"value": 42}))
        self.assertEqual(opened.call_count, 2)
        self.assertEqual(job.cache, {})


class SourcePacing(unittest.TestCase):
    def test_ripe_spacing_keeps_atlas_conservative(self):
        for url, expected in [
            ("https://stat.ripe.net/data/network-info/data.json", 1.0),
            ("https://atlas.ripe.net/api/v2/measurements/", 2.0),
        ]:
            http = Http(pause=1.0)
            http._last = 100.0
            http._open = lambda *args: io.BytesIO(b"{}")
            with (
                patch("pathfinder.sources.gateway.time.monotonic", return_value=100.0),
                patch("pathfinder.sources.gateway._sleep_checked") as sleep,
            ):
                self.assertEqual(http._request(url, None, 20), {})
                sleep.assert_called_once_with(expected, None)
