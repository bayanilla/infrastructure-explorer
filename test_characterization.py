"""Behavioral comparisons against reports generated from the unchanged baseline."""

import json
import unittest
from pathlib import Path

from pathfinder.jobs import Job, _guarded
from pathfinder.validation import validate_footprint_request, validate_request
from pathfinder.workflows.footprint import run_footprint_adjacency, run_footprint_resolution
from pathfinder.workflows.lookup import run_job
from test_asn_analysis import AsHttp
from test_footprint import FakeRipe
from test_probe_analysis import FakeHttp
from tools.normalize_baseline import normalize


class Baseline(unittest.TestCase):
    def test_five_report_workflows_preserve_evidence_and_calculations(self):
        expected = json.loads(Path("tests/baseline_reports.json").read_text())
        for name, body, http in [
            ("ip", {"target": "193.0.6.139"}, FakeHttp()),
            ("asn", {"target": "AS3333"}, AsHttp()),
            ("unrequested", {"target": "AS3333", "control_plane": False}, AsHttp()),
        ]:
            with self.subTest(name=name):
                job = Job()
                run_job(job, validate_request(body), http)
                self.assertEqual(job.status, "done", job.error)
                self.assertEqual(normalize(job.result), expected[name])
        job = Job()
        params = validate_footprint_request(
            {
                "csv": "ip\n193.0.0.0/21\n193.0.4.4\n81.10.1.1\n104.16.0.1\n193.0.4.4\nwrong\n",
                "org_keywords": "example",
            }
        )
        _guarded(job, lambda: run_footprint_resolution(job, params, FakeRipe()))
        self.assertEqual(normalize(job.result), expected["resolution"])
        adj = Job()
        _guarded(
            adj,
            lambda: run_footprint_adjacency(
                adj, {"resolution": job.result, "asns": [3333, 5555]}, FakeRipe()
            ),
        )
        self.assertEqual(normalize(adj.result), expected["footprint"])
