"""Local HTTP boundaries and migration use no live sources."""

import json
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

from pathfinder.jobs import STORE
from pathfinder.server import Handler
from pathfinder.sources.shodan import Shodan
from test_footprint import FakeRipe


class LocalHttp(unittest.TestCase):
    def setUp(self):
        STORE.runs.clear()
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.server.server_address[1]
        self.server.allowed_hosts = {f"127.0.0.1:{self.port}"}
        self.server.http = FakeRipe()
        self.server.shodan = Shodan()
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(2)
        STORE.runs.clear()

    def request(self, path, body=None, headers=None):
        h = {"Content-Type": "application/json", **(headers or {})}
        req = urllib.request.Request(
            f"http://127.0.0.1:{self.port}" + path,
            data=json.dumps(body).encode() if body is not None else None,
            headers=h,
        )
        try:
            result = urllib.request.urlopen(req)
        except urllib.error.HTTPError as err:
            result = err
        with result:
            return result.code, dict(result.headers), result.read()

    def test_browser_assets_csp_and_host_origin_boundaries(self):
        status, headers, body = self.request("/")
        self.assertEqual(status, 200)
        self.assertIn("script-src 'self';", headers["Content-Security-Policy"])
        self.assertNotIn("script-src 'self' 'unsafe-inline'", headers["Content-Security-Policy"])
        self.assertIn(b'type="module" src="/app.js"', body)
        for path in ["/app.js", "/render/chart.js", "/render/jobs.js"]:
            status, headers, body = self.request(path)
            self.assertEqual(status, 200, path)
            self.assertIn("text/javascript", headers["Content-Type"])
        self.assertEqual(self.request("/../pathfinder/server.py")[0], 404)
        self.assertEqual(self.request("/", headers={"Host": "evil.example"})[0], 403)
        self.assertEqual(self.request("/api/import", {}, headers={"Origin": "https://evil.example"})[0], 403)

    def test_import_migrates_offline_and_rejects_unsupported_records(self):
        rec = json.loads(Path("footprint_fixtures.json").read_text())["run"]
        rec["adjacency"]["neighbours"] = rec["adjacency"].pop("neighbors")
        status, headers, body = self.request("/api/import", rec)
        current = json.loads(body)
        self.assertEqual(status, 200, current)
        self.assertEqual(current["meta"], rec["meta"])
        self.assertIn("neighbors", current["adjacency"])
        self.assertEqual(self.server.http.urls, [])
        self.assertEqual(self.request("/api/import", {**rec, "schema": "pathfinder.report/99"})[0], 400)

    def test_shodan_settings_and_records(self):
        status, _, raw = self.request("/api/settings/shodan")
        self.assertEqual(json.loads(raw), {"configured": False})
        status, _, raw = self.request("/api/settings/shodan", {"key": "x" * 32})
        self.assertEqual(status, 200)
        self.assertNotIn(b"xxxxxxxx", raw)
        self.server.shodan.read = lambda *args: {"data": []}
        status, _, raw = self.request("/api/settings/shodan/check", {})
        self.assertEqual(status, 200)
        status, _, raw = self.request("/api/shodan", {"resources": ["8.8.8.8"]})
        self.assertEqual(status, 202)
        job = STORE.get(json.loads(raw)["job_id"])
        import time

        for _ in range(100):
            if job.status != "running":
                break
            time.sleep(0.01)
        self.assertEqual(job.status, "done")
        self.assertEqual(job.result["records"][0]["status"], "empty")
        self.assertNotIn("xxxxxxxx", json.dumps(job.snapshot()))
        status, _, raw = self.request("/api/settings/shodan", {"key": None})
        self.assertEqual(json.loads(raw), {"configured": False})
        status, _, raw = self.request(
            "/api/settings/shodan", {"key": "x" * 32}, {"Origin": "https://untrusted.invalid"}
        )
        self.assertEqual(status, 403)

    def test_removed_exposure_sources_are_not_available(self):
        for source in ("censys", "netlas"):
            self.assertEqual(self.request("/api/settings/" + source)[0], 404)
            self.assertEqual(self.request("/api/settings/" + source, {"key": "a" * 32})[0], 404)
            self.assertEqual(self.request("/api/" + source, {"resources": ["8.8.8.8"]})[0], 404)
