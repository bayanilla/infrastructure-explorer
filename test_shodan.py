import unittest

from pathfinder.errors import UserError
from pathfinder.jobs import Job
from pathfinder.sources.shodan import Shodan, service_details, validate_page, validate_resources


class ShodanTests(unittest.TestCase):
    def test_validation(self):
        self.assertEqual(validate_resources({"resources": ["8.8.8.8", "8.8.8.8"]}), ["8.8.8.8"])
        for r in ["127.0.0.1", "10.0.0.0/8", "8.8.8.1/24", "https://example.com", "AS63"]:
            with self.assertRaises(UserError):
                validate_resources({"resources": [r]})
        with self.assertRaises(UserError):
            validate_resources({"resources": ["8.8.8.8"] * 21})

    def test_keys(self):
        s = Shodan()
        self.assertFalse(s.configured())
        with self.assertRaises(UserError):
            s.configure({"key": "bad&key"})
        self.assertEqual(s.configure({"key": "a" * 32}), {"configured": True})
        self.assertNotIn("key", s.configure({"key": None}))

    def test_records_and_scope(self):
        s = Shodan()
        row = {
            "ip_str": "8.8.8.8",
            "port": 443,
            "transport": "tcp",
            "timestamp": "2026-10-01T00:00:00",
            "_shodan": {"module": "https"},
        }
        calls = []

        def read(path, params, job):
            calls.append((path, params))
            return {"matches": [row, {**row, "ip_str": "1.1.1.1"}], "total": 101}

        s.read = read
        record = s.observe(["8.8.8.0/24"], Job())["records"][0]
        self.assertEqual(calls, [("/shodan/host/search", {"query": "net:8.8.8.0/24", "page": 1})])
        self.assertEqual(record["status"], "partial")
        self.assertTrue(record["truncated"])
        self.assertEqual(record["rejected_records"], 1)
        self.assertEqual(len(record["services"]), 1)
        self.assertEqual(record["services"][0]["observed_at"], row["timestamp"])
        self.assertNotIn("key", str(record))

    def test_empty_failed_and_malformed(self):
        s = Shodan()
        s.read = lambda *a: {"data": []}
        self.assertEqual(s.observe(["8.8.8.8"], Job())["records"][0]["status"], "empty")
        s.read = lambda *a: {"data": [{"port": 80}]}
        self.assertEqual(s.observe(["8.8.8.8"], Job())["records"][0]["status"], "partial")

        def fail(*a):
            raise UserError("Unavailable")

        s.read = fail
        r = s.observe(["8.8.8.8"], Job())["records"][0]
        self.assertEqual(r["status"], "failed")
        self.assertIsNone(r["retrieved_at"])
        self.assertIsNone(r["total"])

    def test_scan_endpoints_are_rejected_before_transport(self):
        s = Shodan()
        s.configure({"key": "x" * 32})
        for path in ["/shodan/scan", "/shodan/host/search/evil", "https://evil.invalid"]:
            with self.assertRaises(UserError):
                s.read(path, {})

    def test_additional_pages(self):
        self.assertEqual(validate_page({"resources": ["8.8.8.0/24"], "page": 2})["page"], 2)
        for p in [True, 1, 101, "2"]:
            with self.assertRaises(UserError):
                validate_page({"resources": ["8.8.8.0/24"], "page": p})
        with self.assertRaises(UserError):
            validate_page({"resources": ["8.8.8.8"], "page": 2})
        s = Shodan()
        calls = []
        row = {"ip_str": "8.8.8.8", "port": 443, "transport": "tcp", "timestamp": "2026-10-01T00:00:00"}

        def read(path, params, job):
            calls.append(params)
            return {"matches": [row], "total": 101}

        s.read = read
        r = s.observe(["8.8.8.0/24"], Job(), 2)["records"][0]
        self.assertEqual(calls, [{"query": "net:8.8.8.0/24", "page": 2}])
        self.assertFalse(r["truncated"])
        self.assertEqual(r["pages"], [2])
        self.assertEqual(r["page_sources"][0]["returned"], 1)

    def test_bounded_service_details(self):
        d = service_details(
            {
                "product": "nginx",
                "version": "1.2",
                "hostnames": ["example.test", None],
                "http": {"title": "<script>untrusted</script>"},
                "ssl": {"cert": {"issuer": {"CN": "example issuer"}, "expires": "20270101000000Z"}},
                "data": "x" * 3000,
            }
        )
        self.assertEqual(d["product"], "nginx")
        self.assertEqual(d["hostnames"], ["example.test"])
        self.assertEqual(len(d["banner"]), 2048)
        self.assertTrue(d["banner_truncated"])
        self.assertIsNone(d["isp"])
        self.assertEqual(d["tls_issuer"], {"CN": "example issuer"})

    def test_missing_prefix_total_stays_unknown(self):
        adapter = Shodan()
        adapter.read = lambda *args: {"matches": []}
        record = adapter.observe(["8.8.8.0/24"], Job())["records"][0]
        self.assertIsNone(record["total"])
        self.assertEqual(record["status"], "partial")
