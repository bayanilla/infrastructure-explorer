"""Bounded, read-only Shodan records. Credentials never enter report records."""

import ipaddress
import json
import re
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime

from pathfinder.clock import utc_now
from pathfinder.errors import UserError
from pathfinder.sources.gateway import verified_ssl_context
from pathfinder.sources.service_inputs import validate_resources


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


class Shodan:
    def __init__(self):
        self._key = None
        self._lock = threading.Lock()
        self._last = 0
        self._open = urllib.request.build_opener(
            NoRedirect(), urllib.request.HTTPSHandler(context=verified_ssl_context())
        ).open

    def configured(self):
        return self._key is not None

    def configure(self, body):
        if not isinstance(body, dict):
            raise UserError("Settings must be an object.")
        key = body.get("key")
        if key is not None and (not isinstance(key, str) or not re.fullmatch(r"[A-Za-z0-9]{16,128}", key)):
            raise UserError("Enter a valid Shodan API key, or remove it.")
        self._key = key
        return {"configured": self.configured()}

    def read(self, path, params, job=None):
        if path not in ("/api-info", "/shodan/host/search"):
            match = re.fullmatch(r"/shodan/host/([^/]+)", path)
            try:
                if not match:
                    raise ValueError()
                ipaddress.ip_address(match.group(1))
            except ValueError:
                raise UserError(
                    "Only read-only Shodan account, IP and prefix lookups are supported."
                ) from None
        key = self._key
        if not key:
            raise UserError("Configure Shodan in Settings first.")
        # Paths are chosen by this adapter, never by supplied input.
        url = "https://api.shodan.io" + path + "?" + urllib.parse.urlencode({**params, "key": key})
        with self._lock:
            while time.monotonic() - self._last < 1:
                if job:
                    job.check()
                time.sleep(0.1)
            try:
                req = urllib.request.Request(url, headers={"Accept": "application/json"}, method="GET")
                with self._open(req, timeout=20) as resp:
                    raw = resp.read(2 * 1024 * 1024 + 1)
                if len(raw) > 2 * 1024 * 1024:
                    raise UserError("Shodan response exceeded the 2 MB limit.")
                data = json.loads(raw)
                if not isinstance(data, dict):
                    raise ValueError()
                return data
            except urllib.error.HTTPError as err:
                code = err.code
                err.close()
                if code == 404 and path.startswith("/shodan/host/") and path != "/shodan/host/search":
                    return {"data": []}
                raise UserError(
                    f"Shodan request failed (HTTP {code}). Check access, credits or rate limits."
                ) from None
            except (urllib.error.URLError, OSError, ValueError):
                raise UserError(
                    "Shodan could not return a valid response. Routing evidence is unaffected."
                ) from None
            finally:
                self._last = time.monotonic()

    def check(self, body):
        self.read("/api-info", {})
        return {"configured": True, "message": "Shodan connection verified."}

    def observe(self, resources, job, page=1):
        results = []
        for resource in resources:
            job.check()
            job.say(f"Reading existing Shodan records for {resource}")
            net = ipaddress.ip_network(resource) if "/" in resource else None
            record = {
                "resource": resource,
                "source": "Shodan",
                "query": f"net:{resource}" if net else resource,
                "source_url": "https://api.shodan.io/shodan/host/search"
                if net
                else f"https://api.shodan.io/shodan/host/{resource}",
                "status": "failed",
                "retrieved_at": None,
                "services": [],
                "total": None,
                "truncated": False,
                "rejected_records": 0,
                "page": page,
                "pages": [page],
                "page_sources": [],
            }
            try:
                data = self.read(
                    "/shodan/host/search" if net else f"/shodan/host/{resource}",
                    {"query": f"net:{resource}", "page": page} if net else {},
                    job,
                )
                record["retrieved_at"] = utc_now()
                rows = data.get("matches" if net else "data", [])
                if not isinstance(rows, list):
                    raise UserError("Shodan returned an invalid record list.")
                total = data.get("total") if net else len(rows)
                if total is not None and (type(total) is not int or total < len(rows)):
                    raise UserError("Shodan returned an invalid result count.")
                record["total"] = total
                record["coverage_unknown"] = total is None
                record["truncated"] = (
                    total is not None and total > ((page - 1) * 100 + min(len(rows), 100))
                    if net
                    else total > min(len(rows), 100)
                )
                record["page_sources"] = [
                    {
                        "page": page,
                        "retrieved_at": record["retrieved_at"],
                        "total": total,
                        "returned": len(rows),
                    }
                ]
                for row in rows[:100]:
                    try:
                        ip = ipaddress.ip_address(row["ip_str"])
                        if (net and ip not in net) or (not net and str(ip) != resource):
                            raise ValueError()
                        port = row["port"]
                        if type(port) is not int or not 1 <= port <= 65535:
                            raise ValueError()
                        transport = row.get("transport")
                        if transport not in ("tcp", "udp"):
                            raise ValueError()
                        observed = row.get("timestamp")
                        if not isinstance(observed, str) or len(observed) > 64:
                            raise ValueError()
                        datetime.fromisoformat(observed.replace("Z", "+00:00"))
                        module = row.get("_shodan", {}).get("module") or row.get("product") or "Unknown"
                        if not isinstance(module, str):
                            raise ValueError()
                        record["services"].append(
                            {
                                "ip": str(ip),
                                "port": port,
                                "transport": transport,
                                "service": module[:120],
                                "observed_at": observed,
                                "timestamp_basis": "Shodan timestamp, preserved as supplied",
                                "details": service_details(row),
                            }
                        )
                    except (KeyError, ValueError, TypeError, AttributeError):
                        record["rejected_records"] += 1
                record["status"] = (
                    "partial"
                    if record["truncated"] or record["rejected_records"] or record["coverage_unknown"]
                    else "available"
                    if rows
                    else "empty"
                )
            except UserError as err:
                record["error"] = str(err)
            results.append(record)
        return {
            "source": "Shodan",
            "records": results,
            "limits": "20 resources per initial run; prefix pages contain up to 100 records. Additional pages are requested explicitly and may consume query credits. Up to 100 source pages (10,000 records) per prefix. Exports contain fetched records only, not all exposed services. Shodan coverage is incomplete and can change between pages.",
        }


def validate_page(body):
    resources = validate_resources(body)
    page = body.get("page")
    if len(resources) != 1 or "/" not in resources[0] or type(page) is not int or not 2 <= page <= 100:
        raise UserError("Additional pages require one prefix and a page number from 2 to 100.")
    return {"resources": resources, "page": page}


def service_details(row):
    """Retain a bounded allowlist of source fields, never executable HTML or URLs."""

    def text(value, limit=256):
        return value[:limit] if isinstance(value, str) else None

    def names(value):
        return [x[:256] for x in value[:20] if isinstance(x, str)] if isinstance(value, list) else []

    http = row.get("http") if isinstance(row.get("http"), dict) else {}
    ssl = row.get("ssl") if isinstance(row.get("ssl"), dict) else {}
    cert = ssl.get("cert") if isinstance(ssl.get("cert"), dict) else {}

    def distinguished(value):
        return (
            {k: text(value.get(k)) for k in ("CN", "O", "OU") if text(value.get(k)) is not None}
            if isinstance(value, dict)
            else {}
        )

    banner = row.get("data")
    return {
        "product": text(row.get("product")),
        "version": text(row.get("version")),
        "hostnames": names(row.get("hostnames")),
        "domains": names(row.get("domains")),
        "organization": text(row.get("org")),
        "isp": text(row.get("isp")),
        "asn": text(row.get("asn")),
        "http_title": text(http.get("title"), 512),
        "http_server": text(http.get("server")),
        "tls_subject": distinguished(cert.get("subject")),
        "tls_issuer": distinguished(cert.get("issuer")),
        "tls_issued": text(cert.get("issued")),
        "tls_expires": text(cert.get("expires")),
        "banner": text(banner, 2048),
        "banner_truncated": isinstance(banner, str) and len(banner) > 2048,
    }
