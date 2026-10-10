"""Loopback HTTP boundary. Domain calculations live outside this module."""

from __future__ import annotations

import argparse
import json
import re
import threading
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from pathfinder import config
from pathfinder.errors import UserError
from pathfinder.jobs import STORE, _guarded, register_job
from pathfinder.reports.schema import upgrade
from pathfinder.sources.gateway import Http
from pathfinder.sources.shodan import Shodan, validate_page, validate_resources
from pathfinder.validation import validate_footprint_request, validate_request
from pathfinder.workflows.footprint import (
    run_footprint_adjacency,
    run_footprint_resolution,
    validate_adjacency_request,
)
from pathfinder.workflows.lookup import run_job

INDEX_PATH = Path(__file__).resolve().parent.parent / "web" / "index.html"


COQUI_PATH = Path(__file__).resolve().parent.parent / "web" / "assets" / "coqui.png"


FAVICON_PATH = Path(__file__).resolve().parent.parent / "web" / "assets" / "mucaro-mark.svg"


CSP = (
    "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
)


class Handler(BaseHTTPRequestHandler):
    server_version = f"MucaroPathfinder/{config.VERSION}"

    def log_message(self, fmt, *args):  # paths only; request bodies are never logged
        print(
            f"{self.address_string()} {self.command} {urllib.parse.urlsplit(self.path).path} {args[1] if len(args) > 1 else ''}"
        )

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
        # Explicit static allowlist: no filesystem paths come from a request.
        static = {
            "/assets/coqui.png": (COQUI_PATH, "image/png"),
            "/assets/mucaro-mark.svg": (FAVICON_PATH, "image/svg+xml"),
            "/app.js": (INDEX_PATH.parent / "app.js", "text/javascript; charset=utf-8"),
            "/styles.css": (INDEX_PATH.parent / "styles.css", "text/css; charset=utf-8"),
        }
        for module in ("format", "lookup", "footprint", "chart", "report", "jobs", "services"):
            static[f"/render/{module}.js"] = (
                INDEX_PATH.parent / "render" / f"{module}.js",
                "text/javascript; charset=utf-8",
            )
        if path in static:
            file, content_type = static[path]
            try:
                return self._send(200, file.read_bytes(), content_type)
            except OSError:
                return self._send(500, {"error": "Missing application asset."})
        if path == "/api/settings/shodan":
            return self._send(200, {"configured": self.server.shodan.configured()})
        if path == "/api/health":
            return self._send(200, {"version": config.VERSION})
        m = re.fullmatch(r"/api/job/([0-9a-f]{32})", path)
        if m:
            job = STORE.get(m.group(1))
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
            job = STORE.get(m.group(1))
            if job:
                job.cancel()
            return self._send(200, {"ok": True})
        routes = {
            "/api/settings/shodan": (2048, lambda body: self.server.shodan.configure(body), None),
            "/api/settings/shodan/check": (2048, lambda body: self.server.shodan.check(body), None),
            "/api/shodan/page": (
                8192,
                validate_page,
                lambda job, params, http: _guarded(
                    job,
                    lambda: setattr(
                        job, "result", self.server.shodan.observe(params["resources"], job, params["page"])
                    ),
                ),
            ),
            "/api/shodan": (
                8192,
                validate_resources,
                lambda job, params, http: _guarded(
                    job, lambda: setattr(job, "result", self.server.shodan.observe(params, job))
                ),
            ),
            "/api/import": (config.MAX_IMPORT_BYTES, upgrade, None),
            "/api/analyze": (config.MAX_BODY_BYTES, validate_request, run_job),
            "/api/footprint/resolve": (
                config.MAX_UPLOAD_BYTES + config.MAX_BODY_BYTES,
                validate_footprint_request,
                lambda job, params, http: _guarded(job, lambda: run_footprint_resolution(job, params, http)),
            ),
            "/api/footprint/adjacency": (
                config.MAX_BODY_BYTES,
                validate_adjacency_request,
                lambda job, params, http: _guarded(job, lambda: run_footprint_adjacency(job, params, http)),
            ),
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
            return self._send(
                413,
                {
                    "error": "The upload is empty or larger than 1 MB."
                    if path == "/api/footprint/resolve"
                    else "Request body is empty or too large."
                },
            )
        try:
            body = json.loads(self.rfile.read(length).decode("utf-8"))
            params = validate(body)
            if runner is None:
                return self._send(200, params)
            job = register_job()
        except UserError as e:
            return self._send(400, {"error": str(e)})
        except (json.JSONDecodeError, UnicodeDecodeError, RecursionError):
            return self._send(400, {"error": "Request body isn't valid JSON."})
        threading.Thread(target=runner, args=(job, params, self.server.http), daemon=True).start()
        return self._send(202, {"job_id": job.id})


def main() -> None:
    ap = argparse.ArgumentParser(
        description="Múcaro | Pathfinder: public routing context for IPs and networks"
    )
    ap.add_argument("--port", type=int, default=config.DEFAULT_PORT)
    ap.add_argument(
        "--pause",
        type=float,
        default=1.0,
        help="seconds between RIPEstat requests (minimum 1.0; Atlas minimum 2.0)",
    )
    args = ap.parse_args()
    server = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    server.allowed_hosts = {f"127.0.0.1:{args.port}", f"localhost:{args.port}"}
    server.shodan = Shodan()
    server.http = Http(pause=max(1.0, args.pause))
    print(f"Pathfinder {config.VERSION} on http://127.0.0.1:{args.port}  (Ctrl+C to stop)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
