"""Verified HTTPS transport, shared request pacing and per-run caching."""

from __future__ import annotations

import copy
import email.utils
import json
import ssl
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from pathfinder import config
from pathfinder.clock import utc_now
from pathfinder.errors import ApiError


def verified_ssl_context():
    """Return a certificate-validating HTTPS context.

    Some macOS Python framework installations advertise a CA-file location that
    is absent until their separate certificate-installation helper has run. When
    that happens, use the operating system CA bundle if it is present. This is a
    trust-store fallback, never a bypass: hostname checks and certificate
    validation remain enabled in both cases.
    """
    paths = ssl.get_default_verify_paths()
    default_bundle = Path(paths.cafile) if paths.cafile else None
    system_bundle = Path("/etc/ssl/cert.pem")
    if default_bundle is not None and default_bundle.is_file():
        return ssl.create_default_context()
    if system_bundle.is_file():
        return ssl.create_default_context(cafile=str(system_bundle))
    return ssl.create_default_context()


def allowed_source_url(url):
    parsed = urllib.parse.urlsplit(url)
    return (
        parsed.scheme == "https"
        and parsed.hostname in {"stat.ripe.net", "atlas.ripe.net"}
        and parsed.port in (None, 443)
        and not parsed.username
        and not parsed.password
    )


class SourceRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not allowed_source_url(newurl):
            raise ApiError(0, "Source redirected outside allowed HTTPS services", _redact(newurl))
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def retry_delay(value, fallback):
    """Respect server Retry-After seconds or HTTP dates; reject impractical waits."""
    if not value:
        return fallback
    try:
        delay = max(0, int(value))
    except ValueError:
        try:
            when = email.utils.parsedate_to_datetime(value).timestamp()
            delay = max(0, when - time.time())
        except (TypeError, ValueError, OverflowError):
            return fallback
    if delay > 3600:
        raise ValueError("RIPE requested a retry more than an hour later; retry the analysis later.")
    return delay


class Http:
    """Shared serial source gate with cancellable waiting and per-run snapshots.

    In-flight socket I/O ends at its timeout; cancellation prevents queued work
    and retries. Cache retrieval times describe the original fetch within the run.
    """

    def __init__(self, pause):
        self.pause = pause
        self._ssl_context = verified_ssl_context()
        self._opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=self._ssl_context), SourceRedirects()
        )
        self._lock = threading.Lock()
        self._last = 0.0
        self.count = 0

    def _open(self, req, timeout):
        return self._opener.open(req, timeout=timeout)

    def get_json(self, url, cache=True, job=None, timeout=45):
        if not allowed_source_url(url):
            raise ApiError(0, "Only fixed RIPE HTTPS sources may be queried", _redact(url))
        if job is not None:
            job.check()
        store = job.cache if cache and job is not None else None
        if store is not None and url in store:
            return copy.deepcopy(store[url])
        data = self._request(url, job, timeout)
        if job is not None:
            job.fetch_times[url] = utc_now()
        if store is not None:
            size = len(json.dumps(data, separators=(",", ":"), ensure_ascii=False).encode("utf-8"))
            if job.cache_bytes + size <= config.MAX_CACHE_BYTES:
                store[url] = copy.deepcopy(data)
                job.cache_bytes += size
        return data

    def _request(self, url, job, timeout):
        for attempt in range(3):
            while not self._lock.acquire(timeout=0.1):
                if job is not None:
                    job.check()
            delay = None
            try:
                if job is not None:
                    job.check()
                spacing = (
                    max(self.pause, 2.0)
                    if urllib.parse.urlsplit(url).hostname == "atlas.ripe.net"
                    else self.pause
                )
                _sleep_checked(max(0, spacing - (time.monotonic() - self._last)), job)
                req = urllib.request.Request(
                    url, method="GET", headers={"User-Agent": config.USER_AGENT, "Accept": "application/json"}
                )
                try:
                    with self._open(req, timeout) as resp:
                        raw = resp.read(config.MAX_RESPONSE_BYTES + 1)
                    self._count(job)
                    if job is not None:
                        job.check()
                    if len(raw) > config.MAX_RESPONSE_BYTES:
                        raise ApiError(0, "response exceeded the size limit", _redact(url))
                    try:
                        return json.loads(raw.decode("utf-8")) if raw else {}
                    except (ValueError, UnicodeDecodeError):
                        raise ApiError(0, "Source response isn't valid UTF-8 JSON", _redact(url)) from None
                except urllib.error.HTTPError as err:
                    self._count(job)
                    detail = _error_detail(err)
                    header = err.headers.get("Retry-After") if err.headers else None
                    err.close()
                    if err.code not in (429, 500, 502, 503, 504) or attempt == 2:
                        raise ApiError(err.code, detail, _redact(url)) from None
                    try:
                        delay = retry_delay(header, 4 * (attempt + 1))
                    except ValueError as invalid:
                        raise ApiError(err.code, str(invalid), _redact(url)) from None
                except (urllib.error.URLError, TimeoutError, ConnectionError) as err:
                    self._count(job)
                    if attempt == 2:
                        raise ApiError(
                            0, f"network error: {getattr(err, 'reason', err)}", _redact(url)
                        ) from None
                    delay = 3 * (attempt + 1)
            finally:
                self._lock.release()
            if delay is not None:
                _sleep_checked(delay, job)
        raise ApiError(0, "retries exhausted", _redact(url))

    def _count(self, job):
        self._last = time.monotonic()
        self.count += 1
        if job is not None:
            job.requests += 1


def _redact(url: str) -> str:
    return url.split("?", 1)[0]


def _error_detail(e: urllib.error.HTTPError) -> str:
    try:
        body = json.loads(e.read(65536).decode("utf-8", "replace"))
    except Exception:
        return e.reason or "HTTP error"
    err = body.get("error") if isinstance(body, dict) else None
    if isinstance(err, dict):
        parts = [err.get("detail") or err.get("title") or ""]
        for sub in err.get("errors") or []:
            if isinstance(sub, dict):
                src = (sub.get("source") or {}).get("pointer", "")
                parts.append(f"{src} {sub.get('detail', '')}".strip())
        text = "; ".join(p for p in parts if p)
        if text:
            return text[:400]
    if isinstance(body, dict) and body.get("messages"):
        return str(body["messages"])[:400]
    return e.reason or "HTTP error"


def _sleep_checked(seconds: float, job) -> None:
    end = time.monotonic() + seconds
    while True:
        if job:
            job.check()
        left = end - time.monotonic()
        if left <= 0:
            return
        time.sleep(min(0.5, left))
