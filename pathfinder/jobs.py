"""Pathfinder jobs responsibilities."""

from __future__ import annotations

import copy
import threading
import time
import uuid

from pathfinder import config
from pathfinder.errors import ApiError, Cancelled, UserError
from pathfinder.reports.schema import stamp_report


class Job:
    def __init__(self):
        self.id = uuid.uuid4().hex
        self.created = time.time()
        self.status = "running"
        self.progress = "Starting"
        self.log: list[str] = []
        self.result = None
        self.error = None
        self.cache: dict[str, object] = {}
        self.cache_bytes = 0
        self.fetch_times: dict[str, str] = {}
        self.requests = 0
        self.finished: float | None = None
        self._cancel = threading.Event()
        self._lock = threading.Lock()

    def say(self, msg: str) -> None:
        with self._lock:
            self.log.append(f"{time.strftime('%H:%M:%S')}  {msg}")
            del self.log[:-200]
            self.progress = msg

    def set_progress(self, msg: str) -> None:
        with self._lock:
            self.progress = msg

    def check(self) -> None:
        if self._cancel.is_set():
            raise Cancelled()

    def cancel(self) -> None:
        self._cancel.set()

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "id": self.id,
                "status": self.status,
                "progress": self.progress,
                "log": list(self.log),
                "error": self.error,
                "result": copy.deepcopy(self.result) if self.status == "done" else None,
            }


class JobStore:
    """Bounded run lifecycle and lookup, independent of HTTP handling.

    Completed runs are ephemeral. TTL begins at completion, not creation;
    capacity may evict older completed runs sooner. Running work is never evicted.
    """

    def __init__(self):
        self.runs: dict[str, Job] = {}
        self.lock = threading.RLock()

    def get(self, jid):
        with self.lock:
            job = self.runs.get(jid)
            if (
                job is not None
                and job.status != "running"
                and time.time() - (job.finished or job.created) > config.JOB_TTL_SECONDS
            ):
                del self.runs[jid]
                return None
            return job

    def register(self):
        now = time.time()
        with self.lock:
            expired = [
                k
                for k, j in self.runs.items()
                if j.status != "running" and now - (j.finished or j.created) > config.JOB_TTL_SECONDS
            ]
            for jid in expired:
                del self.runs[jid]
            if sum(j.status == "running" for j in self.runs.values()) >= 2:
                raise UserError("Two analyses are already running. Wait for one to finish or cancel it.")
            while len(self.runs) >= config.MAX_JOBS:
                idle = [j for j in self.runs.values() if j.status != "running"]
                if not idle:
                    raise UserError("The local run store is full.")
                oldest = min(idle, key=lambda j: j.finished or j.created)
                del self.runs[oldest.id]
            job = Job()
            self.runs[job.id] = job
            return job


STORE = JobStore()
# Compatibility for existing fixtures; application callers use STORE.
JOBS, JOBS_LOCK = STORE.runs, STORE.lock


def register_job():
    return STORE.register()


def _guarded(job: Job, work) -> None:
    """Run a job body; translate failures into job state. Caches never outlive the run."""
    status, error = "done", None
    try:
        work()
        job.check()
    except Cancelled:
        status = "cancelled"
        job.say("Cancelled")
    except UserError as err:
        status, error = "failed", str(err)
    except ApiError as err:
        status = "failed"
        error = f"A RIPE service returned an error ({err.status or 'network'}) for {err.url}: {err.detail}"
    except Exception as err:
        status, error = "failed", f"Unexpected {type(err).__name__}: {err}"
    finally:
        with job._lock:
            if status == "done":
                job.result = stamp_report(job.result)
            job.error, job.status = error, status
            job.cache.clear()
            job.cache_bytes = 0
            job.fetch_times.clear()
            job.finished = time.time()
