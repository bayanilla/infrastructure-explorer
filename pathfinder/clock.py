"""Pathfinder clock responsibilities."""

from __future__ import annotations

import time


def utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
