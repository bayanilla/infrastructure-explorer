"""Pathfinder errors responsibilities."""

from __future__ import annotations


class UserError(Exception):
    """Input or condition the analyst can fix. Message is shown verbatim."""


class ApiError(Exception):
    def __init__(self, status: int, detail: str, url: str):
        super().__init__(f"{status}: {detail}")
        self.status = status
        self.detail = detail
        self.url = url


class Cancelled(Exception):
    pass
