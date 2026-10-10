"""Evidence states and provenance. Empty available data is distinct from missing data.

Partial evidence carries coverage; mapping it cannot silently become complete.
These are immutable snapshots, including nested JSON values.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from types import MappingProxyType
from typing import Callable, Generic, Mapping, TypeVar

T = TypeVar("T")
R = TypeVar("R")


class Status(str, Enum):
    AVAILABLE = "available"
    PARTIAL = "partial"
    UNAVAILABLE = "unavailable"
    NOT_REQUESTED = "not_requested"


def freeze(value):
    if isinstance(value, Mapping):
        return MappingProxyType({k: freeze(v) for k, v in value.items()})
    if isinstance(value, (list, tuple)):
        return tuple(freeze(v) for v in value)
    return value


def thaw(value):
    if isinstance(value, Mapping):
        return {k: thaw(v) for k, v in value.items()}
    if isinstance(value, tuple):
        return [thaw(v) for v in value]
    return value


@dataclass(frozen=True)
class Source:
    name: str
    url: str
    parameters: tuple[tuple[str, str], ...]
    observed_at: str | None = None
    retrieved_at: str | None = None
    error: str | None = None


@dataclass(frozen=True)
class Coverage:
    returned: int | None = None
    reported: int | None = None
    limit: int | None = None
    note: str | None = None

    def __post_init__(self):
        for count in (self.returned, self.reported, self.limit):
            if count is not None and (type(count) is not int or count < 0):
                raise ValueError("Coverage counts must be nonnegative integers or unknown.")


@dataclass(frozen=True)
class Evidence(Generic[T]):
    status: Status
    source: Source
    value: T | None = None
    coverage: Coverage = Coverage()

    def __post_init__(self):
        if not isinstance(self.status, Status):
            raise ValueError("Evidence must use a declared Status.")
        usable = self.status in (Status.AVAILABLE, Status.PARTIAL)
        if usable != (self.value is not None):
            raise ValueError("Only available or partial evidence may contain a value.")
        if usable and self.source.retrieved_at is None:
            raise ValueError("Retrieved evidence must record its retrieval time.")
        if self.status == Status.PARTIAL and self.coverage.note is None:
            raise ValueError("Partial evidence must explain its coverage limit.")
        object.__setattr__(self, "value", freeze(self.value))

    @property
    def usable(self) -> bool:
        return self.status in (Status.AVAILABLE, Status.PARTIAL)

    def map(self, fn: Callable[[T], R]) -> Evidence[R]:
        # Normalize into a fresh value so calculation code never mutates source evidence.
        value = fn(thaw(self.value)) if self.usable else None
        return Evidence(self.status, self.source, value, self.coverage)

    def source_record(self) -> dict:
        record = {
            "name": self.source.name,
            "url": self.source.url,
            "query_parameters": dict(self.source.parameters),
            "status": self.status.value,
            "observed_at": self.source.observed_at,
            "retrieved_at": self.source.retrieved_at,
        }
        if self.source.error is not None:
            record["error"] = self.source.error
        if self.usable:
            record.update(returned_routes=self.coverage.returned, reported_routes=self.coverage.reported)
            if self.source.observed_at is None:
                record["observation_time_note"] = "Source observation time unavailable."
        return record


@dataclass(frozen=True)
class Warning:
    """A calculation outcome; human wording belongs to the reporting boundary."""

    code: str
    data: tuple[tuple[str, int], ...]
