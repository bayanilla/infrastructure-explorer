"""Bounded local operation and fixed public-source endpoints."""

from __future__ import annotations

VERSION = "0.5.0"


SOURCEAPP = "mucaro-pathfinder"


USER_AGENT = f"mucaro-pathfinder/{VERSION} (+https://github.com/bayanilla/pathfinder)"


ATLAS = "https://atlas.ripe.net/api/v2"


STAT = "https://stat.ripe.net/data"


DEFAULT_PORT = 8767


MAX_RESPONSE_BYTES = 32 * 1024 * 1024


MAX_BODY_BYTES = 64 * 1024


MAX_HOP_LOOKUPS = 150  # uncached RIPEstat network-info calls per run


MAX_TRACES = 400


MAX_NAME_LOOKUPS = 60


MAX_GRAPH_NODES = 80


MAX_CP_PATHS_KEPT = 400


MAX_AS_ROUTES = 20000


MAX_AS_PREFIXES = 4000


MAX_OTHER_ORIGINS = 50


MAX_DISCOVERED = 5


JOB_TTL_SECONDS = 3600


MAX_JOBS = 30


MAX_UPLOAD_BYTES = 1024 * 1024


MAX_FOOTPRINT_ROWS = 5000


MAX_REJECTED_LISTED = 500


MAX_RESOLVE_LOOKUPS = 2500


MAX_RANGE_EXPANSION = 100


MAX_CONFIRMED_ASNS = 50


MAX_NEIGHBORS_PER_ASN = 5000


MAX_FOOTPRINT_NAMES = 150


MAX_INPUTS_PER_ORIGIN = 200


MIN_PREFIXLEN = {4: 8, 6: 16}


TS_MIN, TS_MAX = 946684800, 4102444800  # Supported Atlas UNIX time range.

MAX_IMPORT_BYTES = 16 * 1024 * 1024

MAX_CACHE_BYTES = 32 * 1024 * 1024  # Serialized JSON budget per run; Python object overhead is additional.
