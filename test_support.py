"""Compatibility entry point. New code imports cohesive pathfinder modules."""

import urllib.request

from pathfinder import config
from pathfinder.analysis.footprint import aggregate_neighbors, group_origins, mapped_asns
from pathfinder.analysis.routes import _valid_path, collapse, other_origins, select_as_routes
from pathfinder.analysis.routing import calculate_context, entry_of
from pathfinder.clock import utc_now
from pathfinder.config import (
    ATLAS,
    DEFAULT_PORT,
    JOB_TTL_SECONDS,
    MAX_AS_PREFIXES,
    MAX_AS_ROUTES,
    MAX_BODY_BYTES,
    MAX_CONFIRMED_ASNS,
    MAX_CP_PATHS_KEPT,
    MAX_DISCOVERED,
    MAX_FOOTPRINT_NAMES,
    MAX_FOOTPRINT_ROWS,
    MAX_GRAPH_NODES,
    MAX_HOP_LOOKUPS,
    MAX_INPUTS_PER_ORIGIN,
    MAX_JOBS,
    MAX_NAME_LOOKUPS,
    MAX_NEIGHBORS_PER_ASN,
    MAX_OTHER_ORIGINS,
    MAX_RANGE_EXPANSION,
    MAX_REJECTED_LISTED,
    MAX_RESOLVE_LOOKUPS,
    MAX_RESPONSE_BYTES,
    MAX_TRACES,
    MAX_UPLOAD_BYTES,
    MIN_PREFIXLEN,
    SOURCEAPP,
    STAT,
    USER_AGENT,
    VERSION,
)
from pathfinder.errors import ApiError, Cancelled, UserError
from pathfinder.jobs import JOBS, JOBS_LOCK, Job, _guarded, register_job
from pathfinder.reports.wording import (
    ASN_METHODOLOGY,
    FOOTPRINT_FIELDS,
    FOOTPRINT_METHODOLOGY,
    METHODOLOGY,
    exclusion_warning,
)
from pathfinder.server import COQUI_PATH, CSP, FAVICON_PATH, INDEX_PATH, Handler, main
from pathfinder.sources.atlas import (
    MSM_FIELDS,
    _msm_id,
    atlas_definition,
    atlas_discover,
    atlas_latest,
    atlas_probe_meta,
    classify_definition,
    load_samples,
    parse_trace,
    select_definitions,
)
from pathfinder.sources.gateway import Http, _error_detail, _redact, _sleep_checked, verified_ssl_context
from pathfinder.sources.stat import (
    _count,
    _overview,
    as_name,
    network_info,
    read_bgp_state,
    read_neighbors,
    stat_url,
)
from pathfinder.validation import (
    _ASN_TOKEN,
    _parse_footprint_value,
    is_public_ip,
    parse_analysis_target,
    parse_footprint,
    parse_keywords,
    parse_measurement_ids,
    parse_target,
    public_asn,
    valid_timestamp,
    validate_footprint_request,
    validate_request,
)
from pathfinder.workflows.footprint import (
    _THRESHOLD,
    _LookupBudget,
    resolve_footprint,
    run_footprint_adjacency,
    run_footprint_resolution,
    validate_adjacency_request,
)
from pathfinder.workflows.lookup import fill_names, name_networks, run_asn_job, run_ip_job, run_job

if __name__ == "__main__":
    main()
