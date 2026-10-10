"""Shared input bounds for optional public-service sources."""

import ipaddress

from pathfinder.errors import UserError


def validate_resources(body):
    if (
        not isinstance(body, dict)
        or not isinstance(body.get("resources"), list)
        or not 1 <= len(body["resources"]) <= 20
    ):
        raise UserError("Service lookups accept 1 to 20 explicit IPs or prefixes per run.")
    resources = []
    for item in body["resources"]:
        try:
            if not isinstance(item, str) or len(item) > 64:
                raise ValueError()
            obj = ipaddress.ip_network(item, strict=True) if "/" in item else ipaddress.ip_address(item)
            public = (
                (obj.network_address.is_global and obj.broadcast_address.is_global)
                if isinstance(obj, (ipaddress.IPv4Network, ipaddress.IPv6Network))
                else obj.is_global
            )
            if not public:
                raise ValueError()
            resources.append(str(obj))
        except ValueError:
            raise UserError("Service inputs must be public IPs or canonical public CIDR prefixes.") from None
    return list(dict.fromkeys(resources))
