"""Pathfinder validation responsibilities."""

from __future__ import annotations

import csv
import io
import ipaddress
import re

from pathfinder import config
from pathfinder.errors import UserError


def public_asn(n: int) -> bool:
    return 0 < n <= 4294967295 and n != 23456 and not (64496 <= n <= 131071) and not (n >= 4200000000)


def is_public_ip(ip) -> bool:
    if not isinstance(ip, str) or not ip:
        return False
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def valid_timestamp(ts) -> bool:
    """Atlas timestamps are integer UNIX seconds. Missing is allowed; malformed is not."""
    if ts is None:
        return True
    return isinstance(ts, int) and not isinstance(ts, bool) and config.TS_MIN <= ts <= config.TS_MAX


_ASN_TOKEN = re.compile(r"^(?:AS)?([0-9]{1,10})$", re.I)


def parse_target(raw: str):
    """Return (ip, address_family) for one public IP address. Ranges are not accepted."""
    s = str(raw or "").strip()
    if not s:
        raise UserError("Enter a public IP address.")
    if len(s) > 64:
        raise UserError("The target is too long to be an IP address.")
    if "/" in s:
        raise UserError(
            "Enter a single IP address, not a range. The report shows the announced prefix that covers it."
        )
    try:
        ip = ipaddress.ip_address(s)
    except ValueError:
        raise UserError("Enter a public IP address or an ASN such as AS3333.") from None
    if not ip.is_global:
        raise UserError(f"{ip} is a special-use address and isn't routed on the internet.")
    return str(ip), ip.version


def parse_analysis_target(raw):
    """An ASN is a passive resource, never an address chosen for a traceroute."""
    if not isinstance(raw, str) or not raw.strip() or len(raw.strip()) > 64:
        raise UserError("Enter a public IP address or an ASN such as AS3333.")
    value = raw.strip()
    match = _ASN_TOKEN.fullmatch(value)
    if match:
        asn = int(match.group(1))
        if not public_asn(asn):
            raise UserError("Enter a public ASN; reserved and private ASNs are not supported.")
        return {"target_asn": asn, "target_ip": None, "af": None, "target_resource": f"AS{asn}"}
    ip, af = parse_target(value)
    return {"target_asn": None, "target_ip": ip, "af": af, "target_resource": ip}


def parse_measurement_ids(raw) -> list[int]:
    out: list[int] = []
    for tok in re.split(r"[\s,;]+", str(raw or "").strip()):
        if not tok:
            continue
        if not tok.isdigit() or not (0 < int(tok) < 10**9):
            raise UserError(f"“{tok[:24]}” isn't an Atlas measurement ID.")
        if int(tok) not in out:
            out.append(int(tok))
    if len(out) > 10:
        raise UserError("Enter at most 10 measurement IDs.")
    return out


def validate_request(body: dict) -> dict:
    if not isinstance(body, dict):
        raise UserError("Request body must be a JSON object.")
    target = parse_analysis_target(body.get("target"))
    tier = body.get("tier", "public")
    if tier != "public":
        raise UserError("Analysis uses public data only. Scheduling active measurements is disabled.")
    if str(body.get("suspect_asns") or "").strip():
        raise UserError("Suspect-network and enforcement inputs are not supported in passive analysis.")
    if body.get("api_key") or body.get("probe_sets"):
        raise UserError("API keys and probe scheduling are not supported in passive analysis.")
    if not isinstance(body.get("control_plane", True), bool):
        raise UserError("control_plane must be true or false.")
    return {
        "target_input": str(body.get("target")).strip(),
        **target,
        "tier": tier,
        "measurement_ids": parse_measurement_ids(body.get("measurement_ids")),
        "control_plane": body.get("control_plane", True),
    }


def _parse_footprint_value(value: str):
    """Return (entry, reason, syntax_ok). entry is None when the value is rejected."""
    if len(value) > 64:
        return None, "Too long to be an IP address or prefix.", False
    if re.fullmatch(r"[0-9A-Fa-f:.]+\s*-\s*[0-9A-Fa-f:.]+", value):
        return None, "Start-end ranges aren't supported. Use CIDR notation.", True
    note = None
    try:
        if "/" in value:
            try:
                net = ipaddress.ip_network(value, strict=True)
            except ValueError:
                net = ipaddress.ip_network(value, strict=False)
                note = f"Host bits set in {value}; normalized to {net}."
            if net.prefixlen == net.max_prefixlen:
                addr, kind = net.network_address, "ip"
            else:
                if net.prefixlen < config.MIN_PREFIXLEN[net.version]:
                    return (
                        None,
                        (
                            f"/{net.prefixlen} is broader than this tool resolves "
                            f"(minimum /{config.MIN_PREFIXLEN[net.version]} for IPv{net.version})."
                        ),
                        True,
                    )
                if not net.is_global:
                    return None, f"{net} is special-use or private address space.", True
                return {"value": str(net), "kind": "prefix", "note": note}, None, True
        else:
            addr, kind = ipaddress.ip_address(value), "ip"
    except ValueError:
        return None, "Not an IP address or CIDR prefix.", False
    if not addr.is_global:
        return None, f"{addr} is special-use or private address space.", True
    return {"value": str(addr), "kind": kind, "note": note}, None, True


def parse_footprint(text) -> dict:
    """Parse a one-column CSV or text list of IPs and prefixes.

    Reads the first non-empty cell of each row. Blank rows and rows starting with '#'
    are skipped. The first content row is treated as a header only if it isn't an
    address or prefix at all. Exact duplicates (after normalization) are counted and
    dropped; overlapping entries are kept, because each is a distinct input.
    """
    if not isinstance(text, str) or not text.strip():
        raise UserError("The file is empty. Upload a CSV or text file with one IP or prefix per row.")
    if "\x00" in text:
        raise UserError("The file contains binary data. Upload a CSV or plain-text list.")
    entries, rejected, seen = [], [], set()
    duplicates = rows = rejected_total = 0
    header = None
    first = True
    reader = csv.reader(io.StringIO(text.lstrip("﻿")))
    try:
        for row in reader:
            value = next((c.strip().strip("\"'").strip() for c in row if c.strip().strip("\"'").strip()), "")
            if not value or value.startswith("#"):
                continue
            rows += 1
            entry, reason, syntax_ok = _parse_footprint_value(value)
            if first and entry is None and not syntax_ok:
                header = value[:64]
                first = False
                continue
            first = False
            if entry is None:
                rejected_total += 1
                if len(rejected) < config.MAX_REJECTED_LISTED:
                    rejected.append({"line": reader.line_num, "value": value[:80], "reason": reason})
                continue
            if entry["value"] in seen:
                duplicates += 1
                continue
            seen.add(entry["value"])
            entry["line"] = reader.line_num
            entries.append(entry)
            if len(entries) > config.MAX_FOOTPRINT_ROWS:
                raise UserError(
                    f"The file has more than {config.MAX_FOOTPRINT_ROWS} distinct entries. Split it into smaller files."
                )
    except csv.Error as e:
        raise UserError(f"The file couldn't be read as CSV near line {reader.line_num}: {e}.") from None
    if not entries:
        detail = f" First problem: line {rejected[0]['line']}, {rejected[0]['reason']}" if rejected else ""
        raise UserError(f"No usable IPs or prefixes were found ({rejected_total} rows rejected).{detail}")
    return {
        "rows_read": rows,
        "header": header,
        "accepted": len(entries),
        "duplicates": duplicates,
        "rejected_total": rejected_total,
        "rejected": rejected,
        "rejected_truncated": rejected_total > len(rejected),
        "entries": entries,
    }


def parse_keywords(raw) -> list[str]:
    words = []
    for w in re.split(r"[,;\n]+", str(raw or "")):
        w = w.strip().lower()
        if len(w) >= 3 and w not in words:
            words.append(w[:60])
    return words[:10]


def validate_footprint_request(body) -> dict:
    if not isinstance(body, dict):
        raise UserError("Request body must be a JSON object.")
    if not isinstance(body.get("include_low_visibility", False), bool):
        raise UserError("include_low_visibility must be true or false.")
    return {
        "parsed": parse_footprint(body.get("csv")),
        "keywords": parse_keywords(body.get("org_keywords")),
        "include_low_visibility": body.get("include_low_visibility", False),
    }
