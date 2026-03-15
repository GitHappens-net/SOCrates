"""Vendor parser registry for built-in log templates and enrichers."""
from __future__ import annotations

from . import cisco, fortigate, paloalto, windows

BUILTIN_TEMPLATES: list[dict] = []
BUILTIN_TEMPLATES.extend(fortigate.builtins())
BUILTIN_TEMPLATES.extend(cisco.builtins())
BUILTIN_TEMPLATES.extend(paloalto.builtins())
BUILTIN_TEMPLATES.extend(windows.builtins())


def detect_fingerprint(source_ip: str, raw_syslog: str) -> str:
    for matcher in (fortigate.match_fingerprint, cisco.match_fingerprint, paloalto.match_fingerprint, windows.match_fingerprint):
        fp = matcher(raw_syslog)
        if fp:
            return fp

    # Keep legacy Linux detection here because it is vendor-agnostic.
    import re

    if re.search(r"<\d+>[A-Z][a-z]{2}\s+\d+\s+\d+:\d+:\d+\s+\S+\s+\S+", raw_syslog):
        return "linux_syslog_standard"
    return f"unknown_{source_ip}"


def enrich_vendor_fields(vendor: str, fields: dict) -> dict:
    v = (vendor or "").lower()
    if "cisco" in v:
        return cisco.enrich_fields(fields)
    if "palo" in v:
        return paloalto.enrich_fields(fields)
    if "fort" in v:
        return fortigate.enrich_fields(fields)
    if "microsoft" in v or "windows" in v:
        return windows.enrich_fields(fields)
    return fields
