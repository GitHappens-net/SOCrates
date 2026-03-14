"""Built-in templates and detection for FortiGate logs."""
from __future__ import annotations

import re

FORTIGATE_TEMPLATE: dict = {
    "fingerprint": "fortigate_kv",
    "vendor": "Fortinet",
    "device_type": "FortiGate Firewall",
    "parse_mode": "kv",
    "header_regex": (
        r"^(?:<(?P<syslog_priority>\d+)>)?\s*"
        r"(?:[^\s:=]+:\s+)?"
        r"(?P<kvpayload>date=\d{4}-\d{2}-\d{2}\s+time=\S+.+)"
    ),
    "regex": "",
}

_BUILTINS: list[dict] = [FORTIGATE_TEMPLATE]


def builtins() -> list[dict]:
    return [dict(t) for t in _BUILTINS]


def match_fingerprint(raw_syslog: str) -> str | None:
    if re.search(r"date=\d{4}-\d{2}-\d{2}\b", raw_syslog) and re.search(r"\bdevname=", raw_syslog):
        return "fortigate_kv"
    return None


def enrich_fields(fields: dict) -> dict:
    return fields
