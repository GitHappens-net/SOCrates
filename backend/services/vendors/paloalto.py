"""Built-in templates and enrichment helpers for Palo Alto logs."""
from __future__ import annotations

import re

_PA_CSV_FIELDS = [
    "receive_time",
    "serial",
    "type",
    "subtype",
    "config_version",
    "generated_time",
    "src",
    "dst",
    "natsrc",
    "natdst",
    "rule",
    "srcuser",
    "dstuser",
    "app",
    "vsys",
    "from",
    "to",
    "inbound_if",
    "outbound_if",
    "logset",
    "future_use_1",
    "sessionid",
    "repeatcnt",
    "sport",
    "dport",
    "natsport",
    "natdport",
    "flags",
    "proto",
    "action",
    "bytes",
    "bytes_sent",
    "bytes_received",
    "packets",
    "start_time",
    "elapsed",
    "category",
    "future_use_2",
    "seqno",
    "actionflags",
    "srcloc",
    "dstloc",
    "future_use_3",
    "pkts_sent",
    "pkts_received",
    "session_end_reason",
    "dg_hier_level_1",
    "rule_uuid",
]

PALOALTO_CSV_TRAFFIC_TEMPLATE: dict = {
    "fingerprint": "paloalto_csv_traffic",
    "vendor": "Palo Alto",
    "device_type": "Palo Alto Firewall",
    "parse_mode": "csv",
    "csv_fieldnames": _PA_CSV_FIELDS,
    "csv_min_columns": 30,
    "regex": "",
}

_BUILTINS: list[dict] = [PALOALTO_CSV_TRAFFIC_TEMPLATE]


def builtins() -> list[dict]:
    return [dict(t) for t in _BUILTINS]


def match_fingerprint(raw_syslog: str) -> str | None:
    if re.search(
        r"\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2},PA-\d{4},TRAFFIC,end,",
        raw_syslog,
    ):
        return "paloalto_csv_traffic"
    return None


def enrich_fields(fields: dict) -> dict:
    # Align fields with the common schema expected by downstream analytics.
    if fields.get("src"):
        fields.setdefault("srcip", fields["src"])
    if fields.get("dst"):
        fields.setdefault("dstip", fields["dst"])
    if fields.get("sport"):
        fields.setdefault("srcport", fields["sport"])
    if fields.get("dport"):
        fields.setdefault("dstport", fields["dport"])
    if fields.get("app"):
        fields.setdefault("service", fields["app"])
    if fields.get("bytes_sent"):
        fields.setdefault("sentbyte", fields["bytes_sent"])
    if fields.get("bytes_received"):
        fields.setdefault("rcvdbyte", fields["bytes_received"])
    if fields.get("pkts_sent"):
        fields.setdefault("sentpkt", fields["pkts_sent"])
    if fields.get("pkts_received"):
        fields.setdefault("rcvdpkt", fields["pkts_received"])
    return fields
