from __future__ import annotations
import re

CISCO_IOS_TEMPLATE: dict = {
    "fingerprint": "cisco_ios_syslog",
    "vendor": "Cisco",
    "device_type": "Cisco IOS Router",
    "parse_mode": "regex",
    "regex": (
        r"<(?P<priority>\d+)>"
        r"\d+:\s*\*?\s*"
        r"(?P<log_timestamp>[A-Z][a-z]{2}\s+\d+\s+[\d:\.]+):\s*"
        r"%(?P<facility>[A-Z0-9]+)-(?P<severity_level>\d+)-(?P<mnemonic>[A-Z0-9_]+):\s*"
        r"(?P<message>.*)"
    ),
}

# Cisco ASA 8.4(2) style prototype, ex:
# <166>Mar 14 2026 11:22:33: %ASA-6-302013: Built outbound TCP connection ...
CISCO_ASA_842_TEMPLATE: dict = {
    "fingerprint": "cisco_asa_842",
    "vendor": "Cisco",
    "device_type": "Cisco ASA 8.4(2)",
    "parse_mode": "regex",
    "regex": (
        r"(?:<(?P<priority>\d+)>)?"
        r"(?P<log_timestamp>[A-Z][a-z]{2}\s+\d+\s+(?:\d{4}\s+)?[\d:]+):\s*"
        r"%(?P<facility>ASA)-(?P<severity_level>\d+)-(?P<mnemonic>\d+):\s*"
        r"(?P<message>.*)"
    ),
}

_BUILTINS: list[dict] = [CISCO_IOS_TEMPLATE, CISCO_ASA_842_TEMPLATE]

_CISCO_ACL_RE = re.compile(
    r"\blist\s+(?P<acl>\S+)\s+"
    r"(?P<action>permitted|denied)\s+"
    r"(?P<service>[A-Za-z0-9_\-]+)\s+"
    r"(?P<srcip>\d+\.\d+\.\d+\.\d+)"
    r"(?:\([^)]*\))?\s*->\s*"
    r"(?P<dstip>\d+\.\d+\.\d+\.\d+)",
    re.IGNORECASE,
)

_HEARTBEAT_HOST_RE = re.compile(r"\bHEARTBEAT:\s*(?P<hostname>[A-Za-z0-9_.-]+)\b")

# Covers common ASA connection logs for built/teardown/deny events.
_ASA_CONN_RE = re.compile(
    r"(?P<event>Built|Teardown|Deny|Denied)\s+\w+\s+"
    r"(?P<proto>[A-Za-z0-9\-]+)\s+connection\s+\d+\s+for\s+"
    r"(?:\S+:)?(?P<srcip>\d+\.\d+\.\d+\.\d+)\/(?P<srcport>\d+)"
    r".*?to\s+(?:\S+:)?(?P<dstip>\d+\.\d+\.\d+\.\d+)\/(?P<dstport>\d+)",
    re.IGNORECASE,
)

def builtins() -> list[dict]:
    return [dict(t) for t in _BUILTINS]

def match_fingerprint(raw_syslog: str) -> str | None:
    if re.search(r"%ASA-\d+-\d+:", raw_syslog):
        return "cisco_asa_842"
    if re.search(r"%[A-Z0-9]+-\d+-[A-Z0-9_]+:", raw_syslog):
        return "cisco_ios_syslog"
    if re.search(r"<\d+>\d+:\s*\*?[A-Z][a-z]{2}\s+\d+\s+[\d:\.]+:", raw_syslog):
        return "cisco_ios_debug"
    return None

def enrich_fields(fields: dict) -> dict:
    message = fields.get("message", "")
    if not isinstance(message, str) or not message:
        return fields

    m = _CISCO_ACL_RE.search(message)
    if m:
        for key in ("acl", "action", "service", "srcip", "dstip"):
            val = m.groupdict().get(key)
            if val and key not in fields:
                fields[key] = val

    hm = _HEARTBEAT_HOST_RE.search(message)
    if hm and hm.group("hostname") and "hostname" not in fields:
        fields["hostname"] = hm.group("hostname")

    am = _ASA_CONN_RE.search(message)
    if am:
        action = am.group("event").lower()
        if action in ("deny", "denied"):
            fields.setdefault("action", "denied")
        elif action == "teardown":
            fields.setdefault("action", "teardown")
        else:
            fields.setdefault("action", "permitted")
        fields.setdefault("service", am.group("proto").lower())
        fields.setdefault("srcip", am.group("srcip"))
        fields.setdefault("dstip", am.group("dstip"))
        fields.setdefault("srcport", am.group("srcport"))
        fields.setdefault("dstport", am.group("dstport"))

    if "heartbeat" in message.lower():
        fields.setdefault("action", "heartbeat")
        fields.setdefault("service", "ha")

    return fields
