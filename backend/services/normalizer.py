import hashlib
import json
import re
import time

from backend.config import OPENAI_CLIENT, OPENAI_MODEL_PARSER
from backend.database.db import load_templates, save_template

_OPENAI_CLIENT: object | None = OPENAI_CLIENT
_OPENAI_MODEL: str = OPENAI_MODEL_PARSER

_TEMPLATES: list[dict] = [
    {
        "fingerprint": "cisco_ios_syslog",
        "vendor": "Cisco",
        "device_type": "Cisco IOS Router",
        "regex": (
            r"<(?P<priority>\d+)>"
            r"\d+:\s*\*?"
            r"(?P<log_timestamp>[A-Z][a-z]{2}\s+\d+\s+[\d:\.]+):\s*"
            r"%(?P<facility>[A-Z0-9]+)-(?P<severity_level>\d+)-(?P<mnemonic>[A-Z0-9_]+):\s*"
            r"(?P<message>.*)"
        ),
    },
    {
        "fingerprint": "linux_syslog_standard",
        "vendor": "Linux",
        "device_type": "Linux Host",
        "regex": (
            r"<(?P<priority>\d+)>"
            r"(?P<log_timestamp>[A-Z][a-z]{2}\s+\d+\s+[\d:]+)\s+"
            r"(?P<hostname>\S+)\s+"
            r"(?P<process>[^\[:\s]+)"
            r"(?:\[(?P<pid>\d+)\])?:\s*"
            r"(?P<message>.*)"
        ),
    },
    {
        # FortiGate logs are purely key=value after the optional syslog priority.
        # Distinctive markers: date=YYYY-MM-DD, devname=, logid=
        # All log types (traffic, utm, event, gtp, ...) follow this same format.
        "fingerprint": "fortigate_kv",
        "vendor": "Fortinet",
        "device_type": "FortiGate Firewall",
        "parse_mode": "kv",
        # header_regex captures the syslog envelope and names the rest as kvpayload
        # so _parse_kv() can auto-extract every field (srcip, dstip, action, logid, …)
        "header_regex": (
            r"^(?:<(?P<syslog_priority>\d+)>)?\s*"
            r"(?:[^\s:=]+:\s+)?"
            r"(?P<kvpayload>date=\d{4}-\d{2}-\d{2}\s+time=\S+.+)"
        ),
        "regex": "",  # not used in kv mode
    },
]

_AI_FAILED: dict[str, float] = {}
_AI_FAILED_TTL: float = 300.0  # retry after 5 minutes

_KV_RE = re.compile(r'(\w+)=("[^"]*"|\S+)')

# Load AI-generated templates persisted in the database
def init_templates() -> None:
    for t in load_templates():
        if not any(existing["fingerprint"] == t["fingerprint"] for existing in _TEMPLATES):
            _TEMPLATES.append(t)

# Decode syslog priority number (facility, severity)
def _decode_priority(priority: int) -> tuple[int, int]:
    return priority >> 3, priority & 0x7

# Extract priority from syslog header
def _extract_priority(raw_syslog: str) -> tuple[int, int]:
    m = re.match(r"^<(\d+)>", raw_syslog)
    if m:
        return _decode_priority(int(m.group(1)))
    return -1, -1

# Identify log format by pattern matching
def _fingerprint(source_ip: str, raw_syslog: str) -> str:
    # FortiGate: always has date=YYYY-MM-DD and devname= in the same message
    if re.search(r"date=\d{4}-\d{2}-\d{2}\b", raw_syslog) and re.search(r"\bdevname=", raw_syslog):
        return "fortigate_kv"
    if re.search(r"%[A-Z0-9]+-\d+-[A-Z0-9_]+:", raw_syslog):
        return "cisco_ios_syslog"
    if re.search(r"<\d+>\d+:\s*\*?[A-Z][a-z]{2}\s+\d+\s+[\d:\.]+:", raw_syslog):
        return "cisco_ios_debug"
    if re.search(r"<\d+>[A-Z][a-z]{2}\s+\d+\s+\d+:\d+:\d+\s+\S+\s+\S+", raw_syslog):
        return "linux_syslog_standard"
    return f"unknown_{source_ip}"

# Apply regex template to extract named groups
def _try_match(pattern: str, text: str) -> dict | None:
    m = re.search(pattern, text, re.DOTALL)
    if m:
        return {k: v for k, v in m.groupdict().items() if v is not None}
    return None

# Parse key=value format logs
def _parse_kv(raw_syslog: str, header_regex: str | None = None) -> dict | None:
    fields: dict = {}
    payload = raw_syslog
    if header_regex:
        m = re.search(header_regex, raw_syslog, re.DOTALL)
        if m:
            fields.update({k: v for k, v in m.groupdict().items() if v is not None})
            payload = m.group("kvpayload") if "kvpayload" in m.groupdict() else raw_syslog
    for key, val in _KV_RE.findall(payload):
        fields[key] = val.strip('"')
    return fields if fields else None

# Generate parsing template via OpenAI
def _ai_generate_template(raw_syslog: str, fingerprint: str) -> dict | None:
    if not _OPENAI_CLIENT:
        print(f"OPENAI_API_KEY not set — cannot generate template for '{fingerprint}'")
        return None

    prompt = f"""You are a log-parsing expert for a Security Operations Centre (SOC).

Analyse the syslog message below and decide how best to parse it.

Raw syslog message:
{raw_syslog}

There are TWO parse modes you can choose:

1. "regex" — use when the log has a structured text format (e.g. Cisco IOS, Linux syslog).
   Provide a Python regex with named capture groups that generalises to similar messages.

2. "kv" — use when the log is a key=value format (e.g. FortiGate, PaloAlto, Check Point, Juniper).
   Provide a header_regex that captures the syslog envelope and has a named group called
   "kvpayload" matching the key=value portion. The k=v pairs will be auto-parsed.

Rules:
- Make patterns general, not hardcoded to exact values in the example.
- Respond with ONLY valid JSON, no markdown, no explanation.

Required JSON format:
{{
  "vendor": "string — e.g. Cisco, Linux, Fortinet, Palo Alto, Check Point",
  "device_type": "string — e.g. IOS Router, FortiGate Firewall, Ubuntu Host",
  "parse_mode": "regex or kv",
  "regex": "python regex with named groups (required if parse_mode=regex, omit if kv)",
  "header_regex": "regex to extract syslog header + kvpayload group (required if parse_mode=kv, omit if regex)",
  "fields": ["list", "of", "expected", "field", "names"]
}}"""

    content: str | None = None
    try:
        response = _OPENAI_CLIENT.chat.completions.create(
            model=_OPENAI_MODEL,
            messages=[{"role": "user", "content": prompt}],
            temperature=0,
            max_tokens=600,
        )
        content = response.choices[0].message.content.strip()
        content = re.sub(r"^```(?:json)?\s*", "", content)
        content = re.sub(r"\s*```$", "", content)
        return json.loads(content)
    except Exception:
        return {"raw": content if content is not None else ""}

# Main entry point
def normalize_log(source_ip: str, raw_syslog: str) -> dict:
    facility, severity = _extract_priority(raw_syslog)
    fp = _fingerprint(source_ip, raw_syslog)

    # Try existing templates
    for template in _TEMPLATES:
        if template.get("parse_mode") == "kv":
            fields = _parse_kv(raw_syslog, template.get("header_regex"))
        else:
            fields = _try_match(template["regex"], raw_syslog)
        if fields:
            return {
                "fields": fields,
                "facility": facility,
                "severity": severity,
                "vendor": template["vendor"],
                "device_type": template["device_type"],
            }

    # No template match — check if this fingerprint recently failed AI
    failed_at = _AI_FAILED.get(fp)
    if failed_at and (time.time() - failed_at) < _AI_FAILED_TTL:
        return {"fields": {"raw": raw_syslog}, "facility": facility, "severity": severity, "vendor": "unknown", "device_type": "unknown"}
    _AI_FAILED.pop(fp, None)
    ai = _ai_generate_template(raw_syslog, fp)

    if ai:
        parse_mode = ai.get("parse_mode", "regex")
        new_template = {
            "fingerprint": fp,
            "vendor": ai.get("vendor", "unknown"),
            "device_type": ai.get("device_type", "unknown"),
            "parse_mode": parse_mode,
        }
        if parse_mode == "kv":
            new_template["header_regex"] = ai.get("header_regex")
            new_template["regex"] = ""  # not used for kv mode
        else:
            new_template["regex"] = ai.get("regex", "")

        _TEMPLATES.append(new_template)

        # Persist to database for future sessions
        save_template(
            fingerprint=fp,
            vendor=new_template["vendor"],
            device_type=new_template["device_type"],
            parse_mode=parse_mode,
            regex=new_template.get("regex", ""),
            header_regex=new_template.get("header_regex", ""),
            fields=ai.get("fields", []),
        )

        # Apply the new template
        if parse_mode == "kv":
            fields = _parse_kv(raw_syslog, ai.get("header_regex"))
        else:
            fields = _try_match(ai.get("regex", ""), raw_syslog)
        fields = fields or {"raw": raw_syslog}

        return {
            "fields": fields,
            "facility": facility,
            "severity": severity,
            "vendor": ai.get("vendor", "unknown"),
            "device_type": ai.get("device_type", "unknown"),
        }

    # Complete fallback, return raw
    _AI_FAILED[fp] = time.time()
    return {
        "fields": {"raw": raw_syslog},
        "facility": facility,
        "severity": severity,
        "vendor": "unknown",
        "device_type": "unknown",
    }