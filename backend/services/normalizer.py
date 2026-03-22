import json
import re
import time
from csv import reader as csv_reader

from ..config import OPENAI_CLIENT, OPENAI_MODEL_PARSER
from ..database.db import load_templates, save_template
from .vendors import BUILTIN_TEMPLATES, detect_fingerprint, enrich_vendor_fields

_OPENAI_CLIENT: object | None = OPENAI_CLIENT
_OPENAI_MODEL: str = OPENAI_MODEL_PARSER

_TEMPLATES: list[dict] = [
    *BUILTIN_TEMPLATES,
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
]

_AI_FAILED: dict[str, float] = {}
_AI_FAILED_TTL: float = 300.0  # retry after 5 minutes

_KV_RE = re.compile(r'(\w+)=("[^"]*"|\S+)')

_ARROW_IP_RE = re.compile(
    r"(?P<srcip>\d+\.\d+\.\d+\.\d+)"
    r"(?:\([^)]*\))?\s*->\s*"
    r"(?P<dstip>\d+\.\d+\.\d+\.\d+)",
    re.IGNORECASE,
)
_PROTO_RE = re.compile(r"\b(tcp|udp|icmp|ospf|gre|esp|http|https|ssh|dns|snmp)\b", re.IGNORECASE)

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
    return detect_fingerprint(source_ip, raw_syslog)

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

def _parse_csv(raw_syslog: str, fieldnames: list[str], min_columns: int = 0) -> dict | None:
    # Remove optional syslog priority (<166>) before CSV parsing.
    payload = re.sub(r"^<\d+>", "", raw_syslog).strip()
    row = next(csv_reader([payload]), None)
    if not row:
        return None
    if min_columns and len(row) < min_columns:
        return None

    out: dict = {}
    for idx, col in enumerate(fieldnames):
        if idx >= len(row):
            break
        value = row[idx].strip()
        if value:
            out[col] = value
    return out if out else None

# Vendor-agnostic best-effort enrichment from free-form message text.
def _enrich_common_message_fields(fields: dict, source_ip: str) -> dict:
    message = fields.get("message", "")
    if not isinstance(message, str) or not message:
        return fields

    arrow = _ARROW_IP_RE.search(message)
    if arrow:
        fields.setdefault("srcip", arrow.group("srcip"))
        fields.setdefault("dstip", arrow.group("dstip"))

    proto = _PROTO_RE.search(message)
    if proto:
        fields.setdefault("service", proto.group(1).lower())

    low = message.lower()
    if "action" not in fields:
        if any(tok in low for tok in ("permit", "allowed", "accepted")):
            fields["action"] = "permitted"
        elif any(tok in low for tok in ("deny", "denied", "blocked", "dropped")):
            fields["action"] = "denied"
        elif "heartbeat" in low:
            fields["action"] = "heartbeat"

    fields.setdefault("srcip", source_ip)
    return fields

def _infer_severity_from_fields(fields: dict, default_severity: int) -> int:
    """Infer syslog severity numeric value from the parsed fields."""
    sev_str = fields.get("level", fields.get("severity", ""))
    
    # Check for FortiGate 'apprisk' field
    apprisk = fields.get("apprisk", "").lower()
    if apprisk:
        if apprisk == "critical": return 2
        if apprisk == "high" or apprisk == "elevated": return 3
        if apprisk == "medium": return 4
        if apprisk == "low": return 5

    # Check for threatweight / crscore (FortiGate)
    threat_weight = fields.get("threatweight", fields.get("crscore", "0"))
    try:
        tw = int(threat_weight)
        if tw >= 50: return 2
        if tw >= 30: return 3
        if tw >= 20: return 4
    except ValueError:
        pass

    if isinstance(sev_str, str) and sev_str:
        low = sev_str.lower()
        if low in ("emergency", "emerg"): return 0
        if low in ("alert",): return 1
        if low in ("critical", "crit"): return 2
        if low in ("error", "err"): return 3
        if low in ("warning", "warn"): return 4
        if low in ("notice",): return 5
        if low in ("informational", "info"): return 6
        if low in ("debug",): return 7
    
    # Fallback to checking the action / fw rules for PaloAlto and others
    action = fields.get("action", "").lower()
    if action in ("deny", "drop", "blocked", "server-rst", "timeout"):
        # We can map specific apps to higher severities if blocked
        app = fields.get("app", "").lower()
        if app in ("irc", "quic", "ssh"): return 2 # Critical
        if app in ("web-browsing", "smb", "nmap", "ftp"): return 3 # High
        return 4 # Medium
        
    return default_severity

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

    # Try existing templates for THIS fingerprint only.
    # Without this filter, a learned template for one source can mislabel others.
    for template in _TEMPLATES:
        if template.get("fingerprint") != fp:
            continue
        parse_mode = template.get("parse_mode", "regex")
        if parse_mode == "kv":
            fields = _parse_kv(raw_syslog, template.get("header_regex"))
        elif parse_mode == "csv":
            fields = _parse_csv(
                raw_syslog,
                template.get("csv_fieldnames", []),
                int(template.get("csv_min_columns", 0) or 0),
            )
        else:
            fields = _try_match(template["regex"], raw_syslog)
        if fields:
            fields = enrich_vendor_fields(template["vendor"], fields)
            fields = _enrich_common_message_fields(fields, source_ip)
            severity = _infer_severity_from_fields(fields, severity)
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
        elif parse_mode == "csv":
            new_template["regex"] = ""
            new_template["csv_fieldnames"] = ai.get("csv_fieldnames", [])
            new_template["csv_min_columns"] = int(ai.get("csv_min_columns", 0) or 0)
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
        elif parse_mode == "csv":
            fields = _parse_csv(
                raw_syslog,
                ai.get("csv_fieldnames", []),
                int(ai.get("csv_min_columns", 0) or 0),
            )
        else:
            fields = _try_match(ai.get("regex", ""), raw_syslog)
        fields = fields or {"raw": raw_syslog}

        fields = enrich_vendor_fields(ai.get("vendor", "unknown"), fields)
        fields = _enrich_common_message_fields(fields, source_ip)
        severity = _infer_severity_from_fields(fields, severity)

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