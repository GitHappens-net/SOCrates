#  1. Fingerprint the log (identify likely format/vendor).
#  2. Try all known templates (regex match).
#  3. If no template matches -> OpenAI agent generates one, cache it in-memory, then apply it.
#  4. Return a structured dict.

import json
import os
import re
import sys
from pathlib import Path
from dotenv import load_dotenv
from openai import OpenAI

sys.path.insert(0, str(Path(__file__).parent.parent))

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

]

# Syslog priority helpers
def _decode_priority(priority: int) -> tuple[int, int]:
    return priority >> 3, priority & 0x7

def _extract_priority(raw_syslog: str) -> tuple[int, int]:
    m = re.match(r"^<(\d+)>", raw_syslog)
    if m:
        return _decode_priority(int(m.group(1)))
    return -1, -1

# Fingerprinting
def _fingerprint(source_ip: str, raw_syslog: str) -> str:
    if re.search(r"%[A-Z0-9]+-\d+-[A-Z0-9_]+:", raw_syslog):
        return "cisco_ios_syslog"
    if re.search(r"<\d+>\d+:\s*\*?[A-Z][a-z]{2}\s+\d+\s+[\d:\.]+:", raw_syslog):
        return "cisco_ios_debug"
    if re.search(r"<\d+>[A-Z][a-z]{2}\s+\d+\s+\d+:\d+:\d+\s+\S+\s+\S+", raw_syslog):
        return "linux_syslog_standard"
    return f"unknown_{source_ip}"

# Regex matching
def _try_match(pattern: str, text: str) -> dict | None:
    m = re.search(pattern, text, re.DOTALL)
    if m:
        return {k: v for k, v in m.groupdict().items() if v is not None}

    return None

# AI template generation
def _ai_generate_template(raw_syslog: str, fingerprint: str) -> dict | None:
    load_dotenv(Path(__file__).parent.parent / ".env")
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        print("OPENAI_API_KEY not set — cannot generate template for '%s'", fingerprint)
        return None

    model = os.getenv("OPENAI_MODEL_PARSER", "gpt-4.1")
    client = OpenAI(api_key=api_key)

    prompt = f"""You are a log-parsing expert for a Security Operations Centre (SOC).

Analyse the syslog message below and produce a Python regex with named capture groups
that generalises well to similar messages from the same device/process.

Raw syslog message:
{raw_syslog}

Rules:
- Use Python named groups: (?P<field_name>...)
- Make the regex general, not hardcoded to exact values in the example.
- Common fields to try to capture: priority, log_timestamp, hostname, process, pid, message,
  and any vendor-specific fields (facility, severity_level, mnemonic for Cisco, etc.).
- Respond with ONLY valid JSON, no markdown, no explanation.

Required JSON format:
{{
  "vendor": "string — e.g. Cisco, Linux, Juniper, Palo Alto",
  "device_type": "string — e.g. IOS Router, Ubuntu Host",
  "regex": "python regex string with named groups",
  "fields": ["list", "of", "captured", "field", "names"]
}}"""

    response = client.chat.completions.create(
        model=model,
        messages=[{"role": "user", "content": prompt}],
        temperature=0,
        max_tokens=600,
    )

    content = response.choices[0].message.content.strip()
    content = re.sub(r"^```(?:json)?\s*", "", content)
    content = re.sub(r"\s*```$", "", content)

    return json.loads(content)

# Fingerprints that failed AI generation this session — don't retry
_AI_FAILED: set[str] = set()

# Main entry point
def normalize_log(source_ip: str, raw_syslog: str) -> dict:
    facility, severity = _extract_priority(raw_syslog)
    fp = _fingerprint(source_ip, raw_syslog)

    # Try existing templates
    for template in _TEMPLATES:
        fields = _try_match(template["regex"], raw_syslog)
        if fields:
            return {
                "fields": fields,
                "facility": facility,
                "severity": severity,
                "vendor": template["vendor"],
                "device_type": template["device_type"],
            }

    # 2 No template match, generate with AI
    if fp in _AI_FAILED:
        return {"fields": {"raw": raw_syslog}, "facility": facility, "severity": severity, "vendor": "unknown", "device_type": "unknown"}
    ai = _ai_generate_template(raw_syslog, fp)

    if ai and ai.get("regex"):
        _TEMPLATES.append({
            "fingerprint": fp,
            "vendor": ai.get("vendor", "unknown"),
            "device_type": ai.get("device_type", "unknown"),
            "regex": ai["regex"],
        })
        fields = _try_match(ai["regex"], raw_syslog) or {"raw": raw_syslog}
        return {
            "fields": fields,
            "facility": facility,
            "severity": severity,
            "vendor": ai.get("vendor", "unknown"),
            "device_type": ai.get("device_type", "unknown"),
        }

    # 3 Complete fallback, return raw
    _AI_FAILED.add(fp)
    return {
        "fields": {"raw": raw_syslog},
        "facility": facility,
        "severity": severity,
        "vendor": "unknown",
        "device_type": "unknown",
    }