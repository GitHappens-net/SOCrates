"""
SOCrates Threat Analyzer — two-tier AI analysis pipeline.

Tier 1 (Triage):   GPT-4.1   — fast scan of log batches for anomalies.
Tier 2 (Analysis): GPT-5.1   — deep reasoning, correlation, and mitigations.
"""
from __future__ import annotations

import json
import os
import re
import threading
from pathlib import Path

from dotenv import load_dotenv
from openai import OpenAI

from backend.database.db import (
    get_alerts,
    get_devices_list,
    insert_alert,
)

load_dotenv(Path(__file__).resolve().parent.parent / ".env")

_OPENAI_KEY: str | None = os.getenv("OPENAI_API_KEY")
_MODEL_TRIAGE: str = os.getenv("OPENAI_MODEL_AGENT", "gpt-4.1")
_MODEL_REASONING: str = os.getenv("OPENAI_MODEL_REASONING", "gpt-5.1")
_CLIENT: OpenAI | None = OpenAI(api_key=_OPENAI_KEY) if _OPENAI_KEY else None

# Fields to keep when compacting logs for token efficiency
_SECURITY_FIELDS = {
    "date", "time", "srcip", "srcport", "dstip", "dstport",
    "action", "proto", "service", "level", "policyname",
    "sentbyte", "rcvdbyte", "sentpkt", "rcvdpkt",
    "app", "devname", "threatweight", "utmaction", "utmevent", "crscore",
    # Generic syslog
    "hostname", "process", "mnemonic", "message", "severity_level",
}


# ── Helpers ───────────────────────────────────────────────────────────────

def _compact_log(entry: dict) -> str:
    """Produce a one-line summary keeping only security-relevant fields."""
    f = entry["fields"]
    parts = [f"{entry['vendor']}/{entry['source_ip']}"]
    for k in _SECURITY_FIELDS:
        if k in f:
            parts.append(f"{k}={f[k]}")
    return " ".join(parts)


def _numbered_logs(batch: list[dict]) -> str:
    return "\n".join(
        f"#{i} {_compact_log(e)}" for i, e in enumerate(batch)
    )


def _format_alerts_context(alerts: list[dict]) -> str:
    if not alerts:
        return "No previous alerts."
    lines = []
    for a in alerts[:15]:
        lines.append(
            f"[{a['severity'].upper()}] #{a['id']} ({a['status']}) — "
            f"{a['title']}: {a['summary']}"
        )
    return "\n".join(lines)


def _format_devices_context(devices: list[dict]) -> str:
    if not devices:
        return "No known devices."
    return "\n".join(
        f"- {d['ip']}  hostname={d.get('hostname', '?')}  "
        f"vendor={d['vendor']}  type={d['device_type']}"
        for d in devices
    )


def _parse_json(text: str) -> dict | None:
    """Best-effort JSON extraction from AI response."""
    text = re.sub(r"^```(?:json)?\s*", "", text.strip())
    text = re.sub(r"\s*```$", "", text)
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return None


# ── Tier 1: Triage (GPT-4.1) ─────────────────────────────────────────────

_TRIAGE_PROMPT = """\
You are a SOC Level-1 analyst performing initial triage on a batch of firewall / network device logs.

Review the log entries below and identify any security concerns such as:
- Port scanning or reconnaissance
- Brute-force login attempts (many denied connections to SSH/FTP/RDP)
- DDoS or volumetric attacks
- Botnet command-and-control traffic
- Web application attacks (SQLi, XSS)
- Policy violations or lateral movement
- Any anomalous patterns

For each distinct concern, provide a severity, title, summary, and the indices of related logs.

Respond with ONLY valid JSON — no markdown, no explanation:
{
  "threats_detected": true,
  "findings": [
    {
      "severity": "critical|high|medium|low|info",
      "title": "Short descriptive title",
      "summary": "Brief explanation of the concern",
      "related_indices": [0, 5, 12]
    }
  ]
}

If the logs appear entirely benign, respond:
{"threats_detected": false, "findings": []}

Logs (each line is one entry, prefixed with index #):
"""


def _triage_batch(batch: list[dict]) -> dict | None:
    if not _CLIENT:
        print("[analyzer] OPENAI_API_KEY not set — skipping triage")
        return None
    log_text = _numbered_logs(batch)
    try:
        resp = _CLIENT.chat.completions.create(
            model=_MODEL_TRIAGE,
            messages=[{"role": "user", "content": _TRIAGE_PROMPT + log_text}],
            temperature=0,
            max_tokens=1500,
        )
        return _parse_json(resp.choices[0].message.content)
    except Exception as exc:
        print(f"[analyzer] triage API error: {exc}")
        return None


# ── Tier 2: Deep Analysis (GPT-5.1) ──────────────────────────────────────

_ANALYSIS_PROMPT = """\
You are SOCrates, a senior SOC analyst. A triage scan flagged a potential security threat.
Perform a deep analysis: explain what is happening, assess the real severity, correlate with any past alerts, and suggest concrete mitigations.

## Flagged Concern
Title: {title}
Severity: {severity}
Summary: {summary}

## Related Log Entries
{logs}

## Historical Alerts
{past_alerts}

## Device Inventory
{devices}

Respond with ONLY valid JSON — no markdown, no explanation:
{{
  "severity": "critical|high|medium|low|info",
  "title": "Refined alert title",
  "analysis": "Detailed explanation of the threat, attack vector, and any correlations with past alerts",
  "mitigations": [
    {{
      "description": "What to do",
      "command": "Device-specific CLI command (e.g. FortiGate CLI) or 'N/A'",
      "risk": "low|medium|high"
    }}
  ],
  "affected_devices": ["10.0.0.1"]
}}"""


def _deep_analyze(
    finding: dict,
    related_logs: list[dict],
    past_alerts: list[dict],
    devices: list[dict],
) -> dict | None:
    if not _CLIENT:
        return None
    prompt = _ANALYSIS_PROMPT.format(
        title=finding["title"],
        severity=finding["severity"],
        summary=finding["summary"],
        logs=_numbered_logs(related_logs),
        past_alerts=_format_alerts_context(past_alerts),
        devices=_format_devices_context(devices),
    )
    try:
        resp = _CLIENT.chat.completions.create(
            model=_MODEL_REASONING,
            messages=[{"role": "user", "content": prompt}],
            temperature=0,
            max_completion_tokens=2000,
        )
        return _parse_json(resp.choices[0].message.content)
    except Exception as exc:
        print(f"[analyzer] deep-analysis API error: {exc}")
        return None


# ── Orchestrator ──────────────────────────────────────────────────────────

def analyze_batch(batch: list[dict]) -> None:
    """
    Full two-tier analysis pipeline.
    Called from the pipeline's agent queue when a batch is ready.
    Runs in its own daemon thread so it doesn't block log ingestion.
    """
    print(f"[analyzer] starting triage on {len(batch)} logs")

    # Tier 1: triage
    result = _triage_batch(batch)
    if not result or not result.get("threats_detected"):
        print("[analyzer] triage: no threats detected")
        return

    findings = result.get("findings", [])
    print(f"[analyzer] triage found {len(findings)} concern(s) — escalating to deep analysis")

    # Context for Tier 2
    past_alerts = get_alerts(limit=20)
    devices = get_devices_list()

    for finding in findings:
        # Gather the related log entries
        indices = finding.get("related_indices", [])
        related = [batch[i] for i in indices if 0 <= i < len(batch)]
        if not related:
            related = batch  # fallback: use entire batch

        # Tier 2: deep analysis
        analysis = _deep_analyze(finding, related, past_alerts, devices)
        if not analysis:
            # Fallback: store triage finding directly
            alert_id = insert_alert(
                severity=finding["severity"],
                title=finding["title"],
                summary=finding["summary"],
                related_logs=[_compact_log(e) for e in related[:20]],
            )
            print(f"[analyzer] stored triage-only alert #{alert_id}: {finding['title']}")
            continue

        alert_id = insert_alert(
            severity=analysis.get("severity", finding["severity"]),
            title=analysis.get("title", finding["title"]),
            summary=finding["summary"],
            analysis=analysis.get("analysis", ""),
            mitigations=analysis.get("mitigations", []),
            affected_devices=analysis.get("affected_devices", []),
            related_logs=[_compact_log(e) for e in related[:20]],
        )
        print(f"[analyzer] stored alert #{alert_id}: {analysis.get('title', finding['title'])}")


def analyze_batch_async(batch: list[dict]) -> None:
    """Fire-and-forget wrapper — spawns analyze_batch in a daemon thread."""
    threading.Thread(
        target=analyze_batch, args=(batch,), name="analyzer", daemon=True
    ).start()
