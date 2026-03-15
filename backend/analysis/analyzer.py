from __future__ import annotations

import threading
from pydantic import BaseModel, Field
import time

from ..config import OPENAI_CLIENT, OPENAI_MODEL_AGENT, OPENAI_MODEL_REASONING
from ..database.db import get_alerts, get_devices_list, find_duplicate_alert, insert_alert, get_recent_logs, get_connection
from ..services.soar import auto_respond_to_alert

_CLIENT: object | None = OPENAI_CLIENT
_MODEL_TRIAGE: str = OPENAI_MODEL_AGENT
_MODEL_REASONING: str = OPENAI_MODEL_REASONING

# Fields to keep when compacting logs for token efficiency
_SECURITY_FIELDS = {
    "date", "time", "srcip", "srcport", "dstip", "dstport",
    "action", "proto", "service", "level", "policyname",
    "sentbyte", "rcvdbyte", "sentpkt", "rcvdpkt",
    "app", "devname", "threatweight", "utmaction", "utmevent", "crscore",
    # Generic syslog
    "hostname", "process", "mnemonic", "message", "severity_level",
}

# ---------------------------------------------------------------------------
# Helper functions 
# ---------------------------------------------------------------------------
# Produce a one-line summary keeping only security-relevant fields.
def _compact_log(entry: dict) -> str:
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

class TriageFinding(BaseModel):
    severity: str = Field(description="critical|high|medium|low|info")
    title: str = Field(description="Short descriptive title")
    summary: str = Field(description="Brief explanation of the concern")
    related_indices: list[int] = Field(description="Indices of related logs")

class TriageResult(BaseModel):
    threats_detected: bool
    findings: list[TriageFinding]

class Mitigation(BaseModel):
    description: str = Field(description="What to do")
    command: str = Field(description="Device-specific CLI command (e.g. FortiGate CLI) or 'N/A'")
    risk: str = Field(description="low|medium|high")

class DeepAnalysisResult(BaseModel):
    severity: str = Field(description="critical|high|medium|low|info")
    title: str = Field(description="Refined alert title")
    analysis: str = Field(description="Detailed explanation of the threat, attack vector, and any correlations with past alerts")
    mitigations: list[Mitigation]
    affected_devices: list[str] = Field(description="List of device IPs from the inventory that actually generated the problematic logs. Do NOT include devices that didn't generate the logs.")

class EvaluationResult(BaseModel):
    attack_stopped: bool
    reasoning: str

# ---------------------------------------------------------------------------
# Tier 1: Triage
# ---------------------------------------------------------------------------
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

If there are security concerns, explain each distinct concern providing severity, title, summary, and indices of related logs in the required JSON format.

If the logs appear entirely benign, set threats_detected to false and provide an empty array for findings.

Logs (each line is one entry, prefixed with index #):
"""

def _triage_batch(batch: list[dict]) -> dict | None:
    if not _CLIENT:
        print("[analyzer] OPENAI_API_KEY not set — skipping triage")
        return None
    log_text = _numbered_logs(batch)
    try:
        resp = _CLIENT.beta.chat.completions.parse(
            model=_MODEL_TRIAGE,
            messages=[{"role": "user", "content": _TRIAGE_PROMPT + log_text}],
            response_format=TriageResult,
            temperature=0,
            max_tokens=1500,
        )
        return resp.choices[0].message.parsed.model_dump()
    except Exception as exc:
        print(f"[analyzer] triage API error: {exc}")
        return None

# ---------------------------------------------------------------------------
# Tier 2: Deep Analysis
# ---------------------------------------------------------------------------
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
"""

def _deep_analyze(finding: dict, related_logs: list[dict], past_alerts: list[dict], devices: list[dict]) -> dict | None:
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
        resp = _CLIENT.beta.chat.completions.parse(
            model=_MODEL_REASONING,
            messages=[{"role": "user", "content": prompt}],
            response_format=DeepAnalysisResult,
        )
        parsed = resp.choices[0].message.parsed
        if not parsed:
            print(f"[analyzer] deep-analysis: empty response (finish_reason={resp.choices[0].finish_reason})")
            return None
        return parsed.model_dump()
    except Exception as exc:
        print(f"[analyzer] deep-analysis API error: {exc}")
        return None

# ---------------------------------------------------------------------------
# Tier 3: Evaluation Loop
# ---------------------------------------------------------------------------
_EVALUATION_PROMPT = """\
You are a SOC analyst evaluating the effectiveness of an automated mitigation.
2 minutes ago, the following alert was triggered:
Title: {title}
Summary: {summary}

Since then, the following logs have been observed from the affected devices:
{logs}

Did the attack stop? Analyze the recent logs to determine if the malicious behavior is still present.
"""

def _evaluate_mitigation(alert_id: int, title: str, summary: str, devices: list[str]) -> None:
    time.sleep(120)  # Wait 2 minutes for log stream to capture any ongoing attack
    print(f"[analyzer] evaluating mitigation success for alert #{alert_id}...")
    
    # fetch logs for devices
    recent = get_recent_logs(limit=100)
    if devices:
        recent = [l for l in recent if l.get("source_ip") in devices]
        
    log_text = _numbered_logs([
        {"vendor": l["vendor"], "source_ip": l["source_ip"], "fields": l.get("parsed_fields", {})} 
        for l in recent
    ])
    
    prompt = _EVALUATION_PROMPT.format(title=title, summary=summary, logs=log_text)
    
    if not _CLIENT:
        return
        
    try:
        resp = _CLIENT.beta.chat.completions.parse(
            model=_MODEL_TRIAGE,
            messages=[{"role": "user", "content": prompt}],
            response_format=EvaluationResult,
        )
        parsed = resp.choices[0].message.parsed
        if not parsed:
            return
        
        status_tag = "Action Verified: Successful" if parsed.attack_stopped else "Action Verified: Failed"
        append_text = f"\n\n**Mitigation Evaluation**: {status_tag} - {parsed.reasoning}"
        
        conn = get_connection()
        conn.execute(
            "UPDATE alerts SET analysis = analysis || ?, status = ? WHERE id = ?", 
            (append_text, status_tag if parsed.attack_stopped else "open", alert_id)
        )
        conn.commit()
        conn.close()
        print(f"[analyzer] updated alert #{alert_id} evaluation: {status_tag}")
        
    except Exception as exc:
        print(f"[analyzer] evaluation API error: {exc}")

# - Full two-tier analysis pipeline.
# - Called from the pipeline's agent queue when a batch is ready.
# - Runs in its own daemon thread so it doesn't block log ingestion.
def analyze_batch(batch: list[dict]) -> None:
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
            title = finding["title"]
            if find_duplicate_alert(title):
                print(f"[analyzer] skipping duplicate alert: {title}")
                continue
            alert_id = insert_alert(
                severity=finding["severity"],
                title=title,
                summary=finding["summary"],
                related_logs=[_compact_log(e) for e in related[:20]],
            )
            print(f"[analyzer] stored triage-only alert #{alert_id}: {title}")
            actions = auto_respond_to_alert(
                alert_id=alert_id,
                severity=finding["severity"],
                affected_devices=[],
            )
            if actions:
                print(f"[analyzer] auto-response triggered {len(actions)} action(s) for alert #{alert_id}")
                threading.Thread(
                    target=_evaluate_mitigation, 
                    args=(alert_id, title, finding["summary"], []), 
                    daemon=True
                ).start()
            continue

        title = analysis.get("title", finding["title"])
        if find_duplicate_alert(title):
            print(f"[analyzer] skipping duplicate alert: {title}")
            continue
        alert_id = insert_alert(
            severity=analysis.get("severity", finding["severity"]),
            title=title,
            summary=finding["summary"],
            analysis=analysis.get("analysis", ""),
            mitigations=analysis.get("mitigations", []),
            affected_devices=analysis.get("affected_devices", []),
            related_logs=[_compact_log(e) for e in related[:20]],
        )
        print(f"[analyzer] stored alert #{alert_id}: {title}")
        actions = auto_respond_to_alert(
            alert_id=alert_id,
            severity=analysis.get("severity", finding["severity"]),
            affected_devices=analysis.get("affected_devices", []),
        )
        if actions:
            print(f"[analyzer] auto-response triggered {len(actions)} action(s) for alert #{alert_id}")
            threading.Thread(
                target=_evaluate_mitigation, 
                args=(alert_id, title, finding["summary"], analysis.get("affected_devices", [])), 
                daemon=True
            ).start()

def analyze_batch_async(batch: list[dict]) -> None:
    threading.Thread(
        target=analyze_batch, args=(batch,), name="analyzer", daemon=True
    ).start()
