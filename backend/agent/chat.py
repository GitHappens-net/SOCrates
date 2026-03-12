from __future__ import annotations

import re
import threading
from datetime import datetime

from config import OPENAI_CLIENT, OPENAI_MODEL_REASONING
from database.db import get_alerts, get_alerts_since, get_devices_list, get_log_stats
from services.soar import execute_soar_action

_CLIENT: object | None = OPENAI_CLIENT
_MODEL: str = OPENAI_MODEL_REASONING

_sessions: dict[str, list[dict]] = {}
_pending_soar: dict[str, dict] = {}
_lock = threading.Lock()

_MAX_HISTORY = 40  # max messages kept per session

_SYSTEM_PROMPT = """\
You are SOCrates, an AI-powered Security Operations Centre (SOC) assistant.
You help security analysts monitor their infrastructure, investigate alerts,
correlate events, and recommend mitigations.

Guidelines:
- Be concise and actionable.
- When suggesting mitigations, include device-specific CLI commands
  (for example FortiGate CLI commands for Fortinet devices).
- Reference specific alert IDs, device IPs, and log data when available.
- If you don't have enough information to answer, say so clearly.
- You have live access to SOCrates database context on every turn.
- Never claim you do not have live feed/SIEM access unless the context payload is explicitly empty or contains an error.
- Never relabel device vendors or types.
- Treat vendor/type exactly as given in Device Inventory.
- Do not call Cisco IOS routers "FortiGate" or "firewalls" unless their vendor is Fortinet.
- SOCrates itself is the collector and parser in this deployment (syslog ingest + DB + analysis pipeline).
- Do not ask the user for SIEM/collector details unless the user explicitly asks to integrate an external SIEM.
- When the user asks about current threats/logging status, answer from SOCrates context first.

## Current Infrastructure Context

### Device Inventory
{devices}

### Device Roles by Vendor
{device_roles}

### Recent Alerts
{alerts}

### Log Statistics
{stats}

### Snapshot Time (UTC)
{now_utc}
"""

def _build_system_prompt() -> str:
    devices = get_devices_list()
    alerts = get_alerts(limit=25)
    stats = get_log_stats()

    devices_text = "\n".join(
        f"- {d['ip']}  hostname={d.get('hostname', '?')}  "
        f"vendor={d['vendor']}  type={d['device_type']}  last_seen={d['last_seen']}"
        for d in devices
    ) or "No devices registered yet."

    fortinet = [d for d in devices if str(d.get("vendor", "")).lower() == "fortinet"]
    cisco = [d for d in devices if str(d.get("vendor", "")).lower() == "cisco"]
    linux = [d for d in devices if str(d.get("vendor", "")).lower() == "linux"]

    def _fmt(ds: list[dict]) -> str:
        if not ds:
            return "none"
        return ", ".join(f"{d['ip']}({d.get('hostname') or '?'})" for d in ds)

    device_roles_text = (
        f"Fortinet devices: {_fmt(fortinet)}\n"
        f"Cisco devices: {_fmt(cisco)}\n"
        f"Linux devices: {_fmt(linux)}"
    )

    alerts_text = "\n".join(
        f"- [{a['severity'].upper()}] Alert #{a['id']} ({a['status']}) — "
        f"{a['title']}: {a['summary']}"
        + (f"\n  Analysis: {a['analysis'][:200]}" if a.get("analysis") else "")
        for a in alerts
    ) or "No alerts."

    stats_text = (
        f"Total logs ingested: {stats['total_logs']}\n"
        f"By vendor: {stats['by_vendor']}\n"
        f"Top devices (ip->count): {stats['by_device']}\n"
        + "Top devices detailed:\n"
        + "\n".join(
            f"- {d['ip']}  hostname={d.get('hostname') or '?'}  vendor={d.get('vendor')}  type={d.get('device_type')}  logs={d.get('count')}"
            for d in stats.get("by_device_detailed", [])
        )
    )

    return _SYSTEM_PROMPT.format(
        devices=devices_text,
        device_roles=device_roles_text,
        alerts=alerts_text,
        stats=stats_text,
        now_utc=datetime.utcnow().isoformat(timespec="seconds"),
    )

def _extract_recent_threat_minutes(message: str) -> int | None:
    text = message.lower()
    if "last" not in text:
        return None
    if not any(k in text for k in ("threat", "alert", "new")):
        return None

    m = re.search(r"last\s+(\d+)\s*(minute|minutes|min|mins|m)\b", text)
    if m:
        return max(1, min(24 * 60, int(m.group(1))))

    if "last 5 min" in text or "last 5 minute" in text:
        return 5
    return None

def _build_recent_threats_reply(minutes: int) -> str:
    recent = get_alerts_since(minutes=minutes, limit=200)

    # Threat-centric view: focus on open/acknowledged first.
    active = [a for a in recent if a.get("status") in ("open", "acknowledged")]
    to_report = active if active else recent

    if not to_report:
        return (
            f"No new alerts were created in the last {minutes} minutes based on the live SOCrates database.\n\n"
            "Status: no newly detected threats in that time window."
        )

    lines = [
        f"Found {len(to_report)} alert(s) in the last {minutes} minutes (live DB):"
    ]
    for a in to_report[:8]:
        lines.append(
            f"- Alert #{a['id']} [{a['severity'].upper()}] ({a['status']}) at {a['created_at']}: {a['title']}"
        )
    if len(to_report) > 8:
        lines.append(f"- ...and {len(to_report) - 8} more.")

    return "\n".join(lines)


_IP_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")


def _extract_soar_intent(message: str) -> dict | None:
    text = message.lower().strip()

    # e.g. "close port 22 on 127.0.0.1" / "could you close port 22 on the device with ip 127.0.0.1"
    m_close = re.search(
        r"(?:close|block|deny|shutdown|shut\s*down)\b.*?"
        r"port\s+(?P<port>\d{1,5})"
        r"(?:\s*(?:/|over\s+)?(?P<proto>tcp|udp|both))?"
        r"(?:.*?\bon\s+(?:the\s+)?(?:device\s+)?(?:with\s+ip\s+)?(?P<device>\d+\.\d+\.\d+\.\d+))?",
        text,
    )
    if m_close:
        d = m_close.groupdict()
        return {
            "type": "close_port",
            "port": int(d["port"]),
            "protocol": d.get("proto") or "tcp",
            "device_ip": d.get("device"),
        }

    # e.g. "block ip 1.2.3.4 on 127.0.0.1" / "quarantine 1.2.3.4 on device with ip ..."
    m_block = re.search(
        r"(?:block|quarantine)\s+(?:ip\s+)?(?P<target>\d+\.\d+\.\d+\.\d+)"
        r"(?:\s+on\s+(?:the\s+)?(?:device\s+)?(?:with\s+ip\s+)?(?P<device>\d+\.\d+\.\d+\.\d+))?",
        text,
    )
    if m_block:
        d = m_block.groupdict()
        return {
            "type": "block_ip",
            "target_ip": d["target"],
            "device_ip": d.get("device"),
        }

    return None


def _extract_partial_soar_intent(message: str) -> dict | None:
    text = message.lower().strip()

    # Intent to close/block a port but port number is missing.
    if re.search(r"(?:close|block|deny|shutdown|shut\s*down).*\bport\b", text):
        m_proto = re.search(r"\b(tcp|udp|both)\b", text)
        m_dev = re.search(r"(?:device\s+with\s+ip\s+|on\s+)(\d+\.\d+\.\d+\.\d+)", text)
        return {
            "type": "close_port",
            "protocol": m_proto.group(1) if m_proto else "tcp",
            "device_ip": m_dev.group(1) if m_dev else None,
            "missing": ["port"],
        }

    # Intent to block/quarantine an IP but target is missing.
    if re.search(r"\b(block|quarantine)\b", text) and ("ip" in text or "host" in text):
        m_dev = re.search(r"(?:device\s+with\s+ip\s+|on\s+)(\d+\.\d+\.\d+\.\d+)", text)
        return {
            "type": "block_ip",
            "device_ip": m_dev.group(1) if m_dev else None,
            "missing": ["target_ip"],
        }

    return None


def _infer_device_from_history(history: list[dict]) -> str | None:
    """Infer likely Fortinet device IP from recent conversation context."""
    devices = get_devices_list()
    fortigate_ips = {
        str(d.get("ip"))
        for d in devices
        if str(d.get("vendor", "")).lower() == "fortinet"
    }
    if not fortigate_ips:
        return None

    # Search latest messages first; pick first IP that is a Fortinet device.
    for msg in reversed(history[-12:]):
        content = str(msg.get("content", ""))
        for ip in _IP_RE.findall(content):
            if ip in fortigate_ips:
                return ip

    # Fallback: most recently seen Fortinet device.
    for d in devices:
        if str(d.get("vendor", "")).lower() == "fortinet":
            return str(d.get("ip"))
    return None


def _default_fortigate_device_ip() -> str | None:
    devices = get_devices_list()
    for d in devices:
        if str(d.get("vendor", "")).lower() == "fortinet":
            return d.get("ip")
    return None


def _fill_pending_from_message(pending: dict, message: str) -> dict:
    out = dict(pending)
    text = message.lower()

    # Global cancel path.
    if any(x in text for x in ("cancel", "never mind", "nevermind", "stop")):
        out["cancelled"] = True
        return out

    ips = _IP_RE.findall(message)
    if pending.get("type") == "close_port":
        m_port = re.search(r"\b(\d{1,5})\b", text)
        if m_port:
            out["port"] = int(m_port.group(1))
        m_proto = re.search(r"\b(tcp|udp|both)\b", text)
        if m_proto:
            out["protocol"] = m_proto.group(1)
        if ips:
            out["device_ip"] = ips[0]
    elif pending.get("type") == "block_ip":
        if ips:
            # First IP is treated as target if missing target, second as device if present.
            if not out.get("target_ip"):
                out["target_ip"] = ips[0]
                if len(ips) > 1:
                    out["device_ip"] = ips[1]
            else:
                out["device_ip"] = ips[0]

    return out


def _missing_fields(intent: dict) -> list[str]:
    if intent.get("type") == "close_port":
        return ["port"] if not intent.get("port") else []
    if intent.get("type") == "block_ip":
        return ["target_ip"] if not intent.get("target_ip") else []
    return []


def _followup_prompt(intent: dict, history: list[dict]) -> str:
    miss = _missing_fields(intent)
    inferred_device = intent.get("device_ip") or _infer_device_from_history(history) or _default_fortigate_device_ip()

    if intent.get("type") == "close_port" and "port" in miss:
        if inferred_device:
            return (
                f"I can do that. Which port should I close on {inferred_device}? "
                "Optionally specify protocol (tcp/udp/both)."
            )
        return "I can do that. Which port should I close, and on which FortiGate IP?"

    if intent.get("type") == "block_ip" and "target_ip" in miss:
        if inferred_device:
            return f"I can do that. Which target IP should I block on {inferred_device}?"
        return "I can do that. Which target IP should I block, and on which FortiGate IP?"

    return "Please provide the missing action details."


def _handle_soar_intent(intent: dict, session_id: str, message: str, history: list[dict]) -> str:
    device_ip = intent.get("device_ip") or _infer_device_from_history(history) or _default_fortigate_device_ip()
    if not device_ip:
        return "No Fortinet device is available in inventory to execute this action."

    if intent["type"] == "close_port":
        res = execute_soar_action(
            device_ip=device_ip,
            action_type="close_port",
            parameters={
                "port": intent["port"],
                "protocol": intent["protocol"],
            },
            requested_by="chat",
            source="chat",
            dry_run=False,
        )
        reply = (
            f"SOAR action {'succeeded' if res.ok else 'failed'}: close_port on {device_ip}.\n"
            f"action_id={res.action_id} status={res.status}.\n"
            f"{res.summary}"
        )
    elif intent["type"] == "block_ip":
        res = execute_soar_action(
            device_ip=device_ip,
            action_type="block_ip",
            parameters={"target_ip": intent["target_ip"]},
            requested_by="chat",
            source="chat",
            dry_run=False,
        )
        reply = (
            f"SOAR action {'succeeded' if res.ok else 'failed'}: block_ip {intent['target_ip']} on {device_ip}.\n"
            f"action_id={res.action_id} status={res.status}.\n"
            f"{res.summary}"
        )
    else:
        reply = "Unsupported SOAR intent."

    with _lock:
        history = _sessions.setdefault(session_id, [])
        history.append({"role": "user", "content": message})
        history.append({"role": "assistant", "content": reply})
        if len(history) > _MAX_HISTORY:
            history[:] = history[-_MAX_HISTORY:]
    return reply

def chat(message: str, session_id: str = "default") -> str:
    if not _CLIENT:
        return "Error: OPENAI_API_KEY is not configured."

    minutes = _extract_recent_threat_minutes(message)
    if minutes is not None:
        reply = _build_recent_threats_reply(minutes)
        with _lock:
            history = _sessions.setdefault(session_id, [])
            history.append({"role": "user", "content": message})
            history.append({"role": "assistant", "content": reply})
            if len(history) > _MAX_HISTORY:
                history[:] = history[-_MAX_HISTORY:]
        return reply

    with _lock:
        history_snapshot = list(_sessions.setdefault(session_id, []))
        pending = _pending_soar.get(session_id)

    # Continue an existing follow-up flow.
    if pending is not None:
        filled = _fill_pending_from_message(pending, message)
        if filled.get("cancelled"):
            with _lock:
                _pending_soar.pop(session_id, None)
            reply = "Cancelled the pending SOAR action."
            with _lock:
                history = _sessions.setdefault(session_id, [])
                history.append({"role": "user", "content": message})
                history.append({"role": "assistant", "content": reply})
                if len(history) > _MAX_HISTORY:
                    history[:] = history[-_MAX_HISTORY:]
            return reply

        # Auto-fill device from context if still missing.
        if not filled.get("device_ip"):
            filled["device_ip"] = _infer_device_from_history(history_snapshot) or _default_fortigate_device_ip()

        if _missing_fields(filled):
            with _lock:
                _pending_soar[session_id] = filled
            reply = _followup_prompt(filled, history_snapshot)
            with _lock:
                history = _sessions.setdefault(session_id, [])
                history.append({"role": "user", "content": message})
                history.append({"role": "assistant", "content": reply})
                if len(history) > _MAX_HISTORY:
                    history[:] = history[-_MAX_HISTORY:]
            return reply

        with _lock:
            _pending_soar.pop(session_id, None)
        return _handle_soar_intent(filled, session_id, message, history_snapshot)

    intent = _extract_soar_intent(message)
    if intent is not None:
        # Auto-fill device when omitted.
        if not intent.get("device_ip"):
            intent["device_ip"] = _infer_device_from_history(history_snapshot) or _default_fortigate_device_ip()
        return _handle_soar_intent(intent, session_id, message, history_snapshot)

    partial = _extract_partial_soar_intent(message)
    if partial is not None:
        if not partial.get("device_ip"):
            partial["device_ip"] = _infer_device_from_history(history_snapshot) or _default_fortigate_device_ip()
        with _lock:
            _pending_soar[session_id] = partial
        reply = _followup_prompt(partial, history_snapshot)
        with _lock:
            history = _sessions.setdefault(session_id, [])
            history.append({"role": "user", "content": message})
            history.append({"role": "assistant", "content": reply})
            if len(history) > _MAX_HISTORY:
                history[:] = history[-_MAX_HISTORY:]
        return reply

    with _lock:
        history = _sessions.setdefault(session_id, [])

    # Rebuild system prompt with fresh context every turn
    system = _build_system_prompt()
    messages = [{"role": "system", "content": system}]
    messages.extend(history)
    messages.append({"role": "user", "content": message})

    try:
        resp = _CLIENT.chat.completions.create(
            model=_MODEL,
            messages=messages,
            temperature=0.3,
            max_completion_tokens=16000,
        )
        reply = resp.choices[0].message.content.strip()
    except Exception as exc:
        reply = f"Error communicating with the AI model: {exc}"

    # Persist to session history
    with _lock:
        history.append({"role": "user", "content": message})
        history.append({"role": "assistant", "content": reply})
        # Trim old messages
        if len(history) > _MAX_HISTORY:
            history[:] = history[-_MAX_HISTORY:]

    return reply

def clear_session(session_id: str = "default") -> None:
    with _lock:
        _sessions.pop(session_id, None)
        _pending_soar.pop(session_id, None)
