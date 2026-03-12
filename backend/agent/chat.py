"""
SOCrates interactive chat — context-aware conversation with GPT-5.1.

Maintains per-session conversation history in memory and injects
live infrastructure context (alerts, devices, log stats) into
every exchange so the model can answer questions like:
  - "show me the latest critical events"
  - "can you correlate the events — is an attack taking place?"
  - "how do I block this on the FortiGate?"
"""
from __future__ import annotations

import os
import threading
from pathlib import Path

from dotenv import load_dotenv
from openai import OpenAI

from backend.database.db import get_alerts, get_devices_list, get_log_stats

load_dotenv(Path(__file__).resolve().parent.parent / ".env")

_OPENAI_KEY: str | None = os.getenv("OPENAI_API_KEY")
_MODEL: str = os.getenv("OPENAI_MODEL_REASONING", "gpt-5.1")
_CLIENT: OpenAI | None = OpenAI(api_key=_OPENAI_KEY) if _OPENAI_KEY else None

_sessions: dict[str, list[dict]] = {}
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

## Current Infrastructure Context

### Device Inventory
{devices}

### Recent Alerts
{alerts}

### Log Statistics
{stats}
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

    alerts_text = "\n".join(
        f"- [{a['severity'].upper()}] Alert #{a['id']} ({a['status']}) — "
        f"{a['title']}: {a['summary']}"
        + (f"\n  Analysis: {a['analysis'][:200]}" if a.get("analysis") else "")
        for a in alerts
    ) or "No alerts."

    stats_text = (
        f"Total logs ingested: {stats['total_logs']}\n"
        f"By vendor: {stats['by_vendor']}\n"
        f"Top devices: {stats['by_device']}"
    )

    return _SYSTEM_PROMPT.format(
        devices=devices_text, alerts=alerts_text, stats=stats_text,
    )


def chat(message: str, session_id: str = "default") -> str:
    """
    Send a user message and get a context-aware response.
    Conversation history is maintained per session_id.
    """
    if not _CLIENT:
        return "Error: OPENAI_API_KEY is not configured."

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
            max_completion_tokens=2000,
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
