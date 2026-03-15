from __future__ import annotations

import json
import re
import threading
from datetime import datetime

from ..config import (
    OPENAI_CLIENT,
    OPENAI_MODEL_REASONING,
)
from ..database.db import get_alerts, get_alerts_since, get_devices_list, get_log_stats
from ..services.soar import execute_soar_action

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
- ALWAYS use the provided tools (like close_port, open_port, block_ip) to execute actions directly on the devices. NEVER simply give the user commands to run manually unless there aren't any tools that correspond to them.
- Reference specific alert IDs, device IPs, and log data when available.
- If you don't have enough information to answer, use the provided tools to query the database.
- Never claim you do not have live feed/SIEM access unless tool calls explicitly return empty or errors.
- Never relabel device vendors or types.
- Treat vendor/type exactly as returned by tools.
- Do not call Cisco IOS routers "FortiGate" or "firewalls" unless their vendor is Fortinet.
- SOCrates itself is the collector and parser in this deployment (syslog ingest + DB + analysis pipeline).
- Use `search_devices` to list devices if the user asks about the infrastructure.
- Use `query_alerts` to check recent alerts.
- Use `get_log_statistics` if the user asks for ingest stats or top talkers.
- If the user asks to close a port but doesn't specify TCP or UDP, you MUST ask them which protocol they want to block before executing the action.

### Snapshot Time (UTC)
{now_utc}
"""

def _build_system_prompt() -> str:
    return _SYSTEM_PROMPT.format(
        now_utc=datetime.utcnow().isoformat(timespec="seconds"),
    )

_TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "close_port",
            "description": "Issue a command to close or block a port on a specific firewall or network device. ALWAYS ask the user if they want to block TCP or UDP if they don't specify.",
            "parameters": {
                "type": "object",
                "properties": {
                    "port": {
                        "type": "integer",
                        "description": "The port number to close (e.g. 22)."
                    },
                    "protocol": {
                        "type": "string",
                        "enum": ["tcp", "udp"],
                        "description": "The protocol of the port. MUST be exactly 'tcp' or 'udp'."
                    },
                    "device_ip": {
                        "type": "string",
                        "description": "The IP address of the device to run the command on."
                    }
                },
                "required": ["port", "protocol", "device_ip"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "open_port",
            "description": "Issue a command to re-open or unblock a port on a specific firewall or network device by removing the previously created block rule. ALWAYS ask the user if they want to unblock TCP or UDP if they don't specify.",
            "parameters": {
                "type": "object",
                "properties": {
                    "port": {
                        "type": "integer",
                        "description": "The port number to unblock (e.g. 22)."
                    },
                    "protocol": {
                        "type": "string",
                        "enum": ["tcp", "udp"],
                        "description": "The protocol of the port. MUST be exactly 'tcp' or 'udp'."
                    },
                    "device_ip": {
                        "type": "string",
                        "description": "The IP address of the device to run the command on."
                    }
                },
                "required": ["port", "protocol", "device_ip"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "block_ip",
            "description": "Issue a command to block or quarantine a malicious target IP on a firewall or network device.",
            "parameters": {
                "type": "object",
                "properties": {
                    "target_ip": {
                        "type": "string",
                        "description": "The target IP address to block."
                    },
                    "device_ip": {
                        "type": "string",
                        "description": "The IP address of the device to run the command on (e.g. firewall or windows PC)."
                    }
                },
                "required": ["target_ip", "device_ip"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "query_alerts",
            "description": "Get recent threats or alerts. Provide a timeframe in minutes.",
            "parameters": {
                "type": "object",
                "properties": {
                    "minutes": {
                        "type": "integer",
                        "description": "The timeframe in minutes to look back for recent threats (default 60)."
                    }
                }
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "search_devices",
            "description": "Get a list of devices in the inventory.",
            "parameters": {
                "type": "object",
                "properties": {}
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "get_log_statistics",
            "description": "Get statistics about ingested logs, top talkers, and vendors.",
            "parameters": {
                "type": "object",
                "properties": {}
            }
        }
    }
]

def _build_log_statistics_reply() -> str:
    stats = get_log_stats()
    return json.dumps({
        "total_logs": stats['total_logs'],
        "by_vendor": stats['by_vendor'],
        "by_device": stats['by_device'],
        "top_devices_detailed": [
            {"ip": d['ip'], "hostname": d.get('hostname'), "vendor": d.get('vendor'), "type": d.get('device_type'), "logs": d.get('count')}
            for d in stats.get("by_device_detailed", [])
        ]
    })

def _build_search_devices_reply() -> str:
    devices = get_devices_list()
    return json.dumps([
        {"ip": d['ip'], "hostname": d.get('hostname'), "vendor": d.get('vendor'), "type": d.get('device_type'), "last_seen": d['last_seen']}
        for d in devices
    ])

def _build_alerts_reply(minutes: int) -> str:
    recent = get_alerts_since(minutes=minutes, limit=200)
    return json.dumps([
        {"id": a['id'], "status": a['status'], "severity": a['severity'], "created_at": a['created_at'], "title": a['title'], "summary": a['summary']}
        for a in recent
    ])

_IP_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
_SOAR_CONFIRM_PREFIX = "SOAR_CONFIRM::"
_SOAR_RESULT_PREFIX = "SOAR_RESULT::"

def _infer_device_from_history(history: list[dict]) -> str | None:
    """Infer likely device IP from recent conversation context."""
    devices = get_devices_list()
    valid_ips = {
        str(d.get("ip"))
        for d in devices
        if str(d.get("vendor", "")).lower() in ("fortinet", "palo alto", "microsoft", "windows")
    }
    if not valid_ips:
        return None

    # Search latest messages first; pick first IP that is a supported device.
    for msg in reversed(history[-12:]):
        content = str(msg.get("content", ""))
        for ip in _IP_RE.findall(content):
            if ip in valid_ips:
                return ip

    # Fallback: most recently seen supported device.
    for d in devices:
        if str(d.get("vendor", "")).lower() in ("fortinet", "palo alto", "microsoft", "windows"):
            return str(d.get("ip"))
    return None

def _default_device_ip() -> str | None:
    devices = get_devices_list()
    for d in devices:
        if str(d.get("vendor", "")).lower() in ("fortinet", "palo alto", "microsoft", "windows"):
            return d.get("ip")
    return None

def _persist_turn(session_id: str, user: str, assistant: str) -> None:
    with _lock:
        history = _sessions.setdefault(session_id, [])
        history.append({"role": "user", "content": user})
        history.append({"role": "assistant", "content": assistant})
        if len(history) > _MAX_HISTORY:
            history[:] = history[-_MAX_HISTORY:]

def _is_confirm(text: str) -> bool:
    t = text.strip().lower()
    return bool(re.match(r"^(confirm|yes|y|approve|execute|run|go\s+ahead)\b", t))

def _is_cancel(text: str) -> bool:
    t = text.strip().lower()
    return bool(re.match(r"^(cancel|no|n|stop|abort|never\s*mind)\b", t))

def _soar_confirm_message(intent: dict, device_ip: str) -> str:
    payload = {
        "title": "SOAR Action Confirmation",
        "mode": "live",
        "device_ip": device_ip,
        "action_type": intent.get("type"),
        "parameters": {
            "port": intent.get("port"),
            "protocol": intent.get("protocol"),
            "target_ip": intent.get("target_ip"),
        },
        "confirm_hint": "Reply 'confirm' to proceed or 'cancel' to abort.",
    }
    return _SOAR_CONFIRM_PREFIX + json.dumps(payload)

def _soar_result_message(*, ok: bool, action_id: int, status: str, summary: str, details: str | None = None) -> str:
    payload = {
        "ok": ok,
        "action_id": action_id,
        "status": status,
        "summary": summary,
        "details": details,
    }
    return _SOAR_RESULT_PREFIX + json.dumps(payload)

def _execute_soar_intent(intent: dict, device_ip: str) -> str:
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
        )
        details = None
        if res.error and "Missing FortiGate API token" in res.error:
            details = "Set FORTIGATE_API_TOKEN or FORTIGATE_TOKENS_JSON in backend/.env."
        return _soar_result_message(
            ok=res.ok,
            action_id=res.action_id,
            status=res.status,
            summary=(
                f"close_port on {device_ip}"
                if res.ok
                else f"Failed close_port on {device_ip}"
            ),
            details=details or res.summary,
        )

    if intent["type"] == "open_port":
        res = execute_soar_action(
            device_ip=device_ip,
            action_type="open_port",
            parameters={
                "port": intent["port"],
                "protocol": intent["protocol"],
            },
            requested_by="chat",
            source="chat",
        )
        details = None
        if res.error and "Missing API token" in res.error:
            details = "Set appropriate API tokens in backend/.env."
        return _soar_result_message(
            ok=res.ok,
            action_id=res.action_id,
            status=res.status,
            summary=(
                f"open_port on {device_ip}"
                if res.ok
                else f"Failed open_port on {device_ip}"
            ),
            details=details or res.summary,
        )

    if intent["type"] == "block_ip":
        res = execute_soar_action(
            device_ip=device_ip,
            action_type="block_ip",
            parameters={"target_ip": intent["target_ip"]},
            requested_by="chat",
            source="chat",
        )
        details = None
        if res.error and "Missing FortiGate API token" in res.error:
            details = "Set FORTIGATE_API_TOKEN or FORTIGATE_TOKENS_JSON in backend/.env."
        return _soar_result_message(
            ok=res.ok,
            action_id=res.action_id,
            status=res.status,
            summary=(
                f"block_ip {intent['target_ip']} on {device_ip}"
                if res.ok
                else f"Failed block_ip {intent['target_ip']} on {device_ip}"
            ),
            details=details or res.summary,
        )

    return _soar_result_message(ok=False, action_id=0, status="failed", summary="Unsupported SOAR intent")

def _handle_soar_intent(intent: dict, session_id: str, message: str, history: list[dict]) -> str:
    device_ip = intent.get("device_ip") or _infer_device_from_history(history) or _default_device_ip()
    if not device_ip:
        reply = _soar_result_message(
            ok=False,
            action_id=0,
            status="failed",
            summary="No supported device is available in inventory to execute this action.",
        )
        _persist_turn(session_id, message, reply)
        return reply

    # Always require explicit confirmation before executing chat-triggered SOAR.
    staged = {
        **intent,
        "device_ip": device_ip,
        "awaiting_confirmation": True,
    }
    with _lock:
        _pending_soar[session_id] = staged
    reply = _soar_confirm_message(staged, device_ip=device_ip)
    _persist_turn(session_id, message, reply)
    return reply

def chat(message: str, session_id: str = "default") -> str:
    if not _CLIENT:
        return "Error: OPENAI_API_KEY is not configured."

    with _lock:
        history_snapshot = list(_sessions.setdefault(session_id, []))
        pending = _pending_soar.get(session_id)

    # Continue an existing follow-up/confirmation flow.
    if pending is not None and pending.get("awaiting_confirmation"):
        if _is_cancel(message):
            with _lock:
                _pending_soar.pop(session_id, None)
            reply = _soar_result_message(
                ok=False,
                action_id=0,
                status="cancelled",
                summary="Cancelled the pending SOAR action.",
            )
            _persist_turn(session_id, message, reply)
            return reply

        if not _is_confirm(message):
            reply = _soar_confirm_message(
                pending,
                device_ip=pending.get("device_ip"),
            )
            _persist_turn(session_id, message, reply)
            return reply

        with _lock:
            staged = _pending_soar.pop(session_id, None)
        if not staged:
            reply = _soar_result_message(
                ok=False,
                action_id=0,
                status="failed",
                summary="No pending SOAR action to confirm.",
            )
            _persist_turn(session_id, message, reply)
            return reply

        # Execute the tool
        exec_reply = _execute_soar_intent(staged, staged["device_ip"])
        tool_call_dict = staged.get("raw_tool_call")
        msg_obj_dict = staged.get("msg_obj_dict")
        
        # Give the executed result back to the AI for a final summary
        if tool_call_dict and msg_obj_dict:
            # We must restore the correct history context for the AI
            with _lock:
                history = _sessions.setdefault(session_id, [])
            
            system = _build_system_prompt()
            messages = [{"role": "system", "content": system}]
            messages.extend(history)
            messages.append(msg_obj_dict) # The assistant message with the tool_calls
            messages.append({
                "role": "tool",
                "tool_call_id": tool_call_dict["id"],
                "name": tool_call_dict["function"]["name"],
                "content": exec_reply
            })
            
            try:
                resp2 = _CLIENT.chat.completions.create(
                    model=_MODEL,
                    messages=messages,
                    tools=_TOOLS,
                    temperature=0.3,
                    max_completion_tokens=16000,
                )
                ai_text = resp2.choices[0].message.content.strip() if resp2.choices[0].message.content else "Action completed."
                final_reply = exec_reply + "\n\n" + ai_text
            except Exception as exc:
                final_reply = exec_reply + f"\n\n(AI Summary Failed: {exc})"
                
            _persist_turn(session_id, message, final_reply)
            return final_reply
        else:
            # Fallback if no tool call info was stored
            _persist_turn(session_id, message, exec_reply)
            return exec_reply

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
            tools=_TOOLS,
            temperature=0.3,
            max_completion_tokens=16000,
        )
        msg_obj = resp.choices[0].message

        if msg_obj.tool_calls:
            tool_call = msg_obj.tool_calls[0]
            func_name = tool_call.function.name
            args = json.loads(tool_call.function.arguments)

            if func_name in ("close_port", "block_ip", "open_port"):
                intent = {
                    "type": func_name,
                    "raw_tool_call": tool_call.model_dump(),
                    "msg_obj_dict": msg_obj.model_dump(exclude_unset=True)
                }
                intent.update(args)
                return _handle_soar_intent(intent, session_id, message, history_snapshot)

            # Informational tools: run and feed back to agent
            tool_result = ""
            if func_name == "query_alerts":
                tool_result = _build_alerts_reply(args.get("minutes", 60))
            elif func_name == "search_devices":
                tool_result = _build_search_devices_reply()
            elif func_name == "get_log_statistics":
                tool_result = _build_log_statistics_reply()
            else:
                tool_result = f"Unsupported tool call: {func_name}"

            # Prepare messages for 2nd pass
            messages.append(msg_obj)
            messages.append({
                "role": "tool",
                "tool_call_id": tool_call.id,
                "name": func_name,
                "content": tool_result
            })

            resp2 = _CLIENT.chat.completions.create(
                model=_MODEL,
                messages=messages,
                tools=_TOOLS,
                temperature=0.3,
                max_completion_tokens=16000,
            )
            reply = resp2.choices[0].message.content.strip() if resp2.choices[0].message.content else "Done."

        else:
            reply = msg_obj.content.strip() if msg_obj.content else "Done."

    except Exception as exc:
        reply = f"Error communicating with the AI model: {exc}"

    # Persist to session history
    _persist_turn(session_id, message, reply)

    return reply

def clear_session(session_id: str = "default") -> None:
    with _lock:
        _sessions.pop(session_id, None)
        _pending_soar.pop(session_id, None)