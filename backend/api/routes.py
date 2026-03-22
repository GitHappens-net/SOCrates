from flask import Blueprint, jsonify, request
import zlib
from ..analysis.chat import chat, clear_session
from ..database.db import (
    clear_alerts, get_alert, get_alerts, get_devices_list,
    get_fortigate_devices, get_log_stats, get_recent_logs,
    get_soar_action, get_soar_actions, update_alert_status)
from ..services.soar import execute_soar_action, execute_alert_mitigations
from ..services.pipeline import get_unwritten_logs

api_bp = Blueprint("api", __name__)

def _dedup_logs(in_flight, db_logs):
    seen_keys = set()
    combined = []
    
    for log in in_flight:
        clone = dict(log)
        if "id" not in clone:
            # Generate a stable negative ID for React keys mapping
            clone["id"] = - (zlib.crc32((clone["raw_message"] + clone["received_at"]).encode()) & 0x7FFFFFFF)
        key = clone.get("raw_message", "") + clone.get("received_at", "")
        if key not in seen_keys:
            seen_keys.add(key)
            combined.append(clone)
            
    for log in db_logs:
        key = log.get("raw_message", "") + log.get("received_at", "")
        if key not in seen_keys:
            seen_keys.add(key)
            combined.append(log)
            
    return combined

# ---------------------------------------------------------------------------
# Alerts
# ---------------------------------------------------------------------------
@api_bp.route("/alerts", methods=["GET"])
def list_alerts():
    status = request.args.get("status")
    severity = request.args.get("severity")
    limit = request.args.get("limit", 50, type=int)
    offset = request.args.get("offset", 0, type=int)
    return jsonify(get_alerts(status=status, severity=severity, limit=limit, offset=offset))

@api_bp.route("/alerts/<int:alert_id>", methods=["GET"])
def get_single_alert(alert_id: int):
    alert = get_alert(alert_id)
    if not alert:
        return jsonify({"error": "Alert not found"}), 404
    return jsonify(alert)

@api_bp.route("/alerts/<int:alert_id>", methods=["PATCH"])
def patch_alert(alert_id: int):
    body = request.get_json(silent=True) or {}
    new_status = body.get("status")
    if new_status not in ("open", "acknowledged", "resolved", "dismissed"):
        return jsonify({"error": "Invalid status"}), 400
        
    # If the user is resolving the alert, execute SOAR mitigations based on the recommended actions
    # This is a basic implementation executing block_ip to affected_devices through firewall.
    if new_status == "resolved":
        execute_alert_mitigations(alert_id)
        
    if update_alert_status(alert_id, new_status):
        return jsonify(get_alert(alert_id))
    return jsonify({"error": "Alert not found"}), 404

@api_bp.route("/alerts", methods=["DELETE"])
def delete_alerts():
    count = clear_alerts()
    return jsonify({"cleared": count})

# ---------------------------------------------------------------------------
# Devices
# ---------------------------------------------------------------------------
@api_bp.route("/devices", methods=["GET"])
def list_devices():
    return jsonify(get_devices_list())

# ---------------------------------------------------------------------------
# Logs
# ---------------------------------------------------------------------------
@api_bp.route("/logs", methods=["GET"])
def list_logs():
    limit = request.args.get("limit", 50, type=int)
    offset = request.args.get("offset", 0, type=int)
    max_limit = min(limit, 1000)

    in_flight = []
    if offset == 0:
        in_flight = get_unwritten_logs()
        in_flight.reverse()
        
    db_logs = get_recent_logs(limit=max_limit, offset=offset)
    
    combined = _dedup_logs(in_flight, db_logs)
    return jsonify(combined[:max_limit])

@api_bp.route("/devices/<path:device_ip>/logs", methods=["GET"])
def device_logs(device_ip: str):
    limit = request.args.get("limit", 50, type=int)
    offset = request.args.get("offset", 0, type=int)
    max_limit = min(limit, 1000)

    in_flight = []
    if offset == 0:
        raw_in_flight = get_unwritten_logs()
        in_flight = [log for log in raw_in_flight if log.get("source_ip") == device_ip]
        in_flight.reverse()
        
    db_logs = get_recent_logs(limit=max_limit, offset=offset, source_ip=device_ip)
    
    combined = _dedup_logs(in_flight, db_logs)
    return jsonify(combined[:max_limit])

@api_bp.route("/stats", methods=["GET"])
def stats():
    db_stats = get_log_stats()
    unwritten = get_unwritten_logs()
    
    if not unwritten:
        return jsonify(db_stats)
        
    db_stats["total_logs"] += len(unwritten)
    
    for log in unwritten:
        v = log.get("vendor", "unknown")
        db_stats["by_vendor"][v] = db_stats["by_vendor"].get(v, 0) + 1
        
        ip = log.get("source_ip", "unknown")
        db_stats["by_device"][ip] = db_stats["by_device"].get(ip, 0) + 1
        
        # detailed device stats
        found = False
        for d in db_stats["by_device_detailed"]:
            if d["ip"] == ip:
                d["count"] += 1
                if d["vendor"] == "unknown" and v != "unknown":
                    d["vendor"] = v
                found = True
                break
        if not found:
            hostname = None
            for key in ("hostname", "host", "devname", "device_name", "syslog_host"):
                if key in log.get("fields", {}) and log["fields"][key]:
                    hostname = log["fields"][key]
                    break
            
            db_stats["by_device_detailed"].append({
                "ip": ip,
                "hostname": hostname,
                "vendor": v,
                "device_type": log.get("device_type", "unknown"),
                "count": 1
            })
            
    # Re-sort to maintain top 10 limit format if needed (dashboard probably doesn't mind all, but let's sort)
    db_stats["by_vendor"] = dict(sorted(db_stats["by_vendor"].items(), key=lambda x: x[1], reverse=True))
    db_stats["by_device"] = dict(sorted(db_stats["by_device"].items(), key=lambda x: x[1], reverse=True)[:10])
    db_stats["by_device_detailed"] = sorted(db_stats["by_device_detailed"], key=lambda x: x["count"], reverse=True)[:10]

    return jsonify(db_stats)

# ---------------------------------------------------------------------------
# Chat
# ---------------------------------------------------------------------------
@api_bp.route("/chat", methods=["POST"])
def chat_endpoint():
    body = request.get_json(silent=True) or {}
    message = body.get("message", "").strip()
    if not message:
        return jsonify({"error": "message is required"}), 400
    session_id = body.get("session_id", "default")
    reply = chat(message, session_id=session_id)
    return jsonify({"reply": reply, "session_id": session_id})

@api_bp.route("/chat", methods=["DELETE"])
def clear_chat():
    body = request.get_json(silent=True) or {}
    session_id = body.get("session_id", "default")
    clear_session(session_id)
    return jsonify({"cleared": True})

# ---------------------------------------------------------------------------
# SOAR
# ---------------------------------------------------------------------------
@api_bp.route("/soar/actions", methods=["POST"])
def execute_soar():
    body = request.get_json(silent=True) or {}
    device_ip = str(body.get("device_ip", "")).strip()
    action_type = str(body.get("action_type", "")).strip()
    parameters = body.get("parameters") or {}
    requested_by = str(body.get("requested_by", "api"))
    source = str(body.get("source", "manual"))

    if not isinstance(parameters, dict):
        return jsonify({"error": "parameters must be an object"}), 400

    if not device_ip:
        return jsonify({"error": "device_ip is required"}), 400
    if not action_type:
        return jsonify({"error": "action_type is required"}), 400

    res = execute_soar_action(
        device_ip=device_ip,
        action_type=action_type,
        parameters=parameters,
        requested_by=requested_by,
        source=source,
    )
    code = 200 if res.ok else 400
    return jsonify(
        {
            "ok": res.ok,
            "action_id": res.action_id,
            "status": res.status,
            "summary": res.summary,
            "result": res.result,
            "error": res.error,
        }
    ), code

@api_bp.route("/soar/actions", methods=["GET"])
def list_soar_actions():
    limit = request.args.get("limit", 50, type=int)
    offset = request.args.get("offset", 0, type=int)
    status = request.args.get("status")
    return jsonify(get_soar_actions(limit=min(limit, 1000), offset=offset, status=status))

@api_bp.route("/soar/actions/<int:action_id>", methods=["GET"])
def single_soar_action(action_id: int):
    action = get_soar_action(action_id)
    if not action:
        return jsonify({"error": "SOAR action not found"}), 404
    return jsonify(action)

@api_bp.route("/soar/playbooks/contain-host", methods=["POST"])
def soar_contain_host():
    body = request.get_json(silent=True) or {}
    target_ip = str(body.get("target_ip", "")).strip()

    if not target_ip:
        return jsonify({"error": "target_ip is required"}), 400

    fortigates = get_fortigate_devices()
    if not fortigates:
        return jsonify({"error": "No Fortinet devices available in inventory"}), 400

    results: list[dict] = []
    for dev in fortigates:
        res = execute_soar_action(
            device_ip=dev["ip"],
            action_type="block_ip",
            parameters={"target_ip": target_ip},
            requested_by="api",
            source="playbook:contain-host",
        )
        results.append(
            {
                "device_ip": dev["ip"],
                "action_id": res.action_id,
                "ok": res.ok,
                "status": res.status,
                "summary": res.summary,
                "error": res.error,
            }
        )

    return jsonify(
        {
            "target_ip": target_ip,
            "results": results,
        }
    )
