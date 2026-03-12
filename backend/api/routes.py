"""REST API routes for the SOCrates dashboard."""
from flask import Blueprint, jsonify, request

from backend.agent.chat import chat, clear_session
from backend.database.db import (
    clear_alerts,
    get_alert,
    get_alerts,
    get_devices_list,
    get_log_stats,
    get_recent_logs,
    update_alert_status,
)

api_bp = Blueprint("api", __name__)


# ── Alerts ────────────────────────────────────────────────────────────────

@api_bp.route("/alerts", methods=["GET"])
def list_alerts():
    status = request.args.get("status")
    severity = request.args.get("severity")
    limit = request.args.get("limit", 50, type=int)
    return jsonify(get_alerts(status=status, severity=severity, limit=limit))


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
    if update_alert_status(alert_id, new_status):
        return jsonify(get_alert(alert_id))
    return jsonify({"error": "Alert not found"}), 404


@api_bp.route("/alerts", methods=["DELETE"])
def delete_alerts():
    count = clear_alerts()
    return jsonify({"cleared": count})


# ── Devices ───────────────────────────────────────────────────────────────

@api_bp.route("/devices", methods=["GET"])
def list_devices():
    return jsonify(get_devices_list())


# ── Logs ──────────────────────────────────────────────────────────────────

@api_bp.route("/logs", methods=["GET"])
def list_logs():
    limit = request.args.get("limit", 50, type=int)
    return jsonify(get_recent_logs(limit=min(limit, 500)))


@api_bp.route("/stats", methods=["GET"])
def stats():
    return jsonify(get_log_stats())


# ── Chat ──────────────────────────────────────────────────────────────────

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
    return jsonify({"cleared": True})
