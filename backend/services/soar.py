from __future__ import annotations

import ipaddress
from dataclasses import dataclass

import requests

from config import (
    FORTIGATE_API_TOKEN,
    SOAR_AUTO_RESPONSE_DRY_RUN,
    SOAR_AUTO_RESPONSE_ENABLED,
    SOAR_AUTO_RESPONSE_MIN_SEVERITY,
    FORTIGATE_TOKENS_JSON,
    FORTIGATE_TIMEOUT_SECONDS,
    FORTIGATE_VERIFY_SSL,
)
from database.db import (
    create_soar_action,
    get_device,
    get_fortigate_devices,
    update_soar_action_result,
)


class SoarError(Exception):
    pass


@dataclass
class ActionResult:
    ok: bool
    action_id: int
    status: str
    summary: str
    result: dict | None = None
    error: str | None = None


_SEVERITY_RANK = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


def _token_for_device(device_ip: str) -> str | None:
    # Per-device token has priority over global token.
    if device_ip in FORTIGATE_TOKENS_JSON:
        return FORTIGATE_TOKENS_JSON[device_ip]
    return FORTIGATE_API_TOKEN


def _fortigate_base(device_ip: str) -> str:
    # device_ip can also include port (e.g. 10.0.0.1:8443)
    return f"https://{device_ip}"


def _fortigate_request(
    device_ip: str,
    token: str,
    method: str,
    path: str,
    payload: dict | None = None,
) -> dict:
    url = _fortigate_base(device_ip) + path
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }
    resp = requests.request(
        method=method,
        url=url,
        headers=headers,
        json=payload,
        timeout=FORTIGATE_TIMEOUT_SECONDS,
        verify=FORTIGATE_VERIFY_SSL,
    )
    try:
        body = resp.json()
    except Exception:
        body = {"raw": resp.text}

    if resp.status_code >= 300:
        raise SoarError(f"FortiGate API {resp.status_code}: {body}")
    return body


def _validate_ip(ip: str) -> None:
    try:
        ipaddress.ip_address(ip)
    except ValueError as exc:
        raise SoarError(f"Invalid IP: {ip}") from exc


def _validate_port(port: int) -> None:
    if port < 1 or port > 65535:
        raise SoarError("Port must be 1-65535")


def _ensure_fortigate_device(device_ip: str) -> dict:
    dev = get_device(device_ip)
    if not dev:
        raise SoarError(f"Unknown device IP: {device_ip}")
    if str(dev.get("vendor", "")).lower() != "fortinet":
        raise SoarError(
            f"SOAR action currently supports Fortinet only (got vendor={dev.get('vendor')})"
        )
    return dev


def _do_block_ip(device_ip: str, token: str, target_ip: str) -> dict:
    _validate_ip(target_ip)
    obj_name = f"SOC_BLOCK_{target_ip.replace('.', '_')}"

    # Create or update address object.
    addr_payload = {
        "name": obj_name,
        "type": "ipmask",
        "subnet": f"{target_ip} 255.255.255.255",
    }
    try:
        _fortigate_request(device_ip, token, "POST", "/api/v2/cmdb/firewall/address", addr_payload)
    except SoarError:
        # Object might already exist; try update.
        _fortigate_request(
            device_ip,
            token,
            "PUT",
            f"/api/v2/cmdb/firewall/address/{obj_name}",
            addr_payload,
        )

    policy_name = f"SOC-BLOCK-{target_ip.replace('.', '-') }"
    policy_payload = {
        "name": policy_name,
        "srcintf": [{"name": "any"}],
        "dstintf": [{"name": "any"}],
        "srcaddr": [{"name": obj_name}],
        "dstaddr": [{"name": "all"}],
        "action": "deny",
        "schedule": "always",
        "service": [{"name": "ALL"}],
        "logtraffic": "all",
        "status": "enable",
    }
    policy_res = _fortigate_request(
        device_ip,
        token,
        "POST",
        "/api/v2/cmdb/firewall/policy",
        policy_payload,
    )
    return {
        "address_object": obj_name,
        "policy_name": policy_name,
        "policy_response": policy_res,
    }


def _do_close_port(device_ip: str, token: str, port: int, protocol: str) -> dict:
    _validate_port(port)
    proto = protocol.lower()
    if proto not in ("tcp", "udp", "both"):
        raise SoarError("protocol must be tcp|udp|both")

    service_name = f"SOC_CLOSE_{proto.upper()}_{port}"
    svc_payload: dict[str, str] = {"name": service_name}
    if proto in ("tcp", "both"):
        svc_payload["tcp-portrange"] = str(port)
    if proto in ("udp", "both"):
        svc_payload["udp-portrange"] = str(port)

    try:
        _fortigate_request(device_ip, token, "POST", "/api/v2/cmdb/firewall.service/custom", svc_payload)
    except SoarError:
        _fortigate_request(
            device_ip,
            token,
            "PUT",
            f"/api/v2/cmdb/firewall.service/custom/{service_name}",
            svc_payload,
        )

    policy_name = f"SOC-CLOSE-{proto.upper()}-{port}"
    policy_payload = {
        "name": policy_name,
        "srcintf": [{"name": "any"}],
        "dstintf": [{"name": "any"}],
        "srcaddr": [{"name": "all"}],
        "dstaddr": [{"name": "all"}],
        "action": "deny",
        "schedule": "always",
        "service": [{"name": service_name}],
        "logtraffic": "all",
        "status": "enable",
    }
    policy_res = _fortigate_request(
        device_ip,
        token,
        "POST",
        "/api/v2/cmdb/firewall/policy",
        policy_payload,
    )
    return {
        "service_object": service_name,
        "policy_name": policy_name,
        "policy_response": policy_res,
    }


def execute_soar_action(
    *,
    device_ip: str,
    action_type: str,
    parameters: dict,
    requested_by: str = "api",
    source: str = "manual",
    dry_run: bool = False,
) -> ActionResult:
    try:
        dev = _ensure_fortigate_device(device_ip)
    except Exception as exc:
        err = str(exc)
        return ActionResult(False, 0, "failed", err, error=err)

    action_id = create_soar_action(
        device_ip=device_ip,
        vendor=dev["vendor"],
        action_type=action_type,
        parameters={**parameters, "dry_run": dry_run},
        requested_by=requested_by,
        source=source,
    )

    try:
        if dry_run:
            if action_type == "block_ip":
                _validate_ip(str(parameters.get("target_ip", "")))
            elif action_type == "close_port":
                _validate_port(int(parameters.get("port", 0)))
            else:
                raise SoarError(f"Unsupported action_type: {action_type}")
            planned = {
                "device_ip": device_ip,
                "action_type": action_type,
                "parameters": parameters,
                "note": "Dry run only. No device changes were made.",
            }
            update_soar_action_result(action_id, status="dry-run", result=planned)
            return ActionResult(True, action_id, "dry-run", "Dry run successful", result=planned)

        token = _token_for_device(device_ip)
        if not token:
            err = "Missing FortiGate API token (FORTIGATE_API_TOKEN or FORTIGATE_TOKENS_JSON)"
            update_soar_action_result(action_id, status="failed", error=err)
            return ActionResult(False, action_id, "failed", err, error=err)

        if action_type == "block_ip":
            target_ip = str(parameters.get("target_ip", "")).strip()
            result = _do_block_ip(device_ip, token, target_ip)
        elif action_type == "close_port":
            port = int(parameters.get("port", 0))
            protocol = str(parameters.get("protocol", "tcp"))
            result = _do_close_port(device_ip, token, port, protocol)
        else:
            raise SoarError(f"Unsupported action_type: {action_type}")

        update_soar_action_result(action_id, status="success", result=result)
        return ActionResult(True, action_id, "success", "Action executed", result=result)
    except Exception as exc:
        err = str(exc)
        update_soar_action_result(action_id, status="failed", error=err)
        return ActionResult(False, action_id, "failed", err, error=err)


def auto_respond_to_alert(
    *,
    alert_id: int,
    severity: str,
    affected_devices: list[str] | None,
) -> list[dict]:
    """Simple SOAR playbook: block each affected IP on every Fortinet device."""
    if not SOAR_AUTO_RESPONSE_ENABLED:
        return []

    sev_rank = _SEVERITY_RANK.get(str(severity).lower(), 0)
    min_rank = _SEVERITY_RANK.get(SOAR_AUTO_RESPONSE_MIN_SEVERITY, 3)
    if sev_rank < min_rank:
        return []

    targets = [ip for ip in (affected_devices or []) if isinstance(ip, str) and ip.strip()]
    if not targets:
        return []

    fortigates = get_fortigate_devices()
    if not fortigates:
        return []

    out: list[dict] = []
    for fw in fortigates:
        for target_ip in targets:
            res = execute_soar_action(
                device_ip=fw["ip"],
                action_type="block_ip",
                parameters={"target_ip": target_ip},
                requested_by="analyzer",
                source=f"auto-response:alert#{alert_id}",
                dry_run=SOAR_AUTO_RESPONSE_DRY_RUN,
            )
            out.append(
                {
                    "alert_id": alert_id,
                    "firewall_ip": fw["ip"],
                    "target_ip": target_ip,
                    "action_id": res.action_id,
                    "ok": res.ok,
                    "status": res.status,
                    "summary": res.summary,
                    "error": res.error,
                }
            )
    return out
