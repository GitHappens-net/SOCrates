from __future__ import annotations
import ipaddress
from dataclasses import dataclass
from ..config import (
    FORTIGATE_API_TOKEN,
    FORTIGATE_TOKENS_JSON,
    PALOALTO_API_KEY,
    PALOALTO_TOKENS_JSON,
    WINDOWS_USERNAME,
    WINDOWS_PASSWORD,
    SOAR_AUTO_RESPONSE_ENABLED,
    SOAR_AUTO_RESPONSE_MIN_SEVERITY,
)
from ..database.db import create_soar_action, get_device, get_devices_list, update_soar_action_result
from .vendors import fortigate, paloalto, windows

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

def _normalize_device_host(device_ip: str) -> str:
    device_ip = device_ip.strip()
    if not device_ip:
        return device_ip

    if device_ip[0] == "[":
        end = device_ip.find("]")
        if end != -1:
            host = device_ip[1:end]
            return host

    try:
        ipaddress.ip_address(device_ip)
        return device_ip
    except ValueError:
        pass

    if ":" in device_ip:
        host, port = device_ip.rsplit(":", 1)
        if port.isdigit():
            return host

    return device_ip

def _token_for_device(device_ip: str, vendor: str) -> str | None:
    host_key = _normalize_device_host(device_ip)
    v = vendor.lower()
    if v == "fortinet":
        if host_key in FORTIGATE_TOKENS_JSON:
            return FORTIGATE_TOKENS_JSON[host_key]
        return FORTIGATE_API_TOKEN
    elif v == "palo alto":
        if host_key in PALOALTO_TOKENS_JSON:
            return PALOALTO_TOKENS_JSON[host_key]
        return PALOALTO_API_KEY
    elif v in ("microsoft", "windows"):
        if WINDOWS_USERNAME:
            return f"{WINDOWS_USERNAME}:{WINDOWS_PASSWORD}"
        return None
    return None

def _is_localhost_device(device_ip: str) -> bool:
    host = _normalize_device_host(device_ip).strip().lower()
    return host in ("127.0.0.1", "localhost", "::1")

def _ensure_supported_device(device_ip: str) -> dict:
    inventory_key, _, _ = device_ip.partition(":")
    dev = get_device(inventory_key)
    if not dev:
        raise SoarError(f"Unknown device IP: {device_ip}")
    
    vendor = str(dev.get("vendor", "")).lower()
    if vendor not in ("fortinet", "palo alto", "microsoft", "windows"):
        raise SoarError(f"SOAR action not supported for vendor: {dev.get('vendor')}")
    return dev

def _get_vendor_module(vendor: str):
    v = vendor.lower()
    if v == "fortinet":
        return fortigate
    elif v == "palo alto":
        return paloalto
    elif v in ("microsoft", "windows"):
        return windows
    raise SoarError(f"No SOAR module for vendor: {vendor}")

def execute_soar_action(*, device_ip: str, action_type: str, parameters: dict, requested_by: str = "api", source: str = "manual") -> ActionResult:
    if parameters is None:
        parameters = {}
    elif not isinstance(parameters, dict):
        err = f"Invalid parameters type: expected dict, got {type(parameters).__name__}"
        return ActionResult(False, 0, "failed", err, error=err)

    try:
        dev = _ensure_supported_device(device_ip)
    except Exception as exc:
        err = str(exc)
        return ActionResult(False, 0, "failed", err, error=err)

    vendor_name = str(dev.get("vendor", ""))

    action_id = create_soar_action(
        device_ip=device_ip,
        vendor=vendor_name,
        action_type=action_type,
        parameters=parameters,
        requested_by=requested_by,
        source=source,
    )

    try:
        token = _token_for_device(device_ip, vendor_name)
        if not token and not _is_localhost_device(device_ip):
            err = f"Missing API token for {vendor_name} device ({device_ip})"
            update_soar_action_result(action_id, status="failed", error=err)
            return ActionResult(False, action_id, "failed", err, error=err)

        vendor_module = _get_vendor_module(vendor_name)

        if action_type == "block_ip":
            target_ip = str(parameters.get("target_ip", "")).strip()
            result = vendor_module.block_ip(device_ip, token, target_ip)
        elif action_type == "close_port":
            port = int(parameters.get("port", 0))
            protocol = str(parameters.get("protocol", "tcp"))
            result = vendor_module.close_port(device_ip, token, port, protocol)
        elif action_type == "open_port":
            port = int(parameters.get("port", 0))
            protocol = str(parameters.get("protocol", "tcp"))
            if not hasattr(vendor_module, "open_port"):
                raise SoarError(f"vendor module {vendor_name} does not support open_port yet.")
            result = vendor_module.open_port(device_ip, token, port, protocol)
        elif action_type == "unblock_ip":
            target_ip = str(parameters.get("target_ip", "")).strip()
            if not hasattr(vendor_module, "unblock_ip"):
                raise SoarError(f"vendor module {vendor_name} does not support unblock_ip yet.")
            result = vendor_module.unblock_ip(device_ip, token, target_ip)
        elif action_type == "quarantine_mac_address":
            mac_address = str(parameters.get("mac_address", "")).strip()
            if not hasattr(vendor_module, "quarantine_mac_address"):
                raise SoarError(f"vendor module {vendor_name} does not support quarantine_mac_address yet.")
            result = vendor_module.quarantine_mac_address(device_ip, token, mac_address)
        elif action_type == "kill_process":
            pid_or_name = str(parameters.get("pid", parameters.get("pid_or_name", ""))).strip()
            if not hasattr(vendor_module, "kill_process"):
                raise SoarError(f"vendor module {vendor_name} does not support kill_process yet.")
            result = vendor_module.kill_process(device_ip, token, pid_or_name)
        elif action_type == "quarantine_file":
            file_path = str(parameters.get("file_path", "")).strip()
            if not hasattr(vendor_module, "quarantine_file"):
                raise SoarError(f"vendor module {vendor_name} does not support quarantine_file yet.")
            result = vendor_module.quarantine_file(device_ip, token, file_path)
        else:
            raise SoarError(f"Unsupported action_type: {action_type}")

        update_soar_action_result(action_id, status="success", result=result)
        return ActionResult(True, action_id, "success", "Action executed", result=result)
    except Exception as exc:
        err = str(exc)
        update_soar_action_result(action_id, status="failed", error=err)
        return ActionResult(False, action_id, "failed", err, error=err)

def execute_alert_mitigations(alert_id: int) -> list[dict]:
    # Fetch the alert to get mitigations and affected devices
    from ..database.db import get_alert
    import json
    
    alert = get_alert(alert_id)
    if not alert:
        return []
        
    mitigations = alert.get("mitigations", [])
    if not mitigations:
        return []
        
    # In a real environment, you'd parse out *which* SOAR action and *which* device.
    # We will do a generic block_ip across firewalls if the mitigation involves block/close.
    # Note: A real mapping requires deeper string/regex parsing of "command" or the LLM explicitly defining `action_type`.
    
    targets = [ip for ip in (alert.get("affected_devices") or []) if isinstance(ip, str) and ip.strip()]
    if not targets:
        return []

    all_devices = get_devices_list()
    supported_firewalls = [
        d for d in all_devices 
        if str(d.get("vendor", "")).lower() in ("fortinet", "palo alto")
    ]
    
    if not supported_firewalls:
        return []

    out: list[dict] = []
    
    # Very rudimentary execution based on the existence of mitigations
    # Realistically we'd map "block_ip" based on `command` text.
    has_block = any("block" in str(m.get("command", "")).lower() or "deny" in str(m.get("description", "")).lower() for m in mitigations)
    
    if has_block:
        for fw in supported_firewalls:
            for target_ip in targets:
                res = execute_soar_action(
                    device_ip=fw["ip"],
                    action_type="block_ip",
                    parameters={"target_ip": target_ip},
                    requested_by="api",
                    source=f"manual-resolve:alert#{alert_id}",
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

def auto_respond_to_alert(*, alert_id: int, severity: str, affected_devices: list[str] | None) -> list[dict]:
    if not SOAR_AUTO_RESPONSE_ENABLED:
        return []

    sev_rank = _SEVERITY_RANK.get(str(severity).lower(), 0)
    min_rank = _SEVERITY_RANK.get(SOAR_AUTO_RESPONSE_MIN_SEVERITY, 3)
    if sev_rank < min_rank:
        return []

    targets = [ip for ip in (affected_devices or []) if isinstance(ip, str) and ip.strip()]
    if not targets:
        return []

    all_devices = get_devices_list()
    supported_firewalls = [
        d for d in all_devices 
        if str(d.get("vendor", "")).lower() in ("fortinet", "palo alto")
    ]
    
    if not supported_firewalls:
        return []

    out: list[dict] = []
    for fw in supported_firewalls:
        for target_ip in targets:
            res = execute_soar_action(
                device_ip=fw["ip"],
                action_type="block_ip",
                parameters={"target_ip": target_ip},
                requested_by="analyzer",
                source=f"auto-response:alert#{alert_id}",
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
