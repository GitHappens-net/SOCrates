"""Built-in templates and detection for FortiGate logs."""
from __future__ import annotations

import re

FORTIGATE_TEMPLATE: dict = {
    "fingerprint": "fortigate_kv",
    "vendor": "Fortinet",
    "device_type": "FortiGate Firewall",
    "parse_mode": "kv",
    "header_regex": (
        r"^(?:<(?P<syslog_priority>\d+)>)?\s*"
        r"(?:[^\s:=]+:\s+)?"
        r"(?P<kvpayload>date=\d{4}-\d{2}-\d{2}\s+time=\S+.+)"
    ),
    "regex": "",
}

_BUILTINS: list[dict] = [FORTIGATE_TEMPLATE]


def builtins() -> list[dict]:
    return [dict(t) for t in _BUILTINS]


def match_fingerprint(raw_syslog: str) -> str | None:
    if re.search(r"date=\d{4}-\d{2}-\d{2}\b", raw_syslog) and re.search(r"\bdevname=", raw_syslog):
        return "fortigate_kv"
    return None


def enrich_fields(fields: dict) -> dict:
    return fields

import requests
import ipaddress
from ...config import FORTIGATE_VERIFY_SSL, FORTIGATE_TIMEOUT_SECONDS

def _fortigate_base(device_ip: str) -> str:
    return f"https://{device_ip}"

def _fortigate_request(
    device_ip: str,
    token: str | None,
    method: str,
    path: str,
    payload: dict | None = None,
) -> dict:
    url = _fortigate_base(device_ip) + path
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
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
        raise RuntimeError(f"FortiGate API {resp.status_code}: {body}")
    return body

def block_ip(device_ip: str, token: str, target_ip: str) -> dict:
    try:
        ipaddress.ip_address(target_ip)
    except ValueError as exc:
        raise ValueError(f"Invalid IP: {target_ip}") from exc

    obj_name = f"SOC_BLOCK_{target_ip.replace('.', '_')}"

    addr_payload = {
        "name": obj_name,
        "type": "ipmask",
        "subnet": f"{target_ip} 255.255.255.255",
    }
    try:
        _fortigate_request(device_ip, token, "POST", "/api/v2/cmdb/firewall/address", addr_payload)
    except RuntimeError:
        _fortigate_request(
            device_ip,
            token,
            "PUT",
            f"/api/v2/cmdb/firewall/address/{obj_name}",
            addr_payload,
        )

    policy_name = f"SOC-BLOCK-{target_ip.replace('.', '-')}"
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

def close_port(device_ip: str, token: str, port: int, protocol: str) -> dict:
    if port < 1 or port > 65535:
        raise ValueError("Port must be 1-65535")
    proto = protocol.lower()
    if proto not in ("tcp", "udp", "both"):
        raise ValueError("protocol must be tcp|udp|both")

    service_name = f"SOC_CLOSE_{proto.upper()}_{port}"
    svc_payload: dict[str, str] = {"name": service_name}
    if proto in ("tcp", "both"):
        svc_payload["tcp-portrange"] = str(port)
    if proto in ("udp", "both"):
        svc_payload["udp-portrange"] = str(port)

    try:
        _fortigate_request(device_ip, token, "POST", "/api/v2/cmdb/firewall.service/custom", svc_payload)
    except RuntimeError:
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
