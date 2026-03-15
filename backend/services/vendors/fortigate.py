from __future__ import annotations
import re
import requests
import ipaddress
from ...config import FORTIGATE_VERIFY_SSL, FORTIGATE_TIMEOUT_SECONDS

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

def unblock_ip(device_ip: str, token: str, target_ip: str) -> dict:
    try:
        ipaddress.ip_address(target_ip)
    except ValueError as exc:
        raise ValueError(f"Invalid IP: {target_ip}") from exc

    obj_name = f"SOC_BLOCK_{target_ip.replace('.', '_')}"
    policy_name = f"SOC-BLOCK-{target_ip.replace('.', '-')}"

    try:
        # First, try deleting the firewall policy by searching for it, or we could just use name in modern FortiOS.
        # But FortiOS REST API usually requires the policy ID for deletion. 
        # For simplicity, we try to DELETE by name if supported, else we might just accept error.
        # Note: FortiOS 6.4+ supports referencing policies by name in some endpoints, 
        # but safely deleting by name requires fetching it first.
        # We will attempt quick fetch to get ID.
        policies = _fortigate_request(device_ip, token, "GET", f"/api/v2/cmdb/firewall/policy?filter=name=={policy_name}")
        if policies.get("results"):
            pol_id = policies["results"][0].get("policyid")
            if pol_id:
                _fortigate_request(device_ip, token, "DELETE", f"/api/v2/cmdb/firewall/policy/{pol_id}")
    except RuntimeError:
        pass

    try:
        # Then, delete the address object
        _fortigate_request(device_ip, token, "DELETE", f"/api/v2/cmdb/firewall/address/{obj_name}")
    except RuntimeError:
        pass

    return {
        "address_object": obj_name,
        "policy_name": policy_name,
        "status": "deleted"
    }

def open_port(device_ip: str, token: str, port: int, protocol: str) -> dict:
    proto = protocol.lower()
    if proto not in ("tcp", "udp", "both"):
        proto = "tcp"
        
    service_name = f"SOC_CLOSE_{proto.upper()}_{port}"
    policy_name = f"SOC-CLOSE-{proto.upper()}-{port}"

    try:
        # Fetch policy to get ID
        policies = _fortigate_request(device_ip, token, "GET", f"/api/v2/cmdb/firewall/policy?filter=name=={policy_name}")
        if policies.get("results"):
            pol_id = policies["results"][0].get("policyid")
            if pol_id:
                _fortigate_request(device_ip, token, "DELETE", f"/api/v2/cmdb/firewall/policy/{pol_id}")
    except RuntimeError:
        pass

    try:
        # Delete custom service object
        _fortigate_request(device_ip, token, "DELETE", f"/api/v2/cmdb/firewall.service/custom/{service_name}")
    except RuntimeError:
        pass

    return {
        "service_object": service_name,
        "policy_name": policy_name,
        "status": "deleted"
    }

def quarantine_mac_address(device_ip: str, token: str, mac_address: str) -> dict:
    safe_mac = mac_address.replace(":", "_").replace("-", "_").lower()
    obj_name = f"SOC_MAC_{safe_mac}"
    
    addr_payload = {
        "name": obj_name,
        "type": "mac",
        "macaddr": [{"macaddr": mac_address}],
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

    policy_name = f"SOC-BLOCK-MAC-{safe_mac.replace('_', '-')}"
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
        "success": True
    }
