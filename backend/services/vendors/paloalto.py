"""Built-in templates and enrichment helpers for Palo Alto logs."""
from __future__ import annotations

import re

_PA_CSV_FIELDS = [
    "receive_time",
    "serial",
    "type",
    "subtype",
    "config_version",
    "generated_time",
    "src",
    "dst",
    "natsrc",
    "natdst",
    "rule",
    "srcuser",
    "dstuser",
    "app",
    "vsys",
    "from",
    "to",
    "inbound_if",
    "outbound_if",
    "logset",
    "future_use_1",
    "sessionid",
    "repeatcnt",
    "sport",
    "dport",
    "natsport",
    "natdport",
    "flags",
    "proto",
    "action",
    "bytes",
    "bytes_sent",
    "bytes_received",
    "packets",
    "start_time",
    "elapsed",
    "category",
    "future_use_2",
    "seqno",
    "actionflags",
    "srcloc",
    "dstloc",
    "future_use_3",
    "pkts_sent",
    "pkts_received",
    "session_end_reason",
    "dg_hier_level_1",
    "rule_uuid",
]

PALOALTO_CSV_TRAFFIC_TEMPLATE: dict = {
    "fingerprint": "paloalto_csv_traffic",
    "vendor": "Palo Alto",
    "device_type": "Palo Alto Firewall",
    "parse_mode": "csv",
    "csv_fieldnames": _PA_CSV_FIELDS,
    "csv_min_columns": 30,
    "regex": "",
}

_BUILTINS: list[dict] = [PALOALTO_CSV_TRAFFIC_TEMPLATE]


def builtins() -> list[dict]:
    return [dict(t) for t in _BUILTINS]


def match_fingerprint(raw_syslog: str) -> str | None:
    if re.search(
        r"\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2},PA-\d{4},TRAFFIC,end,",
        raw_syslog,
    ):
        return "paloalto_csv_traffic"
    return None


def enrich_fields(fields: dict) -> dict:
    # Align fields with the common schema expected by downstream analytics.
    if fields.get("src"):
        fields.setdefault("srcip", fields["src"])
    if fields.get("dst"):
        fields.setdefault("dstip", fields["dst"])
    if fields.get("sport"):
        fields.setdefault("srcport", fields["sport"])
    if fields.get("dport"):
        fields.setdefault("dstport", fields["dport"])
    if fields.get("app"):
        fields.setdefault("service", fields["app"])
    if fields.get("bytes_sent"):
        fields.setdefault("sentbyte", fields["bytes_sent"])
    if fields.get("bytes_received"):
        fields.setdefault("rcvdbyte", fields["bytes_received"])
    if fields.get("pkts_sent"):
        fields.setdefault("sentpkt", fields["pkts_sent"])
    if fields.get("pkts_received"):
        fields.setdefault("rcvdpkt", fields["pkts_received"])
    if fields.get("serial"):
        fields.setdefault("devname", fields["serial"])
    return fields

import requests
import ipaddress
from ...config import PALOALTO_VERIFY_SSL, PALOALTO_TIMEOUT_SECONDS

def _paloalto_base(device_ip: str) -> str:
    return f"https://{device_ip}/api"

def _paloalto_request(
    device_ip: str,
    token: str | None,
    params: dict,
) -> dict:
    if token:
        params["key"] = token
    
    url = _paloalto_base(device_ip)
    resp = requests.post(
        url,
        data=params, # Form data for XML API
        timeout=PALOALTO_TIMEOUT_SECONDS,
        verify=PALOALTO_VERIFY_SSL,
    )
    
    # We return raw content for simple PAN-OS XML parsing or wrap it
    try:
        body = resp.text
    except Exception:
        body = ""

    if resp.status_code >= 300:
        raise RuntimeError(f"Palo Alto API {resp.status_code}: {resp.text}")
    
    # Very basic evaluation of success in PAN-OS XML
    if 'status="error"' in body:
        raise RuntimeError(f"Palo Alto API Error: {body}")
        
    return {"raw": body}

def block_ip(device_ip: str, token: str, target_ip: str) -> dict:
    try:
        ipaddress.ip_address(target_ip)
    except ValueError as exc:
        raise ValueError(f"Invalid IP: {target_ip}") from exc

    obj_name = f"SOC-BLOCK-{target_ip.replace('.', '-')}"

    # 1. Create Address Object
    # xpath: /config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/address
    addr_xpath = f"/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/address/entry[@name='{obj_name}']"
    addr_element = f"<ip-netmask>{target_ip}/32</ip-netmask>"
    
    _paloalto_request(device_ip, token, {
        "type": "config",
        "action": "set",
        "xpath": addr_xpath,
        "element": addr_element
    })

    # 2. Create Security Rule
    # xpath: /config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/rulebase/security/rules
    policy_name = f"SOC-DENY-{target_ip.replace('.', '-')}"
    rule_xpath = f"/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/rulebase/security/rules/entry[@name='{policy_name}']"
    rule_element = f"""
        <from><member>any</member></from>
        <to><member>any</member></to>
        <source><member>{obj_name}</member></source>
        <destination><member>any</member></destination>
        <application><member>any</member></application>
        <service><member>any</member></service>
        <action>deny</action>
        <log-end>yes</log-end>
    """

    res = _paloalto_request(device_ip, token, {
        "type": "config",
        "action": "set",
        "xpath": rule_xpath,
        "element": rule_element
    })

    # Optionally call a commit, but usually SOAR systems leave commit to another process,
    # or you can issue a commit immediately if required:
    # _paloalto_request(device_ip, token, {"type": "commit", "cmd": "<commit></commit>"})

    return {
        "address_object": obj_name,
        "policy_name": policy_name,
        "success": True
    }

def close_port(device_ip: str, token: str, port: int, protocol: str) -> dict:
    if port < 1 or port > 65535:
        raise ValueError("Port must be 1-65535")
    proto = protocol.lower()
    if proto not in ("tcp", "udp"):
        # Palo Alto API needs distinct protocol definitions (tcp or udp) inside the service.
        # Handling 'both' would require 2 separate service objects. So we enforce one here.
        raise ValueError("protocol must be tcp|udp")

    service_name = f"SOC-CLOSE-{proto.upper()}-{port}"

    # 1. Create Service Object
    svc_xpath = f"/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/service/entry[@name='{service_name}']"
    svc_element = f"<protocol><{proto}><port>{port}</port></{proto}></protocol>"

    _paloalto_request(device_ip, token, {
        "type": "config",
        "action": "set",
        "xpath": svc_xpath,
        "element": svc_element
    })

    # 2. Create Security Rule
    policy_name = f"SOC-DENY-{proto.upper()}-{port}"
    rule_xpath = f"/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/rulebase/security/rules/entry[@name='{policy_name}']"
    rule_element = f"""
        <from><member>any</member></from>
        <to><member>any</member></to>
        <source><member>any</member></source>
        <destination><member>any</member></destination>
        <application><member>any</member></application>
        <service><member>{service_name}</member></service>
        <action>deny</action>
        <log-end>yes</log-end>
    """

    _paloalto_request(device_ip, token, {
        "type": "config",
        "action": "set",
        "xpath": rule_xpath,
        "element": rule_element
    })

    return {
        "service_object": service_name,
        "policy_name": policy_name,
        "success": True
    }
