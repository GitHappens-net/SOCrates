"""Built-in templates and detection for Windows Defender/Firewall logs."""
from __future__ import annotations

import re
import subprocess
import logging

WINDOWS_DEFENDER_TEMPLATE: dict = {
    "fingerprint": "windows_defender",
    "vendor": "Microsoft",
    "device_type": "Windows Defender",
    "parse_mode": "regex",
    "header_regex": "",
    "regex": r"^(?:<(?P<syslog_priority>\d+)>)?\s*(?P<date>[A-Z][a-z]{2}\s+\d+\s+\d+:\d+:\d+)\s+(?P<host>\S+)\s+(?P<process>Microsoft-Windows-Windows_Defender\[\d+\]):\s+(?P<message>.*)",
}

WINDOWS_FIREWALL_TEMPLATE: dict = {
    "fingerprint": "windows_firewall",
    "vendor": "Microsoft",
    "device_type": "Windows Firewall",
    "parse_mode": "regex",
    "header_regex": "",
    "regex": r"^(?:<(?P<syslog_priority>\d+)>)?\s*(?P<date>[A-Z][a-z]{2}\s+\d+\s+\d+:\d+:\d+)\s+(?P<host>\S+)\s+(?P<process>Microsoft-Windows-Windows_Firewall\[\d+\]):\s+(?P<message>.*)",
}

_BUILTINS: list[dict] = [WINDOWS_DEFENDER_TEMPLATE, WINDOWS_FIREWALL_TEMPLATE]

def builtins() -> list[dict]:
    return [dict(t) for t in _BUILTINS]

def match_fingerprint(raw_syslog: str) -> str | None:
    if "Microsoft-Windows-Windows_Defender" in raw_syslog:
        return "windows_defender"
    if "Microsoft-Windows-Windows_Firewall" in raw_syslog:
        return "windows_firewall"
    return None

def enrich_fields(fields: dict) -> dict:
    return fields

def open_port(device_ip: str, token: str | None, port: int, protocol: str = "tcp") -> dict:
    """Remove a previously created block rule for a port using Windows Firewall."""
    if not isinstance(port, int) or port <= 0 or port > 65535:
        raise ValueError(f"Invalid port: {port}")

    if not protocol or str(protocol).lower() in ("none", "both", "any"):
        protos = ["tcp", "udp"]
    else:
        protos = [str(protocol).lower()]

    output_messages = []
    
    for proto in protos:
        if proto not in ("tcp", "udp"):
            proto = "tcp"
            
        rule_name = f"SOC_BLOCK_PORT_{port}_{proto.upper()}"
        
        cmd = [
            "netsh", "advfirewall", "firewall", "delete", "rule", 
            f"name={rule_name}"
        ]
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            if "No rules match the specified criteria." in result.stdout:
                output_messages.append(f"{proto.upper()} rule not found.")
            else:
                output_messages.append(f"{proto.upper()} rule removed.")
        except subprocess.CalledProcessError as e:
            if "No rules match" in (e.stdout or ""):
                output_messages.append(f"{proto.upper()} rule not found.")
            else:
                raise RuntimeError(f"Failed to open port {port} ({proto.upper()}): {e.stderr or e.stdout}")
            
    return {"status": "success", "message": f"Port {port} unblocked. Details: {', '.join(output_messages)}."}

def block_ip(device_ip: str, token: str | None, target_ip: str) -> dict:
    """Block an IP using Windows Firewall."""
    try:
        import ipaddress
        ipaddress.ip_address(target_ip)
    except ValueError:
        raise ValueError(f"Invalid IP: {target_ip}")
    
    rule_name = f"SOC_BLOCK_IP_{target_ip.replace('.', '_')}"
    cmd = [
        "netsh", "advfirewall", "firewall", "add", "rule", 
        f"name={rule_name}", 
        "dir=in", 
        "action=block", 
        f"remoteip={target_ip}"
    ]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        return {"status": "success", "message": f"IP {target_ip} blocked successfully.", "output": result.stdout}
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"Failed to block IP {target_ip}: {e.stderr or e.stdout}")

def close_port(device_ip: str, token: str | None, port: int, protocol: str = "tcp") -> dict:
    """Close or block a specific port using Windows Firewall."""
    if not isinstance(port, int) or port <= 0 or port > 65535:
        raise ValueError(f"Invalid port: {port}")

    # Handle missing or 'both' protocol gracefully
    if not protocol or str(protocol).lower() in ("none", "both", "any"):
        protos = ["tcp", "udp"]
    else:
        protos = [str(protocol).lower()]

    output_messages = []
    
    for proto in protos:
        if proto not in ("tcp", "udp"):
            proto = "tcp" # fallback if something invalid was passed
            
        rule_name = f"SOC_BLOCK_PORT_{port}_{proto.upper()}"
        
        cmd = [
            "netsh", "advfirewall", "firewall", "add", "rule", 
            f"name={rule_name}", 
            "dir=in", 
            "action=block", 
            f"protocol={proto.upper()}", 
            f"localport={port}"
        ]
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            output_messages.append(f"{proto.upper()} blocked.")
        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"Failed to block port {port} ({proto.upper()}): {e.stderr or e.stdout}")
            
    return {"status": "success", "message": f"Port {port} blocked successfully for: {', '.join(output_messages)}."}
