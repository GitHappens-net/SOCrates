"""Built-in templates and detection for Windows Defender/Firewall logs."""
from __future__ import annotations

import re
import logging

def _run_winrm_cmd(device_ip: str, token: str | None, cmd_args: list[str]) -> tuple[int, str, str]:
    try:
        import winrm
    except ImportError:
        raise RuntimeError("pywinrm is required for remote Windows management. Run 'pip install pywinrm'")
    
    if not token or ":" not in token:
        raise ValueError("For Windows, the 'token' parameter must be provided in 'username:password' format.")
    
    user, pwd = token.split(":", 1)
    
    # NTLM transport works over HTTP and encrypts the authentication, making it suitable for Windows targets
    session = winrm.Session(device_ip, auth=(user, pwd), transport='ntlm')
    res = session.run_cmd(cmd_args[0], cmd_args[1:])
    return res.status_code, res.std_out.decode('cp437', errors='ignore'), res.std_err.decode('cp437', errors='ignore')

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
        
        code, stdout, stderr = _run_winrm_cmd(device_ip, token, cmd)
        
        if code == 0:
            if "No rules match the specified criteria." in stdout:
                output_messages.append(f"{proto.upper()} rule not found.")
            else:
                output_messages.append(f"{proto.upper()} rule removed.")
        else:
            if "No rules match" in stdout:
                output_messages.append(f"{proto.upper()} rule not found.")
            else:
                raise RuntimeError(f"Failed to open port {port} ({proto.upper()}): {stderr or stdout}")
            
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
    
    code, stdout, stderr = _run_winrm_cmd(device_ip, token, cmd)
    if code != 0:
        raise RuntimeError(f"Failed to block IP {target_ip}: {stderr or stdout}")
        
    return {"status": "success", "message": f"IP {target_ip} blocked successfully.", "output": stdout}

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
        
        code, stdout, stderr = _run_winrm_cmd(device_ip, token, cmd)
        if code != 0:
            raise RuntimeError(f"Failed to block port {port} ({proto.upper()}): {stderr or stdout}")
            
        output_messages.append(f"{proto.upper()} blocked.")
            
    return {"status": "success", "message": f"Port {port} blocked successfully for: {', '.join(output_messages)}."}
