from __future__ import annotations
import json
import sys
import socket
from pathlib import Path
import urllib.request
import urllib.error

from .format_paloalto import PA_CSV_HEADER

def sink_stdout(line: str) -> None:
    print(line)

def sink_file(path: Path, fmt: str):
    mode = "w" if fmt == "paloalto" else "a"
    fh = open(path, mode, encoding="utf-8")
    if fmt == "paloalto":
        fh.write(PA_CSV_HEADER + "\n")
        fh.flush()

    def _write(line: str) -> None:
        fh.write(line + "\n")
        fh.flush()
    return _write

def sink_syslog(host: str = "127.0.0.1", port: int = 514, source_ip: str | None = None):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sent_count = 0

    def _send_syslog(line: str) -> None:
        nonlocal sent_count
        # PRI = facility*8 + severity; facility=16 (local0), severity=6 (info)
        pri = 134
        
        # Spoof hostname if source_ip is provided, so the receiver knows who sent it
        hostname = source_ip if source_ip else "firewall-sim"
        
        syslog_msg = f"<{pri}>{hostname}: {line}"
        try:
            sock.sendto(syslog_msg.encode("utf-8", errors="ignore"), (host, port))
            sent_count += 1
            if sent_count % 100 == 0:
                print(f"[syslog] {sent_count} logs sent to {host}:{port}", file=sys.stderr)
        except Exception as exc:
            print(f"[WARN] Syslog send failed: {exc}", file=sys.stderr)

    return _send_syslog

def sink_http(endpoint: str):
    def _post(line: str) -> None:
        data = json.dumps({"log": line}).encode("utf-8")
        req = urllib.request.Request(
            endpoint, data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            urllib.request.urlopen(req, timeout=5)
        except urllib.error.URLError as exc:
            print(f"[WARN] POST failed: {exc}", file=sys.stderr)
    return _post
