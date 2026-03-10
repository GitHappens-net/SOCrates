import json
import socket
import sys
from datetime import datetime
from pathlib import Path

from normalizer import normalize_log

sys.path.insert(0, str(Path(__file__).parent))

HOST = "0.0.0.0"
PORT = 514

def parser():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((HOST, PORT))
    print(f"Listening for syslog messages on UDP {HOST}:{PORT}")

    while True:
        data, addr = sock.recvfrom(8192)
        source_ip = addr[0]
        raw_syslog = data.decode(errors="ignore").strip()

        result = normalize_log(source_ip, raw_syslog)

        log_json = {
            "received_at": datetime.now().isoformat(),
            "source_ip": source_ip,
            "vendor": result["vendor"],
            "device_type": result["device_type"],
            "facility": result["facility"],
            "severity": result["severity"],
            "fields": result["fields"],
        }
