import os
import socket
from pathlib import Path

from dotenv import load_dotenv

from backend.services.pipeline import process_log, start_pipeline

load_dotenv(Path(__file__).resolve().parent.parent / ".env")

HOST = os.getenv("SYSLOG_HOST", "0.0.0.0")
PORT = int(os.getenv("SYSLOG_PORT", "514"))

def parser():
    start_pipeline()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((HOST, PORT))
    print(f"Listening for syslog messages on UDP {HOST}:{PORT}")

    while True:
        data, addr = sock.recvfrom(8192)
        source_ip = addr[0]
        raw_syslog = data.decode(errors="ignore").strip()
        process_log(source_ip, raw_syslog)

if __name__ == "__main__":
    parser()
