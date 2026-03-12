import os
import socket
import threading
from pathlib import Path

from dotenv import load_dotenv

from backend.api.app import create_app
from backend.services.pipeline import process_log, start_pipeline

load_dotenv(Path(__file__).resolve().parent.parent / ".env")

HOST = os.getenv("SYSLOG_HOST", "0.0.0.0")
PORT = int(os.getenv("SYSLOG_PORT", "514"))
API_HOST = os.getenv("API_HOST", "0.0.0.0")
API_PORT = int(os.getenv("API_PORT", "5000"))

def parser():
    start_pipeline()

    # Start the REST API in a background thread
    app = create_app()
    api_thread = threading.Thread(
        target=lambda: app.run(host=API_HOST, port=API_PORT, use_reloader=False),
        name="api-server",
        daemon=True,
    )
    api_thread.start()
    print(f"REST API running on http://{API_HOST}:{API_PORT}")

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
