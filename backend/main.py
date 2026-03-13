import socket
import threading

from api.app import create_app
from config import SYSLOG_HOST, SYSLOG_PORT, API_HOST, API_PORT
from services.pipeline import process_log, start_pipeline

def _run_api() -> None:
    app = create_app()
    app.run(host=API_HOST, port=API_PORT, use_reloader=False)

def _run_syslog() -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((SYSLOG_HOST, SYSLOG_PORT))
    print(f"[syslog] listening on UDP {SYSLOG_HOST}:{SYSLOG_PORT}")
    while True:
        data, addr = sock.recvfrom(8192)
        source_ip = addr[0]
        raw_syslog = data.decode(errors="ignore").strip()
        process_log(source_ip, raw_syslog)

def main() -> None:
    start_pipeline()

    api_thread = threading.Thread(target=_run_api, name="api-server", daemon=True)
    api_thread.start()
    print(f"[api] running on http://{API_HOST}:{API_PORT}")

    try:
        _run_syslog()
    except KeyboardInterrupt:
        print("\n[main] shutting down")

if __name__ == "__main__":
    main()
