import socket
import threading
import re
from .api.app import create_app
from .config import SYSLOG_HOST, SYSLOG_PORT, API_HOST, API_PORT
from .services.pipeline import queue_log, start_pipeline

def _run_api() -> None:
    app = create_app()
    app.run(host=API_HOST, port=API_PORT, use_reloader=False)

def _run_syslog() -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((SYSLOG_HOST, SYSLOG_PORT))
    print(f"[syslog] listening on UDP {SYSLOG_HOST}:{SYSLOG_PORT}")
    sock.settimeout(1.0)
    try:
        while True:
            try:
                data, addr = sock.recvfrom(8192)
                raw_syslog = data.decode(errors="ignore").strip()

                print(f"[syslog] received: {raw_syslog}")
                source_ip = addr[0]
    
                match = re.match(r"^<\d+>(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):\s*", raw_syslog)
                if match:
                    parts = match.group(1).split('.')
                    if all(0 <= int(p) <= 255 for p in parts):
                        source_ip = match.group(1)

                queue_log(source_ip, raw_syslog)
            except socket.timeout:
                continue
    finally:
        sock.close()

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
