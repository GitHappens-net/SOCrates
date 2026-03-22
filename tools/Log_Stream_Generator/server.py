from __future__ import annotations
import json
import sys
import threading
from typing import TYPE_CHECKING
import pandas as pd
from http.server import HTTPServer, BaseHTTPRequestHandler

from .engine import stream_logs
from .format_paloalto import PA_CSV_HEADER

if TYPE_CHECKING:
    pass

def run_server(df: pd.DataFrame, host: str, port: int, fmt: str, speed: float, max_flows: int | None, seed: int | None) -> None:
    log_buffer: list[str] = []
    buffer_lock = threading.Lock()
    gen_done = threading.Event()

    def _generate():
        for line in stream_logs(df, max_flows=max_flows, speed=speed,
                                fmt=fmt, seed=seed, shuffle=True):
            with buffer_lock:
                log_buffer.append(line)
        gen_done.set()

    gen_thread = threading.Thread(target=_generate, daemon=True)
    gen_thread.start()

    read_cursor = 0

    class LogHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            nonlocal read_cursor
            if self.path.startswith("/api/v2/log"):
                batch_size = 50
                with buffer_lock:
                    batch = log_buffer[read_cursor:read_cursor + batch_size]
                    read_cursor = min(read_cursor + batch_size, len(log_buffer))
                    total = len(log_buffer)

                if fmt == "fortigate":
                    response = {
                        "http_method": "GET",
                        "results": batch,
                        "vdom": "root",
                        "total": total,
                        "returned": len(batch),
                        "last_cursor": read_cursor,
                    }
                    body = json.dumps(response).encode("utf-8")
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                else:
                    body = (PA_CSV_HEADER + "\n" + "\n".join(batch)).encode("utf-8")
                    self.send_response(200)
                    self.send_header("Content-Type", "text/csv")

                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            elif self.path == "/health":
                body = json.dumps({
                    "status": "running",
                    "logs_generated": len(log_buffer),
                    "generation_complete": gen_done.is_set(),
                }).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            else:
                self.send_response(404)
                self.end_headers()

        def log_message(self, format, *args):
            pass

    server = HTTPServer((host, port), LogHandler)
    print(f"[*] REST API server listening on http://{host}:{port}", file=sys.stderr)
    print(f"[*] Fetch logs:  GET http://{host}:{port}/api/v2/log/traffic", file=sys.stderr)
    print(f"[*] Health:      GET http://{host}:{port}/health", file=sys.stderr)
    print(f"[*] Format: {fmt}", file=sys.stderr)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print(f"\n[*] Server stopped. Generated {len(log_buffer):,} logs total.",
              file=sys.stderr)
        server.server_close()
