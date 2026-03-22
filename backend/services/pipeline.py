import queue
import threading
import time
from datetime import datetime

from ..analysis.analyzer import analyze_batch_async
from ..database.db import get_connection, init_db, insert_logs_batch, upsert_devices_batch
from .normalizer import normalize_log, init_templates

# Agent batch settings
_AGENT_BATCH_SIZE = 100
_AGENT_FLUSH_INTERVAL = 300  # In seconds

_agent_queue: list[dict] = []
_agent_lock = threading.Lock()
_agent_timer: threading.Timer | None = None

# DB writer settings
_DB_BATCH_SIZE = 100
_DB_FLUSH_INTERVAL = 120.0  # 2 minutes

_work_queue: queue.Queue = queue.Queue()

# Queue to offload syslog parsing from the UDP thread
_raw_logs_queue: queue.Queue = queue.Queue()
_ingest_num_threads = 4  # Can adjust based on deployment size

_db_buffer_lock = threading.Lock()
_unwritten_logs: list[dict] = []

def get_unwritten_logs() -> list[dict]:
    with _db_buffer_lock:
        return list(_unwritten_logs)

# ---------------------------------------------------------------------------
# Agent batch helpers
# ---------------------------------------------------------------------------
def get_current_agent_queue() -> list[dict]:
    with _agent_lock:
        return list(_agent_queue)

def _on_batch_ready(batch: list[dict]) -> None:
    print(f"[pipeline] batch of {len(batch)} logs ready for agent analysis")
    analyze_batch_async(batch)

def _flush_agent_queue() -> None:
    global _agent_timer
    with _agent_lock:
        if not _agent_queue:
            _reset_agent_timer()
            return
        batch = list(_agent_queue)
        _agent_queue.clear()
    _on_batch_ready(batch)
    _reset_agent_timer()

def _reset_agent_timer() -> None:
    global _agent_timer
    if _agent_timer is not None:
        _agent_timer.cancel()
    _agent_timer = threading.Timer(_AGENT_FLUSH_INTERVAL, _flush_agent_queue)
    _agent_timer.daemon = True
    _agent_timer.start()

# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------
def _extract_hostname(fields: dict) -> str | None:
    for key in ("hostname", "host", "devname", "device_name", "syslog_host"):
        if key in fields and fields[key]:
            return fields[key]
    return None

# ---------------------------------------------------------------------------
# DB writer thread, owns a single persistent SQLite connection
# ---------------------------------------------------------------------------
def _db_writer() -> None:
    conn = get_connection()
    buffer: list[dict] = []
    last_flush = time.monotonic()

    while True:
        try:
            item = _work_queue.get(timeout=_DB_FLUSH_INTERVAL)
            if item is None:
                break
            buffer.append(item)
        except queue.Empty:
            pass

        now = time.monotonic()
        if buffer and (len(buffer) >= _DB_BATCH_SIZE or (now - last_flush) >= _DB_FLUSH_INTERVAL):
            try:
                insert_logs_batch(conn, buffer)
                upsert_devices_batch(conn, [
                    (e["source_ip"], _extract_hostname(e["fields"]), e["vendor"], e["device_type"])
                    for e in buffer
                ])
                
                global _unwritten_logs
                with _db_buffer_lock:
                    del _unwritten_logs[:len(buffer)]
            except Exception as exc:
                print(f"[pipeline] DB write error: {exc}")
            buffer.clear()
            last_flush = now

    # Flush anything remaining before the thread exits
    if buffer:
        try:
            insert_logs_batch(conn, buffer)
            upsert_devices_batch(conn, [
                (e["source_ip"], _extract_hostname(e["fields"]), e["vendor"], e["device_type"])
                for e in buffer
            ])
            with _db_buffer_lock:
                del _unwritten_logs[:len(buffer)]
        except Exception as exc:
            print(f"[pipeline] DB final flush error: {exc}")
    conn.close()

# ---------------------------------------------------------------------------
# Ingestion Workers
# ---------------------------------------------------------------------------
def _ingest_worker() -> None:
    while True:
        try:
            item = _raw_logs_queue.get()
            if item is None:
                break
            source_ip, raw_syslog = item
            process_log(source_ip, raw_syslog)
        except Exception as e:
            print(f"[pipeline] process log error: {e}")

# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------
def queue_log(source_ip: str, raw_syslog: str) -> None:
    _raw_logs_queue.put((source_ip, raw_syslog))

def process_log(source_ip: str, raw_syslog: str) -> dict:
    received_at = datetime.now().isoformat()
    result = normalize_log(source_ip, raw_syslog)

    log_entry = {
        "received_at": received_at,
        "source_ip": source_ip,
        "vendor": result["vendor"],
        "device_type": result["device_type"],
        "facility": result["facility"],
        "severity": result["severity"],
        "raw_message": raw_syslog,
        "fields": result["fields"],
    }

    # Hand off to DB writer — non-blocking, returns in microseconds
    _work_queue.put(log_entry)
    
    with _db_buffer_lock:
        _unwritten_logs.append(log_entry)

    # Feed the agent queue
    with _agent_lock:
        _agent_queue.append(log_entry)
        if len(_agent_queue) >= _AGENT_BATCH_SIZE:
            batch = list(_agent_queue)
            _agent_queue.clear()
        else:
            batch = None

    if batch:
        _on_batch_ready(batch)
        _reset_agent_timer()

    return log_entry

def start_pipeline() -> None:
    init_db()
    init_templates()
    _reset_agent_timer()
    t = threading.Thread(target=_db_writer, name="db-writer", daemon=True)
    t.start()
    
    for i in range(_ingest_num_threads):
        worker = threading.Thread(target=_ingest_worker, name=f"ingest-worker-{i}", daemon=True)
        worker.start()
        
    print(
        f"[pipeline] started — "
        f"agent batch={_AGENT_BATCH_SIZE} flush={_AGENT_FLUSH_INTERVAL}s | "
        f"db batch={_DB_BATCH_SIZE} flush={_DB_FLUSH_INTERVAL}s | "
        f"ingest workers={_ingest_num_threads}"
    )
