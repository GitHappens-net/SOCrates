import threading
import time
from datetime import datetime

from backend.database.db import init_db, insert_log, upsert_device
from backend.services.normalizer import normalize_log, init_templates

# Queue settings
_BATCH_SIZE = 50
_FLUSH_INTERVAL = 300  # seconds (5 minutes)

_queue: list[dict] = []
_queue_lock = threading.Lock()
_flush_timer: threading.Timer | None = None

# Placeholder — will be replaced by the real agent call
def _on_batch_ready(batch: list[dict]) -> None:
    print(f"[pipeline] batch of {len(batch)} logs ready for agent analysis")

# Flush the queue and send the batch to the agent stub
def _flush_queue() -> None:
    global _flush_timer
    with _queue_lock:
        if not _queue:
            _reset_timer()
            return
        batch = list(_queue)
        _queue.clear()
    _on_batch_ready(batch)
    _reset_timer()

# Reset the periodic flush timer
def _reset_timer() -> None:
    global _flush_timer
    if _flush_timer is not None:
        _flush_timer.cancel()
    _flush_timer = threading.Timer(_FLUSH_INTERVAL, _flush_queue)
    _flush_timer.daemon = True
    _flush_timer.start()

# Extract hostname from parsed fields if present
def _extract_hostname(fields: dict) -> str | None:
    for key in ("hostname", "host", "devname", "device_name", "syslog_host"):
        if key in fields and fields[key]:
            return fields[key]
    return None

# Process one raw syslog message through the full pipeline
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

    # Write to database
    insert_log(
        received_at=received_at,
        source_ip=source_ip,
        vendor=result["vendor"],
        device_type=result["device_type"],
        facility=result["facility"],
        severity=result["severity"],
        raw_message=raw_syslog,
        parsed_fields=result["fields"],
    )

    # Update device inventory
    hostname = _extract_hostname(result["fields"])
    upsert_device(
        ip=source_ip,
        hostname=hostname,
        vendor=result["vendor"],
        device_type=result["device_type"],
    )

    # Add to agent queue
    with _queue_lock:
        _queue.append(log_entry)
        if len(_queue) >= _BATCH_SIZE:
            batch = list(_queue)
            _queue.clear()
        else:
            batch = None

    if batch:
        _on_batch_ready(batch)
        _reset_timer()

    return log_entry

# Called once at startup
def start_pipeline() -> None:
    init_db()
    init_templates()
    _reset_timer()
    print(f"[pipeline] started — queue batch_size={_BATCH_SIZE} flush_interval={_FLUSH_INTERVAL}s")
