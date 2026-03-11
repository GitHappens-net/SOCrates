import json
import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent / "socrates.db"

# Create/open the database and ensure all tables exist
def get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(str(DB_PATH), check_same_thread=False)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.row_factory = sqlite3.Row
    return conn

def init_db() -> None:
    conn = get_connection()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS logs (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            received_at TEXT    NOT NULL,
            source_ip   TEXT    NOT NULL,
            vendor      TEXT    NOT NULL DEFAULT 'unknown',
            device_type TEXT    NOT NULL DEFAULT 'unknown',
            facility    INTEGER NOT NULL DEFAULT -1,
            severity    INTEGER NOT NULL DEFAULT -1,
            raw_message TEXT    NOT NULL,
            parsed_fields TEXT  NOT NULL DEFAULT '{}'
        );

        CREATE TABLE IF NOT EXISTS templates (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            fingerprint   TEXT NOT NULL UNIQUE,
            vendor        TEXT NOT NULL DEFAULT 'unknown',
            device_type   TEXT NOT NULL DEFAULT 'unknown',
            parse_mode    TEXT NOT NULL DEFAULT 'regex',
            regex         TEXT NOT NULL DEFAULT '',
            header_regex  TEXT NOT NULL DEFAULT '',
            fields        TEXT NOT NULL DEFAULT '[]',
            created_at    TEXT NOT NULL DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS devices (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            ip          TEXT    NOT NULL UNIQUE,
            hostname    TEXT,
            vendor      TEXT    NOT NULL DEFAULT 'unknown',
            device_type TEXT    NOT NULL DEFAULT 'unknown',
            first_seen  TEXT    NOT NULL DEFAULT (datetime('now')),
            last_seen   TEXT    NOT NULL DEFAULT (datetime('now'))
        );
    """)
    conn.commit()
    conn.close()

# Logs
def insert_log(received_at: str, source_ip: str, vendor: str, device_type: str, facility: int, severity: int, raw_message: str, parsed_fields: dict) -> int:
    conn = get_connection()
    cur = conn.execute(
        """INSERT INTO logs
           (received_at, source_ip, vendor, device_type, facility, severity, raw_message, parsed_fields)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (received_at, source_ip, vendor, device_type, facility, severity,
         raw_message, json.dumps(parsed_fields)),
    )
    conn.commit()
    row_id = cur.lastrowid
    conn.close()
    return row_id

# Templates
def load_templates() -> list[dict]:
    conn = get_connection()
    rows = conn.execute("SELECT * FROM templates").fetchall()
    conn.close()
    templates = []
    for r in rows:
        templates.append({
            "fingerprint": r["fingerprint"],
            "vendor": r["vendor"],
            "device_type": r["device_type"],
            "parse_mode": r["parse_mode"],
            "regex": r["regex"],
            "header_regex": r["header_regex"],
            "fields": json.loads(r["fields"]),
        })
    return templates

def save_template(fingerprint: str, vendor: str, device_type: str, parse_mode: str, regex: str, header_regex: str, fields: list[str]) -> None:
    conn = get_connection()
    conn.execute(
        """INSERT OR IGNORE INTO templates
           (fingerprint, vendor, device_type, parse_mode, regex, header_regex, fields)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        (fingerprint, vendor, device_type, parse_mode, regex, header_regex,
         json.dumps(fields)),
    )
    conn.commit()
    conn.close()

# Devices
def upsert_device(ip: str, hostname: str | None, vendor: str, device_type: str) -> None:
    conn = get_connection()
    conn.execute(
        """INSERT INTO devices (ip, hostname, vendor, device_type)
           VALUES (?, ?, ?, ?)
           ON CONFLICT(ip) DO UPDATE SET
               hostname    = COALESCE(excluded.hostname, devices.hostname),
               vendor      = excluded.vendor,
               device_type = excluded.device_type,
               last_seen   = datetime('now')""",
        (ip, hostname, vendor, device_type),
    )
    conn.commit()
    conn.close()

# Batch operations — accept a caller-owned connection so the writer thread
# can keep one connection open and avoid per-log open/close overhead.

def insert_logs_batch(conn: sqlite3.Connection, logs: list[dict]) -> None:
    """Insert a batch of normalised log dicts using a single executemany call."""
    conn.executemany(
        """INSERT INTO logs
           (received_at, source_ip, vendor, device_type, facility, severity, raw_message, parsed_fields)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        [
            (
                log["received_at"], log["source_ip"], log["vendor"], log["device_type"],
                log["facility"], log["severity"], log["raw_message"],
                json.dumps(log["fields"]),
            )
            for log in logs
        ],
    )
    conn.commit()

def upsert_devices_batch(conn: sqlite3.Connection, rows: list[tuple]) -> None:
    """Upsert a batch of (ip, hostname, vendor, device_type) tuples."""
    conn.executemany(
        """INSERT INTO devices (ip, hostname, vendor, device_type)
           VALUES (?, ?, ?, ?)
           ON CONFLICT(ip) DO UPDATE SET
               hostname    = COALESCE(excluded.hostname, devices.hostname),
               vendor      = excluded.vendor,
               device_type = excluded.device_type,
               last_seen   = datetime('now')""",
        rows,
    )
    conn.commit()
