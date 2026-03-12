import json
import sqlite3
from datetime import datetime
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

        CREATE TABLE IF NOT EXISTS alerts (
            id               INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at       TEXT    NOT NULL DEFAULT (datetime('now')),
            severity         TEXT    NOT NULL DEFAULT 'medium',
            title            TEXT    NOT NULL,
            summary          TEXT    NOT NULL,
            analysis         TEXT    NOT NULL DEFAULT '',
            mitigations      TEXT    NOT NULL DEFAULT '[]',
            affected_devices TEXT    NOT NULL DEFAULT '[]',
            related_logs     TEXT    NOT NULL DEFAULT '[]',
            status           TEXT    NOT NULL DEFAULT 'open',
            resolved_at      TEXT
        );
    """)
    conn.commit()
    conn.close()

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

# ── Alerts ────────────────────────────────────────────────────────────────

def insert_alert(
    severity: str,
    title: str,
    summary: str,
    analysis: str = "",
    mitigations: list | None = None,
    affected_devices: list | None = None,
    related_logs: list | None = None,
) -> int:
    conn = get_connection()
    cur = conn.execute(
        """INSERT INTO alerts
           (severity, title, summary, analysis, mitigations, affected_devices, related_logs)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        (
            severity, title, summary, analysis,
            json.dumps(mitigations or []),
            json.dumps(affected_devices or []),
            json.dumps(related_logs or []),
        ),
    )
    conn.commit()
    alert_id = cur.lastrowid
    conn.close()
    return alert_id


def get_alerts(
    status: str | None = None,
    severity: str | None = None,
    limit: int = 50,
) -> list[dict]:
    conn = get_connection()
    sql = "SELECT * FROM alerts WHERE 1=1"
    params: list = []
    if status:
        sql += " AND status = ?"
        params.append(status)
    if severity:
        sql += " AND severity = ?"
        params.append(severity)
    sql += " ORDER BY created_at DESC LIMIT ?"
    params.append(limit)
    rows = conn.execute(sql, params).fetchall()
    conn.close()
    return [_row_to_alert(r) for r in rows]


def get_alert(alert_id: int) -> dict | None:
    conn = get_connection()
    row = conn.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,)).fetchone()
    conn.close()
    return _row_to_alert(row) if row else None


def update_alert_status(alert_id: int, status: str) -> bool:
    conn = get_connection()
    resolved_at = datetime.now().isoformat() if status in ("resolved", "dismissed") else None
    cur = conn.execute(
        "UPDATE alerts SET status = ?, resolved_at = COALESCE(?, resolved_at) WHERE id = ?",
        (status, resolved_at, alert_id),
    )
    conn.commit()
    changed = cur.rowcount > 0
    conn.close()
    return changed


def clear_alerts() -> int:
    conn = get_connection()
    cur = conn.execute("DELETE FROM alerts WHERE status IN ('resolved', 'dismissed')")
    conn.commit()
    count = cur.rowcount
    conn.close()
    return count


def _row_to_alert(row: sqlite3.Row) -> dict:
    return {
        "id": row["id"],
        "created_at": row["created_at"],
        "severity": row["severity"],
        "title": row["title"],
        "summary": row["summary"],
        "analysis": row["analysis"],
        "mitigations": json.loads(row["mitigations"]),
        "affected_devices": json.loads(row["affected_devices"]),
        "related_logs": json.loads(row["related_logs"]),
        "status": row["status"],
        "resolved_at": row["resolved_at"],
    }


# ── Query helpers ─────────────────────────────────────────────────────────

def get_devices_list() -> list[dict]:
    conn = get_connection()
    rows = conn.execute("SELECT * FROM devices ORDER BY last_seen DESC").fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_recent_logs(limit: int = 100) -> list[dict]:
    conn = get_connection()
    rows = conn.execute(
        "SELECT * FROM logs ORDER BY id DESC LIMIT ?", (limit,)
    ).fetchall()
    conn.close()
    return [
        {**dict(r), "parsed_fields": json.loads(r["parsed_fields"])}
        for r in rows
    ]


def get_log_stats() -> dict:
    conn = get_connection()
    total = conn.execute("SELECT COUNT(*) as cnt FROM logs").fetchone()["cnt"]
    by_vendor = conn.execute(
        "SELECT vendor, COUNT(*) as cnt FROM logs GROUP BY vendor ORDER BY cnt DESC"
    ).fetchall()
    by_device = conn.execute(
        "SELECT source_ip, COUNT(*) as cnt FROM logs GROUP BY source_ip ORDER BY cnt DESC LIMIT 10"
    ).fetchall()
    conn.close()
    return {
        "total_logs": total,
        "by_vendor": {r["vendor"]: r["cnt"] for r in by_vendor},
        "by_device": {r["source_ip"]: r["cnt"] for r in by_device},
    }
