# Backend

## Quick Start

### 1. Install dependencies

```powershell
pip install -r backend/requirements.txt
```

### 2. Configure environment

Create `backend/.env`:

```env
OPENAI_API_KEY=sk-...
OPENAI_MODEL_AGENT=gpt-4.1        # Tier 1 triage model
OPENAI_MODEL_REASONING=gpt-5.1    # Tier 2 deep analysis + chat model

# Optional — defaults shown
SYSLOG_HOST=0.0.0.0
SYSLOG_PORT=514
API_HOST=0.0.0.0
API_PORT=5000
```

> **Windows note:** UDP port 514 requires an elevated (Administrator) shell.
> Set `SYSLOG_PORT=5514` in `.env` to avoid this during development.

### 3. Start the backend

Run from the **repo root** so `backend` is importable as a package:

```powershell
python -m backend.main
```

This starts three subsystems in one process:
1. **Pipeline** — DB writer thread + agent analysis queue
2. **REST API** — Flask on `API_HOST:API_PORT` (background thread)
3. **Syslog UDP listener** — `SYSLOG_HOST:SYSLOG_PORT` (main thread)

### 4. Stream test logs

Convert a CIC-IDS CSV to parquet (one-time), then stream via syslog:

```powershell
python -m tools.Log_Stream_Generator `
  --parquet data/datasets/CIC-IDS-Collection.parquet `
  --syslog --syslog-host 127.0.0.1 --syslog-port 514 `
  --max-flows 200 --speed 0
```

---

## REST API Reference

All routes are prefixed with `/api`.

### Alerts

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/alerts` | List alerts. Query params: `status`, `severity`, `limit` (default 50), `offset` (default 0) |
| `GET` | `/alerts/<id>` | Get a single alert by ID |
| `PATCH` | `/alerts/<id>` | Update status. Body: `{"status": "open\|acknowledged\|resolved\|dismissed"}` |
| `DELETE` | `/alerts` | Clear all resolved/dismissed alerts |

### Devices & Logs

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/devices` | List all known devices |
| `GET` | `/devices/<ip>/logs` | Logs for a specific device IP. Params: `limit`, `offset` |
| `GET` | `/logs` | All recent logs. Params: `limit` (max 500), `offset` |
| `GET` | `/stats` | Total log count, breakdown by vendor and device |

### Chat

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/chat` | Send a message. Body: `{"message": "...", "session_id": "..."}` |
| `DELETE` | `/chat` | Clear a session's history. Body: `{"session_id": "..."}` |

---

## Components

### `main.py` — Entry Point

Central launcher. Starts the pipeline, spins the Flask API in a daemon thread, then runs the syslog UDP socket on the main thread (so `Ctrl+C` shuts everything down cleanly).

### `services/normalizer.py` — Log Format Detection

Three-stage log parsing:

| Stage | Method | Details |
|-------|--------|---------|
| 1 | **Fingerprint** | Regex heuristics to classify logs (FortiGate kv, Cisco IOS, Linux syslog) |
| 2 | **Built-in templates** | Hardcoded regex/kv patterns for known vendors — zero API calls |
| 3 | **AI fallback** | Sends unknown formats to GPT-4.1 to generate a parsing template (regex or kv), which is persisted to the DB for future use |

Built-in templates:
- **FortiGate** (`kv` mode) — `date=YYYY-MM-DD time=... devname=...` key-value format
- **Cisco IOS** (`regex` mode) — `%FACILITY-SEVERITY-MNEMONIC:` syslog format
- **Linux syslog** (`regex` mode) — Standard `<PRI>Mon DD HH:MM:SS hostname process[pid]:` format

AI-generated templates are cached in the `templates` table and loaded on startup.

### `services/pipeline.py` — Ingestion Pipeline

- **DB writer thread**: Owns a single persistent SQLite connection. Batches logs (50) and flushes every 2 seconds via `executemany`.
- **Agent queue**: Collects normalized logs. Triggers analysis at 100 logs or 5-minute timeout.
- **Device tracker**: Auto-upserts device records (IP, hostname, vendor, type) with every batch.

### `agent/analyzer.py` — Two-Tier AI Analysis

| Tier | Model | Purpose | Input | Output |
|------|-------|---------|-------|--------|
| **1 — Triage** | GPT-4.1 | Fast batch scan for anomalies | Compacted log summaries (security-relevant fields only) | `{threats_detected, findings[{severity, title, summary, related_indices}]}` |
| **2 — Deep Analysis** | GPT-5.1 | Detailed reasoning + mitigations | Finding + related logs + past alerts + device inventory | `{severity, title, analysis, mitigations[{description, command, risk}], affected_devices}` |

Token efficiency: `_compact_log()` strips each log to ~15 security-relevant fields before sending to the model.

If Tier-2 fails, the triage finding is stored directly as a "triage-only" alert.

### `agent/chat.py` — Interactive SOC Chat

GPT-5.1-powered conversational interface. Each turn:
1. Rebuilds system prompt with **live context** (devices, last 25 alerts, log stats)
2. Appends user message to per-session history
3. Sends to GPT-5.1 with `temperature=0.3`
4. Trims history to 40 messages per session

The model can answer questions like:
- *"What threats are affecting my network?"*
- *"Can you correlate these events — is an attack underway?"*
- *"How do I block this on the FortiGate?"*

### `api/routes.py` — REST API

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/alerts` | List alerts — query: `?status=open&severity=critical&limit=50` |
| `GET` | `/api/alerts/<id>` | Single alert with full analysis + mitigations |
| `PATCH` | `/api/alerts/<id>` | Update status: `open`, `acknowledged`, `resolved`, `dismissed` |
| `DELETE` | `/api/alerts` | Clear all resolved/dismissed alerts |
| `GET` | `/api/devices` | List all known devices (IP, hostname, vendor, type, last seen) |
| `GET` | `/api/logs?limit=50` | Recent logs (max 500) with parsed fields |
| `GET` | `/api/stats` | Ingestion statistics (total, by vendor, by device) |
| `POST` | `/api/chat` | `{"message": "...", "session_id": "..."}` → `{"reply": "..."}` |
| `DELETE` | `/api/chat` | Clear chat session: `{"session_id": "..."}` |

CORS is enabled for all origins (development mode).

### `database/db.py` — SQLite Storage

WAL mode for concurrent reads/writes. Four tables:

| Table | Purpose |
|-------|---------|
| `logs` | Raw + parsed log storage (received_at, source_ip, vendor, device_type, facility, severity, raw_message, parsed_fields JSON) |
| `templates` | AI-generated parsing templates (fingerprint, vendor, regex/header_regex, fields) |
| `devices` | Auto-discovered device inventory (IP, hostname, vendor, type, first/last seen) |
| `alerts` | AI analysis results (severity, title, summary, analysis, mitigations JSON, affected_devices JSON, related_logs JSON, status, resolved_at) |

Batch operations (`insert_logs_batch`, `upsert_devices_batch`) use `executemany` for throughput. Alert CRUD supports filtering by status and severity.

---

## Dependencies

Install:
```powershell
pip install -r backend/requirements.txt
```
