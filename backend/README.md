# SOCrates Backend

AI-powered Security Operations Centre backend — ingests syslog streams, auto-detects log formats, runs two-tier GPT analysis, and exposes a REST API for dashboards and interactive SOC chat.

---

## Module Map

```
backend/
├── .env                     # Configuration (API keys, model selection, ports)
├── requirements.txt         # Python dependencies
│
├── services/
│   ├── parser.py            # Entry point — UDP syslog listener + Flask API launcher
│   ├── pipeline.py          # Ingestion pipeline — normalizes, batches, writes DB, feeds agent
│   └── normalizer.py        # Log format detection — built-in templates + AI-generated regex
│
├── agent/
│   ├── analyzer.py          # Two-tier threat analysis (GPT-4.1 triage → GPT-5.1 deep)
│   └── chat.py              # Context-aware SOC chat (GPT-5.1)
│
├── api/
│   ├── app.py               # Flask application factory
│   └── routes.py            # REST API endpoints (alerts, devices, logs, stats, chat)
│
└── database/
    ├── db.py                # SQLite (WAL) — schema, CRUD, batch ops, query helpers
    └── socrates.db          # Auto-created at runtime
```

---

## Data Flow

```
                        UDP :514
Log Source ──────────────────────────> parser.py
                                          │
                                          ▼
                                    normalizer.py
                              ┌─── fingerprint + parse ───┐
                              │   (3 built-in templates   │
                              │   + GPT-4.1 AI fallback)  │
                              └───────────┬───────────────┘
                                          │ normalized dict
                                          ▼
                                    pipeline.py
                           ┌──────────┼──────────┐
                           │          │          │
                    DB writer    Agent queue   Device tracker
                    (batch 50    (batch 100    (auto upsert)
                     / 2s)        / 5min)
                           │          │
                           ▼          ▼
                       socrates.db   analyzer.py
                                      ├─ Tier 1: GPT-4.1 triage
                                      │   └─ threats? ──> Tier 2
                                      └─ Tier 2: GPT-5.1 deep analysis
                                            └─ insert_alert()
                                                    │
                                                    ▼
                                              routes.py (:5000)
                                              ├─ /api/alerts
                                              ├─ /api/devices
                                              ├─ /api/logs
                                              ├─ /api/stats
                                              └─ /api/chat (GPT-5.1)
```

---

## Components

### `services/parser.py` — Entry Point

Starts three subsystems in one process:
1. **UDP syslog listener** on `SYSLOG_HOST:SYSLOG_PORT` (default `0.0.0.0:514`)
2. **Flask REST API** on `API_HOST:API_PORT` (default `0.0.0.0:5000`) in a daemon thread
3. **Pipeline** (DB writer thread + agent batch timer)

```powershell
python -m backend.services.parser
```

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

## Configuration

All configuration is via `backend/.env`:

| Variable | Default | Purpose |
|----------|---------|---------|
| `OPENAI_API_KEY` | — | **Required.** OpenAI API key |
| `OPENAI_MODEL_PARSER` | `gpt-4.1` | Model for AI template generation (normalizer) |
| `OPENAI_MODEL_AGENT` | `gpt-4.1` | Model for Tier-1 triage |
| `OPENAI_MODEL_REASONING` | `gpt-5.1` | Model for Tier-2 deep analysis + chat |
| `SYSLOG_HOST` | `0.0.0.0` | UDP listener bind address |
| `SYSLOG_PORT` | `514` | UDP listener port |
| `API_HOST` | `0.0.0.0` | REST API bind address |
| `API_PORT` | `5000` | REST API port |

---

## Dependencies

```
pandas>=2.0          # DataFrame operations (log generator integration)
pyarrow>=14.0        # Parquet file support
numpy>=1.24          # Numerical operations
openai>=1.0.0        # GPT-4.1 / GPT-5.1 API client
python-dotenv>=1.0.0 # .env file loading
flask>=3.0           # REST API framework
flask-cors>=5.0      # Cross-origin support for frontend
```

Install:
```powershell
pip install -r backend/requirements.txt
```
