# SOCrates
Your SOC AI assistant!

---

## Setup

**Requirements**
```
pip install -r backend/requirements.txt
```

**Dataset**

Download at least the [CIC-IDS Collection](https://www.kaggle.com/datasets/dhoogla/cicidscollection?resource=download) parquet from Kaggle and place it in the `data/` folder:

```
data/
  cic-collection.parquet
```

**`backend/.env`**
```env
OPENAI_API_KEY=sk-...
OPENAI_MODEL_PARSER=gpt-4.1
OPENAI_MODEL_AGENT=gpt-4.1
OPENAI_MODEL_REASONING=gpt-5.1
SYSLOG_HOST=0.0.0.0
SYSLOG_PORT=514
API_HOST=0.0.0.0
API_PORT=5000
```

| Variable | Default | Purpose |
|----------|---------|---------|
| `OPENAI_MODEL_PARSER` | `gpt-4.1` | Template generation for unknown log formats |
| `OPENAI_MODEL_AGENT` | `gpt-4.1` | Tier-1 triage (fast batch scanning) |
| `OPENAI_MODEL_REASONING` | `gpt-5.1` | Tier-2 deep analysis + interactive chat |
| `API_HOST` / `API_PORT` | `0.0.0.0:5000` | REST API bind address |

---

## Running with Docker (Recommended)

The easiest way to run the entire stack (Frontend, Backend, and optionally the Log Engine) is using Docker.

**1. Set up Environment Variables**
Ensure you have created the correct `.env` files for the backend and frontend:

- `backend/.env` (See configuration details above, make sure `OPENAI_API_KEY` is set).
- `frontend/.env`
  ```env
  VITE_BACKEND_URL=http://backend:8000
  ```

**2. Make sure the dataset is correctly placed**
Ensure your parquet file is present at `data/cic-collection.parquet` (this should match the path used in the manual setup section). Note: Check for exact case sensitivity, especially on Linux—if you choose a different filename, update the `docker-compose.yml` accordingly.

**3. Start the application**
To run the Frontend + Backend (no log simulator):
```bash
docker compose up --build
```

To run the Frontend + Backend + **Log Simulator**:
```bash
docker compose --profile simulator up --build
```

**Services will be available at:**
- **Frontend Dashboard:** http://localhost:5173
- **Backend API:** http://localhost:8000
- **Simulator Server (if profile used):** http://localhost:5050

To stop the containers:
```bash
docker compose down
```

---

## Running Locally (Manual Setup)
**Start the backend** (from project root):
```powershell
python -m backend.main
```

This starts:
- **UDP syslog listener** on port 514 (receives logs)
- **REST API server** on port 5000 (dashboard + chat)
- **DB** at `backend/database/socrates.db` (created automatically)

**Simulate logs** (separate terminal, from project root):
```powershell
python -m tools.Log_Stream_Generator --parquet data\cic-collection.parquet --syslog --max-flows 1000 --speed 1
```

`--format` defaults to `fortigate`. Use `--format paloalto` for PaloAlto logs.

Other output modes: `--output file.log` (file), `--endpoint http://...` (HTTP POST), `--serve` (REST API server). See [tools/Log_Stream_Generator/README.md](tools/Log_Stream_Generator/README.md) for full details.

---

## Architecture

```
┌───────────────────┐     UDP/514      ┌──────────────┐
│  Log Stream       │ ───────────────> │   Parser     │
│  Generator        │                  │  (syslog)    │
│  (FortiGate/PA)   │                  └──────┬───────┘
└───────────────────┘                         │
                                              ▼
                                     ┌────────────────┐
                                     │   Normalizer   │
                                     │  (templates /  │
                                     │   AI regex)    │
                                     └───────┬────────┘
                                             │
                              ┌──────────────┼──────────────┐
                              ▼              ▼              ▼
                      ┌──────────┐   ┌──────────────┐  ┌─────────┐
                      │ DB Writer│   │ Agent Queue  │  │ Devices │
                      │ (batch)  │   │ (100 / 5min) │  │ Tracker │
                      └────┬─────┘   └──────┬───────┘  └─────────┘
                           │                │
                           ▼                ▼
                      ┌─────────┐   ┌───────────────┐
                      │ SQLite  │   │ Tier-1 Triage │
                      │  (WAL)  │   │  (GPT-4.1)    │
                      └─────────┘   └───────┬───────┘
                                            │ threats?
                                            ▼
                                    ┌───────────────┐
                                    │ Tier-2 Deep   │
                                    │ Analysis      │
                                    │  (GPT-5.1)    │
                                    └───────┬───────┘
                                            │
                                            ▼
                                    ┌───────────────┐     ┌──────────┐
                                    │    Alerts     │ <── │ REST API │ <── User / Dashboard
                                    │   Database    │ ──> │ :5000    │ ──> Chat (GPT-5.1)
                                    └───────────────┘     └──────────┘
```

### Analysis Pipeline

1. **Ingestion** — Logs arrive via UDP syslog, are normalized (built-in templates or AI-generated regex), and written to SQLite in batches.
2. **Triage (GPT-4.1)** — Every 100 logs or 5 minutes, compact log summaries are sent to GPT-4.1 for fast threat detection.
3. **Deep Analysis (GPT-5.1)** — If triage flags concerns, the flagged logs + historical alerts + device inventory are escalated to GPT-5.1 for detailed reasoning, correlation, and mitigation suggestions.
4. **Alerts** — Results are stored as alerts with severity, analysis, and actionable mitigations (including device-specific CLI commands).
5. **Chat** — Users can ask GPT-5.1 questions about their infrastructure in real-time, with full context of alerts, devices, and log statistics.

---

## REST API

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/alerts` | List alerts (query: `?status=open&severity=critical&limit=50`) |
| `GET` | `/api/alerts/<id>` | Get single alert with full analysis |
| `PATCH` | `/api/alerts/<id>` | Update status: `{"status": "acknowledged\|resolved\|dismissed"}` |
| `DELETE` | `/api/alerts` | Clear resolved/dismissed alerts |
| `GET` | `/api/devices` | List all known devices |
| `GET` | `/api/logs?limit=50` | Recent logs |
| `GET` | `/api/stats` | Log ingestion statistics |
| `POST` | `/api/chat` | Chat: `{"message": "...", "session_id": "..."}` |
| `DELETE` | `/api/chat` | Clear chat session |

---

## Example Datasets

- [Real CyberSecurity Datasets (GitHub)](https://github.com/gfek/Real-CyberSecurity-Datasets)
- [Network Intrusion dataset (CIC-IDS-2017) (Kaggle)](https://www.kaggle.com/datasets/chethuhn/network-intrusion-dataset)
- [CIC-IDS Collection (Kaggle)](https://www.kaggle.com/datasets/dhoogla/cicidscollection)
- [TON IoT and UNSW-NB15 (UNSW)](https://research.unsw.edu.au/projects/unsw-nb15-dataset)